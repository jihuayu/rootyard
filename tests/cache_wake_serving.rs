//! Integration contracts for runtime `ServingCache` (Memory default, explicit
//! fail-closed Redis config, degrade-to-origin, breaker recovery, singleflight,
//! and client-error isolation).
use anyhow::{Result, bail};
use axum::http::StatusCode;
use rootyard::cache_wake::{
    AdvisoryCache, CacheBackendKind, CacheKey, CacheKeyParts, CacheKind, CacheLimits, CacheOutcome, CacheTask,
    CacheValue, MemoryCache, OriginError, ServingCache,
};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

static ENV_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

struct EnvGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(name: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(name);
        // Serialized by ENV_LOCK across tests in this suite.
        unsafe { std::env::set_var(name, value) };
        Self { name, previous }
    }

    fn unset(name: &'static str) -> Self {
        let previous = std::env::var_os(name);
        // Serialized by ENV_LOCK across tests in this suite.
        unsafe { std::env::remove_var(name) };
        Self { name, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(prev) => unsafe { std::env::set_var(self.name, prev) },
            None => unsafe { std::env::remove_var(self.name) },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SampleView {
    oid: String,
    rev: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MockMode {
    Healthy,
    Outage,
    CorruptRead,
}

struct MockFlakyCache {
    limits: CacheLimits,
    inner: Mutex<Arc<MemoryCache>>,
    mode: Mutex<MockMode>,
}

impl MockFlakyCache {
    fn new(limits: CacheLimits) -> Self {
        Self {
            limits,
            inner: Mutex::new(Arc::new(MemoryCache::new(limits).unwrap())),
            mode: Mutex::new(MockMode::Healthy),
        }
    }

    fn set_mode(&self, mode: MockMode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn flush_all(&self) {
        *self.inner.lock().unwrap() = Arc::new(MemoryCache::new(self.limits).unwrap());
    }

    fn snapshot_inner(&self) -> Arc<MemoryCache> {
        self.inner.lock().unwrap().clone()
    }
}

impl AdvisoryCache for MockFlakyCache {
    fn get<'a>(&'a self, key: &'a CacheKey) -> CacheTask<'a, Result<Option<CacheValue>>> {
        let mode = *self.mode.lock().unwrap();
        let store = self.snapshot_inner();
        Box::pin(async move {
            match mode {
                MockMode::Healthy => store.get(key).await,
                MockMode::Outage => bail!("simulated Redis connection reset"),
                MockMode::CorruptRead => Ok(Some(CacheValue::new(key.kind(), key.version(), b"{corrupt".to_vec()))),
            }
        })
    }

    fn put<'a>(&'a self, key: &'a CacheKey, value: CacheValue, ttl: Option<Duration>) -> CacheTask<'a, Result<()>> {
        let mode = *self.mode.lock().unwrap();
        let store = self.snapshot_inner();
        Box::pin(async move {
            match mode {
                MockMode::Healthy | MockMode::CorruptRead => store.put(key, value, ttl).await,
                MockMode::Outage => bail!("simulated Redis write timeout"),
            }
        })
    }

    fn delete<'a>(&'a self, key: &'a CacheKey) -> CacheTask<'a, Result<()>> {
        let mode = *self.mode.lock().unwrap();
        let store = self.snapshot_inner();
        Box::pin(async move {
            match mode {
                MockMode::Healthy | MockMode::CorruptRead => store.delete(key).await,
                MockMode::Outage => bail!("simulated Redis delete error"),
            }
        })
    }
}

fn scoped_key(authority: &str, version: u64, discriminator: &str) -> CacheKey {
    CacheKey::new(CacheKeyParts {
        environment: "test",
        authority,
        schema: 1,
        history_incarnation: Uuid::from_u128(0xAA),
        tenant: Uuid::from_u128(0xBB),
        repo: Uuid::from_u128(0xCC),
        kind: CacheKind::TreeListing,
        version,
        discriminator,
    })
    .unwrap()
}

fn test_limits() -> CacheLimits {
    CacheLimits { breaker_failures: 2, breaker_cooldown: Duration::from_millis(35), ..CacheLimits::default() }
}

#[tokio::test]
async fn standalone_memory_has_no_redis_dependency_and_isolates_authorities() {
    let cache = ServingCache::standalone_memory().unwrap();
    assert_eq!(cache.backend_kind(), CacheBackendKind::Memory);

    let gitfs_key = scoped_key("gitfs", 1, "main:README.md");
    let pando_key = scoped_key("pando", 1, "main:README.md");
    assert_ne!(gitfs_key, pando_key);

    let (gitfs_val, o1) = cache
        .get_or_load_json(
            &gitfs_key,
            None,
            |_: &StatusCode| false,
            || async { Ok(SampleView { oid: "gitfs-111".to_owned(), rev: 1 }) },
        )
        .await
        .unwrap();
    assert_eq!(o1, CacheOutcome::OriginRefill);

    let (pando_val, o2) = cache
        .get_or_load_json(
            &pando_key,
            None,
            |_: &StatusCode| false,
            || async { Ok(SampleView { oid: "pando-222".to_owned(), rev: 2 }) },
        )
        .await
        .unwrap();
    assert_eq!(o2, CacheOutcome::OriginRefill);
    assert_ne!(gitfs_val, pando_val);

    let (cached_gitfs, o3) = cache
        .get_or_load_json(
            &gitfs_key,
            None,
            |_: &StatusCode| false,
            || async {
                panic!("gitfs key must hit memory cache without calling origin");
            },
        )
        .await
        .unwrap();
    assert_eq!(o3, CacheOutcome::Hit);
    assert_eq!(cached_gitfs, gitfs_val);
}

#[tokio::test]
async fn explicit_invalid_and_unavailable_redis_configs_fail_startup_closed() {
    assert!(ServingCache::from_backend_setting_sync(Some("memcached"), test_limits()).is_err());
    assert!(ServingCache::from_backend_setting_async(Some("auto"), test_limits()).await.is_err());

    let _guard = ENV_LOCK.lock().await;
    let _b = EnvGuard::set("ROOTYARD_CACHE_BACKEND", "redis");
    let _u = EnvGuard::unset("ROOTYARD_CACHE_REDIS_URL");
    assert!(ServingCache::from_env().await.is_err());
    assert!(ServingCache::from_env_sync().is_err());

    let _bad_remote = EnvGuard::set("ROOTYARD_CACHE_REDIS_URL", "redis://cache.example.invalid:6379/0");
    assert!(ServingCache::from_env().await.is_err());
    assert!(ServingCache::from_env_sync().is_err());

    let _unset_b = EnvGuard::unset("ROOTYARD_CACHE_BACKEND");
    let _unset_u = EnvGuard::unset("ROOTYARD_CACHE_REDIS_URL");
    let default_sync = ServingCache::from_env_sync().unwrap();
    let default_async = ServingCache::from_env().await.unwrap();
    assert_eq!(default_sync.backend_kind(), CacheBackendKind::Memory);
    assert_eq!(default_async.backend_kind(), CacheBackendKind::Memory);
}

#[tokio::test]
async fn outage_flush_corrupt_payload_and_breaker_degrade_cleanly_to_origin_and_recover() {
    let limits = test_limits();
    let mock = Arc::new(MockFlakyCache::new(limits));
    mock.flush_all();
    let cache = ServingCache::with_advisory_cache(CacheBackendKind::Redis, mock.clone(), limits).unwrap();
    let key = scoped_key("pando", 9, "blob:src/lib.rs");
    let origin_calls = Arc::new(AtomicUsize::new(0));

    let load = |calls: Arc<AtomicUsize>, rev: u64| async move {
        let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
        Ok::<_, StatusCode>(SampleView { oid: format!("oid-{count}"), rev })
    };

    let (v1, out1) =
        cache.get_or_load_json(&key, None, |s| s.is_server_error(), || load(origin_calls.clone(), 1)).await.unwrap();
    assert_eq!(out1, CacheOutcome::OriginRefill);
    assert_eq!(v1.oid, "oid-1");

    // Simulate Redis FLUSHALL wiping all keys simultaneously
    mock.flush_all();
    let (v2, out2) =
        cache.get_or_load_json(&key, None, |s| s.is_server_error(), || load(origin_calls.clone(), 2)).await.unwrap();
    assert_eq!(out2, CacheOutcome::OriginRefill);
    assert_eq!(v2.oid, "oid-2");

    // Unknown extra field is rejected by #[serde(deny_unknown_fields)] as a miss and repaired from origin
    cache
        .put_value(
            &key,
            CacheValue::new(key.kind(), key.version(), br#"{"oid":"tampered","rev":99,"extra":true}"#.to_vec()),
            None,
        )
        .await;
    let (v_strict, out_strict) =
        cache.get_or_load_json(&key, None, |s| s.is_server_error(), || load(origin_calls.clone(), 3)).await.unwrap();
    assert_eq!(out_strict, CacheOutcome::OriginRefill);
    assert_eq!(v_strict.oid, "oid-3");
    assert!(cache.stats().corrupt_values >= 1);

    // Corrupt payload on read is treated as a miss, evicted, and repaired from origin
    mock.set_mode(MockMode::CorruptRead);
    let (v3, out3) =
        cache.get_or_load_json(&key, None, |s| s.is_server_error(), || load(origin_calls.clone(), 4)).await.unwrap();
    assert_eq!(out3, CacheOutcome::OriginRefill);
    assert_eq!(v3.oid, "oid-4");
    assert!(cache.stats().corrupt_values >= 2);

    // Outage triggers advisory breaker and still serves origin without failing reads
    mock.set_mode(MockMode::Outage);
    let (v4, out4) =
        cache.get_or_load_json(&key, None, |s| s.is_server_error(), || load(origin_calls.clone(), 5)).await.unwrap();
    assert_eq!(out4, CacheOutcome::OriginDegraded);
    assert_eq!(v4.oid, "oid-5");
    assert!(cache.is_advisory_breaker_open());

    let skips_before = cache.stats().breaker_skips;
    let (v5, out5) =
        cache.get_or_load_json(&key, None, |s| s.is_server_error(), || load(origin_calls.clone(), 6)).await.unwrap();
    assert_eq!(out5, CacheOutcome::OriginDegraded);
    assert_eq!(v5.oid, "oid-6");
    assert!(cache.stats().breaker_skips > skips_before);

    // Restore backend and allow breaker cooldown to lapse -> recovers automatically
    mock.set_mode(MockMode::Healthy);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (v6, out6) =
        cache.get_or_load_json(&key, None, |s| s.is_server_error(), || load(origin_calls.clone(), 7)).await.unwrap();
    assert_eq!(out6, CacheOutcome::OriginRefill);
    assert_eq!(v6.oid, "oid-7");
    assert!(!cache.is_advisory_breaker_open());

    let (v7, out7) = cache
        .get_or_load_json(
            &key,
            None,
            |s| s.is_server_error(),
            || async {
                panic!("recovered cache must hit without touching origin");
            },
        )
        .await
        .unwrap();
    assert_eq!(out7, CacheOutcome::Hit);
    assert_eq!(v7, v6);
}

#[tokio::test]
async fn singleflight_coalesces_healthy_misses_and_falls_back_when_cache_drops_writes() {
    let cache = Arc::new(ServingCache::standalone_memory().unwrap());
    let key = Arc::new(scoped_key("gitfs", 4, "tree:root"));
    let calls = Arc::new(AtomicUsize::new(0));
    let start = Arc::new(tokio::sync::Barrier::new(6));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..6 {
        let c = cache.clone();
        let k = key.clone();
        let count = calls.clone();
        let barrier = start.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            c.get_or_load_json(
                &k,
                None,
                |_: &StatusCode| false,
                || async move {
                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    Ok(SampleView { oid: format!("tree-{n}"), rev: 4 })
                },
            )
            .await
            .unwrap()
        });
    }
    let mut outcomes = Vec::new();
    while let Some(res) = tasks.join_next().await {
        outcomes.push(res.unwrap());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(outcomes.iter().filter(|(_, out)| *out == CacheOutcome::OriginRefill).count(), 1);
    assert!(
        outcomes
            .iter()
            .all(|(_, out)| matches!(out, CacheOutcome::OriginRefill | CacheOutcome::WaitedHit | CacheOutcome::Hit))
    );
    assert!(cache.stats().singleflight_waits >= 1);

    // Outage mid-flight forces followers to keep their origin fallback closure safely
    let limits = test_limits();
    let outage = Arc::new(MockFlakyCache::new(limits));
    outage.set_mode(MockMode::Outage);
    let degraded = Arc::new(ServingCache::with_advisory_cache(CacheBackendKind::Redis, outage, limits).unwrap());
    let fail_calls = Arc::new(AtomicUsize::new(0));
    let fail_start = Arc::new(tokio::sync::Barrier::new(4));
    let mut degraded_tasks = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let c = degraded.clone();
        let k = key.clone();
        let count = fail_calls.clone();
        let barrier = fail_start.clone();
        degraded_tasks.spawn(async move {
            barrier.wait().await;
            c.get_or_load_json(
                &k,
                None,
                |_: &StatusCode| false,
                || async move {
                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(SampleView { oid: format!("degraded-{n}"), rev: 5 })
                },
            )
            .await
            .unwrap()
        });
    }
    while let Some(res) = degraded_tasks.join_next().await {
        let (val, outcome) = res.unwrap();
        assert_eq!(outcome, CacheOutcome::OriginDegraded);
        assert!(val.oid.starts_with("degraded-"));
    }
    assert_eq!(fail_calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn client_404_errors_never_trip_origin_circuit_breaker() {
    let limits =
        CacheLimits { breaker_failures: 2, breaker_cooldown: Duration::from_secs(5), ..CacheLimits::default() };
    let cache = ServingCache::from_memory(limits).unwrap();
    let missing_key = scoped_key("gitfs", 1, "missing");

    for _ in 0..8 {
        let err = cache
            .get_or_load_json::<SampleView, _, _, _>(
                &missing_key,
                None,
                |s: &StatusCode| s.is_server_error(),
                || async { Err(StatusCode::NOT_FOUND) },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OriginError::Origin(StatusCode::NOT_FOUND)));
    }

    // Two genuine origin 500s DO trip the origin breaker
    for _ in 0..2 {
        let err = cache
            .get_or_load_json::<SampleView, _, _, _>(
                &missing_key,
                None,
                |s: &StatusCode| s.is_server_error(),
                || async { Err(StatusCode::SERVICE_UNAVAILABLE) },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OriginError::Origin(StatusCode::SERVICE_UNAVAILABLE)));
    }
    let open = cache
        .get_or_load_json::<SampleView, _, _, _>(
            &missing_key,
            None,
            |s: &StatusCode| s.is_server_error(),
            || async {
                panic!("open origin breaker must reject before calling origin");
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(open, OriginError::CircuitOpen));
}
