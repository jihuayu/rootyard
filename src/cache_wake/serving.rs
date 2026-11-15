//! Runtime serving cache facade binding Memory/Redis backends, singleflight,
//! origin bounds, and an advisory-only circuit breaker.
//!
//! Nothing stored here is authoritative. Any backend error, timeout, flush,
//! eviction, corrupt payload, or open advisory breaker degrades directly to an
//! origin load without failing the caller's read.
use super::{
    AdvisoryCache, CacheKey, CacheLimits, CacheValue, MemoryCache, OriginError, OriginGuard, SingleFlight,
    WarmupOutcome, breaker::AdvisoryBreaker,
};
use anyhow::{Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fmt,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[cfg(feature = "state-redis")]
use super::redis::{RedisCache, RedisCacheLimits};
#[cfg(feature = "state-redis")]
use zeroize::Zeroizing;

/// Selected advisory cache backend for the serving runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheBackendKind {
    Memory,
    Redis,
}

/// Outcome returned by [`ServingCache::get_or_load_json`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheOutcome {
    Hit,
    WaitedHit,
    OriginRefill,
    OriginDegraded,
}

/// Snapshot of runtime advisory cache counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServingStats {
    pub hits: u64,
    pub misses: u64,
    pub singleflight_waits: u64,
    pub backend_errors: u64,
    pub corrupt_values: u64,
    pub origin_loads: u64,
    pub breaker_skips: u64,
}

#[derive(Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    singleflight_waits: AtomicU64,
    backend_errors: AtomicU64,
    corrupt_values: AtomicU64,
    origin_loads: AtomicU64,
    breaker_skips: AtomicU64,
}

#[cfg(feature = "state-redis")]
struct LazyRedisState {
    url: Zeroizing<String>,
    limits: RedisCacheLimits,
    cell: tokio::sync::OnceCell<RedisCache>,
}

enum Backend {
    Memory(Box<MemoryCache>),
    Custom {
        kind: CacheBackendKind,
        cache: Arc<dyn AdvisoryCache>,
    },
    #[cfg(feature = "state-redis")]
    Redis(Box<RedisCache>),
    #[cfg(feature = "state-redis")]
    LazyRedis(Box<LazyRedisState>),
}

impl Backend {
    fn kind(&self) -> CacheBackendKind {
        match self {
            Self::Memory(_) => CacheBackendKind::Memory,
            Self::Custom { kind, .. } => *kind,
            #[cfg(feature = "state-redis")]
            Self::Redis(_) | Self::LazyRedis(_) => CacheBackendKind::Redis,
        }
    }

    async fn resolve(&self) -> Result<&dyn AdvisoryCache> {
        Ok(match self {
            Self::Memory(cache) => cache.as_ref(),
            Self::Custom { cache, .. } => cache.as_ref(),
            #[cfg(feature = "state-redis")]
            Self::Redis(cache) => cache.as_ref(),
            #[cfg(feature = "state-redis")]
            Self::LazyRedis(lazy) => {
                lazy.cell.get_or_try_init(|| RedisCache::connect(lazy.url.as_str(), lazy.limits)).await?
            }
        })
    }

    async fn get(&self, key: &CacheKey) -> Result<Option<CacheValue>> {
        self.resolve().await?.get(key).await
    }

    async fn put(&self, key: &CacheKey, value: CacheValue, ttl: Option<Duration>) -> Result<()> {
        self.resolve().await?.put(key, value, ttl).await
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        self.resolve().await?.delete(key).await
    }
}

enum GuardProbe<T, E> {
    Ok(T),
    NonFaultErr(E),
}

enum GuardedCompute<T, E> {
    Loaded { value: T, put_ok: bool },
    CallerErr(E),
    GuardErr(OriginError<()>),
}

/// Bounded advisory runtime cache shared by serving handlers.
pub struct ServingCache {
    backend: Backend,
    limits: CacheLimits,
    singleflight: SingleFlight,
    origin_guard: OriginGuard,
    advisory_breaker: AdvisoryBreaker,
    counters: Counters,
}

impl fmt::Debug for ServingCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServingCache")
            .field("backend", &self.backend.kind())
            .field("advisory_breaker_open", &self.advisory_breaker.is_open())
            .finish()
    }
}

impl ServingCache {
    fn build(backend: Backend, limits: CacheLimits) -> Result<Self> {
        limits.validate()?;
        let singleflight = SingleFlight::new(limits.max_inflight, limits.request_timeout)?;
        let origin_guard = OriginGuard::new(limits)?;
        let advisory_breaker = AdvisoryBreaker::new(limits.breaker_failures, limits.breaker_cooldown);
        Ok(Self { backend, limits, singleflight, origin_guard, advisory_breaker, counters: Counters::default() })
    }

    /// Standalone default profile: strictly in-process bounded Memory, no Redis dependency.
    pub fn standalone_memory() -> Result<Self> {
        Self::from_memory(CacheLimits::standalone_memory())
    }

    pub fn from_memory(limits: CacheLimits) -> Result<Self> {
        let cache = MemoryCache::new(limits)?;
        Self::build(Backend::Memory(Box::new(cache)), limits)
    }

    pub fn with_advisory_cache(
        backend: CacheBackendKind,
        cache: Arc<dyn AdvisoryCache>,
        limits: CacheLimits,
    ) -> Result<Self> {
        Self::build(Backend::Custom { kind: backend, cache }, limits)
    }

    #[cfg(feature = "state-redis")]
    pub fn with_redis(redis: RedisCache, limits: CacheLimits) -> Result<Self> {
        Self::build(Backend::Redis(Box::new(redis)), limits)
    }

    pub async fn from_env() -> Result<Self> {
        let raw = std::env::var("ROOTYARD_CACHE_BACKEND").ok();
        let limits = CacheLimits::from_env()?;
        Self::from_backend_setting_async(raw.as_deref(), limits).await
    }

    pub fn from_env_sync() -> Result<Self> {
        let raw = std::env::var("ROOTYARD_CACHE_BACKEND").ok();
        let limits = CacheLimits::from_env()?;
        Self::from_backend_setting_sync(raw.as_deref(), limits)
    }

    pub async fn from_backend_setting_async(backend: Option<&str>, limits: CacheLimits) -> Result<Self> {
        match normalize_backend(backend)? {
            CacheBackendKind::Memory => Self::from_memory(limits),
            CacheBackendKind::Redis => Self::connect_redis_from_env_with_limits(limits).await,
        }
    }

    pub fn from_backend_setting_sync(backend: Option<&str>, limits: CacheLimits) -> Result<Self> {
        match normalize_backend(backend)? {
            CacheBackendKind::Memory => Self::from_memory(limits),
            CacheBackendKind::Redis => Self::connect_redis_sync_probe(limits),
        }
    }

    #[cfg(not(feature = "state-redis"))]
    async fn connect_redis_from_env_with_limits(_limits: CacheLimits) -> Result<Self> {
        bail!("ROOTYARD_CACHE_BACKEND=redis requires building with feature 'state-redis'")
    }

    #[cfg(not(feature = "state-redis"))]
    fn connect_redis_sync_probe(_limits: CacheLimits) -> Result<Self> {
        bail!("ROOTYARD_CACHE_BACKEND=redis requires building with feature 'state-redis'")
    }

    #[cfg(feature = "state-redis")]
    async fn connect_redis_from_env_with_limits(limits: CacheLimits) -> Result<Self> {
        let redis_limits = RedisCacheLimits::from_cache_limits(limits);
        let redis = RedisCache::connect_from_env(redis_limits).await?;
        Self::with_redis(redis, limits)
    }

    #[cfg(feature = "state-redis")]
    fn connect_redis_sync_probe(limits: CacheLimits) -> Result<Self> {
        let raw_url = std::env::var("ROOTYARD_CACHE_REDIS_URL")
            .map_err(|_| anyhow::anyhow!("ROOTYARD_CACHE_REDIS_URL is required for Redis cache"))?;
        let url = Zeroizing::new(raw_url);
        let probe_url = Zeroizing::new(url.as_str().to_owned());
        let redis_limits = RedisCacheLimits::from_cache_limits(limits);
        // Validate startup contract on an isolated probe thread so no connection driver outlives a throwaway runtime.
        let handle = std::thread::spawn(move || -> Result<()> {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            let _probe = rt.block_on(RedisCache::connect(&probe_url, redis_limits))?;
            Ok(())
        });
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(_) => bail!("Redis startup validation thread panicked"),
        }
        let lazy = LazyRedisState { url, limits: redis_limits, cell: tokio::sync::OnceCell::new() };
        Self::build(Backend::LazyRedis(Box::new(lazy)), limits)
    }

    pub fn backend_kind(&self) -> CacheBackendKind {
        self.backend.kind()
    }

    pub fn limits(&self) -> CacheLimits {
        self.limits
    }

    pub fn is_advisory_breaker_open(&self) -> bool {
        self.advisory_breaker.is_open()
    }

    pub fn stats(&self) -> ServingStats {
        ServingStats {
            hits: self.counters.hits.load(Ordering::Relaxed),
            misses: self.counters.misses.load(Ordering::Relaxed),
            singleflight_waits: self.counters.singleflight_waits.load(Ordering::Relaxed),
            backend_errors: self.counters.backend_errors.load(Ordering::Relaxed),
            corrupt_values: self.counters.corrupt_values.load(Ordering::Relaxed),
            origin_loads: self.counters.origin_loads.load(Ordering::Relaxed),
            breaker_skips: self.counters.breaker_skips.load(Ordering::Relaxed),
        }
    }

    async fn get_value_inner(&self, key: &CacheKey) -> (Option<CacheValue>, bool) {
        let Some(permit) = self.advisory_breaker.try_begin() else {
            self.counters.breaker_skips.fetch_add(1, Ordering::Relaxed);
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            return (None, true);
        };
        match self.backend.get(key).await {
            Ok(Some(value)) if value.kind() == key.kind() && value.version() == key.version() => {
                permit.record_ok();
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                (Some(value), false)
            }
            Ok(Some(_)) => {
                permit.record_ok();
                self.counters.corrupt_values.fetch_add(1, Ordering::Relaxed);
                self.counters.misses.fetch_add(1, Ordering::Relaxed);
                self.delete_key(key).await;
                (None, false)
            }
            Ok(None) => {
                permit.record_ok();
                self.counters.misses.fetch_add(1, Ordering::Relaxed);
                (None, false)
            }
            Err(_) => {
                permit.record_err();
                self.counters.backend_errors.fetch_add(1, Ordering::Relaxed);
                self.counters.misses.fetch_add(1, Ordering::Relaxed);
                (None, true)
            }
        }
    }

    pub async fn get_value(&self, key: &CacheKey) -> Option<CacheValue> {
        self.get_value_inner(key).await.0
    }

    async fn put_value_inner(&self, key: &CacheKey, value: CacheValue, ttl: Option<Duration>) -> bool {
        if value.kind() != key.kind() || value.version() != key.version() {
            return false;
        }
        if value.encoded_len() > self.limits.max_value_bytes {
            return true;
        }
        let Some(permit) = self.advisory_breaker.try_begin() else {
            self.counters.breaker_skips.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        match self.backend.put(key, value, ttl).await {
            Ok(()) => {
                permit.record_ok();
                true
            }
            Err(_) => {
                permit.record_err();
                self.counters.backend_errors.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub async fn put_value(&self, key: &CacheKey, value: CacheValue, ttl: Option<Duration>) {
        let _ = self.put_value_inner(key, value, ttl).await;
    }

    pub async fn delete_key(&self, key: &CacheKey) {
        let Some(permit) = self.advisory_breaker.try_begin() else {
            self.counters.breaker_skips.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match self.backend.delete(key).await {
            Ok(()) => permit.record_ok(),
            Err(_) => {
                permit.record_err();
                self.counters.backend_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn get_json_inner<T: DeserializeOwned>(&self, key: &CacheKey) -> (Option<T>, bool) {
        let (value, degraded) = self.get_value_inner(key).await;
        let Some(value) = value else {
            return (None, degraded);
        };
        match serde_json::from_slice::<T>(value.bytes()) {
            Ok(parsed) => (Some(parsed), false),
            Err(_) => {
                self.counters.corrupt_values.fetch_add(1, Ordering::Relaxed);
                self.delete_key(key).await;
                (None, false)
            }
        }
    }

    pub async fn get_json<T: DeserializeOwned>(&self, key: &CacheKey) -> Option<T> {
        self.get_json_inner(key).await.0
    }

    async fn put_json_inner<T: Serialize>(&self, key: &CacheKey, value: &T, ttl: Option<Duration>) -> bool {
        let Ok(bytes) = serde_json::to_vec(value) else {
            return false;
        };
        self.put_value_inner(key, CacheValue::new(key.kind(), key.version(), bytes), ttl).await
    }

    pub async fn put_json<T: Serialize>(&self, key: &CacheKey, value: &T, ttl: Option<Duration>) {
        let _ = self.put_json_inner(key, value, ttl).await;
    }

    async fn call_origin<T, E, F, Fut>(
        &self,
        is_origin_fault: &impl Fn(&E) -> bool,
        load: F,
    ) -> Result<T, OriginError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        self.counters.origin_loads.fetch_add(1, Ordering::Relaxed);
        let result = self
            .origin_guard
            .call(|| async {
                match load().await {
                    Ok(value) => Ok(GuardProbe::Ok(value)),
                    Err(err) if !is_origin_fault(&err) => Ok(GuardProbe::NonFaultErr(err)),
                    Err(err) => Err(err),
                }
            })
            .await;
        match result {
            Ok(GuardProbe::Ok(value)) => Ok(value),
            Ok(GuardProbe::NonFaultErr(err)) => Err(OriginError::Origin(err)),
            Err(err) => Err(err),
        }
    }

    pub async fn get_or_load_json<T, E, F, Fut>(
        &self,
        key: &CacheKey,
        ttl: Option<Duration>,
        is_origin_fault: impl Fn(&E) -> bool,
        load: F,
    ) -> Result<(T, CacheOutcome), OriginError<E>>
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let (cached, mut degraded) = self.get_json_inner::<T>(key).await;
        if let Some(value) = cached {
            return Ok((value, CacheOutcome::Hit));
        }

        let load_slot = Mutex::new(Some(load));
        let flight = self
            .singleflight
            .run(key.as_str().to_owned(), || async {
                let Some(next) = load_slot.lock().unwrap_or_else(|poison| poison.into_inner()).take() else {
                    return Ok(GuardedCompute::GuardErr(OriginError::Busy));
                };
                match self.call_origin(&is_origin_fault, next).await {
                    Ok(value) => {
                        // Populate cache before LeaderGuard drops so waiting followers observe WaitedHit.
                        let put_ok = self.put_json_inner(key, &value, ttl).await;
                        Ok(GuardedCompute::Loaded { value, put_ok })
                    }
                    Err(OriginError::Origin(err)) => Ok(GuardedCompute::CallerErr(err)),
                    Err(OriginError::Busy) => Ok(GuardedCompute::GuardErr(OriginError::Busy)),
                    Err(OriginError::Deadline) => Ok(GuardedCompute::GuardErr(OriginError::Deadline)),
                    Err(OriginError::CircuitOpen) => Ok(GuardedCompute::GuardErr(OriginError::CircuitOpen)),
                }
            })
            .await;

        match flight {
            Ok(WarmupOutcome::Computed(GuardedCompute::Loaded { value, put_ok })) => {
                let outcome =
                    if degraded || !put_ok { CacheOutcome::OriginDegraded } else { CacheOutcome::OriginRefill };
                Ok((value, outcome))
            }
            Ok(WarmupOutcome::Computed(GuardedCompute::CallerErr(err))) => Err(OriginError::Origin(err)),
            Ok(WarmupOutcome::Computed(GuardedCompute::GuardErr(OriginError::Busy))) => Err(OriginError::Busy),
            Ok(WarmupOutcome::Computed(GuardedCompute::GuardErr(OriginError::Deadline))) => Err(OriginError::Deadline),
            Ok(WarmupOutcome::Computed(GuardedCompute::GuardErr(OriginError::CircuitOpen))) => {
                Err(OriginError::CircuitOpen)
            }
            Ok(WarmupOutcome::Computed(GuardedCompute::GuardErr(OriginError::Origin(_)))) => Err(OriginError::Busy),
            Ok(WarmupOutcome::Waited) | Err(_) => {
                if matches!(flight, Ok(WarmupOutcome::Waited)) {
                    self.counters.singleflight_waits.fetch_add(1, Ordering::Relaxed);
                    let (rechecked, recheck_degraded) = self.get_json_inner::<T>(key).await;
                    degraded |= recheck_degraded;
                    if let Some(value) = rechecked {
                        return Ok((value, CacheOutcome::WaitedHit));
                    }
                } else {
                    degraded = true;
                }
                let fallback = load_slot.into_inner().unwrap_or_else(|poison| poison.into_inner());
                let Some(next) = fallback else {
                    return Err(OriginError::Busy);
                };
                let value = self.call_origin(&is_origin_fault, next).await?;
                let put_ok = self.put_json_inner(key, &value, ttl).await;
                let outcome =
                    if degraded || !put_ok { CacheOutcome::OriginDegraded } else { CacheOutcome::OriginRefill };
                Ok((value, outcome))
            }
        }
    }
}

fn normalize_backend(raw: Option<&str>) -> Result<CacheBackendKind> {
    match raw.unwrap_or("") {
        "" | "memory" => Ok(CacheBackendKind::Memory),
        "redis" => Ok(CacheBackendKind::Redis),
        _ => bail!("unsupported ROOTYARD_CACHE_BACKEND (expected 'memory' or 'redis')"),
    }
}
