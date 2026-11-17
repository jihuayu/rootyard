//! Unit tests for Issue #163 version-aware disposable replica cache,
//! singleflight bounds, active pin/hold preservation, #174 fence, and fair scheduling.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    blob_store::{
        BlobLocator,
        budget::ResourceLimits,
        test_support::{blob_backend_identity, digest, store},
    },
    cache_wake::{AdvisoryCache, CacheBackendKind, CacheKey, CacheLimits, CacheTask, CacheValue, ServingCache},
};

use super::*;

fn sample_locator(tenant: Uuid, repo: Uuid, bytes: &[u8]) -> BlobLocator {
    BlobLocator::new(tenant, repo, 1, Uuid::new_v4(), "packs", &digest(bytes), bytes.len() as u64).unwrap()
}

fn sample_pack(tenant: Uuid, repo: Uuid, stem_hex: &str, pack_bytes: &[u8], idx_bytes: &[u8]) -> PackObjectSpec {
    PackObjectSpec::provider_managed(
        format!("pack-{stem_hex}"),
        sample_locator(tenant, repo, pack_bytes),
        sample_locator(tenant, repo, idx_bytes),
    )
}

#[test]
fn keys_and_route_hints_isolate_tenants_histories_backends_and_reject_unknown_fields() {
    let t1 = Uuid::new_v4();
    let t2 = Uuid::new_v4();
    let r1 = Uuid::new_v4();
    let h1 = Uuid::new_v4();
    let h2 = Uuid::new_v4();
    let c1 = Uuid::new_v4();
    let b1 = blob_backend_identity("backend-a");
    let b2 = blob_backend_identity("backend-b");
    let stem = "a".repeat(40);
    let commit_oid = "b".repeat(40);
    let p1 = vec![sample_pack(t1, r1, &stem, b"pack-1", b"idx-1")];
    let p2 = vec![sample_pack(t2, r1, &stem, b"pack-1", b"idx-1")];
    let refs = vec![ReplicaRefSpec::new("refs/heads/main", &commit_oid)];

    let k_base =
        ReplicaViewKey::build(t1, r1, h1, c1, &b1, ReplicaObjectFormat::Sha1, 1, 10, &p1, &refs, "refs/heads/main")
            .unwrap();
    let k_t2 =
        ReplicaViewKey::build(t2, r1, h1, c1, &b1, ReplicaObjectFormat::Sha1, 1, 10, &p2, &refs, "refs/heads/main")
            .unwrap();
    let k_h2 =
        ReplicaViewKey::build(t1, r1, h2, c1, &b1, ReplicaObjectFormat::Sha1, 1, 10, &p1, &refs, "refs/heads/main")
            .unwrap();
    let k_b2 =
        ReplicaViewKey::build(t1, r1, h1, c1, &b2, ReplicaObjectFormat::Sha1, 1, 10, &p1, &refs, "refs/heads/main")
            .unwrap();
    let k_rev =
        ReplicaViewKey::build(t1, r1, h1, c1, &b1, ReplicaObjectFormat::Sha1, 1, 11, &p1, &refs, "refs/heads/main")
            .unwrap();
    let refs_moved = vec![ReplicaRefSpec::new("refs/heads/main", "c".repeat(40))];
    let k_ref_only = ReplicaViewKey::build(
        t1,
        r1,
        h1,
        c1,
        &b1,
        ReplicaObjectFormat::Sha1,
        1,
        10,
        &p1,
        &refs_moved,
        "refs/heads/main",
    )
    .unwrap();

    assert_ne!(k_base.view_key_hex, k_t2.view_key_hex);
    assert_ne!(k_base.view_key_hex, k_h2.view_key_hex);
    assert_ne!(k_base.view_key_hex, k_b2.view_key_hex);
    assert_ne!(k_base.view_key_hex, k_rev.view_key_hex);
    assert_ne!(k_base.view_key_hex, k_ref_only.view_key_hex);
    assert_eq!(k_base.pack_membership_digest, k_ref_only.pack_membership_digest);
    assert_ne!(
        p1[0].pack_cache_key(b1.as_hex(), ReplicaObjectFormat::Sha1),
        p2[0].pack_cache_key(b1.as_hex(), ReplicaObjectFormat::Sha1)
    );
    assert_ne!(
        p1[0].pack_cache_key(b1.as_hex(), ReplicaObjectFormat::Sha1),
        p1[0].pack_cache_key(b2.as_hex(), ReplicaObjectFormat::Sha1)
    );

    assert!(serde_json::from_slice::<RouteDirectoryHint>(br#"{"schema_version":1,"node_id":"n1","extra":1}"#).is_err());
}

#[test]
fn session_lower_bound_enforces_174_monotonicity_and_realm_fence() {
    let pins = DurablePinRegistry::new();
    let t = Uuid::new_v4();
    let r = Uuid::new_v4();
    let h = Uuid::new_v4();
    let c = Uuid::new_v4();
    let snap = AuthoritativeSnapshot {
        tenant_id: t,
        repo_id: r,
        history_id: h,
        cluster_incarnation: c,
        object_format: ReplicaObjectFormat::Sha1,
        authority_epoch: 3,
        gate_revision: 42,
        version_check: VersionCheckVerdict::Changed,
        head_ref: "refs/heads/main".into(),
        refs: vec![ReplicaRefSpec::new("refs/heads/main", "a".repeat(40))],
        packs: vec![sample_pack(t, r, &"b".repeat(40), b"p", b"i")],
        durable_pin: pins.acquire(t, r, 42),
    };

    let ok_bound = SessionLowerBound {
        tenant_id: t,
        repo_id: r,
        history_id: h,
        cluster_incarnation: c,
        authority_epoch: 3,
        min_gate_revision: 42,
    };
    assert!(verify_session_lower_bound(Some(&ok_bound), &snap).is_ok());

    let behind = SessionLowerBound { min_gate_revision: 43, ..ok_bound.clone() };
    assert!(matches!(
        verify_session_lower_bound(Some(&behind), &snap),
        Err(ReplicaCacheError::BehindSessionLowerBound { required: 43, observed: 42 })
    ));

    let rotated_cluster = SessionLowerBound { cluster_incarnation: Uuid::new_v4(), ..ok_bound.clone() };
    assert!(matches!(
        verify_session_lower_bound(Some(&rotated_cluster), &snap),
        Err(ReplicaCacheError::SessionRealmMismatch(_))
    ));

    let wrong_epoch = SessionLowerBound { authority_epoch: 4, ..ok_bound };
    assert!(matches!(
        verify_session_lower_bound(Some(&wrong_epoch), &snap),
        Err(ReplicaCacheError::SessionRealmMismatch(_))
    ));
}

#[tokio::test]
async fn singleflight_bounds_waiters_and_handles_leader_and_waiter_cancellation() {
    let limits = ReplicaCacheLimits {
        max_inflight_builds: 2,
        max_waiters_per_key: 2,
        max_total_waiters: 4,
        waiter_timeout: Duration::from_secs(2),
        ..ReplicaCacheLimits::default()
    };
    let sf = Arc::new(BoundedSingleFlight::new(limits).unwrap());
    let (t, r, h, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let b = blob_backend_identity("sf-test");
    let key = ReplicaViewKey::build(
        t,
        r,
        h,
        c,
        &b,
        ReplicaObjectFormat::Sha1,
        1,
        5,
        &[sample_pack(t, r, &"1".repeat(40), b"pk", b"ix")],
        &[ReplicaRefSpec::new("refs/heads/main", "2".repeat(40))],
        "refs/heads/main",
    )
    .unwrap();

    let leader = match sf.enter(&key).unwrap() {
        FlightEntry::Leader(l) => l,
        FlightEntry::Waiter(_) => panic!("first caller must lead"),
    };
    let w1 = match sf.enter(&key).unwrap() {
        FlightEntry::Waiter(w) => w,
        FlightEntry::Leader(_) => panic!("second caller must wait"),
    };
    let w2 = match sf.enter(&key).unwrap() {
        FlightEntry::Waiter(w) => w,
        FlightEntry::Leader(_) => panic!("third caller must wait"),
    };
    assert!(matches!(sf.enter(&key), Err(ReplicaCacheError::QueueFull(_))));
    assert_eq!(sf.total_waiters(), 2);

    // Cancel w2 while waiting: slot immediately returns to queue capacity.
    drop(w2);
    assert_eq!(sf.total_waiters(), 1);
    let w3 = match sf.enter(&key).unwrap() {
        FlightEntry::Waiter(w) => w,
        FlightEntry::Leader(_) => panic!("slot freed after waiter drop"),
    };

    // Abort/drop leader without completing: all waiters wake cleanly.
    drop(leader);
    let dl = Instant::now() + Duration::from_secs(2);
    let (o1, _) = w1.wait_for_outcome(Duration::from_secs(1), dl).await.unwrap();
    let (o3, _) = w3.wait_for_outcome(Duration::from_secs(1), dl).await.unwrap();
    assert!(matches!(o1, FlightOutcome::LeaderCancelled));
    assert!(matches!(o3, FlightOutcome::LeaderCancelled));
    assert_eq!(sf.inflight_keys(), 0);
    assert_eq!(sf.total_waiters(), 0);
}

#[tokio::test]
async fn tenant_fair_share_prevents_noisy_tenant_from_starving_normal_tenant() {
    let gate = Arc::new(
        TenantFairShareGate::new(TenantFairShareConfig {
            max_total_inflight: 4,
            max_per_tenant_inflight: 2,
            max_waiters_per_tenant: 8,
            max_total_waiters: 16,
            admission_timeout: Duration::from_secs(3),
        })
        .unwrap(),
    );
    let noisy = Uuid::new_v4();
    let normal = Uuid::new_v4();
    let dl = Instant::now() + Duration::from_secs(5);

    // Noisy tenant grabs max_per_tenant_inflight (2) active slots and queues 4 more.
    let (p1, _) = gate.acquire(noisy, dl).await.unwrap();
    let (p2, _) = gate.acquire(noisy, dl).await.unwrap();
    let mut noisy_tasks = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let g = Arc::clone(&gate);
        noisy_tasks.spawn(async move {
            let (_p, _) = g.acquire(noisy, dl).await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(15)).await;

    // Normal tenant arrives and must NOT wait behind noisy tenant's blocked queue!
    let (pn, wait_us) = gate.acquire(normal, dl).await.unwrap();
    assert!(wait_us < 200_000, "normal tenant waited unexpectedly: {wait_us}us");
    drop(pn);
    drop(p1);
    drop(p2);
    while let Some(res) = noisy_tasks.join_next().await {
        res.unwrap();
    }
    let stats = gate.stats();
    assert_eq!(stats.per_tenant_admitted.get(&noisy).copied().unwrap_or(0), 6);
    assert_eq!(stats.per_tenant_admitted.get(&normal).copied().unwrap_or(0), 1);
}

struct MockAuth {
    pins: DurablePinRegistry,
    snapshot: std::sync::Mutex<AuthoritativeSnapshot>,
    allow: AtomicBool,
}

impl LiveAuthorizer for MockAuth {
    fn authorize_and_check_version<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
    ) -> lease_pin::AuthTask<'a, Result<AuthoritativeSnapshot, ReplicaCacheError>> {
        Box::pin(async move {
            if !self.allow.load(Ordering::SeqCst) {
                return Err(ReplicaCacheError::Unauthorized("revoked"));
            }
            let mut snap = self.snapshot.lock().unwrap().clone();
            snap.durable_pin = self.pins.acquire(req.tenant_id, req.repo_id, snap.gate_revision);
            Ok(snap)
        })
    }
}

struct OutageAdvisoryCache;
impl AdvisoryCache for OutageAdvisoryCache {
    fn get<'a>(&'a self, _key: &'a CacheKey) -> CacheTask<'a, anyhow::Result<Option<CacheValue>>> {
        Box::pin(async { anyhow::bail!("simulated redis outage") })
    }
    fn put<'a>(
        &'a self,
        _key: &'a CacheKey,
        _value: CacheValue,
        _ttl: Option<Duration>,
    ) -> CacheTask<'a, anyhow::Result<()>> {
        Box::pin(async { anyhow::bail!("simulated redis outage") })
    }
    fn delete<'a>(&'a self, _key: &'a CacheKey) -> CacheTask<'a, anyhow::Result<()>> {
        Box::pin(async { anyhow::bail!("simulated redis outage") })
    }
}

struct MockNodeBackend {
    id: String,
    fail_with: std::sync::Mutex<Option<ReplicaCacheError>>,
    delegate: Arc<ReplicaCacheNode>,
    calls: AtomicUsize,
}

impl ReplicaBackend for MockNodeBackend {
    fn node_id(&self) -> &str {
        &self.id
    }

    fn serve_replica_view<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
        authorizer: &'a dyn LiveAuthorizer,
        deadline: Instant,
    ) -> lease_pin::AuthTask<'a, Result<ReplicaViewGuard, ReplicaCacheError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if let Some(err) = self.fail_with.lock().unwrap().take() {
                return Err(err);
            }
            self.delegate.serve_view(req, authorizer, deadline).await
        })
    }

    fn is_accepting_traffic(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn scheduler_tolerates_advisory_outage_and_fails_over_on_overload_or_drain() {
    let tmp = TempDir::new().unwrap();
    let (blob_store, _) = store(ResourceLimits::new(2, 2, 1 << 20).unwrap());
    let n1 = Arc::new(
        ReplicaCacheNode::open(
            "node-1",
            &tmp.path().join("r1"),
            blob_store.clone(),
            None,
            ReplicaCacheLimits::default(),
        )
        .unwrap(),
    );
    let n2 = Arc::new(
        ReplicaCacheNode::open("node-2", &tmp.path().join("r2"), blob_store, None, ReplicaCacheLimits::default())
            .unwrap(),
    );

    let route_dir = Arc::new(
        ServingCache::with_advisory_cache(
            CacheBackendKind::Redis,
            Arc::new(OutageAdvisoryCache),
            CacheLimits::default(),
        )
        .unwrap(),
    );
    let b1 = Arc::new(MockNodeBackend {
        id: "node-1".into(),
        fail_with: std::sync::Mutex::new(Some(ReplicaCacheError::QueueFull("saturated"))),
        delegate: n1,
        calls: AtomicUsize::new(0),
    });
    let b2 = Arc::new(MockNodeBackend {
        id: "node-2".into(),
        fail_with: std::sync::Mutex::new(Some(ReplicaCacheError::QueueFull("saturated"))),
        delegate: n2,
        calls: AtomicUsize::new(0),
    });

    let scheduler = ReplicaScheduler::new(
        vec![b1.clone(), b2.clone()],
        TenantFairShareConfig::default(),
        Some(route_dir),
        "test",
        Duration::from_secs(5),
    )
    .unwrap();

    let (t, r, h, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let pins = DurablePinRegistry::new();
    let auth = MockAuth {
        pins,
        snapshot: std::sync::Mutex::new(AuthoritativeSnapshot {
            tenant_id: t,
            repo_id: r,
            history_id: h,
            cluster_incarnation: c,
            object_format: ReplicaObjectFormat::Sha1,
            authority_epoch: 1,
            gate_revision: 1,
            version_check: VersionCheckVerdict::Changed,
            head_ref: "refs/heads/main".into(),
            refs: vec![ReplicaRefSpec::new("refs/heads/main", "a".repeat(40))],
            packs: vec![sample_pack(t, r, &"b".repeat(40), b"p", b"i")],
            durable_pin: DurablePinRegistry::new().acquire(t, r, 1),
        }),
        allow: AtomicBool::new(true),
    };
    let req = ReplicaReadRequest {
        tenant_id: t,
        repo_id: r,
        actor_id: "alice".into(),
        operation: ReplicaOperation::GitUploadPack,
        expected_backend_identity: None,
        session_lower_bound: None,
        known_membership_digest: None,
    };

    // Both nodes return QueueFull -> scheduler returns AllReplicasOverloaded cleanly.
    let err = match scheduler.route_and_serve(&req, &auth, Instant::now() + Duration::from_secs(2)).await {
        Ok(_) => panic!("expected AllReplicasOverloaded"),
        Err(e) => e,
    };
    assert!(matches!(err, ReplicaCacheError::AllReplicasOverloaded));
    assert_eq!(b1.calls.load(Ordering::SeqCst), 1);
    assert_eq!(b2.calls.load(Ordering::SeqCst), 1);

    // Drain primary and make secondary fail with Unauthorized -> auth errors never fail over.
    let order = scheduler.affinity_order(t, r);
    assert_eq!(order.len(), 2);
    assert!(scheduler.begin_drain(&order[0]));
    let order_after_drain = scheduler.affinity_order(t, r);
    assert_eq!(order_after_drain, vec![order[1].clone()]);

    auth.allow.store(false, Ordering::SeqCst);
    let auth_err = match scheduler.route_and_serve(&req, &auth, Instant::now() + Duration::from_secs(2)).await {
        Ok(_) => panic!("expected Unauthorized"),
        Err(e) => e,
    };
    assert!(matches!(auth_err, ReplicaCacheError::Unauthorized(_)));
}
