//! Hardening regression tests for Issue #163 follow-up fixes:
//! canonical path containment, private `PackCacheKey` invariants, orphan restart
//! sweep, end-to-end admission permit lifetime across `ReplicaViewGuard`,
//! contended deadline enforcement, and `rr_order` deduplication.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tempfile::TempDir;
use uuid::Uuid;

use crate::blob_store::{BlobLocator, test_support::digest};

use super::*;

struct AllowOnePackAuthorizer {
    pins: DurablePinRegistry,
    history_id: Uuid,
    cluster_incarnation: Uuid,
}

impl LiveAuthorizer for AllowOnePackAuthorizer {
    fn authorize_and_check_version<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
    ) -> lease_pin::AuthTask<'a, Result<AuthoritativeSnapshot, ReplicaCacheError>> {
        Box::pin(async move {
            let loc = BlobLocator::new(req.tenant_id, req.repo_id, 1, Uuid::new_v4(), "packs", &digest(b"p"), 1)?;
            let idx = BlobLocator::new(req.tenant_id, req.repo_id, 1, Uuid::new_v4(), "packs", &digest(b"i"), 1)?;
            Ok(AuthoritativeSnapshot {
                tenant_id: req.tenant_id,
                repo_id: req.repo_id,
                history_id: self.history_id,
                cluster_incarnation: self.cluster_incarnation,
                object_format: ReplicaObjectFormat::Sha1,
                authority_epoch: 1,
                gate_revision: 1,
                version_check: VersionCheckVerdict::Changed,
                head_ref: "refs/heads/main".into(),
                refs: vec![ReplicaRefSpec::new("refs/heads/main", "a".repeat(40))],
                packs: vec![PackObjectSpec::provider_managed(format!("pack-{}", "b".repeat(40)), loc, idx)],
                durable_pin: self.pins.acquire(req.tenant_id, req.repo_id, 1),
            })
        })
    }
}

struct DummyViewSlot {
    key: ReplicaViewKey,
    path: PathBuf,
    released: AtomicBool,
}

impl ActiveViewSlot for DummyViewSlot {
    fn view_key(&self) -> &ReplicaViewKey {
        &self.key
    }
    fn repo_path(&self) -> Result<&Path, ReplicaCacheError> {
        Ok(&self.path)
    }
    fn ensure_live(&self) -> Result<(), ReplicaCacheError> {
        Ok(())
    }
    fn release_reader(&self) {
        self.released.store(true, Ordering::SeqCst);
    }
}

struct DummyReplicaBackend {
    id: String,
    view_dir: PathBuf,
}

impl ReplicaBackend for DummyReplicaBackend {
    fn node_id(&self) -> &str {
        &self.id
    }
    fn serve_replica_view<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
        authorizer: &'a dyn LiveAuthorizer,
        _deadline: Instant,
    ) -> lease_pin::AuthTask<'a, Result<ReplicaViewGuard, ReplicaCacheError>> {
        Box::pin(async move {
            let snap = authorizer.authorize_and_check_version(req).await?;
            let key = ReplicaViewKey::from_snapshot(&snap, &"0".repeat(64))?;
            let slot = Arc::new(DummyViewSlot { key, path: self.view_dir.clone(), released: AtomicBool::new(false) });
            Ok(ReplicaViewGuard::new(
                self.id.clone(),
                slot,
                snap.durable_pin,
                ReplicaServeSource::MaterializedFromBlob,
                ReplicaRequestMetrics::default(),
                true,
            ))
        })
    }
    fn is_accepting_traffic(&self) -> bool {
        true
    }
}

#[test]
fn pack_cache_key_and_canonical_containment_block_traversal_and_symlinks() {
    let t = Uuid::new_v4();
    let r = Uuid::new_v4();
    let loc = BlobLocator::new(t, r, 1, Uuid::new_v4(), "packs", &digest(b"p"), 1).unwrap();
    let idx = BlobLocator::new(t, r, 1, Uuid::new_v4(), "packs", &digest(b"i"), 1).unwrap();

    for bad_stem in ["../escape", "pack-../escape", "pack-../../outside", "pack-bad\\slash"] {
        let spec = PackObjectSpec::provider_managed(bad_stem, loc.clone(), idx.clone());
        assert!(matches!(
            spec.pack_cache_key(&"0".repeat(64), ReplicaObjectFormat::Sha1),
            Err(ReplicaCacheError::InvalidInput(_))
        ));
    }

    let good_spec = PackObjectSpec::provider_managed(format!("pack-{}", "a".repeat(40)), loc, idx);
    assert!(matches!(
        good_spec.pack_cache_key("not-hex", ReplicaObjectFormat::Sha1),
        Err(ReplicaCacheError::InvalidInput(_))
    ));
    let good_key = good_spec.pack_cache_key(&"1".repeat(64), ReplicaObjectFormat::Sha1).unwrap();
    assert!(good_key.validate().is_ok());

    let dir = TempDir::new().unwrap();
    let root = dir.path().join("packs");
    pack_cache::ensure_private_dir(&root).unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();

    assert!(matches!(
        error::validate_canonical_child_path(&root, &root),
        Err(ReplicaCacheError::TenantIsolationViolation(_))
    ));
    assert!(matches!(
        error::validate_canonical_child_path(&root, &root.join("../outside")),
        Err(ReplicaCacheError::TenantIsolationViolation(_))
    ));

    let link_path = root.join("sym-escape");
    std::os::unix::fs::symlink(&outside, &link_path).unwrap();
    assert!(matches!(
        error::validate_canonical_child_path(&root, &link_path),
        Err(ReplicaCacheError::IntegrityFailed(_))
    ));
}

#[test]
fn pack_cache_open_sweeps_orphan_dirs_and_symlinks_on_restart() {
    let dir = TempDir::new().unwrap();
    let replica = dir.path().join("replica");
    let packs_root = replica.join("packs");
    pack_cache::ensure_private_dir(&replica).unwrap();
    pack_cache::ensure_private_dir(&packs_root).unwrap();

    let outside = dir.path().join("external-target");
    std::fs::create_dir(&outside).unwrap();
    let outside_marker = outside.join("keep.txt");
    std::fs::write(&outside_marker, b"preserve").unwrap();

    let orphan_dir = packs_root.join("orphan-entry");
    std::fs::create_dir(&orphan_dir).unwrap();
    std::fs::write(orphan_dir.join("stale.pack"), b"stale").unwrap();
    let abandoned_stage = packs_root.join(".stage-abandoned");
    std::fs::create_dir(&abandoned_stage).unwrap();
    let orphan_link = packs_root.join("orphan-link");
    std::os::unix::fs::symlink(&outside, &orphan_link).unwrap();

    let catalog = PackCacheCatalog::open(&replica, ReplicaCacheLimits::default()).unwrap();
    catalog.retire_key("../traversal");
    assert_eq!(catalog.entry_count(), 0);
    assert_eq!(catalog.total_bytes(), 0);
    assert!(!orphan_dir.exists());
    assert!(!abandoned_stage.exists());
    assert!(!orphan_link.exists());
    assert!(outside_marker.is_file());
}

#[tokio::test]
async fn scheduler_holds_fair_admission_permit_until_view_guard_drops() {
    let dir = TempDir::new().unwrap();
    let backend = Arc::new(DummyReplicaBackend { id: "node-1".into(), view_dir: dir.path().to_path_buf() });
    let fair_cfg = TenantFairShareConfig {
        max_total_inflight: 2,
        max_per_tenant_inflight: 1,
        max_waiters_per_tenant: 2,
        max_total_waiters: 4,
        admission_timeout: Duration::from_millis(60),
    };
    let scheduler = ReplicaScheduler::new(vec![backend], fair_cfg, None, "test", Duration::from_secs(5)).unwrap();

    let (t1, t2) = (Uuid::new_v4(), Uuid::new_v4());
    let (r1, r2) = (Uuid::new_v4(), Uuid::new_v4());
    let auth1 = AllowOnePackAuthorizer {
        pins: DurablePinRegistry::new(),
        history_id: Uuid::new_v4(),
        cluster_incarnation: Uuid::new_v4(),
    };
    let req1 = ReplicaReadRequest {
        tenant_id: t1,
        repo_id: r1,
        actor_id: "alice".into(),
        operation: ReplicaOperation::GitUploadPack,
        expected_backend_identity: None,
        session_lower_bound: None,
        known_membership_digest: None,
    };

    let outcome1 = scheduler.route_and_serve(&req1, &auth1, Instant::now() + Duration::from_secs(5)).await.unwrap();
    assert_eq!(scheduler.fairness_stats().active_inflight, 1);

    // Same tenant must be capped by `max_per_tenant_inflight == 1` while `outcome1.guard` is held.
    let err = match scheduler.route_and_serve(&req1, &auth1, Instant::now() + Duration::from_secs(5)).await {
        Ok(_) => panic!("expected QueueFull while tenant t1 holds view guard"),
        Err(e) => e,
    };
    assert!(matches!(err, ReplicaCacheError::QueueFull(_)));

    // Different tenant still fits under `max_total_inflight == 2`.
    let auth2 = AllowOnePackAuthorizer {
        pins: DurablePinRegistry::new(),
        history_id: Uuid::new_v4(),
        cluster_incarnation: Uuid::new_v4(),
    };
    let req2 = ReplicaReadRequest { tenant_id: t2, repo_id: r2, ..req1.clone() };
    let outcome2 = scheduler.route_and_serve(&req2, &auth2, Instant::now() + Duration::from_secs(5)).await.unwrap();
    assert_eq!(scheduler.fairness_stats().active_inflight, 2);

    drop(outcome1);
    drop(outcome2);
    assert_eq!(scheduler.fairness_stats().active_inflight, 0);
    let _outcome3 = scheduler.route_and_serve(&req1, &auth1, Instant::now() + Duration::from_secs(5)).await.unwrap();
}

#[tokio::test]
async fn fair_admission_contended_deadline_and_rr_order_deduplication() {
    let cfg = TenantFairShareConfig {
        max_total_inflight: 1,
        max_per_tenant_inflight: 1,
        max_waiters_per_tenant: 4,
        max_total_waiters: 8,
        admission_timeout: Duration::from_secs(5),
    };
    let gate = Arc::new(TenantFairShareGate::new(cfg).unwrap());
    let holder = Uuid::new_v4();
    let churner = Uuid::new_v4();
    let long_dl = Instant::now() + Duration::from_secs(10);
    let (_held, _) = gate.acquire(holder, long_dl).await.unwrap();

    // Multiple waiters for the same tenant must place only 1 token in `rr_order`,
    // and cancelling all waiters removes that tenant from `rr_order` cleanly.
    for _ in 0..3 {
        let g1 = Arc::clone(&gate);
        let g2 = Arc::clone(&gate);
        let h1 = tokio::spawn(async move { g1.acquire(churner, long_dl).await });
        let h2 = tokio::spawn(async move { g2.acquire(churner, long_dl).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(gate.rr_order_snapshot().iter().filter(|id| **id == churner).count(), 1);
        h1.abort();
        h2.abort();
        let _ = (h1.await, h2.await);
        assert_eq!(gate.rr_order_snapshot().iter().filter(|id| **id == churner).count(), 0);
    }

    // Tight caller deadline expires with `DeadlineExceeded` rather than masquerading as `QueueFull`.
    let tight_dl = Instant::now() + Duration::from_millis(15);
    assert!(matches!(gate.acquire(churner, tight_dl).await, Err(ReplicaCacheError::DeadlineExceeded)));
    assert_eq!(gate.stats().queued_waiters, 0);
    assert_eq!(gate.rr_order_snapshot().len(), 0);
}
