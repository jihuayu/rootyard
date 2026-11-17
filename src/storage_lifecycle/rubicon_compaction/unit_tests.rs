//! Unit tests for Rubicon Blob compaction contracts, sharding, segments, leases, and budgets (#162).

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{
    BlobLocator,
    read_accel::{AuthoritativeRef, ReadAccelObjectFormat},
};

use super::{
    CompactionAuthoritativeSnapshot, CompactionAuthorityStore, CompactionBudgetConfig, CompactionByteAccounting,
    CompactionEquivalenceProof, CompactionError, CompactionLeaseKey, CompactionLeaseToken, CompactionPackEntry,
    CompactionPublishReceipt, CompactionPublishRequest, CompactionRef, CompactionResourceBudget, CompactionSegmentLog,
    CompactionShardRouter, DurableCompactionStore, PackSegment, PendingOperationRecord, SegmentState, SegmentTier,
    SegmentTriggerPolicy, TieredMergePlan, shard_for_pack_hash,
};

fn dummy_pack_on_shard(
    tenant: Uuid,
    repo: Uuid,
    seed: u8,
    bytes: u64,
    joined_gen: u64,
    target_shard: u16,
    shard_count: u16,
) -> CompactionPackEntry {
    for salt in 0u16..=u16::MAX {
        let p_sha = hex::encode(Sha256::digest([seed, (salt & 0xff) as u8, (salt >> 8) as u8]));
        if shard_for_pack_hash(&p_sha, shard_count).unwrap() == target_shard {
            let i_sha = hex::encode(Sha256::digest([seed, 0xaa, (salt & 0xff) as u8]));
            let p_loc = BlobLocator::new(tenant, repo, 1, Uuid::new_v4(), "packs", &p_sha, bytes).unwrap();
            let i_loc = BlobLocator::new(tenant, repo, 1, Uuid::new_v4(), "packs", &i_sha, 512).unwrap();
            let stem = format!("pack-{}", hex::encode([seed; 20]));
            return CompactionPackEntry::from_locators(Uuid::new_v4(), stem, &p_loc, &i_loc, joined_gen, shard_count)
                .unwrap();
        }
    }
    unreachable!("shard hash search failed")
}

fn dummy_pack(tenant: Uuid, repo: Uuid, seed: u8, bytes: u64, shard_count: u16) -> CompactionPackEntry {
    dummy_pack_on_shard(tenant, repo, seed, bytes, 1, 0, shard_count)
}

#[test]
fn serde_structs_reject_unknown_fields_and_validate_invariants() {
    assert!(serde_json::from_slice::<CompactionRef>(br#"{"name":"refs/heads/main","oid":"a","extra":1}"#).is_err());
    assert!(serde_json::from_slice::<CompactionPackEntry>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<PackSegment>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<SegmentTriggerPolicy>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<TieredMergePlan>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<CompactionByteAccounting>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<CompactionSegmentLog>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<CompactionLeaseKey>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<CompactionLeaseToken>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<PendingOperationRecord>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<CompactionEquivalenceProof>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<CompactionAuthoritativeSnapshot>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<CompactionPublishRequest>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<CompactionPublishReceipt>(br#"{"extra":true}"#).is_err());
    assert!(serde_json::from_slice::<CompactionShardRouter>(br#"{"shard_count":8,"extra":true}"#).is_err());

    let policy = SegmentTriggerPolicy { delete_old_packs: true, ..SegmentTriggerPolicy::default() };
    assert!(matches!(policy.validate(), Err(CompactionError::DeleteForbidden)));

    let zero_age = SegmentTriggerPolicy { max_segment_age_ms: 0, ..SegmentTriggerPolicy::default() };
    assert!(matches!(zero_age.validate(), Err(CompactionError::InvalidInput(_))));
}

#[test]
fn pack_hash_sharding_is_deterministic_and_worker_assignments_are_disjoint() {
    let router = CompactionShardRouter::new(8).unwrap();
    let digest = hex::encode(Sha256::digest(b"sample-pack-hash"));
    let s1 = shard_for_pack_hash(&digest, 8).unwrap();
    let s2 = router.route_pack(&digest).unwrap();
    assert_eq!(s1, s2);
    assert!(s1 < 8);

    let w0 = router.worker_shards(0, 3).unwrap();
    let w1 = router.worker_shards(1, 3).unwrap();
    let w2 = router.worker_shards(2, 3).unwrap();
    let mut combined = [w0, w1, w2].concat();
    combined.sort_unstable();
    assert_eq!(combined, vec![0, 1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn open_sealed_age_count_bytes_and_tier_isolated_planning() {
    let (tenant, repo) = (Uuid::new_v4(), Uuid::new_v4());
    let policy = SegmentTriggerPolicy {
        max_segment_packs: 2,
        max_segment_bytes: 50_000,
        max_segment_age_ms: 5_000,
        max_packs_per_batch: 4,
        max_rewrite_bytes_per_run: 200_000,
        min_sealed_segments_to_merge: 2,
        delete_old_packs: false,
    };

    let mut log = CompactionSegmentLog::new();
    let p1 = dummy_pack(tenant, repo, 1, 2_000, 1);
    let out1 = log.ingest_pack(p1, 1_000, &policy).unwrap();
    assert!(out1.sealed_segment_id.is_none());
    assert_eq!(log.open_pack_count(0), 1);

    // Age trigger seals the open segment on `seal_aged_segments` without blocking new ingest.
    let aged = log.seal_aged_segments(6_500, &policy).unwrap();
    assert_eq!(aged.len(), 1);
    assert_eq!(log.open_pack_count(0), 0);
    assert_eq!(log.sealed_segment_count(0), 1);

    // Single 1-pack sealed L0 does not compact yet (min_sealed_segments_to_merge = 2).
    assert!(log.plan_tiered_merge(0, &policy).unwrap().is_none());

    // Simulate an existing large L2Base segment; adding a 2nd small L0 must merge ONLY L0 -> L1.
    let large_l2 = dummy_pack(tenant, repo, 2, 80_000, 1);
    let l2_id = Uuid::new_v4();
    log.segments.insert(
        l2_id,
        PackSegment {
            segment_id: l2_id,
            shard_id: 0,
            tier: SegmentTier::L2Base,
            state: SegmentState::Sealed,
            created_at_ms: 500,
            sealed_at_ms: Some(500),
            packs: vec![large_l2],
            total_pair_bytes: 80_512,
        },
    );
    log.segment_order.push(l2_id);

    // Ingest 2nd small L0 pack that auto-seals via age when a 3rd arrives at t=12_000.
    let p3 = dummy_pack(tenant, repo, 3, 2_000, 1);
    log.ingest_pack(p3, 6_600, &policy).unwrap();
    let p4 = dummy_pack(tenant, repo, 4, 2_000, 1);
    let out4 = log.ingest_pack(p4, 12_000, &policy).unwrap();
    assert!(out4.sealed_segment_id.is_some());
    assert_eq!(log.open_pack_count(0), 1);

    let plan = log.plan_tiered_merge(0, &policy).unwrap().expect("L0 merge plan");
    assert_eq!(plan.source_tier, SegmentTier::L0Ingest);
    assert_eq!(plan.target_tier, SegmentTier::L1Merged);
    assert_eq!(plan.input_packs.len(), 2);
    assert!(!plan.input_segment_ids.contains(&l2_id), "small L0 merge must not rewrite large L2Base pack");
}

#[tokio::test]
async fn budget_enforces_batch_scratch_and_concurrency_bounds() {
    let budget = CompactionResourceBudget::new(CompactionBudgetConfig {
        max_concurrent_jobs: 2,
        max_concurrent_git_processes: 1,
        max_scratch_bytes: 4096,
        max_rewrite_bytes_per_run: 1024,
        max_packs_per_batch: 3,
    })
    .unwrap();
    let dl = Instant::now() + Duration::from_secs(5);

    assert!(matches!(budget.reserve_job(4, 512, 1024, dl).await, Err(CompactionError::BudgetExceeded(_))));
    assert!(matches!(budget.reserve_job(2, 2048, 1024, dl).await, Err(CompactionError::BudgetExceeded(_))));

    let j1 = budget.reserve_job(2, 512, 3000, dl).await.unwrap();
    assert!(matches!(budget.reserve_job(2, 512, 2000, dl).await, Err(CompactionError::BudgetExceeded(_))));
    assert_eq!(budget.metrics().active_jobs, 1);
    drop(j1);
    assert_eq!(budget.metrics().active_jobs, 0);
    assert_eq!(budget.metrics().reserved_scratch_bytes, 0);
}

#[tokio::test]
async fn durable_store_rejects_bad_proof_and_atomic_rollback_preserves_state() {
    let store = DurableCompactionStore::in_memory();
    let (tenant, repo, history) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let policy = SegmentTriggerPolicy { max_segment_packs: 2, ..SegmentTriggerPolicy::default() };
    let p1 = dummy_pack(tenant, repo, 10, 2000, 1);
    let p2 = dummy_pack(tenant, repo, 11, 2000, 1);
    let mut p3 = dummy_pack(tenant, repo, 12, 2000, 1);
    p3.joined_generation = 2;
    let refs = vec![AuthoritativeRef::new("refs/heads/main", "a".repeat(40))];
    let snap = store
        .seed_repository(tenant, repo, history, 1, "sha1", 1, vec![p1.clone(), p2.clone()], refs, vec![], 100, &policy)
        .unwrap();

    let key = CompactionLeaseKey { tenant_id: tenant, repo_id: repo, history_id: history, shard_id: 0 };
    let tok = store.acquire_or_renew_lease(&key, "w1", 100, 30_000).await.unwrap();
    let plan = snap.segments.plan_tiered_merge(0, &policy).unwrap().unwrap();
    let bad_proof = CompactionEquivalenceProof {
        object_format: ReadAccelObjectFormat::Sha1,
        total_object_count: 1,
        shard_input_object_count: 1,
        compacted_output_object_count: 1,
        delta_objects_self_contained: 0,
        delta_bases_verified: false,
        oid_set_digest: "abc".into(),
        closure_digest: "def".into(),
        retention_roots_verified: 0,
        refs_digest: snap.refs_digest.clone(),
        fsck_verified: true,
        clone_verified: false,
    };
    let req = CompactionPublishRequest {
        op_id: Uuid::new_v4(),
        tenant_id: tenant,
        repo_id: repo,
        history_id: history,
        authority_epoch: 1,
        shard_id: 0,
        lease_id: tok.lease_id,
        fence_epoch: tok.fence_epoch,
        expected_membership_generation: 1,
        expected_pack_set_digest: snap.pack_set_digest.clone(),
        expected_refs_digest: snap.refs_digest.clone(),
        expected_retention_roots_digest: snap.retention_roots_digest.clone(),
        retired_pack_ids: vec![p1.pack_id, p2.pack_id],
        replacement_pack: p3,
        merge_plan: plan,
        equivalence_proof_digest: bad_proof.canonical_digest(),
        equivalence_proof: bad_proof,
        delete_disabled: true,
    };
    let err = store.cas_publish_compaction(&req, 110, false).await.unwrap_err();
    assert!(matches!(err, CompactionError::EquivalenceFailed(_)));
    let after = store.load_snapshot(tenant, repo, history).await.unwrap();
    assert_eq!(after.membership_generation, 1);
    assert_eq!(after.serving_packs.len(), 2);
}

fn make_valid_publish_req(
    snap: &CompactionAuthoritativeSnapshot,
    tok: &CompactionLeaseToken,
    plan: TieredMergePlan,
    replacement: CompactionPackEntry,
) -> CompactionPublishRequest {
    let proof = CompactionEquivalenceProof {
        object_format: ReadAccelObjectFormat::Sha1,
        total_object_count: 4,
        shard_input_object_count: 2,
        compacted_output_object_count: 2,
        delta_objects_self_contained: 1,
        delta_bases_verified: true,
        oid_set_digest: "oid-digest".into(),
        closure_digest: "closure-digest".into(),
        retention_roots_verified: 0,
        refs_digest: snap.refs_digest.clone(),
        fsck_verified: true,
        clone_verified: true,
    };
    CompactionPublishRequest {
        op_id: Uuid::new_v4(),
        tenant_id: snap.tenant_id,
        repo_id: snap.repo_id,
        history_id: snap.history_id,
        authority_epoch: snap.authority_epoch,
        shard_id: tok.key.shard_id,
        lease_id: tok.lease_id,
        fence_epoch: tok.fence_epoch,
        expected_membership_generation: snap.membership_generation,
        expected_pack_set_digest: snap.pack_set_digest.clone(),
        expected_refs_digest: snap.refs_digest.clone(),
        expected_retention_roots_digest: snap.retention_roots_digest.clone(),
        retired_pack_ids: plan.input_packs.iter().map(|p| p.pack_id).collect(),
        replacement_pack: replacement,
        merge_plan: plan,
        equivalence_proof_digest: proof.canonical_digest(),
        equivalence_proof: proof,
        delete_disabled: true,
    }
}

#[tokio::test]
async fn expired_lease_fails_closed_even_with_frozen_now_ms_and_no_usurper() {
    let tmp = tempfile::tempdir().unwrap();
    let store = DurableCompactionStore::open_with_journal(tmp.path().join("journal.json")).unwrap();
    let (tenant, repo, history) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let policy = SegmentTriggerPolicy { max_segment_packs: 2, ..SegmentTriggerPolicy::default() };
    let p1 = dummy_pack(tenant, repo, 20, 2000, 1);
    let p2 = dummy_pack(tenant, repo, 21, 2000, 1);
    let p3 = dummy_pack_on_shard(tenant, repo, 22, 2000, 2, 0, 1);
    let refs = vec![AuthoritativeRef::new("refs/heads/main", "b".repeat(40))];
    let snap =
        store.seed_repository(tenant, repo, history, 1, "sha1", 1, vec![p1, p2], refs, vec![], 1_000, &policy).unwrap();
    let key = CompactionLeaseKey { tenant_id: tenant, repo_id: repo, history_id: history, shard_id: 0 };
    let tok = store.acquire_or_renew_lease(&key, "w1", 1_000, 20).await.unwrap();
    let plan = snap.segments.plan_tiered_merge(0, &policy).unwrap().unwrap();
    let req = make_valid_publish_req(&snap, &tok, plan, p3);

    tokio::time::sleep(Duration::from_millis(40)).await;
    // Caller continues passing frozen start-time `now_ms = 1_000` with NO usurper: must fail closed.
    assert!(matches!(store.verify_lease_active(&tok, 1_000).await, Err(CompactionError::LeaseLost(_))));
    assert!(matches!(store.cas_publish_compaction(&req, 1_000, false).await, Err(CompactionError::LeaseLost(_))));

    // Restart / reload from disk also preserves expiration with frozen `now_ms`.
    let reloaded = store.reload_after_crash().unwrap();
    assert!(matches!(reloaded.verify_lease_active(&tok, 1_000).await, Err(CompactionError::LeaseLost(_))));
    assert!(matches!(reloaded.cas_publish_compaction(&req, 1_000, false).await, Err(CompactionError::LeaseLost(_))));

    // Re-acquiring after expiry must mint a new lease/fence, never auto-renew the expired handle.
    let new_tok = reloaded.acquire_or_renew_lease(&key, "w1", 1_000, 30_000).await.unwrap();
    assert!(new_tok.lease_id != tok.lease_id && new_tok.fence_epoch > tok.fence_epoch);
    assert!(matches!(reloaded.cas_publish_compaction(&req, 1_000, false).await, Err(CompactionError::LeaseLost(_))));

    let after = reloaded.load_snapshot(tenant, repo, history).await.unwrap();
    assert_eq!((after.membership_generation, after.serving_packs.len(), after.retained_old_packs.len()), (1, 2, 0));
    assert_eq!(after.segments, snap.segments);
}

#[tokio::test]
async fn cas_rejects_shard_tier_segment_and_generation_mismatches_without_mutation() {
    let store = DurableCompactionStore::in_memory();
    let (tenant, repo, history) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let policy = SegmentTriggerPolicy { max_segment_packs: 2, ..SegmentTriggerPolicy::default() };
    let s0_a = dummy_pack_on_shard(tenant, repo, 30, 2000, 1, 0, 2);
    let s0_b = dummy_pack_on_shard(tenant, repo, 31, 2000, 1, 0, 2);
    let s1_a = dummy_pack_on_shard(tenant, repo, 32, 2000, 1, 1, 2);
    let s1_b = dummy_pack_on_shard(tenant, repo, 33, 2000, 1, 1, 2);
    let rep_ok = dummy_pack_on_shard(tenant, repo, 34, 2000, 2, 0, 2);
    let refs = vec![AuthoritativeRef::new("refs/heads/main", "c".repeat(40))];
    let snap = store
        .seed_repository(
            tenant,
            repo,
            history,
            1,
            "sha1",
            2,
            vec![s0_a.clone(), s0_b.clone(), s1_a.clone(), s1_b.clone()],
            refs,
            vec![],
            1_000,
            &policy,
        )
        .unwrap();
    let key0 = CompactionLeaseKey { tenant_id: tenant, repo_id: repo, history_id: history, shard_id: 0 };
    let tok0 = store.acquire_or_renew_lease(&key0, "w0", 1_000, 30_000).await.unwrap();
    let plan0 = snap.segments.plan_tiered_merge(0, &policy).unwrap().unwrap();
    let plan1 = snap.segments.plan_tiered_merge(1, &policy).unwrap().unwrap();

    // 1. Shard-0 lease trying to compact Shard-1's plan/segments.
    let bad_shard = make_valid_publish_req(&snap, &tok0, plan1.clone(), rep_ok.clone());
    assert!(matches!(
        store.cas_publish_compaction(&bad_shard, 1_050, false).await,
        Err(CompactionError::OperationConflict(_))
    ));

    // 2. Plan pointing at Shard-0's segment IDs while input_packs/retired_pack_ids hold Shard-1's packs.
    let mut swapped_packs = plan0.clone();
    swapped_packs.input_packs = vec![s1_a, s1_b];
    let bad_swap = make_valid_publish_req(&snap, &tok0, swapped_packs, rep_ok.clone());
    assert!(matches!(
        store.cas_publish_compaction(&bad_swap, 1_050, false).await,
        Err(CompactionError::OperationConflict(_))
    ));

    // 3. Mismatched tier / target_tier and duplicate segment IDs.
    let mut bad_tier = plan0.clone();
    bad_tier.source_tier = SegmentTier::L1Merged;
    let r_tier = make_valid_publish_req(&snap, &tok0, bad_tier, rep_ok.clone());
    assert!(matches!(
        store.cas_publish_compaction(&r_tier, 1_050, false).await,
        Err(CompactionError::OperationConflict(_))
    ));

    let mut dup_seg = plan0.clone();
    dup_seg.input_segment_ids.push(dup_seg.input_segment_ids[0]);
    let r_dup = make_valid_publish_req(&snap, &tok0, dup_seg, rep_ok.clone());
    assert!(matches!(
        store.cas_publish_compaction(&r_dup, 1_050, false).await,
        Err(CompactionError::OperationConflict(_))
    ));

    // 4. Stale replacement_pack joined_generation (!= membership_generation + 1).
    let mut bad_gen = rep_ok;
    bad_gen.joined_generation = 1;
    let r_gen = make_valid_publish_req(&snap, &tok0, plan0, bad_gen);
    assert!(matches!(
        store.cas_publish_compaction(&r_gen, 1_050, false).await,
        Err(CompactionError::OperationConflict(_))
    ));

    let after = store.load_snapshot(tenant, repo, history).await.unwrap();
    assert_eq!(
        (after.membership_generation, after.serving_packs, after.retained_old_packs),
        (1, snap.serving_packs, vec![])
    );
    assert_eq!(after.segments, snap.segments);
}
