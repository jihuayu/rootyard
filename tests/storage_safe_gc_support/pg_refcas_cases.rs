//! Real PG17 + live Raft Ref-CAS + migration-149 `ref_cas_projection_cursors` cut acceptance (#122).

use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use rootyard::{
    AppState, dispatch, metrics,
    ref_store::projector::{
        ProjectionRealm, RefCasEventEnvelope,
        pg::{load_or_init_cursor_for_update, project_event_in_tx},
    },
    storage,
    storage_lifecycle::{
        models::Policy,
        safe_gc::{
            ENV_BLOB_SAFE_GC_DESTRUCTIVE, SafeGcError,
            anti_aba::AntiAbaKeyRegistry,
            domain::AuthorityRecord,
            model::{GcMode, SafeGcObjectFormat, SourceFreshness},
            pg_maintenance::safe_gc_journal_path,
            pg_maintenance_dist::{InMemoryRefCasCutpointSource, persist_refcas_cutpoint_snapshot},
            pg_reconcile::reconcile_pg_refstore_authority,
            refcas_cut::reconcile_refcas_cut_with_pg,
            store::DurableSafeGcAuthority,
        },
        scheduler, worker,
    },
};
use tempfile::TempDir;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use uuid::Uuid;

use super::{
    PG_SAFE_GC_TEST_LOCK, app_config,
    dist_auth_harness::{
        assert_worker_volume_has_no_external_signing_keys, provision_distributed_trust, seal_test_lane_arm,
        test_arm_signer, test_dist_lane, test_trusted_voters,
    },
    isolated_pg_pool,
    pg_refcas_merge_fixture::{build_refcas_merge_rig, force_scan_and_schedule, production_refcas_pr_merge},
    provision_pg_refstore_repo,
    raft_voter_cluster::{LiveRaftVoterCluster, resolve_raft_node_bin, resolve_voter_bin},
    s3_harness::{LoopbackS3, build_pack_via_opendal, build_snapshot, git_cmd, make_serving_record},
    test_policy,
};

async fn gate_fails_closed(
    state: &Arc<AppState>,
    pool: &deadpool_postgres::Pool,
    policy: &Policy,
    owner: Uuid,
    repo_id: Uuid,
    label: &str,
) -> Result<()> {
    force_scan_and_schedule(state, pool, policy, repo_id).await?;
    let out = worker::run_once(state, policy, owner).await?.with_context(|| format!("{label} worker"))?;
    ensure!(out.state == "failed", "{label} must fail closed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg17_authoritative_refcas_reconciled_cut_blocks_unprojected_commits() -> Result<()> {
    let _serial = PG_SAFE_GC_TEST_LOCK.lock().await;
    let Some(db_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok() else {
        ensure!(
            std::env::var_os("ROOTYARD_SAFE_GC_REQUIRE_PG").is_none(),
            "ROOTYARD_SAFE_GC_REQUIRE_PG=1 but ROOTYARD_TEST_DATABASE_URL is missing"
        );
        return Ok(());
    };
    let Some(node_bin) = resolve_raft_node_bin()? else { return Ok(()) };
    let Some(_voter_bin) = resolve_voter_bin()? else { return Ok(()) };

    let s3 = LoopbackS3::shared();
    let (blob_store, provider) = s3.open_store_and_provider()?;
    let pool = isolated_pg_pool(&db_url).await?;
    let (tenant_id, repo_id, history_id) = provision_pg_refstore_repo(&pool, &blob_store).await?;
    let dir = TempDir::new()?;
    let cfg = app_config(dir.path(), db_url);
    let state = Arc::new(AppState {
        mirror_primary: None,
        dispatch: dispatch::Signals::default(),
        storage: storage::Storage::open(&cfg)?,
        config: cfg,
        pool: pool.clone(),
        hooks: None,
        transfer_metrics: Arc::new(metrics::TransferCounters::default()),
        git_slots: Arc::new(Semaphore::new(2)),
    });
    let cluster = Arc::new(AsyncMutex::new(LiveRaftVoterCluster::start(node_bin).await?));
    let trusted_voters = cluster.lock().await.trusted_voters();
    let pinned = test_trusted_voters();
    assert_eq!(trusted_voters.len(), pinned.len());
    for (live, expected) in trusted_voters.iter().zip(&pinned) {
        assert_eq!(
            (live.voter_id, &live.ed25519_pubkey_hex),
            (expected.voter_id, &expected.ed25519_pubkey_hex),
            "the live voters must match the keys used to seal the initial test arm"
        );
    }
    provision_distributed_trust(&state.storage.root, tenant_id, repo_id, history_id, 2, trusted_voters)?;
    assert_worker_volume_has_no_external_signing_keys(&state.storage.root, repo_id);

    let journal = safe_gc_journal_path(&state.storage.root, repo_id);
    let dl = Instant::now() + Duration::from_secs(60);

    // `base_oid` on `main`, then a fast-forward feature commit `main_oid`; `HEAD` therefore
    // packs both commits into `p_main`.
    let git_repo = dir.path().join("src.git");
    std::fs::create_dir_all(&git_repo)?;
    git_cmd(&git_repo, &["init", "--object-format=sha1", "--initial-branch=main"], None)?;
    std::fs::write(git_repo.join("main.txt"), b"refcas-base")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "base"], None)?;
    let base_oid = git_cmd(&git_repo, &["rev-parse", "refs/heads/main"], None)?;
    std::fs::write(git_repo.join("main.txt"), b"refcas-main")?;
    git_cmd(&git_repo, &["commit", "-am", "main"], None)?;
    let (p_main, p_main_rec, i_main, i_main_rec, main_oid, oids_main) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("sm"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;
    ensure!(main_oid != base_oid, "fast-forward feature commit must advance main");

    git_cmd(&git_repo, &["checkout", "--orphan", "orphan"], None)?;
    git_cmd(&git_repo, &["read-tree", "--empty"], None)?;
    std::fs::remove_file(git_repo.join("main.txt"))?;
    std::fs::write(git_repo.join("orphan.txt"), b"refcas-orphan")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "orphan"], None)?;
    let (p_orph, p_orph_rec, i_orph, i_orph_rec, _orph_oid, oids_orph) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("so"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;

    let rig = build_refcas_merge_rig(Arc::clone(&cluster), tenant_id, repo_id, history_id, &base_oid).await?;

    let auth_rec = AuthorityRecord {
        tenant_id,
        repo_id,
        history_id,
        trusted_arm_pubkey_hex: test_arm_signer().pubkey_hex().to_owned(),
        incarnation_id: Uuid::new_v4(),
        incarnation_epoch: 1,
        membership_generation: 1,
        live_ref_seq: 1,
        lease_epoch: 1,
    };
    let mut reg = AntiAbaKeyRegistry::new();
    let srv_main = make_serving_record(&mut reg, &auth_rec, p_main_rec, i_main_rec, oids_main);
    let srv_orph = make_serving_record(&mut reg, &auth_rec, p_orph_rec, i_orph_rec, oids_orph);
    let seeded = build_snapshot(
        auth_rec.clone(),
        SafeGcObjectFormat::Sha1,
        main_oid.clone(),
        vec![srv_main, srv_orph],
        reg,
        None,
    );
    DurableSafeGcAuthority::open_with_journal(&journal, Some(seeded))?;
    pool.get()
        .await?
        .execute(
            "INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision) VALUES($1,'refs/heads/main',$2,1)",
            &[&repo_id, &main_oid],
        )
        .await?;

    let policy = test_policy();
    let worker_owner = Uuid::new_v4();
    let pre_default_off_deletes = s3.state.delete_requests.load(Ordering::SeqCst);
    unsafe {
        for (k, v) in s3.env_pairs() {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "false");
    }

    // Default-off scheduled worker: compact both packs, zero provider deletes.
    assert_eq!(scheduler::schedule_once(&state, &policy).await?, 1);
    let off_out = worker::run_once(&state, &policy, worker_owner).await?.context("default-off repack")?;
    assert_eq!(off_out.kind, "pando_repack");
    assert_eq!(off_out.state, "succeeded");
    assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_default_off_deletes, "0 deletes when default-off");
    assert!(s3.has_key(&p_main) && s3.has_key(&i_main) && s3.has_key(&p_orph) && s3.has_key(&i_orph));

    let reloaded = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let snap_off = reloaded.snapshot();
    assert_eq!(snap_off.active_packs.len(), 1);
    assert_eq!(snap_off.retired_packs.len(), 2);
    let rep_pack_loc = snap_off.active_packs[0].pack_locator.to_locator()?;
    let rep_idx_loc = snap_off.active_packs[0].idx_locator.to_locator()?;
    drop(reloaded);
    let saved_orph = s3.get_stored(&p_orph).expect("p_orph stored");
    let replaced_orph = s3.overwrite_same_length(&p_orph, 0x6b);
    assert_eq!(replaced_orph.bytes.len(), saved_orph.bytes.len());
    s3.restore_stored(&p_orph, saved_orph);

    // PG ref sequence alone (revision 50) must NEVER unlock DistributedRefCas.
    pool.get()
        .await?
        .execute("UPDATE ref_store_core_refs SET revision = 50 WHERE repository_id = $1", &[&repo_id])
        .await?;
    let armed = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let armed_snap = armed.snapshot();
    let lane_arm = seal_test_lane_arm(
        tenant_id,
        repo_id,
        history_id,
        auth_rec.incarnation_id,
        1,
        test_dist_lane(tenant_id, repo_id, history_id, 1, 1, &armed_snap.global_holds, SafeGcObjectFormat::Sha1),
    )?;
    armed.set_gc_mode(GcMode::ArmedDestructive(Box::new(lane_arm)))?;
    drop(armed);
    unsafe {
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "true");
    }

    // Gate A: a sealed on-volume cutpoint exists, but zero voters answer: fail closed, no fallback.
    let sm_seed = cluster.lock().await.state_machine().await?;
    let sealed = persist_refcas_cutpoint_snapshot(&state.storage.root, repo_id, 0, &sm_seed, &[])?;
    assert!(sealed.is_file());
    gate_fails_closed(&state, &pool, &policy, worker_owner, repo_id, "gate A (0-of-3)").await?;
    assert!(s3.has_key(&p_orph) && s3.has_key(&i_orph), "gate A deleted objects");
    assert!(sealed.is_file(), "the sealed audit file must never be promoted to a cutpoint");

    // Gate A2: only one of three independent voters accepts: 1-of-3 can never reach the threshold.
    cluster.lock().await.set_voter_enabled(1, true);
    gate_fails_closed(&state, &pool, &policy, worker_owner, repo_id, "gate A2 (1-of-3)").await?;
    assert!(s3.has_key(&p_orph) && s3.has_key(&i_orph), "gate A2 deleted objects");

    // The production PR-merge Ref-CAS commit path writes the OpenRaft log (no sealed file fallback).
    let sm = production_refcas_pr_merge(&rig, &base_oid, &main_oid).await?;
    let events: Vec<(u64, u64)> = sm.snapshot()?.body.events.iter().map(|ev| (ev.event_seq, ev.log_index)).collect();
    ensure!(events.len() == 2, "expected the seed and PR-merge Ref-CAS events, got {events:?}");
    let (seed_seq, seed_idx) = events[0];
    let (merge_seq, merge_idx) = events[1];
    assert_eq!((seed_seq, merge_seq), (1, 2));
    assert_eq!(sm.last_applied().context("Ref-CAS last_applied")?.index, merge_idx);
    assert!(seed_idx < merge_idx);

    // Two of three independent voters now answer, and voter 3 stays disabled.
    cluster.lock().await.set_voter_enabled(2, true);
    assert_eq!(cluster.lock().await.enabled_voter_ids(), vec![1, 2]);

    // Gate B: the live quorum cutpoint exists but PG `ref_cas_projection_cursors` is missing.
    gate_fails_closed(&state, &pool, &policy, worker_owner, repo_id, "gate B").await?;
    assert!(s3.has_key(&p_orph) && s3.has_key(&i_orph));

    // Gate C: genesis cursor event_seq=0 vs the quorum Ref-CAS event_seq=2 must fail closed.
    let realm = ProjectionRealm::new(history_id, 0, 1)?;
    let mut tx_conn = pool.get().await?;
    let tx = tx_conn.transaction().await?;
    let _ = load_or_init_cursor_for_update(&tx, realm).await?;
    tx.commit().await?;
    drop(tx_conn);
    let auth = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let pgc = pool.get().await?;
    assert!(matches!(
        reconcile_refcas_cut_with_pg(&**pgc, &sm, repo_id, 0, &auth).await,
        Err(SafeGcError::IncompleteProof(_))
    ));
    drop(pgc);
    drop(auth);
    gate_fails_closed(&state, &pool, &policy, worker_owner, repo_id, "gate C").await?;
    assert!(s3.has_key(&p_orph) && s3.has_key(&i_orph));

    // Gate C2: project only event_seq=1; the unprojected PR merge commit still fails closed.
    let seed_ev = sm.snapshot()?.body.events.first().context("seed event")?.clone();
    let seed_env = RefCasEventEnvelope::from_state_machine_event(realm, Some(tenant_id), None, None, &seed_ev)?;
    let mut tx_conn = pool.get().await?;
    let tx = tx_conn.transaction().await?;
    let _ = project_event_in_tx(&tx, &seed_env, None).await?;
    tx.commit().await?;
    drop(tx_conn);
    gate_fails_closed(&state, &pool, &policy, worker_owner, repo_id, "gate C2").await?;
    assert!(s3.has_key(&p_orph) && s3.has_key(&i_orph));

    // Gate D: project event_seq=2 but leave the queued `ref_cas_projection_jobs` row unresolved.
    let merge_ev = sm.snapshot()?.body.events.last().context("merge event")?.clone();
    let merge_env = RefCasEventEnvelope::from_state_machine_event(realm, Some(tenant_id), None, None, &merge_ev)?;
    let mut tx_conn2 = pool.get().await?;
    let tx2 = tx_conn2.transaction().await?;
    let _ = project_event_in_tx(&tx2, &merge_env, None).await?;
    tx2.commit().await?;
    drop(tx_conn2);
    gate_fails_closed(&state, &pool, &policy, worker_owner, repo_id, "gate D").await?;
    assert!(s3.has_key(&p_orph) && s3.has_key(&i_orph));

    let mem_src = InMemoryRefCasCutpointSource::new();
    mem_src.upsert(repo_id, 0, sm.clone());
    force_scan_and_schedule(&state, &pool, &policy, repo_id).await?;
    let gate_d_mem = worker::run_once_with_refcas_source(&state, &policy, worker_owner, Some(&mem_src)).await?;
    let gate_d_mem = gate_d_mem.context("gate D mem")?;
    assert_eq!(gate_d_mem.state, "failed");
    assert!(s3.has_key(&p_orph) && s3.has_key(&i_orph));

    // Gate E: resolve projection jobs; the independent 2-of-3 voter quorum authorizes the sweep.
    pool.get()
        .await?
        .execute(
            "UPDATE ref_cas_projection_jobs SET state='succeeded', completed_at=clock_timestamp() WHERE repository_id=$1",
            &[&repo_id],
        )
        .await?;
    force_scan_and_schedule(&state, &pool, &policy, repo_id).await?;
    let sweep_out = worker::run_once(&state, &policy, worker_owner).await?.context("distributed safe_gc sweep")?;
    assert_eq!(sweep_out.kind, "pando_tombstone_delete");
    assert_eq!(sweep_out.state, "succeeded");
    let pgc = pool.get().await?;
    let res_json: serde_json::Value =
        pgc.query_one("SELECT result FROM storage_maintenance_jobs WHERE id = $1", &[&sweep_out.job_id]).await?.get(0);
    assert_eq!(res_json["authority_lane"], "distributed_refcas");
    assert_eq!(res_json["refcas_cut_event_seq"].as_u64(), Some(2));
    assert_eq!(res_json["refcas_cut_log_index"].as_u64(), Some(merge_idx));
    drop(pgc);

    // A second pass with a caller-supplied (non-production) cutpoint source must not
    // authorize a distributed destructive sweep. No job is queued here, and any
    // attempted run fails closed by design.
    let _ = worker::run_once_with_refcas_source(&state, &policy, worker_owner, Some(&mem_src)).await;
    unsafe {
        std::env::remove_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE);
    }

    assert!(!s3.has_key(&p_main) && !s3.has_key(&i_main));
    assert!(!s3.has_key(&p_orph) && !s3.has_key(&i_orph));
    let reloaded = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let cut = reloaded.snapshot().paired_cursors.refcas_cut.expect("persisted RefCasReconciledCut");
    assert_eq!(cut.sm_applied_event_seq, 2);
    assert_eq!(cut.sm_applied_log_index, merge_idx);

    // A later pass with projected cursors must never carry this cut forward as Reconciled.
    let pgc_reset = pool.get().await?;
    reconcile_pg_refstore_authority(&**pgc_reset, repo_id, &blob_store, &reloaded, Some(2)).await?;
    drop(pgc_reset);
    assert!(reloaded.snapshot().paired_cursors.refcas_cut.is_none());
    assert_eq!(reloaded.snapshot().paired_cursors.refcas_freshness, SourceFreshness::Unknown);

    let verify_dir = dir.path().join("verify-pg-surviving");
    let (pk_dst, ix_dst) = (verify_dir.join("objects/pack/surv.pack"), verify_dir.join("objects/pack/surv.idx"));
    std::fs::create_dir_all(pk_dst.parent().unwrap())?;
    git_cmd(&verify_dir, &["init", "--bare", "--object-format=sha1"], None)?;
    blob_store.get_to_file(&rep_pack_loc, &pk_dst, dl).await?;
    blob_store.get_to_file(&rep_idx_loc, &ix_dst, dl).await?;
    git_cmd(&verify_dir, &["update-ref", "refs/heads/main", &main_oid], None)?;
    git_cmd(&verify_dir, &["fsck", "--full", "--strict"], None)?;
    Ok(())
}
