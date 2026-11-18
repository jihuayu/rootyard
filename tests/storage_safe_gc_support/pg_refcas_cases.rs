//! Real PG17 + `RefCasStateMachine` + migration-149 `ref_cas_projection_cursors` cut acceptance (#122).

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use rootyard::{
    blob_store::disposable_view::DisposableViewRoot,
    ref_store::{
        CommitRefsRequest, IssuerLane,
        core::{
            contract::CommitMode,
            state_machine::{
                AppliedLogId, BeginOperationCommand, CommitRefsCommand, InitializeGateCommand, RefCasCommand,
                RefCasStateMachine, RepositoryLane, SmPackMode, WireCommitRefsRequest, WireGateInit,
            },
            types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate},
        },
        projector::{
            ProjectionRealm, RefCasEventEnvelope,
            pg::{load_or_init_cursor_for_update, project_event_in_tx},
        },
    },
    storage_lifecycle::safe_gc::{
        SafeGcArmReceipt, SafeGcError,
        anti_aba::AntiAbaKeyRegistry,
        compaction::{CompactionFault, SafeGcCompactionRequest, execute_two_phase_compaction},
        domain::AuthorityRecord,
        executor::{DeleteFaultHook, SafeGcSweepRequest, execute_safe_gc_sweep},
        model::{AuthorityLane, GcMode, SafeGcObjectFormat},
        pg_reconcile::reconcile_pg_refstore_authority,
        refcas_cut::reconcile_refcas_cut_with_pg,
        store::DurableSafeGcAuthority,
    },
};
use tempfile::TempDir;
use uuid::Uuid;

use super::{
    PG_SAFE_GC_TEST_LOCK, isolated_pg_pool, provision_pg_refstore_repo,
    s3_harness::{LoopbackS3, build_pack_via_opendal, build_snapshot, git_cmd, make_serving_record},
};

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

    let s3 = LoopbackS3::shared();
    let (blob_store, provider) = s3.open_store_and_provider()?;
    let pool = isolated_pg_pool(&db_url).await?;
    let (tenant_id, repo_id, history_id) = provision_pg_refstore_repo(&pool, &blob_store).await?;
    let dir = TempDir::new()?;
    let views = DisposableViewRoot::open(&dir.path().join("views"), 4, 64 << 20, Duration::from_secs(60))?;
    let dl = Instant::now() + Duration::from_secs(60);

    let git_repo = dir.path().join("src.git");
    std::fs::create_dir_all(&git_repo)?;
    git_cmd(&git_repo, &["init", "--object-format=sha1", "--initial-branch=main"], None)?;
    std::fs::write(git_repo.join("main.txt"), b"refcas-main")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "main"], None)?;
    let (_, p_main_rec, _, i_main_rec, main_oid, oids_main) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("sm"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;

    git_cmd(&git_repo, &["checkout", "--orphan", "orphan"], None)?;
    git_cmd(&git_repo, &["read-tree", "--empty"], None)?;
    std::fs::remove_file(git_repo.join("main.txt"))?;
    std::fs::write(git_repo.join("orphan.txt"), b"refcas-orphan")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "orphan"], None)?;
    let (p_orph, p_orph_rec, i_orph, i_orph_rec, _orph_oid, oids_orph) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("so"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;

    let auth_rec = AuthorityRecord {
        tenant_id,
        repo_id,
        history_id,
        incarnation_id: Uuid::new_v4(),
        incarnation_epoch: 1,
        membership_generation: 1,
        live_ref_seq: 1,
        lease_epoch: 1,
    };
    let mut reg = AntiAbaKeyRegistry::new();
    let srv_main = make_serving_record(&mut reg, &auth_rec, p_main_rec, i_main_rec, oids_main);
    let srv_orph = make_serving_record(&mut reg, &auth_rec, p_orph_rec, i_orph_rec, oids_orph);
    let journal = dir.path().join("refcas-journal.json");
    let authority = DurableSafeGcAuthority::open_with_journal(
        &journal,
        Some(build_snapshot(
            auth_rec.clone(),
            SafeGcObjectFormat::Sha1,
            main_oid.clone(),
            vec![srv_main, srv_orph.clone()],
            reg,
            None,
        )),
    )?;
    execute_two_phase_compaction(
        &authority,
        &blob_store,
        &provider,
        SafeGcCompactionRequest {
            op_id: Uuid::new_v4(),
            group_id: "g-main",
            blob_generation: 1,
            target_pack_ids: Vec::new(),
            view_root: &views,
            deadline: dl,
            fault: CompactionFault::None,
        },
    )
    .await?;

    // Bump PG ref revision to 50: PG ref sequence ALONE must NEVER satisfy DistributedRefCas cut!
    pool.get()
        .await?
        .execute(
            "INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision) VALUES($1,'refs/heads/main',$2,50)",
            &[&repo_id, &main_oid],
        )
        .await?;
    let pgc = pool.get().await?;
    reconcile_pg_refstore_authority(&**pgc, repo_id, &blob_store, &authority, Some(1)).await?;
    drop(pgc);

    let dist_arm = SafeGcArmReceipt::seal(
        tenant_id,
        repo_id,
        history_id,
        auth_rec.incarnation_id,
        1,
        true,
        AuthorityLane::DistributedRefCas {
            ref_cas_authority_id: repo_id,
            quorum_epoch: 1,
            raft_commit_index: 3,
            quorum_verified: true,
            global_hold_bridge_verified: true,
            global_hold_bridge_seq: 3,
            remote_backup_root_verified: true,
            remote_backup_root_epoch: 1,
            async_projection_only: false,
        },
    )?;
    assert!(matches!(
        authority.build_authoritative_deletion_proof(dist_arm.clone(), &[srv_orph.pack_id]),
        Err(SafeGcError::IncompleteProof(_))
    ));

    // Apply InitializeGate (idx=1) + BeginOperation (idx=2) + CommitRefs (idx=3 -> event_seq=1) in RefCasStateMachine!
    let mut sm = RefCasStateMachine::new();
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit {
                repository_id: repo_id,
                tenant_id,
                object_format: GitObjectFormat::Sha1,
                history_incarnation: history_id,
                authority_epoch: 1,
                group_epoch: 1,
                head_ref: "refs/heads/main".into(),
            },
            lane: RepositoryLane::LegacyUnservedGitfs,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 0,
        }),
    )?;
    let req_domain = CommitRefsRequest::new(
        repo_id,
        tenant_id,
        Uuid::new_v4(),
        IssuerLane::new("push")?,
        1,
        Uuid::new_v4(),
        GitObjectFormat::Sha1,
        history_id,
        1,
        1,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![RefUpdate::new(
            RefName::new("refs/heads/main")?,
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::parse(GitObjectFormat::Sha1, &main_oid)?),
        )],
    )?;
    let fixed_wire = WireCommitRefsRequest::from(&req_domain);

    sm.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::BeginOperation(BeginOperationCommand { identity: fixed_wire.identity.clone(), logical_tick: 1 }),
    )?;
    sm.apply(
        AppliedLogId { term: 1, index: 3 },
        RefCasCommand::CommitRefs(CommitRefsCommand {
            request: fixed_wire,
            decision_id: None,
            required_holds: Vec::new(),
            policy_rejects: BTreeMap::new(),
            logical_tick: 2,
        }),
    )?;

    // 1. Missing ref_cas_projection_cursors row -> fails closed!
    let pgc = pool.get().await?;
    assert!(matches!(
        reconcile_refcas_cut_with_pg(&**pgc, &sm, repo_id, 0, &authority).await,
        Err(SafeGcError::IncompleteProof(_))
    ));
    drop(pgc);

    // 2. Genesis cursor (event_seq=0) while Ref-CAS committed event_seq=1 -> unprojected commit fails closed!
    let realm = ProjectionRealm::new(history_id, 0, 1)?;
    let mut tx_conn = pool.get().await?;
    let tx = tx_conn.transaction().await?;
    let _ = load_or_init_cursor_for_update(&tx, realm).await?;
    tx.commit().await?;
    drop(tx_conn);

    let pgc = pool.get().await?;
    assert!(matches!(
        reconcile_refcas_cut_with_pg(&**pgc, &sm, repo_id, 0, &authority).await,
        Err(SafeGcError::IncompleteProof(_))
    ));
    drop(pgc);

    // 3. Project event_seq=1 into PG (`project_event_in_tx`), leaving queued `ref_cas_projection_jobs` -> still fails closed!
    let sm_ev = sm.snapshot()?.body.events.into_iter().next().expect("committed event");
    let env = RefCasEventEnvelope::from_state_machine_event(realm, Some(tenant_id), None, None, &sm_ev)?;
    let mut tx_conn2 = pool.get().await?;
    let tx2 = tx_conn2.transaction().await?;
    let _ = project_event_in_tx(&tx2, &env, None).await?;
    tx2.commit().await?;
    drop(tx_conn2);

    let pgc = pool.get().await?;
    assert!(matches!(
        reconcile_refcas_cut_with_pg(&**pgc, &sm, repo_id, 0, &authority).await,
        Err(SafeGcError::IncompleteProof(_))
    ));

    // 4. Complete queued downstream projection jobs -> RefCasReconciledCut verifies & DistributedRefCas sweep succeeds!
    pgc.execute(
        "UPDATE ref_cas_projection_jobs SET state='succeeded', completed_at=clock_timestamp() WHERE repository_id=$1",
        &[&repo_id],
    )
    .await?;
    let cut = reconcile_refcas_cut_with_pg(&**pgc, &sm, repo_id, 0, &authority).await?;
    assert_eq!(cut.sm_applied_event_seq, 1);
    assert_eq!(cut.pg_projected_event_seq, 1);
    drop(pgc);

    authority.set_gc_mode(GcMode::ArmedDestructive(dist_arm.clone()))?;
    let proof = authority.build_authoritative_deletion_proof(dist_arm, &[srv_orph.pack_id])?;
    let saved_orph = s3.get_stored(&p_orph).expect("p_orph stored");
    let replaced_orph = s3.overwrite_same_length(&p_orph, 0x6b);
    assert_eq!(replaced_orph.bytes.len(), saved_orph.bytes.len());
    s3.restore_stored(&p_orph, saved_orph);

    let cur = authority.snapshot().authority;
    let rep = execute_safe_gc_sweep(
        &authority,
        &provider,
        SafeGcSweepRequest {
            batch_id: Uuid::new_v4(),
            deleter_incarnation_id: cur.incarnation_id,
            deleter_incarnation_epoch: cur.incarnation_epoch,
            deleter_lease_epoch: cur.lease_epoch,
            proof,
            deadline: dl,
            fault: DeleteFaultHook::None,
        },
    )
    .await?;
    assert_eq!(rep.deleted_keys.len(), 2);
    assert!(!s3.has_key(&p_orph) && !s3.has_key(&i_orph));
    Ok(())
}
