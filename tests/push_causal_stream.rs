//! Real OpenDAL S3 + stock Git (`SHA-1` & `SHA-256`) streaming push & causal proof tests (#183).

#[path = "push_causal_stream/pg_http_gateway.rs"]
mod pg_http_gateway;
#[path = "push_causal_stream/support.rs"]
mod support;

use std::collections::BTreeMap;

use anyhow::Result;
use rootyard::namespace_service::push_causal_stream::quarantine::HoldLifecycleState;
use rootyard::namespace_service::push_causal_stream::*;
use rootyard::ref_store::contract::OperationLookup;
use rootyard::ref_store::core::ref_version::{AuthorityKind, RefVersionRealm, VersionGraph};
use rootyard::ref_store::core::types::GitObjectFormat;
use sha2::{Digest, Sha256};
use support::{
    BaseVersionSpec, LoopbackS3, active_auth, build_base_version, build_receive_wire, chunked_stream, dl, mk_commit,
    run_git, upload_git_pack,
};
use tempfile::TempDir;
use uuid::Uuid;

#[tokio::test]
async fn e2e_sha1_and_sha256_thin_packs_multi_deps_duplicates_and_fail_closed() -> Result<()> {
    let s3 = LoopbackS3::shared();
    let store = s3.open_store()?;
    let carrier = CapacityContractBlobCarrier;

    for (fmt, flag) in [(GitObjectFormat::Sha1, "sha1"), (GitObjectFormat::Sha256, "sha256")] {
        let tmp = TempDir::new()?;
        let (work, bare) = (tmp.path().join("work"), tmp.path().join("bare"));
        run_git(tmp.path(), &["init", &format!("--object-format={flag}"), "-b", "main", work.to_str().unwrap()], None)?;
        run_git(tmp.path(), &["init", "--bare", &format!("--object-format={flag}"), bare.to_str().unwrap()], None)?;
        let c1 = mk_commit(&work, "f.txt", &"base-line-\n".repeat(120), "c1")?;
        let c2 = mk_commit(&work, "f.txt", &format!("{}delta-v2\n", "base-line-\n".repeat(120)), "c2")?;
        let c3 = mk_commit(&work, "f.txt", &format!("{}delta-v3\n", "base-line-\n".repeat(120)), "c3")?;

        let (tenant, repo, hist) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let realm = RefVersionRealm::new(tenant, repo, hist, AuthorityKind::Raft, 1, 0, 1, fmt);
        let b1 = upload_git_pack(&work, &bare, &format!("{c1}\n"), "b1", &store, tenant, repo).await?;
        let b2 = upload_git_pack(&work, &bare, &format!("{c2}\n^{c1}\n"), "b2", &store, tenant, repo).await?;

        let (p1_id, r1_id, p2_id, r2_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let backend_hex = store.backend_identity().as_hex();
        let prov = store.provider().as_str();
        let v1 = build_base_version(BaseVersionSpec {
            realm,
            tenant,
            repo,
            seq: 1,
            oid_hex: &c1,
            parent_v: None,
            deps: vec![],
            pack_id: p1_id,
            reg_id: r1_id,
            pack_len: b1.2 + b1.5,
            backend_hex,
            provider: prov,
        });
        let v2 = build_base_version(BaseVersionSpec {
            realm,
            tenant,
            repo,
            seq: 2,
            oid_hex: &c2,
            parent_v: Some(v1.node.record.version_id()),
            deps: vec![v1.node.record.version_id()],
            pack_id: p2_id,
            reg_id: r2_id,
            pack_len: b2.2 + b2.5,
            backend_hex,
            provider: prov,
        });
        let mut graph = VersionGraph::new();
        graph.insert_active(v1.node.clone());
        graph.insert_active(v2.node.clone());

        let snapshot = AuthorizedSnapshotState {
            realm,
            tenant_id: tenant,
            repository_id: repo,
            history_incarnation: hist,
            authority_epoch: 1,
            group_epoch: 1,
            expected_gate_revision: 2,
            object_format: fmt,
            snapshot_seq: 2,
            root_version_id: Some(v2.node.record.version_id()),
            current_refs: BTreeMap::from([("refs/heads/main".into(), c2.clone())]),
            authorized_base_packs: vec![
                BasePackRef {
                    version_id: v1.node.record.version_id().as_hex(),
                    pack_id: p1_id,
                    registration_id: r1_id,
                    artifact_set_digest_hex: v1.digest_hex,
                    pack_sha256: b1.1,
                    pack_length: b1.2,
                    idx_sha256: b1.4,
                    idx_length: b1.5,
                    pack_locator: b1.0,
                    idx_locator: b1.3,
                    authorized_for_principal: true,
                },
                BasePackRef {
                    version_id: v2.node.record.version_id().as_hex(),
                    pack_id: p2_id,
                    registration_id: r2_id,
                    artifact_set_digest_hex: v2.digest_hex,
                    pack_sha256: b2.1,
                    pack_length: b2.2,
                    idx_sha256: b2.4,
                    idx_length: b2.5,
                    pack_locator: b2.0,
                    idx_locator: b2.3,
                    authorized_for_principal: true,
                },
            ],
        };

        let mut exec = StateMachinePushExecutor::new();
        exec.initialize_repo_gate(
            &snapshot,
            "refs/heads/main",
            BTreeMap::from([("refs/heads/main".into(), c2.clone())]),
        )?;

        let thin_pack = run_git(
            &work,
            &["pack-objects", "--revs", "--thin", "--stdout"],
            Some(format!("{c3}\n^{c1}\n").as_bytes()),
        )?;
        let wire =
            build_receive_wire(&[(&c2, &c3, "refs/heads/main")], "report-status-v2 atomic ofs-delta", &thin_pack);
        let auth = active_auth(Uuid::new_v4(), false);
        let ticket = OperationTicket {
            issuer_id: Uuid::new_v4(),
            lane: "push".into(),
            sequence: 1,
            operation_id: Uuid::new_v4(),
        };
        let reclaim = QuarantineReclaimLedger::open(tmp.path().join("reclaim"))?;

        let out = exec
            .execute_streaming_push(PushExecutionInput {
                reader: chunked_stream(wire),
                gzipped: false,
                store: &store,
                carrier: &carrier,
                snapshot: &snapshot,
                version_graph: Some(&graph),
                auth: &auth,
                branch_policy: &BranchPolicy { fast_forward_only_prefixes: vec![], require_commit_for_branches: true },
                lfs_policy: &LfsPolicy::AllowPlainOnly,
                ticket: &ticket,
                pipeline_mode: PackPipelineMode::OverlappedPipeline,
                ingest_limits: &StreamIngestLimits::default(),
                proc_limits: &GitSubprocessLimits::default(),
                reclaim_ledger: Some(&reclaim),
                fault_hook: FaultInjectionHook::None,
                deadline: dl(),
            })
            .await?;

        out.proof.verify_commit_binding(&snapshot, &ticket, backend_hex, &out.commit_receipt.terminal.refs)?;
        assert_eq!(reclaim.load(ticket.operation_id)?.unwrap().state, UploadReclaimState::VerifiedPromoted);
        assert!(!out.proof.resolved_thin_base_oids.is_empty());
        assert_eq!(out.hold_guard.state, HoldLifecycleState::ConsumedCommitted);
        assert_eq!(exec.sm().read_refs(repo).get("refs/heads/main"), Some(&c3));
        assert!(String::from_utf8_lossy(&out.report_status_wire).contains("ok refs/heads/main\n"));
        assert!(s3.objects.lock().unwrap().contains_key(&LoopbackS3::key(out.proof.pack_locator.as_ref().unwrap())));

        // Merge Gate 2 negative check: non-empty snapshot without verified closure MUST fail closed.
        let mut unverified_snap = snapshot.clone();
        unverified_snap.root_version_id = None;
        let pure_thin = run_git(
            &work,
            &["pack-objects", "--revs", "--thin", "--stdout"],
            Some(format!("{c3}\n^{c2}\n").as_bytes()),
        )?;
        let bad_wire = build_receive_wire(&[(&c2, &c3, "refs/heads/main")], "report-status", &pure_thin);
        let bad_res = exec
            .execute_streaming_push(PushExecutionInput {
                reader: chunked_stream(bad_wire.clone()),
                gzipped: false,
                store: &store,
                carrier: &carrier,
                snapshot: &unverified_snap,
                version_graph: None,
                auth: &auth,
                branch_policy: &BranchPolicy::default(),
                lfs_policy: &LfsPolicy::AllowPlainOnly,
                ticket: &OperationTicket { operation_id: Uuid::new_v4(), sequence: 2, ..ticket.clone() },
                pipeline_mode: PackPipelineMode::Sequential,
                ingest_limits: &StreamIngestLimits::default(),
                proc_limits: &GitSubprocessLimits::default(),
                reclaim_ledger: Some(&reclaim),
                fault_hook: FaultInjectionHook::None,
                deadline: dl(),
            })
            .await;
        assert!(matches!(bad_res, Err(PushCausalError::UnauthorizedBaseDependency(_))));

        // Empty repo + thin pack with missing delta base -> fails closed in index-pack.
        let mut empty_base_snap = unverified_snap;
        empty_base_snap.authorized_base_packs.clear();
        empty_base_snap.current_refs.clear();
        let bad_thin = exec
            .execute_streaming_push(PushExecutionInput {
                reader: chunked_stream(bad_wire),
                gzipped: false,
                store: &store,
                carrier: &carrier,
                snapshot: &empty_base_snap,
                version_graph: None,
                auth: &auth,
                branch_policy: &BranchPolicy::default(),
                lfs_policy: &LfsPolicy::AllowPlainOnly,
                ticket: &OperationTicket { operation_id: Uuid::new_v4(), sequence: 3, ..ticket },
                pipeline_mode: PackPipelineMode::Sequential,
                ingest_limits: &StreamIngestLimits::default(),
                proc_limits: &GitSubprocessLimits::default(),
                reclaim_ledger: Some(&reclaim),
                fault_hook: FaultInjectionHook::None,
                deadline: dl(),
            })
            .await;
        assert!(matches!(bad_thin, Err(PushCausalError::MissingDeltaBase(_) | PushCausalError::CorruptPack(_))));
    }
    Ok(())
}

#[tokio::test]
async fn e2e_cas_race_subset_rebind_reclaim_records_lfs_revocation_and_unknown_ack() -> Result<()> {
    let s3 = LoopbackS3::shared();
    let store = s3.open_store()?;
    let carrier = CapacityContractBlobCarrier;
    let tmp = TempDir::new()?;
    let (work, bare) = (tmp.path().join("w"), tmp.path().join("b"));
    run_git(tmp.path(), &["init", "-b", "main", work.to_str().unwrap()], None)?;
    run_git(tmp.path(), &["init", "--bare", bare.to_str().unwrap()], None)?;

    let c1 = mk_commit(&work, "f.txt", "base\n", "c1")?;
    let c2 = mk_commit(&work, "f.txt", "next\n", "c2")?;
    let (tenant, repo, hist) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let zero = "0".repeat(40);
    let pack = run_git(&work, &["pack-objects", "--revs", "--stdout"], Some(format!("{c2}\n").as_bytes()))?;

    let realm = RefVersionRealm::new(tenant, repo, hist, AuthorityKind::Raft, 1, 0, 1, GitObjectFormat::Sha1);
    let b1 = upload_git_pack(&work, &bare, &format!("{c1}\n"), "base1", &store, tenant, repo).await?;
    let (p1_id, r1_id) = (Uuid::new_v4(), Uuid::new_v4());
    let backend_hex = store.backend_identity().as_hex();
    let v1 = build_base_version(BaseVersionSpec {
        realm,
        tenant,
        repo,
        seq: 1,
        oid_hex: &c1,
        parent_v: None,
        deps: vec![],
        pack_id: p1_id,
        reg_id: r1_id,
        pack_len: b1.2 + b1.5,
        backend_hex,
        provider: store.provider().as_str(),
    });
    let mut graph = VersionGraph::new();
    graph.insert_active(v1.node.clone());

    let snapshot = AuthorizedSnapshotState {
        realm,
        tenant_id: tenant,
        repository_id: repo,
        history_incarnation: hist,
        authority_epoch: 1,
        group_epoch: 1,
        expected_gate_revision: 2,
        object_format: GitObjectFormat::Sha1,
        snapshot_seq: 1,
        root_version_id: Some(v1.node.record.version_id()),
        current_refs: BTreeMap::from([("refs/heads/main".into(), c1.clone())]),
        authorized_base_packs: vec![BasePackRef {
            version_id: v1.node.record.version_id().as_hex(),
            pack_id: p1_id,
            registration_id: r1_id,
            artifact_set_digest_hex: v1.digest_hex,
            pack_sha256: b1.1,
            pack_length: b1.2,
            idx_sha256: b1.4,
            idx_length: b1.5,
            pack_locator: b1.0,
            idx_locator: b1.3,
            authorized_for_principal: true,
        }],
    };

    let mut exec = StateMachinePushExecutor::new();
    exec.initialize_repo_gate(&snapshot, "refs/heads/main", BTreeMap::from([("refs/heads/main".into(), c1.clone())]))?;
    let mut auth = active_auth(Uuid::new_v4(), false);
    let reclaim = QuarantineReclaimLedger::open(tmp.path().join("reclaim-ledger"))?;

    // Merge Gate 4: partial AND unknown Blob uploads persist recoverable reclaim records!
    for (hook, expected_state) in [
        (FaultInjectionHook::SimulatePartialBlobUpload, UploadReclaimState::PartialFailed),
        (FaultInjectionHook::SimulateUnknownBlobUpload, UploadReclaimState::OutcomeUnknown),
    ] {
        let op_f = Uuid::new_v4();
        let tf = OperationTicket { issuer_id: Uuid::new_v4(), lane: "push".into(), sequence: 1, operation_id: op_f };
        let wf = build_receive_wire(&[(&zero, &c2, "refs/heads/other")], "report-status atomic", &pack);
        let rf = exec
            .execute_streaming_push(PushExecutionInput {
                reader: chunked_stream(wf),
                gzipped: false,
                store: &store,
                carrier: &carrier,
                snapshot: &snapshot,
                version_graph: Some(&graph),
                auth: &auth,
                branch_policy: &BranchPolicy::default(),
                lfs_policy: &LfsPolicy::AllowPlainOnly,
                ticket: &tf,
                pipeline_mode: PackPipelineMode::OverlappedPipeline,
                ingest_limits: &StreamIngestLimits::default(),
                proc_limits: &GitSubprocessLimits::default(),
                reclaim_ledger: Some(&reclaim),
                fault_hook: hook,
                deadline: dl(),
            })
            .await;
        assert!(rf.is_err() && !exec.sm().read_refs(repo).contains_key("refs/heads/other"));
        let rec = reclaim.load(op_f)?.expect("recoverable reclaim record must exist");
        assert_eq!(rec.state, expected_state);
        assert!(!rec.recorded_blob_paths.is_empty());
        assert!(reclaim.mark_reclaimed_if_proven_aborted(op_f, false).is_err());
        reclaim.mark_reclaimed_if_proven_aborted(op_f, true)?;
    }

    let t2 =
        OperationTicket { issuer_id: Uuid::new_v4(), lane: "push".into(), sequence: 2, operation_id: Uuid::new_v4() };
    let w2 = build_receive_wire(&[(&zero, &c2, "refs/heads/b1")], "report-status atomic", &pack);
    let r_unk = exec
        .execute_streaming_push(PushExecutionInput {
            reader: chunked_stream(w2),
            gzipped: false,
            store: &store,
            carrier: &carrier,
            snapshot: &snapshot,
            version_graph: Some(&graph),
            auth: &auth,
            branch_policy: &BranchPolicy::default(),
            lfs_policy: &LfsPolicy::AllowPlainOnly,
            ticket: &t2,
            pipeline_mode: PackPipelineMode::OverlappedPipeline,
            ingest_limits: &StreamIngestLimits::default(),
            proc_limits: &GitSubprocessLimits::default(),
            reclaim_ledger: Some(&reclaim),
            fault_hook: FaultInjectionHook::SimulateUnknownAckAfterCommit,
            deadline: dl(),
        })
        .await;
    assert!(matches!(r_unk, Err(PushCausalError::CommitUnknown { .. })));
    assert_eq!(exec.hold_guard(t2.operation_id).unwrap().state, HoldLifecycleState::ActiveHeld);
    assert_eq!(exec.sm().read_refs(repo).get("refs/heads/b1"), Some(&c2));
    assert!(matches!(exec.sm().query_operation(repo, t2.operation_id).unwrap(), OperationLookup::Known(_)));

    let caps = ReceiveCapabilities { report_status: true, ..ReceiveCapabilities::default() };
    let (rec_receipt, rec_wire) = exec.recover_unknown_operation(repo, tenant, t2.operation_id, &caps)?;
    assert!(rec_receipt.replayed && String::from_utf8_lossy(&rec_wire).contains("ok refs/heads/b1\n"));
    assert_eq!(exec.hold_guard(t2.operation_id).unwrap().state, HoldLifecycleState::ConsumedCommitted);

    let mut snap3 = snapshot.clone();
    snap3.expected_gate_revision = 3;
    let w_atomic_race = build_receive_wire(
        &[(&zero, &c2, "refs/heads/b2"), (&c1, &c2, "refs/heads/b1")],
        "report-status atomic",
        &pack,
    );
    let r_race = exec
        .execute_streaming_push(PushExecutionInput {
            reader: chunked_stream(w_atomic_race),
            gzipped: false,
            store: &store,
            carrier: &carrier,
            snapshot: &snap3,
            version_graph: Some(&graph),
            auth: &auth,
            branch_policy: &BranchPolicy::default(),
            lfs_policy: &LfsPolicy::AllowPlainOnly,
            ticket: &OperationTicket { operation_id: Uuid::new_v4(), sequence: 3, ..t2.clone() },
            pipeline_mode: PackPipelineMode::OverlappedPipeline,
            ingest_limits: &StreamIngestLimits::default(),
            proc_limits: &GitSubprocessLimits::default(),
            reclaim_ledger: Some(&reclaim),
            fault_hook: FaultInjectionHook::None,
            deadline: dl(),
        })
        .await;
    assert!(matches!(r_race, Err(PushCausalError::AtomicBatchRejected { .. })));
    assert!(!exec.sm().read_refs(repo).contains_key("refs/heads/b2"));

    // Merge Gate 3: non-atomic `AcceptedSubset` rebinds `out_sub.proof` to the EXACT final CAS subset!
    let t_sub = OperationTicket { operation_id: Uuid::new_v4(), sequence: 4, ..t2.clone() };
    let w_subset =
        build_receive_wire(&[(&zero, &c2, "refs/heads/b2"), (&c1, &c2, "refs/heads/b1")], "report-status", &pack);
    let out_sub = exec
        .execute_streaming_push(PushExecutionInput {
            reader: chunked_stream(w_subset),
            gzipped: false,
            store: &store,
            carrier: &carrier,
            snapshot: &snap3,
            version_graph: Some(&graph),
            auth: &auth,
            branch_policy: &BranchPolicy::default(),
            lfs_policy: &LfsPolicy::AllowPlainOnly,
            ticket: &t_sub,
            pipeline_mode: PackPipelineMode::OverlappedPipeline,
            ingest_limits: &StreamIngestLimits::default(),
            proc_limits: &GitSubprocessLimits::default(),
            reclaim_ledger: Some(&reclaim),
            fault_hook: FaultInjectionHook::None,
            deadline: dl(),
        })
        .await?;
    out_sub.proof.verify_commit_binding(&snap3, &t_sub, backend_hex, &out_sub.commit_receipt.terminal.refs)?;
    assert_eq!(out_sub.proof.accepted_updates.len(), 1);
    assert_eq!(out_sub.proof.rejected_updates.len(), 1);
    assert_eq!(out_sub.proof.accepted_updates[0].ref_name, "refs/heads/b2");
    assert_eq!(out_sub.proof.rejected_updates[0].ref_name, "refs/heads/b1");

    let lfs_hash = hex::encode(Sha256::digest(b"lfs-payload"));
    let _lfs = mk_commit(
        &work,
        "bin.lfs",
        &format!("version https://git-lfs.github.com/spec/v1\noid sha256:{lfs_hash}\nsize 11\n"),
        "lfs",
    )?;
    let c3 = String::from_utf8(run_git(&work, &["rev-parse", "HEAD"], None)?)?.trim().to_owned();
    let p_lfs = run_git(&work, &["pack-objects", "--revs", "--stdout"], Some(format!("{c3}\n").as_bytes()))?;
    let w_lfs = build_receive_wire(&[(&zero, &c3, "refs/heads/lfs-br")], "report-status", &p_lfs);
    let r_lfs = exec
        .execute_streaming_push(PushExecutionInput {
            reader: chunked_stream(w_lfs),
            gzipped: false,
            store: &store,
            carrier: &carrier,
            snapshot: &snap3,
            version_graph: Some(&graph),
            auth: &auth,
            branch_policy: &BranchPolicy::default(),
            lfs_policy: &LfsPolicy::RequireVerifiedBlobs { expected_blobs: BTreeMap::new() },
            ticket: &OperationTicket { operation_id: Uuid::new_v4(), sequence: 5, ..t2.clone() },
            pipeline_mode: PackPipelineMode::Sequential,
            ingest_limits: &StreamIngestLimits::default(),
            proc_limits: &GitSubprocessLimits::default(),
            reclaim_ledger: Some(&reclaim),
            fault_hook: FaultInjectionHook::None,
            deadline: dl(),
        })
        .await;
    assert!(matches!(r_lfs, Err(PushCausalError::LfsObjectMissingOrCorrupt(_))));

    let mut snap4 = snap3;
    snap4.expected_gate_revision = 4;
    let tok = auth.token_scope_id.unwrap();
    exec.close_auth_scope("token", tok, Some(repo), Some(tenant), 20)?;
    auth.principal_authz_epoch = 10;
    let w_rev = build_receive_wire(&[(&zero, &c2, "refs/heads/revoked")], "report-status", &pack);
    let r_rev = exec
        .execute_streaming_push(PushExecutionInput {
            reader: chunked_stream(w_rev),
            gzipped: false,
            store: &store,
            carrier: &carrier,
            snapshot: &snap4,
            version_graph: Some(&graph),
            auth: &auth,
            branch_policy: &BranchPolicy::default(),
            lfs_policy: &LfsPolicy::AllowPlainOnly,
            ticket: &OperationTicket { operation_id: Uuid::new_v4(), sequence: 6, ..t2 },
            pipeline_mode: PackPipelineMode::OverlappedPipeline,
            ingest_limits: &StreamIngestLimits::default(),
            proc_limits: &GitSubprocessLimits::default(),
            reclaim_ledger: Some(&reclaim),
            fault_hook: FaultInjectionHook::None,
            deadline: dl(),
        })
        .await;
    assert!(matches!(r_rev, Err(PushCausalError::AuthorizationDenied(_))));
    Ok(())
}
