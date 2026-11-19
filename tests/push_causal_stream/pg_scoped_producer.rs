//! Direct `commit_push_on_pg` PostgreSQL 17 scoped decision, durable A3 hold, and
//! `AcceptedSubset` CAS receipt rebinding acceptance helper (#183 Merge Gate 3).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, ensure};
use deadpool_postgres::Pool;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::namespace_service::push_causal_stream::quarantine::HoldLifecycleState;
use rootyard::namespace_service::push_causal_stream::*;
use rootyard::ref_store::core::pack_commit::PgPackCommit;
use rootyard::ref_store::core::ref_version::{AuthorityKind, RefVersionRealm};
use rootyard::ref_store::core::types::GitObjectFormat;
use rootyard::ref_store::serving::lookup;
use tempfile::TempDir;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

use super::pg_http_gateway::{PgActor, create_and_provision_repo};
use super::support::{active_auth, mk_commit, run_git};

pub struct PgScopedTestEnv<'a> {
    pub pool: &'a Pool,
    pub store: &'a BlobStore,
    pub gw_addr: SocketAddr,
    pub actor: &'a PgActor,
    pub git_binary: &'a Path,
    pub backend_hex: &'a str,
}

pub async fn exercise_pg_scoped_producer(env: PgScopedTestEnv<'_>) -> Result<()> {
    let repo_name = format!("pgprod-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let repo_id = create_and_provision_repo(env.gw_addr, env.pool, env.store, env.actor, &repo_name, "sha1").await?;
    let dl = TokioInstant::now() + Duration::from_secs(30);
    let mut db_client = env.pool.get().await?;
    let repo_owner_id: Uuid =
        db_client.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repo_id]).await?.get(0);
    let serving =
        lookup(env.pool, &env.actor.identity, &env.actor.username, &repo_name, true, env.store.backend_identity(), dl)
            .await?;
    let gate = serving.gate;
    let baseline = PgPackCommit.capture_baseline(&mut db_client, repo_id, gate.tenant_id(), dl).await?;
    drop(db_client);

    let tmp = TempDir::new()?;
    let (work, bare) = (tmp.path().join("w"), tmp.path().join("b"));
    run_git(tmp.path(), &["init", "-b", "main", work.to_str().unwrap()], None)?;
    run_git(tmp.path(), &["init", "--bare", bare.to_str().unwrap()], None)?;
    let c1 = mk_commit(&work, "p.txt", "pg-scoped-v1\n", "c1")?;
    let raw_pack = run_git(&work, &["pack-objects", "--revs", "--stdout"], Some(format!("{c1}\n").as_bytes()))?;
    let p_path = bare.join("objects/pack/p1.pack");
    let idx_path = bare.join("objects/pack/p1.idx");
    run_git(&bare, &["index-pack", "--stdin", "--strict", p_path.to_str().unwrap()], Some(&raw_pack))?;

    let realm = RefVersionRealm::new(
        gate.tenant_id(),
        repo_id,
        gate.history_incarnation(),
        AuthorityKind::Pg,
        gate.authority_epoch().max(1),
        0,
        gate.group_epoch().max(1),
        GitObjectFormat::Sha1,
    );
    let snapshot = AuthorizedSnapshotState {
        realm,
        tenant_id: gate.tenant_id(),
        repository_id: repo_id,
        history_incarnation: gate.history_incarnation(),
        authority_epoch: gate.authority_epoch().max(1),
        group_epoch: gate.group_epoch().max(1),
        expected_gate_revision: baseline.gate().revision(),
        object_format: GitObjectFormat::Sha1,
        snapshot_seq: baseline.gate().revision(),
        root_version_id: None,
        current_refs: BTreeMap::new(),
        authorized_base_packs: Vec::new(),
    };
    let op_id = Uuid::new_v4();
    let ticket =
        OperationTicket { issuer_id: env.actor.identity.id, lane: "pg-push".into(), sequence: 1, operation_id: op_id };
    let auth = active_auth(env.actor.identity.id, true);
    let caps = ReceiveCapabilities { report_status: true, atomic: false, ..ReceiveCapabilities::default() };

    let accepted = vec![
        AcceptedRefProof {
            ref_name: "refs/heads/main".into(),
            old_oid: None,
            new_oid: Some(c1.clone()),
            target_kind: "commit".into(),
        },
        AcceptedRefProof {
            ref_name: "refs/heads/stale".into(),
            old_oid: Some("1".repeat(40)),
            new_oid: Some(c1.clone()),
            target_kind: "commit".into(),
        },
    ];
    let sub_dig =
        rootyard::namespace_service::push_causal_stream::receipt::compute_accepted_subset_digest(&accepted, &[]);
    let mut receipt = CausalPushProofReceipt {
        receipt_version: 2,
        tenant_id: snapshot.tenant_id,
        repository_id: repo_id,
        history_incarnation: snapshot.history_incarnation,
        authority_epoch: snapshot.authority_epoch,
        group_epoch: snapshot.group_epoch,
        object_format: GitObjectFormat::Sha1,
        operation_id: op_id,
        issuer_id: env.actor.identity.id,
        lane: ticket.lane.clone(),
        sequence: 1,
        base_snapshot_seq: snapshot.snapshot_seq,
        expected_gate_revision: snapshot.expected_gate_revision,
        committed_gate_revision: None,
        base_version_ids: vec![],
        required_ancestor_oids: vec![],
        resolved_thin_base_oids: vec![],
        base_closure_digest: "0".repeat(64),
        pack_sha256: None,
        pack_bytes: 0,
        idx_sha256: None,
        idx_bytes: 0,
        pack_locator: None,
        idx_locator: None,
        pack_pairs: Vec::new(),
        blob_backend_identity: env.backend_hex.to_owned(),
        object_count: 3,
        delta_object_count: 0,
        max_delta_chain_depth: 0,
        duplicate_object_count: 0,
        blob_closure_digest: "0".repeat(64),
        accepted_updates: accepted,
        rejected_updates: vec![],
        accepted_subset_digest: sub_dig,
        proof_digest: String::new(),
    };
    receipt.proof_digest = receipt.recompute_digest();

    let reclaim = QuarantineReclaimLedger::open(tmp.path().join("reclaim"))?;
    let mut hold_guard = OperationHoldGuard::acquire(op_id, vec![], vec![]);
    let outcome = commit_push_on_pg(PgScopedPushParams {
        pool: env.pool,
        store: env.store,
        git_binary: env.git_binary,
        actor: &env.actor.identity,
        owner_id: repo_owner_id,
        snapshot: &snapshot,
        ticket: &ticket,
        auth: &auth,
        capabilities: &caps,
        staged_pack_pair: Some((&p_path, &idx_path)),
        reclaim_ledger: Some(&reclaim),
        receipt: &mut receipt,
        hold_guard: &mut hold_guard,
        deadline: dl,
    })
    .await?;

    ensure!(hold_guard.state == HoldLifecycleState::ConsumedCommitted && hold_guard.hold_ids.len() == 2);
    ensure!(reclaim.load(op_id)?.unwrap().state == UploadReclaimState::VerifiedPromoted);
    let v_client = env.pool.get().await?;
    let dec_cnt: i64 = v_client
        .query_one(
            "SELECT COUNT(*) FROM ref_store_publication_decisions WHERE repository_id=$1 AND operation_id=$2 AND state='CONSUMED'",
            &[&repo_id, &op_id],
        )
        .await?
        .get(0);
    let hold_cnt: i64 = v_client
        .query_one(
            "SELECT COUNT(*) FROM artifact_holds WHERE repository_id=$1 AND operation_id=$2",
            &[&repo_id, &op_id],
        )
        .await?
        .get(0);
    ensure!(dec_cnt == 1 && hold_cnt == 2, "expected 1 consumed decision and 2 holds, got d={dec_cnt} h={hold_cnt}");
    receipt.verify_commit_binding(&snapshot, &ticket, env.backend_hex, &outcome.terminal_refs)?;
    ensure!(receipt.accepted_updates.len() == 1 && receipt.rejected_updates.len() == 1);
    let wire_txt = String::from_utf8_lossy(&outcome.report_status_wire);
    ensure!(wire_txt.contains("ok refs/heads/main\n") && wire_txt.contains("ng refs/heads/stale"));

    // Second pack push on the same lane (`ticket2_in.sequence = 1` pre-reservation) MUST rebind `receipt2.sequence == 2`!
    let c2 = mk_commit(&work, "p2.txt", "pg-scoped-v2\n", "c2")?;
    let raw_pack2 = run_git(&work, &["pack-objects", "--revs", "--stdout"], Some(format!("{c2}\n^{c1}\n").as_bytes()))?;
    let p2_path = bare.join("objects/pack/p2.pack");
    let idx2_path = bare.join("objects/pack/p2.idx");
    run_git(&bare, &["index-pack", "--stdin", "--strict", p2_path.to_str().unwrap()], Some(&raw_pack2))?;

    let mut snap2 = snapshot.clone();
    snap2.expected_gate_revision = outcome.committed_revision;
    snap2.snapshot_seq = outcome.committed_revision;
    snap2.current_refs.insert("refs/heads/main".into(), c1.clone());
    let op_id2 = Uuid::new_v4();
    let ticket2_in =
        OperationTicket { issuer_id: env.actor.identity.id, lane: "pg-push".into(), sequence: 1, operation_id: op_id2 };
    let acc2 = vec![AcceptedRefProof {
        ref_name: "refs/heads/main".into(),
        old_oid: Some(c1),
        new_oid: Some(c2),
        target_kind: "commit".into(),
    }];
    let sub2 = rootyard::namespace_service::push_causal_stream::receipt::compute_accepted_subset_digest(&acc2, &[]);
    let mut receipt2 = CausalPushProofReceipt {
        operation_id: op_id2,
        sequence: 1,
        base_snapshot_seq: snap2.snapshot_seq,
        expected_gate_revision: snap2.expected_gate_revision,
        committed_gate_revision: None,
        accepted_updates: acc2,
        rejected_updates: vec![],
        accepted_subset_digest: sub2,
        proof_digest: String::new(),
        ..receipt
    };
    receipt2.proof_digest = receipt2.recompute_digest();
    let mut hg2 = OperationHoldGuard::acquire(op_id2, vec![], vec![]);
    let out2 = commit_push_on_pg(PgScopedPushParams {
        pool: env.pool,
        store: env.store,
        git_binary: env.git_binary,
        actor: &env.actor.identity,
        owner_id: repo_owner_id,
        snapshot: &snap2,
        ticket: &ticket2_in,
        auth: &auth,
        capabilities: &caps,
        staged_pack_pair: Some((&p2_path, &idx2_path)),
        reclaim_ledger: Some(&reclaim),
        receipt: &mut receipt2,
        hold_guard: &mut hg2,
        deadline: dl,
    })
    .await?;
    ensure!(receipt2.sequence == 2, "expected PG sequence 2 on second commit_push_on_pg, got {}", receipt2.sequence);
    let expected_t2 = OperationTicket { sequence: 2, ..ticket2_in };
    receipt2.verify_commit_binding(&snap2, &expected_t2, env.backend_hex, &out2.terminal_refs)?;
    Ok(())
}
