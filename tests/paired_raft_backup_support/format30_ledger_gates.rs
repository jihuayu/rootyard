//! Explicit A3/A4 ledger gates for paired restore.
//!
//! Source-realm receipts stay byte-for-byte immutable; the new realm is re-established
//! canonically and every cross-incarnation replay is refused with its exact typed error.
use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::Pool;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use rootyard::blob_store::opendal::BlobStore;
use rootyard::maintenance::paired_raft_backup::NewIncarnationAuthority;
use rootyard::ref_store::contract::{IssuerLane, OperationIdentity, RequestDigest};
use rootyard::ref_store::core::artifact_hold::{
    AcquireArtifactHoldsRequest, ArtifactHoldError, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::{
    MembershipDigest, PackCommitError, PackCommitExpectation, PackCommitPlan, PackCommitRejectCode as Code,
    PackCommitScope, PackMode, PgPackCommit,
};
use rootyard::ref_store::core::types::{GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate};
use rootyard::ref_store::{CoreGate, GitObjectFormat, PgRefStore};

const REQUESTS: &str = "SELECT request_id,request_digest,consume_request_id,ack_body,history_incarnation,authority_epoch,group_epoch FROM artifact_hold_requests WHERE repository_id=$1 ORDER BY request_id";
const CONSUMES: &str = "SELECT r.hold_id,r.consume_digest,r.body,q.history_incarnation,q.authority_epoch,q.group_epoch FROM artifact_hold_consume_receipts r JOIN artifact_hold_requests q ON q.request_id=r.request_id WHERE r.repository_id=$1 ORDER BY r.hold_id";
const PUBLICATIONS: &str = "SELECT registration_id,pack_id,parent_digest,ack_body,history_incarnation,authority_epoch,group_epoch FROM ref_store_core_pack_publications WHERE repository_id=$1 ORDER BY registration_id";

#[path = "format30_ledger_gates/public_restore.rs"]
mod public_restore;

type Realm = (Uuid, i64, i64);
/// Immutable pre-backup A3/A4 ledger evidence captured under the source realm.
pub struct PreBackupLedgerProof {
    pub repo_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub object_format: GitObjectFormat,
    pub old_history_inc: Uuid,
    pub old_authority_epoch: i64,
    pub old_group_epoch: i64,
    pub a3_requests: Vec<(Uuid, String, Uuid, String)>,
    pub a3_consumes: Vec<(Uuid, String, String)>,
    pub a4_publications: Vec<(Uuid, Uuid, String, String)>,
}

/// Capture the two A3 acquires, four consume receipts and two A4 registrations in the source realm.
pub async fn capture_pre_backup_ledger_proof(
    src_pool: &Pool,
    repo_id: Uuid,
    gate: &CoreGate,
) -> Result<PreBackupLedgerProof> {
    let c = src_pool.get().await?;
    let owner_id: Uuid = c.query_one("SELECT owner_id FROM public.repositories WHERE id=$1", &[&repo_id]).await?.get(0);
    let expected = (gate.history_incarnation(), gate.authority_epoch(), gate.group_epoch());
    let requests: Vec<(Uuid, String, Uuid, String, Realm)> = c
        .query(REQUESTS, &[&repo_id])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), (r.get(4), r.get(5), r.get(6))))
        .collect();
    let consumes: Vec<(Uuid, String, String, Realm)> = c
        .query(CONSUMES, &[&repo_id])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), (r.get(3), r.get(4), r.get(5))))
        .collect();
    let publications: Vec<(Uuid, Uuid, String, String, Realm)> = c
        .query(PUBLICATIONS, &[&repo_id])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), (r.get(4), r.get(5), r.get(6))))
        .collect();
    ensure!(requests.iter().all(|r| r.4 == expected), "pre-backup A3 request is in a foreign realm");
    ensure!(consumes.iter().all(|r| r.3 == expected), "pre-backup A3 consume is in a foreign realm");
    ensure!(publications.iter().all(|r| r.4 == expected), "pre-backup A4 registration is in a foreign realm");
    ensure!(requests.len() == 2, "expected exactly two pre-backup A3 acquires");
    ensure!(consumes.len() == 4, "expected exactly four pre-backup A3 consume receipts");
    ensure!(publications.len() == 2, "expected exactly two pre-backup A4 registrations");
    Ok(PreBackupLedgerProof {
        repo_id,
        tenant_id: gate.tenant_id(),
        owner_id,
        object_format: gate.object_format(),
        old_history_inc: expected.0,
        old_authority_epoch: expected.1,
        old_group_epoch: expected.2,
        a3_requests: requests.iter().map(|r| (r.0, r.1.clone(), r.2, r.3.clone())).collect(),
        a3_consumes: consumes.iter().map(|r| (r.0, r.1.clone(), r.2.clone())).collect(),
        a4_publications: publications.iter().map(|r| (r.0, r.1, r.2.clone(), r.3.clone())).collect(),
    })
}

/// Prove R_old immutability, canonical R_new rows, and exact cross-incarnation A3/A4 refusals.
pub async fn verify_post_restore_ledger_immutability_and_denials(
    dst_pool: &Pool,
    store: &BlobStore,
    pre: &PreBackupLedgerProof,
    inc: &NewIncarnationAuthority,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut c = dst_pool.get().await?;
    let old = (pre.old_history_inc, pre.old_authority_epoch, pre.old_group_epoch);
    let new = (inc.new_history_incarnation, inc.new_authority_epoch, inc.new_group_epoch);
    public_restore::verify_historical_wrapper_realm_refusal(&c, pre.repo_id, old, inc.new_cluster_incarnation).await?;
    let requests: Vec<(Uuid, String, Uuid, String, Realm)> = c
        .query(REQUESTS, &[&pre.repo_id])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), (r.get(4), r.get(5), r.get(6))))
        .collect();
    let consumes: Vec<(Uuid, String, String, Realm)> = c
        .query(CONSUMES, &[&pre.repo_id])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), (r.get(3), r.get(4), r.get(5))))
        .collect();
    let pubs: Vec<(Uuid, Uuid, String, String, Realm)> = c
        .query(PUBLICATIONS, &[&pre.repo_id])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), (r.get(4), r.get(5), r.get(6))))
        .collect();
    let old_requests: Vec<_> =
        requests.iter().filter(|r| r.4 == old).map(|r| (r.0, r.1.clone(), r.2, r.3.clone())).collect();
    let old_consumes: Vec<_> =
        consumes.iter().filter(|r| r.3 == old).map(|r| (r.0, r.1.clone(), r.2.clone())).collect();
    let old_pubs: Vec<_> = pubs.iter().filter(|r| r.4 == old).map(|r| (r.0, r.1, r.2.clone(), r.3.clone())).collect();
    ensure!(old_requests == pre.a3_requests, "historical A3 requests were rewritten");
    ensure!(old_consumes == pre.a3_consumes, "historical A3 consume receipts were rewritten");
    ensure!(old_pubs == pre.a4_publications, "historical A4 registrations were rewritten");
    ensure!(requests.iter().filter(|r| r.4 == new).count() == 2, "expected two canonical R_new A3 rows");
    ensure!(pubs.iter().filter(|r| r.4 == new).count() == 2, "expected two canonical R_new A4 rows");
    let r_old = pack_scope(pre, old)?;
    let r_new = pack_scope(pre, new)?;
    for (registration, _, parent, _) in &pre.a4_publications {
        let receipt = PgPackCommit.query_registration(&mut c, &r_old, *registration, deadline).await?;
        ensure!(
            receipt.is_some_and(|s| s.replayed && &s.ack.parent_digest == parent),
            "historical A4 registration does not replay under R_old"
        );
    }
    let new_pub =
        pubs.iter().find(|r| r.4 == new).ok_or_else(|| anyhow!("canonical R_new A4 registration is missing"))?;
    ensure!(
        PgPackCommit.query_registration(&mut c, &r_new, new_pub.0, deadline).await?.is_some(),
        "canonical R_new A4 registration does not replay"
    );
    let old_request_id = pre.a3_requests[0].0;
    let reused_request = AcquireArtifactHoldsRequest::new(
        hold_scope(pre, new)?,
        operation(pre, inc.new_history_incarnation, "ledger-new-realm")?,
        old_request_id,
        store.backend_identity().clone(),
        inc.new_storage_authority_id,
        inc.new_storage_generation,
        RequestDigest::of("ledger-new-gate", &[b"g"]),
        vec![spec("1")],
    )?;
    let reused = PgArtifactHoldStore.acquire(&mut c, store, &reused_request, deadline).await;
    ensure!(
        matches!(reused, Err(ArtifactHoldError::DigestConflict { request_id }) if request_id == old_request_id),
        "reusing an R_old A3 request id under R_new must be a digest conflict"
    );
    let pending = operation(pre, pre.old_history_inc, "ledger-old-realm")?;
    let tx = c.transaction().await?;
    PgRefStore.begin(&tx, &pending, deadline).await?;
    tx.commit().await?;
    let stale_request = AcquireArtifactHoldsRequest::new(
        hold_scope(pre, old)?,
        pending.clone(),
        Uuid::new_v4(),
        store.backend_identity().clone(),
        inc.new_storage_authority_id,
        inc.new_storage_generation,
        RequestDigest::of("ledger-old-gate", &[b"g"]),
        vec![spec("2")],
    )?;
    let stale = PgArtifactHoldStore.acquire(&mut c, store, &stale_request, deadline).await;
    ensure!(
        matches!(stale, Err(ArtifactHoldError::ScopeMismatch(_))),
        "an R_old A3 acquire must be refused against the canonical R_new realm"
    );
    let tx = c.transaction().await?;
    PgRefStore.cancel(&tx, &pending, deadline).await?;
    tx.commit().await?;
    let old_registration = pre.a4_publications[0].0;
    let conflict = PgPackCommit.query_registration(&mut c, &r_new, old_registration, deadline).await;
    ensure!(
        matches!(conflict, Err(PackCommitError::Rejected(ref r)) if r.code == Code::RegistrationConflict),
        "an R_old A4 registration must conflict under R_new"
    );
    let identity = operation(pre, pre.old_history_inc, "ledger-old-plan")?;
    let ref_update = RefUpdate::new(
        RefName::new("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(pre.object_format, &"1".repeat(pre.object_format.oid_hex_len()))?),
    );
    let expected = PackCommitExpectation::new(1, RequestDigest::of("old-gate", &[b"g"]), PackMode::MetadataOnly)?;
    let plan = PackCommitPlan::new(
        r_old,
        identity,
        expected,
        HeadUpdate::Keep,
        vec![ref_update],
        MembershipDigest::of(&[]),
        Vec::new(),
        Vec::new(),
    )?;
    let began = PgPackCommit.begin_pending(&mut c, &plan, deadline).await;
    ensure!(
        matches!(began, Err(PackCommitError::Rejected(ref r)) if r.code == Code::HistoryIncarnationMismatch),
        "an R_old A4 plan must not create a pending operation under R_new"
    );
    let captured = PgPackCommit.capture_context(&mut c, &plan, deadline).await;
    ensure!(
        matches!(captured, Err(PackCommitError::Rejected(ref r)) if r.code == Code::HistoryIncarnationMismatch),
        "an R_old A4 plan must not capture an R_new closure context"
    );
    Ok(())
}

/// After the post-restore push, R_old stays frozen while every R_new A3/A4 row must replay.
pub async fn verify_post_push_new_realm_ledger(
    dst_pool: &Pool,
    pre: &PreBackupLedgerProof,
    inc: &NewIncarnationAuthority,
) -> Result<()> {
    let mut c = dst_pool.get().await?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let old = (pre.old_history_inc, pre.old_authority_epoch, pre.old_group_epoch);
    let new = (inc.new_history_incarnation, inc.new_authority_epoch, inc.new_group_epoch);
    let req_rows = c.query(REQUESTS, &[&pre.repo_id]).await?;
    let request_realms: Vec<Realm> = req_rows.iter().map(|r| (r.get(4), r.get(5), r.get(6))).collect();
    let pub_rows = c.query(PUBLICATIONS, &[&pre.repo_id]).await?;
    let pubs: Vec<(Uuid, Realm)> = pub_rows.iter().map(|r| (r.get(0), (r.get(4), r.get(5), r.get(6)))).collect();
    ensure!(request_realms.iter().filter(|r| **r == old).count() == 2, "R_old A3 rows changed after push");
    ensure!(request_realms.iter().filter(|r| **r == new).count() >= 3, "post-push R_new A3 rows are missing");
    ensure!(pubs.iter().filter(|r| r.1 == old).count() == 2, "R_old A4 rows changed after push");
    ensure!(pubs.iter().filter(|r| r.1 == new).count() >= 3, "post-push R_new A4 rows are missing");
    let r_new = pack_scope(pre, new)?;
    for (registration, realm) in &pubs {
        if *realm == new {
            ensure!(
                PgPackCommit.query_registration(&mut c, &r_new, *registration, deadline).await?.is_some(),
                "post-push R_new A4 registration does not replay"
            );
        }
    }
    Ok(())
}

fn pack_scope(pre: &PreBackupLedgerProof, realm: Realm) -> Result<PackCommitScope> {
    Ok(PackCommitScope::new(pre.repo_id, pre.tenant_id, pre.owner_id, pre.object_format, realm.0, realm.1, realm.2)?)
}

fn hold_scope(pre: &PreBackupLedgerProof, realm: Realm) -> Result<HoldScope> {
    Ok(HoldScope::new(
        pre.repo_id,
        pre.tenant_id,
        pre.owner_id,
        ArtifactHoldPurpose::RefPublication,
        pre.object_format,
        realm.0,
        realm.1,
        realm.2,
    )?)
}

fn operation(pre: &PreBackupLedgerProof, issuer: Uuid, lane: &str) -> Result<OperationIdentity> {
    let op_id = Uuid::new_v4();
    Ok(OperationIdentity::new(
        pre.repo_id,
        issuer,
        IssuerLane::new(lane)?,
        1,
        op_id,
        RequestDigest::of(lane, &[op_id.as_bytes()]),
    )?)
}

fn spec(fill: &str) -> ArtifactSpec {
    ArtifactSpec::new("gateway-pack", fill.repeat(64), 1).expect("bounded artifact spec")
}
