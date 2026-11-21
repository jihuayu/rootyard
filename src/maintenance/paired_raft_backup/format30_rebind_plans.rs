//! Canonical A4 follow-up plans for a restored `format 30` rebind: ref-only plans that carry a valid
//! archive beyond one plan's ref/ACK budget without re-registering any pack (#153).

use std::path::Path;

use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

use crate::ref_store::contract::{IssuerLane, OperationIdentity, RequestDigest};
use crate::ref_store::core::pack_commit::{
    PackCommitError, PackCommitExpectation, PackCommitPlan, PackCommitScope, PackMembershipEntry, PackVerifier,
    PgPackCommit,
};
use crate::ref_store::core::terminal::TerminalKind;
use crate::ref_store::core::types::{GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate};

use super::format30_pack_consolidate::pick_any_object_oid_from_pack;
use super::format30_realm_rehome::{RestoredRepoCapture, RestoredRepoPackFile};
use super::types::{NewIncarnationAuthority, PairedBackupError};

pub(super) fn sm_error(error: impl std::fmt::Display) -> PairedBackupError {
    PairedBackupError::StateMachine(error.to_string())
}

fn pack_error(error: PackCommitError) -> PairedBackupError {
    PairedBackupError::StateMachine(format!("restored A4 new-realm rebind refused: {error}"))
}

/// Second and later A4 plans of one restored rebind: a fresh baseline (which already includes the
/// memberships the first plan committed) is replayed as a ref-only plan with no new packs, so an
/// archive holding more refs than one plan admits still rebinds through several canonical plans.
pub(super) async fn commit_followup_ref_plan(
    client: &mut Client,
    verifier: &PackVerifier,
    repo: &RestoredRepoCapture,
    inc: &NewIncarnationAuthority,
    (seq, digest_tag): (i64, &str),
    updates: Vec<RefUpdate>,
    deadline: Instant,
) -> Result<(), PairedBackupError> {
    let (repo_id, tenant_id) = (repo.repository_id, repo.tenant_id);
    let baseline = PgPackCommit.capture_baseline(client, repo_id, tenant_id, deadline).await.map_err(pack_error)?;
    let op_id = Uuid::new_v4();
    let identity = OperationIdentity::new(
        repo.repository_id,
        inc.new_history_incarnation,
        IssuerLane::new("paired-restore-rebind").map_err(sm_error)?,
        seq,
        op_id,
        RequestDigest::of(digest_tag, &[op_id.as_bytes()]),
    )
    .map_err(sm_error)?;
    let mut memberships = Vec::with_capacity(baseline.old_packs().len());
    for pack in baseline.old_packs() {
        memberships.push(PackMembershipEntry::from_pack(pack).map_err(pack_error)?);
    }
    let (gate, mode) = (baseline.gate(), baseline.mode());
    let expected = PackCommitExpectation::new(gate.revision(), *gate.digest(), mode).map_err(pack_error)?;
    let plan = PackCommitPlan::new(
        rebind_scope(repo, inc)?,
        identity,
        expected,
        HeadUpdate::Keep,
        updates,
        baseline.membership_digest(),
        memberships,
        Vec::new(),
    )
    .map_err(pack_error)?;
    let token = PgPackCommit.begin_pending(client, &plan, deadline).await.map_err(pack_error)?;
    let context = PgPackCommit.capture_context(client, &plan, deadline).await.map_err(pack_error)?;
    let proof = verifier.verify(&plan, &context, deadline.into_std()).await.map_err(pack_error)?;
    let committed =
        PgPackCommit.commit_verified_pending(client, &plan, &token, &proof, deadline).await.map_err(pack_error)?;
    if committed.terminal.kind != TerminalKind::Committed {
        return Err(PairedBackupError::StateMachine("restore rebind follow-up plan was rejected".into()));
    }
    Ok(())
}

/// The rotated new-realm scope every restored plan (first, follow-up and adopt-tag) must carry.
pub(super) fn rebind_scope(
    repo: &RestoredRepoCapture,
    inc: &NewIncarnationAuthority,
) -> Result<PackCommitScope, PairedBackupError> {
    PackCommitScope::new(
        repo.repository_id,
        repo.tenant_id,
        repo.owner_id,
        repo.object_format,
        inc.new_history_incarnation,
        inc.new_authority_epoch,
        inc.new_group_epoch,
    )
    .map_err(pack_error)
}

/// Absolute-`Absent` ref updates for one rebind chunk of a fully restored repository.
pub(super) fn ref_updates_for(
    repo: &RestoredRepoCapture,
    chunk: &[(String, String)],
) -> Result<Vec<RefUpdate>, PairedBackupError> {
    let mut updates = Vec::with_capacity(chunk.len());
    for (name, oid) in chunk {
        let target = GitOid::parse(repo.object_format, oid).map_err(sm_error)?;
        updates.push(RefUpdate::new(
            RefName::new(name).map_err(sm_error)?,
            RefPrecondition::Absent,
            RefTarget::Oid(target),
        ));
    }
    Ok(updates)
}

/// A restored repository may legitimately hold zero refs while owning real packs; the A4 pipeline
/// requires a non-empty ref batch, so the packs are adopted under an ephemeral tag that the
/// delete-only follow-up plan removes again.
pub(super) fn adopt_tag_updates(
    git: &Path,
    repo: &RestoredRepoCapture,
    pack: &RestoredRepoPackFile,
    op_id: Uuid,
) -> Result<(Vec<RefUpdate>, Option<(String, GitOid)>), PairedBackupError> {
    let name = format!("refs/tags/rootyard-rebind-{op_id}");
    let hex = pick_any_object_oid_from_pack(git, repo.object_format, &pack.idx_path)?;
    let target = GitOid::parse(repo.object_format, &hex).map_err(sm_error)?;
    let update =
        RefUpdate::new(RefName::new(name.clone()).map_err(sm_error)?, RefPrecondition::Absent, RefTarget::Oid(target));
    Ok((vec![update], Some((name, target))))
}
