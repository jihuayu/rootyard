//! Stage 1 of the authorized publication pipeline: the sealed pre-write capture.
//!
//! Everything read here is real durable state of the original plan's operation:
//! the migration-138 registry row (with its exact terminal replay), the
//! repository authority row, the core gate, the migration-144 protocol realm,
//! the complete ref set, the complete active membership set and the durable
//! same-parent pack registrations. Nothing is written and nothing is inferred
//! from a caller boolean.
use super::super::artifact::RegisteredPack;
use super::super::context::{PackCommitBaseline, refs_digest};
use super::super::contract::{MAX_CAPTURE_REFS, PackMode};
use super::super::error::{PackCommitError, PackCommitRejectCode};
use super::super::plan::PackCommitPlan;
use super::super::receipt::PackCommitReceipt;
use super::super::{pg, registration, sql};
use crate::ref_store::contract::{OperationState, RefStoreError, RequestDigest};
use crate::ref_store::core::decision_commit::{self, RealmExpectation};
use crate::ref_store::pg::PgRefStore;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Result of stage 1.
pub enum PrepareOutcome {
    /// Complete sealed capture of a still-pending operation.
    Prepared(Box<PreparedPublication>),
    /// The operation already has a durable 138 terminal. Returned byte-for-byte
    /// as historical data: no re-authorization, no fence check, no refund.
    Replayed(Box<PackCommitReceipt>),
}

/// Opaque sealed capture of one pending authorized publication.
///
/// Private fields, no `Clone`, no serde and no public constructor: it can only be
/// produced by [`super::PgAuthorizedCommit::prepare`], so a caller cannot invent a
/// capture, a baseline, a closure context or a gate revision. It carries the
/// **original** plan (moved in, never re-derived) so every later stage works on
/// the stable operation id/digest.
pub struct PreparedPublication {
    plan: PackCommitPlan,
    baseline: PackCommitBaseline,
    new_packs: Vec<RegisteredPack>,
    head_ref: String,
    mode: PackMode,
    gate_revision: i64,
    refs_digest: RequestDigest,
}

impl PreparedPublication {
    pub(crate) fn plan(&self) -> &PackCommitPlan {
        &self.plan
    }

    pub(crate) fn baseline(&self) -> &PackCommitBaseline {
        &self.baseline
    }

    pub(crate) fn new_packs(&self) -> &[RegisteredPack] {
        &self.new_packs
    }

    pub fn repository_id(&self) -> Uuid {
        self.plan.repository_id()
    }

    pub fn tenant_id(&self) -> Uuid {
        self.plan.tenant_id()
    }

    pub fn operation_id(&self) -> Uuid {
        self.plan.identity().operation_id()
    }

    pub fn mode(&self) -> PackMode {
        self.mode
    }

    pub fn commit_mode(&self) -> crate::ref_store::CommitMode {
        self.plan.commit_mode()
    }

    pub fn gate_revision(&self) -> i64 {
        self.gate_revision
    }

    pub fn head_ref(&self) -> &str {
        &self.head_ref
    }

    /// Canonical digest of the complete captured ref set. Stage 2 refuses to
    /// install a decision if the live set no longer matches it.
    pub(crate) fn refs_digest(&self) -> &RequestDigest {
        &self.refs_digest
    }

    /// Number of refs of the **original** plan (never a filtered subset).
    pub fn planned_refs(&self) -> usize {
        self.plan.refs().len()
    }
}

/// One short read-only stage. The caller owns and rolls back the transaction.
pub(super) async fn prepare_in_tx(
    tx: &Transaction<'_>,
    plan: PackCommitPlan,
    deadline: Instant,
) -> Result<PrepareOutcome, PackCommitError> {
    crate::ref_store::pg::bound(tx, deadline).await?;
    // Exact migration-138 prefix: operation advisory key, repository existence
    // and issuer lane. An existing terminal replays here, first, unchanged.
    let begun = PgRefStore.begin(tx, plan.identity(), deadline).await?;
    match begun.record.state() {
        OperationState::Committed | OperationState::Rejected => {
            if begun.created {
                return Err(pg::reject(
                    PackCommitRejectCode::AlreadyVerified,
                    "authorized prepare never creates a terminal operation",
                ));
            }
            return Ok(PrepareOutcome::Replayed(Box::new(pg::replay_terminal(begun)?)));
        }
        OperationState::Cancelled => {
            return Err(pg::reject(PackCommitRejectCode::Cancelled, "cancellation tombstone won"));
        }
        OperationState::Pending => {}
    }
    if begun.created {
        return Err(pg::reject(
            PackCommitRejectCode::PendingMissing,
            "authorized prepare requires a pending operation established by the A4 flow",
        ));
    }
    if begun.record.identity() != plan.identity() {
        return Err(PackCommitError::from(RefStoreError::DigestConflict));
    }
    // Unchanged isolated unserved repository authority. No global readiness
    // relaxation is added for the authorized path.
    pg::ensure_repository(tx, plan.repository_id(), plan.tenant_id(), true).await?;
    // Frozen lock order: repository -> (usage) -> gate -> protocol row.
    let (gate, mode) = sql::gate_locked(tx, plan.repository_id())
        .await?
        .ok_or_else(|| pg::reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
    pg::ensure_gate_matches(&plan, &gate, mode)?;
    // The protocol realm must already be provisioned for exactly this realm. The
    // fence itself may still be off here: stage 2 installs the decision state and
    // enables it one-way. A `Required` fence is equally acceptable.
    decision_commit::lock_and_enforce(tx, &RealmExpectation::from_gate(&gate)).await.map_err(PackCommitError::from)?;
    let refs = sql::capture_refs(tx, plan.repository_id(), gate.object_format(), MAX_CAPTURE_REFS).await?;
    let old_packs = registration::old_memberships(tx, &gate, deadline).await?;
    let baseline = PackCommitBaseline::new(gate.version(), mode, refs, old_packs)?;
    let captured_refs_digest = refs_digest(baseline.refs());
    if baseline.membership_digest() != plan.old_membership_digest() {
        return Err(pg::reject(
            PackCommitRejectCode::OldMembershipMismatch,
            "active membership set changed since the plan captured it",
        ));
    }
    // Durable same-parent registrations: complete locator data, read-only.
    let new_packs = sql::registered_for_parent(tx, &plan).await?;
    Ok(PrepareOutcome::Prepared(Box::new(PreparedPublication {
        plan,
        baseline,
        new_packs,
        head_ref: gate.head_ref().as_str().to_owned(),
        mode,
        gate_revision: gate.revision(),
        refs_digest: captured_refs_digest,
    })))
}

#[cfg(test)]
mod tests {
    use super::super::super::contract::VERIFIER_DEADLINE_SECONDS;
    use super::super::effective_deadline;
    use super::*;
    use std::time::Duration;

    #[test]
    fn stage_deadline_is_clamped_and_never_restarted() {
        let far = Instant::now() + Duration::from_secs(VERIFIER_DEADLINE_SECONDS * 10);
        let clamped = effective_deadline(far).unwrap();
        assert!(clamped <= Instant::now() + Duration::from_secs(VERIFIER_DEADLINE_SECONDS + 1));
        assert!(effective_deadline(Instant::now()).is_err());
    }
}
