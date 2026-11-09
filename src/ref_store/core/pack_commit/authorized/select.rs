//! Stage 2 of the authorized pipeline: native facts, then one short decision transaction.
//!
//! The native facts engine runs **before** any PostgreSQL transaction is opened and
//! holds no pooled client: stage 1 already released it. The decision install then
//! runs inside one short transaction that also enables the irreversible fence, so
//! the repository can no longer receive a fresh legacy metadata/A4 write once the
//! decision exists.
use super::super::context::{PackCommitBaseline, refs_digest};
use super::super::contract::MAX_CAPTURE_REFS;
use super::super::error::{PackCommitError, PackCommitRejectCode};
use super::super::facts::{NoDurableLfsBytes, PublicationFactsEngine, VerifiedPublicationFacts};
use super::super::{pg, registration, sql};
use super::{
    AuthorizedCommitError, AuthorizedCommitMode, PgAuthorizedCommit, PreparedPublication, effective_deadline,
    pooled_client,
};
use crate::db::Identity;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::decision_commit::{self, RealmExpectation};
use crate::ref_store::core::publication_decision::{SelectedDecision, select_and_install};
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

/// Opaque result of stage 2: the original capture, the native facts it was
/// selected against and the sealed decision that installed the selection.
///
/// Private fields, no `Clone`, no serde and no public constructor. It carries no
/// token, no token digest and no proof.
pub struct AuthorizedSelection {
    prepared: PreparedPublication,
    facts: VerifiedPublicationFacts,
    selected: SelectedDecision,
    actor: Identity,
}

impl AuthorizedSelection {
    pub(super) fn new(
        prepared: PreparedPublication,
        facts: VerifiedPublicationFacts,
        selected: SelectedDecision,
        actor: Identity,
    ) -> Self {
        Self { prepared, facts, selected, actor }
    }

    pub(crate) fn prepared(&self) -> &PreparedPublication {
        &self.prepared
    }

    pub(crate) fn facts(&self) -> &VerifiedPublicationFacts {
        &self.facts
    }

    /// The sealed decision. It stays opaque; only the decision module can consume
    /// it, and only inside the final commit transaction.
    pub(crate) fn selected(&self) -> &SelectedDecision {
        &self.selected
    }

    pub(super) fn actor(&self) -> &Identity {
        &self.actor
    }

    pub fn operation_id(&self) -> Uuid {
        self.prepared.operation_id()
    }

    pub fn decision_id(&self) -> Uuid {
        self.selected.decision_id()
    }

    pub fn selection_digest(&self) -> &RequestDigest {
        self.selected.selection_digest()
    }

    /// True when the live policy accepted nothing. Such a selection takes no
    /// closure proof and writes no ref/gate revision.
    pub fn is_all_rejected(&self) -> bool {
        self.selected.accepted_is_empty()
    }

    pub fn accepted_refs(&self) -> usize {
        self.selected.accepted().len()
    }

    pub fn planned_refs(&self) -> usize {
        self.prepared.planned_refs()
    }
}

impl PgAuthorizedCommit {
    /// Stage 2: gather the native publication facts outside PostgreSQL, then mint
    /// and persist the decision in one short transaction.
    ///
    /// * the facts engine verifies the registered pack bytes/indexes, object
    ///   presence/type, ancestry, changed paths and LFS pointers; per-ref facts are
    ///   *not* refusals here, they become verdicts;
    /// * the transaction re-checks the captured state (`revision`, gate
    ///   digest/mode, complete ref set and membership digest) before installing, so
    ///   a concurrent legacy or decision write cannot be silently re-selected;
    /// * the protocol realm must match and the irreversible fence is enabled in the
    ///   same transaction as the decision rows;
    /// * `select_and_install` re-reads the live authorization/policy under its own
    ///   `NOWAIT` dependency locks and persists every per-ref verdict plus the
    ///   retained quota charge.
    pub async fn select(
        &self,
        pool: &deadpool_postgres::Pool,
        prepared: PreparedPublication,
        actor: &Identity,
        mode: AuthorizedCommitMode,
        deadline: Instant,
    ) -> Result<AuthorizedSelection, AuthorizedCommitError> {
        if prepared.plan().identity().issuer_id() != actor.id {
            return Err(AuthorizedCommitError::Denied("issuer_mismatch"));
        }
        let deadline = effective_deadline(deadline)?;
        // No PostgreSQL client is held here: the native permit works alone.
        let kind = mode.decision_kind();
        if prepared.plan().commit_mode().as_str() != kind.as_str() {
            return Err(AuthorizedCommitError::Unverifiable("commit mode differs from the original plan"));
        }
        let engine = PublicationFactsEngine::new(self.store.clone(), self.git_binary.clone())?;
        let lfs = NoDurableLfsBytes;
        let new_packs = prepared.new_packs().to_vec();
        let facts = engine.facts(prepared.plan(), prepared.baseline(), new_packs, &lfs, deadline.into_std()).await?;

        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let stage = async {
            pg::set_ack_durability(&tx, deadline).await?;
            pg::acquire_pending_prefix(&tx, prepared.plan(), deadline).await?;
            pg::ensure_repository(&tx, prepared.plan(), true).await?;
            crate::ref_store::core::publication_decision::sql_locks::lock_source_tables(
                &tx,
                &crate::ref_store::core::publication_decision::contract::PublicationAction::Push,
            )
            .await
            .map_err(super::decision_error)?;
            crate::ref_store::core::publication_decision::sql_locks::lock_usage(
                &tx,
                prepared.repository_id(),
                prepared.tenant_id(),
            )
            .await
            .map_err(super::decision_error)?;
            let (gate, mode) = sql::gate_locked(&tx, prepared.repository_id())
                .await?
                .ok_or_else(|| pg::reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
            pg::ensure_gate_matches(prepared.plan(), &gate, mode)?;
            // The native facts were computed against a captured state; refuse to
            // install a decision if anything in that state moved meanwhile.
            let refs = sql::capture_refs(&tx, prepared.repository_id(), gate.object_format(), MAX_CAPTURE_REFS).await?;
            if refs_digest(&refs) != *prepared.refs_digest() {
                return Err(AuthorizedCommitError::from(pg::reject(
                    PackCommitRejectCode::OldOidMismatch,
                    "ref set changed during native facts",
                )));
            }
            let old_packs = registration::old_memberships(&tx, &gate, deadline).await?;
            let baseline = PackCommitBaseline::new(gate.version(), mode, refs, old_packs)?;
            if baseline.membership_digest() != prepared.baseline().membership_digest() {
                return Err(AuthorizedCommitError::from(pg::reject(
                    PackCommitRejectCode::OldMembershipMismatch,
                    "active membership set changed during native facts",
                )));
            }
            // Frozen lock order: ... gate -> protocol row -> decision rows.
            decision_commit::lock_and_enforce(&tx, &RealmExpectation::from_gate(&gate))
                .await
                .map_err(PackCommitError::from)?;
            decision_commit::enable_fence(&tx, prepared.repository_id()).await.map_err(PackCommitError::from)?;
            let selected = select_and_install(&tx, prepared.plan(), &facts, actor, kind, deadline)
                .await
                .map_err(super::decision_error)?;
            Ok::<SelectedDecision, AuthorizedCommitError>(selected)
        };
        let result = match timeout_at(deadline, stage).await {
            Ok(value) => value,
            Err(_) => Err(AuthorizedCommitError::Timeout),
        };
        match result {
            Ok(selected) => {
                commit_bounded(tx, deadline, prepared.repository_id(), Some(prepared.operation_id()))
                    .await
                    .map_err(PackCommitError::from)?;
                Ok(AuthorizedSelection::new(prepared, facts, selected, actor.clone()))
            }
            Err(error) => {
                let _cleanup = super::rollback(tx, deadline).await;
                Err(error)
            }
        }
    }
}
