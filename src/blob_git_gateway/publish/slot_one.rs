//! Crate-private gateway handoff for one exact slot-zero stale retirement.
//!
//! This is deliberately not a serving cutover and is not selected by the
//! current receive route. It is the narrow caller the reviewed
//! [`PgRefStore::rotate_slot_one_in_tx`] foundation was missing: the gateway
//! supplies the same authorized serving realm and the same staged, already
//! checked pack bytes that were ingested for the original producer request, but
//! it never reuses the retired slot-zero selection, private identity, sequence,
//! plan, proof, pack identity or registration identity.
//!
//! # Trusted input
//!
//! [`SlotOneHandoff::from_verified_slot_zero`] accepts the exact
//! [`PublicAttemptRetirement`] selected by the terminal mirror plus the verified
//! current-slot-zero evidence that names the same event. It checks the slot,
//! state, event id/revision, absence of a retired attempt and the recomputable
//! slot-zero proof before constructing the adapter input. A malformed or merely
//! conflicting non-retirement answer is an internal/typed refusal, never a
//! broad [`GatewayError::Conflict`] that could silently become a new push.
//!
//! # Transaction and lock order
//!
//! The low-level rotation owns a `tokio_postgres::Transaction`, while the
//! gateway owns a `deadpool_postgres::Transaction`. There is no supported
//! public conversion that moves the deadpool wrapper's inner transaction out.
//! This adapter therefore uses the existing slot-zero pattern: one SDK
//! savepoint is created from the deadpool-owned transaction and that owned
//! savepoint is passed to the reviewed primitive. The primitive's own savepoint
//! nests inside it, every write stays on the one outer database transaction,
//! and no connection or transaction is split. The savepoint release is only
//! `RELEASE SAVEPOINT`; the deadpool outer `COMMIT` remains the sole durability
//! point.
//!
//! The primitive is the first lock-taking step: it takes the migration-152
//! public/retired/proposed advisory keys and wrapper row lock, the shared
//! restore-incarnation fence, the retired issuer lane, then the ready
//! repository/serving binding and gate. Only after its savepoint is released
//! does this adapter run the existing authorized serving lookup in the same
//! outer transaction. That rechecks the live token/RBAC/membership, ready
//! binding, opened backend identity, restore incarnation and exact realm before
//! the outer `COMMIT`. A moved realm, cluster authority or gate is rolled back
//! and never silently adopted.
//!
//! # Replay and refusal
//!
//! An exact pending rotation replay builds no plan, allocates no lane or
//! sequence and is rolled back without side effects. A typed refusal is also
//! rolled back. The caller receives the fresh plan only after the outer
//! transaction acknowledged `COMMIT`; an unknown `COMMIT` keeps the existing
//! [`GatewayError::OutcomeUnknown`] answer and never names the private UUID. A
//! terminal slot-one result remains the read-only resolver/mirror path's
//! concern, so this adapter never invents a terminal or falls back to legacy
//! refs.
use std::fmt;

use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use crate::{
    db::Identity,
    ref_store::{
        CommitMode, OperationIdentity, OperationState, PgRefStore, RequestDigest,
        core::{
            RealmExpectation,
            pack_commit::{
                GATE_REVISION_MISMATCH_DETAIL, PackCommitBaseline, PackCommitError, PackCommitPlan,
                PackCommitRejectCode, PackCommitRejection,
            },
        },
        pg::{
            public_attempt::{PublicAttemptEvidence, PublicAttemptRequest},
            public_terminal::PublicAttemptRetirement,
            slot_one::{SlotOnePreview, SlotOneRotationReceipt, SlotOneRotationRequest},
            slot_zero,
        },
    },
};

use super::{
    Pair, build_plan_core, commit_deadpool_bounded, public_attempt_request, rollback_bounded, rollback_deadpool_bounded,
};
use crate::blob_git_gateway::{
    error::GatewayError, native::derived_uuid, protocol::PushRequest, serving::ServingRepository, state::BlobGitState,
};

/// The one gateway savepoint that owns the whole slot-one rotation call.
const GATEWAY_SLOT_ONE_SAVEPOINT: &str = "rootyard_gateway_slot_one_handoff";

/// Exact trusted stale-slot-zero retirement paired with the immutable producer
/// identity it belongs to.
///
/// Fields are private so a caller cannot pair a retirement with a different
/// public UUID, wire digest, mode or realm. The only constructor validates the
/// verified current-slot-zero evidence and recomputes its proof.
#[allow(dead_code)] // No route selects exact stale retirement until the reviewed next step.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct SlotOneHandoff {
    public: PublicAttemptRequest,
    retirement: PublicAttemptRetirement,
}

#[allow(dead_code)] // No route selects exact stale retirement until the reviewed next step.
impl SlotOneHandoff {
    /// Build the exact handoff input from a verified public attempt and the
    /// retirement returned for its current slot-zero stale rejection.
    ///
    /// The evidence must be the current slot-zero attempt in `Rejected` state
    /// and the retirement must name that attempt's exact migration-139 event.
    /// The public request is rebuilt from the same authorized serving realm and
    /// captured baseline as the original push; its public UUID, producer wire
    /// digest and commit mode are unchanged. The retired private UUID is only
    /// used to recompute the slot-zero proof and is never copied into the new
    /// request.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_verified_slot_zero(
        serving: &ServingRepository,
        actor: &Identity,
        public_id: Uuid,
        wire_digest: RequestDigest,
        mode: CommitMode,
        baseline: &PackCommitBaseline,
        backend_identity: String,
        evidence: &PublicAttemptEvidence,
        retirement: &PublicAttemptRetirement,
    ) -> Result<Self, GatewayError> {
        let current = &evidence.current;
        if evidence.public_id != public_id
            || evidence.retired.is_some()
            || current.slot != 0
            || current.state != OperationState::Rejected
            || current.private_id.is_nil()
            || current.private_id == public_id
            || current.base_revision <= 0
            || current.sequence <= 0
        {
            return Err(GatewayError::Internal("slot one handoff requires the exact current slot-zero rejection"));
        }
        let (Some(event_id), Some(event_revision)) = (current.event_id, current.event_revision) else {
            return Err(GatewayError::Internal("slot one handoff requires the retired slot-zero event"));
        };
        if event_id.is_nil()
            || event_id != retirement.event_id
            || event_revision != retirement.event_revision
            || event_revision <= current.base_revision
        {
            return Err(GatewayError::Internal(
                "slot one handoff retirement differs from the current slot-zero evidence",
            ));
        }

        let public = public_attempt_request(serving, actor, public_id, wire_digest, mode, baseline, backend_identity)?;
        let proof = slot_zero::recompute_slot_zero_proof(&public, current)
            .map_err(|_| GatewayError::Internal("slot one handoff slot-zero proof is not recomputable"))?;
        if proof != current.proof_digest {
            return Err(GatewayError::Internal("slot one handoff slot-zero proof differs from the durable evidence"));
        }
        Ok(Self { public, retirement: retirement.clone() })
    }

    /// The unchanged public request this handoff will rotate.
    #[allow(dead_code)]
    pub(super) fn public(&self) -> &PublicAttemptRequest {
        &self.public
    }
}

impl fmt::Debug for SlotOneHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlotOneHandoff")
            .field("public", &self.public)
            .field("retirement", &self.retirement)
            .finish()
    }
}

/// The safe result of one gateway slot-one rotation.
///
/// `Fresh` carries the new plan built from the locked preview; all A3/A4 work
/// still happens after this short admission transaction. `Replayed` is a
/// read-only exact pending replay and deliberately carries no plan, no new
/// identity and no sequence.
#[allow(dead_code)] // No route selects exact stale retirement until the reviewed next step.
#[derive(Clone, Eq, PartialEq)]
pub(super) enum SlotOneAdmission {
    Fresh { plan: Box<PackCommitPlan>, receipt: SlotOneRotationReceipt },
    Replayed(SlotOneRotationReceipt),
}

#[allow(dead_code)] // No route selects exact stale retirement until the reviewed next step.
impl SlotOneAdmission {
    /// The durable rotation receipt, whether fresh or an exact pending replay.
    pub(super) fn receipt(&self) -> &SlotOneRotationReceipt {
        match self {
            Self::Fresh { receipt, .. } | Self::Replayed(receipt) => receipt,
        }
    }

    /// Split the fresh plan from its receipt. A replay returns `Err(self)` so a
    /// caller cannot stage or publish bytes under a plan that was never built.
    pub(super) fn into_fresh(self) -> Result<(Box<PackCommitPlan>, SlotOneRotationReceipt), Self> {
        match self {
            Self::Fresh { plan, receipt } => Ok((plan, receipt)),
            replay @ Self::Replayed(_) => Err(replay),
        }
    }
}

impl fmt::Debug for SlotOneAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh { receipt, .. } => formatter
                .debug_struct("SlotOneAdmission::Fresh")
                .field("plan", &Redacted)
                .field("receipt", receipt)
                .finish(),
            Self::Replayed(receipt) => formatter.debug_tuple("SlotOneAdmission::Replayed").field(receipt).finish(),
        }
    }
}

/// Rotate one exact slot-zero stale rejection into a fresh slot-one pending
/// operation and acknowledge only the outer `COMMIT`.
///
/// The caller has already captured `baseline` from the same serving realm and
/// holds the staged original pack/index files. This adapter does not capture a
/// baseline, choose a retirement, retry a stale plan, upload A3 bytes, run A4 or
/// render HTTP. Those remain explicit reviewed callers above it.
#[allow(dead_code)] // No route selects exact stale retirement until the reviewed next step.
#[allow(clippy::too_many_arguments)]
pub(super) async fn rotate_slot_one(
    state: &BlobGitState,
    serving: &ServingRepository,
    actor: &Identity,
    handoff: SlotOneHandoff,
    request: &PushRequest,
    pairs: &[Pair],
    baseline: &PackCommitBaseline,
    deadline: Instant,
) -> Result<SlotOneAdmission, GatewayError> {
    let public = handoff.public.clone();
    let repository_id = public.repository_id;
    let mut client = state.pooled(deadline).await?;
    let mut tx = match timeout_at(deadline, client.transaction()).await {
        Ok(Ok(tx)) => tx,
        Ok(Err(_)) => return Err(GatewayError::Internal("slot one handoff transaction failed")),
        Err(_) => return Err(GatewayError::Timeout),
    };
    let savepoint = {
        let created =
            timeout_at(deadline, tokio_postgres::Transaction::savepoint(&mut *tx, GATEWAY_SLOT_ONE_SAVEPOINT)).await;
        match created {
            Ok(Ok(savepoint)) => savepoint,
            // Dropping the still-owned outer transaction queues its rollback;
            // no savepoint write exists to release.
            Ok(Err(_)) => return Err(GatewayError::Internal("slot one handoff savepoint failed")),
            Err(_) => return Err(GatewayError::Timeout),
        }
    };

    let rotation = SlotOneRotationRequest { public: public.clone(), retirement: handoff.retirement.clone() };
    let mut built = None;
    // Keep the rotation future and its owned savepoint in this block so no
    // result temporary outlives the borrow of the deadpool transaction.
    let (savepoint, result) = {
        let outcome = timeout_at(
            deadline,
            PgRefStore.rotate_slot_one_in_tx(
                savepoint,
                &rotation,
                |preview| {
                    let plan = build_slot_one_plan(request, pairs, &public, baseline, preview)?;
                    built = Some(plan.clone());
                    Ok(plan)
                },
                deadline,
            ),
        )
        .await;
        match outcome {
            Ok(Ok(rotation)) => rotation.into_parts(),
            // The primitive dropped its owned transaction on a fatal error, so
            // dropping the outer owner here queues the full rollback.
            Ok(Err(error)) => return Err(GatewayError::from(error)),
            Err(_) => return Err(GatewayError::Timeout),
        }
    };

    let receipt = match result {
        Ok(receipt) => receipt,
        Err(error) => {
            let _ = rollback_bounded(savepoint, deadline).await;
            let _ = rollback_deadpool_bounded(tx, deadline).await;
            return Err(GatewayError::from(error));
        }
    };

    if receipt.replayed {
        // The primitive fully proved the stored slot-one/retired pair in this
        // read-only call. It must not have built a plan, allocated a lane or
        // advanced a sequence. Discard the empty savepoint and outer owner.
        if built.is_some() {
            let _ = rollback_bounded(savepoint, deadline).await;
            let _ = rollback_deadpool_bounded(tx, deadline).await;
            return Err(GatewayError::Internal("slot one replay built a plan"));
        }
        if receipt.public_id != public.public_id
            || receipt.wire_digest != public.wire_digest
            || receipt.state != OperationState::Pending
        {
            let _ = rollback_bounded(savepoint, deadline).await;
            let _ = rollback_deadpool_bounded(tx, deadline).await;
            return Err(GatewayError::Internal("slot one replay receipt differs from its public request"));
        }
        rollback_bounded(savepoint, deadline).await?;
        rollback_deadpool_bounded(tx, deadline).await?;
        return Ok(SlotOneAdmission::Replayed(receipt));
    }

    let Some(plan) = built else {
        let _ = rollback_bounded(savepoint, deadline).await;
        let _ = rollback_deadpool_bounded(tx, deadline).await;
        return Err(GatewayError::Internal("slot one rotation did not build its plan"));
    };
    if let Err(error) = validate_fresh_receipt(&public, &plan, &receipt) {
        let _ = rollback_bounded(savepoint, deadline).await;
        let _ = rollback_deadpool_bounded(tx, deadline).await;
        return Err(error);
    }

    // Releasing the gateway savepoint only moves the already-written rows into
    // the deadpool-owned outer transaction; it is not a durability point.
    match super::commit_bounded(savepoint, deadline, repository_id, Some(public.public_id)).await {
        Ok(()) => {}
        Err(error) => {
            let _ = rollback_deadpool_bounded(tx, deadline).await;
            return Err(GatewayError::from(error));
        }
    }

    // Same outer transaction, after the lane/repository/gate locks: prove the
    // live token/RBAC/membership, ready serving binding, opened backend,
    // restore incarnation and exact realm before allowing COMMIT.
    let fresh = match crate::ref_store::serving::lookup_in_tx(
        &tx,
        actor,
        &serving.repository.owner,
        &serving.repository.name,
        true,
        state.store().backend_identity(),
        deadline,
    )
    .await
    {
        Ok(fresh) => fresh,
        Err(error) => {
            let _ = rollback_deadpool_bounded(tx, deadline).await;
            return Err(GatewayError::from(error));
        }
    };
    if !same_locked_realm(&fresh, serving, &public, baseline) {
        let _ = rollback_deadpool_bounded(tx, deadline).await;
        return Err(GatewayError::Conflict("repository authority changed; retry"));
    }

    commit_deadpool_bounded(tx, deadline).await?;
    Ok(SlotOneAdmission::Fresh { plan: Box::new(plan), receipt })
}

/// Build the canonical bounded plan from the rotation's locked preview.
///
/// The preview's private UUID, lane, sequence and base revision are the only
/// identity values used. The public request supplies the stable public UUID,
/// producer digest, mode, tenant/owner and realm. A preview at a revision other
/// than the captured baseline is the typed rollback-only revision refusal; this
/// adapter never silently recaptures or retires a different plan.
fn build_slot_one_plan(
    request: &PushRequest,
    pairs: &[Pair],
    public: &PublicAttemptRequest,
    baseline: &PackCommitBaseline,
    preview: SlotOnePreview,
) -> Result<PackCommitPlan, PackCommitError> {
    if preview.base_revision() != baseline.gate().revision() {
        return Err(PackCommitError::Rejected(PackCommitRejection::new(
            PackCommitRejectCode::RevisionMismatch,
            GATE_REVISION_MISMATCH_DETAIL,
        )));
    }
    if preview.private_id().is_nil()
        || preview.private_id() == public.public_id
        || preview.sequence() <= 0
        || public.public_id.is_nil()
    {
        return Err(PackCommitError::Invalid("slot one preview identity is invalid"));
    }
    let identity = OperationIdentity::new(
        public.repository_id,
        public.issuer_id,
        preview.lane().clone(),
        preview.sequence(),
        preview.private_id(),
        public.wire_digest,
    )
    .map_err(PackCommitError::from)?;
    // Keep the exact staged bytes, digests and lengths, but derive every
    // artifact identity from the fresh private attempt. Reusing the retired
    // public-derived pack id would collide with the old A4 registration row and
    // would transplant identity from the stale plan.
    let fresh_pairs = pairs
        .iter()
        .map(|pair| Pair {
            pack: pair.pack.clone(),
            idx: pair.idx.clone(),
            pack_id: slot_one_pack_id(preview.private_id(), &pair.pack_sha),
            pack_sha: pair.pack_sha.clone(),
            pack_len: pair.pack_len,
            idx_sha: pair.idx_sha.clone(),
            idx_len: pair.idx_len,
        })
        .collect::<Vec<_>>();
    build_plan_core(request, &fresh_pairs, public.request_mode, public.admission_owner_id, baseline, identity)
}

/// A4 pack identity for the fresh private attempt. The staged original bytes
/// keep their exact digest and length; only the operation namespace changes.
fn slot_one_pack_id(private_id: Uuid, pack_sha: &str) -> Uuid {
    derived_uuid("pack-id", private_id, pack_sha.as_bytes())
}

/// A fresh rotation receipt must bind exactly the plan and public request that
/// this adapter just admitted. No private UUID is formatted into an error.
fn validate_fresh_receipt(
    public: &PublicAttemptRequest,
    plan: &PackCommitPlan,
    receipt: &SlotOneRotationReceipt,
) -> Result<(), GatewayError> {
    let identity = plan.identity();
    if receipt.replayed
        || receipt.state != OperationState::Pending
        || receipt.public_id != public.public_id
        || receipt.private_id != identity.operation_id()
        || receipt.sequence != identity.sequence()
        || receipt.base_revision != plan.expected().revision()
        || receipt.plan_digest != *plan.parent_digest()
        || receipt.wire_digest != public.wire_digest
        || identity.issuer_id() != public.issuer_id
        || plan.repository_id() != public.repository_id
        || plan.tenant_id() != public.admission_owner_id
        || plan.owner_id() != public.admission_owner_id
        || plan.object_format() != public.object_format
        || plan.history_incarnation() != public.history_incarnation
        || plan.authority_epoch() != public.authority_epoch
        || plan.group_epoch() != public.group_epoch
        || plan.commit_mode() != public.request_mode
    {
        return Err(GatewayError::Internal("slot one rotation receipt differs from its fresh plan"));
    }
    Ok(())
}

/// The after-savepoint serving lookup must prove the same locked realm, cluster
/// restoration and gate version captured before the rotation.
fn same_locked_realm(
    fresh: &ServingRepository,
    serving: &ServingRepository,
    public: &PublicAttemptRequest,
    baseline: &PackCommitBaseline,
) -> bool {
    let gate = &fresh.gate;
    fresh.repository.id == public.repository_id
        && gate.repository_id() == public.repository_id
        && gate.tenant_id() == public.admission_owner_id
        && gate.object_format() == public.object_format
        && gate.history_incarnation() == public.history_incarnation
        && gate.authority_epoch() == public.authority_epoch
        && gate.group_epoch() == public.group_epoch
        && fresh.cluster_incarnation == public.restore_incarnation
        && gate.version() == *baseline.gate()
        && RealmExpectation::from_gate(gate) == RealmExpectation::from_gate(&serving.gate)
}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::Repository,
        ref_store::{
            GitObjectFormat, IssuerLane,
            core::{
                contract::CoreGate,
                pack_commit::{PackCommitBaseline, PackMode},
            },
            pg::public_attempt::PublicAttempt,
        },
    };

    const LANE: &str = "blob-git-receive";

    fn serving() -> ServingRepository {
        let repository_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let gate = CoreGate::new(
            repository_id,
            tenant_id,
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            1,
            1,
            crate::ref_store::RefName::new("refs/heads/main").unwrap(),
            7,
        )
        .unwrap();
        ServingRepository {
            repository: Repository {
                id: repository_id,
                name: "slot-one-handoff".to_owned(),
                owner: "owner".to_owned(),
                state: "ready".to_owned(),
                clone_path: "/git/owner/slot-one-handoff.git".to_owned(),
                storage_backend: "pg_refstore".to_owned(),
                storage_generation: 1,
                object_format: "sha1".to_owned(),
            },
            gate,
            cluster_incarnation: Uuid::new_v4(),
        }
    }

    fn actor() -> Identity {
        Identity {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            parent_token_id: None,
            username: "actor".to_owned(),
            read_only: false,
            token_digest: vec![0; 32],
        }
    }

    fn baseline(serving: &ServingRepository) -> PackCommitBaseline {
        PackCommitBaseline::new(serving.gate.version(), PackMode::MetadataOnly, Vec::new(), Vec::new()).unwrap()
    }

    fn public_request(
        serving: &ServingRepository,
        actor: &Identity,
        public_id: Uuid,
        digest: RequestDigest,
        baseline: &PackCommitBaseline,
    ) -> PublicAttemptRequest {
        public_attempt_request(serving, actor, public_id, digest, CommitMode::AcceptedSubset, baseline, "a".repeat(64))
            .unwrap()
    }

    fn rejected_evidence(
        public: &PublicAttemptRequest,
        private_id: Uuid,
        event_id: Uuid,
        base_revision: i64,
        event_revision: i64,
    ) -> PublicAttemptEvidence {
        let mut current = PublicAttempt {
            slot: 0,
            private_id,
            plan_digest: RequestDigest::of("slot-one-handoff-test-plan", &[b"plan"]),
            proof_digest: RequestDigest::of("slot-one-handoff-test-proof", &[b"placeholder"]),
            base_revision,
            lane: IssuerLane::new(LANE).unwrap(),
            sequence: 4,
            state: OperationState::Rejected,
            event_id: Some(event_id),
            event_revision: Some(event_revision),
        };
        current.proof_digest = slot_zero::recompute_slot_zero_proof(public, &current).unwrap();
        PublicAttemptEvidence { public_id: public.public_id, current, retired: None }
    }

    fn retirement(event_id: Uuid, event_revision: i64) -> PublicAttemptRetirement {
        PublicAttemptRetirement { event_id, event_revision }
    }

    #[test]
    fn trusted_slot_zero_evidence_keeps_the_public_identity_and_redacts_private_ids() {
        let serving = serving();
        let actor = actor();
        let baseline = baseline(&serving);
        let public_id = Uuid::new_v4();
        let private_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let digest = RequestDigest::of("slot-one-handoff-request", &[b"wire"]);
        let public = public_request(&serving, &actor, public_id, digest, &baseline);
        let evidence = rejected_evidence(&public, private_id, event_id, 6, 7);
        let retirement = retirement(event_id, 7);

        let handoff = SlotOneHandoff::from_verified_slot_zero(
            &serving,
            &actor,
            public_id,
            digest,
            CommitMode::AcceptedSubset,
            &baseline,
            "a".repeat(64),
            &evidence,
            &retirement,
        )
        .unwrap();

        assert_eq!(handoff.public().public_id, public_id);
        assert_eq!(handoff.public().wire_digest, digest);
        assert_eq!(handoff.public().request_mode, CommitMode::AcceptedSubset);
        assert_eq!(handoff.public().admission_owner_id, serving.gate.tenant_id());
        assert!(!format!("{handoff:?}").contains(&private_id.to_string()));
        assert!(!format!("{handoff:?}").contains(&event_id.to_string()));
    }

    #[test]
    fn only_the_exact_current_slot_zero_rejection_is_a_handoff_input() {
        let serving = serving();
        let actor = actor();
        let baseline = baseline(&serving);
        let public_id = Uuid::new_v4();
        let private_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let digest = RequestDigest::of("slot-one-handoff-invalid", &[b"wire"]);
        let public = public_request(&serving, &actor, public_id, digest, &baseline);
        let valid = rejected_evidence(&public, private_id, event_id, 6, 7);
        let valid_retirement = retirement(event_id, 7);

        let cases = [
            {
                let mut evidence = valid.clone();
                evidence.current.slot = 1;
                ("slot one is current", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.current.state = OperationState::Pending;
                ("not rejected", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.retired = Some(valid.current.clone());
                ("already retired", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.current.event_id = Some(Uuid::new_v4());
                ("different event", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.current.proof_digest = RequestDigest::of("slot-one-handoff-wrong-proof", &[b"wire"]);
                ("different proof", evidence, valid_retirement.clone())
            },
            {
                let mut evidence = valid.clone();
                evidence.public_id = Uuid::new_v4();
                ("different public id", evidence, valid_retirement.clone())
            },
            ("different revision", valid.clone(), retirement(event_id, 8)),
        ];

        for (label, evidence, retirement) in cases {
            let error = SlotOneHandoff::from_verified_slot_zero(
                &serving,
                &actor,
                public_id,
                digest,
                CommitMode::AcceptedSubset,
                &baseline,
                "a".repeat(64),
                &evidence,
                &retirement,
            )
            .unwrap_err();
            assert!(matches!(error, GatewayError::Internal(_)), "{label}: {error:?}");
            assert!(!error.message().contains(&private_id.to_string()), "{label}");
            assert!(!format!("{error:?}").contains(&private_id.to_string()), "{label}");
            assert!(!format!("{error:?}").contains(&event_id.to_string()), "{label}");
        }
    }

    #[test]
    fn fresh_plan_pack_identity_is_not_the_retired_public_identity() {
        let public_id = Uuid::new_v4();
        let private_id = Uuid::new_v4();
        let sha = "a".repeat(64);
        let retired = crate::blob_git_gateway::native::derived_uuid("pack-id", public_id, sha.as_bytes());
        let fresh = slot_one_pack_id(private_id, &sha);
        assert_ne!(fresh, retired);
        assert_eq!(fresh, slot_one_pack_id(private_id, &sha));
        assert_eq!(fresh, crate::blob_git_gateway::native::derived_uuid("pack-id", private_id, sha.as_bytes()));
    }

    #[test]
    fn unknown_commit_keeps_the_redacted_unknown_outcome() {
        let private_id = Uuid::new_v4();
        let error = GatewayError::from(PackCommitError::CommitUnknown {
            repository_id: Uuid::new_v4(),
            operation_id: private_id,
        });
        assert_eq!(error, GatewayError::OutcomeUnknown);
        assert!(!error.message().contains(&private_id.to_string()));
        assert!(!format!("{error:?}").contains(&private_id.to_string()));
    }
}
