//! RefCas state-machine command builders for push hold acquisition & scoped grants (#183).

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::ref_store::contract::{IssuerLane, RequestDigest};
use crate::ref_store::core::artifact_hold::contract::ArtifactHoldPurpose;
use crate::ref_store::core::command::CommitRefsRequest;
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, CommitRefsCommand, InstallDecisionCommand, InstallScopedDecisionCommand,
    MarkHoldConsumedCommand, RefCasCommand, WireCommitRefsRequest, WireDecisionGrantCommitment, WireDecisionKind,
    WireDecisionScopeDep, WireDecisionVerdict, WireHoldArtifactSpec,
};
use crate::ref_store::core::types::{GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate};

use super::quarantine::OperationHoldGuard;
use super::receipt::CausalPushProofReceipt;
use super::types::{AuthorizedSnapshotState, OperationTicket, PushAuthContext, PushCausalError};

pub(super) fn build_bootstrap_commands(
    snapshot: &AuthorizedSnapshotState,
    gate_revision: i64,
    logical_tick: u64,
    initial_refs: BTreeMap<String, String>,
) -> Result<(RefCasCommand, RefCasCommand), PushCausalError> {
    let mut updates = Vec::new();
    for (name, oid_hex) in initial_refs {
        let r = RefName::new(name).map_err(|e| PushCausalError::MalformedProtocol(e.to_string()))?;
        let oid = GitOid::parse(snapshot.object_format, &oid_hex)?;
        updates.push(RefUpdate::new(r, RefPrecondition::Absent, RefTarget::Oid(oid)));
    }
    let ticket = OperationTicket {
        issuer_id: Uuid::new_v4(),
        lane: "bootstrap".into(),
        sequence: 1,
        operation_id: Uuid::new_v4(),
    };
    let req = CommitRefsRequest::new(
        snapshot.repository_id,
        snapshot.tenant_id,
        ticket.issuer_id,
        IssuerLane::new(ticket.lane.as_str())?,
        ticket.sequence,
        ticket.operation_id,
        snapshot.object_format,
        snapshot.history_incarnation,
        snapshot.authority_epoch,
        snapshot.group_epoch,
        gate_revision,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        updates,
    )?;
    let decision_id = Uuid::new_v4();
    let zero_digest = RequestDigest::of("bootstrap", &[snapshot.repository_id.as_bytes()]).as_hex();
    let verdicts = req
        .refs()
        .iter()
        .map(|u| WireDecisionVerdict { ref_name: u.name().as_str().to_owned(), accepted: true, reject_code: None })
        .collect();
    let install = RefCasCommand::InstallDecision(InstallDecisionCommand {
        decision_id,
        repository_id: snapshot.repository_id,
        tenant_id: snapshot.tenant_id,
        actor_id: ticket.issuer_id,
        operation_id: ticket.operation_id,
        kind: WireDecisionKind::Atomic,
        base_revision: gate_revision,
        command_digest: req.identity().digest().as_hex(),
        selection_digest: zero_digest.clone(),
        policy_digest: zero_digest.clone(),
        facts_digest: zero_digest.clone(),
        authz_digest: zero_digest.clone(),
        dependencies_digest: zero_digest,
        verdicts,
        authz_epoch: 1,
        not_after_tick: logical_tick + 100,
        logical_tick,
    });
    let commit = RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&req),
        decision_id: Some(decision_id),
        required_holds: Vec::new(),
        policy_rejects: BTreeMap::new(),
        logical_tick,
    });
    Ok((install, commit))
}

pub(super) fn build_acquire_holds_cmd(
    receipt: &CausalPushProofReceipt,
    snapshot: &AuthorizedSnapshotState,
    ticket: &OperationTicket,
    auth: &PushAuthContext,
    backend_hex: &str,
    gate_digest: &str,
) -> Option<(RefCasCommand, Vec<Uuid>, Uuid, OperationHoldGuard)> {
    let (Some(pack_loc), Some(idx_loc)) = (&receipt.pack_locator, &receipt.idx_locator) else {
        return None;
    };
    let mut hold_ids = Vec::with_capacity(2);
    let mut specs = Vec::with_capacity(2);
    for (slot, (sha, bytes)) in [
        (0i16, (receipt.pack_sha256.as_deref().unwrap_or(""), receipt.pack_bytes)),
        (1i16, (receipt.idx_sha256.as_deref().unwrap_or(""), receipt.idx_bytes)),
    ] {
        let hid = Uuid::new_v4();
        hold_ids.push(hid);
        specs.push(WireHoldArtifactSpec {
            hold_id: hid,
            slot,
            artifact_digest: sha.to_owned(),
            declared_bytes: bytes.max(1) as i64,
            logical_bytes: 512,
        });
    }
    let consume_request_id = Uuid::new_v4();
    let backend_digest = RequestDigest::of("blob-backend-id", &[backend_hex.as_bytes()]).as_hex();
    let cmd = RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
        request_id: Uuid::new_v4(),
        consume_request_id,
        operation_id: ticket.operation_id,
        repository_id: snapshot.repository_id,
        tenant_id: snapshot.tenant_id,
        owner_id: auth.actor_id,
        purpose: ArtifactHoldPurpose::RefPublication.as_str().to_owned(),
        backend_identity: backend_digest,
        authority_id: snapshot.repository_id,
        authority_generation: snapshot.authority_epoch.max(1),
        expected_gate_digest: gate_digest.to_owned(),
        artifacts: specs,
    });
    let guard =
        OperationHoldGuard::acquire(ticket.operation_id, hold_ids.clone(), vec![pack_loc.clone(), idx_loc.clone()]);
    Some((cmd, hold_ids, consume_request_id, guard))
}

pub(super) struct ScopedDecisionCtx<'a> {
    pub receipt: &'a CausalPushProofReceipt,
    pub snapshot: &'a AuthorizedSnapshotState,
    pub ticket: &'a OperationTicket,
    pub auth: &'a PushAuthContext,
    pub req: &'a CommitRefsRequest,
    pub decision_id: Uuid,
    pub gate_digest: &'a str,
    pub hold_ids: &'a [Uuid],
    pub logical_tick: u64,
}

pub(super) fn build_scoped_decision_cmd(ctx: ScopedDecisionCtx<'_>) -> (RefCasCommand, WireDecisionGrantCommitment) {
    let kind = match ctx.req.mode() {
        CommitMode::Atomic => WireDecisionKind::Atomic,
        CommitMode::AcceptedSubset => WireDecisionKind::AcceptedSubset,
    };
    let verdicts = ctx
        .req
        .refs()
        .iter()
        .map(|u| WireDecisionVerdict { ref_name: u.name().as_str().to_owned(), accepted: true, reject_code: None })
        .collect();
    let packs_digest = RequestDigest::of("causal-packs-v1", &[ctx.receipt.blob_closure_digest.as_bytes()]).as_hex();
    let holds_digest = RequestDigest::of("causal-holds-v1", &[ctx.receipt.proof_digest.as_bytes()]).as_hex();
    let captured_digest =
        RequestDigest::of("causal-captured-v1", &[ctx.receipt.accepted_subset_digest.as_bytes()]).as_hex();
    let commitment = WireDecisionGrantCommitment {
        base_gate_digest: ctx.gate_digest.to_owned(),
        packs_digest: packs_digest.clone(),
        hold_receipts_digest: holds_digest,
        captured_oid_digest: captured_digest,
        required_holds: ctx.hold_ids.to_vec(),
    };
    let mut scope_deps = vec![WireDecisionScopeDep {
        scope_kind: "repo_access".into(),
        scope_id: ctx.snapshot.repository_id,
        observed_version: 1,
        observed_digest: packs_digest.clone(),
    }];
    for (kind_str, id_opt) in [("token", ctx.auth.token_scope_id), ("session", ctx.auth.session_scope_id)] {
        if let Some(sid) = id_opt {
            scope_deps.push(WireDecisionScopeDep {
                scope_kind: kind_str.into(),
                scope_id: sid,
                observed_version: 1,
                observed_digest: packs_digest.clone(),
            });
        }
    }
    let cmd_digest = ctx.req.identity().digest().as_hex();
    let cmd = RefCasCommand::InstallScopedDecision(InstallScopedDecisionCommand {
        decision: InstallDecisionCommand {
            decision_id: ctx.decision_id,
            repository_id: ctx.snapshot.repository_id,
            tenant_id: ctx.snapshot.tenant_id,
            actor_id: ctx.auth.actor_id,
            operation_id: ctx.ticket.operation_id,
            kind,
            base_revision: ctx.snapshot.expected_gate_revision,
            command_digest: cmd_digest.clone(),
            selection_digest: cmd_digest,
            policy_digest: packs_digest,
            facts_digest: ctx.receipt.proof_digest.clone(),
            authz_digest: ctx.receipt.base_closure_digest.clone(),
            dependencies_digest: ctx.receipt.accepted_subset_digest.clone(),
            verdicts,
            authz_epoch: ctx.auth.principal_authz_epoch.max(1),
            not_after_tick: ctx.logical_tick + 1000,
            logical_tick: ctx.logical_tick,
        },
        scope_dependencies: scope_deps,
        grant_commitment: commitment.clone(),
    });
    (cmd, commitment)
}

pub(super) fn build_mark_consumed_cmd(
    snapshot: &AuthorizedSnapshotState,
    consume_request_id: Uuid,
    hold_ids: &[Uuid],
) -> RefCasCommand {
    RefCasCommand::MarkHoldConsumed(MarkHoldConsumedCommand {
        consume_request_id,
        request_id: Uuid::new_v4(),
        repository_id: snapshot.repository_id,
        tenant_id: snapshot.tenant_id,
        hold_ids: hold_ids.to_vec(),
    })
}
