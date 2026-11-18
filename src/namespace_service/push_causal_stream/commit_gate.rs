//! Pre-commit authorization checks, Ref-CAS request builder, and wire report encoder (#183).
//!
//! PostgreSQL commits MUST flow through [`super::pg_producer::commit_push_on_pg`], which
//! enforces a live migration-144 scoped decision (`PgAuthorizedCommit` / `PgAuthorizedMetadata`)
//! and durable A3 artifact holds (`PgArtifactHoldStore`), never raw `PgRefStoreCore::commit_refs`.

use std::time::Instant;

use uuid::Uuid;

use crate::blob_store::opendal::BlobStore;
use crate::ref_store::core::command::CommitRefsRequest;
use crate::ref_store::core::ref_version::VersionGraph;
use crate::ref_store::core::state_machine::{RefCasStateMachine, ScopeLifecycle};
use crate::ref_store::core::terminal::{CommitRefsReceipt, CommitRejectCode, RefCommitResult};
use crate::ref_store::core::types::{GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate};

use super::protocol::encode_receive_pack_report;
use super::quarantine::{OperationHoldGuard, PushBlobCarrier};
use super::receipt::{CausalPushProofReceipt, commit_mode_from_capabilities};
use super::reclaim::QuarantineReclaimLedger;
use super::types::{
    AuthorizedSnapshotState, BranchPolicy, FaultInjectionHook, GitSubprocessLimits, LfsPolicy, OperationTicket,
    PackPipelineMode, PushAuthContext, PushCausalError, PushStageTelemetry, ReceiveCapabilities, StreamIngestLimits,
};

pub use super::pg_producer::{PgScopedPushOutcome, PgScopedPushParams, commit_push_on_pg};

pub(super) const REF_CHANGED_REASON: &str = "ref changed; retry from current refs";

/// Pre-commit live authorization & scope check (`#112/#152`) blocking revoked tokens/sessions/leases.
pub fn evaluate_push_auth_precheck(
    auth: &PushAuthContext,
    repository_id: Uuid,
    sm: Option<&RefCasStateMachine>,
    fault_hook: FaultInjectionHook,
) -> Result<(), PushCausalError> {
    if fault_hook == FaultInjectionHook::RevokeAuthBeforeCommit {
        return Err(PushCausalError::AuthorizationDenied("principal authorization revoked immediately before commit"));
    }
    auth.check_active()?;
    if let Some(machine) = sm {
        if let Some((lifecycle, floor)) = machine.read_scope_lifecycle(repository_id) {
            if lifecycle != ScopeLifecycle::Open {
                return Err(PushCausalError::AuthorizationDenied("repository auth scope closing or closed"));
            }
            if auth.principal_authz_epoch < floor {
                return Err(PushCausalError::AuthorizationDenied("principal authz_epoch below repository floor"));
            }
        }
        for (kind, id_opt) in [("token", auth.token_scope_id), ("session", auth.session_scope_id)] {
            if let Some(scope_id) = id_opt
                && let Some(rec) = machine.read_scope_floor(kind, scope_id)
                && (rec.lifecycle != ScopeLifecycle::Open || auth.principal_authz_epoch < rec.authz_floor)
            {
                return Err(PushCausalError::AuthorizationDenied("token or session scope closed/revoked"));
            }
        }
    }
    Ok(())
}

/// Convert a verified [`CausalPushProofReceipt`] into a PG/Raft [`CommitRefsRequest`],
/// checking exact `(operation_id, snapshot, ticket, backend)` scope binding first.
pub fn build_pg_commit_request(
    receipt: &CausalPushProofReceipt,
    snapshot: &AuthorizedSnapshotState,
    ticket: &OperationTicket,
    capabilities: &ReceiveCapabilities,
    store_backend_identity_hex: &str,
) -> Result<CommitRefsRequest, PushCausalError> {
    receipt.verify_scope(snapshot, ticket, store_backend_identity_hex)?;
    if receipt.accepted_updates.is_empty() {
        return Err(PushCausalError::MalformedProtocol("cannot build CommitRefsRequest for zero updates".into()));
    }
    let mut updates = Vec::with_capacity(receipt.accepted_updates.len());
    for item in &receipt.accepted_updates {
        let name =
            RefName::new(item.ref_name.clone()).map_err(|e| PushCausalError::MalformedProtocol(e.to_string()))?;
        let precondition = match &item.old_oid {
            Some(hex) => RefPrecondition::Present(GitOid::parse(snapshot.object_format, hex)?),
            None => RefPrecondition::Absent,
        };
        let target = match &item.new_oid {
            Some(hex) => RefTarget::Oid(GitOid::parse(snapshot.object_format, hex)?),
            None => RefTarget::Delete,
        };
        updates.push(RefUpdate::new(name, precondition, target));
    }
    let lane = crate::ref_store::contract::IssuerLane::new(ticket.lane.as_str())?;
    let mode = commit_mode_from_capabilities(capabilities);
    let req = CommitRefsRequest::new(
        snapshot.repository_id,
        snapshot.tenant_id,
        ticket.issuer_id,
        lane,
        ticket.sequence,
        ticket.operation_id,
        snapshot.object_format,
        snapshot.history_incarnation,
        snapshot.authority_epoch,
        snapshot.group_epoch,
        snapshot.expected_gate_revision,
        HeadUpdate::Keep,
        mode,
        updates,
    )?;
    Ok(req)
}

/// Render Git `report-status` / `report-status-v2` wire output strictly matching CAS commit outcome.
pub fn report_status_from_terminal_refs(
    capabilities: &ReceiveCapabilities,
    terminal_refs: &[RefCommitResult],
) -> Result<Vec<u8>, PushCausalError> {
    let mut statuses: Vec<(&str, Result<(), &str>)> = Vec::with_capacity(terminal_refs.len());
    for entry in terminal_refs {
        match entry {
            RefCommitResult::Applied { name, .. } => statuses.push((name.as_str(), Ok(()))),
            RefCommitResult::NotApplied { name, reason } => {
                let wire_reason = match reason {
                    CommitRejectCode::OldOidMismatch | CommitRejectCode::RevisionMismatch => REF_CHANGED_REASON,
                    other => other.as_str(),
                };
                statuses.push((name.as_str(), Err(wire_reason)));
            }
        }
    }
    encode_receive_pack_report(capabilities, Ok(()), &statuses)
}

/// Render Git `report-status` / `report-status-v2` wire output from a [`CommitRefsReceipt`].
pub fn report_status_from_pg_receipt(
    capabilities: &ReceiveCapabilities,
    receipt: &CommitRefsReceipt,
) -> Result<Vec<u8>, PushCausalError> {
    report_status_from_terminal_refs(capabilities, &receipt.terminal.refs)
}

/// Complete push execution input against `StateMachinePushExecutor`.
pub struct PushExecutionInput<'a, R> {
    pub reader: R,
    pub gzipped: bool,
    pub store: &'a BlobStore,
    pub carrier: &'a dyn PushBlobCarrier,
    pub snapshot: &'a AuthorizedSnapshotState,
    pub version_graph: Option<&'a VersionGraph>,
    pub auth: &'a PushAuthContext,
    pub branch_policy: &'a BranchPolicy,
    pub lfs_policy: &'a LfsPolicy,
    pub ticket: &'a OperationTicket,
    pub pipeline_mode: PackPipelineMode,
    pub ingest_limits: &'a StreamIngestLimits,
    pub proc_limits: &'a GitSubprocessLimits,
    pub reclaim_ledger: Option<&'a QuarantineReclaimLedger>,
    pub fault_hook: FaultInjectionHook,
    pub deadline: Instant,
}

/// Final durable output returned ONLY after remote Blob proof + Ref-CAS persistence settled.
#[derive(Clone, Debug)]
pub struct PushExecutionOutput {
    pub proof: CausalPushProofReceipt,
    pub commit_receipt: CommitRefsReceipt,
    pub report_status_wire: Vec<u8>,
    pub telemetry: PushStageTelemetry,
    pub hold_guard: OperationHoldGuard,
}
