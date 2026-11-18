//! Scoped-decision and durable-artifact-hold PostgreSQL push producer (#183).
//!
//! Enforces migration-144 scoped decisions (`PgAuthorizedCommit` / `PgAuthorizedMetadata`)
//! and migration-141 durable artifact holds (`PgArtifactHoldStore` + `ProtectedUploader`)
//! before any ref mutation, and rebinds `CausalPushProofReceipt` to the exact final
//! CAS terminal subset (`Atomic` & `AcceptedSubset`).

use std::path::Path;

use deadpool_postgres::Pool;
use tokio::time::Instant;
use uuid::Uuid;

use crate::blob_store::opendal::BlobStore;
use crate::db::Identity;
use crate::ref_store::core::authorized_metadata::{MetadataDecisionPreparation, PgAuthorizedMetadata};
use crate::ref_store::core::pack_commit::{
    AuthorizedCommitError, AuthorizedCommitMode, PackCommitBaseline, PackCommitPlan, PgAuthorizedCommit, PgPackCommit,
    PrepareOutcome,
};
use crate::ref_store::{CommitMode, RefCommitResult, RequestDigest, TerminalKind};

use super::commit_gate::{build_pg_commit_request, evaluate_push_auth_precheck, report_status_from_terminal_refs};
use super::git_proc::sha256_and_len_sync;
use super::pg_producer_plan::{
    HeldUploadArgs, PendingPlanArgs, acquire_and_upload_held_pair, begin_pending_pack_plan,
    handle_authorized_commit_err, map_authorized_err, pooled_client, resolve_or_reserve_pg_sequence,
};
use super::quarantine::OperationHoldGuard;
use super::receipt::{CausalPushProofReceipt, commit_mode_from_capabilities};
use super::reclaim::{QuarantineReclaimLedger, UploadReclaimState};
use super::types::{
    AuthorizedSnapshotState, FaultInjectionHook, OperationTicket, PushAuthContext, PushCausalError, ReceiveCapabilities,
};

/// Parameters for executing a verified causal push through PostgreSQL scoped decisions & holds.
pub struct PgScopedPushParams<'a> {
    pub pool: &'a Pool,
    pub store: &'a BlobStore,
    pub git_binary: &'a Path,
    pub actor: &'a Identity,
    pub owner_id: Uuid,
    pub snapshot: &'a AuthorizedSnapshotState,
    pub ticket: &'a OperationTicket,
    pub auth: &'a PushAuthContext,
    pub capabilities: &'a ReceiveCapabilities,
    pub staged_pack_pair: Option<(&'a Path, &'a Path)>,
    pub reclaim_ledger: Option<&'a QuarantineReclaimLedger>,
    pub receipt: &'a mut CausalPushProofReceipt,
    pub hold_guard: &'a mut OperationHoldGuard,
    pub deadline: Instant,
}

/// Authoritative PostgreSQL commit outcome bound to `CausalPushProofReceipt`.
#[derive(Clone, Debug)]
pub struct PgScopedPushOutcome {
    pub committed_revision: i64,
    pub terminal_kind: TerminalKind,
    pub terminal_refs: Vec<RefCommitResult>,
    pub report_status_wire: Vec<u8>,
}

/// Execute proven Ref-CAS against PostgreSQL strictly gated by a live scoped decision
/// (`PgAuthorizedCommit` / `PgAuthorizedMetadata`) and durable artifact holds (`PgArtifactHoldStore`).
pub async fn commit_push_on_pg(params: PgScopedPushParams<'_>) -> Result<PgScopedPushOutcome, PushCausalError> {
    evaluate_push_auth_precheck(params.auth, params.snapshot.repository_id, None, FaultInjectionHook::None)?;
    if params.actor.read_only || params.actor.id != params.ticket.issuer_id || params.auth.actor_id != params.actor.id {
        return Err(PushCausalError::AuthorizationDenied("actor identity or writable token mismatch"));
    }
    let backend_hex = params.store.backend_identity().as_hex();
    params.receipt.verify_scope(params.snapshot, params.ticket, backend_hex)?;

    match params.staged_pack_pair {
        Some((pack_path, idx_path)) => commit_pack_with_scoped_decision(params, pack_path, idx_path).await,
        None => {
            if params.receipt.pack_locator.is_some() || params.receipt.idx_locator.is_some() {
                return Err(PushCausalError::MalformedProtocol(
                    "pack-bearing receipt requires staged_pack_pair for durable A3 hold upload".into(),
                ));
            }
            commit_metadata_with_scoped_decision(params).await
        }
    }
}

async fn commit_pack_with_scoped_decision(
    params: PgScopedPushParams<'_>,
    pack_path: &Path,
    idx_path: &Path,
) -> Result<PgScopedPushOutcome, PushCausalError> {
    let PgScopedPushParams {
        pool,
        store,
        git_binary,
        actor,
        owner_id,
        snapshot,
        ticket,
        capabilities,
        reclaim_ledger,
        receipt,
        hold_guard,
        deadline,
        ..
    } = params;

    let (pack_sha, pack_len) = sha256_and_len_sync(pack_path)?;
    let (idx_sha, idx_len) = sha256_and_len_sync(idx_path)?;
    let backend_hex = store.backend_identity().as_hex();
    let mode = commit_mode_from_capabilities(capabilities);

    let mut client = pooled_client(pool, deadline).await?;
    let baseline = PgPackCommit
        .capture_baseline(&mut client, snapshot.repository_id, snapshot.tenant_id, deadline)
        .await
        .map_err(|e| PushCausalError::StateMachine(format!("baseline capture failed: {e}")))?;
    drop(client);
    ensure_baseline_matches_snapshot(&baseline, snapshot)?;

    let producer_digest = derive_producer_digest(snapshot, ticket, mode, &pack_sha, &idx_sha);
    let plan = begin_pending_pack_plan(PendingPlanArgs {
        pool,
        actor,
        owner_id,
        snapshot,
        ticket,
        receipt,
        mode,
        pack_sha: &pack_sha,
        pack_len,
        idx_sha: &idx_sha,
        idx_len,
        baseline: &baseline,
        producer_digest,
        deadline,
    })
    .await?;
    let effective_ticket = OperationTicket { sequence: plan.identity().sequence(), ..ticket.clone() };
    receipt.sequence = effective_ticket.sequence;
    receipt.proof_digest = receipt.recompute_digest();

    let planned_pack = plan
        .packs()
        .first()
        .ok_or_else(|| PushCausalError::StateMachine("planned pack missing from PackCommitPlan".into()))?;
    acquire_and_upload_held_pair(HeldUploadArgs {
        pool,
        store,
        plan: &plan,
        pack_id: planned_pack.pack_id(),
        pack_path,
        pack_sha: &pack_sha,
        pack_len,
        idx_path,
        idx_sha: &idx_sha,
        idx_len,
        reclaim_ledger,
        hold_guard,
        deadline,
    })
    .await?;

    let adapter = PgAuthorizedCommit::new(store.clone(), git_binary.to_path_buf())
        .map_err(|_| PushCausalError::StateMachine("PgAuthorizedCommit adapter unavailable".into()))?;
    let auth_mode = match mode {
        CommitMode::Atomic => AuthorizedCommitMode::Atomic,
        CommitMode::AcceptedSubset => AuthorizedCommitMode::AcceptedSubset,
    };
    let terminal = match decide_and_commit_pack(&adapter, pool, actor, plan, auth_mode, deadline).await {
        Ok(term) => term,
        Err(err) => {
            handle_authorized_commit_err(&err, effective_ticket.operation_id, hold_guard, reclaim_ledger)?;
            return Err(map_authorized_err(err, effective_ticket.operation_id));
        }
    };

    finalize_pg_outcome(FinalizeArgs {
        snapshot,
        ticket: &effective_ticket,
        backend_hex,
        capabilities,
        revision: terminal.revision,
        kind: terminal.kind,
        refs: terminal.refs,
        receipt,
        hold_guard,
        reclaim_ledger,
    })
}

async fn commit_metadata_with_scoped_decision(
    params: PgScopedPushParams<'_>,
) -> Result<PgScopedPushOutcome, PushCausalError> {
    let PgScopedPushParams {
        pool,
        store,
        actor,
        snapshot,
        ticket,
        capabilities,
        reclaim_ledger,
        receipt,
        hold_guard,
        deadline,
        ..
    } = params;
    let pg_seq = resolve_or_reserve_pg_sequence(
        pool,
        snapshot.repository_id,
        actor.id,
        ticket.operation_id,
        &ticket.lane,
        deadline,
    )
    .await?;
    let effective_ticket = OperationTicket { sequence: pg_seq, ..ticket.clone() };
    receipt.sequence = effective_ticket.sequence;
    receipt.proof_digest = receipt.recompute_digest();

    let backend_hex = store.backend_identity().as_hex();
    let req = build_pg_commit_request(receipt, snapshot, &effective_ticket, capabilities, backend_hex)?;
    let commit_receipt = match PgAuthorizedMetadata.prepare(pool, req, actor, deadline).await {
        Ok(MetadataDecisionPreparation::Prepared(prepared)) => {
            PgAuthorizedMetadata.commit(pool, &prepared, deadline).await
        }
        Ok(MetadataDecisionPreparation::Replayed(replayed)) => Ok(*replayed),
        Err(err) => Err(err),
    };
    let committed = match commit_receipt {
        Ok(r) => r,
        Err(err) => {
            handle_authorized_commit_err(&err, effective_ticket.operation_id, hold_guard, reclaim_ledger)?;
            return Err(map_authorized_err(err, effective_ticket.operation_id));
        }
    };
    finalize_pg_outcome(FinalizeArgs {
        snapshot,
        ticket: &effective_ticket,
        backend_hex,
        capabilities,
        revision: committed.terminal.revision,
        kind: committed.terminal.kind,
        refs: committed.terminal.refs,
        receipt,
        hold_guard,
        reclaim_ledger,
    })
}

struct FinalizeArgs<'a> {
    snapshot: &'a AuthorizedSnapshotState,
    ticket: &'a OperationTicket,
    backend_hex: &'a str,
    capabilities: &'a ReceiveCapabilities,
    revision: i64,
    kind: TerminalKind,
    refs: Vec<RefCommitResult>,
    receipt: &'a mut CausalPushProofReceipt,
    hold_guard: &'a mut OperationHoldGuard,
    reclaim_ledger: Option<&'a QuarantineReclaimLedger>,
}

fn finalize_pg_outcome(args: FinalizeArgs<'_>) -> Result<PgScopedPushOutcome, PushCausalError> {
    let any_applied =
        args.kind == TerminalKind::Committed || args.refs.iter().any(|r| matches!(r, RefCommitResult::Applied { .. }));
    if any_applied {
        args.hold_guard.mark_committed()?;
        if let Some(ledger) = args.reclaim_ledger
            && ledger.load(args.ticket.operation_id)?.is_some()
        {
            ledger.transition(
                args.ticket.operation_id,
                UploadReclaimState::VerifiedPromoted,
                Vec::new(),
                0,
                "promoted via PG scoped decision commit",
            )?;
        }
    } else {
        args.hold_guard.release_on_proven_abort()?;
        if let Some(ledger) = args.reclaim_ledger
            && ledger.load(args.ticket.operation_id)?.is_some()
        {
            ledger.transition(
                args.ticket.operation_id,
                UploadReclaimState::AbortUnpromoted,
                Vec::new(),
                0,
                "PG scoped decision rejected all ref updates",
            )?;
        }
    }
    args.receipt.rebind_final_cas_terminal(
        args.snapshot,
        args.ticket,
        args.backend_hex,
        Some(args.revision),
        &args.refs,
    )?;
    let wire = report_status_from_terminal_refs(args.capabilities, &args.refs)?;
    Ok(PgScopedPushOutcome {
        committed_revision: args.revision,
        terminal_kind: args.kind,
        terminal_refs: args.refs,
        report_status_wire: wire,
    })
}

async fn decide_and_commit_pack(
    adapter: &PgAuthorizedCommit,
    pool: &Pool,
    actor: &Identity,
    plan: PackCommitPlan,
    mode: AuthorizedCommitMode,
    deadline: Instant,
) -> Result<crate::ref_store::core::pack_commit::PackCommitTerminal, AuthorizedCommitError> {
    let prepared = match adapter.prepare(pool, plan, deadline).await? {
        PrepareOutcome::Prepared(p) => p,
        PrepareOutcome::Replayed(r) => return Ok(r.terminal),
    };
    let selection = adapter.select(pool, *prepared, actor, mode, deadline).await?;
    let verified = adapter.verify(selection, deadline).await?;
    let committed = adapter.commit(pool, &verified, deadline).await?;
    Ok(committed.terminal)
}

fn ensure_baseline_matches_snapshot(
    baseline: &PackCommitBaseline,
    snapshot: &AuthorizedSnapshotState,
) -> Result<(), PushCausalError> {
    let gate = baseline.gate();
    if gate.repository_id() != snapshot.repository_id
        || gate.tenant_id() != snapshot.tenant_id
        || gate.object_format() != snapshot.object_format
        || gate.history_incarnation() != snapshot.history_incarnation
        || gate.authority_epoch() != snapshot.authority_epoch
        || gate.group_epoch() != snapshot.group_epoch
        || gate.revision() != snapshot.expected_gate_revision
    {
        return Err(PushCausalError::ProofScopeMismatch);
    }
    Ok(())
}

fn derive_producer_digest(
    snapshot: &AuthorizedSnapshotState,
    ticket: &OperationTicket,
    mode: CommitMode,
    pack_sha: &str,
    idx_sha: &str,
) -> RequestDigest {
    RequestDigest::of(
        "push-causal-pg-producer-v1",
        &[
            snapshot.repository_id.as_bytes(),
            ticket.operation_id.as_bytes(),
            mode.as_str().as_bytes(),
            pack_sha.as_bytes(),
            idx_sha.as_bytes(),
        ],
    )
}
