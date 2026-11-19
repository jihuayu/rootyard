//! Authoritative PostgreSQL sequence + post-CAS snapshot binding and durable restart replay (#183).
//!
//! Reconstructs and verifies `CausalPushProofReceipt` directly from immutable PostgreSQL
//! (`ref_store_operations.sequence`, `ref_store_publication_decisions.base_revision`,
//! `ref_store_core_events`, `ref_store_core_pack_memberships`, `artifact_holds`) and
//! `BlobStore` `.pack`/`.idx` artifacts (`0..=8` pairs), ensuring byte-for-byte identical
//! receipt materialization on fresh settlement and across full server process restarts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use deadpool_postgres::{Client, Pool};
use serde_json::Value;
use tokio::time::{Instant as TokioInstant, timeout_at};
use uuid::Uuid;

use crate::blob_git_gateway::GatewayError;
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::core::pack_commit::PackCommitTerminal;
use crate::ref_store::core::ref_version::{AuthorityKind, RefVersionRealm};

use super::closure_prove::verify_base_packs_and_dependencies;
use super::gateway_bridge::{
    ClosureGraphSpec, build_closure_graph_from_spec, gateway_auth_context, open_gateway_reclaim_ledger,
    push_observed_gateway_receipt,
};
use super::gateway_durable_sql::{
    DecisionMeta, load_all_operation_pack_pairs, load_decision_or_gate_meta, load_historical_pack_descs,
    load_historical_refs_at_revision,
};
use super::gateway_prover::{CommittedBlobProofArgs, GatewayObjectClosureProof, prove_committed_blob_pairs_closure};
use super::receipt::{
    CausalPushProofReceipt, compute_accepted_subset_digest, compute_multi_pair_closure_digest, split_terminal_subset,
};
use super::reclaim::UploadReclaimState;
use super::reclaim_sweeper::settle_aborted_gateway_reclaim;
use super::types::{AuthorizedSnapshotState, OperationTicket, PushCausalError};

/// Arguments for durable PG-backed receipt settlement and post-restart replay.
pub struct DurableGatewayReceiptArgs<'a> {
    pub pool: &'a Pool,
    pub store: &'a BlobStore,
    pub git_binary: &'a Path,
    pub scratch_root: Option<&'a Path>,
    pub sandbox_root: Option<&'a Path>,
    pub repository_id: Uuid,
    /// Stable public operation identity. This is the receipt/ring key and the
    /// identity rendered to callers.
    pub operation_id: Uuid,
    /// Exact private migration-152 attempt that owns the durable migration-138
    /// operation, decision, pack registrations and event rows. `None` is the
    /// legacy one-identity path. This is never derived from, or written into,
    /// the public identity.
    pub private_operation_id: Option<Uuid>,
    pub deadline: TokioInstant,
}

/// Settle or deterministically replay a `CausalPushProofReceipt` from authoritative PG17 + `BlobStore`.
pub async fn materialize_durable_gateway_receipt(
    args: DurableGatewayReceiptArgs<'_>,
) -> Result<CausalPushProofReceipt, GatewayError> {
    let maybe = load_durable_gateway_push_receipt(&args)
        .await
        .map_err(|_| GatewayError::Internal("failed to materialize durable gateway causal receipt"))?;
    maybe.ok_or(GatewayError::Internal("durable operation terminal missing in PostgreSQL"))
}

/// Load and verify the durable `CausalPushProofReceipt` for `(repository_id, operation_id)` directly
/// from PostgreSQL + `BlobStore` (zero dependency on in-process state; survives process restarts).
pub async fn load_durable_gateway_push_receipt(
    args: &DurableGatewayReceiptArgs<'_>,
) -> Result<Option<CausalPushProofReceipt>, PushCausalError> {
    let durable_operation_id = args.private_operation_id.unwrap_or(args.operation_id);
    if durable_operation_id.is_nil()
        || (args.private_operation_id.is_some() && durable_operation_id == args.operation_id)
    {
        return Err(PushCausalError::StateMachine("durable gateway operation identity is invalid".into()));
    }
    let client = timeout_at(args.deadline, args.pool.get())
        .await
        .map_err(|_| PushCausalError::DeadlineExceeded)?
        .map_err(|e| PushCausalError::Io(e.to_string()))?;

    let op_row = timeout_at(
        args.deadline,
        client.query_opt(
            "SELECT issuer_id, lane, sequence, state, terminal_result
             FROM ref_store_operations
             WHERE repository_id = $1 AND operation_id = $2",
            &[&args.repository_id, &durable_operation_id],
        ),
    )
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
    .map_err(|e| PushCausalError::Io(e.to_string()))?;
    let Some(op_row) = op_row else {
        return Ok(None);
    };

    let issuer_id: Uuid = op_row.get(0);
    let lane: String = op_row.get(1);
    let sequence: i64 = op_row.get(2);
    let state: String = op_row.get(3);
    let terminal_val: Option<Value> = op_row.get(4);
    if !matches!(state.as_str(), "committed" | "rejected") {
        return Ok(None);
    }
    let terminal_json =
        terminal_val.ok_or_else(|| PushCausalError::StateMachine("missing terminal_result JSON".into()))?;
    let terminal: PackCommitTerminal =
        serde_json::from_value(terminal_json).map_err(|e| PushCausalError::Io(e.to_string()))?;

    let meta =
        load_decision_or_gate_meta(&client, args.repository_id, durable_operation_id, &terminal, args.deadline)
            .await?;
    let current_refs =
        load_historical_refs_at_revision(&client, args.repository_id, meta.base_revision, args.deadline).await?;
    let backend_hex = args.store.backend_identity().as_hex();
    let (snapshot, base_version_ids, base_closure_digest) = build_post_cas_snapshot(
        &client,
        args.repository_id,
        &meta,
        issuer_id,
        current_refs,
        backend_hex,
        args.deadline,
    )
    .await?;

    let (pack_pairs, all_hold_paths) =
        load_all_operation_pack_pairs(&client, args.repository_id, durable_operation_id, args.deadline).await?;
    drop(client);

    if let Some(sr) = args.scratch_root {
        if terminal.is_committed() {
            if let Ok(ledger) = open_gateway_reclaim_ledger(sr)
                && matches!(ledger.load(args.operation_id), Ok(Some(_)))
            {
                let bytes: u64 = pack_pairs.iter().map(|p| p.pack_bytes.saturating_add(p.idx_bytes)).sum();
                let _ = ledger.transition(
                    args.operation_id,
                    UploadReclaimState::VerifiedPromoted,
                    all_hold_paths,
                    bytes,
                    "gateway terminal committed",
                );
            }
        } else {
            let _ = settle_aborted_gateway_reclaim(
                args.pool,
                sr,
                args.repository_id,
                args.operation_id,
                backend_hex,
                UploadReclaimState::AbortUnpromoted,
                "gateway terminal rejected",
            )
            .await;
        }
    }

    let obj_proof = if terminal.is_committed() {
        let std_dl = to_std_dl(args.deadline)?;
        let base_tips: Vec<String> = snapshot
            .current_refs
            .values()
            .filter(|oid| !oid.bytes().all(|b| b == b'0'))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        prove_committed_blob_pairs_closure(CommittedBlobProofArgs {
            git_binary: args.git_binary,
            scratch_root: args.sandbox_root.or(args.scratch_root),
            store: args.store,
            format: meta.object_format,
            base_packs: &snapshot.authorized_base_packs,
            base_tips: &base_tips,
            committed_pairs: &pack_pairs,
            terminal_refs: &terminal.refs,
            deadline: std_dl,
        })
        .await?
    } else {
        GatewayObjectClosureProof::default()
    };

    let ticket = OperationTicket { issuer_id, lane: lane.clone(), sequence, operation_id: args.operation_id };
    let (accepted_init, rejected_init) = split_terminal_subset(&terminal.refs);
    let init_subset_digest = compute_accepted_subset_digest(&accepted_init, &rejected_init);
    let committed_rev = terminal.is_committed().then_some(terminal.revision);
    let first = pack_pairs.first();
    let blob_dig = compute_multi_pair_closure_digest(&pack_pairs);

    let mut receipt = CausalPushProofReceipt {
        receipt_version: 2,
        tenant_id: snapshot.tenant_id,
        repository_id: snapshot.repository_id,
        history_incarnation: snapshot.history_incarnation,
        authority_epoch: snapshot.authority_epoch,
        group_epoch: snapshot.group_epoch,
        object_format: snapshot.object_format,
        operation_id: args.operation_id,
        issuer_id,
        lane,
        sequence,
        base_snapshot_seq: snapshot.snapshot_seq,
        expected_gate_revision: snapshot.expected_gate_revision,
        committed_gate_revision: committed_rev,
        base_version_ids,
        required_ancestor_oids: obj_proof.required_ancestor_oids,
        resolved_thin_base_oids: obj_proof.resolved_thin_base_oids,
        base_closure_digest,
        pack_sha256: first.map(|p| p.pack_sha256.clone()),
        pack_bytes: first.map_or(0, |p| p.pack_bytes),
        idx_sha256: first.map(|p| p.idx_sha256.clone()),
        idx_bytes: first.map_or(0, |p| p.idx_bytes),
        pack_locator: first.and_then(|p| p.pack_locator.clone()),
        idx_locator: first.and_then(|p| p.idx_locator.clone()),
        pack_pairs,
        blob_backend_identity: backend_hex.to_owned(),
        object_count: obj_proof.object_count,
        delta_object_count: obj_proof.delta_object_count,
        max_delta_chain_depth: obj_proof.max_delta_chain_depth,
        duplicate_object_count: obj_proof.duplicate_object_count,
        blob_closure_digest: blob_dig,
        accepted_updates: accepted_init,
        rejected_updates: rejected_init,
        accepted_subset_digest: init_subset_digest,
        proof_digest: String::new(),
    };
    receipt.proof_digest = receipt.recompute_digest();
    receipt.rebind_final_cas_terminal(&snapshot, &ticket, backend_hex, committed_rev, &terminal.refs)?;
    push_observed_gateway_receipt(args.operation_id, receipt.clone());
    Ok(Some(receipt))
}

async fn build_post_cas_snapshot(
    client: &Client,
    repository_id: Uuid,
    meta: &DecisionMeta,
    issuer_id: Uuid,
    current_refs: BTreeMap<String, String>,
    backend_hex: &str,
    deadline: TokioInstant,
) -> Result<(AuthorizedSnapshotState, Vec<String>, String), PushCausalError> {
    let realm = RefVersionRealm::new(
        meta.tenant_id,
        repository_id,
        meta.history_incarnation,
        AuthorityKind::Pg,
        meta.authority_epoch,
        0,
        meta.group_epoch,
        meta.object_format,
    );
    let auth = gateway_auth_context(issuer_id, meta.authority_epoch, true);
    let requires_closure = current_refs.values().any(|oid| !oid.bytes().all(|b| b == b'0'));
    if !requires_closure {
        let snap = AuthorizedSnapshotState {
            realm,
            tenant_id: meta.tenant_id,
            repository_id,
            history_incarnation: meta.history_incarnation,
            authority_epoch: meta.authority_epoch,
            group_epoch: meta.group_epoch,
            expected_gate_revision: meta.base_revision,
            object_format: meta.object_format,
            snapshot_seq: meta.base_revision,
            root_version_id: None,
            current_refs,
            authorized_base_packs: Vec::new(),
        };
        let (_, vids, dig) = verify_base_packs_and_dependencies(&snap, None, &auth)?;
        return Ok((snap, vids, dig));
    }

    let raw_packs = load_historical_pack_descs(client, repository_id, meta.base_revision, deadline).await?;
    let (anchor_ref, anchor_oid) = current_refs
        .iter()
        .find(|(_, oid)| !oid.bytes().all(|b| b == b'0'))
        .ok_or_else(|| PushCausalError::StateMachine("missing anchor ref in non-empty base".into()))?;
    let (graph, root_vid, base_packs) = build_closure_graph_from_spec(ClosureGraphSpec {
        realm,
        tenant_id: meta.tenant_id,
        repository_id,
        object_format: meta.object_format,
        snap_revision: meta.base_revision,
        gate_digest: meta.base_gate_digest,
        packs: &raw_packs,
        anchor_ref,
        anchor_oid_hex: anchor_oid,
        backend_hex,
    })
    .map_err(|_| PushCausalError::UnauthorizedBaseDependency("post-CAS snapshot closure build failed".into()))?;

    let snap = AuthorizedSnapshotState {
        realm,
        tenant_id: meta.tenant_id,
        repository_id,
        history_incarnation: meta.history_incarnation,
        authority_epoch: meta.authority_epoch,
        group_epoch: meta.group_epoch,
        expected_gate_revision: meta.base_revision,
        object_format: meta.object_format,
        snapshot_seq: meta.base_revision,
        root_version_id: Some(root_vid),
        current_refs,
        authorized_base_packs: base_packs,
    };
    let (_, vids, dig) = verify_base_packs_and_dependencies(&snap, Some(&graph), &auth)?;
    Ok((snap, vids, dig))
}

fn to_std_dl(dl: TokioInstant) -> Result<Instant, PushCausalError> {
    let now = TokioInstant::now();
    let rem =
        dl.checked_duration_since(now).filter(|d| *d > Duration::ZERO).ok_or(PushCausalError::DeadlineExceeded)?;
    Ok(Instant::now() + rem)
}
