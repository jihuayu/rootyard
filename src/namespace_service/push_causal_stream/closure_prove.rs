//! Streaming quarantine ingest, `#180` base dependency closure verification,
//! overlapped Blob upload/verify pipeline, and `CausalPushProofReceipt` minting (#183).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::AsyncRead;
use uuid::Uuid;

use crate::blob_store::opendal::BlobStore;
use crate::ref_store::core::pack_commit::contract::VERIFIER_MAX_OBJECTS;
use crate::ref_store::core::ref_version::{VersionGraph, verify_dependency_closure};

use super::git_verify::{VerifiedPackStage, stage_and_index_quarantine_pack, verify_causal_closure_and_lfs};
use super::protocol::decode_receive_pack_stream;
use super::quarantine::{
    PushBlobCarrier, QuarantineArtifactSet, QuarantineSlot, QuarantineSweepRecord, UploadedQuarantinePack,
    ingest_pack_to_quarantine,
};
use super::receipt::{AcceptedRefProof, CausalPushProofReceipt, compute_accepted_subset_digest};
use super::reclaim::{QuarantineReclaimLedger, UploadReclaimState};
use super::types::{
    AuthorizedSnapshotState, BasePackRef, BranchPolicy, FaultInjectionHook, GitSubprocessLimits, LfsPolicy,
    OperationTicket, PackPipelineMode, PushAuthContext, PushCausalError, PushStageTelemetry, PushedRefCommand,
    ReceiveCapabilities, StreamIngestLimits,
};

/// Bundle of verification artifacts produced before committing to Ref-CAS.
#[derive(Clone, Debug)]
pub struct ProvedPushBundle {
    pub commands: Vec<PushedRefCommand>,
    pub capabilities: ReceiveCapabilities,
    pub receipt: CausalPushProofReceipt,
    pub telemetry: PushStageTelemetry,
    pub sweep_record: QuarantineSweepRecord,
}

/// Request parameters for proving a streaming Git Smart HTTP push.
pub struct StreamingProofParams<'a, R> {
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

/// Verify `#180` authority snapshot dependency closure & principal authorization for base packs.
/// Fails closed whenever base packs or non-empty refs lack a verified non-empty closure.
pub fn verify_base_packs_and_dependencies<'a>(
    snapshot: &'a AuthorizedSnapshotState,
    version_graph: Option<&VersionGraph>,
    auth: &PushAuthContext,
) -> Result<(Vec<&'a BasePackRef>, Vec<String>, String), PushCausalError> {
    auth.check_active()?;
    if snapshot.realm.tenant_id() != snapshot.tenant_id || snapshot.realm.repository_id() != snapshot.repository_id {
        return Err(PushCausalError::UnauthorizedBaseDependency(
            "snapshot realm disagrees with repository/tenant identity".into(),
        ));
    }

    let requires_closure = !snapshot.authorized_base_packs.is_empty()
        || snapshot.current_refs.values().any(|oid| !oid.bytes().all(|b| b == b'0'));
    let mut allowed_pack_entries = BTreeSet::new();
    let mut base_version_ids = BTreeSet::new();
    let base_closure_digest = match snapshot.root_version_id {
        Some(root_id) => {
            let graph = version_graph.ok_or_else(|| {
                PushCausalError::UnauthorizedBaseDependency(
                    "snapshot specifies root_version_id without VersionGraph".into(),
                )
            })?;
            let closure = verify_dependency_closure(graph, &snapshot.realm, &root_id).map_err(|e| {
                PushCausalError::UnauthorizedBaseDependency(format!("dependency closure failed: {e:?}"))
            })?;
            if closure.packs().is_empty() && requires_closure {
                return Err(PushCausalError::UnauthorizedBaseDependency(
                    "authority snapshot closure pack set is empty for non-empty repository/base set".into(),
                ));
            }
            base_version_ids.insert(closure.root().version_id().as_hex());
            for dep in closure.dependencies() {
                base_version_ids.insert(dep.version_id().as_hex());
            }
            for pack in closure.packs() {
                if pack.storage_tenant_id() != snapshot.tenant_id || pack.authority_id() != snapshot.repository_id {
                    return Err(PushCausalError::UnauthorizedBaseDependency(
                        "closure base pack belongs to another tenant or authority".into(),
                    ));
                }
                allowed_pack_entries.insert(*pack.entry());
            }
            closure.closure_digest().as_hex()
        }
        None => {
            if requires_closure {
                return Err(PushCausalError::UnauthorizedBaseDependency(
                    "base packs and non-empty snapshots require verified authority snapshot closure".into(),
                ));
            }
            let mut h = Sha256::new();
            h.update(b"empty-base-closure-v1\n");
            hex::encode(h.finalize())
        }
    };

    let mut selected = Vec::new();
    for base in &snapshot.authorized_base_packs {
        if !base.authorized_for_principal {
            return Err(PushCausalError::UnauthorizedBaseDependency(format!(
                "base version `{}` not authorized for principal",
                base.version_id
            )));
        }
        let entry = base.pack_set_entry()?;
        if !allowed_pack_entries.contains(&entry) {
            return Err(PushCausalError::UnauthorizedBaseDependency(format!(
                "base pack `{}` is outside verified #180 dependency closure",
                base.pack_id
            )));
        }
        base_version_ids.insert(base.version_id.clone());
        selected.push(base);
    }

    Ok((selected, base_version_ids.into_iter().collect(), base_closure_digest))
}

/// Stream, quarantine, upload + read-back verify, inspect thin/causal/LFS closure, and mint
/// an immutable `CausalPushProofReceipt` under a single shared end-to-end `deadline`.
pub async fn prove_streaming_push<R>(params: StreamingProofParams<'_, R>) -> Result<ProvedPushBundle, PushCausalError>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let StreamingProofParams {
        reader,
        gzipped,
        store,
        carrier,
        snapshot,
        version_graph,
        auth,
        branch_policy,
        lfs_policy,
        ticket,
        pipeline_mode,
        ingest_limits,
        proc_limits,
        reclaim_ledger,
        fault_hook,
        deadline,
    } = params;

    auth.check_active()?;
    if u64::from(ingest_limits.max_pack_objects) > VERIFIER_MAX_OBJECTS {
        return Err(PushCausalError::LimitExceeded("configured max_pack_objects exceeds VERIFIER_MAX_OBJECTS"));
    }

    let decoded = decode_receive_pack_stream(reader, gzipped, snapshot.object_format, ingest_limits, deadline).await?;
    let (authorized_bases, base_version_ids, base_closure_digest) =
        verify_base_packs_and_dependencies(snapshot, version_graph, auth)?;

    let mut slot = QuarantineSlot::create(None)?;
    let ctx = QuarantineProveCtx {
        command_bytes_read: decoded.command_bytes_read,
        commands: &decoded.commands,
        store,
        carrier,
        snapshot,
        authorized_bases: &authorized_bases,
        base_version_ids: &base_version_ids,
        base_closure_digest: &base_closure_digest,
        auth,
        branch_policy,
        lfs_policy,
        ticket,
        pipeline_mode,
        ingest_limits,
        proc_limits,
        reclaim_ledger,
        fault_hook,
        deadline,
    };
    let result = prove_inside_quarantine(&mut slot, decoded.remainder, ctx).await;

    let sweep_record = slot.sweep();
    match result {
        Ok((mut receipt, mut telemetry)) => {
            telemetry.quarantined_paths_swept = sweep_record.removed_files;
            receipt.proof_digest = receipt.recompute_digest();
            Ok(ProvedPushBundle {
                commands: decoded.commands,
                capabilities: decoded.capabilities,
                receipt,
                telemetry,
                sweep_record,
            })
        }
        Err(err) => Err(err),
    }
}

struct QuarantineProveCtx<'a> {
    command_bytes_read: usize,
    commands: &'a [PushedRefCommand],
    store: &'a BlobStore,
    carrier: &'a dyn PushBlobCarrier,
    snapshot: &'a AuthorizedSnapshotState,
    authorized_bases: &'a [&'a BasePackRef],
    base_version_ids: &'a [String],
    base_closure_digest: &'a str,
    auth: &'a PushAuthContext,
    branch_policy: &'a BranchPolicy,
    lfs_policy: &'a LfsPolicy,
    ticket: &'a OperationTicket,
    pipeline_mode: PackPipelineMode,
    ingest_limits: &'a StreamIngestLimits,
    proc_limits: &'a GitSubprocessLimits,
    reclaim_ledger: Option<&'a QuarantineReclaimLedger>,
    fault_hook: FaultInjectionHook,
    deadline: Instant,
}

async fn prove_inside_quarantine(
    slot: &mut QuarantineSlot,
    remainder: Box<dyn AsyncRead + Unpin + Send>,
    ctx: QuarantineProveCtx<'_>,
) -> Result<(CausalPushProofReceipt, PushStageTelemetry), PushCausalError> {
    let ingested = ingest_pack_to_quarantine(
        remainder,
        slot,
        ctx.snapshot.object_format,
        ctx.command_bytes_read,
        ctx.ingest_limits,
        ctx.deadline,
    )
    .await?;

    let view_dir = slot.dir().join("verify-view");
    std::fs::create_dir_all(&view_dir).map_err(|e| PushCausalError::Io(e.to_string()))?;
    let stage = stage_and_index_quarantine_pack(
        &view_dir,
        ctx.store,
        ctx.snapshot,
        ctx.authorized_bases,
        ingested.incoming_pack_path.as_deref(),
        ingested.incoming_object_count,
        ctx.ingest_limits,
        ctx.proc_limits,
        ctx.deadline,
    )
    .await?;

    if ingested.has_pack {
        slot.register_file(stage.resolved_pack_path.clone());
        slot.register_file(stage.resolved_idx_path.clone());
    }

    let (required_ancestor_oids, uploaded_opt, verify_ms, blob_upload_ms, overlap_wall_saved_ms) =
        run_verify_and_upload(&stage, &ctx, ingested.has_pack).await?;

    if let Some(ref uploaded) = uploaded_opt
        && ctx.fault_hook == FaultInjectionHook::AbortAfterBlobQuarantineUpload
    {
        slot.record_unpromoted_blob(uploaded.pack_receipt.locator());
        slot.record_unpromoted_blob(uploaded.idx_receipt.locator());
        if let Some(ledger) = ctx.reclaim_ledger {
            let paths = vec![uploaded.pack_receipt.locator().path(), uploaded.idx_receipt.locator().path()];
            let _ = ledger.transition(
                ctx.ticket.operation_id,
                UploadReclaimState::AbortUnpromoted,
                paths,
                uploaded.pack_bytes.saturating_add(uploaded.idx_bytes),
                "injected fault abort after quarantine Blob upload",
            );
        }
        return Err(PushCausalError::StateMachine(
            "injected fault abort after quarantine Blob upload; refs untouched".into(),
        ));
    }

    let accepted_updates: Vec<AcceptedRefProof> = ctx
        .commands
        .iter()
        .map(|cmd| AcceptedRefProof {
            ref_name: cmd.ref_name.clone(),
            old_oid: (!cmd.is_create()).then(|| cmd.old_oid.clone()),
            new_oid: (!cmd.is_delete()).then(|| cmd.new_oid.clone()),
            target_kind: if cmd.is_delete() {
                "delete".into()
            } else if cmd.ref_name.starts_with("refs/heads/") {
                "commit".into()
            } else {
                "object".into()
            },
        })
        .collect();
    let accepted_subset_digest = compute_accepted_subset_digest(&accepted_updates, &[]);

    let (pack_sha256, pack_bytes, idx_sha256, idx_bytes, pack_locator, idx_locator, blob_closure_digest, put_bytes) =
        match uploaded_opt {
            Some(up) => {
                let put = up.pack_bytes.saturating_add(up.idx_bytes);
                (
                    Some(up.pack_sha256),
                    up.pack_bytes,
                    Some(up.idx_sha256),
                    up.idx_bytes,
                    Some(up.pack_receipt.locator().clone()),
                    Some(up.idx_receipt.locator().clone()),
                    up.blob_closure_digest,
                    put,
                )
            }
            None => (None, 0, None, 0, None, None, "no-new-pack-verified".to_owned(), 0),
        };

    let receipt = CausalPushProofReceipt {
        receipt_version: 2,
        tenant_id: ctx.snapshot.tenant_id,
        repository_id: ctx.snapshot.repository_id,
        history_incarnation: ctx.snapshot.history_incarnation,
        authority_epoch: ctx.snapshot.authority_epoch,
        group_epoch: ctx.snapshot.group_epoch,
        object_format: ctx.snapshot.object_format,
        operation_id: ctx.ticket.operation_id,
        issuer_id: ctx.ticket.issuer_id,
        lane: ctx.ticket.lane.clone(),
        sequence: ctx.ticket.sequence,
        base_snapshot_seq: ctx.snapshot.snapshot_seq,
        expected_gate_revision: ctx.snapshot.expected_gate_revision,
        committed_gate_revision: None,
        base_version_ids: ctx.base_version_ids.to_vec(),
        required_ancestor_oids,
        resolved_thin_base_oids: stage.resolved_thin_base_oids.clone(),
        base_closure_digest: ctx.base_closure_digest.to_owned(),
        pack_sha256,
        pack_bytes,
        idx_sha256,
        idx_bytes,
        pack_locator,
        idx_locator,
        blob_backend_identity: ctx.store.backend_identity().as_hex().to_owned(),
        object_count: stage.resolved_object_count,
        delta_object_count: stage.delta_object_count,
        max_delta_chain_depth: stage.max_delta_chain_depth,
        duplicate_object_count: stage.duplicate_object_count,
        blob_closure_digest,
        accepted_updates,
        rejected_updates: Vec::new(),
        accepted_subset_digest,
        proof_digest: String::new(),
    };

    let telemetry = PushStageTelemetry {
        pipeline_mode: ctx.pipeline_mode,
        stream_wire_bytes: ingested.stream_wire_bytes,
        pack_bytes,
        idx_bytes,
        blob_put_bytes: put_bytes,
        blob_get_bytes: stage.base_get_bytes.saturating_add(put_bytes),
        stream_receive_ms: ingested.stream_receive_ms,
        verify_ms,
        blob_upload_ms,
        overlap_wall_saved_ms,
        commit_ms: 0,
        quarantined_paths_swept: 0,
    };
    Ok((receipt, telemetry))
}

async fn verify_stage(
    stage: &VerifiedPackStage,
    ctx: &QuarantineProveCtx<'_>,
) -> Result<(Vec<String>, u64), PushCausalError> {
    let t0 = Instant::now();
    let ancestors = verify_causal_closure_and_lfs(
        stage,
        ctx.store,
        ctx.snapshot,
        ctx.commands,
        ctx.auth,
        ctx.branch_policy,
        ctx.lfs_policy,
        ctx.ingest_limits,
        ctx.proc_limits,
        ctx.deadline,
    )
    .await?;
    Ok((ancestors, elapsed_ms(t0)))
}

async fn run_verify_and_upload(
    stage: &VerifiedPackStage,
    ctx: &QuarantineProveCtx<'_>,
    has_pack: bool,
) -> Result<(Vec<String>, Option<UploadedQuarantinePack>, u64, u64, u64), PushCausalError> {
    if !has_pack {
        let (ancestors, verify_ms) = verify_stage(stage, ctx).await?;
        return Ok((ancestors, None, verify_ms, 0, 0));
    }

    let artifacts = QuarantineArtifactSet {
        operation_id: ctx.ticket.operation_id,
        tenant_id: ctx.snapshot.tenant_id,
        repository_id: ctx.snapshot.repository_id,
        generation: ctx.snapshot.authority_epoch.max(1),
        pack_path: &stage.resolved_pack_path,
        idx_path: &stage.resolved_idx_path,
        reclaim_ledger: ctx.reclaim_ledger,
        fault_hook: ctx.fault_hook,
    };

    match ctx.pipeline_mode {
        PackPipelineMode::Sequential => {
            let (ancestors, verify_ms) = verify_stage(stage, ctx).await?;
            let t_u = Instant::now();
            let uploaded = ctx.carrier.upload_and_verify_closure(ctx.store, artifacts, ctx.deadline).await?;
            let upload_ms = uploaded.upload_ms.max(elapsed_ms(t_u));
            Ok((ancestors, Some(uploaded), verify_ms, upload_ms, 0))
        }
        PackPipelineMode::OverlappedPipeline => {
            let parallel_started = Instant::now();
            let verify_fut = verify_stage(stage, ctx);
            let upload_fut = async {
                let s = Instant::now();
                let up = ctx.carrier.upload_and_verify_closure(ctx.store, artifacts, ctx.deadline).await?;
                Ok::<_, PushCausalError>((up, elapsed_ms(s)))
            };
            let (v_res, u_res) = tokio::join!(verify_fut, upload_fut);
            match (v_res, u_res) {
                (Ok((ancestors, verify_ms)), Ok((uploaded, upload_ms))) => {
                    let wall_ms = elapsed_ms(parallel_started);
                    let saved = verify_ms.saturating_add(upload_ms).saturating_sub(wall_ms);
                    Ok((ancestors, Some(uploaded), verify_ms, upload_ms, saved))
                }
                (Err(v_err), Ok((uploaded, _))) => {
                    mark_unpromoted_on_abort(ctx.reclaim_ledger, ctx.ticket.operation_id, &uploaded, &v_err);
                    Err(v_err)
                }
                (_, Err(u_err)) => Err(u_err),
            }
        }
    }
}

fn mark_unpromoted_on_abort(
    ledger: Option<&QuarantineReclaimLedger>,
    operation_id: Uuid,
    uploaded: &UploadedQuarantinePack,
    err: &PushCausalError,
) {
    if let Some(ledger) = ledger {
        let paths = vec![uploaded.pack_receipt.locator().path(), uploaded.idx_receipt.locator().path()];
        let _ = ledger.transition(
            operation_id,
            UploadReclaimState::AbortUnpromoted,
            paths,
            uploaded.pack_bytes.saturating_add(uploaded.idx_bytes),
            format!("overlapped verification rejected uploaded staging pack: {err}"),
        );
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    Duration::from_nanos(started.elapsed().as_nanos().min(u64::MAX as u128) as u64).as_millis() as u64
}
