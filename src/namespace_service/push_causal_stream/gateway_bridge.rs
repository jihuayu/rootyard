//! Production `blob_git_gateway::receive` causal closure, reclaim ledger, and receipt bridge (#183).
//!
//! Keeps `src/blob_git_gateway/receive.rs` concise while enforcing:
//! - Verified non-empty authority snapshot closure (`#180`) for all base packs on non-empty repos
//! - Sibling `0700` recoverable reclaim records on partial/unknown Blob uploads (keeping `scratch_root` clean)
//! - Exact `(operation_id, snapshot, ticket, final_accepted_cas_subset)` `CausalPushProofReceipt` binding

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_git_gateway::GatewayError;
use crate::db::Identity;
use crate::ref_store::contract::{IssuerLane, RequestDigest};
use crate::ref_store::core::contract::{CommitMode, CoreGate};
use crate::ref_store::core::pack_commit::{PackArtifactRole, PackCommitTerminal, RegisteredPack};
use crate::ref_store::core::pack_snapshot::ServingReadCapture;
use crate::ref_store::core::ref_version::{
    AuthorityKind, BaseRequestSelector, CausalVersionNode, CommitSetHead, CommitSetInput, CommitSetVersionEntry,
    OperationDigestInput, PackSetEntry, RefVersionIntent, RefVersionKind, RefVersionRealm, VerifiedClosurePack,
    VersionGraph, VersionRecord, VersionRecordInput, compute_commit_set_id, compute_pack_set_digest,
    derive_candidate_version_id, operation_digest,
};
use crate::ref_store::core::terminal::RefCommitResult;
use crate::ref_store::core::types::{GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget};

use super::closure_prove::verify_base_packs_and_dependencies;
use super::receipt::{CausalPushProofReceipt, compute_accepted_subset_digest, split_terminal_subset};
use super::reclaim::{QuarantineReclaimLedger, StagingUploadIntent, UploadReclaimState};
use super::types::{AuthorizedSnapshotState, BasePackRef, OperationTicket, PushAuthContext};

const MAX_OBSERVED_RECEIPTS: usize = 64;
const GATEWAY_LANE: &str = "blob-git-receive";

static OBSERVED_GATEWAY_RECEIPTS: OnceLock<Mutex<VecDeque<(Uuid, CausalPushProofReceipt)>>> = OnceLock::new();

fn receipt_ring() -> &'static Mutex<VecDeque<(Uuid, CausalPushProofReceipt)>> {
    OBSERVED_GATEWAY_RECEIPTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_OBSERVED_RECEIPTS)))
}

/// Inspect a `CausalPushProofReceipt` minted on the production `blob_git_gateway` receive path.
pub fn recent_gateway_push_receipt(operation_id: Uuid) -> Option<CausalPushProofReceipt> {
    let guard = receipt_ring().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.iter().rev().find(|(op, _)| *op == operation_id).map(|(_, r)| r.clone())
}

/// Deterministic private `0700` reclaim ledger directory for a gateway `scratch_root`
/// (kept under system temp dir so `scratch_root` and parent worktrees stay clean).
pub fn gateway_reclaim_ledger_dir_for_scratch(scratch_root: &Path) -> PathBuf {
    let mut h = Sha256::new();
    h.update(b"gateway-reclaim-ledger-dir-v2\n");
    h.update(scratch_root.to_string_lossy().as_bytes());
    let suffix = &hex::encode(h.finalize())[..16];
    std::env::temp_dir().join(format!("rootyard-gw-reclaim-{suffix}"))
}

pub fn open_gateway_reclaim_ledger(scratch_root: &Path) -> Result<QuarantineReclaimLedger, GatewayError> {
    QuarantineReclaimLedger::open(gateway_reclaim_ledger_dir_for_scratch(scratch_root))
        .map_err(|_| GatewayError::Internal("could not open push reclaim ledger"))
}

/// Verified authority snapshot closure context captured before native `receive-pack` runs.
pub struct GatewayClosureContext {
    pub snapshot: AuthorizedSnapshotState,
    pub base_version_ids: Vec<String>,
    pub base_closure_digest: String,
}

/// Summary of a staged `(pack, idx)` pair passed from `receive.rs`.
#[derive(Clone, Debug)]
pub struct GatewayPairSummary {
    pub pack_sha256: String,
    pub pack_len: u64,
    pub idx_sha256: String,
    pub idx_len: u64,
}

/// Enforce `#183` Item 2 on `blob_git_gateway::receive`: every non-empty repository MUST carry
/// a verified non-empty `PackReadSnapshot` pack closure matching `(tenant, repo, format, backend)`.
pub fn verify_gateway_authority_closure(
    gate: &CoreGate,
    actor: &Identity,
    capture: Option<&ServingReadCapture>,
    refs: &[(String, String)],
    backend_hex: &str,
) -> Result<GatewayClosureContext, GatewayError> {
    let authority_epoch = gate.authority_epoch().max(1);
    let group_epoch = gate.group_epoch().max(1);
    let realm = RefVersionRealm::new(
        gate.tenant_id(),
        gate.repository_id(),
        gate.history_incarnation(),
        AuthorityKind::Pg,
        authority_epoch,
        0,
        group_epoch,
        gate.object_format(),
    );

    let current_refs: BTreeMap<String, String> = refs.iter().cloned().collect();
    let requires_closure = current_refs.values().any(|oid| !oid.bytes().all(|b| b == b'0'));
    let auth = PushAuthContext {
        actor_id: actor.id,
        token_scope_id: None,
        session_scope_id: None,
        lease_id: None,
        lease_expires_at_ms: None,
        now_ms: 0,
        principal_authz_epoch: authority_epoch,
        min_required_authz_epoch: authority_epoch,
        write_authorized: !actor.read_only,
        allow_force_push: true,
        allow_branch_delete: true,
        protected_branches: BTreeSet::new(),
        visible_refs: BTreeSet::new(),
    };

    if !requires_closure {
        let rev = capture.map_or_else(|| gate.revision(), ServingReadCapture::gate_revision);
        let snapshot = AuthorizedSnapshotState {
            realm,
            tenant_id: gate.tenant_id(),
            repository_id: gate.repository_id(),
            history_incarnation: gate.history_incarnation(),
            authority_epoch,
            group_epoch,
            expected_gate_revision: rev,
            object_format: gate.object_format(),
            snapshot_seq: rev,
            root_version_id: None,
            current_refs,
            authorized_base_packs: Vec::new(),
        };
        let (_, base_version_ids, base_closure_digest) = verify_base_packs_and_dependencies(&snapshot, None, &auth)
            .map_err(|_| GatewayError::Internal("empty repository base closure check failed"))?;
        return Ok(GatewayClosureContext { snapshot, base_version_ids, base_closure_digest });
    }

    let reg_snap = capture
        .and_then(ServingReadCapture::registered_snapshot)
        .ok_or(GatewayError::Internal("authority snapshot closure is absent for non-empty repository"))?;
    if reg_snap.packs().is_empty() {
        return Err(GatewayError::Internal("authority snapshot closure pack set is empty"));
    }
    if reg_snap.scope().tenant_id() != gate.tenant_id()
        || reg_snap.scope().repository_id() != gate.repository_id()
        || reg_snap.scope().history_incarnation() != gate.history_incarnation()
        || reg_snap.scope().object_format() != gate.object_format()
    {
        return Err(GatewayError::Internal("authority snapshot scope disagrees with repository gate"));
    }

    let (first_ref_name, first_oid_hex) = current_refs
        .iter()
        .find(|(_, oid)| !oid.bytes().all(|b| b == b'0'))
        .ok_or(GatewayError::Internal("missing anchor ref in non-empty snapshot"))?;
    let snap_rev = reg_snap.gate_revision().max(1);
    let (graph, root_vid, base_packs) = build_closure_graph_from_registered(
        realm,
        gate,
        snap_rev,
        reg_snap.packs(),
        first_ref_name,
        first_oid_hex,
        backend_hex,
    )?;

    let snapshot = AuthorizedSnapshotState {
        realm,
        tenant_id: gate.tenant_id(),
        repository_id: gate.repository_id(),
        history_incarnation: gate.history_incarnation(),
        authority_epoch,
        group_epoch,
        expected_gate_revision: reg_snap.gate_revision(),
        object_format: gate.object_format(),
        snapshot_seq: reg_snap.gate_revision(),
        root_version_id: Some(root_vid),
        current_refs,
        authorized_base_packs: base_packs,
    };
    let (_, base_version_ids, base_closure_digest) = verify_base_packs_and_dependencies(&snapshot, Some(&graph), &auth)
        .map_err(|_| GatewayError::Internal("authority snapshot base closure verification failed"))?;
    Ok(GatewayClosureContext { snapshot, base_version_ids, base_closure_digest })
}

fn build_closure_graph_from_registered(
    realm: RefVersionRealm,
    gate: &CoreGate,
    snap_revision: i64,
    packs: &[RegisteredPack],
    anchor_ref: &str,
    anchor_oid_hex: &str,
    backend_hex: &str,
) -> Result<(VersionGraph, crate::ref_store::core::ref_version::VersionId, Vec<BasePackRef>), GatewayError> {
    let ref_name = RefName::new(anchor_ref).map_err(|_| GatewayError::Internal("invalid snapshot ref name"))?;
    let oid = GitOid::parse(gate.object_format(), anchor_oid_hex)
        .map_err(|_| GatewayError::Internal("invalid snapshot ref oid"))?;
    let seq = snap_revision.max(1);
    let op_id = reg_op_uuid(gate.repository_id(), seq);

    let mut entries = Vec::with_capacity(packs.len());
    let mut verified_packs = Vec::with_capacity(packs.len());
    let mut base_refs_raw = Vec::with_capacity(packs.len());

    for rp in packs {
        let p_art = rp.artifact(PackArtifactRole::Pack);
        let i_art = rp.artifact(PackArtifactRole::Idx);
        if p_art.backend_identity() != backend_hex
            || i_art.backend_identity() != backend_hex
            || p_art.provider() != i_art.provider()
        {
            return Err(GatewayError::Internal("registered base pack backend identity mismatch"));
        }
        let p_loc = p_art.locator().blob_locator().map_err(|_| GatewayError::Internal("invalid base pack locator"))?;
        let i_loc = i_art.locator().blob_locator().map_err(|_| GatewayError::Internal("invalid base idx locator"))?;
        if p_loc.tenant_id() != gate.tenant_id()
            || i_loc.tenant_id() != gate.tenant_id()
            || p_loc.authority_id() != i_loc.authority_id()
            || p_loc.authority_id().is_nil()
        {
            return Err(GatewayError::Internal("registered base pack tenant or hold authority mismatch"));
        }
        let entry = PackSetEntry::new(rp.pack_id(), rp.registration_id(), *rp.artifact_set_digest().digest())
            .map_err(|_| GatewayError::Internal("invalid base PackSetEntry"))?;
        let verified_bytes = p_art.verified_length().saturating_add(i_art.verified_length()).max(2);
        // `publish.rs` binds Blob hold locators to a per-operation `hold-authority` UUID while
        // `PackReadSnapshot` authoritatively proves membership in `gate.repository_id()`.
        let vp = VerifiedClosurePack::new(
            entry,
            gate.tenant_id(),
            gate.repository_id(),
            p_art.provider(),
            p_art.backend_identity(),
            verified_bytes,
            2,
        )
        .map_err(|_| GatewayError::TooLarge)?;
        entries.push(entry);
        verified_packs.push(vp);
        base_refs_raw.push((rp, p_art, i_art, p_loc, i_loc));
    }

    let intent = RefVersionIntent::new(
        ref_name.clone(),
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::ExplicitAbsent,
        RefTarget::Oid(oid),
    );
    let lane = IssuerLane::new(GATEWAY_LANE).map_err(|_| GatewayError::Internal("invalid gateway lane"))?;
    let op_in = OperationDigestInput::new(
        realm,
        gate.tenant_id(),
        gate.tenant_id(),
        lane,
        seq,
        op_id,
        seq,
        *gate.digest(),
        CommitMode::Atomic,
        HeadUpdate::Keep,
        vec![intent],
        RequestDigest::of("gw-mem", &[&seq.to_be_bytes()]),
        Vec::new(),
    );
    let op_dig = operation_digest(&op_in).map_err(|_| GatewayError::Internal("operation_digest failed"))?;
    let vid = derive_candidate_version_id(&op_in, op_dig, &ref_name, None)
        .map_err(|_| GatewayError::Internal("derive_candidate_version_id failed"))?;
    let cs = compute_commit_set_id(&CommitSetInput::new(
        realm,
        seq,
        op_id,
        op_dig,
        vec![CommitSetVersionEntry::new(ref_name.clone(), vid, RefVersionKind::Publish, RefTarget::Oid(oid))],
        CommitSetHead::Absent,
    ))
    .map_err(|_| GatewayError::Internal("compute_commit_set_id failed"))?;
    let pack_set_digest = compute_pack_set_digest(&entries).map_err(|_| GatewayError::Internal("pack_set_digest"))?;
    let rec = VersionRecord::seal(VersionRecordInput {
        version_id: vid,
        realm,
        ref_name,
        ref_generation: 1,
        operation_id: op_id,
        operation_digest: op_dig,
        authority_seq: seq,
        kind: RefVersionKind::Publish,
        target: RefTarget::Oid(oid),
        base_version_id: None,
        object_deps: Vec::new(),
        pack_set_digest,
        commit_set_id: cs,
    })
    .map_err(|_| GatewayError::Internal("VersionRecord::seal failed"))?;

    let mut graph = VersionGraph::new();
    graph.insert_active(CausalVersionNode { record: rec, own_packs: verified_packs });
    let vid_hex = vid.as_hex();
    let base_refs = base_refs_raw
        .into_iter()
        .map(|(rp, p_art, i_art, p_loc, i_loc)| BasePackRef {
            version_id: vid_hex.clone(),
            pack_id: rp.pack_id(),
            registration_id: rp.registration_id(),
            artifact_set_digest_hex: rp.artifact_set_digest().as_hex(),
            pack_sha256: p_art.verified_sha256().as_str().to_owned(),
            pack_length: p_art.verified_length(),
            idx_sha256: i_art.verified_sha256().as_str().to_owned(),
            idx_length: i_art.verified_length(),
            pack_locator: p_loc,
            idx_locator: i_loc,
            authorized_for_principal: true,
        })
        .collect();
    Ok((graph, vid, base_refs))
}

pub fn record_gateway_staging_inflight(
    scratch_root: &Path,
    operation_id: Uuid,
    snapshot: &AuthorizedSnapshotState,
    backend_hex: &str,
    pairs: &[GatewayPairSummary],
) -> Result<(), GatewayError> {
    let Some(first) = pairs.first() else { return Ok(()) };
    let ledger = open_gateway_reclaim_ledger(scratch_root)?;
    ledger
        .record_inflight(&StagingUploadIntent {
            operation_id,
            tenant_id: snapshot.tenant_id,
            repository_id: snapshot.repository_id,
            generation: snapshot.authority_epoch.max(1),
            backend_identity: backend_hex,
            pack_sha256: &first.pack_sha256,
            pack_bytes: first.pack_len,
            idx_sha256: &first.idx_sha256,
            idx_bytes: first.idx_len,
        })
        .map(|_| ())
        .map_err(|_| GatewayError::Internal("failed to record inflight staging reclaim intent"))
}

pub fn record_gateway_reclaim_failure(scratch_root: &Path, operation_id: Uuid, error: &GatewayError) {
    let Ok(ledger) = open_gateway_reclaim_ledger(scratch_root) else { return };
    if !matches!(ledger.load(operation_id), Ok(Some(_))) {
        return;
    }
    let state = match error {
        GatewayError::OutcomeUnknown | GatewayError::Timeout => UploadReclaimState::OutcomeUnknown,
        GatewayError::Conflict(_) => UploadReclaimState::AbortUnpromoted,
        _ => UploadReclaimState::PartialFailed,
    };
    let _ = ledger.transition(operation_id, state, Vec::new(), 0, error.message());
}

/// Arguments for minting and verifying a gateway commit receipt on terminal settlement.
pub struct GatewayReceiptArgs<'a> {
    pub scratch_root: &'a Path,
    pub operation_id: Uuid,
    pub issuer_id: Uuid,
    pub closure: &'a GatewayClosureContext,
    pub pairs: &'a [GatewayPairSummary],
    pub backend_hex: &'a str,
    pub terminal: &'a PackCommitTerminal,
}

pub fn finalize_gateway_receipt(args: GatewayReceiptArgs<'_>) -> Result<CausalPushProofReceipt, GatewayError> {
    let GatewayReceiptArgs { scratch_root, operation_id, issuer_id, closure, pairs, backend_hex, terminal } = args;
    if let Ok(ledger) = open_gateway_reclaim_ledger(scratch_root)
        && matches!(ledger.load(operation_id), Ok(Some(_)))
    {
        let any_applied =
            terminal.is_committed() || terminal.refs.iter().any(|r| matches!(r, RefCommitResult::Applied { .. }));
        let state =
            if any_applied { UploadReclaimState::VerifiedPromoted } else { UploadReclaimState::AbortUnpromoted };
        let _ = ledger.transition(operation_id, state, Vec::new(), 0, "gateway terminal settled");
    }

    let ticket = OperationTicket { issuer_id, lane: GATEWAY_LANE.to_owned(), sequence: 1, operation_id };
    let (accepted_init, rejected_init) = split_terminal_subset(&terminal.refs);
    let init_subset_digest = compute_accepted_subset_digest(&accepted_init, &rejected_init);
    let committed_rev = terminal.is_committed().then_some(terminal.revision);
    let first = pairs.first();
    let mut receipt = CausalPushProofReceipt {
        receipt_version: 2,
        tenant_id: closure.snapshot.tenant_id,
        repository_id: closure.snapshot.repository_id,
        history_incarnation: closure.snapshot.history_incarnation,
        authority_epoch: closure.snapshot.authority_epoch,
        group_epoch: closure.snapshot.group_epoch,
        object_format: closure.snapshot.object_format,
        operation_id,
        issuer_id,
        lane: ticket.lane.clone(),
        sequence: ticket.sequence,
        base_snapshot_seq: closure.snapshot.snapshot_seq,
        expected_gate_revision: closure.snapshot.expected_gate_revision,
        committed_gate_revision: committed_rev,
        base_version_ids: closure.base_version_ids.clone(),
        required_ancestor_oids: Vec::new(),
        resolved_thin_base_oids: Vec::new(),
        base_closure_digest: closure.base_closure_digest.clone(),
        pack_sha256: first.map(|p| p.pack_sha256.clone()),
        pack_bytes: first.map_or(0, |p| p.pack_len),
        idx_sha256: first.map(|p| p.idx_sha256.clone()),
        idx_bytes: first.map_or(0, |p| p.idx_len),
        pack_locator: None,
        idx_locator: None,
        blob_backend_identity: backend_hex.to_owned(),
        object_count: 0,
        delta_object_count: 0,
        max_delta_chain_depth: 0,
        duplicate_object_count: 0,
        blob_closure_digest: first
            .map_or_else(|| "no-new-pack".into(), |p| format!("{}:{}", p.pack_sha256, p.idx_sha256)),
        accepted_updates: accepted_init,
        rejected_updates: rejected_init,
        accepted_subset_digest: init_subset_digest,
        proof_digest: String::new(),
    };
    receipt.proof_digest = receipt.recompute_digest();
    receipt
        .rebind_final_cas_terminal(&closure.snapshot, &ticket, backend_hex, committed_rev, &terminal.refs)
        .map_err(|_| GatewayError::Internal("gateway commit receipt failed CAS subset binding"))?;

    let mut ring = receipt_ring().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if ring.len() >= MAX_OBSERVED_RECEIPTS {
        ring.pop_front();
    }
    ring.push_back((operation_id, receipt.clone()));
    Ok(receipt)
}

fn reg_op_uuid(repo: Uuid, seq: i64) -> Uuid {
    let mut h = Sha256::new();
    h.update(b"gw-snapshot-closure-op-v1\0");
    h.update(repo.as_bytes());
    h.update(seq.to_be_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Uuid::from_bytes(b)
}
