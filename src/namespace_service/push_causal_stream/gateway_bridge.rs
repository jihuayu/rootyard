//! Production `blob_git_gateway::receive` causal closure, reclaim ledger, and receipt ring (#183).
//!
//! Keeps `src/blob_git_gateway/receive.rs` concise while enforcing:
//! - Verified non-empty authority snapshot closure (`#180`) for all base packs on non-empty repos
//! - Private `0700` recoverable reclaim records across ALL `0..=8` staged `.pack`/`.idx` pairs
//! - Observable receipt ring populated on both fresh settlement and durable PostgreSQL replay

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_git_gateway::GatewayError;
use crate::blob_store::BlobLocator;
use crate::db::Identity;
use crate::ref_store::contract::{IssuerLane, RequestDigest};
use crate::ref_store::core::contract::{CommitMode, CoreGate};
use crate::ref_store::core::pack_commit::{PackArtifactRole, RegisteredPack};
use crate::ref_store::core::pack_snapshot::ServingReadCapture;
use crate::ref_store::core::ref_version::{
    AuthorityKind, BaseRequestSelector, CausalVersionNode, CommitSetHead, CommitSetInput, CommitSetVersionEntry,
    OperationDigestInput, PackSetEntry, RefVersionIntent, RefVersionKind, RefVersionRealm, VerifiedClosurePack,
    VersionGraph, VersionId, VersionRecord, VersionRecordInput, compute_commit_set_id, compute_pack_set_digest,
    derive_candidate_version_id, operation_digest,
};
use crate::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget};

use super::closure_prove::verify_base_packs_and_dependencies;
use super::receipt::CausalPushProofReceipt;
use super::reclaim::{QuarantineReclaimLedger, StagedPairDigest, UploadReclaimState};
use super::types::{AuthorizedSnapshotState, BasePackRef, PushAuthContext};

const MAX_OBSERVED_RECEIPTS: usize = 64;
pub(super) const GATEWAY_CLOSURE_LANE: &str = "blob-git-receive";

static OBSERVED_GATEWAY_RECEIPTS: OnceLock<Mutex<VecDeque<(Uuid, CausalPushProofReceipt)>>> = OnceLock::new();

fn receipt_ring() -> &'static Mutex<VecDeque<(Uuid, CausalPushProofReceipt)>> {
    OBSERVED_GATEWAY_RECEIPTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_OBSERVED_RECEIPTS)))
}

/// Inspect a `CausalPushProofReceipt` minted or replayed on the production `blob_git_gateway` path.
pub fn recent_gateway_push_receipt(operation_id: Uuid) -> Option<CausalPushProofReceipt> {
    let guard = receipt_ring().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.iter().rev().find(|(op, _)| *op == operation_id).map(|(_, r)| r.clone())
}

/// Clear the in-process receipt cache (used to prove durable post-restart replay from PG + Blob).
pub fn clear_observed_gateway_receipts() {
    let mut guard = receipt_ring().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.clear();
}

pub(super) fn push_observed_gateway_receipt(operation_id: Uuid, receipt: CausalPushProofReceipt) {
    let mut ring = receipt_ring().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if ring.len() >= MAX_OBSERVED_RECEIPTS {
        ring.pop_front();
    }
    ring.push_back((operation_id, receipt));
}

/// Deterministic private `0700` reclaim ledger directory for a gateway `scratch_root`.
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

/// Summary of one staged `(pack, idx)` pair (`0..=8` pairs per operation).
#[derive(Clone, Debug)]
pub struct GatewayPairSummary {
    pub pack_sha256: String,
    pub pack_len: u64,
    pub idx_sha256: String,
    pub idx_len: u64,
}

pub(super) struct RawClosurePackDesc {
    pub(super) pack_id: Uuid,
    pub(super) registration_id: Uuid,
    pub(super) artifact_set_digest_hex: String,
    pub(super) provider: String,
    pub(super) backend_identity: String,
    pub(super) pack_sha256: String,
    pub(super) pack_length: u64,
    pub(super) idx_sha256: String,
    pub(super) idx_length: u64,
    pub(super) pack_locator: BlobLocator,
    pub(super) idx_locator: BlobLocator,
}

pub(super) struct ClosureGraphSpec<'a> {
    pub(super) realm: RefVersionRealm,
    pub(super) tenant_id: Uuid,
    pub(super) repository_id: Uuid,
    pub(super) object_format: GitObjectFormat,
    pub(super) snap_revision: i64,
    pub(super) gate_digest: RequestDigest,
    pub(super) packs: &'a [RawClosurePackDesc],
    pub(super) anchor_ref: &'a str,
    pub(super) anchor_oid_hex: &'a str,
    pub(super) backend_hex: &'a str,
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
    let auth = gateway_auth_context(actor.id, authority_epoch, !actor.read_only);

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

    let raw_packs = registered_to_raw_descs(reg_snap.packs())?;
    let gate_digest = RequestDigest::from_str(reg_snap.gate_digest_hex()).unwrap_or_else(|_| *gate.digest());
    let (anchor_ref, anchor_oid) = current_refs
        .iter()
        .find(|(_, oid)| !oid.bytes().all(|b| b == b'0'))
        .ok_or(GatewayError::Internal("missing anchor ref in non-empty snapshot"))?;
    let (graph, root_vid, base_packs) = build_closure_graph_from_spec(ClosureGraphSpec {
        realm,
        tenant_id: gate.tenant_id(),
        repository_id: gate.repository_id(),
        object_format: gate.object_format(),
        snap_revision: reg_snap.gate_revision().max(1),
        gate_digest,
        packs: &raw_packs,
        anchor_ref,
        anchor_oid_hex: anchor_oid,
        backend_hex,
    })?;

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

pub(super) fn gateway_auth_context(actor_id: Uuid, epoch: i64, writable: bool) -> PushAuthContext {
    PushAuthContext {
        actor_id,
        token_scope_id: None,
        session_scope_id: None,
        lease_id: None,
        lease_expires_at_ms: None,
        now_ms: 0,
        principal_authz_epoch: epoch.max(1),
        min_required_authz_epoch: epoch.max(1),
        write_authorized: writable,
        allow_force_push: true,
        allow_branch_delete: true,
        protected_branches: BTreeSet::new(),
        visible_refs: BTreeSet::new(),
    }
}

fn registered_to_raw_descs(packs: &[RegisteredPack]) -> Result<Vec<RawClosurePackDesc>, GatewayError> {
    let mut out = Vec::with_capacity(packs.len());
    for rp in packs {
        let p_art = rp.artifact(PackArtifactRole::Pack);
        let i_art = rp.artifact(PackArtifactRole::Idx);
        if p_art.provider() != i_art.provider() {
            return Err(GatewayError::Internal("registered pack/idx provider mismatch"));
        }
        let p_loc = p_art.locator().blob_locator().map_err(|_| GatewayError::Internal("invalid base pack locator"))?;
        let i_loc = i_art.locator().blob_locator().map_err(|_| GatewayError::Internal("invalid base idx locator"))?;
        out.push(RawClosurePackDesc {
            pack_id: rp.pack_id(),
            registration_id: rp.registration_id(),
            artifact_set_digest_hex: rp.artifact_set_digest().as_hex(),
            provider: p_art.provider().to_owned(),
            backend_identity: p_art.backend_identity().to_owned(),
            pack_sha256: p_art.verified_sha256().as_str().to_owned(),
            pack_length: p_art.verified_length(),
            idx_sha256: i_art.verified_sha256().as_str().to_owned(),
            idx_length: i_art.verified_length(),
            pack_locator: p_loc,
            idx_locator: i_loc,
        });
    }
    Ok(out)
}

pub(super) fn build_closure_graph_from_spec(
    spec: ClosureGraphSpec<'_>,
) -> Result<(VersionGraph, VersionId, Vec<BasePackRef>), GatewayError> {
    let ref_name = RefName::new(spec.anchor_ref).map_err(|_| GatewayError::Internal("invalid snapshot ref name"))?;
    let oid = GitOid::parse(spec.object_format, spec.anchor_oid_hex)
        .map_err(|_| GatewayError::Internal("invalid snapshot ref oid"))?;
    let seq = spec.snap_revision.max(1);
    let op_id = reg_op_uuid(spec.repository_id, seq);

    let mut entries = Vec::with_capacity(spec.packs.len());
    let mut verified_packs = Vec::with_capacity(spec.packs.len());
    for rp in spec.packs {
        if rp.backend_identity != spec.backend_hex {
            return Err(GatewayError::Internal("registered base pack backend identity mismatch"));
        }
        if rp.pack_locator.tenant_id() != spec.tenant_id
            || rp.idx_locator.tenant_id() != spec.tenant_id
            || rp.pack_locator.authority_id() != rp.idx_locator.authority_id()
            || rp.pack_locator.authority_id().is_nil()
        {
            return Err(GatewayError::Internal("registered base pack tenant or hold authority mismatch"));
        }
        let art_dig = RequestDigest::from_str(&rp.artifact_set_digest_hex)
            .map_err(|_| GatewayError::Internal("invalid base artifact_set_digest"))?;
        let entry = PackSetEntry::new(rp.pack_id, rp.registration_id, art_dig)
            .map_err(|_| GatewayError::Internal("invalid base PackSetEntry"))?;
        let verified_bytes = rp.pack_length.saturating_add(rp.idx_length).max(2);
        let vp = VerifiedClosurePack::new(
            entry,
            spec.tenant_id,
            spec.repository_id,
            rp.provider.clone(),
            rp.backend_identity.clone(),
            verified_bytes,
            2,
        )
        .map_err(|_| GatewayError::TooLarge)?;
        entries.push(entry);
        verified_packs.push(vp);
    }

    let intent = RefVersionIntent::new(
        ref_name.clone(),
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::ExplicitAbsent,
        RefTarget::Oid(oid),
    );
    let lane = IssuerLane::new(GATEWAY_CLOSURE_LANE).map_err(|_| GatewayError::Internal("invalid gateway lane"))?;
    let op_in = OperationDigestInput::new(
        spec.realm,
        spec.tenant_id,
        spec.tenant_id,
        lane,
        seq,
        op_id,
        seq,
        spec.gate_digest,
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
        spec.realm,
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
        realm: spec.realm,
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
    let base_refs = spec
        .packs
        .iter()
        .map(|rp| BasePackRef {
            version_id: vid_hex.clone(),
            pack_id: rp.pack_id,
            registration_id: rp.registration_id,
            artifact_set_digest_hex: rp.artifact_set_digest_hex.clone(),
            pack_sha256: rp.pack_sha256.clone(),
            pack_length: rp.pack_length,
            idx_sha256: rp.idx_sha256.clone(),
            idx_length: rp.idx_length,
            pack_locator: rp.pack_locator.clone(),
            idx_locator: rp.idx_locator.clone(),
            authorized_for_principal: true,
        })
        .collect();
    Ok((graph, vid, base_refs))
}

/// Record ALL `0..=8` staged `.pack`/`.idx` pairs in `QuarantineReclaimLedger` before Blob upload.
pub fn record_gateway_staging_inflight(
    scratch_root: &Path,
    operation_id: Uuid,
    snapshot: &AuthorizedSnapshotState,
    backend_hex: &str,
    pairs: &[GatewayPairSummary],
) -> Result<(), GatewayError> {
    if pairs.is_empty() {
        return Ok(());
    }
    let staged: Vec<StagedPairDigest> = pairs
        .iter()
        .map(|p| StagedPairDigest {
            pack_sha256: p.pack_sha256.clone(),
            pack_bytes: p.pack_len,
            idx_sha256: p.idx_sha256.clone(),
            idx_bytes: p.idx_len,
        })
        .collect();
    let ledger = open_gateway_reclaim_ledger(scratch_root)?;
    ledger
        .record_inflight_multi(
            operation_id,
            snapshot.tenant_id,
            snapshot.repository_id,
            snapshot.authority_epoch.max(1),
            backend_hex,
            &staged,
        )
        .map(|_| ())
        .map_err(|_| GatewayError::Internal("failed to record inflight staging reclaim intent"))
}

pub fn record_gateway_reclaim_failure(scratch_root: &Path, operation_id: Uuid, error: &GatewayError) {
    let Ok(ledger) = open_gateway_reclaim_ledger(scratch_root) else { return };
    if !matches!(ledger.load(operation_id), Ok(Some(_))) {
        return;
    }
    let state = classify_gateway_reclaim_error(error);
    let _ = ledger.transition(operation_id, state, Vec::new(), 0, error.message());
}

pub fn classify_gateway_reclaim_error(error: &GatewayError) -> UploadReclaimState {
    match error {
        GatewayError::OutcomeUnknown | GatewayError::Timeout => UploadReclaimState::OutcomeUnknown,
        GatewayError::Conflict(_) => UploadReclaimState::AbortUnpromoted,
        _ => UploadReclaimState::PartialFailed,
    }
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
