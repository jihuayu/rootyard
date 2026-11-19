//! Production DistributedRefCas cutpoint capture for the scheduled `storage_lifecycle` worker (#122).
//!
//! The scheduled worker must mint a fresh [`RefCasReconciledCut`] from an authoritative
//! `RefCasStateMachine` on every maintenance pass; a PostgreSQL `ref_store_core_refs.revision`
//! sequence or a stale journal-embedded cut can never authorize `DistributedRefCas` deletion.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, RwLock, Weak},
};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::ref_store::core::artifact_hold::reconcile_proof::{
    AttestedGroupSnapshotDto, GROUP_KEYRING_ENV, GroupVoterSignatureDto,
};
use crate::ref_store::core::state_machine::{RefCasLogEntry, RefCasSnapshot, RefCasStateMachine};

use super::{
    SafeGcError,
    dist_auth::{
        QuorumCommitEvidence, SafeGcEd25519Signer, SafeGcRepoTrustConfig, compute_holds_digest,
        restore_attested_state_machine, sign_snapshot_with_keyring_dir, verify_attested_snapshot_with_keyring,
    },
    model::{AuthorityLane, GcMode, SafeGcArmReceipt, SourceFreshness},
    refcas_cut::{RefCasReconciledCut, reconcile_refcas_cut_with_pg},
    store::{DurableSafeGcAuthority, SafeGcRepoSnapshot},
};

/// Sealed on-volume Ref-CAS quorum state-machine envelope consumed by the
/// scheduled maintenance worker (`<storage_root>/safe-gc/refcas/<repo_id>.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedRefCasCutpointEnvelope {
    pub group_id: i64,
    pub snapshot: RefCasSnapshot,
    #[serde(default)]
    pub wal_tail: Vec<RefCasLogEntry>,
    #[serde(default)]
    pub quorum_attestation: Option<AttestedGroupSnapshotDto>,
}

/// Canonical on-volume path of the sealed Ref-CAS cutpoint envelope for one repository.
pub fn safe_gc_refcas_cutpoint_path(storage_root: &Path, repo_id: Uuid) -> PathBuf {
    storage_root.join("safe-gc").join("refcas").join(format!("{repo_id}.json"))
}

fn resolve_keyring_dir(storage_root: &Path, repo_id: Uuid) -> Option<PathBuf> {
    SafeGcRepoTrustConfig::load(storage_root, repo_id)
        .ok()
        .and_then(|trust| trust.refcas_keyring_dir.map(PathBuf::from))
        .or_else(|| std::env::var_os(GROUP_KEYRING_ENV).map(PathBuf::from))
        .filter(|dir| dir.is_dir())
}

fn mint_cutpoint_attestation(
    storage_root: &Path,
    repo_id: Uuid,
    group_id: i64,
    snapshot: &RefCasSnapshot,
) -> Result<Option<AttestedGroupSnapshotDto>, SafeGcError> {
    let Some(keyring_dir) = resolve_keyring_dir(storage_root, repo_id) else {
        return Ok(None);
    };
    let Some(gate) = snapshot.body.gates.iter().find(|gate| gate.repository_id == repo_id) else {
        return Ok(None);
    };
    if snapshot.body.last_applied.is_none() {
        return Ok(None);
    }
    let attested = sign_snapshot_with_keyring_dir(
        &keyring_dir,
        group_id,
        gate.history_incarnation,
        gate.group_epoch,
        gate.authority_epoch,
        snapshot,
    )?;
    Ok(Some(attested))
}

/// Atomically persist a sealed `RefCasSnapshot` plus any WAL tail for worker cutpoint capture.
pub fn persist_refcas_cutpoint_snapshot(
    storage_root: &Path,
    repo_id: Uuid,
    group_id: i64,
    sm: &RefCasStateMachine,
    wal_tail: &[RefCasLogEntry],
) -> Result<PathBuf, SafeGcError> {
    if group_id < 0 {
        return Err(SafeGcError::InvalidInput("Ref-CAS cutpoint group_id must be non-negative".into()));
    }
    let Ok(snapshot) = sm.snapshot() else {
        return Err(SafeGcError::IncompleteProof("failed sealing RefCasSnapshot"));
    };
    if snapshot.verify_integrity().is_err() {
        return Err(SafeGcError::IncompleteProof("failed verifying RefCasSnapshot"));
    }
    let quorum_attestation = mint_cutpoint_attestation(storage_root, repo_id, group_id, &snapshot)?;
    let path = safe_gc_refcas_cutpoint_path(storage_root, repo_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SafeGcError::Io(e.to_string()))?;
    }
    let envelope =
        PersistedRefCasCutpointEnvelope { group_id, snapshot, wal_tail: wal_tail.to_vec(), quorum_attestation };
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| SafeGcError::Serialization(e.to_string()))?;
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    std::fs::write(&tmp, &bytes).map_err(|e| SafeGcError::Io(e.to_string()))?;
    std::fs::rename(&tmp, &path).map_err(|e| SafeGcError::Io(e.to_string()))?;
    Ok(path)
}

#[path = "refcas_publisher.rs"]
mod publisher;

pub use publisher::RefCasCommitCutpointPublisher;

/// Authoritative source of quorum-committed `RefCasStateMachine` state used by
/// the scheduled `storage_lifecycle` worker to mint fresh `RefCasReconciledCut`s.
pub trait RefCasCutpointSource: Send + Sync {
    fn capture_state_machine(&self, repo_id: Uuid) -> Result<Option<(i64, RefCasStateMachine)>, SafeGcError>;

    fn is_production_authority_source(&self) -> bool {
        false
    }
}

/// Volume-sealed default production source backed by [`persist_refcas_cutpoint_snapshot`].
pub struct FsSealedRefCasCutpointSource {
    storage_root: PathBuf,
}

impl FsSealedRefCasCutpointSource {
    pub fn new(storage_root: impl Into<PathBuf>) -> Self {
        Self { storage_root: storage_root.into() }
    }
}

impl RefCasCutpointSource for FsSealedRefCasCutpointSource {
    fn capture_state_machine(&self, repo_id: Uuid) -> Result<Option<(i64, RefCasStateMachine)>, SafeGcError> {
        let path = safe_gc_refcas_cutpoint_path(&self.storage_root, repo_id);
        if !path.is_file() {
            return Ok(None);
        }
        let raw = std::fs::read(&path).map_err(|e| SafeGcError::Io(e.to_string()))?;
        let env: PersistedRefCasCutpointEnvelope = serde_json::from_slice(&raw)
            .map_err(|_| SafeGcError::IncompleteProof("corrupted Ref-CAS cutpoint snapshot"))?;
        if env.snapshot.verify_integrity().is_err() {
            return Err(SafeGcError::IncompleteProof("corrupted Ref-CAS cutpoint snapshot"));
        }
        let Ok(mut sm) = RefCasStateMachine::restore(&env.snapshot) else {
            return Err(SafeGcError::IncompleteProof("corrupted Ref-CAS cutpoint snapshot"));
        };
        if !env.wal_tail.is_empty() && sm.recover_entries(env.wal_tail).is_err() {
            return Err(SafeGcError::IncompleteProof("Ref-CAS cutpoint WAL replay failed"));
        }
        Ok(Some((env.group_id, sm)))
    }
}

/// Explicit in-process source for callers that already hold a verified quorum state machine.
#[derive(Default)]
pub struct InMemoryRefCasCutpointSource {
    entries: Mutex<BTreeMap<Uuid, (i64, RefCasStateMachine)>>,
}

impl InMemoryRefCasCutpointSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&self, repo_id: Uuid, group_id: i64, sm: RefCasStateMachine) {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).insert(repo_id, (group_id, sm));
    }
}

impl RefCasCutpointSource for InMemoryRefCasCutpointSource {
    fn capture_state_machine(&self, repo_id: Uuid) -> Result<Option<(i64, RefCasStateMachine)>, SafeGcError> {
        Ok(self.entries.lock().unwrap_or_else(|e| e.into_inner()).get(&repo_id).cloned())
    }
}

type RefCasSourceKey = (PathBuf, Uuid);
type RefCasSourceMap = BTreeMap<RefCasSourceKey, Arc<dyn RefCasCutpointSource>>;

static PRODUCTION_REFCAS_SOURCES: OnceLock<RwLock<RefCasSourceMap>> = OnceLock::new();

fn production_sources() -> &'static RwLock<RefCasSourceMap> {
    PRODUCTION_REFCAS_SOURCES.get_or_init(|| RwLock::new(BTreeMap::new()))
}

fn canonical_source_key(storage_root: &Path, repo_id: Uuid) -> RefCasSourceKey {
    (storage_root.canonicalize().unwrap_or_else(|_| storage_root.to_path_buf()), repo_id)
}

pub fn register_production_refcas_source(storage_root: &Path, repo_id: Uuid, source: Arc<dyn RefCasCutpointSource>) {
    production_sources()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(canonical_source_key(storage_root, repo_id), source);
}

pub fn unregister_production_refcas_source(storage_root: &Path, repo_id: Uuid) {
    production_sources()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&canonical_source_key(storage_root, repo_id));
}

pub fn lookup_production_refcas_source(storage_root: &Path, repo_id: Uuid) -> Option<Arc<dyn RefCasCutpointSource>> {
    production_sources()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&canonical_source_key(storage_root, repo_id))
        .cloned()
}

struct WeakSmCutpointSource {
    group_id: i64,
    sm: Weak<Mutex<RefCasStateMachine>>,
}

impl RefCasCutpointSource for WeakSmCutpointSource {
    fn capture_state_machine(&self, _repo_id: Uuid) -> Result<Option<(i64, RefCasStateMachine)>, SafeGcError> {
        let Some(sm) = self.sm.upgrade() else {
            return Ok(None);
        };
        let guard = sm.lock().unwrap_or_else(|e| e.into_inner());
        Ok(Some((self.group_id, guard.clone())))
    }
}

/// Publish the running authority's live state machine without owning it.
pub fn register_live_sm_cutpoint_source(
    storage_root: &Path,
    repo_id: Uuid,
    group_id: i64,
    sm: &Arc<Mutex<RefCasStateMachine>>,
) {
    let source: Arc<dyn RefCasCutpointSource> = Arc::new(WeakSmCutpointSource { group_id, sm: Arc::downgrade(sm) });
    register_production_refcas_source(storage_root, repo_id, source);
}

/// Production cutpoint source preferring the live registered authority over sealed files.
#[derive(Clone, Debug)]
pub struct ProductionRefCasAuthoritySource {
    storage_root: PathBuf,
}

impl ProductionRefCasAuthoritySource {
    pub fn new(storage_root: impl Into<PathBuf>) -> Self {
        Self { storage_root: storage_root.into() }
    }
}

impl RefCasCutpointSource for ProductionRefCasAuthoritySource {
    fn capture_state_machine(&self, repo_id: Uuid) -> Result<Option<(i64, RefCasStateMachine)>, SafeGcError> {
        if let Some(source) = lookup_production_refcas_source(&self.storage_root, repo_id)
            && let Some(captured) = source.capture_state_machine(repo_id)?
        {
            return Ok(Some(captured));
        }
        FsSealedRefCasCutpointSource::new(self.storage_root.as_path()).capture_state_machine(repo_id)
    }

    fn is_production_authority_source(&self) -> bool {
        true
    }
}

/// Capture and `#151`-authenticate a cutpoint, refusing unattested on-volume JSON.
pub(super) fn capture_verified_dist_cutpoint(
    storage_root: &Path,
    repo_id: Uuid,
) -> Result<Option<(i64, RefCasStateMachine, Option<Vec<GroupVoterSignatureDto>>)>, SafeGcError> {
    let trust = SafeGcRepoTrustConfig::load(storage_root, repo_id)?;
    let keyring_dir = trust
        .refcas_keyring_dir
        .as_deref()
        .map(PathBuf::from)
        .or_else(|| std::env::var_os(GROUP_KEYRING_ENV).map(PathBuf::from))
        .ok_or(SafeGcError::DistributedPrereqsMissing(
            "DistributedRefCas cutpoint requires a #151 keyring directory",
        ))?;
    if let Some(source) = lookup_production_refcas_source(storage_root, repo_id)
        && let Some((group_id, sm)) = source.capture_state_machine(repo_id)?
    {
        let snapshot =
            sm.snapshot().map_err(|_| SafeGcError::IncompleteProof("failed sealing live Ref-CAS snapshot"))?;
        let gate = snapshot
            .body
            .gates
            .iter()
            .find(|gate| gate.repository_id == repo_id)
            .ok_or(SafeGcError::DistributedPrereqsMissing("live Ref-CAS snapshot missing repository gate"))?;
        let attested = sign_snapshot_with_keyring_dir(
            &keyring_dir,
            group_id,
            gate.history_incarnation,
            gate.group_epoch,
            gate.authority_epoch,
            &snapshot,
        )?;
        let verified = verify_attested_snapshot_with_keyring(&keyring_dir, repo_id, trust.tenant_id, &attested)?;
        let verified_sm = restore_attested_state_machine(&verified)?;
        return Ok(Some((group_id, verified_sm, Some(attested.voter_signatures))));
    }
    let path = safe_gc_refcas_cutpoint_path(storage_root, repo_id);
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read(&path).map_err(|e| SafeGcError::Io(e.to_string()))?;
    let env: PersistedRefCasCutpointEnvelope = serde_json::from_slice(&raw)
        .map_err(|_| SafeGcError::IncompleteProof("corrupted Ref-CAS cutpoint snapshot"))?;
    let attested = env.quorum_attestation.as_ref().ok_or(SafeGcError::DistributedPrereqsMissing(
        "DistributedRefCas cutpoint envelope missing #151 quorum voter attestation",
    ))?;
    let verified_snap = verify_attested_snapshot_with_keyring(&keyring_dir, repo_id, trust.tenant_id, attested)?;
    if verified_snap != env.snapshot {
        return Err(SafeGcError::DistributedPrereqsMissing(
            "attested Ref-CAS quorum snapshot disagrees with sealed cutpoint envelope",
        ));
    }
    if !env.wal_tail.is_empty() {
        return Err(SafeGcError::DistributedPrereqsMissing(
            "Ref-CAS cutpoint WAL tail is not covered by the #151 quorum attestation",
        ));
    }
    let voters = attested.voter_signatures.clone();
    let sm = restore_attested_state_machine(&verified_snap)?;
    Ok(Some((env.group_id, sm, Some(voters))))
}

/// Mint a fresh cut for the current pass; `DistributedRefCas` fails closed without one.
pub(super) async fn reconcile_worker_refcas_cut_if_needed<C: GenericClient + Sync>(
    pg_client: &C,
    repo_id: Uuid,
    storage_root: &Path,
    explicit_source: Option<&dyn RefCasCutpointSource>,
    authority: &DurableSafeGcAuthority,
    destructive_env: bool,
) -> Result<(Option<RefCasReconciledCut>, Option<Vec<GroupVoterSignatureDto>>), anyhow::Error> {
    let snap = authority.snapshot();
    let is_armed_dist = matches!(
        &snap.gc_mode,
        GcMode::ArmedDestructive(arm) if matches!(arm.lane, AuthorityLane::DistributedRefCas { .. })
    );
    let uses_production_authority =
        explicit_source.is_none() || explicit_source.is_some_and(|source| source.is_production_authority_source());
    if is_armed_dist && !uses_production_authority {
        bail!("DistributedRefCas destructive GC requires the production Ref-CAS authority source");
    }
    let mut verified_voters = None;
    let captured = if is_armed_dist {
        let verified = capture_verified_dist_cutpoint(storage_root, repo_id)
            .map_err(|e| anyhow::anyhow!("capture verified Ref-CAS cutpoint: {e}"))?;
        if let Some((group_id, sm, voters)) = verified {
            verified_voters = voters;
            Some((group_id, sm))
        } else {
            None
        }
    } else {
        let fs_default = FsSealedRefCasCutpointSource::new(storage_root);
        let source: &dyn RefCasCutpointSource = explicit_source.unwrap_or(&fs_default);
        source.capture_state_machine(repo_id).map_err(|e| anyhow::anyhow!("capture Ref-CAS state machine: {e}"))?
    };
    let requires_cut = destructive_env
        && (is_armed_dist || snap.paired_cursors.refcas_freshness != SourceFreshness::Reconciled || captured.is_some());
    match (requires_cut, captured) {
        (true, None) => bail!(
            "scheduled Safe GC requires an authoritative RefCasCutpointSource; \
             PG ref sequence cannot prove Ref-CAS cut"
        ),
        (true, Some((group_id, sm))) => {
            let cut = reconcile_refcas_cut_with_pg(pg_client, &sm, repo_id, group_id, authority)
                .await
                .map_err(|e| anyhow::anyhow!("reconcile_refcas_cut_with_pg: {e}"))?;
            Ok((Some(cut), verified_voters))
        }
        (false, Some((group_id, sm))) => {
            Ok((reconcile_refcas_cut_with_pg(pg_client, &sm, repo_id, group_id, authority).await.ok(), verified_voters))
        }
        (false, None) => Ok((None, None)),
    }
}

/// Re-seal the armed authority lane against this pass's live PG fence, trust bundle and fresh cut.
pub(super) fn reseal_worker_arm_receipt(
    storage_root: &Path,
    snap: &SafeGcRepoSnapshot,
    existing_arm: &SafeGcArmReceipt,
    gate_revision: u64,
    fence_epoch: u64,
    fresh_cut: Option<&RefCasReconciledCut>,
    verified_voters: Option<Vec<GroupVoterSignatureDto>>,
) -> Result<SafeGcArmReceipt> {
    let repo_id = snap.authority.repo_id;
    let trust = SafeGcRepoTrustConfig::load(storage_root, repo_id)?;
    trust.verify_arm_against_trust(existing_arm)?;
    if existing_arm.incarnation_id != snap.authority.incarnation_id
        || existing_arm.incarnation_epoch != snap.authority.incarnation_epoch
    {
        bail!("armed Ref-CAS lane does not belong to the current live authority incarnation");
    }
    let arm_signer =
        SafeGcEd25519Signer::load_seed_file(&SafeGcRepoTrustConfig::seed_path(storage_root, repo_id, "arm"))?;
    let lane = match &existing_arm.lane {
        AuthorityLane::SingleNodePg { pg_authority_id, pg_tx_seq, .. } => AuthorityLane::SingleNodePg {
            pg_authority_id: *pg_authority_id,
            pg_tx_seq: (*pg_tx_seq).max(gate_revision),
            pg_gc_fence_epoch: fence_epoch,
            reader_barrier_epoch: fence_epoch,
        },
        AuthorityLane::DistributedRefCas {
            ref_cas_authority_id,
            quorum_epoch,
            raft_commit_index,
            hold_bridge_evidence,
            backup_root_evidence,
            async_projection_only,
            ..
        } => {
            let cut =
                fresh_cut.ok_or_else(|| anyhow::anyhow!("DistributedRefCas requires fresh RefCasReconciledCut"))?;
            ensure!(
                *quorum_epoch == cut.group_epoch,
                "DistributedRefCas quorum_epoch {quorum_epoch} != RefCasReconciledCut group_epoch {}",
                cut.group_epoch
            );
            ensure!(
                cut.sm_applied_log_index >= *raft_commit_index
                    && cut.sm_applied_log_index > 0
                    && cut.sm_applied_log_term > 0,
                "RefCasReconciledCut log coordinate is behind or invalid"
            );
            let voters = verified_voters
                .ok_or_else(|| anyhow::anyhow!("DistributedRefCas requires #151 verified voter signatures"))?;
            let quorum_signer = SafeGcEd25519Signer::load_seed_file(&SafeGcRepoTrustConfig::seed_path(
                storage_root,
                repo_id,
                "quorum",
            ))?;
            let quorum = QuorumCommitEvidence::sign(
                &quorum_signer,
                *ref_cas_authority_id,
                *quorum_epoch,
                cut.group_id,
                cut.sm_applied_log_term,
                cut.sm_applied_log_index,
                cut.sm_snapshot_checksum.clone(),
                voters,
            )?;
            hold_bridge_evidence.verify(*ref_cas_authority_id, *quorum_epoch)?;
            ensure!(
                trust.trusted_hold_bridge_pubkey_hex.as_deref()
                    == Some(hold_bridge_evidence.bridge_pubkey_hex.as_str()),
                "#151 hold_bridge_evidence public key not trusted by repository authority"
            );
            ensure!(
                hold_bridge_evidence.active_holds_digest == compute_holds_digest(&snap.global_holds),
                "#151 hold_bridge_evidence digest disagrees with live global_holds"
            );
            ensure!(
                snap.paired_cursors.pg_applied_seq >= cut.sm_applied_log_index
                    && snap.paired_cursors.pg_applied_seq >= hold_bridge_evidence.bridge_seq,
                "paired PG cursor lags RefCasReconciledCut or #151 hold_bridge_evidence"
            );
            backup_root_evidence.verify(*ref_cas_authority_id, *quorum_epoch)?;
            AuthorityLane::DistributedRefCas {
                ref_cas_authority_id: *ref_cas_authority_id,
                quorum_epoch: *quorum_epoch,
                raft_commit_index: (*raft_commit_index).max(cut.sm_applied_log_index),
                quorum_evidence: Box::new(quorum),
                hold_bridge_evidence: hold_bridge_evidence.clone(),
                backup_root_evidence: backup_root_evidence.clone(),
                async_projection_only: *async_projection_only,
            }
        }
    };
    SafeGcArmReceipt::seal(
        &arm_signer,
        snap.authority.tenant_id,
        repo_id,
        snap.authority.history_id,
        snap.authority.incarnation_id,
        snap.authority.incarnation_epoch,
        true,
        lane,
    )
    .map_err(Into::into)
}
