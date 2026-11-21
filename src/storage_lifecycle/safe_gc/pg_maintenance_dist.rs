//! Production DistributedRefCas cutpoint capture for the scheduled `storage_lifecycle` worker (#122).
//!
//! The scheduled worker must mint a fresh [`RefCasReconciledCut`] from independently attested
//! quorum-committed `RefCasStateMachine` state on every maintenance pass; a PostgreSQL
//! `ref_store_core_refs.revision` sequence, a stale journal-embedded cut or a sealed on-volume
//! envelope can never authorize `DistributedRefCas` deletion.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::ref_store::core::state_machine::{RefCasLogEntry, RefCasSnapshot, RefCasStateMachine};

use super::{
    SafeGcError,
    dist_auth::{
        QuorumCommitEvidence, SafeGcEd25519Signer, SafeGcRepoTrustConfig, compute_holds_digest,
        fetch_quorum_cutpoint_from_voters,
    },
    model::{AuthorityLane, GcMode, SafeGcArmReceipt, SourceFreshness},
    refcas_cut::{RefCasReconciledCut, reconcile_refcas_cut_with_pg},
    store::{DurableSafeGcAuthority, SafeGcRepoSnapshot},
};

/// Sealed on-volume Ref-CAS quorum state-machine envelope (`<storage_root>/safe-gc/refcas/<repo_id>.json`).
///
/// The envelope is audit metadata only: `DistributedRefCas` never treats it as a cutpoint source.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedRefCasCutpointEnvelope {
    pub group_id: i64,
    pub snapshot: RefCasSnapshot,
    #[serde(default)]
    pub wal_tail: Vec<RefCasLogEntry>,
}

/// Canonical on-volume path of the sealed Ref-CAS cutpoint envelope for one repository.
pub fn safe_gc_refcas_cutpoint_path(storage_root: &Path, repo_id: Uuid) -> PathBuf {
    storage_root.join("safe-gc").join("refcas").join(format!("{repo_id}.json"))
}

/// Atomically persist a sealed `RefCasSnapshot` plus any WAL tail for worker cutpoint audit.
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
    let path = safe_gc_refcas_cutpoint_path(storage_root, repo_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SafeGcError::Io(e.to_string()))?;
    }
    let envelope = PersistedRefCasCutpointEnvelope { group_id, snapshot, wal_tail: wal_tail.to_vec() };
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

/// Volume-sealed default production source for NON-distributed lanes only.
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

/// Compatibility hook for `InProcessRefCasBackend::register_safe_gc_repo`.
///
/// Production distributed GC strictly requires independently attested consensus voters and
/// never reads in-process state machines, so registering one is deliberately a no-op.
pub fn register_live_sm_cutpoint_source(
    _storage_root: &Path,
    _repo_id: Uuid,
    _group_id: i64,
    _sm: &Arc<Mutex<RefCasStateMachine>>,
) {
}

/// Production cutpoint source for the distributed lane: independent consensus voters only.
#[derive(Clone, Debug)]
pub struct ProductionRefCasAuthoritySource {
    storage_root: PathBuf,
}

impl ProductionRefCasAuthoritySource {
    pub fn new(storage_root: impl Into<PathBuf>) -> Self {
        Self { storage_root: storage_root.into() }
    }

    pub fn storage_root(&self) -> &Path {
        &self.storage_root
    }
}

impl RefCasCutpointSource for ProductionRefCasAuthoritySource {
    fn capture_state_machine(&self, _repo_id: Uuid) -> Result<Option<(i64, RefCasStateMachine)>, SafeGcError> {
        Ok(None)
    }

    fn is_production_authority_source(&self) -> bool {
        true
    }
}

/// Fetch and threshold-verify the independent voter quorum cutpoint; sealed files are never used.
pub(super) async fn capture_verified_dist_cutpoint(
    storage_root: &Path,
    repo_id: Uuid,
) -> Result<(i64, RefCasStateMachine, QuorumCommitEvidence), SafeGcError> {
    let trust = SafeGcRepoTrustConfig::load(storage_root, repo_id)?;
    if trust.quorum_threshold.is_none() || trust.trusted_consensus_voters.is_empty() {
        return Err(SafeGcError::DistributedPrereqsMissing(
            "DistributedRefCas cutpoint requires pinned independent consensus voters",
        ));
    }
    fetch_quorum_cutpoint_from_voters(&trust, repo_id).await
}

/// Mint a fresh cut for the current pass; `DistributedRefCas` fails closed without one.
pub(super) async fn reconcile_worker_refcas_cut_if_needed<C: GenericClient + Sync>(
    pg_client: &C,
    repo_id: Uuid,
    storage_root: &Path,
    explicit_source: Option<&dyn RefCasCutpointSource>,
    authority: &DurableSafeGcAuthority,
    destructive_env: bool,
) -> Result<(Option<RefCasReconciledCut>, Option<QuorumCommitEvidence>), anyhow::Error> {
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
    let mut verified_quorum = None;
    let captured = if is_armed_dist {
        let (group_id, sm, quorum) = capture_verified_dist_cutpoint(storage_root, repo_id)
            .await
            .map_err(|e| anyhow::anyhow!("capture verified Ref-CAS cutpoint: {e}"))?;
        verified_quorum = Some(quorum);
        Some((group_id, sm))
    } else if let Some(source) = explicit_source {
        source.capture_state_machine(repo_id).map_err(|e| anyhow::anyhow!("capture Ref-CAS state machine: {e}"))?
    } else {
        None
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
            Ok((Some(cut), verified_quorum))
        }
        (false, Some((group_id, sm))) => {
            Ok((reconcile_refcas_cut_with_pg(pg_client, &sm, repo_id, group_id, authority).await.ok(), verified_quorum))
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
    verified_quorum: Option<QuorumCommitEvidence>,
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
            let quorum = verified_quorum.ok_or_else(|| {
                anyhow::anyhow!("DistributedRefCas requires independently verified voter quorum evidence")
            })?;
            let threshold = trust
                .quorum_threshold
                .ok_or_else(|| anyhow::anyhow!("repository trust has no independent voter quorum threshold"))?;
            quorum.verify_against_trusted_voters(
                *ref_cas_authority_id,
                *quorum_epoch,
                snap.authority.history_id,
                &trust.trusted_consensus_voters,
                threshold,
            )?;
            ensure!(quorum.group_id == cut.group_id, "quorum group_id disagrees with RefCasReconciledCut");
            ensure!(quorum.raft_term == cut.sm_applied_log_term, "quorum raft_term disagrees with RefCasReconciledCut");
            ensure!(
                quorum.committed_log_index == cut.sm_applied_log_index,
                "quorum committed_log_index disagrees with RefCasReconciledCut"
            );
            ensure!(
                quorum.snapshot_checksum == cut.sm_snapshot_checksum,
                "quorum snapshot_checksum disagrees with RefCasReconciledCut"
            );
            ensure!(
                quorum.history_incarnation == snap.authority.history_id,
                "quorum history incarnation disagrees with the armed history"
            );
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
