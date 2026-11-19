//! Legacy `DistributedRefCas` journal migration plus explicit pending-delete-preserving re-arm (#122).
//!
//! Legacy journals pinned one HMAC quorum key and cannot attest a live independent voter
//! cutpoint. Migration validates the whole document in memory, disarms destructive GC
//! fail-closed, upgrades only the quorum evidence placeholder, and preserves the complete
//! `pending_delete` batch for a later live-voter re-arm.

use std::{fs, path::Path};

use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::super::{
    SafeGcError,
    domain::AuthorityRecord,
    model::{AuthorityLane, GcMode, SafeGcArmReceipt, validate_sha256_hex},
    proof_digest::compute_proof_digest,
    store::{DurableSafeGcAuthority, SafeGcRepoSnapshot},
    store_barrier::persist_snapshot,
};
use super::{
    BackupRootEvidence, HoldBridgeEvidence, QuorumCommitEvidence, SafeGcEd25519Signer, SafeGcRepoTrustConfig,
    TrustedConsensusVoter, compute_holds_digest, is_lower_hex, migration, validate_ed25519_pubkey_hex,
};

const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

/// The pre-independent-voter quorum evidence kept only to reject or explicitly migrate it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyQuorumCommitEvidence {
    pub group_id: i64,
    #[serde(default)]
    pub history_incarnation: Option<Uuid>,
    pub authority_epoch: i64,
    #[serde(default)]
    pub raft_term: Option<u64>,
    pub committed_log_index: u64,
    #[serde(default)]
    pub raft_commit_digest_hex: Option<String>,
    #[serde(default)]
    pub snapshot_sha256: Option<String>,
    pub snapshot_checksum: String,
    #[serde(default)]
    pub quorum_pubkey_hex: Option<String>,
    #[serde(default)]
    pub quorum_signer_pubkey_hex: Option<String>,
    pub quorum_signature_hex: String,
    #[serde(default)]
    pub voter_hmacs: Vec<(u16, String)>,
}

impl LegacyQuorumCommitEvidence {
    fn validate(&self) -> Result<(), SafeGcError> {
        if self.group_id < 0 || self.authority_epoch <= 0 || self.committed_log_index == 0 {
            return Err(SafeGcError::ArmingRejected("legacy Ref-CAS quorum evidence identity is invalid"));
        }
        validate_sha256_hex(&self.snapshot_checksum)
            .map_err(|_| SafeGcError::ArmingRejected("legacy Ref-CAS snapshot checksum is invalid"))?;
        if let Some(digest) = &self.raft_commit_digest_hex
            && validate_sha256_hex(digest).is_err()
        {
            return Err(SafeGcError::ArmingRejected("legacy Ref-CAS raft commit digest is invalid"));
        }
        if let Some(digest) = &self.snapshot_sha256
            && validate_sha256_hex(digest).is_err()
        {
            return Err(SafeGcError::ArmingRejected("legacy Ref-CAS snapshot sha256 is invalid"));
        }
        for pubkey in
            [self.quorum_pubkey_hex.as_deref(), self.quorum_signer_pubkey_hex.as_deref()].into_iter().flatten()
        {
            validate_ed25519_pubkey_hex(pubkey)?;
        }
        if !is_lower_hex(&self.quorum_signature_hex, 128) {
            return Err(SafeGcError::ArmingRejected("legacy Ref-CAS quorum signature is invalid"));
        }
        Ok(())
    }
}

/// Observable outcome of migrating one legacy trust bundle plus its optional journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalMigrationReport {
    pub journal_migrated: bool,
    pub disarmed_for_voter_rearm: bool,
    pub preserved_pending_batch_id: Option<Uuid>,
    pub preserved_pending_keys: Vec<String>,
    pub preserved_deleted_keys: Vec<String>,
    pub preserved_incarnation_epoch: u64,
}

/// Detect an unmigrated legacy `DistributedRefCas` lane without accepting any partial schema.
pub fn is_unmigrated_legacy_distributed_journal(bytes: &[u8]) -> bool {
    if serde_json::from_slice::<SafeGcRepoSnapshot>(bytes).is_ok() {
        return false;
    }
    let Ok(doc) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    let armed = doc.pointer("/gc_mode/ArmedDestructive/lane").is_some_and(legacy_quorum_in_lane);
    let pending = doc.pointer("/pending_delete/proof/lane").is_some_and(legacy_quorum_in_lane);
    armed || pending
}

fn legacy_quorum_in_lane(lane: &Value) -> bool {
    lane.get("DistributedRefCas")
        .and_then(|dist| dist.get("quorum_evidence"))
        .is_some_and(|quorum| serde_json::from_value::<LegacyQuorumCommitEvidence>(quorum.clone()).is_ok())
}

fn report_from_snapshot(snap: &SafeGcRepoSnapshot, journal_migrated: bool) -> JournalMigrationReport {
    let (preserved_pending_batch_id, preserved_pending_keys, preserved_deleted_keys) = match &snap.pending_delete {
        Some(batch) => (Some(batch.batch_id), batch.pending_keys.clone(), batch.deleted_keys.clone()),
        None => (None, Vec::new(), Vec::new()),
    };
    JournalMigrationReport {
        journal_migrated,
        disarmed_for_voter_rearm: matches!(&snap.gc_mode, GcMode::DisabledByDefault),
        preserved_pending_batch_id,
        preserved_pending_keys,
        preserved_deleted_keys,
        preserved_incarnation_epoch: snap.authority.incarnation_epoch,
    }
}

fn verify_snapshot_identity(
    snap: &SafeGcRepoSnapshot,
    repo_id: Uuid,
    config: &SafeGcRepoTrustConfig,
) -> Result<(), SafeGcError> {
    if snap.authority.repo_id != repo_id
        || snap.authority.tenant_id != config.tenant_id
        || snap.authority.history_id != config.history_id
        || snap.authority.trusted_arm_pubkey_hex != config.trusted_arm_pubkey_hex
    {
        return Err(SafeGcError::ArmingRejected("safe-gc journal identity disagrees with repository trust"));
    }
    Ok(())
}

fn validate_legacy_lane(
    lane: &Value,
    config: &SafeGcRepoTrustConfig,
) -> Result<LegacyQuorumCommitEvidence, SafeGcError> {
    let dist = lane
        .get("DistributedRefCas")
        .ok_or(SafeGcError::ArmingRejected("legacy journal lane is not DistributedRefCas"))?;
    let authority_id: Uuid =
        serde_json::from_value(dist.get("ref_cas_authority_id").cloned().unwrap_or(Value::Null))
            .map_err(|_| SafeGcError::ArmingRejected("legacy journal Ref-CAS authority id is invalid"))?;
    let epoch: u64 = serde_json::from_value(dist.get("quorum_epoch").cloned().unwrap_or(Value::Null))
        .map_err(|_| SafeGcError::ArmingRejected("legacy journal quorum epoch is invalid"))?;
    if authority_id.is_nil() || epoch == 0 {
        return Err(SafeGcError::ArmingRejected("legacy journal Ref-CAS authority coordinates are invalid"));
    }
    let legacy: LegacyQuorumCommitEvidence =
        serde_json::from_value(dist.get("quorum_evidence").cloned().unwrap_or(Value::Null))
            .map_err(|_| SafeGcError::ArmingRejected("legacy journal quorum evidence is invalid"))?;
    legacy.validate()?;
    let bridge: HoldBridgeEvidence =
        serde_json::from_value(dist.get("hold_bridge_evidence").cloned().unwrap_or(Value::Null))
            .map_err(|_| SafeGcError::ArmingRejected("legacy journal #151 hold bridge evidence is invalid"))?;
    bridge.verify(authority_id, epoch)?;
    if config.trusted_hold_bridge_pubkey_hex.as_deref() != Some(bridge.bridge_pubkey_hex.as_str()) {
        return Err(SafeGcError::ArmingRejected("legacy journal #151 bridge key is not trusted"));
    }
    let backup: BackupRootEvidence =
        serde_json::from_value(dist.get("backup_root_evidence").cloned().unwrap_or(Value::Null))
            .map_err(|_| SafeGcError::ArmingRejected("legacy journal #153 backup-root evidence is invalid"))?;
    backup.verify(authority_id, epoch)?;
    if config.trusted_backup_pubkey_hex.as_deref() != Some(backup.backup_pubkey_hex.as_str()) {
        return Err(SafeGcError::ArmingRejected("legacy journal #153 backup key is not trusted"));
    }
    Ok(legacy)
}

fn placeholder_quorum(legacy: &LegacyQuorumCommitEvidence, config: &SafeGcRepoTrustConfig) -> QuorumCommitEvidence {
    QuorumCommitEvidence {
        group_id: legacy.group_id,
        history_incarnation: legacy.history_incarnation.unwrap_or(config.history_id),
        authority_epoch: legacy.authority_epoch,
        raft_term: legacy.raft_term.unwrap_or(1).max(1),
        committed_log_index: legacy.committed_log_index,
        raft_commit_digest_hex: legacy.raft_commit_digest_hex.clone().unwrap_or_else(|| "0".repeat(64)),
        snapshot_sha256: legacy.snapshot_sha256.clone().unwrap_or_else(|| legacy.snapshot_checksum.clone()),
        snapshot_checksum: legacy.snapshot_checksum.clone(),
        quorum_threshold: 0,
        voter_signatures: Vec::new(),
    }
}

fn upgrade_legacy_document(doc: &mut Value, repo_id: Uuid, config: &SafeGcRepoTrustConfig) -> Result<(), SafeGcError> {
    let authority: AuthorityRecord = serde_json::from_value(doc.get("authority").cloned().unwrap_or(Value::Null))
        .map_err(|_| SafeGcError::ArmingRejected("legacy journal authority record is invalid"))?;
    if authority.repo_id != repo_id
        || authority.tenant_id != config.tenant_id
        || authority.history_id != config.history_id
        || authority.trusted_arm_pubkey_hex != config.trusted_arm_pubkey_hex
    {
        return Err(SafeGcError::ArmingRejected("safe-gc journal identity disagrees with repository trust"));
    }
    match doc.get("gc_mode") {
        Some(Value::String(mode)) if mode == "DisabledByDefault" => {}
        Some(Value::Object(armed)) => {
            let lane = armed
                .get("ArmedDestructive")
                .and_then(|receipt| receipt.get("lane"))
                .ok_or(SafeGcError::ArmingRejected("legacy journal gc_mode is invalid"))?;
            validate_legacy_lane(lane, config)?;
        }
        _ => return Err(SafeGcError::ArmingRejected("legacy journal gc_mode is not safely recognizable")),
    }
    if let Some(pending) = doc.get("pending_delete")
        && !pending.is_null()
    {
        let lane = pending
            .get("proof")
            .and_then(|proof| proof.get("lane"))
            .ok_or(SafeGcError::ArmingRejected("legacy pending delete proof lane is missing"))?;
        let legacy = validate_legacy_lane(lane, config)?;
        let placeholder = serde_json::to_value(placeholder_quorum(&legacy, config))
            .map_err(|e| SafeGcError::Serialization(e.to_string()))?;
        doc["pending_delete"]["proof"]["lane"]["DistributedRefCas"]["quorum_evidence"] = placeholder;
    }
    doc["gc_mode"] = json!("DisabledByDefault");
    Ok(())
}

impl SafeGcRepoTrustConfig {
    /// Migrate legacy trust plus its journal in one fail-closed, pending-delete-preserving step.
    pub fn migrate_legacy_trust_and_journal(
        storage_root: &Path,
        journal_path: &Path,
        repo_id: Uuid,
        quorum_threshold: usize,
        trusted_consensus_voters: Vec<TrustedConsensusVoter>,
    ) -> Result<(Self, JournalMigrationReport), SafeGcError> {
        let config =
            migration::prepare_migrated_trust(storage_root, repo_id, quorum_threshold, trusted_consensus_voters)?;
        if !journal_path.exists() {
            migration::commit_migrated_trust(storage_root, &config)?;
            return Ok((
                config,
                JournalMigrationReport {
                    journal_migrated: false,
                    disarmed_for_voter_rearm: true,
                    preserved_pending_batch_id: None,
                    preserved_pending_keys: Vec::new(),
                    preserved_deleted_keys: Vec::new(),
                    preserved_incarnation_epoch: 0,
                },
            ));
        }
        let meta = fs::metadata(journal_path).map_err(|e| SafeGcError::Io(e.to_string()))?;
        if meta.len() > MAX_JOURNAL_BYTES {
            return Err(SafeGcError::ArmingRejected("safe-gc journal exceeds its size bound"));
        }
        let raw = fs::read(journal_path).map_err(|e| SafeGcError::Io(e.to_string()))?;
        if let Ok(snap) = serde_json::from_slice::<SafeGcRepoSnapshot>(&raw) {
            verify_snapshot_identity(&snap, repo_id, &config)?;
            migration::commit_migrated_trust(storage_root, &config)?;
            return Ok((config, report_from_snapshot(&snap, false)));
        }
        let mut doc: Value = serde_json::from_slice(&raw)
            .map_err(|_| SafeGcError::ArmingRejected("legacy safe-gc journal is not valid JSON"))?;
        upgrade_legacy_document(&mut doc, repo_id, &config)?;
        let mut snap: SafeGcRepoSnapshot = serde_json::from_value(doc)
            .map_err(|_| SafeGcError::ArmingRejected("legacy safe-gc journal does not match the current schema"))?;
        if let Some(batch) = snap.pending_delete.as_mut() {
            batch.proof.proof_digest = compute_proof_digest(&batch.proof);
        }
        snap.push_audit("migrate_legacy_distributed_journal", &repo_id.to_string());
        migration::commit_migrated_trust(storage_root, &config)?;
        persist_snapshot(journal_path, &snap)?;
        Ok((config, report_from_snapshot(&snap, true)))
    }

    /// Explicitly re-arm `DistributedRefCas` while preserving every pending-delete batch field.
    pub fn rearm_distributed_with_quorum(
        &self,
        storage_root: &Path,
        journal_path: &Path,
        quorum: QuorumCommitEvidence,
        external_evidence: Option<(Uuid, HoldBridgeEvidence, BackupRootEvidence)>,
    ) -> Result<SafeGcArmReceipt, SafeGcError> {
        let authority = DurableSafeGcAuthority::open_with_journal(journal_path, None)?;
        let snap = authority.snapshot();
        let (lane_authority_id, epoch, _raft_commit_index, lane_bridge, lane_backup) = extract_distributed_lane(&snap)?;
        let (ref_cas_authority_id, bridge, backup) = match external_evidence {
            Some((authority_id, bridge, backup)) => (authority_id, bridge, backup),
            None => (lane_authority_id, lane_bridge, lane_backup),
        };
        let threshold = self
            .quorum_threshold
            .ok_or(SafeGcError::ArmingRejected("repository trust has no independent voter quorum threshold"))?;
        quorum.verify_against_trusted_voters(
            ref_cas_authority_id,
            epoch,
            self.history_id,
            &self.trusted_consensus_voters,
            threshold,
        )?;
        bridge.verify(ref_cas_authority_id, epoch)?;
        backup.verify(ref_cas_authority_id, epoch)?;
        if self.trusted_hold_bridge_pubkey_hex.as_deref() != Some(bridge.bridge_pubkey_hex.as_str()) {
            return Err(SafeGcError::ArmingRejected("re-arm #151 hold bridge key is not trusted"));
        }
        if self.trusted_backup_pubkey_hex.as_deref() != Some(backup.backup_pubkey_hex.as_str()) {
            return Err(SafeGcError::ArmingRejected("re-arm #153 backup key is not trusted"));
        }
        if bridge.active_holds_digest != compute_holds_digest(&snap.global_holds) {
            return Err(SafeGcError::DistributedPrereqsMissing(
                "re-arm #151 hold bridge digest disagrees with live global holds",
            ));
        }
        let arm_signer = SafeGcEd25519Signer::load_seed_file(&Self::seed_path(storage_root, self.repo_id, "arm"))?;
        let arm = SafeGcArmReceipt::seal(
            &arm_signer,
            snap.authority.tenant_id,
            self.repo_id,
            self.history_id,
            snap.authority.incarnation_id,
            snap.authority.incarnation_epoch,
            true,
            AuthorityLane::DistributedRefCas {
                ref_cas_authority_id,
                quorum_epoch: epoch,
                raft_commit_index: quorum.committed_log_index,
                quorum_evidence: Box::new(quorum),
                hold_bridge_evidence: Box::new(bridge),
                backup_root_evidence: Box::new(backup),
                async_projection_only: false,
            },
        )?;
        self.verify_arm_against_trust(&arm)?;
        authority.rearm_preserving_pending_delete(arm.clone())?;
        Ok(arm)
    }

    /// Fetch a fresh independent-voter quorum cutpoint and re-arm without dropping pending deletes.
    pub async fn rearm_distributed_from_voters(
        storage_root: &Path,
        journal_path: &Path,
        repo_id: Uuid,
        external_evidence: Option<(Uuid, HoldBridgeEvidence, BackupRootEvidence)>,
    ) -> Result<SafeGcArmReceipt, SafeGcError> {
        let trust = Self::load(storage_root, repo_id)?;
        let (_group_id, _sm, quorum) = super::fetch_quorum_cutpoint_from_voters(&trust, repo_id).await?;
        trust.rearm_distributed_with_quorum(storage_root, journal_path, quorum, external_evidence)
    }
}

type DistributedLaneEvidence = (Uuid, u64, u64, HoldBridgeEvidence, BackupRootEvidence);

fn extract_distributed_lane(snap: &SafeGcRepoSnapshot) -> Result<DistributedLaneEvidence, SafeGcError> {
    let lane = snap
        .pending_delete
        .as_ref()
        .map(|batch| &batch.proof.lane)
        .or_else(|| match &snap.gc_mode {
            GcMode::ArmedDestructive(arm) if matches!(&arm.lane, AuthorityLane::DistributedRefCas { .. }) => {
                Some(&arm.lane)
            }
            _ => None,
        })
        .ok_or(SafeGcError::ArmingRejected("no DistributedRefCas lane is available for re-arm"))?;
    match lane {
        AuthorityLane::DistributedRefCas {
            ref_cas_authority_id,
            quorum_epoch,
            raft_commit_index,
            hold_bridge_evidence,
            backup_root_evidence,
            ..
        } => Ok((
            *ref_cas_authority_id,
            *quorum_epoch,
            *raft_commit_index,
            hold_bridge_evidence.as_ref().clone(),
            backup_root_evidence.as_ref().clone(),
        )),
        AuthorityLane::SingleNodePg { .. } => Err(SafeGcError::ArmingRejected(
            "stored lane is SingleNodePg; DistributedRefCas re-arm requires external evidence",
        )),
    }
}
