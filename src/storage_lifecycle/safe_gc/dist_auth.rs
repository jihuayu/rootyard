//! Ed25519-authenticated distributed authority for Safe GC (#122/#151/#153).
//!
//! `DistributedRefCas` arming binds a non-deserializable Ed25519 arm signer, independently
//! operated voter public keys, `#151` hold-bridge evidence and `#153` backup-root evidence.
//! The worker volume holds exactly one arm seed: voter, quorum, bridge and backup signers are
//! external, so no local directory can mint a quorum cutpoint.

use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::SafeGcError;
use super::model::{AuthorityLane, PairedCursorReconciliation, SafeGcArmReceipt, SourceFreshness};

#[path = "dist_evidence.rs"]
mod evidence;
#[path = "dist_keyring.rs"]
mod keyring;
#[path = "dist_trust_migration.rs"]
mod migration;

pub use evidence::{
    BackupRootEvidence, HoldBridgeEvidence, QuorumCommitEvidence, QuorumCommitSeal, compute_holds_digest,
};
pub use keyring::{
    TrustedConsensusVoter, VoterCutpointAttestation, VoterCutpointClaims, VoterCutpointSignature,
    fetch_quorum_cutpoint_from_voters, sign_single_voter_cutpoint_attestation, verify_quorum_voter_attestations,
    verify_single_voter_cutpoint_attestation,
};

const SEED_BYTES: usize = 32;
/// Hard ceiling for the repository trust document stored on the worker volume.
const MAX_TRUST_DOCUMENT_BYTES: usize = 64 * 1024;

fn io_error(err: std::io::Error) -> SafeGcError {
    SafeGcError::Io(err.to_string())
}

fn invalid_pubkey() -> SafeGcError {
    SafeGcError::ArmingRejected("invalid Ed25519 public key hex")
}

pub(crate) fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn ensure_private_dir(dir: &Path) -> Result<(), SafeGcError> {
    fs::create_dir_all(dir).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        if fs::metadata(dir).map_err(io_error)?.mode() & 0o777 != 0o700 {
            return Err(SafeGcError::ArmingRejected("safe-gc trust directory must be 0700"));
        }
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SafeGcError> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
        if fs::metadata(path).map_err(io_error)?.mode() & 0o777 != 0o600 {
            return Err(SafeGcError::ArmingRejected("safe-gc secret file must be 0600"));
        }
    }
    Ok(())
}

fn read_private_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, SafeGcError> {
    let meta = fs::metadata(path).map_err(io_error)?;
    if !meta.is_file() || meta.len() > max_bytes as u64 {
        return Err(SafeGcError::ArmingRejected("safe-gc private file missing or over its size bound"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o777 != 0o600 {
            return Err(SafeGcError::ArmingRejected("safe-gc secret file must be 0600"));
        }
    }
    let mut bytes = Vec::new();
    let read_limit = max_bytes as u64 + 1;
    fs::File::open(path).map_err(io_error)?.take(read_limit).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() > max_bytes {
        return Err(SafeGcError::ArmingRejected("safe-gc private file exceeds its size bound"));
    }
    Ok(bytes)
}

/// Ed25519 signer whose raw seed is zeroized on drop and never printed by `Debug`.
pub struct SafeGcEd25519Signer {
    key_pair: Ed25519KeyPair,
    seed: Zeroizing<[u8; SEED_BYTES]>,
    pubkey_hex: String,
}

impl fmt::Debug for SafeGcEd25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeGcEd25519Signer").field("pubkey_hex", &self.pubkey_hex).finish()
    }
}

impl SafeGcEd25519Signer {
    pub fn from_seed(seed: [u8; SEED_BYTES]) -> Result<Self, SafeGcError> {
        if seed.iter().all(|&byte| byte == 0) {
            return Err(SafeGcError::ArmingRejected("Ed25519 seed must be non-zero"));
        }
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| SafeGcError::ArmingRejected("invalid Ed25519 seed"))?;
        let pubkey_hex = hex::encode(key_pair.public_key().as_ref());
        Ok(Self { key_pair, seed: Zeroizing::new(seed), pubkey_hex })
    }

    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    pub fn sign_domain(&self, domain: &[u8], payload: &[u8]) -> String {
        let mut message = Vec::with_capacity(domain.len() + payload.len() + 1);
        message.extend_from_slice(domain);
        message.push(b'|');
        message.extend_from_slice(payload);
        hex::encode(self.key_pair.sign(&message).as_ref())
    }

    pub fn write_seed_file(&self, path: &Path) -> Result<(), SafeGcError> {
        write_private_file(path, &*self.seed)
    }

    pub fn load_seed_file(path: &Path) -> Result<Self, SafeGcError> {
        let bytes = read_private_file(path, SEED_BYTES)?;
        if bytes.len() != SEED_BYTES {
            return Err(SafeGcError::ArmingRejected("Ed25519 seed file must contain 32 bytes"));
        }
        let mut seed = [0_u8; SEED_BYTES];
        seed.copy_from_slice(&bytes);
        Self::from_seed(seed)
    }
}

pub fn validate_ed25519_pubkey_hex(pubkey_hex: &str) -> Result<[u8; SEED_BYTES], SafeGcError> {
    if !is_lower_hex(pubkey_hex, 64) || pubkey_hex.bytes().all(|b| b == b'0') {
        return Err(invalid_pubkey());
    }
    let decoded = hex::decode(pubkey_hex).map_err(|_| invalid_pubkey())?;
    decoded.try_into().map_err(|_| invalid_pubkey())
}

pub fn verify_ed25519_domain(
    pubkey_hex: &str,
    domain: &[u8],
    payload: &[u8],
    sig_hex: &str,
) -> Result<(), SafeGcError> {
    let key = validate_ed25519_pubkey_hex(pubkey_hex)?;
    if !is_lower_hex(sig_hex, 128) {
        return Err(SafeGcError::ArmingRejected("invalid Ed25519 signature hex"));
    }
    let signature = hex::decode(sig_hex).map_err(|_| SafeGcError::ArmingRejected("invalid Ed25519 signature hex"))?;
    let mut message = Vec::with_capacity(domain.len() + payload.len() + 1);
    message.extend_from_slice(domain);
    message.push(b'|');
    message.extend_from_slice(payload);
    UnparsedPublicKey::new(&ED25519, &key)
        .verify(&message, &signature)
        .map_err(|_| SafeGcError::ArmingRejected("Ed25519 signature verification failed"))
}

/// Pinned `#151`/`#153` repository trust bundle stored on the worker volume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeGcRepoTrustConfig {
    pub repo_id: Uuid,
    pub tenant_id: Uuid,
    pub history_id: Uuid,
    pub trusted_arm_pubkey_hex: String,
    pub quorum_threshold: Option<usize>,
    pub trusted_hold_bridge_pubkey_hex: Option<String>,
    pub trusted_backup_pubkey_hex: Option<String>,
    #[serde(default)]
    pub trusted_consensus_voters: Vec<TrustedConsensusVoter>,
}

impl SafeGcRepoTrustConfig {
    pub fn trust_dir(storage_root: &Path) -> PathBuf {
        storage_root.join("safe-gc").join("trust")
    }

    pub fn seed_path(storage_root: &Path, repo_id: Uuid, kind: &str) -> PathBuf {
        Self::trust_dir(storage_root).join(format!("{repo_id}.{kind}.seed"))
    }

    fn config_path(storage_root: &Path, repo_id: Uuid) -> PathBuf {
        Self::trust_dir(storage_root).join(format!("{repo_id}.json"))
    }

    fn write_config(storage_root: &Path, config: &Self) -> Result<(), SafeGcError> {
        let bytes = serde_json::to_vec_pretty(config).map_err(|e| SafeGcError::Serialization(e.to_string()))?;
        let dir = Self::trust_dir(storage_root);
        ensure_private_dir(&dir)?;
        let tmp = dir.join(format!("{}.tmp-{}", config.repo_id, Uuid::new_v4()));
        write_private_file(&tmp, &bytes)?;
        fs::rename(&tmp, Self::config_path(storage_root, config.repo_id)).map_err(io_error)
    }

    pub fn provision_single_node(
        storage_root: &Path,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        arm_signer: &SafeGcEd25519Signer,
    ) -> Result<Self, SafeGcError> {
        let config = Self {
            repo_id,
            tenant_id,
            history_id,
            trusted_arm_pubkey_hex: arm_signer.pubkey_hex().to_owned(),
            quorum_threshold: None,
            trusted_hold_bridge_pubkey_hex: None,
            trusted_backup_pubkey_hex: None,
            trusted_consensus_voters: Vec::new(),
        };
        config.validate_identity()?;
        arm_signer.write_seed_file(&Self::seed_path(storage_root, repo_id, "arm"))?;
        Self::write_config(storage_root, &config)?;
        Ok(config)
    }

    /// Provision independent voter trust; the worker volume receives ONLY `{repo_id}.arm.seed`.
    pub fn provision_distributed(
        storage_root: &Path,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        arm_signer: &SafeGcEd25519Signer,
        quorum_threshold: usize,
        trusted_consensus_voters: Vec<TrustedConsensusVoter>,
        external_pubkeys: (&str, &str),
    ) -> Result<Self, SafeGcError> {
        let config = Self {
            repo_id,
            tenant_id,
            history_id,
            trusted_arm_pubkey_hex: arm_signer.pubkey_hex().to_owned(),
            quorum_threshold: Some(quorum_threshold),
            trusted_hold_bridge_pubkey_hex: Some(external_pubkeys.0.to_owned()),
            trusted_backup_pubkey_hex: Some(external_pubkeys.1.to_owned()),
            trusted_consensus_voters,
        };
        config.validate_identity()?;
        for kind in ["quorum", "bridge", "backup"] {
            let _ = fs::remove_file(Self::seed_path(storage_root, repo_id, kind));
        }
        arm_signer.write_seed_file(&Self::seed_path(storage_root, repo_id, "arm"))?;
        Self::write_config(storage_root, &config)?;
        Ok(config)
    }

    fn validate_identity(&self) -> Result<(), SafeGcError> {
        if self.repo_id.is_nil() || self.tenant_id.is_nil() || self.history_id.is_nil() {
            return Err(SafeGcError::ArmingRejected("safe-gc trust identity must be non-nil"));
        }
        validate_ed25519_pubkey_hex(&self.trusted_arm_pubkey_hex)?;
        let external = [self.trusted_hold_bridge_pubkey_hex.as_deref(), self.trusted_backup_pubkey_hex.as_deref()];
        for key in external.into_iter().flatten() {
            validate_ed25519_pubkey_hex(key)?;
            if key == self.trusted_arm_pubkey_hex {
                return Err(SafeGcError::ArmingRejected("external evidence key must differ from the arm signer"));
            }
        }
        if let (Some(bridge), Some(backup)) = (external[0], external[1])
            && bridge == backup
        {
            return Err(SafeGcError::ArmingRejected("hold-bridge and backup evidence keys must be distinct"));
        }
        let Some(threshold) = self.quorum_threshold else {
            return if self.trusted_consensus_voters.is_empty() {
                Ok(())
            } else {
                Err(SafeGcError::ArmingRejected("trust pins independent voters without a quorum threshold"))
            };
        };
        let voters = &self.trusted_consensus_voters;
        if threshold < 2 || voters.len() < 2 || voters.len() > 32 {
            return Err(SafeGcError::ArmingRejected("independent voter quorum requires two to 32 voters"));
        }
        if threshold < (voters.len() / 2) + 1 || threshold > voters.len() {
            return Err(SafeGcError::ArmingRejected("quorum_threshold must be a strict majority <= voter count"));
        }
        if external[0].is_none() || external[1].is_none() {
            return Err(SafeGcError::ArmingRejected("distributed trust requires external #151/#153 evidence keys"));
        }
        let mut voter_ids = std::collections::BTreeSet::new();
        let mut pubkeys = std::collections::BTreeSet::new();
        for voter in voters {
            keyring::validate_trusted_voter(voter, &self.trusted_arm_pubkey_hex)?;
            if !voter_ids.insert(voter.voter_id) || !pubkeys.insert(voter.ed25519_pubkey_hex.as_str()) {
                return Err(SafeGcError::ArmingRejected("duplicate independent voter identity or public key"));
            }
        }
        Ok(())
    }

    pub fn load(storage_root: &Path, repo_id: Uuid) -> Result<Self, SafeGcError> {
        let dir = Self::trust_dir(storage_root);
        let meta = fs::metadata(&dir).map_err(io_error)?;
        if !meta.is_dir() {
            return Err(SafeGcError::ArmingRejected("safe-gc trust path must be a directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.mode() & 0o777 != 0o700 {
                return Err(SafeGcError::ArmingRejected("safe-gc trust directory must be 0700"));
            }
        }
        let bytes = read_private_file(&Self::config_path(storage_root, repo_id), MAX_TRUST_DOCUMENT_BYTES)?;
        migration::parse_trust_or_reject_legacy(&bytes, repo_id)
    }

    pub fn verify_arm_against_trust(&self, arm: &SafeGcArmReceipt) -> Result<(), SafeGcError> {
        arm.validate()?;
        if arm.repo_id != self.repo_id || arm.tenant_id != self.tenant_id || arm.history_id != self.history_id {
            return Err(SafeGcError::ArmingRejected("arm receipt identity not trusted by repository authority"));
        }
        if arm.arm_pubkey_hex != self.trusted_arm_pubkey_hex {
            return Err(SafeGcError::ArmingRejected(
                "arm receipt Ed25519 public key not trusted by repository authority",
            ));
        }
        if let AuthorityLane::DistributedRefCas {
            ref_cas_authority_id,
            quorum_epoch,
            quorum_evidence,
            hold_bridge_evidence,
            backup_root_evidence,
            ..
        } = &arm.lane
        {
            let threshold = self
                .quorum_threshold
                .ok_or(SafeGcError::ArmingRejected("repository trust has no independent voter quorum threshold"))?;
            quorum_evidence
                .verify_against_trusted_voters(
                    *ref_cas_authority_id,
                    *quorum_epoch,
                    self.history_id,
                    &self.trusted_consensus_voters,
                    threshold,
                )
                .map_err(|_| {
                    SafeGcError::ArmingRejected("independent voter quorum evidence is not authorized by pinned voters")
                })?;
            if self.trusted_hold_bridge_pubkey_hex.as_deref() != Some(hold_bridge_evidence.bridge_pubkey_hex.as_str())
                || self.trusted_backup_pubkey_hex.as_deref() != Some(backup_root_evidence.backup_pubkey_hex.as_str())
            {
                return Err(SafeGcError::ArmingRejected(
                    "distributed arm evidence public keys not trusted by repository authority",
                ));
            }
        }
        Ok(())
    }
}

/// Verify all cryptographic evidence fields of a `DistributedRefCas` authority lane.
pub(super) fn verify_distributed_lane_prereqs(
    ref_cas_authority_id: Uuid,
    quorum_epoch: u64,
    raft_commit_index: u64,
    evidence: (&QuorumCommitEvidence, &HoldBridgeEvidence, &BackupRootEvidence),
    async_projection_only: bool,
) -> Result<(), SafeGcError> {
    if async_projection_only {
        return Err(SafeGcError::DistributedPrereqsMissing("distributed GC cannot rely on async PG projection alone"));
    }
    if ref_cas_authority_id.is_nil() || quorum_epoch == 0 || raft_commit_index == 0 {
        return Err(SafeGcError::DistributedPrereqsMissing("Ref-CAS quorum not verified"));
    }
    evidence.0.verify(ref_cas_authority_id, quorum_epoch)?;
    evidence.1.verify(ref_cas_authority_id, quorum_epoch)?;
    evidence.2.verify(ref_cas_authority_id, quorum_epoch)?;
    if evidence.0.group_id < 0 || evidence.0.committed_log_index > raft_commit_index {
        return Err(SafeGcError::DistributedPrereqsMissing("Ref-CAS quorum log index exceeds armed raft commit index"));
    }
    if evidence.1.bridge_seq == 0 {
        return Err(SafeGcError::DistributedPrereqsMissing("#151 global hold bridge unverified"));
    }
    if evidence.2.protected_root_oids.is_empty() {
        return Err(SafeGcError::DistributedPrereqsMissing("#153 remote backup root unverified"));
    }
    Ok(())
}

/// Verify paired cursor coverage for a `DistributedRefCas` lane against its attested cut.
pub(super) fn verify_distributed_cursor_coverage(
    history_id: Uuid,
    live_ref_seq: u64,
    quorum_epoch: u64,
    raft_commit_index: u64,
    global_hold_bridge_seq: u64,
    quorum_evidence: &QuorumCommitEvidence,
    cursors: &PairedCursorReconciliation,
) -> Result<(), SafeGcError> {
    let refcas_floor = raft_commit_index.max(global_hold_bridge_seq).max(live_ref_seq);
    let Some(ref cut) = cursors.refcas_cut else {
        return Err(SafeGcError::IncompleteProof(
            "DistributedRefCas requires an authoritative RefCasReconciledCut; PG ref seq cannot prove Ref-CAS cut",
        ));
    };
    cut.verify_reconciled(history_id, refcas_floor, quorum_epoch)?;
    if quorum_evidence.history_incarnation != history_id {
        return Err(SafeGcError::IncompleteProof(
            "signed QuorumCommitEvidence history incarnation disagrees with the armed history",
        ));
    }
    if cut.group_id != quorum_evidence.group_id
        || cut.sm_snapshot_checksum != quorum_evidence.snapshot_checksum
        || cut.sm_applied_log_index < quorum_evidence.committed_log_index
    {
        return Err(SafeGcError::IncompleteProof("RefCasReconciledCut disagrees with signed QuorumCommitEvidence"));
    }
    if cut.sm_applied_log_index == quorum_evidence.committed_log_index
        && cut.sm_applied_log_term != quorum_evidence.raft_term
    {
        return Err(SafeGcError::IncompleteProof("RefCasReconciledCut disagrees with signed QuorumCommitEvidence"));
    }
    if cut.sm_applied_log_index > raft_commit_index {
        return Err(SafeGcError::IncompleteProof(
            "verified RefCasReconciledCut exceeds the armed Ref-CAS raft commit index",
        ));
    }
    if cursors.refcas_applied_index != cut.sm_applied_log_index || cursors.refcas_applied_index < refcas_floor {
        return Err(SafeGcError::IncompleteProof("paired Ref-CAS cursor disagrees with verified RefCasReconciledCut"));
    }
    if cursors.pg_applied_seq < global_hold_bridge_seq {
        return Err(SafeGcError::IncompleteProof("paired PG cursor has not covered #151 global_hold_bridge_seq"));
    }
    if cursors.refcas_freshness != SourceFreshness::Reconciled {
        return Err(SafeGcError::IncompleteProof("paired Ref-CAS cursor freshness is not reconciled"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests_dist_auth.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "tests_dist_migration.rs"]
mod migration_tests;
