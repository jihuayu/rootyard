//! Fail-closed migration of legacy safe-gc repository trust documents (#122).

use std::{fs, path::Path};

use serde::Deserialize;
use uuid::Uuid;

use super::{
    MAX_TRUST_DOCUMENT_BYTES, SafeGcError, SafeGcRepoTrustConfig, SafeGcVoterClientAuth, TrustedConsensusVoter,
    io_error, read_private_file,
};

const LEGACY_TRUST_REJECTED: &str =
    "legacy safe-gc trust bundle requires explicit migration to independent consensus voters";

/// Pre-independent-voter trust document kept only to reject or explicitly migrate it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySafeGcRepoTrustConfig {
    pub repo_id: Uuid,
    pub tenant_id: Uuid,
    pub history_id: Uuid,
    pub trusted_arm_pubkey_hex: String,
    #[serde(default)]
    pub trusted_quorum_pubkey_hex: Option<String>,
    #[serde(default)]
    pub trusted_hold_bridge_pubkey_hex: Option<String>,
    #[serde(default)]
    pub trusted_backup_pubkey_hex: Option<String>,
    #[serde(default)]
    pub refcas_keyring_dir: Option<String>,
}

impl From<LegacySafeGcRepoTrustConfig> for SafeGcRepoTrustConfig {
    fn from(legacy: LegacySafeGcRepoTrustConfig) -> Self {
        Self {
            repo_id: legacy.repo_id,
            tenant_id: legacy.tenant_id,
            history_id: legacy.history_id,
            trusted_arm_pubkey_hex: legacy.trusted_arm_pubkey_hex,
            quorum_threshold: None,
            trusted_hold_bridge_pubkey_hex: legacy.trusted_hold_bridge_pubkey_hex,
            trusted_backup_pubkey_hex: legacy.trusted_backup_pubkey_hex,
            trusted_consensus_voters: Vec::new(),
            voter_client_auth: None,
        }
    }
}

fn verify_trust_dir(dir: &Path) -> Result<(), SafeGcError> {
    let meta = fs::metadata(dir).map_err(io_error)?;
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
    Ok(())
}

pub(super) fn parse_trust_or_reject_legacy(bytes: &[u8], repo_id: Uuid) -> Result<SafeGcRepoTrustConfig, SafeGcError> {
    if let Ok(config) = serde_json::from_slice::<SafeGcRepoTrustConfig>(bytes) {
        if config.repo_id != repo_id {
            return Err(SafeGcError::ArmingRejected("safe-gc trust bundle repository mismatch"));
        }
        let pins_legacy = config.trusted_hold_bridge_pubkey_hex.is_some() || config.trusted_backup_pubkey_hex.is_some();
        if pins_legacy && (config.quorum_threshold.is_none() || config.trusted_consensus_voters.is_empty()) {
            return Err(SafeGcError::ArmingRejected(LEGACY_TRUST_REJECTED));
        }
        config.validate_identity()?;
        return Ok(config);
    }
    if let Ok(legacy) = serde_json::from_slice::<LegacySafeGcRepoTrustConfig>(bytes) {
        if legacy.trusted_quorum_pubkey_hex.is_some()
            || legacy.refcas_keyring_dir.is_some()
            || legacy.trusted_hold_bridge_pubkey_hex.is_some()
            || legacy.trusted_backup_pubkey_hex.is_some()
        {
            return Err(SafeGcError::ArmingRejected(LEGACY_TRUST_REJECTED));
        }
        if legacy.repo_id != repo_id {
            return Err(SafeGcError::ArmingRejected("safe-gc trust bundle repository mismatch"));
        }
        let config: SafeGcRepoTrustConfig = legacy.into();
        config.validate_identity()?;
        return Ok(config);
    }
    Err(SafeGcError::Serialization("invalid safe-gc private JSON document".into()))
}

fn pinned_trust(bytes: &[u8], repo_id: Uuid) -> Result<SafeGcRepoTrustConfig, SafeGcError> {
    let config = serde_json::from_slice::<SafeGcRepoTrustConfig>(bytes)
        .or_else(|_| serde_json::from_slice::<LegacySafeGcRepoTrustConfig>(bytes).map(Into::into))
        .map_err(|_| SafeGcError::Serialization("invalid safe-gc private JSON document".into()))?;
    if config.repo_id != repo_id {
        return Err(SafeGcError::ArmingRejected("safe-gc trust bundle repository mismatch"));
    }
    Ok(config)
}

/// Validate a legacy or pinned trust document and build the migrated in-memory config.
pub(super) fn prepare_migrated_trust(
    storage_root: &Path,
    repo_id: Uuid,
    quorum_threshold: usize,
    trusted_consensus_voters: Vec<TrustedConsensusVoter>,
) -> Result<SafeGcRepoTrustConfig, SafeGcError> {
    verify_trust_dir(&SafeGcRepoTrustConfig::trust_dir(storage_root))?;
    let bytes =
        read_private_file(&SafeGcRepoTrustConfig::config_path(storage_root, repo_id), MAX_TRUST_DOCUMENT_BYTES)?;
    let pinned = pinned_trust(&bytes, repo_id)?;
    let config = SafeGcRepoTrustConfig {
        repo_id,
        tenant_id: pinned.tenant_id,
        history_id: pinned.history_id,
        trusted_arm_pubkey_hex: pinned.trusted_arm_pubkey_hex,
        quorum_threshold: Some(quorum_threshold),
        trusted_hold_bridge_pubkey_hex: pinned.trusted_hold_bridge_pubkey_hex,
        trusted_backup_pubkey_hex: pinned.trusted_backup_pubkey_hex,
        trusted_consensus_voters,
        voter_client_auth: pinned.voter_client_auth,
    };
    config.validate_identity()?;
    Ok(config)
}

/// Atomically persist the migrated trust document and delete legacy external signing seeds.
pub(super) fn commit_migrated_trust(storage_root: &Path, config: &SafeGcRepoTrustConfig) -> Result<(), SafeGcError> {
    for kind in ["quorum", "bridge", "backup"] {
        let p = SafeGcRepoTrustConfig::seed_path(storage_root, config.repo_id, kind);
        if p.exists() {
            fs::remove_file(p).map_err(io_error)?;
        }
    }
    SafeGcRepoTrustConfig::write_config(storage_root, config)
}

impl SafeGcRepoTrustConfig {
    /// Explicitly promote a legacy trust bundle to pinned independent consensus voters.
    pub fn migrate_legacy_trust_file(
        storage_root: &Path,
        repo_id: Uuid,
        quorum_threshold: usize,
        trusted_consensus_voters: Vec<TrustedConsensusVoter>,
    ) -> Result<Self, SafeGcError> {
        let config = prepare_migrated_trust(storage_root, repo_id, quorum_threshold, trusted_consensus_voters)?;
        commit_migrated_trust(storage_root, &config)?;
        Ok(config)
    }

    /// Bind the pinned mTLS + `0600` Bearer client auth and persist the migrated trust document.
    pub fn bind_voter_client_auth(
        &mut self,
        storage_root: &Path,
        auth: SafeGcVoterClientAuth,
    ) -> Result<(), SafeGcError> {
        auth.validate()?;
        self.voter_client_auth = Some(auth);
        Self::write_config(storage_root, self)
    }
}
