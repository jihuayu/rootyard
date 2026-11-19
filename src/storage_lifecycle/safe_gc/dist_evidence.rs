//! Ed25519-signed quorum, hold-bridge and backup-root evidence (#122/#151/#153).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::artifact_hold::reconcile_proof::GroupVoterSignatureDto;

use super::super::model::{GlobalHoldEntry, GlobalHoldState, encode_len_bytes, validate_sha256_hex};
use super::{SafeGcEd25519Signer, is_lower_hex, verify_ed25519_domain};

const QUORUM_DOMAIN: &[u8] = b"rootyard/safe-gc-quorum-evidence/v1";
const HOLD_BRIDGE_DOMAIN: &[u8] = b"rootyard/safe-gc-hold-bridge-evidence/v1";
const BACKUP_ROOT_DOMAIN: &[u8] = b"rootyard/safe-gc-backup-root-evidence/v1";
const HOLDS_DIGEST_DOMAIN: &[u8] = b"rootyard/safe-gc-holds-set/v1|";

fn evidence_digest(
    domain: &[u8],
    ref_cas_authority_id: Uuid,
    quorum_epoch: u64,
    encode: impl FnOnce(&mut Sha256),
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(ref_cas_authority_id.as_bytes());
    hasher.update(quorum_epoch.to_be_bytes());
    encode(&mut hasher);
    hasher.finalize().into()
}

/// Ed25519-signed Ref-CAS quorum commit evidence bound to one authority epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumCommitEvidence {
    pub group_id: i64,
    pub raft_term: u64,
    pub committed_log_index: u64,
    pub snapshot_checksum: String,
    pub voter_signatures: Vec<GroupVoterSignatureDto>,
    pub quorum_pubkey_hex: String,
    pub quorum_signature_hex: String,
}

impl QuorumCommitEvidence {
    pub fn sign(
        signer: &SafeGcEd25519Signer,
        ref_cas_authority_id: Uuid,
        quorum_epoch: u64,
        group_id: i64,
        raft_term: u64,
        committed_log_index: u64,
        snapshot_checksum: String,
        voter_signatures: Vec<GroupVoterSignatureDto>,
    ) -> Result<Self, super::SafeGcError> {
        let mut evidence = Self {
            group_id,
            raft_term,
            committed_log_index,
            snapshot_checksum,
            voter_signatures,
            quorum_pubkey_hex: signer.pubkey_hex().to_owned(),
            quorum_signature_hex: String::new(),
        };
        let digest =
            evidence_digest(QUORUM_DOMAIN, ref_cas_authority_id, quorum_epoch, |h| evidence.encode_canonical(h));
        evidence.quorum_signature_hex = signer.sign_domain(QUORUM_DOMAIN, &digest);
        evidence.verify(ref_cas_authority_id, quorum_epoch)?;
        Ok(evidence)
    }

    pub fn verify(&self, ref_cas_authority_id: Uuid, quorum_epoch: u64) -> Result<(), super::SafeGcError> {
        if ref_cas_authority_id.is_nil()
            || quorum_epoch == 0
            || self.group_id < 0
            || self.raft_term == 0
            || self.committed_log_index == 0
        {
            return Err(super::SafeGcError::DistributedPrereqsMissing("Ref-CAS quorum evidence identity invalid"));
        }
        validate_sha256_hex(&self.snapshot_checksum)
            .map_err(|_| super::SafeGcError::DistributedPrereqsMissing("Ref-CAS quorum evidence checksum invalid"))?;
        if self.voter_signatures.is_empty() || self.voter_signatures.len() > 32 {
            return Err(super::SafeGcError::DistributedPrereqsMissing(
                "Ref-CAS quorum voter signature set out of bounds",
            ));
        }
        let mut voters = BTreeSet::new();
        for signature in &self.voter_signatures {
            if signature.voter_id == 0
                || !voters.insert(signature.voter_id)
                || validate_sha256_hex(&signature.mac_hex).is_err()
            {
                return Err(super::SafeGcError::DistributedPrereqsMissing("Ref-CAS quorum voter signature invalid"));
            }
        }
        let digest = evidence_digest(QUORUM_DOMAIN, ref_cas_authority_id, quorum_epoch, |h| self.encode_canonical(h));
        verify_ed25519_domain(&self.quorum_pubkey_hex, QUORUM_DOMAIN, &digest, &self.quorum_signature_hex).map_err(
            |_| super::SafeGcError::DistributedPrereqsMissing("Ref-CAS quorum evidence Ed25519 signature rejected"),
        )
    }

    pub(crate) fn encode_canonical(&self, h: &mut Sha256) {
        h.update(self.group_id.to_be_bytes());
        h.update(self.raft_term.to_be_bytes());
        h.update(self.committed_log_index.to_be_bytes());
        encode_len_bytes(h, self.snapshot_checksum.as_bytes());
        h.update((self.voter_signatures.len() as u64).to_be_bytes());
        for signature in &self.voter_signatures {
            h.update(signature.voter_id.to_be_bytes());
            h.update([signature.key_id]);
            encode_len_bytes(h, signature.mac_hex.as_bytes());
        }
        encode_len_bytes(h, self.quorum_pubkey_hex.as_bytes());
    }
}

/// Ed25519-signed bridge evidence over the complete live global-hold set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldBridgeEvidence {
    pub bridge_seq: u64,
    pub active_holds_digest: String,
    pub bridge_pubkey_hex: String,
    pub bridge_signature_hex: String,
}

impl HoldBridgeEvidence {
    pub fn sign(
        signer: &SafeGcEd25519Signer,
        ref_cas_authority_id: Uuid,
        quorum_epoch: u64,
        bridge_seq: u64,
        holds: &[GlobalHoldEntry],
    ) -> Result<Self, super::SafeGcError> {
        if bridge_seq == 0 {
            return Err(super::SafeGcError::DistributedPrereqsMissing("#151 hold bridge sequence must be positive"));
        }
        let mut evidence = Self {
            bridge_seq,
            active_holds_digest: compute_holds_digest(holds),
            bridge_pubkey_hex: signer.pubkey_hex().to_owned(),
            bridge_signature_hex: String::new(),
        };
        let digest =
            evidence_digest(HOLD_BRIDGE_DOMAIN, ref_cas_authority_id, quorum_epoch, |h| evidence.encode_canonical(h));
        evidence.bridge_signature_hex = signer.sign_domain(HOLD_BRIDGE_DOMAIN, &digest);
        evidence.verify(ref_cas_authority_id, quorum_epoch)?;
        Ok(evidence)
    }

    pub fn verify(&self, ref_cas_authority_id: Uuid, quorum_epoch: u64) -> Result<(), super::SafeGcError> {
        if ref_cas_authority_id.is_nil() || quorum_epoch == 0 || self.bridge_seq == 0 {
            return Err(super::SafeGcError::DistributedPrereqsMissing("#151 hold bridge evidence identity invalid"));
        }
        validate_sha256_hex(&self.active_holds_digest)
            .map_err(|_| super::SafeGcError::DistributedPrereqsMissing("#151 hold bridge digest invalid"))?;
        let digest =
            evidence_digest(HOLD_BRIDGE_DOMAIN, ref_cas_authority_id, quorum_epoch, |h| self.encode_canonical(h));
        verify_ed25519_domain(&self.bridge_pubkey_hex, HOLD_BRIDGE_DOMAIN, &digest, &self.bridge_signature_hex)
            .map_err(|_| super::SafeGcError::DistributedPrereqsMissing("#151 hold bridge Ed25519 signature rejected"))
    }

    pub(crate) fn encode_canonical(&self, h: &mut Sha256) {
        h.update(self.bridge_seq.to_be_bytes());
        encode_len_bytes(h, self.active_holds_digest.as_bytes());
        encode_len_bytes(h, self.bridge_pubkey_hex.as_bytes());
    }
}

/// Ed25519-signed `#153` backup-root protection set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRootEvidence {
    pub backup_root_epoch: u64,
    pub backup_manifest_digest: String,
    pub protected_root_oids: Vec<String>,
    pub backup_pubkey_hex: String,
    pub backup_signature_hex: String,
}

impl BackupRootEvidence {
    pub fn sign(
        signer: &SafeGcEd25519Signer,
        ref_cas_authority_id: Uuid,
        quorum_epoch: u64,
        backup_root_epoch: u64,
        backup_manifest_digest: String,
        protected_root_oids: Vec<String>,
    ) -> Result<Self, super::SafeGcError> {
        if backup_root_epoch == 0 {
            return Err(super::SafeGcError::DistributedPrereqsMissing("#153 backup root epoch must be positive"));
        }
        let normalized: Vec<String> = protected_root_oids.into_iter().collect::<BTreeSet<_>>().into_iter().collect();
        let mut evidence = Self {
            backup_root_epoch,
            backup_manifest_digest,
            protected_root_oids: normalized,
            backup_pubkey_hex: signer.pubkey_hex().to_owned(),
            backup_signature_hex: String::new(),
        };
        let digest =
            evidence_digest(BACKUP_ROOT_DOMAIN, ref_cas_authority_id, quorum_epoch, |h| evidence.encode_canonical(h));
        evidence.backup_signature_hex = signer.sign_domain(BACKUP_ROOT_DOMAIN, &digest);
        evidence.verify(ref_cas_authority_id, quorum_epoch)?;
        Ok(evidence)
    }

    pub fn verify(&self, ref_cas_authority_id: Uuid, quorum_epoch: u64) -> Result<(), super::SafeGcError> {
        if ref_cas_authority_id.is_nil() || quorum_epoch == 0 || self.backup_root_epoch == 0 {
            return Err(super::SafeGcError::DistributedPrereqsMissing("#153 backup root evidence identity invalid"));
        }
        validate_sha256_hex(&self.backup_manifest_digest)
            .map_err(|_| super::SafeGcError::DistributedPrereqsMissing("#153 backup manifest digest invalid"))?;
        if self.protected_root_oids.is_empty() {
            return Err(super::SafeGcError::DistributedPrereqsMissing("#153 backup root evidence protects no roots"));
        }
        for oid in &self.protected_root_oids {
            if !(is_lower_hex(oid, 40) || is_lower_hex(oid, 64)) || oid.bytes().all(|b| b == b'0') {
                return Err(super::SafeGcError::DistributedPrereqsMissing("#153 backup root OID invalid"));
            }
        }
        let digest =
            evidence_digest(BACKUP_ROOT_DOMAIN, ref_cas_authority_id, quorum_epoch, |h| self.encode_canonical(h));
        verify_ed25519_domain(&self.backup_pubkey_hex, BACKUP_ROOT_DOMAIN, &digest, &self.backup_signature_hex)
            .map_err(|_| super::SafeGcError::DistributedPrereqsMissing("#153 backup root Ed25519 signature rejected"))
    }

    pub(crate) fn encode_canonical(&self, h: &mut Sha256) {
        h.update(self.backup_root_epoch.to_be_bytes());
        encode_len_bytes(h, self.backup_manifest_digest.as_bytes());
        h.update((self.protected_root_oids.len() as u64).to_be_bytes());
        for oid in &self.protected_root_oids {
            encode_len_bytes(h, oid.as_bytes());
        }
        encode_len_bytes(h, self.backup_pubkey_hex.as_bytes());
    }
}

fn encode_digest_field(h: &mut Sha256, label: &str, values: impl IntoIterator<Item = String>) {
    h.update((label.len() as u64).to_be_bytes());
    h.update(label.as_bytes());
    let unique: BTreeSet<String> = values.into_iter().collect();
    h.update((unique.len() as u64).to_be_bytes());
    for value in unique {
        encode_len_bytes(h, value.as_bytes());
    }
}

/// Deterministic digest over the entire live global-hold set.
pub fn compute_holds_digest(holds: &[GlobalHoldEntry]) -> String {
    let mut sorted: Vec<&GlobalHoldEntry> = holds.iter().collect();
    sorted.sort_by_key(|hold| (hold.hold_id, hold.registered_seq));
    let mut hasher = Sha256::new();
    hasher.update(HOLDS_DIGEST_DOMAIN);
    hasher.update((sorted.len() as u64).to_be_bytes());
    for hold in sorted {
        hasher.update(hold.hold_id.as_bytes());
        hasher.update(hold.tenant_id.as_bytes());
        hasher.update(hold.repo_id.as_bytes());
        hasher.update(hold.incarnation_epoch.to_be_bytes());
        hasher.update(hold.registered_seq.to_be_bytes());
        match hold.state {
            GlobalHoldState::Active => hasher.update([0]),
            GlobalHoldState::Released { released_at_seq } => {
                hasher.update([1]);
                hasher.update(released_at_seq.to_be_bytes());
            }
            GlobalHoldState::Unknown => hasher.update([2]),
        }
        encode_digest_field(&mut hasher, "packs", hold.protected_pack_ids.iter().map(|id| id.to_string()));
        encode_digest_field(&mut hasher, "oids", hold.protected_oids.iter().cloned());
        encode_digest_field(&mut hasher, "keys", hold.protected_physical_keys.iter().cloned());
    }
    hex::encode(hasher.finalize())
}
