//! `#151` group keyring provisioning, snapshot signing and consensus verification (#122).

use std::{collections::BTreeSet, path::Path};

use ring::hmac;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::artifact_hold::reconcile_proof::{
    AttestedGroupSnapshotDto, GroupConsensusVerifier, GroupHoldBinding, GroupObservationStatus, GroupVoterSignatureDto,
    QuorumCommitClaims, quorum_commit_transcript_bytes,
};
use crate::ref_store::core::state_machine::RefCasSnapshot;

use super::{
    SEED_BYTES, SafeGcError, ensure_private_dir, read_private_file, read_private_json, verify_private_dir,
    write_private_file,
};

const KEYRING_MANIFEST: &str = "keyring.json";
const KEYRING_SCHEMA: u32 = 1;

/// Provision an absolute `#151` group keyring directory compatible with `GroupConsensusVerifier`.
pub fn write_refcas_group_keyring_dir(
    dir: &Path,
    group_id: i64,
    history_id: Uuid,
    quorum_threshold: usize,
    voters: &[(u64, u8, [u8; SEED_BYTES])],
) -> Result<(), SafeGcError> {
    if group_id < 0 || history_id.is_nil() || voters.is_empty() || voters.len() > 32 {
        return Err(SafeGcError::ArmingRejected("invalid Ref-CAS group keyring identity"));
    }
    if !dir.is_absolute() {
        return Err(SafeGcError::ArmingRejected("Ref-CAS group keyring directory must be absolute"));
    }
    let min_quorum = (voters.len() / 2) + 1;
    if quorum_threshold < min_quorum || quorum_threshold > voters.len() {
        return Err(SafeGcError::ArmingRejected("quorum_threshold must be strict majority <= voter count"));
    }
    let mut seen_voters = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let mut entries = Vec::with_capacity(voters.len());
    for (voter_id, key_id, key) in voters {
        if *voter_id == 0
            || !seen_voters.insert(*voter_id)
            || key.iter().all(|&byte| byte == 0)
            || !seen_keys.insert(*key)
        {
            return Err(SafeGcError::ArmingRejected("invalid or duplicate Ref-CAS voter key"));
        }
        entries.push((format!("g{group_id}-v{voter_id}.key"), *voter_id, *key_id, *key));
    }
    ensure_private_dir(dir)?;
    for (file, _, _, key) in &entries {
        write_private_file(&dir.join(file), key)?;
    }
    let manifest = serde_json::json!({
        "schema": KEYRING_SCHEMA,
        "groups": [{
            "group_id": group_id,
            "history_incarnation": history_id,
            "quorum_threshold": quorum_threshold,
            "voters": entries.iter().map(|(file, voter_id, key_id, _)| serde_json::json!({
                "voter_id": voter_id,
                "key_id": key_id,
                "key_file": file,
            })).collect::<Vec<_>>(),
        }],
    });
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| SafeGcError::Serialization(e.to_string()))?;
    write_private_file(&dir.join(KEYRING_MANIFEST), &bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringManifest {
    schema: u32,
    groups: Vec<KeyringGroup>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringGroup {
    group_id: i64,
    history_incarnation: Uuid,
    quorum_threshold: usize,
    voters: Vec<KeyringVoter>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringVoter {
    voter_id: u64,
    key_id: u8,
    key_file: String,
}

fn load_keyring_group(dir: &Path, group_id: i64, history_id: Uuid) -> Result<KeyringGroup, SafeGcError> {
    verify_private_dir(dir)?;
    let manifest: KeyringManifest = read_private_json(&dir.join(KEYRING_MANIFEST), 16 * 1024)?;
    if manifest.schema != KEYRING_SCHEMA {
        return Err(SafeGcError::DistributedPrereqsMissing("unsupported Ref-CAS keyring schema"));
    }
    let group = manifest
        .groups
        .into_iter()
        .find(|group| group.group_id == group_id && group.history_incarnation == history_id)
        .ok_or(SafeGcError::DistributedPrereqsMissing("Ref-CAS keyring has no matching group"))?;
    if group.quorum_threshold == 0 || group.quorum_threshold > group.voters.len() {
        return Err(SafeGcError::DistributedPrereqsMissing("Ref-CAS keyring quorum_threshold exceeds voter count"));
    }
    let mut voter_ids = BTreeSet::new();
    for voter in &group.voters {
        let safe_name = voter.key_file.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if voter.voter_id == 0 || !voter_ids.insert(voter.voter_id) || !safe_name || voter.key_file.contains("..") {
            return Err(SafeGcError::DistributedPrereqsMissing("invalid Ref-CAS keyring voter entry"));
        }
    }
    Ok(group)
}

/// Sign a `RefCasSnapshot` with every trusted voter key of one group.
pub fn sign_snapshot_with_keyring_dir(
    keyring_dir: &Path,
    group_id: i64,
    history_id: Uuid,
    group_epoch: i64,
    authority_epoch: i64,
    sm_snap: &RefCasSnapshot,
) -> Result<AttestedGroupSnapshotDto, SafeGcError> {
    if group_epoch <= 0 || authority_epoch <= 0 {
        return Err(SafeGcError::DistributedPrereqsMissing("Ref-CAS keyring group/authority epoch must be positive"));
    }
    let group = load_keyring_group(keyring_dir, group_id, history_id)?;
    if group.quorum_threshold == 0 || group.voters.is_empty() {
        return Err(SafeGcError::DistributedPrereqsMissing("Ref-CAS keyring group has no voters"));
    }
    sm_snap.verify_integrity().map_err(|_| SafeGcError::IncompleteProof("failed verifying RefCasSnapshot"))?;
    let Some(applied) = sm_snap.body.last_applied else {
        return Err(SafeGcError::DistributedPrereqsMissing("RefCasSnapshot has no applied log coordinate"));
    };
    if applied.term == 0 || applied.index == 0 {
        return Err(SafeGcError::DistributedPrereqsMissing("RefCasSnapshot applied log coordinate is invalid"));
    }
    let snapshot_bytes = serde_json::to_vec(sm_snap).map_err(|e| SafeGcError::Serialization(e.to_string()))?;
    let snapshot_sha256 = hex::encode(Sha256::digest(&snapshot_bytes));
    let snapshot_sha: [u8; 32] = Sha256::digest(&snapshot_bytes).into();
    let mut voter_signatures = Vec::with_capacity(group.voters.len());
    for voter in &group.voters {
        let key = read_private_file(&keyring_dir.join(&voter.key_file), SEED_BYTES)?;
        let claims = QuorumCommitClaims {
            group_id,
            history_incarnation: history_id,
            group_epoch,
            authority_epoch,
            raft_term: applied.term,
            committed_log_index: applied.index,
            voter_id: voter.voter_id,
            key_id: voter.key_id,
            snapshot_sha256: &snapshot_sha,
        };
        let transcript = quorum_commit_transcript_bytes(&claims);
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        voter_signatures.push(GroupVoterSignatureDto {
            voter_id: voter.voter_id,
            key_id: voter.key_id,
            mac_hex: hex::encode(hmac::sign(&hmac_key, &transcript).as_ref()),
        });
    }
    Ok(AttestedGroupSnapshotDto {
        group_id,
        history_incarnation: history_id,
        group_epoch,
        authority_epoch,
        raft_term: applied.term,
        committed_log_index: applied.index,
        snapshot_sha256,
        snapshot_bytes,
        voter_signatures,
    })
}

/// Authenticate an attested snapshot through `#151` `GroupConsensusVerifier` and return it verified.
pub fn verify_attested_snapshot_with_keyring(
    keyring_dir: &Path,
    repo_id: Uuid,
    tenant_id: Uuid,
    attested: &AttestedGroupSnapshotDto,
) -> Result<RefCasSnapshot, SafeGcError> {
    let verifier = GroupConsensusVerifier::from_keyring_dir(keyring_dir)
        .map_err(|_| SafeGcError::DistributedPrereqsMissing("invalid #151 Ref-CAS group keyring"))?;
    let binding = GroupHoldBinding {
        group_id: attested.group_id,
        history_incarnation: attested.history_incarnation,
        expected_group_epoch: attested.group_epoch,
        repository_id: repo_id,
        tenant_id,
        hold_ids: vec![Uuid::from_u128(0x5afe_6c00_0151_0001)],
        retire_request_id: Uuid::from_u128(0x5afe_6c00_0151_0002),
    };
    let observation = verifier
        .verify_attested_observation(
            attested,
            &binding,
            &attested.snapshot_sha256,
            &attested.snapshot_sha256,
            Some(attested.committed_log_index.max(1)),
        )
        .map_err(|_| {
            SafeGcError::DistributedPrereqsMissing("#151 GroupConsensusVerifier rejected Ref-CAS quorum attestation")
        })?;
    if !matches!(observation.status(), GroupObservationStatus::Active | GroupObservationStatus::Retired) {
        return Err(SafeGcError::DistributedPrereqsMissing("Ref-CAS quorum snapshot missing repository gate or stale"));
    }
    let snapshot: RefCasSnapshot = serde_json::from_slice(&attested.snapshot_bytes)
        .map_err(|_| SafeGcError::DistributedPrereqsMissing("attested RefCasSnapshot bytes are not canonical JSON"))?;
    snapshot
        .verify_integrity()
        .map_err(|_| SafeGcError::DistributedPrereqsMissing("attested RefCasSnapshot checksum mismatch"))?;
    Ok(snapshot)
}
