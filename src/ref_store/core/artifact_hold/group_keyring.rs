//! Trusted group-bound consensus quorum keyring and HMAC-SHA256 commit
//! verifier (`#151`).
//!
//! [`GroupConsensusVerifier`] holds per-group trusted voter keys loaded ONLY from
//! an explicit operator keyring (`ROOTYARD_REFCAS_GROUP_KEYRING` / strict
//! `0700`/`0600` directory) — zero ambient keys, zero defaults, zero `Deserialize`.
//! Unauthenticated `RefCasSnapshot` / `RefCasStateMachine` instances cannot mint
//! retirement proofs.

use super::bridge_contract::RetentionBridgeError;
use crate::ref_store::contract::RequestDigest;
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const GROUP_KEYRING_ENV: &str = "ROOTYARD_REFCAS_GROUP_KEYRING";
const MANIFEST_FILE: &str = "keyring.json";
const MANIFEST_SCHEMA: u32 = 1;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SIGNATURES: usize = 32;
const KEY_BYTES: usize = 32;
const MAX_KEY_ID_LEN: usize = 64;
const QUORUM_DOMAIN: &[u8] = b"rootyard/refcas-group-quorum-commit/v1";

/// Canonical commit claims bound inside every voter HMAC-SHA256 signature.
#[derive(Clone, Copy, Debug)]
pub struct QuorumCommitClaims<'a> {
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub group_epoch: i64,
    pub authority_epoch: i64,
    pub raft_term: u64,
    pub committed_log_index: u64,
    pub voter_id: u64,
    pub key_id: u8,
    pub snapshot_sha256: &'a [u8; 32],
}

/// One voter's quorum commit HMAC-SHA256 signature over canonical commit metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupVoterSignatureDto {
    pub voter_id: u64,
    pub key_id: u8,
    pub mac_hex: String,
}

/// Quorum-signed Ref-CAS snapshot envelope delivered by a consensus group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedGroupSnapshotDto {
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub group_epoch: i64,
    pub authority_epoch: i64,
    pub raft_term: u64,
    pub committed_log_index: u64,
    pub snapshot_sha256: String,
    pub snapshot_bytes: Vec<u8>,
    pub voter_signatures: Vec<GroupVoterSignatureDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupKeyringManifest {
    schema: u32,
    groups: Vec<ManifestGroup>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestGroup {
    group_id: i64,
    history_incarnation: Uuid,
    quorum_threshold: usize,
    voters: Vec<ManifestVoter>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestVoter {
    voter_id: u64,
    key_id: u8,
    key_file: String,
}

struct TrustedGroupQuorum {
    quorum_threshold: usize,
    voter_keys: BTreeMap<(u64, u8), Zeroizing<[u8; KEY_BYTES]>>,
}

/// Trusted non-deserializable consensus keyring verifier (redacted `Debug`, zero default keys).
pub struct GroupConsensusVerifier {
    groups: BTreeMap<(i64, Uuid), TrustedGroupQuorum>,
}

impl fmt::Debug for GroupConsensusVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupConsensusVerifier").field("group_count", &self.groups.len()).finish_non_exhaustive()
    }
}

/// Domain-separated canonical transcript authenticated by each quorum voter key.
pub fn quorum_commit_transcript_bytes(claims: &QuorumCommitClaims<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(QUORUM_DOMAIN.len() + 1 + 8 * 5 + 16 + 1 + 32);
    out.extend_from_slice(QUORUM_DOMAIN);
    out.push(0);
    out.extend_from_slice(&claims.group_id.to_be_bytes());
    out.extend_from_slice(claims.history_incarnation.as_bytes());
    out.extend_from_slice(&claims.group_epoch.to_be_bytes());
    out.extend_from_slice(&claims.authority_epoch.to_be_bytes());
    out.extend_from_slice(&claims.raft_term.to_be_bytes());
    out.extend_from_slice(&claims.committed_log_index.to_be_bytes());
    out.extend_from_slice(&claims.voter_id.to_be_bytes());
    out.push(claims.key_id);
    out.extend_from_slice(claims.snapshot_sha256);
    out
}

impl GroupConsensusVerifier {
    pub fn from_env() -> Result<Self, RetentionBridgeError> {
        let dir = std::env::var_os(GROUP_KEYRING_ENV)
            .ok_or_else(|| RetentionBridgeError::InvalidBinding("missing consensus group keyring env".into()))?;
        Self::from_keyring_dir(Path::new(&dir))
    }

    pub fn from_keyring_dir(dir: &Path) -> Result<Self, RetentionBridgeError> {
        let err = |msg: &str| RetentionBridgeError::InvalidBinding(msg.into());
        if !dir.is_absolute() {
            return Err(err("consensus keyring path must be absolute"));
        }
        verify_private_dir(dir)?;
        let manifest_bytes = read_private_file(&dir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
        let manifest: GroupKeyringManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|_| err("invalid consensus keyring manifest"))?;
        if manifest.schema != MANIFEST_SCHEMA || manifest.groups.is_empty() {
            return Err(err("unsupported or empty consensus keyring schema"));
        }
        let (mut groups, mut seen_keys) = (BTreeMap::new(), BTreeSet::<[u8; KEY_BYTES]>::new());
        for grp in manifest.groups {
            if grp.group_id < 0 || grp.history_incarnation.is_nil() || grp.voters.is_empty() {
                return Err(err("invalid group keyring entry"));
            }
            let min_quorum = (grp.voters.len() / 2) + 1;
            if grp.quorum_threshold < min_quorum || grp.quorum_threshold > grp.voters.len() {
                return Err(err("quorum_threshold must be strict majority <= voter count"));
            }
            let (mut voter_keys, mut seen_voters) = (BTreeMap::new(), BTreeSet::new());
            for v in grp.voters {
                if v.voter_id == 0 || !seen_voters.insert(v.voter_id) || !valid_key_filename(&v.key_file) {
                    return Err(err("invalid or duplicate voter entry in keyring"));
                }
                let raw = read_private_file(&dir.join(&v.key_file), KEY_BYTES)?;
                if raw.len() != KEY_BYTES || raw.iter().all(|&b| b == 0) {
                    return Err(err("voter key file must contain 32 non-zero bytes"));
                }
                let mut key_arr = Zeroizing::new([0u8; KEY_BYTES]);
                key_arr.copy_from_slice(&raw);
                if !seen_keys.insert(*key_arr) {
                    return Err(err("duplicate voter key material across keyring"));
                }
                voter_keys.insert((v.voter_id, v.key_id), key_arr);
            }
            if groups
                .insert(
                    (grp.group_id, grp.history_incarnation),
                    TrustedGroupQuorum { quorum_threshold: grp.quorum_threshold, voter_keys },
                )
                .is_some()
            {
                return Err(err("duplicate (group_id, history_incarnation) in keyring"));
            }
        }
        Ok(Self { groups })
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub(super) fn verify_quorum_attestation(
        &self,
        attested: &AttestedGroupSnapshotDto,
    ) -> Result<[u8; 32], RetentionBridgeError> {
        if attested.snapshot_bytes.is_empty()
            || attested.snapshot_bytes.len() > MAX_SNAPSHOT_BYTES
            || attested.voter_signatures.is_empty()
            || attested.voter_signatures.len() > MAX_SIGNATURES
            || attested.group_id < 0
            || attested.history_incarnation.is_nil()
            || attested.group_epoch <= 0
            || attested.authority_epoch <= 0
            || attested.raft_term == 0
            || attested.committed_log_index == 0
        {
            return Err(RetentionBridgeError::UntrustedObservationProof);
        }
        RequestDigest::from_str(&attested.snapshot_sha256)?;
        let expected_sha_bytes =
            hex::decode(&attested.snapshot_sha256).map_err(|_| RetentionBridgeError::UntrustedObservationProof)?;
        let expected_sha: [u8; 32] =
            expected_sha_bytes.try_into().map_err(|_| RetentionBridgeError::UntrustedObservationProof)?;
        let actual_sha: [u8; 32] = Sha256::digest(&attested.snapshot_bytes).into();
        if actual_sha != expected_sha {
            return Err(RetentionBridgeError::UntrustedObservationProof);
        }
        let Some(quorum) = self.groups.get(&(attested.group_id, attested.history_incarnation)) else {
            return Err(RetentionBridgeError::UntrustedObservationProof);
        };
        let mut verified_voters = BTreeSet::new();
        for sig in &attested.voter_signatures {
            if sig.voter_id == 0 || !verified_voters.insert(sig.voter_id) {
                return Err(RetentionBridgeError::UntrustedObservationProof);
            }
            let Some(secret) = quorum.voter_keys.get(&(sig.voter_id, sig.key_id)) else {
                return Err(RetentionBridgeError::UntrustedObservationProof);
            };
            let mac = hex::decode(&sig.mac_hex).map_err(|_| RetentionBridgeError::UntrustedObservationProof)?;
            if mac.len() != 32 {
                return Err(RetentionBridgeError::UntrustedObservationProof);
            }
            let claims = QuorumCommitClaims {
                group_id: attested.group_id,
                history_incarnation: attested.history_incarnation,
                group_epoch: attested.group_epoch,
                authority_epoch: attested.authority_epoch,
                raft_term: attested.raft_term,
                committed_log_index: attested.committed_log_index,
                voter_id: sig.voter_id,
                key_id: sig.key_id,
                snapshot_sha256: &expected_sha,
            };
            let transcript = quorum_commit_transcript_bytes(&claims);
            let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &secret[..]);
            if hmac::verify(&hmac_key, &transcript, &mac).is_err() {
                return Err(RetentionBridgeError::UntrustedObservationProof);
            }
        }
        if verified_voters.len() < quorum.quorum_threshold {
            return Err(RetentionBridgeError::UntrustedObservationProof);
        }
        Ok(expected_sha)
    }

    #[cfg(test)]
    pub(super) fn from_test_quorums(groups: Vec<(i64, Uuid, usize, Vec<(u64, u8, [u8; KEY_BYTES])>)>) -> Self {
        let mut map = BTreeMap::new();
        for (gid, hist, threshold, voters) in groups {
            let mut voter_keys = BTreeMap::new();
            for (vid, kid, raw) in voters {
                voter_keys.insert((vid, kid), Zeroizing::new(raw));
            }
            map.insert((gid, hist), TrustedGroupQuorum { quorum_threshold: threshold, voter_keys });
        }
        Self { groups: map }
    }
}

fn valid_key_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_KEY_ID_LEN
        && name.ends_with(".key")
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && !name.contains("..")
}

fn verify_private_dir(dir: &Path) -> Result<(), RetentionBridgeError> {
    let err = |msg: &str| RetentionBridgeError::InvalidBinding(msg.into());
    let meta = fs::symlink_metadata(dir).map_err(|_| err("consensus keyring dir unavailable"))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(err("consensus keyring dir must be a real directory"));
    }
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid || meta.mode() & 0o777 != 0o700 {
            return Err(err("consensus keyring dir must be mode 0700 owned by euid"));
        }
    }
    Ok(())
}

fn read_private_file(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, RetentionBridgeError> {
    let err = |msg: &str| RetentionBridgeError::InvalidBinding(msg.into());
    #[cfg(unix)]
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| err("consensus keyring file unavailable"))?;
    #[cfg(not(unix))]
    let file = File::options().read(true).open(path).map_err(|_| err("consensus keyring file unavailable"))?;
    let meta = file.metadata().map_err(|_| err("consensus keyring file unavailable"))?;
    if !meta.is_file() || meta.len() > limit as u64 {
        return Err(err("consensus keyring file exceeds bounds or is not a file"));
    }
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid || meta.mode() & 0o777 != 0o600 {
            return Err(err("consensus keyring file must be mode 0600 owned by euid"));
        }
    }
    let named = fs::symlink_metadata(path).map_err(|_| err("consensus keyring file unavailable"))?;
    if !named.is_file() || named.file_type().is_symlink() {
        return Err(err("consensus keyring file cannot be a symlink"));
    }
    #[cfg(unix)]
    if named.dev() != meta.dev() || named.ino() != meta.ino() {
        return Err(err("consensus keyring file changed during open"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0).min(limit)));
    (&file).take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| err("failed reading consensus keyring file"))?;
    if bytes.len() > limit {
        return Err(err("consensus keyring file exceeds size cap"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn test_voter_key(tag: u8, vid: u64) -> [u8; 32] {
        let mut raw = [tag; 32];
        raw[0] = vid as u8;
        raw[31] = tag.wrapping_add(0x41);
        raw
    }

    #[test]
    fn keyring_loader_rejects_weak_quorum_zero_keys_dup_keys_and_bad_mode() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let h1 = Uuid::from_u128(0xabc1);
        let h2 = Uuid::from_u128(0xabc2);
        let write_key = |name: &str, bytes: [u8; 32], mode: u32| {
            let p = dir.path().join(name);
            std::fs::write(&p, bytes).unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let _ = mode;
        };
        for vid in 1..=3 {
            write_key(&format!("g1-v{vid}.key"), test_voter_key(0x11, vid), 0o600);
            write_key(&format!("g2-v{vid}.key"), test_voter_key(0x22, vid), 0o600);
        }
        write_key("zero.key", [0u8; 32], 0o600);
        let mk_voters = |prefix: &str| -> Vec<serde_json::Value> {
            (1..=3)
                .map(
                    |vid| serde_json::json!({"voter_id": vid, "key_id": 1, "key_file": format!("{prefix}-v{vid}.key")}),
                )
                .collect()
        };
        let write_manifest = |val: serde_json::Value| {
            let mp = dir.path().join("keyring.json");
            std::fs::write(&mp, serde_json::to_vec(&val).unwrap()).unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(&mp, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        // Non-majority threshold (1 of 3) MUST fail closed.
        write_manifest(
            serde_json::json!({"schema": 1, "groups": [{"group_id": 10, "history_incarnation": h1, "quorum_threshold": 1, "voters": mk_voters("g1")}]}),
        );
        assert!(GroupConsensusVerifier::from_keyring_dir(dir.path()).is_err());

        // All-zero key file MUST fail closed.
        write_manifest(
            serde_json::json!({"schema": 1, "groups": [{"group_id": 10, "history_incarnation": h1, "quorum_threshold": 1, "voters": [{"voter_id": 1, "key_id": 1, "key_file": "zero.key"}]}]}),
        );
        assert!(GroupConsensusVerifier::from_keyring_dir(dir.path()).is_err());

        // Strict majority 2-of-3 across two groups loads cleanly.
        write_manifest(serde_json::json!({
            "schema": 1,
            "groups": [
                {"group_id": 10, "history_incarnation": h1, "quorum_threshold": 2, "voters": mk_voters("g1")},
                {"group_id": 20, "history_incarnation": h2, "quorum_threshold": 2, "voters": mk_voters("g2")}
            ]
        }));
        let loaded = GroupConsensusVerifier::from_keyring_dir(dir.path()).unwrap();
        assert_eq!(loaded.group_count(), 2);

        // Relaxed key file permissions on Unix MUST fail closed.
        #[cfg(unix)]
        {
            std::fs::set_permissions(dir.path().join("g1-v1.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(GroupConsensusVerifier::from_keyring_dir(dir.path()).is_err());
        }
    }
}
