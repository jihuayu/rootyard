//! Per-voter durable Ed25519 keys and X.509-bound voter identity persistence for the
//! fsynced WAL Raft backend (`WalSyncedRaftBackend`, #153).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{AppliedLogId, RefCasSnapshot};

use super::peer_attestation::{
    PeerDurableAttestation, PeerDurableAttestationClaims, derive_voter_uuid_bound, load_or_create_ed25519_keypair,
};
use super::raft_barrier::{MIN_QUORUM_VOTERS, VoterWalAck};
use super::types::{PairedBackupError, sha256_json_tagged};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WalVoterBinding {
    pub(super) slot: usize,
    pub(super) cert_sha256: String,
    pub(super) ed25519_pubkey_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedVoters {
    group_id: i64,
    voter_ids: Vec<Uuid>,
    bindings: Vec<WalVoterBinding>,
    seal: String,
}

pub(super) struct WalVoterKeys {
    pub(super) voter_ids: Vec<Uuid>,
    pub(super) bindings: Vec<WalVoterBinding>,
    pub(super) keys: Vec<Ed25519KeyPair>,
}

/// Borrowed view over a WAL backend's durable per-voter identities while signing.
pub(super) struct WalVoterRing<'a> {
    pub(super) voter_ids: &'a [Uuid],
    pub(super) bindings: &'a [WalVoterBinding],
    pub(super) keys: &'a [Ed25519KeyPair],
}

pub(super) fn sidecar(base: &Path, suffix: &str) -> PathBuf {
    let mut os = base.as_os_str().to_owned();
    os.push(format!(".{suffix}"));
    PathBuf::from(os)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), PairedBackupError> {
    let tmp = sidecar(path, "tmp");
    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Load or create the three per-voter `0o600` Ed25519 keypairs (`.voter{slot}.pk8`) and
/// their X.509-bound `voter_id`s, persisting the bindings alongside the WAL.
pub(super) fn open_or_create_voters(wal_path: &Path, group_id: i64) -> Result<WalVoterKeys, PairedBackupError> {
    let voters_path = sidecar(wal_path, "voters");
    if voters_path.exists() {
        let persisted: PersistedVoters = serde_json::from_slice(&fs::read(&voters_path)?)
            .map_err(|_| PairedBackupError::StateMachine("corrupt voters file".into()))?;
        let mut clean = persisted.clone();
        clean.seal.clear();
        if persisted.group_id != group_id
            || sha256_json_tagged(b"rootyard-wal-voters-file-v1", &clean)? != persisted.seal
        {
            return Err(PairedBackupError::StateMachine("voters file group_id or seal mismatch".into()));
        }
        if persisted.bindings.len() != persisted.voter_ids.len() || persisted.bindings.len() < MIN_QUORUM_VOTERS {
            return Err(PairedBackupError::StateMachine("voters file binding count mismatch".into()));
        }
        let mut keys = Vec::with_capacity(persisted.bindings.len());
        let mut ids = Vec::with_capacity(persisted.bindings.len());
        for (slot, binding) in persisted.bindings.iter().enumerate() {
            if binding.slot != slot {
                return Err(PairedBackupError::StateMachine("voters file slot order mismatch".into()));
            }
            let (keypair, pubkey_hex) =
                load_or_create_ed25519_keypair(&sidecar(wal_path, &format!("voter{slot}.pk8")))?;
            if pubkey_hex != binding.ed25519_pubkey_hex {
                return Err(PairedBackupError::StateMachine("voter Ed25519 key file changed".into()));
            }
            ids.push(derive_voter_uuid_bound(
                group_id,
                (slot + 1) as u64,
                &binding.cert_sha256,
                &binding.ed25519_pubkey_hex,
            ));
            keys.push(keypair);
        }
        if ids != persisted.voter_ids {
            return Err(PairedBackupError::StateMachine("voters file voter_id binding mismatch".into()));
        }
        return Ok(WalVoterKeys { voter_ids: ids, bindings: persisted.bindings, keys });
    }

    let mut bindings = Vec::with_capacity(MIN_QUORUM_VOTERS);
    let mut keys = Vec::with_capacity(MIN_QUORUM_VOTERS);
    for slot in 0..MIN_QUORUM_VOTERS {
        let (keypair, pubkey_hex) = load_or_create_ed25519_keypair(&sidecar(wal_path, &format!("voter{slot}.pk8")))?;
        let cert_sha256 = sha256_json_tagged(b"wal-voter-cert", &(group_id, slot as u64, &pubkey_hex))?;
        bindings.push(WalVoterBinding { slot, cert_sha256, ed25519_pubkey_hex: pubkey_hex });
        keys.push(keypair);
    }
    let ids: Vec<Uuid> = bindings
        .iter()
        .enumerate()
        .map(|(slot, binding)| {
            derive_voter_uuid_bound(group_id, (slot + 1) as u64, &binding.cert_sha256, &binding.ed25519_pubkey_hex)
        })
        .collect();
    let mut persisted =
        PersistedVoters { group_id, voter_ids: ids.clone(), bindings: bindings.clone(), seal: String::new() };
    persisted.seal = sha256_json_tagged(b"rootyard-wal-voters-file-v1", &persisted)?;
    write_atomic(&voters_path, &serde_json::to_vec(&persisted).unwrap_or_default())?;
    Ok(WalVoterKeys { voter_ids: ids, bindings, keys })
}

/// Sign a locally fsynced `"commit"` `VoterWalAck` with that voter's own Ed25519 key.
pub(super) fn sign_commit_ack(
    ring: &WalVoterRing<'_>,
    group_id: i64,
    slot: usize,
    group_epoch: i64,
    log_id: AppliedLogId,
    command_sha256: &str,
    wal_record_digest: &str,
) -> Result<VoterWalAck, PairedBackupError> {
    let binding =
        ring.bindings.get(slot).ok_or(PairedBackupError::FreezeNotHeld("missing durable voter Ed25519 binding"))?;
    let keypair = ring.keys.get(slot).ok_or(PairedBackupError::FreezeNotHeld("missing durable voter Ed25519 key"))?;
    let attestation = PeerDurableAttestation::sign(
        PeerDurableAttestationClaims {
            kind: "commit".to_owned(),
            group_id,
            group_epoch,
            node_id: (slot + 1) as u64,
            voter_id: ring.voter_ids[slot],
            peer_cert_sha256: binding.cert_sha256.clone(),
            ed25519_pubkey_hex: binding.ed25519_pubkey_hex.clone(),
            raft_term: log_id.term,
            raft_committed_index: log_id.index,
            refcas_seq: log_id.index,
            subject_digest: command_sha256.to_owned(),
            secondary_digest: wal_record_digest.to_owned(),
        },
        keypair,
    )?;
    VoterWalAck {
        voter_id: ring.voter_ids[slot],
        log_id,
        command_sha256: command_sha256.to_owned(),
        wal_record_digest: wal_record_digest.to_owned(),
        peer_attestation: attestation,
        ack_digest: String::new(),
    }
    .seal()
}

/// Sign `"cutpoint"` attestations for every online voter (`> N/2` required by the caller).
pub(super) fn sign_cutpoint_attestations(
    ring: &WalVoterRing<'_>,
    group_id: i64,
    group_epoch: i64,
    online: &[bool],
    snapshot: &RefCasSnapshot,
    state_digest: &str,
) -> Result<Vec<PeerDurableAttestation>, PairedBackupError> {
    let applied = snapshot.body.last_applied.ok_or(PairedBackupError::IncompleteCut(
        "durable WAL snapshot has no applied entry for a cutpoint attestation",
    ))?;
    let mut attestations = Vec::new();
    for slot in 0..ring.voter_ids.len() {
        if !online.get(slot).copied().unwrap_or(false) {
            continue;
        }
        let binding = &ring.bindings[slot];
        attestations.push(PeerDurableAttestation::sign(
            PeerDurableAttestationClaims {
                kind: "cutpoint".to_owned(),
                group_id,
                group_epoch,
                node_id: (slot + 1) as u64,
                voter_id: ring.voter_ids[slot],
                peer_cert_sha256: binding.cert_sha256.clone(),
                ed25519_pubkey_hex: binding.ed25519_pubkey_hex.clone(),
                raft_term: applied.term.max(1),
                raft_committed_index: applied.index,
                refcas_seq: applied.index,
                subject_digest: state_digest.to_owned(),
                secondary_digest: snapshot.checksum.clone(),
            },
            &ring.keys[slot],
        )?);
    }
    Ok(attestations)
}
