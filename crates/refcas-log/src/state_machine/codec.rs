use openraft::{EntryPayload, LogId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{E, Res, checksum, je};

pub(crate) const MAX_KV_KEY_BYTES: usize = 4096;
pub(crate) const MAX_KV_VAL_BYTES: usize = 256 * 1024;

/// Structured deterministic state-machine mutation carried inside `EntryPayload::Normal`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SmCommand {
    Put { key: String, value: String },
    Delete { key: String },
}

impl SmCommand {
    /// Decodes strict `SmCommand` JSON, rejecting unknown fields.
    pub fn decode_strict(bytes: &[u8]) -> Res<Self> {
        serde_json::from_slice(bytes).map_err(|e| E::Codec(format!("decode sm command: {e}")))
    }

    /// Encodes this command as compact JSON bytes for Raft log submission.
    pub fn encode(&self) -> Res<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| E::Codec(format!("encode sm command: {e}")))
    }

    /// Validates Ref-CAS metadata key and value byte limits prior to Raft WAL append.
    pub fn validate_bounds(&self) -> Res<()> {
        validate_kv_cmd(self)
    }
}

pub(crate) struct DecodedPayload {
    pub(crate) kind: &'static str,
    pub(crate) payload_bytes: Vec<u8>,
    pub(crate) kv_cmd: Option<SmCommand>,
    pub(crate) membership: Option<openraft::Membership<u64, openraft::BasicNode>>,
}

pub(crate) fn decode_entry_payload(payload: &EntryPayload<crate::LogTypeConfig>) -> Res<DecodedPayload> {
    match payload {
        EntryPayload::Blank => {
            Ok(DecodedPayload { kind: "blank", payload_bytes: Vec::new(), kv_cmd: None, membership: None })
        }
        EntryPayload::Normal(bytes) => {
            if let Ok(cmd) = serde_json::from_slice::<SmCommand>(bytes) {
                validate_kv_cmd(&cmd)?;
                Ok(DecodedPayload { kind: "kv", payload_bytes: cmd.encode()?, kv_cmd: Some(cmd), membership: None })
            } else {
                Ok(DecodedPayload { kind: "normal", payload_bytes: bytes.clone(), kv_cmd: None, membership: None })
            }
        }
        EntryPayload::Membership(mem) => Ok(DecodedPayload {
            kind: "membership",
            payload_bytes: je(mem)?.into_bytes(),
            kv_cmd: None,
            membership: Some(mem.clone()),
        }),
    }
}

fn validate_kv_cmd(cmd: &SmCommand) -> Res<()> {
    match cmd {
        SmCommand::Put { key, value } => {
            if key.len() > MAX_KV_KEY_BYTES || value.len() > MAX_KV_VAL_BYTES {
                return Err(E::Refused("kv put exceeds key/value byte limits".into()));
            }
        }
        SmCommand::Delete { key } => {
            if key.len() > MAX_KV_KEY_BYTES {
                return Err(E::Refused("kv delete exceeds key byte limit".into()));
            }
        }
    }
    Ok(())
}

pub(crate) fn compute_entry_digest(lid: &LogId<u64>, kind: &str, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(lid.leader_id.term.to_be_bytes());
    hasher.update(lid.leader_id.node_id.to_be_bytes());
    hasher.update(lid.index.to_be_bytes());
    hasher.update((kind.len() as u64).to_be_bytes());
    hasher.update(kind.as_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

pub(crate) fn advance_state_digest(prev_hex: &str, lid: &LogId<u64>, entry_digest: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hex.as_bytes());
    hasher.update(lid.leader_id.term.to_be_bytes());
    hasher.update(lid.leader_id.node_id.to_be_bytes());
    hasher.update(lid.index.to_be_bytes());
    hasher.update(entry_digest);
    let out: [u8; 32] = hasher.finalize().into();
    hex_encode(&out)
}

pub(crate) fn sm_entry_checksum(idx: i64, log_id: &str, kind: &str, payload: &[u8], digest: &[u8]) -> Vec<u8> {
    checksum(&[b"sm_entry", &idx.to_be_bytes(), log_id.as_bytes(), kind.as_bytes(), payload, digest])
}

pub(crate) fn sm_kv_checksum(k: &str, v: &str, last_idx: i64) -> Vec<u8> {
    checksum(&[b"sm_kv", k.as_bytes(), v.as_bytes(), &last_idx.to_be_bytes()])
}

pub(crate) fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn validate_digest_and_boundary(
    state_digest: &str,
    boundary_id: Option<&LogId<u64>>,
    boundary_digest: Option<&str>,
) -> Res<()> {
    if !is_valid_sha256_hex(state_digest) {
        return Err(E::Codec("corrupt state_digest format".into()));
    }
    match (boundary_id, boundary_digest) {
        (None, None) => Ok(()),
        (Some(_), Some(hex)) if is_valid_sha256_hex(hex) => Ok(()),
        (Some(_), None) => Err(E::Refused("missing boundary entry digest".into())),
        (Some(_), Some(_)) => Err(E::Codec("corrupt boundary entry digest format".into())),
        (None, Some(_)) => Err(E::Refused("unexpected boundary entry digest without log id".into())),
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
