//! Legacy KV snapshot envelope (`rootyard-refcas-snapshot/1`).
//!
//! This shape and its canonical checksum payload are preserved byte-for-byte for existing KV
//! mode snapshots. Application mode uses the separate `/2` envelope.

use std::collections::BTreeMap;

use openraft::{BasicNode, LogId, SnapshotMeta, StoredMembership};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state_machine::codec::{hex_encode, is_valid_sha256_hex, validate_digest_and_boundary};
use crate::{E, Res};

pub(crate) const SNAPSHOT_FORMAT: &str = "rootyard-refcas-snapshot/1";

/// Self-verifying persisted snapshot payload transferred across Raft nodes and stored on disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEnvelope {
    pub format: String,
    pub node_id: u64,
    pub generation: u64,
    pub meta: SnapshotMeta<u64, BasicNode>,
    pub last_applied: Option<LogId<u64>>,
    pub last_membership: StoredMembership<u64, BasicNode>,
    pub state_digest_hex: String,
    pub applied_count: u64,
    pub boundary_entry_digest_hex: Option<String>,
    pub kv: BTreeMap<String, String>,
    pub payload_sha256_hex: String,
}

impl SnapshotEnvelope {
    /// Computes canonical SHA-256 digest over all payload fields (excluding `payload_sha256_hex`).
    pub fn compute_payload_sha256(&self) -> Res<String> {
        let mut copy = self.clone();
        copy.payload_sha256_hex.clear();
        let bytes = serde_json::to_vec(&copy).map_err(|e| E::Codec(format!("snapshot digest encode: {e}")))?;
        Ok(hex_encode(&Sha256::digest(&bytes)))
    }

    /// Verifies format marker, internal digest/boundary formats, embedded digest, and metadata consistency.
    pub fn verify_integrity(&self) -> Res<()> {
        if self.format != SNAPSHOT_FORMAT {
            return Err(E::Refused(format!("unknown snapshot format {:?}; expected {SNAPSHOT_FORMAT}", self.format)));
        }
        if self.last_applied != self.meta.last_log_id {
            return Err(E::Refused("snapshot envelope last_applied mismatches meta.last_log_id".into()));
        }
        if self.last_membership != self.meta.last_membership {
            return Err(E::Refused("snapshot envelope membership mismatches meta.last_membership".into()));
        }
        validate_digest_and_boundary(
            &self.state_digest_hex,
            self.last_applied.as_ref(),
            self.boundary_entry_digest_hex.as_deref(),
        )?;
        if !is_valid_sha256_hex(&self.payload_sha256_hex) {
            return Err(E::Codec("invalid snapshot payload_sha256_hex format".into()));
        }
        let expected = self.compute_payload_sha256()?;
        if expected != self.payload_sha256_hex {
            return Err(E::Codec(format!(
                "snapshot payload checksum mismatch: expected {}, got {}",
                expected, self.payload_sha256_hex
            )));
        }
        Ok(())
    }
}
