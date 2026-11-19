//! Optional application snapshot envelope (`rootyard-refcas-snapshot/2`).
//!
//! Legacy KV snapshots keep the byte-identical `rootyard-refcas-snapshot/1` shape. Application
//! mode snapshots carry the reducer's canonical state and its applied coordinate in a separate
//! envelope; KV state is forbidden, so application state is never disguised as KV rows.

use std::collections::BTreeMap;

use openraft::{BasicNode, LogId, SnapshotMeta, StoredMembership};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state_machine::app::{
    ApplicationLogId, ApplicationStateMachine, MAX_APP_STATE_BYTES, is_valid_sha256_hex, validate_domain,
};
use crate::state_machine::codec::{hex_decode, hex_encode, validate_digest_and_boundary};
use crate::{E, Res};

pub(crate) const SNAPSHOT_FORMAT_APP: &str = "rootyard-refcas-snapshot/2";

/// Application payload nested inside the v2 snapshot envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplicationSnapshotBody {
    pub(crate) domain: String,
    pub(crate) version: u16,
    pub(crate) last_applied: Option<ApplicationLogId>,
    pub(crate) state_digest_hex: String,
    pub(crate) state_sha256_hex: String,
    pub(crate) state_hex: String,
}

impl ApplicationSnapshotBody {
    pub(crate) fn verify_integrity(&self) -> Res<()> {
        validate_domain(&self.domain)?;
        if self.version == 0 {
            return Err(E::Refused("application snapshot version must be positive".into()));
        }
        if !is_valid_sha256_hex(&self.state_digest_hex) {
            return Err(E::Codec("invalid application snapshot state digest format".into()));
        }
        if !is_valid_sha256_hex(&self.state_sha256_hex) {
            return Err(E::Codec("invalid application snapshot state bytes digest format".into()));
        }
        if self.state_hex.len() > MAX_APP_STATE_BYTES.saturating_mul(2) {
            return Err(E::Refused("application snapshot state exceeds its byte ceiling".into()));
        }
        let bytes = hex_decode(&self.state_hex)?;
        if bytes.len() > MAX_APP_STATE_BYTES {
            return Err(E::Refused("application snapshot state exceeds its byte ceiling".into()));
        }
        let actual = hex_encode(&Sha256::digest(&bytes));
        if actual != self.state_sha256_hex {
            return Err(E::Codec("application snapshot state bytes digest mismatch".into()));
        }
        Ok(())
    }
}

/// Self-verifying application-mode snapshot envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplicationSnapshotEnvelope {
    pub(crate) format: String,
    pub(crate) node_id: u64,
    pub(crate) generation: u64,
    pub(crate) meta: SnapshotMeta<u64, BasicNode>,
    pub(crate) last_applied: Option<LogId<u64>>,
    pub(crate) last_membership: StoredMembership<u64, BasicNode>,
    pub(crate) state_digest_hex: String,
    pub(crate) applied_count: u64,
    pub(crate) boundary_entry_digest_hex: Option<String>,
    pub(crate) kv: BTreeMap<String, String>,
    pub(crate) app: ApplicationSnapshotBody,
    pub(crate) payload_sha256_hex: String,
}

impl ApplicationSnapshotEnvelope {
    pub(crate) fn compute_payload_sha256(&self) -> Res<String> {
        let mut copy = self.clone();
        copy.payload_sha256_hex.clear();
        let bytes =
            serde_json::to_vec(&copy).map_err(|e| E::Codec(format!("application snapshot digest encode: {e}")))?;
        Ok(hex_encode(&Sha256::digest(&bytes)))
    }

    pub(crate) fn verify_integrity(&self) -> Res<()> {
        if self.format != SNAPSHOT_FORMAT_APP {
            return Err(E::Refused(format!(
                "unknown application snapshot format {:?}; expected {SNAPSHOT_FORMAT_APP}",
                self.format
            )));
        }
        if self.last_applied != self.meta.last_log_id {
            return Err(E::Refused("application snapshot last_applied mismatches meta.last_log_id".into()));
        }
        if self.last_membership != self.meta.last_membership {
            return Err(E::Refused("application snapshot membership mismatches meta.last_membership".into()));
        }
        if !self.kv.is_empty() {
            return Err(E::Refused("application snapshot must not carry KV state".into()));
        }
        validate_digest_and_boundary(
            &self.state_digest_hex,
            self.last_applied.as_ref(),
            self.boundary_entry_digest_hex.as_deref(),
        )?;
        if !is_valid_sha256_hex(&self.payload_sha256_hex) {
            return Err(E::Codec("invalid application snapshot payload_sha256_hex format".into()));
        }
        let expected = self.compute_payload_sha256()?;
        if expected != self.payload_sha256_hex {
            return Err(E::Codec(format!(
                "application snapshot payload checksum mismatch: expected {expected}, got {}",
                self.payload_sha256_hex
            )));
        }
        self.app.verify_integrity()?;
        if self.app.last_applied != self.last_applied.map(ApplicationLogId::from_log_id) {
            return Err(E::Refused("application snapshot body coordinate mismatches envelope".into()));
        }
        Ok(())
    }
}

/// Exports canonical application state into a v2 snapshot body.
pub(crate) fn build_application_body(
    app: &dyn ApplicationStateMachine,
    last_applied: Option<LogId<u64>>,
) -> Res<ApplicationSnapshotBody> {
    let expected = last_applied.map(ApplicationLogId::from_log_id);
    if app.last_applied() != expected {
        return Err(E::Refused(format!(
            "application snapshot coordinate {:?} mismatches state metadata {expected:?}",
            app.last_applied()
        )));
    }
    validate_domain(app.domain())?;
    if app.version() == 0 {
        return Err(E::Refused("application version must be positive".into()));
    }
    let bytes = app.export_state().map_err(|e| E::Refused(format!("application snapshot export refused: {e}")))?;
    if bytes.len() > MAX_APP_STATE_BYTES {
        return Err(E::Refused("application snapshot state exceeds its byte ceiling".into()));
    }
    let state_digest_hex =
        app.state_digest_hex().map_err(|e| E::Refused(format!("application snapshot digest refused: {e}")))?;
    if !is_valid_sha256_hex(&state_digest_hex) {
        return Err(E::Refused("application snapshot state digest is not canonical SHA-256 hex".into()));
    }
    Ok(ApplicationSnapshotBody {
        domain: app.domain().to_owned(),
        version: app.version(),
        last_applied: expected,
        state_digest_hex,
        state_sha256_hex: hex_encode(&Sha256::digest(&bytes)),
        state_hex: hex_encode(&bytes),
    })
}

/// Restores a staged reducer from a verified v2 application body.
pub(crate) fn restore_application_body(
    body: &ApplicationSnapshotBody,
    app: &mut dyn ApplicationStateMachine,
    expected_last: Option<LogId<u64>>,
) -> Res<()> {
    body.verify_integrity()?;
    if body.domain != app.domain() || body.version != app.version() {
        return Err(E::Refused(format!(
            "application snapshot identity mismatch: snapshot {}/{} but reducer {}/{}",
            body.domain,
            body.version,
            app.domain(),
            app.version()
        )));
    }
    let expected = expected_last.map(ApplicationLogId::from_log_id);
    if body.last_applied != expected {
        return Err(E::Refused(format!(
            "application snapshot coordinate {:?} mismatches Raft snapshot {expected:?}",
            body.last_applied
        )));
    }
    let bytes = hex_decode(&body.state_hex)?;
    app.restore_state(&bytes).map_err(|e| E::Refused(format!("application snapshot restore refused: {e}")))?;
    if app.last_applied() != body.last_applied {
        return Err(E::Refused("restored application snapshot coordinate mismatch".into()));
    }
    let digest =
        app.state_digest_hex().map_err(|e| E::Refused(format!("restored application snapshot digest refused: {e}")))?;
    if digest != body.state_digest_hex {
        return Err(E::Refused("restored application snapshot state digest mismatch".into()));
    }
    Ok(())
}
