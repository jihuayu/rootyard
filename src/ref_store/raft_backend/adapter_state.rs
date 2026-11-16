//! Sealed adapter state wrapper for Root snapshot bytes plus the typed outcome ledger.
//!
//! A legacy bare Root `RefCasSnapshot` remains accepted. Once an outcome exists, export uses a
//! versioned `/2` adapter envelope so the outcome ledger is covered by the application state
//! digest and by `/2` Raft snapshots. Unknown adapter formats fail closed.

use std::collections::BTreeMap;

use rootyard_refcas_log::state_machine::{ApplicationError, ApplicationLogId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ref_store::core::state_machine::RefCasStateMachine;
use crate::ref_store::raft_backend::outcome::StoredOutcome;

pub(crate) const ADAPTER_STATE_FORMAT: &str = "rootyard-refcas-adapter/2";
const ADAPTER_DIGEST_DOMAIN: &[u8] = b"rootyard-refcas-adapter-state-v2\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterState {
    format: String,
    /// Canonical Root `RefCasSnapshot` JSON, kept as text to avoid a nested JSON byte array.
    root_snapshot: String,
    outcomes: Vec<StoredOutcome>,
}

#[derive(Deserialize)]
struct StateProbe {
    format: String,
}

pub(crate) fn export_adapter_state(
    root_snapshot: Vec<u8>,
    outcomes: &BTreeMap<ApplicationLogId, StoredOutcome>,
) -> Result<Vec<u8>, ApplicationError> {
    if outcomes.is_empty() {
        return Ok(root_snapshot);
    }
    let root_snapshot = String::from_utf8(root_snapshot)
        .map_err(|_| ApplicationError::new("root Ref-CAS snapshot is not canonical UTF-8 JSON"))?;
    let state = AdapterState {
        format: ADAPTER_STATE_FORMAT.to_owned(),
        root_snapshot,
        outcomes: outcomes.values().cloned().collect(),
    };
    serde_json::to_vec(&state).map_err(|e| ApplicationError::new(format!("encode adapter state: {e}")))
}

pub(crate) fn restore_adapter_state(
    bytes: &[u8],
) -> Result<(RefCasStateMachine, BTreeMap<ApplicationLogId, StoredOutcome>), ApplicationError> {
    let probe = serde_json::from_slice::<StateProbe>(bytes).ok();
    if let Some(probe) = probe.as_ref() {
        if probe.format == ADAPTER_STATE_FORMAT {
            let state: AdapterState = serde_json::from_slice(bytes)
                .map_err(|e| ApplicationError::new(format!("decode adapter state: {e}")))?;
            let machine = RefCasStateMachine::restore_bytes(state.root_snapshot.as_bytes())
                .map_err(|e| ApplicationError::new(format!("restore root snapshot: {e}")))?;
            let mut outcomes = BTreeMap::new();
            for outcome in state.outcomes {
                let log_id = outcome.log_id;
                if outcomes.insert(log_id, outcome).is_some() {
                    return Err(ApplicationError::new("duplicate outcome at one application coordinate"));
                }
            }
            validate_outcomes(&machine, &outcomes)?;
            return Ok((machine, outcomes));
        }
        if probe.format.starts_with("rootyard-refcas-adapter/") {
            return Err(ApplicationError::new(format!(
                "unknown adapter state format {:?}; refusing compatibility fallback",
                probe.format
            )));
        }
    }
    let machine = RefCasStateMachine::restore_bytes(bytes)
        .map_err(|e| ApplicationError::new(format!("restore legacy root snapshot: {e}")))?;
    Ok((machine, BTreeMap::new()))
}

fn validate_outcomes(
    machine: &RefCasStateMachine,
    outcomes: &BTreeMap<ApplicationLogId, StoredOutcome>,
) -> Result<(), ApplicationError> {
    let last = machine.last_applied().map(|log_id| ApplicationLogId::new(log_id.term, log_id.index));
    for (log_id, stored) in outcomes {
        if stored.log_id != *log_id {
            return Err(ApplicationError::new("outcome map key differs from stored log coordinate"));
        }
        if last.is_none_or(|last| stored.log_id.index > last.index) {
            return Err(ApplicationError::new("outcome coordinate follows the restored root snapshot"));
        }
        if !is_lower_hex_sha256(&stored.command_digest_hex) {
            return Err(ApplicationError::new("outcome command digest is not canonical lowercase SHA-256"));
        }
    }
    Ok(())
}

pub(crate) fn adapter_state_digest_hex(
    root_digest_hex: &str,
    state_bytes: &[u8],
    outcomes_empty: bool,
) -> Result<String, ApplicationError> {
    if outcomes_empty {
        return Ok(root_digest_hex.to_owned());
    }
    let mut hasher = Sha256::new();
    hasher.update(ADAPTER_DIGEST_DOMAIN);
    hasher.update(state_bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
