//! Sealed adapter state wrapper for Root snapshot bytes plus bounded proposal receipts.
//!
//! New state uses strict `/3` encoding with a fixed receipt window. Legacy bare Root snapshots and
//! `/2` outcome states are restored without rewriting their bytes or digest; the first subsequent
//! committed entry performs the explicit `/3` transition. KV `/1` snapshots are untouched because
//! they use the separate KV state-machine path.

use std::collections::BTreeMap;

use rootyard_refcas_log::state_machine::{ApplicationError, ApplicationLogId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ref_store::core::state_machine::RefCasStateMachine;
use crate::ref_store::raft_backend::outcome::{RootRefCasOutcome, RootRefCasRefusalKind};
use crate::ref_store::raft_backend::proposal::{
    MAX_ADAPTER_STATE_BYTES, MAX_PROPOSAL_RECEIPT_BYTES, MAX_ROOT_STATE_BYTES, PROPOSAL_WINDOW, ProposalAttempt,
    ProposalAttemptKind,
};

pub(crate) const ADAPTER_STATE_FORMAT_V3: &str = "rootyard-refcas-adapter/3";
pub(crate) const ADAPTER_STATE_FORMAT_V2: &str = "rootyard-refcas-adapter/2";
const ADAPTER_DIGEST_DOMAIN_V3: &[u8] = b"rootyard-refcas-adapter-state-v3\0";
const ADAPTER_DIGEST_DOMAIN_V2: &[u8] = b"rootyard-refcas-adapter-state-v2\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterStateV3 {
    format: String,
    window: u64,
    /// Canonical Root `RefCasSnapshot` JSON, kept as text to expose actual outer escaping.
    root_snapshot: String,
    attempts: Vec<ProposalAttempt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterStateV2 {
    format: String,
    root_snapshot: String,
    outcomes: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct StateProbe {
    format: String,
}

#[derive(Clone, Debug)]
pub(crate) struct LegacyAdapterState {
    pub(crate) bytes: Vec<u8>,
    pub(crate) digest_hex: String,
}

pub(crate) struct RestoredAdapterState {
    pub(crate) machine: RefCasStateMachine,
    pub(crate) attempts: BTreeMap<ApplicationLogId, ProposalAttempt>,
    pub(crate) legacy: Option<LegacyAdapterState>,
}

pub(crate) fn export_adapter_state_v3(
    root_snapshot: Vec<u8>,
    attempts: &BTreeMap<ApplicationLogId, ProposalAttempt>,
) -> Result<Vec<u8>, ApplicationError> {
    let root_snapshot = String::from_utf8(root_snapshot)
        .map_err(|_| ApplicationError::new("root Ref-CAS snapshot is not canonical UTF-8 JSON"))?;
    let state = AdapterStateV3 {
        format: ADAPTER_STATE_FORMAT_V3.to_owned(),
        window: PROPOSAL_WINDOW,
        root_snapshot,
        attempts: attempts.values().cloned().collect(),
    };
    let bytes = serde_json::to_vec(&state).map_err(|e| ApplicationError::new(format!("encode adapter state: {e}")))?;
    if bytes.len() > MAX_ADAPTER_STATE_BYTES {
        return Err(ApplicationError::new(format!(
            "adapter state {} exceeds hard ceiling {MAX_ADAPTER_STATE_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Root plus envelope with an empty receipt set, used for the explicit Root contribution budget.
pub(crate) fn root_only_state_v3(root_snapshot: &[u8]) -> Result<Vec<u8>, ApplicationError> {
    let root_snapshot = std::str::from_utf8(root_snapshot)
        .map_err(|_| ApplicationError::new("root Ref-CAS snapshot is not canonical UTF-8 JSON"))?
        .to_owned();
    let state = AdapterStateV3 {
        format: ADAPTER_STATE_FORMAT_V3.to_owned(),
        window: PROPOSAL_WINDOW,
        root_snapshot,
        attempts: Vec::new(),
    };
    let bytes =
        serde_json::to_vec(&state).map_err(|e| ApplicationError::new(format!("encode root-state budget: {e}")))?;
    if bytes.len() > MAX_ROOT_STATE_BYTES {
        return Err(ApplicationError::new(format!(
            "encoded Root contribution {} exceeds budget {MAX_ROOT_STATE_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

pub(crate) fn restore_adapter_state(bytes: &[u8]) -> Result<RestoredAdapterState, ApplicationError> {
    if bytes.len() > MAX_ADAPTER_STATE_BYTES {
        return Err(ApplicationError::new(format!(
            "adapter state {} exceeds hard ceiling {MAX_ADAPTER_STATE_BYTES}; offline migration required",
            bytes.len()
        )));
    }
    let probe = serde_json::from_slice::<StateProbe>(bytes).ok();
    if let Some(probe) = probe.as_ref() {
        if probe.format == ADAPTER_STATE_FORMAT_V3 {
            let state: AdapterStateV3 = serde_json::from_slice(bytes)
                .map_err(|e| ApplicationError::new(format!("decode adapter state: {e}")))?;
            if state.window != PROPOSAL_WINDOW {
                return Err(ApplicationError::new(format!(
                    "adapter proposal window {} differs from protocol {PROPOSAL_WINDOW}",
                    state.window
                )));
            }
            let machine = RefCasStateMachine::restore_bytes(state.root_snapshot.as_bytes())
                .map_err(|e| ApplicationError::new(format!("restore root snapshot: {e}")))?;
            root_only_state_v3(state.root_snapshot.as_bytes())?;
            let mut attempts = BTreeMap::new();
            for attempt in state.attempts {
                let log_id = attempt.observed_log_id;
                if attempts.insert(log_id, attempt).is_some() {
                    return Err(ApplicationError::new("duplicate attempt at one application coordinate"));
                }
            }
            validate_v3(&machine, &attempts)?;
            return Ok(RestoredAdapterState { machine, attempts, legacy: None });
        }
        if probe.format == ADAPTER_STATE_FORMAT_V2 {
            let state: AdapterStateV2 = serde_json::from_slice(bytes)
                .map_err(|e| ApplicationError::new(format!("decode legacy /2 adapter state: {e}")))?;
            let machine = RefCasStateMachine::restore_bytes(state.root_snapshot.as_bytes())
                .map_err(|e| ApplicationError::new(format!("restore legacy /2 root snapshot: {e}")))?;
            root_only_state_v3(state.root_snapshot.as_bytes())?;
            let digest_hex = if state.outcomes.is_empty() {
                machine.state_digest().map_err(|e| ApplicationError::new(format!("legacy root digest: {e}")))?
            } else {
                legacy_v2_digest(bytes)?
            };
            return Ok(RestoredAdapterState {
                machine,
                attempts: BTreeMap::new(),
                legacy: Some(LegacyAdapterState { bytes: bytes.to_vec(), digest_hex }),
            });
        }
        if probe.format.starts_with("rootyard-refcas-adapter/") {
            return Err(ApplicationError::new(format!(
                "unknown adapter state format {:?}; refusing compatibility fallback",
                probe.format
            )));
        }
    }
    let machine = RefCasStateMachine::restore_bytes(bytes)
        .map_err(|e| ApplicationError::new(format!("restore legacy bare root snapshot: {e}")))?;
    root_only_state_v3(bytes)?;
    let digest_hex =
        machine.state_digest().map_err(|e| ApplicationError::new(format!("legacy bare root digest: {e}")))?;
    Ok(RestoredAdapterState {
        machine,
        attempts: BTreeMap::new(),
        legacy: Some(LegacyAdapterState { bytes: bytes.to_vec(), digest_hex }),
    })
}

fn validate_v3(
    machine: &RefCasStateMachine,
    attempts: &BTreeMap<ApplicationLogId, ProposalAttempt>,
) -> Result<(), ApplicationError> {
    if attempts.len() > usize::try_from(PROPOSAL_WINDOW).unwrap_or(usize::MAX) {
        return Err(ApplicationError::new("adapter attempt count exceeds the fixed window"));
    }
    let last = machine.last_applied().map(|log_id| ApplicationLogId::new(log_id.term, log_id.index));
    let cutoff = last.map(|coordinate| coordinate.index.saturating_sub(PROPOSAL_WINDOW));
    for (log_id, attempt) in attempts {
        if attempt.observed_log_id != *log_id {
            return Err(ApplicationError::new("attempt map key differs from observed coordinate"));
        }
        if last.is_none_or(|last| attempt.observed_log_id.index > last.index) {
            return Err(ApplicationError::new("attempt coordinate follows the restored root snapshot"));
        }
        if cutoff.is_some_and(|cutoff| attempt.observed_log_id.index <= cutoff) {
            return Err(ApplicationError::new("attempt coordinate is outside the retained window"));
        }
        if !is_lower_hex_sha256(&attempt.command_digest_hex) {
            return Err(ApplicationError::new("attempt command digest is not lowercase SHA-256"));
        }
        if attempt.serialized_len()? > MAX_PROPOSAL_RECEIPT_BYTES {
            return Err(ApplicationError::new("attempt receipt exceeds its byte budget"));
        }
        match attempt.kind {
            ProposalAttemptKind::Legacy => {
                if attempt.proposal_id.is_some() {
                    return Err(ApplicationError::new("legacy attempt unexpectedly carries a proposal id"));
                }
            }
            ProposalAttemptKind::First => {
                let Some(id) = attempt.proposal_id.as_ref() else {
                    return Err(ApplicationError::new("first attempt lacks a proposal id"));
                };
                let invalid_proposal_refusal = matches!(
                    &attempt.outcome,
                    RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::ProposalInvalid
                );
                if !invalid_proposal_refusal {
                    id.validate_shape()?;
                }
                if attempt.original_log_id != attempt.observed_log_id {
                    return Err(ApplicationError::new("first attempt original coordinate differs from observed"));
                }
            }
            ProposalAttemptKind::Replayed | ProposalAttemptKind::Conflict => {
                if attempt.proposal_id.is_none() {
                    return Err(ApplicationError::new("replay/conflict attempt lacks a proposal id"));
                }
                if attempt.original_log_id == attempt.observed_log_id {
                    return Err(ApplicationError::new("replay/conflict attempt has no distinct original coordinate"));
                }
                let Some(original) = attempts.get(&attempt.original_log_id) else {
                    return Err(ApplicationError::new("replay/conflict original receipt is missing"));
                };
                if original.kind != ProposalAttemptKind::First || original.proposal_id != attempt.proposal_id {
                    return Err(ApplicationError::new("replay/conflict original receipt is not the first decision"));
                }
            }
            ProposalAttemptKind::Expired | ProposalAttemptKind::Capacity => {
                if attempt.proposal_id.is_none() {
                    return Err(ApplicationError::new("proposal refusal attempt lacks a proposal id"));
                }
                if attempt.original_log_id != attempt.observed_log_id {
                    let Some(original) = attempts.get(&attempt.original_log_id) else {
                        return Err(ApplicationError::new("proposal refusal original receipt is missing"));
                    };
                    if original.kind != ProposalAttemptKind::First || original.proposal_id != attempt.proposal_id {
                        return Err(ApplicationError::new(
                            "proposal refusal original receipt is not the first decision",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn adapter_state_digest_v3(root_digest_hex: &str, state_bytes: &[u8]) -> Result<String, ApplicationError> {
    if root_digest_hex.len() != 64 {
        return Err(ApplicationError::new("root digest is not canonical SHA-256 hex"));
    }
    let mut hasher = Sha256::new();
    hasher.update(ADAPTER_DIGEST_DOMAIN_V3);
    hasher.update(state_bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn legacy_v2_digest(state_bytes: &[u8]) -> Result<String, ApplicationError> {
    let mut hasher = Sha256::new();
    hasher.update(ADAPTER_DIGEST_DOMAIN_V2);
    hasher.update(state_bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rootyard_refcas_log::state_machine::ApplicationStateMachine;

    #[test]
    fn v3_roundtrip_preserves_root_and_empty_window() {
        let machine = RefCasStateMachine::new();
        let root = machine.snapshot_bytes().unwrap();
        let bytes = export_adapter_state_v3(root.clone(), &BTreeMap::new()).unwrap();
        let restored = restore_adapter_state(&bytes).unwrap();
        assert!(restored.attempts.is_empty());
        assert!(restored.legacy.is_none());
        assert_eq!(restored.machine.snapshot_bytes().unwrap(), root);
    }

    #[test]
    fn unknown_v3_like_format_fails_closed() {
        let payload = br#"{"format":"rootyard-refcas-adapter/9","root_snapshot":"{}","attempts":[]}"#;
        assert!(restore_adapter_state(payload).is_err());
    }

    #[test]
    fn legacy_v2_restore_preserves_bytes_and_old_digest() {
        let machine = RefCasStateMachine::new();
        let root = String::from_utf8(machine.snapshot_bytes().unwrap()).unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({
            "format": ADAPTER_STATE_FORMAT_V2,
            "root_snapshot": root,
            "outcomes": [],
        }))
        .unwrap();
        let restored = restore_adapter_state(&payload).unwrap();
        let legacy = restored.legacy.expect("legacy marker");
        assert_eq!(legacy.bytes, payload);
        assert_eq!(legacy.digest_hex, machine.state_digest().unwrap());
    }

    #[test]
    fn legacy_v2_with_outcomes_preserves_v2_domain_digest() {
        let machine = RefCasStateMachine::new();
        let root = String::from_utf8(machine.snapshot_bytes().unwrap()).unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({
            "format": ADAPTER_STATE_FORMAT_V2,
            "root_snapshot": root,
            "outcomes": [{"legacy": true}],
        }))
        .unwrap();
        let restored = restore_adapter_state(&payload).unwrap();
        let legacy = restored.legacy.expect("legacy marker");
        assert_eq!(legacy.bytes, payload);
        assert_eq!(legacy.digest_hex, legacy_v2_digest(&payload).unwrap());
    }
}
