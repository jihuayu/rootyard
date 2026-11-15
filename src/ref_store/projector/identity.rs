//! Deterministic domain-separated SHA-256 event, webhook, job, and closure
//! identities independent of any PostgreSQL sequence or auto-increment column (#117).

use super::types::{ProjectionError, ProjectionJobKind, ProjectionRealm};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const OP_EVENT_DOMAIN: &[u8] = b"rootyard-refcas-op-event-v1";
const REF_EVENT_DOMAIN: &[u8] = b"rootyard-refcas-ref-event-v1";
const JOB_KEY_DOMAIN: &[u8] = b"rootyard-refcas-job-key-v1";
const TERMINAL_DIGEST_DOMAIN: &[u8] = b"rootyard-refcas-terminal-v1";
const CLOSURE_DIGEST_DOMAIN: &[u8] = b"rootyard-refcas-truncation-closure-v1";

fn push_len_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn push_len_str(hash: &mut Sha256, value: &str) {
    push_len_bytes(hash, value.as_bytes());
}

fn push_opt_str(hash: &mut Sha256, value: Option<&str>) {
    match value {
        Some(v) => {
            hash.update([1u8]);
            push_len_str(hash, v);
        }
        None => hash.update([0u8]),
    }
}

fn push_realm(hash: &mut Sha256, realm: &ProjectionRealm) {
    hash.update(realm.history_incarnation.as_bytes());
    hash.update(realm.group_id.to_be_bytes());
    hash.update(realm.group_epoch.to_be_bytes());
}

fn update_canonical_json(hash: &mut Sha256, value: &Value) {
    match value {
        Value::Null => hash.update(b"N"),
        Value::Bool(b) => {
            hash.update(b"B");
            hash.update([u8::from(*b)]);
        }
        Value::Number(n) => {
            hash.update(b"D");
            push_len_str(hash, &n.to_string());
        }
        Value::String(s) => {
            hash.update(b"S");
            push_len_str(hash, s);
        }
        Value::Array(items) => {
            hash.update(b"A");
            hash.update((items.len() as u64).to_be_bytes());
            for item in items {
                update_canonical_json(hash, item);
            }
        }
        Value::Object(map) => {
            hash.update(b"M");
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            hash.update((entries.len() as u64).to_be_bytes());
            for (k, v) in entries {
                push_len_str(hash, k);
                update_canonical_json(hash, v);
            }
        }
    }
}

/// Stable operation-level identity bound to `(history_incarnation, group_id, group_epoch,
/// log_index, operation_id, repository_id)`. Replay at any PG connection or retry yields
/// the identical 64-char hex identity.
pub fn derive_operation_event_id(
    realm: &ProjectionRealm,
    log_index: u64,
    operation_id: Uuid,
    repository_id: Uuid,
) -> Result<String, ProjectionError> {
    realm.validate()?;
    if log_index == 0 || operation_id.is_nil() || repository_id.is_nil() {
        return Err(ProjectionError::InvalidInput("cannot derive operation event id from zero/nil inputs".into()));
    }
    let mut hash = Sha256::new();
    push_len_bytes(&mut hash, OP_EVENT_DOMAIN);
    push_realm(&mut hash, realm);
    hash.update(log_index.to_be_bytes());
    hash.update(operation_id.as_bytes());
    hash.update(repository_id.as_bytes());
    Ok(hex::encode(hash.finalize()))
}

/// Stable per-ref effect identity bound to `(op_event_id, ref_sequence, ref_name)`.
pub fn derive_ref_event_id(op_event_id: &str, ref_sequence: i64, ref_name: &str) -> Result<String, ProjectionError> {
    if op_event_id.is_empty() || ref_sequence <= 0 || ref_name.is_empty() {
        return Err(ProjectionError::InvalidInput("invalid arguments for ref event identity".into()));
    }
    let mut hash = Sha256::new();
    push_len_bytes(&mut hash, REF_EVENT_DOMAIN);
    push_len_str(&mut hash, op_event_id);
    hash.update(ref_sequence.to_be_bytes());
    push_len_str(&mut hash, ref_name);
    Ok(hex::encode(hash.finalize()))
}

/// Webhook delivery dedup identity within `forge_webhook_deliveries` (`<= 128` chars),
/// disjoint from standalone `"outbox:*"` deliveries.
pub fn derive_webhook_event_id(ref_event_id: &str) -> String {
    format!("refcas:{ref_event_id}")
}

/// Deterministic reliable job key so duplicate/out-of-order replays enqueue at most one job.
pub fn derive_job_key(op_event_id: &str, kind: ProjectionJobKind, scope_key: &str) -> Result<String, ProjectionError> {
    if op_event_id.is_empty() || scope_key.is_empty() {
        return Err(ProjectionError::InvalidInput("invalid arguments for job key".into()));
    }
    let mut hash = Sha256::new();
    push_len_bytes(&mut hash, JOB_KEY_DOMAIN);
    push_len_str(&mut hash, op_event_id);
    push_len_str(&mut hash, kind.as_str());
    push_len_str(&mut hash, scope_key);
    Ok(hex::encode(hash.finalize()))
}

/// Canonical digest over an operation outcome & payload to catch stream equivocation on replay.
pub fn compute_terminal_digest(repository_id: Uuid, revision: i64, outcome: &str, payload: &Value) -> String {
    let mut hash = Sha256::new();
    push_len_bytes(&mut hash, TERMINAL_DIGEST_DOMAIN);
    hash.update(repository_id.as_bytes());
    hash.update(revision.to_be_bytes());
    push_len_str(&mut hash, outcome);
    update_canonical_json(&mut hash, payload);
    hex::encode(hash.finalize())
}

/// Sealed cryptographic digest binding the durable retention/archive truncation boundary.
pub fn compute_truncation_closure_digest(
    realm: &ProjectionRealm,
    cutoff_log_index: u64,
    cutoff_event_seq: u64,
    cutoff_log_term: u64,
    last_op_event_id: Option<&str>,
) -> Result<String, ProjectionError> {
    realm.validate()?;
    if cutoff_log_index == 0 || cutoff_event_seq == 0 {
        return Err(ProjectionError::InvalidInput(
            "truncation closure requires log_index >= 1 and event_seq >= 1".into(),
        ));
    }
    let mut hash = Sha256::new();
    push_len_bytes(&mut hash, CLOSURE_DIGEST_DOMAIN);
    push_realm(&mut hash, realm);
    hash.update(cutoff_log_index.to_be_bytes());
    hash.update(cutoff_event_seq.to_be_bytes());
    hash.update(cutoff_log_term.to_be_bytes());
    push_opt_str(&mut hash, last_op_event_id);
    Ok(hex::encode(hash.finalize()))
}
