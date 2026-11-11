//! Synchronous, local-volume evidence for native Git reference transactions.
//! Callers serialize operations per repository and retire only after SQL commit.
use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_RECORD_BYTES: usize = 2 * MAX_BYTES;
const MAX_EVENT_BYTES: usize = 16 * MAX_BYTES;
const MAX_ENTRIES: usize = 16384;
const MAX_REFS: usize = 4096;

#[path = "journal/core.rs"]
mod core;
#[path = "journal/hooks.rs"]
mod hooks;
#[path = "journal/operation.rs"]
mod operation;
#[path = "journal/record.rs"]
mod record;
#[path = "journal/state.rs"]
mod state;

pub(crate) use core::{
    atomic, begin_ci, begin_ci_service, begin_proposal, ensure_sequence_at_least, exists, mkdir, read, safe_path,
};
pub use core::{begin, begin_active, begin_active_with, begin_ref_transaction, pending, sequence};
pub use hooks::{
    record_ref_transaction_intent, record_ref_transaction_receipt, run_hook, run_post_receive, run_pre_receive,
};
pub use operation::{ActiveGuard, HookEvent, HookPhase, Operation, RefChange};
pub use record::{events, receipts, ref_transaction_evidence, requests};
pub(crate) use record::{no_parent_publication_possible, valid_ref};
pub use state::{
    evidence, evidence_digest, finish, is_fenced_aborted, is_finished, is_interrupted, mark_corrupt,
    mark_fenced_aborted, mark_interrupted, retire,
};

/// Non-secret fingerprints tying a native ref transaction to its HTTP
/// Idempotency-Key. They are journal evidence, never an authorization grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyIntent {
    pub key_sha256: String,
    pub request_sha256: String,
}

#[cfg(test)]
#[path = "journal/tests.rs"]
mod tests;
