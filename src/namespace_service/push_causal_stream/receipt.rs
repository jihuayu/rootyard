//! Immutable `CausalPushProofReceipt` and deterministic wire/state-machine proof helpers (#183).
//!
//! Binds the exact `(operation_id, snapshot, ticket, final_accepted_cas_subset)` tuple both
//! before Ref-CAS admission and after actual CAS terminal resolution (`Atomic` & `AcceptedSubset`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::BlobLocator;
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::state_machine::ApplyResponse;
use crate::ref_store::core::terminal::{CommitRejectCode, RefCommitResult};
use crate::ref_store::core::types::GitObjectFormat;

use super::types::{AuthorizedSnapshotState, OperationTicket, PushCausalError, ReceiveCapabilities};

/// Accepted per-ref proof line embedded in [`CausalPushProofReceipt`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedRefProof {
    pub ref_name: String,
    pub old_oid: Option<String>,
    pub new_oid: Option<String>,
    pub target_kind: String,
}

/// Rejected per-ref verdict embedded in [`CausalPushProofReceipt`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedRefProof {
    pub ref_name: String,
    pub code: CommitRejectCode,
    pub reason: String,
}

/// Cryptographically bound causal proof minted after verified Blob read-back + Git closure
/// and rebound to the exact authoritative CAS terminal subset on commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalPushProofReceipt {
    pub receipt_version: u32,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub object_format: GitObjectFormat,
    pub operation_id: Uuid,
    pub issuer_id: Uuid,
    pub lane: String,
    pub sequence: i64,
    pub base_snapshot_seq: i64,
    pub expected_gate_revision: i64,
    pub committed_gate_revision: Option<i64>,
    pub base_version_ids: Vec<String>,
    pub required_ancestor_oids: Vec<String>,
    pub resolved_thin_base_oids: Vec<String>,
    pub base_closure_digest: String,
    pub pack_sha256: Option<String>,
    pub pack_bytes: u64,
    pub idx_sha256: Option<String>,
    pub idx_bytes: u64,
    pub pack_locator: Option<BlobLocator>,
    pub idx_locator: Option<BlobLocator>,
    pub blob_backend_identity: String,
    pub object_count: u64,
    pub delta_object_count: u64,
    pub max_delta_chain_depth: u32,
    pub duplicate_object_count: u64,
    pub blob_closure_digest: String,
    pub accepted_updates: Vec<AcceptedRefProof>,
    pub rejected_updates: Vec<RejectedRefProof>,
    pub accepted_subset_digest: String,
    pub proof_digest: String,
}

impl CausalPushProofReceipt {
    pub fn recompute_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"causal-push-proof-receipt-v2\n");
        let pack_path = self.pack_locator.as_ref().map(|l| l.path()).unwrap_or_default();
        let idx_path = self.idx_locator.as_ref().map(|l| l.path()).unwrap_or_default();
        let committed_rev = self.committed_gate_revision.unwrap_or(-1);
        for bytes in [
            self.receipt_version.to_be_bytes().as_slice(),
            self.tenant_id.as_bytes(),
            self.repository_id.as_bytes(),
            self.history_incarnation.as_bytes(),
            self.authority_epoch.to_be_bytes().as_slice(),
            self.group_epoch.to_be_bytes().as_slice(),
            self.object_format.as_str().as_bytes(),
            self.operation_id.as_bytes(),
            self.issuer_id.as_bytes(),
            self.lane.as_bytes(),
            self.sequence.to_be_bytes().as_slice(),
            self.base_snapshot_seq.to_be_bytes().as_slice(),
            self.expected_gate_revision.to_be_bytes().as_slice(),
            committed_rev.to_be_bytes().as_slice(),
            self.base_closure_digest.as_bytes(),
            self.pack_sha256.as_deref().unwrap_or("").as_bytes(),
            self.pack_bytes.to_be_bytes().as_slice(),
            self.idx_sha256.as_deref().unwrap_or("").as_bytes(),
            self.idx_bytes.to_be_bytes().as_slice(),
            pack_path.as_bytes(),
            idx_path.as_bytes(),
            self.blob_backend_identity.as_bytes(),
            self.object_count.to_be_bytes().as_slice(),
            self.delta_object_count.to_be_bytes().as_slice(),
            self.max_delta_chain_depth.to_be_bytes().as_slice(),
            self.duplicate_object_count.to_be_bytes().as_slice(),
            self.blob_closure_digest.as_bytes(),
            self.accepted_subset_digest.as_bytes(),
        ] {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        }
        for list in [&self.base_version_ids, &self.required_ancestor_oids, &self.resolved_thin_base_oids] {
            h.update((list.len() as u64).to_be_bytes());
            for item in list {
                h.update((item.len() as u64).to_be_bytes());
                h.update(item.as_bytes());
            }
        }
        h.update((self.accepted_updates.len() as u64).to_be_bytes());
        for u in &self.accepted_updates {
            let line = format!(
                "{}|{}|{}|{}",
                u.ref_name,
                u.old_oid.as_deref().unwrap_or(""),
                u.new_oid.as_deref().unwrap_or(""),
                u.target_kind
            );
            h.update((line.len() as u64).to_be_bytes());
            h.update(line.as_bytes());
        }
        h.update((self.rejected_updates.len() as u64).to_be_bytes());
        for r in &self.rejected_updates {
            let line = format!("{}|{}|{}", r.ref_name, r.code.as_str(), r.reason);
            h.update((line.len() as u64).to_be_bytes());
            h.update(line.as_bytes());
        }
        hex::encode(h.finalize())
    }

    pub fn verify_digest(&self) -> Result<(), PushCausalError> {
        if self.recompute_digest() != self.proof_digest {
            return Err(PushCausalError::ProofTampered("proof_digest verification failed"));
        }
        Ok(())
    }

    /// Verify exact `(operation_id, snapshot, ticket, backend)` identity binding.
    pub fn verify_scope(
        &self,
        snapshot: &AuthorizedSnapshotState,
        ticket: &OperationTicket,
        backend_hex: &str,
    ) -> Result<(), PushCausalError> {
        self.verify_digest()?;
        if self.tenant_id != snapshot.tenant_id
            || self.repository_id != snapshot.repository_id
            || self.history_incarnation != snapshot.history_incarnation
            || self.authority_epoch != snapshot.authority_epoch
            || self.group_epoch != snapshot.group_epoch
            || self.object_format != snapshot.object_format
            || self.base_snapshot_seq != snapshot.snapshot_seq
            || self.expected_gate_revision != snapshot.expected_gate_revision
            || self.operation_id != ticket.operation_id
            || self.issuer_id != ticket.issuer_id
            || self.lane != ticket.lane
            || self.sequence != ticket.sequence
            || self.blob_backend_identity != backend_hex
        {
            return Err(PushCausalError::ProofScopeMismatch);
        }
        Ok(())
    }

    /// Rebind this receipt to the exact CAS applied/rejected subset produced by Ref-CAS commit
    /// (`Atomic` or `AcceptedSubset`), recompute `accepted_subset_digest` and `proof_digest`, and
    /// verify the full `(operation, snapshot, ticket, final_cas_subset)` binding.
    pub fn rebind_final_cas_terminal(
        &mut self,
        snapshot: &AuthorizedSnapshotState,
        ticket: &OperationTicket,
        backend_hex: &str,
        committed_revision: Option<i64>,
        terminal_refs: &[RefCommitResult],
    ) -> Result<(), PushCausalError> {
        self.verify_scope(snapshot, ticket, backend_hex)?;
        let (accepted, rejected) = split_terminal_subset(terminal_refs);
        self.committed_gate_revision = committed_revision;
        self.accepted_updates = accepted;
        self.rejected_updates = rejected;
        self.accepted_subset_digest = compute_accepted_subset_digest(&self.accepted_updates, &self.rejected_updates);
        self.proof_digest = self.recompute_digest();
        self.verify_commit_binding(snapshot, ticket, backend_hex, terminal_refs)
    }

    /// Verify that a committed receipt matches `(operation, snapshot, ticket, final_cas_subset)`.
    pub fn verify_commit_binding(
        &self,
        snapshot: &AuthorizedSnapshotState,
        ticket: &OperationTicket,
        backend_hex: &str,
        terminal_refs: &[RefCommitResult],
    ) -> Result<(), PushCausalError> {
        self.verify_scope(snapshot, ticket, backend_hex)?;
        let (expected_accepted, expected_rejected) = split_terminal_subset(terminal_refs);
        let expected_digest = compute_accepted_subset_digest(&expected_accepted, &expected_rejected);
        if self.accepted_updates != expected_accepted
            || self.rejected_updates != expected_rejected
            || self.accepted_subset_digest != expected_digest
        {
            return Err(PushCausalError::ProofTampered(
                "commit receipt accepted/rejected subset disagrees with authoritative CAS terminal",
            ));
        }
        Ok(())
    }
}

pub fn split_terminal_subset(terminal_refs: &[RefCommitResult]) -> (Vec<AcceptedRefProof>, Vec<RejectedRefProof>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for entry in terminal_refs {
        match entry {
            RefCommitResult::Applied { name, old_oid, new_oid } => {
                let target_kind = if new_oid.is_none() {
                    "delete"
                } else if name.starts_with("refs/heads/") {
                    "commit"
                } else {
                    "object"
                };
                accepted.push(AcceptedRefProof {
                    ref_name: name.clone(),
                    old_oid: old_oid.clone(),
                    new_oid: new_oid.clone(),
                    target_kind: target_kind.to_owned(),
                });
            }
            RefCommitResult::NotApplied { name, reason } => {
                rejected.push(RejectedRefProof {
                    ref_name: name.clone(),
                    code: *reason,
                    reason: reason.as_str().to_owned(),
                });
            }
        }
    }
    (accepted, rejected)
}

pub fn compute_accepted_subset_digest(accepted: &[AcceptedRefProof], rejected: &[RejectedRefProof]) -> String {
    let mut h = Sha256::new();
    h.update(b"accepted-subset-v1\n");
    for a in accepted {
        let s =
            format!("ok:{}:{}:{}", a.ref_name, a.old_oid.as_deref().unwrap_or(""), a.new_oid.as_deref().unwrap_or(""));
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    }
    for r in rejected {
        let s = format!("ng:{}:{}", r.ref_name, r.code.as_str());
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    }
    hex::encode(h.finalize())
}

pub fn commit_mode_from_capabilities(caps: &ReceiveCapabilities) -> CommitMode {
    if caps.atomic { CommitMode::Atomic } else { CommitMode::AcceptedSubset }
}

pub fn validate_wire_reason(reason: &str) -> Result<(), PushCausalError> {
    if reason.is_empty() || reason.bytes().any(|b| b < 32 || b == 127) {
        return Err(PushCausalError::MalformedProtocol("report reason contains control characters or is empty".into()));
    }
    Ok(())
}

pub fn extract_state_machine_applied(resp: &ApplyResponse) -> Result<bool, PushCausalError> {
    match resp {
        ApplyResponse::RefsCommitted(receipt) => Ok(receipt.is_committed()),
        other => Err(PushCausalError::StateMachine(format!("unexpected state machine apply response: {other:?}"))),
    }
}
