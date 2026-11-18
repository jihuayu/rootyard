//! Immutable `CausalPushProofReceipt` and deterministic wire/state-machine proof helpers (#183).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::BlobLocator;
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::state_machine::ApplyResponse;
use crate::ref_store::core::terminal::CommitRejectCode;
use crate::ref_store::core::types::GitObjectFormat;

use super::types::{AuthorizedSnapshotState, PushCausalError, ReceiveCapabilities};

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

/// Cryptographically bound causal proof minted ONLY after verified Blob read-back + Git closure.
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
        h.update(b"causal-push-proof-receipt-v1\n");
        let pack_path = self.pack_locator.as_ref().map(|l| l.path()).unwrap_or_default();
        let idx_path = self.idx_locator.as_ref().map(|l| l.path()).unwrap_or_default();
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

    pub fn verify_scope(&self, snapshot: &AuthorizedSnapshotState, backend_hex: &str) -> Result<(), PushCausalError> {
        self.verify_digest()?;
        if self.tenant_id != snapshot.tenant_id
            || self.repository_id != snapshot.repository_id
            || self.history_incarnation != snapshot.history_incarnation
            || self.authority_epoch != snapshot.authority_epoch
            || self.group_epoch != snapshot.group_epoch
            || self.object_format != snapshot.object_format
            || self.blob_backend_identity != backend_hex
        {
            return Err(PushCausalError::ProofScopeMismatch);
        }
        Ok(())
    }
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
