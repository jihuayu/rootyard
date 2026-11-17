//! Durable lease fencing, equivalence proof, and RefStore CAS contract types (#162).

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::read_accel::{AuthoritativeRef, ReadAccelObjectFormat};

use super::{
    CompactionError,
    git_ops::format_label,
    segment::{CompactionByteAccounting, CompactionSegmentLog, SegmentTriggerPolicy, TieredMergePlan},
    sharding::{CompactionPackEntry, CompactionRef},
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CompactionError>> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionLeaseKey {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub shard_id: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionLeaseToken {
    pub key: CompactionLeaseKey,
    pub lease_id: Uuid,
    pub owner_id: String,
    pub fence_epoch: u64,
    pub acquired_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompactionPhase {
    Claimed,
    CandidateUploaded { pack_id: Uuid, pack_path: String, idx_path: String },
    Published { new_membership_generation: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingOperationRecord {
    pub op_id: Uuid,
    pub key: CompactionLeaseKey,
    pub fence_epoch: u64,
    pub expected_membership_generation: u64,
    pub phase: CompactionPhase,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionEquivalenceProof {
    pub object_format: ReadAccelObjectFormat,
    pub total_object_count: usize,
    pub shard_input_object_count: usize,
    pub compacted_output_object_count: usize,
    pub delta_objects_self_contained: usize,
    pub delta_bases_verified: bool,
    pub oid_set_digest: String,
    pub closure_digest: String,
    pub retention_roots_verified: usize,
    pub refs_digest: String,
    pub fsck_verified: bool,
    pub clone_verified: bool,
}

impl CompactionEquivalenceProof {
    pub fn canonical_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(format_label(self.object_format).as_bytes());
        h.update((self.total_object_count as u64).to_be_bytes());
        h.update((self.shard_input_object_count as u64).to_be_bytes());
        h.update((self.compacted_output_object_count as u64).to_be_bytes());
        h.update((self.delta_objects_self_contained as u64).to_be_bytes());
        h.update((self.retention_roots_verified as u64).to_be_bytes());
        h.update(self.oid_set_digest.as_bytes());
        h.update(self.closure_digest.as_bytes());
        h.update(self.refs_digest.as_bytes());
        h.update([u8::from(self.delta_bases_verified), u8::from(self.fsck_verified), u8::from(self.clone_verified)]);
        hex::encode(h.finalize())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionAuthoritativeSnapshot {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub authority_epoch: u64,
    pub object_format: String,
    pub shard_count: u16,
    pub membership_generation: u64,
    pub pack_set_digest: String,
    pub refs_digest: String,
    pub retention_roots_digest: String,
    pub serving_packs: Vec<CompactionPackEntry>,
    pub retained_old_packs: Vec<CompactionPackEntry>,
    pub refs: Vec<CompactionRef>,
    pub retention_roots: Vec<String>,
    pub segments: CompactionSegmentLog,
    pub cumulative_newly_written_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionPublishRequest {
    pub op_id: Uuid,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub authority_epoch: u64,
    pub shard_id: u16,
    pub lease_id: Uuid,
    pub fence_epoch: u64,
    pub expected_membership_generation: u64,
    pub expected_pack_set_digest: String,
    pub expected_refs_digest: String,
    pub expected_retention_roots_digest: String,
    pub retired_pack_ids: Vec<Uuid>,
    pub replacement_pack: CompactionPackEntry,
    pub merge_plan: TieredMergePlan,
    pub equivalence_proof: CompactionEquivalenceProof,
    pub equivalence_proof_digest: String,
    pub delete_disabled: bool,
}

impl CompactionPublishRequest {
    pub fn canonical_digest(&self) -> String {
        let mut h = Sha256::new();
        for b in [
            self.tenant_id.as_bytes().as_slice(),
            self.repo_id.as_bytes().as_slice(),
            self.history_id.as_bytes().as_slice(),
            &self.authority_epoch.to_be_bytes(),
            &self.shard_id.to_be_bytes(),
            &self.expected_membership_generation.to_be_bytes(),
            self.expected_pack_set_digest.as_bytes(),
            self.expected_refs_digest.as_bytes(),
            self.expected_retention_roots_digest.as_bytes(),
            self.replacement_pack.pack_id.as_bytes(),
            self.replacement_pack.pack_sha256.as_bytes(),
            self.replacement_pack.idx_sha256.as_bytes(),
            self.equivalence_proof_digest.as_bytes(),
        ] {
            h.update((b.len() as u64).to_be_bytes());
            h.update(b);
        }
        let mut sorted = self.retired_pack_ids.clone();
        sorted.sort();
        h.update((sorted.len() as u64).to_be_bytes());
        for id in sorted {
            h.update(id.as_bytes());
        }
        h.update([u8::from(self.delete_disabled)]);
        hex::encode(h.finalize())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionPublishReceipt {
    pub op_id: Uuid,
    pub request_digest: String,
    pub authority_epoch: u64,
    pub history_id: Uuid,
    pub previous_membership_generation: u64,
    pub new_membership_generation: u64,
    pub new_pack_set_digest: String,
    pub retired_pack_ids: Vec<Uuid>,
    pub replacement_pack: CompactionPackEntry,
    pub merge_plan: TieredMergePlan,
    pub equivalence_proof: CompactionEquivalenceProof,
    pub accounting: CompactionByteAccounting,
    pub published_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcurrentPushFault {
    pub pack: CompactionPackEntry,
    pub updated_refs: Vec<AuthoritativeRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactionFaultHook {
    None,
    CrashBeforeUpload,
    CrashAfterUploadBeforePublish,
    LoseLeaseBeforePublish { usurper_owner: String },
    ConcurrentPushBeforePublish(Box<ConcurrentPushFault>),
    DropPublishAck,
}

/// Abstract RefStore + lease backend supporting durable local journals and PostgreSQL CAS stores.
pub trait CompactionAuthorityStore: Send + Sync {
    fn acquire_or_renew_lease<'a>(
        &'a self,
        key: &'a CompactionLeaseKey,
        owner_id: &'a str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> BoxFuture<'a, CompactionLeaseToken>;
    fn verify_lease_active<'a>(&'a self, token: &'a CompactionLeaseToken, now_ms: u64) -> BoxFuture<'a, ()>;
    fn release_lease<'a>(&'a self, token: &'a CompactionLeaseToken) -> BoxFuture<'a, ()>;
    fn load_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
    ) -> BoxFuture<'a, CompactionAuthoritativeSnapshot>;
    fn lookup_operation<'a>(&'a self, op_id: Uuid) -> BoxFuture<'a, Option<CompactionPublishReceipt>>;
    fn record_checkpoint<'a>(&'a self, record: PendingOperationRecord) -> BoxFuture<'a, ()>;
    fn cas_publish_compaction<'a>(
        &'a self,
        request: &'a CompactionPublishRequest,
        now_ms: u64,
        drop_ack_fault: bool,
    ) -> BoxFuture<'a, CompactionPublishReceipt>;
    fn inject_fault<'a>(
        &'a self,
        _hook: &'a CompactionFaultHook,
        _key: &'a CompactionLeaseKey,
        _now_ms: u64,
        _policy: &'a SegmentTriggerPolicy,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}
