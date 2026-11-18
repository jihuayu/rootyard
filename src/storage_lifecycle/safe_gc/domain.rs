//! Domain boundaries, non-forgeable delete tickets, active fences, and storage traits (#122).

use std::{future::Future, path::Path, pin::Pin, time::Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{BlobLocator, opendal::BlobStore};

use super::{
    SafeGcError,
    anti_aba::PhysicalBlobKey,
    model::{AuthorityLane, encode_len_bytes, validate_bounded_name, validate_sha256_hex},
    store::DurableSafeGcAuthority,
};

pub type SafeGcFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SafeGcError>> + Send + 'a>>;
pub type ExternalFenceCheck<'a> = &'a (dyn Fn() -> Result<(), SafeGcError> + Send + Sync);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRecord {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub incarnation_id: Uuid,
    pub incarnation_epoch: u64,
    pub membership_generation: u64,
    pub live_ref_seq: u64,
    pub lease_epoch: u64,
}

/// Serializable Blob coordinate mirror preserving BlobLocator and remote object version invariants.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobLocatorRecord {
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: u64,
    pub remote_etag: String,
    pub remote_version_id: Option<String>,
}

impl BlobLocatorRecord {
    pub fn from_locator_versioned(loc: &BlobLocator, remote_etag: String, remote_version_id: Option<String>) -> Self {
        Self {
            tenant_id: loc.tenant_id(),
            authority_id: loc.authority_id(),
            generation: loc.generation(),
            attempt_id: loc.attempt_id(),
            namespace: loc.namespace().to_owned(),
            sha256: loc.sha256().to_owned(),
            length: loc.length(),
            remote_etag,
            remote_version_id,
        }
    }

    pub fn validate_version_binding(&self) -> Result<(), SafeGcError> {
        validate_bounded_name("remote_etag", &self.remote_etag)?;
        if let Some(ref vid) = self.remote_version_id {
            validate_bounded_name("remote_version_id", vid)?;
        }
        Ok(())
    }

    pub fn to_locator(&self) -> Result<BlobLocator, SafeGcError> {
        BlobLocator::new(
            self.tenant_id,
            self.authority_id,
            self.generation,
            self.attempt_id,
            &self.namespace,
            &self.sha256,
            self.length,
        )
        .map_err(SafeGcError::from)
    }

    pub(crate) fn encode_canonical(&self, h: &mut Sha256) {
        h.update(self.tenant_id.as_bytes());
        h.update(self.authority_id.as_bytes());
        h.update(self.generation.to_be_bytes());
        h.update(self.attempt_id.as_bytes());
        encode_len_bytes(h, self.namespace.as_bytes());
        encode_len_bytes(h, self.sha256.as_bytes());
        h.update(self.length.to_be_bytes());
        encode_len_bytes(h, self.remote_etag.as_bytes());
        match &self.remote_version_id {
            Some(vid) => {
                h.update([1]);
                encode_len_bytes(h, vid.as_bytes());
            }
            None => h.update([0]),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadedCompactionPair {
    pub pack_locator: BlobLocatorRecord,
    pub idx_locator: BlobLocatorRecord,
    pub pack_key: PhysicalBlobKey,
    pub idx_key: PhysicalBlobKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StagedUploadState {
    Uploading,
    AbandonedPendingCleanup,
    CleanedUp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedCompactionUpload {
    pub op_id: Uuid,
    pub incarnation_epoch: u64,
    pub pack_key: PhysicalBlobKey,
    pub idx_key: PhysicalBlobKey,
    pub pack_locator: BlobLocatorRecord,
    pub idx_locator: BlobLocatorRecord,
    pub state: StagedUploadState,
}

/// Explicit terminal outcome of a remote provider physical delete operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderDeleteOutcome {
    /// Pre-delete stat saw expected bytes, DELETE succeeded, post-delete stat returned NotFound.
    ConfirmedDeleted,
    /// Pre-delete stat confirmed the object was already absent on the provider.
    AlreadyAbsent,
    /// Provider timeout, 5xx, transport drop, or post-delete stat indeterminate; never treated as deleted.
    OutcomeUnknown { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemotePresence {
    Present { content_length: u64 },
    Absent,
    Unknown { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionPublishResult {
    pub op_id: Uuid,
    pub new_pack_id: Uuid,
    pub new_membership_generation: u64,
    pub new_membership_digest: String,
    pub retired_pack_ids: Vec<Uuid>,
    pub replacement_pack: BlobLocatorRecord,
    pub replacement_idx: BlobLocatorRecord,
    pub pack_key_path: String,
    pub equivalence_digest: String,
    pub prior_closure_retained: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcAuditEvent {
    pub seq: u64,
    pub incarnation_epoch: u64,
    pub action: String,
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteExecutionReport {
    pub batch_id: Uuid,
    pub proof_digest: String,
    pub incarnation_epoch: u64,
    pub deleted_keys: Vec<String>,
    pub already_absent_keys: Vec<String>,
    pub unknown_outcome_keys: Vec<String>,
    pub skipped_or_already_deleted: Vec<String>,
    pub failed_keys: Vec<String>,
    pub reconciled_from_checkpoint: bool,
    pub aborted_stale_incarnation: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagingCleanupReport {
    pub deleted_keys: Vec<String>,
    pub already_absent_keys: Vec<String>,
    pub unknown_outcome_keys: Vec<String>,
}

/// Non-forgeable delete authorization minted solely after barrier fencing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteAuthorizationTicket {
    batch_id: Uuid,
    step_fence_id: Uuid,
    incarnation_id: Uuid,
    incarnation_epoch: u64,
    lease_epoch: u64,
    membership_generation: u64,
    membership_digest: String,
    proof_digest: String,
    pack_id: Uuid,
    key_role: String,
    physical_key: String,
    object_sha256: String,
    provider_generation: i64,
    locator: BlobLocatorRecord,
    staging_cleanup_only: bool,
    ticket_digest: String,
}

/// Input payload for atomic Phase 2 compaction CAS publication.
#[derive(Clone, Debug)]
pub struct CasCompactionPublish {
    pub op_id: Uuid,
    pub group_id: String,
    pub expected_incarnation_id: Uuid,
    pub expected_incarnation_epoch: u64,
    pub expected_generation: u64,
    pub expected_membership_digest: String,
    pub retired_pack_ids: Vec<Uuid>,
    pub uploaded: UploadedCompactionPair,
    pub replacement_oids: Vec<String>,
    pub equivalence_digest: String,
}

pub(crate) struct TicketMintSpec {
    pub batch_id: Uuid,
    pub step_fence_id: Uuid,
    pub incarnation_id: Uuid,
    pub incarnation_epoch: u64,
    pub lease_epoch: u64,
    pub membership_generation: u64,
    pub membership_digest: String,
    pub proof_digest: String,
    pub pack_id: Uuid,
    pub key_role: String,
    pub physical_key: String,
    pub object_sha256: String,
    pub locator: BlobLocatorRecord,
    pub staging_cleanup_only: bool,
}

impl DeleteAuthorizationTicket {
    pub(super) fn mint(spec: TicketMintSpec) -> Self {
        let provider_generation = spec.locator.generation;
        let mut ticket = Self {
            batch_id: spec.batch_id,
            step_fence_id: spec.step_fence_id,
            incarnation_id: spec.incarnation_id,
            incarnation_epoch: spec.incarnation_epoch,
            lease_epoch: spec.lease_epoch,
            membership_generation: spec.membership_generation,
            membership_digest: spec.membership_digest,
            proof_digest: spec.proof_digest,
            pack_id: spec.pack_id,
            key_role: spec.key_role,
            physical_key: spec.physical_key,
            object_sha256: spec.object_sha256,
            provider_generation,
            locator: spec.locator,
            staging_cleanup_only: spec.staging_cleanup_only,
            ticket_digest: String::new(),
        };
        ticket.ticket_digest = ticket.compute_digest();
        ticket
    }

    pub fn compute_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"safe-gc-delete-ticket-v2|");
        h.update(self.batch_id.as_bytes());
        h.update(self.step_fence_id.as_bytes());
        h.update(self.incarnation_id.as_bytes());
        h.update(self.incarnation_epoch.to_be_bytes());
        h.update(self.lease_epoch.to_be_bytes());
        h.update(self.membership_generation.to_be_bytes());
        encode_len_bytes(&mut h, self.membership_digest.as_bytes());
        encode_len_bytes(&mut h, self.proof_digest.as_bytes());
        h.update(self.pack_id.as_bytes());
        encode_len_bytes(&mut h, self.key_role.as_bytes());
        encode_len_bytes(&mut h, self.physical_key.as_bytes());
        encode_len_bytes(&mut h, self.object_sha256.as_bytes());
        h.update(self.provider_generation.to_be_bytes());
        self.locator.encode_canonical(&mut h);
        h.update([u8::from(self.staging_cleanup_only)]);
        hex::encode(h.finalize())
    }

    pub fn verify_digest_and_locator(&self) -> Result<(), SafeGcError> {
        validate_bounded_name("physical_key", &self.physical_key)?;
        validate_sha256_hex(&self.object_sha256)?;
        validate_sha256_hex(&self.membership_digest)?;
        self.locator.validate_version_binding()?;
        if self.provider_generation <= 0
            || self.locator.generation != self.provider_generation
            || self.locator.sha256 != self.object_sha256
        {
            return Err(SafeGcError::StaleDeleterFenced("ticket provider_generation or sha256 disagrees with locator"));
        }
        if self.ticket_digest != self.compute_digest() {
            return Err(SafeGcError::StaleDeleterFenced("delete ticket digest tampered"));
        }
        Ok(())
    }

    pub fn batch_id(&self) -> Uuid {
        self.batch_id
    }

    pub fn step_fence_id(&self) -> Uuid {
        self.step_fence_id
    }

    pub fn incarnation_id(&self) -> Uuid {
        self.incarnation_id
    }

    pub fn incarnation_epoch(&self) -> u64 {
        self.incarnation_epoch
    }

    pub fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }

    pub fn membership_generation(&self) -> u64 {
        self.membership_generation
    }

    pub fn membership_digest(&self) -> &str {
        &self.membership_digest
    }

    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }

    pub fn pack_id(&self) -> Uuid {
        self.pack_id
    }

    pub fn key_role(&self) -> &str {
        &self.key_role
    }

    pub fn physical_key(&self) -> &str {
        &self.physical_key
    }

    pub fn object_sha256(&self) -> &str {
        &self.object_sha256
    }

    pub fn provider_generation(&self) -> i64 {
        self.provider_generation
    }

    pub fn locator(&self) -> &BlobLocatorRecord {
        &self.locator
    }

    pub fn is_staging_cleanup_only(&self) -> bool {
        self.staging_cleanup_only
    }

    pub fn ticket_digest(&self) -> &str {
        &self.ticket_digest
    }
}

/// Active fence held continuously across the entire provider delete operation.
pub struct ActiveDeleteFence<'a> {
    authority: &'a DurableSafeGcAuthority,
    ticket: &'a DeleteAuthorizationTicket,
    external_check: Option<ExternalFenceCheck<'a>>,
}

impl<'a> ActiveDeleteFence<'a> {
    pub(super) fn new(
        authority: &'a DurableSafeGcAuthority,
        ticket: &'a DeleteAuthorizationTicket,
        external_check: Option<ExternalFenceCheck<'a>>,
    ) -> Self {
        Self { authority, ticket, external_check }
    }

    pub fn verify_active_for_ticket(&self, candidate: &DeleteAuthorizationTicket) -> Result<(), SafeGcError> {
        if candidate != self.ticket {
            return Err(SafeGcError::StaleDeleterFenced("provider called with mismatched delete ticket"));
        }
        candidate.verify_digest_and_locator()?;
        self.authority.verify_active_step_ticket(candidate)?;
        let is_pg =
            matches!(self.authority.snapshot().gc_mode.require_armed()?.lane, AuthorityLane::SingleNodePg { .. });
        match (is_pg, self.external_check) {
            (true, None) => {
                return Err(SafeGcError::StaleDeleterFenced(
                    "SingleNodePg ActiveDeleteFence requires live PG lease and gc_epoch fence",
                ));
            }
            (_, Some(ext)) => ext()?,
            (false, None) => {}
        }
        Ok(())
    }
}

/// Pluggable compaction upload hook preserving protected BlobStore boundaries.
pub trait SafeGcCompactionUploader: Send + Sync {
    fn upload_compacted_pair<'a>(
        &'a self,
        store: &'a BlobStore,
        scope: (Uuid, Uuid, i64),
        keys: (PhysicalBlobKey, PhysicalBlobKey),
        paths: (&'a Path, &'a Path),
        deadline: Instant,
    ) -> SafeGcFuture<'a, UploadedCompactionPair>;
}

/// Physical delete backend invoked ONLY under a live [`ActiveDeleteFence`].
pub trait SafeGcDeleteBackend: Send + Sync {
    fn delete_authorized<'a>(
        &'a self,
        fence: &'a ActiveDeleteFence<'a>,
        ticket: &'a DeleteAuthorizationTicket,
        deadline: Instant,
    ) -> SafeGcFuture<'a, ProviderDeleteOutcome>;

    fn probe_presence<'a>(
        &'a self,
        locator: &'a BlobLocatorRecord,
        deadline: Instant,
    ) -> SafeGcFuture<'a, RemotePresence>;
}

/// Default readback-only BlobStore backend preserving `BlobStore::delete == DeleteDisabled`.
pub struct BlobStoreReadbackBackend<'a> {
    pub store: &'a BlobStore,
}

impl<'a> SafeGcDeleteBackend for BlobStoreReadbackBackend<'a> {
    fn delete_authorized<'b>(
        &'b self,
        fence: &'b ActiveDeleteFence<'b>,
        ticket: &'b DeleteAuthorizationTicket,
        deadline: Instant,
    ) -> SafeGcFuture<'b, ProviderDeleteOutcome> {
        Box::pin(async move {
            fence.verify_active_for_ticket(ticket)?;
            let loc = ticket.locator().to_locator()?;
            self.store.delete(&loc, deadline).await?;
            Ok(ProviderDeleteOutcome::ConfirmedDeleted)
        })
    }

    fn probe_presence<'b>(
        &'b self,
        locator: &'b BlobLocatorRecord,
        deadline: Instant,
    ) -> SafeGcFuture<'b, RemotePresence> {
        Box::pin(async move {
            let loc = locator.to_locator()?;
            match self.store.head(&loc, deadline).await {
                Ok(Some(content_length)) => Ok(RemotePresence::Present { content_length }),
                Ok(None) => Ok(RemotePresence::Absent),
                Err(err) => Ok(RemotePresence::Unknown { reason: err.to_string() }),
            }
        })
    }
}
