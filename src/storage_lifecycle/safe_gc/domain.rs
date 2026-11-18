//! Domain boundaries, non-forgeable delete tickets, and storage traits (#122).

use std::{future::Future, path::Path, pin::Pin, time::Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{BlobLocator, opendal::BlobStore};

use super::{SafeGcError, anti_aba::PhysicalBlobKey, model::encode_len_bytes};

pub type SafeGcFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SafeGcError>> + Send + 'a>>;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadedCompactionPair {
    pub pack_locator: BlobLocatorRecord,
    pub idx_locator: BlobLocatorRecord,
    pub pack_key: PhysicalBlobKey,
    pub idx_key: PhysicalBlobKey,
}

/// Serializable Blob coordinate mirror preserving BlobLocator invariants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobLocatorRecord {
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: u64,
}

impl BlobLocatorRecord {
    pub fn from_locator(loc: &BlobLocator) -> Self {
        Self {
            tenant_id: loc.tenant_id(),
            authority_id: loc.authority_id(),
            generation: loc.generation(),
            attempt_id: loc.attempt_id(),
            namespace: loc.namespace().to_owned(),
            sha256: loc.sha256().to_owned(),
            length: loc.length(),
        }
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionPublishResult {
    pub op_id: Uuid,
    pub new_pack_id: Uuid,
    pub new_membership_generation: u64,
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
    pub skipped_or_already_deleted: Vec<String>,
    pub failed_keys: Vec<String>,
    pub reconciled_from_checkpoint: bool,
}

/// Non-forgeable delete authorization minted solely after barrier fencing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteAuthorizationTicket {
    batch_id: Uuid,
    incarnation_id: Uuid,
    incarnation_epoch: u64,
    lease_epoch: u64,
    proof_digest: String,
    pack_id: Uuid,
    physical_key: String,
    object_sha256: String,
    locator: Option<BlobLocatorRecord>,
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
    pub retired_pack_ids: Vec<Uuid>,
    pub uploaded: UploadedCompactionPair,
    pub replacement_oids: Vec<String>,
    pub equivalence_digest: String,
}

impl DeleteAuthorizationTicket {
    pub(super) fn mint(
        batch: (Uuid, Uuid, u64, u64),
        proof_digest: String,
        pack_id: Uuid,
        target: (String, String, Option<BlobLocatorRecord>),
    ) -> Self {
        let (batch_id, incarnation_id, incarnation_epoch, lease_epoch) = batch;
        let (physical_key, object_sha256, locator) = target;
        let mut h = Sha256::new();
        h.update(b"safe-gc-delete-ticket-v1|");
        h.update(batch_id.as_bytes());
        h.update(incarnation_id.as_bytes());
        h.update(incarnation_epoch.to_be_bytes());
        h.update(lease_epoch.to_be_bytes());
        encode_len_bytes(&mut h, proof_digest.as_bytes());
        h.update(pack_id.as_bytes());
        encode_len_bytes(&mut h, physical_key.as_bytes());
        encode_len_bytes(&mut h, object_sha256.as_bytes());
        let ticket_digest = hex::encode(h.finalize());
        Self {
            batch_id,
            incarnation_id,
            incarnation_epoch,
            lease_epoch,
            proof_digest,
            pack_id,
            physical_key,
            object_sha256,
            locator,
            ticket_digest,
        }
    }

    pub fn batch_id(&self) -> Uuid {
        self.batch_id
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

    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }

    pub fn pack_id(&self) -> Uuid {
        self.pack_id
    }

    pub fn physical_key(&self) -> &str {
        &self.physical_key
    }

    pub fn object_sha256(&self) -> &str {
        &self.object_sha256
    }

    pub fn locator(&self) -> Option<&BlobLocatorRecord> {
        self.locator.as_ref()
    }

    pub fn ticket_digest(&self) -> &str {
        &self.ticket_digest
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

/// Physical delete backend invoked ONLY with a fenced [`DeleteAuthorizationTicket`].
pub trait SafeGcDeleteBackend: Send + Sync {
    fn delete_authorized<'a>(
        &'a self,
        ticket: &'a DeleteAuthorizationTicket,
        deadline: Instant,
    ) -> SafeGcFuture<'a, ()>;
}

/// Default readback-only BlobStore backend preserving `BlobStore::delete == DeleteDisabled`.
pub struct BlobStoreReadbackBackend<'a> {
    pub store: &'a BlobStore,
}

impl<'a> SafeGcDeleteBackend for BlobStoreReadbackBackend<'a> {
    fn delete_authorized<'b>(
        &'b self,
        ticket: &'b DeleteAuthorizationTicket,
        deadline: Instant,
    ) -> SafeGcFuture<'b, ()> {
        Box::pin(async move {
            let Some(loc_rec) = ticket.locator() else {
                return Err(SafeGcError::BlobDeleteDisabled);
            };
            let loc = loc_rec.to_locator()?;
            self.store.delete(&loc, deadline).await.map_err(SafeGcError::from)
        })
    }
}
