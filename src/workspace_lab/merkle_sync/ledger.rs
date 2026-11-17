use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
    time::Instant,
};

use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    MerkleSyncError,
    authz::{AccessContext, TenantRepoScopeKey},
    manifest::MerkleStateManifest,
};
use crate::{
    blob_store::{
        BlobLocator, BlobReceipt,
        opendal::BlobStore,
        protected::{ProtectedUploader, UploadSource},
    },
    ref_store::{
        IssuerLane, OperationIdentity, PgRefStore, RequestDigest,
        artifact_hold::{AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactSpec, HoldScope, PgArtifactHoldStore},
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteObjectLocatorEntry {
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: u64,
}

impl RemoteObjectLocatorEntry {
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

    pub fn to_locator(&self) -> Result<BlobLocator, MerkleSyncError> {
        Ok(BlobLocator::new(
            self.tenant_id,
            self.authority_id,
            self.generation,
            self.attempt_id,
            &self.namespace,
            &self.sha256,
            self.length,
        )?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleBlobCheckpointManifest {
    pub schema: u32,
    pub codec_version: String,
    pub checkpoint_id: Uuid,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub workspace_id: Uuid,
    pub backend_identity_hex: String,
    pub merkle_root_digest: String,
    pub state_manifest: MerkleStateManifest,
    pub git_bundle_locator: RemoteObjectLocatorEntry,
    pub chunk_locators: BTreeMap<String, RemoteObjectLocatorEntry>,
    pub node_locators: BTreeMap<String, RemoteObjectLocatorEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointCommitState {
    Staging,
    Committed,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCommitRecord {
    pub checkpoint_id: Uuid,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub workspace_id: Uuid,
    pub backend_identity_hex: String,
    pub merkle_root_digest: String,
    pub state: CheckpointCommitState,
    pub manifest_locator: Option<RemoteObjectLocatorEntry>,
    pub hold_id: Option<Uuid>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncUploadReport {
    pub checkpoint_id: Uuid,
    pub merkle_root_digest: String,
    pub uploaded_chunks: usize,
    pub reused_chunks: usize,
    pub uploaded_nodes: usize,
    pub reused_nodes: usize,
    pub uploaded_bytes: u64,
    pub reused_bytes: u64,
    pub closure_verified: bool,
    pub manifest_locator: RemoteObjectLocatorEntry,
    pub hold_id: Uuid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadFailpoint {
    AfterFirstChunk,
    BeforeManifestUpload,
    BeforeAtomicCommit,
}

pub type UploadVerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<BlobReceipt, MerkleSyncError>> + Send + 'a>>;

#[derive(Clone, Copy)]
pub struct UploadVerifiedArgs<'a> {
    pub store: &'a BlobStore,
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub namespace: &'a str,
    pub sha256: &'a str,
    pub length: u64,
    pub source_path: &'a Path,
    pub deadline: Instant,
}

pub trait BlobUploadDriver: Send + Sync {
    fn upload_verified<'a>(&'a self, args: UploadVerifiedArgs<'a>) -> UploadVerifyFuture<'a>;
}

pub struct PgProtectedUploadDriver {
    pub pool: Pool,
    pub scope: HoldScope,
    pub expected_gate_digest: RequestDigest,
    pub lane: IssuerLane,
    pub next_seq: AtomicI64,
}

impl BlobUploadDriver for PgProtectedUploadDriver {
    fn upload_verified<'a>(&'a self, args: UploadVerifiedArgs<'a>) -> UploadVerifyFuture<'a> {
        Box::pin(async move {
            let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
            let tokio_dl = tokio::time::Instant::from_std(args.deadline);
            let op_digest_bytes: [u8; 32] =
                Sha256::digest(format!("merkle:{}:{}:{seq}", args.namespace, args.sha256).as_bytes()).into();
            let op = OperationIdentity::new(
                self.scope.repository_id(),
                self.scope.owner_id(),
                self.lane.clone(),
                seq,
                Uuid::new_v4(),
                RequestDigest::from_bytes(op_digest_bytes),
            )
            .map_err(|e| MerkleSyncError::InvalidInput(e.to_string()))?;
            let spec = ArtifactSpec::new(args.namespace, args.sha256, args.length)
                .map_err(|e| MerkleSyncError::InvalidInput(e.to_string()))?;
            let mut client =
                self.pool.get().await.map_err(|_| MerkleSyncError::Io("pg pool checkout failed".into()))?;
            let tx = client.transaction().await.map_err(|_| MerkleSyncError::Io("pg tx start failed".into()))?;
            PgRefStore.begin(&tx, &op, tokio_dl).await.map_err(|e| MerkleSyncError::Io(e.to_string()))?;
            tx.commit().await.map_err(|_| MerkleSyncError::Io("pg tx commit failed".into()))?;
            let req = AcquireArtifactHoldsRequest::new(
                self.scope,
                op,
                Uuid::new_v4(),
                args.store.backend_identity().clone(),
                args.authority_id,
                args.generation,
                self.expected_gate_digest,
                vec![spec],
            )
            .map_err(|e| MerkleSyncError::InvalidInput(e.to_string()))?;
            let grant = match PgArtifactHoldStore
                .acquire(&mut client, args.store, &req, tokio_dl)
                .await
                .map_err(|e| MerkleSyncError::Io(e.to_string()))?
            {
                AcquireOutcome::Granted { grant, .. } => grant,
                AcquireOutcome::Replayed { .. } => {
                    return Err(MerkleSyncError::InvalidInput("unexpected hold replay".into()));
                }
            };
            drop(client);
            let pub_res = ProtectedUploader::new(args.store.clone())
                .consume_and_upload(&self.pool, grant, &[UploadSource::new(args.source_path)], args.deadline)
                .await
                .map_err(|e| MerkleSyncError::Io(e.to_string()))?;
            Ok(pub_res.receipts()[0].receipt().clone())
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MerkleCheckpointLedger {
    inner: Arc<Mutex<LedgerState>>,
}

#[derive(Debug, Default)]
struct LedgerState {
    checkpoints: BTreeMap<Uuid, CheckpointCommitRecord>,
    scoped_objects: BTreeMap<TenantRepoScopeKey, RemoteObjectLocatorEntry>,
    all_issued_locators: BTreeSet<String>,
}

impl MerkleCheckpointLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin_staging(&self, rec: CheckpointCommitRecord) -> Result<(), MerkleSyncError> {
        let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = st.checkpoints.get(&rec.checkpoint_id)
            && existing.state == CheckpointCommitState::Committed
        {
            return Err(MerkleSyncError::InvalidInput("checkpoint_id already committed".into()));
        }
        st.checkpoints.insert(rec.checkpoint_id, rec);
        Ok(())
    }

    pub fn abort_staging(&self, checkpoint_id: Uuid) {
        let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(rec) = st.checkpoints.get_mut(&checkpoint_id)
            && rec.state == CheckpointCommitState::Staging
        {
            rec.state = CheckpointCommitState::Aborted;
        }
    }

    pub fn commit_atomic(
        &self,
        checkpoint_id: Uuid,
        locator: RemoteObjectLocatorEntry,
        hold_id: Uuid,
    ) -> Result<(), MerkleSyncError> {
        let loc_path = locator.to_locator()?.path();
        let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        {
            let rec = st
                .checkpoints
                .get_mut(&checkpoint_id)
                .ok_or_else(|| MerkleSyncError::MissingArtifact("staging checkpoint missing".into()))?;
            if rec.state != CheckpointCommitState::Staging {
                return Err(MerkleSyncError::NotQuiescent("checkpoint not in Staging state".into()));
            }
            rec.state = CheckpointCommitState::Committed;
            rec.manifest_locator = Some(locator);
            rec.hold_id = Some(hold_id);
        }
        st.all_issued_locators.insert(loc_path);
        Ok(())
    }

    pub fn record_issued_locator(&self, loc: &BlobLocator) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).all_issued_locators.insert(loc.path());
    }

    pub fn record_scoped_object(&self, key: TenantRepoScopeKey, entry: RemoteObjectLocatorEntry) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).scoped_objects.insert(key, entry);
    }

    pub fn lookup_scoped_object(&self, key: &TenantRepoScopeKey) -> Option<RemoteObjectLocatorEntry> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).scoped_objects.get(key).cloned()
    }

    pub fn get_committed(
        &self,
        ctx: &AccessContext,
        checkpoint_id: Uuid,
    ) -> Result<CheckpointCommitRecord, MerkleSyncError> {
        let st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let rec = st
            .checkpoints
            .get(&checkpoint_id)
            .ok_or_else(|| MerkleSyncError::MissingArtifact("checkpoint not found".into()))?;
        if rec.tenant_id != ctx.tenant_id || rec.repo_id != ctx.repo_id {
            return Err(MerkleSyncError::TenantScopeMismatch("checkpoint belongs to different tenant or repo".into()));
        }
        if rec.history_id != ctx.history_id {
            return Err(MerkleSyncError::StaleHistoryFenced("checkpoint history_id mismatch".into()));
        }
        if rec.state != CheckpointCommitState::Committed {
            return Err(MerkleSyncError::MissingArtifact("checkpoint is not committed".into()));
        }
        Ok(rec.clone())
    }

    pub fn all_issued_locators(&self) -> BTreeSet<String> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).all_issued_locators.clone()
    }

    pub fn committed_locator_paths(&self) -> BTreeSet<String> {
        let st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut set = BTreeSet::new();
        for rec in st.checkpoints.values().filter(|r| r.state == CheckpointCommitState::Committed) {
            if let Some(m) = &rec.manifest_locator
                && let Ok(loc) = m.to_locator()
            {
                set.insert(loc.path());
            }
        }
        for entry in st.scoped_objects.values() {
            if let Ok(loc) = entry.to_locator() {
                set.insert(loc.path());
            }
        }
        set
    }
}
