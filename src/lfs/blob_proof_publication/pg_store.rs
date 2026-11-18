//! PostgreSQL 17 store for remote-Blob LFS objects, holds, and upload operations (`Refs #145`).

use deadpool_postgres::Pool;
use tokio::time::Instant as TokioInstant;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::blob_store::opendal::BlobStore;
use crate::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactGrant, ArtifactHoldPurpose, ArtifactSpec, HoldScope,
    PgArtifactHoldStore,
};
use crate::ref_store::{IssuerLane, OperationIdentity, OperationState, PgRefStore, RequestDigest};

pub use super::pg_schema::{LfsRepoRealm, init_lfs_blob_proof_tables};
use super::types::{CommittedLfsBlobRecord, LfsBlobError, LfsProofRejectCode, StoredBlobLocatorRef};

pub(super) fn pg_err(err: impl std::fmt::Display) -> LfsBlobError {
    LfsBlobError::new(LfsProofRejectCode::PgDatabase, err.to_string())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileUploadsReport {
    pub aborted_orphaned_attempts: u64,
    pub aborted_orphaned_operations: u64,
    pub committed_objects_preserved: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadOperationRow {
    pub repository_id: Uuid,
    pub operation_id: Uuid,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub oid_sha256: String,
    pub size_bytes: i64,
    pub state: String,
    pub locator: Option<StoredBlobLocatorRef>,
    pub hold_id: Option<Uuid>,
}

#[derive(Clone)]
pub struct PgLfsBlobStore {
    pool: Pool,
}

impl PgLfsBlobStore {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub async fn acquire_lfs_upload_hold(
        &self,
        store: &BlobStore,
        realm: &LfsRepoRealm,
        oid_sha256: &str,
        size_bytes: u64,
        pg_deadline: TokioInstant,
    ) -> Result<ArtifactGrant, LfsBlobError> {
        let seq: i64 = {
            let client = self.pool.get().await.map_err(pg_err)?;
            client
                .query_one(
                    "UPDATE lfs_blob_repo_realms SET next_op_seq = next_op_seq + 1
                     WHERE repository_id=$1 RETURNING next_op_seq",
                    &[&realm.repository_id],
                )
                .await
                .map_err(pg_err)?
                .get(0)
        };
        let op_id = Uuid::new_v4();
        let lane = IssuerLane::new("lfs-blob-pub")
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let digest =
            RequestDigest::of("lfs-upload", &[oid_sha256.as_bytes(), &size_bytes.to_be_bytes(), op_id.as_bytes()]);
        let op = OperationIdentity::new(realm.hold_anchor_id, realm.owner_tenant_id, lane, seq, op_id, digest)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        {
            let mut client = self.pool.get().await.map_err(pg_err)?;
            let tx = client.transaction().await.map_err(pg_err)?;
            let begun = PgRefStore.begin(&tx, &op, pg_deadline).await.map_err(pg_err)?;
            if begun.record.state() != OperationState::Pending {
                return Err(LfsBlobError::new(LfsProofRejectCode::PgDatabase, "unexpected non-pending LFS hold op"));
            }
            tx.commit().await.map_err(pg_err)?;
        }
        let scope = HoldScope::new(
            realm.hold_anchor_id,
            realm.owner_tenant_id,
            realm.owner_tenant_id,
            ArtifactHoldPurpose::RefPublication,
            realm.object_format,
            realm.history_incarnation,
            1,
            1,
        )
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let spec = ArtifactSpec::new("lfs-objects", oid_sha256.to_owned(), size_bytes)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let req = AcquireArtifactHoldsRequest::new(
            scope,
            op,
            Uuid::new_v4(),
            store.backend_identity().clone(),
            realm.hold_anchor_id,
            1,
            realm.gate_digest,
            vec![spec],
        )
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let mut client = self.pool.get().await.map_err(pg_err)?;
        match PgArtifactHoldStore.acquire(&mut client, store, &req, pg_deadline).await.map_err(pg_err)? {
            AcquireOutcome::Granted { grant, .. } => Ok(grant),
            AcquireOutcome::Replayed { .. } => {
                Err(LfsBlobError::new(LfsProofRejectCode::PgDatabase, "unexpected fresh LFS hold replay"))
            }
        }
    }

    fn decode_upload_op_row(row: &Row) -> Result<UploadOperationRow, LfsBlobError> {
        let locator = row
            .get::<_, Option<serde_json::Value>>(7)
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        Ok(UploadOperationRow {
            repository_id: row.get(0),
            operation_id: row.get(1),
            tenant_id: row.get(2),
            actor_id: row.get(3),
            oid_sha256: row.get(4),
            size_bytes: row.get(5),
            state: row.get(6),
            locator,
            hold_id: row.get(8),
        })
    }

    pub async fn begin_or_load_upload_operation(
        &self,
        repository_id: Uuid,
        operation_id: Uuid,
        tenant_id: Uuid,
        actor_id: Uuid,
        oid_sha256: &str,
        size_bytes: i64,
    ) -> Result<UploadOperationRow, LfsBlobError> {
        let mut client = self.pool.get().await.map_err(pg_err)?;
        let tx = client.transaction().await.map_err(pg_err)?;
        tx.batch_execute("SET LOCAL synchronous_commit = 'on'").await.map_err(pg_err)?;
        tx.execute(
            "INSERT INTO lfs_blob_upload_operations(repository_id, operation_id, tenant_id, actor_id, oid_sha256, size_bytes, state)
             VALUES($1,$2,$3,$4,$5,$6,'pending') ON CONFLICT (repository_id, operation_id) DO NOTHING",
            &[&repository_id, &operation_id, &tenant_id, &actor_id, &oid_sha256, &size_bytes],
        )
        .await
        .map_err(pg_err)?;
        let row = tx
            .query_one(
                "SELECT repository_id, operation_id, tenant_id, actor_id, oid_sha256, size_bytes, state, locator_json, hold_id
                 FROM lfs_blob_upload_operations WHERE repository_id=$1 AND operation_id=$2 FOR UPDATE",
                &[&repository_id, &operation_id],
            )
            .await
            .map_err(pg_err)?;
        let op_row = Self::decode_upload_op_row(&row)?;
        if op_row.tenant_id != tenant_id
            || op_row.actor_id != actor_id
            || op_row.oid_sha256 != oid_sha256
            || op_row.size_bytes != size_bytes
        {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "upload operation_id reused with conflicting tenant, actor, OID, or byte size",
            ));
        }
        tx.commit().await.map_err(pg_err)?;
        Ok(op_row)
    }

    pub async fn load_upload_operation(
        &self,
        repository_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<UploadOperationRow>, LfsBlobError> {
        let client = self.pool.get().await.map_err(pg_err)?;
        let row = client
            .query_opt(
                "SELECT repository_id, operation_id, tenant_id, actor_id, oid_sha256, size_bytes, state, locator_json, hold_id
                 FROM lfs_blob_upload_operations WHERE repository_id=$1 AND operation_id=$2",
                &[&repository_id, &operation_id],
            )
            .await
            .map_err(pg_err)?;
        row.as_ref().map(Self::decode_upload_op_row).transpose()
    }

    pub async fn record_upload_attempt_start(
        &self,
        attempt_id: Uuid,
        tenant_id: Uuid,
        repository_id: Uuid,
        actor_id: Uuid,
        oid_sha256: &str,
        size_bytes: i64,
    ) -> Result<(), LfsBlobError> {
        let client = self.pool.get().await.map_err(pg_err)?;
        client
            .execute(
                "INSERT INTO lfs_blob_upload_attempts(attempt_id, tenant_id, repository_id, actor_id, oid_sha256, size_bytes, state)
                 VALUES($1,$2,$3,$4,$5,$6,'pending')",
                &[&attempt_id, &tenant_id, &repository_id, &actor_id, &oid_sha256, &size_bytes],
            )
            .await
            .map_err(pg_err)?;
        Ok(())
    }

    pub async fn mark_upload_attempt_aborted(&self, attempt_id: Uuid, reason: &str) -> Result<(), LfsBlobError> {
        let client = self.pool.get().await.map_err(pg_err)?;
        client
            .execute(
                "UPDATE lfs_blob_upload_attempts SET state='aborted_failed', failure_reason=$2, updated_at=clock_timestamp()
                 WHERE attempt_id=$1 AND state='pending'",
                &[&attempt_id, &reason],
            )
            .await
            .map_err(pg_err)?;
        Ok(())
    }

    /// Commits or repairs `lfs_blob_objects` under `FOR UPDATE`, binds `lfs_blob_upload_operations`
    /// and production `lfs_objects`, and returns the **final authoritative committed record** whose
    /// `locator` MUST still be readback-verified by the caller before issuing an HTTP ACK.
    pub async fn record_committed_blob(
        &self,
        attempt_id: Uuid,
        operation_id: Option<Uuid>,
        record: &CommittedLfsBlobRecord,
        stale_missing_locator: Option<&StoredBlobLocatorRef>,
    ) -> Result<CommittedLfsBlobRecord, LfsBlobError> {
        let loc_json = serde_json::to_value(&record.locator)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let mut client = self.pool.get().await.map_err(pg_err)?;
        let tx = client.transaction().await.map_err(pg_err)?;
        tx.batch_execute("SET LOCAL synchronous_commit = 'on'").await.map_err(pg_err)?;
        tx.execute(
            "UPDATE lfs_blob_upload_attempts SET state='committed', updated_at=clock_timestamp() WHERE attempt_id=$1",
            &[&attempt_id],
        )
        .await
        .map_err(pg_err)?;
        let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &record.tenant_id,
            &record.repository_id,
            &record.oid_sha256,
            &record.size_bytes,
            &loc_json,
            &record.hold_id,
            &record.acquire_request_id,
            &record.consume_request_id,
            &record.backend_identity_hex,
            &record.uploader_actor_id,
        ];
        tx.execute(
            "INSERT INTO lfs_blob_objects(
                tenant_id, repository_id, oid_sha256, size_bytes, locator_json, hold_id,
                acquire_request_id, consume_request_id, backend_identity_hex, uploader_actor_id, retired
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,FALSE)
             ON CONFLICT (tenant_id, repository_id, oid_sha256) DO NOTHING",
            params,
        )
        .await
        .map_err(pg_err)?;
        let mut row = tx
            .query_one(
                "SELECT tenant_id, repository_id, oid_sha256, size_bytes, locator_json, hold_id,
                        acquire_request_id, consume_request_id, backend_identity_hex, uploader_actor_id, retired
                 FROM lfs_blob_objects WHERE tenant_id=$1 AND repository_id=$2 AND oid_sha256=$3 FOR UPDATE",
                &[&record.tenant_id, &record.repository_id, &record.oid_sha256],
            )
            .await
            .map_err(pg_err)?;
        let mut stored = Self::decode_blob_row(&row)?;
        if stored.size_bytes != record.size_bytes {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::SizeOrDigestMismatch,
                "existing committed LFS object has conflicting byte length",
            ));
        }
        if stored.locator != record.locator
            && (stored.retired || stale_missing_locator.is_some_and(|stale| *stale == stored.locator))
        {
            tx.batch_execute("SET LOCAL rootyard.lfs_allow_locator_repair = 'on'").await.map_err(pg_err)?;
            row = tx
                .query_one(
                    "UPDATE lfs_blob_objects
                     SET locator_json=$4, hold_id=$5, acquire_request_id=$6, consume_request_id=$7,
                         backend_identity_hex=$8, uploader_actor_id=$9, retired=FALSE, committed_at=clock_timestamp()
                     WHERE tenant_id=$1 AND repository_id=$2 AND oid_sha256=$3
                     RETURNING tenant_id, repository_id, oid_sha256, size_bytes, locator_json, hold_id,
                               acquire_request_id, consume_request_id, backend_identity_hex, uploader_actor_id, retired",
                    &[
                        &record.tenant_id,
                        &record.repository_id,
                        &record.oid_sha256,
                        &loc_json,
                        &record.hold_id,
                        &record.acquire_request_id,
                        &record.consume_request_id,
                        &record.backend_identity_hex,
                        &record.uploader_actor_id,
                    ],
                )
                .await
                .map_err(pg_err)?;
            stored = Self::decode_blob_row(&row)?;
        }

        if let Some(op_id) = operation_id {
            let final_loc_json = serde_json::to_value(&stored.locator)
                .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
            tx.execute(
                "UPDATE lfs_blob_upload_operations
                 SET state='committed', locator_json=$3, hold_id=$4, updated_at=clock_timestamp()
                 WHERE repository_id=$1 AND operation_id=$2",
                &[&record.repository_id, &op_id, &final_loc_json, &stored.hold_id],
            )
            .await
            .map_err(pg_err)?;
        }

        tx.execute(
            "INSERT INTO lfs_objects (tenant_id, repository_id, oid, size, state)
             VALUES ($1, $2, $3, $4, 'ready')
             ON CONFLICT (tenant_id, repository_id, oid)
             DO UPDATE SET state = 'ready', updated_at = clock_timestamp()
             WHERE lfs_objects.size = EXCLUDED.size",
            &[&stored.tenant_id, &stored.repository_id, &stored.oid_sha256, &stored.size_bytes],
        )
        .await
        .map_err(pg_err)?;

        tx.commit().await.map_err(pg_err)?;
        Ok(stored)
    }

    pub(super) fn decode_blob_row(row: &Row) -> Result<CommittedLfsBlobRecord, LfsBlobError> {
        let loc_val: serde_json::Value = row.get(4);
        let locator: StoredBlobLocatorRef = serde_json::from_value(loc_val)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        Ok(CommittedLfsBlobRecord {
            tenant_id: row.get(0),
            repository_id: row.get(1),
            oid_sha256: row.get(2),
            size_bytes: row.get(3),
            locator,
            hold_id: row.get(5),
            acquire_request_id: row.get(6),
            consume_request_id: row.get(7),
            backend_identity_hex: row.get(8),
            uploader_actor_id: row.get(9),
            retired: row.get(10),
        })
    }

    pub async fn load_committed_blob(
        &self,
        tenant_id: Uuid,
        repository_id: Uuid,
        oid_sha256: &str,
    ) -> Result<Option<CommittedLfsBlobRecord>, LfsBlobError> {
        let client = self.pool.get().await.map_err(pg_err)?;
        let row = client
            .query_opt(
                "SELECT tenant_id, repository_id, oid_sha256, size_bytes, locator_json, hold_id,
                        acquire_request_id, consume_request_id, backend_identity_hex, uploader_actor_id, retired
                 FROM lfs_blob_objects WHERE tenant_id=$1 AND repository_id=$2 AND oid_sha256=$3",
                &[&tenant_id, &repository_id, &oid_sha256],
            )
            .await
            .map_err(pg_err)?;
        row.as_ref().map(Self::decode_blob_row).transpose()
    }
}
