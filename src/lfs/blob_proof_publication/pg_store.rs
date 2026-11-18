//! PostgreSQL 17 store for remote-Blob LFS objects, holds, attempts, and shared-holds (`Refs #145`).

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
use super::types::{
    CommittedLfsBlobRecord, LfsBlobError, LfsProofRejectCode, SharedLfsHoldGrant, StoredBlobLocatorRef,
};

pub(super) fn pg_err(err: impl std::fmt::Display) -> LfsBlobError {
    LfsBlobError::new(LfsProofRejectCode::PgDatabase, err.to_string())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileUploadsReport {
    pub aborted_orphaned_attempts: u64,
    pub committed_objects_preserved: u64,
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
        let op = OperationIdentity::new(realm.repository_id, realm.owner_tenant_id, lane, seq, op_id, digest)
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
            realm.repository_id,
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
            realm.repository_id,
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

    pub async fn record_committed_blob(
        &self,
        attempt_id: Uuid,
        record: &CommittedLfsBlobRecord,
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
        tx.execute(
            "INSERT INTO lfs_blob_objects(
                tenant_id, repository_id, oid_sha256, size_bytes, locator_json, hold_id,
                acquire_request_id, consume_request_id, backend_identity_hex, uploader_actor_id, retired
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,FALSE)
             ON CONFLICT (tenant_id, repository_id, oid_sha256) DO NOTHING",
            &[
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
            ],
        )
        .await
        .map_err(pg_err)?;
        let row = tx
            .query_one(
                "SELECT tenant_id, repository_id, oid_sha256, size_bytes, locator_json, hold_id,
                        acquire_request_id, consume_request_id, backend_identity_hex, uploader_actor_id, retired
                 FROM lfs_blob_objects WHERE tenant_id=$1 AND repository_id=$2 AND oid_sha256=$3",
                &[&record.tenant_id, &record.repository_id, &record.oid_sha256],
            )
            .await
            .map_err(pg_err)?;
        let stored = Self::decode_blob_row(&row)?;
        if stored.size_bytes != record.size_bytes {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::SizeOrDigestMismatch,
                "existing committed LFS object has conflicting byte length",
            ));
        }
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

    pub async fn reconcile_in_flight_uploads(&self, repository_id: Uuid) -> Result<ReconcileUploadsReport, LfsBlobError> {
        let client = self.pool.get().await.map_err(pg_err)?;
        let aborted = client
            .execute(
                "UPDATE lfs_blob_upload_attempts
                 SET state='aborted_failed', failure_reason='reconciled after crash/restart before remote receipt', updated_at=clock_timestamp()
                 WHERE repository_id=$1 AND state='pending'",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?;
        let preserved: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM lfs_blob_objects WHERE repository_id=$1 AND retired=FALSE",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?
            .get(0);
        Ok(ReconcileUploadsReport { aborted_orphaned_attempts: aborted, committed_objects_preserved: preserved as u64 })
    }

    pub async fn grant_shared_hold(&self, grant: &SharedLfsHoldGrant) -> Result<(), LfsBlobError> {
        let client = self.pool.get().await.map_err(pg_err)?;
        client
            .execute(
                "INSERT INTO lfs_blob_shared_holds(
                    grant_id, source_tenant_id, source_repository_id, target_tenant_id,
                    target_repository_id, grantee_actor_id, oid_sha256, size_bytes, source_hold_id, active
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                &[
                    &grant.grant_id,
                    &grant.source_tenant_id,
                    &grant.source_repository_id,
                    &grant.target_tenant_id,
                    &grant.target_repository_id,
                    &grant.grantee_actor_id,
                    &grant.oid_sha256,
                    &grant.size_bytes,
                    &grant.source_hold_id,
                    &grant.active,
                ],
            )
            .await
            .map_err(pg_err)?;
        Ok(())
    }

    pub async fn set_shared_hold_active(&self, grant_id: Uuid, active: bool) -> Result<(), LfsBlobError> {
        let client = self.pool.get().await.map_err(pg_err)?;
        client
            .execute("UPDATE lfs_blob_shared_holds SET active=$2 WHERE grant_id=$1", &[&grant_id, &active])
            .await
            .map_err(pg_err)?;
        Ok(())
    }

    pub async fn find_shared_holds_for_target(
        &self,
        target_tenant_id: Uuid,
        target_repository_id: Uuid,
        oid_sha256: &str,
    ) -> Result<Vec<SharedLfsHoldGrant>, LfsBlobError> {
        let client = self.pool.get().await.map_err(pg_err)?;
        let rows = client
            .query(
                "SELECT grant_id, source_tenant_id, source_repository_id, target_tenant_id,
                        target_repository_id, grantee_actor_id, oid_sha256, size_bytes, source_hold_id, active
                 FROM lfs_blob_shared_holds
                 WHERE target_tenant_id=$1 AND target_repository_id=$2 AND oid_sha256=$3
                 ORDER BY active DESC, grant_id ASC",
                &[&target_tenant_id, &target_repository_id, &oid_sha256],
            )
            .await
            .map_err(pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| SharedLfsHoldGrant {
                grant_id: r.get(0),
                source_tenant_id: r.get(1),
                source_repository_id: r.get(2),
                target_tenant_id: r.get(3),
                target_repository_id: r.get(4),
                grantee_actor_id: r.get(5),
                oid_sha256: r.get(6),
                size_bytes: r.get(7),
                source_hold_id: r.get(8),
                active: r.get(9),
            })
            .collect())
    }
}
