//! PostgreSQL 17 S4 Blob-proof DDL & authoritative `namespaces`/`organizations`/RBAC queries (`Refs #145`).

use std::path::Path;
use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::time::Instant as TokioInstant;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::ref_store::core::{CoreGateInit, PgRefStoreCore};
use crate::ref_store::{GitObjectFormat, RefName, RequestDigest};

use super::authz::AuthorizedRepoAccess;
use super::pg_store::{PgLfsBlobStore, pg_err};
use super::types::{LfsBlobError, LfsProofRejectCode, SharedLfsHoldGrant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LfsRepoRealm {
    pub repository_id: Uuid,
    pub hold_anchor_id: Uuid,
    pub owner_tenant_id: Uuid,
    pub owner_username: String,
    pub repo_name: String,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub gate_digest: RequestDigest,
    pub bare_git_dir: String,
}

const LFS_BLOB_PROOF_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS lfs_blob_repo_realms (
    repository_id UUID PRIMARY KEY,
    hold_anchor_id UUID NOT NULL,
    owner_tenant_id UUID NOT NULL,
    owner_username TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
    history_incarnation UUID NOT NULL,
    gate_digest_hex TEXT NOT NULL CHECK (octet_length(gate_digest_hex) = 64),
    bare_git_dir TEXT NOT NULL,
    next_op_seq BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS lfs_blob_upload_attempts (
    attempt_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    oid_sha256 TEXT NOT NULL CHECK (oid_sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    operation_id UUID,
    lease_until TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + make_interval(secs => 30.0)),
    state TEXT NOT NULL CHECK (state IN ('pending', 'committed', 'aborted_failed', 'aborted_cancelled')),
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS lfs_blob_upload_operations (
    repository_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    oid_sha256 TEXT NOT NULL CHECK (oid_sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'committed', 'aborted_failed', 'aborted_cancelled')),
    locator_json JSONB,
    hold_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, operation_id)
);

CREATE TABLE IF NOT EXISTS lfs_blob_objects (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    oid_sha256 TEXT NOT NULL CHECK (oid_sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    locator_json JSONB NOT NULL,
    hold_id UUID NOT NULL,
    acquire_request_id UUID NOT NULL,
    consume_request_id UUID NOT NULL,
    backend_identity_hex TEXT NOT NULL CHECK (octet_length(backend_identity_hex) = 64),
    uploader_actor_id UUID NOT NULL,
    retired BOOLEAN NOT NULL DEFAULT FALSE,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, oid_sha256)
);

CREATE OR REPLACE FUNCTION lfs_blob_objects_guard_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'physical DELETE on lfs_blob_objects is forbidden by policy';
    END IF;
    IF NEW.size_bytes <> OLD.size_bytes OR NEW.oid_sha256 <> OLD.oid_sha256 THEN
        RAISE EXCEPTION 'immutable LFS object size or digest cannot be mutated';
    END IF;
    IF (NEW.locator_json <> OLD.locator_json OR NEW.hold_id <> OLD.hold_id)
       AND NOT OLD.retired
       AND COALESCE(current_setting('rootyard.lfs_allow_locator_repair', true), '') <> 'on' THEN
        RAISE EXCEPTION 'immutable committed LFS locator cannot be overwritten without verified-missing repair guard';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS lfs_blob_objects_immutable_trig ON lfs_blob_objects;
CREATE TRIGGER lfs_blob_objects_immutable_trig
    BEFORE UPDATE OR DELETE ON lfs_blob_objects
    FOR EACH ROW EXECUTE FUNCTION lfs_blob_objects_guard_immutable();

CREATE TABLE IF NOT EXISTS lfs_blob_shared_holds (
    grant_id UUID PRIMARY KEY,
    source_tenant_id UUID NOT NULL,
    source_repository_id UUID NOT NULL,
    target_tenant_id UUID NOT NULL,
    target_repository_id UUID NOT NULL,
    grantee_actor_id UUID,
    oid_sha256 TEXT NOT NULL CHECK (oid_sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    source_hold_id UUID NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS lfs_pointer_attestations (
    repository_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    attestation_id UUID NOT NULL UNIQUE,
    tenant_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
    ref_updates_digest TEXT NOT NULL CHECK (octet_length(ref_updates_digest) = 64),
    proof_digest TEXT NOT NULL CHECK (octet_length(proof_digest) = 64),
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, operation_id)
);
"#;

pub async fn init_lfs_blob_proof_tables(pool: &Pool) -> Result<(), LfsBlobError> {
    let client = pool.get().await.map_err(pg_err)?;
    let exists: bool = client
        .query_one("SELECT to_regclass('lfs_blob_repo_realms') IS NOT NULL", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    if !exists {
        client.batch_execute(LFS_BLOB_PROOF_DDL).await.map_err(pg_err)?;
    } else {
        client
            .batch_execute(
                "ALTER TABLE lfs_blob_upload_attempts ADD COLUMN IF NOT EXISTS operation_id UUID;
                 ALTER TABLE lfs_blob_upload_attempts ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + make_interval(secs => 30.0));",
            )
            .await
            .map_err(pg_err)?;
    }
    Ok(())
}

impl PgLfsBlobStore {
    fn decode_realm(row: &Row) -> Result<LfsRepoRealm, LfsBlobError> {
        let fmt_raw: String = row.get(5);
        let object_format = match fmt_raw.as_str() {
            "sha1" => GitObjectFormat::Sha1,
            "sha256" => GitObjectFormat::Sha256,
            other => return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, format!("bad format {other}"))),
        };
        let gate_hex: String = row.get(7);
        let bytes = hex::decode(&gate_hex)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "bad gate_digest_hex"))?;
        Ok(LfsRepoRealm {
            repository_id: row.get(0),
            hold_anchor_id: row.get(1),
            owner_tenant_id: row.get(2),
            owner_username: row.get(3),
            repo_name: row.get(4),
            object_format,
            history_incarnation: row.get(6),
            gate_digest: RequestDigest::from_bytes(bytes),
            bare_git_dir: row.get(8),
        })
    }

    /// Binds an authoritative Rootyard `repositories JOIN namespaces` row to a `PgRefStoreCore`
    /// hold-anchor gate, and automatically re-syncs the realm whenever ownership transfer or rename
    /// updates `repositories.owner_id` / `namespaces.slug` / `repositories.name`.
    pub async fn ensure_realm_for_repository(
        &self,
        repository_id: Uuid,
        data_root: &Path,
    ) -> Result<LfsRepoRealm, LfsBlobError> {
        init_lfs_blob_proof_tables(self.pool()).await?;
        let mut client = self.pool().get().await.map_err(pg_err)?;
        let repo_row = client
            .query_opt(
                "SELECT r.owner_id, ns.slug, r.name, r.object_format
                 FROM repositories r
                 JOIN namespaces ns ON ns.id = r.owner_id
                 WHERE r.id = $1 AND r.deleted_at IS NULL",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "repository not found"))?;
        let owner_tenant_id: Uuid = repo_row.get(0);
        let owner_slug: String = repo_row.get(1);
        let repo_name: String = repo_row.get(2);
        let fmt_str: String = repo_row.get(3);
        let object_format = match fmt_str.as_str() {
            "sha1" => GitObjectFormat::Sha1,
            "sha256" => GitObjectFormat::Sha256,
            other => return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, format!("bad format {other}"))),
        };
        let bare_path = data_root.join("repos").join(format!("{repository_id}.git"));
        let bare_git_dir = bare_path
            .to_str()
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "non-UTF8 repo path"))?
            .to_owned();

        if let Some(existing) = client
            .query_opt(
                "SELECT repository_id, hold_anchor_id, owner_tenant_id, owner_username, repo_name, object_format,
                        history_incarnation, gate_digest_hex, bare_git_dir
                 FROM lfs_blob_repo_realms WHERE repository_id=$1",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?
        {
            let mut decoded = Self::decode_realm(&existing)?;
            if decoded.owner_tenant_id == owner_tenant_id {
                if decoded.owner_username != owner_slug || decoded.repo_name != repo_name {
                    client
                        .execute(
                            "UPDATE lfs_blob_repo_realms SET owner_username=$2, repo_name=$3 WHERE repository_id=$1",
                            &[&repository_id, &owner_slug, &repo_name],
                        )
                        .await
                        .map_err(pg_err)?;
                    decoded.owner_username = owner_slug;
                    decoded.repo_name = repo_name;
                }
                decoded.bare_git_dir = bare_git_dir;
                return Ok(decoded);
            }
        }

        let hold_anchor_id = Uuid::new_v4();
        let anchor_name = format!("s4_hold_{}", hold_anchor_id.simple());
        client
            .execute(
                "INSERT INTO repositories(
                    id, owner_id, name, object_format, state, storage_backend, transition_state, deleted_at, purge_after
                 ) VALUES(
                    $1, $2, $3, $4, 'provisioning', 'gitfs', 'stable',
                    clock_timestamp(), clock_timestamp() + make_interval(years => 100)
                 )",
                &[&hold_anchor_id, &owner_tenant_id, &anchor_name, &fmt_str],
            )
            .await
            .map_err(pg_err)?;

        let history = Uuid::new_v4();
        let main_ref = RefName::branch("refs/heads/main")
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let init = CoreGateInit::new(hold_anchor_id, owner_tenant_id, object_format, history, 1, 1, main_ref)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let pg_dl = TokioInstant::now() + Duration::from_secs(20);
        let gate_hex = PgRefStoreCore.initialize(&mut client, &init, pg_dl).await.map_err(pg_err)?.digest().as_hex();
        client
            .execute(
                "INSERT INTO lfs_blob_repo_realms(
                    repository_id, hold_anchor_id, owner_tenant_id, owner_username, repo_name, object_format,
                    history_incarnation, gate_digest_hex, bare_git_dir
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
                 ON CONFLICT (repository_id) DO UPDATE SET
                    hold_anchor_id = EXCLUDED.hold_anchor_id,
                    owner_tenant_id = EXCLUDED.owner_tenant_id,
                    owner_username = EXCLUDED.owner_username,
                    repo_name = EXCLUDED.repo_name,
                    object_format = EXCLUDED.object_format,
                    history_incarnation = EXCLUDED.history_incarnation,
                    gate_digest_hex = EXCLUDED.gate_digest_hex,
                    bare_git_dir = EXCLUDED.bare_git_dir",
                &[
                    &repository_id,
                    &hold_anchor_id,
                    &owner_tenant_id,
                    &owner_slug,
                    &repo_name,
                    &fmt_str,
                    &history,
                    &gate_hex,
                    &bare_git_dir,
                ],
            )
            .await
            .map_err(pg_err)?;
        let saved = client
            .query_one(
                "SELECT repository_id, hold_anchor_id, owner_tenant_id, owner_username, repo_name, object_format,
                        history_incarnation, gate_digest_hex, bare_git_dir
                 FROM lfs_blob_repo_realms WHERE repository_id=$1",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?;
        drop(client);
        Self::decode_realm(&saved)
    }

    /// Resolves authoritative subject-to-tenant/organization/collaborator ownership from PostgreSQL
    /// (`repositories`, `namespaces`, `users`, `organizations`, `organization_memberships`,
    /// `organization_teams`, `repository_collaborators`, `repository_teams` under `FOR SHARE`).
    /// Never compares raw caller and tenant UUIDs directly.
    pub async fn resolve_authoritative_repo_access(
        &self,
        realm: &LfsRepoRealm,
        actor_id: Uuid,
        actor_username: &str,
        require_write: bool,
        require_admin: bool,
    ) -> Result<AuthorizedRepoAccess, LfsBlobError> {
        let mut client = self.pool().get().await.map_err(pg_err)?;
        let tx = client.transaction().await.map_err(pg_err)?;
        let access = super::prod_auth_tx::resolve_authoritative_repo_access_in_tx(
            &tx,
            realm.repository_id,
            Some(realm.owner_tenant_id),
            actor_id,
            actor_username,
            require_write,
            require_admin,
        )
        .await?;
        tx.commit().await.map_err(pg_err)?;
        Ok(access)
    }

    pub async fn grant_shared_hold(&self, g: &SharedLfsHoldGrant) -> Result<(), LfsBlobError> {
        let mut client = self.pool().get().await.map_err(pg_err)?;
        let tx = client.transaction().await.map_err(pg_err)?;
        tx.batch_execute("SET LOCAL synchronous_commit = 'on'").await.map_err(pg_err)?;
        tx.execute(
            "INSERT INTO lfs_blob_shared_holds(
                grant_id, source_tenant_id, source_repository_id, target_tenant_id, target_repository_id,
                grantee_actor_id, oid_sha256, size_bytes, source_hold_id, active
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[
                &g.grant_id, &g.source_tenant_id, &g.source_repository_id, &g.target_tenant_id, &g.target_repository_id,
                &g.grantee_actor_id, &g.oid_sha256, &g.size_bytes, &g.source_hold_id, &g.active,
            ],
        )
        .await
        .map_err(pg_err)?;
        tx.commit().await.map_err(pg_err)?;
        Ok(())
    }

    pub async fn set_shared_hold_active(&self, grant_id: Uuid, active: bool) -> Result<(), LfsBlobError> {
        let client = self.pool().get().await.map_err(pg_err)?;
        client
            .execute(
                "UPDATE lfs_blob_shared_holds
                 SET active=$2, revoked_at = CASE WHEN $2 THEN NULL ELSE clock_timestamp() END
                 WHERE grant_id=$1",
                &[&grant_id, &active],
            )
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
        let client = self.pool().get().await.map_err(pg_err)?;
        let rows = client
            .query(
                "SELECT grant_id, source_tenant_id, source_repository_id, target_tenant_id, target_repository_id,
                        grantee_actor_id, oid_sha256, size_bytes, source_hold_id, active
                 FROM lfs_blob_shared_holds
                 WHERE target_tenant_id=$1 AND target_repository_id=$2 AND oid_sha256=$3
                 ORDER BY active DESC, created_at DESC",
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
