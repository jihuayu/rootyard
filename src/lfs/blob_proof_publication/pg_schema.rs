//! PostgreSQL 17 DDL schema initializer and repository/principal realm store (`Refs #145`).

use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::time::Instant as TokioInstant;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::ref_store::{CoreGateInit, GitObjectFormat, PgRefStoreCore, RefName, RequestDigest};

use super::authz::{AuthorizedRepoAccess, LfsPrincipal, evaluate_repo_role_access};
use super::pg_store::{PgLfsBlobStore, pg_err};
use super::types::{LfsBlobError, LfsCollaboratorRole, LfsProofRejectCode};

#[derive(Clone, Debug)]
pub struct LfsRepoRealm {
    pub repository_id: Uuid,
    pub owner_tenant_id: Uuid,
    pub owner_username: String,
    pub repo_name: String,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub gate_digest: RequestDigest,
    pub bare_git_dir: String,
}

/// Initializes ephemeral/isolated LFS Blob proof tables & immutability triggers without altering `migrations/`.
pub async fn init_lfs_blob_proof_tables(pool: &Pool) -> Result<(), LfsBlobError> {
    let client = pool.get().await.map_err(pg_err)?;
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS lfs_blob_principals (
                actor_id UUID PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                secret_sha256 TEXT NOT NULL CHECK (secret_sha256 ~ '^[0-9a-f]{64}$')
            );
            CREATE TABLE IF NOT EXISTS lfs_blob_repo_realms (
                repository_id UUID PRIMARY KEY,
                owner_tenant_id UUID NOT NULL,
                owner_username TEXT NOT NULL,
                repo_name TEXT NOT NULL,
                object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
                history_incarnation UUID NOT NULL,
                gate_digest_hex TEXT NOT NULL CHECK (gate_digest_hex ~ '^[0-9a-f]{64}$'),
                bare_git_dir TEXT NOT NULL,
                next_op_seq BIGINT NOT NULL DEFAULT 0,
                UNIQUE (owner_username, repo_name)
            );
            CREATE TABLE IF NOT EXISTS lfs_blob_collaborators (
                repository_id UUID NOT NULL REFERENCES lfs_blob_repo_realms(repository_id) ON DELETE CASCADE,
                actor_id UUID NOT NULL REFERENCES lfs_blob_principals(actor_id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')),
                PRIMARY KEY (repository_id, actor_id)
            );
            CREATE TABLE IF NOT EXISTS lfs_blob_upload_attempts (
                attempt_id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                repository_id UUID NOT NULL,
                actor_id UUID NOT NULL,
                oid_sha256 TEXT NOT NULL CHECK (oid_sha256 ~ '^[0-9a-f]{64}$'),
                size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
                state TEXT NOT NULL CHECK (state IN ('pending', 'committed', 'aborted_failed')),
                failure_reason TEXT,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
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
                backend_identity_hex TEXT NOT NULL CHECK (backend_identity_hex ~ '^[0-9a-f]{64}$'),
                uploader_actor_id UUID NOT NULL,
                retired BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                PRIMARY KEY (tenant_id, repository_id, oid_sha256)
            );
            CREATE OR REPLACE FUNCTION lfs_blob_objects_immutable_guard() RETURNS trigger AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'committed lfs_blob_objects rows cannot be physically deleted';
                END IF;
                IF NEW.oid_sha256 IS DISTINCT FROM OLD.oid_sha256
                    OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
                    OR NEW.locator_json IS DISTINCT FROM OLD.locator_json
                    OR NEW.hold_id IS DISTINCT FROM OLD.hold_id
                    OR NEW.backend_identity_hex IS DISTINCT FROM OLD.backend_identity_hex
                    OR (OLD.retired = TRUE AND NEW.retired = FALSE)
                THEN
                    RAISE EXCEPTION 'committed lfs_blob_objects locator and digest are immutable';
                END IF;
                RETURN NEW;
            END $$ LANGUAGE plpgsql;
            DROP TRIGGER IF EXISTS lfs_blob_objects_immutable_trig ON lfs_blob_objects;
            CREATE TRIGGER lfs_blob_objects_immutable_trig
                BEFORE UPDATE OR DELETE ON lfs_blob_objects
                FOR EACH ROW EXECUTE FUNCTION lfs_blob_objects_immutable_guard();
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
                active BOOLEAN NOT NULL DEFAULT TRUE
            );
            CREATE TABLE IF NOT EXISTS lfs_blob_locks (
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                repository_id UUID NOT NULL,
                path TEXT NOT NULL,
                owner_actor_id UUID NOT NULL,
                owner_username TEXT NOT NULL,
                locked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                UNIQUE (repository_id, path)
            );
            CREATE TABLE IF NOT EXISTS lfs_pointer_attestations (
                repository_id UUID NOT NULL,
                operation_id UUID NOT NULL,
                attestation_id UUID NOT NULL,
                tenant_id UUID NOT NULL,
                actor_id UUID NOT NULL,
                object_format TEXT NOT NULL,
                ref_updates_digest TEXT NOT NULL CHECK (ref_updates_digest ~ '^[0-9a-f]{64}$'),
                proof_digest TEXT NOT NULL CHECK (proof_digest ~ '^[0-9a-f]{64}$'),
                payload_json JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                PRIMARY KEY (repository_id, operation_id)
            );",
        )
        .await
        .map_err(pg_err)?;
    Ok(())
}

impl PgLfsBlobStore {
    pub async fn register_principal(
        &self,
        actor_id: Uuid,
        username: &str,
        secret: &str,
    ) -> Result<LfsPrincipal, LfsBlobError> {
        let secret_sha256 = LfsPrincipal::hash_secret(secret);
        let client = self.pool().get().await.map_err(pg_err)?;
        client
            .execute("INSERT INTO users(id, username) VALUES($1, $2) ON CONFLICT (id) DO NOTHING", &[&actor_id, &username])
            .await
            .map_err(pg_err)?;
        client
            .execute(
                "INSERT INTO lfs_blob_principals(actor_id, username, secret_sha256) VALUES($1, $2, $3)
                 ON CONFLICT (actor_id) DO UPDATE SET secret_sha256 = EXCLUDED.secret_sha256",
                &[&actor_id, &username, &secret_sha256],
            )
            .await
            .map_err(pg_err)?;
        Ok(LfsPrincipal { actor_id, username: username.to_owned(), secret_sha256 })
    }

    pub async fn authenticate_principal(&self, username: &str, secret: &str) -> Result<LfsPrincipal, LfsBlobError> {
        let expected = LfsPrincipal::hash_secret(secret);
        let client = self.pool().get().await.map_err(pg_err)?;
        let row = client
            .query_opt("SELECT actor_id, username, secret_sha256 FROM lfs_blob_principals WHERE username=$1", &[&username])
            .await
            .map_err(pg_err)?
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "unknown principal"))?;
        let stored: String = row.get(2);
        if stored != expected {
            return Err(LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "invalid principal token"));
        }
        Ok(LfsPrincipal { actor_id: row.get(0), username: row.get(1), secret_sha256: stored })
    }

    pub async fn provision_repository(
        &self,
        repository_id: Uuid,
        owner_tenant_id: Uuid,
        owner_username: &str,
        repo_name: &str,
        object_format: GitObjectFormat,
        bare_git_dir: &str,
    ) -> Result<LfsRepoRealm, LfsBlobError> {
        let history = Uuid::new_v4();
        let fmt_str = match object_format {
            GitObjectFormat::Sha1 => "sha1",
            GitObjectFormat::Sha256 => "sha256",
        };
        let pg_dl = TokioInstant::now() + Duration::from_secs(20);
        let mut client = self.pool().get().await.map_err(pg_err)?;
        client
            .execute(
                "INSERT INTO repositories(id, owner_id, name, state, object_format)
                 VALUES($1, $2, $3, 'provisioning', $4) ON CONFLICT (id) DO NOTHING",
                &[&repository_id, &owner_tenant_id, &repo_name, &fmt_str],
            )
            .await
            .map_err(pg_err)?;
        let main_ref = RefName::branch("refs/heads/main")
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let init = CoreGateInit::new(repository_id, owner_tenant_id, object_format, history, 1, 1, main_ref)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let gate = *PgRefStoreCore.initialize(&mut client, &init, pg_dl).await.map_err(pg_err)?.digest();
        let gate_hex = gate.as_hex();
        client
            .execute(
                "INSERT INTO lfs_blob_repo_realms(
                    repository_id, owner_tenant_id, owner_username, repo_name, object_format,
                    history_incarnation, gate_digest_hex, bare_git_dir
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
                &[
                    &repository_id,
                    &owner_tenant_id,
                    &owner_username,
                    &repo_name,
                    &fmt_str,
                    &history,
                    &gate_hex,
                    &bare_git_dir,
                ],
            )
            .await
            .map_err(pg_err)?;
        Ok(LfsRepoRealm {
            repository_id,
            owner_tenant_id,
            owner_username: owner_username.to_owned(),
            repo_name: repo_name.to_owned(),
            object_format,
            history_incarnation: history,
            gate_digest: gate,
            bare_git_dir: bare_git_dir.to_owned(),
        })
    }

    fn decode_realm(row: &Row) -> Result<LfsRepoRealm, LfsBlobError> {
        let fmt_raw: String = row.get(4);
        let object_format = match fmt_raw.as_str() {
            "sha1" => GitObjectFormat::Sha1,
            "sha256" => GitObjectFormat::Sha256,
            other => return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, format!("bad format {other}"))),
        };
        let gate_hex: String = row.get(6);
        let bytes = hex::decode(&gate_hex)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "bad gate_digest_hex"))?;
        Ok(LfsRepoRealm {
            repository_id: row.get(0),
            owner_tenant_id: row.get(1),
            owner_username: row.get(2),
            repo_name: row.get(3),
            object_format,
            history_incarnation: row.get(5),
            gate_digest: RequestDigest::from_bytes(bytes),
            bare_git_dir: row.get(7),
        })
    }

    pub async fn lookup_repo_by_slug(&self, owner: &str, repo: &str) -> Result<LfsRepoRealm, LfsBlobError> {
        let clean = repo.strip_suffix(".git").unwrap_or(repo);
        let client = self.pool().get().await.map_err(pg_err)?;
        let row = client
            .query_opt(
                "SELECT repository_id, owner_tenant_id, owner_username, repo_name, object_format,
                        history_incarnation, gate_digest_hex, bare_git_dir
                 FROM lfs_blob_repo_realms WHERE owner_username=$1 AND repo_name=$2",
                &[&owner, &clean],
            )
            .await
            .map_err(pg_err)?
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "repository not found"))?;
        Self::decode_realm(&row)
    }

    pub async fn load_repo_by_id(&self, repository_id: Uuid) -> Result<LfsRepoRealm, LfsBlobError> {
        let client = self.pool().get().await.map_err(pg_err)?;
        let row = client
            .query_opt(
                "SELECT repository_id, owner_tenant_id, owner_username, repo_name, object_format,
                        history_incarnation, gate_digest_hex, bare_git_dir
                 FROM lfs_blob_repo_realms WHERE repository_id=$1",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "repository not found"))?;
        Self::decode_realm(&row)
    }

    pub async fn grant_collaborator(
        &self,
        repository_id: Uuid,
        actor_id: Uuid,
        role: LfsCollaboratorRole,
    ) -> Result<(), LfsBlobError> {
        let client = self.pool().get().await.map_err(pg_err)?;
        client
            .execute(
                "INSERT INTO lfs_blob_collaborators(repository_id, actor_id, role) VALUES($1,$2,$3)
                 ON CONFLICT (repository_id, actor_id) DO UPDATE SET role = EXCLUDED.role",
                &[&repository_id, &actor_id, &role.as_str()],
            )
            .await
            .map_err(pg_err)?;
        Ok(())
    }

    pub async fn authorize_repo_access(
        &self,
        realm: &LfsRepoRealm,
        principal: &LfsPrincipal,
        require_write: bool,
        require_admin: bool,
    ) -> Result<AuthorizedRepoAccess, LfsBlobError> {
        let client = self.pool().get().await.map_err(pg_err)?;
        let collab_row = client
            .query_opt(
                "SELECT role FROM lfs_blob_collaborators WHERE repository_id=$1 AND actor_id=$2",
                &[&realm.repository_id, &principal.actor_id],
            )
            .await
            .map_err(pg_err)?;
        let role = match collab_row {
            Some(r) => Some(LfsCollaboratorRole::parse(&r.get::<_, String>(0))?),
            None => None,
        };
        evaluate_repo_role_access(
            realm.repository_id,
            realm.owner_tenant_id,
            principal.actor_id,
            &principal.username,
            role,
            require_write,
            require_admin,
        )
    }
}
