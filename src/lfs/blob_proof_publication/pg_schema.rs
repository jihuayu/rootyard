//! PostgreSQL 17 S4 Blob-proof DDL & authoritative `namespaces`/`organizations`/RBAC queries (`Refs #145`).

use std::path::Path;
use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::time::Instant as TokioInstant;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::ref_store::core::{CoreGateInit, PgRefStoreCore};
use crate::ref_store::{GitObjectFormat, RefName, RequestDigest};

use super::authz::{AuthorizedRepoAccess, SubjectTenantAuthority, evaluate_subject_tenant_access};
use super::pg_store::{PgLfsBlobStore, pg_err};
use super::types::{LfsBlobError, LfsCollaboratorRole, LfsProofRejectCode};

#[derive(Clone, Debug, Eq, PartialEq)]
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

const LFS_BLOB_PROOF_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS lfs_blob_repo_realms (
    repository_id UUID PRIMARY KEY,
    owner_tenant_id UUID NOT NULL,
    owner_username TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
    history_incarnation UUID NOT NULL,
    gate_digest_hex TEXT NOT NULL CHECK (octet_length(gate_digest_hex) = 64),
    bare_git_dir TEXT NOT NULL,
    next_op_seq BIGINT NOT NULL DEFAULT 0,
    UNIQUE (owner_username, repo_name)
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
    state TEXT NOT NULL CHECK (state IN ('pending', 'committed', 'aborted_failed')),
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
    client.batch_execute(LFS_BLOB_PROOF_DDL).await.map_err(pg_err)?;
    Ok(())
}

impl PgLfsBlobStore {
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

    /// Idempotently binds an authoritative Rootyard `repositories` + `namespaces` row to a `PgRefStoreCore`
    /// gate so `PgArtifactHoldStore` and `ProtectedUploader` work seamlessly on production repositories.
    pub async fn ensure_realm_for_repository(
        &self,
        repository_id: Uuid,
        data_root: &Path,
    ) -> Result<LfsRepoRealm, LfsBlobError> {
        init_lfs_blob_proof_tables(self.pool()).await?;
        let mut client = self.pool().get().await.map_err(pg_err)?;
        if let Some(existing) = client
            .query_opt(
                "SELECT repository_id, owner_tenant_id, owner_username, repo_name, object_format,
                        history_incarnation, gate_digest_hex, bare_git_dir
                 FROM lfs_blob_repo_realms WHERE repository_id=$1",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?
        {
            return Self::decode_realm(&existing);
        }

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
        let bare_path = data_root.join("repos").join(repository_id.to_string());
        let bare_git_dir = bare_path
            .to_str()
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "non-UTF8 repo path"))?
            .to_owned();

        let history = Uuid::new_v4();
        let main_ref = RefName::branch("refs/heads/main")
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let init = CoreGateInit::new(repository_id, owner_tenant_id, object_format, history, 1, 1, main_ref)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let pg_dl = TokioInstant::now() + Duration::from_secs(20);
        let gate_hex = match PgRefStoreCore.initialize(&mut client, &init, pg_dl).await {
            Ok(g) => g.digest().as_hex(),
            Err(_) => {
                let row = client
                    .query_one(
                        "SELECT repository_id, owner_tenant_id, owner_username, repo_name, object_format,
                                history_incarnation, gate_digest_hex, bare_git_dir
                         FROM lfs_blob_repo_realms WHERE repository_id=$1",
                        &[&repository_id],
                    )
                    .await
                    .map_err(pg_err)?;
                return Self::decode_realm(&row);
            }
        };
        client
            .execute(
                "INSERT INTO lfs_blob_repo_realms(
                    repository_id, owner_tenant_id, owner_username, repo_name, object_format,
                    history_incarnation, gate_digest_hex, bare_git_dir
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (repository_id) DO UPDATE SET bare_git_dir = EXCLUDED.bare_git_dir",
                &[
                    &repository_id,
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
                "SELECT repository_id, owner_tenant_id, owner_username, repo_name, object_format,
                        history_incarnation, gate_digest_hex, bare_git_dir
                 FROM lfs_blob_repo_realms WHERE repository_id=$1",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?;
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
        let ns_row = tx
            .query_opt(
                "SELECT r.owner_id, ns.slug, ns.kind, ns.user_id, ns.organization_id,
                        r.state, r.transition_state, r.archived_at IS NOT NULL, r.deleted_at IS NOT NULL
                 FROM repositories r
                 JOIN namespaces ns ON ns.id = r.owner_id
                 WHERE r.id = $1
                 FOR SHARE OF r, ns",
                &[&realm.repository_id],
            )
            .await
            .map_err(pg_err)?
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "repository missing"))?;

        let owner_ns_id: Uuid = ns_row.get(0);
        let ns_slug: String = ns_row.get(1);
        let ns_kind: String = ns_row.get(2);
        let ns_user_id: Option<Uuid> = ns_row.get(3);
        let ns_org_id: Option<Uuid> = ns_row.get(4);
        let state: String = ns_row.get(5);
        let transition: String = ns_row.get(6);
        let archived: bool = ns_row.get(7);
        let deleted: bool = ns_row.get(8);
        if deleted
            || state != "ready"
            || (require_write
                && (archived
                    || transition != "stable"
                    || crate::auth::lifecycle::has_active_transfer(&*tx, realm.repository_id)
                        .await
                        .map_err(pg_err)?))
        {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::UnauthorizedCollaborator,
                "repository is deleted, archived, transferring, or not ready for LFS mutation",
            ));
        }

        // 1. Personal namespace owner verified via relational `namespaces JOIN users` (`FOR SHARE`).
        if ns_kind == "user"
            && let Some(bound_uid) = ns_user_id
        {
            let verified_owner = tx
                .query_opt(
                    "SELECT n.id FROM namespaces n JOIN users u ON u.id = n.user_id
                     WHERE n.id = $1 AND n.kind = 'user' AND u.id = $2
                     FOR SHARE OF n, u",
                    &[&owner_ns_id, &actor_id],
                )
                .await
                .map_err(pg_err)?;
            if verified_owner.is_some() && bound_uid == actor_id {
                tx.commit().await.map_err(pg_err)?;
                return evaluate_subject_tenant_access(
                    realm.repository_id,
                    owner_ns_id,
                    actor_id,
                    actor_username,
                    SubjectTenantAuthority::PersonalNamespaceOwner {
                        namespace_id: owner_ns_id,
                        namespace_slug: ns_slug,
                    },
                    require_write,
                    require_admin,
                );
            }
        }

        // 2. Organization memberships + organization teams (`FOR SHARE`), plus direct/team repo collaborators.
        let mut best_org_role: Option<(Uuid, LfsCollaboratorRole)> = None;
        if ns_kind == "organization"
            && let Some(org_id) = ns_org_id
        {
            for r in tx
                .query(
                    "SELECT role FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 FOR SHARE",
                    &[&org_id, &actor_id],
                )
                .await
                .map_err(pg_err)?
            {
                let parsed = LfsCollaboratorRole::parse(r.get::<_, &str>(0))?;
                best_org_role = Some(best_org_role.map_or((org_id, parsed), |(id, cur)| (id, cur.max(parsed))));
            }
            for r in tx
                .query(
                    "SELECT t.role FROM organization_teams t
                     JOIN organization_team_members tm ON tm.team_id = t.id
                     WHERE t.organization_id = $1 AND tm.user_id = $2
                     FOR SHARE OF t, tm",
                    &[&org_id, &actor_id],
                )
                .await
                .map_err(pg_err)?
            {
                let parsed = LfsCollaboratorRole::parse(r.get::<_, &str>(0))?;
                best_org_role = Some(best_org_role.map_or((org_id, parsed), |(id, cur)| (id, cur.max(parsed))));
            }
        }

        let mut best_repo_role: Option<LfsCollaboratorRole> = None;
        for r in tx
            .query(
                "SELECT role FROM repository_collaborators WHERE repository_id=$1 AND user_id=$2 FOR SHARE",
                &[&realm.repository_id, &actor_id],
            )
            .await
            .map_err(pg_err)?
        {
            let parsed = LfsCollaboratorRole::parse(r.get::<_, &str>(0))?;
            best_repo_role = Some(best_repo_role.map_or(parsed, |cur| cur.max(parsed)));
        }
        for r in tx
            .query(
                "SELECT t.role FROM repository_teams t
                 JOIN repository_team_members tm ON tm.team_id = t.id
                 WHERE t.repository_id = $1 AND tm.user_id = $2
                 FOR SHARE OF t, tm",
                &[&realm.repository_id, &actor_id],
            )
            .await
            .map_err(pg_err)?
        {
            let parsed = LfsCollaboratorRole::parse(r.get::<_, &str>(0))?;
            best_repo_role = Some(best_repo_role.map_or(parsed, |cur| cur.max(parsed)));
        }
        tx.commit().await.map_err(pg_err)?;

        let authority = match (best_org_role, best_repo_role) {
            (Some((org_id, org_r)), Some(repo_r)) if repo_r > org_r => {
                SubjectTenantAuthority::RepositoryCollaborator { namespace_slug: ns_slug, role: repo_r }
            }
            (Some((org_id, org_r)), _) => SubjectTenantAuthority::OrganizationMember {
                organization_id: org_id,
                namespace_slug: ns_slug,
                role: org_r,
            },
            (None, Some(repo_r)) => {
                SubjectTenantAuthority::RepositoryCollaborator { namespace_slug: ns_slug, role: repo_r }
            }
            (None, None) => SubjectTenantAuthority::Unrelated,
        };
        evaluate_subject_tenant_access(
            realm.repository_id,
            owner_ns_id,
            actor_id,
            actor_username,
            authority,
            require_write,
            require_admin,
        )
    }
}
