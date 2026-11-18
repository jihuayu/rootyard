//! Single-transaction post-auth authorization checks for durable LFS publication (`Refs #145`).

use deadpool_postgres::Transaction;
use uuid::Uuid;

use crate::token_scopes::RepoAction;

use super::authz::{AuthorizedRepoAccess, SubjectTenantAuthority, evaluate_subject_tenant_access};
use super::pg_store::{PgLfsBlobStore, pg_err};
use super::types::{LfsBlobError, LfsCollaboratorRole, LfsProofRejectCode};

#[derive(Clone)]
pub struct ProdCommitAuthCheck {
    pub actor: crate::db::Identity,
    pub owner_slug: String,
    pub repo_name: String,
    pub expected_generation: Option<i64>,
}

#[derive(Clone, Copy, Debug)]
pub struct PushCommitAuthCheck {
    pub actor_id: Uuid,
    pub token_id: Option<Uuid>,
    pub expected_generation: Option<i64>,
}

/// Stable PostgreSQL session-advisory-lock key pair for one upload attempt.
pub fn upload_attempt_advisory_keys(attempt_id: Uuid) -> (i32, i32) {
    let hi64 = ((attempt_id.as_u128() >> 64) as u64) ^ 0x5334_4c46_535f_5550u64;
    ((hi64 >> 32) as i32, (hi64 & 0xffff_ffff) as i32)
}

pub(super) fn map_app_auth_err(err: crate::Error) -> LfsBlobError {
    match err.0 {
        axum::http::StatusCode::UNAUTHORIZED => LfsBlobError::new(LfsProofRejectCode::Unauthenticated, err.1),
        axum::http::StatusCode::FORBIDDEN | axum::http::StatusCode::NOT_FOUND => {
            LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, err.1)
        }
        axum::http::StatusCode::CONFLICT => LfsBlobError::new(LfsProofRejectCode::AttestationEquivocation, err.1),
        _ => LfsBlobError::new(LfsProofRejectCode::PgDatabase, err.1),
    }
}

/// Resolves authoritative relational RBAC inside the caller's transaction, without committing it.
pub(super) async fn resolve_authoritative_repo_access_in_tx(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    expected_tenant_id: Option<Uuid>,
    actor_id: Uuid,
    actor_username: &str,
    require_write: bool,
    require_admin: bool,
) -> Result<AuthorizedRepoAccess, LfsBlobError> {
    let ns_row = tx
        .query_opt(
            "SELECT r.owner_id, ns.slug, ns.kind, ns.user_id, ns.organization_id,
                    r.state, r.transition_state, r.archived_at IS NOT NULL, r.deleted_at IS NOT NULL
             FROM repositories r
             JOIN namespaces ns ON ns.id = r.owner_id
             WHERE r.id = $1
             FOR SHARE OF r, ns",
            &[&repository_id],
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
    if let Some(exp_tenant) = expected_tenant_id
        && owner_ns_id != exp_tenant
    {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::AttestationEquivocation,
            "repository ownership tenant changed",
        ));
    }
    if deleted
        || state != "ready"
        || (require_write
            && (archived
                || transition != "stable"
                || crate::auth::lifecycle::has_active_transfer(&**tx, repository_id).await.map_err(pg_err)?))
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
            return evaluate_subject_tenant_access(
                repository_id,
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
            &[&repository_id, &actor_id],
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
            &[&repository_id, &actor_id],
        )
        .await
        .map_err(pg_err)?
    {
        let parsed = LfsCollaboratorRole::parse(r.get::<_, &str>(0))?;
        best_repo_role = Some(best_repo_role.map_or(parsed, |cur| cur.max(parsed)));
    }

    let authority = match (best_org_role, best_repo_role) {
        (Some((_org_id, org_r)), Some(repo_r)) if repo_r > org_r => {
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
        repository_id,
        owner_ns_id,
        actor_id,
        actor_username,
        authority,
        require_write,
        require_admin,
    )
}

/// Verifies live token liveness, repository identity/generation, and relational write RBAC inside `tx`.
pub(super) async fn verify_commit_write_authority_in_tx(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    expected_tenant_id: Uuid,
    uploader_actor_id: Uuid,
    commit_auth: Option<&ProdCommitAuthCheck>,
) -> Result<(), LfsBlobError> {
    if let Some(ca) = commit_auth {
        if let Some(exp_gen) = ca.expected_generation {
            crate::auth::authorize_publication_window(tx, &ca.actor, repository_id, exp_gen)
                .await
                .map_err(map_app_auth_err)?;
        }
        let reauth = crate::auth::authorize_repo_with_role(
            tx,
            &ca.actor,
            &ca.owner_slug,
            &ca.repo_name,
            crate::auth::Role::Write,
            RepoAction::ContentsWrite,
        )
        .await
        .map_err(map_app_auth_err)?;
        if reauth.repo_id != repository_id || reauth.owner_id != expected_tenant_id {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "repository identity changed during upload",
            ));
        }
        crate::auth::verify_token(tx, &ca.actor, true).await.map_err(map_app_auth_err)?;
    }
    let user_row = tx
        .query_opt("SELECT username FROM users WHERE id = $1 FOR SHARE", &[&uploader_actor_id])
        .await
        .map_err(pg_err)?
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "uploader actor missing"))?;
    let _ = resolve_authoritative_repo_access_in_tx(
        tx,
        repository_id,
        Some(expected_tenant_id),
        uploader_actor_id,
        user_row.get(0),
        true,
        false,
    )
    .await?;
    Ok(())
}

/// Verifies live push attestation authority, generation, and token write scope inside `tx`.
pub(super) async fn verify_push_attestation_authority_in_tx(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    expected_tenant_id: Uuid,
    actor_id: Uuid,
    push_auth: Option<PushCommitAuthCheck>,
) -> Result<(), LfsBlobError> {
    let username: String = tx
        .query_opt("SELECT username FROM users WHERE id = $1 FOR SHARE", &[&actor_id])
        .await
        .map_err(pg_err)?
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "attestation actor missing"))?
        .get(0);
    resolve_authoritative_repo_access_in_tx(
        tx,
        repository_id,
        Some(expected_tenant_id),
        actor_id,
        &username,
        true,
        false,
    )
    .await?;
    if let Some(pa) = push_auth {
        if let Some(exp_gen) = pa.expected_generation {
            let cur_gen: i64 = tx
                .query_one("SELECT storage_generation FROM repositories WHERE id = $1 FOR SHARE", &[&repository_id])
                .await
                .map_err(pg_err)?
                .get(0);
            if cur_gen != exp_gen {
                return Err(LfsBlobError::new(
                    LfsProofRejectCode::AttestationEquivocation,
                    "repository generation changed before push attestation",
                ));
            }
        }
        if let Some(tok_id) = pa.token_id {
            crate::auth::verify_repo_write_access(
                &**tx,
                pa.actor_id,
                tok_id,
                repository_id,
                false,
                RepoAction::ContentsWrite,
            )
            .await
            .map_err(map_app_auth_err)?;
        }
    }
    Ok(())
}

/// Authorizes a write actor against live relational RBAC before any realm or `pending` mutation.
pub(super) async fn preflight_write_authority(
    pg: &PgLfsBlobStore,
    repository_id: Uuid,
    expected_tenant_id: Uuid,
    actor_id: Uuid,
    actor_username: &str,
) -> Result<(), LfsBlobError> {
    let mut client = pg.pool().get().await.map_err(pg_err)?;
    let tx = client.transaction().await.map_err(pg_err)?;
    resolve_authoritative_repo_access_in_tx(
        &tx,
        repository_id,
        Some(expected_tenant_id),
        actor_id,
        actor_username,
        true,
        false,
    )
    .await?;
    tx.commit().await.map_err(pg_err)?;
    Ok(())
}
