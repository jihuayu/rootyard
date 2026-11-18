//! Authoritative relational RBAC resolution inside an existing transaction (`Refs #145`).

use deadpool_postgres::Transaction;
use uuid::Uuid;

use super::authz::{AuthorizedRepoAccess, SubjectTenantAuthority, evaluate_subject_tenant_access};
use super::pg_store::pg_err;
use super::types::{LfsBlobError, LfsCollaboratorRole, LfsProofRejectCode};

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
