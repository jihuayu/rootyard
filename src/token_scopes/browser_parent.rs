//! Shared live-authority loader for direct API tokens and parent-bound browser children.

use std::collections::{BTreeMap, BTreeSet};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::{NamespaceAction, RepoAction, ScopeDenial};

/// Resolved token flags and scope-table key returned by [`load_token_for_share`].
pub(super) struct ResolvedToken {
    pub(super) scope_token_id: Uuid,
    pub(super) read_only: bool,
    pub(super) restricted: bool,
}

/// Lock and resolve live authority metadata for either a direct human `api` token
/// (`parent_token_id = None`) or an active `browser` session bound to its live
/// `api` parent (`parent_token_id = Some(parent_id)`).
///
/// Browser sessions inherit `read_only OR parent.read_only`, `is_restricted OR
/// parent.is_restricted`, and read their grants from the parent token id under
/// `FOR SHARE OF t, p`.
pub(super) async fn load_token_for_share<C: GenericClient + Sync>(
    client: &C,
    token_id: Uuid,
    actor_id: Uuid,
    parent_token_id: Option<Uuid>,
    allow_browser_session: bool,
) -> Result<ResolvedToken, ScopeDenial> {
    let row = match parent_token_id {
        None => {
            client
                .query_opt(
                    "SELECT t.id, t.read_only, t.is_restricted \
                       FROM tokens t \
                      WHERE t.id = $1 AND t.user_id = $2 AND t.revoked = false \
                        AND t.kind = 'api' \
                        AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                      FOR SHARE OF t",
                    &[&token_id, &actor_id],
                )
                .await
        }
        Some(parent_id) => {
            if !allow_browser_session {
                return Err(ScopeDenial::InvalidToken);
            }
            client
                .query_opt(
                    "SELECT p.id, (t.read_only OR p.read_only), (t.is_restricted OR p.is_restricted) \
                       FROM tokens t \
                       JOIN tokens p ON p.id = $3 AND p.user_id = t.user_id AND p.kind = 'api' \
                      WHERE t.id = $1 AND t.user_id = $2 AND t.kind = 'browser' \
                        AND t.revoked = false \
                        AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                        AND p.revoked = false \
                        AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp()) \
                        AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = t.id \
                                     AND NOT s.revoked AND s.expires_at > clock_timestamp()) \
                      FOR SHARE OF t, p",
                    &[&token_id, &actor_id, &parent_id],
                )
                .await
        }
    }
    .map_err(|_| ScopeDenial::Unavailable)?;
    let Some(row) = row else {
        return Err(ScopeDenial::InvalidToken);
    };
    Ok(ResolvedToken {
        scope_token_id: row.get(0),
        read_only: row.get(1),
        restricted: row.get(2),
    })
}

/// Load explicit repository action grants stored under `scope_token_id`.
pub(super) async fn load_repository_scopes<C: GenericClient + Sync>(
    client: &C,
    scope_token_id: Uuid,
) -> Result<BTreeMap<Uuid, BTreeSet<RepoAction>>, ScopeDenial> {
    let mut repositories: BTreeMap<Uuid, BTreeSet<RepoAction>> = BTreeMap::new();
    let rows = client
        .query("SELECT repository_id, action FROM token_repository_scopes WHERE token_id = $1", &[&scope_token_id])
        .await
        .map_err(|_| ScopeDenial::Unavailable)?;
    for row in rows {
        let repository_id: Uuid = row.get(0);
        let action: String = row.get(1);
        let action = RepoAction::parse(&action).ok_or(ScopeDenial::Unavailable)?;
        repositories.entry(repository_id).or_default().insert(action);
    }
    Ok(repositories)
}

/// Load explicit namespace action grants stored under `scope_token_id`.
pub(super) async fn load_namespace_scopes<C: GenericClient + Sync>(
    client: &C,
    scope_token_id: Uuid,
) -> Result<BTreeMap<Uuid, BTreeSet<NamespaceAction>>, ScopeDenial> {
    let mut namespaces: BTreeMap<Uuid, BTreeSet<NamespaceAction>> = BTreeMap::new();
    let rows = client
        .query("SELECT organization_id, action FROM token_namespace_scopes WHERE token_id = $1", &[&scope_token_id])
        .await
        .map_err(|_| ScopeDenial::Unavailable)?;
    for row in rows {
        let organization_id: Uuid = row.get(0);
        let action: String = row.get(1);
        let action = NamespaceAction::parse(&action).ok_or(ScopeDenial::Unavailable)?;
        namespaces.entry(organization_id).or_default().insert(action);
    }
    Ok(namespaces)
}

#[cfg(test)]
mod tests {
    use super::super::{RepoAction, ScopeDenial, TokenAuthority};
    use std::collections::{BTreeMap, BTreeSet};
    use uuid::Uuid;

    #[test]
    fn inherited_authority_narrows_to_parent_repo_and_read_only_flags() {
        let allowed_repo = Uuid::new_v4();
        let other_repo = Uuid::new_v4();
        let mut repos = BTreeMap::new();
        repos.insert(allowed_repo, BTreeSet::from([RepoAction::ContentsRead, RepoAction::ContentsWrite]));
        let authority = TokenAuthority {
            token_id: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
            read_only: true,
            restricted: true,
            repositories: repos,
            namespaces: BTreeMap::new(),
        };
        assert_eq!(authority.check_repository(allowed_repo, RepoAction::ContentsRead), Ok(()));
        assert_eq!(
            authority.check_repository(allowed_repo, RepoAction::ContentsWrite),
            Err(ScopeDenial::Forbidden)
        );
        assert_eq!(authority.check_repository(other_repo, RepoAction::ContentsRead), Err(ScopeDenial::Forbidden));
    }
}
