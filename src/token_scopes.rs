//! Personal access token scopes for human users.
//!
//! This module owns the *authorisation data model* for restricted personal
//! access tokens (PATs). It is deliberately not wired into any issuance,
//! login or HTTP handler yet: until every authorised entry point (native API,
//! CLI, browser sessions) consults [`authorize_repository`] and the browser
//! inheritance policy from schema 136 is implemented, restricted tokens are
//! not issued anywhere.
//!
//! # Semantics
//!
//! * A token with `is_restricted = false` keeps its historical, account-wide
//!   behaviour, still intersected with `tokens.read_only`.
//! * A token with `is_restricted = true` is allowed to do exactly what its
//!   rows in `token_repository_scopes` / `token_namespace_scopes` say. An empty
//!   grant set denies everything; it is never an alias for "all".
//! * A repository grant never implies organisation administration, cluster
//!   operator status, or trusted-CI identity. `ryj_` CI credentials remain a
//!   separate authority; scopes cannot be derived from or turned into them.
//! * [`authorize_repository`] is *not* a replacement for role based access
//!   control. Callers must first check that the actor currently holds the
//!   required repository or organisation role. Scopes can only narrow that
//!   decision, never widen it.
//! * Expiry is evaluated with `clock_timestamp()`, not the transaction's fixed
//!   `now()`, so a request that began before expiry stops being authorised as
//!   soon as the token actually expires.
//!
//! # Concurrency contract for future grant writers
//!
//! Readers lock the token row `FOR SHARE OF t` until the end of their
//! transaction, so a grant writer must `SELECT ... FOR UPDATE` the same token
//! row, mutate grants, and increment `tokens.scope_version` in one transaction.
//! That prevents narrowing a token while a request is still being authorised
//! against the wider set. [`narrow_repository_scope`] and
//! [`revoke_repository_scope`] implement that protocol and can only remove
//! grant rows; they never insert or widen. Grant *insertion* is test-only
//! (`#[cfg(test)]`) until issuance is wired end to end.

use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;

/// Repository-scoped actions a restricted human PAT may hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RepoAction {
    ContentsRead,
    ContentsWrite,
    IssuesRead,
    IssuesWrite,
    PullsRead,
    PullsWrite,
    ChecksRead,
    ChecksWrite,
    HooksRead,
    HooksAdmin,
    MembersRead,
    MembersAdmin,
    CiRead,
    CiDispatch,
    WorkspacesRead,
    WorkspacesWrite,
    RepoRead,
    RepoAdmin,
}

impl RepoAction {
    pub const ALL: [RepoAction; 18] = [
        RepoAction::ContentsRead,
        RepoAction::ContentsWrite,
        RepoAction::IssuesRead,
        RepoAction::IssuesWrite,
        RepoAction::PullsRead,
        RepoAction::PullsWrite,
        RepoAction::ChecksRead,
        RepoAction::ChecksWrite,
        RepoAction::HooksRead,
        RepoAction::HooksAdmin,
        RepoAction::MembersRead,
        RepoAction::MembersAdmin,
        RepoAction::CiRead,
        RepoAction::CiDispatch,
        RepoAction::WorkspacesRead,
        RepoAction::WorkspacesWrite,
        RepoAction::RepoRead,
        RepoAction::RepoAdmin,
    ];

    /// Stable text stored in `token_repository_scopes.action`; it is also the
    /// value embedded in the migration's `CHECK` constraint.
    pub const fn as_str(self) -> &'static str {
        match self {
            RepoAction::ContentsRead => "contents_read",
            RepoAction::ContentsWrite => "contents_write",
            RepoAction::IssuesRead => "issues_read",
            RepoAction::IssuesWrite => "issues_write",
            RepoAction::PullsRead => "pulls_read",
            RepoAction::PullsWrite => "pulls_write",
            RepoAction::ChecksRead => "checks_read",
            RepoAction::ChecksWrite => "checks_write",
            RepoAction::HooksRead => "hooks_read",
            RepoAction::HooksAdmin => "hooks_admin",
            RepoAction::MembersRead => "members_read",
            RepoAction::MembersAdmin => "members_admin",
            RepoAction::CiRead => "ci_read",
            RepoAction::CiDispatch => "ci_dispatch",
            RepoAction::WorkspacesRead => "workspaces_read",
            RepoAction::WorkspacesWrite => "workspaces_write",
            RepoAction::RepoRead => "repo_read",
            RepoAction::RepoAdmin => "repo_admin",
        }
    }

    /// Whether the action can change repository state. `read_only` tokens are
    /// denied every mutating action, even when the grant row exists.
    pub const fn is_mutating(self) -> bool {
        matches!(
            self,
            RepoAction::ContentsWrite
                | RepoAction::IssuesWrite
                | RepoAction::PullsWrite
                | RepoAction::ChecksWrite
                | RepoAction::HooksAdmin
                | RepoAction::MembersAdmin
                | RepoAction::CiDispatch
                | RepoAction::WorkspacesWrite
                | RepoAction::RepoAdmin
        )
    }

    pub fn parse(value: &str) -> Option<Self> {
        RepoAction::ALL.into_iter().find(|action| action.as_str() == value)
    }
}

/// Organisation-namespace actions. These are independent of repository grants
/// so a repository token can never acquire organisation administration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NamespaceAction {
    OrgRead,
    OrgMembersWrite,
    OrgTeamsWrite,
}

impl NamespaceAction {
    pub const ALL: [NamespaceAction; 3] =
        [NamespaceAction::OrgRead, NamespaceAction::OrgMembersWrite, NamespaceAction::OrgTeamsWrite];

    pub const fn as_str(self) -> &'static str {
        match self {
            NamespaceAction::OrgRead => "org:read",
            NamespaceAction::OrgMembersWrite => "org:members_write",
            NamespaceAction::OrgTeamsWrite => "org:teams_write",
        }
    }

    pub const fn is_mutating(self) -> bool {
        matches!(self, NamespaceAction::OrgMembersWrite | NamespaceAction::OrgTeamsWrite)
    }

    pub fn parse(value: &str) -> Option<Self> {
        NamespaceAction::ALL.into_iter().find(|action| action.as_str() == value)
    }
}

/// Why a scope check did not grant access. Neither variant carries SQL text,
/// token material or other credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeDenial {
    /// The token is unknown, revoked, expired, belongs to another actor, or is
    /// not a human `api` token. Callers map this to `401`.
    InvalidToken,
    /// The token is live but its scope set does not cover the request. Callers
    /// map this to `403`.
    Forbidden,
    /// The scope store could not be read or is inconsistent. Fail closed with
    /// `500`; the variant deliberately carries no SQL text or credentials.
    Unavailable,
}

impl ScopeDenial {
    pub const fn status_code(self) -> u16 {
        match self {
            ScopeDenial::InvalidToken => 401,
            ScopeDenial::Forbidden => 403,
            ScopeDenial::Unavailable => 500,
        }
    }
}

/// A loaded, live token plus its explicit grant set.
#[derive(Clone, Debug)]
pub struct TokenAuthority {
    token_id: Uuid,
    actor_id: Uuid,
    read_only: bool,
    restricted: bool,
    repositories: BTreeMap<Uuid, BTreeSet<RepoAction>>,
    namespaces: BTreeMap<Uuid, BTreeSet<NamespaceAction>>,
}

impl TokenAuthority {
    pub fn token_id(&self) -> Uuid {
        self.token_id
    }

    pub fn actor_id(&self) -> Uuid {
        self.actor_id
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub fn is_restricted(&self) -> bool {
        self.restricted
    }

    /// Explicit repository actions for one repository (empty when restricted
    /// without grants, or when the token has no grant for that repository).
    pub fn repository_actions(&self, repository_id: Uuid) -> BTreeSet<RepoAction> {
        self.repositories.get(&repository_id).cloned().unwrap_or_default()
    }

    pub fn namespace_actions(&self, organization_id: Uuid) -> BTreeSet<NamespaceAction> {
        self.namespaces.get(&organization_id).cloned().unwrap_or_default()
    }

    /// Pure decision function: no I/O, used by the async helpers and directly
    /// unit-tested.
    pub fn check_repository(&self, repository_id: Uuid, action: RepoAction) -> Result<(), ScopeDenial> {
        if self.read_only && action.is_mutating() {
            return Err(ScopeDenial::Forbidden);
        }
        if !self.restricted {
            // Legacy token: account-wide grant, narrowed only by read_only.
            return Ok(());
        }
        if self.repositories.get(&repository_id).is_some_and(|actions| actions.contains(&action)) {
            Ok(())
        } else {
            Err(ScopeDenial::Forbidden)
        }
    }

    pub fn check_namespace(&self, organization_id: Uuid, action: NamespaceAction) -> Result<(), ScopeDenial> {
        if self.read_only && action.is_mutating() {
            return Err(ScopeDenial::Forbidden);
        }
        if !self.restricted {
            return Ok(());
        }
        if self.namespaces.get(&organization_id).is_some_and(|actions| actions.contains(&action)) {
            Ok(())
        } else {
            Err(ScopeDenial::Forbidden)
        }
    }
}

/// Load a live human API token for `actor_id` and all of its grants inside the
/// caller's transaction.
///
/// The token row is locked `FOR SHARE OF t` until the transaction ends, which
/// blocks the `FOR UPDATE` protocol used by grant writers. Unknown, revoked,
/// expired, foreign, or `browser`-kind tokens yield [`ScopeDenial::InvalidToken`].
/// Browser children are intentionally not accepted: a browser request must
/// first resolve its live parent (schema 136) or the OIDC account session, and
/// that wiring does not exist yet.
pub async fn load_authority(
    tx: &Transaction<'_>,
    token_id: Uuid,
    actor_id: Uuid,
) -> Result<TokenAuthority, ScopeDenial> {
    load_authority_in_transaction(tx, token_id, actor_id, false).await
}

/// Shared transaction loader. `allow_browser_session` only admits a live
/// browser child whose own `is_restricted` is false and whose `web_sessions`
/// row is still live. Browser children never consult grant tables: a restricted
/// browser child is rejected outright (`InvalidToken`) so it cannot be mistaken
/// for an unrestricted legacy browser. The caller must additionally verify the
/// browser session's parent is live and unrestricted; this loader alone cannot
/// see the parent binding.
async fn load_authority_in_transaction(
    tx: &Transaction<'_>,
    token_id: Uuid,
    actor_id: Uuid,
    allow_browser_session: bool,
) -> Result<TokenAuthority, ScopeDenial> {
    let row = tx
        .query_opt(
            "SELECT t.read_only, t.is_restricted \
               FROM tokens t \
              WHERE t.id = $1 AND t.user_id = $2 AND t.revoked = false \
                AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                AND (t.kind = 'api' OR ($3 AND t.kind = 'browser' AND t.is_restricted = false \
                     AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = t.id \
                                  AND NOT s.revoked AND s.expires_at > clock_timestamp()))) \
              FOR SHARE OF t",
            &[&token_id, &actor_id, &allow_browser_session],
        )
        .await
        .map_err(|_| ScopeDenial::Unavailable)?;
    let Some(row) = row else {
        return Err(ScopeDenial::InvalidToken);
    };
    let read_only: bool = row.get(0);
    let restricted: bool = row.get(1);

    let mut repositories: BTreeMap<Uuid, BTreeSet<RepoAction>> = BTreeMap::new();
    let mut namespaces: BTreeMap<Uuid, BTreeSet<NamespaceAction>> = BTreeMap::new();
    if restricted {
        let rows = tx
            .query("SELECT repository_id, action FROM token_repository_scopes WHERE token_id = $1", &[&token_id])
            .await
            .map_err(|_| ScopeDenial::Unavailable)?;
        for row in rows {
            let repository_id: Uuid = row.get(0);
            let action: String = row.get(1);
            let action = RepoAction::parse(&action).ok_or(ScopeDenial::Unavailable)?;
            repositories.entry(repository_id).or_default().insert(action);
        }
        let rows = tx
            .query("SELECT organization_id, action FROM token_namespace_scopes WHERE token_id = $1", &[&token_id])
            .await
            .map_err(|_| ScopeDenial::Unavailable)?;
        for row in rows {
            let organization_id: Uuid = row.get(0);
            let action: String = row.get(1);
            let action = NamespaceAction::parse(&action).ok_or(ScopeDenial::Unavailable)?;
            namespaces.entry(organization_id).or_default().insert(action);
        }
    }

    Ok(TokenAuthority { token_id, actor_id, read_only, restricted, repositories, namespaces })
}

/// Authorise one repository action for an HTTP request.
///
/// API tokens use the normal scope path. `allow_browser_session` is only true
/// inside the browser middleware; a legacy browser child is then treated as an
/// unrestricted legacy token and granted only if it is itself non-restricted.
/// Restricted browser children are rejected, never widened.
pub async fn authorize_repository_for_request(
    tx: &Transaction<'_>,
    token_id: Uuid,
    actor_id: Uuid,
    repository_id: Uuid,
    action: RepoAction,
    allow_browser_session: bool,
) -> Result<(), ScopeDenial> {
    let authority = load_authority_in_transaction(tx, token_id, actor_id, allow_browser_session).await?;
    authority.check_repository(repository_id, action)
}

/// Authorise one organisation namespace action for an HTTP request, with the
/// same browser rule as [`authorize_repository_for_request`].
pub async fn authorize_namespace_for_request(
    tx: &Transaction<'_>,
    token_id: Uuid,
    actor_id: Uuid,
    organization_id: Uuid,
    action: NamespaceAction,
    allow_browser_session: bool,
) -> Result<(), ScopeDenial> {
    let authority = load_authority_in_transaction(tx, token_id, actor_id, allow_browser_session).await?;
    authority.check_namespace(organization_id, action)
}

/// Late repository scope check that locks the token row for the duration of the
/// caller's transaction when one is supplied.
///
/// The query selects the token `FOR SHARE OF t`. With a real transaction that
/// lock is held until commit, so a grant writer using the documented `FOR
/// UPDATE` protocol cannot narrow the grant set between this check and the
/// commit. A bare auto-commit client only holds the lock for this statement: it
/// still re-reads the live token and grants immediately before publication, but
/// callers must not claim that the lock covers a later Git CAS or ref
/// publication. Callers that need the transaction-scoped guarantee must pass a
/// real transaction (as the browse ref transaction and ref-admission settlement
/// paths do).
pub async fn authorize_repository_late<C: GenericClient + Sync>(
    client: &C,
    token_id: Uuid,
    actor_id: Uuid,
    repository_id: Uuid,
    action: RepoAction,
    allow_browser_session: bool,
) -> Result<(), ScopeDenial> {
    let row = client
        .query_opt(
            "SELECT t.read_only, t.is_restricted \
               FROM tokens t \
              WHERE t.id = $1 AND t.user_id = $2 AND t.revoked = false \
                AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                AND (t.kind = 'api' OR ($3 AND t.kind = 'browser' AND t.is_restricted = false \
                     AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id = t.id \
                                  AND NOT s.revoked AND s.expires_at > clock_timestamp()))) \
              FOR SHARE OF t",
            &[&token_id, &actor_id, &allow_browser_session],
        )
        .await
        .map_err(|_| ScopeDenial::Unavailable)?;
    let Some(row) = row else {
        return Err(ScopeDenial::InvalidToken);
    };
    let read_only: bool = row.get(0);
    let restricted: bool = row.get(1);
    let mut repositories: BTreeMap<Uuid, BTreeSet<RepoAction>> = BTreeMap::new();
    if restricted {
        let rows = client
            .query("SELECT repository_id, action FROM token_repository_scopes WHERE token_id = $1", &[&token_id])
            .await
            .map_err(|_| ScopeDenial::Unavailable)?;
        for row in rows {
            let id: Uuid = row.get(0);
            let action: String = row.get(1);
            let action = RepoAction::parse(&action).ok_or(ScopeDenial::Unavailable)?;
            repositories.entry(id).or_default().insert(action);
        }
    }
    let authority = TokenAuthority {
        token_id,
        actor_id,
        read_only,
        restricted,
        repositories,
        namespaces: BTreeMap::new(),
    };
    authority.check_repository(repository_id, action)
}

/// Authorise one repository action for a personal access token.
///
/// Returns [`ScopeDenial::InvalidToken`] (401) when the token is not live and
/// [`ScopeDenial::Forbidden`] (403) when the scope set does not cover the
/// request. The caller is still responsible for verifying the actor's current
/// repository role; this helper only enforces the token's narrowing.
pub async fn authorize_repository(
    tx: &Transaction<'_>,
    token_id: Uuid,
    actor_id: Uuid,
    repository_id: Uuid,
    action: RepoAction,
) -> Result<(), ScopeDenial> {
    let authority = load_authority(tx, token_id, actor_id).await?;
    authority.check_repository(repository_id, action)
}

/// Authorise one organisation namespace action. Repository grants never imply
/// these actions, and these never imply cluster operator authority.
pub async fn authorize_namespace(
    tx: &Transaction<'_>,
    token_id: Uuid,
    actor_id: Uuid,
    organization_id: Uuid,
    action: NamespaceAction,
) -> Result<(), ScopeDenial> {
    let authority = load_authority(tx, token_id, actor_id).await?;
    authority.check_namespace(organization_id, action)
}

/// Internal grant-mutation failures are reported without SQL text or values.
fn store_error() -> anyhow::Error {
    anyhow::anyhow!("token scope store operation failed")
}

/// Lock a restricted token for a grant mutation and bump `scope_version`.
/// Returns `false` when the token is not a live restricted personal token.
async fn lock_restricted_token(tx: &Transaction<'_>, token_id: Uuid, actor_id: Uuid) -> Result<bool> {
    let row = tx
        .query_opt(
            "SELECT t.id FROM tokens t \
              WHERE t.id = $1 AND t.user_id = $2 AND t.revoked = false \
                AND t.is_restricted = true AND t.kind = 'api' \
              FOR UPDATE OF t",
            &[&token_id, &actor_id],
        )
        .await
        .map_err(|_| store_error())?;
    if row.is_none() {
        return Ok(false);
    }
    tx.execute("UPDATE tokens SET scope_version = scope_version + 1 WHERE id = $1", &[&token_id])
        .await
        .map_err(|_| store_error())?;
    Ok(true)
}

/// Narrow or revoke repository grants for a restricted token.
///
/// `keep` lists the actions that must remain for `repository_id`; every other
/// grant row for that repository is deleted. Actions listed in `keep` that are
/// not already granted are *not* inserted, so this helper can never widen a
/// token. The token row is locked `FOR UPDATE` and `scope_version` is
/// incremented in the same transaction. Returns `false` when the token is not a
/// live restricted personal token.
pub async fn narrow_repository_scope(
    tx: &Transaction<'_>,
    token_id: Uuid,
    actor_id: Uuid,
    repository_id: Uuid,
    keep: &[RepoAction],
) -> Result<bool> {
    if !lock_restricted_token(tx, token_id, actor_id).await? {
        return Ok(false);
    }
    let keep: Vec<&str> = keep.iter().map(|action| action.as_str()).collect();
    tx.execute(
        "DELETE FROM token_repository_scopes \
          WHERE token_id = $1 AND repository_id = $2 \
            AND NOT (action = ANY($3::text[]))",
        &[&token_id, &repository_id, &keep],
    )
    .await
    .map_err(|_| store_error())?;
    Ok(true)
}

/// Remove every repository grant for `repository_id` from a restricted token.
/// Narrowing only: no row is ever inserted.
pub async fn revoke_repository_scope(
    tx: &Transaction<'_>,
    token_id: Uuid,
    actor_id: Uuid,
    repository_id: Uuid,
) -> Result<bool> {
    narrow_repository_scope(tx, token_id, actor_id, repository_id, &[]).await
}

/// Validate a human-supplied display name for a future restricted token.
pub fn valid_display_name(name: &str) -> bool {
    let len = name.chars().count();
    (1..=80).contains(&len) && !name.chars().any(|c| c.is_control())
}

// Test-only grant helpers and regressions live in their own file so the
// production half above stays reviewable.
// The test-only half lives beside the module directory; the non-standard path is
// spelled out explicitly, matching `organizations/handlers.rs`.
#[cfg(test)]
#[path = "token_scopes/tests.rs"]
mod tests;
