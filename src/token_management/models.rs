//! Data model and validators for personal access token / browser session
//! management.
//!
//! The model is deliberately separate from both transports: the shared service
//! accepts an already authenticated [`crate::db::Identity`], so the API can use
//! `auth::authenticate` (Authorization header only) while the browser UI uses
//! `web::authenticate_web` after the cookie/Origin/CSRF middleware.
//!
//! Nothing in this module ever carries, serialises or logs a token digest, a
//! plaintext secret, a session cookie or a CSRF value. Secrets exist only in the
//! create/rotate service results and their single HTTP response.

use crate::{
    Error,
    members::models::Role,
    token_scopes::{NamespaceAction, RepoAction},
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Default page size for the management list endpoints.
pub const DEFAULT_LIMIT: i64 = 50;
/// Hard upper bound for a management list page; unbounded reads are rejected.
pub const MAX_LIMIT: i64 = 100;
/// Maximum number of explicit grant rows (repository + namespace actions) per token.
pub const MAX_GRANTS: usize = 128;
/// Default lifetime for a newly issued restricted token.
pub const DEFAULT_EXPIRY_DAYS: i64 = 30;
/// Hard upper bound for a newly issued token; infinite tokens are not offered.
pub const MAX_EXPIRY_DAYS: i64 = 365;

/// Repository action grants requested for one repository.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryGrantInput {
    pub repository_id: Uuid,
    pub actions: Vec<String>,
}

/// Organisation action grants requested for one organisation namespace.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceGrantInput {
    pub organization_id: Uuid,
    pub actions: Vec<String>,
}

/// Create a restricted personal token. An empty grant set is a valid, explicit
/// deny-all token; it is never interpreted as "all repositories".
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTokenInput {
    pub display_name: String,
    #[serde(default)]
    pub expires_in_days: Option<i64>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub repository_grants: Vec<RepositoryGrantInput>,
    #[serde(default)]
    pub namespace_grants: Vec<NamespaceGrantInput>,
}

/// Replace the complete grant set (narrowing only) and/or rename a token.
/// `expected_scope_version` is the optimistic-concurrency check; the service
/// locks the token row `FOR UPDATE` and bumps `scope_version` in the same
/// transaction as the grant mutation.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTokenInput {
    pub expected_scope_version: i64,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub repository_grants: Option<Vec<RepositoryGrantInput>>,
    #[serde(default)]
    pub namespace_grants: Option<Vec<NamespaceGrantInput>>,
}

/// Query parameters shared by token and session listings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

impl PageQuery {
    /// Validate the bounded page size (default 50, maximum 100).
    pub fn validate(&self) -> Result<(Option<String>, i64), Error> {
        let limit = self.limit.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(Error(StatusCode::BAD_REQUEST, "limit must be between 1 and 100"));
        }
        Ok((self.after.clone(), limit))
    }
}

/// Safe token metadata. Never contains a digest, secret or credential.
#[derive(Clone, Debug, Serialize)]
pub struct TokenView {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub read_only: bool,
    pub is_restricted: bool,
    pub scope_version: i64,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub repository_grants: Vec<RepositoryGrantView>,
    pub namespace_grants: Vec<NamespaceGrantView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RepositoryGrantView {
    pub repository_id: Uuid,
    pub owner: String,
    pub name: String,
    pub actions: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NamespaceGrantView {
    pub organization_id: Uuid,
    pub slug: String,
    pub actions: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenPage {
    pub items: Vec<TokenView>,
    pub next_after: Option<String>,
}

/// Issue response. `secret` is present exactly once, on create and on rotate.
///
/// Deliberately not `Debug`: the plaintext secret must not reach a diagnostic
/// formatter that could end up in a log or a test failure message.
#[derive(Clone, Serialize)]
pub struct IssuedToken {
    #[serde(flatten)]
    pub token: TokenView,
    pub secret: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionView {
    pub token_id: Uuid,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionPage {
    pub items: Vec<SessionView>,
    pub next_after: Option<String>,
}

/// Minimum repository role required to hold an action grant.
///
/// The values mirror the minimum role the current handlers require for the
/// same action. Actions not yet wired to a handler use the same documented
/// role family (read -> `Read`, mutation -> `Write`, administration -> `Admin`)
/// so a low-role user can never mint a grant above their current role.
pub const fn repository_min_role(action: RepoAction) -> Role {
    match action {
        RepoAction::ContentsRead
        | RepoAction::IssuesRead
        | RepoAction::PullsRead
        | RepoAction::ChecksRead
        | RepoAction::HooksRead
        | RepoAction::MembersRead
        | RepoAction::CiRead
        | RepoAction::WorkspacesRead
        | RepoAction::RepoRead => Role::Read,
        RepoAction::IssuesWrite => Role::Triage,
        RepoAction::ContentsWrite
        | RepoAction::PullsWrite
        | RepoAction::ChecksWrite
        | RepoAction::CiDispatch
        | RepoAction::WorkspacesWrite => Role::Write,
        RepoAction::HooksAdmin => Role::Maintain,
        RepoAction::MembersAdmin | RepoAction::RepoAdmin => Role::Admin,
    }
}

/// Minimum organisation membership role required to hold a namespace grant.
/// Repository grants never imply these actions and these never imply
/// organisation administration outside the specific namespace.
pub const fn namespace_min_role(action: NamespaceAction) -> Role {
    match action {
        NamespaceAction::OrgRead => Role::Read,
        NamespaceAction::OrgMembersWrite | NamespaceAction::OrgTeamsWrite => Role::Admin,
    }
}

pub fn validate_display_name(name: &str) -> Result<String, Error> {
    if !crate::token_scopes::valid_display_name(name) {
        return Err(Error(StatusCode::BAD_REQUEST, "display_name must be 1-80 non-control characters"));
    }
    Ok(name.to_owned())
}

pub fn validate_expiry_days(days: Option<i64>) -> Result<i64, Error> {
    let days = days.unwrap_or(DEFAULT_EXPIRY_DAYS);
    if !(1..=MAX_EXPIRY_DAYS).contains(&days) {
        return Err(Error(StatusCode::BAD_REQUEST, "expires_in_days must be between 1 and 365"));
    }
    Ok(days)
}

/// Normalise and de-duplicate repository actions. Unknown actions are rejected
/// instead of being silently dropped; actions are fixed by the schema `CHECK`.
pub fn normalize_repository_grants(
    input: Vec<RepositoryGrantInput>,
) -> Result<BTreeMap<Uuid, BTreeSet<RepoAction>>, Error> {
    let mut out: BTreeMap<Uuid, BTreeSet<RepoAction>> = BTreeMap::new();
    for grant in input {
        if grant.actions.is_empty() {
            return Err(Error(StatusCode::BAD_REQUEST, "a repository grant needs at least one action"));
        }
        let actions = out.entry(grant.repository_id).or_default();
        for action in grant.actions {
            let parsed = RepoAction::parse(&action)
                .ok_or(Error(StatusCode::BAD_REQUEST, "unknown repository action"))?;
            actions.insert(parsed);
        }
    }
    Ok(out)
}

/// Normalise and de-duplicate namespace actions with the same rules.
pub fn normalize_namespace_grants(
    input: Vec<NamespaceGrantInput>,
) -> Result<BTreeMap<Uuid, BTreeSet<NamespaceAction>>, Error> {
    let mut out: BTreeMap<Uuid, BTreeSet<NamespaceAction>> = BTreeMap::new();
    for grant in input {
        if grant.actions.is_empty() {
            return Err(Error(StatusCode::BAD_REQUEST, "an organisation grant needs at least one action"));
        }
        let actions = out.entry(grant.organization_id).or_default();
        for action in grant.actions {
            let parsed = NamespaceAction::parse(&action)
                .ok_or(Error(StatusCode::BAD_REQUEST, "unknown organisation action"))?;
            actions.insert(parsed);
        }
    }
    Ok(out)
}

pub fn grant_count(
    repositories: &BTreeMap<Uuid, BTreeSet<RepoAction>>,
    namespaces: &BTreeMap<Uuid, BTreeSet<NamespaceAction>>,
) -> usize {
    repositories.values().map(|actions| actions.len()).sum::<usize>()
        + namespaces.values().map(|actions| actions.len()).sum::<usize>()
}

pub fn validate_grant_count(
    repositories: &BTreeMap<Uuid, BTreeSet<RepoAction>>,
    namespaces: &BTreeMap<Uuid, BTreeSet<NamespaceAction>>,
) -> Result<(), Error> {
    if grant_count(repositories, namespaces) > MAX_GRANTS {
        return Err(Error(StatusCode::BAD_REQUEST, "a token may hold at most 128 grants"));
    }
    Ok(())
}

/// True when every requested repository action already exists in `current`.
pub fn is_repository_subset(
    requested: &BTreeMap<Uuid, BTreeSet<RepoAction>>,
    current: &BTreeMap<Uuid, BTreeSet<RepoAction>>,
) -> bool {
    requested.iter().all(|(repository, actions)| {
        current.get(repository).is_some_and(|existing| actions.is_subset(existing))
    })
}

/// True when every requested namespace action already exists in `current`.
pub fn is_namespace_subset(
    requested: &BTreeMap<Uuid, BTreeSet<NamespaceAction>>,
    current: &BTreeMap<Uuid, BTreeSet<NamespaceAction>>,
) -> bool {
    requested.iter().all(|(organization, actions)| {
        current.get(organization).is_some_and(|existing| actions.is_subset(existing))
    })
}

/// Derive the live browser parent id from a session secret.
///
/// The session secret embeds the issuing API token id in its first 32 hex
/// characters; the stored digest binds that id, so a forged prefix cannot pick
/// another parent. This mirrors `web::session` without exporting its internals.
pub fn session_parent(secret: &str) -> Option<Uuid> {
    let bytes = hex::decode(secret.get(4..36)?).ok()?;
    Uuid::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_and_names_are_bounded() {
        assert!(PageQuery { after: None, limit: Some(0) }.validate().is_err());
        assert!(PageQuery { after: None, limit: Some(101) }.validate().is_err());
        assert_eq!(PageQuery { after: None, limit: None }.validate().unwrap().1, DEFAULT_LIMIT);
        assert!(validate_expiry_days(Some(0)).is_err());
        assert!(validate_expiry_days(Some(366)).is_err());
        assert_eq!(validate_expiry_days(None).unwrap(), DEFAULT_EXPIRY_DAYS);
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name(&"x".repeat(81)).is_err());
        assert!(validate_display_name("deploy key").is_ok());
    }

    #[test]
    fn actions_dedupe_and_unknown_values_fail() {
        let grants = normalize_repository_grants(vec![RepositoryGrantInput {
            repository_id: Uuid::nil(),
            actions: vec!["contents_read".into(), "contents_read".into(), "repo_read".into()],
        }])
        .unwrap();
        assert_eq!(grants[&Uuid::nil()].len(), 2);
        assert!(
            normalize_repository_grants(vec![RepositoryGrantInput {
                repository_id: Uuid::nil(),
                actions: vec!["org:read".into()],
            }])
            .is_err()
        );
        assert!(
            normalize_namespace_grants(vec![NamespaceGrantInput {
                organization_id: Uuid::nil(),
                actions: vec!["contents_read".into()],
            }])
            .is_err()
        );
    }

    #[test]
    fn subset_never_widens() {
        let mut current: BTreeMap<Uuid, BTreeSet<RepoAction>> = BTreeMap::new();
        current.entry(Uuid::nil()).or_default().insert(RepoAction::ContentsRead);
        let mut narrower: BTreeMap<Uuid, BTreeSet<RepoAction>> = BTreeMap::new();
        narrower.entry(Uuid::nil()).or_default().insert(RepoAction::ContentsRead);
        assert!(is_repository_subset(&narrower, &current));
        let mut wider = narrower.clone();
        wider.entry(Uuid::nil()).or_default().insert(RepoAction::ContentsWrite);
        assert!(!is_repository_subset(&wider, &current));
        let mut foreign = BTreeMap::new();
        foreign.entry(Uuid::from_u128(1)).or_default().insert(RepoAction::ContentsRead);
        assert!(!is_repository_subset(&foreign, &current));
    }

    #[test]
    fn token_view_formatting_and_json_carry_no_credentials() {
        let view = TokenView {
            id: Uuid::nil(),
            display_name: Some("deploy".to_owned()),
            read_only: false,
            is_restricted: true,
            scope_version: 1,
            expires_at: Some("2030-01-01T00:00:00Z".to_owned()),
            created_at: "2025-01-01T00:00:00Z".to_owned(),
            repository_grants: Vec::new(),
            namespace_grants: Vec::new(),
        };
        let debug = format!("{view:?}");
        let json = serde_json::to_string(&view).unwrap();
        for rendered in [debug, json] {
            assert!(!rendered.contains("secret"));
            assert!(!rendered.contains("digest"));
            assert!(!rendered.contains("csrf"));
        }
    }

    #[test]
    fn parent_binding_requires_the_embedded_id() {
        let parent = Uuid::new_v4();
        let secret = format!("ryt_{}{}", parent.simple(), "0".repeat(32));
        assert_eq!(session_parent(&secret), Some(parent));
        assert_eq!(session_parent("ryt_short"), None);
        assert_eq!(session_parent("nope"), None);
    }
}
