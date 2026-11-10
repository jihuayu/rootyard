//! Data models, 5-level Role hierarchy, request/query extractors, validators,
//! and idempotent schema initialization for Track B (Collaborator/Team RBAC & Audit Log).
use crate::{Error, db};
use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_postgres::Row;
use uuid::Uuid;

pub const COLLABORATOR_FIELDS: &str = "c.repository_id, c.user_id, u.username, c.role, c.version, c.created_at::text, c.updated_at::text";
pub const TEAM_FIELDS: &str =
    "id, repository_id, slug, name, description, role, version, created_at::text, updated_at::text";
pub const TEAM_MEMBER_FIELDS: &str =
    "tm.team_id, tm.repository_id, tm.user_id, u.username, tm.created_at::text";
pub const AUDIT_FIELDS: &str = "id, repository_id, actor_id, actor_name, action, target_type, target_name, details, created_unix, created_at::text";

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Read = 10,
    Triage = 20,
    Write = 30,
    Maintain = 40,
    Admin = 50,
}

impl Role {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Triage => "triage",
            Self::Write => "write",
            Self::Maintain => "maintain",
            Self::Admin => "admin",
        }
    }

    pub const fn level(&self) -> u8 {
        *self as u8
    }

    pub fn from_str_role(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "triage" => Some(Self::Triage),
            "write" => Some(Self::Write),
            "maintain" => Some(Self::Maintain),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    pub fn parse(s: &str) -> Result<Self, Error> {
        Self::from_str_role(s).ok_or_else(Error::bad_request)
    }

    pub const fn allows_read(&self) -> bool {
        (*self as u8) >= (Self::Read as u8)
    }

    pub const fn allows_triage(&self) -> bool {
        (*self as u8) >= (Self::Triage as u8)
    }

    pub const fn allows_write(&self) -> bool {
        (*self as u8) >= (Self::Write as u8)
    }

    pub const fn allows_maintain(&self) -> bool {
        (*self as u8) >= (Self::Maintain as u8)
    }

    pub const fn allows_admin(&self) -> bool {
        (*self as u8) >= (Self::Admin as u8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepoAccess {
    pub repo_id: Uuid,
    pub owner_id: Uuid,
    pub role: Role,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Collaborator {
    pub repository_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub role: Role,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Collaborator {
    pub fn row(row: &Row) -> Result<Self, Error> {
        let role_str: String = row.get("role");
        Ok(Self {
            repository_id: row.get("repository_id"),
            user_id: row.get("user_id"),
            username: row.get("username"),
            role: Role::parse(&role_str)?,
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollaboratorInput {
    pub username: Option<String>,
    pub role: Role,
    pub expected_version: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Team {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub role: Role,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Team {
    pub fn row(row: &Row) -> Result<Self, Error> {
        let role_str: String = row.get("role");
        Ok(Self {
            id: row.get("id"),
            repository_id: row.get("repository_id"),
            slug: row.get("slug"),
            name: row.get("name"),
            description: row.get("description"),
            role: Role::parse(&role_str)?,
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewTeam {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub role: Role,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamPatch {
    pub expected_version: i64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub role: Option<Role>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TeamMember {
    pub team_id: Uuid,
    pub repository_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub created_at: String,
}

impl TeamMember {
    pub fn row(row: &Row) -> Self {
        Self {
            team_id: row.get("team_id"),
            repository_id: row.get("repository_id"),
            user_id: row.get("user_id"),
            username: row.get("username"),
            created_at: row.get("created_at"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamMemberInput {
    pub username: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectivePermission {
    pub repository_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub role: Option<Role>,
    pub direct_role: Option<Role>,
    pub team_role: Option<Role>,
    pub is_owner: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: i64,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub actor_name: String,
    pub action: String,
    pub target_type: String,
    pub target_name: String,
    pub details: Value,
    pub created_unix: i64,
    pub created_at: String,
}

impl AuditEntry {
    pub fn row(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            repository_id: row.get("repository_id"),
            actor_id: row.get("actor_id"),
            actor_name: row.get("actor_name"),
            action: row.get("action"),
            target_type: row.get("target_type"),
            target_name: row.get("target_name"),
            details: row.get("details"),
            created_unix: row.get("created_unix"),
            created_at: row.get("created_at"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditPage {
    pub items: Vec<AuditEntry>,
    pub next_after: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

impl AuditQuery {
    pub fn validate(&self) -> Result<(i64, i64), Error> {
        let after = self.after.unwrap_or(0);
        let limit = self.limit.unwrap_or(50);
        if after < 0 || !(1..=100).contains(&limit) {
            return Err(Error::bad_request());
        }
        if let Some(ref actor) = self.actor
            && !db::valid_name(actor) {
                return Err(Error::bad_request());
            }
        if let Some(ref action) = self.action
            && !valid_audit_token(action) {
                return Err(Error::bad_request());
            }
        if let (Some(since), Some(until)) = (self.since, self.until) {
            if since > until || since < 0 || until < 0 {
                return Err(Error::bad_request());
            }
        } else if self.since.is_some_and(|s| s < 0) || self.until.is_some_and(|u| u < 0) {
            return Err(Error::bad_request());
        }
        Ok((after, limit))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

impl Page {
    pub fn bounds(&self) -> Result<(i64, i64), Error> {
        let after = self.after.unwrap_or(0);
        let limit = self.limit.unwrap_or(50);
        if after < 0 || !(1..=100).contains(&limit) {
            return Err(Error::bad_request());
        }
        Ok((after, limit))
    }
}

pub fn json(status: StatusCode, value: impl Serialize) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

pub fn valid_team_slug(slug: &str) -> bool {
    db::valid_name(slug)
}

pub fn valid_team_name(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
}

pub fn valid_team_description(desc: &str) -> bool {
    desc.len() <= 1024
        && !desc
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

pub fn valid_audit_token(token: &str) -> bool {
    let bytes = token.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'.' | b'_' | b':' | b'-'))
}

pub async fn ensure_schema(pool: &Pool) -> Result<(), Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    let installed: bool = client
        .query_one(
            "SELECT to_regclass('repository_collaborators') IS NOT NULL AND to_regclass('repository_audit_log') IS NOT NULL",
            &[],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    if !installed {
        return Err(Error::internal("members schema is not migrated"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;

    #[test]
    fn role_hierarchy_and_parsing() {
        assert!(Role::Read < Role::Triage);
        assert!(Role::Triage < Role::Write);
        assert!(Role::Write < Role::Maintain);
        assert!(Role::Maintain < Role::Admin);
        assert!(!Role::Read.allows_triage());
        assert!(Role::Triage.allows_triage());
        assert!(!Role::Triage.allows_write());
        assert!(Role::Write.allows_write());
        assert!(!Role::Write.allows_maintain());
        assert!(Role::Maintain.allows_maintain());
        assert!(!Role::Maintain.allows_admin());
        assert!(Role::Admin.allows_admin());

        for (raw, expected) in [
            ("read", Role::Read),
            ("triage", Role::Triage),
            ("write", Role::Write),
            ("maintain", Role::Maintain),
            ("admin", Role::Admin),
        ] {
            assert_eq!(Role::parse(raw).unwrap(), expected);
            assert_eq!(expected.as_str(), raw);
        }
        for bad in ["", "Read", "ADMIN", "owner", "superadmin"] {
            assert!(Role::parse(bad).is_err());
        }
    }

    #[test]
    fn team_and_audit_validators() {
        assert!(valid_team_slug("core-reviewers"));
        assert!(valid_team_slug("sec_team_1"));
        for bad_slug in ["", "-bad", "Upper", "team/one", &"a".repeat(64)] {
            assert!(!valid_team_slug(bad_slug));
        }
        assert!(valid_team_name("Core Reviewers"));
        assert!(!valid_team_name("   "));
        assert!(!valid_team_name("bad\nname"));
        assert!(!valid_team_name(&"x".repeat(129)));
        assert!(valid_team_description(
            "Handles core reviews\nand security."
        ));
        assert!(!valid_team_description("bad\0desc"));
        assert!(!valid_team_description(&"x".repeat(1025)));

        let uri =
            "/audit?actor=alice&action=collaborator.upsert&since=100&until=200&after=5&limit=25"
                .parse()
                .unwrap();
        let Query(q) = Query::<AuditQuery>::try_from_uri(&uri).unwrap();
        assert_eq!(q.validate().unwrap(), (5, 25));

        for bad_q in [
            AuditQuery {
                actor: Some("BadActor".into()),
                action: None,
                since: None,
                until: None,
                after: None,
                limit: None,
            },
            AuditQuery {
                actor: None,
                action: Some("bad action!".into()),
                since: None,
                until: None,
                after: None,
                limit: None,
            },
            AuditQuery {
                actor: None,
                action: None,
                since: Some(300),
                until: Some(100),
                after: None,
                limit: None,
            },
            AuditQuery {
                actor: None,
                action: None,
                since: None,
                until: None,
                after: Some(-1),
                limit: None,
            },
            AuditQuery {
                actor: None,
                action: None,
                since: None,
                until: None,
                after: None,
                limit: Some(101),
            },
        ] {
            assert!(bad_q.validate().is_err());
        }
    }
}
