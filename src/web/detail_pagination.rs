//! Stable `number`-keyset pagination for issue comments and pull reviews.
//!
//! Both child tables (`forge_issue_comments.issue_number`/`number` and
//! `forge_pull_reviews.pull_number`/`number`) have no surrogate `id`, so the
//! only stable ordering key is the per-parent `number`. A page is fetched with
//! `number > $after ORDER BY number ASC LIMIT 101`: 100 rows are rendered and
//! the extra row only signals that another page exists.
//!
//! The cursor is `base64url(JSON)` carrying the version, the authorization
//! scope it was minted for (`actor_uuid`, `repo_uuid`, `parent_number`, `kind`)
//! and the `after` position. It is deliberately *not* an authorization
//! credential: every request re-authenticates and re-loads the current role,
//! and a cursor that does not match the freshly resolved actor/repository/
//! parent/kind is rejected instead of widening or narrowing access.
use crate::Error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Rows rendered per detail page.
pub const PAGE_SIZE: i64 = 100;
/// One extra row proves whether a further page exists.
pub const FETCH_LIMIT: i64 = PAGE_SIZE + 1;
/// Maximum accepted encoded cursor before any decoding work.
pub const MAX_CURSOR_BYTES: usize = 1024;
const CURSOR_VERSION: u8 = 1;

/// Which child list a cursor belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    IssueComments,
    PullReviews,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::IssueComments => "issue_comments",
            Self::PullReviews => "pull_reviews",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "issue_comments" => Some(Self::IssueComments),
            "pull_reviews" => Some(Self::PullReviews),
            _ => None,
        }
    }
}

/// Authorization scope a cursor is bound to.
#[derive(Clone, Copy, Debug)]
pub struct Scope {
    pub actor_id: Uuid,
    pub repo_id: Uuid,
    pub parent_number: i64,
    pub kind: Kind,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    v: u8,
    actor_uuid: Uuid,
    repo_uuid: Uuid,
    parent_number: i64,
    kind: String,
    after: i64,
}

/// `?cursor=` query for detail views. Unknown query keys are rejected.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetailPageQuery {
    pub cursor: Option<String>,
}

/// Decodes and mints cursors for one authorized detail parent.
#[derive(Clone, Copy, Debug)]
pub struct DetailPager {
    scope: Scope,
}

impl DetailPager {
    pub fn new(actor_id: Uuid, repo_id: Uuid, parent_number: i64, kind: Kind) -> Self {
        Self {
            scope: Scope {
                actor_id,
                repo_id,
                parent_number,
                kind,
            },
        }
    }

    /// Resume position for this request. A missing cursor starts at the first
    /// page; a malformed or foreign cursor is a client error, never a silent
    /// restart and never an unauthenticated shortcut.
    pub fn resume_after(&self, cursor: Option<&str>) -> Result<i64, Error> {
        match cursor {
            None => Ok(0),
            Some(raw) => self.decode(raw),
        }
    }

    /// Opaque next-page cursor from the last rendered `number`, if the probe
    /// row showed another page exists.
    pub fn next_cursor(&self, next_after: Option<i64>) -> Option<String> {
        let after = next_after.filter(|number| *number > 0)?;
        let payload = CursorPayload {
            v: CURSOR_VERSION,
            actor_uuid: self.scope.actor_id,
            repo_uuid: self.scope.repo_id,
            parent_number: self.scope.parent_number,
            kind: self.scope.kind.as_str().to_owned(),
            after,
        };
        let bytes = serde_json::to_vec(&payload).ok()?;
        Some(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn decode(&self, raw: &str) -> Result<i64, Error> {
        if raw.is_empty() || raw.len() > MAX_CURSOR_BYTES {
            return Err(bad_cursor());
        }
        let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| bad_cursor())?;
        let payload: CursorPayload =
            serde_json::from_slice(&bytes).map_err(|_| bad_cursor())?;
        let kind_matches = Kind::parse(&payload.kind) == Some(self.scope.kind);
        if payload.v != CURSOR_VERSION
            || !kind_matches
            || payload.actor_uuid != self.scope.actor_id
            || payload.repo_uuid != self.scope.repo_id
            || payload.parent_number != self.scope.parent_number
            || payload.after <= 0
        {
            return Err(bad_cursor());
        }
        Ok(payload.after)
    }
}

fn bad_cursor() -> Error {
    Error::bad_request()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pager() -> DetailPager {
        DetailPager::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            7,
            Kind::IssueComments,
        )
    }

    #[test]
    fn round_trips_and_starts_without_a_cursor() {
        let pager = pager();
        assert_eq!(pager.resume_after(None).unwrap(), 0);
        let cursor = pager.next_cursor(Some(100)).unwrap();
        assert_eq!(pager.resume_after(Some(&cursor)).unwrap(), 100);
        assert!(pager.next_cursor(None).is_none());
        assert!(pager.next_cursor(Some(0)).is_none());
    }

    #[test]
    fn cursor_payload_shape_is_versioned_and_after_is_last() {
        let cursor = pager().next_cursor(Some(42)).unwrap();
        let raw = URL_SAFE_NO_PAD.decode(cursor).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["v"], 1);
        assert_eq!(value["kind"], "issue_comments");
        assert_eq!(value["parent_number"], 7);
        assert_eq!(value["after"], 42);
        assert!(value.get("created_at").is_none());
    }

    #[test]
    fn rejects_foreign_scope() {
        let cursor = pager().next_cursor(Some(3)).unwrap();
        for other in [
            DetailPager::new(Uuid::from_u128(9), Uuid::from_u128(2), 7, Kind::IssueComments),
            DetailPager::new(Uuid::from_u128(1), Uuid::from_u128(9), 7, Kind::IssueComments),
            DetailPager::new(Uuid::from_u128(1), Uuid::from_u128(2), 8, Kind::IssueComments),
            DetailPager::new(Uuid::from_u128(1), Uuid::from_u128(2), 7, Kind::PullReviews),
        ] {
            assert!(other.resume_after(Some(&cursor)).is_err());
        }
    }

    #[test]
    fn rejects_malformed_oversized_and_unknown_field_cursors() {
        let pager = pager();
        assert!(pager.resume_after(Some("")).is_err());
        assert!(pager.resume_after(Some("not base64!")).is_err());
        assert!(pager.resume_after(Some(&"a".repeat(MAX_CURSOR_BYTES + 1))).is_err());

        let raw = serde_json::json!({
            "v": 1,
            "actor_uuid": Uuid::from_u128(1).to_string(),
            "repo_uuid": Uuid::from_u128(2).to_string(),
            "parent_number": 7,
            "kind": "issue_comments",
            "after": 10,
            "extra": true,
        });
        let cursor = URL_SAFE_NO_PAD.encode(raw.to_string().as_bytes());
        assert!(pager.resume_after(Some(&cursor)).is_err());

        let zero_after = serde_json::json!({
            "v": 1,
            "actor_uuid": Uuid::from_u128(1).to_string(),
            "repo_uuid": Uuid::from_u128(2).to_string(),
            "parent_number": 7,
            "kind": "issue_comments",
            "after": 0,
        });
        let cursor = URL_SAFE_NO_PAD.encode(zero_after.to_string().as_bytes());
        assert!(pager.resume_after(Some(&cursor)).is_err());
    }
}
