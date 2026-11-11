//! The token attached to one successful response (#174).
//!
//! [`IssuedSession`] is produced only by the issuer after a sealed serving proof
//! or a committed-write proof was admitted. Its fields are private; a verifier
//! trusts only the signed frame it re-parses.
use axum::{
    http::{HeaderName, HeaderValue, header},
    response::Response,
};
#[cfg(test)]
use uuid::Uuid;

use super::realm::SessionRealm;
use super::{REVISION_HEADER, SESSION_HEADER};

/// A token handed back with the actual served revision.
pub(crate) struct IssuedSession {
    pub(super) token: String,
    pub(super) revision: i64,
    /// The lifetime signed into the frame. Production derives it from the
    /// signed frame itself; only the test-only descriptor reports it.
    #[cfg(test)]
    pub(super) lifetime_seconds: u32,
    pub(super) realm: SessionRealm,
}

impl IssuedSession {
    /// Test-only: round-trip and rotation fixtures present the real header.
    #[cfg(test)]
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// Test-only: proves an issued session names the exact served revision.
    #[cfg(test)]
    pub(crate) fn revision(&self) -> i64 {
        self.revision
    }

    /// Attach the bearer-equivalent token, the served revision and the
    /// no-store policy. The token is never placed in a URL.
    pub(crate) fn apply(&self, response: &mut Response) {
        let headers = response.headers_mut();
        if let Ok(value) = HeaderValue::from_str(&self.token) {
            headers.insert(HeaderName::from_static(SESSION_HEADER), value);
        }
        if let Ok(value) = HeaderValue::from_str(&self.revision.to_string()) {
            headers.insert(HeaderName::from_static(REVISION_HEADER), value);
        }
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::VARY, HeaderValue::from_static("authorization, x-rootyard-session"));
        debug_assert!(!self.realm.repository_id.is_nil());
    }
}

impl std::fmt::Debug for IssuedSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The encoded token is bearer-equivalent: never print it.
        formatter
            .debug_struct("IssuedSession")
            .field("repository_id", &self.realm.repository_id)
            .field("revision", &self.revision)
            .finish()
    }
}

/// Non-secret session metadata for a JSON body. It omits the token, both
/// incarnations and the tenant id, and says nothing about any other
/// repository. Test-only: the gateway sends the token and served revision as
/// headers ([`IssuedSession::apply`]) and builds no JSON body from it.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SessionDescriptor {
    pub(crate) revision: i64,
    pub(crate) lifetime_seconds: u32,
    pub(crate) repository_id: Uuid,
}

#[cfg(test)]
impl IssuedSession {
    /// Test-only: non-secret facts for a JSON body. The token itself is never
    /// serialized; the descriptor states exactly the revision and lifetime the
    /// token was issued with.
    pub(crate) fn descriptor(&self) -> SessionDescriptor {
        SessionDescriptor {
            revision: self.revision,
            lifetime_seconds: self.lifetime_seconds,
            repository_id: self.realm.repository_id,
        }
    }
}
