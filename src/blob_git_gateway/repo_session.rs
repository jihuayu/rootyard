//! Bounded, server-authenticated repository session tokens (#174, design #172).
//!
//! A session token is an *opaque read lower bound* for one actor's API session.
//! It is not a credential: it never grants permission, never replaces the live
//! token/RBAC/scope/backend check of a read, never pins pack layout and never
//! substitutes for a pin/hold or the verified Blob closure. Its only claim is
//! that the server had already committed (push) or served a complete view of
//! this exact core gate state for this tenant and repository.
//!
//! ## The one version sequence
//!
//! The lower bound is **only** the RefStore core gate revision — the same
//! number a push terminal records (`PackCommitTerminal::revision`) and a read
//! capture records (`ServingReadCapture::gate_revision`). A token never carries,
//! derives or derives-from a projection cursor, a pack/membership version or any
//! other layout counter, and two revisions are comparable only when the full
//! binding below is identical.
//!
//! ## The binding
//!
//! * tenant id (owner namespace) and repository id and object format;
//! * `history_incarnation`, `authority_epoch` and `group_epoch` of the live
//!   serving binding;
//! * the **cluster authority incarnation** (`cluster_authority.incarnation`)
//!   that the request read from PostgreSQL. A restore rotates it while the
//!   RefStore history stays the same, so a token issued before a restore is
//!   refused after it, no matter how large its revision was;
//! * the HMAC-SHA256 key id (and the codec is bound to the opened Blob backend
//!   digest it was configured for).
//!
//! ## Format
//!
//! `rs1.<body>.<mac>`, both parts unpadded base64url.
//!
//! ```text
//! off len field
//!   0   1 format byte (1)
//!   1   1 reserved byte (0)
//!   2   1 signing key id used for this MAC
//!   3   4 bounded lifetime seconds
//!   7   8 version lower bound = core gate revision
//!  15  16 tenant id (the owner namespace id)
//!  31  16 repository id
//!  47   1 object format (1 = sha1, 2 = sha256)
//!  48   1 reserved byte (0)
//!  49  16 history incarnation
//!  65   8 authority epoch
//!  73   8 group epoch
//!  81  16 cluster authority incarnation
//!  97   4 issue time (Unix seconds)
//! 101  10 "session/v1" trailer
//! ```
//!
//! The MAC is HMAC-SHA256 over a length-delimited domain transcript (including
//! the Blob backend digest) and the encoded body, so adjacent fields can never
//! be shifted into one another. Expiry is `issue + lifetime`, the lifetime is
//! inside the signed frame and bounded by [`MAX_LIFETIME_SECONDS`]; a token
//! with another lifetime is not authentic. A token has a fixed maximum length.
//! Rotation adds a key id; retiring a key stops every token it signed within at
//! most one maximum lifetime, needs no database and has no recovery path.
//!
//! ## Request ordering (used by the gateway)
//!
//! 1. authenticate the actor (unchanged shared authentication);
//! 2. authorize the repository through the live shared read lookup;
//! 3. read the live gate state, the binding and the cluster authority
//!    incarnation *now*;
//! 4. only then verify the token and score the version.
//!
//! Steps 3–4 therefore run after authorization: an unauthenticated or
//! unauthorized caller cannot use a token error as a version or existence
//! oracle. A token that authenticates but does not bind the identical live
//! realm is refused as [`SessionTokenError::Realm`] — a retired or foreign key
//! is [`SessionTokenError::Invalid`] — and the refusal names neither the other
//! realm nor the current revision.
//!
//! ## Refusals are not an invitation to drop the bound
//!
//! [`SessionTokenError::Expired`], [`SessionTokenError::Realm`] and
//! [`SessionTokenError::Behind`] all mean "the lower bound cannot be proven at
//! this authority": the client re-reads the authoritative gate (or resumes the
//! queue and retries against the *same* bound) and obtains a fresh token from a
//! real serving capture or committed receipt. None of them is satisfied by an
//! unbounded read, a replica or cache read, or a relaxed read-your-writes or
//! monotonic guarantee. [`VersionComparison::Behind`] is the only scoring place
//! and it always carries the same live revision it was given. The live revision
//! is only ever a RefStore core gate revision: `compare` takes it as an explicit
//! argument, right beside the live realm, so no caller can score a bound
//! against a realm alone, and storage generations or cache cursors cannot be
//! passed in its place.
//!
//! ## Layout
//!
//! This file holds the pieces the gateway shares and exports ([`SessionTokens`],
//! [`SessionRealm`], [`RepoSession`], [`VersionComparison`], [`SessionTokenError`]).
//! The signed frame lives in the private `codec` submodule; unit tests live in
//! the private `tests` submodule. The gateway JSON read routes reach the scoring
//! boundary only through `super::read_session`; no token is issued yet (the
//! low-level mint is test-only).
use std::{fmt, sync::Arc};

use axum::{
    http::{HeaderName, HeaderValue, header},
    response::Response,
};
use uuid::Uuid;

use super::error::GatewayError;
use crate::ref_store::GitObjectFormat;

mod codec;

#[cfg(test)]
mod tests;

/// The opened key set, built only by the private keyring loader. Tests open
/// tokens through the very same type.
pub(crate) use codec::SessionTokenCodec;
/// Header-only extraction of a presented token; the gateway read session and
/// the keyring rotation tests both present real header values.
pub(crate) use codec::presented;
pub(crate) use codec::{MAX_LIFETIME_SECONDS, MIN_LIFETIME_SECONDS};
#[cfg(test)]
pub(crate) use codec::presented as presented_for_test;

use codec::{Presented, now_seconds};

/// Request header carrying the session token. There is deliberately no query
/// parameter: a token never appears in a URL, log line or referrer.
pub(crate) const SESSION_HEADER: &str = "x-rootyard-session";
/// Response header naming the actual gate revision served by this response.
pub(crate) const REVISION_HEADER: &str = "x-rootyard-session-revision";

/// Upper bound on encoded token length; see `codec::MAX_TOKEN_LEN`.
#[cfg(test)]
pub(crate) use codec::MAX_TOKEN_LEN as TEST_MAX_TOKEN_LEN;
/// The exact realm a token is bound to, as read from PostgreSQL during this
/// request. Nothing here comes from process start-up state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionRealm {
    tenant_id: Uuid,
    repository_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    cluster_incarnation: Uuid,
}

/// Epoch floor/ceiling shared with the codec frame.
const MIN_EPOCH: i64 = 1;
const MAX_EPOCH: i64 = i32::MAX as i64;

impl SessionRealm {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        tenant_id: Uuid,
        repository_id: Uuid,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
        cluster_incarnation: Uuid,
    ) -> Result<Self, SessionTokenError> {
        if tenant_id.is_nil()
            || repository_id.is_nil()
            || history_incarnation.is_nil()
            || cluster_incarnation.is_nil()
            || !(MIN_EPOCH..=MAX_EPOCH).contains(&authority_epoch)
            || !(MIN_EPOCH..=MAX_EPOCH).contains(&group_epoch)
        {
            return Err(SessionTokenError::Invalid);
        }
        Ok(Self {
            tenant_id,
            repository_id,
            object_format,
            history_incarnation,
            authority_epoch,
            group_epoch,
            cluster_incarnation,
        })
    }
}

/// One MAC-verified session bound to a realm, at or beyond its lower bound.
/// It carries no key, no actor credential and no permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepoSession {
    realm: SessionRealm,
    bound: i64,
    lifetime_seconds: u32,
    issued_unix: i64,
}

impl RepoSession {
    pub(crate) fn bound(&self) -> i64 {
        self.bound
    }
    pub(crate) fn realm(&self) -> &SessionRealm {
        &self.realm
    }
}

/// The only place a lower bound is scored: after the live realm was
/// authorized and found identical to the token's realm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VersionComparison {
    /// The live gate revision is at or beyond the token's lower bound.
    Satisfied { bound: i64 },
    /// Same realm, but the live gate revision is behind the lower bound. The
    /// caller must answer with an explicit distinguishable refusal; it must
    /// never return this (older) view as satisfying and must never fall back to
    /// an unbounded answer.
    Behind { live_revision: i64 },
}

/// The only place a lower bound is scored. `live_revision` is the RefStore
/// core gate revision the request actually read from the authoritative store;
/// it is never a storage generation, a layout counter or a cache cursor, and
/// it is the only number compared with the bound.
pub(crate) fn compare(
    session: &RepoSession,
    live: &SessionRealm,
    live_revision: i64,
) -> Result<VersionComparison, SessionTokenError> {
    if session.realm != *live {
        return Err(SessionTokenError::Realm);
    }
    if live_revision >= session.bound {
        Ok(VersionComparison::Satisfied { bound: session.bound })
    } else {
        Ok(VersionComparison::Behind { live_revision })
    }
}

/// A token handed back with the actual served revision.
///
/// Its fields are what [`IssuedSession::descriptor`] and
/// [`IssuedSession::apply`] are built from; a verifier trusts only the signed
/// frame it re-parses.
pub(crate) struct IssuedSession {
    token: String,
    revision: i64,
    lifetime_seconds: u32,
    realm: SessionRealm,
}

impl IssuedSession {
    /// Test-only: round-trip and rotation fixtures present the real header.
    #[cfg(test)]
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

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

impl fmt::Debug for IssuedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The encoded token is bearer-equivalent: never print it.
        formatter
            .debug_struct("IssuedSession")
            .field("repository_id", &self.realm.repository_id)
            .field("revision", &self.revision)
            .finish()
    }
}

/// Non-secret session metadata, the body of the issuance reply. It omits the
/// token, both incarnations and the tenant id, and says nothing about any
/// other repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SessionDescriptor {
    pub(crate) revision: i64,
    pub(crate) lifetime_seconds: u32,
    pub(crate) repository_id: Uuid,
}

impl IssuedSession {
    /// Non-secret facts for a JSON body. The token itself is never serialized.
    /// Every issuance reply is built from this pair, so a token is never sent
    /// without the revision and lifetime it is bound to.
    pub(crate) fn descriptor(&self) -> SessionDescriptor {
        SessionDescriptor {
            revision: self.revision,
            lifetime_seconds: self.lifetime_seconds,
            repository_id: self.realm.repository_id,
        }
    }
}

/// Fixed refusal vocabulary. No variant carries a token or a key, and a forged
/// token is indistinguishable from a random string, so no response can probe
/// whether another repository, tenant or history exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionTokenError {
    /// Malformed, oversized, tampered, foreign-key or non-canonical token.
    Invalid,
    /// Authentic, but its bounded lifetime elapsed.
    Expired,
    /// Authentic and unexpired, but bound to another realm (tenant,
    /// repository, object format, history, authority/group epoch or cluster
    /// authority incarnation).
    Realm,
    /// Authentic, same realm, but the live gate is behind the bound.
    Behind,
}

/// The refusal text of [`SessionTokenError::Behind`], naming the exact lower
/// bound the client must keep. Kept as one constant so the message and every
/// client-facing promise about it can be tested verbatim.
pub(crate) const BEHIND_MESSAGE: &str = "repository session lower bound is not yet served by the authoritative store; wait for the authoritative store to reach that bound and retry against the same bound, keeping read-your-writes and monotonic reads (do not fall back to a stale, replica or cache read)";

impl SessionTokenError {
    pub(crate) fn for_repo(&self) -> GatewayError {
        match self {
            Self::Invalid => GatewayError::BadRequest("invalid repository session token"),
            // A fresh token is only ever issued at a revision this server
            // really committed or served; the client asks the same authority
            // for it and never resets its own lower bound.
            Self::Expired => GatewayError::Unavailable(
                "repository session has expired; resume read-your-writes and monotonic reads against the authoritative store and retry from a freshly committed or served revision",
            ),
            Self::Realm => GatewayError::Conflict(
                "repository session belongs to another repository, history or authority generation; re-read the authoritative store and obtain a fresh session there",
            ),
            Self::Behind => GatewayError::Unavailable(BEHIND_MESSAGE),
        }
    }
}

/// One gateway's immutable key set. Every verify/issue call reads the trusted
/// wall clock itself; no cross-request state is kept here.
#[derive(Clone)]
pub struct SessionTokens {
    codec: Arc<SessionTokenCodec>,
}

impl fmt::Debug for SessionTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SessionTokens").field("codec", &self.codec).finish_non_exhaustive()
    }
}

impl SessionTokens {
    pub(crate) fn new(codec: SessionTokenCodec) -> Self {
        Self { codec: Arc::new(codec) }
    }

    pub(crate) fn lifetime_seconds(&self) -> u32 {
        self.codec.lifetime_seconds()
    }

    /// Verify a header value against the authorized live realm and the live
    /// gate revision read in this request; `None` is the unchanged token-free
    /// path. Only callers that already parsed the header (see `presented`) use
    /// this; it validates the frame and delegates to the same `compare` scoring
    /// as everything else, so there is no second, revision-blind comparison.
    pub(crate) fn verify(
        &self,
        presented: &Presented<'_>,
        live: &SessionRealm,
        live_revision: i64,
    ) -> Result<Option<VersionComparison>, SessionTokenError> {
        match presented {
            Presented::None => Ok(None),
            Presented::Token(token) => self.codec.verify(token, now_seconds(), live, live_revision).map(Some),
        }
    }

    /// Issue a token for the revision this request really committed or served.
    /// The bound may equal the live revision but never exceeds it: a bound
    /// above the authoritative gate would make the very next read `Behind`.
    ///
    /// This is a test-only low-level mint, not the serving API. A bare `i64` is
    /// not a proof of what this server committed or served, so production code
    /// cannot reach it; the issuance route is added only in a later task, and it
    /// must take an opaque proof from a real
    /// [`ServingReadCapture`](crate::ref_store::core::pack_snapshot::ServingReadCapture) /
    /// committed receipt. It never accepts a client-supplied revision.
    #[cfg(test)]
    pub(crate) fn issue_for_test(
        &self,
        live: &SessionRealm,
        served_revision: i64,
    ) -> Result<IssuedSession, SessionTokenError> {
        self.codec.issue(live, served_revision, now_seconds())
    }
}
