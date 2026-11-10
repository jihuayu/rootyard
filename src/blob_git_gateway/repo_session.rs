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
//! oracle. A token that authenticates but binds another realm is refused; the
//! refusal names neither the other realm nor the current revision.
use std::{fmt, sync::Arc};

use axum::{
    http::{HeaderMap, HeaderName, HeaderValue, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::error::GatewayError;
use crate::{blob_store::BlobBackendIdentity, ref_store::GitObjectFormat};

/// Request header carrying the session token. There is deliberately no query
/// parameter: a token never appears in a URL, log line or referrer.
pub(crate) const SESSION_HEADER: &str = "x-rootyard-session";
/// Response header naming the actual gate revision served by this response.
pub(crate) const REVISION_HEADER: &str = "x-rootyard-session-revision";
const PREFIX: &str = "rs1.";
const FORMAT_BYTE: u8 = 1;
const TRAILER: &[u8; 10] = b"session/v1";
const BODY_LEN: usize = 111;
const MAC_LEN: usize = 32;
const BODY_B64_LEN: usize = 148;
const MAC_B64_LEN: usize = 43;
/// `rs1.` + body + `.` + MAC. The ceiling is checked before any decoding.
pub(crate) const MAX_TOKEN_LEN: usize = PREFIX.len() + BODY_B64_LEN + 1 + MAC_B64_LEN;
/// Hard lifetime ceiling; also the maximum key-retirement staleness window.
pub(crate) const MAX_LIFETIME_SECONDS: u32 = 15 * 60;
/// Smallest accepted lifetime.
pub(crate) const MIN_LIFETIME_SECONDS: u32 = 30;
const MIN_REVISION: i64 = 1;
const MIN_EPOCH: i64 = 1;
const MAX_EPOCH: i64 = i32::MAX as i64;
const DOMAIN: &[u8] = b"rootyard/blob-git-gateway/repo-session/v1";

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
    pub(crate) fn lifetime_seconds(&self) -> u32 {
        self.lifetime_seconds
    }
    pub(crate) fn issued_unix(&self) -> i64 {
        self.issued_unix
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

/// Verify `session` against the already-authorized live realm.
pub(crate) fn compare(session: &RepoSession, live: &SessionRealm) -> Result<VersionComparison, SessionTokenError> {
    if session.realm != *live {
        return Err(SessionTokenError::Realm);
    }
    Ok(VersionComparison::Satisfied { bound: session.bound })
}

/// A token handed back with the actual served revision.
pub(crate) struct IssuedSession {
    token: String,
    revision: i64,
    lifetime_seconds: u32,
    realm: SessionRealm,
}

impl IssuedSession {
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

/// Non-secret session metadata. It omits the token, both incarnations and the
/// tenant id, and says nothing about any other repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SessionDescriptor {
    pub(crate) revision: i64,
    pub(crate) lifetime_seconds: u32,
    pub(crate) repository_id: Uuid,
}

impl IssuedSession {
    /// Non-secret facts for a JSON body. The token itself is never serialized.
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

impl SessionTokenError {
    pub(crate) fn for_repo(&self) -> GatewayError {
        match self {
            Self::Invalid => GatewayError::BadRequest("invalid repository session token"),
            Self::Expired => GatewayError::Unavailable("repository session has expired; read without a bound again"),
            Self::Realm => GatewayError::Conflict(
                "repository session belongs to another repository, history or authority generation; refresh it",
            ),
            Self::Behind => GatewayError::Unavailable(
                "repository session bound is not yet available from the authoritative store; retry without a stale bound",
            ),
        }
    }
}

/// One immutable key set plus the exact Blob backend digest the gateway opened.
/// Keys are 32-byte MAC secrets held in zeroizing memory.
pub(crate) struct SessionTokenCodec {
    keys: Box<[Option<Zeroizing<[u8; 32]>>; 256]>,
    current: u8,
    backend: [u8; 32],
    lifetime_seconds: u32,
}

impl fmt::Debug for SessionTokenCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids = (0..=u8::MAX).filter(|id| self.keys[*id as usize].is_some()).collect::<Vec<_>>();
        formatter
            .debug_struct("SessionTokenCodec")
            .field("key_ids", &ids)
            .field("current", &self.current)
            .field("lifetime_seconds", &self.lifetime_seconds)
            .finish()
    }
}

impl SessionTokenCodec {
    /// Build one key set. `current` must name a configured key; key ids are the
    /// fixed one-byte encodings unique to a key.
    pub(crate) fn new(
        keys: impl IntoIterator<Item = (u8, [u8; 32])>,
        current: u8,
        backend: &BlobBackendIdentity,
        lifetime_seconds: u32,
    ) -> Result<Self, GatewayError> {
        let mut slots: Box<[Option<Zeroizing<[u8; 32]>>; 256]> = Box::new(std::array::from_fn(|_| None));
        for (id, bytes) in keys {
            if slots[id as usize].replace(Zeroizing::new(bytes)).is_some() {
                return Err(GatewayError::Internal("repository session key ids are not unique"));
            }
        }
        if slots[current as usize].is_none() {
            return Err(GatewayError::Internal("repository session signing key is not configured"));
        }
        if !(MIN_LIFETIME_SECONDS..=MAX_LIFETIME_SECONDS).contains(&lifetime_seconds) {
            return Err(GatewayError::Internal("repository session lifetime is outside its fixed bound"));
        }
        Ok(Self { keys: slots, current, backend: backend_digest(backend)?, lifetime_seconds })
    }

    pub(crate) fn lifetime_seconds(&self) -> u32 {
        self.lifetime_seconds
    }

    /// The exact message the MAC covers: domain transcript, then the body.
    fn message(&self, id: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + body.len());
        for field in [DOMAIN, &self.backend[..], &[id][..], body] {
            out.push(u8::try_from(field.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(field);
        }
        out.extend_from_slice(body);
        out
    }

    /// MAC-only verification with the caller's trusted clock second.
    pub(crate) fn authenticate(&self, token: &str, now_unix: i64) -> Result<RepoSession, SessionTokenError> {
        if token.len() > MAX_TOKEN_LEN || !token.is_ascii() {
            return Err(SessionTokenError::Invalid);
        }
        let rest = token.strip_prefix(PREFIX).ok_or(SessionTokenError::Invalid)?;
        let (body_b64, mac_b64) = rest.split_once('.').ok_or(SessionTokenError::Invalid)?;
        if body_b64.len() != BODY_B64_LEN || mac_b64.len() != MAC_B64_LEN {
            return Err(SessionTokenError::Invalid);
        }
        let mut frame = Zeroizing::new([0u8; BODY_LEN]);
        if URL_SAFE_NO_PAD.decode_slice(body_b64, frame.as_mut()).ok() != Some(BODY_LEN) {
            return Err(SessionTokenError::Invalid);
        }
        let mut mac = [0u8; MAC_LEN];
        if URL_SAFE_NO_PAD.decode_slice(mac_b64, &mut mac).ok() != Some(MAC_LEN) {
            return Err(SessionTokenError::Invalid);
        }
        let body = frame.as_ref();
        let id = body[2];
        let key = self.keys[id as usize].as_ref().ok_or(SessionTokenError::Invalid)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key[..]);
        // `hmac::verify` recomputes and compares in constant time.
        if hmac::verify(&key, &self.message(id, body), &mac).is_err() {
            return Err(SessionTokenError::Invalid);
        }
        let session = parse_body(body)?;
        // A frame issued in the future (clock skew) or older than its own
        // lifetime is refused; the caller's clock never extends a token's life.
        if now_unix < session.issued_unix
            || now_unix >= session.issued_unix.saturating_add(i64::from(session.lifetime_seconds))
        {
            return Err(SessionTokenError::Expired);
        }
        Ok(session)
    }

    /// Verify then compare with the already-authorized live realm.
    pub(crate) fn verify(
        &self,
        token: &str,
        now_unix: i64,
        live: &SessionRealm,
        live_revision: i64,
    ) -> Result<VersionComparison, SessionTokenError> {
        let session = self.authenticate(token, now_unix)?;
        if session.realm != *live {
            return Err(SessionTokenError::Realm);
        }
        if live_revision >= session.bound {
            Ok(VersionComparison::Satisfied { bound: session.bound })
        } else {
            Ok(VersionComparison::Behind { live_revision })
        }
    }

    /// Issue a token for an already-authorized live realm at the revision the
    /// server actually committed or served in this request.
    pub(crate) fn issue(
        &self,
        live: &SessionRealm,
        served_revision: i64,
        now_unix: i64,
    ) -> Result<IssuedSession, SessionTokenError> {
        if served_revision < MIN_REVISION || now_unix < 0 {
            return Err(SessionTokenError::Invalid);
        }
        let mut body = [0u8; BODY_LEN];
        body[0] = FORMAT_BYTE;
        body[2] = self.current;
        body[3..7].copy_from_slice(&self.lifetime_seconds.to_be_bytes());
        body[7..15].copy_from_slice(&served_revision.to_be_bytes());
        body[15..31].copy_from_slice(live.tenant_id.as_bytes());
        body[31..47].copy_from_slice(live.repository_id.as_bytes());
        body[47] = match live.object_format {
            GitObjectFormat::Sha1 => 1,
            GitObjectFormat::Sha256 => 2,
        };
        body[49..65].copy_from_slice(live.history_incarnation.as_bytes());
        body[65..73].copy_from_slice(&live.authority_epoch.to_be_bytes());
        body[73..81].copy_from_slice(&live.group_epoch.to_be_bytes());
        body[81..97].copy_from_slice(live.cluster_incarnation.as_bytes());
        body[97..101].copy_from_slice(&u32::try_from(now_unix).unwrap_or(u32::MAX).to_be_bytes());
        body[101..111].copy_from_slice(TRAILER);
        let key = hmac::Key::new(
            hmac::HMAC_SHA256,
            &self.keys[self.current as usize].as_ref().ok_or(SessionTokenError::Invalid)?[..],
        );
        let mac = hmac::sign(&key, &self.message(self.current, &body));
        Ok(IssuedSession {
            token: format!("{PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(body), URL_SAFE_NO_PAD.encode(mac.as_ref())),
            revision: served_revision,
            lifetime_seconds: self.lifetime_seconds,
            realm: *live,
        })
    }
}

fn backend_digest(backend: &BlobBackendIdentity) -> Result<[u8; 32], GatewayError> {
    hex::decode(backend.as_hex())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or(GatewayError::Internal("invalid Blob backend identity"))
}

/// What one request presented.
pub(crate) enum Presented<'a> {
    None,
    Token(&'a str),
}

/// Extract the explicitly presented token from the request header only.
/// Duplicates are refused, and only a bounded ASCII value is considered.
pub(crate) fn presented<'a>(headers: &'a HeaderMap) -> Result<Presented<'a>, SessionTokenError> {
    let name = HeaderName::from_static(SESSION_HEADER);
    let mut values = headers.get_all(&name).iter();
    let Some(value) = values.next() else { return Ok(Presented::None) };
    let token = value.to_str().map_err(|_| SessionTokenError::Invalid)?;
    if values.next().is_some() {
        return Err(SessionTokenError::Invalid);
    }
    Ok(Presented::Token(token))
}

/// Trusted wall-clock second. A clock before the Unix epoch yields `0`, which
/// can only make a later token fail closed.
pub(crate) fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn parse_body(body: &[u8]) -> Result<RepoSession, SessionTokenError> {
    if body.len() != BODY_LEN || body[0] != FORMAT_BYTE || body[1] != 0 || body[48] != 0 || &body[101..111] != TRAILER {
        return Err(SessionTokenError::Invalid);
    }
    let lifetime_seconds = u32::from_be_bytes(read::<4>(&body[3..7]));
    if !(MIN_LIFETIME_SECONDS..=MAX_LIFETIME_SECONDS).contains(&lifetime_seconds) {
        return Err(SessionTokenError::Invalid);
    }
    let object_format = match body[47] {
        1 => GitObjectFormat::Sha1,
        2 => GitObjectFormat::Sha256,
        _ => return Err(SessionTokenError::Invalid),
    };
    // Re-check the realm through the same constructor the issuer used.
    let realm = SessionRealm::new(
        Uuid::from_bytes(read::<16>(&body[15..31])),
        Uuid::from_bytes(read::<16>(&body[31..47])),
        object_format,
        Uuid::from_bytes(read::<16>(&body[49..65])),
        i64::from_be_bytes(read::<8>(&body[65..73])),
        i64::from_be_bytes(read::<8>(&body[73..81])),
        Uuid::from_bytes(read::<16>(&body[81..97])),
    )?;
    let bound = i64::from_be_bytes(read::<8>(&body[7..15]));
    if bound < MIN_REVISION {
        return Err(SessionTokenError::Invalid);
    }
    Ok(RepoSession {
        realm,
        bound,
        lifetime_seconds,
        issued_unix: i64::from(u32::from_be_bytes(read::<4>(&body[97..101]))),
    })
}

fn read<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&slice[..N]);
    out
}

/// One gateway's immutable key set. Every verify/issue call reads the trusted
/// wall clock itself; no cross-request state is kept here.
#[derive(Clone)]
pub(crate) struct SessionTokens {
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

    /// Verify a presented header token against the authorized live realm and
    /// the live gate revision read in this request.
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

    pub(crate) fn issue(&self, live: &SessionRealm, served_revision: i64) -> Result<IssuedSession, SessionTokenError> {
        self.codec.issue(live, served_revision, now_seconds())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two genuinely distinct, real `cfg(test)` memory-store identities. The
    /// codec stores only their digest, never a profile or credential.
    fn backends() -> (BlobBackendIdentity, BlobBackendIdentity) {
        crate::blob_store::test_support::distinct_backend_identities()
    }

    fn codec_with(keys: &[(u8, [u8; 32])], current: u8, backend: &BlobBackendIdentity) -> SessionTokenCodec {
        SessionTokenCodec::new(keys.iter().copied(), current, backend, 120).expect("codec")
    }

    fn codec(keys: &[(u8, [u8; 32])], current: u8) -> SessionTokenCodec {
        codec_with(keys, current, &backends().0)
    }

    fn key(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    fn realm(seed: u8) -> SessionRealm {
        SessionRealm::new(
            Uuid::from_bytes([seed; 16]),
            Uuid::from_bytes([seed.wrapping_add(10); 16]),
            GitObjectFormat::Sha1,
            Uuid::from_bytes([seed.wrapping_add(20); 16]),
            1,
            1,
            Uuid::from_bytes([seed.wrapping_add(30); 16]),
        )
        .expect("realm")
    }

    #[test]
    fn round_trip_binds_the_full_realm_at_the_served_gate_revision() {
        let codec = codec(&[(3, key(7))], 3);
        let live = realm(1);
        let issued = codec.issue(&live, 9, 1_000).expect("issue");
        assert!(issued.token().len() <= MAX_TOKEN_LEN, "token must stay inside its fixed ceiling");
        let comparison = codec.verify(issued.token(), 1_010, &live, 9).expect("verify");
        assert_eq!(comparison, VersionComparison::Satisfied { bound: 9 });
        let session = codec.authenticate(issued.token(), 1_010).expect("mac");
        assert_eq!(session.realm(), &live);
        assert_eq!(session.bound(), 9);
        assert_eq!(session.lifetime_seconds(), 120);
        assert_eq!(session.issued_unix(), 1_000);
    }

    #[test]
    fn a_bound_is_scored_against_gate_revisions_only() {
        let codec = codec(&[(0, key(1))], 0);
        let live = realm(2);
        let issued = codec.issue(&live, 10, 1_000).expect("issue");
        // A binding-only comparison must still read the live gate revision.
        assert_eq!(
            compare(&codec.authenticate(issued.token(), 1_001).expect("mac"), &live).expect("same realm"),
            VersionComparison::Satisfied { bound: 10 }
        );
        // Live gate behind the bound: explicit, distinguishable refusal.
        assert_eq!(codec.verify(issued.token(), 1_001, &live, 9), Ok(VersionComparison::Behind { live_revision: 9 }));
        // At the bound and beyond are satisfied.
        assert_eq!(codec.verify(issued.token(), 1_001, &live, 10), Ok(VersionComparison::Satisfied { bound: 10 }));
        assert_eq!(codec.verify(issued.token(), 1_001, &live, 12), Ok(VersionComparison::Satisfied { bound: 10 }));
        assert_eq!(SessionTokenError::Behind.for_repo().status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn every_realm_field_mismatch_is_refused_never_compared() {
        let codec = codec(&[(0, key(1))], 0);
        let live = realm(4);
        let issued = codec.issue(&live, 5, 1_000).expect("issue");
        let variants = [
            SessionRealm { tenant_id: Uuid::from_bytes([99; 16]), ..live },
            SessionRealm { repository_id: Uuid::from_bytes([99; 16]), ..live },
            SessionRealm { history_incarnation: Uuid::from_bytes([99; 16]), ..live },
            SessionRealm { authority_epoch: 2, ..live },
            SessionRealm { group_epoch: 2, ..live },
            SessionRealm { object_format: GitObjectFormat::Sha256, ..live },
            // A restore rotates only the cluster authority incarnation.
            SessionRealm { cluster_incarnation: Uuid::from_bytes([98; 16]), ..live },
        ];
        for variant in variants {
            // A different realm is refused at every live gate revision: a
            // revision from another realm never scores as older or newer.
            for revision in [1, 5, 50] {
                assert_eq!(
                    codec.verify(issued.token(), 1_001, &variant, revision),
                    Err(SessionTokenError::Realm),
                    "{variant:?} @ {revision}"
                );
            }
        }
    }

    #[test]
    fn expiry_is_judged_inside_the_signed_frame() {
        let codec = codec(&[(0, key(1))], 0);
        let live = realm(5);
        let issued = codec.issue(&live, 2, 100_000).expect("issue");
        assert!(codec.authenticate(issued.token(), 100_119).is_ok());
        assert_eq!(codec.authenticate(issued.token(), 100_120), Err(SessionTokenError::Expired));
        assert_eq!(codec.authenticate(issued.token(), 99_999), Err(SessionTokenError::Expired), "clock before issue");

        // A correctly signed frame cannot extend the bound beyond the ceiling.
        let mut frame = [0u8; BODY_LEN];
        frame[0] = FORMAT_BYTE;
        frame[2] = 0;
        frame[3..7].copy_from_slice(&(MAX_LIFETIME_SECONDS + 1).to_be_bytes());
        frame[7..15].copy_from_slice(&2i64.to_be_bytes());
        frame[15..31].copy_from_slice(live.tenant_id.as_bytes());
        frame[31..47].copy_from_slice(live.repository_id.as_bytes());
        frame[47] = 1;
        frame[49..65].copy_from_slice(live.history_incarnation.as_bytes());
        frame[65..73].copy_from_slice(&1i64.to_be_bytes());
        frame[73..81].copy_from_slice(&1i64.to_be_bytes());
        frame[81..97].copy_from_slice(live.cluster_incarnation.as_bytes());
        frame[97..101].copy_from_slice(&100_000u32.to_be_bytes());
        frame[101..111].copy_from_slice(TRAILER);
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key(1));
        let tag = hmac::sign(&key, &codec.message(0, &frame));
        let overlong = format!("{PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(frame), URL_SAFE_NO_PAD.encode(tag.as_ref()));
        assert_eq!(codec.authenticate(&overlong, 100_001), Err(SessionTokenError::Invalid));
    }

    #[test]
    fn rotated_deleted_and_forged_tokens_fail_closed() {
        let backend = backends().0;
        let codec = codec_with(&[(0, key(1))], 0, &backend);
        let live = realm(6);
        let issued = codec.issue(&live, 2, 1_000).expect("issue");
        // Rotation: a key set without the signer refuses its tokens.
        let rotated = codec_with(&[(1, key(2))], 1, &backend);
        assert_eq!(rotated.authenticate(issued.token(), 1_001), Err(SessionTokenError::Invalid));
        // Overlap: old key configured but not current verifies until retired.
        let transition = codec_with(&[(0, key(1)), (1, key(2))], 1, &backend);
        assert!(transition.authenticate(issued.token(), 1_001).is_ok());
        // New tokens are signed by the current key id.
        let body = URL_SAFE_NO_PAD
            .decode(transition.issue(&live, 2, 1_001).expect("issue").token().split('.').nth(1).expect("body"))
            .expect("b64");
        assert_eq!(body[2], 1, "new tokens use the current key");
        // The key id byte redirects which secret verifies; it cannot forge.
        let mut bytes = issued.token().as_bytes().to_vec();
        let id_offset = PREFIX.len() + 2;
        bytes[id_offset] = b'B';
        let forged = std::str::from_utf8(&bytes).expect("ascii");
        assert_eq!(codec.authenticate(forged, 1_001), Err(SessionTokenError::Invalid));
        assert_eq!(transition.authenticate(forged, 1_001), Err(SessionTokenError::Invalid));

        // Corruption anywhere in frame or MAC is refused.
        for index in [0, 4, 10, 40, 80, 120, bytes.len() - 5, bytes.len() - 1] {
            let mut corrupt = issued.token().as_bytes().to_vec();
            corrupt[index] = if corrupt[index] == b'A' { b'B' } else { b'A' };
            let text = std::str::from_utf8(&corrupt).expect("ascii");
            if text != issued.token() {
                assert_eq!(codec.authenticate(text, 1_001), Err(SessionTokenError::Invalid), "byte {index}");
            }
        }
    }

    #[test]
    fn malformed_and_oversized_tokens_are_invalid_without_specifics() {
        let codec = codec(&[(0, key(1))], 0);
        let live = realm(7);
        let good = codec.issue(&live, 1, 1_000).expect("issue");
        let cases = [
            String::new(),
            "rs1.".to_owned(),
            "rs2.abc.def".to_owned(),
            "x".repeat(MAX_TOKEN_LEN + 1),
            format!("{}=", good.token()),
            good.token().replace('.', ""),
            format!("{}é", &good.token()[..MAX_TOKEN_LEN - 1]),
            good.token()[..good.token().len() - 1].to_owned(),
        ];
        for case in cases {
            assert_eq!(codec.authenticate(&case, 1_001), Err(SessionTokenError::Invalid), "{case:?}");
        }
    }

    #[test]
    fn a_codec_is_bound_to_the_backend_its_gateway_opened() {
        let keys = [(0u8, key(1))];
        let (first, second) = backends();
        let left = codec_with(&keys, 0, &first);
        let right = codec_with(&keys, 0, &second);
        let live = realm(8);
        let issued = left.issue(&live, 1, 1_000).expect("issue");
        assert!(left.verify(issued.token(), 1_001, &live, 1).is_ok());
        assert_eq!(right.authenticate(issued.token(), 1_001), Err(SessionTokenError::Invalid));
    }

    #[test]
    fn key_and_lifetime_configuration_is_validated() {
        let (target, _) = backends();
        let live = realm(9);
        let cases = [
            (SessionTokenCodec::new([(0u8, key(1))], 1, &target, 120), "current key must exist"),
            (SessionTokenCodec::new([(0u8, key(1)), (0, key(2))], 0, &target, 120), "duplicate ids"),
            (SessionTokenCodec::new([(0u8, key(1))], 0, &target, MAX_LIFETIME_SECONDS + 1), "too long"),
            (SessionTokenCodec::new([(0u8, key(1))], 0, &target, MIN_LIFETIME_SECONDS - 1), "too short"),
        ];
        for (result, reason) in cases {
            assert!(result.is_err(), "{reason}");
        }
        let codec = SessionTokenCodec::new([(0u8, key(1))], 0, &target, 120).expect("codec");
        assert!(codec.issue(&live, 0, 1_000).is_err(), "revision below one is refused");
        assert_eq!(codec.verify("anything", 1_000, &live, 1), Err(SessionTokenError::Invalid));
        let nil_tenant = SessionRealm::new(
            Uuid::nil(),
            live.repository_id,
            GitObjectFormat::Sha1,
            live.history_incarnation,
            1,
            1,
            live.cluster_incarnation,
        );
        assert_eq!(nil_tenant, Err(SessionTokenError::Invalid));
        let nil_cluster = SessionRealm::new(
            live.tenant_id,
            live.repository_id,
            GitObjectFormat::Sha1,
            live.history_incarnation,
            1,
            1,
            Uuid::nil(),
        );
        assert_eq!(nil_cluster, Err(SessionTokenError::Invalid));
        let zero_epoch = SessionRealm::new(
            live.tenant_id,
            live.repository_id,
            GitObjectFormat::Sha1,
            live.history_incarnation,
            0,
            1,
            live.cluster_incarnation,
        );
        assert_eq!(zero_epoch, Err(SessionTokenError::Invalid));
    }

    #[test]
    fn only_the_header_carries_a_token() {
        let mut headers = HeaderMap::new();
        assert!(matches!(presented(&headers), Ok(Presented::None)));
        headers.insert(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.body.mac"));
        assert!(matches!(presented(&headers), Ok(Presented::Token("rs1.body.mac"))));
        headers.append(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.body.mac"));
        assert!(matches!(presented(&headers), Err(SessionTokenError::Invalid)));
        // A token value is never percent-decoded: the alphabet is literal.
        headers.clear();
        headers.insert(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_static("rs1.a%2Bb.c"));
        let codec = codec(&[(0, key(1))], 0);
        assert_eq!(codec.authenticate("rs1.a%2Bb.c", 1_000), Err(SessionTokenError::Invalid));
    }

    #[test]
    fn errors_and_debug_output_never_render_token_material() {
        let live = realm(10);
        let issued = codec_with(&[(0, key(1))], 0, &backends().0).issue(&live, 1, 1_000).expect("issue");
        let text = format!("{issued:?} {:?}", SessionTokens::new(codec(&[(0, key(1))], 0)));
        let token = issued.token();
        assert!(!text.contains(token));
        assert!(!text.contains(&token[PREFIX.len()..PREFIX.len() + 8]));
        assert!(!text.contains(&hex::encode(key(1))));
        for error in [SessionTokenError::Invalid, SessionTokenError::Expired, SessionTokenError::Realm] {
            let message = error.for_repo().message();
            assert!(!message.contains(token), "{message}");
        }
        assert_eq!(error_status(SessionTokenError::Invalid).as_u16(), 400);
        assert_eq!(error_status(SessionTokenError::Expired).as_u16(), 503);
        assert_eq!(error_status(SessionTokenError::Realm).as_u16(), 409);
    }

    fn error_status(error: SessionTokenError) -> axum::http::StatusCode {
        use axum::response::IntoResponse;
        error.for_repo().into_response().status()
    }

    #[test]
    fn issue_and_verify_use_the_same_served_revision_without_any_global_state() {
        let tokens = SessionTokens::new(codec(&[(0, key(1))], 0));
        let live = realm(11);
        // Two independent requests issuing at the same served revision produce
        // the same bound: the gateway holds no cross-request write flag.
        assert_eq!(tokens.issue(&live, 3).expect("a").revision(), 3);
        let second = tokens.issue(&live, 3).expect("b");
        assert_eq!(second.revision(), 3);
        let Some(comparison) = tokens.verify(&Presented::Token(second.token()), &live, 3).expect("verify") else {
            panic!("a presented token must be verified");
        };
        assert_eq!(comparison, VersionComparison::Satisfied { bound: 3 });
    }
}
