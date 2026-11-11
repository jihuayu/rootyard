//! Private signed-frame codec for repository session tokens (#174).
//!
//! Everything here is invisible outside `repo_session`: the gateway only sees
//! [`SessionTokens`], [`IssuedSession`], [`RepoSession`] and the shared
//! [`compare`] scoring. All version scoring goes through `compare`; this module
//! never compares revisions itself, so no caller can score a bound without a
//! live revision.
//!
//! Key ids are explicit stable `u8` values carried inside the manifest and the
//! signed frame (see `standalone/session_keyring.rs`). They are never list
//! positions, so retiring or reordering one key never re-labels another. A
//! frame whose id is not in this codec's key set is [`SessionTokenError::Invalid`].
//!
//! The signed frame binds an explicit authority kind and group id next to the
//! tenant, repository, history and epoch fields, so a future Raft Ref-CAS
//! authority can never accept a standalone PostgreSQL token by comparing epochs
//! alone. The MAC transcript length-prefixes every field with a canonical
//! two-byte big-endian length and includes the body exactly once.
//!
//! ## Clock rule
//!
//! Verification uses the verifier's trusted wall clock with **zero** future
//! `iat` allowance: `now_unix < issued_unix` fails as
//! [`SessionTokenError::Expired`], and
//! `now_unix >= issued_unix.saturating_add(lifetime_seconds)` also fails as
//! `Expired`. Multi-process or multi-host deployments must run synchronized NTP
//! clocks; the signed lifetime is never extended to hide skew.
use std::fmt;

use axum::http::{HeaderMap, HeaderName};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    AuthorityKind, IssuedSession, RepoSession, SESSION_HEADER, SessionRealm, SessionRealmFields, SessionTokenError,
    VersionComparison, compare,
};
use crate::{blob_git_gateway::error::GatewayError, blob_store::BlobBackendIdentity, ref_store::GitObjectFormat};

pub(super) const PREFIX: &str = "rs1.";
pub(super) const FORMAT_BYTE: u8 = 2;
pub(super) const TRAILER: &[u8; 10] = b"session/v1";
pub(super) const BODY_LEN: usize = 119;
const MAC_LEN: usize = 32;
const BODY_B64_LEN: usize = 159;
const MAC_B64_LEN: usize = 43;
/// `rs1.` + body + `.` + MAC. The ceiling is checked before any decoding.
pub(crate) const MAX_TOKEN_LEN: usize = PREFIX.len() + BODY_B64_LEN + 1 + MAC_B64_LEN;
/// Hard lifetime ceiling; also the maximum key-retirement staleness window.
pub(crate) const MAX_LIFETIME_SECONDS: u32 = 15 * 60;
/// Smallest accepted lifetime.
pub(crate) const MIN_LIFETIME_SECONDS: u32 = 30;
const MIN_REVISION: i64 = 1;
const DOMAIN: &[u8] = b"rootyard/blob-git-gateway/repo-session/v1";

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
    ///
    /// Key material is moved in as [`Zeroizing`] owners and stored only inside
    /// the slot of its key id, so the key bytes exist in one owner buffer that
    /// wipes itself on drop. (Registers and transient copies inside the HMAC
    /// primitive are outside this guarantee.)
    pub(crate) fn new(
        keys: impl IntoIterator<Item = (u8, Zeroizing<[u8; 32]>)>,
        current: u8,
        backend: &BlobBackendIdentity,
        lifetime_seconds: u32,
    ) -> Result<Self, GatewayError> {
        let mut slots: Box<[Option<Zeroizing<[u8; 32]>>; 256]> = Box::new(std::array::from_fn(|_| None));
        for (id, bytes) in keys {
            // Copy once into the slot's own owner, then wipe the moved-in buffer.
            let mut slot = Zeroizing::new([0u8; 32]);
            slot.copy_from_slice(&bytes[..]);
            if slots[id as usize].replace(slot).is_some() {
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

    /// Test-only: the configured lifetime, for descriptor/lifetime fixtures.
    #[cfg(test)]
    pub(super) fn lifetime_seconds(&self) -> u32 {
        self.lifetime_seconds
    }

    /// The exact message the MAC covers: canonical two-byte big-endian field
    /// lengths, then each field, with the body included exactly once.
    pub(super) fn message(&self, id: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 * 4 + DOMAIN.len() + self.backend.len() + 1 + body.len());
        for field in [DOMAIN, &self.backend[..], &[id][..], body] {
            let length = u16::try_from(field.len()).expect("session transcript fields are bounded");
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    /// MAC-only verification with the caller's trusted clock second. Private:
    /// only `verify` authenticates, then always scores through `compare`.
    fn authenticate(&self, token: &str, now_unix: i64) -> Result<RepoSession, SessionTokenError> {
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
        // Zero future-`iat` skew: a verifier behind the issuer refuses rather
        // than extending the token's life. The upper bound is half-open and
        // saturating, so the signed lifetime is never widened.
        if now_unix < session.issued_unix
            || now_unix >= session.issued_unix.saturating_add(i64::from(session.lifetime_seconds))
        {
            return Err(SessionTokenError::Expired);
        }
        Ok(session)
    }

    /// Authenticate, then score through the shared `compare` with the live
    /// gate revision the request read. This is the only verify path.
    pub(super) fn verify(
        &self,
        token: &str,
        now_unix: i64,
        live: &SessionRealm,
        live_revision: i64,
    ) -> Result<VersionComparison, SessionTokenError> {
        let session = self.authenticate(token, now_unix)?;
        compare(&session, live, live_revision)
    }

    /// Test-only view of the MAC/expiry step, so tests can prove the frame
    /// alone (no revision) authenticates while scoring always needs a live one.
    #[cfg(test)]
    pub(super) fn authenticate_for_test(&self, token: &str, now_unix: i64) -> Result<RepoSession, SessionTokenError> {
        self.authenticate(token, now_unix)
    }

    /// Issue a token for an already-authorized live realm at the revision the
    /// server actually committed or served in this request.
    pub(super) fn issue(
        &self,
        live: &SessionRealm,
        served_revision: i64,
        now_unix: i64,
    ) -> Result<IssuedSession, SessionTokenError> {
        if served_revision < MIN_REVISION || now_unix < 0 || now_unix > i64::from(u32::MAX) {
            return Err(SessionTokenError::Invalid);
        }
        let mut body = [0u8; BODY_LEN];
        body[0] = FORMAT_BYTE;
        body[1] = live.authority.wire();
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
        body[97..105].copy_from_slice(&live.group_id.to_be_bytes());
        body[105..109].copy_from_slice(&u32::try_from(now_unix).expect("issue time was range-checked").to_be_bytes());
        body[109..119].copy_from_slice(TRAILER);
        let key = hmac::Key::new(
            hmac::HMAC_SHA256,
            &self.keys[self.current as usize].as_ref().ok_or(SessionTokenError::Invalid)?[..],
        );
        let mac = hmac::sign(&key, &self.message(self.current, &body));
        Ok(IssuedSession {
            token: format!("{PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(body), URL_SAFE_NO_PAD.encode(mac.as_ref())),
            revision: served_revision,
            #[cfg(test)]
            lifetime_seconds: self.lifetime_seconds,
            realm: *live,
        })
    }
}

fn parse_body(body: &[u8]) -> Result<RepoSession, SessionTokenError> {
    if body.len() != BODY_LEN || body[0] != FORMAT_BYTE || body[48] != 0 || &body[109..119] != TRAILER {
        return Err(SessionTokenError::Invalid);
    }
    let authority = AuthorityKind::from_wire(body[1]).ok_or(SessionTokenError::Malformed)?;
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
    let realm = SessionRealm::new(SessionRealmFields {
        tenant_id: Uuid::from_bytes(read::<16>(&body[15..31])),
        repository_id: Uuid::from_bytes(read::<16>(&body[31..47])),
        object_format,
        history_incarnation: Uuid::from_bytes(read::<16>(&body[49..65])),
        authority,
        authority_epoch: i64::from_be_bytes(read::<8>(&body[65..73])),
        group_id: u64::from_be_bytes(read::<8>(&body[97..105])),
        group_epoch: i64::from_be_bytes(read::<8>(&body[73..81])),
        cluster_incarnation: Uuid::from_bytes(read::<16>(&body[81..97])),
    })?;
    let bound = i64::from_be_bytes(read::<8>(&body[7..15]));
    if bound < MIN_REVISION {
        return Err(SessionTokenError::Invalid);
    }
    Ok(RepoSession {
        realm,
        bound,
        lifetime_seconds,
        issued_unix: i64::from(u32::from_be_bytes(read::<4>(&body[105..109]))),
    })
}

fn read<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&slice[..N]);
    out
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
///
/// This is pure header admission: a duplicate or non-text value is refused. It
/// never authenticates a frame and says nothing about a repository, so a caller
/// may run it before or after the live lookup; `authenticate` (inside the only
/// `verify`/scoring path) re-checks the length and ASCII ceiling.
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
pub(super) fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
