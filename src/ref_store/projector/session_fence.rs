//! Distributed Raft Ref-CAS repository causal session lower bounds and
//! linearizable ReadIndex / monotonic-read admission gates (#175).
//!
//! Coordinates strictly separated:
//! * `(group_id, group_epoch, history_incarnation, authority_id, authority_epoch, cluster_incarnation)`
//!   identify the exact consensus stream & authority instance.
//! * `raft_log_index` tracks committed/applied Raft log progress inside that group.
//! * `repo_ref_version` tracks the Ref-CAS core gate revision for the repository.
//! * Raft `term` is NEVER stored as a monotonic epoch or compared as a version, and
//!   PG projection cursors / Redis advisory caches are NEVER treated as commit authority.

use std::fmt;
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ref_store::GitObjectFormat;

pub const RAFT_SESSION_HEADER: &str = "x-rootyard-session";
pub const RAFT_TOKEN_PREFIX: &str = "rrs1.";
pub const MIN_LIFETIME_SECONDS: u32 = 30;
pub const MAX_LIFETIME_SECONDS: u32 = 15 * 60;

const FORMAT_VERSION: u8 = 1;
const MAC_LEN: usize = 32;
const MAC_B64_LEN: usize = 43;
pub const MAX_RAFT_TOKEN_LEN: usize = 1024;
const TRANSCRIPT_DOMAIN: &[u8] = b"rootyard/ref-store/raft-session-lower-bound/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionFenceError {
    Unauthenticated,
    PermissionDenied,
    MalformedToken(&'static str),
    ForgedOrInvalidToken,
    Expired,
    RealmMismatch,
    BehindLowerBound {
        required_log_index: u64,
        required_repo_ref_version: i64,
        observed_log_index: u64,
        observed_repo_ref_version: i64,
    },
    QuorumUnavailable(String),
    AuthorityViolation(&'static str),
    InvalidInput(&'static str),
    Internal(&'static str),
}

impl SessionFenceError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthenticated | Self::ForgedOrInvalidToken => StatusCode::UNAUTHORIZED,
            Self::PermissionDenied => StatusCode::FORBIDDEN,
            Self::MalformedToken(_) | Self::InvalidInput(_) => StatusCode::BAD_REQUEST,
            Self::Expired | Self::RealmMismatch => StatusCode::CONFLICT,
            Self::BehindLowerBound { .. } | Self::QuorumUnavailable(_) | Self::AuthorityViolation(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl fmt::Display for SessionFenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("caller is not authenticated"),
            Self::PermissionDenied => f.write_str("caller lacks live permission for repository"),
            Self::MalformedToken(r) => write!(f, "malformed raft session header: {r}"),
            Self::ForgedOrInvalidToken => f.write_str("invalid or unrecognized raft session token"),
            Self::Expired => f.write_str("raft session lower bound expired; re-read from leader"),
            Self::RealmMismatch => f.write_str("raft session realm/history/authority changed"),
            Self::BehindLowerBound {
                required_log_index: rl,
                required_repo_ref_version: rv,
                observed_log_index: ol,
                observed_repo_ref_version: ov,
            } => write!(f, "replica behind lower bound: need ({rl},{rv}), got ({ol},{ov})"),
            Self::QuorumUnavailable(msg) => write!(f, "raft quorum/ReadIndex unavailable: {msg}"),
            Self::AuthorityViolation(msg) => write!(f, "raft authority violation: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid raft session input: {msg}"),
            Self::Internal(msg) => write!(f, "internal raft session error: {msg}"),
        }
    }
}

impl std::error::Error for SessionFenceError {}

/// Immutable identity binding a Raft session token to one exact repository consensus stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RaftSessionRealm {
    pub group_id: i64,
    pub group_epoch: i64,
    pub history_incarnation: Uuid,
    pub authority_id: Uuid,
    pub authority_epoch: i64,
    pub cluster_incarnation: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub object_format: GitObjectFormat,
}

impl RaftSessionRealm {
    pub fn validate(&self) -> Result<(), SessionFenceError> {
        if self.group_id < 0 || self.group_epoch < 1 || self.authority_epoch < 1 {
            return Err(SessionFenceError::InvalidInput("group/authority epochs must be >= 1 and group_id >= 0"));
        }
        let ids =
            [self.history_incarnation, self.authority_id, self.cluster_incarnation, self.tenant_id, self.repository_id];
        if ids.iter().any(Uuid::is_nil) {
            return Err(SessionFenceError::InvalidInput("realm UUID fields must be non-nil"));
        }
        Ok(())
    }
}

/// Verified repository read/write causal lower bound carried in `rrs1.` headers.
/// Explicitly separates `(group_id, history_incarnation, authority_id, raft_log_index, repo_ref_version)`
/// from `projection_cursor` and Raft `term`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RaftSessionLowerBound {
    pub realm: RaftSessionRealm,
    pub raft_log_index: u64,
    pub repo_ref_version: i64,
    pub key_id: u8,
    pub issued_unix: i64,
    pub lifetime_seconds: u32,
}

impl RaftSessionLowerBound {
    pub fn satisfies(
        &self,
        committed_log_index: u64,
        last_applied_log_index: u64,
        live_repo_ref_version: i64,
        live_realm: &RaftSessionRealm,
    ) -> Result<(), SessionFenceError> {
        live_realm.validate()?;
        if &self.realm != live_realm {
            return Err(SessionFenceError::RealmMismatch);
        }
        let observed_idx = committed_log_index.min(last_applied_log_index);
        if observed_idx < self.raft_log_index || live_repo_ref_version < self.repo_ref_version {
            return Err(SessionFenceError::BehindLowerBound {
                required_log_index: self.raft_log_index,
                required_repo_ref_version: self.repo_ref_version,
                observed_log_index: observed_idx,
                observed_repo_ref_version: live_repo_ref_version,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySourceKind {
    RaftReadIndexQuorum,
    UnverifiedLocalReplica,
    PgRefsProjection,
    RedisCache,
}

pub fn assert_authoritative_source(source: AuthoritySourceKind) -> Result<(), SessionFenceError> {
    let reason = match source {
        AuthoritySourceKind::RaftReadIndexQuorum => return Ok(()),
        AuthoritySourceKind::UnverifiedLocalReplica => "unverified local replica cannot satisfy linearizable read",
        AuthoritySourceKind::PgRefsProjection => "pg refs projection cannot substitute for Raft commit authority",
        AuthoritySourceKind::RedisCache => "redis cache cannot substitute for Raft commit authority",
    };
    Err(SessionFenceError::AuthorityViolation(reason))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RaftReadProof {
    pub source: AuthoritySourceKind,
    pub realm: RaftSessionRealm,
    pub leader_id: Option<u64>,
    pub committed_log_index: u64,
    pub last_applied_log_index: u64,
    pub repo_ref_version: i64,
    pub state_digest_hex: String,
    pub pin_closure_intact: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallerAccessState {
    pub authenticated: bool,
    pub has_read_permission: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedRaftRead {
    pub realm: RaftSessionRealm,
    pub committed_log_index: u64,
    pub last_applied_log_index: u64,
    pub repo_ref_version: i64,
    pub session_token: String,
    pub leader_id: Option<u64>,
    pub state_digest_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RaftProbeOutcome {
    Ready(RaftReadProof),
    ForwardToLeader(u64),
    QuorumUnavailable(String),
}

pub struct RaftSessionCodec {
    keys: Box<[Option<Zeroizing<[u8; 32]>>; 256]>,
    current: u8,
    lifetime_seconds: u32,
}

impl fmt::Debug for RaftSessionCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_ids: Vec<u8> = (0..=u8::MAX).filter(|id| self.keys[*id as usize].is_some()).collect();
        f.debug_struct("RaftSessionCodec")
            .field("key_ids", &key_ids)
            .field("current", &self.current)
            .field("lifetime_seconds", &self.lifetime_seconds)
            .finish()
    }
}

impl RaftSessionCodec {
    pub fn new(
        keys: impl IntoIterator<Item = (u8, Zeroizing<[u8; 32]>)>,
        current: u8,
        lifetime_seconds: u32,
    ) -> Result<Self, SessionFenceError> {
        let mut slots: Box<[Option<Zeroizing<[u8; 32]>>; 256]> = Box::new(std::array::from_fn(|_| None));
        for (id, bytes) in keys {
            let mut slot = Zeroizing::new([0u8; 32]);
            slot.copy_from_slice(&bytes[..]);
            if slots[id as usize].replace(slot).is_some() {
                return Err(SessionFenceError::InvalidInput("duplicate raft session key id"));
            }
        }
        if slots[current as usize].is_none() {
            return Err(SessionFenceError::InvalidInput("missing current signing key id"));
        }
        if !(MIN_LIFETIME_SECONDS..=MAX_LIFETIME_SECONDS).contains(&lifetime_seconds) {
            return Err(SessionFenceError::InvalidInput("lifetime_seconds outside 30..=900"));
        }
        Ok(Self { keys: slots, current, lifetime_seconds })
    }

    pub fn extract_header(headers: &HeaderMap) -> Result<Option<&str>, SessionFenceError> {
        let mut iter = headers.get_all(RAFT_SESSION_HEADER).iter();
        let Some(first) = iter.next() else {
            return Ok(None);
        };
        if iter.next().is_some() {
            return Err(SessionFenceError::MalformedToken("duplicate session header"));
        }
        let text = first.to_str().map_err(|_| SessionFenceError::MalformedToken("non-ascii header"))?;
        if text.is_empty() || text.len() > MAX_RAFT_TOKEN_LEN || text.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(SessionFenceError::MalformedToken("invalid token length or whitespace"));
        }
        Ok(Some(text))
    }

    pub fn mint_token(
        &self,
        realm: &RaftSessionRealm,
        raft_log_index: u64,
        repo_ref_version: i64,
        now_unix: i64,
    ) -> Result<String, SessionFenceError> {
        realm.validate()?;
        if raft_log_index == 0 || repo_ref_version < 1 || now_unix < 0 {
            return Err(SessionFenceError::InvalidInput("raft_log_index and repo_ref_version must be >= 1"));
        }
        let key_bytes = self.keys[self.current as usize].as_ref().ok_or(SessionFenceError::Internal("missing key"))?;
        let bound = RaftSessionLowerBound {
            realm: realm.clone(),
            raft_log_index,
            repo_ref_version,
            key_id: self.current,
            issued_unix: now_unix,
            lifetime_seconds: self.lifetime_seconds,
        };
        let mut body = Zeroizing::new(vec![FORMAT_VERSION, self.current]);
        serde_json::to_writer(&mut *body, &bound).map_err(|_| SessionFenceError::Internal("encode frame failed"))?;
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key_bytes[..]), &mac_transcript(self.current, &body));
        Ok(format!("{RAFT_TOKEN_PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(&*body), URL_SAFE_NO_PAD.encode(tag.as_ref())))
    }

    pub fn verify_token(
        &self,
        raw: &str,
        live_realm: &RaftSessionRealm,
        now_unix: i64,
    ) -> Result<RaftSessionLowerBound, SessionFenceError> {
        live_realm.validate()?;
        if raw.len() > MAX_RAFT_TOKEN_LEN || !raw.is_ascii() {
            return Err(SessionFenceError::MalformedToken("non-ascii or over-length token"));
        }
        let rest = raw.strip_prefix(RAFT_TOKEN_PREFIX).ok_or(SessionFenceError::ForgedOrInvalidToken)?;
        let (body_b64, mac_b64) = rest.split_once('.').ok_or(SessionFenceError::ForgedOrInvalidToken)?;
        if body_b64.is_empty() || mac_b64.len() != MAC_B64_LEN {
            return Err(SessionFenceError::MalformedToken("invalid token encoding length"));
        }
        let body = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(body_b64)
                .map_err(|_| SessionFenceError::MalformedToken("corrupt base64url body"))?,
        );
        if body.len() < 4 || body[0] != FORMAT_VERSION {
            return Err(SessionFenceError::MalformedToken("invalid frame prefix"));
        }
        let mut mac = [0u8; MAC_LEN];
        if URL_SAFE_NO_PAD.decode_slice(mac_b64, &mut mac).ok() != Some(MAC_LEN) {
            return Err(SessionFenceError::MalformedToken("corrupt base64url mac"));
        }
        let key_id = body[1];
        let key_bytes = self.keys[key_id as usize].as_ref().ok_or(SessionFenceError::ForgedOrInvalidToken)?;
        if hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, &key_bytes[..]), &mac_transcript(key_id, &body), &mac)
            .is_err()
        {
            return Err(SessionFenceError::ForgedOrInvalidToken);
        }
        let bound: RaftSessionLowerBound =
            serde_json::from_slice(&body[2..]).map_err(|_| SessionFenceError::MalformedToken("corrupt frame json"))?;
        if bound.key_id != key_id
            || !(MIN_LIFETIME_SECONDS..=MAX_LIFETIME_SECONDS).contains(&bound.lifetime_seconds)
            || bound.raft_log_index == 0
            || bound.repo_ref_version < 1
            || bound.issued_unix < 0
        {
            return Err(SessionFenceError::ForgedOrInvalidToken);
        }
        bound.realm.validate()?;
        if now_unix < bound.issued_unix
            || now_unix >= bound.issued_unix.saturating_add(i64::from(bound.lifetime_seconds))
        {
            return Err(SessionFenceError::Expired);
        }
        if &bound.realm != live_realm {
            return Err(SessionFenceError::RealmMismatch);
        }
        Ok(bound)
    }
}

pub fn current_unix_seconds() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

fn check_access(access: CallerAccessState) -> Result<(), SessionFenceError> {
    if !access.authenticated {
        return Err(SessionFenceError::Unauthenticated);
    }
    if !access.has_read_permission {
        return Err(SessionFenceError::PermissionDenied);
    }
    Ok(())
}

async fn sleep_before(deadline: Instant, poll_interval: Duration) -> bool {
    let now = Instant::now();
    if now >= deadline {
        return false;
    }
    tokio::time::sleep(poll_interval.min(deadline.saturating_duration_since(now))).await;
    true
}

pub fn evaluate_raft_read(
    access: CallerAccessState,
    codec: &RaftSessionCodec,
    proof: &RaftReadProof,
    presented_token: Option<&str>,
    now_unix: i64,
) -> Result<AdmittedRaftRead, SessionFenceError> {
    check_access(access)?;
    assert_authoritative_source(proof.source)?;
    proof.realm.validate()?;
    if !proof.pin_closure_intact {
        return Err(SessionFenceError::AuthorityViolation("pin or packed OID closure integrity check failed"));
    }
    if proof.committed_log_index == 0 || proof.last_applied_log_index == 0 || proof.repo_ref_version < 1 {
        return Err(SessionFenceError::BehindLowerBound {
            required_log_index: 1,
            required_repo_ref_version: 1,
            observed_log_index: proof.committed_log_index.min(proof.last_applied_log_index),
            observed_repo_ref_version: proof.repo_ref_version,
        });
    }
    let presented_bound = match presented_token {
        Some(raw) => {
            let bound = codec.verify_token(raw, &proof.realm, now_unix)?;
            bound.satisfies(
                proof.committed_log_index,
                proof.last_applied_log_index,
                proof.repo_ref_version,
                &proof.realm,
            )?;
            Some(bound)
        }
        None => None,
    };
    let (next_log_index, next_version) = match &presented_bound {
        Some(b) => (proof.last_applied_log_index.max(b.raft_log_index), proof.repo_ref_version.max(b.repo_ref_version)),
        None => (proof.last_applied_log_index, proof.repo_ref_version),
    };
    let session_token = codec.mint_token(&proof.realm, next_log_index, next_version, now_unix)?;
    Ok(AdmittedRaftRead {
        realm: proof.realm.clone(),
        committed_log_index: proof.committed_log_index,
        last_applied_log_index: proof.last_applied_log_index,
        repo_ref_version: proof.repo_ref_version,
        session_token,
        leader_id: proof.leader_id,
        state_digest_hex: proof.state_digest_hex.clone(),
    })
}

pub async fn await_raft_read_or_redirect<F, Fut>(
    access: CallerAccessState,
    codec: &RaftSessionCodec,
    presented_token: Option<&str>,
    wait_budget: Duration,
    poll_interval: Duration,
    max_redirects: usize,
    mut probe: F,
) -> Result<AdmittedRaftRead, SessionFenceError>
where
    F: FnMut(Option<u64>) -> Fut,
    Fut: Future<Output = Result<RaftProbeOutcome, SessionFenceError>>,
{
    check_access(access)?;
    let deadline = Instant::now() + wait_budget;
    let mut target_leader: Option<u64> = None;
    let mut redirects = 0usize;
    loop {
        if !wait_budget.is_zero() && Instant::now() >= deadline {
            return Err(SessionFenceError::QuorumUnavailable("raft ReadIndex wait budget exceeded".into()));
        }
        let outcome = timeout_at(deadline, probe(target_leader))
            .await
            .map_err(|_| SessionFenceError::QuorumUnavailable("raft ReadIndex wait budget exceeded".into()))??;
        match outcome {
            RaftProbeOutcome::Ready(proof) => {
                if !wait_budget.is_zero() && Instant::now() > deadline {
                    return Err(SessionFenceError::QuorumUnavailable("raft ReadIndex wait budget exceeded".into()));
                }
                match evaluate_raft_read(access, codec, &proof, presented_token, current_unix_seconds()) {
                    Ok(admitted) => return Ok(admitted),
                    Err(err @ SessionFenceError::BehindLowerBound { .. }) => {
                        if !sleep_before(deadline, poll_interval).await {
                            return Err(err);
                        }
                    }
                    Err(fatal) => return Err(fatal),
                }
            }
            RaftProbeOutcome::ForwardToLeader(leader_id) => {
                if redirects >= max_redirects || Instant::now() >= deadline {
                    let msg = format!("leader redirect budget exhausted targeting node {leader_id}");
                    return Err(SessionFenceError::QuorumUnavailable(msg));
                }
                target_leader = Some(leader_id);
                redirects += 1;
            }
            RaftProbeOutcome::QuorumUnavailable(reason) => {
                if !sleep_before(deadline, poll_interval).await {
                    return Err(SessionFenceError::QuorumUnavailable(reason));
                }
            }
        }
    }
}

fn mac_transcript(key_id: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * 3 + TRANSCRIPT_DOMAIN.len() + 1 + body.len());
    for part in [TRANSCRIPT_DOMAIN, &[key_id][..], body] {
        let len = u16::try_from(part.len()).expect("bounded transcript slice");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}
