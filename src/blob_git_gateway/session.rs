//! Request authentication, operation identity and protocol header admission.
//!
//! Authentication happens before any Blob/native IO. The operation identifier
//! may come from the `X-Rootyard-Operation` header or the `operation` query
//! parameter; whichever is used is echoed on the response so an unknown outcome
//! can be resolved later instead of blindly retried. Multiple or conflicting
//! values are refused rather than guessed.
//!
//! A read view is captured together with the exact realm that authorized it
//! ([`ReadAuthorization`]). The Smart-HTTP read path revalidates that realm and
//! the caller's *current* token/RBAC/scope/backend immediately before it admits
//! the first advertisement or body byte, and the native streaming worker polls
//! the same guard independently of a slow client. A ref revision may advance
//! while an older captured view is still being served; that is valid as long as
//! the realm does not change. A revocation, membership removal, scope narrowing
//! or backend re-binding aborts the stream instead.
//!
//! The `401` challenge is a transport decision downstream of this credential
//! check, never an authorization grant. [`GatewayError`] itself renders no
//! challenge. The gateway router adds Bearer only to its own `/api/repos` group
//! and Basic to Smart HTTP; the merged shared `/api/tokens` and `/api/sessions`
//! routes deliberately keep the shared application's existing Basic challenge.
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, StatusCode, Uri};
use tokio::time::Instant;
use uuid::Uuid;

use super::{
    error::GatewayError,
    serving::{ServingRepository, lookup},
    state::BlobGitState,
};
use crate::{db::Identity, ref_store::core::GitObjectFormat};

pub(super) async fn authenticate(state: &BlobGitState, headers: &HeaderMap) -> Result<Identity, GatewayError> {
    tokio::time::timeout_at(state.deadline(), crate::auth::authenticate(state.pool(), headers))
        .await
        .map_err(|_| GatewayError::Timeout)?
        .map_err(GatewayError::from)
}

pub(super) fn authorize_write(identity: &Identity) -> Result<(), GatewayError> {
    crate::auth::writable(identity).map_err(GatewayError::from)
}

/// Map a shared authorization error without re-labelling a read denial as a
/// missing write permission. The underlying vocabulary is static, so this
/// exposes no SQL/token/provider detail.
pub(super) fn authority_error(error: crate::Error) -> GatewayError {
    match error.0 {
        StatusCode::UNAUTHORIZED => GatewayError::Unauthorized,
        StatusCode::FORBIDDEN => GatewayError::Forbidden("repository authorization is no longer valid"),
        StatusCode::NOT_FOUND => GatewayError::NotFound,
        StatusCode::CONFLICT => GatewayError::Conflict("repository is not ready"),
        _ => GatewayError::from(error),
    }
}

/// The durable authority realm that produced one captured read view.
///
/// It deliberately excludes the gate revision/digest: a ref commit changes
/// those while an older captured snapshot remains a valid, consistent view. A
/// history/authority/group epoch change, a different repository/owner/object
/// format, a backend change, revocation or a lost grant all invalidate it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapturedRealm {
    repository_id: Uuid,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
}

impl CapturedRealm {
    fn of(serving: &ServingRepository) -> Self {
        Self {
            repository_id: serving.gate.repository_id(),
            tenant_id: serving.gate.tenant_id(),
            object_format: serving.gate.object_format(),
            history_incarnation: serving.gate.history_incarnation(),
            authority_epoch: serving.gate.authority_epoch(),
            group_epoch: serving.gate.group_epoch(),
        }
    }

    fn matches(&self, serving: &ServingRepository) -> bool {
        let gate = &serving.gate;
        self.repository_id == gate.repository_id()
            && self.tenant_id == gate.tenant_id()
            && self.object_format == gate.object_format()
            && self.history_incarnation == gate.history_incarnation()
            && self.authority_epoch == gate.authority_epoch()
            && self.group_epoch == gate.group_epoch()
    }
}

/// Read-only authorization bound to one captured repository view.
///
/// It carries the authenticated actor identity (whose private token verifier
/// digest is never serialized) and the repository/realm facts. It exposes no
/// scope grant, raw token or Blob capability. The native upload-pack stream
/// owns a clone and re-runs the shared lookup against the live token, RBAC,
/// read scope, ready binding and the actually opened Blob backend; it never
/// reuses the allow decision made before materialization.
#[derive(Clone)]
pub(super) struct ReadAuthorization {
    state: Arc<BlobGitState>,
    actor: Identity,
    owner: String,
    name: String,
    realm: CapturedRealm,
}

/// Capture the read authorization/realm of an already-authorized serving
/// lookup. This performs no IO and grants nothing; [`ReadAuthorization::revalidate`]
/// is the decision point.
pub(super) fn read_authorization(
    state: Arc<BlobGitState>,
    actor: &Identity,
    serving: &ServingRepository,
) -> ReadAuthorization {
    ReadAuthorization {
        state,
        actor: actor.clone(),
        owner: serving.repository.owner.clone(),
        name: serving.repository.name.clone(),
        realm: CapturedRealm::of(serving),
    }
}

impl ReadAuthorization {
    /// Re-run the complete shared read authority (live token, RBAC, contents
    /// read scope, ready exact binding, configured Blob backend) and require the
    /// same realm as the captured view.
    ///
    /// [`lookup`] owns one short, deadline-bounded transaction and rolls it
    /// back before it returns, so no PostgreSQL client is held while the caller
    /// materializes Blob/Git data afterwards.
    pub(super) async fn revalidate(&self, deadline: Instant) -> Result<(), GatewayError> {
        self.revalidate_serving(deadline).await.map(|_| ())
    }

    /// [`Self::revalidate`] that also returns the fresh authorized lookup, so a
    /// caller can fence the cluster authority incarnation that lookup just read
    /// (session issuance) and nothing else.
    pub(super) async fn revalidate_serving(&self, deadline: Instant) -> Result<ServingRepository, GatewayError> {
        let serving = lookup(
            self.state.pool(),
            &self.actor,
            &self.owner,
            &self.name,
            false,
            self.state.store().backend_identity(),
            deadline,
        )
        .await
        .map_err(authority_error)?;
        self.ensure_same_realm(&serving)?;
        Ok(serving)
    }

    /// Compare a fresh serving lookup with the captured realm without doing
    /// additional IO. Used by the write advertisement, which performs its own
    /// fresh `writable` lookup before the first advertisement byte.
    pub(super) fn ensure_same_realm(&self, serving: &ServingRepository) -> Result<(), GatewayError> {
        if self.realm.matches(serving) {
            Ok(())
        } else {
            Err(GatewayError::Conflict("repository authority changed after the read view was captured; retry"))
        }
    }
}

/// Resolve the stable operation identifier. A fresh random id is minted only
/// when the caller supplied none, and it is returned in the response header; the
/// caller must reuse it to resolve an unknown outcome.
pub(super) fn operation_id(headers: &HeaderMap, uri: &Uri) -> Result<Uuid, GatewayError> {
    let header_value = single_header(headers, "x-rootyard-operation")?;
    let query_value = query_parameter(uri, "operation")?;
    let raw = match (header_value, query_value) {
        (Some(header), Some(query)) if header != query => {
            return Err(GatewayError::BadRequest("conflicting operation identifiers"));
        }
        (Some(value), _) | (None, Some(value)) => value,
        (None, None) => return Ok(Uuid::new_v4()),
    };
    let operation = Uuid::parse_str(&raw).map_err(|_| GatewayError::BadRequest("invalid operation identifier"))?;
    if operation.is_nil() {
        return Err(GatewayError::BadRequest("invalid operation identifier"));
    }
    Ok(operation)
}

fn single_header(headers: &HeaderMap, name: &'static str) -> Result<Option<String>, GatewayError> {
    let name = HeaderName::from_static(name);
    let mut values = headers.get_all(&name).iter();
    let Some(first) = values.next() else { return Ok(None) };
    if values.next().is_some() {
        return Err(GatewayError::BadRequest("duplicate operation identifier header"));
    }
    first
        .to_str()
        .map(|value| Some(value.to_owned()))
        .map_err(|_| GatewayError::BadRequest("operation identifier header is not text"))
}

fn query_parameter(uri: &Uri, key: &str) -> Result<Option<String>, GatewayError> {
    let Some(query) = uri.query() else { return Ok(None) };
    let mut found = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name != key {
            continue;
        }
        if found.is_some() {
            return Err(GatewayError::BadRequest("duplicate operation identifier parameter"));
        }
        found = Some(value.to_owned());
    }
    Ok(found)
}

pub(super) fn validate_git_protocol(headers: &HeaderMap) -> Result<(), GatewayError> {
    match headers.get("git-protocol").and_then(|value| value.to_str().ok()) {
        None | Some("version=0") | Some("version=1") | Some("version=2") => Ok(()),
        Some(_) => Err(GatewayError::BadRequest("unsupported Git protocol version")),
    }
}

/// Exact `Git-Protocol` environment value for the native upload-pack child.
pub(super) fn git_protocol(headers: &HeaderMap) -> Option<&'static str> {
    match headers.get("git-protocol").and_then(|value| value.to_str().ok()) {
        Some("version=2") => Some("version=2"),
        Some("version=1") => Some("version=1"),
        _ => None,
    }
}
