//! Incoming repository session lower-bound enforcement for JSON read routes
//! (#174).
//!
//! This is the only gateway place a presented `x-rootyard-session` header is
//! scored. Every caller invokes it only after the request's current actor was
//! authenticated and the repository was authorized by the live serving lookup
//! ([`ServingRepository`]), which it must be handed. Nothing here is cached:
//! every request reads its own gate, binding, capture and cluster authority
//! incarnation.
//!
//! Ordering of one read request:
//!
//! 1. authenticate the actor and authorize the repository (`lookup`);
//! 2. inspect the header (duplicate/non-text refused; without a key set, only
//!    the presence of any occurrence is inspected, and it is a `501`);
//! 3. capture the ref view; its cluster authority incarnation must be the
//!    authorized lookup's own value or the refusal is a generic `503`. This
//!    anchor check is unconditional: it applies whether or not a key set is
//!    configured and whether or not the request presented a header, because it
//!    gates materialization, not the token verdict;
//! 4. only after that anchor check, and before any Blob/native materialization,
//!    score a presented header against the authorized realm (with the capture's
//!    incarnation) and the revision the capture actually locked through the
//!    single `SessionTokens::verify`/`compare` boundary. Without a key set there
//!    is nothing to verify and step 4 is skipped.
//!
//! Every refusal after capture releases the transient capture through the
//! bounded `snapshot::release_view` path before it is returned. A refusal never
//! invites dropping the bound: `Behind` stays a `503` with the same guidance,
//! a foreign/restored realm and a malformed header are both a generic `400`.
//!
//! Issuance is the mirror image and lives in `browse::finalize`: after the body
//! is encoded it re-reads the authorized lookup once and applies the same
//! unconditional capture-incarnation fence ([`verify_capture_anchor`]) before a
//! token may be signed from the sealed proof.
use axum::http::HeaderMap;
use uuid::Uuid;

use super::{
    error::GatewayError,
    repo_session::{
        AuthorityKind, BEHIND_MESSAGE, Presented, SESSION_HEADER, SessionRealm, SessionRealmFields, SessionTokens,
        VersionComparison, presented,
    },
    serving::ServingRepository,
    snapshot::{self, RefView},
    state::BlobGitState,
};
use crate::ref_store::core::pack_snapshot::MaterializedServingRead;

/// Keyring absent: the gateway cannot judge any lower bound.
pub(super) const SESSIONS_DISABLED: &str = "repository session tokens are not configured on this gateway";

/// The single generic, retryable refusal for a restore rotation observed
/// between the lookup/token verdict and the capture. It names no incarnation.
pub(super) const AUTHORITY_CHANGED: &str =
    "repository authority changed after the read view was authorized; retry the same request";

/// Inspect the presented header after the authorized lookup and before any
/// capture or materialization. With a key set, duplicates/non-text values are
/// refused (the frame is scored later, against the captured revision); without
/// one, only the *presence* of any occurrence is inspected and any presented
/// header is the explicit `501`. The authorized `serving` argument is the
/// ordering guard: no header error can be produced before the lookup succeeded.
pub(super) fn admit(
    tokens: Option<&SessionTokens>,
    headers: &HeaderMap,
    serving: &ServingRepository,
) -> Result<(), GatewayError> {
    let Some(_) = tokens else {
        if headers.get_all(SESSION_HEADER).iter().next().is_some() {
            return Err(GatewayError::NotImplemented(SESSIONS_DISABLED));
        }
        return Ok(());
    };
    // Header admission comes first: no token-free request may be refused by a
    // realm limit that only matters to a token it did not present.
    if matches!(presented(headers).map_err(|error| error.for_repo())?, Presented::None) {
        return Ok(());
    }
    live_realm(serving, serving.cluster_incarnation).map(|_| ())
}

/// Capture the ref view and require it to belong to the cluster authority
/// incarnation the authorization was made under, then score the header against
/// the *captured* revision (never the lookup's). Any refusal releases the
/// capture through [`snapshot::release_view`] and never materializes.
pub(super) async fn capture(
    state: &BlobGitState,
    headers: &HeaderMap,
    serving: &ServingRepository,
    deadline: tokio::time::Instant,
) -> Result<RefView, GatewayError> {
    let view = snapshot::load_ref_view(state, serving, deadline).await?;
    let verdict = match snapshot::capture_gate_revision(&view) {
        Some(captured_revision) => {
            answer(snapshot::capture_incarnation(&view), state.sessions(), headers, serving, captured_revision)
        }
        None => Err(GatewayError::Unavailable(AUTHORITY_CHANGED)),
    };
    if let Err(error) = verdict {
        snapshot::release_view(state, &view, deadline).await;
        return Err(error);
    }
    Ok(view)
}

/// The pure verdict for one loaded capture. The capture's own cluster anchor is
/// checked first and unconditionally: a missing, nil or rotated anchor refuses
/// with [`AUTHORITY_CHANGED`] before the key set or the header is considered, so
/// a token-disabled or token-free read can never materialize a view captured in
/// another incarnation. Only after that anchor matches is a presented header
/// scored (when a key set exists) against the authorized realm bound to the
/// *captured* incarnation and the revision the capture actually locked.
fn answer(
    captured_incarnation: Option<Uuid>,
    tokens: Option<&SessionTokens>,
    headers: &HeaderMap,
    serving: &ServingRepository,
    captured_revision: i64,
) -> Result<(), GatewayError> {
    let captured = captured_incarnation
        .filter(|captured| !captured.is_nil() && *captured == serving.cluster_incarnation)
        .ok_or(GatewayError::Unavailable(AUTHORITY_CHANGED))?;
    let Some(tokens) = tokens else { return Ok(()) };
    // Inspect the header before constructing the realm. A token-free read must
    // stay token-free even when the live realm cannot be represented (for
    // example an otherwise valid epoch the old i32 frame bound refused).
    let header = presented(headers).map_err(|error| error.for_repo())?;
    if matches!(header, Presented::None) {
        return Ok(());
    }
    let realm = live_realm(serving, captured)?;
    match tokens.verify(&header, &realm, captured_revision).map_err(|error| error.for_repo())? {
        None | Some(VersionComparison::Satisfied { .. }) => Ok(()),
        // An authentic same-realm token bound above the captured revision must
        // never be served from this older view; the bound is kept, never exposed.
        Some(VersionComparison::Behind { .. }) => Err(GatewayError::Unavailable(BEHIND_MESSAGE)),
    }
}

/// The final restore/incarnation fence shared by every successful JSON read
/// (`browse::finalize`), applied after the body was encoded and a fresh
/// authorized lookup succeeded.
///
/// It is unconditional: a missing, nil or rotated anchor refuses with
/// [`AUTHORITY_CHANGED`] whether or not a key set is configured and whether or
/// not a token is issued. The fresh lookup raised its own read authorization
/// error before this fence is consulted. A `Some` view must carry a proof bound
/// to this same anchor (a proof is the only thing a token may be signed from);
/// a `None` view has no proof (a checked empty capture), which never issues.
/// The proof's full realm (including that incarnation) is then compared by the
/// caller against this same fresh lookup, and the issuance decision repeats the
/// proof-vs-anchor check, so no path reaches signing outside this fence.
pub(super) fn verify_capture_anchor(
    anchor: Option<Uuid>,
    read: Option<&MaterializedServingRead>,
    serving: &ServingRepository,
) -> Result<Uuid, GatewayError> {
    let anchor = anchor.filter(|anchor| !anchor.is_nil()).ok_or(GatewayError::Unavailable(AUTHORITY_CHANGED))?;
    if anchor != serving.cluster_incarnation {
        return Err(GatewayError::Unavailable(AUTHORITY_CHANGED));
    }
    if let Some(read) = read
        && read.proof().cluster_incarnation() != anchor
    {
        return Err(GatewayError::Unavailable(AUTHORITY_CHANGED));
    }
    Ok(anchor)
}

/// The full realm of an authorized serving lookup bound to the incarnation the
/// capture actually locked. Every field is re-checked by [`SessionRealm::new`],
/// so a nil/non-canonical live value is never compared.
fn live_realm(serving: &ServingRepository, captured: Uuid) -> Result<SessionRealm, GatewayError> {
    let gate = &serving.gate;
    SessionRealm::new(SessionRealmFields {
        tenant_id: gate.tenant_id(),
        repository_id: gate.repository_id(),
        object_format: gate.object_format(),
        history_incarnation: gate.history_incarnation(),
        authority: AuthorityKind::PgRefStore,
        authority_epoch: gate.authority_epoch(),
        group_id: super::repo_session::STANDALONE_GROUP_ID,
        group_epoch: gate.group_epoch(),
        cluster_incarnation: captured,
    })
    .map_err(|error| error.for_repo())
}

#[cfg(test)]
mod tests;
