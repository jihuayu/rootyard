//! Pre-native operation identity and typed terminal replay.
//!
//! The receive path must answer one question **before** it runs a native child
//! or any A3/A4 write: is this `(repository, operation id, issuer)` already a
//! durable terminal, and does the exact request this caller sent match that
//! terminal? A pending operation is an unknown outcome (query later), never a
//! Git `ng`. A known terminal is replayed only from the persisted migration-138
//! result decoded by the core's own pack-commit receipt helper; no caller
//! boolean, local Git view or captured baseline is treated as proof.
//!
//! Two *different* digests exist and must never be confused:
//!
//! * the **producer** request digest of this gateway (decoded wire body bytes
//!   plus repository/operation/format/mode/commands), the only value an exact
//!   HTTP retry can be compared against, and
//! * the **core** canonical plan parent digest that migration 138 stores in
//!   `ref_store_operations.request_digest` and that every A3 receipt and stored
//!   registration is bound to.
//!
//! Migration 147 (`ref_store_serving_operations`) is the durable producer
//! binding. Exact replay compares the stored *producer* digest — never
//! `record.identity().digest()`, which is the core parent digest. A known
//! operation without a producer binding is a typed conflict and can never be
//! claimed as an ordinary Git result on this endpoint; a missing row is not a
//! fallback to "same commands" or to a weaker name-only comparison.
use std::{collections::BTreeSet, path::Path};

use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use crate::ref_store::{
    CommitMode, GitObjectFormat, OperationLookup, OperationRecord, OperationState, PgRefStore, RefCommitResult,
    RequestDigest, TerminalKind,
    core::pack_commit::{PackCommitTerminal, read_serving_operation},
};

use super::{error::GatewayError, native, protocol::PushRequest, state::BlobGitState};

/// Domain separator of the producer operation digest. Changing it invalidates
/// every durable producer digest, so it is versioned like any other contract.
const DIGEST_DOMAIN: &str = "blob-git-receive-wire-body-v1";

/// Result of the immutable pre-native operation probe.
#[derive(Debug)]
pub(super) enum Claim {
    /// No durable row: the caller may run the fresh native/A4 path.
    Fresh,
    /// A durable pack terminal for exactly this request; replay it.
    Replay(PackCommitTerminal),
    /// A durable cancellation tombstone with a verified ledger result.
    Cancelled(&'static str),
    /// Durably pending/in-flight: the outcome is unknown, never `ng`.
    Pending,
}

/// One durable operation record plus its separately stored producer binding.
///
/// The wrapper exists so classification can never accidentally compare against
/// the core plan parent digest: the only replay key is `producer_digest`, which
/// came from migration 147 and was validated against the very same migration-138
/// record (same issuer, same parent digest) inside one bounded read transaction.
#[derive(Debug)]
pub(super) struct ResolvedOperation {
    record: OperationRecord,
    producer_digest: RequestDigest,
}

/// Local lookup result. `Known` always carries a validated producer binding; a
/// known record without one is refused while loading (typed conflict).
#[derive(Debug)]
pub(super) enum Lookup {
    Known(ResolvedOperation),
    Unknown,
}

/// Compute the operation-level request digest over the **decoded** wire body.
///
/// `body` is the already-spooled Smart-HTTP body (after any gzip/x-gzip decode
/// performed by the native spooler). Hashing is bounded asynchronous file IO;
/// the pack is never buffered in memory.
pub(super) async fn request_digest(
    repository_id: Uuid,
    operation_id: Uuid,
    format: GitObjectFormat,
    request: &PushRequest,
    mode: CommitMode,
    body: &Path,
    deadline: Instant,
) -> Result<RequestDigest, GatewayError> {
    let (body_sha256, body_len) =
        timeout_at(deadline, native::file_digest(body)).await.map_err(|_| GatewayError::Timeout)??;
    Ok(digest_from_parts(repository_id, operation_id, format, request, mode, &body_sha256, body_len))
}

/// Pure digest assembly split out so the identity contract is unit-testable
/// without touching a file. Every field is length-delimited by
/// [`RequestDigest::of`], so concatenation cannot be ambiguous.
fn digest_from_parts(
    repository_id: Uuid,
    operation_id: Uuid,
    format: GitObjectFormat,
    request: &PushRequest,
    mode: CommitMode,
    body_sha256: &str,
    body_len: u64,
) -> RequestDigest {
    let mut fields: Vec<Vec<u8>> = Vec::with_capacity(7 + request.commands.len() * 3);
    fields.push(repository_id.as_bytes().to_vec());
    fields.push(operation_id.as_bytes().to_vec());
    fields.push(format.as_str().as_bytes().to_vec());
    fields.push(mode.as_str().as_bytes().to_vec());
    fields.push(body_sha256.as_bytes().to_vec());
    fields.push(body_len.to_be_bytes().to_vec());
    fields.push((request.commands.len() as u64).to_be_bytes().to_vec());
    for command in &request.commands {
        fields.push(command.old.as_bytes().to_vec());
        fields.push(command.new.as_bytes().to_vec());
        fields.push(command.name.as_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of(DIGEST_DOMAIN, &parts)
}

/// Internal repository-scoped lookup of one typed operation record **and** its
/// durable producer binding.
///
/// Both rows are read in the same short read-only transaction on one pooled
/// client; the client is released before any native/Blob work. A missing
/// operation is `Unknown`, never an aborted result. A known operation without a
/// migration-147 binding (for example one written by an older library/A4 path)
/// is a typed conflict: it must never be replayed as a Git result here.
///
/// The transaction is also where the caller's serving authority is proven
/// (`serving::lookup_in_tx`: token, RBAC, repository `ready`, durable binding and
/// live gate), so a record can never be classified for a repository the caller
/// may not serve. The local row read itself is [`lookup_in_tx`].
pub(super) async fn lookup(
    state: &BlobGitState,
    serving: &crate::ref_store::serving::ServingRepository,
    actor: &crate::db::Identity,
    operation_id: Uuid,
    deadline: Instant,
) -> Result<Lookup, GatewayError> {
    let repository_id = serving.gate.repository_id();
    let mut client = state.pooled(deadline).await?;
    let tx = timeout_at(deadline, client.transaction())
        .await
        .map_err(|_| GatewayError::Timeout)?
        .map_err(|_| GatewayError::Internal("operation lookup transaction failed"))?;
    let fresh = crate::ref_store::serving::lookup_in_tx(
        &tx,
        actor,
        &serving.repository.owner,
        &serving.repository.name,
        true,
        state.store().backend_identity(),
        deadline,
    )
    .await
    .map_err(GatewayError::from)?;
    if fresh.gate.repository_id() != repository_id
        || crate::ref_store::core::RealmExpectation::from_gate(&fresh.gate)
            != crate::ref_store::core::RealmExpectation::from_gate(&serving.gate)
    {
        let _ = timeout_at(deadline, tx.rollback()).await;
        return Err(GatewayError::Conflict("repository authority changed; retry"));
    }
    let local = lookup_in_tx(&tx, repository_id, operation_id, deadline).await;
    let cleanup = timeout_at(deadline, tx.rollback()).await;
    drop(client);
    match cleanup {
        Err(_) => return Err(GatewayError::Timeout),
        Ok(Err(_)) => return Err(GatewayError::Internal("operation lookup cleanup failed")),
        Ok(Ok(())) => {}
    }
    local
}

/// Local half of the probe: the typed operation record and its migration-147
/// producer binding read inside a **caller-owned** transaction.
///
/// This helper performs no authorization and no repository resolution; it is
/// only valid when the caller's transaction is already authorized for exactly
/// this repository. That is true both for the authorized read probe above and
/// for the gateway's fresh write transaction, whose earlier authorized probe on
/// this same request has completed (so the write transaction must not take a
/// second repository read lock).
///
/// `Unknown` means no operation row. A known record without a producer binding
/// is a typed conflict, never a replay. The binding's stored parent digest is
/// compared against the very record read above: the A3 invariant makes it equal
/// to `identity.digest()`, so a binding that disagrees names a different
/// operation than the one being classified.
pub(super) async fn lookup_in_tx(
    tx: &tokio_postgres::Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
    deadline: Instant,
) -> Result<Lookup, GatewayError> {
    match PgRefStore.get(tx, repository_id, operation_id, deadline).await.map_err(GatewayError::from)? {
        OperationLookup::Unknown => Ok(Lookup::Unknown),
        OperationLookup::Known(record) => {
            let Some(binding) =
                read_serving_operation(tx, repository_id, operation_id, deadline).await.map_err(GatewayError::from)?
            else {
                return Err(GatewayError::Conflict(
                    "operation has no durable producer request binding; it cannot be replayed from this endpoint",
                ));
            };
            if binding.parent_digest() != record.identity().digest() {
                return Err(GatewayError::Internal(
                    "serving producer binding parent digest differs from its operation record",
                ));
            }
            Ok(Lookup::Known(ResolvedOperation { record, producer_digest: *binding.producer_digest() }))
        }
    }
}

/// Query the immutable operation registry before native ingestion.
pub(super) async fn probe(
    state: &BlobGitState,
    serving: &crate::ref_store::serving::ServingRepository,
    actor: &crate::db::Identity,
    operation_id: Uuid,
    request: &PushRequest,
    digest: RequestDigest,
    deadline: Instant,
) -> Result<Claim, GatewayError> {
    let repository_id = serving.gate.repository_id();
    let issuer_id = actor.id;
    match lookup(state, serving, actor, operation_id, deadline).await? {
        Lookup::Unknown => Ok(Claim::Fresh),
        Lookup::Known(resolved) => classify(resolved, repository_id, issuer_id, operation_id, request, digest),
    }
}

/// Classify one already-fetched operation against this exact request.
///
/// Order matters and is part of the contract:
///
/// 1. the identity must be the one that was asked for;
/// 2. a foreign issuer is refused **before** any state or terminal is decoded,
///    so another issuer's receipt can never be observed;
/// 3. the stored *producer* digest must equal this request's digest before any
///    state is interpreted, so a different wire body is a conflict (409) and can
///    never inherit another request's pending "unknown" answer or terminal
///    replay;
/// 4. only then is the durable state resolved: exact pending stays an unknown
///    outcome, an exact cancelled tombstone replays as cancelled, and an exact
///    terminal replays through the core decoder.
pub(super) fn classify(
    resolved: ResolvedOperation,
    repository_id: Uuid,
    issuer_id: Uuid,
    operation_id: Uuid,
    request: &PushRequest,
    digest: RequestDigest,
) -> Result<Claim, GatewayError> {
    let ResolvedOperation { record, producer_digest } = resolved;
    let identity = record.identity();
    if identity.repository_id() != repository_id || identity.operation_id() != operation_id {
        return Err(GatewayError::Internal("operation lookup returned a foreign identity"));
    }
    if identity.issuer_id() != issuer_id {
        return Err(GatewayError::Forbidden("operation belongs to another issuer"));
    }
    // Exact replay is decided by the durable *producer* binding only. The core
    // parent digest in `identity.digest()` is a different value and is never a
    // substitute: it binds the A3 plan, not the HTTP wire request. Checking it
    // here (before the state match) makes a reused operation id with different
    // bytes a conflict even while the operation is still pending.
    if producer_digest != digest {
        return Err(GatewayError::Conflict("operation identifier was already used with a different request"));
    }
    match record.state() {
        // An exact pending row is an open outcome: the caller answers "unknown"
        // and never a Git `ng`/`ok`.
        OperationState::Pending => Ok(Claim::Pending),
        OperationState::Cancelled => match cancellation_reason(&record) {
            Some(reason) => Ok(Claim::Cancelled(reason)),
            None => Err(GatewayError::Internal("stored cancellation receipt is not a verified tombstone")),
        },
        OperationState::Committed | OperationState::Rejected => {
            let terminal = decode_terminal(&record, repository_id)?;
            match terminal_binding(&terminal, request)? {
                Binding::Mismatch => {
                    Err(GatewayError::Internal("stored operation receipt does not cover the replayed request"))
                }
                Binding::Exact | Binding::NamesOnly => Ok(Claim::Replay(terminal)),
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Binding {
    /// Every command is `Applied` with the exact old/new object ids.
    Exact,
    /// Every command name is covered, but at least one ref was not applied.
    NamesOnly,
    /// The persisted terminal does not cover this request.
    Mismatch,
}

/// Compare the persisted terminal with the wire command set.
///
/// The terminal is a trusted durable result; a duplicate ref, an `Applied` row
/// inside a rejection or a foreign repository is ledger corruption and fails
/// closed as an internal error (never a replayed `ok`).
fn terminal_binding(terminal: &PackCommitTerminal, request: &PushRequest) -> Result<Binding, GatewayError> {
    if terminal.refs.len() != request.commands.len() {
        return Ok(Binding::Mismatch);
    }
    let mut names = BTreeSet::new();
    if !terminal.refs.iter().all(|result| names.insert(result_name(result))) {
        return Err(GatewayError::Internal("stored operation receipt repeats a ref"));
    }
    let mut all_applied = !terminal.refs.is_empty();
    for command in &request.commands {
        let Some(result) = terminal.refs.iter().find(|result| result_name(result) == command.name) else {
            return Ok(Binding::Mismatch);
        };
        match result {
            RefCommitResult::Applied { old_oid, new_oid, .. } => {
                if terminal.kind != TerminalKind::Committed {
                    return Err(GatewayError::Internal("stored rejection receipt contains an applied ref"));
                }
                if old_oid.as_deref() != wire_oid(&command.old) || new_oid.as_deref() != wire_oid(&command.new) {
                    return Ok(Binding::Mismatch);
                }
            }
            RefCommitResult::NotApplied { .. } => all_applied = false,
        }
    }
    Ok(if all_applied { Binding::Exact } else { Binding::NamesOnly })
}

fn decode_terminal(record: &OperationRecord, repository_id: Uuid) -> Result<PackCommitTerminal, GatewayError> {
    let stored = record.terminal_result().ok_or(GatewayError::Internal("terminal operation has no ledger result"))?;
    let terminal = PackCommitTerminal::from_terminal_result(stored)
        .map_err(|_| GatewayError::Internal("stored operation result is not a pack commit terminal"))?;
    if terminal.repository_id != repository_id {
        return Err(GatewayError::Internal("stored operation receipt belongs to another repository"));
    }
    Ok(terminal)
}

/// The only cancellation ledger bodies `PgRefStore` writes. A `Cancelled` row
/// with any other body is not a verified tombstone and is never replayed.
fn cancellation_reason(record: &OperationRecord) -> Option<&'static str> {
    let value = record.terminal_result()?.value();
    let object = value.as_object()?;
    if object.get("state")?.as_str()? != "cancelled" {
        return None;
    }
    match object.get("reason")?.as_str()? {
        "cancel_before_register" => Some("operation was cancelled before registration"),
        "cancel_requested" => Some("operation was cancelled"),
        _ => None,
    }
}

pub(super) fn result_name(result: &RefCommitResult) -> &str {
    match result {
        RefCommitResult::Applied { name, .. } | RefCommitResult::NotApplied { name, .. } => name,
    }
}

/// A Git delete/create is an all-zero wire object id; the persisted terminal
/// uses `None` for that same case.
fn wire_oid(value: &str) -> Option<&str> {
    if value.bytes().all(|byte| byte == b'0') { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::super::protocol::PushCommand;
    use super::*;
    use crate::ref_store::{IssuerLane, OperationIdentity, TerminalResult};
    use serde_json::json;

    const OLD: &str = "1111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222";
    const ZERO: &str = "0000000000000000000000000000000000000000";

    fn repo() -> Uuid {
        Uuid::from_bytes([1; 16])
    }

    fn issuer() -> Uuid {
        Uuid::from_bytes([2; 16])
    }

    fn operation() -> Uuid {
        Uuid::from_bytes([3; 16])
    }

    fn command(old: &str, new: &str, name: &str) -> PushCommand {
        PushCommand { old: old.to_owned(), new: new.to_owned(), name: name.to_owned() }
    }

    fn request(commands: Vec<PushCommand>) -> PushRequest {
        PushRequest { commands, capabilities: vec!["report-status".to_owned()] }
    }

    fn main_request() -> PushRequest {
        request(vec![command(OLD, NEW, "refs/heads/main")])
    }

    fn identity(digest: RequestDigest) -> OperationIdentity {
        OperationIdentity::new(repo(), issuer(), IssuerLane::new("blob-git-receive").unwrap(), 1, operation(), digest)
            .unwrap()
    }

    fn digest(body: &str) -> RequestDigest {
        digest_from_parts(
            repo(),
            operation(),
            GitObjectFormat::Sha1,
            &main_request(),
            CommitMode::AcceptedSubset,
            body,
            128,
        )
    }

    fn committed_terminal(refs: Vec<RefCommitResult>) -> PackCommitTerminal {
        PackCommitTerminal {
            kind: TerminalKind::Committed,
            repository_id: repo(),
            revision: 2,
            head_ref: Some("refs/heads/main".to_owned()),
            mode: "pack_verified".to_owned(),
            refs,
            registrations: Vec::new(),
            rejection: None,
        }
    }

    fn make_record(
        identity: OperationIdentity,
        state: OperationState,
        terminal: Option<&PackCommitTerminal>,
        raw: Option<serde_json::Value>,
    ) -> OperationRecord {
        let result = match (terminal, raw) {
            (Some(terminal), _) => Some(TerminalResult::json(serde_json::to_value(terminal).unwrap()).unwrap()),
            (None, Some(raw)) => Some(TerminalResult::json(raw).unwrap()),
            (None, None) => None,
        };
        OperationRecord::new(identity, state, result).unwrap()
    }

    /// Pure classifier fixture: the stored *producer* binding is the digest of
    /// the fixture identity, exactly like a row written by migration 147 would
    /// carry the producer digest of the wire request. This is a unit fixture,
    /// not evidence of a native or durable run.
    fn resolved(
        identity: OperationIdentity,
        state: OperationState,
        terminal: Option<&PackCommitTerminal>,
        raw: Option<serde_json::Value>,
    ) -> ResolvedOperation {
        let producer_digest = *identity.digest();
        ResolvedOperation { record: make_record(identity, state, terminal, raw), producer_digest }
    }

    fn applied() -> RefCommitResult {
        RefCommitResult::Applied {
            name: "refs/heads/main".to_owned(),
            old_oid: Some(OLD.to_owned()),
            new_oid: Some(NEW.to_owned()),
        }
    }

    #[test]
    fn different_payload_with_the_same_operation_id_changes_the_digest() {
        let first = digest(&"a".repeat(64));
        let second = digest(&"b".repeat(64));
        assert_ne!(first, second, "the wire body must be bound into the digest");

        let other_operation = digest_from_parts(
            repo(),
            Uuid::from_bytes([9; 16]),
            GitObjectFormat::Sha1,
            &main_request(),
            CommitMode::AcceptedSubset,
            &"a".repeat(64),
            128,
        );
        assert_ne!(first, other_operation);

        let other_target = request(vec![command(OLD, ZERO, "refs/heads/main")]);
        let other_commands = digest_from_parts(
            repo(),
            operation(),
            GitObjectFormat::Sha1,
            &other_target,
            CommitMode::AcceptedSubset,
            &"a".repeat(64),
            128,
        );
        assert_ne!(first, other_commands);
    }

    #[test]
    fn pending_is_unknown_and_never_a_terminal() {
        let digest = digest(&"a".repeat(64));
        let record = resolved(identity(digest), OperationState::Pending, None, None);
        assert!(matches!(
            classify(record, repo(), issuer(), operation(), &main_request(), digest).unwrap(),
            Claim::Pending
        ));
    }

    #[test]
    fn pending_bound_to_another_wire_request_is_a_conflict_not_unknown() {
        let stored = digest(&"a".repeat(64));
        let incoming = digest(&"b".repeat(64));
        let record = resolved(identity(stored), OperationState::Pending, None, None);
        let error = classify(record, repo(), issuer(), operation(), &main_request(), incoming).unwrap_err();
        assert!(matches!(error, GatewayError::Conflict(_)), "unexpected {error:?}");
    }

    #[test]
    fn a_foreign_issuer_is_refused_before_the_pending_digest_check() {
        let stored = digest(&"a".repeat(64));
        let incoming = digest(&"b".repeat(64));
        let record = resolved(identity(stored), OperationState::Pending, None, None);
        let error =
            classify(record, repo(), Uuid::from_bytes([8; 16]), operation(), &main_request(), incoming).unwrap_err();
        assert_eq!(error, GatewayError::Forbidden("operation belongs to another issuer"));
    }

    #[test]
    fn the_producer_binding_is_the_only_replay_key_for_a_pending_row() {
        // The record's own core digest is deliberately different from the stored
        // producer digest: only the migration-147 value may decide exactness, and
        // a pending row bound to another producer request is a conflict, never
        // an "unknown" answer for this caller's request.
        let stored = digest(&"a".repeat(64));
        let record = ResolvedOperation {
            record: make_record(identity(stored), OperationState::Pending, None, None),
            producer_digest: digest(&"c".repeat(64)),
        };
        let error = classify(record, repo(), issuer(), operation(), &main_request(), stored).unwrap_err();
        assert!(matches!(error, GatewayError::Conflict(_)), "unexpected {error:?}");
    }

    #[test]
    fn an_exact_byte_terminal_replays_the_typed_report() {
        let digest = digest(&"a".repeat(64));
        let terminal = committed_terminal(vec![applied()]);
        let record = resolved(identity(digest), OperationState::Committed, Some(&terminal), None);
        match classify(record, repo(), issuer(), operation(), &main_request(), digest).unwrap() {
            Claim::Replay(replayed) => assert_eq!(replayed, terminal),
            _ => panic!("an exact committed terminal must replay"),
        }
    }

    #[test]
    fn a_different_payload_with_the_same_operation_id_is_a_conflict() {
        let stored = digest(&"a".repeat(64));
        let incoming = digest(&"b".repeat(64));
        let terminal = committed_terminal(vec![applied()]);
        let record = resolved(identity(stored), OperationState::Committed, Some(&terminal), None);
        let error = classify(record, repo(), issuer(), operation(), &main_request(), incoming).unwrap_err();
        assert!(matches!(error, GatewayError::Conflict(_)), "unexpected {error:?}");
    }

    #[test]
    fn a_terminal_that_does_not_cover_the_request_is_a_conflict() {
        let stored = digest(&"a".repeat(64));
        let terminal = committed_terminal(vec![RefCommitResult::Applied {
            name: "refs/heads/other".to_owned(),
            old_oid: Some(OLD.to_owned()),
            new_oid: Some(NEW.to_owned()),
        }]);
        let record = resolved(identity(stored), OperationState::Committed, Some(&terminal), None);
        let error =
            classify(record, repo(), issuer(), operation(), &main_request(), digest(&"a".repeat(64))).unwrap_err();
        assert!(matches!(error, GatewayError::Internal(_)), "unexpected {error:?}");
    }

    #[test]
    fn a_foreign_issuer_is_forbidden_before_any_terminal_decode() {
        let digest = digest(&"a".repeat(64));
        let terminal = committed_terminal(vec![applied()]);
        let record = resolved(identity(digest), OperationState::Committed, Some(&terminal), None);
        let error =
            classify(record, repo(), Uuid::from_bytes([8; 16]), operation(), &main_request(), digest).unwrap_err();
        assert_eq!(error, GatewayError::Forbidden("operation belongs to another issuer"));
    }

    #[test]
    fn cancellation_requires_a_verified_tombstone_body() {
        let digest = digest(&"a".repeat(64));
        let verified = json!({"state": "cancelled", "reason": "cancel_requested"});
        let record = resolved(identity(digest), OperationState::Cancelled, None, Some(verified));
        assert!(matches!(
            classify(record, repo(), issuer(), operation(), &main_request(), digest).unwrap(),
            Claim::Cancelled("operation was cancelled")
        ));

        let invented = json!({"state": "cancelled", "reason": "invented"});
        let record = resolved(identity(digest), OperationState::Cancelled, None, Some(invented));
        let error = classify(record, repo(), issuer(), operation(), &main_request(), digest).unwrap_err();
        assert!(matches!(error, GatewayError::Internal(_)), "unexpected {error:?}");
    }

    #[test]
    fn a_tombstone_bound_to_another_wire_request_never_replays_as_cancelled() {
        let stored = digest(&"a".repeat(64));
        let incoming = digest(&"b".repeat(64));
        let verified = json!({"state": "cancelled", "reason": "cancel_requested"});
        let record = resolved(identity(stored), OperationState::Cancelled, None, Some(verified));
        let error = classify(record, repo(), issuer(), operation(), &main_request(), incoming).unwrap_err();
        assert!(matches!(error, GatewayError::Conflict(_)), "unexpected {error:?}");
    }

    #[test]
    fn a_rejected_terminal_replays_names_only_without_claiming_success() {
        let digest = digest(&"a".repeat(64));
        let terminal = PackCommitTerminal {
            kind: TerminalKind::Rejected,
            repository_id: repo(),
            revision: 2,
            head_ref: Some("refs/heads/main".to_owned()),
            mode: "pack_verified".to_owned(),
            refs: vec![RefCommitResult::NotApplied {
                name: "refs/heads/main".to_owned(),
                reason: crate::ref_store::CommitRejectCode::OldOidMismatch,
            }],
            registrations: Vec::new(),
            rejection: None,
        };
        let record = resolved(identity(digest), OperationState::Rejected, Some(&terminal), None);
        match classify(record, repo(), issuer(), operation(), &main_request(), digest).unwrap() {
            Claim::Replay(replayed) => assert_eq!(replayed.kind, TerminalKind::Rejected),
            _ => panic!("a matching rejection receipt must replay as ng"),
        }
    }
}
