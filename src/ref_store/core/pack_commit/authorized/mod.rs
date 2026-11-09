//! Authorized (decision-gated) publication pipeline — PostgreSQL stages.
//!
//! This module is the only place where a *decision-authorized* ref publication is
//! assembled. It owns the transaction shape; it owns **no** authorization, policy,
//! fact or proof logic. Those come from the decision owner
//! (`publication_decision::*`) and the native/subset owner
//! (`pack_commit::facts` / `SelectedPackPlan` / `PackClosureProof`), and the calls
//! are direct concrete calls — there is no trait adapter to implement.
//!
//! Staged API (Root-frozen):
//!
//! | stage | entry point | PostgreSQL | native/Blob |
//! | --- | --- | --- | --- |
//! | 1 | [`PgAuthorizedCommit::prepare`] | one short read-only tx | none |
//! | 2 | [`PgAuthorizedCommit::select`] | one short write tx (`select_and_install`) | facts gathered before the tx |
//! | 3 | `verify` | one short read tx | final closure outside PG |
//! | 4 | `commit` | one short write tx | none |
//!
//! [`PgAuthorizedCommit::cancel`] writes the real migration-138 cancellation
//! tombstone and the decision tombstone in one short transaction (the decision
//! module performs both under the operation advisory key, so exactly one terminal
//! wins).
//!
//! Guarantees that hold for every stage:
//!
//! * the original [`PackCommitPlan`] identity/digest/operation id is never
//!   re-derived or replaced (no fake A4 projection parent);
//! * a PG client is never held across Blob/native work: stages 1 and 2 release the
//!   pooled client before stage 3 starts, and stage 3 completes before stage 4
//!   opens a transaction;
//! * every mutating transaction sets `SET LOCAL synchronous_commit = 'on'`, and an
//!   ambiguous `COMMIT` stays [`PackCommitError::CommitUnknown`];
//! * the irreversible per-repository `decision_required` fence is enabled in the
//!   same transaction that installs the decision, so a fresh legacy metadata/A4
//!   write can no longer bypass it (exact 138 terminal replay keeps working);
//! * no public constructor here grants a decision, a token check, a fact, a proof
//!   or a protocol realm: every stage re-reads real durable state.
//!
//! All four stages use the original operation identity and a sealed selection.
//! The final transaction consumes the decision together with the selected ref
//! effects and the durable terminal result.
mod cancel;
mod commit;
mod prepare;
mod select;
mod verify;

use super::contract::VERIFIER_DEADLINE_SECONDS;
use super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use super::plan::PackCommitPlan;
use crate::ref_store::contract::RefStoreError;
use deadpool_postgres::Pool;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::{Instant, timeout_at};

pub use cancel::{AuthorizedCancelOutcome, AuthorizedCancelReceipt};
pub use commit::AuthorizedCommitReceipt;
pub use prepare::{PrepareOutcome, PreparedPublication};
pub use select::AuthorizedSelection;
pub use verify::VerifiedAuthorizedPublication;

/// Public semantic commit mode of one authorized publication.
///
/// Constructing it grants nothing: it only selects the decision kind that
/// `publication_decision::select_and_install` applies. `Atomic` is the
/// decision-gated all-or-nothing publication; `AcceptedSubset` is the verified
/// per-ref filtered publication. The policy/authorization decision itself is
/// always taken by the decision module from live PostgreSQL state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizedCommitMode {
    Atomic,
    AcceptedSubset,
}

impl AuthorizedCommitMode {
    /// Map the public semantic mode onto the decision module's kind. The
    /// authorization/policy decision itself is always taken from live state.
    pub(super) fn decision_kind(self) -> crate::ref_store::core::publication_decision::DecisionKind {
        use crate::ref_store::core::publication_decision::DecisionKind;
        match self {
            Self::Atomic => DecisionKind::Atomic,
            Self::AcceptedSubset => DecisionKind::AcceptedSubset,
        }
    }
}

/// Public, lossless refusal vocabulary of the authorized pipeline.
///
/// It never contains a token, a token digest, raw authorization rows or any
/// caller-supplied text: literals come from the owning module.
#[derive(Debug)]
pub enum AuthorizedCommitError {
    /// The pack/registry/ref side refused (typed `PackCommitError` preserved).
    Pack(PackCommitError),
    /// Live authorization/policy denied the publication (`DenialCode` literal).
    Denied(&'static str),
    /// A required fact row could not be verified; fail closed.
    Unverifiable(&'static str),
    /// A frozen dependency lock was contended; retry the whole stage.
    Contended(&'static str),
    /// The decision/operation is already terminal (`state` literal).
    Terminal(&'static str),
    /// Retained quota backpressure.
    QuotaExceeded,
    /// Persisted rows are partial/rewritten/inconsistent.
    Ledger(&'static str),
    Database(String),
    Timeout,
}

impl AuthorizedCommitError {
    /// Stable machine-readable label for tests and receipts.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Pack(error) => error.rejection().map(|rejection| rejection.code.as_str()).unwrap_or("pack_commit"),
            Self::Denied(_) => "denied",
            Self::Unverifiable(_) => "unverifiable",
            Self::Contended(_) => "contended",
            Self::Terminal(_) => "terminal",
            Self::QuotaExceeded => "quota_exceeded",
            Self::Ledger(_) => "ledger",
            Self::Database(_) => "database",
            Self::Timeout => "timeout",
        }
    }

    /// True only for `COMMIT`-issued-but-unacknowledged outcomes, which must be
    /// resolved by querying the same operation identity (never retried blindly).
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Pack(error) if error.is_unknown())
    }
}

impl From<PackCommitError> for AuthorizedCommitError {
    fn from(error: PackCommitError) -> Self {
        Self::Pack(error)
    }
}

impl From<RefStoreError> for AuthorizedCommitError {
    fn from(error: RefStoreError) -> Self {
        Self::Pack(PackCommitError::from(error))
    }
}

impl std::fmt::Display for AuthorizedCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pack(error) => write!(formatter, "authorized publication: {error}"),
            Self::Denied(code) => write!(formatter, "authorized publication denied: {code}"),
            Self::Unverifiable(detail) => write!(formatter, "authorized publication unverifiable: {detail}"),
            Self::Contended(detail) => write!(formatter, "authorized publication lock contended: {detail}"),
            Self::Terminal(detail) => write!(formatter, "authorized publication terminal: {detail}"),
            Self::QuotaExceeded => formatter.write_str("authorized publication quota exceeded"),
            Self::Ledger(detail) => write!(formatter, "authorized publication ledger: {detail}"),
            Self::Database(detail) => write!(formatter, "authorized publication database: {detail}"),
            Self::Timeout => formatter.write_str("authorized publication deadline expired"),
        }
    }
}

impl std::error::Error for AuthorizedCommitError {}

/// Staged authorized-publication adapter.
///
/// It owns the live Blob store and the trusted Git binary used by the native
/// facts/closure stages. The constructor grants nothing: no token, no decision, no
/// pending row and no proof. Each stage re-checks the live realm/gate/CAS under
/// PostgreSQL locks and the decision stage re-reads the actual authorization and
/// policy.
#[derive(Clone)]
pub struct PgAuthorizedCommit {
    pub(super) store: crate::blob_store::opendal::BlobStore,
    pub(super) git_binary: PathBuf,
}

impl PgAuthorizedCommit {
    pub fn new(
        store: crate::blob_store::opendal::BlobStore,
        git_binary: PathBuf,
    ) -> Result<Self, AuthorizedCommitError> {
        super::PackVerifier::new(store.clone(), git_binary.clone())?;
        Ok(Self { store, git_binary })
    }

    /// Stage 1: capture the complete pre-write state of an **existing** durable
    /// pending operation for this exact original plan.
    ///
    /// One short read-only transaction on one pooled client: migration-138
    /// `begin` (exact terminal replay first), repository authority, gate realm,
    /// protocol realm, complete refs/HEAD/memberships and the durable
    /// same-parent registrations. The transaction is always rolled back and the
    /// pooled client is dropped before any native/Blob work happens.
    ///
    /// Typed refusals: a terminal operation returns [`PrepareOutcome::Replayed`]
    /// (historical data, never re-authorized, never blocked by the decision
    /// fence), a cancelled operation is `Rejected(Cancelled)`, a missing pending
    /// row is `Rejected(PendingMissing)` (this stage never creates one) and an
    /// unprovisioned protocol realm is the `Unsupported` refusal.
    pub async fn prepare(
        &self,
        pool: &Pool,
        plan: PackCommitPlan,
        deadline: Instant,
    ) -> Result<PrepareOutcome, AuthorizedCommitError> {
        let deadline = effective_deadline(deadline)?;
        let mut client = pooled_client(pool, deadline).await?;
        let outcome = {
            let tx = crate::ref_store::tx::begin_bounded(&mut client, deadline).await?;
            let captured = match timeout_at(deadline, prepare::prepare_in_tx(&tx, plan, deadline)).await {
                Ok(value) => value.map_err(AuthorizedCommitError::from),
                Err(_) => Err(AuthorizedCommitError::from(PackCommitError::from(RefStoreError::Timeout))),
            };
            let cleanup = timeout_at(deadline, tx.rollback()).await;
            match (captured, cleanup) {
                (Ok(outcome), Ok(Ok(()))) => Ok(outcome),
                (Ok(_), Ok(Err(_))) => Err(AuthorizedCommitError::from(PackCommitError::from(
                    RefStoreError::Database("authorized prepare transaction cleanup failed".into()),
                ))),
                (Ok(_), Err(_)) => Err(AuthorizedCommitError::from(PackCommitError::from(RefStoreError::Timeout))),
                (Err(error), _) => Err(error),
            }
        };
        drop(client);
        outcome
    }
}

/// Cleanup is bounded separately from work; a successful stage waits for it.
pub(super) async fn rollback(
    tx: tokio_postgres::Transaction<'_>,
    _deadline: Instant,
) -> Result<(), AuthorizedCommitError> {
    match timeout_at(Instant::now() + Duration::from_secs(2), tx.rollback()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(AuthorizedCommitError::Unverifiable("transaction cleanup failed")),
        Err(_) => Err(AuthorizedCommitError::Timeout),
    }
}

/// Clamp the caller deadline to the fixed verifier/stage ceiling. A deadline that
/// already expired is a typed `Timeout`, never a silently restarted stage.
pub(super) fn effective_deadline(deadline: Instant) -> Result<Instant, AuthorizedCommitError> {
    let ceiling = Instant::now() + Duration::from_secs(VERIFIER_DEADLINE_SECONDS);
    let deadline = deadline.min(ceiling);
    if deadline <= Instant::now() {
        return Err(AuthorizedCommitError::Timeout);
    }
    Ok(deadline)
}

/// Take exactly one pooled client with the caller's effective deadline. The
/// returned client is owned by one stage only and is dropped before native work.
pub(super) async fn pooled_client(
    pool: &Pool,
    deadline: Instant,
) -> Result<deadpool_postgres::Client, AuthorizedCommitError> {
    let pool = pool.clone();
    match timeout_at(deadline, pool.get()).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(_)) => Err(AuthorizedCommitError::from(PackCommitError::from(RefStoreError::Unsupported(
            "authorized commit PostgreSQL pool is unavailable",
        )))),
        Err(_) => Err(AuthorizedCommitError::Timeout),
    }
}

/// Map one decisions-owner refusal onto the public pipeline vocabulary without
/// losing the stable literal.
pub(super) fn decision_error(
    error: crate::ref_store::core::publication_decision::DecisionError,
) -> AuthorizedCommitError {
    use crate::ref_store::core::publication_decision::DecisionError as Decision;
    match error {
        Decision::RefStore(error) => AuthorizedCommitError::from(error),
        Decision::Denied(code) => AuthorizedCommitError::Denied(code.as_str()),
        Decision::Unverifiable(detail) => AuthorizedCommitError::Unverifiable(detail),
        Decision::Contended(detail) => AuthorizedCommitError::Contended(detail),
        Decision::DecisionNotFound(_) => AuthorizedCommitError::Terminal("decision_not_found"),
        Decision::DecisionConflict { state, .. } => AuthorizedCommitError::Terminal(state.as_str()),
        Decision::Cancelled { .. } => AuthorizedCommitError::Terminal("cancelled"),
        Decision::Consumed { .. } => AuthorizedCommitError::Terminal("consumed"),
        Decision::QuotaExceeded { .. } => AuthorizedCommitError::QuotaExceeded,
        Decision::Ledger(detail) => AuthorizedCommitError::Ledger(detail),
        Decision::Database(detail) => AuthorizedCommitError::Database(detail),
        Decision::Timeout => AuthorizedCommitError::Timeout,
    }
}

/// Refusal helper shared by the stages.
pub(super) fn reject(code: PackCommitRejectCode, detail: &'static str) -> AuthorizedCommitError {
    AuthorizedCommitError::Pack(PackCommitError::Rejected(PackCommitRejection::new(code, detail)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn stage_deadline_is_clamped_and_never_restarted() {
        assert!(effective_deadline(Instant::now()).is_err());
        let far = Instant::now() + Duration::from_secs(3600);
        let clamped = effective_deadline(far).expect("a future deadline is accepted");
        assert!(clamped <= Instant::now() + Duration::from_secs(VERIFIER_DEADLINE_SECONDS + 1));
    }

    #[test]
    fn public_vocabulary_is_stable_and_secret_free() {
        let error = reject(PackCommitRejectCode::Cancelled, "cancellation tombstone won");
        assert_eq!(error.code(), "cancelled");
        assert!(!error.is_unknown());
        assert!(!format!("{error}").contains("token"));
        let unknown = AuthorizedCommitError::from(PackCommitError::CommitUnknown {
            repository_id: Uuid::nil(),
            operation_id: Uuid::nil(),
        });
        assert!(unknown.is_unknown());
        assert_eq!(AuthorizedCommitError::QuotaExceeded.code(), "quota_exceeded");
    }
}
