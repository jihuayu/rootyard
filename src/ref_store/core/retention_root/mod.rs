//! Durable **retention roots**: non-expiring, self-contained protection of an existing pack-verified snapshot.
//!
//! A root is not a renamed metadata pin. It owns immutable capture rows plus its own complete pack locator rows,
//! has no foreign key to `repositories`/`users`/`tenants`, and therefore survives source-pin expiry/release, source
//! snapshot pruning and a whole business-repository delete. It never mutates another operation's snapshot, pin,
//! membership, publication or hold, and it never deletes a Blob byte.
//!
//! | step | API |
//! | --- | --- |
//! | seal one existing snapshot as a candidate (T1 metadata + actual Blob/native closure) | [`PgRetentionRoots::prepare`] |
//! | commit the sealed candidate as an immutable root (one short gate-locked tx) | [`PgRetentionRoots::register`] |
//! | release (or fence a not-yet-registered root) one-way | [`PgRetentionRoots::release`] |
//! | historical metadata / receipt reads (data only) | [`PgRetentionRoots::get`] / [`PgRetentionRoots::query_receipt`] |
//! | native byte read requiring current authority + active root at T2 | [`PgRetentionRoots::materialize`] |
//!
//! ## Guarantees
//!
//! * **Exact selectors.** Either the whole captured snapshot (every captured ref + HEAD) or an explicit set of
//!   `1..=256` object ids of the gate's exact object-format width — including an older commit that is no longer
//!   referenced by any branch but still lives in one of the registered packs. Object presence and closure are
//!   proven natively from the actual Blob pack/idx bytes, never inferred from metadata.
//! * **Sealed candidate.** [`RootCandidate`] has private fields, no public constructor, no `Clone` and no serde;
//!   `register` moves it by value and re-reads the original pin/realm/full pack identity under PostgreSQL locks.
//! * **Never reused / never reopened.** A root has exactly one capture (`generation 1`); release is the terminal
//!   `generation 2`. There is no renew, reopen or second-generation API. A release-before-register tombstone binds
//!   the full scope and the expected register digest, so a delayed register is refused.
//! * **Exact replay.** Same `(repository_id, request_id)` returns the stored receipt with `replayed = true` before
//!   any liveness/quota work and without an extra charge; same id with a different digest is a typed conflict.
//! * **Retained quota.** Fixed repo/tenant ceilings are charged from the **actual** canonical column bytes of every
//!   row the mutation writes (ref names/oids, both complete pack locators, header scope/digests) plus a bounded
//!   per-row overhead, applied under both usage row locks before the first root row is written and never refunded
//!   or auto-pruned. A release-before-register inserts a terminal head and therefore consumes one root slot.
//! * **Frozen lock order.** tenant usage -> repository usage -> core gate -> protocol state -> root head/tombstone
//!   rows, in one short transaction; the usage rows are locked (zero charge) before the gate and charged later.
//! * **Separate monotone state.** `roots_revision` lives in `ref_store_core_protocol_repos`; the frozen migration
//!   139 gate row shape is unchanged, and a root change takes the same core gate lock as a ref commit.
//! * **One absolute deadline per call.** Pool acquisition, `BEGIN`, the local `statement_timeout`/`lock_timeout`
//!   bound (taken before the first query), every SQL stage, native work, commit and cleanup share one clamped
//!   deadline that is never restarted; cleanup is always bounded and a value is returned only after it succeeds.
//! * **Complete receipt scope.** A receipt query must match the row columns *and* the immutable body's object
//!   format, history incarnation, authority epoch and group epoch, so a changed-realm query is refused.
//!
//! Out of scope by design: no serving route, no gateway authority, no business producer handoff/cutover, no GC
//! executor (this module only publishes explicit protection data), no decisions, no accepted subsets.
mod candidate;
mod capture;
mod error;
mod handle;
mod pg;
mod pg_register;
mod pg_release;
mod read;
mod receipt;
mod record;
mod request;
mod rows;
mod scope;
mod selector;
mod sql;
mod sql_insert;
mod sql_read;
mod usage;
mod view;

pub use candidate::RootCandidate;
pub use error::RootError;
pub use handle::{RootReadAuthority, RootReadRequest, RootReceiptQuery, RootRef};
pub use pg::PgRetentionRoots;
pub use receipt::{RootAction, RootReceipt};
pub use record::RootRecord;
pub use request::{PrepareRootRequest, RegisterRootRequest, ReleaseRootRequest};
pub use scope::{RootPurpose, RootsScope};
pub use selector::{RootSelector, RootSelectorKind};
pub use usage::{
    MAX_RECEIPT_BODY_BYTES, MAX_ROOT_OIDS, REPO_MAX_LOGICAL_BYTES, REPO_MAX_PACK_BINDINGS, REPO_MAX_RECEIPTS,
    REPO_MAX_ROOT_OID_REFS, REPO_MAX_ROOTS, RootQuotaResource, TENANT_MAX_LOGICAL_BYTES, TENANT_MAX_PACK_BINDINGS,
    TENANT_MAX_RECEIPTS, TENANT_MAX_ROOT_OID_REFS, TENANT_MAX_ROOTS,
};
pub use view::RootReadView;

pub(crate) use self::pg::{ValidatedCapture, validate_capture};
