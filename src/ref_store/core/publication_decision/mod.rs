//! Publication decisions: live PostgreSQL authorization, single-use decision capabilities and the
//! cancel-before-install tombstone (unserved, internal).
//!
//! The module is deliberately *not* a serving path: it adds no HTTP route, no CLI, no Raft bridge and
//! no GC consumer. The integration commit calls the concrete functions here with the opaque native
//! `VerifiedPublicationFacts` value and the sealed `SelectedPackPlan`.
//!
//! # Correctness rules (frozen)
//!
//! * All authority, policy and decision state is PostgreSQL in the same database. Correctness comes
//!   from one frozen lock order plus transaction order, never from a cache, a lease or a version
//!   counter alone.
//! * `LOCK TABLE ... IN SHARE MODE NOWAIT` on the complete actual source set
//!   ([`sql_locks::SOURCE_TABLES`]) conflicts with every API/CLI/worker/direct-SQL writer, including
//!   phantom inserts. A `Merge` action takes `SHARE ROW EXCLUSIVE` on `forge_pulls` up front. It never
//!   waits and never upgrades; a contended attempt aborts and is retried under the same operation
//!   identity.
//! * Control tables (`ref_store_publication_decisions`, `ref_store_decision_*`, the gate and the
//!   separate protocol realm row) are locked **by row**. A table `SHARE` lock followed by an
//!   `INSERT` into the same table would be a self-conflicting upgrade and is never done.
//! * The fence is `ref_store_core_protocol_repos.decision_required` (there is no
//!   `core_gates.decision_mode` column). Gate and protocol rows are read in that order and their
//!   immutable realm fields must match exactly.
//! * After the waits the database clock and every dependency are re-read. Legacy writers of auth/policy
//!   rows do not bump scope versions, so re-checks compare canonical fact digests, not only versions.
//! * The commit mode ([`DecisionKind`]) and the semantic action ([`PublicationAction`]) are separate.
//!   A merge is never inferred from a `head_ref`; a direct push with `required_approvals > 0` is always
//!   rejected.
//! * Selection is `subset::SelectedPackPlan::seal(original.clone(), &facts, &policies)` **before**
//!   persistence. The persisted selection digest and every verdict row come from that sealed
//!   projection; there is no second decision-owned selection domain and no post-proof filtering.
//! * No raw token, token digest, receipt body or routable locator is ever rendered into a public
//!   receipt; the PG-only credential identity stays in the protected decision row.
//!
//! # Layout
//!
//! [`contract`] codes/verdicts/outcomes/action, [`capability`] the unforgeable capability,
//! [`digest`] canonical digest material, [`facts_bridge`] the concrete native-facts bridge,
//! [`sql_locks`] the frozen lock order/clock/protocol reads, [`auth_deps`] live PG authorization and
//! policy reads, [`policy`] the live policy row reads, [`select`] the pure per-ref policy pass,
//! [`install`] the `OPEN` decision mint, [`consume`] the in-commit final check, [`cancel`]
//! cancellation, [`query`] historical selection-row reads and [`usage`] retained quota arithmetic.
//! A `Merge` action is only vocabulary plus the live `forge_pulls` policy reads here: the guarded
//! finalizer lives in the commit transaction owned by Root, not in a second decision writer.
pub(crate) mod auth_deps;
pub(crate) mod cancel;
pub(crate) mod capability;
pub(crate) mod codes;
pub(crate) mod consume;
pub(crate) mod contract;
pub(crate) mod digest;
pub(crate) mod facts_bridge;
pub(crate) mod install;
pub(crate) mod metadata;
pub(crate) mod metadata_check;
pub(crate) mod policy;
pub(crate) mod query;
pub(crate) mod select;
pub(crate) mod sql_locks;
pub(crate) mod usage;

/// The sealed accepted-subset vocabulary is the shared one; decisions never define a parallel set.
pub(crate) use crate::ref_store::core::subset;

pub(crate) use cancel::coordinator_cancel;
pub(crate) use consume::authorized_final_check;
pub(crate) use contract::{
    CancelOutcome, ConsumptionRecord, DecisionError, DecisionKind, PublicationAction, SelectedDecision,
};
pub(crate) use install::select_and_install;
pub(crate) use metadata::{MetadataSelectedDecision, select_and_install_metadata};
pub(crate) use metadata_check::authorized_metadata_final_check;
pub(crate) use sql_locks::{lock_source_tables, lock_usage};
