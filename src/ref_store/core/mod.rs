//! Isolated PostgreSQL metadata core for prioritized #107 work.
//!
//! This component owns one explicit gate and the current refs of a repository
//! that has no live legacy Pando authority and is still explicitly unserved.
//! It is deliberately internal and currently unwired: no HTTP route, runtime
//! profile, serving cutover, pack or blob IO, snapshot pin, root, hold, decision
//! or GC consumer is added here. Legacy Pando/GitFS call sites and long read
//! leases are unchanged. A repository with a core gate is **not** serve-ready;
//! activation needs a later, explicit cutover API.
//!
//! Layout: [`contract`] owns the gate/version proof, [`command`] the exact CAS
//! command and its canonical digest, [`types`] the ref vocabulary,
//! [`terminal`] the immutable terminal shapes and [`sql`]/[`pg`] the owned
//! short-transaction adapter over the migration-138 registry.
pub mod command;
pub mod contract;
pub mod pg;
pub mod sql;
pub mod terminal;
pub mod types;

pub use command::CommitRefsRequest;
pub use contract::{CommitMode, CoreGate, CoreGateInit, CoreGateVersion, VersionCheck};
pub use pg::PgRefStoreCore;
pub use terminal::{CommitRefsReceipt, CommitRejectCode, CommitRejection, CommitTerminal, RefCommitResult, TerminalKind};
pub use types::{
    GitObjectFormat, GitOid, HeadUpdate, MAX_REFS_PER_COMMIT, RefName, RefPrecondition, RefTarget, RefUpdate,
};
