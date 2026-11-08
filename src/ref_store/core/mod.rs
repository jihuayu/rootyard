//! Isolated PostgreSQL metadata core for prioritized #107 work.
//!
//! This component owns one explicit gate and the current refs of a repository
//! that has no live legacy Pando authority and is still explicitly unserved.
//! It is deliberately internal and currently unwired: no HTTP route, runtime
//! profile, serving cutover, pack or blob IO, root, hold, decision or GC
//! consumer is added here. Legacy Pando/GitFS call sites and long read
//! leases are unchanged. A repository with a core gate is **not** serve-ready;
//! activation needs a later, explicit cutover API.
//!
//! A2 adds a **metadata-only** snapshot/pin contract: immutable refs/HEAD rows
//! captured with the exact gate revision/digest, a durable metadata pin,
//! bounded keyset pages, generation-CAS renewal/release and a bounded
//! successful-mutation receipt ledger with retained repo/tenant admission
//! usage. It is not a Git `ReadSnapshot`: pack membership is typed
//! `Unavailable`, and a metadata pin is not protective of Git objects.
//!
//! Layout: [`contract`] owns the gate/version proof, [`command`] the exact CAS
//! command and its canonical digest, [`types`] the ref vocabulary,
//! [`terminal`] the immutable terminal shapes and [`sql`]/[`pg`] the owned
//! short-transaction adapter over the migration-138 registry. A2 adds
//! [`snapshot_contract`]/[`snapshot_receipt`] (pure contract),
//! `snapshot_request` (bounded requests and digests), `pin` (pin/snapshot state
//! machine and receipt codec), `snapshot_sql`/`snapshot_usage` (SQL-only
//! helpers) and `snapshot_pg`/`pin_pg` (owned short transactions over migration
//! 140).
pub mod artifact_hold;
pub mod command;
pub mod contract;
pub mod pg;
pub mod sql;
pub mod terminal;
pub mod types;

mod pin;
mod pin_pg;
mod snapshot_pg;
mod snapshot_request;
mod snapshot_sql;
mod snapshot_usage;

pub mod snapshot_contract;
pub mod snapshot_receipt;

pub use command::CommitRefsRequest;
pub use contract::{CommitMode, CoreGate, CoreGateInit, CoreGateVersion, VersionCheck};
pub use pg::PgRefStoreCore;
pub use snapshot_contract::{
    MAX_PIN_LEASE_SECONDS, MAX_RECEIPT_BODY_BYTES, MAX_SNAPSHOT_LOGICAL_BYTES, MAX_SNAPSHOT_PAGE, MAX_SNAPSHOT_REFS,
    MetadataSnapshotCursor, MetadataSnapshotScope, PackMembershipDescriptor, REPO_MAX_LOGICAL_BYTES, REPO_MAX_RECEIPTS,
    REPO_MAX_SNAPSHOT_REFS, REPO_MAX_SNAPSHOTS, RefPrefix, TENANT_MAX_LOGICAL_BYTES, TENANT_MAX_RECEIPTS,
    TENANT_MAX_SNAPSHOT_REFS, TENANT_MAX_SNAPSHOTS,
};
pub use snapshot_receipt::{
    CreateMetadataSnapshotOutcome, MetadataPinOutcome, MetadataPinReceipt, MetadataReceipt, MetadataReceiptLookup,
    MetadataSnapshotPage, MetadataSnapshotReceipt, MetadataSnapshotRef,
};
pub use snapshot_request::{
    CreateMetadataSnapshotRequest, PinReleaseReason, ReadMetadataSnapshotPageRequest, ReleaseMetadataPinRequest,
    RenewMetadataPinRequest,
};
pub use terminal::{
    CommitRefsReceipt, CommitRejectCode, CommitRejection, CommitTerminal, RefCommitResult, TerminalKind,
};
pub use types::{
    GitObjectFormat, GitOid, HeadUpdate, MAX_REFS_PER_COMMIT, RefName, RefPrecondition, RefTarget, RefUpdate,
};
