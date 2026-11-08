//! A5b adds [`PgPackSnapshotMaterializer`]: T1 sealed metadata, actual verified
//! Blob/native Git closure outside every PostgreSQL lease, then a fresh-locked T2
//! revalidation under one absolute effective deadline. Its
//! [`MaterializedPackRead`] is an opaque owned local view; it grants no new
//! serving or write authority and claims no physical Blob-byte backup.
//!
//! A5a: atomic, durable, complete **registered pack membership** snapshot plus a
//! durable pin and permanent historical receipts (#107 foundation).
//!
//! One library path (no HTTP route, no runtime profile, no serving cutover):
//!
//! | step | API |
//! | --- | --- |
//! | capture refs + HEAD + all memberships + pin + receipt + history | [`PgPackSnapshot::create`] |
//! | read one sealed complete snapshot | [`PgPackSnapshot::read`] |
//! | historical receipt by global request id | [`PgPackSnapshot::query_receipt`] |
//! | renew/release the pin | `PgRefStoreCore::renew_metadata_pin` / `release_metadata_pin` |
//!
//! What this module claims: under the single core gate `FOR UPDATE` that
//! `CommitRefs` and an A4 verified commit also take, it captures the exact gate
//! revision/digest/mode, **all** refs and HEAD, and **all** active registered pack
//! memberships (each with its complete artifact locator/provider/backend/verified
//! identity) into immutable rows, with the durable pin, the A2 creation receipt,
//! the permanent history row and both retained counter families in the *same*
//! transaction. [`PackReadSnapshot`] then re-derives every digest and returns the
//! complete sorted ref and pack sets as one sealed value.
//!
//! The A5a metadata value does not claim current Blob bytes or native Git
//! closure: its `complete_git_read_snapshot()` remains `false`. The separate
//! A5b materializer verifies those bytes and closure before returning a complete
//! local view. Neither value claims roots/decisions/accepted subsets, serving,
//! GC/detach, encryption, Blob-byte backup or write authority.
//!
//! A2 compatibility: the A2 header gained only defaulted pack columns, the A2
//! receipt codec gained only `serde(default)`/`skip_serializing_if` pack fields
//! (so an old body stays byte-identical and replays exactly), an old metadata
//! pin mutation on a pack-aware pin is routed through this ledger/counter path,
//! and a fresh metadata-only create is refused on a `pack_verified` gate.
mod contract;
mod materialize;
mod pg;
mod query;
mod read_snapshot;
mod receipt;
mod request;
pub(super) mod sql;
pub(crate) mod usage;

pub(crate) use contract::history_logical_bytes;
pub use contract::{
    CREATE_REQUEST_DIGEST_DOMAIN, MAX_PACK_HISTORY_BODY_BYTES, PACK_BINDING_OVERHEAD_BYTES,
    PACK_HISTORY_OVERHEAD_BYTES, PACK_MODE_VERIFIED, READ_RESULT_DIGEST_DOMAIN, REPO_MAX_PACK_BINDINGS,
    REPO_MAX_PACK_HISTORY, REPO_MAX_PACK_LOGICAL_BYTES, REPO_MAX_PACK_PINS, REPO_MAX_PACK_RECEIPTS, REPO_MAX_PACK_REFS,
    REPO_MAX_PACK_SNAPSHOTS, SNAPSHOT_DIGEST_DOMAIN, TENANT_MAX_PACK_BINDINGS, TENANT_MAX_PACK_HISTORY,
    TENANT_MAX_PACK_LOGICAL_BYTES, TENANT_MAX_PACK_PINS, TENANT_MAX_PACK_RECEIPTS, TENANT_MAX_PACK_REFS,
    TENANT_MAX_PACK_SNAPSHOTS, TENANT_PACK_FACTOR,
};
pub use materialize::{MaterializedPackRead, PgPackSnapshotMaterializer};
pub use pg::PgPackSnapshot;
pub use read_snapshot::PackReadSnapshot;
pub use receipt::{PackPinReceipt, PackSnapshotLookup, PackSnapshotOutcome, PackSnapshotReceipt};
pub use request::{CreatePackSnapshotRequest, PackSnapshotExpectation, PackSnapshotReceiptQuery, PackSnapshotRef};
