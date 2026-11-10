//! A5b adds [`PgPackSnapshotMaterializer`]: T1 sealed metadata, actual verified
//! Blob/native Git closure outside every PostgreSQL lease, then a fresh-locked T2
//! revalidation under one absolute effective deadline. Its
//! [`MaterializedPackRead`] is an opaque owned local view; it grants no new
//! serving or write authority and claims no physical Blob-byte backup.
//!
//! # Session proof (#174): NOT wired
//!
//! [`PgPackSnapshotMaterializer::materialize_serving_read_sealed`] returns the
//! view together with an internal [`VerifiedReadViewProof`] (non-empty
//! captures only). **No gateway route consumes it.** It is not proof that a
//! response was served: a later task must, in the gateway, copy packs/index,
//! check checksums and `verify_refs`, fully encode the body, run the final
//! authorization and the cluster-incarnation fence, restore the incarnation
//! and only then seal/issue. The proof carries the cluster authority
//! incarnation its capture locked `FOR SHARE` (migration 085) and its T2
//! re-read identically, but a restore rotation between capture and T2 refuses
//! with no view and no proof; "response and token share the same PG
//! snapshot/final fence" remains a consumer requirement that is unimplemented
//! here.
//!
//! `snapshot::build_view` still materializes through the unsealed
//! [`PgPackSnapshotMaterializer::materialize_serving_read`]; dead code remains
//! until that wiring lands, so this module is not strict-clippy clean.
//!
//! Serving-read addition (#107/#114/#144): [`PgServingReads`] is a separate,
//! bounded **transient** read-pin family (migration 146). One GET captures the
//! current refs/HEAD/registered membership under the same strict `pg_refstore`
//! serving authority and the same core gate lock, protects it for a bounded
//! lease and deletes/reclaims the row on release/expiry. It never appends a
//! durable snapshot, pin, receipt or history row, so the retained 64-per-
//! repository A5a quota is unchanged. [`ServingReadCapture`] is opaque and
//! either a checked empty-repository observation or a real [`PackReadSnapshot`]
//! with [`ReadSnapshotSourceKind::ServingTransient`]; the materializer routes
//! that source kind to the migration-146 T2 recheck. Both shapes also keep the
//! cluster authority incarnation the capture locked first (see
//! `serving_read`), and T2 refuses when it moved.
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
mod serving_proof;
mod serving_read;
mod serving_read_request;
mod serving_read_sql;
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
#[cfg(test)]
pub(crate) use materialize::test_materialized_view;
pub(crate) use materialize::MaterializedServingRead;
pub use materialize::{MaterializedPackRead, PgPackSnapshotMaterializer};
pub use pg::PgPackSnapshot;
pub use read_snapshot::{PackReadSnapshot, ReadSnapshotSourceKind};
pub use receipt::{PackPinReceipt, PackSnapshotLookup, PackSnapshotOutcome, PackSnapshotReceipt};
pub use request::{CreatePackSnapshotRequest, PackSnapshotExpectation, PackSnapshotReceiptQuery, PackSnapshotRef};
pub(crate) use serving_proof::VerifiedReadViewProof;
#[cfg(test)]
pub(crate) use serving_proof::{ProvenScope, probe_a5a};
pub use serving_read::{PgServingReads, ServingReadCapture};
pub use serving_read_request::{
    MAX_EXPIRED_SERVING_READ_RECLAIM, MAX_SERVING_READ_LEASE_SECONDS, MIN_SERVING_READ_LEASE_SECONDS,
    REPO_MAX_ACTIVE_SERVING_READS, REPO_MAX_SERVING_READ_LOGICAL_BYTES, SERVING_CAPTURE_DIGEST_DOMAIN,
    SERVING_EMPTY_CAPTURE_DIGEST_DOMAIN, TENANT_MAX_ACTIVE_SERVING_READS, TENANT_MAX_SERVING_READ_LOGICAL_BYTES,
};
