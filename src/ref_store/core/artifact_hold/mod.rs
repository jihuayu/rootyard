//! Global, permanent artifact-hold ledger and protected upload slice (A3).
//!
//! This module is the trusted internal dependency for #107/#113: a batch of
//! fresh Blob upload intents is reserved as durable, always-active,
//! generation-1 holds in one all-or-none PostgreSQL transaction, and the only
//! way to obtain write authority again is a durable one-shot consume receipt
//! followed by the sealed `blob_store` raw writer.
//!
//! Boundaries that are deliberately **not** implemented here:
//!
//! * no release, TTL/expiry, retirement, state transition or `DELETE` path;
//!   every hold, receipt, quota counter and dedup identity is permanent;
//! * no physical object dedup/reuse, no existing/unregistered locator upload,
//!   no GC consumer and no object deletion;
//! * no HTTP route, runtime profile activation, serving cutover, complete
//!   artifact-holds/roots/pack/snapshot capability or candidate/membership;
//! * no cross-store transaction: PostgreSQL commits the ledger first, and only
//!   a positive `COMMIT` acknowledgement yields a private grant/consumed token;
//!   Blob IO never runs inside a PostgreSQL transaction.
//!
//! Physical identity: every request, ACK, hold row and consume receipt records
//! the deterministic non-secret `BlobBackendIdentity` hex of the store that was
//! actually opened (provider + endpoint + bucket/container + root + region +
//! stable account identity). The adapter compares it with the live store before
//! acquire and the protected uploader compares it again before consuming, so a
//! same-provider-but-other-bucket/root/account store can never acquire, replay
//! or upload.
//!
//! The adapter and protected uploader are library modules; no route, runtime
//! profile or serving entry point enables them. It never touches
//! migration 138/139/140 tables except to share the exact 138 operation
//! advisory/issuer-lane lock prefix and to read the current unserved core gate
//! proof, and it never inserts or updates a 138 pending operation row.
//!
//! Layout:
//!
//! * [`contract`] — bounded values, exact limits, typed errors and capability
//!   declaration (no IO);
//! * [`request`] — the bounded acquire request and its stable digest;
//! * [`receipt`] — immutable acquire ACK / consume receipts and their codec;
//! * `quota` — exact retained-admission arithmetic;
//! * `sql`/`sql_rows` — SQL-only lock/row helpers (no commit logic);
//! * `pg::capability` (private) — the mint surface of the boxed, non-Clone and
//!   non-Serde upload grant and of the post-ACK consumed token;
//! * `consume` (private) — pure row/body verification helpers;
//! * `pg` — the owned short-transaction acquire/consume adapter;
//! * `query` — receipt-only unknown-COMMIT resolution (no grant, no IO).
pub mod contract;
pub mod receipt;
pub mod request;

mod consume;
mod pg;
mod query;
mod quota;
mod sql;
mod sql_rows;

pub use contract::{
    ArtifactHoldCapabilities, ArtifactHoldError, ArtifactHoldPurpose, ArtifactSpec, GLOBAL_SHARDS, HoldQuotaResource,
    HoldQuotaScope, HoldScope, MAX_ARTIFACT_DECLARED_BYTES, MAX_BATCH_ARTIFACTS, MAX_RECEIPT_BODY_BYTES,
    REPO_MAX_DECLARED_BYTES, REPO_MAX_HOLDS, REPO_MAX_LOGICAL_BYTES, REPO_MAX_RECEIPTS, SHARD_MAX_DECLARED_BYTES,
    SHARD_MAX_HOLDS, SHARD_MAX_LOGICAL_BYTES, SHARD_MAX_RECEIPTS, ShardId, TENANT_MAX_DECLARED_BYTES, TENANT_MAX_HOLDS,
    TENANT_MAX_LOGICAL_BYTES, TENANT_MAX_RECEIPTS,
};
pub use pg::{AcquireOutcome, ArtifactGrant, ConsumedArtifacts, PgArtifactHoldStore};
pub use receipt::{AcquireAck, AcquireLookup, ConsumeAck, ConsumeLookup, HoldAck, HoldArtifactIdentity};
pub use request::AcquireArtifactHoldsRequest;

/// Consumed-token body handed to the `blob_store::protected` child. The type is
/// nameable crate-wide, but nothing outside `pg::capability` can construct a
/// [`ConsumedArtifacts`] token in the first place.
pub(crate) use pg::ConsumedUpload;
