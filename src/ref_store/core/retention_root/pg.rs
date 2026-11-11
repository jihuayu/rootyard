//! The durable roots adapter: `prepare` (T1 sealed metadata + private native closure) and `new`.
//!
//! `prepare` never writes. It reads the sealed source snapshot in one short bounded transaction, drops the pooled
//! client/transaction before any Blob or native Git IO, proves the actual Blob + Git object closure of the exact
//! selector through the private native engine, and returns an opaque [`RootCandidate`]. A sealed candidate exists
//! only if (a) the T1 transaction cleanup succeeded, (b) every registered pack/idx was downloaded and verified,
//! (c) the synthetic non-branch root refs and HEAD attested exactly, and (d) the native closure carries exactly
//! the canonical binding digest computed from the sealed metadata.
use super::candidate::{RootCandidate, SealRequest, source_read_digest};
use super::capture::{BindingParts, binding_digest};
use super::error::RootError;
use super::request::PrepareRootRequest;
use super::selector::{native_refs, resolve_oids};
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::core::pack_commit::{NativeReadEngine, NativeReadRequest, PackCommitError};
use crate::ref_store::core::pack_snapshot::{PackReadSnapshot, PackSnapshotRef, PgPackSnapshot};
use crate::ref_store::pg;
use crate::ref_store::tx::begin_bounded;
use deadpool_postgres::Pool;
use std::path::PathBuf;
use tokio::time::{Instant, timeout_at};

/// Frozen roots adapter. Construction validates the absolute trusted Git binary once; it grants no capability.
pub struct PgRetentionRoots {
    engine: NativeReadEngine,
}

impl PgRetentionRoots {
    /// Build one adapter for a live Blob store and an absolute trusted Git binary. No ambient store and no
    /// `PATH` lookup.
    pub fn new(store: BlobStore, git_binary: PathBuf) -> Result<Self, RootError> {
        let engine = NativeReadEngine::new(store, git_binary)?;
        Ok(Self { engine })
    }

    pub(super) fn engine(&self) -> &NativeReadEngine {
        &self.engine
    }

    /// Phase 1: seal one existing durable pack snapshot as a root candidate.
    ///
    /// One call uses exactly one effective deadline for the pool wait, the T1 transaction, every verified Blob
    /// GET, every native Git child and the cleanup. No PostgreSQL transaction or pooled client is held across
    /// Blob/native IO.
    pub async fn prepare(
        &self,
        pool: &Pool,
        request: PrepareRootRequest,
        deadline: Instant,
    ) -> Result<RootCandidate, RootError> {
        request.validate()?;
        let deadline = effective_deadline(deadline)?;
        let reference = *request.reference();
        let sealed = capture_t1(pool, &reference, deadline).await?;
        if sealed.pack_count() <= 0 || !sealed.complete_registered_pack_membership() {
            return Err(RootError::RootSourceChanged("source snapshot has no complete pack membership"));
        }
        let format = sealed.scope().object_format();
        let oids = resolve_oids(request.selector(), format, sealed.refs(), sealed.head_oid_hex())?;
        let native_set = native_refs(format, sealed.refs(), &oids)?;
        let operation_digest = request.digest();
        let source_read = source_read_digest(&sealed, &oids, request.selector().kind());

        // The canonical binding digest every later read re-derives from retained rows. The native closure must
        // carry exactly this value, so a closure produced for another selector/source cannot be reused.
        let binding = binding_digest(&BindingParts {
            scope: *request.scope(),
            root_id: request.root_id(),
            generation: 1,
            operation_id: request.operation_id(),
            operation_digest: &operation_digest.as_hex(),
            selector_kind: request.selector().kind(),
            oids: &oids,
            source_snapshot_id: sealed.snapshot_id(),
            source_pin_id: sealed.pin_id(),
            source_pin_generation: sealed.pin_generation(),
            source_read_digest: &source_read.as_hex(),
            gate_revision: sealed.gate_revision(),
            gate_digest: sealed.gate_digest_hex(),
            head_ref: sealed.head_ref(),
            head_oid: sealed.head_oid_hex(),
            captured_refs: sealed.refs(),
            native_refs: &native_set,
            packs: sealed.packs(),
            membership_digest: sealed.membership_digest_hex(),
        });
        let binding_hex = binding.as_hex();
        let native = self
            .engine
            .materialize(
                &NativeReadRequest {
                    format,
                    head_ref: sealed.head_ref(),
                    head_oid: sealed.head_oid_hex(),
                    refs: &native_set,
                    packs: sealed.packs(),
                    read_digest: &binding_hex,
                },
                deadline.into_std(),
            )
            .await
            .map_err(map_native_error)?;
        if native.read_digest() != binding {
            return Err(RootError::RootClosureUnproven("native closure binding differs from the sealed source"));
        }
        if native.verified_pairs() != sealed.packs().len() {
            return Err(RootError::RootClosureUnproven("native closure did not cover every registered pack"));
        }
        if native.retained_bytes(deadline.into_std()).await.map_err(map_native_error)?
            > crate::ref_store::core::pack_commit::contract::VERIFIER_VIEW_MAX_LOGICAL_BYTES
        {
            return Err(RootError::RootClosureUnproven("materialized root view exceeds the workspace bound"));
        }
        // The closure proved every selected object id is present and connected in the captured packs. It is
        // dropped here: later root reads re-materialize from the root's own retained rows.
        drop(native);

        let candidate = RootCandidate::seal(
            SealRequest {
                scope: *request.scope(),
                reference,
                root_id: request.root_id(),
                operation_id: request.operation_id(),
                operation_digest,
                selector_kind: request.selector().kind(),
                oids,
                packs: sealed.packs().to_vec(),
            },
            &sealed,
        )?;
        if candidate.binding_digest() != binding {
            return Err(RootError::RootDigestConflict("sealed candidate binding differs from the native binding"));
        }
        Ok(candidate)
    }
}

/// One absolute effective work deadline for the whole call (never restarted, never above 30 s).
pub(super) fn effective_deadline(caller: Instant) -> Result<Instant, RootError> {
    let ceiling = Instant::now()
        + std::time::Duration::from_secs(crate::ref_store::core::pack_commit::contract::VERIFIER_DEADLINE_SECONDS);
    let deadline = caller.min(ceiling);
    if deadline <= Instant::now() {
        return Err(RootError::Store(RefStoreError::Timeout));
    }
    Ok(deadline)
}

/// Take one pooled client with the caller's exact effective deadline.
pub(super) async fn pooled_client(pool: &Pool, deadline: Instant) -> Result<deadpool_postgres::Client, RootError> {
    let pool = pool.clone();
    match timeout_at(deadline, pool.get()).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(_)) => Err(RootError::Store(RefStoreError::Unsupported("roots PostgreSQL pool is unavailable"))),
        Err(_) => Err(RootError::Store(RefStoreError::Timeout)),
    }
}

/// Take the local `statement_timeout`/`lock_timeout` bound from the remaining absolute budget.
///
/// This is `ref_store::pg::bound`. A bounded pool acquisition and a bounded `BEGIN` never bound a blocked
/// `FOR UPDATE`/`FOR SHARE` row wait, so every roots transaction calls this immediately after `begin_bounded`
/// and before its first query or lock.
pub(super) async fn bound_tx(tx: &tokio_postgres::Transaction<'_>, deadline: Instant) -> Result<(), RootError> {
    pg::bound(tx, deadline).await.map_err(RootError::from)
}

/// Run one complete asynchronous SQL body under the single absolute deadline.
///
/// This has exactly the effect of `ref_store::pg::before_deadline` (the same absolute `timeout_at` instant), but
/// keeps the typed roots refusal instead of collapsing it into a shared store error on the way out.
pub(super) async fn before_deadline<T, F>(deadline: Instant, body: F) -> Result<T, RootError>
where
    F: std::future::Future<Output = Result<T, RootError>>,
{
    match timeout_at(deadline, body).await {
        Ok(result) => result,
        Err(_) => Err(RootError::Store(RefStoreError::Timeout)),
    }
}

/// Bounded transaction cleanup. Never an unbounded `rollback().await`: the rollback itself must finish before
/// the one absolute deadline, and a timeout or failed rollback is a typed refusal rather than a silent success.
pub(super) async fn rollback_reads(tx: tokio_postgres::Transaction<'_>, deadline: Instant) -> Result<(), RootError> {
    match timeout_at(deadline, tx.rollback()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(RootError::Store(RefStoreError::Database("root transaction cleanup failed".into()))),
        Err(_) => Err(RootError::Store(RefStoreError::Timeout)),
    }
}

/// (T1) Sealed metadata capture in one short bounded transaction whose pooled client is released before native
/// work. A sealed snapshot is yielded only when the bounded rollback succeeded.
async fn capture_t1(
    pool: &Pool,
    reference: &PackSnapshotRef,
    deadline: Instant,
) -> Result<PackReadSnapshot, RootError> {
    let mut client = pooled_client(pool, deadline).await?;
    let tx = begin_bounded(&mut client, deadline).await?;
    if let Err(error) = bound_tx(&tx, deadline).await {
        let _cleanup = rollback_reads(tx, deadline).await;
        drop(client);
        return Err(error);
    }
    let read = pg::before_deadline(deadline, PgPackSnapshot.read_checked(&tx, reference, deadline)).await;
    let cleanup = rollback_reads(tx, deadline).await;
    drop(client);
    match (read, cleanup) {
        (Err(error), _) => Err(error.into()),
        (Ok(_), Err(error)) => Err(error),
        (Ok(snapshot), Ok(())) => Ok(snapshot),
    }
}

/// Map the private native refusal without promoting Git text, argv, a path, a locator or provider text.
fn map_native_error(error: PackCommitError) -> RootError {
    RootError::from(error)
}
