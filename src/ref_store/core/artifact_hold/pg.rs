//! Owned short-transaction adapter for the global artifact-hold ledger (A3).
//!
//! Every public method opens and owns exactly one short transaction from a
//! caller `&mut tokio_postgres::Client`:
//!
//! * a returned grant/receipt means `COMMIT` was acknowledged;
//! * every `Err` before `COMMIT` is rolled back through the owned transaction,
//!   so no hold/receipt/quota row remains committable;
//! * a `COMMIT` timeout or error reply is a typed `AcquireUnknown` /
//!   `ConsumeUnknown` carrying the stable global request/consume/hold ids. It is
//!   never an abort: the ledger may have committed, so the caller resolves it
//!   with the receipt-only query and uploads nothing.
//!
//! Lock order (fixed): exact parent 138 operation advisory key -> repository
//! existence -> issuer lane -> 138 pending/cancellation rows -> separate-domain
//! global request advisory key -> global shard -> tenant quota -> repository
//! quota -> repository/gate -> sorted hold rows -> immutable receipts.
//!
//! Physical binding is checked *before* the database work: the request must name
//! the actually opened store's [`BlobBackendIdentity`](crate::blob_store::BlobBackendIdentity),
//! so a same-provider-but-other-bucket/root/account store can neither acquire nor
//! replay a hold, and the grant's own intents/ACK/hold rows must agree again
//! before a consume transaction starts.
//!
//! There is no Blob IO inside any transaction: acquire mints opaque upload
//! intents before `BEGIN`, the grant is built only after a positive `COMMIT`,
//! and consume returns its private token only after a positive `COMMIT`. The
//! `blob_store::protected` child is the only caller that may then use the
//! sealed raw writer.
//!
//! Cancellation lifetime (deliberate, documented): a `COMMIT`-ACKed consume
//! that is followed by a parent cancellation can block later publication, but it
//! cannot undo the durable receipt, any provider write already issued by a late
//! detached task, or the hold. That leaves a permanently held, never released
//! orphan. There is no release/retire path in this increment by design.
use super::consume::{ensure_complete_batch, ensure_granted_hold, ensure_immutable_batch};
use super::contract::{ArtifactHoldCapabilities, ArtifactHoldError, HoldScope, MAX_BATCH_ARTIFACTS, ShardId};
use super::quota;
use super::receipt::{AcquireAck, ConsumeAck, HoldAck, HoldArtifactIdentity};
use super::request::AcquireArtifactHoldsRequest;
use super::sql;
use super::sql_rows;
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::contract::{OperationIdentity, RefStoreError, RequestDigest};
use crate::ref_store::pg;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use std::future::Future;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

mod capability;

/// Private consumed-token body. It is nameable crate-wide only because the
/// `blob_store::protected` child receives it; it is not constructible there.
pub(crate) use capability::ConsumedUpload;
use capability::GrantedUpload;
/// Read-only re-export of the opaque upload capability and of the consumed
/// token. Their mint functions stay `pub(super)` to this module.
pub use capability::{ArtifactGrant, ConsumedArtifacts};

/// Result of one acquire call. A replay never returns a grant.
pub enum AcquireOutcome {
    Granted { ack: AcquireAck, grant: ArtifactGrant },
    Replayed { ack: AcquireAck },
}

/// Trusted internal adapter over migration 141. It is unserved: no route,
/// runtime profile or service handler is added here.
#[derive(Clone, Copy, Debug, Default)]
pub struct PgArtifactHoldStore;

struct PreparedAcquire {
    ack: AcquireAck,
    replayed: bool,
}

/// Deadline guard typed for the artifact-hold error, mirroring the RefStore
/// helper. It never runs its inner future after the absolute deadline.
pub(super) async fn before_deadline<T, F>(deadline: Instant, future: F) -> Result<T, ArtifactHoldError>
where
    F: Future<Output = Result<T, ArtifactHoldError>>,
{
    match timeout_at(deadline, future).await {
        Ok(result) => result,
        Err(_) => Err(ArtifactHoldError::Timeout),
    }
}

/// Validate a stored immutable ACK against the request, its digest, every
/// duplicated column of its ledger row *and* the complete bounded hold set of
/// that request. This never mints write authority; a mismatch is a
/// conflict/integrity error, not a replay.
fn replay_ack(
    stored: &sql::StoredAcquire,
    holds: &[sql_rows::StoredHold],
    request: &AcquireArtifactHoldsRequest,
    digest_hex: &str,
) -> Result<AcquireAck, ArtifactHoldError> {
    let scope = request.scope();
    if stored.repository_id != scope.repository_id() || stored.tenant_id != scope.tenant_id() {
        return Err(ArtifactHoldError::IdentityConflict { request_id: request.request_id() });
    }
    if stored.request_digest != digest_hex {
        return Err(ArtifactHoldError::DigestConflict { request_id: request.request_id() });
    }
    // The same global request id under a different physical backend produces a
    // different semantic digest, so it is the conflict above; this comparison
    // additionally refuses a row that disagrees with its own body.
    if stored.backend_identity != request.backend_identity().as_hex() {
        return Err(ArtifactHoldError::DigestConflict { request_id: request.request_id() });
    }
    let ack = AcquireAck::decode(&stored.body)?;
    ack.ensure_scope(scope)?;
    // Replay is immutable history, not authority: it needs no current core
    // gate, no pending parent row and mints no token. It must still prove that
    // the durable request row and its body describe exactly the complete
    // bounded active generation-1 hold set (scope/operation/artifact/backend/
    // byte count), so a partial or rewritten hold set is corruption and never
    // a successful `Replayed`.
    ensure_immutable_batch(stored, &ack, holds)?;
    Ok(ack)
}

impl PgArtifactHoldStore {
    pub const fn capabilities(&self) -> ArtifactHoldCapabilities {
        ArtifactHoldCapabilities::artifact_hold_increment()
    }

    /// Reserve 1..=16 fresh Blob attempts as durable holds in one all-or-none
    /// short transaction, then return a private grant that owns the intents.
    ///
    /// The caller-fixed semantic digest covers the trusted scope/owner/purpose,
    /// the exact parent operation binding, the expected unserved core gate
    /// proof, the physical backend identity, the storage authority/generation
    /// and every artifact specification - never the fresh server attempt. An
    /// identical replay returns the old immutable ACK and drops the newly minted
    /// intents, but only after the complete bounded active generation-1 hold set
    /// of that request has been re-read and proven to be exactly the ACK batch
    /// (a partial/rewritten hold set is a ledger-integrity error, not a replay);
    /// a changed request id/digest/backend is a conflict, and an unknown
    /// `COMMIT` returns no grant at all.
    ///
    /// The stable consume request id is allocated *here*, in the same
    /// transaction, and stored in the immutable ACK/request row, so a consume
    /// never invents a new random id.
    ///
    /// The parent operation must already be a durable *pending* row in the
    /// migration-138 registry, registered through the existing
    /// `PgRefStore::begin` owned short transaction (or `reserve_sequence` + an
    /// equivalent caller transaction); this adapter never inserts a 138 pending
    /// row, never authorises a guessed UUID and never treats a cancel
    /// tombstone as provisional. A missing/non-pending/cancelled parent is a
    /// refusal, not an implicit registration.
    pub async fn acquire(
        &self,
        client: &mut Client,
        blob: &BlobStore,
        request: &AcquireArtifactHoldsRequest,
        deadline: Instant,
    ) -> Result<AcquireOutcome, ArtifactHoldError> {
        request.validate()?;
        let scope = *request.scope();
        // Physical binding before any database work or provider IO. A request
        // built against a different endpoint/bucket/root/account is refused here
        // even when it names the same provider.
        let backend_hex = request.backend_identity().as_hex();
        if backend_hex != blob.backend_identity().as_hex() {
            return Err(ArtifactHoldError::BackendMismatch);
        }
        let provider = blob.provider().as_str();
        // Intents are minted before any database work (no provider IO); their
        // random attempt ids are what the ledger records.
        let mut intents = Vec::with_capacity(request.artifact_count());
        for artifact in request.artifacts() {
            let intent = blob
                .new_upload(
                    scope.tenant_id(),
                    request.authority_id(),
                    request.authority_generation(),
                    artifact.namespace(),
                    artifact.sha256(),
                    artifact.length(),
                )
                .map_err(|error| {
                    ArtifactHoldError::InvalidRequest(format!("blob layer rejected the artifact identity: {error}"))
                })?;
            if intent.backend_identity().as_hex() != backend_hex {
                return Err(ArtifactHoldError::BackendMismatch);
            }
            intents.push(intent);
        }
        let digest = request.digest();
        let tx = begin_bounded(client, deadline).await.map_err(ArtifactHoldError::from)?;
        let prepared = self.acquire_stage(&tx, request, &digest, &intents, provider, deadline).await;
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = tx.rollback().await;
                return Err(error);
            }
        };
        if prepared.replayed {
            let _ = tx.rollback().await;
            // Dropping the fresh intents is intentional: a replay never gets
            // another grant and never uploads to a server path from a retry.
            drop(intents);
            return Ok(AcquireOutcome::Replayed { ack: prepared.ack });
        }
        let ack = prepared.ack;
        match commit_bounded(tx, deadline, scope.repository_id(), Some(request.operation().operation_id())).await {
            Ok(()) => {
                let mut uploads = Vec::with_capacity(intents.len());
                for (index, intent) in intents.into_iter().enumerate() {
                    let hold = ack
                        .artifacts
                        .get(index)
                        .ok_or(ArtifactHoldError::LedgerIntegrity("ACK/hold batch length mismatch"))?;
                    let upload = GrantedUpload::new(hold.hold_id, hold.slot, intent);
                    // Prove the privately owned intent still names exactly the
                    // recorded physical locator and backend before handing it over.
                    if HoldArtifactIdentity::from_intent(provider, &upload.intent) != hold.artifact {
                        return Err(ArtifactHoldError::LedgerIntegrity(
                            "privately owned upload intent differs from the committed hold",
                        ));
                    }
                    uploads.push(upload);
                }
                Ok(AcquireOutcome::Granted {
                    grant: ArtifactGrant::new(scope, request.operation().clone(), ack.clone(), uploads),
                    ack,
                })
            }
            Err(RefStoreError::CommitUnknown { .. }) => {
                Err(ArtifactHoldError::AcquireUnknown { request_id: request.request_id() })
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn acquire_stage(
        &self,
        tx: &Transaction<'_>,
        request: &AcquireArtifactHoldsRequest,
        digest: &RequestDigest,
        intents: &[crate::blob_store::UploadIntent],
        provider: &str,
        deadline: Instant,
    ) -> Result<PreparedAcquire, ArtifactHoldError> {
        before_deadline(deadline, self.acquire_checked(tx, request, digest, intents, provider, deadline)).await
    }

    async fn acquire_checked(
        &self,
        tx: &Transaction<'_>,
        request: &AcquireArtifactHoldsRequest,
        digest: &RequestDigest,
        intents: &[crate::blob_store::UploadIntent],
        provider: &str,
        deadline: Instant,
    ) -> Result<PreparedAcquire, ArtifactHoldError> {
        pg::bound(tx, deadline).await?;
        let scope = request.scope();
        let digest_hex = digest.as_hex();
        // Immutable ACK replay is answerable before any authority check: it
        // returns ids only and no grant, so it stays valid after a cancel,
        // commit or even business-row deletion.
        if let Some(stored) = sql::stored_acquire(tx, request.request_id()).await? {
            // Read every bounded hold row of the request (read-only, no lock) so
            // the replay answer is the whole immutable batch, never a partial
            // or rewritten one.
            let holds = sql_rows::holds_for_request(tx, request.request_id()).await?;
            let ack = replay_ack(&stored, &holds, request, &digest_hex)?;
            return Ok(PreparedAcquire { ack, replayed: true });
        }
        sql::lock_parent_prefix(tx, request.operation()).await?;
        sql::request_lock(tx, request.request_id()).await?;
        // Re-check under the request lock so two concurrent first attempts of
        // the same request cannot both insert; the loser replays the winner.
        if let Some(stored) = sql::stored_acquire(tx, request.request_id()).await? {
            let holds = sql_rows::holds_for_request(tx, request.request_id()).await?;
            let ack = replay_ack(&stored, &holds, request, &digest_hex)?;
            return Ok(PreparedAcquire { ack, replayed: true });
        }
        // A new admission requires the exact live pending parent and no
        // cancel tombstone.
        sql::verify_parent_pending(tx, request.operation()).await?;
        sql::set_ack_durability(tx).await?;

        let shard = ShardId::of(request.request_id());
        let shard_usage = sql::lock_shard(tx, shard).await?;
        let (tenant_usage, repository_usage) = sql::lock_usage(tx, scope.tenant_id(), scope.repository_id()).await?;
        let gate = sql::lock_scope_gate(tx, scope).await?;
        if gate.digest() != request.expected_gate_digest() {
            return Err(ArtifactHoldError::ScopeMismatch("expected core gate proof"));
        }

        let mut holds = Vec::with_capacity(intents.len());
        let mut declared_total: i64 = 0;
        let mut logical_total: i64 = 0;
        for (index, (artifact, intent)) in request.artifacts().iter().zip(intents.iter()).enumerate() {
            let slot = i32::try_from(index).map_err(|_| {
                ArtifactHoldError::InvalidRequest("artifact slot does not fit the INTEGER column".into())
            })?;
            declared_total = declared_total.checked_add(artifact.declared_bytes()).ok_or_else(|| {
                ArtifactHoldError::InvalidRequest("artifact declared-byte total overflows i64".into())
            })?;
            logical_total = logical_total
                .checked_add(artifact.logical_bytes())
                .ok_or_else(|| ArtifactHoldError::InvalidRequest("artifact logical-byte total overflows i64".into()))?;
            holds.push(HoldAck::new(
                Uuid::new_v4(),
                slot,
                HoldArtifactIdentity::from_intent(provider, intent),
                artifact.declared_bytes(),
                artifact.logical_bytes(),
            ));
        }
        if holds.len() != request.artifact_count() || holds.is_empty() || holds.len() > MAX_BATCH_ARTIFACTS {
            return Err(ArtifactHoldError::InvalidRequest("artifact hold batch shape is not bounded".into()));
        }
        let ack = AcquireAck {
            request_id: request.request_id(),
            request_digest: digest_hex.clone(),
            repository_id: scope.repository_id(),
            tenant_id: scope.tenant_id(),
            owner_id: scope.owner_id(),
            purpose: scope.purpose(),
            object_format: scope.object_format(),
            history_incarnation: scope.history_incarnation(),
            authority_epoch: scope.authority_epoch(),
            group_epoch: scope.group_epoch(),
            issuer_id: request.operation().issuer_id(),
            lane: request.operation().lane().as_str().to_owned(),
            sequence: request.operation().sequence(),
            operation_id: request.operation().operation_id(),
            operation_digest: request.operation().digest().as_hex(),
            gate_revision: gate.revision(),
            gate_digest: gate.digest().as_hex(),
            shard: shard.as_i32(),
            backend_identity: request.backend_identity().as_hex().to_owned(),
            // Stable consume id: allocated once, by this first acquire.
            consume_request_id: Uuid::new_v4(),
            artifacts: holds,
            declared_bytes: declared_total,
            logical_bytes: logical_total,
        };
        ack.ensure_batch_shape()?;
        let body = ack.encode()?;
        let delta = quota::acquire_delta(request.artifacts(), body.len())?;
        quota::check_admission(shard_usage, tenant_usage, repository_usage, delta)?;
        sql::apply_usage(tx, scope.tenant_id(), scope.repository_id(), shard, delta).await?;
        sql_rows::insert_acquire(tx, &ack, &digest_hex, &body).await?;
        Ok(PreparedAcquire { ack, replayed: false })
    }

    /// Durably consume one grant and return the private one-shot token.
    ///
    /// The grant is moved in, so a failure (including an unknown `COMMIT`)
    /// burns it permanently: the caller cannot retry the upload with the same
    /// grant. Before any lock or transaction, the grant proves in memory that
    /// its intents, immutable ACK, trusted scope and *full parent operation
    /// tuple* (`repo, tenant, issuer, lane, sequence, op id, digest`) agree, so a
    /// different pending operation can never qualify it. Consumption then
    /// rechecks the exact parent pending/cancel state, the current unserved core
    /// gate proof, the complete canonical hold set and every active
    /// generation-1 hold locator/backend, inserts one immutable receipt per slot
    /// with a unique-slot CAS, and charges quota before returning a token.
    ///
    /// The consume id is the ACK's stable id (allocated at acquire), never a new
    /// random value.
    pub async fn consume(
        &self,
        client: &mut Client,
        grant: ArtifactGrant,
        deadline: Instant,
    ) -> Result<ConsumedArtifacts, ArtifactHoldError> {
        let (scope, operation, ack, uploads) = grant.into_checked_parts()?;
        let consume_request_id = ack.consume_request_id;
        let hold_ids = ack.artifacts.iter().map(|hold| hold.hold_id).collect::<Vec<_>>();
        let tx = begin_bounded(client, deadline).await.map_err(ArtifactHoldError::from)?;
        let prepared = self.consume_stage(&tx, &scope, &operation, &ack, consume_request_id, deadline).await;
        let receipts = match prepared {
            Ok(receipts) => receipts,
            Err(error) => {
                let _ = tx.rollback().await;
                return Err(error);
            }
        };
        match commit_bounded(tx, deadline, scope.repository_id(), Some(operation.operation_id())).await {
            Ok(()) => {
                let consumed = uploads
                    .into_iter()
                    .map(|upload| ConsumedUpload { hold_id: upload.hold_id, slot: upload.slot, intent: upload.intent })
                    .collect();
                // Both ids come straight from the durable acquire ACK: the acquire id
                // was persisted by the acquire transaction and the consume id is its
                // stable, pre-allocated counterpart. Neither is derived here.
                Ok(ConsumedArtifacts::new(ack.request_id, consume_request_id, receipts, consumed))
            }
            Err(RefStoreError::CommitUnknown { .. }) => {
                Err(ArtifactHoldError::ConsumeUnknown { consume_request_id, hold_ids })
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn consume_stage(
        &self,
        tx: &Transaction<'_>,
        scope: &HoldScope,
        operation: &OperationIdentity,
        ack: &AcquireAck,
        consume_request_id: Uuid,
        deadline: Instant,
    ) -> Result<Vec<ConsumeAck>, ArtifactHoldError> {
        before_deadline(deadline, self.consume_checked(tx, scope, operation, ack, consume_request_id, deadline)).await
    }

    async fn consume_checked(
        &self,
        tx: &Transaction<'_>,
        scope: &HoldScope,
        operation: &OperationIdentity,
        ack: &AcquireAck,
        consume_request_id: Uuid,
        deadline: Instant,
    ) -> Result<Vec<ConsumeAck>, ArtifactHoldError> {
        pg::bound(tx, deadline).await?;
        sql::set_ack_durability(tx).await?;
        sql::lock_parent_prefix(tx, operation).await?;
        sql::verify_parent_pending(tx, operation).await?;
        sql::request_lock(tx, consume_request_id).await?;
        // The grant must still name the one committed acquire request row and
        // its exact digest/shard/artifact count; the immutable row is never
        // re-read from the in-memory grant alone.
        let stored_request = sql::stored_acquire(tx, ack.request_id)
            .await?
            .ok_or(ArtifactHoldError::IdentityConflict { request_id: ack.request_id })?;
        stored_request.ensure_ack(ack)?;
        // The row we just read must describe exactly the operation whose
        // pending/cancel rows we locked, not merely one with the same id.
        stored_request.ensure_parent(operation)?;
        if stored_request.consume_request_id != consume_request_id {
            return Err(ArtifactHoldError::LedgerIntegrity("consume id differs from its immutable acquire row"));
        }
        let shard = ack.shard_id()?;
        let shard_usage = sql::lock_shard(tx, shard).await?;
        let (tenant_usage, repository_usage) = sql::lock_usage(tx, scope.tenant_id(), scope.repository_id()).await?;
        let gate = sql::lock_scope_gate(tx, scope).await?;
        if gate.revision() != ack.gate_revision || gate.digest().as_hex() != ack.gate_digest {
            return Err(ArtifactHoldError::ScopeMismatch("current core gate moved before consume"));
        }
        // Lock and compare the *complete* hold batch of this request: exact
        // count, every slot/identity/generation/backend and no extra row.
        let stored = sql_rows::lock_request_holds(tx, ack.request_id).await?;
        ensure_complete_batch(&stored, ack)?;
        for row in &stored {
            let expected = ack
                .hold(row.hold_id)
                .ok_or(ArtifactHoldError::LedgerIntegrity("stored hold row is outside its acquire ACK"))?;
            ensure_granted_hold(row, expected, scope, ack.request_id)?;
            if row.operation_id != ack.operation_id || row.operation_digest != ack.operation_digest {
                return Err(ArtifactHoldError::HoldIdentityMismatch { hold_id: row.hold_id });
            }
            if sql_rows::stored_purpose(&row.purpose)? != scope.purpose() {
                return Err(ArtifactHoldError::ScopeMismatch("stored hold purpose"));
            }
        }
        let existing = sql_rows::receipts_for_request(tx, ack.request_id).await?;
        if let Some(first) = existing.first() {
            return Err(ArtifactHoldError::HoldAlreadyConsumed { hold_id: first.hold_id });
        }
        let now = sql_rows::database_now_micros(tx).await?;
        let mut receipts = Vec::with_capacity(ack.artifacts.len());
        let mut body_total: i64 = 0;
        for hold in &ack.artifacts {
            let receipt = ConsumeAck::new(ack, hold, now);
            let body = receipt.encode()?;
            body_total = body_total
                .checked_add(i64::try_from(body.len()).map_err(|_| {
                    ArtifactHoldError::InvalidRequest("consume receipt body length does not fit i64".into())
                })?)
                .ok_or_else(|| ArtifactHoldError::InvalidRequest("consume receipt byte total overflows i64".into()))?;
            receipts.push(receipt);
        }
        if receipts.len() != ack.artifacts.len() {
            return Err(ArtifactHoldError::LedgerIntegrity("consume batch differs from its acquire ACK"));
        }
        let delta = quota::consume_delta(receipts.len(), body_total)?;
        quota::check_admission(shard_usage, tenant_usage, repository_usage, delta)?;
        sql::apply_usage(tx, scope.tenant_id(), scope.repository_id(), shard, delta).await?;
        for receipt in &receipts {
            let body = receipt.encode()?;
            sql_rows::insert_consume_receipt(tx, receipt, &body).await?;
        }
        Ok(receipts)
    }
}
