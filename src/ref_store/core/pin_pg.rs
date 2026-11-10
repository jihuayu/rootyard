//! Short owned-transaction adapter for metadata pin renew/release.
//!
//! Both mutations keep the same prefix order as every other A2/A5 write:
//!
//! request advisory key -> permanent pack tenant usage (only when the pin's
//! stored snapshot is pack-aware) -> A2 tenant usage -> permanent pack repository
//! usage -> A2 repository usage -> repository row `FOR SHARE` -> gate -> pin row
//! `FOR UPDATE` -> successful receipt -> permanent history row.
//!
//! Two fences matter here:
//!
//! * **Exact old replay first.** An identical renew/release request returns its
//!   original receipt before any mode/lifecycle fence, so old A2 receipts keep
//!   replaying exactly.
//! * **Old A2 mutations cannot bypass the A5 ledger.** A fresh renew/release of a
//!   pin whose stored snapshot is `pack_verified` charges the permanent pack
//!   snapshot counters *and* appends a permanent history row in the same
//!   transaction as its A2 receipt, before the pin row is written. The
//!   pack-awareness decision is taken from immutable rows without a lock so the
//!   counters can be locked in the frozen tenant->repository order; the locked
//!   `FOR UPDATE` path re-reads the same immutable header and refuses to proceed
//!   if it disagrees.
//!
//! Renewal rechecks the current A1 unserved predicate and the live lease, then
//! advances the generation by exactly one with a CAS on the expected generation.
//! Release is exact: it uses the stored snapshot/pin scope and generation, is
//! allowed after expiry or a repository transition, and never ends a newer
//! renewed pin, refunds usage, or deletes the immutable identity.
use super::super::contract::{MetadataMutationAction, RefStoreError};
use super::super::pg;
use super::super::tx::{begin_bounded, commit_bounded};
use super::pack_snapshot::{self, usage::PackUsageDelta};
use super::pg::PgRefStoreCore;
use super::pin::{self, SnapshotHeader};
use super::snapshot_contract::{MAX_RECEIPT_BODY_BYTES, receipt_logical_bytes};
use super::snapshot_pg::{metadata_commit_result, replay_receipt};
use super::snapshot_receipt::{MetadataPinOutcome, MetadataPinReceipt, MetadataReceipt, PinReceiptParts};
use super::snapshot_request::{ReleaseMetadataPinRequest, RenewMetadataPinRequest};
use super::snapshot_sql;
use super::snapshot_usage::{self, UsageDelta};
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

/// Permanent logical bytes of one appended history row plus its bounded body.
fn pack_pin_logical_bytes() -> i64 {
    pack_snapshot::history_logical_bytes(pack_snapshot::MAX_PACK_HISTORY_BODY_BYTES)
}

/// For a pack-aware pin: the permanent admission delta that must be charged in
/// the same transaction as its A2 receipt. The A2 counters themselves are
/// admitted inside `lock_pin_usage` and need not be carried further.
struct PinUsage {
    pack: Option<PackUsageDelta>,
}

impl PgRefStoreCore {
    /// Read the stored snapshot header of this pin **without any lock**.
    ///
    /// Only an immutable answer is taken from it (`pack_mode` and the snapshot's
    /// digest fields can never change: the header has an unconditional
    /// `BEFORE UPDATE` refusal). A missing pin or a pin of another
    /// tenant/owner/purpose answers `None`, so the locked path below produces the
    /// ordinary typed error and no permanent counter is touched.
    async fn pack_pin_header(
        &self,
        tx: &Transaction<'_>,
        tenant_id: Uuid,
        owner_id: Uuid,
        purpose: crate::ref_store::MetadataPinPurpose,
        repository_id: Uuid,
        pin_id: Uuid,
    ) -> Result<Option<SnapshotHeader>, RefStoreError> {
        // `pin_identity` is a lock-free read of immutable identity columns only.
        let Some(pin) = snapshot_sql::pin_identity(tx, pin_id, repository_id).await? else { return Ok(None) };
        if pin.tenant_id != tenant_id || pin.owner_id != owner_id || pin.purpose != purpose {
            return Ok(None);
        }
        let header = snapshot_sql::snapshot_header(tx, pin.snapshot_id, repository_id)
            .await?
            .ok_or(RefStoreError::MetadataSnapshotNotFound { snapshot_id: pin.snapshot_id })?;
        Ok(header.is_pack_verified().then_some(header))
    }

    /// A pack-aware exact replay must also see the permanent history partner of
    /// its A2 ledger row; a missing or mismatched partner is ledger integrity and
    /// never a successful replay. Legacy metadata-only receipts are unchanged
    /// (they have no history row by design).
    async fn require_pack_history_partner(
        &self,
        tx: &Transaction<'_>,
        scope: &super::snapshot_contract::MetadataSnapshotScope,
        pin_id: Uuid,
        request_id: Uuid,
        kind: &'static str,
    ) -> Result<(), RefStoreError> {
        let pack_aware = self
            .pack_pin_header(tx, scope.tenant_id(), scope.owner_id(), scope.purpose(), scope.repository_id(), pin_id)
            .await?
            .is_some();
        if !pack_aware {
            return Ok(());
        }
        let ledger = snapshot_sql::stored_receipt(tx, request_id)
            .await?
            .ok_or_else(|| RefStoreError::Database("replayed pack pin receipt vanished".into()))?;
        pack_snapshot::sql::ensure_history_partner(tx, &ledger, scope.owner_id(), kind).await
    }

    /// Lock the two counter families in the frozen order and admit the mutation
    /// before the first persistent business write.
    async fn lock_pin_usage(
        &self,
        tx: &Transaction<'_>,
        scope: &super::snapshot_contract::MetadataSnapshotScope,
        pack_aware: bool,
        a2_delta: UsageDelta,
    ) -> Result<PinUsage, RefStoreError> {
        if pack_aware {
            let pack_tenant = pack_snapshot::usage::lock_tenant(tx, scope.tenant_id()).await?;
            let a2_tenant = snapshot_usage::lock_tenant_usage(tx, scope.tenant_id()).await?;
            let pack_repository =
                pack_snapshot::usage::lock_repository(tx, scope.tenant_id(), scope.repository_id()).await?;
            let a2_repository =
                snapshot_usage::lock_repository_usage(tx, scope.tenant_id(), scope.repository_id()).await?;
            let pack = PackUsageDelta::history_mutation(pack_pin_logical_bytes());
            pack_snapshot::usage::check_admission(pack_tenant, pack_repository, pack)?;
            snapshot_usage::check_admission(a2_tenant, a2_repository, a2_delta)?;
            Ok(PinUsage { pack: Some(pack) })
        } else {
            let (a2_tenant, a2_repository) =
                snapshot_usage::lock_usage(tx, scope.tenant_id(), scope.repository_id()).await?;
            snapshot_usage::check_admission(a2_tenant, a2_repository, a2_delta)?;
            Ok(PinUsage { pack: None })
        }
    }

    /// Renew a live metadata pin: recheck the current unserved predicate, the
    /// stored scope and the generation, then extend the lease and advance the
    /// generation by one. An exact replay returns the old receipt only; it is
    /// not proof the lease is currently live.
    pub async fn renew_metadata_pin(
        &self,
        client: &mut Client,
        request: &RenewMetadataPinRequest,
        deadline: Instant,
    ) -> Result<MetadataPinOutcome, RefStoreError> {
        request.validate()?;
        let tx = begin_bounded(client, deadline).await?;
        let result = async {
            snapshot_sql::durable_write(&tx, deadline).await?;
            self.renew_in_tx(&tx, request, deadline).await
        }
        .await;
        match result {
            Ok(outcome) => {
                let committed = commit_bounded(tx, deadline, request.scope().repository_id(), None).await;
                metadata_commit_result(
                    committed,
                    request.scope().repository_id(),
                    request.request_id(),
                    request.pin_id(),
                    MetadataMutationAction::Renew,
                )?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    async fn renew_in_tx(
        &self,
        tx: &Transaction<'_>,
        request: &RenewMetadataPinRequest,
        deadline: Instant,
    ) -> Result<MetadataPinOutcome, RefStoreError> {
        pg::before_deadline(deadline, self.renew_checked(tx, request, deadline)).await
    }

    async fn renew_checked(
        &self,
        tx: &Transaction<'_>,
        request: &RenewMetadataPinRequest,
        deadline: Instant,
    ) -> Result<MetadataPinOutcome, RefStoreError> {
        let scope = request.scope();
        pg::bound(tx, deadline).await?;
        if let Some(receipt) =
            replay_receipt(tx, scope, request.request_id(), &request.digest(), MetadataMutationAction::Renew).await?
        {
            let receipt = receipt
                .as_pin()
                .ok_or_else(|| RefStoreError::Database("renew request id resolved to a non-pin receipt".into()))?
                .clone();
            self.require_pack_history_partner(
                tx,
                scope,
                request.pin_id(),
                request.request_id(),
                pack_snapshot::sql::HISTORY_RENEWED,
            )
            .await?;
            return Ok(MetadataPinOutcome { replayed: true, receipt });
        }
        // A5 reservation before any quota admission or mutation: exact historical
        // data replays with no new live lease, anything else is a typed conflict.
        if let Some(reservation) = pack_snapshot::sql::reserved_history(
            tx,
            &pack_snapshot::sql::ReservationLookup {
                request_id: request.request_id(),
                scope,
                kind: pack_snapshot::sql::HISTORY_RENEWED,
                snapshot_id: None,
                pin_id: request.pin_id(),
                request_digest: &request.digest().as_hex(),
            },
        )
        .await?
        {
            let receipt = reservation
                .receipt
                .as_pin()
                .ok_or_else(|| RefStoreError::Database("reserved renew request id is not a pin receipt".into()))?
                .clone();
            return Ok(MetadataPinOutcome { replayed: true, receipt });
        }
        // A5 pre-fence from immutable rows: pack-aware pins charge the permanent
        // ledger even when the caller used the old A2 request type.
        let pack_header = self
            .pack_pin_header(
                tx,
                scope.tenant_id(),
                scope.owner_id(),
                scope.purpose(),
                scope.repository_id(),
                request.pin_id(),
            )
            .await?;
        let a2_delta = UsageDelta::receipt(receipt_logical_bytes(MAX_RECEIPT_BODY_BYTES));
        let usage = self.lock_pin_usage(tx, scope, pack_header.is_some(), a2_delta).await?;

        snapshot_sql::lock_scope(tx, scope, true, false).await?;
        let pin = snapshot_sql::pin_for_update(tx, request.pin_id(), scope.repository_id())
            .await?
            .ok_or(RefStoreError::MetadataPinNotFound { pin_id: request.pin_id() })?;
        let header = snapshot_sql::snapshot_header(tx, pin.snapshot_id, scope.repository_id())
            .await?
            .ok_or(RefStoreError::MetadataSnapshotNotFound { snapshot_id: pin.snapshot_id })?;
        header.ensure_scope(scope)?;
        pin.ensure_scope(scope, header.snapshot_id)?;
        pin.ensure_renewable(request.expected_generation())?;
        // Immutable headers cannot legitimately change between the unlocked
        // admission and this lock; a disagreement is ledger tampering.
        if header.is_pack_verified() != usage.pack.is_some() {
            return Err(RefStoreError::Database(
                "pin snapshot pack mode changed between quota admission and the pin lock".into(),
            ));
        }

        if usage.pack.is_some() {
            pack_snapshot::sql::ensure_lifecycle_binding(
                tx,
                header.snapshot_id,
                pin.pin_id,
                scope.repository_id(),
                scope.tenant_id(),
                scope.owner_id(),
            )
            .await?;
        }

        let renewed = snapshot_sql::renew_pin(
            tx,
            request.pin_id(),
            scope.repository_id(),
            request.expected_generation(),
            request.lease_seconds(),
        )
        .await?;
        let Some((generation, expires_at_unix_micros)) = renewed else {
            // The UPDATE predicate re-reads the database clock atomically. The
            // row is still locked, so a zero-row update means the lease crossed
            // expiry (or the state/generation is no longer renewable); never
            // charge usage or write a receipt in that case.
            let locked = snapshot_sql::pin_for_update(tx, request.pin_id(), scope.repository_id())
                .await?
                .ok_or(RefStoreError::MetadataPinNotFound { pin_id: request.pin_id() })?;
            return Err(locked.renew_conflict_error(request.expected_generation()));
        };

        let receipt = MetadataReceipt::Pin(MetadataPinReceipt::from_parts(PinReceiptParts {
            action: MetadataMutationAction::Renew,
            request_id: request.request_id(),
            scope: *scope,
            snapshot_id: header.snapshot_id,
            pin_id: pin.pin_id,
            pin_generation: generation,
            expires_at_unix_micros,
            released_at_unix_micros: None,
            release_reason: None,
        }));
        let body = pin::encode_receipt(&receipt)?;
        snapshot_sql::insert_receipt(
            tx,
            request.request_id(),
            scope,
            MetadataMutationAction::Renew,
            &request.digest().as_hex(),
            &receipt,
            &body,
        )
        .await?;
        if let Some(delta) = usage.pack {
            pack_snapshot::sql::insert_history(
                tx,
                &pack_snapshot::sql::HistoryInsert {
                    request_id: request.request_id(),
                    scope,
                    snapshot_id: header.snapshot_id,
                    pin_id: pin.pin_id,
                    kind: pack_snapshot::sql::HISTORY_RENEWED,
                    request_digest: &request.digest().as_hex(),
                    header: &header,
                    body: &body,
                },
            )
            .await?;
            pack_snapshot::usage::apply(tx, scope.tenant_id(), scope.repository_id(), delta).await?;
        }
        snapshot_usage::apply_usage(tx, scope.tenant_id(), scope.repository_id(), a2_delta).await?;

        let receipt = receipt
            .as_pin()
            .cloned()
            .ok_or_else(|| RefStoreError::Database("renew receipt encoding produced the wrong action".into()))?;
        Ok(MetadataPinOutcome { replayed: false, receipt })
    }

    /// Explicitly release exactly this pin at exactly this generation. Expiry
    /// and a repository transition do not block it; a stale or newer generation
    /// and an already released pin do.
    pub async fn release_metadata_pin(
        &self,
        client: &mut Client,
        request: &ReleaseMetadataPinRequest,
        deadline: Instant,
    ) -> Result<MetadataPinOutcome, RefStoreError> {
        request.validate()?;
        let tx = begin_bounded(client, deadline).await?;
        let result = async {
            snapshot_sql::durable_write(&tx, deadline).await?;
            self.release_in_tx(&tx, request, deadline).await
        }
        .await;
        match result {
            Ok(outcome) => {
                let committed = commit_bounded(tx, deadline, request.scope().repository_id(), None).await;
                metadata_commit_result(
                    committed,
                    request.scope().repository_id(),
                    request.request_id(),
                    request.pin_id(),
                    MetadataMutationAction::Release,
                )?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    async fn release_in_tx(
        &self,
        tx: &Transaction<'_>,
        request: &ReleaseMetadataPinRequest,
        deadline: Instant,
    ) -> Result<MetadataPinOutcome, RefStoreError> {
        pg::before_deadline(deadline, self.release_checked(tx, request, deadline)).await
    }

    async fn release_checked(
        &self,
        tx: &Transaction<'_>,
        request: &ReleaseMetadataPinRequest,
        deadline: Instant,
    ) -> Result<MetadataPinOutcome, RefStoreError> {
        let scope = request.scope();
        pg::bound(tx, deadline).await?;
        if let Some(receipt) =
            replay_receipt(tx, scope, request.request_id(), &request.digest(), MetadataMutationAction::Release).await?
        {
            let receipt = receipt
                .as_pin()
                .ok_or_else(|| RefStoreError::Database("release request id resolved to a non-pin receipt".into()))?
                .clone();
            self.require_pack_history_partner(
                tx,
                scope,
                request.pin_id(),
                request.request_id(),
                pack_snapshot::sql::HISTORY_RELEASED,
            )
            .await?;
            return Ok(MetadataPinOutcome { replayed: true, receipt });
        }
        // A5 reservation before any quota admission or mutation: exact historical
        // data replays with no new live lease, anything else is a typed conflict.
        if let Some(reservation) = pack_snapshot::sql::reserved_history(
            tx,
            &pack_snapshot::sql::ReservationLookup {
                request_id: request.request_id(),
                scope,
                kind: pack_snapshot::sql::HISTORY_RELEASED,
                snapshot_id: None,
                pin_id: request.pin_id(),
                request_digest: &request.digest().as_hex(),
            },
        )
        .await?
        {
            let receipt = reservation
                .receipt
                .as_pin()
                .ok_or_else(|| RefStoreError::Database("reserved release request id is not a pin receipt".into()))?
                .clone();
            return Ok(MetadataPinOutcome { replayed: true, receipt });
        }
        let pack_header = self
            .pack_pin_header(
                tx,
                scope.tenant_id(),
                scope.owner_id(),
                scope.purpose(),
                scope.repository_id(),
                request.pin_id(),
            )
            .await?;
        let a2_delta = UsageDelta::receipt(receipt_logical_bytes(MAX_RECEIPT_BODY_BYTES));
        let usage = self.lock_pin_usage(tx, scope, pack_header.is_some(), a2_delta).await?;

        // Release deliberately does not require the repository to still be an
        // unserved core repository: a transition must not strand a pin. The
        // stored snapshot/pin rows are the authority for its exact scope.
        snapshot_sql::lock_scope(tx, scope, false, false).await?;
        let pin = snapshot_sql::pin_for_update(tx, request.pin_id(), scope.repository_id())
            .await?
            .ok_or(RefStoreError::MetadataPinNotFound { pin_id: request.pin_id() })?;
        let header = snapshot_sql::snapshot_header(tx, pin.snapshot_id, scope.repository_id())
            .await?
            .ok_or(RefStoreError::MetadataSnapshotNotFound { snapshot_id: pin.snapshot_id })?;
        header.ensure_scope(scope)?;
        pin.ensure_scope(scope, header.snapshot_id)?;
        pin.ensure_releasable(request.expected_generation())?;
        if header.is_pack_verified() != usage.pack.is_some() {
            return Err(RefStoreError::Database(
                "pin snapshot pack mode changed between quota admission and the pin lock".into(),
            ));
        }

        if usage.pack.is_some() {
            pack_snapshot::sql::ensure_lifecycle_binding(
                tx,
                header.snapshot_id,
                pin.pin_id,
                scope.repository_id(),
                scope.tenant_id(),
                scope.owner_id(),
            )
            .await?;
        }

        let released = snapshot_sql::release_pin(
            tx,
            request.pin_id(),
            scope.repository_id(),
            request.expected_generation(),
            request.request_id(),
            request.reason(),
        )
        .await?;
        let (generation, released_at_unix_micros, expires_at_unix_micros) =
            released.ok_or_else(|| RefStoreError::Database("locked metadata pin changed during release".into()))?;

        let receipt = MetadataReceipt::Pin(MetadataPinReceipt::from_parts(PinReceiptParts {
            action: MetadataMutationAction::Release,
            request_id: request.request_id(),
            scope: *scope,
            snapshot_id: header.snapshot_id,
            pin_id: pin.pin_id,
            pin_generation: generation,
            expires_at_unix_micros,
            released_at_unix_micros: Some(released_at_unix_micros),
            release_reason: Some(request.reason()),
        }));
        let body = pin::encode_receipt(&receipt)?;
        snapshot_sql::insert_receipt(
            tx,
            request.request_id(),
            scope,
            MetadataMutationAction::Release,
            &request.digest().as_hex(),
            &receipt,
            &body,
        )
        .await?;
        if let Some(delta) = usage.pack {
            pack_snapshot::sql::insert_history(
                tx,
                &pack_snapshot::sql::HistoryInsert {
                    request_id: request.request_id(),
                    scope,
                    snapshot_id: header.snapshot_id,
                    pin_id: pin.pin_id,
                    kind: pack_snapshot::sql::HISTORY_RELEASED,
                    request_digest: &request.digest().as_hex(),
                    header: &header,
                    body: &body,
                },
            )
            .await?;
            pack_snapshot::usage::apply(tx, scope.tenant_id(), scope.repository_id(), delta).await?;
        }
        snapshot_usage::apply_usage(tx, scope.tenant_id(), scope.repository_id(), a2_delta).await?;

        let receipt = receipt
            .as_pin()
            .cloned()
            .ok_or_else(|| RefStoreError::Database("release receipt encoding produced the wrong action".into()))?;
        Ok(MetadataPinOutcome { replayed: false, receipt })
    }
}
