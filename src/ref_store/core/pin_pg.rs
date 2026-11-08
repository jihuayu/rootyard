//! Short owned-transaction adapter for metadata pin renew/release.
//!
//! Both mutations keep the same prefix order as snapshot creation: advisory
//! request key -> tenant usage row -> repository usage row -> repository row
//! `FOR SHARE` -> gate -> pin row `FOR UPDATE` -> successful receipt.
//!
//! Renewal rechecks the current A1 unserved predicate and the live lease, then
//! advances the generation by exactly one with a CAS on the expected
//! generation. Release is exact: it uses the stored snapshot/pin scope and
//! generation, is allowed after expiry or a repository transition, and never
//! ends a newer renewed pin, refunds usage, or deletes the immutable identity.
use super::super::contract::{MetadataMutationAction, RefStoreError};
use super::super::pg;
use super::super::tx::{begin_bounded, commit_bounded};
use super::pg::PgRefStoreCore;
use super::pin;
use super::snapshot_contract::{MAX_RECEIPT_BODY_BYTES, receipt_logical_bytes};
use super::snapshot_pg::{metadata_commit_result, replay_receipt};
use super::snapshot_receipt::{MetadataPinOutcome, MetadataPinReceipt, MetadataReceipt, PinReceiptParts};
use super::snapshot_request::{ReleaseMetadataPinRequest, RenewMetadataPinRequest};
use super::snapshot_sql;
use super::snapshot_usage::{self, UsageDelta};
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};

impl PgRefStoreCore {
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
        let result = self.renew_in_tx(&tx, request, deadline).await;
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
                .ok_or_else(|| RefStoreError::Database("renew request id resolved to a non-pin receipt".into()))?;
            return Ok(MetadataPinOutcome { replayed: true, receipt: receipt.clone() });
        }
        let (tenant_usage, repository_usage) =
            snapshot_usage::lock_usage(tx, scope.tenant_id(), scope.repository_id()).await?;
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
        let delta = UsageDelta::receipt(receipt_logical_bytes(MAX_RECEIPT_BODY_BYTES));
        snapshot_usage::check_admission(tenant_usage, repository_usage, delta)?;
        snapshot_usage::apply_usage(tx, scope.tenant_id(), scope.repository_id(), delta).await?;

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
        let result = self.release_in_tx(&tx, request, deadline).await;
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
                .ok_or_else(|| RefStoreError::Database("release request id resolved to a non-pin receipt".into()))?;
            return Ok(MetadataPinOutcome { replayed: true, receipt: receipt.clone() });
        }
        let (tenant_usage, repository_usage) =
            snapshot_usage::lock_usage(tx, scope.tenant_id(), scope.repository_id()).await?;
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
        let delta = UsageDelta::receipt(receipt_logical_bytes(MAX_RECEIPT_BODY_BYTES));
        snapshot_usage::check_admission(tenant_usage, repository_usage, delta)?;
        snapshot_usage::apply_usage(tx, scope.tenant_id(), scope.repository_id(), delta).await?;

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
        let receipt = receipt
            .as_pin()
            .cloned()
            .ok_or_else(|| RefStoreError::Database("release receipt encoding produced the wrong action".into()))?;
        Ok(MetadataPinOutcome { replayed: false, receipt })
    }
}
