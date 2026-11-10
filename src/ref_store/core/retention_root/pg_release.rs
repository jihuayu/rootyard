//! `release` (one-way tombstone + head CAS) and the data-only historical reads (`get`, `query_receipt`).
//!
//! Release is valid before a capture exists: it writes a durable tombstone binding the whole scope and the
//! expected register digest, so a delayed register can never install protection the caller already released. It
//! never touches another consumer's holds, memberships, pins or Blob bytes, and it never refunds retained quota.
//!
//! Every path here uses one absolute deadline: pool wait, `BEGIN`, the local statement/lock bound taken *before*
//! the first query, each SQL stage and the bounded cleanup. No Blob or native Git IO happens in any transaction.
use super::error::RootError;
use super::handle::{RootReceiptQuery, RootRef};
use super::pg::{before_deadline, bound_tx, effective_deadline, pooled_client, rollback_reads};
use super::receipt::{RootAction, RootReceipt, release_body};
use super::record::RootRecord;
use super::request::ReleaseRootRequest;
use super::usage::RootCharge;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use deadpool_postgres::Pool;
use tokio::time::Instant;

impl super::pg::PgRetentionRoots {
    /// Release one root id (or fence a not-yet-registered one). One short bounded transaction, no native IO.
    pub async fn release(
        &self,
        pool: &Pool,
        request: ReleaseRootRequest,
        deadline: Instant,
    ) -> Result<RootReceipt, RootError> {
        let deadline = effective_deadline(deadline)?;
        let scope = *request.scope();
        let repository_id = scope.repository_id();
        let intent = request.intent_digest();
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        if let Err(error) = bound_tx(&tx, deadline).await {
            let _cleanup = rollback_reads(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome = before_deadline(deadline, self.release_in_tx(&tx, &request, intent)).await;
        match outcome {
            Ok(receipt) => {
                commit_bounded(tx, deadline, repository_id, None).await?;
                Ok(receipt)
            }
            Err(error) => {
                let _cleanup = rollback_reads(tx, deadline).await;
                drop(client);
                Err(error)
            }
        }
    }

    async fn release_in_tx(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        request: &ReleaseRootRequest,
        intent: crate::ref_store::contract::RequestDigest,
    ) -> Result<RootReceipt, RootError> {
        let scope = *request.scope();
        let repository_id = scope.repository_id();
        let root_id = request.root_id();

        // (1) Exact replay first: no liveness, no charge, no second tombstone.
        if let Some(row) = super::sql::lookup_receipt(tx, repository_id, request.request_id()).await? {
            super::receipt::verify_scope(&row, &scope)?;
            if row.action != RootAction::Release || row.root_id != root_id || row.request_digest != intent.as_hex() {
                return Err(RootError::RootDigestConflict("release request id reused with a different digest"));
            }
            return RootReceipt::from_row(row, true);
        }

        // (2) Frozen lock order: tenant usage -> repository usage -> core gate -> root rows. Usage rows are locked
        // here with a zero charge; the exact charge is applied below, before the first retained row is written.
        super::sql::lock_usage(tx, &scope).await?;

        // A concurrent identical request may have committed while quota locks waited.
        if let Some(row) = super::sql::lookup_receipt(tx, repository_id, request.request_id()).await? {
            super::receipt::verify_scope(&row, &scope)?;
            if row.action != RootAction::Release || row.root_id != root_id || row.request_digest != intent.as_hex() {
                return Err(RootError::RootDigestConflict("release request id reused with a different digest"));
            }
            return RootReceipt::from_row(row, true);
        }

        // (3) Core gate lock (same order as a ref commit). A release is a terminal data-only fence, so a
        // repository whose gate row is already gone can still be released: the tombstone keeps the root id and
        // its expected register digest unusable, which is what prevents a late register from installing
        // protection the caller already released. A live gate must still belong to the releasing tenant.
        if let Some(gate) = super::sql::gate_realm(tx, repository_id, true).await?
            && gate.tenant_id != scope.tenant_id()
        {
            return Err(RootError::RootRealmMismatch("release gate tenant"));
        }

        // (4) Current head/tombstone probes decide exactly which rows this release writes; nothing is written yet.
        let head = super::sql::head_for_update(tx, repository_id, root_id).await?;
        let tombstone = super::sql::latest_tombstone(tx, repository_id, root_id).await?;
        let head_inserted = match &head {
            Some(head) => {
                super::handle::scope_matches(
                    &scope,
                    head.tenant_id,
                    head.owner_id,
                    head.purpose.as_str(),
                    &head.business_intent_digest,
                )?;
                if head.is_released() {
                    return Err(RootError::RootReleased { repository_id, root_id, generation: head.last_generation });
                }
                if !head.is_active() {
                    return Err(RootError::RootGenerationConflict {
                        root_id,
                        expected_generation: request.expected_generation(),
                        actual_generation: head.last_generation,
                    });
                }
                // Generation + digest CAS: a stale release never releases a newer/different register intent.
                if head.register_digest != request.expected_register_digest().as_hex() {
                    return Err(RootError::RootGenerationConflict {
                        root_id,
                        expected_generation: request.expected_generation(),
                        actual_generation: head.last_generation,
                    });
                }
                false
            }
            None => {
                if let Some(tombstone) = &tombstone {
                    super::handle::scope_matches(
                        &scope,
                        tombstone.tenant_id,
                        tombstone.owner_id,
                        tombstone.purpose.as_str(),
                        &tombstone.business_intent_digest,
                    )?;
                    return Err(super::sql::refuse_released(
                        tombstone,
                        root_id,
                        repository_id,
                        &request.expected_register_digest(),
                    ));
                }
                // Release-before-register: the released head records the register digest it fences.
                true
            }
        };
        let tombstone_inserted = match &tombstone {
            Some(existing) => {
                if existing.release_digest != request.release_digest().as_hex() {
                    return Err(RootError::RootDigestConflict("root id is already released with a different digest"));
                }
                false
            }
            None => true,
        };

        // (5) Bounded receipt body, then the exact charge from the actual canonical column bytes of the rows this
        // transaction is about to write, applied under both already-locked usage rows before the first write.
        let body = release_body(
            &scope,
            root_id,
            &request.expected_register_digest(),
            &request.release_digest(),
            request.reason(),
            head_inserted,
        )?;
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|_| {
                RootError::Store(crate::ref_store::contract::RefStoreError::Database(
                    "root release receipt body cannot be serialized".into(),
                ))
            })?
            .len();
        let charge = RootCharge::release(
            &scope,
            &request.expected_register_digest(),
            request.reason(),
            body_bytes,
            head_inserted,
            tombstone_inserted,
        );
        super::sql::apply_charge(tx, &scope, charge).await?;

        // (6) Retained writes, all in this same transaction, now that every row is charged.
        match &head {
            Some(_) => {
                if !super::sql::mark_head_released(tx, repository_id, root_id).await? {
                    return Err(RootError::RootGenerationConflict {
                        root_id,
                        expected_generation: request.expected_generation(),
                        actual_generation: 1,
                    });
                }
            }
            None => {
                super::sql::insert_head(tx, &scope, root_id, &request.expected_register_digest(), true).await?;
            }
        }
        if tombstone_inserted {
            super::sql::insert_tombstone(
                tx,
                &scope,
                root_id,
                request.request_id(),
                &request.release_digest(),
                &request.expected_register_digest(),
                request.reason(),
            )
            .await?;
        }
        let created_at = super::sql::insert_receipt(
            tx,
            request.request_id(),
            &scope,
            root_id,
            2,
            RootAction::Release,
            &intent,
            &body,
        )
        .await?;
        Ok(RootReceipt::new(
            RootAction::Release,
            false,
            repository_id,
            scope.tenant_id(),
            scope.owner_id(),
            root_id,
            2,
            intent,
            body,
            created_at,
        ))
    }

    /// Data-only historical read of one retained capture. Never requires the source pin/snapshot or the
    /// repository to still exist; the complete retained binding is re-proved before the value is returned.
    pub async fn get(&self, pool: &Pool, root: RootRef, deadline: Instant) -> Result<Option<RootRecord>, RootError> {
        let deadline = effective_deadline(deadline)?;
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        if let Err(error) = bound_tx(&tx, deadline).await {
            let _cleanup = rollback_reads(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let read = before_deadline(deadline, async {
            let head = super::sql::head_state(&tx, root.repository_id(), root.root_id()).await?;
            let capture = super::sql_read::read_capture(&tx, root).await?;
            Ok::<_, RootError>((head, capture))
        })
        .await;
        let result = read.and_then(|(head, capture)| match capture {
            Some(capture) => {
                let state = head.map(|head| head.state).unwrap_or_else(|| "released".to_owned());
                capture.binding_digest()?;
                Ok(Some(RootRecord::new(state, capture)))
            }
            None => Ok(None),
        });
        let cleanup = rollback_reads(tx, deadline).await;
        drop(client);
        match (result, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    /// Exact historical receipt by request id under the complete trusted scope. No current gate/authority needed.
    pub async fn query_receipt(
        &self,
        pool: &Pool,
        query: RootReceiptQuery,
        deadline: Instant,
    ) -> Result<Option<RootReceipt>, RootError> {
        let deadline = effective_deadline(deadline)?;
        let scope = *query.scope();
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        if let Err(error) = bound_tx(&tx, deadline).await {
            let _cleanup = rollback_reads(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let read = before_deadline(deadline, async {
            let row = super::sql::lookup_receipt(&tx, scope.repository_id(), query.request_id()).await?;
            match row {
                Some(row) => {
                    super::receipt::verify_scope(&row, &scope)?;
                    Ok(Some(RootReceipt::from_row(row, true)?))
                }
                None => Ok(None),
            }
        })
        .await;
        let cleanup = rollback_reads(tx, deadline).await;
        drop(client);
        match (read, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
}
