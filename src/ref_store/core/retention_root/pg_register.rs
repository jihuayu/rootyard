//! `register`: one short transaction that turns a sealed candidate into an immutable, non-expiring root.
//!
//! Lock/serialization order is the frozen cross-feature order: tenant usage row, then repository usage row, then
//! the core gate row `FOR UPDATE` (so a root change and a ref commit serialize on the same gate), then the
//! separate protocol-state row (monotone `roots_revision`), then the root head/tombstone/capture rows. The usage
//! rows are locked *before* the gate with a zero charge and the exact charge is applied atomically after the
//! protocol bump, immediately before the first retained row is written. The exact `(repository_id, request_id)`
//! replay is decided **before** any lock, liveness or quota work, and nothing is ever refunded.
//!
//! One absolute deadline bounds the pool wait, `BEGIN`, the local statement/lock timeouts, every SQL stage and the
//! bounded commit/cleanup. No Blob or native Git IO happens inside this transaction.
use super::error::RootError;
use super::pg::{PgRetentionRoots, before_deadline, bound_tx, effective_deadline, pooled_client, rollback_reads};
use super::receipt::{RootAction, RootReceipt, register_body};
use super::request::RegisterRootRequest;
use super::usage::RootCharge;
use crate::ref_store::core::pack_commit::refs_digest;
use crate::ref_store::core::pack_snapshot::PgPackSnapshot;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use deadpool_postgres::Pool;
use tokio::time::Instant;
use uuid::Uuid;

impl PgRetentionRoots {
    /// Phase 2: commit one sealed root capture.
    ///
    /// One call uses exactly one effective deadline for the pool wait, the local statement/lock bound, every SQL
    /// stage, the commit and any cleanup. The transaction never runs native Git or Blob IO.
    pub async fn register(
        &self,
        pool: &Pool,
        request: RegisterRootRequest,
        deadline: Instant,
    ) -> Result<RootReceipt, RootError> {
        let deadline = effective_deadline(deadline)?;
        let request_digest = request.digest();
        let (candidate, request_id) = request.into_parts();
        let repository_id = candidate.scope().repository_id();
        let operation_id = candidate.operation_id();
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        // Absolute row-lock/statement bound *before* the first query: a bounded `BEGIN` alone never bounds a
        // blocked `FOR UPDATE`/`FOR SHARE` wait.
        if let Err(error) = bound_tx(&tx, deadline).await {
            let _cleanup = rollback_reads(tx, deadline).await;
            drop(client);
            return Err(error);
        }
        let outcome =
            before_deadline(deadline, self.register_in_tx(&tx, &candidate, request_id, request_digest, deadline)).await;
        match outcome {
            Ok(receipt) => {
                commit_bounded(tx, deadline, repository_id, Some(operation_id)).await?;
                Ok(receipt)
            }
            Err(error) => {
                // Bounded cleanup (never an unbounded `rollback().await`) that keeps the typed refusal.
                let _cleanup = rollback_reads(tx, deadline).await;
                drop(client);
                Err(error)
            }
        }
    }

    async fn register_in_tx(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        candidate: &super::candidate::RootCandidate,
        request_id: Uuid,
        request_digest: crate::ref_store::contract::RequestDigest,
        deadline: Instant,
    ) -> Result<RootReceipt, RootError> {
        let scope = *candidate.scope();
        let repository_id = scope.repository_id();
        let root_id = candidate.root_id();
        let register_digest = candidate.register_digest();

        // (1) Exact replay first: an already stored receipt returns without any liveness check or extra charge.
        if let Some(row) = super::sql::lookup_receipt(tx, repository_id, request_id).await? {
            super::receipt::verify_scope(&row, &scope)?;
            if row.action != RootAction::Register
                || row.root_id != root_id
                || row.generation != 1
                || row.request_digest != request_digest.as_hex()
            {
                return Err(RootError::RootDigestConflict("register request id reused with a different digest"));
            }
            return RootReceipt::from_row(row, true);
        }

        // (2) Frozen lock order: tenant usage -> repository usage -> core gate -> protocol -> root rows. The two
        // usage rows are locked here with a zero charge so a deadlock-prone gate-first order is never taken; the
        // exact charge is applied below, in this same transaction, before the first retained row is written.
        super::sql::lock_usage(tx, &scope).await?;

        // A concurrent identical request may have committed while quota locks waited.
        if let Some(row) = super::sql::lookup_receipt(tx, repository_id, request_id).await? {
            super::receipt::verify_scope(&row, &scope)?;
            if row.action != RootAction::Register
                || row.root_id != root_id
                || row.generation != 1
                || row.request_digest != request_digest.as_hex()
            {
                return Err(RootError::RootDigestConflict("register request id reused with a different digest"));
            }
            return RootReceipt::from_row(row, true);
        }

        // (3) Core gate lock: the same gate `CommitRefs`/A4 take, so a root change is serialized with ref commits
        // and the fresh source recheck cannot be invalidated by a concurrent realm/gate move.
        let gate = super::sql::gate_realm(tx, repository_id, true)
            .await?
            .ok_or(RootError::RootAuthorityRequired("register requires a live core gate"))?;
        super::sql::require_realm(
            &gate,
            &scope,
            scope.object_format(),
            scope.history_incarnation(),
            scope.authority_epoch(),
            scope.group_epoch(),
            "register gate realm",
        )?;

        // (4) Fresh revalidation of the ORIGINAL active pin + realm + complete immutable pack identity under the
        // gate lock. This re-reads the source snapshot rows (and locks the pin FOR SHARE) and re-checks liveness,
        // generation, expiry and release; the sealed candidate must agree byte for byte.
        let fresh = PgPackSnapshot.read_checked(tx, candidate.reference(), deadline).await?;
        candidate.verify_source(&fresh)?;

        // (5) Monotone separate protocol revision (never a gate row shape change). It becomes durable only with
        // the capture rows below, so any later refusal rolls the bump back with the whole transaction.
        let roots_revision = super::sql::bump_roots_revision(tx, &scope).await?;

        // (6) A release-before-register tombstone refuses the delayed register before any row or charge exists.
        if let Some(tombstone) = super::sql::latest_tombstone(tx, repository_id, root_id).await? {
            super::handle::scope_matches(
                &scope,
                tombstone.tenant_id,
                tombstone.owner_id,
                tombstone.purpose.as_str(),
                &tombstone.business_intent_digest,
            )?;
            return Err(super::sql::refuse_released(&tombstone, root_id, repository_id, &register_digest));
        }

        // (7) Root id is single-capture: never reused, never reopened, never overwritten.
        if let Some(head) = super::sql::head_for_update(tx, repository_id, root_id).await? {
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
            if head.register_digest != register_digest.as_hex() {
                return Err(RootError::RootDigestConflict("root id is already bound to a different register digest"));
            }
            return Err(RootError::RootAlreadyActive { repository_id, root_id });
        }

        // (8) Bounded canonical receipt body, then the exact charge computed from the actual canonical column
        // bytes of every row this transaction is about to write, applied atomically under both already-locked
        // usage rows and before the first retained row.
        let body = register_body(
            &scope,
            root_id,
            candidate.operation_id(),
            &candidate.operation_digest(),
            candidate.source_snapshot_id(),
            candidate.source_pin_id(),
            candidate.source_pin_generation(),
            &candidate.source_read_digest_hex(),
            &register_digest,
            &candidate.binding_digest().as_hex(),
            candidate.selector_kind().as_str(),
            &refs_digest(candidate.captured_refs()).as_hex(),
            &crate::ref_store::core::pack_commit::packs_digest(candidate.packs()).as_hex(),
            candidate.gate_revision,
            &candidate.gate_digest,
            candidate.ref_count(),
            i64::try_from(candidate.root_oids().len()).unwrap_or(i64::MAX),
            candidate.pack_count(),
            roots_revision,
        )?;
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|_| {
                RootError::Store(crate::ref_store::contract::RefStoreError::Database(
                    "root receipt body cannot be serialized".into(),
                ))
            })?
            .len();
        let charge = RootCharge::register(candidate, body_bytes);
        super::sql::apply_charge(tx, &scope, charge).await?;

        // (9) All retained rows in this same transaction.
        super::sql::insert_head(tx, &scope, root_id, &register_digest, false).await?;
        super::sql_insert::insert_capture(tx, candidate, request_id, roots_revision).await?;
        super::sql_insert::insert_refs(tx, repository_id, root_id, candidate.captured_refs()).await?;
        super::sql_insert::insert_oids(tx, repository_id, root_id, candidate.root_oids()).await?;
        super::sql_insert::insert_packs(tx, repository_id, root_id, candidate.packs()).await?;
        let created_at = super::sql::insert_receipt(
            tx,
            request_id,
            &scope,
            root_id,
            1,
            RootAction::Register,
            &request_digest,
            &body,
        )
        .await?;
        Ok(RootReceipt::new(
            RootAction::Register,
            false,
            repository_id,
            scope.tenant_id(),
            scope.owner_id(),
            root_id,
            1,
            request_digest,
            body,
            created_at,
        ))
    }
}
