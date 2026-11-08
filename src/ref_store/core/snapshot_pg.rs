//! Short owned-transaction adapter for metadata snapshot creation and pages.
//!
//! `create_metadata_snapshot` materializes the immutable header, the immutable
//! refs, the durable pin and the creation receipt in **one** transaction under
//! the same gate lock `CommitRefs` takes, after the retained tenant/repository
//! usage rows. There is no list-then-pin sequence and no cross-page
//! transaction.
//!
//! `read_metadata_snapshot_page` is one bounded read-write transaction (never
//! `read_only=true`, which PostgreSQL forbids around `SELECT ... FOR SHARE`)
//! that rechecks the current unserved predicate, holds the gate and the pin
//! `FOR SHARE`, and reads only immutable snapshot rows.
//!
//! Lock order for a successful new mutation:
//!
//! request advisory key -> tenant usage row -> repository usage row ->
//! repository row `FOR SHARE` -> core gate -> immutable snapshot/pin ->
//! successful receipt.
//!
//! A1 `CommitRefs` keeps operation -> lane -> repository -> gate; the quota rows
//! are always taken before the gate and never after it, so no path builds the
//! reverse order. Expiry/release never refund usage or delete an identity.
use super::super::contract::{MetadataMutationAction, RefStoreError, RequestDigest};
use super::super::pg;
use super::super::tx::{begin_bounded, commit_bounded};
use super::pg::PgRefStoreCore;
use super::pin;
use super::snapshot_contract::{
    MAX_RECEIPT_BODY_BYTES, MetadataSnapshotScope, pin_logical_bytes, receipt_logical_bytes, refs_digest,
    snapshot_budget_guard, snapshot_logical_bytes,
};
use super::snapshot_receipt::{
    CreateMetadataSnapshotOutcome, MetadataReceipt, MetadataReceiptLookup, MetadataSnapshotPage,
    MetadataSnapshotReceipt, SnapshotReceiptParts,
};
use super::snapshot_request::{CreateMetadataSnapshotRequest, ReadMetadataSnapshotPageRequest};
use super::snapshot_sql::{self, SnapshotInsert};
use super::snapshot_usage::{self, UsageDelta};
use super::types::{GitOid, RefName};
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

/// Convert an unacknowledged `COMMIT` into the accurately typed metadata
/// unknown. It is never an abort or a rejection: the caller resolves it with
/// the same `request_id` through the receipt ledger.
pub(super) fn metadata_commit_result(
    result: Result<(), RefStoreError>,
    repository_id: Uuid,
    request_id: Uuid,
    pin_id: Uuid,
    action: MetadataMutationAction,
) -> Result<(), RefStoreError> {
    result.map_err(|error| match error {
        RefStoreError::CommitUnknown { .. } => {
            RefStoreError::MetadataCommitUnknown { repository_id, request_id, pin_id, action }
        }
        other => other,
    })
}

/// Decode a stored ledger body and prove it agrees with the immutable ledger
/// row, the immutable snapshot header and the immutable pin identity. It is
/// deliberately never compared with the current refs revision, pin generation
/// or expiry: a legitimate renewal/release advances the pin, and an old receipt
/// must remain the exact old receipt.
async fn validate_stored_receipt(
    tx: &Transaction<'_>,
    stored: &snapshot_sql::StoredReceipt,
    scope: &MetadataSnapshotScope,
) -> Result<MetadataReceipt, RefStoreError> {
    let receipt = pin::decode_receipt(stored.action, &stored.body)?;
    pin::ensure_receipt_scope(&receipt, scope)?;
    pin::ensure_receipt_ledger(
        &receipt,
        stored.request_id,
        stored.repository_id,
        stored.tenant_id,
        stored.action,
        stored.pin_id,
        stored.snapshot_id,
        stored.pin_generation,
    )?;
    let header = snapshot_sql::snapshot_header(tx, stored.snapshot_id, scope.repository_id())
        .await?
        .ok_or(RefStoreError::MetadataSnapshotNotFound { snapshot_id: stored.snapshot_id })?;
    header.ensure_scope(scope)?;
    pin::ensure_receipt_snapshot(&receipt, &header)?;
    let pin_identity = snapshot_sql::pin_identity(tx, stored.pin_id, scope.repository_id())
        .await?
        .ok_or(RefStoreError::MetadataPinNotFound { pin_id: stored.pin_id })?;
    pin::ensure_receipt_pin_identity(&receipt, &pin_identity)?;
    Ok(receipt)
}

/// First step of every metadata mutation: serialize on the request id, then
/// replay an existing identical receipt or report a conflict.
pub(super) async fn replay_receipt(
    tx: &Transaction<'_>,
    scope: &MetadataSnapshotScope,
    request_id: Uuid,
    digest: &RequestDigest,
    action: MetadataMutationAction,
) -> Result<Option<MetadataReceipt>, RefStoreError> {
    snapshot_sql::advisory_request_lock(tx, request_id).await?;
    let Some(stored) = snapshot_sql::stored_receipt(tx, request_id).await? else { return Ok(None) };
    if stored.request_id != request_id
        || stored.repository_id != scope.repository_id()
        || stored.tenant_id != scope.tenant_id()
    {
        return Err(RefStoreError::IdentityConflict);
    }
    if stored.action != action || stored.request_digest != digest.as_hex() {
        return Err(RefStoreError::DigestConflict);
    }
    validate_stored_receipt(tx, &stored, scope).await.map(Some)
}

impl PgRefStoreCore {
    /// Capture refs + HEAD + the exact gate revision/digest into immutable rows,
    /// while inserting the retained pin and the creation receipt in the same
    /// short transaction. An exact retry returns the original receipt only; it
    /// never returns a page, revives a released pin or extends an expiry.
    pub async fn create_metadata_snapshot(
        &self,
        client: &mut Client,
        request: &CreateMetadataSnapshotRequest,
        deadline: Instant,
    ) -> Result<CreateMetadataSnapshotOutcome, RefStoreError> {
        request.validate()?;
        let tx = begin_bounded(client, deadline).await?;
        let result = self.create_snapshot_in_tx(&tx, request, deadline).await;
        match result {
            Ok(outcome) => {
                let committed = commit_bounded(tx, deadline, request.scope().repository_id(), None).await;
                metadata_commit_result(
                    committed,
                    request.scope().repository_id(),
                    request.request_id(),
                    request.pin_id(),
                    MetadataMutationAction::Create,
                )?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    async fn create_snapshot_in_tx(
        &self,
        tx: &Transaction<'_>,
        request: &CreateMetadataSnapshotRequest,
        deadline: Instant,
    ) -> Result<CreateMetadataSnapshotOutcome, RefStoreError> {
        pg::before_deadline(deadline, self.create_snapshot_checked(tx, request, deadline)).await
    }

    async fn create_snapshot_checked(
        &self,
        tx: &Transaction<'_>,
        request: &CreateMetadataSnapshotRequest,
        deadline: Instant,
    ) -> Result<CreateMetadataSnapshotOutcome, RefStoreError> {
        let scope = request.scope();
        pg::bound(tx, deadline).await?;
        if let Some(receipt) =
            replay_receipt(tx, scope, request.request_id(), &request.digest(), MetadataMutationAction::Create).await?
        {
            let receipt = receipt
                .as_snapshot()
                .ok_or_else(|| RefStoreError::Database("create request id resolved to a non-create receipt".into()))?;
            return Ok(CreateMetadataSnapshotOutcome { replayed: true, receipt: receipt.clone() });
        }
        let (tenant_usage, repository_usage) =
            snapshot_usage::lock_usage(tx, scope.tenant_id(), scope.repository_id()).await?;

        // Gate `FOR UPDATE` serializes capture with `CommitRefs`, so refs, HEAD
        // and the gate revision/digest are one revision.
        let gate = snapshot_sql::lock_scope(tx, scope, true, true).await?;
        if gate.digest() != request.expected_gate_digest() {
            return Err(RefStoreError::MetadataGateVersionMismatch);
        }
        let refs = snapshot_sql::capture_refs(tx, scope.repository_id()).await?;
        let head_oid = refs.iter().find(|(name, _)| name == gate.head_ref().as_str()).map(|(_, oid)| oid.clone());
        let snapshot_bytes = snapshot_logical_bytes(gate.head_ref().as_str(), head_oid.as_deref(), &refs);
        snapshot_budget_guard(snapshot_bytes, refs.len())?;
        let refs_digest = refs_digest(&refs);
        let delta = UsageDelta {
            snapshots: 1,
            snapshot_refs: refs.len() as i64,
            logical_bytes: snapshot_bytes + pin_logical_bytes() + receipt_logical_bytes(MAX_RECEIPT_BODY_BYTES),
            receipts: 1,
        };
        snapshot_usage::check_admission(tenant_usage, repository_usage, delta)?;
        snapshot_usage::apply_usage(tx, scope.tenant_id(), scope.repository_id(), delta).await?;

        let gate_digest = gate.digest().as_hex();
        let refs_digest_hex = refs_digest.as_hex();
        let insert = SnapshotInsert {
            snapshot_id: request.snapshot_id(),
            scope,
            gate_revision: gate.revision(),
            gate_digest: &gate_digest,
            head_ref: gate.head_ref().as_str(),
            head_oid: head_oid.as_deref(),
            ref_count: refs.len() as i64,
            refs_digest: &refs_digest_hex,
            logical_bytes: snapshot_bytes,
        };
        snapshot_sql::insert_snapshot(tx, &insert).await?;
        snapshot_sql::insert_snapshot_refs(tx, request.snapshot_id(), &refs).await?;
        let expires_at_unix_micros = snapshot_sql::insert_pin(
            tx,
            request.pin_id(),
            scope,
            request.snapshot_id(),
            request.request_id(),
            &request.digest().as_hex(),
            request.lease_seconds(),
        )
        .await?;

        let receipt = MetadataReceipt::Snapshot(MetadataSnapshotReceipt::from_parts(SnapshotReceiptParts {
            request_id: request.request_id(),
            snapshot_id: request.snapshot_id(),
            pin_id: request.pin_id(),
            pin_generation: 1,
            scope: *scope,
            gate_revision: gate.revision(),
            gate_digest: gate.digest().as_hex(),
            head_ref: gate.head_ref().as_str().to_owned(),
            head_oid,
            ref_count: refs.len() as i64,
            refs_digest: refs_digest_hex,
            logical_bytes: snapshot_bytes,
            expires_at_unix_micros,
        }));
        let body = pin::encode_receipt(&receipt)?;
        snapshot_sql::insert_receipt(
            tx,
            request.request_id(),
            scope,
            MetadataMutationAction::Create,
            &request.digest().as_hex(),
            &receipt,
            &body,
        )
        .await?;
        let receipt = receipt
            .as_snapshot()
            .cloned()
            .ok_or_else(|| RefStoreError::Database("create receipt encoding produced the wrong action".into()))?;
        Ok(CreateMetadataSnapshotOutcome { replayed: false, receipt })
    }

    /// One bounded page over immutable snapshot rows. The current unserved
    /// predicate, the immutable row scope, the live pin generation and the
    /// pinned cursor scope are all rechecked; a release `FOR UPDATE` orders
    /// after an admitted page.
    pub async fn read_metadata_snapshot_page(
        &self,
        client: &mut Client,
        request: &ReadMetadataSnapshotPageRequest,
        deadline: Instant,
    ) -> Result<MetadataSnapshotPage, RefStoreError> {
        request.validate()?;
        let tx = begin_bounded(client, deadline).await?;
        let result = self.page_in_tx(&tx, request, deadline).await;
        let _ = tx.rollback().await;
        result
    }

    async fn page_in_tx(
        &self,
        tx: &Transaction<'_>,
        request: &ReadMetadataSnapshotPageRequest,
        deadline: Instant,
    ) -> Result<MetadataSnapshotPage, RefStoreError> {
        pg::before_deadline(deadline, self.page_checked(tx, request, deadline)).await
    }

    async fn page_checked(
        &self,
        tx: &Transaction<'_>,
        request: &ReadMetadataSnapshotPageRequest,
        deadline: Instant,
    ) -> Result<MetadataSnapshotPage, RefStoreError> {
        pg::bound(tx, deadline).await?;
        let scope = request.scope();
        // Repository/gate `FOR SHARE`: new pages and renewals stop once the
        // repository leaves the unserved core state; immutable old rows remain.
        snapshot_sql::lock_scope(tx, scope, true, false).await?;
        let header = snapshot_sql::snapshot_header(tx, request.snapshot_id(), scope.repository_id())
            .await?
            .ok_or(RefStoreError::MetadataSnapshotNotFound { snapshot_id: request.snapshot_id() })?;
        header.ensure_scope(scope)?;
        let pin = snapshot_sql::pin_for_share(tx, request.pin_id(), scope.repository_id())
            .await?
            .ok_or(RefStoreError::MetadataPinNotFound { pin_id: request.pin_id() })?;
        pin.ensure_scope(scope, header.snapshot_id)?;
        pin.ensure_live(request.pin_generation())?;

        let after = request.cursor().map(|cursor| cursor.after().as_str().to_owned());
        let prefix = request.prefix().map(|prefix| prefix.as_str().to_owned());
        let limit = i64::from(request.limit());
        let rows =
            snapshot_sql::page_refs(tx, request.snapshot_id(), after.as_deref(), prefix.as_deref(), limit + 1).await?;
        let more = rows.len() as i64 > limit;
        let rows = rows.into_iter().take(limit as usize).collect::<Vec<_>>();
        let mut refs = Vec::with_capacity(rows.len());
        for (name, oid) in rows {
            refs.push(super::snapshot_receipt::MetadataSnapshotRef::new(
                RefName::new(name)?,
                GitOid::parse(header.object_format, &oid)?,
            ));
        }
        let next = more.then(|| {
            refs.last().map(|last| {
                super::snapshot_contract::MetadataSnapshotCursor::new(
                    *scope,
                    request.snapshot_id(),
                    request.pin_id(),
                    request.pin_generation(),
                    request.prefix().cloned(),
                    last.name().clone(),
                )
            })
        });
        let next = match next {
            Some(next) => Some(
                next.ok_or_else(|| RefStoreError::Database("a non-final metadata page yielded no cursor row".into()))?,
            ),
            None => None,
        };
        Ok(MetadataSnapshotPage::new(
            header.snapshot_id,
            pin.pin_id,
            pin.generation,
            header.gate_revision,
            header.ref_count,
            refs,
            next,
        ))
    }

    /// Scoped receipt/pin-status lookup for an unknown metadata COMMIT. A
    /// missing request id is `Unknown`, never a success or an abort guess, and
    /// there is no unrestricted get-by-guessed-UUID path.
    pub async fn metadata_receipt(
        &self,
        client: &mut Client,
        scope: &MetadataSnapshotScope,
        request_id: Uuid,
        deadline: Instant,
    ) -> Result<MetadataReceiptLookup, RefStoreError> {
        if request_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("metadata request id must be non-nil".into()));
        }
        let tx = begin_bounded(client, deadline).await?;
        let result = pg::before_deadline(deadline, async {
            pg::bound(&tx, deadline).await?;
            match snapshot_sql::stored_receipt(&tx, request_id).await? {
                None => Ok(MetadataReceiptLookup::Unknown),
                Some(stored) => {
                    if stored.repository_id != scope.repository_id() || stored.tenant_id != scope.tenant_id() {
                        return Err(RefStoreError::RepositoryNotFound);
                    }
                    let receipt = validate_stored_receipt(&tx, &stored, scope).await?;
                    Ok(MetadataReceiptLookup::Found(receipt))
                }
            }
        })
        .await;
        let _ = tx.rollback().await;
        result
    }
}
