//! Short owned-transaction adapter for the A5a complete registered-pack
//! snapshot.
//!
//! Three entry points, each one owned transaction from a caller
//! `&mut tokio_postgres::Client`:
//!
//! * [`PgPackSnapshot::create`] — capture `gate.revision + pack_mode + ALL refs +
//!   HEAD + ALL active registered memberships` and write the immutable header,
//!   the immutable refs, the pack bindings, the durable pin, the A2 creation
//!   receipt, the permanent history row and both retained counter families in
//!   **one** transaction under the same gate `FOR UPDATE` that `CommitRefs` and
//!   the A4 verified commit take.
//! * [`PgPackSnapshot::read`] — one bounded transaction that rechecks the current
//!   unserved/pack realm, the live pin generation/lease and re-derives every
//!   digest from the immutable rows.
//! * [`PgPackSnapshot::query_receipt`] — historical receipt resolution by request
//!   id with no current authority, from the A2 ledger while the repository exists
//!   and from the permanent history ledger after it was deleted.
//!
//! Frozen lock order of every write here:
//!
//! request advisory key -> permanent pack tenant usage -> A2 tenant usage ->
//! permanent pack repository usage -> A2 repository usage -> repository row
//! `FOR SHARE` (unserved predicate) -> core gate `FOR UPDATE` ->
//! immutable snapshot/pin/binding rows -> A2 receipt -> permanent history.
//!
//! No BlobStore call, Git child, temp file, network fetch or pool lease exists in
//! this module: it is PostgreSQL metadata only, and the caller's absolute
//! deadline covers transaction acquisition, every SQL stage and `COMMIT`.
use super::super::pack_commit::{self, CapturedRef, PackMode};
use super::super::pin;
use super::super::snapshot_contract::{
    MAX_RECEIPT_BODY_BYTES, MAX_SNAPSHOT_REFS, pin_logical_bytes, receipt_logical_bytes, refs_digest,
    snapshot_budget_guard, snapshot_logical_bytes,
};
use super::super::snapshot_pg::{metadata_commit_result, replay_receipt};
use super::super::snapshot_receipt::{
    MetadataReceipt, MetadataSnapshotReceipt, PackReceiptFields, SnapshotReceiptParts,
};
use super::super::snapshot_sql::{self, PackHeaderInsert, SnapshotInsert};
use super::super::snapshot_usage::{self, UsageDelta};
use super::contract as pack_contract;
use super::read_snapshot::{PackReadSnapshot, ReadSnapshotParts};
use super::receipt::{PackSnapshotOutcome, PackSnapshotReceipt, StoredPackSnapshot};
use super::request::{CreatePackSnapshotRequest, PackSnapshotRef};
use super::sql;
use super::usage::{self, PackUsageDelta};
use crate::ref_store::contract::{MetadataMutationAction, RefStoreError};
use crate::ref_store::pg;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};

/// Stateless PostgreSQL adapter for the A5a pack snapshot slice.
#[derive(Clone, Copy, Debug, Default)]
pub struct PgPackSnapshot;

impl PgPackSnapshot {
    /// Capture one complete pack-aware snapshot plus its pin, receipt and
    /// permanent history row.
    ///
    /// An exact retry returns the original receipt only (never a fresh snapshot,
    /// a revived pin or an extended lease); a changed retry under the same global
    /// request id is a typed conflict with zero writes. An unacknowledged
    /// `COMMIT` is reported as the metadata-unknown error and returns no value.
    pub async fn create(
        &self,
        client: &mut Client,
        request: &CreatePackSnapshotRequest,
        deadline: Instant,
    ) -> Result<PackSnapshotOutcome, RefStoreError> {
        request.validate()?;
        let repository_id = request.scope().repository_id();
        let tx = begin_bounded(client, deadline).await?;
        let result = async {
            snapshot_sql::durable_write(&tx, deadline).await?;
            pg::before_deadline(deadline, self.create_checked(&tx, request, deadline)).await
        }
        .await;
        match result {
            Ok(outcome) => {
                let committed = commit_bounded(tx, deadline, repository_id, None).await;
                metadata_commit_result(
                    committed,
                    repository_id,
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

    async fn create_checked(
        &self,
        tx: &Transaction<'_>,
        request: &CreatePackSnapshotRequest,
        deadline: Instant,
    ) -> Result<PackSnapshotOutcome, RefStoreError> {
        let scope = request.scope();
        let repository_id = scope.repository_id();
        pg::bound(tx, deadline).await?;

        // (1) Exact old-replay first: one global request-id space, and this
        // happens *before* any fresh mode/lifecycle/quota fence. An old A2
        // metadata create receipt still replays as itself; a pack request id that
        // already holds a metadata receipt is a digest conflict, not a replay.
        if let Some(receipt) =
            replay_receipt(tx, scope, request.request_id(), &request.digest(), MetadataMutationAction::Create).await?
        {
            let snapshot = receipt
                .as_snapshot()
                .ok_or_else(|| RefStoreError::Database("create request id resolved to a non-create receipt".into()))?;
            if snapshot.pack_mode() != Some(pack_contract::PACK_MODE_VERIFIED) {
                return Err(RefStoreError::DigestConflict);
            }
            let header = snapshot_sql::snapshot_header(tx, snapshot.snapshot_id(), repository_id)
                .await?
                .ok_or(RefStoreError::MetadataSnapshotNotFound { snapshot_id: snapshot.snapshot_id() })?;
            let stored = StoredPackSnapshot::from_header(&header)?;
            // A pack-aware create replay must see BOTH immutable rows written by
            // its original transaction; a missing partner is ledger integrity,
            // never a successful replay.
            let ledger = snapshot_sql::stored_receipt(tx, request.request_id())
                .await?
                .ok_or_else(|| RefStoreError::Database("replayed pack create receipt vanished".into()))?;
            sql::ensure_history_partner(tx, &ledger, header.owner_id, sql::HISTORY_CREATED).await?;
            return Ok(PackSnapshotOutcome {
                replayed: true,
                receipt: PackSnapshotReceipt::from_stored(snapshot, &stored)?,
            });
        }

        // (1b) Permanent reservation: after exact A2 replay and before any quota
        // lock or business write, a request id that already names a permanent A5
        // operation is either the exact historical operation (replayed, minting
        // no new live lease) or a typed conflict, never a generic uniqueness
        // failure after admission work.
        let request_digest = request.digest().as_hex();
        if let Some(reservation) = sql::reserved_history(
            tx,
            &sql::ReservationLookup {
                request_id: request.request_id(),
                scope,
                kind: sql::HISTORY_CREATED,
                snapshot_id: Some(request.snapshot_id()),
                pin_id: request.pin_id(),
                request_digest: &request_digest,
            },
        )
        .await?
        {
            let snapshot = reservation.receipt.as_snapshot().ok_or_else(|| {
                RefStoreError::Database("reserved pack create request id is not a create receipt".into())
            })?;
            if snapshot.pack_mode() != Some(pack_contract::PACK_MODE_VERIFIED) {
                return Err(RefStoreError::DigestConflict);
            }
            let stored = StoredPackSnapshot::from_history(&reservation.history, snapshot)?;
            return Ok(PackSnapshotOutcome {
                replayed: true,
                receipt: PackSnapshotReceipt::from_stored(snapshot, &stored)?,
            });
        }

        // (2) Frozen quota prefix: pack tenant -> A2 tenant -> pack repository ->
        // A2 repository. Every write path uses this same total order.
        let pack_tenant = usage::lock_tenant(tx, scope.tenant_id()).await?;
        let a2_tenant = snapshot_usage::lock_tenant_usage(tx, scope.tenant_id()).await?;
        let pack_repository = usage::lock_repository(tx, scope.tenant_id(), repository_id).await?;
        let a2_repository = snapshot_usage::lock_repository_usage(tx, scope.tenant_id(), repository_id).await?;

        // (3) Exact A2 repository/gate fence, then the pack-mode and expected
        // gate proof. The gate `FOR UPDATE` serializes with `CommitRefs` and the
        // A4 verified commit, so refs, HEAD and memberships are one revision.
        let gate = snapshot_sql::lock_scope(tx, scope, true, true).await?;
        if snapshot_sql::gate_pack_mode(tx, repository_id).await? != PackMode::PackVerified {
            return Err(RefStoreError::Unsupported("fresh pack snapshot capture requires a pack_verified gate"));
        }
        request.expected().check(&gate)?;

        // (3b) Retained create identity. A pack snapshot id or pin id may never
        // be reused, even after the A2 rows of an earlier snapshot were cascaded
        // away with a deleted repository: old permanent receipts still name them.
        // Only `created` history rows are considered (renew/release repeat the
        // pair by design), and this is checked before any charge or write.
        if sql::retained_create_identity(tx, request.snapshot_id(), request.pin_id()).await?.is_some() {
            return Err(RefStoreError::IdentityConflict);
        }

        // (4) Capture ALL refs (bounded) and HEAD.
        let refs = snapshot_sql::capture_refs(tx, repository_id).await?;
        let head_oid = refs.iter().find(|(name, _)| name == gate.head_ref().as_str()).map(|(_, oid)| oid.clone());
        let head_ref = gate.head_ref().as_str().to_owned();
        let snapshot_bytes = snapshot_logical_bytes(&head_ref, head_oid.as_deref(), &refs);
        snapshot_budget_guard(snapshot_bytes, refs.len())?;
        let refs_digest = refs_digest(&refs);
        let refs_digest_hex = refs_digest.as_hex();
        let ref_count = i64::try_from(refs.len()).unwrap_or(i64::MAX);

        // (5) ALL memberships through the A4 reader (full publication/ACK/
        // artifact/A3-ledger validation, stored publisher owner, joined-revision
        // rules). A `pack_verified` gate always has at least one active pack.
        let packs =
            pack_commit::read_membership_set(tx, &gate, deadline).await.map_err(pack_contract::map_pack_error)?;
        if packs.is_empty() {
            return Err(RefStoreError::Database("pack_verified gate has no active registered pack membership".into()));
        }
        let entries = pack_contract::membership_entries(&packs)?;
        let membership_hex = pack_contract::membership_digest(&packs)?.as_hex();
        let pack_count = i64::try_from(entries.len()).unwrap_or(i64::MAX);
        let gate_digest_hex = gate.digest().as_hex();
        let snapshot_digest_hex = pack_contract::snapshot_digest(
            scope,
            request.snapshot_id(),
            gate.revision(),
            &gate_digest_hex,
            &head_ref,
            head_oid.as_deref(),
            ref_count,
            &refs_digest_hex,
            &membership_hex,
            pack_count,
        )
        .as_hex();
        let logical_bytes = snapshot_bytes.saturating_add(pack_contract::pack_binding_logical_bytes(entries.len()));

        // (6) Full admission of BOTH counter families before the first write.
        let a2_delta = UsageDelta {
            snapshots: 1,
            snapshot_refs: ref_count,
            logical_bytes: snapshot_bytes
                .saturating_add(pin_logical_bytes())
                .saturating_add(receipt_logical_bytes(MAX_RECEIPT_BODY_BYTES)),
            receipts: 1,
        };
        let pack_delta = PackUsageDelta {
            snapshots: 1,
            refs: ref_count,
            bindings: pack_count,
            pins: 1,
            history: 1,
            receipts: 1,
            logical_bytes: snapshot_bytes
                .saturating_add(pack_contract::pack_binding_logical_bytes(entries.len()))
                .saturating_add(pin_logical_bytes())
                .saturating_add(receipt_logical_bytes(MAX_RECEIPT_BODY_BYTES))
                .saturating_add(pack_contract::history_logical_bytes(pack_contract::MAX_PACK_HISTORY_BODY_BYTES)),
        };
        snapshot_usage::check_admission(a2_tenant, a2_repository, a2_delta)?;
        usage::check_admission(pack_tenant, pack_repository, pack_delta)?;

        // (7) One atomic write set: header, refs, bindings, pin, receipt, history.
        snapshot_sql::insert_snapshot(
            tx,
            &SnapshotInsert {
                snapshot_id: request.snapshot_id(),
                scope,
                gate_revision: gate.revision(),
                gate_digest: &gate_digest_hex,
                head_ref: &head_ref,
                head_oid: head_oid.as_deref(),
                ref_count,
                refs_digest: &refs_digest_hex,
                logical_bytes,
                pack: Some(PackHeaderInsert {
                    pack_count,
                    membership_digest: &membership_hex,
                    snapshot_digest: &snapshot_digest_hex,
                }),
            },
        )
        .await?;
        snapshot_sql::insert_snapshot_refs(tx, request.snapshot_id(), &refs).await?;
        sql::insert_bindings(tx, repository_id, request.snapshot_id(), &entries).await?;
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
            gate_digest: gate_digest_hex.clone(),
            head_ref: head_ref.clone(),
            head_oid: head_oid.clone(),
            ref_count,
            refs_digest: refs_digest_hex.clone(),
            logical_bytes,
            expires_at_unix_micros,
            pack: Some(PackReceiptFields {
                pack_count,
                membership_digest: membership_hex.clone(),
                snapshot_digest: snapshot_digest_hex.clone(),
            }),
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

        // (8) Read back the immutable header and prove it is exactly what this
        // transaction intended; the permanent history row is built from the
        // *stored* header, never from local variables.
        let header = snapshot_sql::snapshot_header(tx, request.snapshot_id(), repository_id)
            .await?
            .ok_or(RefStoreError::MetadataSnapshotNotFound { snapshot_id: request.snapshot_id() })?;
        if header.gate_revision != gate.revision()
            || header.gate_digest != gate_digest_hex
            || header.head_ref != head_ref
            || header.head_oid != head_oid
            || header.ref_count != ref_count
            || header.refs_digest != refs_digest_hex
            || header.pack_mode != PackMode::PackVerified
            || header.pack_count != pack_count
            || header.membership_digest.as_deref() != Some(membership_hex.as_str())
            || header.snapshot_digest.as_deref() != Some(snapshot_digest_hex.as_str())
            || header.logical_bytes != logical_bytes
        {
            return Err(RefStoreError::Database(
                "stored pack snapshot header disagrees with the captured revision".into(),
            ));
        }
        sql::insert_history(
            tx,
            &sql::HistoryInsert {
                request_id: request.request_id(),
                scope,
                snapshot_id: request.snapshot_id(),
                pin_id: request.pin_id(),
                kind: sql::HISTORY_CREATED,
                request_digest: &request_digest,
                header: &header,
                body: &body,
            },
        )
        .await?;

        // (9) Charge both retained counter families in the same transaction.
        usage::apply(tx, scope.tenant_id(), repository_id, pack_delta).await?;
        snapshot_usage::apply_usage(tx, scope.tenant_id(), repository_id, a2_delta).await?;

        let receipt = receipt
            .as_snapshot()
            .cloned()
            .ok_or_else(|| RefStoreError::Database("pack create receipt encoding produced the wrong action".into()))?;
        Ok(PackSnapshotOutcome {
            replayed: false,
            receipt: PackSnapshotReceipt::from_stored(&receipt, &StoredPackSnapshot::from_header(&header)?)?,
        })
    }

    /// Read one sealed complete registered-membership snapshot.
    ///
    /// The stored header supplies the trusted historical scope; the current
    /// unserved repository predicate and the current `pack_verified` mode are
    /// both rechecked, but the stored gate *revision* is allowed to be older than
    /// the current one (a legitimately pinned older snapshot stays readable).
    pub async fn read(
        &self,
        client: &mut Client,
        reference: &PackSnapshotRef,
        deadline: Instant,
    ) -> Result<PackReadSnapshot, RefStoreError> {
        reference.validate()?;
        let tx = begin_bounded(client, deadline).await?;
        let result = pg::before_deadline(deadline, self.read_checked(&tx, reference, deadline)).await;
        let _ = tx.rollback().await;
        result
    }

    async fn read_checked(
        &self,
        tx: &Transaction<'_>,
        reference: &PackSnapshotRef,
        deadline: Instant,
    ) -> Result<PackReadSnapshot, RefStoreError> {
        pg::bound(tx, deadline).await?;
        let header = snapshot_sql::snapshot_header(tx, reference.snapshot_id(), reference.repository_id())
            .await?
            .ok_or(RefStoreError::MetadataSnapshotNotFound { snapshot_id: reference.snapshot_id() })?;
        header.ensure_read_identity(reference.repository_id(), reference.tenant_id())?;
        header.ensure_pack_verified()?;
        let scope = header.stored_scope()?;

        // Current realm read fence: same unserved predicate and the same stored
        // object format/history/authority/group epochs, `FOR SHARE` so a
        // transition or epoch move cannot interleave with the read.
        snapshot_sql::lock_scope(tx, &scope, true, false).await?;
        if snapshot_sql::gate_pack_mode(tx, reference.repository_id()).await? != PackMode::PackVerified {
            return Err(RefStoreError::Unsupported("pack snapshot read requires a pack_verified gate"));
        }

        let pin = snapshot_sql::pin_for_share(tx, reference.pin_id(), reference.repository_id())
            .await?
            .ok_or(RefStoreError::MetadataPinNotFound { pin_id: reference.pin_id() })?;
        pin.ensure_scope(&scope, header.snapshot_id)?;
        pin.ensure_live(reference.expected_generation())?;

        // Complete refs: `limit = 4096 + 1` proves overflow instead of truncating.
        let rows = snapshot_sql::page_refs(
            tx,
            header.snapshot_id,
            None,
            None,
            i64::try_from(MAX_SNAPSHOT_REFS).unwrap_or(i64::MAX).saturating_add(1),
        )
        .await?;
        if rows.len() > MAX_SNAPSHOT_REFS {
            return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count: rows.len(), max_refs: MAX_SNAPSHOT_REFS });
        }
        let recomputed_refs_digest = refs_digest(&rows).as_hex();
        if recomputed_refs_digest != header.refs_digest {
            return Err(RefStoreError::Database(
                "stored snapshot ref digest disagrees with its captured ref rows".into(),
            ));
        }
        let ref_count = i64::try_from(rows.len()).unwrap_or(i64::MAX);
        if ref_count != header.ref_count {
            return Err(RefStoreError::Database(
                "stored snapshot ref count disagrees with its captured ref rows".into(),
            ));
        }
        let head_oid = rows.iter().find(|(name, _)| name == &header.head_ref).map(|(_, oid)| oid.clone());
        if head_oid != header.head_oid {
            return Err(RefStoreError::Database("stored snapshot HEAD disagrees with its captured ref rows".into()));
        }
        let mut refs = Vec::with_capacity(rows.len());
        for (name, oid) in rows {
            refs.push(
                CapturedRef::from_stored(header.object_format, name, oid)
                    .map_err(|_| RefStoreError::Database("stored snapshot ref row is invalid".into()))?,
            );
        }

        // Complete registered membership through the full A4 readers.
        let entries = sql::snapshot_bindings(tx, reference.repository_id(), header.snapshot_id).await?;
        if i64::try_from(entries.len()).unwrap_or(i64::MAX) != header.pack_count {
            return Err(RefStoreError::Database("stored pack binding count disagrees with the snapshot header".into()));
        }
        let packs = pack_commit::read_pack_bindings(
            tx,
            header.repository_id,
            header.tenant_id,
            header.object_format,
            header.history_incarnation,
            header.authority_epoch,
            header.group_epoch,
            header.gate_revision,
            &entries,
            deadline,
        )
        .await
        .map_err(pack_contract::map_pack_error)?;

        let recomputed_membership = pack_contract::membership_digest(&packs)?.as_hex();
        if header.membership_digest.as_deref() != Some(recomputed_membership.as_str()) {
            return Err(RefStoreError::Database(
                "stored membership digest disagrees with the bound registered packs".into(),
            ));
        }
        let recomputed_snapshot_digest = pack_contract::snapshot_digest(
            &scope,
            header.snapshot_id,
            header.gate_revision,
            &header.gate_digest,
            &header.head_ref,
            header.head_oid.as_deref(),
            header.ref_count,
            &header.refs_digest,
            &recomputed_membership,
            header.pack_count,
        )
        .as_hex();
        if header.snapshot_digest.as_deref() != Some(recomputed_snapshot_digest.as_str()) {
            return Err(RefStoreError::Database(
                "stored snapshot digest disagrees with the captured snapshot identity".into(),
            ));
        }

        PackReadSnapshot::new(ReadSnapshotParts {
            snapshot_id: header.snapshot_id,
            pin_id: pin.pin_id,
            pin_generation: pin.generation,
            scope,
            gate_revision: header.gate_revision,
            gate_digest: header.gate_digest.clone(),
            head_ref: header.head_ref.clone(),
            head_oid: header.head_oid.clone(),
            refs,
            packs,
            membership_digest: recomputed_membership,
            snapshot_digest: recomputed_snapshot_digest,
            logical_bytes: header.logical_bytes,
            expires_at_unix_micros: pin.expires_at_unix_micros,
        })
    }
}
