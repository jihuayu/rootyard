//! Historical receipt resolution for the A5a pack snapshot slice.
//!
//! [`PgPackSnapshot::query_receipt`] is the **only** supported resolution of an
//! unknown `COMMIT`. It takes no lock, no gate and no current authority: it reads
//! the A2 receipt ledger while the repository exists and the permanent history
//! ledger after the business rows were legitimately deleted, and it never returns
//! a [`super::PackReadSnapshot`], a live pin generation or any write authority.
//!
//! A pack-aware mutation is two immutable rows written in one transaction (the A2
//! ledger row and the permanent history row, with the same canonical body). A
//! replay or lookup that sees only one of them is a ledger-integrity error, never
//! a successful replay; the single exception is a legitimate whole-repository
//! delete, where the A2 rows are cascaded away and the permanent row survives.
use super::super::pin;
use super::super::snapshot_pg::validate_stored_receipt;
use super::super::snapshot_receipt::MetadataReceipt;
use super::super::snapshot_sql;
use super::pg::PgPackSnapshot;
use super::receipt::{PackPinReceipt, PackSnapshotLookup, PackSnapshotReceipt, StoredPackSnapshot};
use super::request::PackSnapshotReceiptQuery;
use super::sql;
use crate::ref_store::contract::{MetadataMutationAction, RefStoreError};
use crate::ref_store::pg;
use crate::ref_store::tx::begin_bounded;
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};

impl PgPackSnapshot {
    /// Resolve a historical pack-snapshot receipt by its global request id.
    ///
    /// The query names the full trusted historical `MetadataSnapshotScope` plus
    /// the request id, so a foreign repository/tenant/owner/purpose/format/epoch
    /// is a typed refusal rather than somebody else's receipt. An id with no
    /// durable row at all is `Unknown`: not an abort, not a rejection, and not
    /// something a caller may resolve by inventing a new id.
    pub async fn query_receipt(
        &self,
        client: &mut Client,
        query: &PackSnapshotReceiptQuery,
        deadline: Instant,
    ) -> Result<PackSnapshotLookup, RefStoreError> {
        let tx = begin_bounded(client, deadline).await?;
        let result = pg::before_deadline(deadline, self.query_checked(&tx, query, deadline)).await;
        let _ = tx.rollback().await;
        result
    }

    async fn query_checked(
        &self,
        tx: &Transaction<'_>,
        query: &PackSnapshotReceiptQuery,
        deadline: Instant,
    ) -> Result<PackSnapshotLookup, RefStoreError> {
        pg::bound(tx, deadline).await?;
        let scope = query.scope();
        let request_id = query.request_id();
        let stored = snapshot_sql::stored_receipt(tx, request_id).await?;
        let history = sql::stored_history(tx, request_id).await?;
        match (stored, history) {
            (None, None) => Ok(PackSnapshotLookup::Unknown),

            // The A2 ledger row exists but its permanent partner does not. For a
            // pack-aware header that is a missing partner (ledger integrity); a
            // metadata-only request id is simply not an A5 receipt at all.
            (Some(stored), None) => {
                let header = snapshot_sql::snapshot_header(tx, stored.snapshot_id, scope.repository_id()).await?;
                match header {
                    Some(header) if !header.is_pack_verified() => Err(RefStoreError::DigestConflict),
                    _ => Err(RefStoreError::Database("pack snapshot receipt has no permanent history partner".into())),
                }
            }

            // The business rows are legitimately gone (whole-repository delete):
            // the permanent ledger is the only retained authority.
            (None, Some(history)) => {
                if sql::repository_exists(tx, scope.repository_id()).await? {
                    return Err(RefStoreError::Database(
                        "permanent pack snapshot history has no A2 receipt while its repository exists".into(),
                    ));
                }
                if history.repository_id != scope.repository_id() || history.tenant_id != scope.tenant_id() {
                    return Err(RefStoreError::RepositoryNotFound);
                }
                if history.owner_id != scope.owner_id() {
                    return Err(RefStoreError::MetadataScopeMismatch("permanent history owner"));
                }
                let receipt = match history.kind.as_str() {
                    sql::HISTORY_CREATED => pin::decode_receipt(MetadataMutationAction::Create, &history.body)?,
                    sql::HISTORY_RENEWED => pin::decode_receipt(MetadataMutationAction::Renew, &history.body)?,
                    sql::HISTORY_RELEASED => pin::decode_receipt(MetadataMutationAction::Release, &history.body)?,
                    _ => {
                        return Err(RefStoreError::Database(
                            "permanent pack snapshot history kind is not recognized".into(),
                        ));
                    }
                };
                pin::ensure_receipt_scope(&receipt, scope)?;
                if receipt.snapshot_id() != history.snapshot_id || receipt.pin_id() != history.pin_id {
                    return Err(RefStoreError::Database("permanent history row names another snapshot/pin".into()));
                }
                match receipt {
                    MetadataReceipt::Snapshot(snapshot) => {
                        let stored_pack = StoredPackSnapshot::from_history(&history, &snapshot)?;
                        Ok(PackSnapshotLookup::Found(PackSnapshotReceipt::from_stored(&snapshot, &stored_pack)?))
                    }
                    MetadataReceipt::Pin(pin_receipt) => {
                        Ok(PackSnapshotLookup::FoundPin(PackPinReceipt::from_pin_receipt(&pin_receipt, *scope)?))
                    }
                }
            }

            // Both immutable rows exist: full historical A2 validation plus the
            // permanent partner check, for a create or a pack-aware lifecycle
            // receipt. Nothing here is a live pin/snapshot authority.
            (Some(stored), Some(_history)) => {
                if stored.repository_id != scope.repository_id() || stored.tenant_id != scope.tenant_id() {
                    return Err(RefStoreError::RepositoryNotFound);
                }
                let receipt = validate_stored_receipt(tx, &stored, scope).await?;
                let header = snapshot_sql::snapshot_header(tx, stored.snapshot_id, scope.repository_id())
                    .await?
                    .ok_or(RefStoreError::MetadataSnapshotNotFound { snapshot_id: stored.snapshot_id })?;
                if !header.is_pack_verified() {
                    return Err(RefStoreError::DigestConflict);
                }
                match receipt {
                    MetadataReceipt::Snapshot(snapshot) => {
                        sql::ensure_history_partner(tx, &stored, header.owner_id, sql::HISTORY_CREATED).await?;
                        Ok(PackSnapshotLookup::Found(PackSnapshotReceipt::from_stored(
                            &snapshot,
                            &StoredPackSnapshot::from_header(&header)?,
                        )?))
                    }
                    MetadataReceipt::Pin(pin_receipt) => {
                        let kind = match pin_receipt.action() {
                            MetadataMutationAction::Renew => sql::HISTORY_RENEWED,
                            MetadataMutationAction::Release => sql::HISTORY_RELEASED,
                            MetadataMutationAction::Create => {
                                return Err(RefStoreError::Database(
                                    "permanent history names a create action for a pin receipt".into(),
                                ));
                            }
                        };
                        sql::ensure_history_partner(tx, &stored, header.owner_id, kind).await?;
                        Ok(PackSnapshotLookup::FoundPin(PackPinReceipt::from_pin_receipt(&pin_receipt, *scope)?))
                    }
                }
            }
        }
    }
}
