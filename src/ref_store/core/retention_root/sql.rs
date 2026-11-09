//! SQL statements for the durable roots adapter (heads, protocol state, tombstones, receipts, quota).
//!
//! These helpers are always called inside the short transaction `super::pg` owns. They contain no commit/rollback
//! logic, never open a connection and never run while a PostgreSQL transaction is held across Blob or native Git
//! IO. Lock order is the frozen cross-feature order: tenant usage -> repository usage -> core gate -> protocol
//! state -> root head/tombstone rows. Usage rows are locked *before* the gate and charged afterwards, in the same
//! transaction, before the first retained row is written.
use super::error::RootError;
use super::rows::{GateRealm, HeadRow, ReceiptRow, TombstoneRow};
use super::scope::RootsScope;
use super::usage::{RootCharge, RootQuotaResource};
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::pg;
use tokio_postgres::Transaction;
use uuid::Uuid;

const HEAD_COLUMNS: &str = "tenant_id,owner_id,purpose,business_intent_digest,register_digest,state,last_generation";
const TOMBSTONE_COLUMNS: &str =
    "generation,tenant_id,owner_id,purpose,business_intent_digest,expected_register_digest,release_digest";
const RECEIPT_COLUMNS: &str = "repository_id,tenant_id,owner_id,purpose,business_intent_digest,root_id,generation,
    action,request_digest,body,(extract(epoch FROM created_at)*1000000)::bigint AS created_at_unix_micros";

/// The live core gate realm, locked `FOR UPDATE` (root mutation) or `FOR SHARE` (byte read).
pub(super) async fn gate_realm(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    for_update: bool,
) -> Result<Option<GateRealm>, RootError> {
    let query = format!(
        "SELECT tenant_id,object_format,history_incarnation,authority_epoch,group_epoch
         FROM ref_store_core_gates WHERE repository_id=$1{}",
        if for_update { " FOR UPDATE" } else { " FOR SHARE" }
    );
    let row = tx.query_opt(&query, &[&repository_id]).await.map_err(pg::db_error)?;
    row.as_ref().map(GateRealm::from_row).transpose()
}

/// Require one gate realm to belong to the root scope (tenant/format/history/epochs). A root is captured at an
/// exact realm; a later epoch move does not re-own or widen it.
pub(super) fn require_realm(
    realm: &GateRealm,
    scope: &RootsScope,
    format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    what: &'static str,
) -> Result<(), RootError> {
    if realm.tenant_id != scope.tenant_id()
        || realm.object_format != format
        || realm.history_incarnation != history_incarnation
        || realm.authority_epoch != authority_epoch
        || realm.group_epoch != group_epoch
    {
        return Err(RootError::RootRealmMismatch(what));
    }
    Ok(())
}

/// Bump and return the monotone per-repository roots revision.
///
/// The row is created once from the captured realm, and only ever incremented afterwards; the realm columns of an
/// existing row are never rewritten. Any realm disagreement is a typed refusal.
pub(super) async fn bump_roots_revision(tx: &Transaction<'_>, scope: &RootsScope) -> Result<i64, RootError> {
    // `SELECT ... FOR UPDATE` first so two concurrent registers serialize on the same protocol row.
    let existing = tx
        .query_opt(
            "SELECT roots_revision,tenant_id,object_format,history_incarnation,authority_epoch,group_epoch
             FROM ref_store_core_protocol_repos WHERE repository_id=$1 FOR UPDATE",
            &[&scope.repository_id()],
        )
        .await
        .map_err(pg::db_error)?;
    let revision: i64 = match existing {
        Some(row) => {
            let tenant_id: Uuid = row.get(1);
            let object_format: String = row.get(2);
            let history: Uuid = row.get(3);
            let authority_epoch: i64 = row.get(4);
            let group_epoch: i64 = row.get(5);
            if tenant_id != scope.tenant_id()
                || history != scope.history_incarnation()
                || object_format != scope.object_format().as_str()
                || authority_epoch != scope.authority_epoch()
                || group_epoch != scope.group_epoch()
            {
                return Err(RootError::RootRealmMismatch("protocol roots realm"));
            }
            let current: i64 = row.get(0);
            let next = current
                .checked_add(1)
                .ok_or_else(|| RootError::Store(RefStoreError::Database("roots revision overflowed".into())))?;
            tx.execute(
                "UPDATE ref_store_core_protocol_repos SET roots_revision=$2,updated_at=clock_timestamp()
                 WHERE repository_id=$1",
                &[&scope.repository_id(), &next],
            )
            .await
            .map_err(pg::db_error)?;
            next
        }
        None => {
            tx.execute(
                "INSERT INTO ref_store_core_protocol_repos(repository_id,tenant_id,object_format,
                     history_incarnation,authority_epoch,group_epoch,roots_revision)
                 VALUES($1,$2,$3,$4,$5,$6,1)",
                &[
                    &scope.repository_id(),
                    &scope.tenant_id(),
                    &scope.object_format().as_str(),
                    &scope.history_incarnation(),
                    &scope.authority_epoch(),
                    &scope.group_epoch(),
                ],
            )
            .await
            .map_err(pg::db_error)?;
            1
        }
    };
    Ok(revision)
}

/// Current root head locked `FOR UPDATE` (register/release).
pub(super) async fn head_for_update(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    root_id: Uuid,
) -> Result<Option<HeadRow>, RootError> {
    let query = format!(
        "SELECT {HEAD_COLUMNS} FROM ref_store_core_root_heads WHERE repository_id=$1 AND root_id=$2 FOR UPDATE"
    );
    let row = tx.query_opt(&query, &[&repository_id, &root_id]).await.map_err(pg::db_error)?;
    row.as_ref().map(HeadRow::from_row).transpose()
}

/// Current root head locked `FOR SHARE` (byte read T2).
pub(super) async fn head_for_share(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    root_id: Uuid,
) -> Result<Option<HeadRow>, RootError> {
    let query =
        format!("SELECT {HEAD_COLUMNS} FROM ref_store_core_root_heads WHERE repository_id=$1 AND root_id=$2 FOR SHARE");
    let row = tx.query_opt(&query, &[&repository_id, &root_id]).await.map_err(pg::db_error)?;
    row.as_ref().map(HeadRow::from_row).transpose()
}

pub(super) async fn head_state(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    root_id: Uuid,
) -> Result<Option<HeadRow>, RootError> {
    let query = format!("SELECT {HEAD_COLUMNS} FROM ref_store_core_root_heads WHERE repository_id=$1 AND root_id=$2");
    let row = tx.query_opt(&query, &[&repository_id, &root_id]).await.map_err(pg::db_error)?;
    row.as_ref().map(HeadRow::from_row).transpose()
}

/// The highest durable release tombstone for one root id (there is at most one generation).
pub(super) async fn latest_tombstone(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    root_id: Uuid,
) -> Result<Option<TombstoneRow>, RootError> {
    let query = format!(
        "SELECT {TOMBSTONE_COLUMNS} FROM ref_store_core_root_tombstones
         WHERE repository_id=$1 AND root_id=$2 ORDER BY generation DESC LIMIT 1"
    );
    let row = tx.query_opt(&query, &[&repository_id, &root_id]).await.map_err(pg::db_error)?;
    row.as_ref().map(TombstoneRow::from_row).transpose()
}

/// A delayed register of the same root id must find a tombstone even if it carries a different expected digest.
pub(super) fn refuse_released(
    tombstone: &TombstoneRow,
    root_id: Uuid,
    repository_id: Uuid,
    expected_register_digest: &RequestDigest,
) -> RootError {
    if tombstone.expected_register_digest != expected_register_digest.as_hex() {
        return RootError::RootDigestConflict("root id was released for a different register digest");
    }
    RootError::RootReleased { repository_id, root_id, generation: tombstone.generation }
}

pub(super) async fn insert_head(
    tx: &Transaction<'_>,
    scope: &RootsScope,
    root_id: Uuid,
    register_digest: &RequestDigest,
    released: bool,
) -> Result<(), RootError> {
    let (state, generation): (&str, i64) = if released { ("released", 2) } else { ("active", 1) };
    tx.execute(
        "INSERT INTO ref_store_core_root_heads(repository_id,root_id,tenant_id,owner_id,purpose,
             business_intent_digest,register_digest,state,last_generation)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[
            &scope.repository_id(),
            &root_id,
            &scope.tenant_id(),
            &scope.owner_id(),
            &scope.purpose().as_str(),
            &scope.business_intent_hex(),
            &register_digest.as_hex(),
            &state,
            &generation,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// The only legal head transition: active/1 -> released/2. Returns `false` when the CAS did not match.
pub(super) async fn mark_head_released(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    root_id: Uuid,
) -> Result<bool, RootError> {
    let updated = tx
        .execute(
            "UPDATE ref_store_core_root_heads SET state='released',last_generation=2,updated_at=clock_timestamp()
             WHERE repository_id=$1 AND root_id=$2 AND state='active' AND last_generation=1",
            &[&repository_id, &root_id],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(updated == 1)
}

pub(super) async fn insert_tombstone(
    tx: &Transaction<'_>,
    scope: &RootsScope,
    root_id: Uuid,
    request_id: Uuid,
    release_digest: &RequestDigest,
    expected_register_digest: &RequestDigest,
    reason: &str,
) -> Result<(), RootError> {
    tx.execute(
        "INSERT INTO ref_store_core_root_tombstones(repository_id,root_id,generation,tenant_id,owner_id,purpose,
             business_intent_digest,release_request_id,release_digest,expected_register_digest,reason)
         VALUES($1,$2,2,$3,$4,$5,$6,$7,$8,$9,$10)",
        &[
            &scope.repository_id(),
            &root_id,
            &scope.tenant_id(),
            &scope.owner_id(),
            &scope.purpose().as_str(),
            &scope.business_intent_hex(),
            &request_id,
            &release_digest.as_hex(),
            &expected_register_digest.as_hex(),
            &reason,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

/// Exact receipt replay lookup by `(repository_id, request_id)`. Never charges, never re-authorizes.
pub(super) async fn lookup_receipt(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    request_id: Uuid,
) -> Result<Option<ReceiptRow>, RootError> {
    let query =
        format!("SELECT {RECEIPT_COLUMNS} FROM ref_store_core_root_receipts WHERE repository_id=$1 AND request_id=$2");
    let row = tx.query_opt(&query, &[&repository_id, &request_id]).await.map_err(pg::db_error)?;
    row.as_ref().map(ReceiptRow::from_row).transpose()
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_receipt(
    tx: &Transaction<'_>,
    request_id: Uuid,
    scope: &RootsScope,
    root_id: Uuid,
    generation: i64,
    action: super::receipt::RootAction,
    request_digest: &RequestDigest,
    body: &serde_json::Value,
) -> Result<i64, RootError> {
    let row = tx
        .query_one(
            "INSERT INTO ref_store_core_root_receipts(request_id,repository_id,tenant_id,owner_id,purpose,
             business_intent_digest,root_id,generation,action,request_digest,body)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         RETURNING (extract(epoch FROM created_at)*1000000)::bigint",
            &[
                &request_id,
                &scope.repository_id(),
                &scope.tenant_id(),
                &scope.owner_id(),
                &scope.purpose().as_str(),
                &scope.business_intent_hex(),
                &root_id,
                &generation,
                &action.as_str(),
                &request_digest.as_hex(),
                body,
            ],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(row.get(0))
}

/// Lock (creating on first use) the tenant usage row **then** the repository usage row.
///
/// The frozen cross-feature order is tenant usage -> repository usage -> core gate -> protocol -> root/decision
/// rows, so the usage rows are taken *before* the core gate lock. This helper applies a **zero** charge: it only
/// establishes the two row locks, so the exact charge can be computed from the request body afterwards and
/// applied atomically by [`apply_charge`] in the same transaction, before the first retained row is written.
/// Nothing is ever refunded on any later path.
pub(super) async fn lock_usage(tx: &Transaction<'_>, scope: &RootsScope) -> Result<(), RootError> {
    tx.execute(
        "INSERT INTO ref_store_core_root_tenant_usage(tenant_id) VALUES($1) ON CONFLICT (tenant_id) DO NOTHING",
        &[&scope.tenant_id()],
    )
    .await
    .map_err(pg::db_error)?;
    tx.query_one(
        "SELECT tenant_id FROM ref_store_core_root_tenant_usage WHERE tenant_id=$1 FOR UPDATE",
        &[&scope.tenant_id()],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "INSERT INTO ref_store_core_root_repo_usage(repository_id,tenant_id) VALUES($1,$2)
         ON CONFLICT (repository_id) DO NOTHING",
        &[&scope.repository_id(), &scope.tenant_id()],
    )
    .await
    .map_err(pg::db_error)?;
    let repo = tx
        .query_one(
            "SELECT tenant_id FROM ref_store_core_root_repo_usage WHERE repository_id=$1 FOR UPDATE",
            &[&scope.repository_id()],
        )
        .await
        .map_err(pg::db_error)?;
    let repo_tenant: Uuid = repo.get(0);
    if repo_tenant != scope.tenant_id() {
        return Err(RootError::RootRealmMismatch("retained roots usage tenant"));
    }
    Ok(())
}

/// Apply one mutation's exact charge to both usage rows already locked by [`lock_usage`] and refuse past a
/// fixed repository/tenant ceiling. Both rows are read and written inside the caller's transaction, so the two
/// counters advance atomically with the retained rows this charge covers.
pub(super) async fn apply_charge(
    tx: &Transaction<'_>,
    scope: &RootsScope,
    charge: RootCharge,
) -> Result<(), RootError> {
    let repo = tx
        .query_one(
            "SELECT tenant_id,roots,root_oid_refs,pack_bindings,receipts,logical_bytes
             FROM ref_store_core_root_repo_usage WHERE repository_id=$1 FOR UPDATE",
            &[&scope.repository_id()],
        )
        .await
        .map_err(pg::db_error)?;
    let repo_tenant: Uuid = repo.get(0);
    if repo_tenant != scope.tenant_id() {
        return Err(RootError::RootRealmMismatch("retained roots usage tenant"));
    }
    let tenant = tx
        .query_one(
            "SELECT roots,root_oid_refs,pack_bindings,receipts,logical_bytes
             FROM ref_store_core_root_tenant_usage WHERE tenant_id=$1 FOR UPDATE",
            &[&scope.tenant_id()],
        )
        .await
        .map_err(pg::db_error)?;
    let (repo_roots, repo_refs, repo_packs, repo_receipts, repo_bytes): (i64, i64, i64, i64, i64) =
        (repo.get(1), repo.get(2), repo.get(3), repo.get(4), repo.get(5));
    let (tenant_roots, tenant_refs, tenant_packs, tenant_receipts, tenant_bytes): (i64, i64, i64, i64, i64) =
        (tenant.get(0), tenant.get(1), tenant.get(2), tenant.get(3), tenant.get(4));
    let repo_next = next_counters((repo_roots, repo_refs, repo_packs, repo_receipts, repo_bytes), charge)?;
    let tenant_next = next_counters((tenant_roots, tenant_refs, tenant_packs, tenant_receipts, tenant_bytes), charge)?;
    for (resource, (repo_value, tenant_value)) in [
        (RootQuotaResource::Roots, (repo_next.0, tenant_next.0)),
        (RootQuotaResource::RootOidRefs, (repo_next.1, tenant_next.1)),
        (RootQuotaResource::PackBindings, (repo_next.2, tenant_next.2)),
        (RootQuotaResource::Receipts, (repo_next.3, tenant_next.3)),
        (RootQuotaResource::LogicalBytes, (repo_next.4, tenant_next.4)),
    ] {
        let (repo_bound, tenant_bound) = RootCharge::bounds(resource);
        if repo_value > repo_bound {
            return Err(RootError::RootQuotaExceeded { resource, actual: repo_value, bound: repo_bound });
        }
        if tenant_value > tenant_bound {
            return Err(RootError::RootQuotaExceeded { resource, actual: tenant_value, bound: tenant_bound });
        }
    }
    tx.execute(
        "UPDATE ref_store_core_root_repo_usage SET roots=$2,root_oid_refs=$3,pack_bindings=$4,receipts=$5,
             logical_bytes=$6,updated_at=clock_timestamp() WHERE repository_id=$1",
        &[&scope.repository_id(), &repo_next.0, &repo_next.1, &repo_next.2, &repo_next.3, &repo_next.4],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "UPDATE ref_store_core_root_tenant_usage SET roots=$2,root_oid_refs=$3,pack_bindings=$4,receipts=$5,
             logical_bytes=$6,updated_at=clock_timestamp() WHERE tenant_id=$1",
        &[&scope.tenant_id(), &tenant_next.0, &tenant_next.1, &tenant_next.2, &tenant_next.3, &tenant_next.4],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

type Counters = (i64, i64, i64, i64, i64);

fn next_counters(current: Counters, charge: RootCharge) -> Result<Counters, RootError> {
    let add = |value: i64, extra: i64| -> Result<i64, RootError> {
        value
            .checked_add(extra)
            .ok_or_else(|| RootError::Store(RefStoreError::Database("roots usage counter overflowed".into())))
    };
    Ok((
        add(current.0, charge.roots)?,
        add(current.1, charge.root_oid_refs)?,
        add(current.2, charge.pack_bindings)?,
        add(current.3, charge.receipts)?,
        add(current.4, charge.logical_bytes)?,
    ))
}
