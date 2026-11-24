//! Production remote partial/unpromoted `.pack`/`.idx` reclaim consumer & sweeper (#183).
//!
//! Collects ALL `0..=8` staged/uploaded `.pack` and `.idx` remote `BlobLocator` paths from
//! `artifact_holds` + `QuarantineReclaimLedger`, requires POSITIVE durable PostgreSQL terminal-abort
//! proof (`ref_store_operations.state IN ('rejected','cancelled')`, or a durable
//! `ref_store_cancellations` / `REJECTED`|`CANCELLED` decision tombstone for a missing operation row)
//! with ZERO active pack memberships, snapshot/serving-read pins, active retention roots or
//! open/consumed decisions, and only then sweeps 100% of quarantined remote objects via OpenDAL
//! when remote reclaim deletion is enabled (default-off when `BlobDeletePolicy::Disabled`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use deadpool_postgres::Pool;
use opendal::services::S3;
use opendal::{ErrorKind, Operator};
use tokio::time::{Instant as TokioInstant, timeout_at};
use tokio_postgres::{GenericClient, IsolationLevel};
use uuid::Uuid;

use crate::blob_store::BlobLocator;
use crate::blob_store::config::BlobProfile;
use crate::blob_store::opendal::BlobStore;

use super::gateway_bridge::open_gateway_reclaim_ledger;
use super::gateway_durable_binding::{ReclaimBinding, reclaim_binding, verify_reclaim_wrapper};
use super::reclaim::{BlobUploadReclaimRecord, UploadReclaimState};
use super::types::PushCausalError;

/// Explicit S3 connection settings for remote unpromoted staging reclaim sweeps.
#[derive(Clone, Debug)]
pub struct RemoteS3ReclaimConfig {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub root: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

static RECLAIM_OPERATORS: OnceLock<Mutex<BTreeMap<String, Operator>>> = OnceLock::new();

fn operator_registry() -> &'static Mutex<BTreeMap<String, Operator>> {
    RECLAIM_OPERATORS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Enable physical OpenDAL S3 deletion of unpromoted/partial/rejected staging packs for `backend_hex`.
pub fn configure_gateway_remote_reclaim_s3(
    backend_hex: &str,
    cfg: RemoteS3ReclaimConfig,
) -> Result<(), PushCausalError> {
    let builder = S3::default()
        .bucket(&cfg.bucket)
        .root(&cfg.root)
        .endpoint(&cfg.endpoint)
        .region(&cfg.region)
        .access_key_id(&cfg.access_key_id)
        .secret_access_key(&cfg.secret_access_key)
        .disable_config_load()
        .disable_ec2_metadata();
    let op = Operator::new(builder).map_err(|e| PushCausalError::Io(e.to_string()))?.finish();
    let mut map = operator_registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    map.insert(backend_hex.to_owned(), op);
    Ok(())
}

/// Disable explicit S3 reclaim operator registration for `backend_hex` (returns to default-off).
pub fn clear_gateway_remote_reclaim_s3(backend_hex: &str) {
    let mut map = operator_registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    map.remove(backend_hex);
}

fn resolve_reclaim_operator(backend_hex: &str) -> Option<Operator> {
    {
        let map = operator_registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(op) = map.get(backend_hex) {
            return Some(op.clone());
        }
    }
    if std::env::var("ROOTYARD_PUSH_RECLAIM_REMOTE_DELETE").ok().as_deref() != Some("1") {
        return None;
    }
    let profile = BlobProfile::from_env().ok()?;
    if profile.provider().as_str() != "s3"
        || BlobStore::open(profile.clone()).ok()?.backend_identity().as_hex() != backend_hex
    {
        return None;
    }
    let ak = std::env::var("ROOTYARD_BLOB_ACCESS_KEY_ID").ok()?;
    let sk = std::env::var("ROOTYARD_BLOB_SECRET_ACCESS_KEY").ok()?;
    let mut builder = S3::default()
        .bucket(profile.bucket())
        .root(profile.root())
        .access_key_id(&ak)
        .secret_access_key(&sk)
        .disable_config_load()
        .disable_ec2_metadata();
    if let Some(region) = profile.region() {
        builder = builder.region(region);
    }
    if let Some(ep) = profile.endpoint() {
        builder = builder.endpoint(ep.as_str());
    }
    if let Ok(tok) = std::env::var("ROOTYARD_BLOB_SESSION_TOKEN")
        && !tok.is_empty()
    {
        builder = builder.session_token(&tok);
    }
    Some(Operator::new(builder).ok()?.finish())
}

/// Read the exact hold locators for a legacy operation or all attempts of a
/// public operation, excluding any hold outside its backend and tenant.
pub async fn query_operation_hold_blob_paths(
    pool: &Pool,
    repository_id: Uuid,
    operation_id: Uuid,
    backend_hex: &str,
    deadline: TokioInstant,
) -> Result<(Vec<String>, u64), PushCausalError> {
    Ok(reclaim_read(pool, repository_id, operation_id, backend_hex, None, deadline)
        .await?
        .map_or_else(Default::default, |read| (read.paths, read.bytes)))
}

struct ReclaimRead {
    paths: Vec<String>,
    bytes: u64,
    proven: bool,
    public: bool,
}

/// Resolve the stable ledger key, collect locators and prove abort/zero references
/// in one bounded snapshot. A pending or committed public wrapper never deletes
/// staged objects, even when an earlier private attempt was retired as rejected.
async fn reclaim_read(
    pool: &Pool,
    repository_id: Uuid,
    operation_id: Uuid,
    backend_hex: &str,
    ledger_tenant: Option<Uuid>,
    deadline: TokioInstant,
) -> Result<Option<ReclaimRead>, PushCausalError> {
    timeout_at(deadline, async {
        let mut client = pool.get().await.map_err(|e| PushCausalError::Io(e.to_string()))?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(|e| PushCausalError::Io(e.to_string()))?;
        let Some(binding) = reclaim_binding(&tx, repository_id, operation_id).await? else { return Ok(None) };
        let (attempts, tenant, may_abort, public) = match binding {
            ReclaimBinding::Legacy => (vec![operation_id], ledger_tenant, true, false),
            ReclaimBinding::Public { owner, backend, attempts, terminal_abort } => {
                if backend != backend_hex || ledger_tenant.is_some_and(|tenant| tenant != owner) {
                    return Ok(None);
                }
                if terminal_abort {
                    verify_reclaim_wrapper(&tx, repository_id, operation_id).await?;
                }
                (attempts, Some(owner), terminal_abort, true)
            }
        };
        let (paths, bytes) = read_hold_paths(&*tx, repository_id, &attempts, backend_hex, tenant).await?;
        let proven = may_abort && prove_aborts_without_references(&*tx, repository_id, &attempts).await?;
        Ok(Some(ReclaimRead { paths, bytes, proven, public }))
    })
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
}

async fn read_hold_paths(
    client: &(impl GenericClient + Sync),
    repository_id: Uuid,
    attempts: &[Uuid],
    backend_hex: &str,
    tenant_id: Option<Uuid>,
) -> Result<(Vec<String>, u64), PushCausalError> {
    let rows = client.query(
            "SELECT storage_tenant_id, authority_id, authority_generation, attempt_id, namespace, sha256, content_length
             FROM artifact_holds
             WHERE repository_id = $1 AND operation_id = ANY($2) AND backend_identity = $3
               AND ($4::uuid IS NULL OR storage_tenant_id = $4)
             ORDER BY request_id ASC, slot ASC",
            &[&repository_id, &attempts, &backend_hex, &tenant_id],
        ).await.map_err(|e| PushCausalError::Io(e.to_string()))?;

    let mut paths = Vec::with_capacity(rows.len());
    let mut total_bytes = 0u64;
    for r in rows {
        let len_i64: i64 = r.get(6);
        let len = u64::try_from(len_i64).unwrap_or(0);
        let loc = BlobLocator::new(
            r.get::<_, Uuid>(0),
            r.get::<_, Uuid>(1),
            r.get::<_, i64>(2),
            r.get::<_, Uuid>(3),
            r.get::<_, &str>(4),
            r.get::<_, &str>(5),
            len,
        )?;
        paths.push(loc.path());
        total_bytes = total_bytes.saturating_add(len);
    }
    Ok((paths, total_bytes))
}

/// Authoritatively verify in PostgreSQL that `operation_id` has POSITIVE durable terminal-abort
/// proof (`ref_store_operations.state IN ('rejected', 'cancelled')`, OR when absent from
/// `ref_store_operations`, an explicit durable row in `ref_store_cancellations` or terminal
/// `'REJECTED'`/`'CANCELLED'` row in `ref_store_publication_decisions`) AND that ZERO active
/// pack memberships, snapshot pins, serving reads, active retention roots, or open/consumed
/// decisions reference its artifacts.
///
/// A missing `ref_store_operations` row with no durable abort tombstone NEVER qualifies as
/// deletable (`Ok(false)`), even when all reference counts are zero.
pub async fn is_operation_proven_aborted_and_unreferenced(
    pool: &Pool,
    repository_id: Uuid,
    operation_id: Uuid,
    deadline: TokioInstant,
) -> Result<bool, PushCausalError> {
    timeout_at(deadline, async {
        let mut client = pool.get().await.map_err(|e| PushCausalError::Io(e.to_string()))?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(|e| PushCausalError::Io(e.to_string()))?;
        let attempts = match reclaim_binding(&tx, repository_id, operation_id).await? {
            Some(ReclaimBinding::Legacy) => vec![operation_id],
            Some(ReclaimBinding::Public { attempts, terminal_abort: true, .. }) => {
                verify_reclaim_wrapper(&tx, repository_id, operation_id).await?;
                attempts
            }
            _ => return Ok(false),
        };
        prove_aborts_without_references(&*tx, repository_id, &attempts).await
    })
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?
}

async fn prove_aborts_without_references(
    client: &(impl GenericClient + Sync),
    repository_id: Uuid,
    attempts: &[Uuid],
) -> Result<bool, PushCausalError> {
    let proven_terminal_abort: bool = client
        .query_one(
            "SELECT coalesce(bool_and(CASE WHEN o.operation_id IS NOT NULL
                    THEN o.state IN ('rejected','cancelled')
                    ELSE EXISTS(SELECT 1 FROM ref_store_cancellations c
                                WHERE c.repository_id=$1 AND c.operation_id=a.id)
                      OR EXISTS(SELECT 1 FROM ref_store_publication_decisions d
                                WHERE d.repository_id=$1 AND d.operation_id=a.id
                                  AND d.state IN ('REJECTED','CANCELLED'))
                    END), false)
         FROM unnest($2::uuid[]) a(id)
         LEFT JOIN ref_store_operations o ON o.repository_id=$1 AND o.operation_id=a.id",
            &[&repository_id, &attempts],
        )
        .await
        .map_err(|e| PushCausalError::Io(e.to_string()))?
        .get(0);
    if !proven_terminal_abort {
        return Ok(false);
    }

    let ref_row = client
        .query_one(
            "SELECT
               (SELECT COUNT(*) FROM ref_store_core_pack_memberships m
                JOIN ref_store_core_pack_publications p ON p.repository_id = m.repository_id AND p.pack_id = m.pack_id
                WHERE m.repository_id = $1 AND p.plan_operation_id = ANY($2))
             + (SELECT COUNT(*) FROM ref_store_core_snapshot_packs sp
                JOIN ref_store_core_pack_publications p ON p.registration_id = sp.registration_id
                WHERE p.repository_id = $1 AND p.plan_operation_id = ANY($2))
             + (SELECT COUNT(*) FROM ref_store_core_serving_read_packs srp
                JOIN ref_store_core_pack_publications p ON p.registration_id = srp.registration_id
                WHERE p.repository_id = $1 AND p.plan_operation_id = ANY($2))
             + (SELECT COUNT(*) FROM ref_store_core_root_packs rp
                JOIN ref_store_core_root_heads rh
                  ON rh.repository_id = rp.repository_id AND rh.root_id = rp.root_id AND rh.state = 'active'
                JOIN ref_store_core_pack_publications p ON p.registration_id = rp.registration_id
                WHERE rp.repository_id = $1 AND p.plan_operation_id = ANY($2))
             + (SELECT COUNT(*) FROM ref_store_publication_decisions d
                WHERE d.repository_id = $1 AND d.operation_id = ANY($2) AND d.state IN ('OPEN', 'CONSUMED'))",
            &[&repository_id, &attempts],
        )
        .await
        .map_err(|e| PushCausalError::Io(e.to_string()))?;
    let live_refs: i64 = ref_row.get(0);
    Ok(live_refs == 0)
}

/// Record ALL `artifact_holds` remote paths for an unpromoted/aborted gateway push and sweep
/// 100% of its remote `.pack`/`.idx` objects when proven aborted and remote reclaim is enabled.
pub async fn settle_aborted_gateway_reclaim(
    pool: &Pool,
    scratch_root: &Path,
    repository_id: Uuid,
    operation_id: Uuid,
    backend_hex: &str,
    fallback_state: UploadReclaimState,
    detail: &str,
) -> Option<BlobUploadReclaimRecord> {
    let ledger = open_gateway_reclaim_ledger(scratch_root).ok()?;
    let existing = ledger.load(operation_id).ok()??;
    if existing.state == UploadReclaimState::VerifiedPromoted
        || existing.state == UploadReclaimState::ReclaimedAfterAbort
    {
        return Some(existing);
    }
    // The public ledger key is authoritative, but this run may only touch a
    // record for the exact repository/backend it opened.
    if existing.repository_id != repository_id || existing.backend_identity.as_str() != backend_hex {
        return Some(existing);
    }
    let dl = TokioInstant::now() + Duration::from_secs(5);
    let read =
        reclaim_read(pool, repository_id, operation_id, backend_hex, Some(existing.tenant_id), dl).await.ok()??;
    let all_paths = verified_paths(&existing, &read)?;
    // Never relabel an unproven attempt as aborted. Unknown/unresolved records
    // keep their staged paths and remain in the recoverable retention state.
    let state = if fallback_state == UploadReclaimState::AbortUnpromoted && !read.proven {
        UploadReclaimState::OutcomeUnknown
    } else {
        fallback_state
    };
    let updated = ledger.transition(operation_id, state, all_paths.clone(), read.bytes, detail).ok()?;

    if read.proven
        && let Some(op) = resolve_reclaim_operator(backend_hex)
        && delete_and_verify_absent(&op, &all_paths, dl).await.is_ok()
    {
        return ledger.mark_reclaimed_if_proven_aborted(operation_id, true).ok();
    }
    Some(updated)
}

/// Startup & request-entry recovery consumer: scans `QuarantineReclaimLedger` for `needs_recovery()`
/// records whose PG operations have now settled as `rejected`/`cancelled` with positive durable
/// terminal-abort proof and sweeps all unpromoted remote `.pack` and `.idx` objects from `BlobStore`.
///
/// The sweep is a fresh-admission side effect only (`Claim::Fresh`). Callers never invoke it on a
/// `Claim::Pending`, `Claim::Cancelled` or `Claim::Replay` path, so a pure replay performs zero local
/// ledger writes, zero state transitions and zero remote deletes. A backend without an armed reclaim
/// operator or a scratch root without an existing private ledger directory is a strict no-op: the
/// ledger directory is never created for a sweep that cannot delete anything.
pub async fn sweep_gateway_reclaim_ledger(
    pool: &Pool,
    scratch_root: &Path,
    backend_hex: &str,
    deadline: TokioInstant,
) -> Result<usize, PushCausalError> {
    let Some(op) = resolve_reclaim_operator(backend_hex) else {
        return Ok(0);
    };
    if !super::gateway_bridge::gateway_reclaim_ledger_dir_for_scratch(scratch_root).is_dir() {
        return Ok(0);
    }
    let ledger = open_gateway_reclaim_ledger(scratch_root)
        .map_err(|_| PushCausalError::Io("could not open gateway reclaim ledger".into()))?;
    let mut swept = 0usize;
    for rec in ledger.list_recoverable()? {
        if rec.backend_identity != backend_hex {
            continue;
        }
        let Some(read) =
            reclaim_read(pool, rec.repository_id, rec.operation_id, backend_hex, Some(rec.tenant_id), deadline).await?
        else {
            continue;
        };
        let Some(all_paths) = verified_paths(&rec, &read) else { continue };
        if all_paths != rec.recorded_blob_paths {
            let _ = ledger.transition(rec.operation_id, rec.state, all_paths.clone(), read.bytes, &rec.detail);
        }
        // A missing operation row or a still-`pending` row is NOT positive durable abort proof, so the
        // quarantined record and every staged remote object stay intact (`0` deletes, `0` transitions).
        if read.proven {
            delete_and_verify_absent(&op, &all_paths, deadline).await?;
            ledger.mark_reclaimed_if_proven_aborted(rec.operation_id, true)?;
            swept += 1;
        }
    }
    Ok(swept)
}

fn verified_paths(record: &BlobUploadReclaimRecord, read: &ReclaimRead) -> Option<Vec<String>> {
    let mut paths: BTreeSet<_> = read.paths.iter().cloned().collect();
    let prefix = format!("v1/tenants/{}/", record.tenant_id);
    for path in &record.recorded_blob_paths {
        // A public record can contain paths from older attempts, but only the
        // exact PG hold history authorizes them. Legacy upload records also
        // support paths persisted before a hold was written.
        if read.public {
            if !paths.contains(path) {
                return None;
            }
        } else {
            if !path.starts_with(&prefix) || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
                return None;
            }
            paths.insert(path.clone());
        }
    }
    Some(paths.into_iter().collect())
}

async fn delete_and_verify_absent(
    op: &Operator,
    paths: &[String],
    deadline: TokioInstant,
) -> Result<(), PushCausalError> {
    for path in paths {
        timeout_at(deadline, op.delete(path))
            .await
            .map_err(|_| PushCausalError::DeadlineExceeded)?
            .map_err(|e| PushCausalError::Io(format!("remote staging delete failed: {e}")))?;
        match timeout_at(deadline, op.stat(path)).await {
            Ok(Err(e)) if e.kind() == ErrorKind::NotFound => {}
            Ok(Ok(_)) => return Err(PushCausalError::Io(format!("remote staging blob still present: {path}"))),
            Ok(Err(e)) => return Err(PushCausalError::Io(format!("remote staging stat check failed: {e}"))),
            Err(_) => return Err(PushCausalError::DeadlineExceeded),
        }
    }
    Ok(())
}
