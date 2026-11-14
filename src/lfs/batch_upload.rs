//! Three-phase Git LFS Batch upload handler with bounded retry verification on
//! concurrent `pending -> ready` transitions and deduplicated remote repairs.
use super::{
    handlers::{obj_error, reauthorize_repo},
    handlers_batch::{BatchContext, object_href, verify_href},
    models::{
        self, BatchActionLink, BatchActions, BatchObjectResult, BatchObjectSpec, LFS_MEDIA_TYPE,
    },
    storage,
};
use crate::{Error, auth, token_scopes::RepoAction};
use axum::http::StatusCode;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::SystemTime,
};
use uuid::Uuid;

const MAX_BATCH_UPLOAD_PASSES: usize = 3;

enum UploadSlot {
    Invalid,
    TooLarge,
    SizeMismatch,
    ReadyCandidate { updated_at: SystemTime },
    VerifiedReady,
    NeedsPending { prev_ready_at: Option<SystemTime> },
}

#[derive(Clone, Copy)]
enum ReserveOutcome {
    Reserved,
    SizeMismatch,
    NewlyReady { updated_at: SystemTime },
    DeferredPending,
}

fn dedup_ready_result(oid: String, size: i64) -> BatchObjectResult {
    BatchObjectResult { oid, size, authenticated: Some(true), actions: None, error: None }
}

fn upload_actions_result(ctx: &BatchContext<'_>, oid: String, size: i64) -> BatchObjectResult {
    let href = object_href(ctx, &oid, size);
    let v_href = verify_href(ctx);
    let mut upload_header = ctx.action_header.clone();
    upload_header.insert("Content-Type".to_owned(), "application/octet-stream".to_owned());
    let mut verify_header = ctx.action_header.clone();
    verify_header.insert("Content-Type".to_owned(), LFS_MEDIA_TYPE.to_owned());
    BatchObjectResult {
        oid,
        size,
        authenticated: Some(true),
        actions: Some(BatchActions {
            upload: Some(BatchActionLink { href, header: upload_header, expires_in: Some(3600) }),
            download: None,
            verify: Some(BatchActionLink { href: v_href, header: verify_header, expires_in: Some(3600) }),
        }),
        error: None,
    }
}

pub(super) async fn batch_upload(
    ctx: &BatchContext<'_>,
    objects: Vec<BatchObjectSpec>,
) -> Result<Vec<BatchObjectResult>, Error> {
    // Phase 1: short read transaction for write RBAC + metadata lookup, then explicitly drop `client`.
    let (repo_id, tenant_id, mut slots) = {
        let mut client = ctx.state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let access = auth::authorize_repo_with_role(
            &tx,
            ctx.actor,
            ctx.owner,
            ctx.name,
            auth::Role::Write,
            RepoAction::ContentsWrite,
        )
        .await?;
        let (repo_id, tenant_id) = (access.repo_id, access.owner_id);
        let mut slots = Vec::with_capacity(objects.len());
        for spec in objects {
            if !models::valid_lfs_oid(&spec.oid) || spec.size < 0 {
                slots.push((spec, UploadSlot::Invalid));
                continue;
            }
            if spec.size as u64 > ctx.state.config.max_request_bytes {
                slots.push((spec, UploadSlot::TooLarge));
                continue;
            }
            let row = tx
                .query_opt(
                    "SELECT size, state, updated_at FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
                    &[&tenant_id, &repo_id, &spec.oid],
                )
                .await
                .map_err(Error::internal)?;
            let slot = match row {
                None => UploadSlot::NeedsPending { prev_ready_at: None },
                Some(r) => {
                    let (existing_size, existing_state, updated_at): (i64, String, SystemTime) =
                        (r.get(0), r.get(1), r.get(2));
                    if existing_size != spec.size {
                        UploadSlot::SizeMismatch
                    } else if existing_state == "ready" {
                        UploadSlot::ReadyCandidate { updated_at }
                    } else {
                        UploadSlot::NeedsPending { prev_ready_at: None }
                    }
                }
            };
            slots.push((spec, slot));
        }
        auth::finish_tx(tx, ctx.actor, true).await?;
        drop(client);
        (repo_id, tenant_id, slots)
    };

    let mut ran_ensure_readable = false;
    let mut repairs: BTreeSet<(String, u64)> = BTreeSet::new();
    let mut final_results: Option<Vec<BatchObjectResult>> = None;

    for pass in 0..MAX_BATCH_UPLOAD_PASSES {
        // Phase 2: run `ensure_readable` ONLY for `ReadyCandidate` rows with zero DB connections held.
        let mut pass_verified: BTreeMap<(String, u64), bool> = BTreeMap::new();
        for (spec, slot) in &mut slots {
            if let UploadSlot::ReadyCandidate { updated_at } = *slot {
                ran_ensure_readable = true;
                let key = (spec.oid.clone(), spec.size as u64);
                let on_disk = if let Some(&cached) = pass_verified.get(&key) {
                    cached
                } else {
                    let ok = storage::ensure_readable(
                        &ctx.state.storage.root,
                        repo_id,
                        tenant_id,
                        &spec.oid,
                        spec.size as u64,
                        ctx.deadline,
                    )
                    .await
                    .map_err(Error::internal)?;
                    pass_verified.insert(key, ok);
                    ok
                };
                *slot = if on_disk {
                    UploadSlot::VerifiedReady
                } else {
                    UploadSlot::NeedsPending { prev_ready_at: Some(updated_at) }
                };
            }
        }

        // Phase 3: either re-authorize after `ensure_readable` (dedup-only) or enter a write tx.
        let needs_write_tx = slots.iter().any(|(_, slot)| matches!(slot, UploadSlot::NeedsPending { .. }));
        if !needs_write_tx {
            if ran_ensure_readable {
                reauthorize_repo(
                    ctx.state,
                    ctx.actor,
                    ctx.owner,
                    ctx.name,
                    repo_id,
                    tenant_id,
                    auth::Role::Write,
                    RepoAction::ContentsWrite,
                    true,
                )
                .await?;
            }
            let mut results = Vec::with_capacity(slots.len());
            for (spec, slot) in slots {
                match slot {
                    UploadSlot::Invalid => {
                        results.push(obj_error(spec.oid, spec.size, 422, "Invalid LFS object oid or size"));
                    }
                    UploadSlot::TooLarge => {
                        results.push(obj_error(spec.oid, spec.size, 413, "LFS object exceeds maximum request size"));
                    }
                    UploadSlot::SizeMismatch => {
                        results.push(obj_error(spec.oid, spec.size, 422, "Object size mismatch with existing record"));
                    }
                    UploadSlot::VerifiedReady => {
                        repairs.insert((spec.oid.clone(), spec.size as u64));
                        results.push(dedup_ready_result(spec.oid, spec.size));
                    }
                    UploadSlot::ReadyCandidate { .. } | UploadSlot::NeedsPending { .. } => unreachable!(),
                }
            }
            final_results = Some(results);
            break;
        }

        let mut client = ctx.state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let reauth = auth::authorize_repo_with_role(
            &tx,
            ctx.actor,
            ctx.owner,
            ctx.name,
            auth::Role::Write,
            RepoAction::ContentsWrite,
        )
        .await?;
        if reauth.repo_id != repo_id || reauth.owner_id != tenant_id {
            return Err(Error(StatusCode::CONFLICT, "repository identity changed"));
        }

        let mut pass_results = Vec::with_capacity(slots.len());
        let mut pass_repairs = BTreeSet::new();
        let mut saw_newly_ready = false;

        for (spec, slot) in &mut slots {
            match *slot {
                UploadSlot::Invalid => {
                    pass_results.push(obj_error(spec.oid.clone(), spec.size, 422, "Invalid LFS object oid or size"));
                }
                UploadSlot::TooLarge => {
                    pass_results.push(obj_error(
                        spec.oid.clone(),
                        spec.size,
                        413,
                        "LFS object exceeds maximum request size",
                    ));
                }
                UploadSlot::SizeMismatch => {
                    pass_results.push(obj_error(
                        spec.oid.clone(),
                        spec.size,
                        422,
                        "Object size mismatch with existing record",
                    ));
                }
                UploadSlot::VerifiedReady => {
                    pass_repairs.insert((spec.oid.clone(), spec.size as u64));
                    pass_results.push(dedup_ready_result(spec.oid.clone(), spec.size));
                }
                UploadSlot::ReadyCandidate { .. } => unreachable!(),
                UploadSlot::NeedsPending { prev_ready_at } => {
                    match try_reserve_pending_row(&tx, tenant_id, repo_id, spec, prev_ready_at, saw_newly_ready).await? {
                        ReserveOutcome::Reserved => {
                            pass_results.push(upload_actions_result(ctx, spec.oid.clone(), spec.size));
                        }
                        ReserveOutcome::SizeMismatch => {
                            *slot = UploadSlot::SizeMismatch;
                            pass_results.push(obj_error(
                                spec.oid.clone(),
                                spec.size,
                                422,
                                "Object size mismatch with existing record",
                            ));
                        }
                        ReserveOutcome::NewlyReady { updated_at } => {
                            *slot = UploadSlot::ReadyCandidate { updated_at };
                            saw_newly_ready = true;
                        }
                        ReserveOutcome::DeferredPending => {}
                    }
                }
            }
        }

        if saw_newly_ready {
            tx.rollback().await.map_err(Error::internal)?;
            drop(client);
            if pass + 1 == MAX_BATCH_UPLOAD_PASSES {
                return Err(Error(StatusCode::CONFLICT, "LFS object state changed concurrently"));
            }
            continue;
        }

        auth::finish_tx(tx, ctx.actor, true).await?;
        drop(client);
        repairs = pass_repairs;
        final_results = Some(pass_results);
        break;
    }

    let results = final_results.ok_or(Error(StatusCode::CONFLICT, "LFS object state changed concurrently"))?;
    for (oid, size) in repairs {
        // Explicit write-path repair hook: never touched by reads, deduplicated per (oid, size).
        storage::schedule_remote_repair(
            ctx.state.storage.root.clone(),
            repo_id,
            tenant_id,
            oid,
            size,
            ctx.state.config.git_timeout,
        );
    }
    Ok(results)
}

fn classify_existing_row(
    spec_size: i64,
    cur_size: i64,
    cur_state: &str,
    cur_updated_at: SystemTime,
    prev_ready_at: Option<SystemTime>,
) -> Option<ReserveOutcome> {
    if cur_size != spec_size {
        return Some(ReserveOutcome::SizeMismatch);
    }
    if cur_state == "ready" && prev_ready_at != Some(cur_updated_at) {
        return Some(ReserveOutcome::NewlyReady { updated_at: cur_updated_at });
    }
    None
}

async fn try_reserve_pending_row(
    tx: &deadpool_postgres::Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    spec: &BatchObjectSpec,
    prev_ready_at: Option<SystemTime>,
    dry_run: bool,
) -> Result<ReserveOutcome, Error> {
    if dry_run {
        let Some(row) = tx
            .query_opt(
                "SELECT size, state, updated_at FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
                &[&tenant_id, &repo_id, &spec.oid],
            )
            .await
            .map_err(Error::internal)?
        else {
            return Ok(ReserveOutcome::DeferredPending);
        };
        let (cur_size, cur_state, cur_updated_at): (i64, String, SystemTime) = (row.get(0), row.get(1), row.get(2));
        return Ok(
            classify_existing_row(spec.size, cur_size, &cur_state, cur_updated_at, prev_ready_at)
                .unwrap_or(ReserveOutcome::DeferredPending),
        );
    }

    let mut locked = tx
        .query_opt(
            "SELECT size, state, updated_at FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3 FOR UPDATE",
            &[&tenant_id, &repo_id, &spec.oid],
        )
        .await
        .map_err(Error::internal)?;
    if locked.is_none() {
        let inserted = tx
            .execute(
                "INSERT INTO lfs_objects (tenant_id, repository_id, oid, size, state) VALUES ($1, $2, $3, $4, 'pending') ON CONFLICT (tenant_id, repository_id, oid) DO NOTHING",
                &[&tenant_id, &repo_id, &spec.oid, &spec.size],
            )
            .await
            .map_err(Error::internal)?;
        if inserted == 1 {
            return Ok(ReserveOutcome::Reserved);
        }
        locked = tx
            .query_opt(
                "SELECT size, state, updated_at FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3 FOR UPDATE",
                &[&tenant_id, &repo_id, &spec.oid],
            )
            .await
            .map_err(Error::internal)?;
    }

    let row = locked.ok_or_else(|| Error::internal("LFS object row disappeared under lock"))?;
    let (cur_size, cur_state, cur_updated_at): (i64, String, SystemTime) = (row.get(0), row.get(1), row.get(2));
    if let Some(outcome) = classify_existing_row(spec.size, cur_size, &cur_state, cur_updated_at, prev_ready_at) {
        return Ok(outcome);
    }
    tx.execute(
        "UPDATE lfs_objects SET state = 'pending', updated_at = clock_timestamp() WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
        &[&tenant_id, &repo_id, &spec.oid],
    )
    .await
    .map_err(Error::internal)?;
    Ok(ReserveOutcome::Reserved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn classify_existing_row_requires_ensure_readable_on_unverified_ready_timestamp() {
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let t2 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_001);

        assert!(matches!(
            classify_existing_row(64, 32, "ready", t1, None),
            Some(ReserveOutcome::SizeMismatch)
        ));
        assert!(matches!(
            classify_existing_row(64, 64, "ready", t1, None),
            Some(ReserveOutcome::NewlyReady { updated_at }) if updated_at == t1
        ));
        assert!(matches!(
            classify_existing_row(64, 64, "ready", t2, Some(t1)),
            Some(ReserveOutcome::NewlyReady { updated_at }) if updated_at == t2
        ));
        // Only after `ensure_readable` checked `t1` and returned false (`prev_ready_at == Some(t1)`)
        // or when the row is still `'pending'` may Phase 3 reset it to `'pending'`.
        assert!(classify_existing_row(64, 64, "ready", t1, Some(t1)).is_none());
        assert!(classify_existing_row(64, 64, "pending", t1, None).is_none());
        assert_eq!(MAX_BATCH_UPLOAD_PASSES, 3);
    }

    #[test]
    fn duplicate_oids_collapse_in_repair_set() {
        let oid1 = "a".repeat(64);
        let oid2 = "b".repeat(64);
        let mut repairs = BTreeSet::new();
        for (oid, size) in [(oid1.clone(), 128), (oid1.clone(), 128), (oid2.clone(), 256), (oid1.clone(), 128)] {
            repairs.insert((oid, size));
        }
        assert_eq!(repairs.len(), 2);
        assert!(repairs.contains(&(oid1, 128)));
        assert!(repairs.contains(&(oid2, 256)));
    }
}

