//! Three-phase Git LFS Batch handlers that release database connections and row
//! locks before disk digest verification or cold remote hydration.
use super::{
    handlers::obj_error,
    models::{
        self, BatchActionLink, BatchActions, BatchObjectResult, BatchObjectSpec, LFS_MEDIA_TYPE,
    },
    storage,
};
use crate::{AppState, Error, auth, token_scopes::RepoAction};
use axum::http::StatusCode;
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};
use tokio::time::Instant;
use uuid::Uuid;

pub(super) struct BatchContext<'a> {
    pub state: &'a Arc<AppState>,
    pub actor: &'a crate::db::Identity,
    pub owner: &'a str,
    pub name: &'a str,
    pub base_url: &'a str,
    pub action_header: &'a BTreeMap<String, String>,
    pub deadline: Instant,
}

enum DownloadSlot {
    Invalid,
    TooLarge,
    NotReady,
    ReadyCandidate,
}

enum UploadPhase1 {
    Invalid,
    TooLarge,
    SizeMismatch,
    ReadyCandidate { updated_at: SystemTime },
    NeedsPending { prev_ready_at: Option<SystemTime> },
}

enum UploadPhase2 {
    Invalid,
    TooLarge,
    SizeMismatch,
    VerifiedReady,
    NeedsPending { prev_ready_at: Option<SystemTime> },
}

fn object_href(ctx: &BatchContext<'_>, oid: &str, size: i64) -> String {
    format!("{}/git/{}/{}.git/info/lfs/objects/{oid}/{size}", ctx.base_url, ctx.owner, ctx.name)
}

fn verify_href(ctx: &BatchContext<'_>) -> String {
    format!("{}/git/{}/{}.git/info/lfs/verify", ctx.base_url, ctx.owner, ctx.name)
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

pub(super) async fn batch_download(
    ctx: &BatchContext<'_>,
    objects: Vec<BatchObjectSpec>,
) -> Result<Vec<BatchObjectResult>, Error> {
    // Phase 1: short read transaction for RBAC + metadata lookup, then explicitly drop `client`.
    let (repo_id, tenant_id, slots) = {
        let mut client = ctx.state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let access = auth::authorize_repo_with_role(
            &tx,
            ctx.actor,
            ctx.owner,
            ctx.name,
            auth::Role::Read,
            RepoAction::ContentsRead,
        )
        .await?;
        let (repo_id, tenant_id) = (access.repo_id, access.owner_id);
        let mut slots = Vec::with_capacity(objects.len());
        for spec in &objects {
            if !models::valid_lfs_oid(&spec.oid) || spec.size < 0 {
                slots.push(DownloadSlot::Invalid);
                continue;
            }
            if spec.size as u64 > ctx.state.config.max_request_bytes {
                slots.push(DownloadSlot::TooLarge);
                continue;
            }
            let row = tx
                .query_opt(
                    "SELECT size, state FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
                    &[&tenant_id, &repo_id, &spec.oid],
                )
                .await
                .map_err(Error::internal)?;
            let is_ready = row.is_some_and(|r| {
                let (existing_size, existing_state): (i64, String) = (r.get(0), r.get(1));
                existing_state == "ready" && existing_size == spec.size
            });
            slots.push(if is_ready { DownloadSlot::ReadyCandidate } else { DownloadSlot::NotReady });
        }
        auth::finish_tx(tx, ctx.actor, false).await?;
        drop(client);
        (repo_id, tenant_id, slots)
    };

    // Phase 2: verify/hydrate ready candidates with zero DB connection held.
    let mut results = Vec::with_capacity(objects.len());
    for (spec, slot) in objects.into_iter().zip(slots) {
        match slot {
            DownloadSlot::Invalid => {
                results.push(obj_error(spec.oid, spec.size, 422, "Invalid LFS object oid or size"));
            }
            DownloadSlot::TooLarge => {
                results.push(obj_error(spec.oid, spec.size, 413, "LFS object exceeds maximum request size"));
            }
            DownloadSlot::NotReady => {
                results.push(obj_error(spec.oid, spec.size, 404, "LFS object does not exist"));
            }
            DownloadSlot::ReadyCandidate => {
                let ready_on_disk = storage::ensure_readable(
                    &ctx.state.storage.root,
                    repo_id,
                    tenant_id,
                    &spec.oid,
                    spec.size as u64,
                    ctx.deadline,
                )
                .await
                .map_err(Error::internal)?;
                if ready_on_disk {
                    let href = object_href(ctx, &spec.oid, spec.size);
                    results.push(BatchObjectResult {
                        oid: spec.oid,
                        size: spec.size,
                        authenticated: Some(true),
                        actions: Some(BatchActions {
                            upload: None,
                            download: Some(BatchActionLink {
                                href,
                                header: ctx.action_header.clone(),
                                expires_in: Some(3600),
                            }),
                            verify: None,
                        }),
                        error: None,
                    });
                } else {
                    results.push(obj_error(spec.oid, spec.size, 404, "LFS object does not exist"));
                }
            }
        }
    }
    Ok(results)
}

pub(super) async fn batch_upload(
    ctx: &BatchContext<'_>,
    objects: Vec<BatchObjectSpec>,
) -> Result<Vec<BatchObjectResult>, Error> {
    // Phase 1: short read transaction for write RBAC + metadata lookup, then explicitly drop `client`.
    let (repo_id, tenant_id, phase1) = {
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
        let mut phase1 = Vec::with_capacity(objects.len());
        for spec in &objects {
            if !models::valid_lfs_oid(&spec.oid) || spec.size < 0 {
                phase1.push(UploadPhase1::Invalid);
                continue;
            }
            if spec.size as u64 > ctx.state.config.max_request_bytes {
                phase1.push(UploadPhase1::TooLarge);
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
                None => UploadPhase1::NeedsPending { prev_ready_at: None },
                Some(r) => {
                    let (existing_size, existing_state, updated_at): (i64, String, SystemTime) =
                        (r.get(0), r.get(1), r.get(2));
                    if existing_size != spec.size {
                        UploadPhase1::SizeMismatch
                    } else if existing_state == "ready" {
                        UploadPhase1::ReadyCandidate { updated_at }
                    } else {
                        UploadPhase1::NeedsPending { prev_ready_at: None }
                    }
                }
            };
            phase1.push(slot);
        }
        auth::finish_tx(tx, ctx.actor, false).await?;
        drop(client);
        (repo_id, tenant_id, phase1)
    };

    // Phase 2: run `ensure_readable` ONLY for rows that were `ready` with matching size,
    // holding zero database connections or row locks.
    let mut phase2 = Vec::with_capacity(objects.len());
    for (spec, slot) in objects.into_iter().zip(phase1) {
        let next = match slot {
            UploadPhase1::Invalid => UploadPhase2::Invalid,
            UploadPhase1::TooLarge => UploadPhase2::TooLarge,
            UploadPhase1::SizeMismatch => UploadPhase2::SizeMismatch,
            UploadPhase1::NeedsPending { prev_ready_at } => UploadPhase2::NeedsPending { prev_ready_at },
            UploadPhase1::ReadyCandidate { updated_at } => {
                let on_disk = storage::ensure_readable(
                    &ctx.state.storage.root,
                    repo_id,
                    tenant_id,
                    &spec.oid,
                    spec.size as u64,
                    ctx.deadline,
                )
                .await
                .map_err(Error::internal)?;
                if on_disk {
                    UploadPhase2::VerifiedReady
                } else {
                    UploadPhase2::NeedsPending { prev_ready_at: Some(updated_at) }
                }
            }
        };
        phase2.push((spec, next));
    }

    // Phase 3: only acquire a write transaction if at least one object needs `'pending'` reservation.
    let needs_write_tx = phase2.iter().any(|(_, slot)| matches!(slot, UploadPhase2::NeedsPending { .. }));
    let mut repairs: Vec<(String, u64)> = Vec::new();
    let mut results = Vec::with_capacity(phase2.len());

    if !needs_write_tx {
        for (spec, slot) in phase2 {
            match slot {
                UploadPhase2::Invalid => {
                    results.push(obj_error(spec.oid, spec.size, 422, "Invalid LFS object oid or size"));
                }
                UploadPhase2::TooLarge => {
                    results.push(obj_error(spec.oid, spec.size, 413, "LFS object exceeds maximum request size"));
                }
                UploadPhase2::SizeMismatch => {
                    results.push(obj_error(spec.oid, spec.size, 422, "Object size mismatch with existing record"));
                }
                UploadPhase2::VerifiedReady => {
                    repairs.push((spec.oid.clone(), spec.size as u64));
                    results.push(dedup_ready_result(spec.oid, spec.size));
                }
                UploadPhase2::NeedsPending { .. } => unreachable!(),
            }
        }
    } else {
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
        for (spec, slot) in phase2 {
            match slot {
                UploadPhase2::Invalid => {
                    results.push(obj_error(spec.oid, spec.size, 422, "Invalid LFS object oid or size"));
                }
                UploadPhase2::TooLarge => {
                    results.push(obj_error(spec.oid, spec.size, 413, "LFS object exceeds maximum request size"));
                }
                UploadPhase2::SizeMismatch => {
                    results.push(obj_error(spec.oid, spec.size, 422, "Object size mismatch with existing record"));
                }
                UploadPhase2::VerifiedReady => {
                    repairs.push((spec.oid.clone(), spec.size as u64));
                    results.push(dedup_ready_result(spec.oid, spec.size));
                }
                UploadPhase2::NeedsPending { prev_ready_at } => {
                    results.push(
                        reserve_pending_row(ctx, &tx, tenant_id, repo_id, spec, prev_ready_at, &mut repairs).await?,
                    );
                }
            }
        }
        auth::finish_tx(tx, ctx.actor, true).await?;
        drop(client);
    }

    for (oid, size) in repairs {
        // Explicit write-path repair hook: never touched by reads.
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

async fn reserve_pending_row(
    ctx: &BatchContext<'_>,
    tx: &deadpool_postgres::Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    spec: BatchObjectSpec,
    prev_ready_at: Option<SystemTime>,
    repairs: &mut Vec<(String, u64)>,
) -> Result<BatchObjectResult, Error> {
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
            return Ok(upload_actions_result(ctx, spec.oid, spec.size));
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
    if cur_size != spec.size {
        return Ok(obj_error(spec.oid, spec.size, 422, "Object size mismatch with existing record"));
    }
    if cur_state == "ready"
        && prev_ready_at != Some(cur_updated_at)
        && storage::object_exists_with_size(&ctx.state.storage.root, repo_id, &spec.oid, spec.size as u64)
            .map_err(Error::internal)?
    {
        repairs.push((spec.oid.clone(), spec.size as u64));
        return Ok(dedup_ready_result(spec.oid, spec.size));
    }
    tx.execute(
        "UPDATE lfs_objects SET state = 'pending', updated_at = clock_timestamp() WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
        &[&tenant_id, &repo_id, &spec.oid],
    )
    .await
    .map_err(Error::internal)?;
    Ok(upload_actions_result(ctx, spec.oid, spec.size))
}
