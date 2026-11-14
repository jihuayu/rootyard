//! Three-phase Git LFS Batch context and download handler that releases database
//! connections and row locks before disk digest verification or cold hydration.
pub(super) use super::batch_upload::batch_upload;
use super::{
    handlers::{obj_error, reauthorize_repo},
    models::{self, BatchActionLink, BatchActions, BatchObjectResult, BatchObjectSpec},
    storage,
};
use crate::{AppState, Error, auth, token_scopes::RepoAction};
use std::{collections::BTreeMap, sync::Arc};
use tokio::time::Instant;

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

pub(super) fn object_href(ctx: &BatchContext<'_>, oid: &str, size: i64) -> String {
    format!("{}/git/{}/{}.git/info/lfs/objects/{oid}/{size}", ctx.base_url, ctx.owner, ctx.name)
}

pub(super) fn verify_href(ctx: &BatchContext<'_>) -> String {
    format!("{}/git/{}/{}.git/info/lfs/verify", ctx.base_url, ctx.owner, ctx.name)
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
    let ran_ensure_readable = slots.iter().any(|slot| matches!(slot, DownloadSlot::ReadyCandidate));
    let mut pass_verified: BTreeMap<(String, u64), bool> = BTreeMap::new();
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
                let key = (spec.oid.clone(), spec.size as u64);
                let ready_on_disk = if let Some(&cached) = pass_verified.get(&key) {
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

    if ran_ensure_readable {
        reauthorize_repo(
            ctx.state,
            ctx.actor,
            ctx.owner,
            ctx.name,
            repo_id,
            tenant_id,
            auth::Role::Read,
            RepoAction::ContentsRead,
            false,
        )
        .await?;
    }
    Ok(results)
}
