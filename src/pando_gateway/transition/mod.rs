//! Durable two-phase GitFS <-> Pando cutover and rollback.
//!
//! The transition fence lives on `repositories`: the begin step atomically sets
//! `transition_state='draining'`, mints a `transition_id` and bumps
//! `backend_transition_epoch`. Every write admission reads that state, so no
//! operation admitted after the fence can mutate authority. The final switch
//! re-checks the same fence row before committing the new backend.
use super::pack_store::PackStore;
use crate::{AppState, Error, db::Repository};
use anyhow::{Result, ensure};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use tokio::time::Instant;
use uuid::Uuid;

mod fence;
mod gitfs;
#[cfg(test)]
mod tests;

pub use fence::admit_write;
use fence::{
    Fence, acquire_publication_lock, begin, complete_cutover, complete_rollback, fail, release_publication_lock,
};
use gitfs::{WorkDir, git, index_pack, parse_refs, plan_ref_mutations, valid_head, verify_closure, work_dir};

pub(super) const MAX_REFS: usize = 4096;
pub(super) const MAX_PACKS: usize = 256;
pub(super) const MAX_ERROR: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Cutover,
    Rollback,
}
impl Direction {
    fn name(self) -> &'static str {
        match self {
            Self::Cutover => "gitfs_to_pando",
            Self::Rollback => "pando_to_gitfs",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransitionReport {
    pub repository_id: Uuid,
    pub direction: String,
    pub transition_id: Uuid,
    pub transition_epoch: i64,
    pub old_storage_backend: String,
    pub new_storage_backend: String,
    pub storage_generation: i64,
    pub refs: usize,
    pub packs: usize,
    pub objects_verified: u64,
}

/// Export every GitFS branch/tag into a verified encrypted Pando pack set and
/// atomically switch the authoritative backend. Concurrent writes are rejected
/// by the durable draining fence from `begin` onward.
pub async fn cutover(state: &Arc<AppState>, repo: &Repository, deadline: Instant) -> Result<TransitionReport, Error> {
    if repo.storage_backend != "gitfs" {
        return Err(Error(StatusCode::CONFLICT, "cutover requires a GitFS repository"));
    }
    let fence = begin(state, repo.id, Direction::Cutover).await?;
    let lock = match acquire_publication_lock(&state.pool, repo.id, deadline).await {
        Ok(lock) => lock,
        Err(error) => {
            fail(state, repo.id, &fence, &anyhow::anyhow!("publication lock unavailable")).await;
            return Err(error);
        }
    };
    let result: Result<TransitionReport> = async {
        let _write = state.storage.write_lock(repo.id).await;
        let _exclusive = state.storage.maintenance_exclusive(repo.id).await;
        let bare = state.storage.verify_path(repo.id)?;
        git(state, &bare, &["fsck", "--full", "--strict"], deadline).await?;
        let all = parse_refs(
            &git(state, &bare, &["for-each-ref", "--format=%(refname) %(objectname)"], deadline).await?,
            &repo.object_format,
        )?;
        let refs: BTreeMap<_, _> = all.into_iter().filter(|(name, _)| gitfs::exported(name)).collect();
        ensure!(!refs.is_empty(), "Pando cutover requires at least one branch or tag");
        let head_ref =
            String::from_utf8(git(state, &bare, &["symbolic-ref", "HEAD"], deadline).await?)?.trim().to_owned();
        ensure!(valid_head(&head_ref), "GitFS HEAD is not an authoritative branch");
        git(state, &bare, &["repack", "-ad"], deadline).await?;
        let pack_dir = bare.join("objects/pack");
        let packs: Vec<std::path::PathBuf> = std::fs::read_dir(&pack_dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|path| path.extension().is_some_and(|ext| ext == "pack"))
            .collect();
        ensure!(packs.len() == 1, "GitFS cutover requires one consolidated pack");
        let pack = packs.into_iter().next().expect("consolidated pack");
        let index = pack.with_extension("idx");
        ensure!(index.is_file(), "GitFS cutover pack index missing");
        let objects =
            verify_closure(state, &repo.object_format, std::slice::from_ref(&pack), &refs, &head_ref, deadline).await?;
        let tenant_id: Uuid = {
            let client = state.pool.get().await?;
            client.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repo.id]).await?.get(0)
        };
        let store = PackStore::from_env(state.storage.root.join("pando-pack-work"), state.config.git.clone())?;
        let manifest = store
            .publish(
                &state.pool,
                repo.id,
                tenant_id,
                repo.storage_generation,
                &repo.object_format,
                &pack,
                &index,
                deadline,
            )
            .await?;
        complete_cutover(state, repo, &fence, tenant_id, &refs, &head_ref, &manifest)
            .await
            .map_err(|error| anyhow::anyhow!("{}", error.1))?;
        Ok(TransitionReport {
            repository_id: repo.id,
            direction: Direction::Cutover.name().into(),
            transition_id: fence.id,
            transition_epoch: fence.epoch,
            old_storage_backend: "gitfs".into(),
            new_storage_backend: "pando".into(),
            storage_generation: fence.generation,
            refs: refs.len(),
            packs: 1,
            objects_verified: objects,
        })
    }
    .await;
    release_publication_lock(&lock, repo.id).await;
    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            fail(state, repo.id, &fence, &error).await;
            Err(Error(StatusCode::SERVICE_UNAVAILABLE, "repository storage transition failed"))
        }
    }
}

/// Rehydrate the encrypted Pando pack closure into the GitFS bare repository,
/// verify ref/object parity, then atomically restore GitFS authority.
pub async fn rollback(state: &Arc<AppState>, repo: &Repository, deadline: Instant) -> Result<TransitionReport, Error> {
    if repo.storage_backend != "pando" {
        return Err(Error(StatusCode::CONFLICT, "rollback requires a Pando repository"));
    }
    let fence = begin(state, repo.id, Direction::Rollback).await?;
    let lock = match acquire_publication_lock(&state.pool, repo.id, deadline).await {
        Ok(lock) => lock,
        Err(error) => {
            fail(state, repo.id, &fence, &anyhow::anyhow!("publication lock unavailable")).await;
            return Err(error);
        }
    };
    let result: Result<TransitionReport> = async {
        let _write = state.storage.write_lock(repo.id).await;
        let _exclusive = state.storage.maintenance_exclusive(repo.id).await;
        let bare = state.storage.verify_path(repo.id)?;
        let (tenant_id, refs, head_ref, pack_ids) = {
            let client = state.pool.get().await?;
            let row = client
                .query_one(
                    "SELECT r.owner_id,s.state,s.head_ref,s.pack_ids FROM repositories r \
                JOIN pando_repository_states s ON s.repository_id=r.id \
                WHERE r.id=$1 AND s.storage_generation=r.storage_generation",
                    &[&repo.id],
                )
                .await?;
            ensure!(
                matches!(row.get::<_, String>("state").as_str(), "serving" | "rollback"),
                "Pando repository has no serving snapshot"
            );
            let pack_ids: Vec<Uuid> = row.get("pack_ids");
            ensure!(!pack_ids.is_empty() && pack_ids.len() <= MAX_PACKS, "Pando pack closure exceeds bound");
            let head_ref: String = row.get("head_ref");
            ensure!(valid_head(&head_ref), "Pando advertised HEAD is invalid");
            let rows = client
                .query("SELECT ref_name,oid FROM pando_refs WHERE repository_id=$1 ORDER BY ref_name", &[&repo.id])
                .await?;
            let mut refs = BTreeMap::new();
            for row in rows {
                let name: String = row.get(0);
                ensure!(gitfs::exported(&name), "Pando snapshot contains a non-exported ref");
                refs.insert(name, row.get(1));
            }
            ensure!(!refs.is_empty() && refs.len() <= MAX_REFS, "Pando snapshot has no refs");
            (row.get::<_, Uuid>("owner_id"), refs, head_ref, pack_ids)
        };
        let work = WorkDir(work_dir(state)?);
        let store = PackStore::from_env(state.storage.root.join("pando-pack-work"), state.config.git.clone())?;
        let mut packs = Vec::new();
        for pack_id in &pack_ids {
            let recovered = store.recover(&state.pool, repo.id, *pack_id, &work.0, deadline).await?;
            ensure!(recovered.tenant_id == tenant_id, "Pando pack tenant mismatch");
            let target = work.0.join(format!("pack-{pack_id}.pack"));
            ensure!(target.is_file(), "recovered Pando pack is missing");
            packs.push(target);
        }
        let objects = verify_closure(state, &repo.object_format, &packs, &refs, &head_ref, deadline).await?;
        // Install the verified closure in the durable GitFS volume.
        git(state, &bare, &["fsck", "--full", "--strict"], deadline).await?;
        for pack in &packs {
            index_pack(state, &bare, pack, deadline).await?;
        }
        let current = parse_refs(
            &git(state, &bare, &["for-each-ref", "--format=%(refname) %(objectname)"], deadline).await?,
            &repo.object_format,
        )?;
        let (updates, deletes) = plan_ref_mutations(&current, &refs);
        for (name, oid) in &updates {
            git(state, &bare, &["update-ref", "--no-deref", name, oid], deadline).await?;
        }
        for name in &deletes {
            git(state, &bare, &["update-ref", "--no-deref", "-d", name], deadline).await?;
        }
        git(state, &bare, &["symbolic-ref", "HEAD", &head_ref], deadline).await?;
        git(state, &bare, &["fsck", "--full", "--strict"], deadline).await?;
        let observed = parse_refs(
            &git(state, &bare, &["for-each-ref", "--format=%(refname) %(objectname)"], deadline).await?,
            &repo.object_format,
        )?;
        let observed: BTreeMap<_, _> = observed.into_iter().filter(|(name, _)| gitfs::exported(name)).collect();
        ensure!(observed == refs, "GitFS ref parity mismatch after rollback");
        let observed_head =
            String::from_utf8(git(state, &bare, &["symbolic-ref", "HEAD"], deadline).await?)?.trim().to_owned();
        ensure!(observed_head == head_ref, "GitFS HEAD parity mismatch after rollback");
        complete_rollback(state, repo, &fence).await.map_err(|error| anyhow::anyhow!("{}", error.1))?;
        Ok(TransitionReport {
            repository_id: repo.id,
            direction: Direction::Rollback.name().into(),
            transition_id: fence.id,
            transition_epoch: fence.epoch,
            old_storage_backend: "pando".into(),
            new_storage_backend: "gitfs".into(),
            storage_generation: fence.generation,
            refs: refs.len(),
            packs: pack_ids.len(),
            objects_verified: objects,
        })
    }
    .await;
    release_publication_lock(&lock, repo.id).await;
    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            fail(state, repo.id, &fence, &error).await;
            Err(Error(StatusCode::SERVICE_UNAVAILABLE, "repository storage transition failed"))
        }
    }
}
