//! Cross-host workspace lease takeover materialization and pre-`COMMIT` guards.
//!
//! Takeover materializes `workspaces/<id>` (and `lazy/<id>.json` in FUSE mode)
//! during Phase 2 while holding the per-workspace [`blocking::MutationGuard`]
//! and zero PostgreSQL row locks. The returned [`TakeoverGuards`] stay armed
//! across Phase 3 and are disarmed immediately before `tx.commit().await`, so a
//! lost takeover race or pre-`COMMIT` conflict cleans up the unreferenced lower
//! tree and sidecar instead of wedging a subsequent takeover at a newer
//! checkpoint. A pre-existing matching tree is never armed.
use crate::{
    AppState, Error,
    workspace_lab::core,
    workspaces::{blocking, lazy, models::Workspace, mounts, remote, service, snapshot},
};
use std::{fs, sync::Arc};
use uuid::Uuid;

#[derive(Default)]
pub(super) struct TakeoverGuards {
    lazy: Option<lazy::LazyPublished>,
    direct: Option<snapshot::Published>,
}

impl TakeoverGuards {
    pub(super) fn keep(&mut self) {
        if let Some(guard) = self.lazy.take() {
            guard.keep();
        }
        if let Some(guard) = self.direct.take() {
            guard.keep();
        }
    }

    pub(super) async fn cleanup(&mut self) {
        if let Some(guard) = self.lazy.take() {
            guard.cleanup().await;
        }
        if let Some(guard) = self.direct.take() {
            guard.cleanup().await;
        }
    }
}

pub(super) async fn verify_takeover_checkpoint(
    tx: &deadpool_postgres::Transaction<'_>,
    ws: &Workspace,
) -> Result<Uuid, Error> {
    let cp = ws.last_checkpoint_id.ok_or_else(service::conflict)?;
    let cp_row = tx
        .query_opt(
            "SELECT state,captured_revision FROM workspace_checkpoints WHERE id=$1 AND workspace_id=$2",
            &[&cp, &ws.id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(service::conflict)?;
    if cp_row.get::<_, String>(0) != "committed" || ws.revision != cp_row.get::<_, i64>(1) + 1 {
        return Err(service::conflict());
    }
    Ok(cp)
}

pub(super) async fn prepare_takeover(
    state: &Arc<AppState>,
    id: Uuid,
    cp: Uuid,
    repository_id: Uuid,
    tenant: Uuid,
    mutation: &blocking::MutationGuard,
) -> Result<TakeoverGuards, Error> {
    if mounts::enabled() {
        let lazy = lazy::prepare(state, id, cp, repository_id, tenant, mutation).await?;
        Ok(TakeoverGuards { lazy: Some(lazy), direct: None })
    } else {
        remote::ensure_local(state, cp, repository_id, tenant).await?;
        let state_copy = state.clone();
        let direct = blocking::run_mutating(mutation, move |abandoned, fence| {
            if abandoned.is_abandoned() {
                return Err(Error::timeout());
            }
            let mut published = materialize_takeover(&state_copy, id, cp)?;
            if let Some(ref mut guard) = published {
                guard.attach_fence(fence);
            }
            if abandoned.is_abandoned() {
                if let Some(guard) = published.take() {
                    guard.cleanup_sync();
                }
                return Err(Error::timeout());
            }
            Ok(published)
        })
        .await?;
        Ok(TakeoverGuards { lazy: None, direct })
    }
}

fn materialize_takeover(state: &AppState, id: Uuid, cp: Uuid) -> Result<Option<snapshot::Published>, Error> {
    let source = service::checkpoint_repo(state, cp);
    let destination = mounts::lower_path(state, id);
    materialize_takeover_paths(&source, &destination)
}

pub(super) async fn commit_lease_tx(
    state: &AppState,
    actor: &crate::db::Identity,
    id: Uuid,
    expected_lease_epoch: i64,
    planned_takeover: Option<Uuid>,
    takeover_guards: &mut TakeoverGuards,
    commit_started: &std::sync::atomic::AtomicBool,
) -> Result<(Workspace, i64), Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ws = super::locked_inner(
        &tx,
        actor,
        id,
        crate::members::models::Role::Write,
        crate::token_scopes::RepoAction::WorkspacesWrite,
        false,
    )
    .await?;
    if ws.lease_epoch != expected_lease_epoch {
        return Err(service::conflict());
    }
    if let Some(planned_cp) = planned_takeover {
        if ws.host_id == state.storage.volume_id {
            return Err(service::conflict());
        }
        let expired: bool = tx
            .query_one("SELECT lease_until<=clock_timestamp() FROM workspaces WHERE id=$1", &[&id])
            .await
            .map_err(Error::internal)?
            .get(0);
        if !expired || planned_cp != verify_takeover_checkpoint(&tx, &ws).await? {
            return Err(service::conflict());
        }
    } else if ws.host_id != state.storage.volume_id {
        return Err(service::conflict());
    }
    let active: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM sandbox_jobs WHERE workspace_id=$1 AND state IN ('queued','running'))",
            &[&id],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    if active {
        return Err(service::conflict());
    }
    let row = tx
        .query_opt(
            &format!(
                "UPDATE workspaces SET host_id=$2,lease_epoch=lease_epoch+1,lease_until=clock_timestamp()+interval '5 minutes' \
                 WHERE id=$1 AND lease_epoch=$3 AND (host_id=$2 OR lease_until<=clock_timestamp()) \
                 RETURNING {},EXTRACT(EPOCH FROM lease_until)::bigint AS lease_deadline",
                super::WS_COLUMNS
            ),
            &[&id, &state.storage.volume_id, &expected_lease_epoch],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(service::conflict)?;
    let deadline: i64 = row.get("lease_deadline");
    takeover_guards.keep();
    commit_started.store(true, std::sync::atomic::Ordering::Release);
    tx.commit().await.map_err(Error::internal)?;
    Ok((Workspace::from_row(&row), deadline))
}

fn materialize_takeover_paths(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<Option<snapshot::Published>, Error> {
    if destination.exists() {
        if core::inventory(destination).map_err(Error::internal)? != core::inventory(source).map_err(Error::internal)? {
            return Err(service::conflict());
        }
        return Ok(None);
    }
    let parent = destination.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let stage = parent.join(format!(".transfer-{}", Uuid::new_v4()));
    let outcome =
        core::copy_all(source, &stage).map_err(Error::internal).and_then(|()| snapshot::publish(&stage, destination));
    if outcome.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    outcome.map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_repo(root: &std::path::Path, content: &[u8]) {
        fs::create_dir_all(root.join(".git/objects")).unwrap();
        fs::create_dir_all(root.join(".git/refs")).unwrap();
        fs::write(root.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(root.join("hello.txt"), content).unwrap();
        fs::set_permissions(root.join("hello.txt"), fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn lost_takeover_cleans_up_uncommitted_tree_and_allows_newer_checkpoint_while_preserving_existing() {
        let root = tempfile::tempdir().unwrap();
        let cp1 = root.path().join("checkpoints/cp1");
        let cp2 = root.path().join("checkpoints/cp2");
        write_repo(&cp1, b"cp1\n");
        write_repo(&cp2, b"cp2\n");
        let dest = root.path().join("workspaces/ws1");

        let guard_cp1 = materialize_takeover_paths(&cp1, &dest).unwrap();
        assert!(guard_cp1.is_some());
        assert!(dest.exists());
        drop(guard_cp1);
        assert!(!dest.exists(), "aborted cp1 takeover must not wedge dest");

        let guard_cp2 = materialize_takeover_paths(&cp2, &dest).unwrap();
        guard_cp2.unwrap().keep();
        assert_eq!(fs::read(dest.join("hello.txt")).unwrap(), b"cp2\n");

        let repeat = materialize_takeover_paths(&cp2, &dest).unwrap();
        assert!(repeat.is_none());
        drop(repeat);
        assert_eq!(fs::read(dest.join("hello.txt")).unwrap(), b"cp2\n");
    }
}
