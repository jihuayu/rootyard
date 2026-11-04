//! GitFS evidence ingestion. PostgreSQL never decides which Git refs committed.
use crate::{AppState, Error, auth, db, events, journal};
use anyhow::{Result, ensure};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::{fs::File, path::Path as FsPath, sync::Arc};
use uuid::Uuid;

pub struct HookInstallation {
    executable: File,
    identity: (u64, u64, u64, i64, i64, i64, i64),
}
fn hook_identity(meta: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt;
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}
pub fn install_hooks(root: &FsPath) -> Result<HookInstallation> {
    use std::os::unix::fs::PermissionsExt;
    let dir = root.join("managed-hooks");
    std::fs::create_dir_all(&dir)?;
    ensure!(
        !std::fs::symlink_metadata(&dir)?.file_type().is_symlink(),
        "invalid hooks directory"
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    // Keep a private durable copy, not a symlink to a deploy path that may be
    // removed while this server still runs. Replacement occurs only at startup
    // under the exclusive inherited volume lock, before any receiver starts.
    let temporary = dir.join(format!(".runner-{}", Uuid::new_v4()));
    std::fs::copy(std::env::current_exe()?, &temporary)?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o500))?;
    File::open(&temporary)?.sync_all()?;
    let runner = dir.join(".runner");
    std::fs::rename(temporary, &runner)?;
    for name in ["pre-receive", "reference-transaction", "post-receive"] {
        let temporary = dir.join(format!(".{name}-{}", Uuid::new_v4()));
        std::os::unix::fs::symlink(".runner", &temporary)?;
        std::fs::rename(temporary, dir.join(name))?;
    }
    File::open(&dir)?.sync_all()?;
    File::open(root)?.sync_all()?;
    executable_access(&runner)?;
    let probe = std::process::Command::new(dir.join("pre-receive"))
        .arg("--rootyard-hook-self-check")
        .env_clear()
        .output()?;
    ensure!(
        probe.status.success() && probe.stdout == b"rootyard-hook-v1\n",
        "hook executable self-check failed; the data volume must permit execution"
    );
    let executable = File::open(runner)?;
    let identity = hook_identity(&executable.metadata()?);
    Ok(HookInstallation {
        executable,
        identity,
    })
}
fn executable_access(path: &FsPath) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    ensure!(
        unsafe { libc::access(path.as_ptr(), libc::X_OK) } == 0,
        "hook is not executable; data volume must permit execution"
    );
    Ok(())
}
pub fn verify_hooks(state: &AppState) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let hooks = state
        .hooks
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("write hooks not installed"))?;
    let dir = state.storage.root.join("managed-hooks");
    ensure!(
        !std::fs::symlink_metadata(&dir)?.file_type().is_symlink(),
        "invalid hooks directory"
    );
    let meta = std::fs::symlink_metadata(dir.join(".runner"))?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.permissions().mode() & 0o777 == 0o500,
        "invalid hook executable"
    );
    ensure!(
        hook_identity(&meta) == hooks.identity
            && hook_identity(&hooks.executable.metadata()?) == hooks.identity,
        "hook executable changed"
    );
    executable_access(&dir.join(".runner"))?;
    for name in ["pre-receive", "reference-transaction", "post-receive"] {
        executable_access(&dir.join(name))?;
        ensure!(
            std::fs::read_link(dir.join(name))? == FsPath::new(".runner"),
            "mandatory hook missing or changed"
        );
    }
    Ok(())
}

/// Caller holds the repository write lock and has proved old writers stopped.
/// Startup alone may finish an interrupted operation: the inherited volume flock
/// proves no old Git process still owns this volume. Runtime never guesses this.
pub async fn reconcile(
    state: &AppState,
    repo: Uuid,
    generation: i64,
    startup: bool,
) -> Result<bool> {
    let pending = match journal::pending(&state.storage.root, repo) {
        Ok(pending) => pending,
        Err(error) => {
            recovering(state, repo, "journal_invalid").await?;
            return Err(error);
        }
    };
    let mut clear = true;
    for operation in pending {
        match crate::maintenance::retire_if_resolved(&state.pool, &state.storage, &operation).await
        {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                recovering(state, repo, "resolved_journal_changed").await?;
                return Err(error);
            }
        }
        if startup && !journal::is_finished(&operation)? {
            journal::mark_interrupted(&operation)?;
            journal::finish(&operation)?;
        }
        let finished = journal::is_finished(&operation)?;
        let interrupted = journal::is_interrupted(&operation)?;
        let evidence = (
            journal::events(&operation),
            journal::receipts(&operation),
            journal::requests(&operation),
        );
        let (outcome, changes, evidence) = match evidence {
            (Ok(raw), Ok(receipt), Ok(requested)) => {
                let valid = finished && operation.storage_generation == generation;
                let repeated = receipt.as_ref().is_some_and(|items| {
                    let mut seen = std::collections::HashSet::new();
                    items.iter().any(|item| !seen.insert(&item.ref_name))
                });
                let outcome = if !valid || repeated {
                    "unknown"
                } else if receipt.is_some() {
                    "recorded"
                } else if !interrupted && raw.iter().all(|event| event.changes.is_empty()) {
                    "no_ref_changes"
                } else {
                    "unknown"
                };
                let changes = receipt
                    .as_ref()
                    .filter(|_| outcome == "recorded")
                    .map(|items| {
                        items
                            .iter()
                            .enumerate()
                            .filter(|(_, item)| item.ref_name.starts_with("refs/"))
                            .map(|(index, item)| events::RefEventInput {
                                transaction_sequence: index as i64 + 1,
                                ref_name: item.ref_name.clone(),
                                old_oid: item.old_oid.clone(),
                                new_oid: item.new_oid.clone(),
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let evidence = serde_json::json!({"version":1,"finished":finished,"interrupted":interrupted,"reference_events":raw,"requested":requested,"post_receive":receipt,"storage_generation_matches":operation.storage_generation==generation,"repeated_receipt_refs":repeated});
                (outcome, changes, evidence)
            }
            _ => (
                "unknown",
                Vec::new(),
                serde_json::json!({"version":1,"finished":finished,"invalid_journal":true}),
            ),
        };
        events::publish(
            &state.pool,
            &events::OperationRecord {
                id: operation.id,
                repository_id: repo,
                actor_id: operation.actor_id,
                token_id: operation.token_id,
                actor_name: operation.actor_name.clone(),
                sequence: operation.sequence,
                storage_generation: operation.storage_generation,
                outcome: outcome.into(),
                evidence,
            },
            &changes,
        )
        .await?;
        // PG publication committed. Wake hints can be lost and never affect correctness.
        state.dispatch.committed();
        if outcome == "unknown" {
            clear = false;
            recovering(state, repo, "push_outcome_unknown").await?;
        } else {
            journal::retire(&operation)?;
        }
    }
    if clear {
        // Only clear our own temporary ambiguity flag, never an unrelated
        // storage incident, and never while a durable unknown barrier remains.
        state.pool.get().await?.execute("UPDATE repositories r SET state='ready',recovery_reason=NULL WHERE id=$1 AND state='recovering' AND recovery_reason='push_outcome_unknown' AND NOT EXISTS(SELECT 1 FROM git_operations o WHERE o.repository_id=r.id AND o.outcome='unknown' AND NOT EXISTS(SELECT 1 FROM operation_resolutions covered WHERE covered.operation_id=o.id))",&[&repo]).await?;
    }
    Ok(clear)
}
async fn recovering(state: &AppState, repo: Uuid, reason: &str) -> Result<()> {
    state.pool.get().await?.execute("UPDATE repositories SET state='recovering',recovery_reason=CASE WHEN state<>'recovering' OR recovery_reason IS NULL OR recovery_reason='push_outcome_unknown' THEN $2 ELSE recovery_reason END WHERE id=$1 AND state<>'provisioning'",&[&repo,&reason]).await?;
    Ok(())
}

pub async fn before_push(state: &AppState, repo: &db::Repository) -> Result<()> {
    verify_hooks(state)?;
    ensure!(
        reconcile(state, repo.id, repo.storage_generation, false).await?,
        "repository recovery required"
    );
    let row = state
        .pool
        .get()
        .await?
        .query_one(
            "SELECT state,storage_generation FROM repositories WHERE id=$1",
            &[&repo.id],
        )
        .await?;
    ensure!(
        row.get::<_, String>(0) == "ready" && row.get::<_, i64>(1) == repo.storage_generation,
        "repository changed or recovery required"
    );
    let maximum: i64 = state
        .pool
        .get()
        .await?
        .query_one(
            "SELECT COALESCE(max(sequence),0) FROM git_operations WHERE repository_id=$1",
            &[&repo.id],
        )
        .await?
        .get(0);
    if !matches!(journal::sequence(&state.storage.root,repo.id),Ok(value) if value>=maximum) {
        recovering(state, repo.id, "journal_sequence_mismatch").await?;
        anyhow::bail!("journal sequence missing or behind durable operation history");
    }
    ensure!(
        events::pending_count(&state.pool).await? < state.config.max_pending_deliveries,
        "durable event backlog limit reached"
    );
    Ok(())
}
pub async fn complete(state: &AppState, operation: Option<journal::Operation>) -> Result<()> {
    if let Some(operation) = operation {
        if verify_hooks(state).is_err() {
            journal::mark_corrupt(&operation)?;
        }
        journal::finish(&operation)?;
        // Failure keeps the journal, so another push retries ingestion first.
        ensure!(
            reconcile(
                state,
                operation.repository_id,
                operation.storage_generation,
                false
            )
            .await?,
            "push outcome unknown"
        );
    }
    Ok(())
}
pub async fn recover_startup(state: &AppState) -> Result<()> {
    let mut after = Uuid::nil();
    loop {
        let rows=state.pool.get().await?.query("SELECT id,storage_generation FROM repositories WHERE state<>'provisioning' AND id>$1 ORDER BY id LIMIT 256",&[&after]).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let id: Uuid = row.get(0);
            after = id;
            let _lock = state.storage.write_lock(id).await;
            if reconcile(state, id, row.get(1), true).await.is_err() {
                eprintln!("rootyard: repository {id} requires journal recovery");
            }
        }
    }
    Ok(())
}
/// Runtime retry scans only retained journals, never treats an unfinished writer
/// as stopped. A busy repository is skipped rather than delaying other recovery.
pub async fn recover_pending(state: &AppState) -> Result<()> {
    let path = state.storage.root.join("journal");
    if !path.exists() {
        return Ok(());
    }
    let mut count = 0;
    for entry in std::fs::read_dir(path)? {
        count += 1;
        ensure!(count <= 100_000, "journal repository listing exceeds limit");
        let entry = entry?;
        let Some(id) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<Uuid>().ok())
        else {
            continue;
        };
        let Ok(_guard) = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            state.storage.write_lock(id),
        )
        .await
        else {
            continue;
        };
        let row = state
            .pool
            .get()
            .await?
            .query_opt(
                "SELECT storage_generation FROM repositories WHERE id=$1 AND (state='ready' OR (state='recovering' AND recovery_reason='push_outcome_unknown'))",
                &[&id],
            )
            .await?;
        if let Some(row) = row {
            if reconcile(state, id, row.get(0), false).await.is_err() {
                eprintln!("rootyard: journal ingestion retry unavailable");
            }
        }
    }
    Ok(())
}
pub async fn worker_once(state: &AppState) -> Result<usize> {
    let owner = Uuid::new_v4();
    let mut count = 0;
    for consumer in ["audit-log", "ref-index"] {
        count += events::worker_once(&state.pool, consumer, owner, 64).await?;
    }
    Ok(count)
}
async fn authorized_repo(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
) -> Result<Uuid, Error> {
    let identity = auth::authenticate(&state.pool, headers).await?;
    if owner != identity.username || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    Ok(state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            "SELECT id FROM repositories WHERE owner_id=$1 AND name=$2",
            &[&identity.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0))
}
pub async fn operations(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let id = authorized_repo(&state, &headers, &owner, &name).await?;
    let rows=state.pool.get().await.map_err(Error::internal)?.query("SELECT jsonb_build_object('id',id,'sequence',sequence,'storage_generation',storage_generation,'outcome',outcome,'resolution_id',(SELECT resolution_id FROM operation_resolutions covered WHERE covered.operation_id=git_operations.id),'actor',actor_name,'created_at',created_at,'settled_at',settled_at,'evidence_summary',jsonb_build_object('reference_event_count',jsonb_array_length(COALESCE(evidence->'reference_events','[]'::jsonb)),'receipt_count',CASE WHEN jsonb_typeof(evidence->'post_receive')='array' THEN jsonb_array_length(evidence->'post_receive') ELSE NULL END,'invalid_journal',evidence->'invalid_journal')) FROM git_operations WHERE repository_id=$1 ORDER BY storage_generation DESC,sequence DESC LIMIT 100",&[&id]).await.map_err(Error::internal)?;
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(
            rows.iter()
                .map(|r| r.get::<_, serde_json::Value>(0))
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}
pub async fn event_list(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let id = authorized_repo(&state, &headers, &owner, &name).await?;
    let rows=state.pool.get().await.map_err(Error::internal)?.query("SELECT to_jsonb(e)||jsonb_build_object('operation_outcome',o.outcome,'resolution_id',r.resolution_id,'delivery_effects',(SELECT jsonb_object_agg(consumer,effect) FROM event_deliveries WHERE event_id=e.event_id)) FROM outbox_events e JOIN git_operations o ON o.id=e.operation_id LEFT JOIN operation_resolutions r ON r.operation_id=o.id WHERE e.repository_id=$1 ORDER BY e.storage_generation DESC,e.operation_sequence DESC,e.transaction_sequence DESC LIMIT 1000",&[&id]).await.map_err(Error::internal)?;
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(
            rows.iter()
                .map(|r| r.get::<_, serde_json::Value>(0))
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}

pub async fn resolutions(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let id = authorized_repo(&state, &headers, &owner, &name).await?;
    let rows=state.pool.get().await.map_err(Error::internal)?.query("SELECT jsonb_build_object('id',id,'old_generation',old_generation,'new_generation',new_generation,'incident_revision',incident_revision,'inspected_fingerprint',inspected_fingerprint,'reason',reason,'created_at',created_at,'ref_count',jsonb_array_length(snapshot->'refs'),'covered_operations',(SELECT count(*) FROM operation_resolutions covered WHERE covered.resolution_id=recovery_resolutions.id)) FROM recovery_resolutions WHERE repository_id=$1 ORDER BY new_generation DESC LIMIT 100",&[&id]).await.map_err(Error::internal)?;
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(
            rows.iter()
                .map(|r| r.get::<_, serde_json::Value>(0))
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn executable_access_checks_capability_not_just_file_presence() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook");
        std::fs::write(&path, b"not executable").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(executable_access(&path).is_err());
        assert!(executable_access(&dir.path().join("absent")).is_err());
    }
}
