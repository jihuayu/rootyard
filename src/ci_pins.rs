//! Controller-owned, exact-target GitFS retention. Local intent and pinned receipt
//! are part of the paired offline volume backup, not a second authority for refs.
use crate::{AppState, Error, auth, db, git_http, journal, reliability, storage};
use anyhow::{Context, Result, ensure};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub(crate) const MAX_PINS: usize = 1024;
const NAMESPACE: &str = "refs/rootyard-ci";
const ZERO: &str = "0000000000000000000000000000000000000000";

pub(crate) fn reserved(name: &str) -> bool {
    name == NAMESPACE || name.starts_with("refs/rootyard-ci/")
}
pub(crate) fn valid_oid(oid: &str) -> bool {
    oid.len() == 40
        && oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub version: u32,
    pub job_id: Uuid,
    pub owner_id: Uuid,
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub object_format: String,
    pub target_oid: String,
    pub retention_ref: String,
}
impl Intent {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.object_format == "sha1"
                && self.storage_generation > 0
                && valid_oid(&self.target_oid)
                && self.target_oid != ZERO
                && self.retention_ref == format!("{NAMESPACE}/jobs/{}", self.job_id),
            "invalid CI intent"
        );
        Ok(())
    }
    pub(crate) fn change(&self) -> journal::RefChange {
        journal::RefChange {
            ref_name: self.retention_ref.clone(),
            old_oid: ZERO.into(),
            new_oid: self.target_oid.clone(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinRequest {
    job_id: Uuid,
    target_oid: String,
    storage_generation: i64,
}
fn directory(root: &FsPath, repo: Uuid) -> PathBuf {
    root.join("ci-pins").join(repo.to_string())
}
pub(crate) fn load_intent(root: &FsPath, repo: Uuid, job: Uuid) -> Result<Intent> {
    let intent: Intent = serde_json::from_slice(&journal::read(
        &directory(root, repo).join(format!("{job}.json")),
    )?)?;
    intent.validate()?;
    ensure!(
        intent.repository_id == repo && intent.job_id == job,
        "CI intent path mismatch"
    );
    Ok(intent)
}
fn receipt(root: &FsPath, intent: &Intent) -> Result<()> {
    journal::atomic(
        &directory(root, intent.repository_id).join(format!("{}.pinned.json", intent.job_id)),
        &serde_json::to_vec(intent)?,
        false,
    )
}
fn intents(root: &FsPath, repo: Uuid) -> Result<HashMap<String, Intent>> {
    let path = directory(root, repo);
    if !journal::exists(&path)? {
        return Ok(HashMap::new());
    }
    let mut result = HashMap::new();
    let mut entries = 0;
    for entry in std::fs::read_dir(&path)? {
        entries += 1;
        ensure!(
            entries <= 3 * MAX_PINS + 16,
            "CI metadata directory exceeds limit"
        );
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("invalid CI filename"))?;
        if name.starts_with(".tmp-") {
            continue;
        }
        let suffix = if name.ends_with(".pinned.json") {
            ".pinned.json"
        } else {
            ".json"
        };
        let job: Uuid = name
            .strip_suffix(suffix)
            .context("invalid CI record")?
            .parse()?;
        let intent = load_intent(root, repo, job)?;
        if suffix == ".pinned.json" {
            ensure!(
                journal::read(&entry.path())? == serde_json::to_vec(&intent)?,
                "CI pinned receipt changed"
            );
        } else {
            ensure!(name == format!("{job}.json"), "noncanonical CI identity");
            result.insert(intent.retention_ref.clone(), intent);
            ensure!(result.len() <= MAX_PINS, "CI plan admission limit reached");
        }
    }
    Ok(result)
}
fn git(state: &AppState, repo: Uuid) -> Result<tokio::process::Command> {
    let mut cmd = crate::mirror::mirror_git(state);
    cmd.arg("--git-dir").arg(state.storage.verify_path(repo)?);
    Ok(cmd)
}
async fn run(state: &AppState, repo: Uuid, args: &[&str], limit: usize) -> Result<Vec<u8>> {
    let mut cmd = git(state, repo)?;
    cmd.args(args);
    git_http::collect_git_output(cmd, limit, state.config.git_timeout).await
}
// Include symbolic targets so a symbolic ref cannot masquerade as immutable.
async fn roots(state: &AppState, repo: Uuid) -> Result<HashMap<String, String>> {
    let bytes = run(
        state,
        repo,
        &[
            "for-each-ref",
            "--count=1026",
            "--format=%(refname)%00%(objectname)%00%(symref)",
            NAMESPACE,
        ],
        256 * 1024,
    )
    .await?;
    let mut result = HashMap::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let fields: Vec<_> = line.split('\0').collect();
        ensure!(
            fields.len() == 3
                && reserved(fields[0])
                && valid_oid(fields[1])
                && fields[2].is_empty(),
            "unsupported CI retention ref"
        );
        result.insert(fields[0].to_owned(), fields[1].to_owned());
        ensure!(
            result.len() <= MAX_PINS,
            "CI retention namespace exceeds limit"
        );
    }
    // for-each-ref omits broken symbolic refs. Inspect the loose reserved tree
    // too: an unlisted/dangling ref, lock or symlink must never be overwritten
    // by the first create-only CAS (including --no-deref on a symbolic ref).
    let repo_path = state.storage.verify_path(repo)?;
    let reserved_path = repo_path.join(NAMESPACE);
    if journal::exists(&reserved_path)? {
        let mut pending = vec![reserved_path];
        let mut count = 0;
        while let Some(path) = pending.pop() {
            count += 1;
            ensure!(count <= 3 * MAX_PINS + 16, "CI loose refs exceed bound");
            journal::safe_path(&path)?;
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                for entry in std::fs::read_dir(&path)? {
                    pending.push(entry?.path());
                }
            } else {
                ensure!(meta.is_file(), "unsupported CI loose ref");
                let name = path
                    .strip_prefix(&repo_path)?
                    .to_str()
                    .context("invalid CI ref path")?;
                let bytes = journal::read(&path)?;
                let value = std::str::from_utf8(&bytes)?
                    .strip_suffix('\n')
                    .context("invalid CI ref content")?;
                ensure!(
                    valid_oid(value) && result.get(name).is_some_and(|oid| oid == value),
                    "unlisted or symbolic CI ref collision"
                );
            }
        }
    }
    Ok(result)
}
async fn commit(state: &AppState, repo: Uuid, oid: &str) -> Result<()> {
    ensure!(
        run(state, repo, &["rev-parse", "--show-object-format"], 128).await? == b"sha1\n",
        "CI requires SHA-1 repository"
    );
    ensure!(
        run(state, repo, &["cat-file", "-t", oid], 128).await? == b"commit\n",
        "target is not an actual commit"
    );
    Ok(())
}

/// Recover only a typed exact maintenance operation. Caller proves child completion
/// (or startup volume ownership) and holds the writer lock. Native refs remain truth.
/// This is explicitly observed retention evidence, never a fabricated push receipt.
pub(crate) async fn observed_operation(
    state: &AppState,
    operation: &journal::Operation,
) -> Result<Option<Vec<journal::RefChange>>> {
    let Some(intent) = &operation.ci_pin else {
        return Ok(None);
    };
    ensure!(
        load_intent(&state.storage.root, intent.repository_id, intent.job_id)? == *intent,
        "CI intent changed"
    );
    let owner = state
        .pool
        .get()
        .await?
        .query_one(
            "SELECT owner_id,storage_generation FROM repositories WHERE id=$1",
            &[&intent.repository_id],
        )
        .await?;
    ensure!(
        owner.get::<_, Uuid>(0) == intent.owner_id
            && owner.get::<_, i64>(1) == intent.storage_generation,
        "CI authority changed"
    );
    let events = journal::events(operation)?;
    ensure!(
        events
            .iter()
            .all(|event| event.changes == [intent.change()]),
        "CI maintenance evidence changed"
    );
    ensure!(
        journal::requests(operation)?.is_none() && journal::receipts(operation)?.is_none(),
        "CI operation is not receive-pack"
    );
    let current = roots(state, intent.repository_id).await?;
    match current.get(&intent.retention_ref) {
        Some(oid) => {
            ensure!(oid == &intent.target_oid, "retention root changed");
            commit(state, intent.repository_id, oid).await?;
            Ok(Some(vec![intent.change()]))
        }
        None => {
            ensure!(
                !events
                    .iter()
                    .any(|event| event.phase == journal::HookPhase::Committed),
                "committed retention root is missing"
            );
            ensure!(
                !journal::exists(
                    &directory(&state.storage.root, intent.repository_id)
                        .join(format!("{}.pinned.json", intent.job_id))
                )?,
                "pinned retention root is missing"
            );
            Ok(Some(Vec::new()))
        }
    }
}

pub async fn pin(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<PinRequest>,
) -> Result<Response, Error> {
    tokio::spawn(async move { pin_inner(state, owner, name, headers, input).await })
        .await
        .map_err(Error::internal)?
}
async fn pin_inner(
    state: Arc<AppState>,
    owner: String,
    name: String,
    headers: HeaderMap,
    input: PinRequest,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    if owner != actor.username || !db::valid_name(&owner) || !db::valid_name(&name) {
        return Err(Error::not_found());
    }
    if !valid_oid(&input.target_oid) || input.target_oid == ZERO || input.storage_generation <= 0 {
        return Err(Error::bad_request());
    }
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            &format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT),
            &[&actor.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let repo = db::Repository::from_row(&row);
    if repo.storage_generation != input.storage_generation {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    if repo.state != "ready" {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "repository not ready",
        ));
    }
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    reliability::before_push(&state, &repo)
        .await
        .map_err(Error::internal)?;
    // Hold current token/owner/repository authority through ref publication. The
    // durable journal is reconciled after releasing SQL locks; it is not rolled
    // back by a database disconnect and never pretends to be a SQL transaction.
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    tx.batch_execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='10s'")
        .await
        .map_err(Error::internal)?;
    tx.query_opt("SELECT t.id FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.id=$1 AND t.user_id=$2 AND u.username=$3 FOR SHARE OF t,u", &[&actor.token_id,&actor.id,&owner]).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    let locked = tx.query_opt("SELECT state,storage_generation FROM repositories WHERE id=$1 AND owner_id=$2 AND name=$3 FOR SHARE", &[&repo.id,&actor.id,&name]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let token = tx.query_opt("SELECT read_only FROM tokens WHERE id=$1 AND user_id=$2 AND digest=$3 AND NOT revoked AND (expires_at IS NULL OR expires_at > clock_timestamp())", &[&actor.token_id,&actor.id,&actor.token_digest]).await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    if token.get::<_, bool>(0) {
        return Err(Error(StatusCode::FORBIDDEN, "write permission required"));
    }
    if locked.get::<_, i64>(1) != input.storage_generation {
        return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
    }
    if locked.get::<_, String>(0) != "ready" {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "repository not ready",
        ));
    }
    let intent = Intent {
        version: 1,
        job_id: input.job_id,
        owner_id: actor.id,
        repository_id: repo.id,
        storage_generation: input.storage_generation,
        object_format: "sha1".into(),
        target_oid: input.target_oid,
        retention_ref: format!("{NAMESPACE}/jobs/{}", input.job_id),
    };
    let existing = intents(&state.storage.root, repo.id).map_err(Error::internal)?;
    if let Some(prior) = existing.get(&intent.retention_ref) {
        if prior != &intent {
            return Err(Error(
                StatusCode::CONFLICT,
                "job already has a different target or generation",
            ));
        }
    } else if existing.len() >= MAX_PINS {
        return Err(Error(
            StatusCode::TOO_MANY_REQUESTS,
            "CI plan admission limit reached",
        ));
    }
    let native = roots(&state, repo.id)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "CI retention namespace collision"))?;
    for (name, oid) in &native {
        if !existing
            .get(name)
            .is_some_and(|plan| plan.target_oid == *oid && plan.owner_id == actor.id)
        {
            return Err(Error(
                StatusCode::CONFLICT,
                "unmanaged or changed CI retention ref; operator investigation required",
            ));
        }
    }
    commit(&state, repo.id, &intent.target_oid)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "exact commit unavailable"))?;
    let repo_path = state
        .storage
        .verify_path(repo.id)
        .map_err(Error::internal)?;
    let quota = state.config.max_repo_bytes;
    let size = tokio::task::spawn_blocking(move || storage::disk_bytes(&repo_path, quota))
        .await
        .map_err(Error::internal)?
        .map_err(Error::internal)?;
    if size.saturating_add(4096) >= quota {
        return Err(Error(
            StatusCode::INSUFFICIENT_STORAGE,
            "repository quota reached",
        ));
    }
    let root = state.storage.root.join("ci-pins");
    journal::mkdir(&root).map_err(Error::internal)?;
    let dir = directory(&state.storage.root, repo.id);
    journal::mkdir(&dir).map_err(Error::internal)?;
    journal::atomic(
        &dir.join(format!("{}.json", intent.job_id)),
        &serde_json::to_vec(&intent).map_err(Error::internal)?,
        false,
    )
    .map_err(Error::internal)?;
    if !native.contains_key(&intent.retention_ref) {
        // A pinned receipt without its root is corruption, never permission to
        // recreate or overwrite a previously promised immutable retention root.
        if journal::exists(&dir.join(format!("{}.pinned.json", intent.job_id)))
            .map_err(Error::internal)?
        {
            return Err(Error::internal("pinned CI root missing"));
        }
        let operation =
            journal::begin_ci(&state.storage.root, actor.username, actor.token_id, &intent)
                .map_err(Error::internal)?;
        let mut cmd = git(&state, repo.id).map_err(Error::internal)?;
        cmd.arg("-c")
            .arg(format!(
                "core.hooksPath={}",
                state.storage.root.join("managed-hooks").display()
            ))
            .env("ROOTYARD_JOURNAL_OPERATION", &operation.path)
            .args([
                "update-ref",
                "--no-deref",
                &intent.retention_ref,
                &intent.target_oid,
                ZERO,
            ]);
        // collect_git_output owns/kills/waits for the entire child process group.
        // A failed/timeout command is not evidence of rollback; reconcile refs.
        let result = git_http::collect_git_output(cmd, 4096, state.config.git_timeout).await;
        journal::finish(&operation).map_err(Error::internal)?;
        drop(tx);
        drop(client);
        reliability::complete(&state, Some(operation))
            .await
            .map_err(Error::internal)?;
        result.map_err(Error::internal)?;
    } else {
        tx.commit().await.map_err(Error::internal)?;
        drop(client);
    }
    let native = roots(&state, repo.id).await.map_err(Error::internal)?;
    if native.get(&intent.retention_ref) != Some(&intent.target_oid) {
        return Err(Error::internal("CI retention root not verified"));
    }
    receipt(&state.storage.root, &intent).map_err(Error::internal)?;
    // Revalidate before returning a usable receipt; a revoked caller may have
    // retained bytes but cannot obtain new readiness or read access.
    let current = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&current)?;
    if current.id != actor.id || current.username != owner {
        return Err(Error::unauthorized());
    }
    let current_repo = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_one(
            "SELECT state,storage_generation FROM repositories WHERE id=$1 AND owner_id=$2",
            &[&repo.id, &actor.id],
        )
        .await
        .map_err(Error::internal)?;
    if current_repo.get::<_, String>(0) != "ready"
        || current_repo.get::<_, i64>(1) != intent.storage_generation
    {
        return Err(Error(
            StatusCode::CONFLICT,
            "repository changed during pinning",
        ));
    }
    let mut value = serde_json::to_value(intent).map_err(Error::internal)?;
    value["state"] = "pinned".into();
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response())
}

/// Verify retained native truth under the caller-held repository writer lock.
/// The receipt is evidence of retention, never an authorization source.
pub(crate) async fn verify_receipt(state: &AppState, expected: &Intent) -> Result<String> {
    use sha2::{Digest, Sha256};
    expected.validate()?;
    ensure!(
        load_intent(&state.storage.root, expected.repository_id, expected.job_id)? == *expected,
        "source intent differs"
    );
    let bytes = journal::read(
        &directory(&state.storage.root, expected.repository_id)
            .join(format!("{}.pinned.json", expected.job_id)),
    )?;
    ensure!(
        bytes == serde_json::to_vec(expected)?,
        "source receipt differs"
    );
    let path = state.storage.verify_path(expected.repository_id)?;
    for forbidden in [
        "shallow",
        "info/grafts",
        "objects/info/alternates",
        "objects/info/http-alternates",
    ] {
        ensure!(
            !journal::exists(&path.join(forbidden))?,
            "unsupported source object topology"
        );
    }
    ensure!(
        roots(state, expected.repository_id)
            .await?
            .get(&expected.retention_ref)
            == Some(&expected.target_oid),
        "source retention missing or changed"
    );
    commit(state, expected.repository_id, &expected.target_oid).await?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_oid_and_reserved_namespace() {
        assert!(valid_oid(&"a".repeat(40)));
        for value in [
            "HEAD".to_owned(),
            "A".repeat(40),
            "a".repeat(39),
            "a".repeat(64),
        ] {
            assert!(!valid_oid(&value));
        }
        for name in [
            "refs/rootyard-ci",
            "refs/rootyard-ci/jobs",
            "refs/rootyard-ci/jobs/a",
        ] {
            assert!(reserved(name));
        }
        for name in [
            "refs/heads/rootyard-ci",
            "refs/rootyard-ci-other",
            "refs/rootyard",
        ] {
            assert!(!reserved(name));
        }
    }
    #[test]
    fn metadata_identity_and_receipt_are_immutable() {
        let root = tempfile::tempdir().unwrap();
        let intent = Intent {
            version: 1,
            job_id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            storage_generation: 1,
            object_format: "sha1".into(),
            target_oid: "a".repeat(40),
            retention_ref: String::new(),
        };
        let intent = Intent {
            retention_ref: format!("{NAMESPACE}/jobs/{}", intent.job_id),
            ..intent
        };
        journal::mkdir(&root.path().join("ci-pins")).unwrap();
        let directory = directory(root.path(), intent.repository_id);
        journal::mkdir(&directory).unwrap();
        journal::atomic(
            &directory.join(format!("{}.json", intent.job_id)),
            &serde_json::to_vec(&intent).unwrap(),
            false,
        )
        .unwrap();
        receipt(root.path(), &intent).unwrap();
        receipt(root.path(), &intent).unwrap();
        assert_eq!(
            load_intent(root.path(), intent.repository_id, intent.job_id).unwrap(),
            intent
        );
        let changed = Intent {
            target_oid: "b".repeat(40),
            ..intent.clone()
        };
        assert!(receipt(root.path(), &changed).is_err());
        assert_eq!(intents(root.path(), intent.repository_id).unwrap().len(), 1);
        let changed = Intent {
            object_format: "sha256".into(),
            ..intent
        };
        assert!(changed.validate().is_err());
    }
}
