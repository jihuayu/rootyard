//! Git LFS v1 lock protocol and repository-scoped path ownership.
use crate::journal::RefChange;
use crate::{
    AppState, Error, auth,
    lfs::models,
    members::{audit, models::Role},
    pulls::models::{creation_replay, record_creation},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::{path::Path as FsPath, time::Duration};
use tokio_postgres::GenericClient;
use uuid::Uuid;

type Res = Result<Response, Error>;
fn response(code: StatusCode, value: impl Serialize) -> Response {
    let mut res = (code, Json(value)).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        models::LFS_MEDIA_TYPE.parse().unwrap(),
    );
    res.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    res
}
fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
fn valid_ref_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 1024 && !name.chars().any(char::is_control)
}
fn valid_lock_ref(reference: Option<&LockRef>) -> bool {
    reference.is_none_or(|r| valid_ref_name(&r.name))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockRef {
    pub name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewLock {
    pub path: String,
    #[serde(rename = "ref")]
    pub reference: Option<LockRef>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockRequest {
    #[serde(default)]
    pub force: bool,
    #[serde(rename = "ref")]
    pub reference: Option<LockRef>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    pub path: Option<String>,
    pub id: Option<Uuid>,
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
    pub refspec: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyInput {
    cursor: Option<Uuid>,
    limit: Option<i64>,
    #[serde(rename = "ref")]
    reference: Option<LockRef>,
}
#[derive(Serialize)]
pub struct LockOwner {
    pub name: String,
}
#[derive(Serialize)]
pub struct LockView {
    pub id: Uuid,
    pub path: String,
    pub locked_at: String,
    pub owner: LockOwner,
}
fn lock_view(row: &tokio_postgres::Row) -> LockView {
    LockView {
        id: row.get("id"),
        path: row.get("path"),
        locked_at: row.get("locked_at"),
        owner: LockOwner {
            name: row.get("username"),
        },
    }
}
async fn load_lock(
    tx: &Transaction<'_>,
    repo_id: Uuid,
    id: Uuid,
) -> Result<(LockView, Uuid), Error> {
    let row = tx.query_opt("SELECT l.id,l.path,to_char(l.locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS locked_at,u.username,l.owner_user_id FROM lfs_locks l JOIN users u ON u.id=l.owner_user_id WHERE l.repository_id=$1 AND l.id=$2", &[&repo_id,&id])
        .await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    Ok((lock_view(&row), row.get("owner_user_id")))
}

pub async fn create_lock(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<NewLock>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let repo = models::normalize_repo_name(&repo_raw)?;
    if !valid_path(&input.path) || !valid_lock_ref(input.reference.as_ref()) {
        return Err(Error::bad_request());
    }
    let key = auth::idempotency_key(&headers)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, repo, Role::Write).await?;
    let request = json!({"operation":"lfs_lock","path":input.path});
    if let Some(key) = key {
        if let Some(saved) =
            creation_replay(&tx, access.owner_id, access.repo_id, key, &request).await?
        {
            auth::finish_tx(tx, &actor, true).await?;
            return Ok(response(StatusCode::CREATED, saved));
        }
    }
    let id = Uuid::new_v4();
    let inserted = tx.query_opt("INSERT INTO lfs_locks(id,tenant_id,repository_id,path,owner_user_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(repository_id,path) DO NOTHING RETURNING id, path, to_char(locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS locked_at",
        &[&id,&access.owner_id,&access.repo_id,&input.path,&actor.id]).await.map_err(Error::internal)?;
    let Some(row) = inserted else {
        let existing = tx.query_one("SELECT l.id,l.path,to_char(l.locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS locked_at,u.username FROM lfs_locks l JOIN users u ON u.id=l.owner_user_id WHERE l.repository_id=$1 AND l.path=$2", &[&access.repo_id,&input.path]).await.map_err(Error::internal)?;
        auth::finish_tx(tx, &actor, false).await?;
        return Ok(response(
            StatusCode::CONFLICT,
            json!({"message":"path is already locked","lock":lock_view(&existing)}),
        ));
    };
    let view = LockView {
        id: row.get("id"),
        path: row.get("path"),
        locked_at: row.get("locked_at"),
        owner: LockOwner {
            name: actor.username.clone(),
        },
    };
    let value = json!({"lock":view});
    record_creation(&tx, access.owner_id, access.repo_id, key, &value).await?;
    audit::record_audit_event(
        &tx,
        access.owner_id,
        access.repo_id,
        &actor,
        "lfs_lock.created",
        "lfs_lock",
        &input.path,
        json!({"id":id}),
    )
    .await?;
    auth::finish_tx(tx, &actor, true).await?;
    Ok(response(StatusCode::CREATED, value))
}

pub async fn list_locks(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let repo = models::normalize_repo_name(&repo_raw)?;
    let limit = query.limit.unwrap_or(100);
    if !(1..=100).contains(&limit)
        || query.path.as_ref().is_some_and(|p| !valid_path(p))
        || query
            .refspec
            .as_deref()
            .is_some_and(|name| !valid_ref_name(name))
    {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, repo, Role::Read).await?;
    let rows = tx.query("SELECT l.id,l.path,to_char(l.locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS locked_at,u.username FROM lfs_locks l JOIN users u ON u.id=l.owner_user_id WHERE l.tenant_id=$1 AND l.repository_id=$2 AND ($3::text IS NULL OR l.path=$3) AND ($4::uuid IS NULL OR l.id=$4) AND ($5::uuid IS NULL OR l.id>$5) ORDER BY l.id LIMIT $6",
        &[&access.owner_id,&access.repo_id,&query.path,&query.id,&query.cursor,&(limit+1)]).await.map_err(Error::internal)?;
    let locks: Vec<_> = rows.iter().take(limit as usize).map(lock_view).collect();
    let next = if rows.len() > limit as usize {
        locks.last().map(|l| l.id.to_string())
    } else {
        None
    };
    auth::finish_tx(tx, &actor, false).await?;
    Ok(response(
        StatusCode::OK,
        json!({"locks":locks,"next_cursor":next}),
    ))
}

pub async fn verify_locks(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let repo = models::normalize_repo_name(&repo_raw)?;
    let input = if body.is_empty() {
        VerifyInput::default()
    } else {
        serde_json::from_slice::<VerifyInput>(&body).map_err(|_| Error::bad_request())?
    };
    if !valid_lock_ref(input.reference.as_ref())
        || input.cursor.is_some() && query.cursor.is_some() && input.cursor != query.cursor
        || input.limit.is_some() && query.limit.is_some() && input.limit != query.limit
    {
        return Err(Error::bad_request());
    }
    let cursor = input.cursor.or(query.cursor);
    let limit = input.limit.or(query.limit).unwrap_or(100);
    if !(1..=100).contains(&limit) {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, repo, Role::Write).await?;
    let rows = tx.query("SELECT l.id,l.path,to_char(l.locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS locked_at,u.username,l.owner_user_id FROM lfs_locks l JOIN users u ON u.id=l.owner_user_id WHERE l.tenant_id=$1 AND l.repository_id=$2 AND ($3::uuid IS NULL OR l.id>$3) ORDER BY l.id LIMIT $4",
        &[&access.owner_id,&access.repo_id,&cursor,&(limit+1)]).await.map_err(Error::internal)?;
    let mut ours = Vec::new();
    let mut theirs = Vec::new();
    for row in rows.iter().take(limit as usize) {
        let view = lock_view(row);
        if row.get::<_, Uuid>("owner_user_id") == actor.id {
            ours.push(view);
        } else {
            theirs.push(view);
        }
    }
    let next = if rows.len() > limit as usize {
        rows.get(limit as usize - 1)
            .map(|r| r.get::<_, Uuid>("id").to_string())
    } else {
        None
    };
    auth::finish_tx(tx, &actor, false).await?;
    Ok(response(
        StatusCode::OK,
        json!({"ours":ours,"theirs":theirs,"next_cursor":next}),
    ))
}

pub async fn unlock(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw, id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<UnlockRequest>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let repo = models::normalize_repo_name(&repo_raw)?;
    if !valid_lock_ref(input.reference.as_ref()) {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, repo, Role::Write).await?;
    let (view, owner_id) = load_lock(&tx, access.repo_id, id).await?;
    if actor.id != owner_id && !(input.force && access.role >= Role::Admin) {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "only lock owner or repository admin may unlock",
        ));
    }
    tx.execute(
        "DELETE FROM lfs_locks WHERE repository_id=$1 AND id=$2",
        &[&access.repo_id, &id],
    )
    .await
    .map_err(Error::internal)?;
    audit::record_audit_event(
        &tx,
        access.owner_id,
        access.repo_id,
        &actor,
        "lfs_lock.removed",
        "lfs_lock",
        &view.path,
        json!({"id":id,"force":input.force}),
    )
    .await?;
    auth::finish_tx(tx, &actor, true).await?;
    Ok(response(StatusCode::OK, json!({"lock":view})))
}

/// Pre-receive policy: a writer cannot change a path locked by another user.
/// Invoke under the same repository publication lock as the ref update.
pub async fn validate_new_refs_with_client<C: GenericClient + Sync>(
    client: &C,
    git_dir: &FsPath,
    git_bin: &FsPath,
    timeout: Duration,
    repo_id: Uuid,
    actor_id: Uuid,
    changes: &[RefChange],
) -> Result<(), Error> {
    let mut paths = std::collections::BTreeSet::new();
    let deadline = tokio::time::Instant::now() + timeout;
    let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());
    let mut inspected_commits = 0usize;
    if changes.len() > 256 {
        return Err(Error(
            StatusCode::CONFLICT,
            "LFS lock ref inspection exceeded limit",
        ));
    }
    for change in changes {
        if change.new_oid.bytes().all(|b| b == b'0') {
            continue;
        }
        let valid_oid = |oid: &str| {
            matches!(oid.len(), 40 | 64)
                && oid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !valid_oid(&change.old_oid)
            || !valid_oid(&change.new_oid)
            || change.old_oid.len() != change.new_oid.len()
        {
            return Err(Error(
                StatusCode::CONFLICT,
                "LFS lock Git object ID mismatch",
            ));
        }
        // A new branch can introduce an earlier commit A that edits a locked
        // path and a tip B that edits only an unrelated path. A tip-only diff
        // misses A. Inspect every commit not reachable from any existing ref;
        // a 4097th commit fails closed instead of silently truncating history.
        let count = super::publication::git_input(
            git_dir,
            git_bin,
            remaining(),
            &[
                "rev-list",
                "--count",
                "--max-count=4097",
                &change.new_oid,
                "--not",
                "--all",
            ],
            &[],
        )
        .await?;
        let count: usize = std::str::from_utf8(&count)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or(Error(StatusCode::CONFLICT, "invalid LFS lock history count"))?;
        inspected_commits = inspected_commits.saturating_add(count);
        if inspected_commits > 4096 {
            return Err(Error(
                StatusCode::CONFLICT,
                "LFS lock history inspection exceeded limit",
            ));
        }
        let raw = super::publication::git_input(
            git_dir,
            git_bin,
            remaining(),
            &[
                "log",
                "--root",
                "-m",
                "--format=",
                "--name-only",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                &change.new_oid,
                "--not",
                "--all",
            ],
            &[],
        )
        .await?;
        for part in raw.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            let path = std::str::from_utf8(part)
                .map_err(|_| Error(StatusCode::CONFLICT, "non-UTF8 locked path inspection"))?;
            paths.insert(path.to_owned());
            if paths.len() > 20_000 {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "LFS lock path inspection exceeded limit",
                ));
            }
        }
        // A ref can move to history already reachable under another branch;
        // its new commits set is empty but its visible tree may still change.
        if change.old_oid.bytes().any(|b| b != b'0') {
            let raw = super::publication::git_input(
                git_dir,
                git_bin,
                remaining(),
                &[
                    "diff",
                    "--no-ext-diff",
                    "--no-renames",
                    "--name-only",
                    "-z",
                    change.old_oid.as_str(),
                    change.new_oid.as_str(),
                ],
                &[],
            )
            .await?;
            for part in raw.split(|b| *b == 0).filter(|p| !p.is_empty()) {
                let path = std::str::from_utf8(part)
                    .map_err(|_| Error(StatusCode::CONFLICT, "non-UTF8 locked path inspection"))?;
                paths.insert(path.to_owned());
                if paths.len() > 20_000 {
                    return Err(Error(
                        StatusCode::CONFLICT,
                        "LFS lock path inspection exceeded limit",
                    ));
                }
            }
        }
    }
    if paths.is_empty() {
        return Ok(());
    }
    let paths: Vec<_> = paths.into_iter().collect();
    let conflict = client.query_opt("SELECT path FROM lfs_locks WHERE repository_id=$1 AND path=ANY($2::text[]) AND owner_user_id<>$3 LIMIT 1",
        &[&repo_id,&paths,&actor_id]).await.map_err(Error::internal)?;
    if conflict.is_some() {
        return Err(Error(
            StatusCode::CONFLICT,
            "Git update modifies a path locked by another user",
        ));
    }
    Ok(())
}
