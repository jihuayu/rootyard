//! HTTP handlers for Track 2B Git LFS Batch API, streaming upload/download, and verification.
use crate::{
    AppState, Error, auth,
    lfs::{
        models::{
            self, BatchActionLink, BatchActions, BatchObjectError, BatchObjectResult,
            BatchObjectSpec, BatchRequest, BatchResponse, LFS_MEDIA_TYPE,
        },
        storage,
    },
};
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, OnceLock},
};
use uuid::Uuid;

static UPLOAD_WAITERS: OnceLock<Mutex<HashMap<Uuid, usize>>> = OnceLock::new();
fn waiters() -> &'static Mutex<HashMap<Uuid, usize>> {
    UPLOAD_WAITERS.get_or_init(|| Mutex::new(HashMap::new()))
}
struct UploadWaiter(Uuid);
impl UploadWaiter {
    fn new(id: Uuid) -> Self {
        *waiters().lock().unwrap().entry(id).or_default() += 1;
        Self(id)
    }
}
impl Drop for UploadWaiter {
    fn drop(&mut self) {
        let mut guard = waiters().lock().unwrap();
        if let Some(count) = guard.get_mut(&self.0) {
            *count -= 1;
            if *count == 0 {
                guard.remove(&self.0);
            }
        }
    }
}

/// Read-only diagnostic used to prove a request passed metadata authorization
/// and is queued behind the repository publication lock.
pub async fn upload_waiters(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let name = models::normalize_repo_name(&repo_raw)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Admin).await?;
    let count = *waiters().lock().unwrap().get(&access.repo_id).unwrap_or(&0);
    auth::finish_tx(tx, &actor, false).await?;
    Ok(lfs_json(
        StatusCode::OK,
        serde_json::json!({"waiters":count}),
    ))
}

/// Deduplicates multiple byte-for-byte identical `Authorization` headers while leaving
/// distinct conflicting `Authorization` headers untouched so `auth::authenticate` rejects them.
pub fn sanitize_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = headers.clone();
    let auth_values: Vec<HeaderValue> = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .cloned()
        .collect();
    if auth_values.len() > 1 {
        let first = &auth_values[0];
        if auth_values.iter().all(|v| v.as_bytes() == first.as_bytes()) {
            out.insert(header::AUTHORIZATION, first.clone());
        }
    }
    out
}

fn lfs_json(status: StatusCode, value: impl Serialize) -> Response {
    let mut res = (status, Json(value)).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(LFS_MEDIA_TYPE),
    );
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    if status == StatusCode::UNAUTHORIZED {
        res.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"Rootyard\", charset=\"UTF-8\""),
        );
    }
    res
}

fn lfs_error(status: StatusCode, message: &str) -> Response {
    lfs_json(
        status,
        serde_json::json!({ "message": message, "error": message }),
    )
}

fn obj_error(oid: String, size: i64, code: u16, msg: &str) -> BatchObjectResult {
    BatchObjectResult {
        oid,
        size,
        authenticated: None,
        actions: None,
        error: Some(BatchObjectError {
            code,
            message: msg.to_owned(),
        }),
    }
}

fn build_base_url(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.eq_ignore_ascii_case("https"))
        .map(|_| "https")
        .unwrap_or("http");
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|h| {
            !h.is_empty()
                && h.len() <= 255
                && h.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-' | b'[' | b']')
                })
        })
    else {
        return String::new();
    };
    format!("{scheme}://{host}")
}

pub async fn batch(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    let headers = sanitize_headers(&headers);
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let name = models::normalize_repo_name(&repo_raw)?;
    models::check_lfs_json_headers(&headers)?;

    let req: BatchRequest = serde_json::from_slice(&body).map_err(|_| Error::bad_request())?;
    let write = match req.operation.as_str() {
        "upload" => true,
        "download" => false,
        _ => return Err(Error::bad_request()),
    };
    if write {
        auth::writable(&actor)?;
    }
    if !req.transfers.is_empty() && !req.transfers.iter().any(|t| t == "basic") {
        return Ok(lfs_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "only basic transfer adapter is supported",
        ));
    }
    if req.hash_algo.as_deref().is_some_and(|h| h != "sha256") {
        return Ok(lfs_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "only sha256 hash_algo is supported",
        ));
    }
    if req.objects.is_empty() || req.objects.len() > models::MAX_BATCH_OBJECTS {
        return Err(Error::bad_request());
    }

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(
        &tx,
        &actor,
        &owner,
        name,
        if write {
            auth::Role::Write
        } else {
            auth::Role::Read
        },
    )
    .await?;
    let (repo_id, tenant_id) = (access.repo_id, access.owner_id);

    let base_url = build_base_url(&headers);
    let mut action_header = BTreeMap::new();
    if let Some(auth_val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        action_header.insert("Authorization".to_owned(), auth_val.to_owned());
    }

    let mut results = Vec::with_capacity(req.objects.len());
    for spec in req.objects {
        if !models::valid_lfs_oid(&spec.oid) || spec.size < 0 {
            results.push(obj_error(
                spec.oid,
                spec.size,
                422,
                "Invalid LFS object oid or size",
            ));
            continue;
        }
        if spec.size as u64 > state.config.max_request_bytes {
            results.push(obj_error(
                spec.oid,
                spec.size,
                413,
                "LFS object exceeds maximum request size",
            ));
            continue;
        }

        let row = tx
            .query_opt(
                "SELECT size, state FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
                &[&tenant_id, &repo_id, &spec.oid],
            )
            .await
            .map_err(Error::internal)?;
        let object_href = format!(
            "{base_url}/git/{owner}/{name}.git/info/lfs/objects/{}/{}",
            spec.oid, spec.size
        );
        let verify_href = format!("{base_url}/git/{owner}/{name}.git/info/lfs/verify");

        if write {
            if let Some(r) = row {
                let (existing_size, existing_state): (i64, String) = (r.get(0), r.get(1));
                if existing_size != spec.size {
                    results.push(obj_error(
                        spec.oid,
                        spec.size,
                        422,
                        "Object size mismatch with existing record",
                    ));
                    continue;
                }
                let on_disk = storage::object_exists_with_size(
                    &state.storage.root,
                    repo_id,
                    &spec.oid,
                    spec.size as u64,
                )
                .map_err(Error::internal)?;
                if existing_state == "ready" && on_disk {
                    results.push(BatchObjectResult {
                        oid: spec.oid,
                        size: spec.size,
                        authenticated: Some(true),
                        actions: None,
                        error: None,
                    });
                    continue;
                }
                tx.execute(
                    "UPDATE lfs_objects SET state = 'pending', updated_at = clock_timestamp() WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
                    &[&tenant_id, &repo_id, &spec.oid],
                )
                .await
                .map_err(Error::internal)?;
            } else {
                tx.execute(
                    "INSERT INTO lfs_objects (tenant_id, repository_id, oid, size, state) VALUES ($1, $2, $3, $4, 'pending')",
                    &[&tenant_id, &repo_id, &spec.oid, &spec.size],
                )
                .await
                .map_err(Error::internal)?;
            }

            let mut upload_header = action_header.clone();
            upload_header.insert(
                "Content-Type".to_owned(),
                "application/octet-stream".to_owned(),
            );
            let mut verify_header = action_header.clone();
            verify_header.insert("Content-Type".to_owned(), LFS_MEDIA_TYPE.to_owned());

            results.push(BatchObjectResult {
                oid: spec.oid,
                size: spec.size,
                authenticated: Some(true),
                actions: Some(BatchActions {
                    upload: Some(BatchActionLink {
                        href: object_href,
                        header: upload_header,
                        expires_in: Some(3600),
                    }),
                    download: None,
                    verify: Some(BatchActionLink {
                        href: verify_href,
                        header: verify_header,
                        expires_in: Some(3600),
                    }),
                }),
                error: None,
            });
        } else {
            let ready_on_disk = if let Some(r) = row {
                let (existing_size, existing_state): (i64, String) = (r.get(0), r.get(1));
                existing_state == "ready"
                    && existing_size == spec.size
                    && storage::object_exists_with_size(
                        &state.storage.root,
                        repo_id,
                        &spec.oid,
                        spec.size as u64,
                    )
                    .map_err(Error::internal)?
            } else {
                false
            };
            if ready_on_disk {
                results.push(BatchObjectResult {
                    oid: spec.oid,
                    size: spec.size,
                    authenticated: Some(true),
                    actions: Some(BatchActions {
                        upload: None,
                        download: Some(BatchActionLink {
                            href: object_href,
                            header: action_header.clone(),
                            expires_in: Some(3600),
                        }),
                        verify: None,
                    }),
                    error: None,
                });
            } else {
                results.push(obj_error(
                    spec.oid,
                    spec.size,
                    404,
                    "LFS object does not exist",
                ));
            }
        }
    }

    auth::finish_tx(tx, &actor, write).await?;
    Ok(lfs_json(
        StatusCode::OK,
        BatchResponse {
            transfer: "basic",
            objects: results,
            hash_algo: "sha256",
        },
    ))
}

pub async fn upload_object(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    tokio::spawn(
        async move { upload_inner(state, owner, repo_raw, oid, None, headers, body).await },
    )
    .await
    .map_err(Error::internal)?
}

pub async fn upload_object_with_size(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw, oid, size)): Path<(String, String, String, i64)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    tokio::spawn(async move {
        upload_inner(state, owner, repo_raw, oid, Some(size), headers, body).await
    })
    .await
    .map_err(Error::internal)?
}

async fn upload_inner(
    state: Arc<AppState>,
    owner: String,
    repo_raw: String,
    oid: String,
    size_param: Option<i64>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    let headers = sanitize_headers(&headers);
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    let name = models::normalize_repo_name(&repo_raw)?;
    if !models::valid_lfs_oid(&oid) {
        return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "invalid LFS oid"));
    }
    if let Some(sz) = size_param {
        if sz < 0 {
            return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "invalid LFS size"));
        }
        if sz as u64 > state.config.max_request_bytes {
            return Err(Error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request size limit exceeded",
            ));
        }
    }
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|cl| cl > state.config.max_request_bytes)
    {
        return Err(Error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request size limit exceeded",
        ));
    }

    let (repo_id, tenant_id, expected_size) = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let access =
            auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Write).await?;
        let (repo_id, tenant_id) = (access.repo_id, access.owner_id);
        let row = tx
            .query_opt(
                "SELECT size, state FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
                &[&tenant_id, &repo_id, &oid],
            )
            .await
            .map_err(Error::internal)?;
        let expected = if let Some(r) = row {
            let db_size: i64 = r.get(0);
            if size_param.is_some_and(|sz| sz != db_size) {
                return Err(Error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "LFS object size mismatch",
                ));
            }
            db_size as u64
        } else if let Some(sz) = size_param {
            tx.execute(
                "INSERT INTO lfs_objects (tenant_id, repository_id, oid, size, state) VALUES ($1, $2, $3, $4, 'pending')",
                &[&tenant_id, &repo_id, &oid, &sz],
            )
            .await
            .map_err(Error::internal)?;
            sz as u64
        } else {
            return Err(Error::not_found());
        };
        auth::finish_tx(tx, &actor, true).await?;
        (repo_id, tenant_id, expected)
    };

    let waiter = UploadWaiter::new(repo_id);
    let _write_guard =
        tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo_id))
            .await
            .map_err(|_| Error::timeout())?;
    drop(waiter);

    // The reservation snapshot predates the lock. A queued upload may now be
    // superseded by a completed upload or lose authorization while waiting.
    {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Write).await?;
        let row = tx.query_opt(
            "SELECT size, state FROM lfs_objects WHERE tenant_id=$1 AND repository_id=$2 AND oid=$3",
            &[&tenant_id, &repo_id, &oid],
        ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
        let size: i64 = row.get("size");
        if size != expected_size as i64 {
            return Err(Error(
                StatusCode::CONFLICT,
                "LFS object reservation changed",
            ));
        }
        if row.get::<_, &str>("state") == "ready"
            && storage::verify_object_integrity(&state.storage.root, repo_id, &oid, expected_size)
                .map_err(Error::internal)?
        {
            auth::finish_tx(tx, &actor, true).await?;
            return Ok(lfs_json(
                StatusCode::OK,
                serde_json::json!({ "oid": oid, "size": expected_size, "state": "ready" }),
            ));
        }
        auth::finish_tx(tx, &actor, true).await?;
    }

    storage::check_repo_quota(&state, repo_id, expected_size).await?;
    tokio::time::timeout(
        state.config.git_timeout,
        storage::stream_to_staging_and_publish(&state, repo_id, &oid, expected_size, body),
    )
    .await
    .map_err(|_| Error::timeout())??;

    let finalize_res: Result<(), Error> = async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let _ = auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Write).await?;
        let updated = tx
            .execute(
                "UPDATE lfs_objects SET state = 'ready', updated_at = clock_timestamp() WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3 AND size = $4",
                &[&tenant_id, &repo_id, &oid, &(expected_size as i64)],
            )
            .await
            .map_err(Error::internal)?;
        if updated != 1 {
            return Err(Error(StatusCode::CONFLICT, "LFS object reservation missing or modified"));
        }
        auth::finish_tx(tx, &actor, true).await
    }
    .await;

    if let Err(err) = finalize_res {
        // The OID path is immutable shared content. A request that lost its token
        // after publishing must never remove bytes another request committed.
        state.transfer_metrics.record_failure();
        return Err(err);
    }

    state.transfer_metrics.record_success();
    Ok(lfs_json(
        StatusCode::OK,
        serde_json::json!({ "oid": oid, "size": expected_size, "state": "ready" }),
    ))
}

pub async fn post_object_or_verify(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    if oid == "verify" {
        return verify_object(State(state), Path((owner, repo_raw)), headers, body).await;
    }
    Err(Error::not_found())
}

pub async fn verify_object(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    let headers = sanitize_headers(&headers);
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    let name = models::normalize_repo_name(&repo_raw)?;
    models::check_lfs_json_headers(&headers)?;

    let spec: BatchObjectSpec = serde_json::from_slice(&body).map_err(|_| Error::bad_request())?;
    if !models::valid_lfs_oid(&spec.oid) || spec.size < 0 {
        return Ok(lfs_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid LFS object oid or size",
        ));
    }

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Write).await?;
    let (repo_id, tenant_id) = (access.repo_id, access.owner_id);

    let row = tx
        .query_opt(
            "SELECT size, state FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
            &[&tenant_id, &repo_id, &spec.oid],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let (db_size, db_state): (i64, String) = (row.get(0), row.get(1));
    if db_state != "ready" {
        return Err(Error::not_found());
    }
    if db_size != spec.size {
        return Ok(lfs_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "LFS object size mismatch",
        ));
    }

    let root = state.storage.root.clone();
    let oid_clone = spec.oid.clone();
    let expected_u64 = spec.size as u64;
    let verified = tokio::task::spawn_blocking(move || {
        storage::verify_object_integrity(&root, repo_id, &oid_clone, expected_u64)
    })
    .await
    .map_err(Error::internal)?
    .map_err(Error::internal)?;
    if !verified {
        return Ok(lfs_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "LFS object integrity verification failed",
        ));
    }

    auth::finish_tx(tx, &actor, true).await?;
    Ok(lfs_json(
        StatusCode::OK,
        serde_json::json!({ "oid": spec.oid, "size": spec.size, "verified": true }),
    ))
}

pub async fn download_object(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    download_inner(state, owner, repo_raw, oid, None, headers).await
}

pub async fn download_object_with_size(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw, oid, size)): Path<(String, String, String, i64)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    download_inner(state, owner, repo_raw, oid, Some(size), headers).await
}

async fn download_inner(
    state: Arc<AppState>,
    owner: String,
    repo_raw: String,
    oid: String,
    size_param: Option<i64>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let headers = sanitize_headers(&headers);
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let name = models::normalize_repo_name(&repo_raw)?;
    if !models::valid_lfs_oid(&oid) {
        return Err(Error::not_found());
    }
    if size_param.is_some_and(|s| s < 0) {
        return Err(Error::bad_request());
    }

    let (repo_id, expected_size) = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let access =
            auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Read).await?;
        let (repo_id, tenant_id) = (access.repo_id, access.owner_id);
        let row = tx
            .query_opt(
                "SELECT size, state FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
                &[&tenant_id, &repo_id, &oid],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        let (db_size, db_state): (i64, String) = (row.get(0), row.get(1));
        if db_state != "ready" || size_param.is_some_and(|sz| sz != db_size) {
            return Err(Error::not_found());
        }
        auth::finish_tx(tx, &actor, false).await?;
        (repo_id, db_size as u64)
    };

    let stream_body =
        storage::open_verified_download_stream(&state, repo_id, &oid, expected_size).await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, expected_size.to_string())
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("x-lfs-oid", &oid)
        .body(stream_body)
        .map_err(Error::internal)
}
