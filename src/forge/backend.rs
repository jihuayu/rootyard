//! Repository storage backend status and administrative switch.
use super::handlers::{json, positive};
use crate::{AppState, Error, auth::{self, Role, authorize_repo_with_role as authorize, finish_tx as finish}};
use axum::{Json, extract::{Path, State}, http::{HeaderMap, StatusCode}, response::Response};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct BackendPatch {
    pub storage_backend: String,
    pub expected_storage_generation: Option<i64>,
    #[serde(default)]
    pub write_paused: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageBackendMarker {
    pub storage_backend: String,
    pub storage_generation: i64,
    #[serde(default)]
    pub write_paused: bool,
    #[serde(default)]
    pub pando_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackendStatusResponse {
    pub repository_id: Uuid,
    pub owner: String,
    pub name: String,
    pub storage_backend: String,
    pub storage_generation: i64,
    pub state: String,
    pub gateway_route: String,
    pub read_backend: String,
    pub write_backend: String,
    pub write_paused: bool,
    pub pando_ready: bool,
    pub gitfs_ready: bool,
}

pub(crate) fn read_repo_git_config_backend(repo_path: &std::path::Path) -> (Option<String>, bool) {
    let Ok(cfg_text) = std::fs::read_to_string(repo_path.join("config")) else { return (None, false); };
    let (mut in_ry, mut backend, mut paused) = (false, None, false);
    for raw in cfg_text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_ry = line[1..line.len() - 1].trim().eq_ignore_ascii_case("rootyard");
        } else if in_ry
            && let Some((k, v)) = line.split_once('=') {
                let (k, v) = (k.trim(), v.trim().trim_matches('"'));
                if k.eq_ignore_ascii_case("storagebackend") && matches!(v, "gitfs" | "pando") {
                    backend = Some(v.to_owned());
                } else if k.eq_ignore_ascii_case("writepaused") {
                    paused = v.eq_ignore_ascii_case("true") || v == "1" || v.eq_ignore_ascii_case("yes");
                }
            }
    }
    (backend, paused)
}

pub(crate) fn read_repo_backend_marker(repo_path: &std::path::Path) -> Option<StorageBackendMarker> {
    serde_json::from_slice(&std::fs::read(repo_path.join("rootyard-storage-backend.json")).ok()?).ok()
}

fn write_repo_backend_marker(repo_path: &std::path::Path, marker: &StorageBackendMarker) -> std::io::Result<()> {
    let tmp = repo_path.join(format!(".rootyard-storage-backend.tmp-{}", Uuid::new_v4()));
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    std::io::Write::write_all(&mut f, &serde_json::to_vec_pretty(marker)?)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, repo_path.join("rootyard-storage-backend.json"))?;
    std::fs::File::open(repo_path)?.sync_all()
}

pub(crate) fn build_backend_status(
    state: &AppState, repository_id: Uuid, owner: String, name: String, repo_state: String, db_backend: &str, storage_generation: i64,
) -> BackendStatusResponse {
    let repo_path = state.storage.repo_path(repository_id);
    let gitfs_ready = repo_state == "ready" && state.storage.verify_path(repository_id).is_ok();
    let marker = read_repo_backend_marker(&repo_path);
    let (_, cfg_paused) = read_repo_git_config_backend(&repo_path);
    // Marker/config hints never promote a backend: only a verified migration
    // can commit the authoritative database backend and enable its dispatcher.
    let storage_backend = db_backend.to_owned();
    let write_paused = marker.as_ref().map(|m| m.write_paused).unwrap_or(cfg_paused);
    let serving = if db_backend == "gitfs" { "gitfs" } else { "unavailable" };
    let gateway_route = if db_backend == "gitfs" { "gitfs_local" } else { "unavailable" }.to_owned();
    let pando_ready = false;
    BackendStatusResponse {
        repository_id, owner, name, read_backend: serving.into(), write_backend: serving.into(),
        storage_backend, storage_generation, state: repo_state, gateway_route, write_paused,
        pando_ready, gitfs_ready: gitfs_ready && db_backend == "gitfs",
    }
}

pub async fn get_backend(
    State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>, headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Read, crate::token_scopes::RepoAction::RepoRead).await.map(|access| access.repo_id)?;
    let row = tx.query_one("SELECT r.name, r.state, r.storage_backend, r.storage_generation, ns.slug FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id WHERE r.id = $1", &[&repo_id]).await.map_err(Error::internal)?;
    let status = build_backend_status(&state, repo_id, row.get("slug"), row.get("name"), row.get("state"), row.get::<_, &str>("storage_backend"), row.get("storage_generation"));
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, status))
}

pub async fn set_backend(
    State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>, headers: HeaderMap, Json(input): Json<BackendPatch>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !matches!(input.storage_backend.as_str(), "gitfs" | "pando") { return Err(Error::bad_request()); }
    if let Some(expected) = input.expected_storage_generation { positive(expected)?; }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Admin, crate::token_scopes::RepoAction::RepoAdmin).await?;
    let repo_id = access.repo_id;
    if input.storage_backend == "pando" {
        return Err(Error(StatusCode::CONFLICT,
            "Pando cutover requires a verified production migration"));
    }
    let _write_guard = state.storage.write_lock(repo_id).await;
    let row = tx.query_one("SELECT r.name, r.state, r.storage_backend, r.storage_generation, ns.slug FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id WHERE r.id = $1 FOR UPDATE OF r", &[&repo_id]).await.map_err(Error::internal)?;
    if row.get::<_, &str>("storage_backend") != "gitfs" {
        return Err(Error(StatusCode::CONFLICT,
            "backend changes require a verified migration"));
    }
    let current_gen: i64 = row.get("storage_generation");
    if input.expected_storage_generation.is_some_and(|exp| exp != current_gen) {
        return Err(Error(StatusCode::CONFLICT, "storage generation conflict"));
    }
    let updated = tx.query_one("UPDATE repositories SET storage_generation = storage_generation + 1 WHERE id = $1 RETURNING state, storage_generation", &[&repo_id]).await.map_err(Error::internal)?;
    let (new_gen, repo_state): (i64, String) = (updated.get("storage_generation"), updated.get("state"));
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let marker = StorageBackendMarker { storage_backend: input.storage_backend.clone(), storage_generation: new_gen, write_paused: input.write_paused, pando_ready: false };
    write_repo_backend_marker(&repo_path, &marker).map_err(Error::internal)?;
    let (gen_str, paused_str) = (new_gen.to_string(), if input.write_paused { "true" } else { "false" });
    let receive_pack = if !input.write_paused && input.storage_backend == "gitfs" { "true" } else { "false" };
    for (k, v) in [("rootyard.storageBackend", input.storage_backend.as_str()), ("rootyard.storageGeneration", gen_str.as_str()), ("rootyard.writePaused", paused_str), ("http.receivepack", receive_pack)] {
        let out = state.storage.git(&state.config).arg("--git-dir").arg(&repo_path).args(["config", k, v]).output().await.map_err(Error::internal)?;
        if !out.status.success() { return Err(Error::internal("failed to update repository backend config")); }
    }
    crate::members::audit::record_audit_event(&tx, access.owner_id, repo_id, &actor, "repository.storage_backend.changed", "repository", &name, serde_json::json!({"storage_backend": input.storage_backend, "old_storage_generation": current_gen, "new_storage_generation": new_gen})).await?;
    let status = build_backend_status(&state, repo_id, row.get("slug"), row.get("name"), repo_state, &input.storage_backend, new_gen);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, status))
}
