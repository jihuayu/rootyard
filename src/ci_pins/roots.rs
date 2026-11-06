//! CI pin roots implementation.
use super::*;
/// Inspect `refs/rootyard-ci/*` in an arbitrary bare Git directory (e.g. a mirror snapshot's `repository.git`).
pub async fn git_dir_pinned_roots(
    state: &AppState,
    git_dir: &FsPath,
) -> Result<HashMap<String, String>> {
    if !git_dir.exists() {
        return Ok(HashMap::new());
    }
    let mut cmd = crate::mirror::mirror_git(state);
    cmd.arg("--git-dir").arg(git_dir).args([
        "for-each-ref",
        "--count=1026",
        "--format=%(refname)%00%(objectname)%00%(symref)",
        NAMESPACE,
    ]);
    let bytes = git_http::collect_git_output(cmd, 256 * 1024, state.config.git_timeout).await?;
    let mut result = HashMap::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let fields: Vec<_> = line.split('\0').collect();
        if fields.len() == 3
            && reserved(fields[0])
            && valid_oid(fields[1])
            && fields[2].is_empty()
        {
            result.insert(fields[0].to_owned(), fields[1].to_owned());
        }
    }
    Ok(result)
}

/// Return all active `target_oid`s pinned under `refs/rootyard-ci/jobs/*` for `(repo_id, generation)`.
/// Works on both primary and read-mirror instances.
pub async fn active_pinned_oids(
    state: &AppState,
    repo_id: Uuid,
    generation: i64,
) -> Result<std::collections::BTreeSet<String>> {
    let mut oids = std::collections::BTreeSet::new();
    let mut released_refs = std::collections::HashSet::new();

    // 1. Authoritative SQL outbox_events state for `refs/rootyard-ci/*` in this generation.
    let client = state.pool.get().await?;
    let rows = client
        .query(
            "SELECT DISTINCT ON (e.ref_name) e.ref_name, e.new_oid \
             FROM outbox_events e \
             JOIN git_operations o ON o.id = e.operation_id \
             WHERE e.repository_id = $1 \
               AND e.storage_generation = $2 \
               AND e.ref_name LIKE 'refs/rootyard-ci/%' \
               AND o.outcome = 'recorded' \
             ORDER BY e.ref_name, e.operation_sequence DESC, e.transaction_sequence DESC",
            &[&repo_id, &generation],
        )
        .await?;
    for row in rows {
        let ref_name: String = row.get(0);
        let new_oid: String = row.get(1);
        if new_oid.bytes().all(|b|b==b'0') {
            released_refs.insert(ref_name);
        } else if valid_oid(&new_oid) {
            oids.insert(new_oid);
        }
    }

    // 2. Local primary or mirror filesystem state.
    if state.mirror_primary.is_none() {
        if let Ok(existing) = intents(&state.storage.root, repo_id) {
            for (ref_name, intent) in existing {
                if intent.storage_generation == generation && !released_refs.contains(&ref_name) {
                    oids.insert(intent.target_oid);
                }
            }
        }
        if let Ok(native) = roots(state, repo_id).await {
            for (ref_name, oid) in native {
                if !released_refs.contains(&ref_name) {
                    oids.insert(oid);
                }
            }
        }
    } else {
        let repo_root = state.storage.root.join("repos").join(repo_id.to_string());
        let current_path = repo_root.join("current.json");
        if let Ok(bytes) = std::fs::read(&current_path) {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if val.get("storage_generation").and_then(|v| v.as_i64()) == Some(generation) {
                    if let Some(snap) = val.get("snapshot").and_then(|v| v.as_str()) {
                        let bare = repo_root.join(snap).join("repository.git");
                        if let Ok(native) = git_dir_pinned_roots(state, &bare).await {
                            for (ref_name, oid) in native {
                                if !released_refs.contains(&ref_name) {
                                    oids.insert(oid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(oids)
}

