//! Safe isolation of cloned/restored Pando authorities sharing a bucket (#77).
//!
//! When a metadata-only PostgreSQL dump or PITR clone is detached from the
//! source deployment via `pando-authority isolate --confirm-shared-bucket`, any
//! live authority-scoped manifests referenced by `pando_repository_states`
//! would become unreadable if their `pando_remote_artifacts` and
//! `pando_manifest_artifacts` rows were simply wiped without copying and
//! re-registering their objects under the new authority.
//!
//! This module validates every live manifest's object closure up front,
//! copies all deduplicated scoped artifacts into fresh keys under the new
//! authority (without issuing any `DELETE` on the previous authority), and
//! atomically rotates `pando_storage_authorities` plus artifact metadata. Any
//! missing, retired, deleting, deleted, or partial live closure fails closed
//! before modifying PostgreSQL.
use crate::{
    pando_gateway::{pack_store::PackManifest, pitr_fence, pitr_lock::AuthorityLockGuard, retention},
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
};
use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::{Object, Pool};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use tokio::time::Instant;
use tokio_postgres::GenericClient;
use uuid::Uuid;

struct IsolateWorkDir(PathBuf);
impl Drop for IsolateWorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ArtifactKey {
    tenant_id: Uuid,
    namespace: String,
    sha256: String,
}

#[derive(Clone, Debug)]
struct StagedArtifact {
    src_key: ObjectKey,
    dst_key: ObjectKey,
    size: u64,
}

#[derive(Clone, Debug)]
struct MigratedLink {
    manifest_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    namespace: String,
    sha256: String,
    role: String,
}

struct LiveManifestRow {
    id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    parsed: PackManifest,
}

fn expected_manifest_roles(parsed: &PackManifest) -> [(&'static str, &'static str, &str, u64); 4] {
    [
        ("pack-cipher", retention::NAMESPACE_CIPHER, &parsed.pack.ciphertext_sha256, parsed.pack.ciphertext_bytes),
        ("pack-envelope", retention::NAMESPACE_ENVELOPE, &parsed.pack.envelope_sha256, parsed.pack.envelope_bytes),
        ("index-cipher", retention::NAMESPACE_CIPHER, &parsed.index.ciphertext_sha256, parsed.index.ciphertext_bytes),
        ("index-envelope", retention::NAMESPACE_ENVELOPE, &parsed.index.envelope_sha256, parsed.index.envelope_bytes),
    ]
}

async fn load_live_manifests<C: GenericClient + Sync>(client: &C) -> Result<Vec<LiveManifestRow>> {
    if let Some(missing) = client
        .query_opt(
            "SELECT s.repository_id, u.pack_id \
             FROM pando_repository_states s \
             CROSS JOIN LATERAL unnest(s.pack_ids) AS u(pack_id) \
             LEFT JOIN pando_pack_manifests m ON m.id = u.pack_id AND m.repository_id = s.repository_id \
             WHERE m.id IS NULL \
             LIMIT 1",
            &[],
        )
        .await?
    {
        let repo_id: Uuid = missing.get(0);
        let pack_id: Uuid = missing.get(1);
        bail!("cannot isolate cloned authority: live manifest {pack_id} for repository {repo_id} is missing");
    }

    let rows = client
        .query(
            "SELECT DISTINCT m.id, m.repository_id, m.tenant_id, m.manifest \
             FROM pando_repository_states s \
             JOIN pando_pack_manifests m ON m.repository_id = s.repository_id AND m.id = ANY(s.pack_ids) \
             ORDER BY m.id",
            &[],
        )
        .await?;

    let mut manifests = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row.get(0);
        let repository_id: Uuid = row.get(1);
        let tenant_id: Uuid = row.get(2);
        let raw_manifest: Value = row.get(3);
        let parsed: PackManifest =
            serde_json::from_value(raw_manifest).with_context(|| format!("invalid Pando manifest JSON for {id}"))?;
        ensure!(
            parsed.id == id && parsed.repository_id == repository_id && parsed.tenant_id == tenant_id,
            "live Pando manifest {id} identity does not match PostgreSQL row"
        );
        manifests.push(LiveManifestRow { id, repository_id, tenant_id, parsed });
    }
    Ok(manifests)
}

async fn validate_legacy_manifest<C: GenericClient + Sync>(
    client: &C,
    remote: &RemoteObjectStore,
    old_authority_id: Uuid,
    manifest: &LiveManifestRow,
    deadline: Instant,
) -> Result<()> {
    let conflict = client
        .query_opt(
            "SELECT 1 FROM pando_remote_artifacts \
             WHERE authority_id = $1 AND tenant_id = $2 \
               AND ((namespace = 'pando-cipher' AND sha256 IN ($3, $4)) \
                 OR (namespace = 'pando-envelope' AND sha256 IN ($5, $6))) \
             LIMIT 1",
            &[
                &old_authority_id,
                &manifest.tenant_id,
                &manifest.parsed.pack.ciphertext_sha256,
                &manifest.parsed.index.ciphertext_sha256,
                &manifest.parsed.pack.envelope_sha256,
                &manifest.parsed.index.envelope_sha256,
            ],
        )
        .await?;
    ensure!(
        conflict.is_none(),
        "cannot isolate cloned authority: live manifest {} lacks pando_manifest_artifacts links",
        manifest.id
    );
    for (_, ns, sha, expected_size) in expected_manifest_roles(&manifest.parsed) {
        let key = ObjectKey::new(manifest.tenant_id, ns, sha)?;
        let stored = Box::pin(remote.head(&key, deadline))
            .await?
            .with_context(|| format!("legacy Pando object {} missing from object store; cannot isolate", key.path()))?;
        ensure!(stored.size == expected_size, "legacy Pando object {} size mismatch", key.path());
    }
    Ok(())
}

struct LinkRow {
    repository_id: Uuid,
    authority_id: Uuid,
    tenant_id: Uuid,
    namespace: String,
    sha256: String,
    object_generation: Option<i64>,
    size: Option<i64>,
    remote_path: Option<String>,
    state: Option<String>,
}

async fn stage_live_migration<C: GenericClient + Sync>(
    client: &C,
    remote: &RemoteObjectStore,
    old_authority_id: Uuid,
    new_authority_id: Uuid,
    deadline: Instant,
) -> Result<(Vec<Uuid>, BTreeMap<ArtifactKey, StagedArtifact>, Vec<MigratedLink>)> {
    let manifests = load_live_manifests(client).await?;
    let manifest_ids: Vec<Uuid> = manifests.iter().map(|m| m.id).collect();
    if manifest_ids.is_empty() {
        return Ok((manifest_ids, BTreeMap::new(), Vec::new()));
    }

    let link_rows = client
        .query(
            "SELECT l.manifest_id, l.repository_id, l.authority_id, l.tenant_id, l.namespace, \
                    l.sha256, l.artifact_role, a.object_generation, a.size, a.remote_path, a.state \
             FROM pando_manifest_artifacts l \
             LEFT JOIN pando_remote_artifacts a \
               ON a.authority_id = l.authority_id AND a.tenant_id = l.tenant_id \
              AND a.namespace = l.namespace AND a.sha256 = l.sha256 \
             WHERE l.manifest_id = ANY($1::uuid[])",
            &[&manifest_ids],
        )
        .await?;

    let mut by_manifest: BTreeMap<Uuid, BTreeMap<String, LinkRow>> = BTreeMap::new();
    for row in link_rows {
        let manifest_id: Uuid = row.get(0);
        let role: String = row.get(6);
        by_manifest.entry(manifest_id).or_default().insert(
            role,
            LinkRow {
                repository_id: row.get(1),
                authority_id: row.get(2),
                tenant_id: row.get(3),
                namespace: row.get(4),
                sha256: row.get(5),
                object_generation: row.get(7),
                size: row.get(8),
                remote_path: row.get(9),
                state: row.get(10),
            },
        );
    }

    let mut artifacts = BTreeMap::new();
    let mut links = Vec::new();
    for manifest in &manifests {
        let Some(role_map) = by_manifest.get(&manifest.id) else {
            Box::pin(validate_legacy_manifest(client, remote, old_authority_id, manifest, deadline)).await?;
            continue;
        };
        ensure!(
            role_map.len() == 4,
            "cannot isolate cloned authority: live manifest {} has incomplete artifact links ({} != 4)",
            manifest.id,
            role_map.len()
        );
        for (role, expected_ns, expected_sha, expected_size) in expected_manifest_roles(&manifest.parsed) {
            let link = role_map
                .get(role)
                .with_context(|| format!("live manifest {} missing artifact role {role}", manifest.id))?;
            ensure!(
                link.authority_id == old_authority_id,
                "cannot isolate cloned authority: live manifest {} belongs to mismatched authority {}",
                manifest.id,
                link.authority_id
            );
            ensure!(
                link.repository_id == manifest.repository_id
                    && link.tenant_id == manifest.tenant_id
                    && link.namespace == expected_ns
                    && link.sha256 == expected_sha,
                "cannot isolate cloned authority: live manifest {} role {role} link mismatches manifest metadata",
                manifest.id
            );
            let state = link
                .state
                .as_deref()
                .with_context(|| format!("live manifest {} role {role} remote artifact row missing", manifest.id))?;
            ensure!(
                state == "active",
                "cannot isolate cloned authority: live manifest {} role {role} is in state '{state}' instead of 'active'",
                manifest.id
            );
            let object_gen = link.object_generation.context("missing object_generation")?;
            let db_size = link.size.context("missing artifact size")?;
            ensure!(db_size == expected_size as i64, "live manifest {} role {role} size mismatch", manifest.id);
            let src_key =
                ObjectKey::scoped(link.tenant_id, old_authority_id, object_gen, &link.namespace, &link.sha256)?;
            ensure!(
                link.remote_path.as_deref() == Some(src_key.path().as_str()),
                "live manifest {} role {role} remote_path mismatch",
                manifest.id
            );
            let dst_key = ObjectKey::scoped(link.tenant_id, new_authority_id, 1, &link.namespace, &link.sha256)?;
            artifacts
                .entry(ArtifactKey {
                    tenant_id: link.tenant_id,
                    namespace: link.namespace.clone(),
                    sha256: link.sha256.clone(),
                })
                .or_insert(StagedArtifact { src_key, dst_key, size: expected_size });
            links.push(MigratedLink {
                manifest_id: manifest.id,
                repository_id: manifest.repository_id,
                tenant_id: link.tenant_id,
                namespace: link.namespace.clone(),
                sha256: link.sha256.clone(),
                role: role.to_owned(),
            });
        }
    }

    Ok((manifest_ids, artifacts, links))
}

async fn copy_staged_artifacts(
    remote: &RemoteObjectStore,
    work_dir: &Path,
    artifacts: &BTreeMap<ArtifactKey, StagedArtifact>,
    deadline: Instant,
) -> Result<()> {
    tokio::fs::create_dir_all(work_dir).await?;
    for (idx, artifact) in artifacts.values().enumerate() {
        let stored = Box::pin(remote.head(&artifact.src_key, deadline)).await?.with_context(|| {
            format!("cannot isolate cloned authority: source object {} missing", artifact.src_key.path())
        })?;
        ensure!(
            stored.size == artifact.size,
            "cannot isolate cloned authority: source object {} size {} != expected {}",
            artifact.src_key.path(),
            stored.size,
            artifact.size
        );
        let stage_path = work_dir.join(format!("{idx}-{}.bin", artifact.src_key.sha256));
        Box::pin(remote.get_to_file(&artifact.src_key, &stage_path, artifact.size, deadline))
            .await
            .with_context(|| format!("download live scoped object {} during isolate", artifact.src_key.path()))?;
        let put_res = Box::pin(remote.put_file(&artifact.dst_key, &stage_path, artifact.size, deadline))
            .await
            .with_context(|| format!("upload isolated scoped object {} during isolate", artifact.dst_key.path()));
        let _ = tokio::fs::remove_file(&stage_path).await;
        put_res?;
    }
    Ok(())
}

struct MigrationPlan<'a> {
    previous_id: Uuid,
    new_authority_id: Uuid,
    staged_manifest_ids: &'a [Uuid],
    artifacts: &'a BTreeMap<ArtifactKey, StagedArtifact>,
    links: &'a [MigratedLink],
}

async fn commit_isolated_authority_locked(
    client: &mut Object,
    data_dir: &Path,
    remote: &RemoteObjectStore,
    plan: &MigrationPlan<'_>,
    deadline: Instant,
) -> Result<pitr_fence::AuthorityState> {
    let tx = client.transaction().await?;
    let locked_auth: Uuid = tx
        .query_one("SELECT authority_id FROM pando_storage_authorities WHERE singleton FOR UPDATE", &[])
        .await?
        .get(0);
    ensure!(locked_auth == plan.previous_id, "pando_storage_authorities changed concurrently during isolate");

    let current_live_rows = tx
        .query(
            "SELECT DISTINCT u.pack_id FROM pando_repository_states s \
             CROSS JOIN LATERAL unnest(s.pack_ids) AS u(pack_id) ORDER BY u.pack_id",
            &[],
        )
        .await?;
    let current_live_ids: BTreeSet<Uuid> = current_live_rows.into_iter().map(|r| r.get(0)).collect();
    let staged_set: BTreeSet<Uuid> = plan.staged_manifest_ids.iter().copied().collect();
    ensure!(current_live_ids == staged_set, "live Pando pack set changed concurrently during isolate");

    tx.execute("DELETE FROM pando_retention_root_manifests", &[]).await?;
    tx.execute("DELETE FROM pando_retention_roots", &[]).await?;
    tx.execute("DELETE FROM pando_manifest_artifacts", &[]).await?;
    tx.execute("DELETE FROM pando_publication_fences", &[]).await?;
    tx.execute("DELETE FROM pando_remote_artifacts", &[]).await?;
    tx.execute(
        "UPDATE pando_storage_authorities \
         SET authority_id = $1, generation = 1, restore_generation = restore_generation + 1, \
             authority_epoch = 1, deployment_id = NULL, volume_id = NULL, \
             db_system_identifier = NULL, db_database_oid = NULL, db_schema_oid = NULL, \
             pg_timeline_id = NULL, backend_identity = NULL, proof_nonce = NULL, \
             remote_delete_fenced = false, remote_delete_fence_reason = NULL, attested_at = NULL, \
             created_at = clock_timestamp(), rotated_at = clock_timestamp() \
         WHERE singleton",
        &[&plan.new_authority_id],
    )
    .await?;

    for (key, art) in plan.artifacts {
        tx.execute(
            "INSERT INTO pando_remote_artifacts \
             (authority_id, tenant_id, namespace, sha256, size, object_generation, remote_path, state) \
             VALUES ($1, $2, $3, $4, $5, 1, $6, 'active')",
            &[
                &plan.new_authority_id,
                &key.tenant_id,
                &key.namespace,
                &key.sha256,
                &(art.size as i64),
                &art.dst_key.path(),
            ],
        )
        .await?;
    }
    for link in plan.links {
        tx.execute(
            "INSERT INTO pando_manifest_artifacts \
             (manifest_id, repository_id, authority_id, tenant_id, namespace, sha256, artifact_role) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &link.manifest_id,
                &link.repository_id,
                &plan.new_authority_id,
                &link.tenant_id,
                &link.namespace,
                &link.sha256,
                &link.role,
            ],
        )
        .await?;
    }
    tx.commit().await?;

    pitr_fence::clear_claim_file_best_effort(data_dir, plan.previous_id);
    Box::pin(pitr_fence::verify_or_attest_locked(&***client, data_dir, remote, deadline, "isolate_authority")).await
}

/// Mint a new authority for a cloned/restored database, preserving all live
/// serving manifests by verifying and copying their scoped remote objects into
/// the new authority namespace without deleting anything from the source
/// authority.
pub async fn isolate_cloned_authority(
    pool: &Pool,
    data_dir: &Path,
    remote: &RemoteObjectStore,
    deadline: Instant,
) -> Result<pitr_fence::AuthorityState> {
    let previous = {
        let client = pool.get().await?;
        retention::authority(&**client).await?
    };
    let new_authority_id = Uuid::new_v4();
    let (staged_manifest_ids, artifacts, links) = {
        let client = pool.get().await?;
        Box::pin(stage_live_migration(&**client, remote, previous.id, new_authority_id, deadline)).await?
    };

    let _work_guard = if artifacts.is_empty() {
        None
    } else {
        let work_dir = data_dir.join(format!("pando-isolate-{}", Uuid::new_v4()));
        let guard = IsolateWorkDir(work_dir.clone());
        Box::pin(copy_staged_artifacts(remote, &work_dir, &artifacts, deadline)).await?;
        Some(guard)
    };

    let plan = MigrationPlan {
        previous_id: previous.id,
        new_authority_id,
        staged_manifest_ids: &staged_manifest_ids,
        artifacts: &artifacts,
        links: &links,
    };
    let mut lock = AuthorityLockGuard::acquire(pool, deadline).await?;
    let res = Box::pin(commit_isolated_authority_locked(lock.client_mut(), data_dir, remote, &plan, deadline)).await;
    lock.release().await;
    res
}
