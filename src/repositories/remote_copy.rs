//! Verified remote object copy and tenant manifest rekeying for ownership transfer (#85).
use super::transfer_model::{CopiedRemoteObject, rekey_workspace_manifest};
use crate::{
    Error,
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
    workspaces::remote::RemoteManifest,
};
use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};
use tokio::{fs, time::Instant};
use uuid::Uuid;

struct TempStageFile(PathBuf);

impl Drop for TempStageFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Copy one content-addressed object from `src` to `dst` via verified stream
/// read-back + upload, skipping cleanly if `dst` already exists with matching
/// length. Returns `Ok(None)` if `src` is absent in the remote store.
pub async fn copy_object_if_present(
    store: &RemoteObjectStore,
    stage_dir: &Path,
    kind: &str,
    src: &ObjectKey,
    dst: &ObjectKey,
    expected_size: Option<u64>,
    deadline: Instant,
) -> Result<Option<CopiedRemoteObject>> {
    let Some(src_meta) = store.head(src, deadline).await? else {
        return Ok(None);
    };
    let size = src_meta.size;
    if let Some(expected) = expected_size {
        ensure!(size == expected, "remote source object {} size {} != expected {}", src.path(), size, expected);
    }
    if let Some(dst_meta) = store.head(dst, deadline).await? {
        ensure!(
            dst_meta.size == size,
            "destination object {} already exists with size {} != {}",
            dst.path(),
            dst_meta.size,
            size
        );
        return Ok(Some(CopiedRemoteObject {
            kind: kind.to_owned(),
            from_key: src.path(),
            to_key: dst.path(),
            size,
            sha256: Some(dst.sha256.clone()),
        }));
    }
    fs::create_dir_all(stage_dir).await?;
    let stage = TempStageFile(stage_dir.join(format!("transfer-{}.bin", Uuid::new_v4())));
    store
        .get_to_file(src, &stage.0, size, deadline)
        .await
        .with_context(|| format!("download {} for tenant copy", src.path()))?;
    let uploaded = store
        .put_file(dst, &stage.0, size, deadline)
        .await
        .with_context(|| format!("upload {} during tenant copy", dst.path()))?;
    ensure!(uploaded.size == size, "copied object {} size mismatch", dst.path());
    Ok(Some(CopiedRemoteObject {
        kind: kind.to_owned(),
        from_key: src.path(),
        to_key: dst.path(),
        size,
        sha256: Some(uploaded.sha256),
    }))
}

/// Fetch a committed workspace `RemoteManifest` under `from_tenant`, copy all
/// referenced file objects into `to_tenant`'s keyspace, write a re-tenanted
/// manifest JSON object, and return `(new_manifest_digest, new_manifest_size, records)`.
pub async fn copy_and_rekey_workspace_checkpoint(
    store: &RemoteObjectStore,
    stage_dir: &Path,
    from_tenant: Uuid,
    to_tenant: Uuid,
    manifest_digest: &str,
    manifest_size: u64,
    deadline: Instant,
) -> Result<(String, u64, Vec<CopiedRemoteObject>)> {
    let src_manifest_key = ObjectKey::new(from_tenant, "workspace", manifest_digest)?;
    fs::create_dir_all(stage_dir).await?;
    let stage = TempStageFile(stage_dir.join(format!("manifest-{}.json", Uuid::new_v4())));
    store
        .get_to_file(&src_manifest_key, &stage.0, manifest_size, deadline)
        .await
        .with_context(|| format!("download workspace manifest {}", src_manifest_key.path()))?;
    let raw = fs::read(&stage.0).await?;
    let manifest: RemoteManifest = serde_json::from_slice(&raw).context("decode workspace remote manifest")?;
    ensure!(manifest.tenant_id == from_tenant, "workspace manifest tenant_id mismatch");

    let mut records = Vec::new();
    for entry in &manifest.entries {
        if entry.kind != "file" || entry.sha256.is_empty() {
            continue;
        }
        let src_blob = ObjectKey::new(from_tenant, "workspace", &entry.sha256)?;
        let dst_blob = ObjectKey::new(to_tenant, "workspace", &entry.sha256)?;
        let copied = copy_object_if_present(
            store,
            stage_dir,
            "workspace_blob",
            &src_blob,
            &dst_blob,
            Some(entry.size),
            deadline,
        )
        .await?
        .with_context(|| format!("missing workspace blob {}", src_blob.path()))?;
        records.push(copied);
    }

    let (new_bytes, new_digest, new_manifest_key) = rekey_workspace_manifest(manifest, to_tenant).map_err(|e| {
        anyhow::anyhow!(
            "failed to rekey workspace manifest: {}",
            match e {
                Error(_, msg) => msg,
            }
        )
    })?;
    let new_size = new_bytes.len() as u64;
    let out_stage = TempStageFile(stage_dir.join(format!("rekey-manifest-{}.json", Uuid::new_v4())));
    fs::write(&out_stage.0, &new_bytes).await?;
    store.put_file(&new_manifest_key, &out_stage.0, new_size, deadline).await?;
    records.push(CopiedRemoteObject {
        kind: "workspace_manifest".into(),
        from_key: src_manifest_key.path(),
        to_key: new_manifest_key.path(),
        size: new_size,
        sha256: Some(new_digest.clone()),
    });
    Ok((new_digest, new_size, records))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspaces::remote::RemoteEntry;
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn copy_object_and_rekey_workspace_manifest_preserve_source_and_verify_dest() {
        let dir = std::env::temp_dir().join(format!("rootyard-copy-test-{}", Uuid::new_v4()));
        let store = RemoteObjectStore::Local(dir.join("remote"));
        let stage = dir.join("stage");
        fs::create_dir_all(&stage).await.unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(30);

        let from = Uuid::new_v4();
        let to = Uuid::new_v4();
        let blob_bytes = b"hello workspace blob".to_vec();
        let blob_sha = hex::encode(Sha256::digest(&blob_bytes));
        let blob_src_file = stage.join("seed.bin");
        fs::write(&blob_src_file, &blob_bytes).await.unwrap();
        let src_blob_key = ObjectKey::new(from, "workspace", &blob_sha).unwrap();
        store.put_file(&src_blob_key, &blob_src_file, blob_bytes.len() as u64, deadline).await.unwrap();

        let manifest = RemoteManifest {
            schema: 1,
            checkpoint_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            tenant_id: from,
            captured_revision: 3,
            entries: vec![RemoteEntry {
                path_base64: "ZmlsZS50eHQ=".into(),
                kind: "file".into(),
                mode: 0o100644,
                size: blob_bytes.len() as u64,
                sha256: blob_sha.clone(),
                target_base64: None,
            }],
        };
        let m_bytes = serde_json::to_vec(&manifest).unwrap();
        let m_sha = hex::encode(Sha256::digest(&m_bytes));
        let m_file = stage.join("manifest.json");
        fs::write(&m_file, &m_bytes).await.unwrap();
        let src_manifest_key = ObjectKey::new(from, "workspace", &m_sha).unwrap();
        store.put_file(&src_manifest_key, &m_file, m_bytes.len() as u64, deadline).await.unwrap();

        let (new_digest, new_size, copied) =
            copy_and_rekey_workspace_checkpoint(&store, &stage, from, to, &m_sha, m_bytes.len() as u64, deadline)
                .await
                .unwrap();
        assert_eq!(copied.len(), 2);
        assert_ne!(new_digest, m_sha);
        assert!(store.head(&src_blob_key, deadline).await.unwrap().is_some());
        assert!(store.head(&ObjectKey::new(to, "workspace", &blob_sha).unwrap(), deadline).await.unwrap().is_some());
        assert!(
            store
                .head(&ObjectKey::new(to, "workspace", &new_digest).unwrap(), deadline)
                .await
                .unwrap()
                .is_some_and(|m| m.size == new_size)
        );
        // Second call hits idempotent skip safely.
        let (new_digest_2, _, _) =
            copy_and_rekey_workspace_checkpoint(&store, &stage, from, to, &m_sha, m_bytes.len() as u64, deadline)
                .await
                .unwrap();
        assert_eq!(new_digest_2, new_digest);
        let _ = fs::remove_dir_all(&dir).await;
    }
}
