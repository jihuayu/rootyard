//! Legacy `RemoteObjectStore` publish and delete path.
//!
//! Publish hashes the local source, uploads to the frozen content key, then
//! verifies size and a full provider read-back before returning. Delete is
//! exact-key only and idempotent; there is no listing or prefix sweep here.
use anyhow::{Context, Result, ensure};
use std::path::Path;
use tokio::{fs, time::Instant};
use uuid::Uuid;

use crate::storage::{
    remote_local::{hash_file, local_delete, local_put},
    remote_objects::{ObjectKey, RemoteObjectStore, StoredObject},
    remote_provider_errors::object_error,
};

impl RemoteObjectStore {
    pub async fn put_file(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected_size: u64,
        deadline: Instant,
    ) -> Result<StoredObject> {
        let (digest, size) = hash_file(source, deadline).await?;
        ensure!(
            size == expected_size && digest == key.sha256,
            "object source digest or size mismatch"
        );
        let rel_path = key.path();
        match self {
            Self::Local(root) => local_put(root, &rel_path, source, deadline).await?,
            Self::OpenDal(store) => {
                store.put(&rel_path, source, &key.sha256, expected_size, deadline).await.map_err(object_error)?
            }
        }
        let head = self.head(key, deadline).await?.context("uploaded object is missing")?;
        ensure!(head.size == expected_size, "uploaded object is truncated");
        let verification = std::env::temp_dir().join(format!("rootyard-verify-{}", Uuid::new_v4()));
        let verified = self.get_to_file(key, &verification, expected_size, deadline).await;
        let _ = fs::remove_file(&verification).await;
        verified?;
        Ok(StoredObject { sha256: digest, size })
    }

    pub async fn delete(&self, key: &ObjectKey, deadline: Instant) -> Result<()> {
        let rel_path = key.path();
        match self {
            Self::Local(root) => local_delete(root, &rel_path).await,
            Self::OpenDal(store) => Ok(store.delete(&rel_path, deadline).await.map_err(object_error)?),
        }
    }
}
