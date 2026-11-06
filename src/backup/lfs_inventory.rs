//! Self-contained LFS closure: hydrate verified remote bytes before snapshot copy.
use super::*;
use crate::storage::remote_objects::{ObjectKey, RemoteObjectStore};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Object {
    tenant_id: Uuid,
    repository_id: Uuid,
    oid: String,
    size: u64,
}

pub(super) async fn metadata(client: &(impl GenericClient + Sync)) -> Result<Vec<Object>> {
    let mut objects = Vec::new();
    let mut cursor = (Uuid::nil(), String::new());
    loop {
        let rows = client.query(
            "SELECT tenant_id,repository_id,oid,size FROM public.lfs_objects \
             WHERE state='ready' AND (repository_id,oid)>($1,$2) \
             ORDER BY repository_id,oid LIMIT 1000", &[&cursor.0,&cursor.1],
        ).await?;
        if rows.is_empty() { break; }
        for row in rows {
            let size: i64 = row.get(3);
            ensure!(size >= 0, "invalid LFS object size");
            let object = Object { tenant_id:row.get(0), repository_id:row.get(1),
                oid:row.get(2), size:size as u64 };
            cursor = (object.repository_id, object.oid.clone());
            objects.push(object);
            ensure!(objects.len() <= MAX_ENTRIES, "LFS inventory exceeds backup limit");
        }
    }
    Ok(objects)
}

pub(super) async fn hydrate(config: &Config, objects: &[Object]) -> Result<()> {
    let remote = if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_some() {
        Some(RemoteObjectStore::from_env(config.data_dir.join("remote-objects"))?)
    } else { None };
    for object in objects {
        if crate::lfs::storage::verify_object_integrity(&config.data_dir,
            object.repository_id, &object.oid, object.size)? { continue; }
        let store = remote.as_ref().context("ready LFS object missing from backup source")?;
        let dir = crate::lfs::storage::ensure_repo_lfs_dir(&config.data_dir, object.repository_id)?;
        let target = dir.join(&object.oid);
        let key = ObjectKey::new(object.tenant_id,"lfs",&object.oid)?;
        store.get_to_file(&key,&target,object.size,
            tokio::time::Instant::now()+config.git_timeout).await?;
        fs::set_permissions(&target,fs::Permissions::from_mode(0o600))?;
        ensure!(crate::lfs::storage::verify_object_integrity(&config.data_dir,
            object.repository_id,&object.oid,object.size)?, "downloaded LFS object failed backup verification");
    }
    Ok(())
}

pub(super) fn verify(volume: &Path, objects: &[Object]) -> Result<()> {
    ensure!(objects.len() <= MAX_ENTRIES, "LFS inventory exceeds backup limit");
    let mut previous = None;
    for object in objects {
        let key = (object.repository_id,object.oid.as_str());
        ensure!(previous.is_none_or(|old| old < key), "LFS inventory must be unique and sorted");
        previous = Some(key);
        ensure!(crate::lfs::storage::verify_object_integrity(volume,
            object.repository_id,&object.oid,object.size)?, "backup LFS object missing or corrupt");
    }
    Ok(())
}
