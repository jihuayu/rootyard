//! Fail-closed external bucket authority proofs for Pando storage (#77).
//!
//! Each live deployment binds its PostgreSQL `pando_storage_authorities` row to
//! immutable write-once epoch proof objects in the shared object store under
//! `pando-authorities/<authority_id>/epochs/<epoch:020>.json`. Conditional
//! create (`If-None-Match: *` / exclusive local link) prevents two metadata-only
//! clones or PITR rollbacks from sharing or mutating the same epoch lineage.
use crate::blob_store::BlobError;
use crate::storage::{
    remote_errors::RemoteOp,
    remote_objects::RemoteObjectStore,
    remote_provider::{LegacyS3Store, READ_CHUNK, UPLOAD_CHUNK, tokio_deadline},
    remote_provider_errors::{deadline_error, object_error, observe},
};
use anyhow::{Context, Result, bail, ensure};
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
use tokio::time::Instant;
use url::{Host, Url};
use uuid::Uuid;

const MAX_AUTHORITY_PROOF_BYTES: usize = 16 * 1024;
const AUTHORITY_PREFIX: &str = "pando-authorities";
pub const PROOF_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEpochProof {
    pub version: u32,
    pub authority_id: Uuid,
    pub epoch: i64,
    pub restore_generation: i64,
    pub generation: i64,
    pub deployment_id: Uuid,
    pub volume_id: Uuid,
    pub db_system_identifier: String,
    pub db_database_oid: i64,
    pub db_schema_oid: i64,
    pub pg_timeline_id: i32,
    pub backend_identity: String,
    pub proof_nonce: Uuid,
    pub operation: String,
}

impl AuthorityEpochProof {
    pub fn validate(&self, expected_authority: Uuid, expected_epoch: i64) -> Result<()> {
        ensure!(self.version == PROOF_VERSION, "unsupported external authority proof version");
        ensure!(self.authority_id == expected_authority, "external authority proof authority_id mismatch");
        ensure!(self.epoch == expected_epoch && self.epoch >= 1, "external authority proof epoch mismatch");
        ensure!(self.restore_generation >= 0, "external authority proof restore_generation is negative");
        ensure!(self.generation >= 1, "external authority proof generation must be positive");
        ensure!(self.db_database_oid > 0 && self.db_schema_oid > 0, "external authority proof DB OID is invalid");
        ensure!(self.pg_timeline_id > 0, "external authority proof timeline_id is invalid");
        ensure!(
            !self.db_system_identifier.is_empty()
                && self.db_system_identifier.len() <= 64
                && self.db_system_identifier.bytes().all(|b| b.is_ascii_digit()),
            "external authority proof db_system_identifier is invalid"
        );
        ensure!(
            self.backend_identity.len() == 64
                && self.backend_identity.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "external authority proof backend_identity is invalid"
        );
        ensure!(
            matches!(
                self.operation.as_str(),
                "attest" | "delete_epoch" | "pin_recovery_root" | "isolate_authority" | "manual_check"
            ),
            "external authority proof operation is unsupported"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityCreateOutcome {
    Created,
    AlreadyExists(Option<AuthorityEpochProof>),
}

/// Compute a canonical 64-hex SHA-256 identity for an OpenDAL S3 endpoint,
/// region and bucket while omitting all credentials and query parameters.
pub(crate) fn s3_backend_identity(endpoint: &Url, region: &str, bucket: &str) -> Result<String> {
    let scheme = endpoint.scheme().to_ascii_lowercase();
    ensure!(matches!(scheme.as_str(), "http" | "https"), "unsupported object store scheme");
    let host = match endpoint.host().context("object store endpoint missing host")? {
        Host::Domain(domain) => domain.to_ascii_lowercase(),
        Host::Ipv4(addr) => addr.to_string(),
        Host::Ipv6(addr) => format!("[{addr}]"),
    };
    let port_suffix = match (scheme.as_str(), endpoint.port_or_known_default()) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
        (_, Some(port)) => format!(":{port}"),
    };
    let trimmed_path = endpoint.path().trim_end_matches('/');
    let region = region.trim();
    let bucket = bucket.trim();
    ensure!(!region.is_empty() && !bucket.is_empty(), "object store region and bucket must be non-empty");
    let canonical = format!("opendal-s3\0{scheme}://{host}{port_suffix}{trimmed_path}\0{region}\0{bucket}");
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

pub fn local_backend_identity(root: &Path) -> Result<String> {
    let normalized = normalize_path(root)?;
    let canonical = format!("local-dir\0{}", normalized.to_string_lossy());
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

fn normalize_path(path: &Path) -> Result<PathBuf> {
    if let Ok(resolved) = path.canonicalize() {
        return Ok(resolved);
    }
    let abs = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    let mut existing = abs.as_path();
    let mut tail = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name() else {
            break;
        };
        tail.push(name.to_os_string());
        let Some(parent) = existing.parent() else {
            break;
        };
        existing = parent;
    }
    let mut resolved = existing.canonicalize().unwrap_or_else(|_| clean_components(existing));
    for segment in tail.into_iter().rev() {
        resolved.push(segment);
    }
    Ok(resolved)
}

fn clean_components(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn authority_proof_key(authority_id: Uuid, epoch: i64) -> Result<String> {
    ensure!(epoch >= 1, "authority epoch must be >= 1");
    Ok(format!("{AUTHORITY_PREFIX}/{authority_id}/epochs/{epoch:020}.json"))
}

impl RemoteObjectStore {
    pub fn backend_identity(&self) -> Result<String> {
        match self {
            Self::Local(root) => local_backend_identity(root),
            Self::OpenDal(store) => Ok(store.backend_identity().to_owned()),
        }
    }

    pub async fn authority_proof_exists(&self, authority_id: Uuid, epoch: i64, deadline: Instant) -> Result<bool> {
        let key = authority_proof_key(authority_id, epoch)?;
        match self {
            Self::Local(root) => local_proof_exists(root, &key),
            Self::OpenDal(store) => match store.head(&key, deadline).await {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(error) => Err(object_error(error)),
            },
        }
    }

    pub async fn read_authority_proof(
        &self,
        authority_id: Uuid,
        epoch: i64,
        deadline: Instant,
    ) -> Result<Option<AuthorityEpochProof>> {
        let key = authority_proof_key(authority_id, epoch)?;
        let raw = match self {
            Self::Local(root) => local_read_proof(root, &key)?,
            Self::OpenDal(store) => s3_read_proof_if_exists(store, &key, deadline).await?,
        };
        let Some(bytes) = raw else {
            return Ok(None);
        };
        let proof: AuthorityEpochProof =
            serde_json::from_slice(&bytes).context("parse external authority proof JSON")?;
        proof.validate(authority_id, epoch)?;
        Ok(Some(proof))
    }

    pub async fn put_authority_proof_if_absent(
        &self,
        proof: &AuthorityEpochProof,
        deadline: Instant,
    ) -> Result<AuthorityCreateOutcome> {
        proof.validate(proof.authority_id, proof.epoch)?;
        let key = authority_proof_key(proof.authority_id, proof.epoch)?;
        let payload = serde_json::to_vec(proof)?;
        ensure!(payload.len() <= MAX_AUTHORITY_PROOF_BYTES, "authority proof exceeds size bound");
        let created = match self {
            Self::Local(root) => local_put_proof_if_absent(root, &key, &payload)?,
            Self::OpenDal(store) => s3_put_proof_if_absent(store, &key, payload, deadline).await?,
        };
        if created {
            Ok(AuthorityCreateOutcome::Created)
        } else {
            let existing = self.read_authority_proof(proof.authority_id, proof.epoch, deadline).await?;
            Ok(AuthorityCreateOutcome::AlreadyExists(existing))
        }
    }
}

fn ensure_private_local_path(root: &Path, key: &str) -> Result<PathBuf> {
    let mut cursor = root.to_path_buf();
    for segment in key.split('/') {
        ensure!(!segment.is_empty() && segment != "." && segment != "..", "invalid local authority key");
        cursor.push(segment);
    }
    Ok(cursor)
}

fn local_proof_exists(root: &Path, key: &str) -> Result<bool> {
    let path = ensure_private_local_path(root, key)?;
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            ensure!(meta.is_file() && !meta.file_type().is_symlink(), "authority proof path is not a regular file");
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn local_read_proof(root: &Path, key: &str) -> Result<Option<Vec<u8>>> {
    let path = ensure_private_local_path(root, key)?;
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
        "local authority proof is not an unaliased regular file"
    );
    ensure!(meta.len() <= MAX_AUTHORITY_PROOF_BYTES as u64, "local authority proof exceeds size bound");
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path)?;
    let mut buf = Vec::with_capacity(meta.len() as usize);
    (&mut file).take(MAX_AUTHORITY_PROOF_BYTES as u64 + 1).read_to_end(&mut buf)?;
    ensure!(buf.len() <= MAX_AUTHORITY_PROOF_BYTES, "local authority proof exceeds size bound");
    Ok(Some(buf))
}

fn local_put_proof_if_absent(root: &Path, key: &str, payload: &[u8]) -> Result<bool> {
    let target = ensure_private_local_path(root, key)?;
    let parent = target.parent().context("authority proof missing parent dir")?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    let tmp = parent.join(format!(".tmp-proof-{}.json", Uuid::new_v4()));
    let mut file =
        OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
    let write_result = file.write_all(payload).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.into());
    }
    let linked = std::fs::hard_link(&tmp, &target);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => {
            File::open(parent)?.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn s3_read_proof_if_exists(store: &LegacyS3Store, key: &str, deadline: Instant) -> Result<Option<Vec<u8>>> {
    let reader =
        match tokio::time::timeout_at(tokio_deadline(deadline), observe(RemoteOp::Get, store.operator().reader(key)))
            .await
        {
            Ok(Ok(reader)) => reader,
            Ok(Err(failure)) if failure.is_not_found() => return Ok(None),
            Ok(Err(failure)) => return Err(object_error(BlobError::Remote(failure.into_error()))),
            Err(_) => return Err(object_error(deadline_error(RemoteOp::Get))),
        };
    let mut stream =
        match tokio::time::timeout_at(tokio_deadline(deadline), observe(RemoteOp::Get, reader.into_bytes_stream(..)))
            .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(failure)) if failure.is_not_found() => return Ok(None),
            Ok(Err(failure)) => return Err(object_error(BlobError::Remote(failure.into_error()))),
            Err(_) => return Err(object_error(deadline_error(RemoteOp::Get))),
        };
    let mut out = Vec::new();
    loop {
        let next = match tokio::time::timeout_at(tokio_deadline(deadline), stream.try_next()).await {
            Ok(Ok(item)) => item,
            Ok(Err(error)) => return Err(object_error(error)),
            Err(_) => return Err(object_error(deadline_error(RemoteOp::Get))),
        };
        let Some(chunk) = next else {
            break;
        };
        ensure!(
            out.len().saturating_add(chunk.len()) <= MAX_AUTHORITY_PROOF_BYTES,
            "external authority proof exceeds limit"
        );
        out.extend_from_slice(&chunk);
    }
    Ok(Some(out))
}

async fn s3_put_proof_if_absent(store: &LegacyS3Store, key: &str, payload: Vec<u8>, deadline: Instant) -> Result<bool> {
    let writer = store.operator().writer_with(key).if_not_exists(true);
    let writer = match tokio::time::timeout_at(tokio_deadline(deadline), observe(RemoteOp::Put, writer)).await {
        Ok(Ok(writer)) => writer,
        Ok(Err(failure)) if failure.is_conflict() => return Ok(false),
        Ok(Err(failure)) => return Err(object_error(BlobError::Remote(failure.into_error()))),
        Err(_) => return Err(object_error(deadline_error(RemoteOp::Put))),
    };
    let mut guard = store.upload_guard(writer);
    for chunk in payload.chunks(READ_CHUNK) {
        let bytes = bytes::Bytes::copy_from_slice(chunk);
        match tokio::time::timeout_at(tokio_deadline(deadline), observe(RemoteOp::Put, guard.writer().write(bytes)))
            .await
        {
            Ok(Ok(())) => guard.note_written(chunk.len()),
            Ok(Err(failure)) if failure.is_conflict() => {
                guard.abort_now().await;
                return Ok(false);
            }
            Ok(Err(failure)) => {
                guard.abort_now().await;
                return Err(object_error(BlobError::Remote(failure.into_error())));
            }
            Err(_) => {
                guard.abort_now().await;
                return Err(object_error(deadline_error(RemoteOp::Put)));
            }
        }
    }
    match guard.close(tokio_deadline(deadline), UPLOAD_CHUNK as u64).await {
        Ok(()) => {
            guard.disarm();
            Ok(true)
        }
        Err(BlobError::AlreadyExists) => Ok(false),
        Err(error) => Err(object_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_proof(authority_id: Uuid, epoch: i64, deployment_id: Uuid) -> AuthorityEpochProof {
        AuthorityEpochProof {
            version: PROOF_VERSION,
            authority_id,
            epoch,
            restore_generation: 0,
            generation: 1,
            deployment_id,
            volume_id: Uuid::new_v4(),
            db_system_identifier: "7708238811453628456".into(),
            db_database_oid: 5,
            db_schema_oid: 2200,
            pg_timeline_id: 1,
            backend_identity: "a".repeat(64),
            proof_nonce: Uuid::new_v4(),
            operation: "attest".into(),
        }
    }

    #[test]
    fn s3_backend_identity_redacts_secrets_and_normalizes_endpoint() {
        let u1 = Url::parse("HTTP://S3.Example.COM:80/prefix/?foo=bar").unwrap();
        let u2 = Url::parse("http://user:pass@s3.example.com/prefix").unwrap();
        let u3 = Url::parse("https://s3.example.com/prefix").unwrap();
        assert_eq!(
            s3_backend_identity(&u1, "garage", "rootyard").unwrap(),
            s3_backend_identity(&u2, "garage", "rootyard").unwrap()
        );
        assert_ne!(
            s3_backend_identity(&u1, "garage", "rootyard").unwrap(),
            s3_backend_identity(&u3, "garage", "rootyard").unwrap()
        );
        assert_ne!(
            s3_backend_identity(&u1, "garage", "other-bucket").unwrap(),
            s3_backend_identity(&u1, "garage", "rootyard").unwrap()
        );
    }

    #[test]
    fn authority_proof_rejects_unknown_json_fields() {
        let proof = sample_proof(Uuid::new_v4(), 1, Uuid::new_v4());
        let mut value = serde_json::to_value(&proof).unwrap();
        value.as_object_mut().unwrap().insert("unexpected".into(), serde_json::json!(true));
        let err = serde_json::from_value::<AuthorityEpochProof>(value).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[tokio::test]
    async fn local_store_authority_proof_cas_is_write_once() {
        let dir = std::env::temp_dir().join(format!("rootyard-auth-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = RemoteObjectStore::Local(dir.clone());
        let authority_id = Uuid::new_v4();
        let dep1 = Uuid::new_v4();
        let dep2 = Uuid::new_v4();
        let mut p1 = sample_proof(authority_id, 1, dep1);
        p1.backend_identity = store.backend_identity().unwrap();
        let mut p2 = sample_proof(authority_id, 1, dep2);
        p2.backend_identity = p1.backend_identity.clone();
        let deadline = Instant::now() + Duration::from_secs(10);

        assert!(!store.authority_proof_exists(authority_id, 1, deadline).await.unwrap());
        assert_eq!(store.put_authority_proof_if_absent(&p1, deadline).await.unwrap(), AuthorityCreateOutcome::Created);
        assert!(store.authority_proof_exists(authority_id, 1, deadline).await.unwrap());
        assert_eq!(
            store.put_authority_proof_if_absent(&p2, deadline).await.unwrap(),
            AuthorityCreateOutcome::AlreadyExists(Some(p1.clone()))
        );
        assert_eq!(store.read_authority_proof(authority_id, 1, deadline).await.unwrap(), Some(p1));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
