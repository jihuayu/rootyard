//! Streaming, content-addressed object storage shared by pack, LFS and workspace publishers.
//!
//! **Legacy compatibility layer.** This module keeps the pre-OpenDAL public API,
//! legacy content-addressed paths and legacy semantics alive while delegating
//! transport/signing/multipart/retry to Apache OpenDAL. New standalone
//! deployments must use [`crate::blob_store`] instead: its versioned locators
//! bind tenant, authority, generation and a unique publication attempt, its
//! production profile refuses missing config/`fs`/`memory`, and its receipt is
//! a SHA-256 read-back proof.
//!
//! `RemoteObjectStore::Local` is an explicitly legacy local fixture/development
//! backend. It is selected only when `ROOTYARD_OBJECT_STORE_ENDPOINT` is absent
//! and callers that require a remote authority (Workspace, production Pando)
//! already reject it. Local LFS/checkpoint ACK durability is tracked separately
//! (#109) and is not solved by this module.
//!
//! **Typed failure surface (preserved).** `RemoteOp` and `RemoteStoreError`
//! stay exactly where the ref-store integration put them:
//! `remote_errors` owns the bounded operation enumeration, the numeric HTTP
//! status and the privacy-safe `Display`/`Debug`, and this module re-exports
//! both so `lfs::hydration` and the worker diagnostics in `observability` keep
//! downcasting to the same type across the OpenDAL adapter. The adapter must
//! therefore translate provider failures into `RemoteStoreError`, never into a
//! flattened string.
//!
//! **Module wiring.** The inherent read path (`head`, `get_to_file`,
//! `get_range`) lives in [`super::remote_io`], publish/delete in
//! [`super::remote_publish`]; both are `impl RemoteObjectStore` blocks split out
//! only for reviewability. The pre-OpenDAL hand-written S3 implementation that
//! also defined those methods is historical and no longer compiled:
//! `src/storage/historical_s3.rs`.
use anyhow::{Context, Result, ensure};
use reqwest::Url;
use std::path::PathBuf;
use uuid::Uuid;

#[cfg(test)]
use futures_util::StreamExt;
#[cfg(test)]
use reqwest::{Client, Method};
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use tokio::time::Instant;

use crate::storage::remote_provider::LegacyS3Store;

pub use super::remote_errors::{RemoteOp, RemoteStoreError};

/// One remote body-boundary read against a `reqwest` response stream.
///
/// Retained from the pre-OpenDAL transport as the legacy fault-coverage
/// oracle: it pins the equivalence the old provider guaranteed, namely that
/// deadline exhaustion becomes `RemoteStoreError::timeout(op)` and a
/// mid-body stream failure becomes `RemoteStoreError::transport(op, error)`
/// with the source chain intact, while local file readers never pass
/// through it. The live adapter reaches the provider through OpenDAL, so
/// this helper is compiled for the regression tests only.
#[cfg(test)]
async fn remote_chunk<S>(stream: &mut S, op: RemoteOp, deadline: Instant) -> Result<Option<bytes::Bytes>>
where
    S: futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin,
{
    match tokio::time::timeout_at(deadline, stream.next()).await {
        Ok(Some(Ok(chunk))) => Ok(Some(chunk)),
        Ok(Some(Err(error))) => Err(RemoteStoreError::transport(op, Box::new(error)).into()),
        Ok(None) => Ok(None),
        Err(_) => Err(RemoteStoreError::timeout(op).into()),
    }
}

/// The small control-response equivalent of [`remote_chunk`]. It is kept
/// beside it because the legacy multipart control bodies were read under
/// the same deadline with the same typed mapping; no production path owns a
/// `reqwest::Response` any more, so it exists for the regression tests.
#[cfg(test)]
#[allow(dead_code)]
async fn remote_text(response: reqwest::Response, op: RemoteOp, deadline: Instant) -> Result<String> {
    match tokio::time::timeout_at(deadline, response.text()).await {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(error)) => Err(RemoteStoreError::transport(op, Box::new(error)).into()),
        Err(_) => Err(RemoteStoreError::timeout(op).into()),
    }
}

#[derive(Clone, Debug)]
pub struct ObjectKey {
    pub tenant_id: Uuid,
    // A Pando storage authority scopes deletable objects to one database
    // installation. Legacy/LFS/workspace keys keep `authority = None` and are
    // never eligible for Pando remote deletion.
    pub authority: Option<(Uuid, i64)>,
    pub namespace: String,
    pub sha256: String,
}
impl ObjectKey {
    fn validate(tenant_id: Uuid, namespace: &str, sha256: &str) -> Result<()> {
        ensure!(!tenant_id.is_nil(), "object key needs a tenant");
        ensure!(
            !namespace.is_empty()
                && namespace.len() <= 48
                && namespace.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid object namespace"
        );
        ensure!(
            sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid object digest"
        );
        Ok(())
    }

    /// Legacy tenant-only content-addressed key. Never registered as a
    /// deletable Pando artifact. Its physical path is frozen for old readers.
    pub fn new(tenant_id: Uuid, namespace: &str, sha256: &str) -> Result<Self> {
        Self::validate(tenant_id, namespace, sha256)?;
        Ok(Self { tenant_id, authority: None, namespace: namespace.into(), sha256: sha256.into() })
    }

    /// Authority-scoped key for newly acknowledged Pando pack artifacts.
    pub fn scoped(tenant_id: Uuid, authority_id: Uuid, generation: i64, namespace: &str, sha256: &str) -> Result<Self> {
        Self::validate(tenant_id, namespace, sha256)?;
        ensure!(!authority_id.is_nil() && generation > 0, "invalid storage authority identity");
        Ok(Self {
            tenant_id,
            authority: Some((authority_id, generation)),
            namespace: namespace.into(),
            sha256: sha256.into(),
        })
    }

    /// Authority-free backup volume layout. Backup archives must stay readable
    /// by older binaries and by a restore that mints a different authority.
    pub fn volume_path(&self) -> String {
        format!("tenants/{}/{}/{}", self.tenant_id, self.namespace, self.sha256)
    }

    pub fn path(&self) -> String {
        match self.authority {
            Some((authority_id, generation)) => format!(
                "tenants/{}/authorities/{authority_id}/g{generation}/{}/{}",
                self.tenant_id, self.namespace, self.sha256
            ),
            None => self.volume_path(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    pub sha256: String,
    pub size: u64,
}

/// Legacy store selector. `Local` is explicitly node-local legacy behavior;
/// `OpenDal` is a remote S3-compatible provider under the frozen legacy paths.
pub enum RemoteObjectStore {
    Local(PathBuf),
    OpenDal(LegacyS3Store),
}

impl RemoteObjectStore {
    /// Legacy selector. With no `ROOTYARD_OBJECT_STORE_ENDPOINT` it returns the
    /// explicitly legacy local backend; that fallback is *not* available from
    /// `crate::blob_store::BlobProfile`, which rejects missing configuration.
    pub fn from_env(local_root: PathBuf) -> Result<Self> {
        let Ok(endpoint) = std::env::var("ROOTYARD_OBJECT_STORE_ENDPOINT") else {
            return Ok(Self::Local(local_root));
        };
        let endpoint = Url::parse(&endpoint)?;
        let loopback = matches!(endpoint.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
        ensure!(endpoint.scheme() == "https" || endpoint.scheme() == "http" && loopback, "object store requires TLS");
        ensure!(
            endpoint.path() == "/"
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.username().is_empty()
                && endpoint.password().is_none(),
            "object store endpoint must be an origin URL"
        );
        let bucket = std::env::var("ROOTYARD_OBJECT_STORE_BUCKET").context("object store bucket missing")?;
        ensure!(valid_bucket(&bucket), "invalid object store bucket");
        let region = std::env::var("ROOTYARD_OBJECT_STORE_REGION").context("object store region missing")?;
        ensure!(
            !region.is_empty() && region.len() <= 64 && region.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid object store region"
        );
        let access_key =
            std::env::var("ROOTYARD_OBJECT_STORE_ACCESS_KEY").context("object store access key missing")?;
        let secret_key =
            std::env::var("ROOTYARD_OBJECT_STORE_SECRET_KEY").context("object store secret key missing")?;
        ensure!(!access_key.is_empty() && !secret_key.is_empty(), "object store credentials missing");
        let session_token = std::env::var("ROOTYARD_OBJECT_STORE_SESSION_TOKEN").ok();
        let store = LegacyS3Store::open(&endpoint, &bucket, &region, access_key, secret_key, session_token)?;
        Ok(Self::OpenDal(store))
    }

    /// Retained for callers that explicitly need the old path-only accessor.
    pub fn is_legacy_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }
}

fn valid_bucket(s: &str) -> bool {
    (3..=63).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
}

#[cfg(test)]
#[path = "remote_objects_tests.rs"]
mod typed_error_tests;
