//! `cfg(test)`-only helpers: a `memory`-backed BlobStore with a private budget.
//!
//! These helpers never read `ROOTYARD_BLOB_*` environment variables, so tests
//! cannot race each other through shared process environment. They are also not
//! a production construction path: `BlobStore::open_memory` is `cfg(test)` and
//! the strict profile continues to reject `memory` by name.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    BlobBackendIdentity, UploadIntent,
    budget::{ResourceContext, ResourceLimits},
    config::BlobProfile,
    opendal::BlobStore,
};

pub(crate) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

pub(crate) fn short_deadline() -> Instant {
    Instant::now() + Duration::from_millis(60)
}

/// A memory-backed store plus the exact private context it charges.
pub(crate) fn store(limits: ResourceLimits) -> (BlobStore, Arc<ResourceContext>) {
    let resources = Arc::new(ResourceContext::new(limits));
    let store = BlobStore::open_memory(BlobProfile::memory_profile(limits), Arc::clone(&resources));
    (store, resources)
}

/// Two distinct real `cfg(test)` memory-store identities from one shared
/// private budget. Callers that need a stable identity per test compare the
/// returned values instead of opening a new store per call.
pub(crate) fn distinct_backend_identities() -> (BlobBackendIdentity, BlobBackendIdentity) {
    let limits = ResourceLimits::new(2, 2, 1 << 20).expect("test budget");
    let (first, _) = store(limits);
    let (second, _) = store(limits);
    (first.backend_identity().clone(), second.backend_identity().clone())
}

/// The stable synthetic identity named `name`. Two calls with one name are
/// equal; different names are distinct. Not a real store and not a secret.
pub(crate) fn blob_backend_identity(name: &str) -> BlobBackendIdentity {
    BlobBackendIdentity::named_test_identity(name)
}

pub(crate) fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Mint a fresh one-use upload intent for a test payload. Every call gets a new
/// random attempt address; callers capture `locator()` before consuming it.
pub(crate) fn upload(blob: &BlobStore, namespace: &str, bytes: &[u8]) -> UploadIntent {
    blob.new_upload(Uuid::new_v4(), Uuid::new_v4(), 1, namespace, &digest(bytes), bytes.len() as u64)
        .expect("test upload intent")
}

pub(crate) fn write_source(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join("source");
    std::fs::write(&path, bytes).expect("test source write");
    path
}
