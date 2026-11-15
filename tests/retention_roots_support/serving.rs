//! Serving-only composition of the real provisioning path with the shared
//! verified A3/A4/native fixture. This module is not included by the
//! roots/decisions backup support, which reuses `pack.rs` against its
//! parent-owned attachment database and intentionally has no serving actor or
//! provisioning helpers.

use anyhow::Result;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db::{Identity, Repository};
use rootyard::ref_store::GitObjectFormat;

use super::db::Db;
use super::pack::{Verified, verify_new_in_repo};

/// Actual provision + A3/A4/native verified first commit on a ready
/// `pg_refstore` repository. The caller gets the production Identity and
/// repository metadata for the serving snapshot coordinator.
pub async fn verify_new_serving(
    db: &Db,
    store: &BlobStore,
    git: &std::path::Path,
    name: &str,
) -> Result<(Verified, Identity, Repository)> {
    let actor = super::db::serving_actor(&db.pool, "roots-serving-owner-").await?;
    let repository = super::db::provision_serving(&db.pool, &actor, store, name).await?;
    let tenant = actor.id;
    let gate = super::db::gate_version(&db.pool, repository.id, tenant).await?;
    let verified = verify_new_in_repo(db, store, git, GitObjectFormat::Sha1, tenant, repository.id, gate).await?;
    Ok((verified, actor, repository))
}
