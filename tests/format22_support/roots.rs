//! Retention-root requests with an explicit producer owner.
//!
//! `retention_roots_support` fixes `owner_id == tenant_id` for every root. Issue
//! #169 requires the positive format22 source to carry roots whose producer is
//! not the repository tenant, so this module rebuilds the same `RootsScope`
//! with `owner_id` = producer and `tenant_id` = repository tenant and reuses the
//! unchanged real `PgRetentionRoots` API for prepare/register/release.

use anyhow::{Result, anyhow};
use deadpool_postgres::Pool;
use rootyard::ref_store::core::pack_snapshot::PackSnapshotRef;
use rootyard::ref_store::core::retention_root::{
    PgRetentionRoots, PrepareRootRequest, RegisterRootRequest, ReleaseRootRequest, RootCandidate, RootError,
    RootPurpose, RootReceipt, RootSelector, RootsScope,
};
use rootyard::ref_store::{CoreGateVersion, RequestDigest};
use tokio::time::Instant;
use uuid::Uuid;

use super::pack::SourceSnapshot;

pub fn producer_scope(repo: Uuid, tenant: Uuid, producer: Uuid, gate: &CoreGateVersion) -> Result<RootsScope> {
    let intent = RequestDigest::from_bytes([0x96; 32]);
    RootsScope::new(
        repo,
        tenant,
        producer,
        RootPurpose::Backup,
        &intent.as_hex(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )
    .map_err(|error| anyhow!("producer root scope rejected: {error:?}"))
}

pub fn reference(source: &SourceSnapshot) -> Result<PackSnapshotRef> {
    Ok(PackSnapshotRef::new(
        source.scope.repository_id(),
        source.scope.tenant_id(),
        source.snapshot_id,
        source.pin_id,
        1,
    )?)
}

pub struct RootRequestIds {
    pub root_id: Uuid,
    pub operation_id: Uuid,
    pub request_id: Uuid,
}

pub async fn prepare(
    adapter: &PgRetentionRoots,
    pool: &Pool,
    scope: RootsScope,
    source: &SourceSnapshot,
    ids: RootRequestIds,
    deadline: Instant,
) -> Result<RootCandidate, RootError> {
    let reference =
        reference(source).map_err(|_| RootError::RootSourceChanged("fixture snapshot reference invalid"))?;
    let request = PrepareRootRequest::new(
        scope,
        reference,
        ids.root_id,
        ids.operation_id,
        RootSelector::Snapshot,
        ids.request_id,
    )?;
    adapter.prepare(pool, request, deadline).await
}

pub async fn register(
    adapter: &PgRetentionRoots,
    pool: &Pool,
    candidate: RootCandidate,
    request_id: Uuid,
    deadline: Instant,
) -> Result<RootReceipt, RootError> {
    adapter.register(pool, RegisterRootRequest::new(candidate, request_id)?, deadline).await
}

pub struct ReleaseRequest<'a> {
    pub scope: RootsScope,
    pub root_id: Uuid,
    pub request_id: Uuid,
    pub expected_register_digest: &'a str,
    pub release_digest: &'a str,
}

pub async fn release(
    adapter: &PgRetentionRoots,
    pool: &Pool,
    request: ReleaseRequest<'_>,
    deadline: Instant,
) -> Result<RootReceipt, RootError> {
    let request = ReleaseRootRequest::new(
        request.scope,
        request.root_id,
        1,
        request.request_id,
        request.expected_register_digest,
        request.release_digest,
        "operator released retained root",
    )?;
    adapter.release(pool, request, deadline).await
}
