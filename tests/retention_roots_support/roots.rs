//! Thin roots fixture: trusted scope, exact source reference, read authority
//! and request constructors. It never constructs a `RootCandidate`; candidates
//! only come from the real `PgRetentionRoots::prepare` path.
use anyhow::Result;
use deadpool_postgres::Pool;
use rootyard::ref_store::core::pack_snapshot::PackSnapshotRef;
use rootyard::ref_store::core::retention_root::{
    PgRetentionRoots, PrepareRootRequest, RegisterRootRequest, ReleaseRootRequest, RootCandidate, RootReadAuthority,
    RootReadRequest, RootReceipt, RootReceiptQuery, RootRef, RootSelector, RootsScope,
};
use rootyard::ref_store::{CoreGateVersion, RequestDigest};
use tokio::time::Instant;
use uuid::Uuid;

use super::pack::SourceSnapshot;

pub fn scope(repo: Uuid, tenant: Uuid, gate: &CoreGateVersion) -> Result<RootsScope> {
    let intent = RequestDigest::from_bytes([0x42; 32]);
    Ok(RootsScope::new(
        repo,
        tenant,
        tenant,
        rootyard::ref_store::core::retention_root::RootPurpose::Ci,
        &intent.as_hex(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?)
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

pub fn read_authority(repo: Uuid, tenant: Uuid, gate: &CoreGateVersion) -> Result<RootReadAuthority> {
    Ok(RootReadAuthority::new(
        repo,
        tenant,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?)
}

pub fn read_request(repo: Uuid, tenant: Uuid, gate: &CoreGateVersion, root_id: Uuid) -> Result<RootReadRequest> {
    Ok(RootReadRequest::new(RootRef::new(repo, root_id, 1)?, read_authority(repo, tenant, gate)?)?)
}

pub async fn prepare(
    adapter: &PgRetentionRoots,
    pool: &Pool,
    scope: RootsScope,
    source: &SourceSnapshot,
    root_id: Uuid,
    operation_id: Uuid,
    selector: RootSelector,
    request_id: Uuid,
    deadline: Instant,
) -> Result<RootCandidate, rootyard::ref_store::core::retention_root::RootError> {
    let reference = reference(source).map_err(|_| {
        rootyard::ref_store::core::retention_root::RootError::RootSourceChanged("fixture snapshot reference invalid")
    })?;
    let request = PrepareRootRequest::new(scope, reference, root_id, operation_id, selector, request_id)?;
    adapter.prepare(pool, request, deadline).await
}

pub async fn register(
    adapter: &PgRetentionRoots,
    pool: &Pool,
    candidate: RootCandidate,
    request_id: Uuid,
    deadline: Instant,
) -> Result<RootReceipt, rootyard::ref_store::core::retention_root::RootError> {
    adapter.register(pool, RegisterRootRequest::new(candidate, request_id)?, deadline).await
}

pub async fn release(
    adapter: &PgRetentionRoots,
    pool: &Pool,
    scope: RootsScope,
    root_id: Uuid,
    request_id: Uuid,
    expected_register_digest: &str,
    release_digest: &str,
    deadline: Instant,
) -> Result<RootReceipt, rootyard::ref_store::core::retention_root::RootError> {
    let request = ReleaseRootRequest::new(
        scope,
        root_id,
        1,
        request_id,
        expected_register_digest,
        release_digest,
        "operator released retained root",
    )?;
    adapter.release(pool, request, deadline).await
}

pub fn receipt_query(scope: RootsScope, request_id: Uuid) -> Result<RootReceiptQuery> {
    Ok(RootReceiptQuery::new(scope, request_id)?)
}

/// Deterministic but distinct release intent digest for one release request.
pub fn release_digest(label: &str) -> String {
    let mut seed = [0x5a; 32];
    for (index, byte) in label.as_bytes().iter().enumerate() {
        seed[index % 32] ^= *byte;
    }
    RequestDigest::from_bytes(seed).as_hex()
}
