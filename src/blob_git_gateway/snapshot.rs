//! Sealed pack-snapshot read path and native materialization.
//!
//! A read never touches legacy GitFS/Pando authority and never invents a ref.
//! The complete ref/membership set comes from `PgServingReads`; the exact bytes
//! are downloaded, verified and materialized by the sealed A5b materializer
//! outside every PostgreSQL lease. The gateway then composes a private temporary
//! bare repository from those verified bytes. An empty `metadata_only` gate is
//! represented as an empty temporary Git view without pretending byte proof; a
//! `metadata_only` gate that already has refs is refused because no verified
//! pack bytes exist for it.
use std::collections::BTreeSet;
use std::path::Path;

use uuid::Uuid;

use super::{
    error::GatewayError,
    native::{TempGitView, run_capture},
    state::BlobGitState,
};
use crate::ref_store::{
    GitObjectFormat, MetadataPinPurpose, RefStoreError,
    core::{
        MetadataSnapshotScope, PgPackSnapshotMaterializer,
        pack_commit::{PackCommitBaseline, PgPackCommit},
        pack_snapshot::{PgServingReads, ServingReadCapture},
    },
    serving::ServingRepository,
};

pub(super) const SNAPSHOT_LEASE_SECONDS: u32 = 300;

/// A transient, captured ref view. Only the materializer verifies its bytes.
pub(super) struct RefView {
    pub format: GitObjectFormat,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub refs: Vec<(String, String)>,
    pub handle: Option<ServingReadCapture>,
    pool: deadpool_postgres::Pool,
    released: std::sync::atomic::AtomicBool,
}

impl Drop for RefView {
    fn drop(&mut self) {
        if self.released.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let Some(capture) = self.handle.take() else { return };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let pool = self.pool.clone();
        runtime.spawn(async move {
            // Cleanup has its own small budget and grants no work/serve time.
            // A killed process or unavailable PG still falls back to expiry.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
            let _ = PgServingReads.release(&pool, &capture, deadline).await;
        });
    }
}

/// Keep the workspace charged until the last streaming/native user drops its
/// computed view. Drop the files before returning their reserved capacity.
pub(super) struct ComputedView {
    git: TempGitView,
    _workspace: super::state::WorkspaceLease,
}

impl std::ops::Deref for ComputedView {
    type Target = TempGitView;

    fn deref(&self) -> &Self::Target {
        &self.git
    }
}

/// Capture the complete ref/membership view of the current gate.
pub(super) async fn load_ref_view(
    state: &BlobGitState,
    serving: &ServingRepository,
    deadline: tokio::time::Instant,
) -> Result<RefView, GatewayError> {
    let gate = &serving.gate;
    let scope = MetadataSnapshotScope::new(
        gate.repository_id(),
        gate.tenant_id(),
        gate.tenant_id(),
        MetadataPinPurpose::Verification,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )
    .map_err(ref_error)?;
    let capture = PgServingReads
        .capture(state.pool(), &scope, state.store().backend_identity(), SNAPSHOT_LEASE_SECONDS, deadline)
        .await
        .map_err(ref_error)?;
    let refs = capture
        .registered_snapshot()
        .map(|snapshot| {
            snapshot
                .refs()
                .iter()
                .map(|reference| (reference.name().to_owned(), reference.oid_hex().to_owned()))
                .collect()
        })
        .unwrap_or_default();
    Ok(RefView {
        format: gate.object_format(),
        head_ref: capture.head_ref().to_owned(),
        head_oid: capture.registered_snapshot().and_then(|snapshot| snapshot.head_oid_hex().map(str::to_owned)),
        refs,
        handle: Some(capture),
        pool: state.pool().clone(),
        released: std::sync::atomic::AtomicBool::new(false),
    })
}

/// The cluster authority incarnation the capture locked `FOR SHARE`; a JSON
/// read refuses to materialize unless it is the authorized lookup's own value.
pub(super) fn capture_incarnation(view: &RefView) -> Option<Uuid> {
    view.handle.as_ref().map(ServingReadCapture::capture_incarnation)
}

/// The core gate revision the capture actually locked. Unlike the lookup's
/// revision (read before PostgreSQL), this is the only input to a lower bound.
pub(super) fn capture_gate_revision(view: &RefView) -> Option<i64> {
    view.handle.as_ref().map(ServingReadCapture::gate_revision)
}

/// Compose one private bare Git view from the verified snapshot bytes. The
/// transient read pin is released on every outcome (success or typed failure).
pub(super) async fn build_view(
    state: &BlobGitState,
    view: &RefView,
    deadline: tokio::time::Instant,
) -> Result<ComputedView, GatewayError> {
    // The sealed descriptor lengths are known before Blob IO. Account for the
    // materializer, the gateway copy and transient copies, plus fresh receive
    // staging, rather than reserving only the request's Content-Length.
    let pack_bytes = view
        .handle
        .as_ref()
        .and_then(ServingReadCapture::registered_snapshot)
        .map(|snapshot| super::resource::registered_packs_workspace_bytes(snapshot.packs()))
        .unwrap_or(0);
    let bytes = pack_bytes
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(state.limits().max_request_bytes.checked_mul(2)?))
        .ok_or(GatewayError::TooLarge)?;
    let workspace = match state.reserve_workspace(bytes) {
        Ok(lease) => lease,
        Err(error) => {
            release_view(state, view, deadline).await;
            return Err(error);
        }
    };
    let git = match TempGitView::create(state, view.format, deadline).await {
        Ok(git) => git,
        Err(error) => {
            release_view(state, view, deadline).await;
            return Err(error);
        }
    };
    let outcome = build_into(state, &git, view, deadline).await;
    release_view(state, view, deadline).await;
    outcome?;
    verify_refs(state, &git, view, deadline).await?;
    Ok(ComputedView { git, _workspace: workspace })
}

async fn build_into(
    state: &BlobGitState,
    git: &TempGitView,
    view: &RefView,
    deadline: tokio::time::Instant,
) -> Result<(), GatewayError> {
    let Some(handle) = &view.handle else {
        write_refs(git.repo(), &view.refs, &view.head_ref)?;
        return Ok(());
    };
    let materializer =
        PgPackSnapshotMaterializer::new(state.store().clone(), state.git_binary().to_path_buf()).map_err(ref_error)?;
    let read = materializer.materialize_serving_read(state.pool(), handle, deadline).await.map_err(ref_error)?;
    let Some(read) = read else {
        write_refs(git.repo(), &view.refs, &view.head_ref)?;
        return Ok(());
    };
    let materialized_refs = read
        .refs()
        .iter()
        .map(|reference| (reference.name().to_owned(), reference.oid_hex().to_owned()))
        .collect::<Vec<_>>();
    if materialized_refs != view.refs {
        return Err(GatewayError::Conflict("materialized ref set differs from the sealed snapshot"));
    }
    let pack_dir = git.repo().join("objects").join("pack");
    std::fs::create_dir_all(&pack_dir)
        .map_err(|_| GatewayError::Internal("could not create the temporary pack directory"))?;
    for pack in read.packs() {
        let pack_id = pack.pack_id();
        let pack_bytes = read.pack_bytes(pack_id, deadline).await.map_err(ref_error)?;
        let idx_bytes = read.idx_bytes(pack_id, deadline).await.map_err(ref_error)?;
        // The membership UUID is not a Git pack filename. The materializer
        // already verified these exact bytes and the pack/index checksum pair;
        // use their object-format-sized pack checksum as Git's canonical stem.
        let hash_bytes = match view.format {
            GitObjectFormat::Sha1 => 20,
            GitObjectFormat::Sha256 => 32,
        };
        let trailer = pack_bytes
            .get(pack_bytes.len().saturating_sub(hash_bytes)..)
            .filter(|bytes| bytes.len() == hash_bytes)
            .ok_or(GatewayError::Internal("verified pack has no checksum trailer"))?;
        let index_pack_checksum =
            idx_bytes.get(idx_bytes.len().saturating_sub(2 * hash_bytes)..idx_bytes.len().saturating_sub(hash_bytes));
        if index_pack_checksum != Some(trailer) {
            return Err(GatewayError::Internal("verified index and pack checksum disagree"));
        }
        let stem = format!("pack-{}", hex::encode(trailer));
        std::fs::write(pack_dir.join(format!("{stem}.pack")), pack_bytes)
            .map_err(|_| GatewayError::Internal("could not stage a verified pack"))?;
        std::fs::write(pack_dir.join(format!("{stem}.idx")), idx_bytes)
            .map_err(|_| GatewayError::Internal("could not stage a verified index"))?;
    }
    write_refs(git.repo(), &view.refs, &view.head_ref)
}

/// Release the transient read pin of a view that was not materialized (for
/// example the receive-pack advertisement, which only needs refs).
pub(super) async fn release_view(state: &BlobGitState, view: &RefView, deadline: tokio::time::Instant) {
    if let Some(handle) = &view.handle
        && PgServingReads.release(state.pool(), handle, deadline).await.is_ok()
    {
        view.released.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Empty/complete advertisement bytes are produced by the caller from this exact
/// same view, never from a different read.
pub(super) fn service_prefix(service: &str) -> Vec<u8> {
    let line = format!("# service={service}\n");
    let mut bytes = format!("{:04x}", line.len() + 4).into_bytes();
    bytes.extend_from_slice(line.as_bytes());
    bytes.extend_from_slice(b"0000");
    bytes
}

fn write_refs(repo: &Path, refs: &[(String, String)], head_ref: &str) -> Result<(), GatewayError> {
    let mut sorted = refs.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    if !sorted.is_empty() {
        let mut packed = String::new();
        for (name, oid) in &sorted {
            packed.push_str(oid);
            packed.push(' ');
            packed.push_str(name);
            packed.push('\n');
        }
        std::fs::write(repo.join("packed-refs"), packed)
            .map_err(|_| GatewayError::Internal("could not write the temporary packed-refs"))?;
    }
    std::fs::write(repo.join("HEAD"), format!("ref: {head_ref}\n"))
        .map_err(|_| GatewayError::Internal("could not write the temporary HEAD"))?;
    Ok(())
}

async fn verify_refs(
    state: &BlobGitState,
    git: &TempGitView,
    view: &RefView,
    deadline: tokio::time::Instant,
) -> Result<(), GatewayError> {
    let mut command = git.command(state.git_binary());
    command.arg("for-each-ref").arg("--format=%(objectname) %(refname)");
    let captured = run_capture(command, None, 4 * 1024 * 1024, deadline).await?;
    if !captured.success {
        return Err(GatewayError::Internal("temporary Git view could not be read back"));
    }
    let text = std::str::from_utf8(&captured.stdout)
        .map_err(|_| GatewayError::Internal("temporary Git refs are not UTF-8"))?;
    let mut observed = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| match line.split_once(' ') {
            Some((oid, name)) => Ok((name.to_owned(), oid.to_owned())),
            None => Err(GatewayError::Internal("temporary Git ref line is malformed")),
        })
        .collect::<Result<Vec<_>, GatewayError>>()?;
    let mut expected = view.refs.clone();
    observed.sort();
    expected.sort();
    if observed != expected {
        return Err(GatewayError::Internal("temporary Git view does not reproduce the sealed refs"));
    }
    let mut names = BTreeSet::new();
    if !expected.iter().all(|(name, _)| names.insert(name.clone())) {
        return Err(GatewayError::Internal("sealed ref set contains a duplicate name"));
    }
    if let Some(head_oid) = &view.head_oid {
        let mut command = git.command(state.git_binary());
        command.arg("rev-parse").arg("--verify").arg(&view.head_ref);
        let captured = run_capture(command, None, 1024, deadline).await?;
        let observed = std::str::from_utf8(&captured.stdout)
            .map_err(|_| GatewayError::Internal("temporary HEAD is not UTF-8"))?
            .trim();
        if !captured.success || observed != head_oid {
            return Err(GatewayError::Internal("temporary Git view does not reproduce the sealed HEAD"));
        }
    }
    Ok(())
}

pub(super) async fn capture_baseline(
    state: &BlobGitState,
    repository_id: Uuid,
    tenant_id: Uuid,
    deadline: tokio::time::Instant,
) -> Result<PackCommitBaseline, GatewayError> {
    let mut client = state.pooled(deadline).await?;
    PgPackCommit.capture_baseline(&mut client, repository_id, tenant_id, deadline).await.map_err(Into::into)
}

pub(super) fn ref_error(error: RefStoreError) -> GatewayError {
    error.into()
}
