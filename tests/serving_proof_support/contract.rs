//! Real-PostgreSQL + native Git contract cases for the sealed serving proof (#174).
//!
//! The production builder `materialize_serving_read_sealed` is crate-private, so
//! this file is **not** an integration test binary: it is `#[path]`-included
//! inside the crate's own `cfg(test)` build
//! (`pack_snapshot::materialize::serving_tests::contract`) and drives the actual
//! builder. It is `#[ignore]`-gated and every service is a hard failure, never a
//! silent skip: a missing database, Blob profile or Git binary must not turn into
//! an offline pass.
//!
//! The repository, gate, actor and backend fixtures are the real ones from
//! `tests/serving_reads_support` and `tests/serving_support` (the same modules
//! `ref_store_serving_reads.rs` and `ref_store_serving.rs` compile), selected
//! with `#[path]` so nothing is copied. The pack is a real A4 artifact hold →
//! protected upload → registration → native verifier proof → verified commit;
//! the native/pack helpers live in [`contract_fixtures`].
//!
//! What these cases prove:
//!
//! * a non-empty sealed materialization is produced by the production builder
//!   and carries the capture's own gate revision and realm plus the **A5b**
//!   materialization digest, while the verified native view stays alive;
//! * a checked empty capture seals to `Ok(None)` through the sealed builder;
//! * a restore rotation between capture and T2 refuses with no view or proof;
//! * deleting a registered pack from Blob after the capture and before T2 makes
//!   the sealed builder refuse: no `MaterializedServingRead` and no session
//!   proof can be produced from missing bytes.
#[path = "contract_fixtures.rs"]
mod contract_fixtures;
#[path = "../serving_reads_support/mod.rs"]
mod serving_reads_support;
#[path = "../serving_support/mod.rs"]
mod serving_support;

use self::contract_fixtures::{
    FirstPackRequest, GitRepo, LEASE_SECONDS, commit_first_pack, gate_version, git_binary, main_update, open_store,
    protected_pack_count,
};
use self::serving_reads_support::{RepoFixture, ensure_migration_146, operation_deadline, provision_ready};
use self::serving_support::{Actor, Fixture, actor};
use super::PgPackSnapshotMaterializer;
use crate::blob_store::test_support::delete_exact;
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::core::pack_commit::PackArtifactRole;
use crate::ref_store::core::pack_snapshot::{PgServingReads, ServingReadCapture, probe_a5a};
use anyhow::{Result, anyhow, ensure};
use uuid::Uuid;

/// Names the production Blob profile's root prefix to this case alone. The guard
/// restores the previous value on exit; the empty case downloads nothing.
struct BlobRootIsolation(Option<std::ffi::OsString>);

impl BlobRootIsolation {
    fn new() -> Self {
        let previous = std::env::var_os("ROOTYARD_BLOB_ROOT");
        // SAFETY: the provisioned identity and the materializer both read this
        // same value, and nothing else in this binary writes it concurrently for
        // this ignored case.
        unsafe { std::env::set_var("ROOTYARD_BLOB_ROOT", format!("fixture-{}", Uuid::new_v4().simple())) };
        Self(previous)
    }
}

impl Drop for BlobRootIsolation {
    fn drop(&mut self) {
        // SAFETY: as above; the restore runs on every exit path.
        unsafe {
            match &self.0 {
                Some(value) => std::env::set_var("ROOTYARD_BLOB_ROOT", value),
                None => std::env::remove_var("ROOTYARD_BLOB_ROOT"),
            }
        }
    }
}

/// The current global cluster authority incarnation (migration 085).
async fn current_incarnation(fixture: &Fixture) -> Result<Uuid> {
    Ok(fixture
        .pool
        .get()
        .await?
        .query_one("SELECT incarnation FROM public.cluster_authority WHERE singleton=true", &[])
        .await?
        .get(0))
}

/// Rotate the singleton exactly as the restore rotation
/// (`src/backup/authority::fence`) does and return the freshly committed value.
async fn rotate_incarnation(fixture: &Fixture) -> Result<Uuid> {
    let rotated: Uuid = fixture
        .pool
        .get()
        .await?
        .query_one(
            "UPDATE public.cluster_authority SET incarnation=gen_random_uuid(),rotated_at=clock_timestamp()
             WHERE singleton=true RETURNING incarnation",
            &[],
        )
        .await?
        .get(0);
    ensure!(!rotated.is_nil(), "a rotation must never commit a nil incarnation");
    Ok(rotated)
}

/// A real-PostgreSQL `metadata_only` repository together with the owner actor
/// that provisioned it, for the captured-but-refused cases that still need a
/// transient pin row. Every later authorized write must go through this same
/// owner: the owner identity is what the real `PgAuthorizedCommit` decision
/// resolves an effective RBAC role from, so a second actor would be denied.
async fn provision_empty_repository(fixture: &Fixture, name: &str) -> Result<(Actor, RepoFixture)> {
    ensure_migration_146(fixture).await?;
    let owner = actor(&fixture.pool, false).await?;
    let repo = provision_ready(fixture, &owner.identity, name).await?;
    Ok((owner, repo))
}

/// Make one registered pack + one ref through the real authorized pipeline
/// under the repository's owner `identity` (the actor that provisioned `repo`),
/// so a subsequent capture is a real non-empty `pack_verified` serving read.
async fn provision_verified_pack(fixture: &Fixture, repo: &RepoFixture, owner: &crate::db::Identity) -> Result<()> {
    let store = open_store()?;
    let format = repo.ready.object_format;
    let git = git_binary()?;
    let source = GitRepo::new(git.clone(), format).await?;
    let commit_oid = source.build_commit("file.txt", b"serving proof fixture\n", "serving proof main").await?;
    source.update_ref("refs/heads/main", &commit_oid).await?;
    let files = source.pack_all("first").await?;
    let gate = gate_version(&fixture.pool, repo.ready.repository_id, repo.ready.tenant_id).await?;
    commit_first_pack(FirstPackRequest {
        fixture,
        store: &store,
        tenant: repo.ready.tenant_id,
        owner: repo.ready.owner_id,
        repo: repo.ready.repository_id,
        gate,
        git: &git,
        actor: owner,
        refs: vec![main_update(format, &commit_oid)?],
        files: &files,
    })
    .await?;
    let mode: String = fixture
        .pool
        .get()
        .await?
        .query_one("SELECT pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&repo.ready.repository_id])
        .await?
        .get(0);
    ensure!(mode == "pack_verified", "the authorized commit must advance the gate to pack_verified, got {mode}");
    Ok(())
}

/// Seal one real capture and run `check` inside the pin window, then release
/// the transient pin once `check` returns its capture, whether it returns
/// `Ok` or an `Err`, before returning the check's own outcome.
async fn with_sealed_capture<F, Fut>(fixture: &Fixture, repo: &RepoFixture, check: F) -> Result<()>
where
    F: FnOnce(ServingReadCapture) -> Fut,
    Fut: std::future::Future<Output = (ServingReadCapture, Result<()>)>,
{
    let scope = repo.ready.scope()?;
    let reads = PgServingReads;
    let capture = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await?;
    let (capture, result) = check(capture).await;
    let released = reads.release(&fixture.pool, &capture, operation_deadline()).await;
    result?;
    released.map_err(|error| anyhow!("serving read release failed: {error}"))
}

/// The production builder, the sealed proof and the surviving native view.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL, the production Blob profile and native git"]
async fn sealed_materialization_carries_a5b_binding_and_keeps_the_native_view() -> Result<()> {
    let fixture = Fixture::new().await?;
    let provisioned = async {
        let (owner, repo) = provision_empty_repository(&fixture, "serving-proof-native").await?;
        provision_verified_pack(&fixture, &repo, &owner.identity).await?;
        Ok::<_, anyhow::Error>(repo)
    }
    .await;
    let repo = match provisioned {
        Ok(repo) => repo,
        Err(error) => {
            fixture.teardown().await?;
            return Err(error);
        }
    };
    let fixture_ref = &fixture;
    let repo_ref = &repo;
    let checked = with_sealed_capture(fixture_ref, repo_ref, move |capture| async move {
        let fixture = fixture_ref;
        let repo = repo_ref;
        let result = async {
            // A pack_verified gate with one registered pack never captures as empty.
            ensure!(!capture.is_empty(), "a pack_verified gate with one registered pack must not capture as empty");
            let (snapshot, binding, capture_anchor) = capture.registered_parts()?;
            let a5a = probe_a5a(&snapshot);
            let captured_incarnation = capture.capture_incarnation();
            ensure!(
                capture_anchor == captured_incarnation,
                "the registered parts must carry the capture's own cluster authority incarnation"
            );
            ensure!(!captured_incarnation.is_nil(), "the capture anchor must be a non-nil incarnation");
            ensure!(
                captured_incarnation == current_incarnation(fixture).await?,
                "the capture anchor must be the current cluster authority incarnation"
            );
            let materializer: PgPackSnapshotMaterializer = repo.materializer()?;
            let sealed =
                match materializer.materialize_serving_read_sealed(&fixture.pool, &capture, operation_deadline()).await
                {
                    Ok(Some(sealed)) => sealed,
                    Ok(None) => return Err(anyhow!("non-empty capture sealed to Ok(None)")),
                    Err(error) => return Err(anyhow!("the production sealed builder refused a real capture: {error}")),
                };
            let view = sealed.view();
            ensure!(
                view.serving_incarnation() == Some(captured_incarnation),
                "the sealed view must carry exactly the T2-compared capture anchor"
            );
            let (proof_revision, proven, proof_binding) = sealed.contract_parts();
            let capture_pin = capture.pin_id().ok_or_else(|| anyhow!("the non-empty capture must carry a pin id"))?;
            let expected_packs = protected_pack_count(fixture, capture_pin).await?;
            ensure!(expected_packs > 0, "the capture must register at least one pack");
            ensure!(view.pack_count() == expected_packs, "the sealed view must expose every captured pack");
            ensure!(view.verified_pairs() == 1, "the sealed view must cover one native-verified pair");
            ensure!(
                proof_revision == view.gate_revision() && proof_revision > repo.ready.gate_revision,
                "the proof must state the captured (post commit) gate revision"
            );
            ensure!(proof_binding == binding, "the proof must carry the capture's A5b binding");
            ensure!(view.read_digest_hex() == binding.as_hex(), "the view's A5b binding is its native digest");
            ensure!(
                a5a.as_hex() != proof_binding.as_hex(),
                "the A5a read digest must never be mistaken for the A5b binding"
            );
            ensure!(
                proven.contract_tenant_id() == repo.ready.tenant_id
                    && proven.contract_repository_id() == repo.ready.repository_id
                    && proven.contract_object_format() == repo.ready.object_format
                    && proven.contract_history_incarnation() == repo.ready.history_incarnation
                    && proven.contract_authority_epoch() == repo.ready.authority_epoch
                    && proven.contract_group_epoch() == repo.ready.group_epoch,
                "the proof realm must be the capture realm"
            );
            ensure!(
                sealed.proof().contract_cluster_incarnation() == captured_incarnation,
                "the proof must carry exactly the capture's cluster authority incarnation"
            );
            ensure!(view.verified_read_scope(&binding).is_some(), "the view must prove the same A5b binding");
            ensure!(view.verified_read_scope(&a5a).is_none(), "the view must never prove the narrower A5a read digest");
            // The factory reads the incarnation back from the view: re-running it
            // over the sealed view reproduces exactly that T2-bound anchor.
            let refactory = sealed.contract_refactory()?;
            ensure!(
                refactory.contract_cluster_incarnation() == captured_incarnation,
                "the proof incarnation must be fixed to the view's T2-bound anchor"
            );
            Ok(())
        }
        .await;
        (capture, result)
    })
    .await;
    // The capture was released before this teardown on every check outcome.
    fixture.teardown().await?;
    checked
}

/// A restore rotation between capture and T2 must refuse before any view or
/// proof exists, and the transient pin must still be released afterwards.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL, the production Blob profile and native git"]
async fn a_restore_rotation_between_capture_and_t2_refuses_the_sealed_materialization() -> Result<()> {
    let fixture = Fixture::new().await?;
    let provisioned = async {
        let (owner, repo) = provision_empty_repository(&fixture, "serving-proof-rotation").await?;
        provision_verified_pack(&fixture, &repo, &owner.identity).await?;
        Ok::<_, anyhow::Error>(repo)
    }
    .await;
    let repo = match provisioned {
        Ok(repo) => repo,
        Err(error) => {
            fixture.teardown().await?;
            return Err(error);
        }
    };
    let fixture_ref = &fixture;
    let repo_ref = &repo;
    let checked = with_sealed_capture(fixture_ref, repo_ref, move |capture| async move {
        let fixture = fixture_ref;
        let repo = repo_ref;
        let result = async {
            ensure!(!capture.is_empty(), "the rotation case needs a real non-empty capture");
            let captured_incarnation = capture.capture_incarnation();
            let pin_id = capture.pin_id().ok_or_else(|| anyhow!("the non-empty capture must carry a pin id"))?;
            // The restore rotation runs while Blob/native IO is in flight, i.e.
            // between the capture and T2.
            let rotated = rotate_incarnation(fixture).await?;
            ensure!(rotated != captured_incarnation, "the rotation must change the incarnation");
            ensure!(
                current_incarnation(fixture).await? == rotated,
                "the rotation must be committed before the sealed builder runs"
            );
            let materializer: PgPackSnapshotMaterializer = repo.materializer()?;
            let refused =
                materializer.materialize_serving_read_sealed(&fixture.pool, &capture, operation_deadline()).await;
            match refused {
                Err(RefStoreError::MetadataScopeMismatch(field)) => {
                    ensure!(
                        field == "cluster authority incarnation",
                        "the refusal must name the incarnation, got {field}"
                    );
                }
                Err(error) => {
                    return Err(anyhow!("a rotated incarnation must be a typed incarnation refusal, got {error}"));
                }
                Ok(None) => return Err(anyhow!("a non-empty capture must never seal to Ok(None)")),
                Ok(Some(_)) => return Err(anyhow!("a rotated incarnation must never produce a sealed view or proof")),
            }
            // The refused capture's pin is still exactly the one that must be
            // released, and its anchor never becomes the rotated value.
            ensure!(capture.pin_id() == Some(pin_id), "the refused capture must keep its own pin identity");
            ensure!(capture.capture_incarnation() == captured_incarnation, "the capture anchor must not be rewritten");
            Ok(())
        }
        .await;
        (capture, result)
    })
    .await;
    // The refused capture's pin was released before this teardown on both the
    // refusal and any earlier check failure.
    fixture.teardown().await?;
    checked
}

/// The checked-empty capture still carries the current non-nil incarnation as
/// its anchor, seals to `Ok(None)` (no bytes, no proof) before and after a
/// rotation, and releases without owning a row.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL, the production Blob profile and native git"]
async fn sealed_materialization_returns_none_for_a_checked_empty_capture() -> Result<()> {
    let _blob_root = BlobRootIsolation::new();
    let fixture = Fixture::new().await?;
    let outcome = async {
        // Only the provisioned repository matters here; nothing writes to it.
        let (_owner, repo) = provision_empty_repository(&fixture, "serving-proof-empty").await?;
        let current = current_incarnation(&fixture).await?;
        ensure!(!current.is_nil(), "the cluster authority incarnation must never be nil");
        let scope = repo.ready.scope()?;
        let reads = PgServingReads;
        let capture = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await?;
        ensure!(capture.is_empty(), "a metadata_only repository must capture as empty");
        ensure!(capture.capture_incarnation() == current, "the empty capture anchor must be the current incarnation");
        let materializer: PgPackSnapshotMaterializer = repo.materializer()?;
        let result =
            match materializer.materialize_serving_read_sealed(&fixture.pool, &capture, operation_deadline()).await {
                Ok(None) => Ok(()),
                Ok(Some(_)) => Err(anyhow!("an empty capture must never seal a proof")),
                Err(RefStoreError::Unsupported(reason)) => {
                    Err(anyhow!("an empty capture must seal to Ok(None), not a refusal: {reason}"))
                }
                Err(error) => Err(anyhow!("an empty capture must seal to Ok(None): {error}")),
            };
        // A restore rotation does not turn the (byte-less) empty observation
        // into a proof either; the capture keeps its original anchor.
        let rotated = rotate_incarnation(&fixture).await?;
        ensure!(capture.capture_incarnation() == current, "the empty capture anchor must never be rewritten");
        ensure!(rotated != current, "the rotation must change the incarnation");
        let after_rotation =
            materializer.materialize_serving_read_sealed(&fixture.pool, &capture, operation_deadline()).await;
        let after = match after_rotation {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(anyhow!("a rotated empty capture must never seal a proof")),
            Err(error) => Err(anyhow!("a rotated empty capture must still seal to Ok(None): {error}")),
        };
        // A checked-empty capture owns no pin row, so its release is an
        // acknowledged no-op and never touches the fixture's loan.
        let released = reads.release(&fixture.pool, &capture, operation_deadline()).await;
        result?;
        after?;
        released.map_err(|error| anyhow!("serving read release failed: {error}"))
    }
    .await;
    // Teardown owns the fixture and runs exactly once, after the outcome, on
    // both success and error; the empty capture held no pin that could outlive it.
    fixture.teardown().await?;
    outcome
}

/// Deleting a registered pack after capture but before T2 must refuse the
/// sealed builder: missing bytes can never produce a `MaterializedServingRead`
/// (and therefore never a session proof).
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL, the production Blob profile and native git"]
async fn corrupting_a_registered_pack_after_capture_refuses_the_sealed_materialization() -> Result<()> {
    let fixture = Fixture::new().await?;
    let provisioned = async {
        let (owner, repo) = provision_empty_repository(&fixture, "serving-proof-corrupt-pack").await?;
        provision_verified_pack(&fixture, &repo, &owner.identity).await?;
        Ok::<_, anyhow::Error>(repo)
    }
    .await;
    let repo = match provisioned {
        Ok(repo) => repo,
        Err(error) => {
            fixture.teardown().await?;
            return Err(error);
        }
    };
    let fixture_ref = &fixture;
    let repo_ref = &repo;
    let checked = with_sealed_capture(fixture_ref, repo_ref, move |capture| async move {
        let fixture = fixture_ref;
        let repo = repo_ref;
        let result = async {
            ensure!(!capture.is_empty(), "the corruption case needs a real non-empty capture");
            let snapshot = capture
                .registered_snapshot()
                .ok_or_else(|| anyhow!("a registered capture must expose its snapshot"))?;
            let pack = snapshot.packs().first().ok_or_else(|| anyhow!("the capture registered no pack"))?;
            let locator = pack
                .artifact(PackArtifactRole::Pack)
                .locator()
                .blob_locator()
                .map_err(|error| anyhow!("registered pack locator is invalid: {error}"))?;
            // The capture, its pin and the durable registration all still exist;
            // only the acknowledged Blob object disappears.
            let store = open_store()?;
            delete_exact(&store, &locator).await?;
            let materializer: PgPackSnapshotMaterializer = repo.materializer()?;
            let refused =
                materializer.materialize_serving_read_sealed(&fixture.pool, &capture, operation_deadline()).await;
            match refused {
                Err(_) => Ok(()),
                Ok(None) => Err(anyhow!("a non-empty capture must never seal to Ok(None)")),
                Ok(Some(_)) => Err(anyhow!("a capture whose registered pack is gone must never produce a sealed read")),
            }
        }
        .await;
        (capture, result)
    })
    .await;
    fixture.teardown().await?;
    checked
}
