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
//! with `#[path]` so nothing is copied; inside the library's own test build the
//! crate is available under its own name through `extern crate self as
//! rootyard` in `src/lib.rs`. The pack is a real A4
//! artifact hold → protected upload → registration → native verifier proof →
//! verified commit.
//!
//! What these cases prove:
//!
//! * a non-empty sealed materialization is produced by the production builder
//!   and carries the capture's own gate revision and realm plus the **A5b**
//!   materialization digest — which differs from the narrower A5a read digest —
//!   while the verified native view (with its packs) stays alive next to it;
//! * the sealed view re-proves through the same factory on that A5b binding;
//! * a checked empty capture seals to `Ok(None)` through the sealed builder: no
//!   bytes, no proof, while still carrying the current non-nil cluster authority
//!   incarnation as its anchor;
//! * the sealed proof carries exactly the cluster authority incarnation the
//!   capture locked and its T2 re-read identically (the view's own anchor, which
//!   no caller can supply), and rotating `cluster_authority.incarnation` between
//!   capture and T2 (the same `UPDATE` effect the restore rotation runs) makes
//!   the sealed builder refuse with no view and no proof, after which the
//!   transient pin is still released.
//!
//! What they do not prove: that any HTTP response was served. The proof is an
//! internal materialization proof and no gateway route consumes it.
#![allow(clippy::too_many_arguments)]

// Every `rootyard::…` path in the `#[path]`d integration fixtures below resolves
// to this crate. Paths here are relative to this file
// (`tests/serving_proof_support/`).
#[path = "../serving_reads_support/mod.rs"]
mod serving_reads_support;
#[path = "../serving_support/mod.rs"]
mod serving_support;

use self::serving_reads_support::{RepoFixture, ensure_migration_146, operation_deadline, provision_ready};
use self::serving_support::{Actor, Fixture, actor};
use super::PgPackSnapshotMaterializer;
use crate::blob_store::BlobProvider;
use crate::blob_store::config::BlobProfile;
use crate::blob_store::opendal::BlobStore;
use crate::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use crate::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::pack_commit::{
    AuthorizedCommitMode, AuthorizedSelection, ContentDigest, PackArtifactRole, PackCommitExpectation, PackCommitPlan,
    PackCommitScope, PackMembershipEntry, PackPendingToken, PackRegistrationRequest, PgAuthorizedCommit, PgPackCommit,
    PlannedArtifact, PlannedPack, PrepareOutcome, PreparedPublication, VerifiedAuthorizedPublication,
};
use crate::ref_store::core::pack_snapshot::{PgServingReads, probe_a5a};
use crate::ref_store::core::{CommitMode, PgRefStoreCore};
use crate::ref_store::{
    CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationIdentity, RefName, RefPrecondition,
    RefTarget, RefUpdate, VersionCheck,
};
use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::core::pack_snapshot::ServingReadCapture;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const LEASE_SECONDS: u32 = 60;
const NATIVE_SECONDS: u64 = 120;
const HOLD_NAMESPACE: &str = "core-pack";

fn std_deadline() -> StdInstant {
    StdInstant::now() + Duration::from_secs(NATIVE_SECONDS)
}

fn git_binary() -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()));
    ensure!(path.is_absolute() && path.is_file(), "ROOTYARD_TEST_GIT must be an absolute existing git binary");
    Ok(path)
}

fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "the native serving fixture requires the S3 Blob profile");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

/// Owned fixture Git: cleared environment, known author, bounded timeout,
/// synthetic bytes only.
struct GitRepo {
    _root: tempfile::TempDir,
    bare: PathBuf,
    home: PathBuf,
    template: PathBuf,
    git: PathBuf,
}

impl GitRepo {
    async fn new(git: PathBuf, format: GitObjectFormat) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let template = root.path().join("template");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&template)?;
        let repo = Self { bare: root.path().join("fixture.git"), home, template, git, _root: root };
        let object_format = format!("--object-format={}", format.as_str());
        let template_arg = format!("--template={}", repo.template.display());
        repo.run(&["init", "--bare", "--quiet", object_format.as_str(), template_arg.as_str()], None).await?;
        Ok(repo)
    }

    async fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        let with_repo = self.bare.is_dir();
        let mut command = tokio::process::Command::new(&self.git);
        command
            .current_dir(self._root.path())
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TEMPLATE_DIR", &self.template)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_NAME", "Rootyard Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@rootyard.invalid")
            .env("GIT_COMMITTER_NAME", "Rootyard Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@rootyard.invalid")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("gc.auto=0")
            .arg("--no-replace-objects")
            .args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if with_repo {
            command.env("GIT_DIR", &self.bare);
        }
        let mut child = command.spawn()?;
        if let Some(bytes) = stdin {
            let mut pipe = child.stdin.take().ok_or_else(|| anyhow!("fixture git stdin is not piped"))?;
            pipe.write_all(bytes).await?;
            drop(pipe);
        }
        let output = tokio::time::timeout(Duration::from_secs(NATIVE_SECONDS), child.wait_with_output())
            .await
            .map_err(|_| anyhow!("fixture git timed out"))??;
        ensure!(
            output.status.success(),
            "fixture git `{}` failed: {}",
            args.first().copied().unwrap_or("<none>"),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    fn text(bytes: &[u8]) -> Result<String> {
        Ok(std::str::from_utf8(bytes)?.trim().to_owned())
    }

    async fn add_blob(&self, bytes: &[u8]) -> Result<String> {
        Self::text(&self.run(&["hash-object", "-w", "--stdin"], Some(bytes)).await?)
    }

    async fn build_commit(&self, file: &str, content: &[u8], message: &str) -> Result<String> {
        let blob = self.add_blob(content).await?;
        let entry = format!("100644 blob {blob}\t{file}\n");
        let tree = Self::text(&self.run(&["mktree"], Some(entry.as_bytes())).await?)?;
        Self::text(&self.run(&["commit-tree", &tree, "-m", message], None).await?)
    }

    async fn update_ref(&self, name: &str, oid: &str) -> Result<()> {
        self.run(&["update-ref", name, oid], None).await?;
        Ok(())
    }

    fn artifacts_dir(&self) -> Result<PathBuf> {
        let dir = self.bare.parent().ok_or_else(|| anyhow!("fixture repo has no parent"))?.join("artifacts");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    async fn pack_all(&self, name: &str) -> Result<PairFiles> {
        let bytes = self.run(&["pack-objects", "--stdout", "--all"], None).await?;
        ensure!(bytes.starts_with(b"PACK"), "git pack-objects did not produce a pack stream");
        let pack = self.artifacts_dir()?.join(format!("{name}.pack"));
        std::fs::write(&pack, &bytes)?;
        let pack_arg = pack.to_str().ok_or_else(|| anyhow!("fixture pack path is not UTF-8"))?.to_owned();
        self.run(&["index-pack", pack_arg.as_str()], None).await?;
        PairFiles::new(pack, self.artifacts_dir()?.join(format!("{name}.idx")))
    }
}

struct PairFiles {
    pack: PathBuf,
    idx: PathBuf,
}

impl PairFiles {
    fn new(pack: PathBuf, idx: PathBuf) -> Result<Self> {
        ensure!(pack.is_file() && idx.is_file(), "fixture pack/idx file is missing");
        Ok(Self { pack, idx })
    }
}

fn digest_file(path: &Path) -> Result<(String, u64)> {
    let bytes = std::fs::read(path)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}

fn main_update(format: GitObjectFormat, new: &str) -> Result<RefUpdate> {
    Ok(RefUpdate::new(
        RefName::branch("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(format, new)?),
    ))
}

async fn gate_version(pool: &deadpool_postgres::Pool, repo: Uuid, tenant: Uuid) -> Result<CoreGateVersion> {
    let mut client = pool.get().await?;
    match PgRefStoreCore.check_version(&mut client, repo, tenant, None, operation_deadline()).await? {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(version),
        VersionCheck::Unknown => Err(anyhow!("the fixture gate disappeared")),
    }
}

/// One real publish of one real pack with one real ref through the staged
/// authorized pipeline: A3 hold → protected upload → registration →
/// `begin_pending` stages the durable pending operation first; then
/// `PgAuthorizedCommit::{prepare, select, verify, commit}` take the real
/// decision-gated path (and enable the irreversible `decision_required` fence).
/// The committed gate must be `pack_verified`.
async fn commit_first_pack(
    fixture: &Fixture,
    store: &BlobStore,
    tenant: Uuid,
    owner: Uuid,
    repo: Uuid,
    gate: CoreGateVersion,
    git: &Path,
    actor: &crate::db::Identity,
    refs: Vec<RefUpdate>,
    files: &PairFiles,
) -> Result<()> {
    let adapter = PgAuthorizedCommit::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("authorized adapter constructor refused: {error:?}"))?;
    let mut client = fixture.pool.get().await?;
    let baseline = PgPackCommit.capture_baseline(&mut client, repo, tenant, operation_deadline()).await?;
    ensure!(
        baseline.gate().revision() == gate.revision() && baseline.gate().digest() == gate.digest(),
        "captured baseline differs from the expected gate"
    );
    let old_entries = baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?;
    let (pack_sha, pack_len) = digest_file(&files.pack)?;
    let (idx_sha, idx_len) = digest_file(&files.idx)?;
    let planned = vec![PlannedPack::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha.clone())?, pack_len)?,
        PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha.clone())?, idx_len)?,
    )?];
    let scope = PackCommitScope::new(
        repo,
        tenant,
        owner,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let identity = OperationIdentity::new(
        repo,
        actor.id,
        IssuerLane::new("pack")?,
        1,
        Uuid::new_v4(),
        RequestDigest::from_bytes([0; 32]),
    )?;
    let plan = PackCommitPlan::new(
        scope,
        identity,
        PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?,
        HeadUpdate::Keep,
        refs,
        baseline.membership_digest(),
        old_entries,
        planned,
    )?;
    // Stage 0: the durable pending operation precedes every authorized stage.
    let _token: PackPendingToken = PgPackCommit.begin_pending(&mut client, &plan, operation_deadline()).await?;
    drop(client);

    let hold_scope = HoldScope::new(
        plan.repository_id(),
        plan.tenant_id(),
        plan.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    )
    .map_err(|error| anyhow!("hold scope rejected: {error}"))?;
    let request = AcquireArtifactHoldsRequest::new(
        hold_scope,
        plan.identity().clone(),
        Uuid::new_v4(),
        store.backend_identity().clone(),
        Uuid::new_v4(),
        1,
        *plan.expected().gate_digest(),
        vec![
            ArtifactSpec::new(HOLD_NAMESPACE, pack_sha, pack_len)?,
            ArtifactSpec::new(HOLD_NAMESPACE, idx_sha, idx_len)?,
        ],
    )?;
    let mut client = fixture.pool.get().await?;
    let grant = match PgArtifactHoldStore.acquire(&mut client, store, &request, operation_deadline()).await? {
        AcquireOutcome::Granted { grant, .. } => grant,
        AcquireOutcome::Replayed { .. } => return Err(anyhow!("a fresh A3 acquire replayed")),
    };
    drop(client);
    let sources = [UploadSource::new(files.pack.clone()), UploadSource::new(files.idx.clone())];
    let publication = ProtectedUploader::new(store.clone())
        .consume_and_upload(&fixture.pool, grant, &sources, std_deadline())
        .await
        .map_err(|_| anyhow!("protected upload refused"))?;
    ensure!(publication.receipts().len() == 2, "publication is not exactly one pair");
    register(fixture, &plan, &publication).await?;
    // The first publication of a repository is atomic: all-or-nothing.
    ensure!(plan.commit_mode() == CommitMode::Atomic, "the first pack plan is not an atomic publication");
    let mode = match plan.commit_mode() {
        CommitMode::Atomic => AuthorizedCommitMode::Atomic,
        CommitMode::AcceptedSubset => AuthorizedCommitMode::AcceptedSubset,
    };
    // Stage 1: capture the durable pending operation (read-only).
    let prepared: PreparedPublication = match adapter
        .prepare(&fixture.pool, plan.clone(), operation_deadline())
        .await
        .map_err(|error| anyhow!("authorized prepare refused: {error:?}"))?
    {
        PrepareOutcome::Prepared(prepared) => *prepared,
        PrepareOutcome::Replayed(_) => return Err(anyhow!("prepare replayed instead of staging the fresh pending")),
    };
    // Stage 2: the real decision select, as the owner identity.
    let selection: AuthorizedSelection = adapter
        .select(&fixture.pool, prepared, actor, mode, operation_deadline())
        .await
        .map_err(|error| anyhow!("authorized select refused: {error:?}"))?;
    // Stage 3: the native closure proof over the selected plan (no PG client held).
    let verified: VerifiedAuthorizedPublication = adapter
        .verify(selection, operation_deadline())
        .await
        .map_err(|error| anyhow!("authorized verify refused: {error:?}"))?;
    // Stage 4: the decision-gated terminal, enabling the `decision_required` fence.
    let receipt = adapter
        .commit(&fixture.pool, &verified, operation_deadline())
        .await
        .map_err(|error| anyhow!("authorized commit refused: {error:?}"))?;
    ensure!(receipt.is_committed() && !receipt.replayed, "fresh authorized commit did not commit");
    ensure!(
        gate_version(&fixture.pool, repo, tenant).await?.revision() > gate.revision(),
        "the authorized commit must advance the gate revision past {}",
        gate.revision()
    );
    Ok(())
}

async fn register(fixture: &Fixture, plan: &PackCommitPlan, publication: &ProtectedPublication) -> Result<()> {
    let mut client = fixture.pool.get().await?;
    ensure!(plan.packs().len() == 1, "this fixture registers exactly one planned pack");
    let request = PackRegistrationRequest::new(plan, plan.packs()[0].pack_id(), publication)?;
    PgPackCommit.register_publication(&mut client, request, operation_deadline()).await?;
    Ok(())
}

async fn protected_pack_count(fixture: &Fixture, pin_id: Uuid) -> Result<i64> {
    Ok(fixture
        .pool
        .get()
        .await?
        .query_one("SELECT count(*)::bigint FROM ref_store_core_serving_read_packs WHERE pin_id=$1", &[&pin_id])
        .await?
        .get(0))
}

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
    commit_first_pack(
        fixture,
        &store,
        repo.ready.tenant_id,
        repo.ready.owner_id,
        repo.ready.repository_id,
        gate,
        &git,
        owner,
        vec![main_update(format, &commit_oid)?],
        &files,
    )
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
/// `Ok` or an `Err`, before returning the check's own outcome. A panicking
/// `check` never hands the capture back, so no release runs on that path.
///
/// `check` owns the capture for the duration of the window and must hand it
/// back: the released pin is exactly the capture the case checked. The helper
/// only borrows `fixture`, so tearing the fixture down stays with the caller,
/// which owns it.
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
