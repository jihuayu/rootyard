//! Real native-Git/pack publication fixtures for the sealed serving proof.
//!
//! Split out of `contract.rs` so that file stays inside the submodule line
//! bound while the real A3 hold -> protected upload -> registration ->
//! decision-gated commit path stays verbatim.
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use super::serving_support::Fixture;
use crate::blob_store::BlobProvider;
use crate::blob_store::config::BlobProfile;
use crate::blob_store::opendal::BlobStore;
use crate::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use crate::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::{
    AuthorizedCommitMode, AuthorizedSelection, ContentDigest, PackArtifactRole, PackCommitExpectation, PackCommitPlan,
    PackCommitScope, PackMembershipEntry, PackPendingToken, PackRegistrationRequest, PgAuthorizedCommit, PgPackCommit,
    PlannedArtifact, PlannedPack, PrepareOutcome, PreparedPublication, VerifiedAuthorizedPublication,
};
use crate::ref_store::core::{CommitMode, PgRefStoreCore};
use crate::ref_store::{
    CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationIdentity, RefName, RefPrecondition,
    RefTarget, RefUpdate, VersionCheck,
};

pub(super) const LEASE_SECONDS: u32 = 60;
const NATIVE_SECONDS: u64 = 120;
const HOLD_NAMESPACE: &str = "core-pack";

fn std_deadline() -> StdInstant {
    StdInstant::now() + Duration::from_secs(NATIVE_SECONDS)
}

pub(super) fn git_binary() -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()));
    ensure!(path.is_absolute() && path.is_file(), "ROOTYARD_TEST_GIT must be an absolute existing git binary");
    Ok(path)
}

pub(super) fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "the native serving fixture requires the S3 Blob profile");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

/// Owned fixture Git: cleared environment, known author, bounded timeout,
/// synthetic bytes only.
pub(super) struct GitRepo {
    _root: tempfile::TempDir,
    bare: PathBuf,
    home: PathBuf,
    template: PathBuf,
    git: PathBuf,
}

impl GitRepo {
    pub(super) async fn new(git: PathBuf, format: GitObjectFormat) -> Result<Self> {
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

    pub(super) async fn build_commit(&self, file: &str, content: &[u8], message: &str) -> Result<String> {
        let blob = self.add_blob(content).await?;
        let entry = format!("100644 blob {blob}\t{file}\n");
        let tree = Self::text(&self.run(&["mktree"], Some(entry.as_bytes())).await?)?;
        Self::text(&self.run(&["commit-tree", &tree, "-m", message], None).await?)
    }

    pub(super) async fn update_ref(&self, name: &str, oid: &str) -> Result<()> {
        self.run(&["update-ref", name, oid], None).await?;
        Ok(())
    }

    fn artifacts_dir(&self) -> Result<PathBuf> {
        let dir = self.bare.parent().ok_or_else(|| anyhow!("fixture repo has no parent"))?.join("artifacts");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub(super) async fn pack_all(&self, name: &str) -> Result<PairFiles> {
        let bytes = self.run(&["pack-objects", "--stdout", "--all"], None).await?;
        ensure!(bytes.starts_with(b"PACK"), "git pack-objects did not produce a pack stream");
        let pack = self.artifacts_dir()?.join(format!("{name}.pack"));
        std::fs::write(&pack, &bytes)?;
        let pack_arg = pack.to_str().ok_or_else(|| anyhow!("fixture pack path is not UTF-8"))?.to_owned();
        self.run(&["index-pack", pack_arg.as_str()], None).await?;
        PairFiles::new(pack, self.artifacts_dir()?.join(format!("{name}.idx")))
    }
}

pub(super) struct PairFiles {
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

pub(super) fn main_update(format: GitObjectFormat, new: &str) -> Result<RefUpdate> {
    Ok(RefUpdate::new(
        RefName::branch("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(format, new)?),
    ))
}

pub(super) async fn gate_version(pool: &deadpool_postgres::Pool, repo: Uuid, tenant: Uuid) -> Result<CoreGateVersion> {
    let mut client = pool.get().await?;
    match PgRefStoreCore
        .check_version(&mut client, repo, tenant, None, super::serving_reads_support::operation_deadline())
        .await?
    {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(version),
        VersionCheck::Unknown => Err(anyhow!("the fixture gate disappeared")),
    }
}

/// One first-pack fixture bundle. The struct keeps the ten real fixture
/// handles explicit without suppressing Clippy's argument-count lint.
pub(super) struct FirstPackRequest<'a> {
    pub(super) fixture: &'a Fixture,
    pub(super) store: &'a BlobStore,
    pub(super) tenant: Uuid,
    pub(super) owner: Uuid,
    pub(super) repo: Uuid,
    pub(super) gate: CoreGateVersion,
    pub(super) git: &'a Path,
    pub(super) actor: &'a crate::db::Identity,
    pub(super) refs: Vec<RefUpdate>,
    pub(super) files: &'a PairFiles,
}

pub(super) async fn commit_first_pack(request: FirstPackRequest<'_>) -> Result<()> {
    let FirstPackRequest { fixture, store, tenant, owner, repo, gate, git, actor, refs, files } = request;
    let adapter = PgAuthorizedCommit::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("authorized adapter constructor refused: {error:?}"))?;
    let mut client = fixture.pool.get().await?;
    let baseline = PgPackCommit
        .capture_baseline(&mut client, repo, tenant, super::serving_reads_support::operation_deadline())
        .await?;
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
    let _token: PackPendingToken =
        PgPackCommit.begin_pending(&mut client, &plan, super::serving_reads_support::operation_deadline()).await?;
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
    let grant = match PgArtifactHoldStore
        .acquire(&mut client, store, &request, super::serving_reads_support::operation_deadline())
        .await?
    {
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
        .prepare(&fixture.pool, plan.clone(), super::serving_reads_support::operation_deadline())
        .await
        .map_err(|error| anyhow!("authorized prepare refused: {error:?}"))?
    {
        PrepareOutcome::Prepared(prepared) => *prepared,
        PrepareOutcome::Replayed(_) => return Err(anyhow!("prepare replayed instead of staging the fresh pending")),
    };
    // Stage 2: the real decision select, as the owner identity.
    let selection: AuthorizedSelection = adapter
        .select(&fixture.pool, prepared, actor, mode, super::serving_reads_support::operation_deadline())
        .await
        .map_err(|error| anyhow!("authorized select refused: {error:?}"))?;
    // Stage 3: the native closure proof over the selected plan (no PG client held).
    let verified: VerifiedAuthorizedPublication = adapter
        .verify(selection, super::serving_reads_support::operation_deadline())
        .await
        .map_err(|error| anyhow!("authorized verify refused: {error:?}"))?;
    // Stage 4: the decision-gated terminal, enabling the `decision_required` fence.
    let receipt = adapter
        .commit(&fixture.pool, &verified, super::serving_reads_support::operation_deadline())
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
    PgPackCommit.register_publication(&mut client, request, super::serving_reads_support::operation_deadline()).await?;
    Ok(())
}

pub(super) async fn protected_pack_count(fixture: &Fixture, pin_id: Uuid) -> Result<i64> {
    Ok(fixture
        .pool
        .get()
        .await?
        .query_one("SELECT count(*)::bigint FROM ref_store_core_serving_read_packs WHERE pin_id=$1", &[&pin_id])
        .await?
        .get(0))
}
