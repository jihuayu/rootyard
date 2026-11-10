//! Real-PostgreSQL + native Git contract tests for the sealed transient serving
//! read materialization (#174).
//!
//! Every case is `#[ignore]`-gated and drives the *production* builder
//! `PgPackSnapshotMaterializer::materialize_serving_read_sealed` against an
//! actual migrated PostgreSQL schema, the actual production Blob profile and the
//! actual trusted native Git binary. A missing service is a hard failure, never
//! a silent skip: an offline or AST-only pass would prove nothing.
//!
//! The fixture is the same real A4 verified-commit path (artifact hold →
//! protected upload → registration → native verifier proof → verified commit)
//! that `ref_store_materialized_reads.rs` uses, so the pack bytes and refs the
//! serving read downloads are real. The case then flips the gate to
//! `pack_verified` and captures a real migration-146 transient read.
//!
//! What these cases prove:
//!
//! * a non-empty sealed materialization is produced by the production builder,
//!   carries the capture's own gate revision and realm, and carries the **A5b**
//!   materialization digest — not the narrower A5a read digest, which is
//!   deliberately checked to differ — while the verified native view (with its
//!   verified packs) stays alive next to the proof;
//! * a checked empty capture materializes to `Ok(None)` through the sealed
//!   builder too: no bytes, no proof.
//!
//! What they do not prove: that any HTTP response was served. The sealed proof
//! is an internal materialization proof and is not wired to a gateway route.
#![allow(clippy::too_many_arguments)]

use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use rootyard::blob_store::{BlobProvider, ContentDigestBytes};
use rootyard::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::{
    ContentDigest, PackArtifactRole, PackClosureContext, PackClosureProof, PackCommitExpectation, PackCommitPlan,
    PackCommitReceipt, PackCommitScope, PackMembershipEntry, PackPendingToken, PackRegistrationRequest, PackVerifier,
    PgPackCommit, PlannedArtifact, PlannedPack,
};
use rootyard::ref_store::core::pack_snapshot::{PgPackSnapshotMaterializer, PgServingReads};
use rootyard::ref_store::{
    CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationIdentity, RefName, RefPrecondition,
    RefStoreError, RefTarget, RefUpdate, RequestDigest, VersionCheck,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};
use tokio::io::AsyncWriteExt;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

mod serving_reads_support;
mod serving_support;

use serving_reads_support::{ensure_migration_146, force_gate_pack_verified, operation_deadline, provision_ready};
use serving_support::{Fixture, actor};

const LEASE_SECONDS: u32 = 60;
const OP_SECONDS: u64 = 30;
const NATIVE_SECONDS: u64 = 120;
const HOLD_NAMESPACE: &str = "core-pack";

fn deadline() -> TokioInstant {
    TokioInstant::now() + Duration::from_secs(OP_SECONDS)
}

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
    match PgRefStoreCore.check_version(&mut client, repo, tenant, None, deadline()).await? {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(version),
        VersionCheck::Unknown => Err(anyhow!("the fixture gate disappeared")),
    }
}

/// One real A4 verified commit of one real pack with one real ref.
async fn commit_first_pack(
    fixture: &Fixture,
    store: &BlobStore,
    tenant: Uuid,
    repo: Uuid,
    gate: CoreGateVersion,
    format: GitObjectFormat,
    git: &Path,
    refs: Vec<RefUpdate>,
    files: &PairFiles,
) -> Result<()> {
    let mut client = fixture.pool.get().await?;
    let baseline = PgPackCommit.capture_baseline(&mut client, repo, tenant, deadline()).await?;
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
        PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha)?, pack_len)?,
        PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha)?, idx_len)?,
    )?];
    let scope = PackCommitScope::new(
        repo,
        tenant,
        tenant,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let identity = OperationIdentity::new(
        repo,
        tenant,
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
    let token: PackPendingToken = PgPackCommit.begin_pending(&mut client, &plan, deadline()).await?;
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
    let grant = match PgArtifactHoldStore.acquire(&mut client, store, &request, deadline()).await? {
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
    let context: PackClosureContext = {
        let mut client = fixture.pool.get().await?;
        PgPackCommit.capture_context(&mut client, &plan, deadline()).await?
    };
    ensure!(context.new_packs().len() == 1 && context.old_packs().is_empty(), "first closure is not one new pack");
    let proof: PackClosureProof =
        PackVerifier::new(store.clone(), git.to_path_buf())?.verify(&plan, &context, std_deadline()).await?;
    let mut client = fixture.pool.get().await?;
    let receipt: PackCommitReceipt =
        PgPackCommit.commit_verified_pending(&mut client, &plan, &token, &proof, deadline()).await?;
    drop(client);
    ensure!(receipt.is_committed() && !receipt.replayed, "fresh verified commit did not commit");
    Ok(())
}

async fn register(fixture: &Fixture, plan: &PackCommitPlan, publication: &ProtectedPublication) -> Result<()> {
    let mut client = fixture.pool.get().await?;
    let request = PackRegistrationRequest::new(plan, publication)?;
    PgPackCommit.register_publication(&mut client, request, deadline()).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL, the production Blob profile and native git"]
async fn sealed_materialization_carries_a5b_binding_and_keeps_the_native_view() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outcome = async {
        ensure_migration_146(&fixture).await?;
        let owner = actor(&fixture.pool, false).await?;
        let repo = provision_ready(&fixture, &owner.identity, "serving-proof-native").await?;
        let store = open_store()?;
        let format = repo.ready.object_format;
        let git = git_binary()?;
        let source = GitRepo::new(git.clone(), format).await?;
        let commit_oid = source.build_commit("file.txt", b"serving proof fixture\n", "serving proof main").await?;
        source.update_ref("refs/heads/main", &commit_oid).await?;
        let files = source.pack_all("first").await?;
        let gate = gate_version(&fixture.pool, repo.ready.repository_id, repo.ready.tenant_id).await?;
        commit_first_pack(
            &fixture,
            &store,
            repo.ready.tenant_id,
            repo.ready.repository_id,
            gate,
            format,
            &git,
            vec![main_update(format, &commit_oid)?],
            &files,
        )
        .await?;
        force_gate_pack_verified(&fixture, repo.ready.repository_id).await?;

        let scope = repo.ready.scope()?;
        let reads = PgServingReads;
        let capture = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await?;
        ensure!(!capture.is_empty(), "a pack_verified gate with one registered pack must not capture as empty");
        let materializer: PgPackSnapshotMaterializer = repo.materializer()?;
        let sealed = materializer.materialize_serving_read_sealed(&fixture.pool, &capture, operation_deadline()).await;
        let sealed = match sealed {
            Ok(Some(sealed)) => sealed,
            Ok(None) => return Err(anyhow!("non-empty capture sealed to Ok(None)")),
            Err(error) => return Err(anyhow!("the production sealed builder refused a real capture: {error}")),
        };
        let view = sealed.view();
        let (proof_revision, proven, proof_binding, a5a_probe) = sealed.contract_parts();
        let (_, binding) = capture.registered_parts()?;
        let expected_packs: i64 = fixture
            .pool
            .get()
            .await?
            .query_one(
                "SELECT count(*)::bigint FROM ref_store_core_serving_read_packs WHERE repository_id=$1",
                &[&repo.ready.repository_id],
            )
            .await?
            .get(0);
        ensure!(expected_packs > 0, "the capture must register at least one pack");
        ensure!(view.pack_count() == expected_packs, "the sealed view must expose every captured pack");
        ensure!(view.verified_pairs() == 1, "the sealed view must cover one native-verified pair");
        ensure!(
            proof_revision == view.gate_revision() && proof_revision > repo.ready.gate_revision,
            "the proof must state the captured (post force) gate revision"
        );
        ensure!(proof_binding == binding, "the proof must carry the capture's A5b binding");
        ensure!(
            a5a_probe.as_hex() != proof_binding.as_hex() && a5a_probe.as_hex() == view.read_digest_hex(),
            "the A5a read digest must never be mistaken for the A5b binding"
        );
        ensure!(
            proven.contract_tenant_id() == repo.ready.tenant_id
                && proven.contract_repository_id() == repo.ready.repository_id
                && proven.contract_object_format() == format
                && proven.contract_history_incarnation() == repo.ready.history_incarnation
                && proven.contract_authority_epoch() == repo.ready.authority_epoch
                && proven.contract_group_epoch() == repo.ready.group_epoch,
            "the proof realm must be the capture realm"
        );
        ensure!(view.verified_read_scope(&binding).is_some(), "the view must prove the same A5b binding");
        reads.release(&fixture.pool, &capture, operation_deadline()).await?;
        Ok(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}

/// Names the production Blob profile's root prefix to this case alone. The guard
/// restores the previous value (and the parent copy on fork) on exit; the empty
/// case below downloads nothing.
struct BlobRootIsolation(Option<std::ffi::OsString>);

impl BlobRootIsolation {
    fn new() -> Self {
        let previous = std::env::var_os("ROOTYARD_BLOB_ROOT");
        // SAFETY: the provisioned identity and the materializer both read this
        // same value, and nothing else in this file writes it.
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

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the production Blob profile"]
async fn sealed_materialization_returns_none_for_a_checked_empty_capture() -> Result<()> {
    let _blob_root = BlobRootIsolation::new();
    let fixture = Fixture::new().await?;
    let outcome = async {
        ensure_migration_146(&fixture).await?;
        let owner = actor(&fixture.pool, false).await?;
        let repo = provision_ready(&fixture, &owner.identity, "serving-proof-empty").await?;
        let scope = repo.ready.scope()?;
        let reads = PgServingReads;
        let capture = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await?;
        ensure!(capture.is_empty(), "a metadata_only repository must capture as empty");
        let materializer: PgPackSnapshotMaterializer = repo.materializer()?;
        let sealed = materializer.materialize_serving_read_sealed(&fixture.pool, &capture, operation_deadline()).await;
        match sealed {
            Ok(None) => {}
            Ok(Some(_)) => return Err(anyhow!("an empty capture must never seal a proof")),
            Err(RefStoreError::Unsupported(reason)) => {
                return Err(anyhow!("an empty capture must seal to Ok(None), not a refusal: {reason}"));
            }
            Err(error) => return Err(anyhow!("an empty capture must seal to Ok(None): {error}")),
        }
        reads.release(&fixture.pool, &capture, operation_deadline()).await?;
        Ok(())
    }
    .await;
    fixture.teardown().await?;
    outcome
}
