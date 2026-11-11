//! A5b (`#105`/`#107`) materialized Git ReadSnapshot integration tests.
//!
//! Every case requires *actual* explicit PostgreSQL, *actual* S3-compatible
//! object storage and the *actual* trusted native Git binary. There is no
//! optional skip and no early `Ok(())`: a missing service is a hard failure,
//! because a fake pass would prove nothing about the A5b contract. All cases are
//! `#[ignore]`-gated so a plain `cargo test` never pretends to have run them.
//!
//! Fixture helpers are copied from `tests/ref_store_pack_snapshots.rs` (the A5a
//! suite stays byte-identical), plus three A5b-only builders:
//!
//! * `GitGate` — an owned fault wrapper that is installed as the *materializer's*
//!   trusted Git binary. It gates the FIRST real Git invocation of one native
//!   read materialization and then `exec`s the actual trusted Git binary, so it
//!   can never fabricate closure evidence: it only delays real Git.
//! * `S3Fault` — a signed fixture-only S3 DELETE/PUT used to remove or corrupt
//!   one freshly registered pack object after A4 committed it. The bucket must
//!   allow fixture overwrite/delete (see `docs/opendal-blob.md`).
//! * `SERIAL` — one file-wide async mutex, because the A5b view budget and the
//!   native verification semaphore are process-wide: capacity cases must not
//!   race the other cases in this binary.
//!
//! No PASS is claimed by this file; the Root runner executes it.
#![allow(clippy::too_many_arguments)]

use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::{Manager, Pool};
use hmac::{Hmac, Mac};
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use rootyard::blob_store::{BlobLocator, BlobProvider};
use rootyard::db;
use rootyard::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::{
    ContentDigest, PackArtifactRole, PackClosureContext, PackClosureProof, PackCommitError, PackCommitExpectation,
    PackCommitPlan, PackCommitReceipt, PackCommitScope, PackMembershipEntry, PackPendingToken, PackRegistrationRequest,
    PackVerifier, PgPackCommit, PlannedArtifact, PlannedPack, RegisteredPack,
};
use rootyard::ref_store::core::pack_snapshot::{MaterializedPackRead, PgPackSnapshotMaterializer};
use rootyard::ref_store::core::{
    CreatePackSnapshotRequest, MetadataPinOutcome, MetadataSnapshotScope, PackSnapshotExpectation, PackSnapshotOutcome,
    PackSnapshotRef, PgPackSnapshot, PgRefStoreCore, ReleaseMetadataPinRequest, RenewMetadataPinRequest,
};
use rootyard::ref_store::{
    CoreGateInit, CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataPinPurpose,
    OperationIdentity, PinReleaseReason, RefName, RefPrecondition, RefStoreError, RefTarget, RefUpdate, RequestDigest,
    VersionCheck,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant, SystemTime};
use tokio::io::AsyncWriteExt;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

/// One operation deadline for typed SQL calls outside the materialized read.
const OP_SECONDS: u64 = 30;
/// Fixture Git timeout for the trusted binary the test itself drives.
const GIT_SECONDS: u64 = 60;
/// Artifact-hold namespace used by the A4 publication fixture.
const HOLD_NAMESPACE: &str = "core-pack";
/// The single file-wide capacity/ordering guard (see module docs).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn deadline() -> TokioInstant {
    TokioInstant::now() + Duration::from_secs(OP_SECONDS)
}
fn std_deadline() -> StdInstant {
    StdInstant::now() + Duration::from_secs(OP_SECONDS)
}
fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set for ref_store_materialized_reads")
}
fn git_binary() -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()));
    ensure!(path.is_absolute() && path.is_file(), "ROOTYARD_TEST_GIT must be an absolute existing git binary");
    Ok(path)
}
/// The configured profile must be real S3; a missing/invalid profile is a hard
/// failure.
fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}
/// Open the same configured S3 endpoint/credentials with a DIFFERENT root
/// prefix: a real, distinct physical backend identity that cannot serve the
/// artifacts this schema registered.
fn store_with_root(root: &str) -> Result<BlobStore> {
    let previous = std::env::var_os("ROOTYARD_BLOB_ROOT");
    // SAFETY: the whole file holds `SERIAL`, so no case in this binary observes
    // the temporary environment change; the previous value is restored before
    // returning either way.
    unsafe { std::env::set_var("ROOTYARD_BLOB_ROOT", root) };
    let opened = open_store();
    match previous {
        Some(value) => unsafe { std::env::set_var("ROOTYARD_BLOB_ROOT", value) },
        None => unsafe { std::env::remove_var("ROOTYARD_BLOB_ROOT") },
    }
    opened
}
fn is_executable(path: &Path) -> bool {
    path.metadata().map(|meta| meta.is_file() && meta.permissions().mode() & 0o100 != 0).unwrap_or(false)
}
fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn pool_for(url: &str, schema: &str, max: usize) -> Result<Pool> {
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"));
    Ok(Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(max)
        .build()?)
}

/// One random schema, real `db::migrate` (migration 143 asserted), real pools.
struct Db {
    admin: Pool,
    pool: Pool,
    url: String,
    schema: String,
}
impl Db {
    async fn setup() -> Result<Self> {
        let url = database_url();
        let admin = db::pool(&url)?;
        let schema = format!("ref_store_materialized_reads_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let pool = pool_for(&url, &schema, 16)?;
        db::migrate(&pool).await?;
        let client = pool.get().await?;
        let installed: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=143)
                    AND to_regclass('ref_store_core_pack_snapshot_history') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        ensure!(installed, "db::migrate did not install migration 143");
        drop(client);
        Ok(Self { admin, pool, url, schema })
    }
    fn new_pool(&self, max: usize) -> Result<Pool> {
        pool_for(&self.url, &self.schema, max)
    }
    async fn teardown(&self) -> Result<()> {
        self.admin.get().await?.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema)).await?;
        Ok(())
    }
    async fn finish(&self, outcome: Result<()>) -> Result<()> {
        match outcome {
            Ok(()) => self.teardown().await,
            Err(error) => {
                let _ = self.teardown().await;
                Err(error)
            }
        }
    }
    /// One trusted user (also tenant/repository owner) and one unserved repo.
    async fn business(&self, format: GitObjectFormat) -> Result<(Uuid, Uuid)> {
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO users(id,username) VALUES($1,$2)",
                &[&tenant, &format!("a5b{}", &tenant.simple().to_string()[..10])],
            )
            .await?;
        client
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,object_format)
                 VALUES($1,$2,$3,'provisioning',$4)",
                &[&repo, &tenant, &format!("repo{}", &repo.simple().to_string()[..10]), &format.as_str()],
            )
            .await?;
        drop(client);
        Ok((tenant, repo))
    }
    async fn gate(&self, repo: Uuid, tenant: Uuid, format: GitObjectFormat) -> Result<CoreGateVersion> {
        let init = CoreGateInit::new(repo, tenant, format, Uuid::new_v4(), 1, 1, RefName::branch("refs/heads/main")?)?;
        let mut client = self.pool.get().await?;
        Ok(PgRefStoreCore.initialize(&mut client, &init, deadline()).await?.version())
    }
}
async fn gate_version(pool: &Pool, repo: Uuid, tenant: Uuid) -> Result<CoreGateVersion> {
    let mut client = pool.get().await?;
    match PgRefStoreCore.check_version(&mut client, repo, tenant, None, deadline()).await? {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(version),
        VersionCheck::Unknown => Err(anyhow!("gate disappeared")),
    }
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
        let output = tokio::time::timeout(Duration::from_secs(GIT_SECONDS), child.wait_with_output())
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
struct Draft {
    plan: PackCommitPlan,
    token: PackPendingToken,
}
fn main_update(format: GitObjectFormat, old: Option<&str>, new: &str) -> Result<RefUpdate> {
    let precondition = match old {
        Some(value) => RefPrecondition::Present(GitOid::parse(format, value)?),
        None => RefPrecondition::Absent,
    };
    Ok(RefUpdate::new(RefName::branch("refs/heads/main")?, precondition, RefTarget::Oid(GitOid::parse(format, new)?)))
}
async fn draft(
    db: &Db,
    repo: Uuid,
    tenant: Uuid,
    sequence: i64,
    gate: &CoreGateVersion,
    refs: Vec<RefUpdate>,
    files: &[PairFiles],
) -> Result<Draft> {
    let mut client = db.pool.get().await?;
    let baseline = PgPackCommit.capture_baseline(&mut client, repo, tenant, deadline()).await?;
    ensure!(
        baseline.gate().revision() == gate.revision() && baseline.gate().digest() == gate.digest(),
        "captured baseline differs from expected gate"
    );
    let old_entries = baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?;
    let mut planned = Vec::with_capacity(files.len());
    for file in files {
        let (pack_sha, pack_len) = digest_file(&file.pack)?;
        let (idx_sha, idx_len) = digest_file(&file.idx)?;
        planned.push(PlannedPack::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha)?, pack_len)?,
            PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha)?, idx_len)?,
        )?);
    }
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
        sequence,
        Uuid::new_v4(),
        RequestDigest::from_bytes([0; 32]),
    )?;
    let expectation = PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?;
    let plan = PackCommitPlan::new(
        scope,
        identity,
        expectation,
        HeadUpdate::Keep,
        refs,
        baseline.membership_digest(),
        old_entries,
        planned,
    )?;
    let token = PgPackCommit.begin_pending(&mut client, &plan, deadline()).await?;
    drop(client);
    Ok(Draft { plan, token })
}
fn hold_scope(plan: &PackCommitPlan) -> Result<HoldScope> {
    HoldScope::new(
        plan.repository_id(),
        plan.tenant_id(),
        plan.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    )
    .map_err(|error| anyhow!("hold scope rejected: {error}"))
}
async fn publish(db: &Db, store: &BlobStore, plan: &PackCommitPlan, file: &PairFiles) -> Result<ProtectedPublication> {
    let (pack_sha, pack_len) = digest_file(&file.pack)?;
    let (idx_sha, idx_len) = digest_file(&file.idx)?;
    let request = AcquireArtifactHoldsRequest::new(
        hold_scope(plan)?,
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
    let grant = {
        let mut client = db.pool.get().await?;
        match PgArtifactHoldStore.acquire(&mut client, store, &request, deadline()).await? {
            AcquireOutcome::Granted { grant, .. } => grant,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh A3 acquire replayed")),
        }
    };
    let uploader = ProtectedUploader::new(store.clone());
    let sources = [UploadSource::new(file.pack.clone()), UploadSource::new(file.idx.clone())];
    let publication = uploader
        .consume_and_upload(&db.pool, grant, &sources, std_deadline())
        .await
        .map_err(|_| anyhow!("protected upload refused"))?;
    ensure!(publication.receipts().len() == 2, "publication is not exactly one pair");
    Ok(publication)
}
async fn register(db: &Db, plan: &PackCommitPlan, pack_id: Uuid, publication: &ProtectedPublication) -> Result<()> {
    let mut client = db.pool.get().await?;
    let request = PackRegistrationRequest::new(plan, pack_id, publication)?;
    PgPackCommit.register_publication(&mut client, request, deadline()).await?;
    Ok(())
}
async fn closure(db: &Db, plan: &PackCommitPlan) -> Result<PackClosureContext> {
    let mut client = db.pool.get().await?;
    Ok(PgPackCommit.capture_context(&mut client, plan, deadline()).await?)
}
async fn prove(
    store: &BlobStore,
    git: &Path,
    plan: &PackCommitPlan,
    context: &PackClosureContext,
) -> Result<PackClosureProof> {
    Ok(PackVerifier::new(store.clone(), git.to_path_buf())?.verify(plan, context, std_deadline()).await?)
}
async fn commit(
    db: &Db,
    plan: &PackCommitPlan,
    token: &PackPendingToken,
    proof: &PackClosureProof,
) -> Result<PackCommitReceipt> {
    let mut client = db.pool.get().await?;
    Ok(PgPackCommit.commit_verified_pending(&mut client, plan, token, proof, deadline()).await?)
}
struct Verified {
    tenant: Uuid,
    repo: Uuid,
    gate: CoreGateVersion,
    fixture: GitRepo,
    commit_oid: String,
    new_packs: Vec<RegisteredPack>,
}
/// Real first A4 verified commit: one fresh pack, one real proof, real commit.
async fn commit_first_pack(
    db: &Db,
    store: &BlobStore,
    tenant: Uuid,
    repo: Uuid,
    gate: CoreGateVersion,
    format: GitObjectFormat,
    git: &Path,
    refs: Vec<RefUpdate>,
    files: &PairFiles,
    commit_oid: String,
    fixture: GitRepo,
) -> Result<Verified> {
    let draft = draft(db, repo, tenant, 1, &gate, refs, std::slice::from_ref(files)).await?;
    let publication = publish(db, store, &draft.plan, files).await?;
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    register(db, &draft.plan, pack_id, &publication).await?;
    let context = closure(db, &draft.plan).await?;
    ensure!(context.new_packs().len() == 1 && context.old_packs().is_empty(), "first closure is not one new pack");
    let proof = prove(store, git, &draft.plan, &context).await?;
    let receipt = commit(db, &draft.plan, &draft.token, &proof).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "fresh verified commit did not commit");
    let gate = gate_version(&db.pool, repo, tenant).await?;
    ensure!(
        gate.revision() == receipt.terminal.revision && gate.object_format() == format,
        "gate after commit differs"
    );
    let new_packs = context.new_packs().to_vec();
    Ok(Verified { tenant, repo, gate, fixture, commit_oid, new_packs })
}
async fn verify_existing(
    db: &Db,
    store: &BlobStore,
    git: &Path,
    tenant: Uuid,
    repo: Uuid,
    gate: CoreGateVersion,
    format: GitObjectFormat,
) -> Result<Verified> {
    let fixture = GitRepo::new(git.to_path_buf(), format).await?;
    let commit_oid = fixture.build_commit("file.txt", b"materialized read fixture\n", "fixture main").await?;
    fixture.update_ref("refs/heads/main", &commit_oid).await?;
    let files = fixture.pack_all("first").await?;
    let refs = vec![main_update(format, None, &commit_oid)?];
    commit_first_pack(db, store, tenant, repo, gate, format, git, refs, &files, commit_oid, fixture).await
}
async fn verify_new(db: &Db, store: &BlobStore, git: &Path, format: GitObjectFormat) -> Result<Verified> {
    let (tenant, repo) = db.business(format).await?;
    let gate = db.gate(repo, tenant, format).await?;
    verify_existing(db, store, git, tenant, repo, gate, format).await
}
/// Real second A4 verified commit: advances the gate, adds one pack, moves main.
async fn verify_advance(
    db: &Db,
    store: &BlobStore,
    verified: &mut Verified,
    sequence: i64,
    content: &[u8],
) -> Result<Vec<RegisteredPack>> {
    let format = verified.gate.object_format();
    let oid = verified.fixture.build_commit("advance.txt", content, "fixture advance").await?;
    verified.fixture.update_ref("refs/heads/main", &oid).await?;
    let files = verified.fixture.pack_all("advance").await?;
    let old = verified.commit_oid.clone();
    let refs = vec![main_update(format, Some(&old), &oid)?];
    let draft =
        draft(db, verified.repo, verified.tenant, sequence, &verified.gate, refs, std::slice::from_ref(&files)).await?;
    let publication = publish(db, store, &draft.plan, &files).await?;
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    register(db, &draft.plan, pack_id, &publication).await?;
    let context = closure(db, &draft.plan).await?;
    ensure!(
        context.new_packs().len() == 1 && context.old_packs().len() == 1,
        "second closure is not one new/one old pack"
    );
    let proof = prove(store, &verified.fixture.git.clone(), &draft.plan, &context).await?;
    let receipt = commit(db, &draft.plan, &draft.token, &proof).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "second verified commit did not commit");
    let packs = context.new_packs().to_vec();
    verified.commit_oid = oid;
    verified.gate = gate_version(&db.pool, verified.repo, verified.tenant).await?;
    verified.new_packs = packs.clone();
    ensure!(verified.gate.revision() == receipt.terminal.revision, "advanced gate revision differs");
    Ok(packs)
}
fn assert_pack_identity(expected: &RegisteredPack, actual: &RegisteredPack) -> Result<()> {
    ensure!(expected.pack_id() == actual.pack_id(), "pack id differs");
    ensure!(expected.registration_id() == actual.registration_id(), "registration id differs");
    ensure!(
        expected.artifact_set_digest().as_hex() == actual.artifact_set_digest().as_hex(),
        "artifact-set digest differs"
    );
    ensure!(expected.artifacts().len() == actual.artifacts().len(), "artifact count differs");
    for role in [PackArtifactRole::Pack, PackArtifactRole::Idx] {
        let (e, a) = (expected.artifact(role), actual.artifact(role));
        ensure!(e.slot() == a.slot() && e.hold_id() == a.hold_id(), "artifact slot/hold differs");
        ensure!(
            e.provider() == a.provider() && e.backend_identity() == a.backend_identity(),
            "artifact backend differs"
        );
        ensure!(
            e.verified_sha256() == a.verified_sha256() && e.verified_length() == a.verified_length(),
            "verified digest differs"
        );
        let (el, al) = (e.locator(), a.locator());
        ensure!(
            el.tenant_id() == al.tenant_id()
                && el.authority_id() == al.authority_id()
                && el.authority_generation() == al.authority_generation()
                && el.attempt_id() == al.attempt_id()
                && el.namespace() == al.namespace()
                && el.sha256() == al.sha256()
                && el.length() == al.length(),
            "physical locator differs"
        );
    }
    Ok(())
}
fn scope_for(
    repo: Uuid,
    tenant: Uuid,
    owner: Uuid,
    gate: &CoreGateVersion,
    purpose: MetadataPinPurpose,
) -> Result<MetadataSnapshotScope> {
    Ok(MetadataSnapshotScope::new(
        repo,
        tenant,
        owner,
        purpose,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?)
}
fn a5_request(
    scope: MetadataSnapshotScope,
    gate: &CoreGateVersion,
    lease: i64,
) -> Result<(CreatePackSnapshotRequest, Uuid, Uuid, Uuid)> {
    let request_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let pin_id = Uuid::new_v4();
    let expected = PackSnapshotExpectation::new(gate.revision(), *gate.digest())?;
    Ok((
        CreatePackSnapshotRequest::new(scope, request_id, pin_id, snapshot_id, lease, expected)?,
        request_id,
        snapshot_id,
        pin_id,
    ))
}
async fn a5_create(pool: &Pool, request: &CreatePackSnapshotRequest) -> Result<PackSnapshotOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgPackSnapshot.create(&mut client, request, deadline()).await
}
fn pool_error(error: deadpool_postgres::PoolError) -> RefStoreError {
    RefStoreError::Database(error.to_string())
}
async fn a2_renew(pool: &Pool, request: &RenewMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.renew_metadata_pin(&mut client, request, deadline()).await
}
async fn a2_release(pool: &Pool, request: &ReleaseMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.release_metadata_pin(&mut client, request, deadline()).await
}
/// Owned fault wrapper installed as the materializer's trusted Git binary.
///
/// It gates exactly ONE real invocation (the first one) and then `exec`s the
/// actual trusted binary with the original argv, so every piece of native
/// closure evidence is still produced by real Git. Nothing here can fabricate a
/// ref, a pack or an fsck result: it only delays real Git.
struct GitGate {
    dir: tempfile::TempDir,
}
impl GitGate {
    fn new(real_git: &Path) -> Result<Self> {
        ensure!(real_git.is_absolute(), "trusted git must be an absolute path");
        let dir = tempfile::tempdir()?;
        let script = dir.path().join("git-gate");
        let body = format!(
            "#!/bin/sh\n\
             set -eu\n\
             if [ ! -e '{mark}' ]; then\n\
             \x20 : > '{ready}'\n\
             \x20 S=/bin/sleep\n\
             \x20 [ -x \"$S\" ] || S=/usr/bin/sleep\n\
             \x20 while [ ! -e '{release}' ]; do \"$S\" 0.02 || :; done\n\
             \x20 : > '{mark}'\n\
             fi\n\
             exec '{real}' \"$@\"\n",
            mark = dir.path().join("gated").display(),
            ready = dir.path().join("ready").display(),
            release = dir.path().join("release").display(),
            real = real_git.display(),
        );
        std::fs::write(&script, body)?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
        ensure!(is_executable(&script), "the fault Git wrapper is not owner-executable");
        Ok(Self { dir })
    }
    fn binary(&self) -> PathBuf {
        self.dir.path().join("git-gate")
    }
    fn materializer(&self, store: &BlobStore) -> Result<PgPackSnapshotMaterializer> {
        Ok(PgPackSnapshotMaterializer::new(store.clone(), self.binary())?)
    }
    async fn wait_ready(&self) -> Result<()> {
        let ready = self.dir.path().join("ready");
        tokio::time::timeout(Duration::from_secs(20), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| anyhow!("materialization never reached its first real native Git step"))?;
        Ok(())
    }
    fn release(&self) -> Result<()> {
        std::fs::write(self.dir.path().join("release"), b"go")?;
        Ok(())
    }
    /// Exact marker path of the gated FIRST real Git invocation. Its absence
    /// proves no native child was ever executed through this wrapper.
    fn ready_marker(&self) -> PathBuf {
        self.dir.path().join("ready")
    }
    fn is_ready(&self) -> bool {
        self.ready_marker().exists()
    }
}
/// Releases the fault gate on ANY exit path (including an early `?`), so a
/// failing fixture mutation can never leave the gated real Git blocked.
struct GateRelease<'a>(&'a GitGate);
impl Drop for GateRelease<'_> {
    fn drop(&mut self) {
        let _ = self.0.release();
    }
}
/// Releases an async fixture hold (for example a pooled observer connection)
/// on ANY exit path, so a failed assertion cannot leave a future waiting on it.
struct OneshotRelease(Option<tokio::sync::oneshot::Sender<()>>);
impl OneshotRelease {
    fn new(sender: tokio::sync::oneshot::Sender<()>) -> Self {
        Self(Some(sender))
    }
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for OneshotRelease {
    fn drop(&mut self) {
        self.release();
    }
}
/// One materialized read of one exact snapshot reference.
async fn materialize(
    materializer: &PgPackSnapshotMaterializer,
    pool: &Pool,
    repo: Uuid,
    tenant: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    generation: i64,
    deadline: TokioInstant,
) -> Result<MaterializedPackRead, RefStoreError> {
    let reference = PackSnapshotRef::new(repo, tenant, snapshot_id, pin_id, generation)?;
    materializer.read(pool, &reference, deadline).await
}
/// The exact physical locator of one registered artifact.
fn pack_locator(pack: &RegisteredPack, role: PackArtifactRole) -> Result<BlobLocator> {
    pack.artifact(role).locator().blob_locator().map_err(|_| anyhow!("registered locator was rejected"))
}
/// Fixture-only signed S3 access used to remove or corrupt ONE freshly
/// registered pack object, so A5b fail-closed paths are exercised against the
/// *actual* provider instead of a mocked store. The fixture bucket must permit
/// fixture-only overwrite/delete (see `docs/opendal-blob.md`), and only locators
/// from this test's own random schema are touched.
struct S3Fault {
    endpoint: String,
    bucket: String,
    root: String,
    region: String,
    access: String,
    secret: String,
    token: Option<String>,
    client: reqwest::Client,
}
impl S3Fault {
    fn from_env() -> Result<Self> {
        let endpoint = std::env::var("ROOTYARD_BLOB_ENDPOINT")
            .map_err(|_| anyhow!("ROOTYARD_BLOB_ENDPOINT is required by the S3 fault fixture"))?;
        let bucket = std::env::var("ROOTYARD_BLOB_BUCKET")
            .map_err(|_| anyhow!("ROOTYARD_BLOB_BUCKET is required by the S3 fault fixture"))?;
        let root = std::env::var("ROOTYARD_BLOB_ROOT").unwrap_or_default();
        let region = std::env::var("ROOTYARD_BLOB_REGION").unwrap_or_else(|_| "us-east-1".to_owned());
        let access = std::env::var("ROOTYARD_BLOB_ACCESS_KEY_ID")
            .map_err(|_| anyhow!("ROOTYARD_BLOB_ACCESS_KEY_ID is required by the S3 fault fixture"))?;
        let secret = std::env::var("ROOTYARD_BLOB_SECRET_ACCESS_KEY")
            .map_err(|_| anyhow!("ROOTYARD_BLOB_SECRET_ACCESS_KEY is required by the S3 fault fixture"))?;
        let token = std::env::var("ROOTYARD_BLOB_SESSION_TOKEN").ok();
        let _ = rustls::crypto::ring::default_provider().install_default();
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            bucket,
            root,
            region,
            access,
            secret,
            token,
            client: reqwest::Client::new(),
        })
    }
    /// Physical object key under this profile's root prefix.
    fn key(&self, locator: &BlobLocator) -> String {
        if self.root.is_empty() {
            locator.path()
        } else {
            format!("{}/{}", self.root.trim_matches('/'), locator.path())
        }
    }
    /// Remove exactly one object; a non-success answer is a hard failure.
    async fn delete(&self, locator: &BlobLocator) -> Result<()> {
        self.send(reqwest::Method::DELETE, &self.key(locator), &[]).await
    }
    /// Replace exactly one object's bytes (same path, same length, other bytes).
    async fn overwrite(&self, locator: &BlobLocator, body: &[u8]) -> Result<()> {
        self.send(reqwest::Method::PUT, &self.key(locator), body).await
    }
    async fn send(&self, method: reqwest::Method, key: &str, body: &[u8]) -> Result<()> {
        let host = self
            .endpoint
            .split_once("://")
            .map(|(_, rest)| rest.trim_end_matches('/').to_owned())
            .ok_or_else(|| anyhow!("ROOTYARD_BLOB_ENDPOINT must be an origin"))?;
        let encoded = encode_s3_path(&format!("/{}/{key}", self.bucket));
        let url = format!("{}{encoded}", self.endpoint);
        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let (amz_date, date) = amz_timestamps(now);
        let payload_hash = hex::encode(Sha256::digest(body));
        let mut signed_headers: Vec<(&str, String)> =
            vec![("host", host), ("x-amz-content-sha256", payload_hash.clone()), ("x-amz-date", amz_date.clone())];
        if let Some(token) = &self.token {
            signed_headers.push(("x-amz-security-token", token.clone()));
        }
        signed_headers.sort();
        let canonical_headers =
            signed_headers.iter().map(|(name, value)| format!("{name}:{value}\n")).collect::<String>();
        let names = signed_headers.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(";");
        let canonical_request =
            format!("{}\n{encoded}\n\n{canonical_headers}\n{names}\n{payload_hash}", method.as_str());
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let signing = hmac_sha256(
            &hmac_sha256(
                &hmac_sha256(
                    &hmac_sha256(format!("AWS4{}", self.secret).as_bytes(), date.as_bytes()),
                    self.region.as_bytes(),
                ),
                b"s3",
            ),
            b"aws4_request",
        );
        let signature = hex::encode(hmac_sha256(&signing, to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
            self.access
        );
        let mut request = self
            .client
            .request(method, url.as_str())
            .header("x-amz-content-sha256", &payload_hash)
            .header("x-amz-date", &amz_date)
            .header("authorization", authorization);
        if let Some(token) = &self.token {
            request = request.header("x-amz-security-token", token);
        }
        if !body.is_empty() {
            request = request.body(body.to_vec());
        }
        let response = request.send().await.map_err(|error| anyhow!("S3 fault request failed: {error}"))?;
        let status = response.status();
        ensure!(
            status.is_success(),
            "S3 fault request to key `{key}` was answered with {status} (the fixture bucket must allow fixture-only overwrite/delete and use path-style access)"
        );
        Ok(())
    }
}
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
/// Percent-encode one S3 object path, keeping `/` as a separator.
fn encode_s3_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => encoded.push(byte as char),
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}
/// `(yyyyMMdd'T'HHMMSS'Z', yyyyMMdd)` in UTC, as SigV4 requires.
fn amz_timestamps(epoch_secs: u64) -> (String, String) {
    let (year, month, day, seconds) = civil_from_epoch(epoch_secs);
    let date = format!("{year:04}{month:02}{day:02}");
    let stamp = format!("{date}T{:02}{:02}{:02}Z", seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    (stamp, date)
}
fn civil_from_epoch(epoch_secs: u64) -> (i64, u32, u32, u64) {
    let days = (epoch_secs / 86_400) as i64;
    let seconds = epoch_secs % 86_400;
    let shifted = days + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 } as u32;
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day, seconds)
}
/// CASES, most meaningful first.
///
/// SHA-1: one complete materialized view with the exact local pack/idx bytes,
/// then a real second A4 commit and a materialized read of the PINNED older
/// revision in the same realm.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn sha1_complete_view_exact_local_bytes_and_pinned_older_revision() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let first_pack_bytes = std::fs::read(v.fixture.artifacts_dir()?.join("first.pack"))?;
        let first_idx_bytes = std::fs::read(v.fixture.artifacts_dir()?.join("first.idx"))?;
        let first_rev = v.gate.revision();
        let first_oid = v.commit_oid.clone();
        let first_pack = v.new_packs[0].clone();
        let producer = Uuid::new_v4();
        db.pool
            .get()
            .await?
            .execute(
                "INSERT INTO users(id,username) VALUES($1,$2)",
                &[&producer, &format!("producer{}", &producer.simple().to_string()[..8])],
            )
            .await?;
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (request, request_id, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        let created = a5_create(&db.pool, &request).await?;
        ensure!(!created.replayed && created.receipt.snapshot_id() == snapshot_id, "fresh pack snapshot differs");
        ensure!(created.receipt.request_id() == request_id && created.receipt.pin_id() == pin_id, "ids differ");
        let materializer = PgPackSnapshotMaterializer::new(store.clone(), git.clone())?;
        let view = materialize(&materializer, &db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1, deadline()).await?;
        ensure!(view.complete_git_read_snapshot(), "materialized view is not complete");
        ensure!(
            view.complete_registered_pack_membership() && view.packs_complete(),
            "materialized view membership claims differ"
        );
        ensure!(view.snapshot_id() == snapshot_id && view.pin_id() == pin_id, "view ids differ");
        ensure!(view.pin_generation() == 1, "view pin generation differs");
        ensure!(view.repository_id() == v.repo && view.tenant_id() == v.tenant, "view realm differs");
        ensure!(view.owner_id() == producer, "view owner differs from the historical producer");
        ensure!(view.scope().object_format() == GitObjectFormat::Sha1, "view format differs");
        ensure!(view.scope().purpose() == MetadataPinPurpose::Verification, "view purpose differs");
        ensure!(view.gate_revision() == first_rev && view.pack_mode() == "pack_verified", "view gate/mode differs");
        ensure!(view.gate_digest_hex() == v.gate.digest().as_hex(), "view gate digest differs");
        ensure!(is_hex64(&view.read_digest_hex()), "view read digest is not sha256 hex");
        ensure!(
            is_hex64(view.membership_digest_hex()) && is_hex64(view.snapshot_digest_hex()),
            "view binding digests are not sha256 hex"
        );
        ensure!(view.logical_bytes() > 0, "view logical bytes are empty");
        ensure!(view.expires_at_unix_micros() > 0 && view.expires_at()? > SystemTime::now(), "view lease is not live");
        ensure!(view.head_ref() == "refs/heads/main", "view HEAD ref differs");
        ensure!(view.head_oid_hex() == Some(first_oid.as_str()), "view HEAD oid differs");
        ensure!(view.ref_count() == 1 && view.refs().len() == 1, "view ref count differs");
        ensure!(
            view.refs()[0].name() == "refs/heads/main" && view.refs()[0].oid_hex() == first_oid.as_str(),
            "view ref differs"
        );
        ensure!(view.pack_count() == 1 && view.packs().len() == 1, "view pack count differs");
        assert_pack_identity(&first_pack, &view.packs()[0])?;
        ensure!(view.verified_pairs() == 1, "view verified pair count differs");
        ensure!(
            view.verified_bytes() == (first_pack_bytes.len() + first_idx_bytes.len()) as u64,
            "view verified byte count differs"
        );
        let pack_id = first_pack.pack_id();
        ensure!(
            view.pack_bytes(pack_id, deadline()).await? == first_pack_bytes,
            "materialized pack bytes are not the exact registered bytes"
        );
        ensure!(
            view.idx_bytes(pack_id, deadline()).await? == first_idx_bytes,
            "materialized idx bytes are not the exact registered bytes"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
/// A real second A4 commit advances the gate, yet the older sealed snapshot stays
/// materializable: the pinned historical revision and its exact pack bytes are
/// served from the SAME realm, never mixed with the newer revision.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn pinned_older_revision_survives_new_a4_commit() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let mut v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let first_rev = v.gate.revision();
        let first_oid = v.commit_oid.clone();
        let first_pack = v.new_packs[0].clone();
        let first_pack_bytes = std::fs::read(v.fixture.artifacts_dir()?.join("first.pack"))?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (request, _, old_snapshot, old_pin) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &request).await?;
        let second = verify_advance(&db, &store, &mut v, 2, b"second verified commit\n").await?;
        ensure!(v.gate.revision() == first_rev + 1, "the second A4 commit did not advance the gate");
        let advanced_scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (advanced, _, new_snapshot, new_pin) = a5_request(advanced_scope, &v.gate, 300)?;
        a5_create(&db.pool, &advanced).await?;
        let materializer = PgPackSnapshotMaterializer::new(store.clone(), git.clone())?;
        let old = materialize(&materializer, &db.pool, v.repo, v.tenant, old_snapshot, old_pin, 1, deadline()).await?;
        ensure!(old.complete_git_read_snapshot(), "pinned older view is not complete");
        ensure!(old.gate_revision() == first_rev, "pinned older view took the newer revision");
        ensure!(old.refs().len() == 1 && old.refs()[0].oid_hex() == first_oid.as_str(), "pinned older ref differs");
        ensure!(old.head_oid_hex() == Some(first_oid.as_str()), "pinned older HEAD differs");
        ensure!(old.packs().len() == 1, "pinned older view pack count differs");
        assert_pack_identity(&first_pack, &old.packs()[0])?;
        ensure!(
            old.pack_bytes(first_pack.pack_id(), deadline()).await? == first_pack_bytes,
            "pinned older pack bytes differ from the registered bytes"
        );
        let new = materialize(&materializer, &db.pool, v.repo, v.tenant, new_snapshot, new_pin, 1, deadline()).await?;
        ensure!(new.complete_git_read_snapshot(), "advanced view is not complete");
        ensure!(new.gate_revision() == v.gate.revision(), "advanced view gate revision differs");
        ensure!(new.refs().len() == 1 && new.refs()[0].oid_hex() == v.commit_oid.as_str(), "advanced ref differs");
        ensure!(new.packs().len() == 2, "advanced view did not capture both registered packs");
        for expected in v.new_packs.iter().chain(std::iter::once(&first_pack)) {
            let actual = new
                .packs()
                .iter()
                .find(|pack| pack.pack_id() == expected.pack_id())
                .ok_or_else(|| anyhow!("advanced view omitted a registered pack"))?;
            assert_pack_identity(expected, actual)?;
        }
        ensure!(second.len() == 1, "advance did not report exactly one new pack");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
/// SHA-256: the same complete-view contract on the other object format, and an
/// unknown pack id is refused instead of exposing a path or a copy.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn sha256_complete_view_and_unknown_pack_id_is_refused() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha256).await?;
        ensure!(v.gate.object_format() == GitObjectFormat::Sha256, "fixture gate is not sha256");
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (request, _, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &request).await?;
        let materializer = PgPackSnapshotMaterializer::new(store.clone(), git.clone())?;
        let view = materialize(&materializer, &db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1, deadline()).await?;
        ensure!(view.complete_git_read_snapshot(), "sha256 view is not complete");
        ensure!(view.scope().object_format() == GitObjectFormat::Sha256, "sha256 view format differs");
        ensure!(view.refs().len() == 1 && view.refs()[0].oid_hex() == v.commit_oid.as_str(), "sha256 ref differs");
        ensure!(view.packs().len() == 1 && view.verified_pairs() == 1, "sha256 pack counts differ");
        assert_pack_identity(&v.new_packs[0], &view.packs()[0])?;
        let pack_id = v.new_packs[0].pack_id();
        let pack = view.pack_bytes(pack_id, deadline()).await?;
        ensure!(
            pack.len() as u64 == v.new_packs[0].artifact(PackArtifactRole::Pack).verified_length(),
            "pack length differs"
        );
        let unknown = Uuid::new_v4();
        match view.pack_bytes(unknown, deadline()).await {
            Err(RefStoreError::Unsupported(_)) => {}
            Ok(_) => return Err(anyhow!("an unregistered pack id returned materialized bytes")),
            Err(other) => return Err(anyhow!("unregistered pack id was refused unexpectedly: {other:?}")),
        }
        match view.idx_bytes(unknown, deadline()).await {
            Err(RefStoreError::Unsupported(_)) => {}
            Ok(_) => return Err(anyhow!("an unregistered pack id returned materialized index bytes")),
            Err(other) => return Err(anyhow!("unregistered idx id was refused unexpectedly: {other:?}")),
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
fn fail_closed<T>(result: Result<T, RefStoreError>, what: &str) -> Result<()> {
    match result {
        Err(RefStoreError::Timeout) | Err(RefStoreError::Unsupported(_)) | Err(RefStoreError::Database(_)) => Ok(()),
        Err(other) => Err(anyhow!("{what} was refused with an unexpected error: {other:?}")),
        Ok(_) => Err(anyhow!("{what} produced a public materialized view")),
    }
}
/// A wrong physical backend, a missing registered object and byte-corrupted
/// object all fail closed with a typed refusal and no public view. The faults are
/// real provider operations on this test's own freshly registered object.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn wrong_backend_missing_object_and_corrupt_bytes_fail_closed() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let pack = v.new_packs[0].clone();
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (request, _, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &request).await?;
        // (a) A different root prefix is a genuinely different physical backend.
        let foreign_root = format!("a5b-foreign-{}", Uuid::new_v4().simple());
        let foreign = store_with_root(&foreign_root)?;
        ensure!(
            foreign.backend_identity().as_hex() != store.backend_identity().as_hex(),
            "the foreign fixture store accidentally shares the registered backend identity"
        );
        let foreign_materializer = PgPackSnapshotMaterializer::new(foreign, git.clone())?;
        let foreign_read =
            materialize(&foreign_materializer, &db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1, deadline()).await;
        fail_closed(foreign_read, "a materialized read from a foreign Blob backend")?;
        // (b) Remove the registered pack object from the real provider.
        let fault = S3Fault::from_env()?;
        let locator = pack_locator(&pack, PackArtifactRole::Pack)?;
        fault.delete(&locator).await?;
        let materializer = PgPackSnapshotMaterializer::new(store.clone(), git.clone())?;
        let missing = materialize(&materializer, &db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1, deadline()).await;
        fail_closed(missing, "a materialized read of a missing registered object")?;
        // (c) Re-create the same object path with the same length, other bytes.
        let mut corrupt = std::fs::read(v.fixture.artifacts_dir()?.join("first.pack"))?;
        ensure!(!corrupt.is_empty(), "fixture pack is empty");
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0x5a;
        fault.overwrite(&locator, &corrupt).await?;
        let corrupted =
            materialize(&materializer, &db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1, deadline()).await;
        fail_closed(corrupted, "a materialized read of a corrupted registered object")?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
fn expect_refusal<T>(result: Result<T, RefStoreError>) -> Result<RefStoreError> {
    match result {
        Ok(_) => Err(anyhow!("a snapshot that changed during materialization still produced a public view")),
        Err(error) => Ok(error),
    }
}
/// A pin release and a generation-renew that both land while the actual
/// Blob/native phase runs: each must refuse the public value at T2 because the
/// retained pin lock and the fresh DB clock are re-read after the slow phase.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn release_and_generation_change_between_t1_and_t2_refuse() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let repo = v.repo;
        // (1) release the pin while the native phase is gated.
        let (request, _, released_snapshot, released_pin) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &request).await?;
        let gate = GitGate::new(&git)?;
        let materializer = gate.materializer(&store)?;
        let read = materialize(&materializer, &db.pool, repo, v.tenant, released_snapshot, released_pin, 1, deadline());
        let mutate = async {
            let _gate_guard = GateRelease(&gate);
            gate.wait_ready().await?;
            let release =
                ReleaseMetadataPinRequest::new(scope, Uuid::new_v4(), released_pin, 1, PinReleaseReason::ClientDone)?;
            a2_release(&db.pool, &release).await?;
            gate.release()?;
            Ok::<(), anyhow::Error>(())
        };
        let (read_result, mutation) = tokio::join!(read, mutate);
        mutation?;
        let refusal = expect_refusal(read_result)?;
        ensure!(
            matches!(&refusal, RefStoreError::MetadataPinReleased { pin_id, .. } if *pin_id == released_pin),
            "a pin released during native materialization was not refused as released: {refusal:?}"
        );
        // (2) renew the pin (generation 1 -> 2) while the native phase is gated.
        let (renew_request, _, renewed_snapshot, renewed_pin) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &renew_request).await?;
        let gate = GitGate::new(&git)?;
        let materializer = gate.materializer(&store)?;
        let read = materialize(&materializer, &db.pool, repo, v.tenant, renewed_snapshot, renewed_pin, 1, deadline());
        let mutate = async {
            let _gate_guard = GateRelease(&gate);
            gate.wait_ready().await?;
            let renew = RenewMetadataPinRequest::new(scope, Uuid::new_v4(), renewed_pin, 1, 300)?;
            a2_renew(&db.pool, &renew).await?;
            gate.release()?;
            Ok::<(), anyhow::Error>(())
        };
        let (read_result, mutation) = tokio::join!(read, mutate);
        mutation?;
        let refusal = expect_refusal(read_result)?;
        ensure!(
            matches!(&refusal, RefStoreError::MetadataPinGenerationMismatch { .. }),
            "a renewed pin generation during native materialization was not refused: {refusal:?}"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
/// An expiry that lands during the native phase (fresh DB clock, not the initial
/// pin flag) and a realm/group-epoch change both refuse. The realm change is not
/// rolled back: the old pin stays refused, and only a fresh snapshot in the
/// current epoch materializes positively.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn expiry_and_realm_change_between_t1_and_t2_refuse() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let repo = v.repo;
        // (1) A real short lease expires under the DB clock while the native
        // phase is gated. The pin is NOT mutated and the production trigger is
        // left enabled: only elapsed time can make this renewal/read invalid.
        let (request, _, expired_snapshot, expired_pin) = a5_request(scope, &v.gate, 2)?;
        a5_create(&db.pool, &request).await?;
        let gate = GitGate::new(&git)?;
        let materializer = gate.materializer(&store)?;
        let read = materialize(&materializer, &db.pool, repo, v.tenant, expired_snapshot, expired_pin, 1, deadline());
        let mutate = async {
            let _gate_guard = GateRelease(&gate);
            gate.wait_ready().await?;
            let client = db.pool.get().await?;
            let expires: i64 = client
                .query_one(
                    "SELECT (extract(epoch FROM expires_at)*1000000)::bigint
                       FROM ref_store_core_pins WHERE pin_id=$1",
                    &[&expired_pin],
                )
                .await?
                .get(0);
            let started = StdInstant::now();
            loop {
                let now: i64 = client
                    .query_one("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint", &[])
                    .await?
                    .get(0);
                if now >= expires {
                    break;
                }
                ensure!(started.elapsed() < Duration::from_secs(15), "short pin lease did not expire under DB clock");
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            gate.release()?;
            Ok::<(), anyhow::Error>(())
        };
        let (read_result, mutation) = tokio::join!(read, mutate);
        mutation?;
        let refusal = expect_refusal(read_result)?;
        ensure!(
            matches!(&refusal, RefStoreError::MetadataPinExpired { pin_id, .. } if *pin_id == expired_pin),
            "a pin whose actual lease expired during native materialization was not refused as expired: {refusal:?}"
        );
        // (2) Advance the realm (group epoch) while the native phase is gated.
        // This fixture-only gate change is intentionally NOT rolled back: the
        // old pin remains stale under the new realm; the existing immutable
        // pack publications are not re-admitted into a new authority here.
        let (realm_request, _, realm_snapshot, realm_pin) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &realm_request).await?;
        let gate = GitGate::new(&git)?;
        let materializer = gate.materializer(&store)?;
        let read = materialize(&materializer, &db.pool, repo, v.tenant, realm_snapshot, realm_pin, 1, deadline());
        let mutate = async {
            let _gate_guard = GateRelease(&gate);
            gate.wait_ready().await?;
            db.pool
                .get()
                .await?
                .execute(
                    "UPDATE ref_store_core_gates SET group_epoch = group_epoch + 1 WHERE repository_id=$1",
                    &[&repo],
                )
                .await?;
            gate.release()?;
            Ok::<(), anyhow::Error>(())
        };
        let (read_result, mutation) = tokio::join!(read, mutate);
        mutation?;
        let refusal = expect_refusal(read_result)?;
        ensure!(
            matches!(&refusal, RefStoreError::MetadataScopeMismatch(_)),
            "a realm change during native materialization was not refused as a scope mismatch: {refusal:?}"
        );
        let next_gate = gate_version(&db.pool, repo, v.tenant).await?;
        ensure!(
            next_gate.group_epoch() == v.gate.group_epoch() + 1 && next_gate.revision() == v.gate.revision(),
            "current gate is not the unchanged revision in the advanced realm"
        );
        // The old pin remains refused: do not restore the old realm to resume it.
        let old_again =
            materialize(&materializer, &db.pool, repo, v.tenant, realm_snapshot, realm_pin, 1, deadline()).await;
        let old_refusal = expect_refusal(old_again)?;
        ensure!(
            matches!(&old_refusal, RefStoreError::MetadataScopeMismatch(_)),
            "the old-realm pin was unexpectedly usable after the realm advanced: {old_refusal:?}"
        );
        // Complete authority handoff/re-admission is outside this suite. The
        // old epoch is never restored to reactivate a stale pin.
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
/// Both bounded pool waits are inside the ONE effective deadline: a blocked T1
/// acquisition (before any sealed read) and a blocked T2 acquisition (during the
/// native phase) each refuse with `Timeout` instead of hanging.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn both_pool_wait_deadlines_are_bounded() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (request, _, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &request).await?;
        let pool = db.new_pool(1)?;
        let materializer = PgPackSnapshotMaterializer::new(store.clone(), git.clone())?;
        // (1) T1 pool wait: the only connection is held by this test.
        let held = pool.get().await?;
        let started = StdInstant::now();
        let first = materialize(
            &materializer,
            &pool,
            v.repo,
            v.tenant,
            snapshot_id,
            pin_id,
            1,
            TokioInstant::now() + Duration::from_millis(400),
        )
        .await;
        ensure!(
            matches!(first, Err(RefStoreError::Timeout)),
            "a blocked T1 pool acquisition was not refused as Timeout"
        );
        ensure!(started.elapsed() < Duration::from_secs(5), "the T1 pool wait was not bounded");
        drop(held);
        // (2) T2 pool wait: the only connection is held during the native phase.
        // The read future's completion is measured INDEPENDENTLY of the gated
        // observer: the mutation future must not finish (and therefore must not
        // release the only connection) before the read reports `Timeout`.
        let gate = GitGate::new(&git)?;
        let gated = gate.materializer(&store)?;
        let read = materialize(
            &gated,
            &pool,
            v.repo,
            v.tenant,
            snapshot_id,
            pin_id,
            1,
            TokioInstant::now() + Duration::from_secs(5),
        );
        tokio::pin!(read);
        let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let mut observer_release = OneshotRelease::new(release_tx);
        let mutate = async {
            let _gate_guard = GateRelease(&gate);
            gate.wait_ready().await?;
            // T1 already dropped its client: this acquisition must succeed while
            // the native phase runs, and then block the T2 acquisition.
            let observer = pool.get().await?;
            gate.release()?;
            let _ = held_tx.send(());
            let _ = release_rx.await;
            drop(observer);
            Ok::<(), anyhow::Error>(())
        };
        tokio::pin!(mutate);
        tokio::select! {
            _ = &mut mutate => return Err(anyhow!("the T2 observer fixture finished before the read")),
            result = &mut read => return Err(match result {
                Ok(_) => anyhow!("the read completed before the observer held the only connection"),
                Err(error) => anyhow!("the read failed before the observer held the only connection: {error:?}"),
            }),
            _ = held_rx => {},
            _ = tokio::time::sleep(Duration::from_secs(6)) => {
                return Err(anyhow!("the T2 observer fixture never acquired the only connection"));
            }
        }
        let observer_held_at = StdInstant::now();
        let read_result = tokio::select! {
            result = &mut read => result,
            _ = &mut mutate => return Err(anyhow!("the observer was released before the read completed")),
            _ = tokio::time::sleep(Duration::from_secs(6)) => {
                return Err(anyhow!("the T2 pool wait was not bounded while the observer still held the connection"));
            }
        };
        // The read completed while the mutation future was still waiting on its
        // separate release channel, i.e. before we release the held observer.
        observer_release.release();
        mutate.await?;
        ensure!(observer_held_at.elapsed() < Duration::from_secs(6), "the T2 pool wait exceeded its independent bound");
        ensure!(
            matches!(read_result, Err(RefStoreError::Timeout)),
            "a blocked T2 pool acquisition was not refused as Timeout"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
/// With a max-size-1 pool, an ordinary observer must acquire the only connection
/// and run SQL while the materialization is inside its Blob/native phase, and the
/// same materialization must then still return a complete view.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn pool_max_one_observer_succeeds_during_blob_and_native() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (request, _, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &request).await?;
        let pool = db.new_pool(1)?;
        let gate = GitGate::new(&git)?;
        let materializer = gate.materializer(&store)?;
        let read = materialize(&materializer, &pool, v.repo, v.tenant, snapshot_id, pin_id, 1, deadline());
        let observe = async {
            let _gate_guard = GateRelease(&gate);
            gate.wait_ready().await?;
            let observer = pool.get().await?;
            let pins: i64 = observer
                .query_one("SELECT count(*) FROM ref_store_core_pins WHERE pin_id=$1", &[&pin_id])
                .await?
                .get(0);
            ensure!(pins == 1, "the observing connection did not see the sealed pin");
            gate.release()?;
            drop(observer);
            Ok::<(), anyhow::Error>(())
        };
        let (read_result, observed) = tokio::join!(read, observe);
        observed?;
        let view = read_result?;
        ensure!(view.complete_git_read_snapshot(), "the observed materialization is not complete");
        ensure!(
            view.packs().len() == 1 && view.refs().len() == 1 && view.verified_pairs() == 1,
            "the observed materialization lost its closure"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
/// Two idle long-lived views keep their workspace/view budget but no native
/// permit: a real A4 verified commit still succeeds beside them. The view budget
/// is exactly two, and dropping one view reclaims it.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn two_idle_views_do_not_starve_a4_and_drop_reclaims_the_budget() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (first_request, _, first_snapshot, first_pin) = a5_request(scope, &v.gate, 300)?;
        let (second_request, _, second_snapshot, second_pin) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &first_request).await?;
        a5_create(&db.pool, &second_request).await?;
        let materializer = PgPackSnapshotMaterializer::new(store.clone(), git.clone())?;
        let first =
            materialize(&materializer, &db.pool, v.repo, v.tenant, first_snapshot, first_pin, 1, deadline()).await?;
        let second =
            materialize(&materializer, &db.pool, v.repo, v.tenant, second_snapshot, second_pin, 1, deadline()).await?;
        ensure!(
            first.complete_git_read_snapshot() && second.complete_git_read_snapshot(),
            "the two retained views are not complete"
        );
        // A4 verification must not be starved by two idle views.
        let a4 = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        // Bootstrap created revision 1; the real verified first-pack commit is
        // revision 2. Assert the ACTUAL post-commit gate, not the pre-commit one.
        ensure!(
            a4.gate.revision() == 2
                && a4.gate.object_format() == GitObjectFormat::Sha1
                && a4.commit_oid.len() == 40
                && a4.new_packs.len() == 1,
            "a real A4 verified commit did not complete beside two retained views"
        );
        // A third view must wait at admission, not time out in T1 or start a
        // native child and merely time out later. This trusted wrapper would
        // leave a marker if admission incorrectly allowed its first Git call.
        let third_gate = GitGate::new(&git)?;
        let blocked_materializer = third_gate.materializer(&store)?;
        let _third_release = GateRelease(&third_gate);
        let admission_started = StdInstant::now();
        let third = materialize(
            &blocked_materializer,
            &db.pool,
            v.repo,
            v.tenant,
            first_snapshot,
            first_pin,
            1,
            TokioInstant::now() + Duration::from_millis(1500),
        )
        .await;
        ensure!(
            matches!(third, Err(RefStoreError::Unsupported("native materialized read verification is unavailable"))),
            "the third view did not reach bounded native-view admission"
        );
        ensure!(
            admission_started.elapsed() >= Duration::from_secs(1),
            "view admission failed before waiting on its budget"
        );
        ensure!(!third_gate.ready_marker().exists(), "a third view started a native child beyond the view budget");
        // Dropping one view reclaims its workspace and budget slot.
        drop(first);
        let third =
            materialize(&materializer, &db.pool, v.repo, v.tenant, first_snapshot, first_pin, 1, deadline()).await?;
        ensure!(third.complete_git_read_snapshot(), "the reclaimed-budget view is not complete");
        drop(second);
        drop(third);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
/// The issue139 shape on real Git: 127 legal 52-byte ref names with 16 nested
/// segments below `refs/heads/`, plus the real `refs/heads/main` HEAD ref. The
/// shared engine must write one sorted packed-refs file in the owned view,
/// re-read exactly these refs/HEAD and fsck the closure, so the public view
/// carries the exact 128-ref closure instead of a directory explosion.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn deep_nested_refs_issue139_packed_native_closure() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let format = GitObjectFormat::Sha1;
        let (tenant, repo) = db.business(format).await?;
        let gate = db.gate(repo, tenant, format).await?;
        let fixture = GitRepo::new(git.clone(), format).await?;
        let commit_oid = fixture.build_commit("deep.txt", b"deep ref fixture\n", "deep fixture").await?;
        // All 128 fixture refs exist locally so the one real pack artifact
        // contains the complete closure this case reads.
        let mut expected: Vec<(String, String)> = Vec::with_capacity(128);
        let mut deep_updates: Vec<RefUpdate> = Vec::with_capacity(127);
        for index in 0..127usize {
            let name = deep_ref_name(index);
            ensure!(name.len() == 52 && name.split('/').count() == 18, "deep ref name shape differs");
            ensure!(name.as_str() != "refs/heads/main", "a deep ref name collided with HEAD branch");
            fixture.update_ref(&name, &commit_oid).await?;
            deep_updates.push(RefUpdate::new(
                RefName::new(&name)?,
                RefPrecondition::Absent,
                RefTarget::Oid(GitOid::parse(format, &commit_oid)?),
            ));
            expected.push((name, commit_oid.clone()));
        }
        // The 128th ref is the real HEAD branch at the same actual commit, so the
        // materialized HEAD stays on refs/heads/main while 127 names are deep.
        fixture.update_ref("refs/heads/main", &commit_oid).await?;
        expected.push(("refs/heads/main".to_owned(), commit_oid.clone()));
        ensure!(deep_updates.len() == 127 && expected.len() == 128, "fixture refs differ");
        expected.sort();
        let files = fixture.pack_all("deep").await?;

        // FIRST commit: only the real HEAD ref plus the one actual registered pack.
        // `ensure_pack_terminal_budget` pads every planned name to 1024 bytes, so a
        // single 128-ref plan would exceed the 64 KiB terminal bound. The actual
        // contract is preserved by chunking the deep ref publication instead of
        // shortening names, skipping refs or raising the production bound.
        let main_ref = vec![main_update(format, None, &commit_oid)?];
        let mut verified = commit_first_pack(
            &db,
            &store,
            tenant,
            repo,
            gate,
            format,
            &git,
            main_ref,
            &files,
            commit_oid.clone(),
            fixture,
        )
        .await?;
        ensure!(verified.new_packs.len() == 1, "first commit did not register exactly one pack");

        // Publish the 127 deep refs through four ACTUAL typed A4 ref-only plans
        // (<=32 names each), each with zero new packs, one old pack, a real
        // PackVerifier proof over the already-registered pair, and a real commit.
        // All OIDs are the same actual commit already present in that first pack.
        let deep_count = deep_updates.len();
        let mut chunk_index = 0usize;
        while !deep_updates.is_empty() {
            let take = deep_updates.len().min(32);
            let chunk: Vec<RefUpdate> = deep_updates.drain(0..take).collect();
            ensure!(!chunk.is_empty() && chunk.len() <= 32, "deep ref chunk is not bounded");
            let sequence = 2 + i64::try_from(chunk_index)?;
            let draft = draft(&db, repo, tenant, sequence, &verified.gate, chunk, &[]).await?;
            ensure!(draft.plan.packs().is_empty(), "ref-only plan unexpectedly planned a new pack");
            let context = closure(&db, &draft.plan).await?;
            ensure!(
                context.old_packs().len() == 1 && context.new_packs().is_empty(),
                "ref-only closure is not exactly one old/zero new packs"
            );
            assert_pack_identity(&verified.new_packs[0], &context.old_packs()[0])?;
            let proof = prove(&store, &git, &draft.plan, &context).await?;
            let receipt = commit(&db, &draft.plan, &draft.token, &proof).await?;
            ensure!(receipt.is_committed() && !receipt.replayed, "a deep-ref ref-only commit did not commit");
            let next = gate_version(&db.pool, repo, tenant).await?;
            ensure!(
                next.revision() == receipt.terminal.revision && next.revision() == verified.gate.revision() + 1,
                "deep-ref gate revision did not advance by exactly one real commit"
            );
            verified.gate = next;
            chunk_index += 1;
        }
        ensure!(chunk_index == 4 && deep_count == 127, "deep refs were not published in four bounded chunks");

        let producer = Uuid::new_v4();
        let scope = scope_for(repo, tenant, producer, &verified.gate, MetadataPinPurpose::Verification)?;
        let (request, _, snapshot_id, pin_id) = a5_request(scope, &verified.gate, 300)?;
        a5_create(&db.pool, &request).await?;
        let materializer = PgPackSnapshotMaterializer::new(store.clone(), git.clone())?;
        let view = materialize(&materializer, &db.pool, repo, tenant, snapshot_id, pin_id, 1, deadline()).await?;
        ensure!(view.complete_git_read_snapshot(), "deep-ref view is not complete");
        ensure!(view.ref_count() == 128 && view.refs().len() == 128, "deep-ref view did not carry 128 refs");
        ensure!(
            view.head_ref() == "refs/heads/main" && view.head_oid_hex() == Some(commit_oid.as_str()),
            "deep-ref HEAD differs"
        );
        // The four ref-only commits added no pack: the original actual registered
        // pack is still the complete pack membership and was re-verified natively.
        ensure!(
            view.packs().len() == 1 && view.pack_count() == 1 && view.verified_pairs() == 1,
            "deep-ref closure pack counts differ"
        );
        assert_pack_identity(&verified.new_packs[0], &view.packs()[0])?;
        let actual = view
            .refs()
            .iter()
            .map(|reference| (reference.name().to_owned(), reference.oid_hex().to_owned()))
            .collect::<Vec<_>>();
        ensure!(actual == expected, "the materialized ref closure is not the exact captured 128-ref set");
        for pair in actual.windows(2) {
            ensure!(pair[0].0 < pair[1].0, "materialized refs are not sorted and unique");
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
/// The issue139 repro shape: 52 bytes, 16 nested segments below `refs/heads/`.
fn deep_ref_name(index: usize) -> String {
    let mut segments: Vec<String> = (0..16)
        .map(|position| {
            if position == 0 {
                format!("{index:02x}")
            } else if position < 10 {
                format!("{position:02x}")
            } else {
                format!("{position:x}")
            }
        })
        .collect();
    segments.insert(0, "refs".to_owned());
    segments.insert(1, "heads".to_owned());
    segments.join("/")
}

/// Two actual A5b materializations hold the ONE process-wide native semaphore of
/// two while their real Git children are gated. A third A4 verification must then
/// wait for admission, refuse at its short deadline, and never execute a native
/// child through its own gate. This distinguishes the shared global bound from a
/// second A4/A5b pool or from a Git work timeout after admission.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn third_a4_native_child_is_not_admitted_while_two_views_hold_global_slots() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (request, _, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &request).await?;

        // Valid typed A4 ref-only pending plan/context on the CURRENT revision and
        // the one already-registered pack. A same-OID main CAS is a real valid
        // update and needs NO new S3 upload; the old pack is re-verified natively.
        let refs = vec![main_update(v.gate.object_format(), Some(&v.commit_oid), &v.commit_oid)?];
        let draft = draft(&db, v.repo, v.tenant, 2, &v.gate, refs, &[]).await?;
        ensure!(draft.plan.packs().is_empty(), "A4 admission fixture planned an unexpected new pack");
        let context = closure(&db, &draft.plan).await?;
        ensure!(
            context.old_packs().len() == 1 && context.new_packs().is_empty(),
            "A4 admission fixture closure is not one old/zero new packs"
        );

        let first_gate = GitGate::new(&git)?;
        let second_gate = GitGate::new(&git)?;
        let third_gate = GitGate::new(&git)?;
        let first_materializer = first_gate.materializer(&store)?;
        let second_materializer = second_gate.materializer(&store)?;
        let first = materialize(&first_materializer, &db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1, deadline());
        let second = materialize(&second_materializer, &db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1, deadline());
        let control = async {
            // All three wrappers release on every exit path. The first two gates
            // are explicitly released after the A4 attempt; the third is never
            // expected to have run at all.
            let _first_release = GateRelease(&first_gate);
            let _second_release = GateRelease(&second_gate);
            let _third_release = GateRelease(&third_gate);
            first_gate.wait_ready().await?;
            second_gate.wait_ready().await?;
            let verifier = PackVerifier::new(store.clone(), third_gate.binary())?;
            let outcome = verifier.verify(&draft.plan, &context, StdInstant::now() + Duration::from_millis(400)).await;
            // The absence of this marker is the proof that the error was admission
            // backpressure, NOT a started Git child that merely hit its timeout.
            ensure!(!third_gate.is_ready(), "A4 executed a native Git child outside the shared global admission");
            match outcome {
                Err(PackCommitError::ProofUnavailable(_)) => {}
                other => return Err(anyhow!("A4 was expected to refuse without admission, got {other:?}")),
            }
            first_gate.release()?;
            second_gate.release()?;
            Ok::<(), anyhow::Error>(())
        };
        let (first_result, second_result, control_result) = tokio::join!(first, second, control);
        control_result?;
        let first_view = first_result?;
        let second_view = second_result?;
        ensure!(
            first_view.complete_git_read_snapshot() && second_view.complete_git_read_snapshot(),
            "the two originally admitted materializations did not both complete"
        );
        ensure!(
            first_view.verified_pairs() == 1 && second_view.verified_pairs() == 1,
            "the two admitted materializations did not verify the registered pack"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

/// End-of-T2 expiry against a REAL slow ledger read: the reader's exact backend
/// is blocked on `ref_store_core_pack_publications` by another transaction after
/// T1/native completed. The pin lease expires while that lock is held, so only a
/// fresh DB-clock expiry check AFTER the ledger reads can refuse the view. A
/// pre-ledger-only expiry check would return a public value here.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn end_of_t2_expiry_after_blocked_pack_publication_ledger_read() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        // ~10 second lease: long enough for the native phase and the observer
        // lock, short enough to expire deterministically inside one 30 s budget.
        let (request, _, snapshot_id, pin_id) = a5_request(scope, &v.gate, 10)?;
        a5_create(&db.pool, &request).await?;

        let reader_pool = db.new_pool(1)?;
        // Record the exact reader backend before the call and release the borrow;
        // the max-1 pool reuses that same backend for T1 and T2.
        let reader_pid: i32 = {
            let client = reader_pool.get().await?;
            let pid = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            drop(client);
            pid
        };
        let observer_pool = db.new_pool(2)?;
        let gate = GitGate::new(&git)?;
        let materializer = gate.materializer(&store)?;
        let read = materialize(&materializer, &reader_pool, v.repo, v.tenant, snapshot_id, pin_id, 1, deadline());
        let control = async {
            let _gate_guard = GateRelease(&gate);
            gate.wait_ready().await?;
            let mut observer = observer_pool.get().await?;
            // Separate PG transaction (different pool/backend) holds an ACCESS
            // EXCLUSIVE relation lock on the publication ledger. RAII/SDK rollback
            // releases it on every non-success exit; no global pg cancel is used.
            let tx = observer.transaction().await?;
            tx.execute("LOCK TABLE ref_store_core_pack_publications IN ACCESS EXCLUSIVE MODE", &[]).await?;
            gate.release()?;
            let table = format!("{}.ref_store_core_pack_publications", db.schema);
            let waited = StdInstant::now();
            loop {
                let blocked: bool = tx
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_locks
                           WHERE pid=$1 AND relation=to_regclass($2)
                             AND mode='AccessShareLock' AND NOT granted)",
                        &[&reader_pid, &table],
                    )
                    .await?
                    .get(0);
                if blocked {
                    break;
                }
                ensure!(
                    waited.elapsed() < Duration::from_secs(10),
                    "T2 never waited on the exact blocked publication ledger relation"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let before_expiry: bool = tx
                .query_one(
                    "SELECT clock_timestamp() < expires_at FROM ref_store_core_pins
                       WHERE pin_id=$1 AND repository_id=$2",
                    &[&pin_id, &v.repo],
                )
                .await?
                .get(0);
            ensure!(before_expiry, "the pin had already expired before the T2 ledger wait");
            let expires: i64 = tx
                .query_one(
                    "SELECT (extract(epoch FROM expires_at)*1000000)::bigint FROM ref_store_core_pins
                       WHERE pin_id=$1 AND repository_id=$2",
                    &[&pin_id, &v.repo],
                )
                .await?
                .get(0);
            let polled = StdInstant::now();
            loop {
                let now: i64 =
                    tx.query_one("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint", &[]).await?.get(0);
                if now >= expires {
                    break;
                }
                ensure!(
                    polled.elapsed() < Duration::from_secs(20),
                    "the DB clock did not pass the pin lease while the ledger lock was held"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            tx.rollback().await?;
            Ok::<(), anyhow::Error>(())
        };
        let (read_result, control_result) = tokio::join!(read, control);
        control_result?;
        let refusal = expect_refusal(read_result)?;
        ensure!(
            matches!(&refusal, RefStoreError::MetadataPinExpired { pin_id: refused, .. } if *refused == pin_id),
            "expiry after the blocked T2 ledger read was not refused as MetadataPinExpired: {refusal:?}"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
