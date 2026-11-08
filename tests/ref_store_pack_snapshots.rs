//! Real PostgreSQL + real S3 + native Git acceptance tests for A5a pack snapshots (#105/#107).
//!
//! Root runs with `ROOTYARD_TEST_DATABASE_URL`, a real S3 `ROOTYARD_BLOB_*` profile and
//! `ROOTYARD_TEST_GIT`. Every case is `#[ignore]`, hard-fails on missing config, builds one
//! random schema via `db::migrate` only (migration 143 asserted), and drives the actual typed
//! A4 registration/proof/verified-commit path to establish `pack_verified`. No fake ACK,
//! token, receipt or proof is created; no SQL row is used as an ACK. No PASS is claimed here.
#![allow(clippy::too_many_arguments)]

use anyhow::{Context, Result, anyhow, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::BlobProvider;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use rootyard::db;
use rootyard::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::{
    ContentDigest, PackArtifactRole, PackClosureContext, PackClosureProof, PackCommitExpectation, PackCommitPlan,
    PackCommitReceipt, PackCommitScope, PackMembershipEntry, PackPendingToken, PackRegistrationRequest, PackVerifier,
    PgPackCommit, PlannedArtifact, PlannedPack, RegisteredPack,
};
use rootyard::ref_store::core::{
    CreateMetadataSnapshotOutcome, CreateMetadataSnapshotRequest, CreatePackSnapshotRequest, MetadataPinOutcome,
    MetadataReceipt, MetadataReceiptLookup, MetadataSnapshotPage, MetadataSnapshotScope, PackReadSnapshot,
    PackSnapshotExpectation, PackSnapshotLookup, PackSnapshotOutcome, PackSnapshotReceiptQuery, PackSnapshotRef,
    PgPackSnapshot, PgRefStoreCore, ReadMetadataSnapshotPageRequest, ReleaseMetadataPinRequest,
    RenewMetadataPinRequest,
};
use rootyard::ref_store::{
    CoreGateInit, CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataMutationAction,
    MetadataPinPurpose, OperationIdentity, PgRefStore, PinReleaseReason, RefName, RefPrecondition, RefStoreError,
    RefTarget, RefUpdate, RequestDigest, VersionCheck,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

const OP_SECONDS: u64 = 30;
const GIT_SECONDS: u64 = 60;
const HOLD_NAMESPACE: &str = "core-pack";

fn deadline() -> TokioInstant {
    TokioInstant::now() + Duration::from_secs(OP_SECONDS)
}
fn std_deadline() -> StdInstant {
    StdInstant::now() + Duration::from_secs(OP_SECONDS)
}
fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set for ref_store_pack_snapshots")
}
fn git_binary() -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()));
    ensure!(path.is_absolute() && path.is_file(), "ROOTYARD_TEST_GIT must be an absolute existing git binary");
    Ok(path)
}
/// The configured profile must be real S3; a missing/invalid profile is a hard failure.
fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}
fn random_key() -> i64 {
    i64::from_be_bytes(Uuid::new_v4().into_bytes()[..8].try_into().expect("eight bytes"))
}
fn bounded_refusal(error: &RefStoreError) -> bool {
    match error {
        RefStoreError::Timeout => true,
        RefStoreError::Database(text) => {
            let lower = text.to_ascii_lowercase();
            lower.contains("canceling statement") || lower.contains("timeout") || lower.contains("57014")
        }
        _ => false,
    }
}
async fn show_sync(client: &tokio_postgres::Client) -> String {
    client.query_one("SHOW synchronous_commit", &[]).await.unwrap().get(0)
}
fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn pool_for(url: &str, schema: &str, max: usize, extra: Option<&str>) -> Result<Pool> {
    let mut config: tokio_postgres::Config = url.parse()?;
    let mut options =
        format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000");
    if let Some(extra) = extra {
        options.push_str(&format!(" -c {extra}"));
    }
    config.options(options);
    Ok(Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(max)
        .build()?)
}

/// One random schema, real `db::migrate` (143 asserted), real pools only.
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
        let schema = format!("ref_store_pack_snapshot_test_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let pool = pool_for(&url, &schema, 16, None)?;
        db::migrate(&pool).await?;
        let client = pool.get().await?;
        let installed: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=143)
                    AND to_regclass('ref_store_core_snapshots') IS NOT NULL
                    AND to_regclass('ref_store_core_snapshot_packs') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_snapshot_history') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_snapshot_repo_usage') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_snapshot_tenant_usage') IS NOT NULL
                    AND EXISTS(SELECT 1 FROM information_schema.columns
                               WHERE table_name='ref_store_core_snapshots' AND column_name='membership_digest')",
                &[],
            )
            .await?
            .get(0);
        ensure!(installed, "db::migrate did not install migration 143 or its real tables");
        drop(client);
        Ok(Self { admin, pool, url, schema })
    }
    fn new_pool(&self, max: usize) -> Result<Pool> {
        pool_for(&self.url, &self.schema, max, None)
    }
    fn off_pool(&self, max: usize) -> Result<Pool> {
        pool_for(&self.url, &self.schema, max, Some("synchronous_commit=off"))
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
    /// One trusted user (also tenant/repository owner) and one isolated unserved gitfs repo.
    async fn business(&self, format: GitObjectFormat) -> Result<(Uuid, Uuid)> {
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let object_format = format.as_str();
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO users(id,username) VALUES($1,$2)",
                &[&tenant, &format!("packsnap{}", &tenant.simple().to_string()[..10])],
            )
            .await?;
        client
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,object_format)
                 VALUES($1,$2,$3,'provisioning',$4)",
                &[&repo, &tenant, &format!("repo{}", &repo.simple().to_string()[..10]), &object_format],
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
/// Owned fixture Git: cleared environment, known author, bounded timeout, synthetic bytes.
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
    plan: PackCommitPlan,
    new_packs: Vec<RegisteredPack>,
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
    let commit_oid = fixture.build_commit("file.txt", b"pack snapshot fixture\n", "fixture main").await?;
    fixture.update_ref("refs/heads/main", &commit_oid).await?;
    let files = fixture.pack_all("first").await?;
    let draft =
        draft(db, repo, tenant, 1, &gate, vec![main_update(format, None, &commit_oid)?], std::slice::from_ref(&files))
            .await?;
    let publication = publish(db, store, &draft.plan, &files).await?;
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
    Ok(Verified { tenant, repo, gate, fixture, commit_oid, plan: draft.plan, new_packs })
}
async fn verify_new(db: &Db, store: &BlobStore, git: &Path, format: GitObjectFormat) -> Result<Verified> {
    let (tenant, repo) = db.business(format).await?;
    let gate = db.gate(repo, tenant, format).await?;
    verify_existing(db, store, git, tenant, repo, gate, format).await
}
/// Real second A4 verified commit: advances the gate, adds one pack and updates main.
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
    let draft = draft(
        db,
        verified.repo,
        verified.tenant,
        sequence,
        &verified.gate,
        vec![main_update(format, Some(&old), &oid)?],
        std::slice::from_ref(&files),
    )
    .await?;
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
    verified.plan = draft.plan;
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
struct OldSnapshot {
    request: CreateMetadataSnapshotRequest,
    snapshot_id: Uuid,
    pin_id: Uuid,
    page: MetadataSnapshotPage,
}
async fn a2_create(
    pool: &Pool,
    request: &CreateMetadataSnapshotRequest,
) -> Result<CreateMetadataSnapshotOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.create_metadata_snapshot(&mut client, request, deadline()).await
}
fn pool_error(error: deadpool_postgres::PoolError) -> RefStoreError {
    RefStoreError::Database(error.to_string())
}
async fn old_page(
    pool: &Pool,
    scope: MetadataSnapshotScope,
    old: &OldSnapshot,
    generation: i64,
) -> Result<MetadataSnapshotPage> {
    let request =
        ReadMetadataSnapshotPageRequest::new(scope, old.snapshot_id, old.pin_id, generation, None, None, 128)?;
    let mut client = pool.get().await?;
    Ok(PgRefStoreCore.read_metadata_snapshot_page(&mut client, &request, deadline()).await?)
}
async fn create_old(db: &Db, tenant: Uuid, repo: Uuid, gate: &CoreGateVersion) -> Result<OldSnapshot> {
    let scope = scope_for(repo, tenant, tenant, gate, MetadataPinPurpose::Verification)?;
    let request_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let pin_id = Uuid::new_v4();
    let request = CreateMetadataSnapshotRequest::new(scope, request_id, pin_id, snapshot_id, 300, *gate.digest())?;
    let outcome = a2_create(&db.pool, &request).await?;
    ensure!(!outcome.replayed, "fresh A2 metadata snapshot replayed");
    let page_request = ReadMetadataSnapshotPageRequest::new(scope, snapshot_id, pin_id, 1, None, None, 128)?;
    let mut client = db.pool.get().await?;
    let page = PgRefStoreCore.read_metadata_snapshot_page(&mut client, &page_request, deadline()).await?;
    Ok(OldSnapshot { request, snapshot_id, pin_id, page })
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
    let request = CreatePackSnapshotRequest::new(scope, request_id, pin_id, snapshot_id, lease, expected)?;
    Ok((request, request_id, snapshot_id, pin_id))
}
async fn a5_create(pool: &Pool, request: &CreatePackSnapshotRequest) -> Result<PackSnapshotOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgPackSnapshot.create(&mut client, request, deadline()).await
}
async fn a5_read(
    pool: &Pool,
    repo: Uuid,
    tenant: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    generation: i64,
) -> Result<PackReadSnapshot, RefStoreError> {
    let reference = PackSnapshotRef::new(repo, tenant, snapshot_id, pin_id, generation)?;
    let mut client = pool.get().await.map_err(pool_error)?;
    PgPackSnapshot.read(&mut client, &reference, deadline()).await
}
async fn a5_query(
    pool: &Pool,
    scope: MetadataSnapshotScope,
    request_id: Uuid,
) -> Result<PackSnapshotLookup, RefStoreError> {
    let query = PackSnapshotReceiptQuery::new(scope, request_id)?;
    let mut client = pool.get().await.map_err(pool_error)?;
    PgPackSnapshot.query_receipt(&mut client, &query, deadline()).await
}
async fn pack_usage(pool: &Pool, repo: Uuid) -> Result<Option<[i64; 7]>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT snapshot_count,snapshot_ref_count,binding_count,pin_count,history_count,receipt_count,logical_bytes
         FROM ref_store_core_pack_snapshot_repo_usage WHERE repository_id=$1",
            &[&repo],
        )
        .await?;
    Ok(row.map(|r| [r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5), r.get(6)]))
}
async fn pack_tenant_usage(pool: &Pool, tenant: Uuid) -> Result<Option<[i64; 7]>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT snapshot_count,snapshot_ref_count,binding_count,pin_count,history_count,receipt_count,logical_bytes
         FROM ref_store_core_pack_snapshot_tenant_usage WHERE tenant_id=$1",
            &[&tenant],
        )
        .await?;
    Ok(row.map(|r| [r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5), r.get(6)]))
}
async fn a2_usage(pool: &Pool, repo: Uuid) -> Result<[i64; 4]> {
    let row = pool.get().await?.query_opt(
        "SELECT snapshot_count,snapshot_ref_count,logical_bytes,receipt_count FROM ref_store_core_repo_usage WHERE repository_id=$1",
        &[&repo],
    ).await?;
    Ok(row.map(|r| [r.get(0), r.get(1), r.get(2), r.get(3)]).unwrap_or([0; 4]))
}
async fn snapshot_counts(pool: &Pool, repo: Uuid) -> Result<(i64, i64, i64, i64, i64)> {
    let row = pool.get().await?.query_one(
        "SELECT (SELECT count(*) FROM ref_store_core_snapshots WHERE repository_id=$1),
                (SELECT count(*) FROM ref_store_core_snapshot_refs r JOIN ref_store_core_snapshots s USING(snapshot_id) WHERE s.repository_id=$1),
                (SELECT count(*) FROM ref_store_core_pins WHERE repository_id=$1),
                (SELECT count(*) FROM ref_store_core_receipts WHERE repository_id=$1),
                (SELECT count(*) FROM ref_store_core_snapshot_packs WHERE repository_id=$1)",
        &[&repo],
    ).await?;
    Ok((row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
}
async fn membership_joined(pool: &Pool, repo: Uuid, pack_id: Uuid) -> Result<i64> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT joined_revision FROM ref_store_core_pack_memberships WHERE repository_id=$1 AND pack_id=$2",
            &[&repo, &pack_id],
        )
        .await?
        .get(0))
}
struct Barrier {
    release: Option<oneshot::Sender<()>>,
    unlock: Option<tokio::task::JoinHandle<()>>,
}
impl Barrier {
    async fn release(mut self) -> Result<()> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(unlock) = self.unlock.take() {
            unlock.await.context("fixture unlock task failed")?;
        }
        Ok(())
    }
}
impl Drop for Barrier {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}
async fn acquire_barrier(pool: &Pool, key: i64) -> Result<Barrier> {
    let client = pool.get().await?;
    client.query_one("SELECT pg_advisory_lock($1)", &[&key]).await?;
    let (release, released) = oneshot::channel::<()>();
    let unlock = tokio::spawn(async move {
        let _ = released.await;
        let _ = client.query_one("SELECT pg_advisory_unlock($1)", &[&key]).await;
    });
    Ok(Barrier { release: Some(release), unlock: Some(unlock) })
}
async fn wait_advisory_key(pool: &Pool, pid: i32, key: i64) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = observer
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted
                    AND ((classid::bigint << 32) | objid::bigint) = $2)",
                    &[&pid, &key],
                )
                .await?
                .get(0);
            if waiting {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("backend never parked on the owned advisory key"))??;
    Ok(())
}
async fn wait_lock_wait(pool: &Pool, pid: i32) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let parked: bool = observer.query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)
                    AND EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND state='active' AND wait_event_type='Lock')",
                &[&pid],
            ).await?.get(0);
            if parked { return Ok::<(), anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_| anyhow!("backend never parked on a PostgreSQL lock"))??;
    Ok(())
}
async fn wait_blocked_by(pool: &Pool, pid: i32, blocker: i32) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let pids: Vec<i32> = observer.query_one("SELECT pg_blocking_pids($1)", &[&pid]).await?.get(0);
            if pids.contains(&blocker) {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("backend was never observably blocked by the capture backend"))??;
    Ok(())
}
async fn install_snapshot_park(pool: &Pool, key: i64) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(&format!(
            "CREATE FUNCTION fixture_a5_snapshot_park() RETURNS trigger LANGUAGE plpgsql AS $$
           BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN NEW; END $$;
         CREATE TRIGGER fixture_a5_snapshot_park BEFORE INSERT ON ref_store_core_snapshots
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_snapshot_park();"
        ))
        .await?;
    Ok(())
}
async fn drop_snapshot_park(pool: &Pool) -> Result<()> {
    pool.get().await?.batch_execute(
        "DROP TRIGGER fixture_a5_snapshot_park ON ref_store_core_snapshots; DROP FUNCTION fixture_a5_snapshot_park();",
    ).await?;
    Ok(())
}
async fn install_receipt_park(pool: &Pool, key: i64) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(&format!(
            "CREATE FUNCTION fixture_receipt_timeouts() RETURNS trigger LANGUAGE plpgsql AS $$
           BEGIN SET LOCAL lock_timeout='30s'; SET LOCAL statement_timeout='30s'; RETURN NEW; END $$;
         CREATE TRIGGER fixture_receipt_timeouts BEFORE INSERT ON ref_store_core_receipts
           FOR EACH ROW EXECUTE FUNCTION fixture_receipt_timeouts();
         CREATE FUNCTION fixture_receipt_park() RETURNS trigger LANGUAGE plpgsql AS $$
           BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN NEW; END $$;
         CREATE CONSTRAINT TRIGGER fixture_receipt_park AFTER INSERT ON ref_store_core_receipts
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fixture_receipt_park();"
        ))
        .await?;
    Ok(())
}
async fn drop_receipt_park(pool: &Pool) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(
            "DROP TRIGGER fixture_receipt_park ON ref_store_core_receipts; DROP FUNCTION fixture_receipt_park();
         DROP TRIGGER fixture_receipt_timeouts ON ref_store_core_receipts; DROP FUNCTION fixture_receipt_timeouts();",
        )
        .await?;
    Ok(())
}
async fn install_sync_probe(pool: &Pool) -> Result<()> {
    pool.get().await?.batch_execute(
        "CREATE TABLE fixture_a5_sync_probe(probe_id BIGSERIAL PRIMARY KEY, source TEXT NOT NULL, value TEXT NOT NULL);
         CREATE FUNCTION fixture_a5_sync_record() RETURNS trigger LANGUAGE plpgsql AS $$
           BEGIN INSERT INTO fixture_a5_sync_probe(source,value)
             VALUES (TG_TABLE_NAME || ':' || TG_OP, current_setting('synchronous_commit')); RETURN NEW; END $$;
         CREATE TRIGGER fixture_a5_sync_snapshots BEFORE INSERT ON ref_store_core_snapshots
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_sync_record();
         CREATE TRIGGER fixture_a5_sync_pins BEFORE INSERT OR UPDATE ON ref_store_core_pins
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_sync_record();
         CREATE TRIGGER fixture_a5_sync_receipts BEFORE INSERT ON ref_store_core_receipts
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_sync_record();
         CREATE TRIGGER fixture_a5_sync_bindings BEFORE INSERT ON ref_store_core_snapshot_packs
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_sync_record();
         CREATE TRIGGER fixture_a5_sync_history BEFORE INSERT ON ref_store_core_pack_snapshot_history
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_sync_record();
         CREATE TRIGGER fixture_a5_sync_pack_repo_usage BEFORE INSERT OR UPDATE ON ref_store_core_pack_snapshot_repo_usage
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_sync_record();
         CREATE TRIGGER fixture_a5_sync_pack_tenant_usage BEFORE INSERT OR UPDATE ON ref_store_core_pack_snapshot_tenant_usage
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_sync_record();
         CREATE TRIGGER fixture_a5_sync_a2_repo_usage BEFORE INSERT OR UPDATE ON ref_store_core_repo_usage
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_sync_record();
         CREATE TRIGGER fixture_a5_sync_a2_tenant_usage BEFORE INSERT OR UPDATE ON ref_store_core_tenant_usage
           FOR EACH ROW EXECUTE FUNCTION fixture_a5_sync_record();",
    ).await?;
    Ok(())
}
async fn probe_values(pool: &Pool) -> Result<Vec<(String, String)>> {
    let rows = pool.get().await?.query("SELECT source,value FROM fixture_a5_sync_probe ORDER BY probe_id", &[]).await?;
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
}
async fn clear_probe(pool: &Pool) -> Result<()> {
    pool.get().await?.batch_execute("TRUNCATE fixture_a5_sync_probe").await?;
    Ok(())
}
struct GateBlock {
    release: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl GateBlock {
    async fn hold(pool: &Pool, repo: Uuid) -> Result<Self> {
        let (ready_tx, ready_rx) = oneshot::channel::<i32>();
        let (release, released) = oneshot::channel::<()>();
        let pool = pool.clone();
        let task = tokio::spawn(async move {
            let Ok(mut client) = pool.get().await else { return };
            let Ok(tx) = client.transaction().await else { return };
            let Ok(row) = tx
                .query_opt("SELECT revision FROM ref_store_core_gates WHERE repository_id=$1 FOR UPDATE", &[&repo])
                .await
            else {
                return;
            };
            if row.is_some() {
                let _ = ready_tx.send(1);
                let _ = released.await;
            }
            let _ = tx.rollback().await;
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .map_err(|_| anyhow!("gate blocker never locked"))??;
        Ok(Self { release: Some(release), task: Some(task) })
    }
    async fn release(mut self) -> Result<()> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.map_err(|_| anyhow!("gate blocker task failed"))?;
        }
        Ok(())
    }
}
impl Drop for GateBlock {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}
async fn scenario_assert_sqlstate(pool: &Pool, statement: &str, expected: &str) -> Result<()> {
    let error = pool.get().await?.batch_execute(statement).await.expect_err("statement must be refused");
    ensure!(error.code().map(|code| code.code()) == Some(expected), "unexpected SQLSTATE: {error}");
    Ok(())
}
struct PreparedAdvance {
    plan: PackCommitPlan,
    token: PackPendingToken,
    proof: PackClosureProof,
    new_oid: String,
}
async fn prepare_advance(
    db: &Db,
    store: &BlobStore,
    verified: &Verified,
    sequence: i64,
    content: &[u8],
) -> Result<PreparedAdvance> {
    let format = verified.gate.object_format();
    let oid = verified.fixture.build_commit("race.txt", content, "fixture race").await?;
    verified.fixture.update_ref("refs/heads/main", &oid).await?;
    let files = verified.fixture.pack_all("race").await?;
    let old = verified.commit_oid.clone();
    let draft = draft(
        db,
        verified.repo,
        verified.tenant,
        sequence,
        &verified.gate,
        vec![main_update(format, Some(&old), &oid)?],
        std::slice::from_ref(&files),
    )
    .await?;
    let publication = publish(db, store, &draft.plan, &files).await?;
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    register(db, &draft.plan, pack_id, &publication).await?;
    let context = closure(db, &draft.plan).await?;
    let proof = prove(store, &verified.fixture.git.clone(), &draft.plan, &context).await?;
    Ok(PreparedAdvance { plan: draft.plan, token: draft.token, proof, new_oid: oid })
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn positive_producer_b_old_revision_survives_second_verified_commit() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let mut v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let first_packs = v.new_packs.clone();
        let first_oid = v.commit_oid.clone();
        let first_rev = v.gate.revision();
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
        ensure!(!created.replayed, "fresh pack snapshot replayed");
        let receipt = &created.receipt;
        ensure!(
            receipt.request_id() == request_id && receipt.snapshot_id() == snapshot_id && receipt.pin_id() == pin_id,
            "receipt ids differ"
        );
        ensure!(
            receipt.repository_id() == v.repo && receipt.tenant_id() == v.tenant && receipt.owner_id() == producer,
            "receipt scope differs"
        );
        ensure!(
            receipt.gate_revision() == first_rev && receipt.pack_mode() == "pack_verified",
            "receipt gate/mode differs"
        );
        ensure!(receipt.pack_count() == 1 && receipt.ref_count() == 1, "receipt pack/ref count differs");
        ensure!(
            is_hex64(receipt.membership_digest_hex())
                && is_hex64(receipt.snapshot_digest_hex())
                && is_hex64(receipt.refs_digest_hex()),
            "receipt digest is not sha256 hex"
        );
        ensure!(
            !receipt.complete_registered_pack_membership() && !receipt.complete_git_read_snapshot(),
            "receipt claimed data authority"
        );
        let read = a5_read(&db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1).await?;
        ensure!(read.gate_revision() == first_rev && read.refs().len() == 1, "first read gate/refs differ");
        ensure!(
            read.refs()[0].name() == "refs/heads/main" && read.refs()[0].oid_hex() == first_oid.as_str(),
            "first read ref differs"
        );
        ensure!(
            read.head_ref() == "refs/heads/main" && read.head_oid_hex() == Some(first_oid.as_str()),
            "first read HEAD differs"
        );
        ensure!(read.packs().len() == 1, "first read pack count differs");
        assert_pack_identity(&first_packs[0], &read.packs()[0])?;
        ensure!(read.packs()[0].joined_revision() == Some(first_rev), "first pack joined revision differs");
        ensure!(
            read.complete_registered_pack_membership() && read.packs_complete() && !read.complete_git_read_snapshot(),
            "read data claims differ"
        );
        let second_packs = verify_advance(&db, &store, &mut v, 2, b"second verified commit\n").await?;
        ensure!(v.gate.revision() == first_rev + 1, "second commit did not advance the gate");
        let after_second = pack_usage(&db.pool, v.repo).await?;
        let replayed = a5_create(&db.pool, &request).await?;
        ensure!(
            replayed.replayed && replayed.receipt == created.receipt,
            "old create did not replay its exact receipt"
        );
        ensure!(pack_usage(&db.pool, v.repo).await? == after_second, "create replay charged quota twice");
        let old = a5_read(&db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1).await?;
        ensure!(
            old.gate_revision() == first_rev && old.refs()[0].oid_hex() == first_oid.as_str() && old.packs().len() == 1,
            "old snapshot read mixed with the newer revision"
        );
        assert_pack_identity(&first_packs[0], &old.packs()[0])?;
        let producer_scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (request2, _, snapshot2, pin2) = a5_request(producer_scope, &v.gate, 300)?;
        let created2 = a5_create(&db.pool, &request2).await?;
        ensure!(
            !created2.replayed && created2.receipt.pack_count() == 2 && created2.receipt.ref_count() == 1,
            "new revision receipt is not two packs/one ref"
        );
        let read2 = a5_read(&db.pool, v.repo, v.tenant, snapshot2, pin2, 1).await?;
        ensure!(
            read2.gate_revision() == v.gate.revision() && read2.refs()[0].oid_hex() == v.commit_oid.as_str(),
            "new read is not the advanced revision"
        );
        ensure!(read2.packs().len() == 2, "new read did not capture both registered packs");
        let joined_new = membership_joined(&db.pool, v.repo, second_packs[0].pack_id()).await?;
        ensure!(joined_new == v.gate.revision(), "new pack joined revision differs");
        for expected in first_packs.iter().chain(second_packs.iter()) {
            let actual = read2
                .packs()
                .iter()
                .find(|pack| pack.pack_id() == expected.pack_id())
                .ok_or_else(|| anyhow!("read omitted a registered pack"))?;
            assert_pack_identity(expected, actual)?;
        }
        ensure!(
            read2.complete_registered_pack_membership() && !read2.complete_git_read_snapshot(),
            "new read cargo claims differ"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
async fn a2_renew(pool: &Pool, request: &RenewMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.renew_metadata_pin(&mut client, request, deadline()).await
}
async fn a2_release(pool: &Pool, request: &ReleaseMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.release_metadata_pin(&mut client, request, deadline()).await
}
async fn a2_receipt(
    pool: &Pool,
    scope: MetadataSnapshotScope,
    request_id: Uuid,
) -> Result<MetadataReceiptLookup, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.metadata_receipt(&mut client, &scope, request_id, deadline()).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn old_a2_fence_replay_and_pack_aware_lifecycle_charges() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (tenant, repo) = db.business(GitObjectFormat::Sha1).await?;
        let gate = db.gate(repo, tenant, GitObjectFormat::Sha1).await?;
        let old = create_old(&db, tenant, repo, &gate).await?;
        let old_scope = *old.request.scope();
        let v = verify_existing(&db, &store, &git, tenant, repo, gate, GitObjectFormat::Sha1).await?;
        let counts_before = snapshot_counts(&db.pool, repo).await?;
        let usage_before = pack_usage(&db.pool, repo).await?;
        let fresh_scope = scope_for(repo, tenant, tenant, &v.gate, MetadataPinPurpose::Verification)?;
        let fresh = CreateMetadataSnapshotRequest::new(
            fresh_scope,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            300,
            *v.gate.digest(),
        )?;
        match a2_create(&db.pool, &fresh).await {
            Err(RefStoreError::Unsupported(_)) => {}
            other => panic!("fresh A2 create on a pack_verified gate was not refused: {other:?}"),
        }
        ensure!(snapshot_counts(&db.pool, repo).await? == counts_before, "refused A2 create wrote rows");
        ensure!(pack_usage(&db.pool, repo).await? == usage_before, "refused A2 create charged quota");
        let replay = a2_create(&db.pool, &old.request).await?;
        ensure!(
            replay.replayed && replay.receipt.snapshot_id() == old.snapshot_id && replay.receipt.pin_id() == old.pin_id,
            "old A2 receipt did not replay exactly"
        );
        ensure!(replay.receipt.gate_revision() == old.page.gate_revision(), "old A2 replay changed its gate revision");
        let page = old_page(&db.pool, old_scope, &old, 1).await?;
        ensure!(page == old.page && page.complete(), "old A2 page changed after pack activation");
        let renew = RenewMetadataPinRequest::new(old_scope, Uuid::new_v4(), old.pin_id, 1, 300)?;
        let renewed = a2_renew(&db.pool, &renew).await?;
        ensure!(!renewed.replayed && renewed.receipt.pin_generation() == 2, "old A2 renew did not advance once");
        let page2 = old_page(&db.pool, old_scope, &old, 2).await?;
        ensure!(
            page2.refs() == old.page.refs() && page2.gate_revision() == old.page.gate_revision(),
            "old A2 page content changed after renew"
        );
        let release =
            ReleaseMetadataPinRequest::new(old_scope, Uuid::new_v4(), old.pin_id, 2, PinReleaseReason::ClientDone)?;
        let released = a2_release(&db.pool, &release).await?;
        ensure!(
            !released.replayed && released.receipt.released_at_unix_micros().is_some(),
            "old A2 release did not record a release"
        );
        let page_error = old_page(&db.pool, old_scope, &old, 2).await.expect_err("released old A2 pin still served a page");
        ensure!(matches!(page_error.downcast_ref::<RefStoreError>(), Some(RefStoreError::MetadataPinReleased { pin_id, .. }) if *pin_id == old.pin_id), "released old A2 pin failed for another reason: {page_error}");
        match a2_receipt(&db.pool, old_scope, old.request.request_id()).await? {
            MetadataReceiptLookup::Found(MetadataReceipt::Snapshot(receipt)) => {
                ensure!(receipt.gate_revision() == old.page.gate_revision(), "old A2 receipt page revision changed");
            }
            other => panic!("old A2 create receipt disappeared: {other:?}"),
        }
        let producer = Uuid::new_v4();
        let scope = scope_for(repo, tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (create, _, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        let created = a5_create(&db.pool, &create).await?;
        ensure!(!created.replayed, "fresh pack create replayed");
        let before_renew = pack_usage(&db.pool, repo).await?.ok_or_else(|| anyhow!("pack usage missing"))?;
        let a2_before = a2_usage(&db.pool, repo).await?;
        let renew_pack = RenewMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 1, 300)?;
        let renew_pack_id = renew_pack.request_id();
        let pack_renewed = a2_renew(&db.pool, &renew_pack).await?;
        ensure!(
            !pack_renewed.replayed && pack_renewed.receipt.pin_generation() == 2,
            "pack-aware renew did not advance"
        );
        let after_renew = pack_usage(&db.pool, repo).await?.ok_or_else(|| anyhow!("pack usage missing"))?;
        ensure!(
            after_renew[4] == before_renew[4] + 1
                && after_renew[5] == before_renew[5] + 1
                && after_renew[6] > before_renew[6],
            "renew did not charge permanent history/receipt/bytes"
        );
        ensure!(
            after_renew[0] == before_renew[0] && after_renew[2] == before_renew[2] && after_renew[3] == before_renew[3],
            "renew changed snapshot/binding/pin counters"
        );
        let a2_after = a2_usage(&db.pool, repo).await?;
        ensure!(
            a2_after[3] == a2_before[3] + 1 && a2_after[2] > a2_before[2],
            "renew did not charge the A2 receipt ledger"
        );
        match a5_query(&db.pool, scope, renew_pack_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(
                    receipt.action() == MetadataMutationAction::Renew && receipt.history_kind() == "renewed",
                    "renew lookup kind differs"
                );
                ensure!(
                    receipt.snapshot_id() == snapshot_id && receipt.pin_id() == pin_id && !receipt.grants_live_lease(),
                    "renew lookup identity/authority differs"
                );
            }
            other => panic!("renew receipt is not a typed FoundPin: {other:?}"),
        }
        let release_pack =
            ReleaseMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 2, PinReleaseReason::ClientDone)?;
        let release_pack_id = release_pack.request_id();
        let pack_released = a2_release(&db.pool, &release_pack).await?;
        ensure!(
            !pack_released.replayed && pack_released.receipt.released_at_unix_micros().is_some(),
            "pack-aware release did not record"
        );
        let after_release = pack_usage(&db.pool, repo).await?.ok_or_else(|| anyhow!("pack usage missing"))?;
        ensure!(
            after_release[4] == after_renew[4] + 1
                && after_release[5] == after_renew[5] + 1
                && after_release[6] > after_renew[6],
            "release did not charge permanent history/receipt/bytes"
        );
        match a5_query(&db.pool, scope, release_pack_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(
                    receipt.action() == MetadataMutationAction::Release
                        && receipt.history_kind() == "released"
                        && receipt.released_at_unix_micros().is_some(),
                    "release lookup differs"
                );
            }
            other => panic!("release receipt is not a typed FoundPin: {other:?}"),
        }
        match a5_read(&db.pool, repo, tenant, snapshot_id, pin_id, 2).await {
            Err(RefStoreError::MetadataPinReleased { pin_id: id, .. }) if id == pin_id => {}
            other => panic!("released pack pin still served a read: {other:?}"),
        }
        let replayed_release = a2_release(&db.pool, &release_pack).await?;
        ensure!(replayed_release.replayed, "exact release retry did not replay");
        ensure!(pack_usage(&db.pool, repo).await? == Some(after_release), "release replay charged twice");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn gate_capture_race_serializes_with_a4_commit_on_distinct_backends() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let captured_revision = v.gate.revision();
        let old_oid = v.commit_oid.clone();
        let prepared = prepare_advance(&db, &store, &v, 2, b"race commit\n").await?;
        let new_oid = prepared.new_oid.clone();
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (request, _, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        let key = random_key();
        let observer = db.new_pool(4)?;
        let barrier = acquire_barrier(&observer, key).await?;
        install_snapshot_park(&db.pool, key).await?;
        let writer_a5 = db.new_pool(1)?;
        let writer_a4 = db.new_pool(1)?;
        let (a5_pid_tx, a5_pid_rx) = oneshot::channel::<i32>();
        let req = request.clone();
        let a5_task = tokio::spawn(async move {
            let mut client = writer_a5.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = a5_pid_tx.send(pid);
            let result = PgPackSnapshot.create(&mut client, &req, deadline()).await;
            Ok::<_, anyhow::Error>((pid, result))
        });
        let a5_pid = a5_pid_rx.await.map_err(|_| anyhow!("A5 create never reported its pid"))?;
        wait_advisory_key(&observer, a5_pid, key).await?;
        let observer_client = observer.get().await?;
        let holds_gate: bool = observer_client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation'
                AND relation='ref_store_core_gates'::regclass AND granted)",
                &[&a5_pid],
            )
            .await?
            .get(0);
        ensure!(holds_gate, "parked A5 capture does not hold the core gate lock");
        let (a4_pid_tx, a4_pid_rx) = oneshot::channel::<i32>();
        let a4_task = tokio::spawn(async move {
            let mut client = writer_a4.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = a4_pid_tx.send(pid);
            let result = PgPackCommit
                .commit_verified_pending(&mut client, &prepared.plan, &prepared.token, &prepared.proof, deadline())
                .await;
            Ok::<_, anyhow::Error>((pid, result))
        });
        let a4_pid = a4_pid_rx.await.map_err(|_| anyhow!("A4 commit never reported its pid"))?;
        ensure!(a4_pid != a5_pid, "A5 capture and A4 commit shared one backend");
        wait_blocked_by(&observer, a4_pid, a5_pid).await?;
        ensure!(!a5_task.is_finished() && !a4_task.is_finished(), "a backend escaped the barrier");
        barrier.release().await?;
        let (_, a5_result) = a5_task.await.map_err(|_| anyhow!("A5 capture task failed"))??;
        let (_, a4_result) = a4_task.await.map_err(|_| anyhow!("A4 commit task failed"))??;
        drop_snapshot_park(&db.pool).await?;
        let created = a5_result?;
        let a4_receipt = a4_result?;
        ensure!(
            !created.replayed && created.receipt.gate_revision() == captured_revision,
            "A5 capture did not commit the pre-race revision"
        );
        ensure!(
            a4_receipt.is_committed() && a4_receipt.terminal.revision == captured_revision + 1,
            "A4 commit did not follow the capture revision"
        );
        let gate = gate_version(&db.pool, v.repo, v.tenant).await?;
        ensure!(gate.revision() == captured_revision + 1, "gate did not advance after both commits");
        let read = a5_read(&db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1).await?;
        ensure!(
            read.gate_revision() == captured_revision && read.refs().len() == 1,
            "captured snapshot mixed revisions"
        );
        ensure!(
            read.refs()[0].oid_hex() == old_oid.as_str() && read.refs()[0].oid_hex() != new_oid.as_str(),
            "captured snapshot contains the later A4 ref"
        );
        ensure!(
            read.packs().len() == 1 && read.packs()[0].pack_id() == v.new_packs[0].pack_id(),
            "captured snapshot mixed pack membership"
        );
        let after = a5_read(&db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1).await?;
        ensure!(
            after.gate_revision() == captured_revision && after.snapshot_digest_hex() == read.snapshot_digest_hex(),
            "old snapshot changed after A4 advanced the realm"
        );
        let counts = snapshot_counts(&db.pool, v.repo).await?;
        ensure!(counts.0 == 1 && counts.4 == 1, "race wrote an extra snapshot/binding");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
fn assert_probe(values: &[(String, String)], expected: &[&str]) -> Result<()> {
    ensure!(!values.is_empty(), "durable write probe recorded no rows");
    for (source, value) in values {
        ensure!(value.as_str() == "on", "probe observed non-durable synchronous_commit at {source}");
    }
    for source in expected {
        ensure!(
            values.iter().any(|(name, _)| name.as_str() == *source),
            "durable write probe missing table coverage: {source}"
        );
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn session_off_still_acknowledges_durably_and_gate_deadline_is_recoverable() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (tenant_m, repo_m) = db.business(GitObjectFormat::Sha1).await?;
        let gate_m = db.gate(repo_m, tenant_m, GitObjectFormat::Sha1).await?;
        install_sync_probe(&db.pool).await?;
        let off = db.off_pool(1)?;
        let mut client = off.get().await?;
        ensure!(show_sync(&client).await == "off", "off pool did not start with synchronous_commit=off");
        let metadata_scope = scope_for(repo_m, tenant_m, tenant_m, &gate_m, MetadataPinPurpose::Verification)?;
        let metadata = CreateMetadataSnapshotRequest::new(
            metadata_scope,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            300,
            *gate_m.digest(),
        )?;
        PgRefStoreCore.create_metadata_snapshot(&mut client, &metadata, deadline()).await?;
        assert_probe(
            &probe_values(&db.pool).await?,
            &[
                "ref_store_core_snapshots:INSERT",
                "ref_store_core_pins:INSERT",
                "ref_store_core_receipts:INSERT",
                "ref_store_core_repo_usage:INSERT",
                "ref_store_core_repo_usage:UPDATE",
                "ref_store_core_tenant_usage:INSERT",
                "ref_store_core_tenant_usage:UPDATE",
            ],
        )?;
        ensure!(show_sync(&client).await == "off", "A2 create leaked SET LOCAL synchronous_commit");
        clear_probe(&db.pool).await?;
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (create, _, _snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        PgPackSnapshot.create(&mut client, &create, deadline()).await?;
        assert_probe(
            &probe_values(&db.pool).await?,
            &[
                "ref_store_core_snapshots:INSERT",
                "ref_store_core_pins:INSERT",
                "ref_store_core_receipts:INSERT",
                "ref_store_core_snapshot_packs:INSERT",
                "ref_store_core_pack_snapshot_history:INSERT",
                "ref_store_core_pack_snapshot_repo_usage:INSERT",
                "ref_store_core_pack_snapshot_repo_usage:UPDATE",
                "ref_store_core_pack_snapshot_tenant_usage:INSERT",
                "ref_store_core_pack_snapshot_tenant_usage:UPDATE",
                "ref_store_core_repo_usage:INSERT",
                "ref_store_core_repo_usage:UPDATE",
                "ref_store_core_tenant_usage:INSERT",
                "ref_store_core_tenant_usage:UPDATE",
            ],
        )?;
        ensure!(show_sync(&client).await == "off", "A5 create leaked SET LOCAL synchronous_commit");
        clear_probe(&db.pool).await?;
        let renew = RenewMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 1, 300)?;
        PgRefStoreCore.renew_metadata_pin(&mut client, &renew, deadline()).await?;
        assert_probe(
            &probe_values(&db.pool).await?,
            &[
                "ref_store_core_pins:UPDATE",
                "ref_store_core_receipts:INSERT",
                "ref_store_core_pack_snapshot_history:INSERT",
                "ref_store_core_pack_snapshot_repo_usage:INSERT",
                "ref_store_core_pack_snapshot_repo_usage:UPDATE",
                "ref_store_core_pack_snapshot_tenant_usage:INSERT",
                "ref_store_core_pack_snapshot_tenant_usage:UPDATE",
                "ref_store_core_repo_usage:INSERT",
                "ref_store_core_repo_usage:UPDATE",
                "ref_store_core_tenant_usage:INSERT",
                "ref_store_core_tenant_usage:UPDATE",
            ],
        )?;
        ensure!(show_sync(&client).await == "off", "A5 renew leaked SET LOCAL synchronous_commit");
        clear_probe(&db.pool).await?;
        let release = ReleaseMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 2, PinReleaseReason::ClientDone)?;
        PgRefStoreCore.release_metadata_pin(&mut client, &release, deadline()).await?;
        assert_probe(
            &probe_values(&db.pool).await?,
            &[
                "ref_store_core_pins:UPDATE",
                "ref_store_core_receipts:INSERT",
                "ref_store_core_pack_snapshot_history:INSERT",
                "ref_store_core_pack_snapshot_repo_usage:INSERT",
                "ref_store_core_pack_snapshot_repo_usage:UPDATE",
                "ref_store_core_pack_snapshot_tenant_usage:INSERT",
                "ref_store_core_pack_snapshot_tenant_usage:UPDATE",
                "ref_store_core_repo_usage:INSERT",
                "ref_store_core_repo_usage:UPDATE",
                "ref_store_core_tenant_usage:INSERT",
                "ref_store_core_tenant_usage:UPDATE",
            ],
        )?;
        ensure!(show_sync(&client).await == "off", "A5 release leaked SET LOCAL synchronous_commit");
        clear_probe(&db.pool).await?;
        let refused_scope = scope_for(v.repo, v.tenant, v.tenant, &v.gate, MetadataPinPurpose::Verification)?;
        let refused = CreateMetadataSnapshotRequest::new(
            refused_scope,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            300,
            *v.gate.digest(),
        )?;
        match PgRefStoreCore.create_metadata_snapshot(&mut client, &refused, deadline()).await {
            Err(RefStoreError::Unsupported(_)) => {}
            other => panic!("fresh A2 create on pack gate was not refused: {other:?}"),
        }
        ensure!(probe_values(&db.pool).await?.is_empty(), "refused A2 create performed a probed write");
        ensure!(show_sync(&client).await == "off", "refused A2 create leaked SET LOCAL synchronous_commit");
        let (open, _, open_snapshot, open_pin) = a5_request(scope, &v.gate, 300)?;
        PgPackSnapshot.create(&mut client, &open, deadline()).await?;
        let blocker = GateBlock::hold(&db.pool, v.repo).await?;
        let observer = db.new_pool(4)?;
        let (blocked, _, _, _) = a5_request(scope, &v.gate, 300)?;
        let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        let started = StdInstant::now();
        let task = tokio::spawn(async move {
            let result =
                PgPackSnapshot.create(&mut client, &blocked, TokioInstant::now() + Duration::from_secs(2)).await;
            (client, result)
        });
        wait_lock_wait(&observer, pid).await?;
        let (mut client, capture) = task.await.map_err(|_| anyhow!("blocked A5 capture task failed"))?;
        let error = capture.expect_err("capture blocked on the gate succeeded");
        ensure!(bounded_refusal(&error), "blocked capture failed for another reason: {error}");
        ensure!(started.elapsed() >= Duration::from_millis(500), "blocked capture did not wait for its deadline");
        let _: i32 = client.query_one("SELECT 1", &[]).await?.get(0);
        ensure!(show_sync(&client).await == "off", "blocked capture leaked session durability setting");
        let reference = PackSnapshotRef::new(v.repo, v.tenant, open_snapshot, open_pin, 1)?;
        let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        let started = StdInstant::now();
        let task = tokio::spawn(async move {
            let result =
                PgPackSnapshot.read(&mut client, &reference, TokioInstant::now() + Duration::from_secs(2)).await;
            (client, result)
        });
        wait_lock_wait(&observer, pid).await?;
        let (mut client, read) = task.await.map_err(|_| anyhow!("blocked A5 read task failed"))?;
        let error = read.expect_err("read blocked on the gate succeeded");
        ensure!(bounded_refusal(&error), "blocked read failed for another reason: {error}");
        ensure!(started.elapsed() >= Duration::from_millis(500), "blocked read did not wait for its deadline");
        let _: i32 = client.query_one("SELECT 1", &[]).await?.get(0);
        ensure!(show_sync(&client).await == "off", "blocked read leaked session durability setting");
        blocker.release().await?;
        let recovered = PgPackSnapshot.read(&mut client, &reference, deadline()).await?;
        ensure!(
            recovered.snapshot_id() == open_snapshot && recovered.gate_revision() == v.gate.revision(),
            "recovered read differs"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn historical_scope_queries_survive_delete_and_ledger_corruption_is_never_an_ack() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (create, create_id, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &create).await?;
        let renew = RenewMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 1, 300)?;
        let renew_id = renew.request_id();
        a2_renew(&db.pool, &renew).await?;
        let release = ReleaseMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 2, PinReleaseReason::ClientDone)?;
        let release_id = release.request_id();
        a2_release(&db.pool, &release).await?;
        match a5_query(&db.pool, scope, create_id).await? {
            PackSnapshotLookup::Found(receipt) => {
                ensure!(receipt.snapshot_id() == snapshot_id && receipt.pin_id() == pin_id, "create lookup differs")
            }
            other => panic!("create receipt not Found: {other:?}"),
        }
        match a5_query(&db.pool, scope, renew_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(receipt.history_kind() == "renewed", "renew lookup differs")
            }
            other => panic!("renew receipt not FoundPin: {other:?}"),
        }
        match a5_query(&db.pool, scope, release_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(receipt.history_kind() == "released", "release lookup differs")
            }
            other => panic!("release receipt not FoundPin: {other:?}"),
        }
        let usage = pack_usage(&db.pool, v.repo).await?;
        let wrong_owner = MetadataSnapshotScope::new(
            v.repo,
            v.tenant,
            Uuid::new_v4(),
            MetadataPinPurpose::Verification,
            v.gate.object_format(),
            v.gate.history_incarnation(),
            v.gate.authority_epoch(),
            v.gate.group_epoch(),
        )?;
        ensure!(
            matches!(a5_query(&db.pool, wrong_owner, create_id).await, Err(RefStoreError::MetadataScopeMismatch(_))),
            "wrong owner query was not a scope refusal"
        );
        let wrong_tenant = MetadataSnapshotScope::new(
            v.repo,
            Uuid::new_v4(),
            producer,
            MetadataPinPurpose::Verification,
            v.gate.object_format(),
            v.gate.history_incarnation(),
            v.gate.authority_epoch(),
            v.gate.group_epoch(),
        )?;
        ensure!(
            matches!(a5_query(&db.pool, wrong_tenant, create_id).await, Err(RefStoreError::RepositoryNotFound)),
            "wrong tenant query was not refused"
        );
        let wrong_purpose = MetadataSnapshotScope::new(
            v.repo,
            v.tenant,
            producer,
            MetadataPinPurpose::Backup,
            v.gate.object_format(),
            v.gate.history_incarnation(),
            v.gate.authority_epoch(),
            v.gate.group_epoch(),
        )?;
        ensure!(
            matches!(a5_query(&db.pool, wrong_purpose, create_id).await, Err(RefStoreError::MetadataScopeMismatch(_))),
            "wrong purpose query was not refused"
        );
        let wrong_epoch = MetadataSnapshotScope::new(
            v.repo,
            v.tenant,
            producer,
            MetadataPinPurpose::Verification,
            v.gate.object_format(),
            v.gate.history_incarnation(),
            v.gate.authority_epoch() + 1,
            v.gate.group_epoch(),
        )?;
        ensure!(
            matches!(a5_query(&db.pool, wrong_epoch, create_id).await, Err(RefStoreError::MetadataScopeMismatch(_))),
            "wrong epoch query was not refused"
        );
        ensure!(
            matches!(a5_query(&db.pool, scope, Uuid::new_v4()).await?, PackSnapshotLookup::Unknown),
            "unknown request id was not Unknown"
        );
        ensure!(pack_usage(&db.pool, v.repo).await? == usage, "receipt queries charged or regranted quota");
        let (create2, create2_id, _, _) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &create2).await?;
        let corrupt_before = pack_usage(&db.pool, v.repo).await?;
        db.pool
            .get()
            .await?
            .batch_execute(&format!(
                "DROP TRIGGER ref_store_core_pack_snapshot_history_immutable ON ref_store_core_pack_snapshot_history;
             UPDATE ref_store_core_pack_snapshot_history SET body = body || ' ' WHERE request_id='{create2_id}';
             CREATE TRIGGER ref_store_core_pack_snapshot_history_immutable
               BEFORE UPDATE OR DELETE ON ref_store_core_pack_snapshot_history
               FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();"
            ))
            .await?;
        match a5_create(&db.pool, &create2).await {
            Err(RefStoreError::Database(_)) => {}
            other => panic!("mismatched permanent history partner must be ledger integrity: {other:?}"),
        }
        ensure!(pack_usage(&db.pool, v.repo).await? == corrupt_before, "corrupt replay charged quota");
        db.pool
            .get()
            .await?
            .batch_execute(&format!(
                "DROP TRIGGER ref_store_core_pack_snapshot_history_immutable ON ref_store_core_pack_snapshot_history;
             DELETE FROM ref_store_core_pack_snapshot_history WHERE request_id='{create2_id}';
             CREATE TRIGGER ref_store_core_pack_snapshot_history_immutable
               BEFORE UPDATE OR DELETE ON ref_store_core_pack_snapshot_history
               FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();"
            ))
            .await?;
        match a5_create(&db.pool, &create2).await {
            Err(RefStoreError::Database(_)) => {}
            other => panic!("missing permanent history partner must be ledger integrity: {other:?}"),
        }
        ensure!(pack_usage(&db.pool, v.repo).await? == corrupt_before, "missing-partner replay charged quota");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn permanent_ledger_survives_delete_and_cross_ledger_request_reuse_is_refused() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (create, create_id, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &create).await?;
        let renew = RenewMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 1, 300)?;
        let renew_id = renew.request_id();
        a2_renew(&db.pool, &renew).await?;
        let release = ReleaseMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 2, PinReleaseReason::ClientDone)?;
        let release_id = release.request_id();
        a2_release(&db.pool, &release).await?;
        let (active, active_id, active_snapshot, active_pin) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &active).await?;
        let retained = pack_usage(&db.pool, v.repo).await?.ok_or_else(|| anyhow!("pack usage missing"))?;
        let tenant_retained =
            pack_tenant_usage(&db.pool, v.tenant).await?.ok_or_else(|| anyhow!("tenant pack usage missing"))?;
        let repo = v.repo;
        scenario_assert_sqlstate(
            &db.pool,
            &format!(
                "UPDATE ref_store_core_pack_snapshot_repo_usage SET repository_id='{}' WHERE repository_id='{repo}'",
                Uuid::new_v4()
            ),
            "P0001",
        )
        .await?;
        scenario_assert_sqlstate(
            &db.pool,
            &format!(
                "UPDATE ref_store_core_pack_snapshot_repo_usage SET tenant_id='{}' WHERE repository_id='{repo}'",
                Uuid::new_v4()
            ),
            "P0001",
        )
        .await?;
        for statement in [
            format!("DELETE FROM ref_store_core_pack_snapshot_repo_usage WHERE repository_id='{repo}'"),
            "TRUNCATE ref_store_core_pack_snapshot_repo_usage".to_owned(),
            "TRUNCATE ref_store_core_pack_snapshot_tenant_usage".to_owned(),
            format!("DELETE FROM ref_store_core_pack_snapshot_history WHERE repository_id='{repo}'"),
            format!("UPDATE ref_store_core_pack_snapshot_history SET body=body WHERE repository_id='{repo}'"),
            format!("UPDATE ref_store_core_pack_snapshot_history SET kind=kind WHERE repository_id='{repo}'"),
            "TRUNCATE ref_store_core_pack_snapshot_history".to_owned(),
            format!("DELETE FROM ref_store_core_snapshot_packs WHERE repository_id='{repo}'"),
            "TRUNCATE ref_store_core_snapshot_packs".to_owned(),
            format!("DELETE FROM ref_store_core_snapshots WHERE repository_id='{repo}'"),
        ] {
            scenario_assert_sqlstate(&db.pool, &statement, "P0001").await?;
        }
        ensure!(pack_usage(&db.pool, v.repo).await? == Some(retained), "guarded DML changed retained counters");
        db.pool.get().await?.execute("DELETE FROM repositories WHERE id=$1", &[&v.repo]).await?;
        db.pool.get().await?.execute("DELETE FROM namespaces WHERE user_id=$1", &[&v.tenant]).await?;
        db.pool.get().await?.execute("DELETE FROM users WHERE id=$1", &[&v.tenant]).await?;
        ensure!(
            pack_usage(&db.pool, v.repo).await? == Some(retained),
            "repository delete removed or reset pack repo counters"
        );
        ensure!(
            pack_tenant_usage(&db.pool, v.tenant).await? == Some(tenant_retained),
            "user delete removed or reset pack tenant counters"
        );
        let retained_create = match a5_query(&db.pool, scope, create_id).await? {
            PackSnapshotLookup::Found(receipt) => {
                ensure!(receipt.snapshot_id() == snapshot_id, "retained create receipt differs");
                receipt
            }
            other => panic!("retained create receipt is not Found: {other:?}"),
        };
        match a5_query(&db.pool, scope, renew_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(
                    receipt.history_kind() == "renewed" && !receipt.grants_live_lease(),
                    "retained renew differs/granted lease"
                )
            }
            other => panic!("retained renew is not FoundPin: {other:?}"),
        }
        match a5_query(&db.pool, scope, release_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(
                    receipt.history_kind() == "released" && !receipt.grants_live_lease(),
                    "retained release differs/granted lease"
                )
            }
            other => panic!("retained release is not FoundPin: {other:?}"),
        }
        let exact_create = a5_create(&db.pool, &create).await?;
        ensure!(
            exact_create.replayed && exact_create.receipt == retained_create,
            "exact historical create did not replay after delete"
        );
        let exact_renew = a2_renew(&db.pool, &renew).await?;
        ensure!(
            exact_renew.replayed && exact_renew.receipt.pin_generation() == 2,
            "exact retained renew did not replay its historical generation"
        );
        let exact_release = a2_release(&db.pool, &release).await?;
        ensure!(
            exact_release.replayed && exact_release.receipt.released_at_unix_micros().is_some(),
            "exact retained release did not replay after delete"
        );
        ensure!(pack_usage(&db.pool, v.repo).await? == Some(retained), "exact post-delete replays wrote/charged rows");
        let changed_create = CreatePackSnapshotRequest::new(
            scope,
            create_id,
            pin_id,
            snapshot_id,
            301,
            PackSnapshotExpectation::new(v.gate.revision(), *v.gate.digest())?,
        )?;
        ensure!(
            matches!(a5_create(&db.pool, &changed_create).await, Err(RefStoreError::DigestConflict)),
            "changed create lease after delete was not DigestConflict"
        );
        let changed_gate = CreatePackSnapshotRequest::new(
            scope,
            create_id,
            pin_id,
            snapshot_id,
            300,
            PackSnapshotExpectation::new(v.gate.revision() + 1, *v.gate.digest())?,
        )?;
        ensure!(
            matches!(a5_create(&db.pool, &changed_gate).await, Err(RefStoreError::DigestConflict)),
            "changed expected gate after delete was not DigestConflict"
        );
        let changed_renew = RenewMetadataPinRequest::new(scope, renew_id, pin_id, 1, 301)?;
        ensure!(
            matches!(a2_renew(&db.pool, &changed_renew).await, Err(RefStoreError::DigestConflict)),
            "changed renew lease after delete was not DigestConflict"
        );
        let changed_release =
            ReleaseMetadataPinRequest::new(scope, release_id, pin_id, 2, PinReleaseReason::Superseded)?;
        ensure!(
            matches!(a2_release(&db.pool, &changed_release).await, Err(RefStoreError::DigestConflict)),
            "changed release reason after delete was not DigestConflict"
        );
        let action_reuse = RenewMetadataPinRequest::new(scope, create_id, pin_id, 1, 300)?;
        ensure!(
            matches!(a2_renew(&db.pool, &action_reuse).await, Err(RefStoreError::DigestConflict)),
            "create request id reused for a renew action after delete was not DigestConflict"
        );
        ensure!(
            pack_usage(&db.pool, v.repo).await? == Some(retained),
            "digest-conflict retries changed retained counters"
        );
        match a5_read(&db.pool, v.repo, v.tenant, active_snapshot, active_pin, 1).await {
            Err(RefStoreError::MetadataSnapshotNotFound { snapshot_id: id }) if id == active_snapshot => {}
            other => panic!("deleted repository still served an active full read: {other:?}"),
        }
        let v2 = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer2 = Uuid::new_v4();
        let scope2 = scope_for(v2.repo, v2.tenant, producer2, &v2.gate, MetadataPinPurpose::Verification)?;
        let reused_ids = CreatePackSnapshotRequest::new(
            scope2,
            Uuid::new_v4(),
            pin_id,
            snapshot_id,
            300,
            PackSnapshotExpectation::new(v2.gate.revision(), *v2.gate.digest())?,
        )?;
        match a5_create(&db.pool, &reused_ids).await {
            Err(RefStoreError::IdentityConflict) => {}
            other => panic!("reused snapshot/pin identity was not IdentityConflict: {other:?}"),
        }
        ensure!(pack_usage(&db.pool, v2.repo).await?.is_none(), "identity-conflict create charged quota");
        let reused_request = CreatePackSnapshotRequest::new(
            scope2,
            create_id,
            Uuid::new_v4(),
            Uuid::new_v4(),
            300,
            PackSnapshotExpectation::new(v2.gate.revision(), *v2.gate.digest())?,
        )?;
        ensure!(
            matches!(a5_create(&db.pool, &reused_request).await, Err(RefStoreError::IdentityConflict)),
            "reused cross-ledger request id did not yield IdentityConflict"
        );
        ensure!(pack_usage(&db.pool, v2.repo).await?.is_none(), "cross-ledger A5 reuse charged quota");
        let (tenant3, repo3) = db.business(GitObjectFormat::Sha1).await?;
        let gate3 = db.gate(repo3, tenant3, GitObjectFormat::Sha1).await?;
        let scope3 = scope_for(repo3, tenant3, tenant3, &gate3, MetadataPinPurpose::Verification)?;
        let reused_a2 = CreateMetadataSnapshotRequest::new(
            scope3,
            create_id,
            Uuid::new_v4(),
            Uuid::new_v4(),
            300,
            *gate3.digest(),
        )?;
        ensure!(
            matches!(a2_create(&db.pool, &reused_a2).await, Err(RefStoreError::IdentityConflict)),
            "reused cross-ledger A2 request id did not yield IdentityConflict"
        );
        let reused_a5_ids_a2 =
            CreateMetadataSnapshotRequest::new(scope3, Uuid::new_v4(), pin_id, snapshot_id, 300, *gate3.digest())?;
        ensure!(
            matches!(a2_create(&db.pool, &reused_a5_ids_a2).await, Err(RefStoreError::IdentityConflict)),
            "old A2 API reused retained A5 snapshot/pin identity"
        );
        ensure!(a2_usage(&db.pool, repo3).await? == [0; 4], "cross-ledger A2 reuse charged quota");
        ensure!(snapshot_counts(&db.pool, repo3).await? == (0, 0, 0, 0, 0), "cross-ledger A2 reuse wrote rows");
        ensure!(pack_usage(&db.pool, v2.repo).await?.is_none() && active_id != create_id, "fixture ids collided");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
/// Bounded refusal diagnostics: actual SQLSTATE, the database message and the exact refused statement.
/// Output is clipped and a client-side failure never echoes a connection URL (it may embed
/// credentials), so a wrong guard expectation is debuggable without leaking the test profile.
fn sql_refusal_diagnostic(statement: &str, error: &tokio_postgres::Error) -> String {
    fn clip(text: &str, limit: usize) -> String {
        let flat: String = text.chars().map(|character| if character.is_control() { ' ' } else { character }).collect();
        match flat.char_indices().nth(limit) {
            Some((index, _)) => format!("{}...", &flat[..index]),
            None => flat,
        }
    }
    let code = error.code().map(|code| code.code()).unwrap_or("<no-sqlstate>");
    let message = error
        .as_db_error()
        .map(|db| match db.detail() {
            Some(detail) => format!("{} (detail: {detail})", db.message()),
            None => db.message().to_owned(),
        })
        .unwrap_or_else(|| "no database error body (client-side failure)".to_owned());
    format!("actual SQLSTATE {code}; db message `{}`; statement `{}`", clip(&message, 240), clip(statement, 160))
}
async fn expect_client_sqlstate(client: &tokio_postgres::Client, statement: &str, expected: &str) -> Result<()> {
    let error = client.batch_execute(statement).await.expect_err("statement must be refused");
    let actual = error.code().map(|code| code.code());
    ensure!(actual == Some(expected), "expected SQLSTATE {expected} but saw {}", sql_refusal_diagnostic(statement, &error));
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn header_check_constraints_and_permanent_bounds_refuse_without_partial_charge() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (create, _, snapshot_id, _) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &create).await?;
        let client = db.pool.get().await?;
        client.batch_execute("CREATE TEMP TABLE fixture_a5_header_clone (LIKE ref_store_core_snapshots INCLUDING CONSTRAINTS INCLUDING DEFAULTS)").await?;
        client.execute("INSERT INTO fixture_a5_header_clone SELECT * FROM ref_store_core_snapshots WHERE snapshot_id=$1", &[&snapshot_id]).await?;
        let valid: i64 = client.query_one("SELECT count(*) FROM fixture_a5_header_clone", &[]).await?.get(0);
        ensure!(valid == 1, "valid pack header did not copy into the constrained clone");
        expect_client_sqlstate(&client, &format!("UPDATE fixture_a5_header_clone SET membership_digest=NULL WHERE snapshot_id='{snapshot_id}'"), "23514").await?;
        expect_client_sqlstate(&client, &format!("UPDATE fixture_a5_header_clone SET snapshot_digest=NULL WHERE snapshot_id='{snapshot_id}'"), "23514").await?;
        expect_client_sqlstate(&client, &format!("UPDATE fixture_a5_header_clone SET membership_digest='zz' WHERE snapshot_id='{snapshot_id}'"), "23514").await?;
        let still_valid: i64 = client.query_one("SELECT count(*) FROM fixture_a5_header_clone WHERE membership_digest IS NOT NULL AND snapshot_digest IS NOT NULL", &[]).await?.get(0);
        ensure!(still_valid == 1, "failed NULL probes changed the valid clone row");
        let repo = v.repo;
        expect_client_sqlstate(&client, &format!("UPDATE ref_store_core_pack_snapshot_repo_usage SET snapshot_count=65 WHERE repository_id='{repo}'"), "23514").await?;
        expect_client_sqlstate(&client, &format!("UPDATE ref_store_core_pack_snapshot_repo_usage SET snapshot_ref_count=16385 WHERE repository_id='{repo}'"), "23514").await?;
        expect_client_sqlstate(&client, &format!("UPDATE ref_store_core_pack_snapshot_repo_usage SET binding_count=1025 WHERE repository_id='{repo}'"), "23514").await?;
        expect_client_sqlstate(&client, &format!("UPDATE ref_store_core_pack_snapshot_repo_usage SET snapshot_count=snapshot_count-1 WHERE repository_id='{repo}'"), "P0001").await?;
        // Migration 142's row-level BEFORE DELETE immutability trigger raises P0001 before the
        // migration-143 A5 FK RESTRICT could ever raise 23503, so the observed runtime guard
        // SQLSTATE is P0001. The RESTRICT binding itself is asserted structurally below.
        expect_client_sqlstate(
            &client,
            &format!("DELETE FROM ref_store_core_pack_memberships WHERE repository_id='{repo}'"),
            "P0001",
        )
        .await?;
        let binding_fk = client
            .query(
                "SELECT c.convalidated, c.confdeltype::text,
                        (SELECT coalesce(string_agg(a.attname::text, ',' ORDER BY a.attname), '')
                           FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
                           JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum),
                        (SELECT coalesce(string_agg(a.attname::text, ',' ORDER BY a.attname), '')
                           FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum, ord)
                           JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum),
                        (SELECT coalesce(bool_and(ca.attname = fa.attname), false)
                           FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
                           JOIN pg_attribute ca ON ca.attrelid = c.conrelid AND ca.attnum = k.attnum
                           JOIN unnest(c.confkey) WITH ORDINALITY AS r(attnum, ord) ON r.ord = k.ord
                           JOIN pg_attribute fa ON fa.attrelid = c.confrelid AND fa.attnum = r.attnum),
                        pg_get_constraintdef(c.oid)
                   FROM pg_constraint c
                  WHERE c.contype = 'f'
                    AND c.conrelid = 'ref_store_core_snapshot_packs'::regclass
                    AND c.confrelid = 'ref_store_core_pack_memberships'::regclass",
                &[],
            )
            .await?;
        ensure!(binding_fk.len() == 1, "expected exactly one A5 binding -> membership FK, saw {}", binding_fk.len());
        let validated: bool = binding_fk[0].get(0);
        let delete_action: String = binding_fk[0].get(1);
        let binding_columns: String = binding_fk[0].get(2);
        let membership_columns: String = binding_fk[0].get(3);
        let same_names: bool = binding_fk[0].get(4);
        let definition: String = binding_fk[0].get(5);
        let exact_columns = "artifact_set_digest,pack_id,registration_id,repository_id";
        ensure!(validated, "A5 binding -> membership FK is not validated: {definition}");
        ensure!(
            delete_action == "r",
            "A5 binding -> membership FK delete action is {delete_action}, not RESTRICT: {definition}"
        );
        ensure!(same_names, "A5 binding -> membership FK pairs differently named columns: {definition}");
        ensure!(
            binding_columns == exact_columns && membership_columns == exact_columns,
            "A5 binding -> membership FK columns are {binding_columns} -> {membership_columns}, expected {exact_columns}: {definition}"
        );
        let usage_before = pack_usage(&db.pool, repo).await?;
        let counts_before = snapshot_counts(&db.pool, repo).await?;
        let stale = CreatePackSnapshotRequest::new(scope, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 300,
            PackSnapshotExpectation::new(v.gate.revision() - 1, *v.gate.digest())?)?;
        match a5_create(&db.pool, &stale).await {
            Err(RefStoreError::MetadataGateVersionMismatch) => {}
            other => panic!("stale gate capture was not a typed mismatch: {other:?}"),
        }
        let bad_epoch = MetadataSnapshotScope::new(repo, v.tenant, producer, MetadataPinPurpose::Verification, v.gate.object_format(), v.gate.history_incarnation(), v.gate.authority_epoch() + 1, v.gate.group_epoch())?;
        let wrong = CreatePackSnapshotRequest::new(bad_epoch, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 300,
            PackSnapshotExpectation::new(v.gate.revision(), *v.gate.digest())?)?;
        match a5_create(&db.pool, &wrong).await {
            Err(RefStoreError::MetadataScopeMismatch(_)) => {}
            other => panic!("wrong epoch capture was not a typed scope mismatch: {other:?}"),
        }
        ensure!(pack_usage(&db.pool, repo).await? == usage_before, "refused captures partially charged quota");
        ensure!(snapshot_counts(&db.pool, repo).await? == counts_before, "refused captures wrote snapshot rows");
        Ok::<(), anyhow::Error>(())
    }.await;
    db.finish(outcome).await
}
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn unknown_release_commit_resolves_after_whole_repository_delete() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (create, create_id, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &create).await?;
        let renew = RenewMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 1, 300)?;
        let renew_id = renew.request_id();
        a2_renew(&db.pool, &renew).await?;
        let release = ReleaseMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 2, PinReleaseReason::ClientDone)?;
        let release_id = release.request_id();
        let writer = db.new_pool(1)?;
        let observer = db.new_pool(4)?;
        let key = random_key();
        let barrier = acquire_barrier(&observer, key).await?;
        install_receipt_park(&db.pool, key).await?;
        let (pid_tx, pid_rx) = oneshot::channel::<i32>();
        let (returned_tx, returned_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let req = release.clone();
        let writer_task = writer.clone();
        let task = tokio::spawn(async move {
            let mut client = writer_task.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = pid_tx.send(pid);
            let result = PgRefStoreCore
                .release_metadata_pin(&mut client, &req, TokioInstant::now() + Duration::from_secs(2))
                .await;
            let _ = returned_tx.send(());
            let _ = release_rx.await;
            client.batch_execute("SELECT 1").await?;
            Ok::<_, anyhow::Error>((pid, result))
        });
        let pid = pid_rx.await.map_err(|_| anyhow!("unknown-release backend never reported its pid"))?;
        wait_advisory_key(&observer, pid, key).await?;
        ensure!(
            matches!(a5_query(&observer, scope, release_id).await?, PackSnapshotLookup::Unknown),
            "uncommitted release was visible"
        );
        returned_rx.await.map_err(|_| anyhow!("release never returned at its deadline"))?;
        barrier.release().await?;
        let _ = release_tx.send(());
        let (_pid, result) = task.await.map_err(|_| anyhow!("unknown release task failed"))??;
        match result {
            Err(RefStoreError::MetadataCommitUnknown { request_id, action, .. }) => {
                ensure!(
                    request_id == release_id && action == MetadataMutationAction::Release,
                    "unknown release identity differs"
                );
            }
            other => panic!("parked release COMMIT did not return MetadataCommitUnknown: {other:?}"),
        }
        drop_receipt_park(&db.pool).await?;
        let release_usage = pack_usage(&db.pool, v.repo).await?;
        match a5_query(&observer, scope, release_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(
                    receipt.history_kind() == "released"
                        && receipt.snapshot_id() == snapshot_id
                        && receipt.pin_id() == pin_id,
                    "resolved release differs"
                );
            }
            other => panic!("committed release is not FoundPin: {other:?}"),
        }
        let retried = a2_release(&observer, &release).await?;
        ensure!(retried.replayed, "exact release retry did not replay");
        ensure!(pack_usage(&db.pool, v.repo).await? == release_usage, "release retry duplicated charges");
        db.pool.get().await?.execute("DELETE FROM repositories WHERE id=$1", &[&v.repo]).await?;
        db.pool.get().await?.execute("DELETE FROM namespaces WHERE user_id=$1", &[&v.tenant]).await?;
        db.pool.get().await?.execute("DELETE FROM users WHERE id=$1", &[&v.tenant]).await?;
        ensure!(pack_usage(&db.pool, v.repo).await? == release_usage, "repository delete reset retained pack counters");
        match a5_query(&observer, scope, create_id).await? {
            PackSnapshotLookup::Found(receipt) => {
                ensure!(receipt.snapshot_id() == snapshot_id, "post-delete create receipt differs")
            }
            other => panic!("post-delete create receipt is not Found: {other:?}"),
        }
        match a5_query(&observer, scope, renew_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(receipt.history_kind() == "renewed", "post-delete renew differs")
            }
            other => panic!("post-delete renew is not FoundPin: {other:?}"),
        }
        match a5_query(&observer, scope, release_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(receipt.history_kind() == "released", "post-delete release differs")
            }
            other => panic!("post-delete release is not FoundPin: {other:?}"),
        }
        ensure!(
            a5_read(&db.pool, v.repo, v.tenant, snapshot_id, pin_id, 2).await.is_err(),
            "deleted repository still served a read"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn realm_expiry_generation_fences_and_cancelled_a4_publication() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (create, _, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &create).await?;
        match a5_read(&db.pool, v.repo, v.tenant, snapshot_id, pin_id, 2).await {
            Err(RefStoreError::MetadataPinGenerationMismatch { expected: 2, actual: 1, .. }) => {}
            other => panic!("wrong pin generation was not a typed mismatch: {other:?}"),
        }
        let release = ReleaseMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 1, PinReleaseReason::ClientDone)?;
        a2_release(&db.pool, &release).await?;
        match a5_read(&db.pool, v.repo, v.tenant, snapshot_id, pin_id, 1).await {
            Err(RefStoreError::MetadataPinReleased { pin_id: id, .. }) if id == pin_id => {}
            other => panic!("released pin still served a read: {other:?}"),
        }
        let (short, _, short_snapshot, short_pin) = a5_request(scope, &v.gate, 1)?;
        a5_create(&db.pool, &short).await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let expired: bool = db
                    .pool
                    .get()
                    .await?
                    .query_one(
                        "SELECT clock_timestamp() >= expires_at FROM ref_store_core_pins WHERE pin_id=$1",
                        &[&short_pin],
                    )
                    .await?
                    .get(0);
                if expired {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| anyhow!("DB clock never reached the short lease expiry"))??;
        match a5_read(&db.pool, v.repo, v.tenant, short_snapshot, short_pin, 1).await {
            Err(RefStoreError::MetadataPinExpired { pin_id: id, .. }) if id == short_pin => {}
            other => panic!("DB-clock expired pin still served a read: {other:?}"),
        }
        let (realm, _, realm_snapshot, realm_pin) = a5_request(scope, &v.gate, 300)?;
        a5_create(&db.pool, &realm).await?;
        let repo = v.repo;
        for column in ["authority_epoch", "group_epoch", "history_incarnation"] {
            let bump = if column == "history_incarnation" {
                format!("{column} = gen_random_uuid()")
            } else {
                format!("{column} = {column} + 1")
            };
            db.pool
                .get()
                .await?
                .batch_execute(&format!("UPDATE ref_store_core_gates SET {bump} WHERE repository_id='{repo}'"))
                .await?;
            match a5_read(&db.pool, v.repo, v.tenant, realm_snapshot, realm_pin, 1).await {
                Err(RefStoreError::MetadataScopeMismatch(_)) => {}
                other => panic!("changed gate {column} did not fence the read: {other:?}"),
            }
            let restore = if column == "history_incarnation" {
                format!("{column} = '{}'", v.gate.history_incarnation())
            } else {
                format!(
                    "{column} = {}",
                    if column == "authority_epoch" { v.gate.authority_epoch() } else { v.gate.group_epoch() }
                )
            };
            db.pool
                .get()
                .await?
                .batch_execute(&format!("UPDATE ref_store_core_gates SET {restore} WHERE repository_id='{repo}'"))
                .await?;
        }
        let restored = gate_version(&db.pool, repo, v.tenant).await?;
        ensure!(restored.digest() == v.gate.digest(), "realm restore did not restore the gate digest");
        ensure!(
            a5_read(&db.pool, v.repo, v.tenant, realm_snapshot, realm_pin, 1).await?.gate_revision()
                == v.gate.revision(),
            "snapshot no longer reads after realm restore"
        );
        let (tenant_c, repo_c) = db.business(GitObjectFormat::Sha1).await?;
        let gate_c = db.gate(repo_c, tenant_c, GitObjectFormat::Sha1).await?;
        let fixture = GitRepo::new(git.clone(), GitObjectFormat::Sha1).await?;
        let oid = fixture.build_commit("cancel.txt", b"cancel fixture\n", "cancel fixture").await?;
        fixture.update_ref("refs/heads/main", &oid).await?;
        let files = fixture.pack_all("cancel").await?;
        let cancel_draft = draft(
            &db,
            repo_c,
            tenant_c,
            1,
            &gate_c,
            vec![main_update(GitObjectFormat::Sha1, None, &oid)?],
            std::slice::from_ref(&files),
        )
        .await?;
        let publication = publish(&db, &store, &cancel_draft.plan, &files).await?;
        let pack_id = cancel_draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
        register(&db, &cancel_draft.plan, pack_id, &publication).await?;
        let mut client = db.pool.get().await?;
        let tx = client.transaction().await?;
        let cancel = PgRefStore.cancel(&tx, cancel_draft.plan.identity(), deadline()).await?;
        tx.commit().await?;
        drop(client);
        ensure!(cancel.tombstone_created, "A4 cancel did not record a durable tombstone");
        let context = closure(&db, &cancel_draft.plan).await?;
        let proof = prove(&store, &git, &cancel_draft.plan, &context).await?;
        let mut client = db.pool.get().await?;
        let error = PgPackCommit
            .commit_verified_pending(&mut client, &cancel_draft.plan, &cancel_draft.token, &proof, deadline())
            .await
            .expect_err("cancelled A4 publication still committed");
        ensure!(
            error.rejection().map(|rejection| rejection.code.as_str()) == Some("cancelled"),
            "cancelled A4 commit had another rejection: {error}"
        );
        let (revision, mode) = db
            .pool
            .get()
            .await?
            .query_one("SELECT revision,pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&repo_c])
            .await
            .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))?;
        ensure!(revision == gate_c.revision() && mode == "metadata_only", "cancelled A4 publication moved the gate");
        let memberships: i64 = db
            .pool
            .get()
            .await?
            .query_one("SELECT count(*) FROM ref_store_core_pack_memberships WHERE repository_id=$1", &[&repo_c])
            .await?
            .get(0);
        ensure!(memberships == 0, "cancelled A4 publication created active pack membership");
        let main: Option<String> = db
            .pool
            .get()
            .await?
            .query_opt(
                "SELECT oid FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name='refs/heads/main'",
                &[&repo_c],
            )
            .await?
            .map(|row| row.get(0));
        ensure!(main.is_none(), "cancelled A4 publication wrote a ref");
        let producer = Uuid::new_v4();
        let cancel_scope = scope_for(repo_c, tenant_c, producer, &gate_c, MetadataPinPurpose::Verification)?;
        let (blocked, _, _, _) = a5_request(cancel_scope, &gate_c, 300)?;
        match a5_create(&db.pool, &blocked).await {
            Err(RefStoreError::Unsupported(_)) => {}
            other => panic!("A5 create on a cancelled metadata_only gate was not Unsupported: {other:?}"),
        }
        ensure!(pack_usage(&db.pool, repo_c).await?.is_none(), "cancelled A4 publication let A5 create charge quota");
        ensure!(
            snapshot_counts(&db.pool, repo_c).await? == (0, 0, 0, 0, 0),
            "cancelled A4 publication let A5 create write rows"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn deadline_on_inflight_commit_returns_no_value_for_create_and_renew() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let v = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let producer = Uuid::new_v4();
        let scope = scope_for(v.repo, v.tenant, producer, &v.gate, MetadataPinPurpose::Verification)?;
        let (create, create_id, snapshot_id, pin_id) = a5_request(scope, &v.gate, 300)?;
        let writer = db.new_pool(1)?;
        let observer = db.new_pool(4)?;
        let key = random_key();
        let barrier = acquire_barrier(&observer, key).await?;
        install_receipt_park(&db.pool, key).await?;
        let (pid_tx, pid_rx) = oneshot::channel::<i32>();
        let (returned_tx, returned_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let req = create.clone();
        let writer_task = writer.clone();
        let task = tokio::spawn(async move {
            let mut client = writer_task.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = pid_tx.send(pid);
            let result = PgPackSnapshot.create(&mut client, &req, TokioInstant::now() + Duration::from_secs(2)).await;
            let _ = returned_tx.send(());
            let _ = release_rx.await;
            client.batch_execute("SELECT 1").await?;
            Ok::<_, anyhow::Error>((pid, result))
        });
        let pid = pid_rx.await.map_err(|_| anyhow!("unknown-create backend never reported its pid"))?;
        wait_advisory_key(&observer, pid, key).await?;
        ensure!(
            matches!(a5_query(&observer, scope, create_id).await?, PackSnapshotLookup::Unknown),
            "uncommitted create was visible to a full-scope query"
        );
        ensure!(!task.is_finished(), "unknown create returned before its client deadline");
        returned_rx.await.map_err(|_| anyhow!("create never returned at its deadline"))?;
        ensure!(!task.is_finished(), "create task finished while its COMMIT was still parked");
        barrier.release().await?;
        let _ = release_tx.send(());
        let (_pid, result) = task.await.map_err(|_| anyhow!("unknown create task failed"))??;
        match result {
            Err(RefStoreError::MetadataCommitUnknown { repository_id, request_id, pin_id: counted_pin, action }) => {
                ensure!(
                    repository_id == v.repo
                        && request_id == create_id
                        && counted_pin == pin_id
                        && action == MetadataMutationAction::Create,
                    "unknown create identity differs"
                );
            }
            other => panic!("parked create COMMIT did not return MetadataCommitUnknown: {other:?}"),
        }
        drop_receipt_park(&db.pool).await?;
        let found = match a5_query(&observer, scope, create_id).await? {
            PackSnapshotLookup::Found(receipt) => receipt,
            other => panic!("committed create is not Found: {other:?}"),
        };
        ensure!(found.snapshot_id() == snapshot_id && found.pin_id() == pin_id, "resolved create differs");
        let create_usage = pack_usage(&db.pool, v.repo).await?;
        let retried = a5_create(&observer, &create).await?;
        ensure!(retried.replayed && retried.receipt == found, "exact create retry did not replay the resolved receipt");
        ensure!(pack_usage(&db.pool, v.repo).await? == create_usage, "create retry duplicated charges");
        let renew = RenewMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 1, 300)?;
        let renew_id = renew.request_id();
        let key = random_key();
        let barrier = acquire_barrier(&observer, key).await?;
        install_receipt_park(&db.pool, key).await?;
        let (pid_tx, pid_rx) = oneshot::channel::<i32>();
        let (returned_tx, returned_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let writer_task = writer.clone();
        let req = renew.clone();
        let task = tokio::spawn(async move {
            let mut client = writer_task.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = pid_tx.send(pid);
            let result = PgRefStoreCore
                .renew_metadata_pin(&mut client, &req, TokioInstant::now() + Duration::from_secs(2))
                .await;
            let _ = returned_tx.send(());
            let _ = release_rx.await;
            client.batch_execute("SELECT 1").await?;
            Ok::<_, anyhow::Error>((pid, result))
        });
        let pid = pid_rx.await.map_err(|_| anyhow!("unknown-renew backend never reported its pid"))?;
        wait_advisory_key(&observer, pid, key).await?;
        ensure!(
            matches!(a5_query(&observer, scope, renew_id).await?, PackSnapshotLookup::Unknown),
            "uncommitted renew was visible"
        );
        returned_rx.await.map_err(|_| anyhow!("renew never returned at its deadline"))?;
        barrier.release().await?;
        let _ = release_tx.send(());
        let (_pid, result) = task.await.map_err(|_| anyhow!("unknown renew task failed"))??;
        match result {
            Err(RefStoreError::MetadataCommitUnknown { request_id, action, .. }) => {
                ensure!(
                    request_id == renew_id && action == MetadataMutationAction::Renew,
                    "unknown renew identity differs"
                );
            }
            other => panic!("parked renew COMMIT did not return MetadataCommitUnknown: {other:?}"),
        }
        drop_receipt_park(&db.pool).await?;
        let renew_usage = pack_usage(&db.pool, v.repo).await?;
        match a5_query(&observer, scope, renew_id).await? {
            PackSnapshotLookup::FoundPin(receipt) => {
                ensure!(receipt.history_kind() == "renewed", "resolved renew differs")
            }
            other => panic!("committed renew is not FoundPin: {other:?}"),
        }
        let renewed = a2_renew(&observer, &renew).await?;
        ensure!(renewed.replayed, "exact renew retry did not replay");
        ensure!(pack_usage(&db.pool, v.repo).await? == renew_usage, "renew retry duplicated charges");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
