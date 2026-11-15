//! PostgreSQL (shared CI instance or ephemeral `initdb`/`pg_ctl`) + native Git pack helpers.

use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use rootyard::db;
use rootyard::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::{
    ContentDigest, PackArtifactRole, PackClosureContext, PackClosureProof, PackCommitExpectation, PackCommitPlan,
    PackCommitScope, PackMembershipEntry, PackPendingToken, PackRegistrationRequest, PackVerifier, PgPackCommit,
    PlannedArtifact, PlannedPack,
};
use rootyard::ref_store::core::{
    CreatePackSnapshotRequest, MetadataSnapshotScope, PackSnapshotExpectation, PackSnapshotRef, PgPackSnapshot,
};
use rootyard::ref_store::{
    CoreGateInit, CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataPinPurpose,
    OperationIdentity, PgRefStoreCore, RefName, RefPrecondition, RefTarget, RefUpdate, RequestDigest, VersionCheck,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};
use tokio::io::AsyncWriteExt;
use tokio::sync::OnceCell;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

const OP_SECONDS: u64 = 30;
const GIT_SECONDS: u64 = 60;
const HOLD_NAMESPACE: &str = "core-pack";

pub fn deadline() -> TokioInstant {
    TokioInstant::now() + Duration::from_secs(OP_SECONDS)
}

pub fn std_deadline() -> StdInstant {
    StdInstant::now() + Duration::from_secs(OP_SECONDS)
}

pub fn git_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("ROOTYARD_GIT_BIN")
        && !path.is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    let usr_bin = PathBuf::from("/usr/bin/git");
    if usr_bin.is_file() {
        return Ok(usr_bin);
    }
    Err(anyhow!("stock git binary missing at /usr/bin/git and ROOTYARD_GIT_BIN is unset"))
}

pub fn git_version_string(git: &Path) -> Result<String> {
    let out = std::process::Command::new(git).arg("--version").output()?;
    ensure!(out.status.success(), "git --version failed");
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

static RESOLVED_PG: OnceCell<(String, &'static str)> = OnceCell::const_new();
#[cfg(unix)]
static PG_CLEANUP: std::sync::OnceLock<(PathBuf, PathBuf)> = std::sync::OnceLock::new();

#[cfg(unix)]
extern "C" fn stop_ephemeral_pg() {
    if let Some((pg_ctl, root)) = PG_CLEANUP.get() {
        let pgdata = root.join("pgdata");
        let _ = std::process::Command::new(pg_ctl)
            .args(["-D", &pgdata.to_string_lossy(), "-m", "immediate", "-w", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(unix)]
fn find_pg_tool(name: &str) -> Result<PathBuf> {
    if let Ok(status) =
        std::process::Command::new(name).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status()
        && status.success()
    {
        return Ok(PathBuf::from(name));
    }
    let pg_lib = Path::new("/usr/lib/postgresql");
    if pg_lib.is_dir() {
        let mut versions =
            std::fs::read_dir(pg_lib)?.filter_map(|e| e.ok().map(|entry| entry.path())).collect::<Vec<_>>();
        versions.sort();
        versions.reverse();
        for dir in versions {
            let candidate = dir.join("bin").join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(anyhow!("ROOTYARD_TEST_DATABASE_URL is unset and `{name}` was not found in PATH or /usr/lib/postgresql"))
}

async fn start_ephemeral_pg() -> Result<(String, &'static str)> {
    #[cfg(not(unix))]
    {
        Err(anyhow!("ROOTYARD_TEST_DATABASE_URL must be set on non-Unix hosts"))
    }
    #[cfg(unix)]
    {
        let initdb = find_pg_tool("initdb")?;
        let pg_ctl = find_pg_tool("pg_ctl")?;
        let root = std::env::temp_dir().join(format!("rootyard-vb-pg-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&root)?;
        let pgdata = root.join("pgdata");
        let init = std::process::Command::new(&initdb)
            .args([
                "--no-instructions",
                "-A",
                "trust",
                "-U",
                "rootyard",
                "--no-locale",
                "--encoding=UTF8",
                "-D",
                &pgdata.to_string_lossy(),
            ])
            .output()?;
        ensure!(init.status.success(), "initdb failed: {}", String::from_utf8_lossy(&init.stderr));

        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);

        let _ = PG_CLEANUP.set((pg_ctl.clone(), root.clone()));
        unsafe {
            libc::atexit(stop_ephemeral_pg);
        }

        let log = root.join("pg.log");
        let opts = format!("-h 127.0.0.1 -p {port} -k ''");
        let start = std::process::Command::new(&pg_ctl)
            .args(["-D", &pgdata.to_string_lossy(), "-l", &log.to_string_lossy(), "-o", &opts, "-w", "start"])
            .output()?;
        ensure!(start.status.success(), "pg_ctl start failed: {}", String::from_utf8_lossy(&start.stderr));

        let admin_url = format!("postgresql://rootyard@127.0.0.1:{port}/postgres");
        let (client, conn) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client.batch_execute("CREATE DATABASE rootyard_test TEMPLATE template0").await?;
        Ok((format!("postgresql://rootyard@127.0.0.1:{port}/rootyard_test"), "ephemeral_initdb"))
    }
}

async fn database_info() -> Result<&'static (String, &'static str)> {
    RESOLVED_PG
        .get_or_try_init(|| async {
            if let Ok(url) = std::env::var("ROOTYARD_TEST_DATABASE_URL")
                && !url.trim().is_empty()
            {
                return Ok((url, "ROOTYARD_TEST_DATABASE_URL"));
            }
            start_ephemeral_pg().await
        })
        .await
}

pub struct Db {
    admin: Pool,
    pub pool: Pool,
    schema: String,
    pub pg_source: &'static str,
}

impl Db {
    pub async fn setup() -> Result<Self> {
        let (url, pg_source) = database_info().await?;
        let admin = db::pool(url)?;
        let schema = format!("verifier_budgets_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let mut config: tokio_postgres::Config = url.parse()?;
        config.options(format!(
            "-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"
        ));
        let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(16)
            .build()?;
        db::migrate(&pool).await?;
        Ok(Self { admin, pool, schema, pg_source })
    }

    pub async fn finish(&self, outcome: Result<()>) -> Result<()> {
        let drop_res = self.admin.get().await?.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema)).await;
        match (outcome, drop_res) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), _) => Err(err),
            (Ok(()), Err(drop_err)) => Err(drop_err.into()),
        }
    }

    async fn create_repo_and_gate(&self, format: GitObjectFormat) -> Result<(Uuid, Uuid, CoreGateVersion)> {
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO users(id,username) VALUES($1,$2)",
                &[&tenant, &format!("vb{}", &tenant.simple().to_string()[..12])],
            )
            .await?;
        client
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,object_format) VALUES($1,$2,$3,'provisioning',$4)",
                &[&repo, &tenant, &format!("repo{}", &repo.simple().to_string()[..12]), &format.as_str()],
            )
            .await?;
        drop(client);
        let init = CoreGateInit::new(repo, tenant, format, Uuid::new_v4(), 1, 1, RefName::branch("refs/heads/main")?)?;
        let mut client = self.pool.get().await?;
        let gate = PgRefStoreCore.initialize(&mut client, &init, deadline()).await?;
        Ok((tenant, repo, gate.version()))
    }
}

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
        let fmt = format!("--object-format={}", format.as_str());
        let tmpl = format!("--template={}", repo.template.display());
        repo.run(&["init", "--bare", "--quiet", &fmt, &tmpl], None).await?;
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
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TEMPLATE_DIR", &self.template)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_NAME", "Rootyard Verifier Bench")
            .env("GIT_AUTHOR_EMAIL", "bench@rootyard.invalid")
            .env("GIT_COMMITTER_NAME", "Rootyard Verifier Bench")
            .env("GIT_COMMITTER_EMAIL", "bench@rootyard.invalid")
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
            let mut pipe = child.stdin.take().ok_or_else(|| anyhow!("git stdin missing"))?;
            pipe.write_all(bytes).await?;
            drop(pipe);
        }
        let out = tokio::time::timeout(Duration::from_secs(GIT_SECONDS), child.wait_with_output()).await??;
        ensure!(out.status.success(), "git `{:?}` failed: {}", args.first(), String::from_utf8_lossy(&out.stderr));
        Ok(out.stdout)
    }

    async fn build_pack(&self, name: &str, content: &[u8]) -> Result<(String, PathBuf, PathBuf)> {
        let blob =
            String::from_utf8(self.run(&["hash-object", "-w", "--stdin"], Some(content)).await?)?.trim().to_owned();
        let entry = format!("100644 blob {blob}\tpayload.bin\n");
        let tree = String::from_utf8(self.run(&["mktree"], Some(entry.as_bytes())).await?)?.trim().to_owned();
        let commit =
            String::from_utf8(self.run(&["commit-tree", &tree, "-m", "fixture"], None).await?)?.trim().to_owned();
        self.run(&["update-ref", "refs/heads/main", &commit], None).await?;
        let pack_bytes = self.run(&["pack-objects", "--stdout", "--all"], None).await?;
        let dir = self._root.path().join("artifacts");
        std::fs::create_dir_all(&dir)?;
        let pack = dir.join(format!("{name}.pack"));
        std::fs::write(&pack, &pack_bytes)?;
        self.run(&["index-pack", &pack.to_string_lossy()], None).await?;
        let idx = dir.join(format!("{name}.idx"));
        Ok((commit, pack, idx))
    }
}

fn incompressible_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

pub struct PreparedCommit {
    pub repo: Uuid,
    pub tenant: Uuid,
    pub gate: CoreGateVersion,
    pub pack_id: Uuid,
    pub plan: PackCommitPlan,
    pub token: PackPendingToken,
    pub context: PackClosureContext,
    pub pack_bytes: Vec<u8>,
    pub idx_bytes: Vec<u8>,
}

fn digest_bytes(bytes: &[u8]) -> (String, u64) {
    (hex::encode(Sha256::digest(bytes)), bytes.len() as u64)
}

pub async fn prepare_fresh_commit(
    db: &Db,
    store: &BlobStore,
    git: &Path,
    seed: u64,
    payload_bytes: usize,
) -> Result<PreparedCommit> {
    let format = GitObjectFormat::Sha1;
    let (tenant, repo, gate) = db.create_repo_and_gate(format).await?;
    let fixture = GitRepo::new(git.to_path_buf(), format).await?;
    let payload = incompressible_payload(seed, payload_bytes);
    let (commit_oid, pack_path, idx_path) = fixture.build_pack("initial", &payload).await?;
    let pack_bytes = std::fs::read(&pack_path)?;
    let idx_bytes = std::fs::read(&idx_path)?;
    let (pack_sha, pack_len) = digest_bytes(&pack_bytes);
    let (idx_sha, idx_len) = digest_bytes(&idx_bytes);

    let mut client = db.pool.get().await?;
    let baseline = PgPackCommit.capture_baseline(&mut client, repo, tenant, deadline()).await?;
    let old_entries = baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?;
    let pack_id = Uuid::new_v4();
    let planned = vec![PlannedPack::new(
        pack_id,
        Uuid::new_v4(),
        PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha.clone())?, pack_len)?,
        PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha.clone())?, idx_len)?,
    )?];
    let refs = vec![RefUpdate::new(
        RefName::branch("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(format, &commit_oid)?),
    )];
    let scope = PackCommitScope::new(
        repo,
        tenant,
        tenant,
        format,
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

    let hold_scope = HoldScope::new(
        plan.repository_id(),
        plan.tenant_id(),
        plan.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    )?;
    let hold_req = AcquireArtifactHoldsRequest::new(
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
    let grant = {
        let mut client = db.pool.get().await?;
        match PgArtifactHoldStore.acquire(&mut client, store, &hold_req, deadline()).await? {
            AcquireOutcome::Granted { grant, .. } => grant,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh acquire replayed")),
        }
    };
    let publication: ProtectedPublication = ProtectedUploader::new(store.clone())
        .consume_and_upload(
            &db.pool,
            grant,
            &[UploadSource::new(pack_path), UploadSource::new(idx_path)],
            std_deadline(),
        )
        .await
        .map_err(|_| anyhow!("protected upload refused"))?;
    let mut client = db.pool.get().await?;
    PgPackCommit
        .register_publication(&mut client, PackRegistrationRequest::new(&plan, pack_id, &publication)?, deadline())
        .await?;
    let context = PgPackCommit.capture_context(&mut client, &plan, deadline()).await?;

    Ok(PreparedCommit { repo, tenant, gate, pack_id, plan, token, context, pack_bytes, idx_bytes })
}

pub async fn pin_committed_snapshot(pool: &Pool, prepared: &PreparedCommit) -> Result<PackSnapshotRef> {
    let mut client = pool.get().await?;
    let gate = match PgRefStoreCore.check_version(&mut client, prepared.repo, prepared.tenant, None, deadline()).await?
    {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => version,
        VersionCheck::Unknown => return Err(anyhow!("committed repository gate disappeared")),
    };
    let scope = MetadataSnapshotScope::new(
        prepared.repo,
        prepared.tenant,
        Uuid::new_v4(),
        MetadataPinPurpose::Verification,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let snapshot_id = Uuid::new_v4();
    let pin_id = Uuid::new_v4();
    let expected = PackSnapshotExpectation::new(gate.revision(), *gate.digest())?;
    let req = CreatePackSnapshotRequest::new(scope, Uuid::new_v4(), pin_id, snapshot_id, 300, expected)?;
    let outcome = PgPackSnapshot.create(&mut client, &req, deadline()).await?;
    ensure!(!outcome.replayed && outcome.receipt.snapshot_id() == snapshot_id, "snapshot was not created");
    Ok(PackSnapshotRef::new(prepared.repo, prepared.tenant, snapshot_id, pin_id, 1)?)
}

pub async fn commit_and_pin_snapshot(
    db: &Db,
    prepared: &PreparedCommit,
    verifier: &PackVerifier,
    maintenance: bool,
) -> Result<PackSnapshotRef> {
    let proof: PackClosureProof = if maintenance {
        verifier.verify_maintenance(&prepared.plan, &prepared.context, std_deadline()).await?
    } else {
        verifier.verify(&prepared.plan, &prepared.context, std_deadline()).await?
    };
    let mut client = db.pool.get().await?;
    let receipt =
        PgPackCommit.commit_verified_pending(&mut client, &prepared.plan, &prepared.token, &proof, deadline()).await?;
    ensure!(receipt.is_committed(), "verified commit did not reach committed state");
    drop(client);
    pin_committed_snapshot(&db.pool, prepared).await
}
