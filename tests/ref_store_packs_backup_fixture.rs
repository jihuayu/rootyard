//! Root-selected companion fixture for the populated schema-142 A4a pack-ledger
//! backup drill (#107).
//!
//! Only `tests/backup_refstore_packs142.py` selects this integration-test
//! executable. It never creates a database/schema and never runs a migration: the
//! parent owns one fresh migrated database, seeds the inherited plain-SQL
//! migration-139 metadata gate/ref fixture and then runs this helper.
//!
//! This helper creates its **own** random unserved `provisioning`/`gitfs`
//! repository and initializes its core gate through the typed
//! `PgRefStoreCore::initialize` API. The inherited 139 metadata gate/ref rows are
//! a plain-SQL fixture whose `refs/heads/main` names no real Git object, so the
//! native proof deliberately runs against the separate typed gate instead.
//!
//! Seed mode is the real typed pipeline: mature Git writes an actual `.pack`/
//! `.idx` from a synthetic native commit, A3 acquires two holds, the protected
//! uploader consumes them and uploads the exact bytes to the configured real S3
//! store, A4 registers the publication, captures the closure context, runs the
//! real `PackVerifier` against the S3 bytes with the configured absolute Git
//! binary and only then performs the verified PG commit. All rows stay durable.
//!
//! Verify mode runs against the restored database. It rebuilds the exact plan and
//! A3 request values from the private secret-free manifest and uses only typed,
//! read-only adapter paths: immutable `query_registration`, the A3
//! `acquire_receipt`/`consume_receipt` ledgers and the migration-138 operation
//! terminal lookup. It mints no proof, no grant and no authority, charges no
//! quota, and compares physical locators, ACK/receipt ids, counters, refs/HEAD,
//! gate revision/mode, pack history and the committed event. It needs no
//! source-only pack/idx tempfiles: the S3 originals are re-read and hashed.
//!
//! Not claimed: Blob byte backup. The S3 originals are external, are only
//! re-read, and no delete of any held remote object is performed.

use anyhow::{Context, Result, anyhow, bail, ensure};
use deadpool_postgres::Pool;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use rootyard::db;
use rootyard::ref_store::artifact_hold::{
    AcquireAck, AcquireArtifactHoldsRequest, AcquireLookup, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec,
    ConsumeAck, ConsumeLookup, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::contract::RECEIPT_OVERHEAD_BYTES;
use rootyard::ref_store::core::pack_commit::{
    ContentDigest, MembershipDigest, PackArtifactRole, PackClosureContext, PackClosureProof, PackCommitExpectation,
    PackCommitPlan, PackCommitReceipt, PackCommitScope, PackMode, PackPendingToken, PackRegistrationAck,
    PackRegistrationReceipt, PackRegistrationRequest, PackVerifier, PgPackCommit, PlannedArtifact, PlannedPack,
    RegisteredPack,
};
use rootyard::ref_store::{
    CoreGateInit, CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationIdentity, OperationLookup,
    OperationState, PgRefStore, PgRefStoreCore, RefName, RefPrecondition, RefTarget, RefUpdate, RequestDigest,
    VersionCheck,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use uuid::Uuid;

const MARKER: &str = "ROOTYARD-REF-STORE-PACKS-FIXTURE-METADATA";
const MANIFEST_KIND: &str = "rootyard/ref-store-core-packs-backup-fixture";
const LANE: &str = "pack-backup-drill";
const HOLD_NAMESPACE: &str = "core-pack";
const DEADLINE_SECONDS: u64 = 40;

#[derive(Clone, Copy)]
enum Owner {
    Repo,
    Tenant,
    All,
}

/// The six migration-142 tables owned by this drill.
const PACK_TABLES: [(&str, Owner); 6] = [
    ("ref_store_core_pack_publications", Owner::Repo),
    ("ref_store_core_pack_artifacts", Owner::Repo),
    ("ref_store_core_pack_memberships", Owner::Repo),
    ("ref_store_core_pack_history", Owner::Repo),
    ("ref_store_core_pack_repo_usage", Owner::Repo),
    ("ref_store_core_pack_tenant_usage", Owner::Tenant),
];

/// The complete inherited migration-141 hold ledger of this drill.
const HOLD_TABLES: [(&str, Owner); 6] = [
    ("artifact_hold_requests", Owner::Repo),
    ("artifact_holds", Owner::Repo),
    ("artifact_hold_consume_receipts", Owner::Repo),
    ("artifact_hold_shards", Owner::All),
    ("artifact_hold_repo_usage", Owner::Repo),
    ("artifact_hold_tenant_usage", Owner::Tenant),
];

/// The six migration-139 registry/gate tables, scoped to the pack repository.
const CORE_TABLES: [(&str, Owner); 6] = [
    ("ref_store_issuer_lanes", Owner::Repo),
    ("ref_store_operations", Owner::Repo),
    ("ref_store_cancellations", Owner::Repo),
    ("ref_store_core_gates", Owner::Repo),
    ("ref_store_core_refs", Owner::Repo),
    ("ref_store_core_events", Owner::Repo),
];

enum Mode {
    Seed,
    Verify,
}

impl Mode {
    fn from_env() -> Self {
        match required("ROOTYARD_PACKS_FIXTURE_MODE").as_str() {
            "seed" => Self::Seed,
            "verify" => Self::Verify,
            other => panic!("ROOTYARD_PACKS_FIXTURE_MODE must be 'seed' or 'verify', not {other:?}"),
        }
    }
}

struct Fixture {
    url: String,
    output: PathBuf,
    git: PathBuf,
    format: GitObjectFormat,
}

impl Fixture {
    fn from_env() -> Self {
        let format = match std::env::var("ROOTYARD_PACKS_FIXTURE_FORMAT") {
            Ok(value) => GitObjectFormat::parse(&value)
                .unwrap_or_else(|error| panic!("ROOTYARD_PACKS_FIXTURE_FORMAT is invalid: {error}")),
            Err(_) => GitObjectFormat::Sha1,
        };
        Self {
            url: required("ROOTYARD_TEST_DATABASE_URL"),
            output: PathBuf::from(required("ROOTYARD_PACKS_FIXTURE_OUTPUT")),
            git: git_binary(),
            format,
        }
    }
}

fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "{name} is required: this fixture only runs under the owning pack backup drill, \
             never from a routine test command"
        ),
    }
}

/// Trusted absolute Git binary supplied by Root (defaults to `/usr/bin/git`).
fn git_binary() -> PathBuf {
    let path = match std::env::var("ROOTYARD_TEST_GIT") {
        Ok(value) => PathBuf::from(value),
        Err(_) => PathBuf::from("/usr/bin/git"),
    };
    assert!(path.is_absolute(), "ROOTYARD_TEST_GIT must be an absolute path");
    assert!(path.is_file(), "the configured absolute git binary does not exist");
    path
}

/// Real store from the operator-supplied Blob profile (real S3 credentials are
/// inherited; no credential, endpoint or DSN is ever printed or persisted).
fn open_store() -> Result<BlobStore> {
    let profile =
        BlobProfile::from_env().map_err(|error| anyhow!("configured ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == rootyard::blob_store::BlobProvider::S3, "pack backup qualification requires real S3");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(DEADLINE_SECONDS)
}

fn std_deadline() -> std::time::Instant {
    std::time::Instant::now() + Duration::from_secs(DEADLINE_SECONDS)
}

fn digest_file(path: &Path) -> Result<(String, u64)> {
    let bytes = std::fs::read(path)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}

fn main_update(format: GitObjectFormat, commit: &str) -> Result<RefUpdate> {
    Ok(RefUpdate::new(
        RefName::branch("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(format, commit)?),
    ))
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

/// Fixture-only business rows: one internal producer identity (also the
/// repository owner/tenant) and one isolated unserved provisioning repository.
/// No tenant equality with the inherited 139 metadata fixture is required.
async fn create_business(pool: &Pool, repository: Uuid, tenant: Uuid, format: GitObjectFormat) -> Result<()> {
    let object_format = format.as_str().to_owned();
    let username = format!("packdrill{}", &tenant.simple().to_string()[..12]);
    let name = format!("packdrill{}", &repository.simple().to_string()[..12]);
    let client = pool.get().await?;
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&tenant, &username]).await?;
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,storage_backend,storage_generation,next_retry_at,
                 provision_attempts,object_format)
             VALUES($1,$2,$3,'provisioning','gitfs',1,clock_timestamp()+interval '100 years',0,$4)",
            &[&repository, &tenant, &name, &object_format],
        )
        .await?;
    drop(client);
    Ok(())
}

async fn initialize_gate(
    pool: &Pool,
    repository: Uuid,
    tenant: Uuid,
    format: GitObjectFormat,
) -> Result<CoreGateVersion> {
    let init =
        CoreGateInit::new(repository, tenant, format, Uuid::new_v4(), 1, 1, RefName::branch("refs/heads/main")?)?;
    let mut client = pool.get().await?;
    let gate = PgRefStoreCore.initialize(&mut client, &init, deadline()).await?;
    drop(client);
    ensure!(gate.revision() == 1, "a fresh typed gate is not revision 1");
    ensure!(gate.tenant_id() == tenant && gate.repository_id() == repository, "typed gate scope differs");
    Ok(gate.version())
}

async fn gate_state(pool: &Pool, repository: Uuid) -> Result<(i64, String)> {
    let row = pool
        .get()
        .await?
        .query_one("SELECT revision,pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&repository])
        .await?;
    Ok((row.get(0), row.get(1)))
}

async fn usage_rows(pool: &Pool, repository: Uuid, tenant: Uuid) -> Result<([i64; 5], [i64; 5])> {
    let client = pool.get().await?;
    let repo = client
        .query_one(
            "SELECT registration_count,artifact_count,membership_count,logical_bytes,receipt_count
             FROM ref_store_core_pack_repo_usage WHERE repository_id=$1",
            &[&repository],
        )
        .await?;
    let ten = client
        .query_one(
            "SELECT registration_count,artifact_count,membership_count,logical_bytes,receipt_count
             FROM ref_store_core_pack_tenant_usage WHERE tenant_id=$1",
            &[&tenant],
        )
        .await?;
    let tuple =
        |row: &tokio_postgres::Row| -> [i64; 5] { [row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)] };
    Ok((tuple(&repo), tuple(&ten)))
}

async fn ack_body(pool: &Pool, registration_id: Uuid) -> Result<String> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT ack_body FROM ref_store_core_pack_publications WHERE registration_id=$1",
            &[&registration_id],
        )
        .await?
        .get(0))
}

/// Observation-only JSON capture of one table (never an ACK or a grant).
async fn rows_json(pool: &Pool, table: &str, owner: Owner, repository: Uuid, tenant: Uuid) -> Result<Value> {
    let client = pool.get().await?;
    let text: String = match owner {
        Owner::Repo => client
            .query_one(
                &format!(
                    "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)::text \
                         FROM public.\"{table}\" t WHERE t.repository_id=$1"
                ),
                &[&repository],
            )
            .await?
            .get(0),
        Owner::Tenant => client
            .query_one(
                &format!(
                    "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)::text \
                         FROM public.\"{table}\" t WHERE t.tenant_id=$1"
                ),
                &[&tenant],
            )
            .await?
            .get(0),
        Owner::All => client
            .query_one(
                &format!(
                    "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)::text FROM public.\"{table}\" t"
                ),
                &[],
            )
            .await?
            .get(0),
    };
    Ok(serde_json::from_str(&text)?)
}

async fn capture(pool: &Pool, tables: &[(&str, Owner)], repository: Uuid, tenant: Uuid) -> Result<Value> {
    let mut object = serde_json::Map::new();
    for &(table, owner) in tables {
        object.insert(table.to_owned(), rows_json(pool, table, owner, repository, tenant).await?);
    }
    Ok(Value::Object(object))
}

fn counts(rows: &Value) -> Value {
    let mut object = serde_json::Map::new();
    if let Value::Object(tables) = rows {
        for (name, value) in tables {
            object.insert(name.clone(), json!(value.as_array().map(Vec::len).unwrap_or(0)));
        }
    }
    Value::Object(object)
}

fn value_of<T: serde::Serialize>(value: &T) -> Result<Value> {
    Ok(serde_json::to_value(value)?)
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).with_context(|| format!("fixture metadata field {key:?} is missing"))
}

fn text_field(value: &Value, key: &str) -> Result<String> {
    Ok(field(value, key)?
        .as_str()
        .with_context(|| format!("fixture metadata field {key:?} must be a string"))?
        .to_owned())
}

fn uuid_field(value: &Value, key: &str) -> Result<Uuid> {
    Uuid::parse_str(&text_field(value, key)?).with_context(|| format!("fixture metadata field {key:?} is not a UUID"))
}

fn int_field(value: &Value, key: &str) -> Result<i64> {
    field(value, key)?.as_i64().with_context(|| format!("fixture metadata field {key:?} must be an integer"))
}

fn u64_field(value: &Value, key: &str) -> Result<u64> {
    u64::try_from(int_field(value, key)?)
        .with_context(|| format!("fixture metadata field {key:?} must be non-negative"))
}

fn array_field<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    field(value, key)?.as_array().with_context(|| format!("fixture metadata field {key:?} must be an array"))
}

fn table<'a>(rows: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    array_field(rows, name)
}

/// Harden fixture Git: owned HOME/template, empty environment, known author,
/// closed argv and a bounded timeout. All fixture bytes are synthetic.
struct GitRepo {
    _root: tempfile::TempDir,
    bare: PathBuf,
    home: PathBuf,
    template: PathBuf,
    git: PathBuf,
    format: GitObjectFormat,
}

impl GitRepo {
    async fn new(git: PathBuf, object_format: GitObjectFormat) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let template = root.path().join("template");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&template)?;
        let repo =
            Self { bare: root.path().join("fixture.git"), home, template, git, format: object_format, _root: root };
        let object_format = format!("--object-format={}", object_format.as_str());
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
            .env("GIT_ATTR_NOSYSTEM", "1")
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
        let output = tokio::time::timeout(Duration::from_secs(DEADLINE_SECONDS), child.wait_with_output())
            .await
            .map_err(|_| anyhow!("fixture native git command timed out"))??;
        ensure!(
            output.status.success(),
            "fixture native git `{}` failed with {:?}: {}",
            args.first().copied().unwrap_or("<none>"),
            output.status.code(),
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

    async fn mktree(&self, file: &str, blob: &str) -> Result<String> {
        Self::text(&self.run(&["mktree"], Some(format!("100644 blob {blob}\t{file}\n").as_bytes())).await?)
    }

    async fn commit_tree(&self, tree: &str, message: &str) -> Result<String> {
        Self::text(&self.run(&["commit-tree", tree, "-m", message], None).await?)
    }

    async fn update_ref(&self, name: &str, oid: &str) -> Result<()> {
        self.run(&["update-ref", name, oid], None).await?;
        Ok(())
    }

    fn artifacts_dir(&self) -> Result<PathBuf> {
        let parent = self.bare.parent().ok_or_else(|| anyhow!("fixture repository has no parent"))?;
        let dir = parent.join("artifacts");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Let mature Git write the actual `.pack` stream and the matching `.idx`.
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
        ensure!(pack.is_file(), "fixture pack file is missing");
        ensure!(idx.is_file(), "fixture idx file is missing");
        Ok(Self { pack, idx })
    }
}

struct Draft {
    plan: PackCommitPlan,
    token: PackPendingToken,
}

/// Read-only verified remote GET of every registered artifact.
async fn readback(store: &BlobStore, packs: &[RegisteredPack], work: &Path) -> Result<()> {
    for pack in packs {
        for artifact in pack.artifacts() {
            let locator = artifact.locator().blob_locator()?;
            let destination = work.join(format!("readback-{}-{}", artifact.slot(), Uuid::new_v4()));
            store.get_to_file(&locator, &destination, std_deadline()).await?;
            let (sha256, length) = digest_file(&destination)?;
            ensure!(
                sha256 == artifact.verified_sha256().as_str() && length == artifact.verified_length(),
                "independent remote read-back differs from the registered artifact"
            );
            std::fs::remove_file(&destination)?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "root-selected only: needs the parent Python fixture database plus ROOTYARD_PACKS_FIXTURE_* and real Blob/Git env"]
async fn ref_store_pack_backup_metadata_fixture() -> Result<()> {
    let fixture = Fixture::from_env();
    let mode = Mode::from_env();
    let store = open_store()?;
    let pool = db::pool(&fixture.url).context("connect to the parent fixture database")?;
    match mode {
        Mode::Seed => seed(&pool, &store, &fixture).await,
        Mode::Verify => verify(&pool, &store, &fixture).await,
    }
}

async fn seed(pool: &Pool, store: &BlobStore, fixture: &Fixture) -> Result<()> {
    let format = fixture.format;
    let tenant = Uuid::new_v4();
    let repository = Uuid::new_v4();
    create_business(pool, repository, tenant, format).await?;
    let gate = initialize_gate(pool, repository, tenant, format).await?;

    let git = GitRepo::new(fixture.git.clone(), format).await?;
    ensure!(git.format == format, "fixture git object format differs from the gate");
    let content = b"rootyard ref-store pack backup fixture\n";
    let content_sha256 = hex::encode(Sha256::digest(content));
    let blob_oid = git.add_blob(content).await?;
    let tree_oid = git.mktree("pack-backup.txt", &blob_oid).await?;
    let commit_oid = git.commit_tree(&tree_oid, "fixture pack backup").await?;
    git.update_ref("refs/heads/main", &commit_oid).await?;
    let files = git.pack_all("backup-closure").await?;
    let (pack_sha, pack_len) = digest_file(&files.pack)?;
    let (idx_sha, idx_len) = digest_file(&files.idx)?;

    let baseline = {
        let mut client = pool.get().await?;
        PgPackCommit.capture_baseline(&mut client, repository, tenant, deadline()).await?
    };
    ensure!(baseline.mode() == PackMode::MetadataOnly, "fresh gate is not metadata_only");
    ensure!(baseline.gate().revision() == 1, "fresh gate revision is not 1");
    ensure!(baseline.refs().is_empty() && baseline.old_packs().is_empty(), "fresh gate is not empty");

    let pack_id = Uuid::new_v4();
    let registration_id = Uuid::new_v4();
    let planned = PlannedPack::new(
        pack_id,
        registration_id,
        PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha.clone())?, pack_len)?,
        PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha.clone())?, idx_len)?,
    )?;
    let scope = PackCommitScope::new(
        repository,
        tenant,
        tenant,
        format,
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let operation_id = Uuid::new_v4();
    let operation_digest = RequestDigest::from_bytes([0x5a; 32]);
    let identity =
        OperationIdentity::new(repository, tenant, IssuerLane::new(LANE)?, 1, operation_id, operation_digest)?;
    let expectation = PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?;
    let plan = PackCommitPlan::new(
        scope.clone(),
        identity,
        expectation,
        HeadUpdate::Keep,
        vec![main_update(format, &commit_oid)?],
        baseline.membership_digest(),
        Vec::new(),
        vec![planned],
    )?;
    let token = {
        let mut client = pool.get().await?;
        PgPackCommit.begin_pending(&mut client, &plan, deadline()).await?
    };
    let draft = Draft { plan, token };
    let plan = &draft.plan;

    // A3: real acquire, protected consume+upload of the exact pack/idx bytes.
    let request = AcquireArtifactHoldsRequest::new(
        hold_scope(plan)?,
        plan.identity().clone(),
        Uuid::new_v4(),
        store.backend_identity().clone(),
        Uuid::new_v4(),
        1,
        *plan.expected().gate_digest(),
        vec![
            ArtifactSpec::new(HOLD_NAMESPACE, pack_sha.clone(), pack_len)?,
            ArtifactSpec::new(HOLD_NAMESPACE, idx_sha.clone(), idx_len)?,
        ],
    )?;
    let acquire_request_id = request.request_id();
    let grant = {
        let mut client = pool.get().await?;
        match PgArtifactHoldStore.acquire(&mut client, store, &request, deadline()).await? {
            AcquireOutcome::Granted { grant, .. } => grant,
            AcquireOutcome::Replayed { .. } => bail!("fresh A3 acquire unexpectedly replayed"),
        }
    };
    let uploader = ProtectedUploader::new(store.clone());
    let sources = [UploadSource::new(files.pack.clone()), UploadSource::new(files.idx.clone())];
    let publication: ProtectedPublication = uploader
        .consume_and_upload(pool, grant, &sources, std_deadline())
        .await
        .map_err(|_| anyhow!("protected upload refused by the protected uploader"))?;
    ensure!(publication.receipts().len() == 2, "publication is not exactly a two-artifact pair");
    ensure!(publication.acquire_request_id() == acquire_request_id, "publication acquire id differs");

    // A4: durable registration bound to the exact A3 pair.
    let registration: PackRegistrationReceipt = {
        let mut client = pool.get().await?;
        let request = PackRegistrationRequest::new(plan, pack_id, &publication)?;
        PgPackCommit.register_publication(&mut client, request, deadline()).await?
    };
    ensure!(!registration.replayed, "fresh registration replayed an old ACK");
    ensure!(
        registration.ack.registration_id == registration_id && registration.ack.pack_id == pack_id,
        "registration ACK names another identity"
    );
    ensure!(registration.ack.consume_request_id == publication.consume_request_id(), "ACK consume id differs");

    // Closure context, verified S3 read-back, real native PackVerifier proof.
    let context: PackClosureContext = {
        let mut client = pool.get().await?;
        PgPackCommit.capture_context(&mut client, plan, deadline()).await?
    };
    ensure!(context.new_packs().len() == 1 && context.old_packs().is_empty(), "closure pack set differs");
    let readback_dir = tempfile::tempdir()?;
    readback(store, context.new_packs(), readback_dir.path()).await?;
    let proof: PackClosureProof =
        PackVerifier::new(store.clone(), fixture.git.clone())?.verify(plan, &context, std_deadline()).await?;
    let receipt: PackCommitReceipt = {
        let mut client = pool.get().await?;
        PgPackCommit.commit_verified_pending(&mut client, plan, &draft.token, &proof, deadline()).await?
    };
    ensure!(receipt.is_committed() && !receipt.replayed, "fresh verified commit did not commit");

    // Post-commit typed/observational checks.
    let (revision, pack_mode) = gate_state(pool, repository).await?;
    ensure!(revision == 2 && pack_mode == "pack_verified", "gate did not move to pack_verified revision 2");
    let after = {
        let mut client = pool.get().await?;
        PgPackCommit.capture_baseline(&mut client, repository, tenant, deadline()).await?
    };
    ensure!(after.mode() == PackMode::PackVerified && after.gate().revision() == 2, "committed baseline differs");
    ensure!(
        after.refs().len() == 1
            && after.refs()[0].name() == "refs/heads/main"
            && after.refs()[0].oid_hex() == commit_oid.as_str(),
        "committed refs/heads/main is not the fixture commit"
    );
    ensure!(after.old_packs().len() == 1, "committed membership is not exactly one pack");
    let active = &after.old_packs()[0];
    ensure!(
        active.pack_id() == pack_id
            && active.registration_id() == registration_id
            && active.joined_revision() == Some(2)
            && active.artifact_set_digest().as_hex() == registration.ack.artifact_set_digest,
        "committed membership identity differs"
    );
    let committed_membership = after.membership_digest().as_hex();
    let record = {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let lookup = PgRefStore.get(&tx, repository, operation_id, deadline()).await?;
        let _ = tx.rollback().await;
        match lookup {
            OperationLookup::Known(record) => record,
            OperationLookup::Unknown => bail!("the committed pack operation is missing from the 138 registry"),
        }
    };
    ensure!(record.state() == OperationState::Committed, "operation terminal is not committed");
    ensure!(record.identity() == plan.identity(), "operation identity differs from the plan");
    let terminal_value = value_of(&receipt.terminal)?;
    match record.terminal_result() {
        Some(stored) => {
            ensure!(stored.value() == &terminal_value, "stored terminal differs from the committed receipt")
        }
        None => bail!("committed operation has no terminal result"),
    }

    let (repo_usage, tenant_usage) = usage_rows(pool, repository, tenant).await?;
    ensure!(repo_usage == tenant_usage, "retained pack counters differ between repository and tenant");
    ensure!(
        repo_usage[0] == 1 && repo_usage[1] == 2 && repo_usage[2] == 1 && repo_usage[4] == 4 && repo_usage[3] > 0,
        "retained pack counters are not one registration/two artifacts/one membership/four receipts"
    );
    let stored_ack_body = ack_body(pool, registration_id).await?;
    let registered_history_body = stored_ack_body.len();
    let committed_history_body = proof.context_digest().as_hex().len();
    let terminal_body = serde_json::to_vec(&receipt.terminal)?.len();
    let expected_logical = 8 * RECEIPT_OVERHEAD_BYTES
        + i64::try_from(
            registered_history_body + registered_history_body + committed_history_body + 2 * terminal_body,
        )?;
    ensure!(repo_usage[3] == expected_logical, "retained logical bytes do not equal the exact fixed-point charge");

    let pack_rows = capture(pool, &PACK_TABLES, repository, tenant).await?;
    let hold_rows = capture(pool, &HOLD_TABLES, repository, tenant).await?;
    let core_rows = capture(pool, &CORE_TABLES, repository, tenant).await?;
    ensure!(table(&pack_rows, "ref_store_core_pack_publications")?.len() == 1, "publication row count differs");
    ensure!(table(&pack_rows, "ref_store_core_pack_artifacts")?.len() == 2, "artifact row count differs");
    ensure!(table(&pack_rows, "ref_store_core_pack_memberships")?.len() == 1, "membership row count differs");
    ensure!(table(&pack_rows, "ref_store_core_pack_history")?.len() == 2, "history row count differs");
    ensure!(table(&pack_rows, "ref_store_core_pack_repo_usage")?.len() == 1, "repo usage row is missing");
    ensure!(table(&pack_rows, "ref_store_core_pack_tenant_usage")?.len() == 1, "tenant usage row is missing");
    ensure!(table(&hold_rows, "artifact_hold_requests")?.len() == 1, "A3 request row count differs");
    ensure!(table(&hold_rows, "artifact_holds")?.len() == 2, "A3 hold row count differs");
    ensure!(table(&hold_rows, "artifact_hold_consume_receipts")?.len() == 2, "A3 consume receipt count differs");
    ensure!(table(&hold_rows, "artifact_hold_shards")?.len() == 64, "the fixed 64 A3 shard rows changed");
    ensure!(table(&core_rows, "ref_store_operations")?.len() == 1, "138 operation row count differs");
    ensure!(table(&core_rows, "ref_store_core_gates")?.len() == 1, "core gate row count differs");
    ensure!(table(&core_rows, "ref_store_core_refs")?.len() == 1, "core ref row count differs");
    ensure!(table(&core_rows, "ref_store_core_events")?.len() == 1, "core event row count differs");
    ensure!(table(&core_rows, "ref_store_cancellations")?.is_empty(), "a cancellation tombstone was written");

    let scope_json = json!({
        "repository_id": repository.to_string(),
        "tenant_id": tenant.to_string(),
        "owner_id": plan.owner_id().to_string(),
        "purpose": "ref_publication",
        "object_format": format.as_str(),
        "history_incarnation": plan.history_incarnation().to_string(),
        "authority_epoch": plan.authority_epoch(),
        "group_epoch": plan.group_epoch(),
    });
    let plan_json = json!({
        "operation": {
            "issuer_id": tenant.to_string(),
            "lane": LANE,
            "sequence": 1,
            "operation_id": operation_id.to_string(),
            "operation_digest": operation_digest.as_hex(),
        },
        "parent_digest": plan.parent_digest().as_hex(),
        "old_membership_digest": plan.old_membership_digest().as_hex(),
        "expected_gate_revision": plan.expected().revision(),
        "expected_gate_digest": plan.expected().gate_digest().as_hex(),
        "expected_mode": plan.expected().mode().as_str(),
        "refs": [{"name": "refs/heads/main", "old_oid": Value::Null, "new_oid": commit_oid.clone()}],
        "packs": [{
            "pack_id": pack_id.to_string(),
            "registration_id": registration_id.to_string(),
            "pack_sha256": pack_sha,
            "pack_length": pack_len,
            "idx_sha256": idx_sha,
            "idx_length": idx_len,
        }],
    });
    let seed_holds = hold_scope(plan)?;
    let acquire_lookup = {
        let mut client = pool.get().await?;
        PgArtifactHoldStore.acquire_receipt(&mut client, &seed_holds, acquire_request_id, deadline()).await?
    };
    let acquire: AcquireAck = match acquire_lookup {
        AcquireLookup::Found(ack) => ack,
        AcquireLookup::Unknown => bail!("the just-committed A3 acquire receipt is missing"),
    };
    let consume_lookup = {
        let mut client = pool.get().await?;
        PgArtifactHoldStore
            .consume_receipt(&mut client, &seed_holds, acquire_request_id, acquire.consume_request_id, deadline())
            .await?
    };
    let consumed: Vec<ConsumeAck> = match consume_lookup {
        ConsumeLookup::Found(receipts) => receipts,
        ConsumeLookup::Unknown => bail!("the just-committed A3 consume receipts are missing"),
    };

    let marker = json!({
        "kind": MANIFEST_KIND,
        "version": 1,
        "mode": "seed",
        "scope": scope_json,
        "gate": {
            "initial": {"revision": plan.expected().revision(), "digest": plan.expected().gate_digest().as_hex()},
            "committed": {
                "revision": revision,
                "digest": after.gate().digest().as_hex(),
                "pack_mode": pack_mode,
                "head_ref": "refs/heads/main",
                "ref_oid": commit_oid,
                "membership_digest": committed_membership,
            },
        },
        "plan": plan_json,
        "source": {
            "file": "pack-backup.txt",
            "content_sha256": content_sha256,
            "content_length": content.len(),
            "blob_oid": blob_oid,
            "tree_oid": tree_oid,
            "commit_oid": commit_oid,
            "pack_sha256": plan.packs()[0].artifact(PackArtifactRole::Pack).content().as_str(),
            "pack_length": plan.packs()[0].artifact(PackArtifactRole::Pack).length(),
            "idx_sha256": plan.packs()[0].artifact(PackArtifactRole::Idx).content().as_str(),
            "idx_length": plan.packs()[0].artifact(PackArtifactRole::Idx).length(),
        },
        "context_digest": proof.context_digest().as_hex(),
        "verified_pairs": proof.verified_pairs(),
        "verified_bytes": proof.verified_bytes(),
        "backend_identity": store.backend_identity().as_hex(),
        "authority_id": acquire.artifacts[0].artifact.authority_id.to_string(),
        "authority_generation": acquire.artifacts[0].artifact.authority_generation,
        "acquire_request_id": acquire_request_id.to_string(),
        "consume_request_id": acquire.consume_request_id.to_string(),
        "a3": {"ack": value_of(&acquire)?, "receipts": value_of(&consumed)?},
        "registration": {"ack": value_of(&registration.ack)?},
        "terminal": terminal_value,
        "usage": [repo_usage[0], repo_usage[1], repo_usage[2], repo_usage[3], repo_usage[4]],
        "logical_accounting": {
            "ack_body_bytes": registered_history_body,
            "registered_history_body_bytes": registered_history_body,
            "committed_history_body_bytes": committed_history_body,
            "terminal_body_bytes": terminal_body,
            "receipt_overhead_bytes": RECEIPT_OVERHEAD_BYTES,
            "expected_logical_bytes": expected_logical,
        },
        "counts": {"pack": counts(&pack_rows), "holds": counts(&hold_rows), "core": counts(&core_rows)},
        "rows": {"pack": pack_rows, "holds": hold_rows, "core": core_rows},
        "provider_io_attempted": true,
        "protected_upload_attempted": true,
        "s3_original_bytes_read_back_after_upload": true,
        "restored_blob_bytes_backed_up": false,
        "restored_blob_bytes_qualified": false,
        "physical_blob_backup_closure": false,
        "held_remote_objects_deleted": false,
    });
    write_marker(&fixture.output, &marker)?;
    Ok(())
}

fn write_marker(output: &Path, marker: &Value) -> Result<()> {
    std::fs::write(output, serde_json::to_vec_pretty(marker)?)
        .with_context(|| format!("write the private fixture manifest to {}", output.display()))?;
    println!("{MARKER} {}", serde_json::to_string(marker)?);
    Ok(())
}

fn scope_from(manifest: &Value) -> Result<PackCommitScope> {
    let scope = field(manifest, "scope")?;
    PackCommitScope::new(
        uuid_field(scope, "repository_id")?,
        uuid_field(scope, "tenant_id")?,
        uuid_field(scope, "owner_id")?,
        GitObjectFormat::parse(&text_field(scope, "object_format")?)?,
        uuid_field(scope, "history_incarnation")?,
        int_field(scope, "authority_epoch")?,
        int_field(scope, "group_epoch")?,
    )
    .map_err(|error| anyhow!("rebuilt plan scope rejected: {error}"))
}

fn plan_from(manifest: &Value) -> Result<PackCommitPlan> {
    let scope = scope_from(manifest)?;
    let plan = field(manifest, "plan")?;
    let operation = field(plan, "operation")?;
    let identity = OperationIdentity::new(
        scope.repository_id(),
        uuid_field(operation, "issuer_id")?,
        IssuerLane::new(text_field(operation, "lane")?)?,
        int_field(operation, "sequence")?,
        uuid_field(operation, "operation_id")?,
        RequestDigest::from_str(&text_field(operation, "operation_digest")?)?,
    )?;
    let expectation = PackCommitExpectation::new(
        int_field(plan, "expected_gate_revision")?,
        RequestDigest::from_str(&text_field(plan, "expected_gate_digest")?)?,
        PackMode::parse(&text_field(plan, "expected_mode")?)?,
    )?;
    let mut refs = Vec::new();
    for entry in array_field(plan, "refs")? {
        ensure!(entry.get("old_oid").map(Value::is_null).unwrap_or(false), "the plan precondition is not Absent");
        refs.push(RefUpdate::new(
            RefName::new(text_field(entry, "name")?)?,
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::parse(scope.object_format(), &text_field(entry, "new_oid")?)?),
        ));
    }
    let mut packs = Vec::new();
    for entry in array_field(plan, "packs")? {
        packs.push(PlannedPack::new(
            uuid_field(entry, "pack_id")?,
            uuid_field(entry, "registration_id")?,
            PlannedArtifact::new(
                PackArtifactRole::Pack,
                ContentDigest::parse(text_field(entry, "pack_sha256")?)?,
                u64_field(entry, "pack_length")?,
            )?,
            PlannedArtifact::new(
                PackArtifactRole::Idx,
                ContentDigest::parse(text_field(entry, "idx_sha256")?)?,
                u64_field(entry, "idx_length")?,
            )?,
        )?);
    }
    let built = PackCommitPlan::new(
        scope,
        identity,
        expectation,
        HeadUpdate::Keep,
        refs,
        MembershipDigest::of(&[]),
        Vec::new(),
        packs,
    )?;
    ensure!(
        built.parent_digest().as_hex() == text_field(plan, "parent_digest")?,
        "the rebuilt plan parent digest differs from the seeded plan"
    );
    Ok(built)
}

/// Read-only, authority-free verification of the restored metadata.
///
/// It mints no proof and no grant, charges no quota and performs no write: the
/// immutable registration, A3 acquire/consume receipts and the committed
/// migration-138 terminal are read through typed adapters, then every captured
/// row of the pack/hold/core ledgers must still equal the pre-read capture.
async fn verify(pool: &Pool, store: &BlobStore, fixture: &Fixture) -> Result<()> {
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&fixture.output)
            .with_context(|| format!("read the private fixture manifest {}", fixture.output.display()))?,
    )
    .context("parse the private fixture manifest")?;
    ensure!(field(&manifest, "kind")?.as_str() == Some(MANIFEST_KIND), "manifest kind differs");
    ensure!(field(&manifest, "mode")?.as_str() == Some("seed"), "verify needs the seed manifest");
    let plan = plan_from(&manifest)?;
    let scope = plan.scope().clone();
    let repository = plan.repository_id();
    let tenant = plan.tenant_id();
    let registration_id = plan.packs()[0].registration_id();
    let acquire_request_id = uuid_field(&manifest, "acquire_request_id")?;
    let scope_holds = hold_scope(&plan)?;

    let restored_gate = {
        let mut client = pool.get().await?;
        match PgRefStoreCore.check_version(&mut client, repository, tenant, None, deadline()).await? {
            VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => version,
            VersionCheck::Unknown => bail!("the restored repository has no core gate"),
        }
    };
    let gate = field(&manifest, "gate")?;
    let committed = field(gate, "committed")?;
    ensure!(
        restored_gate.revision() == int_field(committed, "revision")?,
        "restored gate revision differs from the committed revision"
    );
    ensure!(
        restored_gate.digest().as_hex() == text_field(committed, "digest")?,
        "restored committed gate digest differs"
    );
    ensure!(restored_gate.head_ref().as_str() == "refs/heads/main", "restored gate HEAD differs");
    ensure!(restored_gate.object_format() == plan.object_format(), "restored gate object format differs");
    ensure!(restored_gate.history_incarnation() == plan.history_incarnation(), "restored gate history differs");
    ensure!(restored_gate.authority_epoch() == plan.authority_epoch(), "restored gate authority epoch differs");
    ensure!(restored_gate.group_epoch() == plan.group_epoch(), "restored gate group epoch differs");
    let (revision, pack_mode) = gate_state(pool, repository).await?;
    ensure!(revision == restored_gate.revision(), "observed gate revision differs from the typed version");
    ensure!(pack_mode == "pack_verified", "the restored gate did not retain pack_verified mode");
    ensure!(pack_mode == text_field(committed, "pack_mode")?, "restored gate pack mode differs from the seed");

    let before = json!({
        "pack": capture(pool, &PACK_TABLES, repository, tenant).await?,
        "holds": capture(pool, &HOLD_TABLES, repository, tenant).await?,
        "core": capture(pool, &CORE_TABLES, repository, tenant).await?,
    });
    ensure!(&before == field(&manifest, "rows")?, "restored rows differ from the pre-backup seed rows");

    // Immutable registration (no proof, no pending parent, no quota charge).
    let registration: PackRegistrationReceipt = {
        let mut client = pool.get().await?;
        match PgPackCommit.query_registration(&mut client, &scope, registration_id, deadline()).await? {
            Some(receipt) => receipt,
            None => bail!("the restored registration is missing"),
        }
    };
    ensure!(registration.replayed, "query_registration is not a read-only replay");
    let expected_ack: PackRegistrationAck =
        serde_json::from_value(field(field(&manifest, "registration")?, "ack")?.clone())?;
    ensure!(registration.ack == expected_ack, "the restored registration ACK differs");

    // A3 acquire/consume ledgers (typed receipt lookup, no grant/token).
    let acquire_ack: AcquireAck = {
        let mut client = pool.get().await?;
        match PgArtifactHoldStore.acquire_receipt(&mut client, &scope_holds, acquire_request_id, deadline()).await? {
            AcquireLookup::Found(ack) => ack,
            AcquireLookup::Unknown => bail!("the restored A3 acquire receipt is missing"),
        }
    };
    let expected_acquire: AcquireAck = serde_json::from_value(field(field(&manifest, "a3")?, "ack")?.clone())?;
    ensure!(acquire_ack == expected_acquire, "the restored A3 acquire ACK differs");
    let consume_receipts: Vec<ConsumeAck> = {
        let mut client = pool.get().await?;
        match PgArtifactHoldStore
            .consume_receipt(&mut client, &scope_holds, acquire_request_id, acquire_ack.consume_request_id, deadline())
            .await?
        {
            ConsumeLookup::Found(receipts) => receipts,
            ConsumeLookup::Unknown => bail!("the restored A3 consume receipts are missing"),
        }
    };
    let expected_receipts: Vec<ConsumeAck> =
        serde_json::from_value(field(field(&manifest, "a3")?, "receipts")?.clone())?;
    ensure!(consume_receipts == expected_receipts, "the restored A3 consume receipts differ");
    ensure!(consume_receipts.len() == 2, "the restored A3 consume batch is not a pair");

    // Committed refs/HEAD/membership plus the immutable physical locators.
    let baseline = {
        let mut client = pool.get().await?;
        PgPackCommit.capture_baseline(&mut client, repository, tenant, deadline()).await?
    };
    ensure!(baseline.mode() == PackMode::PackVerified, "restored baseline mode is not pack_verified");
    ensure!(
        baseline.membership_digest().as_hex() == text_field(committed, "membership_digest")?,
        "restored membership digest differs"
    );
    ensure!(baseline.refs().len() == 1, "restored ref set is not exactly one ref");
    ensure!(
        baseline.refs()[0].name() == "refs/heads/main"
            && baseline.refs()[0].oid_hex() == text_field(committed, "ref_oid")?.as_str(),
        "restored refs/heads/main differs"
    );
    ensure!(baseline.old_packs().len() == 1, "restored active membership is not exactly one pack");
    let active = &baseline.old_packs()[0];
    let planned = &plan.packs()[0];
    ensure!(active.pack_id() == planned.pack_id(), "restored membership pack id differs");
    ensure!(active.registration_id() == registration_id, "restored membership registration id differs");
    ensure!(active.joined_revision() == Some(restored_gate.revision()), "restored joined revision differs");
    ensure!(
        active.artifact_set_digest().as_hex() == expected_ack.artifact_set_digest,
        "restored artifact set digest differs"
    );
    let mut holds = expected_ack.hold_ids.clone();
    holds.sort();
    let mut restarted_holds = active.artifacts().iter().map(|artifact| artifact.hold_id()).collect::<Vec<_>>();
    restarted_holds.sort();
    ensure!(holds == restarted_holds, "restored physical hold ids differ");
    for artifact in active.artifacts() {
        let role = artifact.role();
        let planned_artifact = planned.artifact(role);
        ensure!(
            artifact.slot() == role_slot(role) && artifact.locator().length() == planned_artifact.length(),
            "restored artifact slot/length differs"
        );
        ensure!(
            artifact.locator().sha256().as_str() == planned_artifact.content().as_str(),
            "restored artifact content digest differs"
        );
        ensure!(artifact.locator().namespace() == HOLD_NAMESPACE, "restored artifact namespace differs");
        ensure!(artifact.locator().tenant_id() == tenant, "restored artifact tenant differs");
        ensure!(
            artifact.provider() == expected_acquire.artifacts[artifact.slot() as usize].artifact.provider.as_str(),
            "restored artifact provider differs"
        );
        ensure!(
            artifact.backend_identity() == store.backend_identity().as_hex(),
            "restored artifact backend differs from the opened store"
        );
        ensure!(
            artifact.backend_identity() == expected_ack.backend_identity.as_str(),
            "restored artifact backend differs from the registration ACK"
        );
    }

    // Committed terminal via the public migration-138 operation lookup.
    let record = {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let lookup = PgRefStore.get(&tx, repository, plan.identity().operation_id(), deadline()).await?;
        let _ = tx.rollback().await;
        match lookup {
            OperationLookup::Known(record) => record,
            OperationLookup::Unknown => bail!("the restored pack operation is missing from the 138 registry"),
        }
    };
    ensure!(record.state() == OperationState::Committed, "restored operation terminal is not committed");
    ensure!(record.identity() == plan.identity(), "restored operation identity differs from the plan");
    let terminal = match record.terminal_result() {
        Some(stored) => stored.value().clone(),
        None => bail!("the restored committed operation has no terminal result"),
    };
    ensure!(&terminal == field(&manifest, "terminal")?, "the replayed terminal differs from the commit receipt");

    // Counters are unchanged by the read-only replay, and still the seed values.
    let (repo_usage, tenant_usage) = usage_rows(pool, repository, tenant).await?;
    ensure!(repo_usage == tenant_usage, "restored pack counters differ between repository and tenant");
    let restored_usage = json!([repo_usage[0], repo_usage[1], repo_usage[2], repo_usage[3], repo_usage[4]]);
    ensure!(&restored_usage == field(&manifest, "usage")?, "the read-only replay changed retained pack counters");

    // S3 originals are external: re-read them, hash them and delete nothing.
    let readback_dir = tempfile::tempdir()?;
    readback(store, baseline.old_packs(), readback_dir.path()).await?;

    let after = json!({
        "pack": capture(pool, &PACK_TABLES, repository, tenant).await?,
        "holds": capture(pool, &HOLD_TABLES, repository, tenant).await?,
        "core": capture(pool, &CORE_TABLES, repository, tenant).await?,
    });
    ensure!(after == before, "the read-only verification mutated restored rows, counters or timestamps");

    let scope_json = json!({
        "repository_id": repository.to_string(),
        "tenant_id": tenant.to_string(),
        "owner_id": plan.owner_id().to_string(),
        "purpose": "ref_publication",
        "object_format": plan.object_format().as_str(),
        "history_incarnation": plan.history_incarnation().to_string(),
        "authority_epoch": plan.authority_epoch(),
        "group_epoch": plan.group_epoch(),
    });
    let marker = json!({
        "kind": MANIFEST_KIND,
        "version": 1,
        "mode": "verify",
        "scope": scope_json,
        "gate": {
            "committed": {
                "revision": restored_gate.revision(),
                "digest": restored_gate.digest().as_hex(),
                "pack_mode": pack_mode,
                "head_ref": restored_gate.head_ref().as_str(),
                "membership_digest": baseline.membership_digest().as_hex(),
            },
        },
        "plan": field(&manifest, "plan")?.clone(),
        "terminal": terminal,
        "registration_ack": value_of(&registration.ack)?,
        "a3_ack": value_of(&acquire_ack)?,
        "a3_receipts": value_of(&consume_receipts)?,
        "usage": [repo_usage[0], repo_usage[1], repo_usage[2], repo_usage[3], repo_usage[4]],
        "counts": {
            "pack": counts(field(&before, "pack")?),
            "holds": counts(field(&before, "holds")?),
            "core": counts(field(&before, "core")?),
        },
        "checks": {
            "restored_rows_equal_pre_backup_rows": true,
            "immutable_registration_replayed_without_grant": true,
            "a3_acquire_and_consume_receipts_match": true,
            "operation_terminal_replay_without_proof_or_authority": true,
            "retained_pack_counters_unchanged": true,
            "physical_locators_and_backend_identity_match": true,
            "known_refs_head_mode_revision_history_event_match": true,
            "s3_original_bytes_read_back_unchanged": true,
            "source_only_tempfiles_required": false,
            "quota_charged_by_replay": false,
        },
        "provider_io_attempted": true,
        "protected_upload_attempted": false,
        "restored_blob_bytes_backed_up": false,
        "restored_blob_bytes_qualified": false,
        "physical_blob_backup_closure": false,
        "held_remote_objects_deleted": false,
    });
    write_marker(&fixture.output.with_extension("verify.json"), &marker)?;
    Ok(())
}

fn role_slot(role: PackArtifactRole) -> i32 {
    match role {
        PackArtifactRole::Pack => 0,
        PackArtifactRole::Idx => 1,
    }
}
