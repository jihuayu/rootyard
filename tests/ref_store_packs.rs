//! Real PostgreSQL + real S3 + native Git acceptance for A4a pack commit (#107).
//!
//! Run explicitly by Root:
//! `ROOTYARD_TEST_DATABASE_URL=... ROOTYARD_BLOB_SERVICE=s3 ROOTYARD_BLOB_ENDPOINT=...
//!  ROOTYARD_BLOB_BUCKET=... ROOTYARD_BLOB_REGION=... ROOTYARD_BLOB_ACCESS_KEY_ID=...
//!  ROOTYARD_BLOB_SECRET_ACCESS_KEY=... ROOTYARD_TEST_GIT=/usr/bin/git
//!  cargo test --test ref_store_packs -- --ignored`.
//!
//! Every case is `#[ignore]` and hard-fails when the mandatory PostgreSQL or Blob
//! profile is missing: there is no skip, no in-memory store, no fake provider, no
//! fake HTTP provider and no fabricated proof/token/ACK. The suite builds a valid
//! synthetic native Git commit/tree/blob in an owned temporary bare repository
//! (SHA-1 and SHA-256), lets mature Git write the actual `.pack`/`.idx`
//! (`pack-objects`/`index-pack`), uploads those exact bytes through A3
//! acquire+consume+protected upload, registers the pair, captures the closure
//! context, runs the real `PackVerifier` against the configured S3 bytes with the
//! configured absolute Git binary, and only then performs the PG atomic commit.
//!
//! Implemented here as behavior, not as a serving claim: the real S3 profile is
//! enforced, retained quota counters must refuse `DELETE`/`TRUNCATE` through
//! their actual 142 guards, and REGISTER vs CANCEL are ordered on the real
//! migration-138 operation advisory prefix with two distinct backends.
//! Still not claimed: restart/HA, encryption, roots/decisions, `ReadSnapshot`,
//! GC, Blob backup, activation/serving, the two-plan same-baseline race and the
//! strict cancel-before-any-pending-row phase.
#![allow(clippy::too_many_arguments)]

use anyhow::{Result, anyhow, ensure};
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
    ContentDigest, PackArtifactRole, PackClosureContext, PackClosureProof, PackCommitError, PackCommitExpectation,
    PackCommitPlan, PackCommitReceipt, PackCommitScope, PackMembershipEntry, PackMode, PackPendingToken,
    PackRegistrationReceipt, PackRegistrationRequest, PackVerifier, PgPackCommit, PlannedArtifact, PlannedPack,
    RegisteredPack,
};
use rootyard::ref_store::pg::OPERATION_LOCK_DOMAIN;
use rootyard::ref_store::{
    CoreGateInit, CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationIdentity, OperationLookup,
    OperationState, PgRefStore, PgRefStoreCore, RefName, RefPrecondition, RefTarget, RefUpdate, RequestDigest,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};
use tokio::io::AsyncWriteExt;
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
        .expect("ROOTYARD_TEST_DATABASE_URL must be set when running the ignored ref_store_packs suite")
}

/// Trusted absolute Git binary supplied by Root (never `PATH`-resolved here).
fn git_binary() -> Result<PathBuf> {
    let path = match std::env::var("ROOTYARD_TEST_GIT") {
        Ok(value) => PathBuf::from(value),
        Err(_) => PathBuf::from("/usr/bin/git"),
    };
    ensure!(path.is_absolute(), "ROOTYARD_TEST_GIT must be an absolute path");
    ensure!(path.is_file(), "the configured absolute git binary does not exist");
    Ok(path)
}

/// The real store from the operator-supplied Blob profile. A missing or invalid
/// `ROOTYARD_BLOB_*` profile is a hard failure, never a skipped case.
fn open_store() -> Result<BlobStore> {
    let profile =
        BlobProfile::from_env().map_err(|error| anyhow!("configured ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(
        profile.provider() == BlobProvider::S3,
        "this suite qualifies the real S3 profile only; ROOTYARD_BLOB_SERVICE must be s3"
    );
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

/// One random schema, built only by `db::migrate` (migration 142 asserted).
struct Db {
    admin: Pool,
    pool: Pool,
    schema: String,
}

impl Db {
    async fn setup() -> Result<Self> {
        let url = database_url();
        let admin = db::pool(&url)?;
        let schema = format!("ref_store_packs_test_{}", Uuid::new_v4().simple());
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
        let client = pool.get().await?;
        let installed: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=142)
                    AND to_regclass('ref_store_core_pack_publications') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_artifacts') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_memberships') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_history') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_repo_usage') IS NOT NULL
                    AND to_regclass('ref_store_core_pack_tenant_usage') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        ensure!(installed, "db::migrate did not install migration 142; no DDL fallback exists in this suite");
        drop(client);
        Ok(Self { admin, pool, schema })
    }

    async fn teardown(&self) -> Result<()> {
        self.admin.get().await?.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema)).await?;
        Ok(())
    }

    /// Always drop the owned schema, but never hide the primary test failure.
    async fn finish(&self, outcome: Result<()>) -> Result<()> {
        match outcome {
            Ok(()) => self.teardown().await,
            Err(error) => {
                let _ = self.teardown().await;
                Err(error)
            }
        }
    }

    /// Fixture-only business rows: one user (also the tenant/owner) and one
    /// isolated unserved provisioning `gitfs` repository of the gate format.
    async fn business(&self, format: GitObjectFormat) -> Result<(Uuid, Uuid)> {
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let object_format = format.as_str().to_owned();
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO users(id,username) VALUES($1,$2)",
                &[&tenant, &format!("packs{}", &tenant.simple().to_string()[..12])],
            )
            .await?;
        client
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,object_format)
                 VALUES($1,$2,$3,'provisioning',$4)",
                &[&repo, &tenant, &format!("repo{}", &repo.simple().to_string()[..12]), &object_format],
            )
            .await?;
        drop(client);
        Ok((tenant, repo))
    }

    async fn gate(&self, repo: Uuid, tenant: Uuid, format: GitObjectFormat) -> Result<CoreGateVersion> {
        let init = CoreGateInit::new(repo, tenant, format, Uuid::new_v4(), 1, 1, RefName::branch("refs/heads/main")?)?;
        let mut client = self.pool.get().await?;
        let gate = PgRefStoreCore.initialize(&mut client, &init, deadline()).await?;
        Ok(gate.version())
    }
}

async fn gate_state(pool: &Pool, repo: Uuid) -> Result<(i64, String)> {
    let row = pool
        .get()
        .await?
        .query_one("SELECT revision,pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&repo])
        .await?;
    Ok((row.get(0), row.get(1)))
}

async fn ref_oid(pool: &Pool, repo: Uuid, name: &str) -> Result<Option<String>> {
    let row = pool
        .get()
        .await?
        .query_opt("SELECT oid FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name=$2", &[&repo, &name])
        .await?;
    Ok(row.map(|row| row.get(0)))
}

/// Exact A4 row counts: publications, artifacts, memberships, committed history
/// rows and committed events. Direct SQL is observation only here, never an ACK.
async fn row_counts(pool: &Pool, repo: Uuid) -> Result<(i64, i64, i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT (SELECT count(*) FROM ref_store_core_pack_publications WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_pack_artifacts WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_pack_memberships WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_pack_history WHERE repository_id=$1 AND kind='committed'),
                    (SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1 AND outcome='committed')",
            &[&repo],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
}

/// Retained admission counters of the repository usage row.
async fn usage_row(pool: &Pool, repo: Uuid) -> Result<[i64; 5]> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT registration_count,artifact_count,membership_count,logical_bytes,receipt_count
             FROM ref_store_core_pack_repo_usage WHERE repository_id=$1",
            &[&repo],
        )
        .await?;
    Ok(row.map(|row| [row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)]).unwrap_or([0; 5]))
}

/// Retained admission counters of the tenant usage row.
async fn tenant_usage_row(pool: &Pool, tenant: Uuid) -> Result<[i64; 5]> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT registration_count,artifact_count,membership_count,logical_bytes,receipt_count
             FROM ref_store_core_pack_tenant_usage WHERE tenant_id=$1",
            &[&tenant],
        )
        .await?;
    Ok(row.map(|row| [row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)]).unwrap_or([0; 5]))
}

/// Repository and tenant retained counters of one isolated tenant/repository.
async fn usage_both(pool: &Pool, repo: Uuid, tenant: Uuid) -> Result<([i64; 5], [i64; 5])> {
    Ok((usage_row(pool, repo).await?, tenant_usage_row(pool, tenant).await?))
}

/// Durable migration-138 operation state (public registry API, not SQL).
async fn operation_state(pool: &Pool, repo: Uuid, operation: Uuid) -> Result<OperationState> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let lookup = PgRefStore.get(&tx, repo, operation, deadline()).await?;
    let _ = tx.rollback().await;
    match lookup {
        OperationLookup::Known(record) => Ok(record.state()),
        OperationLookup::Unknown => Err(anyhow!("operation row is missing from the 138 registry")),
    }
}

/// Harden fixture Git: owned HOME/template, no inherited environment, known
/// author, closed argv and a bounded timeout. Fixture bytes are synthetic.
struct GitRepo {
    _root: tempfile::TempDir,
    bare: PathBuf,
    home: PathBuf,
    template: PathBuf,
    git: PathBuf,
    format: GitObjectFormat,
}

impl GitRepo {
    async fn new(git: PathBuf, format: GitObjectFormat) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let template = root.path().join("template");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&template)?;
        let repo = Self { bare: root.path().join("fixture.git"), home, template, git, format, _root: root };
        let object_format = format!("--object-format={}", format.as_str());
        let template_arg = format!("--template={}", repo.template.display());
        repo.run(&["init", "--bare", "--quiet", object_format.as_str(), template_arg.as_str()], None).await?;
        Ok(repo)
    }

    async fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        // `init` runs before the bare directory exists; every later plumbing
        // command is bound to the owned fixture repository through GIT_DIR.
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
        let output = tokio::time::timeout(Duration::from_secs(GIT_SECONDS), child.wait_with_output())
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
        let entry = format!("100644 blob {blob}\t{file}\n");
        Self::text(&self.run(&["mktree"], Some(entry.as_bytes())).await?)
    }

    async fn commit_tree(&self, tree: &str, message: &str) -> Result<String> {
        Self::text(&self.run(&["commit-tree", tree, "-m", message], None).await?)
    }

    async fn update_ref(&self, name: &str, oid: &str) -> Result<()> {
        self.run(&["update-ref", name, oid], None).await?;
        Ok(())
    }

    /// Valid synthetic commit with exactly one blob and one tree.
    async fn build_commit(&self, file: &str, content: &[u8], message: &str) -> Result<String> {
        let blob = self.add_blob(content).await?;
        let tree = self.mktree(file, &blob).await?;
        self.commit_tree(&tree, message).await
    }

    fn artifacts_dir(&self) -> Result<PathBuf> {
        let parent = self.bare.parent().ok_or_else(|| anyhow!("fixture repository has no parent"))?;
        let dir = parent.join("artifacts");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Let mature Git write the actual `.pack` stream and the matching `.idx`.
    /// `args` are `pack-objects` arguments; `revisions` is its stdin when needed.
    async fn pack(&self, name: &str, args: &[&str], revisions: Option<&[u8]>) -> Result<PairFiles> {
        let bytes = self.run(args, revisions).await?;
        ensure!(bytes.starts_with(b"PACK"), "git pack-objects did not produce a pack stream");
        let pack = self.artifacts_dir()?.join(format!("{name}.pack"));
        std::fs::write(&pack, &bytes)?;
        let pack_arg = pack.to_str().ok_or_else(|| anyhow!("fixture pack path is not UTF-8"))?.to_owned();
        self.run(&["index-pack", pack_arg.as_str()], None).await?;
        PairFiles::new(pack, self.artifacts_dir()?.join(format!("{name}.idx")))
    }

    /// Every object reachable from every fixture ref.
    async fn pack_all(&self, name: &str) -> Result<PairFiles> {
        self.pack(name, &["pack-objects", "--stdout", "--all"], None).await
    }

    /// Closure of exactly one revision.
    async fn pack_revision(&self, name: &str, oid: &str) -> Result<PairFiles> {
        let stdin = format!("{oid}\n");
        self.pack(name, &["pack-objects", "--stdout", "--revs"], Some(stdin.as_bytes())).await
    }

    /// Exactly one object and no closure (a deliberately incomplete pack).
    async fn pack_object_only(&self, name: &str, oid: &str) -> Result<PairFiles> {
        let stdin = format!("{oid}\n");
        self.pack(name, &["pack-objects", "--stdout"], Some(stdin.as_bytes())).await
    }

    fn format(&self) -> GitObjectFormat {
        self.format
    }
}

/// One actual `.pack` + `.idx` pair produced by mature Git.
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

    /// A deliberately truncated pack (bad header) paired with a real index.
    fn truncated_header(&self) -> Result<Self> {
        let bytes = std::fs::read(&self.pack)?;
        ensure!(bytes.len() > 12, "fixture pack is too short to truncate");
        let short = self.pack.with_file_name("truncated-header.pack");
        std::fs::write(&short, &bytes[..8])?;
        Ok(Self { pack: short, idx: self.idx.clone() })
    }
}

fn digest_file(path: &Path) -> Result<(String, u64)> {
    let bytes = std::fs::read(path)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}

/// One end-to-end successful pack commit, ready for row/terminal assertions.
struct Flow {
    repo: Uuid,
    tenant: Uuid,
    gate: CoreGateVersion,
    draft: Draft,
    proof: PackClosureProof,
    receipt: PackCommitReceipt,
    publication: ProtectedPublication,
    registration: PackRegistrationReceipt,
}

/// Valid native pack -> protected S3 upload -> durable registration -> closure
/// context -> real `PackVerifier` -> PG atomic verified commit.
async fn positive(db: &Db, store: &BlobStore, git: &Path, format: GitObjectFormat) -> Result<Flow> {
    let (tenant, repo) = db.business(format).await?;
    let gate = db.gate(repo, tenant, format).await?;
    let fixture = GitRepo::new(git.to_path_buf(), format).await?;
    ensure!(fixture.format() == format, "fixture object format is not the gate format");
    let commit_oid = fixture.build_commit("file.txt", b"pack commit fixture\n", "fixture main").await?;
    fixture.update_ref("refs/heads/main", &commit_oid).await?;
    let files = fixture.pack_all("closure").await?;
    let draft =
        draft(db, repo, tenant, 1, &gate, vec![main_update(format, &commit_oid)?], std::slice::from_ref(&files))
            .await?;
    ensure!(expected_main_oid(&draft.plan)? == commit_oid, "plan does not target the fixture commit");
    ensure!(draft.plan.expected().mode() == PackMode::MetadataOnly, "fresh gate is not metadata_only");
    let publication = publish(db, store, &draft.plan, &files).await?;
    let registration = register(db, &draft.plan, planned_pack_id(&draft.plan)?, &publication).await?;
    ensure!(!registration.replayed, "fresh registration replayed an old ACK");
    let context = closure(db, &draft.plan).await?;
    ensure!(
        context.new_packs().len() == 1 && context.old_packs().is_empty(),
        "closure pack set is not the single planned pack"
    );
    readback(store, context.new_packs(), fixture._root.path()).await?;
    let proof = prove(store, git, &draft.plan, &context).await?;
    let receipt = commit(db, &draft, &proof).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "fresh verified commit did not commit");
    Ok(Flow { repo, tenant, gate, draft, proof, receipt, publication, registration })
}

/// Exact rows, gate revision/mode, operation state and retained counters.
async fn assert_committed(db: &Db, flow: &Flow) -> Result<()> {
    let (revision, mode) = gate_state(&db.pool, flow.repo).await?;
    ensure!(revision == flow.gate.revision() + 1, "gate revision is not exactly +1");
    ensure!(mode == "pack_verified", "gate mode did not move to pack_verified");
    let expected_oid = expected_main_oid(&flow.draft.plan)?;
    ensure!(
        ref_oid(&db.pool, flow.repo, "refs/heads/main").await?.as_deref() == Some(expected_oid.as_str()),
        "stored refs/heads/main is not the planned object id"
    );
    ensure!(
        operation_state(&db.pool, flow.repo, flow.draft.plan.identity().operation_id()).await?
            == OperationState::Committed,
        "operation terminal is not committed"
    );

    let terminal = &flow.receipt.terminal;
    ensure!(terminal.is_committed(), "receipt terminal is not committed");
    ensure!(terminal.revision == revision, "terminal revision is not the new gate revision");
    ensure!(terminal.mode == "pack_verified", "terminal mode is not pack_verified");
    ensure!(terminal.head_ref.as_deref() == Some("refs/heads/main"), "terminal HEAD is not refs/heads/main");
    ensure!(terminal.registrations.len() == 1, "terminal does not carry exactly one registration");
    let planned = planned_pack_id(&flow.draft.plan)?;
    ensure!(terminal.registrations[0].pack_id == planned, "terminal names another pack id");
    ensure!(
        terminal.registrations[0].registration_id == flow.registration.ack.registration_id,
        "terminal names another registration id"
    );

    // The publication's direct acquire/consume ids are the registered ACK ids.
    let ack = &flow.registration.ack;
    ensure!(
        ack.acquire_request_id == flow.publication.acquire_request_id(),
        "registration ACK acquire id is not the publication acquire id"
    );
    ensure!(
        ack.consume_request_id == flow.publication.consume_request_id(),
        "registration ACK consume id is not the publication consume id"
    );
    let mut ack_holds = ack.hold_ids.clone();
    let mut receipt_holds = flow.publication.receipts().iter().map(|receipt| receipt.hold_id()).collect::<Vec<_>>();
    ack_holds.sort();
    receipt_holds.sort();
    ensure!(ack_holds == receipt_holds, "registration ACK holds are not the publication holds");
    ensure!(ack.parent_digest == flow.draft.plan.parent_digest().as_hex(), "ACK parent digest differs");
    ensure!(ack.artifact_set_digest.len() == 64, "ACK artifact-set digest is not sha256 hex");

    ensure!(row_counts(&db.pool, flow.repo).await? == (1, 2, 1, 1, 1), "unexpected A4 row counts");
    let (usage, tenant_usage) = usage_both(&db.pool, flow.repo, flow.tenant).await?;
    ensure!(
        usage[0] == 1 && usage[1] == 2 && usage[2] == 1 && usage[4] == 4 && usage[3] > 0,
        "retained usage counters are not one registration/two artifacts/one membership/four receipts"
    );
    ensure!(tenant_usage == usage, "tenant retained counters differ from the repository counters");
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn sha1_native_pack_registers_publishes_commits_and_replays_terminal() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let flow = positive(&db, &store, &git, GitObjectFormat::Sha1).await?;
        assert_committed(&db, &flow).await?;
        let counts = row_counts(&db.pool, flow.repo).await?;
        let usage = usage_both(&db.pool, flow.repo, flow.tenant).await?;
        let again = commit(&db, &flow.draft, &flow.proof).await?;
        ensure!(again.replayed, "repeat verified commit did not replay the old terminal");
        ensure!(again.terminal == flow.receipt.terminal, "repeat replay terminal differs");
        ensure!(again.record.state() == OperationState::Committed, "repeat replay state is not committed");
        ensure!(row_counts(&db.pool, flow.repo).await? == counts, "repeat replay wrote additional rows");
        ensure!(usage_both(&db.pool, flow.repo, flow.tenant).await? == usage, "repeat replay charged additional quota");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn sha256_native_pack_registers_publishes_and_commits() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let flow = positive(&db, &store, &git, GitObjectFormat::Sha256).await?;
        assert_committed(&db, &flow).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

async fn active_holds(pool: &Pool, repo: Uuid) -> Result<i64> {
    Ok(pool
        .get()
        .await?
        .query_one("SELECT count(*) FROM artifact_holds WHERE repository_id=$1 AND state='active'", &[&repo])
        .await?
        .get(0))
}

/// Register the pair and require the real native verifier to deny it. A denial
/// leaves the durable registration and the permanent A3 holds retained.
async fn denied(
    db: &Db,
    store: &BlobStore,
    git: &Path,
    repo: Uuid,
    tenant: Uuid,
    sequence: i64,
    gate: &CoreGateVersion,
    format: GitObjectFormat,
    commit_oid: &str,
    files: &PairFiles,
) -> Result<()> {
    let draft =
        draft(db, repo, tenant, sequence, gate, vec![main_update(format, commit_oid)?], std::slice::from_ref(files))
            .await?;
    let pack_id = planned_pack_id(&draft.plan)?;
    let publication = publish(db, store, &draft.plan, files).await?;
    let registration = register(db, &draft.plan, pack_id, &publication).await?;
    ensure!(!registration.replayed, "denial registration replayed an old ACK");
    let context = closure(db, &draft.plan).await?;
    let error = prove(store, git, &draft.plan, &context)
        .await
        .expect_err("the native verifier accepted invalid closure artifacts");
    ensure!(
        matches!(error.downcast_ref::<PackCommitError>(), Some(PackCommitError::ProofUnavailable(_))),
        "unexpected verifier refusal kind: {error}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn mismatched_idx_and_missing_closure_object_are_denied_without_writes() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (tenant, repo) = db.business(GitObjectFormat::Sha1).await?;
        let gate = db.gate(repo, tenant, GitObjectFormat::Sha1).await?;
        let fixture = GitRepo::new(git.clone(), GitObjectFormat::Sha1).await?;
        let first = fixture.build_commit("a.txt", b"first fixture file\n", "fixture first").await?;
        fixture.update_ref("refs/heads/main", &first).await?;
        let second = fixture.build_commit("b.txt", b"second fixture file\n", "fixture second").await?;
        fixture.update_ref("refs/heads/other", &second).await?;
        let pack_first = fixture.pack_revision("rev-a", &first).await?;
        let pack_second = fixture.pack_revision("rev-b", &second).await?;

        // (1) Individually valid `.pack` of one commit with the `.idx` of another.
        let mismatched = PairFiles { pack: pack_first.pack.clone(), idx: pack_second.idx.clone() };
        denied(&db, &store, &git, repo, tenant, 1, &gate, GitObjectFormat::Sha1, &first, &mismatched).await?;

        // (2) A pack holding only the commit: the ref target's tree is missing.
        let incomplete = fixture.pack_object_only("commit-only", &first).await?;
        denied(&db, &store, &git, repo, tenant, 2, &gate, GitObjectFormat::Sha1, &first, &incomplete).await?;

        ensure!(
            gate_state(&db.pool, repo).await? == (gate.revision(), "metadata_only".to_owned()),
            "a denial moved the gate"
        );
        ensure!(ref_oid(&db.pool, repo, "refs/heads/main").await?.is_none(), "a denial wrote the ref");
        ensure!(row_counts(&db.pool, repo).await? == (2, 4, 0, 0, 0), "a denial wrote membership/terminal/event rows");
        let usage = usage_row(&db.pool, repo).await?;
        ensure!(usage[0] == 2 && usage[1] == 4 && usage[2] == 0 && usage[4] == 4, "denial counters differ");
        ensure!(active_holds(&db.pool, repo).await? == 4, "denial holds are not permanently retained");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn truncated_pack_header_and_wrong_object_format_are_denied() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        // (1) Eight-byte pack: the verifier's fixed 12-byte header admission fails.
        let (tenant, repo) = db.business(GitObjectFormat::Sha1).await?;
        let gate = db.gate(repo, tenant, GitObjectFormat::Sha1).await?;
        let fixture = GitRepo::new(git.clone(), GitObjectFormat::Sha1).await?;
        let commit_oid = fixture.build_commit("a.txt", b"header fixture\n", "fixture header").await?;
        fixture.update_ref("refs/heads/main", &commit_oid).await?;
        let pair = fixture.pack_all("closure").await?;
        let torn = pair.truncated_header()?;
        denied(&db, &store, &git, repo, tenant, 1, &gate, GitObjectFormat::Sha1, &commit_oid, &torn).await?;
        ensure!(
            gate_state(&db.pool, repo).await? == (gate.revision(), "metadata_only".to_owned()),
            "header denial moved the gate"
        );
        ensure!(ref_oid(&db.pool, repo, "refs/heads/main").await?.is_none(), "header denial wrote the ref");

        // (2) A SHA-1 pack registered for a SHA-256 gate: native Git refuses it.
        let (tenant, repo) = db.business(GitObjectFormat::Sha256).await?;
        let gate = db.gate(repo, tenant, GitObjectFormat::Sha256).await?;
        let fixture = GitRepo::new(git.clone(), GitObjectFormat::Sha256).await?;
        let commit_oid = fixture.build_commit("a.txt", b"sha256 fixture\n", "fixture sha256").await?;
        fixture.update_ref("refs/heads/main", &commit_oid).await?;
        let sha1_fixture = GitRepo::new(git.clone(), GitObjectFormat::Sha1).await?;
        let sha1_commit = sha1_fixture.build_commit("a.txt", b"sha1 fixture\n", "fixture sha1").await?;
        sha1_fixture.update_ref("refs/heads/main", &sha1_commit).await?;
        let foreign = sha1_fixture.pack_all("sha1-closure").await?;
        denied(&db, &store, &git, repo, tenant, 1, &gate, GitObjectFormat::Sha256, &commit_oid, &foreign).await?;
        ensure!(
            gate_state(&db.pool, repo).await? == (gate.revision(), "metadata_only".to_owned()),
            "format denial moved the gate"
        );
        ensure!(ref_oid(&db.pool, repo, "refs/heads/main").await?.is_none(), "format denial wrote the ref");
        ensure!(
            row_counts(&db.pool, repo).await? == (1, 2, 0, 0, 0),
            "format denial wrote membership/terminal/event rows"
        );
        ensure!(active_holds(&db.pool, repo).await? == 2, "format denial holds are not retained");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

/// A plan plus the opaque Pending token minted by `begin_pending`.
struct Draft {
    plan: PackCommitPlan,
    token: PackPendingToken,
}

fn main_update(format: GitObjectFormat, commit: &str) -> Result<RefUpdate> {
    Ok(RefUpdate::new(
        RefName::branch("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(format, commit)?),
    ))
}

fn planned_pack_id(plan: &PackCommitPlan) -> Result<Uuid> {
    plan.packs().first().map(|pack| pack.pack_id()).ok_or_else(|| anyhow!("the plan has no planned pack"))
}

fn expected_main_oid(plan: &PackCommitPlan) -> Result<String> {
    match plan.refs().first().map(RefUpdate::target) {
        Some(RefTarget::Oid(oid)) => Ok(oid.as_hex()),
        _ => Err(anyhow!("the plan has no object-id ref update")),
    }
}

/// Capture the baseline, build the pre-A3 plan with preallocated pack and
/// registration ids and establish the durable Pending row.
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
        "captured baseline is not the expected gate revision/digest"
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

/// Real A3 acquire, then (after the PostgreSQL client is closed) the protected
/// consume+upload of the exact pack/idx bytes through the configured S3 store.
async fn publish(db: &Db, store: &BlobStore, plan: &PackCommitPlan, file: &PairFiles) -> Result<ProtectedPublication> {
    let (pack_sha, pack_len) = digest_file(&file.pack)?;
    let (idx_sha, idx_len) = digest_file(&file.idx)?;
    let specs = vec![
        ArtifactSpec::new(HOLD_NAMESPACE, pack_sha, pack_len)?,
        ArtifactSpec::new(HOLD_NAMESPACE, idx_sha, idx_len)?,
    ];
    let request = AcquireArtifactHoldsRequest::new(
        hold_scope(plan)?,
        plan.identity().clone(),
        Uuid::new_v4(),
        store.backend_identity().clone(),
        Uuid::new_v4(),
        1,
        *plan.expected().gate_digest(),
        specs,
    )?;
    let grant = {
        let mut client = db.pool.get().await?;
        match PgArtifactHoldStore.acquire(&mut client, store, &request, deadline()).await? {
            AcquireOutcome::Granted { grant, .. } => grant,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh A3 acquire unexpectedly replayed")),
        }
    };
    // No PostgreSQL client, transaction or pool lease is alive here.
    let uploader = ProtectedUploader::new(store.clone());
    let sources = [UploadSource::new(file.pack.clone()), UploadSource::new(file.idx.clone())];
    let publication = uploader
        .consume_and_upload(&db.pool, grant, &sources, std_deadline())
        .await
        // Typed refusal only: no provider/endpoint/credential text is surfaced.
        .map_err(|_| anyhow!("protected upload refused by the protected uploader"))?;
    ensure!(publication.receipts().len() == 2, "publication is not exactly a two-artifact pair");
    Ok(publication)
}

async fn register(
    db: &Db,
    plan: &PackCommitPlan,
    pack_id: Uuid,
    publication: &ProtectedPublication,
) -> Result<PackRegistrationReceipt> {
    let mut client = db.pool.get().await?;
    let request = PackRegistrationRequest::new(plan, pack_id, publication)?;
    Ok(PgPackCommit.register_publication(&mut client, request, deadline()).await?)
}

async fn closure(db: &Db, plan: &PackCommitPlan) -> Result<PackClosureContext> {
    let mut client = db.pool.get().await?;
    Ok(PgPackCommit.capture_context(&mut client, plan, deadline()).await?)
}

/// Real native verification of the registered S3 bytes with the trusted Git.
async fn prove(
    store: &BlobStore,
    git: &Path,
    plan: &PackCommitPlan,
    context: &PackClosureContext,
) -> Result<PackClosureProof> {
    let verifier = PackVerifier::new(store.clone(), git.to_path_buf())?;
    Ok(verifier.verify(plan, context, std_deadline()).await?)
}

async fn commit(db: &Db, draft: &Draft, proof: &PackClosureProof) -> Result<PackCommitReceipt> {
    let mut client = db.pool.get().await?;
    Ok(PgPackCommit.commit_verified_pending(&mut client, &draft.plan, &draft.token, proof, deadline()).await?)
}

/// Our own verified remote GET read-back of every registered artifact.
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

// ---------------------------------------------------------------------------
// Follow-up behavior cases (fixture-only probes; never adapter ACKs).
// ---------------------------------------------------------------------------

/// Fixture-only BEFORE INSERT probes on 138 pending, new publication and core
/// event rows. They record what `synchronous_commit` the adapter's own
/// transaction actually had, in a private table of this suite's random schema.
async fn install_sync_probe(pool: &Pool) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(
            "CREATE TABLE fixture_pack_sync_probe(
                 probe_id BIGSERIAL PRIMARY KEY,
                 source TEXT NOT NULL,
                 value TEXT NOT NULL);
             CREATE FUNCTION fixture_pack_sync_record() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN
                 INSERT INTO fixture_pack_sync_probe(source,value)
                 VALUES (TG_TABLE_NAME || ':' || TG_OP, current_setting('synchronous_commit'));
                 RETURN NEW;
               END $$;
             CREATE TRIGGER fixture_pack_sync_operations BEFORE INSERT ON ref_store_operations
               FOR EACH ROW EXECUTE FUNCTION fixture_pack_sync_record();
             CREATE TRIGGER fixture_pack_sync_publications BEFORE INSERT ON ref_store_core_pack_publications
               FOR EACH ROW EXECUTE FUNCTION fixture_pack_sync_record();
             CREATE TRIGGER fixture_pack_sync_events BEFORE INSERT ON ref_store_core_events
               FOR EACH ROW EXECUTE FUNCTION fixture_pack_sync_record();",
        )
        .await?;
    Ok(())
}

/// Probe answer: every recorded write happened with durable `on`, and the three
/// probed write paths were all exercised.
async fn sync_probe_values(pool: &Pool) -> Result<Vec<(String, String)>> {
    let rows =
        pool.get().await?.query("SELECT source,value FROM fixture_pack_sync_probe ORDER BY probe_id", &[]).await?;
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
}

/// Plan construction on one caller-owned client (the session that must carry
/// `synchronous_commit=off` for the whole adapter call sequence).
async fn draft_on(
    client: &mut tokio_postgres::Client,
    repo: Uuid,
    tenant: Uuid,
    sequence: i64,
    gate: &CoreGateVersion,
    refs: Vec<RefUpdate>,
    files: &[PairFiles],
) -> Result<Draft> {
    let baseline = PgPackCommit.capture_baseline(client, repo, tenant, deadline()).await?;
    ensure!(
        baseline.gate().revision() == gate.revision() && baseline.gate().digest() == gate.digest(),
        "captured baseline is not the expected gate revision/digest"
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
    let token = PgPackCommit.begin_pending(client, &plan, deadline()).await?;
    Ok(Draft { plan, token })
}

async fn register_on(
    client: &mut tokio_postgres::Client,
    plan: &PackCommitPlan,
    pack_id: Uuid,
    publication: &ProtectedPublication,
) -> Result<PackRegistrationReceipt> {
    let request = PackRegistrationRequest::new(plan, pack_id, publication)?;
    Ok(PgPackCommit.register_publication(client, request, deadline()).await?)
}

async fn commit_on(
    client: &mut tokio_postgres::Client,
    draft: &Draft,
    proof: &PackClosureProof,
) -> Result<PackCommitReceipt> {
    Ok(PgPackCommit.commit_verified_pending(client, &draft.plan, &draft.token, proof, deadline()).await?)
}

async fn session_synchronous_commit(client: &tokio_postgres::Client) -> Result<String> {
    Ok(client.query_one("SHOW synchronous_commit", &[]).await?.get(0))
}

/// Case 1: a caller session with `synchronous_commit=off` still makes every
/// adapter write durable-on (fixture BEFORE-write probes), and the adapter's
/// `SET LOCAL` never leaks into the caller's session after it returns.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn caller_session_off_still_records_durable_on_and_never_leaks_setlocal() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (tenant, repo) = db.business(GitObjectFormat::Sha1).await?;
        let gate = db.gate(repo, tenant, GitObjectFormat::Sha1).await?;
        install_sync_probe(&db.pool).await?;
        let fixture = GitRepo::new(git.clone(), GitObjectFormat::Sha1).await?;
        let commit_oid = fixture.build_commit("a.txt", b"durability fixture\n", "fixture durability").await?;
        fixture.update_ref("refs/heads/main", &commit_oid).await?;
        let files = fixture.pack_all("durability").await?;

        let mut writer = db.pool.get().await?;
        writer.batch_execute("SET synchronous_commit=off").await?;
        ensure!(
            session_synchronous_commit(&writer).await? == "off",
            "the caller session did not adopt synchronous_commit=off"
        );
        let draft = draft_on(
            &mut writer,
            repo,
            tenant,
            1,
            &gate,
            vec![main_update(GitObjectFormat::Sha1, &commit_oid)?],
            std::slice::from_ref(&files),
        )
        .await?;
        let publication = publish(&db, &store, &draft.plan, &files).await?;
        let registration = register_on(&mut writer, &draft.plan, planned_pack_id(&draft.plan)?, &publication).await?;
        ensure!(!registration.replayed, "fresh registration replayed");
        let context = PgPackCommit.capture_context(&mut writer, &draft.plan, deadline()).await?;
        ensure!(
            session_synchronous_commit(&writer).await? == "off",
            "begin_pending/registration leaked SET LOCAL synchronous_commit into the caller session"
        );
        // No PostgreSQL client, transaction or lease may be alive during native IO.
        drop(writer);
        readback(&store, context.new_packs(), fixture._root.path()).await?;
        let proof = prove(&store, &git, &draft.plan, &context).await?;
        drop(fixture);
        let mut committer = db.pool.get().await?;
        committer.batch_execute("SET synchronous_commit=off").await?;
        let receipt = commit_on(&mut committer, &draft, &proof).await?;
        ensure!(receipt.is_committed() && !receipt.replayed, "verified commit did not commit");
        ensure!(
            session_synchronous_commit(&committer).await? == "off",
            "verified commit leaked SET LOCAL synchronous_commit into the caller session"
        );
        drop(committer);

        let flow = Flow { repo, tenant, gate, draft, proof, receipt, publication, registration };
        assert_committed(&db, &flow).await?;
        let probes = sync_probe_values(&db.pool).await?;
        ensure!(!probes.is_empty(), "no fixture durability probe fired");
        ensure!(
            probes.iter().all(|(_, value)| value == "on"),
            "an adapter write was not executed with durable synchronous_commit=on"
        );
        for table in ["ref_store_operations", "ref_store_core_pack_publications", "ref_store_core_events"] {
            ensure!(
                probes.iter().any(|(source, _)| source.starts_with(table)),
                "durability probe for {table} did not fire"
            );
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

/// RAII blocker: one backend holds the repository's core gate row `FOR UPDATE`
/// until `release()` (or drop) lets its owned transaction roll back.
struct GateBlock {
    release: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl GateBlock {
    async fn hold(pool: &Pool, repo: Uuid) -> Result<Self> {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<i32>();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let pool = pool.clone();
        let task = tokio::spawn(async move {
            let Ok(mut client) = pool.get().await else { return };
            let pid: i32 = match client.query_one("SELECT pg_backend_pid()", &[]).await {
                Ok(row) => row.get(0),
                Err(_) => return,
            };
            let Ok(tx) = client.transaction().await else { return };
            let locked = tx
                .query_opt("SELECT revision FROM ref_store_core_gates WHERE repository_id=$1 FOR UPDATE", &[&repo])
                .await
                .map(|row| row.is_some())
                .unwrap_or(false);
            if locked {
                let _ = ready_tx.send(pid);
                let _ = released.await;
            }
            let _ = tx.rollback().await;
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .map_err(|_| anyhow!("gate blocker never acquired the row lock"))?
            .map_err(|_| anyhow!("gate blocker task failed"))?;
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

/// Observer: the given backend is really parked on a lock right now.
async fn wait_for_lock_wait(pool: &Pool, pid: i32) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let parked: bool = observer
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)
                        AND EXISTS(SELECT 1 FROM pg_stat_activity
                                   WHERE pid=$1 AND state='active' AND wait_event_type='Lock')",
                    &[&pid],
                )
                .await?
                .get(0);
            if parked {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("the capture backend never parked on the gate lock"))??;
    Ok(())
}

fn bounded_deadline_failure(error: &PackCommitError) -> bool {
    use rootyard::ref_store::RefStoreError;
    match error {
        PackCommitError::RefStore(RefStoreError::Timeout) => true,
        PackCommitError::RefStore(RefStoreError::Database(text)) => {
            let lower = text.to_ascii_lowercase();
            lower.contains("canceling statement") || lower.contains("timeout") || lower.contains("57014")
        }
        _ => false,
    }
}

/// Case 2: a read capture blocked on the gate row must fail on its own bounded
/// deadline (not a generic error), write nothing, and leave the client usable.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn blocked_gate_capture_fails_on_bounded_deadline_and_client_recovers() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = async {
        let (tenant, repo) = db.business(GitObjectFormat::Sha1).await?;
        let gate = db.gate(repo, tenant, GitObjectFormat::Sha1).await?;
        let blocker = GateBlock::hold(&db.pool, repo).await?;

        let mut client = db.pool.get().await?;
        let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        let started = StdInstant::now();
        let capture = tokio::spawn(async move {
            let outcome = PgPackCommit
                .capture_baseline(&mut client, repo, tenant, TokioInstant::now() + Duration::from_secs(2))
                .await;
            (client, outcome)
        });
        // Observed while the capture is still parked: the new backend waits on the
        // gate row lock, so the failure below cannot be a pre-lock short circuit.
        wait_for_lock_wait(&db.pool, pid).await?;
        let (mut client, capture) = capture.await.map_err(|_| anyhow!("blocked capture task failed"))?;
        let elapsed = started.elapsed();
        let error = capture.expect_err("blocked capture succeeded");
        ensure!(bounded_deadline_failure(&error), "blocked capture failed for another reason: {error}");
        ensure!(elapsed >= Duration::from_millis(500), "blocked capture did not wait for its bounded deadline");
        ensure!(elapsed <= Duration::from_secs(20), "blocked capture cleanup was not bounded");

        ensure!(
            gate_state(&db.pool, repo).await? == (gate.revision(), "metadata_only".to_owned()),
            "the blocked capture wrote the gate"
        );
        ensure!(ref_oid(&db.pool, repo, "refs/heads/main").await?.is_none(), "the blocked capture wrote a ref");

        // Same client, owned rollback completed: a plain statement still works.
        let _: i32 = client.query_one("SELECT 1", &[]).await?.get(0);
        blocker.release().await?;
        let recovered = PgPackCommit.capture_baseline(&mut client, repo, tenant, deadline()).await?;
        ensure!(recovered.gate().revision() == gate.revision(), "recovered capture is not the expected gate");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

async fn attempt_statement(pool: &Pool, statement: &str) -> Result<Result<(), tokio_postgres::Error>> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let result = tx.batch_execute(statement).await;
    let _ = tx.rollback().await;
    Ok(result)
}

/// An FK-only `0A000` is never a guard: `CASCADE` must still be refused by the
/// actual immutability trigger, and the refusal must carry a trigger/check code.
fn guard_refusal(error: &tokio_postgres::Error) -> Option<String> {
    let database = error.as_db_error()?;
    let code = database.code().code();
    match code {
        "P0001" | "23514" | "23503" | "42501" | "55000" => Some(format!("{code}: {}", database.message())),
        _ => None,
    }
}

async fn ddl_denied(pool: &Pool, table: &str, operation: &str) -> Result<()> {
    let statement =
        if operation == "DELETE" { format!("DELETE FROM {table}") } else { format!("TRUNCATE TABLE {table}") };
    let first = attempt_statement(pool, &statement).await?;
    let guard = match first {
        Err(error) if error.as_db_error().map(|database| database.code().code()) == Some("0A000") => {
            let cascade = format!("{statement} CASCADE");
            attempt_statement(pool, &cascade).await?.err().and_then(|error| guard_refusal(&error))
        }
        Err(error) => guard_refusal(&error),
        Ok(()) => None,
    };
    ensure!(guard.is_some(), "{operation} on {table} was not refused by an actual guard (accepted or FK-only)");
    Ok(())
}

/// Case 3: both usage-counter tables refuse DELETE and TRUNCATE with their real
/// guards, and a trusted-scope historic ACK query after a cancel stays read-only
/// while a changed owner scope yields nothing.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn usage_counter_ddl_is_denied_and_historic_ack_query_needs_the_trusted_scope() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let flow = positive(&db, &store, &git, GitObjectFormat::Sha1).await?;
        assert_committed(&db, &flow).await?;
        let counters = usage_both(&db.pool, flow.repo, flow.tenant).await?;
        let counts = row_counts(&db.pool, flow.repo).await?;

        for table in ["ref_store_core_pack_repo_usage", "ref_store_core_pack_tenant_usage"] {
            ddl_denied(&db.pool, table, "DELETE").await?;
            ddl_denied(&db.pool, table, "TRUNCATE").await?;
        }
        ensure!(
            usage_both(&db.pool, flow.repo, flow.tenant).await? == counters,
            "a refused DDL changed the retained counters"
        );
        ensure!(row_counts(&db.pool, flow.repo).await? == counts, "a refused DDL changed the A4 ledger");

        // A durable cancellation tombstone for an already committed operation is
        // recorded without rewriting its immutable terminal.
        let mut canceller = db.pool.get().await?;
        let tx = canceller.transaction().await?;
        let cancel = PgRefStore.cancel(&tx, flow.draft.plan.identity(), deadline()).await?;
        tx.commit().await?;
        drop(canceller);
        ensure!(cancel.tombstone_created, "the cancellation tombstone was not recorded");
        ensure!(
            operation_state(&db.pool, flow.repo, flow.draft.plan.identity().operation_id()).await?
                == OperationState::Committed,
            "a cancel rewrote a committed terminal"
        );

        let registration_id = flow.registration.ack.registration_id;
        let mut reader = db.pool.get().await?;
        let historical = PgPackCommit
            .query_registration(&mut reader, flow.draft.plan.scope(), registration_id, deadline())
            .await?
            .ok_or_else(|| anyhow!("the historic registration ACK disappeared"))?;
        ensure!(historical.ack == flow.registration.ack, "the historic ACK differs from the registration ACK");
        ensure!(
            historical.ack.acquire_request_id == flow.publication.acquire_request_id(),
            "the historic ACK lost the direct acquire id"
        );
        let foreign_scope = PackCommitScope::new(
            flow.repo,
            flow.draft.plan.tenant_id(),
            Uuid::new_v4(),
            flow.gate.object_format(),
            flow.gate.history_incarnation(),
            flow.gate.authority_epoch(),
            flow.gate.group_epoch(),
        )?;
        let foreign = PgPackCommit.query_registration(&mut reader, &foreign_scope, registration_id, deadline()).await;
        ensure!(
            matches!(foreign, Ok(None)) || foreign.is_err(),
            "a foreign-owner scope returned the trusted registration ACK"
        );
        drop(reader);
        ensure!(
            usage_both(&db.pool, flow.repo, flow.tenant).await? == counters,
            "historic queries charged retained quota"
        );
        ensure!(row_counts(&db.pool, flow.repo).await? == counts, "historic queries wrote A4 rows");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

/// Fresh positive per-run advisory key; never a fixed database-global constant.
fn random_barrier_key() -> i64 {
    let bytes = Uuid::new_v4().into_bytes();
    let raw = i64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
    (raw & i64::MAX) | 1
}

/// RAII holder of one session advisory lock on its own backend.
struct BarrierLock {
    release: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl BarrierLock {
    async fn hold(pool: &Pool, key: i64) -> Result<Self> {
        ensure!(key > 0, "a fixture barrier key must be a fresh positive per-run advisory key");
        let client = pool.get().await?;
        tokio::time::timeout_at(deadline(), client.query_one("SELECT pg_advisory_lock($1)", &[&key]))
            .await
            .map_err(|_| anyhow!("fixture barrier key was not acquired before the bounded deadline"))??;
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = released.await;
            let _ = client.query_one("SELECT pg_advisory_unlock($1)", &[&key]).await;
        });
        Ok(Self { release: Some(release), task: Some(task) })
    }

    async fn release(mut self) -> Result<()> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.map_err(|_| anyhow!("fixture barrier unlock task failed"))?;
        }
        Ok(())
    }
}

impl Drop for BarrierLock {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

/// Fixture-only probe: the registration transaction parks at its own COMMIT on a
/// private advisory key, i.e. only after every write and while it still holds
/// the migration-138 parent prefix lock. Production is unchanged.
async fn install_registration_park(pool: &Pool, key: i64) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(&format!(
            "CREATE FUNCTION fixture_pack_reg_budget() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN
                 PERFORM set_config('statement_timeout','30000',true);
                 PERFORM set_config('lock_timeout','30000',true);
                 RETURN NEW;
               END $$;
             CREATE TRIGGER fixture_pack_reg_budget BEFORE INSERT ON ref_store_core_pack_publications
               FOR EACH ROW EXECUTE FUNCTION fixture_pack_reg_budget();
             CREATE FUNCTION fixture_pack_reg_park() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN NEW; END $$;
             CREATE CONSTRAINT TRIGGER fixture_pack_reg_park AFTER INSERT ON ref_store_core_pack_publications
               DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fixture_pack_reg_park();"
        ))
        .await?;
    Ok(())
}

/// Authoritative migration-138 operation prefix key, computed by PostgreSQL with
/// the production domain constant and the production hash expression.
async fn operation_prefix_key(pool: &Pool, repo: Uuid, operation: Uuid) -> Result<i64> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT hashtextextended($1::text || '/' || $2::uuid::text || '/' || $3::uuid::text, 0)",
            &[&OPERATION_LOCK_DOMAIN, &repo, &operation],
        )
        .await?;
    Ok(row.get(0))
}

/// Exact-key correlation in `pg_locks`: one-argument advisory keys are stored as
/// `classid`/`objid` with `objsubid = 1`, so the reconstructed 64-bit key must
/// equal the expected key and the grant state must match.
async fn advisory_key_state(pool: &Pool, pid: i32, key: i64, granted: bool) -> Result<bool> {
    let state: bool = pool
        .get()
        .await?
        .query_one(
            "SELECT EXISTS(
               SELECT 1 FROM pg_locks
               WHERE pid=$1 AND locktype='advisory' AND objsubid=1 AND granted=$3::boolean
                 AND (((classid::bigint << 32) | objid::bigint) = $2::bigint))",
            &[&pid, &key, &granted],
        )
        .await?
        .get(0);
    Ok(state)
}

async fn wait_for_key_wait(pool: &Pool, pid: i32, key: i64) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let lockwait = advisory_key_state(pool, pid, key, false).await?
                && observer
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                           WHERE pid=$1 AND state='active' AND wait_event_type='Lock')",
                        &[&pid],
                    )
                    .await?
                    .get::<_, bool>(0);
            if lockwait {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("backend never waited on the exact expected advisory key"))??;
    Ok(())
}

async fn wait_for_key_held(pool: &Pool, pid: i32, key: i64) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if advisory_key_state(pool, pid, key, true).await? {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("backend never held the exact expected advisory key"))??;
    Ok(())
}

fn rejected_as(error: &PackCommitError, code: &str) -> bool {
    matches!(error, PackCommitError::Rejected(rejection) if rejection.code.as_str() == code)
}

/// Case 4: REGISTER vs CANCEL on two distinct backends, linearized by the real
/// migration-138 advisory prefix, plus the reverse cancel-first refusal.
#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn registration_and_cancel_serialize_on_the_138_prefix() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (tenant, repo) = db.business(GitObjectFormat::Sha1).await?;
        let gate = db.gate(repo, tenant, GitObjectFormat::Sha1).await?;
        let fixture = GitRepo::new(git.clone(), GitObjectFormat::Sha1).await?;
        let commit_oid = fixture.build_commit("a.txt", b"barrier fixture\n", "fixture barrier").await?;
        fixture.update_ref("refs/heads/main", &commit_oid).await?;
        let files = fixture.pack_all("barrier").await?;
        let draft = draft(
            &db,
            repo,
            tenant,
            1,
            &gate,
            vec![main_update(GitObjectFormat::Sha1, &commit_oid)?],
            std::slice::from_ref(&files),
        )
        .await?;
        let pack_id = planned_pack_id(&draft.plan)?;
        let publication = publish(&db, &store, &draft.plan, &files).await?;

        let barrier_key = random_barrier_key();
        install_registration_park(&db.pool, barrier_key).await?;
        let barrier = BarrierLock::hold(&db.pool, barrier_key).await?;

        let plan_for_task = draft.plan.clone();
        let pool = db.pool.clone();
        let (reg_pid_tx, reg_pid_rx) = tokio::sync::oneshot::channel::<i32>();
        let registration = tokio::spawn(async move {
            let mut client = pool.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = reg_pid_tx.send(pid);
            let receipt = register_on(&mut client, &plan_for_task, pack_id, &publication).await?;
            Ok::<_, anyhow::Error>((pid, receipt))
        });
        let reg_pid = reg_pid_rx.await.map_err(|_| anyhow!("registration backend never reported its pid"))?;
        // Registration is parked at COMMIT on exactly our per-run barrier key and
        // still holds the exact migration-138 operation prefix key.
        wait_for_key_wait(&db.pool, reg_pid, barrier_key).await?;
        let prefix_key = operation_prefix_key(&db.pool, repo, draft.plan.identity().operation_id()).await?;
        ensure!(prefix_key != barrier_key, "the fixture barrier key collides with the 138 prefix key");
        wait_for_key_held(&db.pool, reg_pid, prefix_key)
            .await
            .map_err(|_| anyhow!("registration does not hold the exact 138 operation prefix key"))?;

        let identity = draft.plan.identity().clone();
        let pool = db.pool.clone();
        let (cancel_pid_tx, cancel_pid_rx) = tokio::sync::oneshot::channel::<i32>();
        let cancellation = tokio::spawn(async move {
            let mut client = pool.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            let _ = cancel_pid_tx.send(pid);
            let tx = client.transaction().await?;
            let receipt = PgRefStore.cancel(&tx, &identity, deadline()).await?;
            tx.commit().await?;
            Ok::<_, anyhow::Error>((pid, receipt))
        });
        let cancel_pid = cancel_pid_rx.await.map_err(|_| anyhow!("cancel backend never reported its pid"))?;
        ensure!(reg_pid != cancel_pid, "registration and cancel used the same PG backend");
        wait_for_key_wait(&db.pool, cancel_pid, prefix_key)
            .await
            .map_err(|_| anyhow!("cancel never waited on the exact 138 operation prefix key"))?;
        ensure!(
            advisory_key_state(&db.pool, cancel_pid, prefix_key, false).await?,
            "cancel is not observably waiting on the exact 138 operation prefix key"
        );
        ensure!(!cancellation.is_finished(), "cancel finished while registration still held the 138 prefix");

        barrier.release().await?;
        let (_, registration) = registration.await.map_err(|_| anyhow!("registration task failed"))??;
        let (_, cancel) = cancellation.await.map_err(|_| anyhow!("cancel task failed"))??;
        ensure!(!registration.replayed, "the barrier registration replayed an old ACK");
        ensure!(cancel.tombstone_created, "cancel recorded no durable tombstone");
        ensure!(
            operation_state(&db.pool, repo, draft.plan.identity().operation_id()).await? == OperationState::Cancelled,
            "the final operation state is not cancelled"
        );
        ensure!(
            gate_state(&db.pool, repo).await? == (gate.revision(), "metadata_only".to_owned()),
            "registration/cancel moved the gate"
        );
        ensure!(ref_oid(&db.pool, repo, "refs/heads/main").await?.is_none(), "a cancelled registration wrote a ref");
        ensure!(
            row_counts(&db.pool, repo).await? == (1, 2, 0, 0, 0),
            "the cancelled registration wrote membership/terminal/event rows"
        );
        ensure!(active_holds(&db.pool, repo).await? == 2, "the cancelled registration did not retain its holds");
        let (usage, tenant_usage) = usage_both(&db.pool, repo, tenant).await?;
        ensure!(
            usage[0] == 1 && usage[1] == 2 && usage[2] == 0 && usage[4] == 2,
            "the cancelled registration charged the wrong retained counters"
        );
        ensure!(tenant_usage == usage, "tenant counters differ from the repository counters");

        // A real proof over the cancelled closure still cannot commit.
        let mut client = db.pool.get().await?;
        let context = PgPackCommit.capture_context(&mut client, &draft.plan, deadline()).await?;
        drop(client);
        let proof = prove(&store, &git, &draft.plan, &context).await?;
        let refused = commit(&db, &draft, &proof).await.expect_err("a cancelled pending operation committed");
        ensure!(
            refused.downcast_ref::<PackCommitError>().map(|error| rejected_as(error, "cancelled")).unwrap_or(false),
            "unexpected refused-commit error: {refused}"
        );
        ensure!(row_counts(&db.pool, repo).await? == (1, 2, 0, 0, 0), "the refused commit wrote rows");

        // Reverse phase: cancel after the publication but before registration
        // denies the later registration and leaves no A4 publication rows.
        let (tenant, repo) = db.business(GitObjectFormat::Sha1).await?;
        let gate = db.gate(repo, tenant, GitObjectFormat::Sha1).await?;
        let fixture = GitRepo::new(git.clone(), GitObjectFormat::Sha1).await?;
        let commit_oid = fixture.build_commit("a.txt", b"reverse fixture\n", "fixture reverse").await?;
        fixture.update_ref("refs/heads/main", &commit_oid).await?;
        let files = fixture.pack_all("reverse").await?;
        let reverse_draft = self::draft(
            &db,
            repo,
            tenant,
            1,
            &gate,
            vec![main_update(GitObjectFormat::Sha1, &commit_oid)?],
            std::slice::from_ref(&files),
        )
        .await?;
        let publication = publish(&db, &store, &reverse_draft.plan, &files).await?;
        let mut canceller = db.pool.get().await?;
        let tx = canceller.transaction().await?;
        let cancel = PgRefStore.cancel(&tx, reverse_draft.plan.identity(), deadline()).await?;
        tx.commit().await?;
        drop(canceller);
        ensure!(
            cancel.record.as_ref().map(|record| record.state()) == Some(OperationState::Cancelled),
            "cancel-after-pending did not cancel the pending row"
        );
        let mut registrar = db.pool.get().await?;
        let refused =
            register_on(&mut registrar, &reverse_draft.plan, planned_pack_id(&reverse_draft.plan)?, &publication).await;
        drop(registrar);
        let error = refused.err().ok_or_else(|| anyhow!("registration after a durable cancel was accepted"))?;
        ensure!(
            matches!(error.downcast_ref::<PackCommitError>(), Some(error) if rejected_as(error, "cancelled")),
            "unexpected registration-after-cancel error: {error}"
        );
        ensure!(
            row_counts(&db.pool, repo).await? == (0, 0, 0, 0, 0),
            "registration after a durable cancel wrote A4 rows"
        );
        ensure!(
            usage_both(&db.pool, repo, tenant).await? == ([0; 5], [0; 5]),
            "registration after a durable cancel charged retained counters"
        );
        ensure!(ref_oid(&db.pool, repo, "refs/heads/main").await?.is_none(), "registration after cancel wrote a ref");
        ensure!(active_holds(&db.pool, repo).await? == 2, "the cancelled publication lost its permanent holds");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
