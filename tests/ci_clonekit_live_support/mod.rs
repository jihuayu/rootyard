//! Test-only bounded phase diagnostics for the live PostgreSQL 17 / Garage CloneKit case.
//!
//! The live case keeps its exact name and `#[ignore]` in `tests/ci_clonekit.rs`; its
//! unchanged fixture/proof body lives here so its finite phases can be marked without
//! growing that source past its line contract. A failure or panic emits exactly one fixed
//! marker with a closed phase/class and a source location, never an error body,
//! environment value or command output.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::{config::BlobProfile, opendal::BlobStore};
use rootyard::ci_checkouts::clonekit::{
    BlobHoldPublishContext, CheckoutStrategy, CloneKitAuthorityOracle, CloneKitError, CloneKitObjectFormat::Sha1,
    PgCheckoutAuthorityOracle, publish_clonekit_to_blob_store,
};
use rootyard::db;
use rootyard::ref_store::{
    CoreGateInit, GitObjectFormat, IssuerLane, OperationIdentity, OperationState, PgRefStore, PgRefStoreCore, RefName,
    RequestDigest,
    artifact_hold::{ArtifactHoldPurpose, HoldScope},
};
use tempfile::TempDir;
use uuid::Uuid;

use super::ck_diag::Class;
use super::{Co, add_commit, build_kit_with_clock, init_repo, make_grant, payload_bytes, pol, private_vr};

/// Closed phases for the live case, in execution order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LivePhase {
    Setup,
    Schema,
    Migrate,
    BlobOpen,
    Seed,
    CoreInit,
    OperationRegister,
    BuildKit,
    Publish,
    Readiness,
    JobInsert,
    Checkout,
    ActiveHolds,
    Revocation,
    DeniedReplay,
    Teardown,
}

impl LivePhase {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "SETUP",
            Self::Schema => "SCHEMA",
            Self::Migrate => "MIGRATE",
            Self::BlobOpen => "BLOB_OPEN",
            Self::Seed => "SEED",
            Self::CoreInit => "CORE_INIT",
            Self::OperationRegister => "OPERATION_REGISTER",
            Self::BuildKit => "BUILD_KIT",
            Self::Publish => "PUBLISH",
            Self::Readiness => "READINESS",
            Self::JobInsert => "JOB_INSERT",
            Self::Checkout => "CHECKOUT",
            Self::ActiveHolds => "ACTIVE_HOLDS",
            Self::Revocation => "REVOCATION",
            Self::DeniedReplay => "DENIED_REPLAY",
            Self::Teardown => "TEARDOWN",
        }
    }

    const fn is_assert_phase(self) -> bool {
        matches!(
            self,
            Self::OperationRegister
                | Self::Publish
                | Self::Readiness
                | Self::Checkout
                | Self::ActiveHolds
                | Self::DeniedReplay
        )
    }
}

#[derive(Clone, Copy)]
struct Frame {
    phase: LivePhase,
    class: Class,
    file: &'static str,
    line: u32,
}

/// One armed recorder: the first observed failure/panic wins, and only that frame is emitted.
pub(crate) struct LiveRecorder {
    armed: bool,
    phase: LivePhase,
    file: &'static str,
    line: u32,
    first: Option<Frame>,
}

impl LiveRecorder {
    pub(crate) fn new(file: &'static str, line: u32) -> Self {
        Self { armed: true, phase: LivePhase::Setup, file, line, first: None }
    }

    pub(crate) fn mark(&mut self, phase: LivePhase, file: &'static str, line: u32) {
        self.phase = phase;
        self.file = file;
        self.line = line;
    }

    fn record(&mut self, phase: LivePhase, class: Class, file: &'static str, line: u32) {
        if self.first.is_none() {
            self.first = Some(Frame { phase, class, file, line });
        }
    }

    /// Preserve a returned error's exact typed class at the last marked operation.
    pub(crate) fn observe_final(&mut self, err: &anyhow::Error) {
        let class = err
            .downcast_ref::<CloneKitError>()
            .map(Class::from_ck)
            .unwrap_or_else(|| if self.phase.is_assert_phase() { Class::Assert } else { Class::Other });
        self.record(self.phase, class, self.file, self.line);
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for LiveRecorder {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let frame = self.first.unwrap_or(Frame {
            phase: self.phase,
            class: if std::thread::panicking() { Class::Panic } else { Class::Other },
            file: self.file,
            line: self.line,
        });
        // Best-effort fixed marker. A diagnostic I/O failure must not replace the original
        // test error or panic, and no raw error text is ever written.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "ISSUE182_LIVE_PG_GARAGE phase={} class={} source={}:{}",
            frame.phase.as_str(),
            frame.class.as_str(),
            frame.file,
            frame.line
        );
    }
}

/// Exact live case body. The wrapper in `tests/ci_clonekit.rs` keeps the original test name,
/// ignore attribute, inventory and return type; this function changes no fixture or proof.
pub(crate) async fn run() -> Result<()> {
    let mut diag = LiveRecorder::new(file!(), line!());
    let result: Result<()> = async {
        diag.mark(LivePhase::Setup, file!(), line!());
        let url = std::env::var("ROOTYARD_TEST_DATABASE_URL").expect("ROOTYARD_TEST_DATABASE_URL");
        let (admin, schema) = (db::pool(&url)?, format!("clonekit_test_{}", Uuid::new_v4().simple()));
        diag.mark(LivePhase::Schema, file!(), line!());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let mut cfg: tokio_postgres::Config = url.parse()?;
        cfg.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000"));
        diag.mark(LivePhase::Setup, file!(), line!());
        let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(8)
            .build()?;
        let res = run_body(&mut diag, &pool).await;
        if res.is_ok() {
            diag.mark(LivePhase::Teardown, file!(), line!());
        }
        pool.close();
        drop(pool);
        admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
        admin.close();
        res
    }
    .await;
    match &result {
        Ok(()) => diag.disarm(),
        Err(err) => diag.observe_final(err),
    }
    result
}

async fn run_body(diag: &mut LiveRecorder, pool: &Pool) -> Result<()> {
    diag.mark(LivePhase::Migrate, file!(), line!());
    db::migrate(pool).await?;
    diag.mark(LivePhase::BlobOpen, file!(), line!());
    let (blob, td) = (BlobStore::open(BlobProfile::from_env()?)?, TempDir::new()?);
    diag.mark(LivePhase::Seed, file!(), line!());
    let (vr, repo) = (private_vr(&td)?, init_repo(td.path(), "pg_repo", Sha1)?);
    let c1 = add_commit(&repo, "big.bin", &payload_bytes(9, 128 * 1024), "c1")?;
    let (ids, token_id) = ((Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()), Uuid::new_v4());
    let client = pool.get().await?;
    let (token_digest, credential_digest): (&[u8], &[u8]) = (&[7u8; 32], &[9u8; 32]);
    client
        .execute(
            "INSERT INTO users(id,username) VALUES($1,$2)",
            &[&ids.0, &format!("ck_{}", &ids.0.simple().to_string()[..8])],
        )
        .await?;
    client
        .execute("INSERT INTO tokens(id,user_id,digest) VALUES($1,$2,$3)", &[&token_id, &ids.0, &token_digest])
        .await?;
    client.execute("INSERT INTO repositories(id,owner_id,name,state,object_format,storage_generation) VALUES($1,$2,$3,'provisioning','sha1',1)", &[&ids.1, &ids.0, &"ckrepo"]).await?;
    drop(client);
    diag.mark(LivePhase::CoreInit, file!(), line!());
    let pg_dl = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut c = pool.get().await?;
    let gate = *PgRefStoreCore
        .initialize(
            &mut c,
            &CoreGateInit::new(ids.1, ids.0, GitObjectFormat::Sha1, ids.2, 1, 1, RefName::branch("refs/heads/main")?)?,
            pg_dl,
        )
        .await?
        .digest();
    diag.mark(LivePhase::OperationRegister, file!(), line!());
    let op = OperationIdentity::new(
        ids.1,
        ids.0,
        IssuerLane::new("ci-clonekit")?,
        1,
        Uuid::new_v4(),
        RequestDigest::from_bytes([1u8; 32]),
    )?;
    let tx = c.transaction().await?;
    ensure!(PgRefStore.begin(&tx, &op, pg_dl).await?.record.state() == OperationState::Pending);
    tx.commit().await?;
    drop(c);
    diag.mark(LivePhase::BuildKit, file!(), line!());
    let now: i64 =
        pool.get().await?.query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[]).await?.get(0);
    let mut built = build_kit_with_clock(ids, Sha1, 1, (&repo, &td), None, None, Some(now))?;
    diag.mark(LivePhase::Publish, file!(), line!());
    let receipts = publish_clonekit_to_blob_store(
        pool,
        &blob,
        &BlobHoldPublishContext {
            scope: HoldScope::new(
                ids.1,
                ids.0,
                ids.0,
                ArtifactHoldPurpose::RefPublication,
                GitObjectFormat::Sha1,
                ids.2,
                1,
                1,
            )?,
            operation: op,
            expected_gate_digest: gate,
            authority_id: ids.1,
            authority_generation: 1,
        },
        &mut built,
        None,
    )
    .await?;
    ensure!(receipts.len() == 2 && built.manifest.pack.as_ref().and_then(|p| p.blob_locator.as_ref()).is_some());
    diag.mark(LivePhase::Readiness, file!(), line!());
    // Publish from the unserved core lane, then become ready for the checkout oracle.
    let updated = pool.get().await?.execute("UPDATE repositories SET state='ready' WHERE id=$1", &[&ids.1]).await?;
    ensure!(updated == 1, "fixture readiness transition updated {updated} rows");
    diag.mark(LivePhase::JobInsert, file!(), line!());
    let c2 = add_commit(&repo, "next.txt", b"delta2\n", "c2")?;
    let (signed, ctx) = make_grant(ids, Sha1, &c2, None, now)?;
    let plan = serde_json::json!({"version":1,"job_id":ctx.job_id,"owner_id":ids.0,"repository_id":ids.1,"storage_generation":1,"object_format":"sha1","target_oid":c2,"source_receipt_sha256":"a".repeat(64),"mirror_audience":ctx.audience,"expires_unix":signed.claims.not_after_unix,"dependencies":{"version":1,"history":"full","tags":[],"lfs":[],"submodules":[]}});
    pool.get().await?.execute("INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,plan,issuer_token_id,credential_digest,expires_unix) VALUES($1,$2,$3,$4,$5,$6,$7)", &[&ids.1, &ctx.job_id, &ids.0, &plan, &token_id, &credential_digest, &signed.claims.not_after_unix]).await?;
    diag.mark(LivePhase::Checkout, file!(), line!());
    let pg_auth: Arc<dyn CloneKitAuthorityOracle> = Arc::new(PgCheckoutAuthorityOracle::new(Pool::clone(pool)));
    let co = Co { manifest: Some(&built.manifest), blob: Some(&blob), ..Co::new(&vr) };
    let outcome = co.run(&signed, &ctx, &pg_auth, pol(true, true), repo.to_str().expect("utf8"), None).await?;
    ensure!(
        outcome.telemetry.strategy == CheckoutStrategy::CloneKitIncremental { kit_generation: 1, base_commit_oid: c1 }
    );
    diag.mark(LivePhase::ActiveHolds, file!(), line!());
    ensure!(
        pool.get()
            .await?
            .query_one("SELECT count(*) FROM artifact_holds WHERE state = 'active'", &[])
            .await?
            .get::<_, i64>(0)
            == 2
    );
    diag.mark(LivePhase::Revocation, file!(), line!());
    pool.get()
        .await?
        .execute(
            "UPDATE ci_checkout_jobs SET revoked = true WHERE repository_id=$1 AND job_id=$2",
            &[&ids.1, &ctx.job_id],
        )
        .await?;
    diag.mark(LivePhase::DeniedReplay, file!(), line!());
    ensure!(matches!(
        co.run(&signed, &ctx, &pg_auth, pol(false, true), repo.to_str().expect("utf8"), None).await,
        Err(CloneKitError::GrantRevoked(_))
    ));
    Ok(())
}
