//! Test-only bounded phase diagnostics for the live PostgreSQL 17 / Garage CloneKit case.
//!
//! The live case keeps its exact name and `#[ignore]` in `tests/ci_clonekit.rs`; its
//! unchanged fixture/proof body lives here so its finite phases can be marked without
//! growing that source past its line contract. A failure or panic emits exactly one fixed
//! marker with a closed phase/class and a source location, never an error body,
//! environment value or command output. Successful body plus cleanup writes one fixed
//! completion marker to `ROOTYARD_LIVE_COMPLETION_FILE`; the collector requires exactly
//! one marker line for a green live step. ASSERT is reserved for explicitly observed
//! predicate failures; external or unknown errors are OTHER unless they carry an
//! existing typed CloneKit class.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
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
}

#[derive(Clone, Copy)]
pub(crate) struct Frame {
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

    /// Preserve the first returned error's typed class at the last marked operation.
    ///
    /// Only an existing typed `CloneKitError` maps to a non-OTHER class here. Explicit
    /// fixture predicates call [`Self::fail_assert`] at their own source instead.
    pub(crate) fn observe_final(&mut self, err: &anyhow::Error) {
        let class = err.downcast_ref::<CloneKitError>().map(Class::from_ck).unwrap_or(Class::Other);
        self.record(self.phase, class, self.file, self.line);
    }

    /// Record an explicit predicate failure at the failing predicate site.
    pub(crate) fn fail_assert(&mut self, file: &'static str, line: u32) {
        self.record(self.phase, Class::Assert, file, line);
    }

    #[cfg(test)]
    pub(crate) fn recorded_frame(&self) -> Option<Frame> {
        self.first
    }

    #[cfg(test)]
    pub(crate) fn disarm_for_test(&mut self) {
        self.armed = false;
    }

    /// Write exactly one successful exact-case completion after body and cleanup finish.
    ///
    /// The marker is a file so it survives libtest's capture of passing-test stderr.
    /// The post-pipeline collector requires the file to contain exactly one fixed line.
    pub(crate) fn complete(&mut self) {
        if !self.armed || self.first.is_some() {
            return;
        }
        self.armed = false;
        let path = std::env::var(LIVE_COMPLETION_ENV).unwrap_or_else(|_| LIVE_COMPLETION_DEFAULT.to_owned());
        if let Some(parent) = Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(file, "{LIVE_COMPLETION_MARKER}");
        }
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
        let body = run_body(&mut diag, &pool).await;
        if let Err(err) = &body {
            // Keep the real body failure as primary before cleanup can replace the returned error.
            diag.observe_final(err);
        }
        diag.mark(LivePhase::Teardown, file!(), line!());
        pool.close();
        drop(pool);
        let cleanup: Result<()> = async {
            admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
            admin.close();
            Ok(())
        }
        .await;
        // Preserve the original return semantics: cleanup failure wins; otherwise return the body.
        match cleanup {
            Ok(()) => body,
            Err(err) => Err(err),
        }
    }
    .await;
    match &result {
        Ok(()) => diag.complete(),
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
    let begun = PgRefStore.begin(&tx, &op, pg_dl).await?;
    if begun.record.state() != OperationState::Pending {
        diag.fail_assert(file!(), line!());
        return Err(anyhow::Error::msg(
            "Condition failed: `PgRefStore.begin(&tx, &op, pg_dl).await?.record.state() == OperationState::Pending`",
        ));
    }
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
    if receipts.len() != 2 || built.manifest.pack.as_ref().and_then(|p| p.blob_locator.as_ref()).is_none() {
        diag.fail_assert(file!(), line!());
        return Err(anyhow::Error::msg(
            "Condition failed: `receipts.len() == 2 && built.manifest.pack.as_ref().and_then(|p| p.blob_locator.as_ref()).is_some()`",
        ));
    }
    diag.mark(LivePhase::Readiness, file!(), line!());
    // Publish from the unserved core lane, then become ready for the checkout oracle.
    let updated = pool.get().await?.execute("UPDATE repositories SET state='ready' WHERE id=$1", &[&ids.1]).await?;
    if updated != 1 {
        diag.fail_assert(file!(), line!());
        return Err(anyhow::Error::msg(format!("fixture readiness transition updated {updated} rows")));
    }
    diag.mark(LivePhase::JobInsert, file!(), line!());
    let c2 = add_commit(&repo, "next.txt", b"delta2\n", "c2")?;
    let (signed, ctx) = make_grant(ids, Sha1, &c2, None, now)?;
    let plan = serde_json::json!({"version":1,"job_id":ctx.job_id,"owner_id":ids.0,"repository_id":ids.1,"storage_generation":1,"object_format":"sha1","target_oid":c2,"source_receipt_sha256":"a".repeat(64),"mirror_audience":ctx.audience,"expires_unix":signed.claims.not_after_unix,"dependencies":{"version":1,"history":"full","tags":[],"lfs":[],"submodules":[]}});
    pool.get().await?.execute("INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,plan,issuer_token_id,credential_digest,expires_unix) VALUES($1,$2,$3,$4,$5,$6,$7)", &[&ids.1, &ctx.job_id, &ids.0, &plan, &token_id, &credential_digest, &signed.claims.not_after_unix]).await?;
    diag.mark(LivePhase::Checkout, file!(), line!());
    let pg_auth: Arc<dyn CloneKitAuthorityOracle> = Arc::new(PgCheckoutAuthorityOracle::new(Pool::clone(pool)));
    let co = Co { manifest: Some(&built.manifest), blob: Some(&blob), ..Co::new(&vr) };
    let outcome = co.run(&signed, &ctx, &pg_auth, pol(true, true), repo.to_str().expect("utf8"), None).await?;
    if outcome.telemetry.strategy != (CheckoutStrategy::CloneKitIncremental { kit_generation: 1, base_commit_oid: c1 })
    {
        diag.fail_assert(file!(), line!());
        return Err(anyhow::Error::msg(
            "Condition failed: `outcome.telemetry.strategy == CheckoutStrategy::CloneKitIncremental { kit_generation: 1, base_commit_oid: c1 }`",
        ));
    }
    diag.mark(LivePhase::ActiveHolds, file!(), line!());
    let active_holds = pool
        .get()
        .await?
        .query_one("SELECT count(*) FROM artifact_holds WHERE state = 'active'", &[])
        .await?
        .get::<_, i64>(0);
    if active_holds != 2 {
        diag.fail_assert(file!(), line!());
        return Err(anyhow::Error::msg(
            "Condition failed: `pool.get().await?.query_one(\"SELECT count(*) FROM artifact_holds WHERE state = 'active'\", &[]).await?.get::<_, i64>(0) == 2`",
        ));
    }
    diag.mark(LivePhase::Revocation, file!(), line!());
    pool.get()
        .await?
        .execute(
            "UPDATE ci_checkout_jobs SET revoked = true WHERE repository_id=$1 AND job_id=$2",
            &[&ids.1, &ctx.job_id],
        )
        .await?;
    diag.mark(LivePhase::DeniedReplay, file!(), line!());
    let denied = co.run(&signed, &ctx, &pg_auth, pol(false, true), repo.to_str().expect("utf8"), None).await;
    if !matches!(denied, Err(CloneKitError::GrantRevoked(_))) {
        diag.fail_assert(file!(), line!());
        return Err(anyhow::Error::msg(
            "Condition failed: `matches!(co.run(&signed, &ctx, &pg_auth, pol(false, true), repo.to_str().expect(\"utf8\"), None).await, Err(CloneKitError::GrantRevoked(_)))`",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_for(phase: LivePhase, err: &anyhow::Error) -> Frame {
        let mut recorder = LiveRecorder::new(file!(), line!());
        recorder.mark(phase, file!(), line!());
        recorder.observe_final(err);
        let frame = recorder.recorded_frame().expect("recorded frame");
        recorder.disarm_for_test();
        frame
    }

    #[test]
    fn unknown_errors_are_other_without_phase_inference() {
        // Checkout and Readiness were previously classified by the phase heuristic.
        let checkout = frame_for(LivePhase::Checkout, &anyhow::anyhow!("postgres unavailable"));
        assert_eq!(checkout.class, Class::Other);
        let readiness = frame_for(LivePhase::Readiness, &anyhow::anyhow!("refstore unavailable"));
        assert_eq!(readiness.class, Class::Other);
    }

    #[test]
    fn typed_clonekit_classes_remain_exact() {
        let database =
            frame_for(LivePhase::Publish, &anyhow::Error::new(CloneKitError::DatabaseFailed("synthetic".to_owned())));
        assert_eq!(database.class, Class::DatabaseFailed);
        let revoked = frame_for(LivePhase::DeniedReplay, &anyhow::Error::new(CloneKitError::GrantRevoked("synthetic")));
        assert_eq!(revoked.class, Class::GrantRevoked);
        let git = frame_for(LivePhase::Checkout, &anyhow::Error::new(CloneKitError::GitFailed("synthetic".to_owned())));
        assert_eq!(git.class, Class::GitFailed);
    }

    #[test]
    fn explicit_predicate_failure_is_assert_and_keeps_first_error() {
        let mut recorder = LiveRecorder::new(file!(), line!());
        recorder.mark(LivePhase::Checkout, file!(), line!());
        let predicate_line = line!();
        recorder.fail_assert(file!(), predicate_line);
        recorder.observe_final(&anyhow::anyhow!("later body error"));
        let frame = recorder.recorded_frame().expect("recorded frame");
        assert_eq!(frame.phase, LivePhase::Checkout);
        assert_eq!(frame.class, Class::Assert);
        assert_eq!(frame.line, predicate_line);
        recorder.disarm_for_test();
    }

    #[test]
    fn first_body_error_survives_later_teardown_error() {
        let mut recorder = LiveRecorder::new(file!(), line!());
        recorder.mark(LivePhase::Checkout, file!(), line!());
        recorder.observe_final(&anyhow::anyhow!("body failure"));
        recorder.mark(LivePhase::Teardown, file!(), line!());
        recorder.observe_final(&anyhow::anyhow!("cleanup failure"));
        let frame = recorder.recorded_frame().expect("recorded frame");
        assert_eq!(frame.phase, LivePhase::Checkout);
        assert_eq!(frame.class, Class::Other);
        recorder.disarm_for_test();
    }
}
