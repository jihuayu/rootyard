//! One real A3/A4/A5 seeded repository plus the authorized pipeline stages.
//!
//! The seed is `verify_new()` from the shared roots fixture: exactly one real
//! protected upload, real A4 registration, real native closure proof and a real
//! verified commit. Its pack contains the commit, tree and blob object that
//! every later decision plan references. Because those objects are already
//! registered, later authorized plans use `packs = []` (ref-only) against the
//! same durable membership: a real native fact/closure pass without inventing
//! new upload bytes.
use super::auth::{self, Actor};
use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::Pool;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::core::CommitMode;
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, ProtocolRepoRealm, RealmExpectation};
use rootyard::ref_store::core::pack_commit::{
    AuthorizedCommitMode, AuthorizedCommitReceipt, AuthorizedSelection, PackCommitExpectation, PackCommitPlan,
    PackCommitReceipt, PackCommitScope, PackMembershipEntry, PackPendingToken, PgAuthorizedCommit, PgPackCommit,
    PrepareOutcome, PreparedPublication, VerifiedAuthorizedPublication,
};
use rootyard::ref_store::{
    CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationIdentity, RefName, RefPrecondition,
    RefTarget, RefUpdate, RequestDigest,
};
use std::path::PathBuf;
use uuid::Uuid;

use crate::retention_roots_support::db::{Db, deadline, gate_version};
use crate::retention_roots_support::git::{GitRepo, git_binary};
use crate::retention_roots_support::pack::{Verified, verify_new};

pub fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(
        profile.provider() == rootyard::blob_store::BlobProvider::S3,
        "ROOTYARD_BLOB_SERVICE must be s3 for this suite"
    );
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

/// A second, genuinely real Blob store pointing at the same bucket under an
/// absent root. Reading the registered pack through it must fail natively
/// (missing shared bytes), which is the corruption/global-integrity case.
pub fn absent_store() -> Result<BlobStore> {
    const KEY: &str = "ROOTYARD_BLOB_ROOT";
    let original = std::env::var(KEY).ok();
    let base = original.clone().unwrap_or_else(|| "state144".to_owned());
    // The suite runs with `--test-threads=1`; this window is synchronous and is
    // restored before any await, so no other test observes it.
    unsafe { std::env::set_var(KEY, format!("{base}/absent-{}", Uuid::new_v4().simple())) };
    let opened = BlobProfile::from_env()
        .map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))
        .and_then(|profile| BlobStore::open(profile).map_err(|error| anyhow!("absent Blob store rejected: {error}")));
    match original {
        Some(value) => unsafe { std::env::set_var(KEY, value) },
        None => unsafe { std::env::remove_var(KEY) },
    }
    opened
}

pub struct World {
    pub db: Db,
    pub store: BlobStore,
    pub git: PathBuf,
    pub verified: Verified,
    pub adapter: PgAuthorizedCommit,
    pub actor: Actor,
}

impl World {
    pub async fn new(format: GitObjectFormat) -> Result<Self> {
        let db = Db::setup().await?;
        let store = open_store()?;
        let git = git_binary()?;
        let verified = verify_new(&db, &store, &git, format).await?;
        let actor = auth::owner(&db.pool, verified.tenant).await?;
        let adapter = PgAuthorizedCommit::new(store.clone(), git.clone())
            .map_err(|error| anyhow!("authorized adapter constructor refused: {error:?}"))?;
        Ok(Self { db, store, git, verified, adapter, actor })
    }

    pub async fn finish(self, outcome: Result<()>) -> Result<()> {
        self.db.finish(outcome).await
    }

    pub async fn refresh_gate(&mut self) -> Result<CoreGateVersion> {
        self.verified.gate = gate_version(&self.db.pool, self.verified.repo, self.verified.tenant).await?;
        Ok(self.verified.gate.clone())
    }

    pub async fn provision(&self) -> Result<ProtocolRepoRealm> {
        let gate = &self.verified.gate;
        let expectation = RealmExpectation::new(
            self.verified.repo,
            self.verified.tenant,
            gate.object_format(),
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
        )?;
        let mut client = self.db.pool.get().await?;
        PgDecisionProtocol
            .provision(&mut client, &expectation, deadline())
            .await
            .map_err(|error| anyhow!("per-repository decision protocol provisioning refused: {error}"))
    }

    pub async fn plan(
        &self,
        refs: Vec<RefUpdate>,
        sequence: i64,
        mode: CommitMode,
        head: HeadUpdate,
    ) -> Result<(PackCommitPlan, PackPendingToken)> {
        self.plan_as(refs, sequence, mode, head, self.verified.tenant, "decision-subset").await
    }

    /// Same original plan, issued by the exact authenticated actor (the
    /// production facade requires `issuer_id == actor.id`), with its own lane.
    pub async fn plan_as(
        &self,
        refs: Vec<RefUpdate>,
        sequence: i64,
        mode: CommitMode,
        head: HeadUpdate,
        issuer_id: Uuid,
        lane: &str,
    ) -> Result<(PackCommitPlan, PackPendingToken)> {
        let producer = self.verified.tenant;
        self.plan_as_producer(refs, sequence, mode, head, issuer_id, lane, producer).await
    }

    /// Same original plan with the production producer semantics: the scope's
    /// `tenant_id` is the repository tenant, while `owner_id` is the independent
    /// publication producer (a real, maybe non-tenant, API user), and the issuer
    /// is the exact authenticated actor.
    #[allow(clippy::too_many_arguments)]
    pub async fn plan_as_producer(
        &self,
        refs: Vec<RefUpdate>,
        sequence: i64,
        mode: CommitMode,
        head: HeadUpdate,
        issuer_id: Uuid,
        lane: &str,
        producer: Uuid,
    ) -> Result<(PackCommitPlan, PackPendingToken)> {
        let gate = &self.verified.gate;
        let mut client = self.db.pool.get().await?;
        let baseline =
            PgPackCommit.capture_baseline(&mut client, self.verified.repo, self.verified.tenant, deadline()).await?;
        ensure!(
            baseline.gate().revision() == gate.revision() && baseline.gate().digest() == gate.digest(),
            "captured baseline differs from the seeded gate"
        );
        let old_memberships =
            baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?;
        let scope = PackCommitScope::new(
            self.verified.repo,
            self.verified.tenant,
            producer,
            gate.object_format(),
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
        )?;
        let identity = OperationIdentity::new(
            self.verified.repo,
            issuer_id,
            IssuerLane::new(lane)?,
            sequence,
            Uuid::new_v4(),
            RequestDigest::from_bytes([0; 32]),
        )?;
        let expectation = PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?;
        let plan = PackCommitPlan::new_with_mode(
            scope,
            identity,
            expectation,
            head,
            refs,
            baseline.membership_digest(),
            old_memberships,
            Vec::new(),
            mode,
        )?;
        let token = PgPackCommit.begin_pending(&mut client, &plan, deadline()).await?;
        Ok((plan, token))
    }

    pub async fn plan_with_head(
        &self,
        refs: Vec<RefUpdate>,
        sequence: i64,
        head: HeadUpdate,
    ) -> Result<PackCommitPlan> {
        Ok(self.plan(refs, sequence, CommitMode::AcceptedSubset, head).await?.0)
    }

    pub async fn plan_with_head_as(
        &self,
        refs: Vec<RefUpdate>,
        sequence: i64,
        head: HeadUpdate,
        issuer_id: Uuid,
        lane: &str,
    ) -> Result<PackCommitPlan> {
        Ok(self.plan_as(refs, sequence, CommitMode::AcceptedSubset, head, issuer_id, lane).await?.0)
    }

    /// `plan_with_head_as` with a non-tenant publication producer.
    pub async fn plan_with_head_as_producer(
        &self,
        refs: Vec<RefUpdate>,
        sequence: i64,
        head: HeadUpdate,
        issuer_id: Uuid,
        lane: &str,
        producer: Uuid,
    ) -> Result<PackCommitPlan> {
        Ok(self.plan_as_producer(refs, sequence, CommitMode::AcceptedSubset, head, issuer_id, lane, producer).await?.0)
    }

    /// Drive the full staged facade and return the exact-op receipt. A final
    /// authorization/policy drift is an `Ok` receipt with a rejected terminal;
    /// native/whole-operation failures stay `Err`.
    pub async fn commit_receipt(&self, plan: PackCommitPlan) -> Result<AuthorizedCommitReceipt> {
        let prepared = prepare(&self.adapter, &self.db.pool, plan).await?;
        let selection = select(&self.adapter, &self.db.pool, prepared, &self.actor).await?;
        let verified = verify(&self.adapter, selection).await?;
        commit_receipt(&self.adapter, &self.db.pool, &verified).await
    }

    /// Expected-success commit: the durable terminal must be committed.
    pub async fn commit(&self, plan: PackCommitPlan) -> Result<()> {
        let receipt = self.commit_receipt(plan).await?;
        ensure!(receipt.is_committed(), "authorized commit returned a non-committed terminal");
        Ok(())
    }
}

pub async fn prepare(adapter: &PgAuthorizedCommit, pool: &Pool, plan: PackCommitPlan) -> Result<PreparedPublication> {
    match adapter.prepare(pool, plan, deadline()).await.map_err(|error| anyhow!("prepare refused: {error:?}"))? {
        PrepareOutcome::Prepared(prepared) => Ok(*prepared),
        PrepareOutcome::Replayed(_) => Err(anyhow!("prepare replayed an existing terminal instead of staging")),
    }
}

pub async fn prepare_replay(
    adapter: &PgAuthorizedCommit,
    pool: &Pool,
    plan: PackCommitPlan,
) -> Result<PackCommitReceipt> {
    match adapter.prepare(pool, plan, deadline()).await.map_err(|error| anyhow!("replay prepare refused: {error:?}"))? {
        PrepareOutcome::Prepared(_) => Err(anyhow!("prepare staged a pending operation instead of replaying")),
        PrepareOutcome::Replayed(receipt) => Ok(*receipt),
    }
}

pub async fn select(
    adapter: &PgAuthorizedCommit,
    pool: &Pool,
    prepared: PreparedPublication,
    actor: &Actor,
) -> Result<AuthorizedSelection> {
    select_as(adapter, pool, prepared, &actor.identity).await
}

/// `select` as an exact authenticated identity (the production facade itself refuses any
/// issuer/actor mismatch; this exists to exercise that refusal with a real second session).
pub async fn select_as(
    adapter: &PgAuthorizedCommit,
    pool: &Pool,
    prepared: PreparedPublication,
    actor: &rootyard::db::Identity,
) -> Result<AuthorizedSelection> {
    let mode = match prepared.commit_mode() {
        CommitMode::Atomic => AuthorizedCommitMode::Atomic,
        CommitMode::AcceptedSubset => AuthorizedCommitMode::AcceptedSubset,
    };
    adapter.select(pool, prepared, actor, mode, deadline()).await.map_err(|error| anyhow!("select refused: {error:?}"))
}

pub async fn verify(
    adapter: &PgAuthorizedCommit,
    selection: AuthorizedSelection,
) -> Result<VerifiedAuthorizedPublication> {
    adapter.verify(selection, deadline()).await.map_err(|error| anyhow!("verify refused: {error:?}"))
}

/// Exact-op commit stage. A final authorization/policy drift is a durable
/// `Ok` receipt whose terminal is `Rejected`; whole-operation/native failures
/// stay `Err`. Callers must never treat `Err` as a vacuous pass.
pub async fn commit_receipt(
    adapter: &PgAuthorizedCommit,
    pool: &Pool,
    verified: &VerifiedAuthorizedPublication,
) -> Result<AuthorizedCommitReceipt> {
    adapter.commit(pool, verified, deadline()).await.map_err(|error| anyhow!("commit refused: {error:?}"))
}

/// Expected-success commit: the durable terminal must be committed.
pub async fn commit(adapter: &PgAuthorizedCommit, pool: &Pool, verified: &VerifiedAuthorizedPublication) -> Result<()> {
    let receipt = commit_receipt(adapter, pool, verified).await?;
    ensure!(receipt.is_committed(), "authorized commit returned a non-committed terminal");
    Ok(())
}

pub async fn cancel(
    adapter: &PgAuthorizedCommit,
    pool: &Pool,
    actor: &Actor,
    identity: &OperationIdentity,
    reason: &str,
) -> Result<()> {
    adapter
        .cancel(pool, &actor.identity, identity, reason, deadline())
        .await
        .map_err(|error| anyhow!("cancel refused: {error:?}"))?;
    Ok(())
}

pub fn update(format: GitObjectFormat, name: &str, old: Option<&str>, new: Option<&str>) -> Result<RefUpdate> {
    let name = RefName::new(name)?;
    let precondition = match old {
        Some(value) => RefPrecondition::Present(GitOid::parse(format, value)?),
        None => RefPrecondition::Absent,
    };
    let target = match new {
        Some(value) => RefTarget::Oid(GitOid::parse(format, value)?),
        None => RefTarget::Delete,
    };
    Ok(RefUpdate::new(name, precondition, target))
}

pub fn main_update(format: GitObjectFormat, old: Option<&str>, new: Option<&str>) -> Result<RefUpdate> {
    update(format, "refs/heads/main", old, new)
}

pub fn missing_oid(format: GitObjectFormat) -> String {
    let width = if format == GitObjectFormat::Sha1 { 20 } else { 32 };
    hex::encode(vec![0xab; width])
}

pub async fn object_ids(fixture: &GitRepo, commit_oid: &str) -> Result<(String, String)> {
    let tree_spec = format!("{commit_oid}^{{tree}}");
    let tree = GitRepo::text(&fixture.run(&["rev-parse", tree_spec.as_str()], None).await?)?;
    let blob_spec = format!("{commit_oid}:file.txt");
    let blob = GitRepo::text(&fixture.run(&["rev-parse", blob_spec.as_str()], None).await?)?;
    Ok((tree, blob))
}

pub async fn wait_db_clock_millis(pool: &Pool, target: i64) -> Result<()> {
    let started = std::time::Instant::now();
    loop {
        let now: i64 = pool
            .get()
            .await?
            .query_one("SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint", &[])
            .await?
            .get(0);
        if now >= target {
            return Ok(());
        }
        if started.elapsed() > std::time::Duration::from_secs(10) {
            return Err(anyhow!("database clock did not pass the token expiry"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
