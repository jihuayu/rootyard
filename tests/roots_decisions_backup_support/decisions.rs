//! Real publication-decision pipeline for the backup drill.
//!
//! Only the actual public production facade is used; no decision row,
//! capability, ACK or proof is fabricated with SQL:
//!
//! * a real API token (`db::issue_token`) authenticated through
//!   `auth::authenticate`, so the trusted actor is a genuine `db::Identity`
//!   carrying the real PG `token_digest` (never printed);
//! * the real migration-144 protocol realm (`PgDecisionProtocol::provision`);
//! * a real pending migration-138/A4 operation (`pack::draft` ->
//!   `PgPackCommit::begin_pending`);
//! * the real staged authorized pipeline
//!   `PgAuthorizedCommit::{prepare,select,verify,commit}`, so one decision
//!   reaches `CONSUMED` and writes the selected refs plus the terminal/event;
//! * a real post-install cancel (`PgAuthorizedCommit::cancel`, OPEN ->
//!   CANCELLED) and a real cancel-before-install tombstone (`decision_id =
//!   NULL`, migration-138 tombstone + decision tombstone).
use anyhow::{Result, anyhow, ensure};
use axum::http::{HeaderMap, HeaderValue, header};
use deadpool_postgres::Pool;
use rootyard::auth;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db::{self, Identity};
use rootyard::ref_store::core::CommitMode;
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, ProtocolRepoRealm, RealmExpectation};
use rootyard::ref_store::core::pack_commit::{
    AuthorizedCommitMode, AuthorizedSelection, PackCommitExpectation, PackCommitPlan, PackCommitScope,
    PackMembershipEntry, PgAuthorizedCommit, PgPackCommit, PrepareOutcome, PreparedPublication,
};
use rootyard::ref_store::{CoreGateVersion, HeadUpdate, IssuerLane, OperationIdentity, RequestDigest};
use serde_json::{Value, json};
use std::path::Path;
use uuid::Uuid;

use super::db::{Db, deadline};
use super::pack;

pub struct Actor {
    pub identity: Identity,
    pub token_id: Uuid,
    pub user_id: Uuid,
}

pub fn adapter(store: &BlobStore, git: &Path) -> Result<PgAuthorizedCommit> {
    PgAuthorizedCommit::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("authorized pipeline rejected the Blob/Git configuration: {error}"))
}

/// Issue a real API token for the fixture owner and authenticate it through the
/// real auth path (never a hand-built `Identity`).
pub async fn owner_actor(pool: &Pool, owner: Uuid) -> Result<Actor> {
    let username = super::db::username(pool, owner).await?;
    let issued = db::issue_token(pool, &username, false, false)
        .await
        .map_err(|error| anyhow!("real api token issuance failed: {error}"))?;
    let token = issued
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("db::issue_token returned no token"))?
        .to_owned();
    let token_id = issued
        .get("token_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("db::issue_token returned no token id"))
        .and_then(|value| Uuid::parse_str(value).map_err(|error| anyhow!("token id is not a uuid: {error}")))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|error| anyhow!("bearer header rejected: {error}"))?,
    );
    let identity = auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("real api token authentication failed: {} {}", error.0, error.1))?;
    ensure!(
        identity.id == owner && identity.token_id == token_id && !identity.read_only,
        "authenticated fixture identity is not the writable owner token"
    );
    Ok(Actor { identity, token_id, user_id: owner })
}

/// Bind the migration-144 protocol realm to the current core gate. Idempotent
/// for an identical realm.
pub async fn provision(pool: &Pool, repo: Uuid, tenant: Uuid, gate: &CoreGateVersion) -> Result<ProtocolRepoRealm> {
    let expectation = RealmExpectation::new(
        repo,
        tenant,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let mut client = pool.get().await?;
    PgDecisionProtocol
        .provision(&mut client, &expectation, deadline())
        .await
        .map_err(|error| anyhow!("protocol provisioning refused: {error}"))
}

pub async fn read_protocol(pool: &Pool, repo: Uuid) -> Result<Option<ProtocolRepoRealm>> {
    let mut client = pool.get().await?;
    PgDecisionProtocol
        .read(&mut client, repo, deadline())
        .await
        .map_err(|error| anyhow!("protocol realm read failed: {error}"))
}

/// A real pending A4/138 operation. No pack is uploaded and no proof is minted:
/// the plan only moves commits that already live in the registered packs.
pub async fn pending_plan(
    db: &Db,
    verified: &pack::Verified,
    sequence: i64,
    refs: Vec<rootyard::ref_store::RefUpdate>,
    mode: CommitMode,
) -> Result<(PackCommitPlan, Uuid)> {
    let mut client = db.pool.get().await?;
    let baseline = PgPackCommit.capture_baseline(&mut client, verified.repo, verified.tenant, deadline()).await?;
    let gate = &verified.gate;
    ensure!(baseline.gate() == gate, "backup plan baseline changed");
    let memberships = baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?;
    let scope = PackCommitScope::new(
        verified.repo,
        verified.tenant,
        verified.tenant,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let identity = OperationIdentity::new(
        verified.repo,
        verified.tenant,
        IssuerLane::new("backup-decisions")?,
        sequence,
        Uuid::new_v4(),
        RequestDigest::from_bytes([0; 32]),
    )?;
    let expectation = PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?;
    let plan = PackCommitPlan::new_with_mode(
        scope,
        identity,
        expectation,
        HeadUpdate::Keep,
        refs,
        baseline.membership_digest(),
        memberships,
        Vec::new(),
        mode,
    )?;
    let operation_id = plan.identity().operation_id();
    let _pending = PgPackCommit.begin_pending(&mut client, &plan, deadline()).await?;
    Ok((plan, operation_id))
}

pub struct Prepared {
    pub operation_id: Uuid,
    pub gate_revision: i64,
    pub planned_refs: usize,
    pub mode: String,
    pub head_ref: String,
    pub publication: PreparedPublication,
}

/// Real stage 1 capture of the pending operation (one short read-only
/// transaction, no native/Blob work).
pub async fn prepare(adapter: &PgAuthorizedCommit, pool: &Pool, plan: PackCommitPlan) -> Result<Prepared> {
    let outcome = adapter
        .prepare(pool, plan, deadline())
        .await
        .map_err(|error| anyhow!("authorized prepare refused ({}): {error}", error.code()))?;
    match outcome {
        PrepareOutcome::Prepared(publication) => Ok(Prepared {
            operation_id: publication.operation_id(),
            gate_revision: publication.gate_revision(),
            planned_refs: publication.planned_refs(),
            mode: publication.mode().as_str().to_owned(),
            head_ref: publication.head_ref().to_owned(),
            publication: *publication,
        }),
        PrepareOutcome::Replayed(_) => {
            Err(anyhow!("authorized prepare replayed an existing terminal for a fresh drill operation"))
        }
    }
}

pub struct Installed {
    pub decision_id: Uuid,
    pub operation_id: Uuid,
    pub selection_digest: String,
    pub accepted_refs: usize,
    pub planned_refs: usize,
    pub all_rejected: bool,
    pub selection: AuthorizedSelection,
}

/// Real stage 2: native facts outside PostgreSQL, then the decision install
/// (all per-ref verdicts + retained quota) in one short transaction.
pub async fn select(
    adapter: &PgAuthorizedCommit,
    pool: &Pool,
    prepared: Prepared,
    actor: &Actor,
    mode: AuthorizedCommitMode,
) -> Result<Installed> {
    let selection = adapter
        .select(pool, prepared.publication, &actor.identity, mode, deadline())
        .await
        .map_err(|error| anyhow!("authorized selection refused ({}): {error}", error.code()))?;
    Ok(Installed {
        decision_id: selection.decision_id(),
        operation_id: selection.operation_id(),
        selection_digest: selection.selection_digest().as_hex(),
        accepted_refs: selection.accepted_refs(),
        planned_refs: selection.planned_refs(),
        all_rejected: selection.is_all_rejected(),
        selection,
    })
}

pub struct Consumed {
    pub operation_id: Uuid,
    pub decision_id: Uuid,
    pub selection_digest: String,
    pub record_state: String,
    pub revision: i64,
    pub head_ref: Option<String>,
    pub refs: usize,
    pub replayed: bool,
    pub committed: bool,
}

/// Real stages 3+4: final native closure verification, then one transaction
/// that consumes the decision and writes the selected refs/terminal/event.
pub async fn consume(adapter: &PgAuthorizedCommit, pool: &Pool, installed: Installed) -> Result<Consumed> {
    let operation_id = installed.operation_id;
    let decision_id = installed.decision_id;
    let selection_digest = installed.selection_digest.clone();
    let verified = adapter
        .verify(installed.selection, deadline())
        .await
        .map_err(|error| anyhow!("authorized closure verification refused ({}): {error}", error.code()))?;
    let receipt = adapter
        .commit(pool, &verified, deadline())
        .await
        .map_err(|error| anyhow!("authorized commit refused ({}): {error}", error.code()))?;
    let record_state = format!("{:?}", receipt.record.state()).to_ascii_lowercase();
    Ok(Consumed {
        operation_id,
        decision_id,
        selection_digest,
        record_state,
        revision: receipt.terminal.revision,
        head_ref: receipt.terminal.head_ref.clone(),
        refs: receipt.terminal.refs.len(),
        replayed: receipt.replayed,
        committed: receipt.is_committed(),
    })
}

pub struct Cancelled {
    pub operation_id: Uuid,
    pub decision_id: Option<Uuid>,
    pub outcome: String,
    pub cancelled: bool,
}

/// Real cancellation: the migration-138 tombstone and the decision tombstone
/// are written by the production path. Used both after an installed OPEN
/// decision (OPEN -> CANCELLED) and before any install (`decision_id = NULL`).
pub async fn cancel(
    adapter: &PgAuthorizedCommit,
    pool: &Pool,
    actor: &Actor,
    identity: &rootyard::ref_store::OperationIdentity,
    reason: &str,
) -> Result<Cancelled> {
    let receipt = adapter
        .cancel(pool, &actor.identity, identity, reason, deadline())
        .await
        .map_err(|error| anyhow!("authorized cancel refused ({}): {error}", error.code()))?;
    Ok(Cancelled {
        operation_id: receipt.operation_id,
        decision_id: receipt.decision_id,
        outcome: format!("{:?}", receipt.outcome),
        cancelled: receipt.is_cancelled(),
    })
}

pub fn mode(name: &str) -> Result<AuthorizedCommitMode> {
    match name {
        "atomic" => Ok(AuthorizedCommitMode::Atomic),
        "accepted_subset" => Ok(AuthorizedCommitMode::AcceptedSubset),
        other => Err(anyhow!("unknown authorized commit mode {other}")),
    }
}

pub fn counts_json(marker: &Value) -> Value {
    marker.get("decision_family_counts").cloned().unwrap_or_else(|| json!({}))
}
