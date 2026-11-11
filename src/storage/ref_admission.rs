//! Durable PostgreSQL admission and epoch fencing for native Git ref writers.
//!
//! A receive-pack writer inserts an `ADMITTED` row before it stages journal or
//! object data. Route takeover fences the old shard epoch in PostgreSQL and
//! either drains those rows or marks them `FENCED_ABORTED`. The writer's SQL
//! settlement requires `ADMITTED` inside the same transaction that publishes
//! outbox events, so a paused writer that resumes after takeover cannot publish.
//! Native Git may already have advanced local refs before that check; the
//! fenced path restores the journal's old OIDs under the repository write lock
//! and retires the journal without touching SQL ref history.
use crate::{AppState, Error, auth, db::Identity, journal};
use axum::http::StatusCode;
use deadpool_postgres::{Pool, Transaction};
use std::{collections::HashSet, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

pub const DRAIN_WINDOW: Duration = Duration::from_millis(750);
pub const MAX_REFS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Admitted,
    Committed,
    Aborted,
    FencedAborted,
}

impl State {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "ADMITTED" => Some(Self::Admitted),
            "COMMITTED" => Some(Self::Committed),
            "ABORTED" => Some(Self::Aborted),
            "FENCED_ABORTED" => Some(Self::FencedAborted),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "ADMITTED",
            Self::Committed => "COMMITTED",
            Self::Aborted => "ABORTED",
            Self::FencedAborted => "FENCED_ABORTED",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Admission {
    pub writer_id: Uuid,
    pub repository_id: Uuid,
    pub shard_epoch: i64,
    pub refs: Vec<String>,
}

fn conflict(message: &'static str) -> Error {
    Error(StatusCode::CONFLICT, message)
}

fn all_zero(oid: &str) -> bool {
    oid.bytes().all(|byte| byte == b'0')
}

fn normalized_refs(refs: &[String]) -> Result<Vec<String>, Error> {
    if refs.is_empty() || refs.len() > MAX_REFS {
        return Err(Error::bad_request());
    }
    let mut names = refs.to_vec();
    names.sort();
    let mut seen = HashSet::new();
    for name in &names {
        if !crate::journal::valid_ref(name) || !name.starts_with("refs/") || !seen.insert(name) {
            return Err(Error::bad_request());
        }
    }
    Ok(names)
}

/// Insert the writer's durable admission before any journal or object staging.
/// The route row is share-locked so takeover's epoch fence cannot commit while
/// an admission rooted in the old epoch is still being created.
pub async fn admit(
    pool: &Pool,
    repository_id: Uuid,
    generation: i64,
    actor: &Identity,
    refs: &[String],
    deadline: Instant,
) -> Result<Admission, Error> {
    if repository_id.is_nil() || generation <= 0 || Instant::now() >= deadline {
        return Err(Error::bad_request());
    }
    let names = normalized_refs(refs)?;
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let shard_epoch = match tx
        .query_opt(
            "SELECT route_epoch,primary_node_id,draining,read_only_degraded,fenced_epoch \
             FROM repository_shard_routes WHERE repository_id=$1 FOR SHARE",
            &[&repository_id],
        )
        .await
        .map_err(Error::internal)?
    {
        Some(row) => {
            let epoch: i64 = row.get(0);
            let primary: String = row.get(1);
            let draining: bool = row.get(2);
            let degraded: bool = row.get(3);
            let fenced: i64 = row.get(4);
            if epoch <= 0 || draining || degraded || fenced >= epoch {
                return Err(conflict("repository route is draining, degraded, or fenced"));
            }
            match crate::sharding::transport::node_id()? {
                Some(local) if local == primary => {}
                Some(_) => {
                    return Err(conflict("local storage node is not the repository primary"));
                }
                None => {
                    let count: i64 =
                        tx.query_one("SELECT COUNT(*) FROM shard_nodes", &[]).await.map_err(Error::internal)?.get(0);
                    if count > 1 {
                        return Err(conflict("cluster writer requires a local node identity"));
                    }
                }
            }
            epoch
        }
        None => {
            let installed: bool = tx
                .query_one("SELECT to_regclass('shard_nodes') IS NOT NULL", &[])
                .await
                .map_err(Error::internal)?
                .get(0);
            if installed {
                let count: i64 =
                    tx.query_one("SELECT COUNT(*) FROM shard_nodes", &[]).await.map_err(Error::internal)?.get(0);
                if count > 1 {
                    return Err(conflict("cluster writer requires a durable repository route"));
                }
            }
            1
        }
    };
    let row = tx
        .query_opt("SELECT storage_generation,state FROM repositories WHERE id=$1", &[&repository_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, i64>(0) != generation || row.get::<_, String>(1) != "ready" {
        return Err(conflict("repository generation or state changed during ref admission"));
    }
    auth::verify_repo_write_access(
        &*tx,
        actor.id,
        actor.token_id,
        repository_id,
        auth::web_scope_enabled(),
        crate::token_scopes::RepoAction::ContentsWrite,
    )
    .await?;
    let writer_id = Uuid::new_v4();
    let node_id = crate::sharding::transport::node_id()?;
    tx.execute(
        "INSERT INTO git_ref_admissions(writer_id,repository_id,shard_epoch,node_id,actor_id,token_id,ref_names,state) \
         VALUES($1,$2,$3,$4,$5,$6,$7,'ADMITTED')",
        &[&writer_id, &repository_id, &shard_epoch, &node_id, &actor.id, &actor.token_id, &names],
    )
    .await
    .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(Admission { writer_id, repository_id, shard_epoch, refs: names })
}

/// A writer that never reached Git release its admission without publishing.
pub async fn abort(pool: &Pool, writer_id: Uuid) -> Result<(), Error> {
    pool.get()
        .await
        .map_err(Error::internal)?
        .execute(
            "UPDATE git_ref_admissions SET state='ABORTED',settled_at=clock_timestamp() \
             WHERE writer_id=$1 AND state='ADMITTED'",
            &[&writer_id],
        )
        .await
        .map_err(Error::internal)?;
    Ok(())
}

/// Fence every still-open writer under `epoch`. The caller must already hold the
/// route's row lock and must have advanced `fenced_epoch`/`route_epoch` first.
/// The bounded wait lets a settlement that acquired the route lock earlier
/// commit; everything still ADMITTED afterwards is deterministically fenced.
pub async fn fence_epoch(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    epoch: i64,
    wait: Duration,
) -> Result<usize, Error> {
    if epoch <= 0 {
        return Err(Error::bad_request());
    }
    let deadline = Instant::now() + wait;
    loop {
        let open: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM git_ref_admissions \
                 WHERE repository_id=$1 AND shard_epoch=$2 AND state='ADMITTED'",
                &[&repository_id, &epoch],
            )
            .await
            .map_err(Error::internal)?
            .get(0);
        if open == 0 {
            return Ok(0);
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let changed = tx
        .execute(
            "UPDATE git_ref_admissions SET state='FENCED_ABORTED',settled_at=clock_timestamp() \
             WHERE repository_id=$1 AND shard_epoch=$2 AND state='ADMITTED'",
            &[&repository_id, &epoch],
        )
        .await
        .map_err(Error::internal)?;
    Ok(changed as usize)
}

/// A terminal admission may only replay the exact operation that originally
/// settled it. The operation row and every outbox event are immutable once
/// terminal, so a different operation cannot borrow a COMMITTED/ABORTED
/// writer id and current auth/route changes cannot invalidate real history.
#[allow(clippy::too_many_arguments)]
async fn ensure_terminal_replay<C: tokio_postgres::GenericClient + Sync>(
    tx: &C,
    operation_id: Uuid,
    repository_id: Uuid,
    storage_generation: i64,
    actor_id: Uuid,
    token_id: Uuid,
    outcome: &str,
    changes: &[crate::events::RefEventInput],
) -> anyhow::Result<()> {
    let row = tx
        .query_opt(
            "SELECT repository_id,actor_id,token_id,storage_generation,outcome \
             FROM git_operations WHERE id=$1 FOR UPDATE",
            &[&operation_id],
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("terminal ref admission has no original operation"))?;
    if row.get::<_, Uuid>(0) != repository_id
        || row.get::<_, Option<Uuid>>(1) != Some(actor_id)
        || row.get::<_, Option<Uuid>>(2) != Some(token_id)
        || row.get::<_, i64>(3) != storage_generation
        || row.get::<_, String>(4) != outcome
    {
        anyhow::bail!("terminal operation replay identity or outcome mismatch");
    }
    let rows = tx
        .query(
            "SELECT transaction_sequence,ref_name,old_oid,new_oid FROM outbox_events WHERE operation_id=$1",
            &[&operation_id],
        )
        .await?;
    let stored = rows
        .iter()
        .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1), row.get::<_, String>(2), row.get::<_, String>(3)))
        .collect::<HashSet<_>>();
    let replayed = changes
        .iter()
        .map(|change| {
            (change.transaction_sequence, change.ref_name.clone(), change.old_oid.clone(), change.new_oid.clone())
        })
        .collect::<HashSet<_>>();
    if stored.len() != rows.len() || replayed.len() != changes.len() || stored != replayed {
        anyhow::bail!("terminal operation replay event set differs");
    }
    Ok(())
}

/// Settlement inside the exact transaction that publishes `git_operations` and
/// outbox events. It re-verifies the repository generation/state, the route
/// epoch/fence, the database actor/token identity and the ADMITTED state before
/// allowing any row to become visible.
///
/// Two journal capabilities may skip only the *current* token/RBAC recheck:
/// `NoGrantAbort` for a provably ref-free interrupted push and
/// `RecordedReceiptProof` for a transaction native Git already committed. Both
/// are re-bound here to the database admission identity; normal new writes and
/// any missing or mismatched proof still verify current authority.
#[allow(clippy::too_many_arguments)]
pub async fn settle_in_tx<C: tokio_postgres::GenericClient + Sync>(
    tx: &C,
    repository_id: Uuid,
    storage_generation: i64,
    admission: &crate::events::AdmissionRecord,
    actor_id: Uuid,
    token_id: Uuid,
    outcome: &str,
    changes: &[crate::events::RefEventInput],
    no_grant: Option<&crate::storage::no_grant_proof::NoGrantAbort>,
    recorded: Option<&crate::storage::recorded_receipt_proof::RecordedReceiptProof>,
) -> anyhow::Result<()> {
    // Same-transaction repository row: the current generation must still be
    // the operation's generation. A journal capability may project past facts
    // while the repository carries only the temporary unknown-push flag; every
    // other state or operator recovery reason still rejects settlement.
    let repo = tx
        .query_opt(
            "SELECT storage_generation,state,COALESCE(recovery_reason,'') FROM repositories WHERE id=$1 FOR SHARE",
            &[&repository_id],
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("repository is missing during ref settlement"))?;
    let repo_state: String = repo.get(1);
    let recovery_reason: String = repo.get(2);
    let proof_present = no_grant.is_some() || recorded.is_some();
    let row = tx
        .query_opt(
            "SELECT state,shard_epoch,actor_id,token_id,ref_names FROM git_ref_admissions WHERE writer_id=$1 AND repository_id=$2 FOR UPDATE",
            &[&admission.writer_id, &repository_id],
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("ref admission is missing"))?;
    let state =
        State::parse(row.get::<_, String>(0).as_str()).ok_or_else(|| anyhow::anyhow!("invalid ref admission state"))?;
    // Immutable admission identity is checked on every path, including a
    // terminal replay. Current authority (token/RBAC, repository ready state
    // and the live route/fence) is checked only for a new ADMITTED settlement
    // so a crash after commit can still replay the exact original operation.
    let admitted_epoch: i64 = row.get(1);
    let database_actor: Uuid = row.get(2);
    let database_token: Uuid = row.get(3);
    let database_refs: Vec<String> = row.get(4);
    if admitted_epoch != admission.shard_epoch {
        anyhow::bail!("ref admission epoch differs from its journal");
    }
    // The database row, never the caller's proof or journal, owns actor/token
    // identity. A proof minted for another principal cannot settle here.
    if database_actor != actor_id || database_token != token_id {
        anyhow::bail!("ref admission actor/token identity changed");
    }
    if !changes.iter().all(|change| database_refs.iter().any(|name| name == &change.ref_name)) {
        anyhow::bail!("ref event was not in the admitted ref-name set");
    }
    if state == State::Committed {
        // Terminal replay after a crash between outbox commit and journal
        // retirement. The original settlement already ran in one transaction;
        // only the exact operation row and event set may be replayed.
        ensure_terminal_replay(
            tx,
            admission.writer_id,
            repository_id,
            storage_generation,
            actor_id,
            token_id,
            outcome,
            changes,
        )
        .await?;
        return Ok(());
    }
    if state == State::Aborted {
        if outcome != "no_ref_changes" {
            anyhow::bail!("ref admission was already aborted for a different outcome");
        }
        ensure_terminal_replay(
            tx,
            admission.writer_id,
            repository_id,
            storage_generation,
            actor_id,
            token_id,
            outcome,
            changes,
        )
        .await?;
        return Ok(());
    }
    if state == State::FencedAborted {
        anyhow::bail!("ref admission is fenced");
    }
    // Only an ADMITTED settlement has to project into the current repository
    // generation/state; a terminal replay above is already durable and only
    // repeats identical rows, even after current route/auth changes.
    if repo.get::<_, i64>(0) != storage_generation {
        anyhow::bail!("repository generation changed during ref settlement");
    }
    if repo_state != "ready"
        && !(proof_present && repo_state == "recovering" && recovery_reason == "push_outcome_unknown")
    {
        anyhow::bail!("repository state does not allow ref settlement");
    }
    if let Some(route) = tx
        .query_opt(
            "SELECT route_epoch,primary_node_id,draining,read_only_degraded,fenced_epoch FROM repository_shard_routes WHERE repository_id=$1 FOR SHARE",
            &[&repository_id],
        )
        .await?
    {
        let epoch: i64 = route.get(0);
        let primary: String = route.get(1);
        let draining: bool = route.get(2);
        let degraded: bool = route.get(3);
        let fenced: i64 = route.get(4);
        if epoch != admitted_epoch || draining || degraded || fenced >= epoch {
            anyhow::bail!("ref admission route epoch changed or is fenced");
        }
        if let Some(local) = crate::sharding::transport::node_id().map_err(|error| anyhow::anyhow!(error.1))?
            && local != primary
        {
            anyhow::bail!("ref admission writer is not the current repository primary");
        }
    }
    // A revocation that races a provably ref-free push must not strand the
    // admission. Journal-derived proof that no grant marker, hook event,
    // receipt or request ever existed means the child could not have changed a
    // ref, so the authority recheck is skipped for that exact identity-matched
    // proof and only for `no_ref_changes`; route/epoch/fence checks still apply.
    // No request exists in that case, so no ref names are invented here.
    let proven_ref_free = outcome == "no_ref_changes"
        && no_grant.is_some_and(|proof| proof.matches_admission(repository_id, admission, actor_id, token_id));
    // A real receipt plus matching request and committed reference events may
    // skip only the current token/RBAC/`ready` recheck: the transaction being
    // projected already committed before the crash and this path never grants
    // a new ref. The proof must cover exactly the admitted ref-name set, the
    // database principal and the complete event payload.
    let proven_recorded = match recorded {
        Some(proof) => {
            if outcome != "recorded" {
                anyhow::bail!("recorded receipt proof differs from settlement outcome");
            }
            if changes.is_empty() {
                anyhow::bail!("recorded receipt proof has no committed changes");
            }
            if !proof.matches_admission(
                repository_id,
                storage_generation,
                admission,
                actor_id,
                token_id,
                database_actor,
                database_token,
                &database_refs,
            ) {
                anyhow::bail!("recorded receipt proof differs from its admission");
            }
            true
        }
        None => false,
    };
    if !proven_ref_free && !proven_recorded {
        auth::verify_repo_write_access(
            tx,
            actor_id,
            token_id,
            repository_id,
            false,
            crate::token_scopes::RepoAction::ContentsWrite,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.1))?;
    }
    let terminal = match outcome {
        "no_ref_changes" => State::Aborted,
        _ => State::Committed,
    };
    let changed = tx
        .execute(
            "UPDATE git_ref_admissions SET state=$3,settled_at=clock_timestamp() \
             WHERE writer_id=$1 AND shard_epoch=$2 AND state='ADMITTED'",
            &[&admission.writer_id, &admission.shard_epoch, &terminal.as_str()],
        )
        .await?;
    if changed != 1 {
        anyhow::bail!("ref admission settlement lost its ADMITTED row");
    }
    Ok(())
}

/// True when a journal operation can no longer publish refs: its admission was
/// fenced/aborted, its route epoch moved, or its node lost primary status.
pub async fn operation_is_fenced(state: &AppState, operation: &journal::Operation) -> anyhow::Result<bool> {
    if !operation.requires_parent_publication || operation.shard_epoch <= 0 {
        return Ok(false);
    }
    if journal::is_fenced_aborted(operation)? {
        return Ok(true);
    }
    let row = state
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT a.state,a.shard_epoch,r.route_epoch,r.primary_node_id,r.draining, \
                    r.read_only_degraded,r.fenced_epoch \
             FROM git_ref_admissions a \
             LEFT JOIN repository_shard_routes r ON r.repository_id=a.repository_id \
             WHERE a.writer_id=$1 AND a.repository_id=$2",
            &[&operation.id, &operation.repository_id],
        )
        .await?;
    let Some(row) = row else {
        // A pre-admission journal (upgrade boundary) keeps the legacy path.
        return Ok(false);
    };
    let state =
        State::parse(row.get::<_, String>(0).as_str()).ok_or_else(|| anyhow::anyhow!("invalid ref admission state"))?;
    match state {
        State::Committed => return Ok(false),
        State::Aborted | State::FencedAborted => return Ok(true),
        State::Admitted => {}
    }
    let epoch: i64 = row.get(1);
    let Some(route_epoch) = row.get::<_, Option<i64>>(2) else {
        return Ok(false);
    };
    let primary: Option<String> = row.get(3);
    let draining: Option<bool> = row.get(4);
    let degraded: Option<bool> = row.get(5);
    let fenced: Option<i64> = row.get(6);
    if route_epoch != epoch
        || draining.unwrap_or(false)
        || degraded.unwrap_or(false)
        || fenced.unwrap_or(0) >= route_epoch
    {
        return Ok(true);
    }
    if let (Some(local), Some(primary)) =
        (crate::sharding::transport::node_id().map_err(|error| anyhow::anyhow!(error.1))?, primary)
        && local != primary
    {
        return Ok(true);
    }
    Ok(false)
}

/// Restore every requested ref whose current value is still this writer's new
/// OID, then durably mark and retire the journal. The caller holds the local
/// repository write lock (and the writer process must be quiescent).
pub async fn rollback_fenced(state: &AppState, operation: &journal::Operation) -> anyhow::Result<()> {
    if !operation.requires_parent_publication || operation.shard_epoch <= 0 {
        return Ok(());
    }
    if let Some(requested) = journal::requests(operation)? {
        rollback_refs(state, operation.repository_id, &requested).await?;
    }
    journal::mark_fenced_aborted(operation)?;
    state
        .pool
        .get()
        .await?
        .execute(
            "UPDATE git_ref_admissions SET state='FENCED_ABORTED',settled_at=clock_timestamp() \
             WHERE writer_id=$1 AND shard_epoch=$2 AND state='ADMITTED'",
            &[&operation.id, &operation.shard_epoch],
        )
        .await?;
    journal::finish(operation)?;
    journal::retire(operation)?;
    Ok(())
}

async fn rollback_refs(state: &AppState, repository_id: Uuid, changes: &[journal::RefChange]) -> anyhow::Result<()> {
    for change in changes {
        // A missing ref must read as "absent", not as a failed observation:
        // `show-ref --verify` reports absence as the generic fatal 128, while
        // the quiet `rev-parse --verify` probe answers exactly 1 for it.
        let observed = match crate::browse::git_read::run_git(
            state,
            repository_id,
            crate::browse::git_read::GitStep::RefVerify,
            &["rev-parse", "--verify", "--quiet", &change.ref_name],
            128,
        )
        .await
        {
            Ok(raw) => Some(String::from_utf8_lossy(&raw).trim().to_owned()),
            Err(error) if error.0 == StatusCode::NOT_FOUND => None,
            Err(_) => anyhow::bail!("cannot observe local ref before fenced rollback"),
        };
        if observed.as_deref() != Some(change.new_oid.as_str()) {
            continue;
        }
        let mut command =
            crate::browse::git_read::git_cmd(state, repository_id).map_err(|error| anyhow::anyhow!(error.1))?;
        if all_zero(&change.old_oid) {
            command.args(["update-ref", "-d", "--no-deref", &change.ref_name, &change.new_oid]);
        } else {
            command.args(["update-ref", "--no-deref", &change.ref_name, &change.old_oid, &change.new_oid]);
        }
        crate::git_http::collect_git_output(command, 4096, state.config.git_timeout).await?;
    }
    Ok(())
}

/// Best-effort local cleanup after takeover. Only quiescent fenced journals are
/// touched; a still-live writer is left for its own settlement path to rollback.
pub async fn cleanup_fenced(state: &AppState, repository_id: Uuid) -> anyhow::Result<usize> {
    let mut count = 0;
    for operation in journal::pending(&state.storage.root, repository_id)? {
        if !operation.requires_parent_publication || operation.shard_epoch <= 0 {
            continue;
        }
        if journal::ActiveGuard::operation_is_live(&operation)? {
            continue;
        }
        if operation_is_fenced(state, &operation).await? {
            rollback_fenced(state, &operation).await?;
            count += 1;
        }
    }
    Ok(count)
}

/// Gate a native hook phase on the row written before Git started. `preparing`
/// and `prepared` both call this; `prepared` is the last SQL-visible point
/// before Git writes refs. The token/role check also closes the long-transfer
/// revocation window.
pub async fn ensure_hook_admitted<C: tokio_postgres::GenericClient + Sync>(
    client: &C,
    operation: &journal::Operation,
) -> anyhow::Result<()> {
    if !operation.requires_parent_publication || operation.shard_epoch <= 0 {
        return Ok(());
    }
    let row = client
        .query_opt(
            "SELECT state,shard_epoch,actor_id,token_id FROM git_ref_admissions \
             WHERE writer_id=$1 AND repository_id=$2",
            &[&operation.id, &operation.repository_id],
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("native ref writer has no durable admission"))?;
    if State::parse(row.get::<_, String>(0).as_str()) != Some(State::Admitted) {
        anyhow::bail!("native ref admission is no longer ADMITTED");
    }
    if row.get::<_, i64>(1) != operation.shard_epoch {
        anyhow::bail!("native ref admission shard epoch changed");
    }
    let actor_id: Uuid = row.get(2);
    let token_id: Uuid = row.get(3);
    if actor_id != operation.actor_id || token_id != operation.token_id {
        anyhow::bail!("native ref admission identity changed");
    }
    auth::verify_repo_write_access(
        client,
        actor_id,
        token_id,
        operation.repository_id,
        false,
        crate::token_scopes::RepoAction::ContentsWrite,
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.1))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db, events};
    use tokio::time::Duration;

    async fn fixture() -> Option<(deadpool_postgres::Pool, String, Identity, Uuid, Uuid)> {
        let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok()?;
        let admin = db::pool(&base_url).unwrap();
        let schema = format!("ref_admission_{}", Uuid::new_v4().simple());
        admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA \"{schema}\"")).await.unwrap();
        let mut url = reqwest::Url::parse(&base_url).unwrap();
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let pool = db::pool(url.as_str()).unwrap();
        db::migrate(&pool).await.unwrap();
        let issued = db::issue_token(&pool, "alice", true, false).await.unwrap();
        let actor_id: Uuid = serde_json::from_value(issued["user_id"].clone()).unwrap();
        let token_id: Uuid = serde_json::from_value(issued["token_id"].clone()).unwrap();
        let digest: Vec<u8> = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT digest FROM tokens WHERE id=$1", &[&token_id])
            .await
            .unwrap()
            .get(0);
        let actor =
            Identity { id: actor_id, token_id, username: "alice".into(), read_only: false, token_digest: digest };
        let repo = Uuid::new_v4();
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'demo','ready')",
                &[&repo, &actor_id],
            )
            .await
            .unwrap();
        pool.get().await.unwrap().execute(
            "INSERT INTO shard_nodes(node_id,endpoint,role,status) VALUES('node-a','http://127.0.0.1:1','primary','healthy')",
            &[]).await.unwrap();
        pool.get().await.unwrap().execute(
            "INSERT INTO repository_shard_routes(tenant_id,repository_id,bucket_id,primary_node_id,route_epoch,fencing_token,required_generation) \
             VALUES($1,$2,0,'node-a',7,7,1)",
            &[&actor_id, &repo]).await.unwrap();
        Some((pool, url.to_string(), actor, repo, actor_id))
    }

    fn record(
        id: Uuid,
        actor: &Identity,
        repo: Uuid,
        admission: Option<events::AdmissionRecord>,
        outcome: &str,
    ) -> events::OperationRecord {
        events::OperationRecord {
            id,
            repository_id: repo,
            actor_id: actor.id,
            token_id: actor.token_id,
            service_principal_id: None,
            actor_name: actor.username.clone(),
            sequence: 1,
            storage_generation: 1,
            outcome: outcome.into(),
            evidence: serde_json::json!({"version":1}),
            admission,
        }
    }

    #[tokio::test]
    async fn fenced_epoch_prevents_outbox_settlement() {
        let Some((pool, _, actor, repo, _)) = fixture().await else {
            return;
        };
        let refs = vec!["refs/heads/main".to_string()];
        let admission = admit(&pool, repo, 1, &actor, &refs, Instant::now() + Duration::from_secs(5)).await.unwrap();
        let mut client = pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        tx.execute(
            "UPDATE repository_shard_routes SET draining=true,route_epoch=8, \
            fencing_token=8,fenced_epoch=7 WHERE repository_id=$1",
            &[&repo],
        )
        .await
        .unwrap();
        let fenced = fence_epoch(&tx, repo, 7, Duration::ZERO).await.unwrap();
        assert_eq!(fenced, 1);
        tx.commit().await.unwrap();
        let state: String = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT state FROM git_ref_admissions WHERE writer_id=$1", &[&admission.writer_id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "FENCED_ABORTED");
        let result = events::publish(
            &pool,
            &record(
                admission.writer_id,
                &actor,
                repo,
                Some(events::AdmissionRecord { writer_id: admission.writer_id, shard_epoch: admission.shard_epoch }),
                "recorded",
            ),
            &[],
        )
        .await;
        assert!(result.is_err(), "fenced admission published SQL settlement");
        let operations: i64 =
            pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM git_operations", &[]).await.unwrap().get(0);
        let outbox: i64 =
            pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM outbox_events", &[]).await.unwrap().get(0);
        assert_eq!((operations, outbox), (0, 0));
    }

    #[tokio::test]
    async fn revoked_token_cannot_settle_admitted_refs() {
        let Some((pool, url, actor, repo, _)) = fixture().await else {
            return;
        };
        let refs = vec!["refs/heads/main".to_string()];
        let admission = admit(&pool, repo, 1, &actor, &refs, Instant::now() + Duration::from_secs(5)).await.unwrap();
        let client = db::connect_url(&url).await.unwrap();
        let root = tempfile::tempdir().unwrap();
        let (operation, _active) = journal::begin_active_with(
            root.path(),
            repo,
            actor.id,
            actor.username.clone(),
            actor.token_id,
            1,
            admission.writer_id,
            admission.shard_epoch,
        )
        .unwrap();
        ensure_hook_admitted(&client, &operation).await.unwrap();
        pool.get()
            .await
            .unwrap()
            .execute("UPDATE tokens SET revoked=true WHERE id=$1", &[&actor.token_id])
            .await
            .unwrap();
        let result = events::publish(
            &pool,
            &record(
                admission.writer_id,
                &actor,
                repo,
                Some(events::AdmissionRecord { writer_id: admission.writer_id, shard_epoch: admission.shard_epoch }),
                "recorded",
            ),
            &[],
        )
        .await;
        assert!(result.is_err(), "revoked token settled a ref operation");
        let operations: i64 =
            pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM git_operations", &[]).await.unwrap().get(0);
        assert_eq!(operations, 0);
        let state: String = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT state FROM git_ref_admissions WHERE writer_id=$1", &[&admission.writer_id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "ADMITTED", "revocation must not fabricate a settled admission");
    }

    #[tokio::test]
    async fn admitted_writer_settles_once_and_replays_idempotently() {
        let Some((pool, _, actor, repo, _)) = fixture().await else {
            return;
        };
        let refs = vec!["refs/heads/main".to_string()];
        let admission = admit(&pool, repo, 1, &actor, &refs, Instant::now() + Duration::from_secs(5)).await.unwrap();
        let change = events::RefEventInput {
            transaction_sequence: 1,
            ref_name: "refs/heads/main".into(),
            old_oid: "0".repeat(40),
            new_oid: "a".repeat(40),
        };
        let body = record(
            admission.writer_id,
            &actor,
            repo,
            Some(events::AdmissionRecord { writer_id: admission.writer_id, shard_epoch: admission.shard_epoch }),
            "recorded",
        );
        events::publish(&pool, &body, std::slice::from_ref(&change)).await.unwrap();
        let state: String = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT state FROM git_ref_admissions WHERE writer_id=$1", &[&admission.writer_id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "COMMITTED");
        // Legitimate historical replay must not depend on current auth or route.
        pool.get()
            .await
            .unwrap()
            .execute("UPDATE tokens SET revoked=true WHERE id=$1", &[&actor.token_id])
            .await
            .unwrap();
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE repository_shard_routes SET draining=true,route_epoch=8,\
                 fencing_token=8,fenced_epoch=7 WHERE repository_id=$1",
                &[&repo],
            )
            .await
            .unwrap();
        events::publish(&pool, &body, std::slice::from_ref(&change)).await.unwrap();
        // A different operation cannot borrow the committed writer id.
        let borrowed = record(
            Uuid::new_v4(),
            &actor,
            repo,
            Some(events::AdmissionRecord { writer_id: admission.writer_id, shard_epoch: admission.shard_epoch }),
            "recorded",
        );
        assert!(events::publish(&pool, &borrowed, std::slice::from_ref(&change)).await.is_err());
        // Nor can the exact operation id be replayed with another principal.
        let mut tampered = body.clone();
        tampered.actor_id = Uuid::new_v4();
        assert!(events::publish(&pool, &tampered, std::slice::from_ref(&change)).await.is_err());
        // Nor with an omitted, changed or invented event set.
        assert!(events::publish(&pool, &body, &[]).await.is_err());
        let mut changed = change.clone();
        changed.new_oid = "b".repeat(40);
        assert!(events::publish(&pool, &body, &[changed]).await.is_err());
        let outbox: i64 =
            pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM outbox_events", &[]).await.unwrap().get(0);
        let operations: i64 =
            pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM git_operations", &[]).await.unwrap().get(0);
        assert_eq!((outbox, operations), (1, 1));
    }

    #[tokio::test]
    async fn operation_cannot_borrow_another_admission_writer() {
        let Some((pool, _, actor, repo, _)) = fixture().await else {
            return;
        };
        let refs = vec!["refs/heads/main".to_string()];
        let admission = admit(&pool, repo, 1, &actor, &refs, Instant::now() + Duration::from_secs(5)).await.unwrap();
        let foreign = record(
            Uuid::new_v4(),
            &actor,
            repo,
            Some(events::AdmissionRecord { writer_id: admission.writer_id, shard_epoch: admission.shard_epoch }),
            "no_ref_changes",
        );
        assert!(
            events::publish(&pool, &foreign, &[]).await.is_err(),
            "an operation must not settle through another operation's admission"
        );
        let operations: i64 =
            pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM git_operations", &[]).await.unwrap().get(0);
        assert_eq!(operations, 0);
        let state: String = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT state FROM git_ref_admissions WHERE writer_id=$1", &[&admission.writer_id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "ADMITTED");
    }

    #[tokio::test]
    async fn aborted_no_ref_changes_replays_only_its_own_operation() {
        let Some((pool, _, actor, repo, _)) = fixture().await else {
            return;
        };
        let refs = vec!["refs/heads/main".to_string()];
        let admission = admit(&pool, repo, 1, &actor, &refs, Instant::now() + Duration::from_secs(5)).await.unwrap();
        let body = record(
            admission.writer_id,
            &actor,
            repo,
            Some(events::AdmissionRecord { writer_id: admission.writer_id, shard_epoch: admission.shard_epoch }),
            "no_ref_changes",
        );
        events::publish(&pool, &body, &[]).await.unwrap();
        let state: String = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT state FROM git_ref_admissions WHERE writer_id=$1", &[&admission.writer_id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "ABORTED");
        // Terminal ABORTED replay also survives current auth and route changes.
        pool.get()
            .await
            .unwrap()
            .execute("UPDATE tokens SET revoked=true WHERE id=$1", &[&actor.token_id])
            .await
            .unwrap();
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE repository_shard_routes SET draining=true,route_epoch=8,\
                 fencing_token=8,fenced_epoch=7 WHERE repository_id=$1",
                &[&repo],
            )
            .await
            .unwrap();
        events::publish(&pool, &body, &[]).await.unwrap();
        let borrowed = record(
            Uuid::new_v4(),
            &actor,
            repo,
            Some(events::AdmissionRecord { writer_id: admission.writer_id, shard_epoch: admission.shard_epoch }),
            "no_ref_changes",
        );
        assert!(events::publish(&pool, &borrowed, &[]).await.is_err());
        let mut tampered = body.clone();
        tampered.actor_id = Uuid::new_v4();
        assert!(events::publish(&pool, &tampered, &[]).await.is_err());
        let mut different = body.clone();
        different.outcome = "recorded".into();
        assert!(events::publish(&pool, &different, &[]).await.is_err());
        let operations: i64 =
            pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM git_operations", &[]).await.unwrap().get(0);
        let outbox: i64 =
            pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM outbox_events", &[]).await.unwrap().get(0);
        assert_eq!((operations, outbox), (1, 0));
    }
}
