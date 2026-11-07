//! Fair, bounded repository scheduling for the background webhook worker.
//!
//! PostgreSQL rows remain the only durable work queue. This module only decides
//! which bounded slice of repositories is examined next and bounds how much
//! concurrent work one round may create. A slow receiver therefore occupies at
//! most one repository slot for at most one phase deadline; it cannot hold the
//! whole scan or every later repository behind it.
use crate::{AppState, Error};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// A native Git process consumes one `git_slots` permit and then a short read
/// lease. Four repository workers leave room for HTTP readers and SQL work.
pub(crate) const MAX_CONCURRENT_REPOSITORIES: usize = 4;
/// One round advances a bounded cursor window. A restart replays from the
/// beginning, which is safe because every phase is idempotent/at-least-once.
pub(crate) const MAX_REPOSITORIES_PER_ROUND: i64 = 16;
/// PR ref resolution and orchestration are cancellation-sensitive. Bound each
/// repository phase so queued capacity cannot be monopolised by one repository.
pub(crate) const REPOSITORY_PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// A delivery worker stops *starting* sends after this budget. A send already
/// in flight is allowed to finish under its hook's own timeout (at most 30 s).
pub(crate) const DELIVERY_REPOSITORY_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
/// Maximum hook transport timeout plus one delivery budget per repository wave.
pub(crate) const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// Pulls examined per repository phase. `repair_pull_orchestration` writes its
/// progress marker, so the next round continues with the next pulls.
pub(crate) const PULL_RECONCILE_LIMIT: i64 = 16;
pub(crate) const PULL_REPAIR_LIMIT: i64 = 16;
/// Sends per hook-bearing repository per round. Sends remain serial inside a
/// repository so observable per-hook sequence order is not inverted.
pub(crate) const DELIVERY_LIMIT: i64 = 8;
/// One bounded backfill page selects missing (outbox event, active push hook)
/// pairs. The limit caps both work and memory independently of hook count.
pub(crate) const OUTBOX_BACKFILL_LIMIT: i64 = 128;
/// Backfill stops before this per-repository budget and is separately wrapped
/// in a timeout, so it can never delay the HTTP phase indefinitely.
pub(crate) const OUTBOX_BACKFILL_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
/// Phase two stops *starting* work at this point in a round. The remaining 60 s
/// of `SCAN_TIMEOUT` covers one 30 s hook transport already in flight plus
/// scheduling/DB overhead, so the outer timeout never drops a valid send.
pub(crate) const SCAN_WORK_BUDGET: std::time::Duration = std::time::Duration::from_secs(240);
/// In-process pull cursors are pruned by age and bounded by capacity. They are
/// touched whenever a repository is examined, so an active multi-page prefix is
/// not reset, while closed/deleted/backend-changed repositories age out.
pub(crate) const PULL_CURSOR_TTL: std::time::Duration = std::time::Duration::from_secs(1800);
pub(crate) const PULL_CURSOR_CAPACITY: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct RepositoryKey {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Candidate {
    pub key: RepositoryKey,
    pub has_webhooks: bool,
    pub has_open_pulls: bool,
    pub gitfs_ready: bool,
}

#[derive(Default, Debug)]
pub(crate) struct RoundSummary {
    pub completed: usize,
    pub failures: usize,
}

impl RoundSummary {
    pub(crate) fn merge(&mut self, other: RunOutcome) {
        self.completed += other.completed;
        self.failures += other.failures;
    }
}

#[derive(Default, Debug)]
pub(crate) struct RunOutcome {
    pub completed: usize,
    pub failures: usize,
}

/// In-process fair cursor for Pull Requests inside one repository. Absence of a
/// value means the next page starts at the first open pull. The cursor only
/// advances after a successfully examined page, so cancellation replays it.
///
/// Entries are bounded by age and capacity rather than being pruned against the
/// current candidate window, so a repository outside this round's 16-row page
/// keeps its progress. Every use refreshes the entry; this prevents an active
/// multi-page prefix from being reset on the next page.
#[derive(Clone, Copy)]
struct PullCursor {
    after: i64,
    touched: std::time::Instant,
}

#[derive(Clone, Default)]
pub(crate) struct PullCursors(Arc<Mutex<HashMap<Uuid, PullCursor>>>);

fn prune_pull_cursors(cursors: &mut HashMap<Uuid, PullCursor>, now: std::time::Instant) {
    cursors.retain(|_, cursor| now.saturating_duration_since(cursor.touched) <= PULL_CURSOR_TTL);
    if cursors.len() <= PULL_CURSOR_CAPACITY {
        return;
    }
    let mut oldest: Vec<(Uuid, std::time::Instant)> =
        cursors.iter().map(|(repository_id, cursor)| (*repository_id, cursor.touched)).collect();
    oldest.sort_by_key(|(_, touched)| *touched);
    for (repository_id, _) in oldest.into_iter().take(cursors.len() - PULL_CURSOR_CAPACITY) {
        cursors.remove(&repository_id);
    }
}

impl PullCursors {
    pub(crate) fn after(&self, repository_id: Uuid) -> Option<i64> {
        let now = std::time::Instant::now();
        let mut cursors = self.0.lock().expect("pull cursor poisoned");
        prune_pull_cursors(&mut cursors, now);
        let cursor = cursors.get_mut(&repository_id)?;
        cursor.touched = now;
        Some(cursor.after)
    }

    pub(crate) fn set(&self, repository_id: Uuid, after: Option<i64>) {
        let now = std::time::Instant::now();
        let mut cursors = self.0.lock().expect("pull cursor poisoned");
        match after {
            Some(number) => {
                cursors.insert(repository_id, PullCursor { after: number, touched: now });
            }
            None => {
                cursors.remove(&repository_id);
            }
        }
        prune_pull_cursors(&mut cursors, now);
    }
}

/// In-process round-robin cursor. Durable state lives in PostgreSQL rows, so a
/// restart safely replays earlier repositories rather than losing work.
#[derive(Default)]
pub(crate) struct Scheduler {
    cursor: Option<RepositoryKey>,
    pull_cursors: PullCursors,
}

const CANDIDATE_SQL: &str = "\
WITH candidates AS ( \
  SELECT tenant_id,repository_id,bool_or(has_webhooks) AS has_webhooks, \
         bool_or(has_open_pulls) AS has_open_pulls \
  FROM ( \
    SELECT w.tenant_id,w.repository_id,true AS has_webhooks,false AS has_open_pulls \
      FROM forge_webhooks w WHERE w.active=true \
    UNION ALL \
    SELECT p.tenant_id,p.repository_id,false,true \
      FROM forge_pulls p WHERE p.state='open' \
  ) sources GROUP BY tenant_id,repository_id) \
SELECT c.tenant_id,c.repository_id,c.has_webhooks,c.has_open_pulls, \
       (r.storage_backend='gitfs') AS gitfs_ready \
FROM candidates c JOIN repositories r ON r.id=c.repository_id AND r.owner_id=c.tenant_id \
WHERE r.state='ready' \
  AND ($1::uuid IS NULL OR (c.tenant_id,c.repository_id)>($1::uuid,$2::uuid)) \
ORDER BY c.tenant_id,c.repository_id LIMIT $3";

impl Scheduler {
    pub(crate) fn pull_cursors(&self) -> PullCursors {
        self.pull_cursors.clone()
    }

    /// Page through repository candidates in stable `(tenant_id,repository_id)`
    /// order. Empty trailing pages wrap to the beginning on the next call.
    pub(crate) async fn next_page(&mut self, state: &AppState) -> Result<Vec<Candidate>, Error> {
        loop {
            let after = self.cursor;
            let client = state.pool.get().await.map_err(Error::internal)?;
            let rows = client
                .query(
                    CANDIDATE_SQL,
                    &[
                        &after.map(|key| key.tenant_id),
                        &after.map(|key| key.repository_id),
                        &MAX_REPOSITORIES_PER_ROUND,
                    ],
                )
                .await
                .map_err(Error::internal)?;
            drop(client);
            if rows.is_empty() && after.is_some() {
                self.cursor = None;
                continue;
            }
            let mut candidates = Vec::with_capacity(rows.len());
            for row in rows {
                candidates.push(Candidate {
                    key: RepositoryKey { tenant_id: row.get(0), repository_id: row.get(1) },
                    has_webhooks: row.get(2),
                    has_open_pulls: row.get(3),
                    gitfs_ready: row.get(4),
                });
            }
            self.cursor = if (candidates.len() as i64) < MAX_REPOSITORIES_PER_ROUND {
                None
            } else {
                candidates.last().map(|candidate| candidate.key)
            };
            return Ok(candidates);
        }
    }
}

pub(crate) type RepoFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

/// Runs one phase over a bounded candidate set with at most
/// `MAX_CONCURRENT_REPOSITORIES` in flight. Cancellation aborts every owned
/// task before returning; no task outlives the round.
pub(crate) async fn run_bounded<F>(stop: &CancellationToken, candidates: &[Candidate], mut work: F) -> RunOutcome
where
    F: FnMut(Candidate) -> RepoFuture,
{
    let mut outcome = RunOutcome::default();
    if candidates.is_empty() {
        return outcome;
    }
    let mut tasks = JoinSet::new();
    let mut remaining = candidates.iter().copied();
    for _ in 0..MAX_CONCURRENT_REPOSITORIES.min(candidates.len()) {
        if let Some(candidate) = remaining.next() {
            tasks.spawn(work(candidate));
        }
    }
    loop {
        tokio::select! {
            _ = stop.cancelled() => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok(Ok(()))) => outcome.completed += 1,
                    Some(Ok(Err(_))) | Some(Err(_)) => outcome.failures += 1,
                    None => break,
                }
                if let Some(candidate) = remaining.next() {
                    tasks.spawn(work(candidate));
                }
            }
        }
    }
    outcome
}
