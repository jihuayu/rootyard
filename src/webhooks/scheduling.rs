//! Fair, bounded repository scheduling for the background webhook worker.
//!
//! PostgreSQL rows remain the only durable work queue. This module only decides
//! which bounded slice of repositories is examined next and bounds how much
//! concurrent work one round may create. A slow receiver therefore occupies at
//! most one repository slot for at most one phase deadline; it cannot hold the
//! whole scan or every later repository behind it.
use crate::{AppState, Error};
use std::{
    collections::BTreeMap,
    future::Future,
    ops::Bound,
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
/// Phase two stops *starting* work at this point in a scan. The remaining 60 s
/// of `SCAN_TIMEOUT` covers one 30 s hook transport already in flight (plus
/// backfill and scheduling/DB overhead), so the outer timeout never drops a
/// valid send. The budget is anchored at the start of the scan, before the
/// candidate query, so query latency cannot consume this reserve.
pub(crate) const SCAN_WORK_BUDGET: std::time::Duration = std::time::Duration::from_secs(240);
/// Cursor pruning examines at most this many repository IDs per round. Because
/// `PullCursors::set(..., None)` retires a completed prefix immediately, this
/// only reclaims repositories that became closed/deleted/non-ready or left
/// GitFS. A full sweep of N retained cursors takes `ceil(N / batch)` rounds, so
/// pruning is finite work bounded independently of the candidate page.
pub(crate) const PULL_CURSOR_PRUNE_BATCH: usize = 128;

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
/// State is proportional to the repositories that currently have an unfinished
/// multi-page open-PR prefix, not to history: `set(..., None)` removes a
/// completed entry immediately and each repository keeps exactly one entry (no
/// FIFO of old pages). There is deliberately no age TTL or capacity eviction,
/// because either would silently reset an active prefix whenever more than the
/// old fixed cap of repositories were busy or a long sweep outlived the TTL.
/// A rotating, bounded prune instead retires only repository IDs whose row is
/// deleted, not `ready`, not GitFS-backed, or no longer has an open pull. The
/// prune never treats a repository outside the current 16-row candidate page as
/// inactive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PullCursor {
    after: i64,
    /// Global monotonic tag captured when this entry was written. An async prune
    /// result only removes an entry whose tag still matches, so a cursor that was
    /// advanced or recreated after the eligibility query cannot be deleted.
    generation: u64,
}

#[derive(Default)]
struct CursorState {
    entries: BTreeMap<Uuid, PullCursor>,
    /// Exclusive lower bound of the next rotating prune window. The BTreeMap
    /// range below gives O(log N + batch) selection without copying every key.
    prune_after: Option<Uuid>,
    generation: u64,
}

#[derive(Clone, Default)]
pub(crate) struct PullCursors(Arc<Mutex<CursorState>>);

/// One bounded inspect window over the cursor keys. `candidates` carries the
/// generation observed under the lock, which fences the later removal pass.
struct CursorPruneBatch {
    candidates: Vec<(Uuid, u64)>,
}

impl PullCursors {
    pub(crate) fn after(&self, repository_id: Uuid) -> Option<i64> {
        let cursors = self.0.lock().expect("pull cursor poisoned");
        cursors.entries.get(&repository_id).map(|cursor| cursor.after)
    }

    pub(crate) fn set(&self, repository_id: Uuid, after: Option<i64>) {
        let mut cursors = self.0.lock().expect("pull cursor poisoned");
        match after {
            Some(number) => {
                cursors.generation = cursors.generation.wrapping_add(1);
                let generation = cursors.generation;
                // Replace in place: one current entry per repository, never a
                // growing chain of stale pages from earlier rounds.
                cursors.entries.insert(repository_id, PullCursor { after: number, generation });
            }
            None => {
                // A repository that reached the last page has no unfinished
                // prefix, so its state is reclaimed immediately, not by a later
                // eviction sweep.
                cursors.entries.remove(&repository_id);
            }
        }
    }

    /// Select at most `limit` cursor IDs in ascending repository order, starting
    /// after the rotating bound and wrapping once. Each candidate carries the
    /// generation seen while holding the lock.
    fn take_prune_batch(&self, limit: usize) -> CursorPruneBatch {
        let mut cursors = self.0.lock().expect("pull cursor poisoned");
        let limit = limit.max(1);
        let total = cursors.entries.len();
        if total == 0 {
            cursors.prune_after = None;
            return CursorPruneBatch { candidates: Vec::new() };
        }
        let after = cursors.prune_after;
        let mut candidates = Vec::with_capacity(limit.min(total));
        if let Some(after) = after {
            for (&repository_id, cursor) in cursors.entries.range((Bound::Excluded(after), Bound::Unbounded)) {
                if candidates.len() == limit {
                    break;
                }
                candidates.push((repository_id, cursor.generation));
            }
            if candidates.len() < limit {
                for (&repository_id, cursor) in cursors.entries.range(..) {
                    if candidates.len() == limit || Some(repository_id) == after {
                        break;
                    }
                    candidates.push((repository_id, cursor.generation));
                }
            }
        } else {
            for (&repository_id, cursor) in cursors.entries.range(..) {
                if candidates.len() == limit {
                    break;
                }
                candidates.push((repository_id, cursor.generation));
            }
        }
        // Reset after a full sweep so the next round starts from the smallest
        // retained key; otherwise continue strictly after the last inspected
        // key. A removed key remains a valid ordering bound.
        cursors.prune_after =
            if candidates.len() >= total { None } else { candidates.last().map(|(repository_id, _)| *repository_id) };
        CursorPruneBatch { candidates }
    }

    /// Apply an eligibility result. An `Err` retains every cursor; a candidate is
    /// removed only when the database reported it ineligible *and* its entry
    /// generation is unchanged, so a concurrent advance/recreate wins.
    fn apply_prune_outcome(&self, batch: CursorPruneBatch, outcome: Result<Vec<Uuid>, Error>) -> Result<usize, Error> {
        let ineligible = outcome?;
        let mut cursors = self.0.lock().expect("pull cursor poisoned");
        let mut removed = 0;
        for (repository_id, generation) in batch.candidates {
            if !ineligible.contains(&repository_id) {
                continue;
            }
            let unchanged = cursors.entries.get(&repository_id).is_some_and(|cursor| cursor.generation == generation);
            if unchanged && cursors.entries.remove(&repository_id).is_some() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Run one bounded prune page. Query errors are returned and leave the state
    /// untouched; the caller continues the scan and retries on a later round.
    pub(crate) async fn prune(&self, state: &AppState) -> Result<usize, Error> {
        let batch = self.take_prune_batch(PULL_CURSOR_PRUNE_BATCH);
        if batch.candidates.is_empty() {
            return Ok(0);
        }
        let repository_ids: Vec<Uuid> = batch.candidates.iter().map(|(id, _)| *id).collect();
        let outcome = ineligible_cursor_repositories(state, &repository_ids).await;
        self.apply_prune_outcome(batch, outcome)
    }
}

/// Returns the subset of `repository_ids` that must no longer keep a PR cursor:
/// the repository row is gone, not `ready`, no longer GitFS-backed, or has no
/// open pull left. The array is bounded by `PULL_CURSOR_PRUNE_BATCH`, the pool's
/// statement timeout bounds the query, and no candidate-page state is consulted.
async fn ineligible_cursor_repositories(state: &AppState, repository_ids: &[Uuid]) -> Result<Vec<Uuid>, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT c.repository_id FROM unnest($1::uuid[]) AS c(repository_id) \
             WHERE NOT EXISTS ( \
               SELECT 1 FROM repositories r \
               WHERE r.id=c.repository_id AND r.state='ready' AND r.storage_backend='gitfs' \
                 AND EXISTS (SELECT 1 FROM forge_pulls p \
                             WHERE p.repository_id=r.id AND p.state='open') \
             )",
            &[&repository_ids],
        )
        .await
        .map_err(Error::internal)?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
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
            // Rotate one bounded eligibility page per scan. The cursor window is
            // independent of `candidates`: repositories outside this round's
            // 16-row page are not evidence that their PR prefix is inactive.
            // A failed prune keeps every cursor and does not fail the scan.
            if let Err(error) = self.pull_cursors.prune(state).await {
                eprintln!("rootyard: webhook pull cursor prune deferred ({})", error.1);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_ids(cursors: &PullCursors) -> Vec<Uuid> {
        cursors.0.lock().expect("pull cursor poisoned").entries.keys().copied().collect()
    }

    #[test]
    fn completed_prefix_is_removed_at_once_and_replaced_in_place() {
        let cursors = PullCursors::default();
        let repository_id = Uuid::new_v4();
        cursors.set(repository_id, Some(17));
        assert_eq!(cursors.after(repository_id), Some(17));
        // A later page of the same repository replaces the entry rather than
        // appending, so a long active prefix cannot leak duplicate state.
        cursors.set(repository_id, Some(33));
        assert_eq!(cursors.after(repository_id), Some(33));
        assert_eq!(stored_ids(&cursors), vec![repository_id]);
        // Reaching the last page reclaims state immediately.
        cursors.set(repository_id, None);
        assert_eq!(cursors.after(repository_id), None);
        assert!(stored_ids(&cursors).is_empty());
    }

    #[test]
    fn retained_cursors_are_not_capacity_evicted() {
        let cursors = PullCursors::default();
        let total = 4096 + 3;
        let mut repository_ids = Vec::with_capacity(total);
        for _ in 0..total {
            let repository_id = Uuid::new_v4();
            cursors.set(repository_id, Some(PULL_RECONCILE_LIMIT));
            repository_ids.push(repository_id);
        }
        // Repeated rounds whose eligibility query finds nothing to retire must
        // retain every eligible cursor, including all keys above the old 4096
        // capacity. A capacity policy would have silently dropped three here.
        for _ in 0..64 {
            let batch = cursors.take_prune_batch(PULL_CURSOR_PRUNE_BATCH);
            assert!(!batch.candidates.is_empty());
            assert!(batch.candidates.len() <= PULL_CURSOR_PRUNE_BATCH);
            assert_eq!(cursors.apply_prune_outcome(batch, Ok(Vec::new())).unwrap(), 0);
        }
        assert_eq!(stored_ids(&cursors).len(), total);
        for repository_id in repository_ids {
            assert_eq!(cursors.after(repository_id), Some(PULL_RECONCILE_LIMIT));
        }
    }

    #[test]
    fn prune_retires_cleanup_candidates_but_preserves_a_concurrent_update() {
        let cursors = PullCursors::default();
        let closed = Uuid::new_v4();
        let backend_changed = Uuid::new_v4();
        let deleted = Uuid::new_v4();
        let updated = Uuid::new_v4();
        let active = Uuid::new_v4();
        for repository_id in [closed, backend_changed, deleted, updated, active] {
            cursors.set(repository_id, Some(PULL_RECONCILE_LIMIT));
        }
        let batch = cursors.take_prune_batch(PULL_CURSOR_PRUNE_BATCH);
        assert_eq!(batch.candidates.len(), 5);
        // The database answer was computed before this repository's next page
        // advanced. The generation fence must keep the newer cursor.
        cursors.set(updated, Some(PULL_RECONCILE_LIMIT * 2));
        let removed = cursors.apply_prune_outcome(batch, Ok(vec![closed, backend_changed, deleted, updated])).unwrap();
        assert_eq!(removed, 3);
        assert_eq!(cursors.after(closed), None);
        assert_eq!(cursors.after(backend_changed), None);
        assert_eq!(cursors.after(deleted), None);
        assert_eq!(cursors.after(updated), Some(PULL_RECONCILE_LIMIT * 2));
        assert_eq!(cursors.after(active), Some(PULL_RECONCILE_LIMIT));
    }

    #[test]
    fn prune_query_error_retains_every_cursor() {
        let cursors = PullCursors::default();
        let repository_ids: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
        for repository_id in &repository_ids {
            cursors.set(*repository_id, Some(PULL_RECONCILE_LIMIT));
        }
        let batch = cursors.take_prune_batch(PULL_CURSOR_PRUNE_BATCH);
        let result = cursors.apply_prune_outcome(batch, Err(Error::internal("prune query failed")));
        assert!(result.is_err());
        assert_eq!(stored_ids(&cursors).len(), repository_ids.len());
        for repository_id in repository_ids {
            assert_eq!(cursors.after(repository_id), Some(PULL_RECONCILE_LIMIT));
        }
    }

    #[test]
    fn rotating_batches_reach_later_ineligible_ids_without_full_key_copy() {
        let cursors = PullCursors::default();
        let mut repository_ids: Vec<Uuid> = (0..(PULL_CURSOR_PRUNE_BATCH * 2 + 5)).map(|_| Uuid::new_v4()).collect();
        repository_ids.sort();
        for repository_id in &repository_ids {
            cursors.set(*repository_id, Some(PULL_RECONCILE_LIMIT));
        }
        let target = *repository_ids.last().unwrap();
        let mut removed = 0;
        for _ in 0..3 {
            let batch = cursors.take_prune_batch(PULL_CURSOR_PRUNE_BATCH);
            assert!(batch.candidates.len() <= PULL_CURSOR_PRUNE_BATCH);
            removed += cursors.apply_prune_outcome(batch, Ok(vec![target])).unwrap();
        }
        assert_eq!(removed, 1);
        assert_eq!(cursors.after(target), None);
        assert_eq!(stored_ids(&cursors).len(), repository_ids.len() - 1);
    }
}
