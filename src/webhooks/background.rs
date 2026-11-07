//! Durable, fair polling repairs lost wakeups and progresses webhook retries.
//!
//! A round reconciles Pull Requests for every candidate repository first and
//! only then performs network delivery. The phases are separate so a blocked
//! receiver cannot delay an open PR update, and both phases bound per-repository
//! work, concurrency and cancellation.
use crate::{
    AppState, Error,
    pulls::models::{PULL_FIELDS, PullRequest, resolve_ref_oid},
    webhooks::{
        delivery::{
            current_unix_seconds, dispatch_due_deliveries_until, on_pull_synchronized, sync_outbox_events_bounded,
        },
        scheduling::{
            Candidate, DELIVERY_LIMIT, DELIVERY_REPOSITORY_BUDGET, OUTBOX_BACKFILL_BUDGET, OUTBOX_BACKFILL_LIMIT,
            PULL_RECONCILE_LIMIT, PULL_REPAIR_LIMIT, PullCursors, REPOSITORY_PHASE_TIMEOUT, RoundSummary, SCAN_TIMEOUT,
            SCAN_WORK_BUDGET, Scheduler, run_bounded,
        },
    },
};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// One absolute timeline for a scan. The worker takes the anchor before the
/// candidate query, so PostgreSQL latency is charged to the work window instead
/// of silently consuming the reserve that protects an already-started send.
#[derive(Clone, Copy, Debug)]
struct ScanWindow {
    work_deadline: Instant,
    scan_deadline: Instant,
}

impl ScanWindow {
    fn starting_at(start: Instant) -> Self {
        let work_deadline = start + SCAN_WORK_BUDGET;
        let scan_deadline = start + SCAN_TIMEOUT;
        debug_assert!(scan_deadline.saturating_duration_since(work_deadline) >= Duration::from_secs(60));
        Self { work_deadline, scan_deadline }
    }

    /// New work may start only inside this window. Requests already in flight
    /// keep their own hook transport deadline and are not cancelled here.
    fn work_open(&self, now: Instant) -> bool {
        now < self.work_deadline
    }

    /// Time after the work window that remains for one in-flight delivery.
    #[cfg(test)]
    fn tail(&self) -> Duration {
        self.scan_deadline.saturating_duration_since(self.work_deadline)
    }
}

/// Polling is the durable repair path. A wake only shortens latency; failures
/// leave PostgreSQL rows eligible and are surfaced once per outage.
pub async fn worker(state: Arc<AppState>, stop: CancellationToken) {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut scheduler = Scheduler::default();
    let mut unavailable = false;
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = tick.tick() => {},
            _ = state.dispatch.local.notified() => {},
        }
        // One anchor for both the outer timeout and the work budget. Taking it
        // before the candidate query is what makes the 60 s tail real.
        let window = ScanWindow::starting_at(Instant::now());
        let result = tokio::select! {
            _ = stop.cancelled() => break,
            result = tokio::time::timeout_at(window.scan_deadline, scan_round(&state, &mut scheduler, window, &stop)) => result,
        };
        let failed = !matches!(result, Ok(Ok(ref summary)) if summary.failures == 0);
        if failed && !unavailable {
            eprintln!("rootyard: webhook synchronization unavailable; durable retry scheduled");
        }
        unavailable = failed;
        tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(Duration::from_millis(25)) => {} }
    }
}

async fn scan_round(
    state: &Arc<AppState>,
    scheduler: &mut Scheduler,
    window: ScanWindow,
    stop: &CancellationToken,
) -> Result<RoundSummary, Error> {
    // The candidate query itself runs inside the work window: `window` was
    // anchored by the worker before this future started.
    let candidates = scheduler.next_page(state).await?;
    let mut summary = RoundSummary::default();
    // Stop starting network work early enough that an already-started request
    // can use its full hook timeout before the outer SCAN_TIMEOUT fires. Phase
    // one is independently bounded far below this point.
    let round_deadline = window.work_deadline;

    // Phase one is PostgreSQL/native-Git only. No webhook receive socket is
    // touched here, so a slow receiver on an earlier repository cannot delay a
    // later repository's PR head/base reconciliation.
    let pulls: Vec<Candidate> =
        candidates.iter().copied().filter(|candidate| candidate.has_open_pulls && candidate.gitfs_ready).collect();
    if !pulls.is_empty() && !stop.is_cancelled() && window.work_open(Instant::now()) {
        let state = Arc::clone(state);
        let cursors = scheduler.pull_cursors();
        let outcome = run_bounded(stop, &pulls, move |candidate| {
            let state = Arc::clone(&state);
            let cursors = cursors.clone();
            let after = cursors.after(candidate.key.repository_id);
            Box::pin(async move {
                match tokio::time::timeout(
                    REPOSITORY_PHASE_TIMEOUT,
                    reconcile_candidate(&state, candidate, after, &cursors),
                )
                .await
                {
                    Ok(result) => result,
                    // Cancellation drops live local Git children and leases. The
                    // durable pull/outbox/progress rows make the next round safe,
                    // and an uncompleted pull page keeps its old cursor.
                    Err(_) => Ok(()),
                }
            })
        })
        .await;
        summary.merge(outcome);
    }
    if stop.is_cancelled() {
        return Ok(summary);
    }

    // Phase two performs outbox backfill and bounded network sends. If the work
    // window closed while phase one ran, no new backfill or send starts; the
    // remaining tail is reserved for requests that were already in flight.
    let deliveries: Vec<Candidate> = candidates.iter().copied().filter(|candidate| candidate.has_webhooks).collect();
    if !deliveries.is_empty() && window.work_open(Instant::now()) {
        let state = Arc::clone(state);
        let outcome = run_bounded(stop, &deliveries, move |candidate| {
            let state = Arc::clone(&state);
            // No whole-repository timeout here: a legitimate in-flight request
            // may use up to the hook's declared 30 s transport timeout. The
            // shared round deadline only stops starting new sends.
            Box::pin(async move { deliver_candidate(&state, candidate, round_deadline).await })
        })
        .await;
        summary.merge(outcome);
    }
    Ok(summary)
}

async fn reconcile_candidate(
    state: &AppState,
    candidate: Candidate,
    after: Option<i64>,
    cursors: &PullCursors,
) -> Result<(), Error> {
    if !candidate.has_open_pulls || !candidate.gitfs_ready {
        return Ok(());
    }
    let next = reconcile_pull_refs(state, candidate.key.tenant_id, candidate.key.repository_id, after).await?;
    cursors.set(candidate.key.repository_id, next);
    repair_pull_orchestration(state, candidate.key.tenant_id, candidate.key.repository_id).await
}

async fn deliver_candidate(state: &AppState, candidate: Candidate, round_deadline: Instant) -> Result<(), Error> {
    if !candidate.has_webhooks || Instant::now() >= round_deadline {
        return Ok(());
    }
    let tenant_id = candidate.key.tenant_id;
    let repository_id = candidate.key.repository_id;
    // Backfill is a separate, bounded phase before any HTTP starts. Selection
    // is LIMITed to missing (event, hook) pairs and the pool's 5 s statement
    // timeout caps the statement; the outer timeout caps the whole page. Memory
    // follows OUTBOX_BACKFILL_LIMIT, not the repository's active hook count.
    let backfill_deadline = (Instant::now() + OUTBOX_BACKFILL_BUDGET).min(round_deadline);
    let backfill_error = match tokio::time::timeout_at(
        backfill_deadline,
        sync_outbox_events_bounded(state, tenant_id, repository_id, OUTBOX_BACKFILL_LIMIT, backfill_deadline),
    )
    .await
    {
        Ok(Ok(_)) => None,
        Ok(Err(error)) => Some(error),
        // A bounded backfill skip starts no HTTP and leaves pairs durable for
        // the next round, so it must not mark the repository failed.
        Err(_) => None,
    };
    let work_deadline = (Instant::now() + DELIVERY_REPOSITORY_BUDGET).min(round_deadline);
    let dispatched = dispatch_due_deliveries_until(
        state,
        tenant_id,
        repository_id,
        DELIVERY_LIMIT,
        current_unix_seconds(),
        work_deadline,
    )
    .await;
    match (dispatched, backfill_error) {
        (Err(error), _) => Err(error),
        (Ok(_), Some(error)) => Err(error),
        (Ok(_), None) => Ok(()),
    }
}

/// Recover a PR whose row advanced but whose pin, runs, or deliveries did not
/// finish. The marker is written last, after every idempotent side effect, and
/// the bounded LIMIT advances because each repaired pull gains that marker.
async fn repair_pull_orchestration(state: &AppState, tenant: Uuid, repo: Uuid) -> Result<(), Error> {
    if !crate::sharding::transport::is_local_primary_for_repo(state, tenant, repo).await? {
        return Ok(());
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            &format!(
                "SELECT {PULL_FIELDS} FROM forge_pulls p \
                 WHERE p.tenant_id=$1 AND p.repository_id=$2 AND p.state='open' AND NOT EXISTS( \
                   SELECT 1 FROM ci_pull_sync_progress s WHERE s.repository_id=p.repository_id \
                     AND s.pull_number=p.number AND s.pull_version=p.version \
                     AND s.head_oid=p.head_oid AND s.base_oid=p.base_oid \
                     AND s.storage_generation=(SELECT storage_generation FROM repositories \
                       WHERE id=p.repository_id)) ORDER BY p.number LIMIT $3"
            ),
            &[&tenant, &repo, &PULL_REPAIR_LIMIT],
        )
        .await
        .map_err(Error::internal)?;
    drop(client);
    for row in rows {
        let pull = PullRequest::row(&row);
        let action = if pull.version == 1 { "opened" } else { "synchronize" };
        on_pull_synchronized(state, repo, &pull, action).await?;
    }
    Ok(())
}

/// Authoritative Git refs advance an open PR's immutable candidate version after
/// push. The optimistic version guard prevents replacing a concurrent user edit.
///
/// Only pulls with a non-zero outbox ref event that differs from the stored OID
/// are examined, so repositories with many unchanged open PRs do not launch a
/// native Git process per pull on every scan.
async fn reconcile_pull_refs(
    state: &AppState,
    tenant: Uuid,
    repo: Uuid,
    after: Option<i64>,
) -> Result<Option<i64>, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let sql = format!(
        "SELECT {PULL_FIELDS} FROM forge_pulls p \
         WHERE p.tenant_id=$1 AND p.repository_id=$2 AND p.state='open' \
           AND ($3::bigint IS NULL OR p.number > $3) \
         ORDER BY p.number LIMIT $4"
    );
    let rows = client.query(&sql, &[&tenant, &repo, &after, &PULL_RECONCILE_LIMIT]).await.map_err(Error::internal)?;
    drop(client);
    if rows.is_empty() {
        return Ok(None);
    }
    if !crate::sharding::transport::is_local_primary_for_repo(state, tenant, repo).await? {
        return Ok(after);
    }
    let page_len = rows.len();
    let page_full = i64::try_from(page_len).unwrap_or(i64::MAX) == PULL_RECONCILE_LIMIT;
    let mut last_examined = None;
    let mut completed = 0usize;

    // Native Git reads take one process slot, a cross-process read lease and the
    // local reader gate. Capacity exhaustion is a bounded skip, not a failure of
    // every repository in the round.
    let Ok(slot) = tokio::time::timeout(Duration::from_secs(2), state.git_slots.clone().acquire_owned()).await else {
        return Ok(after);
    };
    let _slot = match slot {
        Ok(slot) => slot,
        Err(_) => return Ok(after),
    };
    let deadline = Instant::now() + REPOSITORY_PHASE_TIMEOUT;
    let lease = crate::storage::read_leases::shared(&state.pool, repo, deadline).await?;
    let _read_gate = tokio::time::timeout_at(deadline, state.storage.read_snapshot_lock(repo))
        .await
        .map_err(|_| Error::timeout())?;

    for row in rows {
        if Instant::now() >= deadline {
            break;
        }
        lease.ensure_active()?;
        let pull = PullRequest::row(&row);
        last_examined = Some(pull.number);
        completed += 1;
        let head = match tokio::time::timeout_at(deadline, resolve_ref_oid(state, repo, &pull.head_ref)).await {
            Ok(result) => result?,
            Err(_) => break,
        };
        let base = match tokio::time::timeout_at(deadline, resolve_ref_oid(state, repo, &pull.base_ref)).await {
            Ok(result) => result?,
            Err(_) => break,
        };
        let (Some(head), Some(base)) = (head, base) else {
            continue;
        };
        if head == pull.head_oid && base == pull.base_oid {
            continue;
        }
        lease.ensure_active()?;
        let client = state.pool.get().await.map_err(Error::internal)?;
        let sql = format!(
            "UPDATE forge_pulls SET head_oid=$5,base_oid=$6,version=version+1,updated_at=clock_timestamp() \
             WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 AND version=$4 AND state='open' \
             RETURNING {PULL_FIELDS}"
        );
        let _ = client
            .query_opt(&sql, &[&tenant, &repo, &pull.number, &pull.version, &head, &base])
            .await
            .map_err(Error::internal)?;
        drop(client);
        // Pin/run/delivery orchestration is repair_pull_orchestration's job. The
        // PR version update is the durable handoff: a crash between the two
        // leaves the new version without a completion marker and is repaired.
    }
    let next =
        if completed == page_len { if page_full { last_examined } else { None } } else { last_examined.or(after) };
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_window_charges_candidate_latency_to_the_work_budget() {
        let now = Instant::now();
        let fresh = ScanWindow::starting_at(now);
        assert!(fresh.work_open(now));
        // The reserve for an already-started hook request is real even when the
        // candidate query returns immediately.
        assert!(fresh.tail() >= Duration::from_secs(60));
        assert_eq!(fresh.work_deadline, now + SCAN_WORK_BUDGET);
        assert_eq!(fresh.scan_deadline, now + SCAN_TIMEOUT);

        // A query that consumed almost the whole work budget leaves the window
        // open for a last bounded task.
        let nearly_spent = ScanWindow::starting_at(now - (SCAN_WORK_BUDGET - Duration::from_millis(1)));
        assert!(nearly_spent.work_open(now));

        // Once the anchored budget is exhausted, no new work starts, yet the
        // outer tail still covers a request that was already in flight.
        let spent = ScanWindow::starting_at(now - SCAN_WORK_BUDGET);
        assert!(!spent.work_open(now));
        assert!(spent.scan_deadline.saturating_duration_since(now) >= Duration::from_secs(59));
    }
}
