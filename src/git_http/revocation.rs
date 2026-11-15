//! Bounded in-flight transfer reauthorization and process-group cancellation.
use crate::{AppState, auth, db::Identity, db::Repository};
use axum::body::Body;
use futures_util::StreamExt;
use std::{future::Future, io, process::Stdio, sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, time::Instant};

use super::process::{GitCommandFailed, Process};

pub const REVOCATION_BOUND_ENV: &str = "ROOTYARD_TRANSFER_REVOCATION_BOUND_MS";
pub const DEFAULT_REVOCATION_BOUND_MS: u64 = 3_000;
pub const MIN_REVOCATION_BOUND_MS: u64 = 300;
pub const MAX_REVOCATION_BOUND_MS: u64 = 60_000;

/// Derived timing budget ensuring detection + DB check + child termination fit within `total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationBound {
    pub total: Duration,
    pub check_interval: Duration,
    pub reauth_timeout: Duration,
    pub stop_grace: Duration,
}

impl RevocationBound {
    pub fn from_ms(total_ms: u64) -> Result<Self, String> {
        if !(MIN_REVOCATION_BOUND_MS..=MAX_REVOCATION_BOUND_MS).contains(&total_ms) {
            return Err(format!(
                "{REVOCATION_BOUND_ENV} must be between {MIN_REVOCATION_BOUND_MS} and {MAX_REVOCATION_BOUND_MS} ms"
            ));
        }
        let check_ms = (total_ms / 4).clamp(50, 5_000);
        let reauth_ms = (total_ms / 3).clamp(100, 2_000);
        let stop_ms = (total_ms / 4).clamp(50, 1_000);
        Ok(Self {
            total: Duration::from_millis(total_ms),
            check_interval: Duration::from_millis(check_ms),
            reauth_timeout: Duration::from_millis(reauth_ms),
            stop_grace: Duration::from_millis(stop_ms),
        })
    }

    pub fn from_raw(raw: Option<&str>) -> Result<Self, String> {
        let ms = match raw {
            Some(v) => v.trim().parse::<u64>().map_err(|_| format!("invalid {REVOCATION_BOUND_ENV}"))?,
            None => DEFAULT_REVOCATION_BOUND_MS,
        };
        Self::from_ms(ms)
    }
}

pub(crate) fn validate_env() -> anyhow::Result<RevocationBound> {
    let raw = std::env::var(REVOCATION_BOUND_ENV).ok();
    RevocationBound::from_raw(raw.as_deref()).map_err(anyhow::Error::msg)
}

pub(crate) fn bound() -> RevocationBound {
    validate_env().unwrap_or_else(|_| {
        RevocationBound::from_ms(DEFAULT_REVOCATION_BOUND_MS).expect("default revocation bound valid")
    })
}

pub(crate) enum BoundedOutcome<T> {
    Ready(T),
    Revoked(crate::Error),
    TimedOut,
}

/// Executes a bounded boolean authority check, failing closed on errors or timeout.
pub(crate) async fn check_bounded<F>(timeout: Duration, check: F) -> Result<(), crate::Error>
where
    F: Future<Output = Result<bool, crate::Error>>,
{
    match tokio::time::timeout(timeout, check).await {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err(crate::Error::unauthorized()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(crate::Error(axum::http::StatusCode::SERVICE_UNAVAILABLE, "authority check timed out")),
    }
}

/// Re-verifies active Git HTTP or CI checkout authority within `reauth_timeout`, preserving HTTP status classification.
pub(crate) async fn verify_transfer_authority(
    state: &AppState,
    identity: Option<&Identity>,
    job_plan: Option<&crate::ci_checkouts::Plan>,
    job_principal: Option<&crate::ci_checkouts::authority::CheckoutPrincipal>,
    repo: &Repository,
    write: bool,
    reauth_timeout: Duration,
) -> Result<(), crate::Error> {
    if let Some(plan) = job_plan {
        let digest = match job_principal {
            Some(crate::ci_checkouts::authority::CheckoutPrincipal::User(user)) => &user.token_digest,
            Some(crate::ci_checkouts::authority::CheckoutPrincipal::Integration { token_digest, .. }) => token_digest,
            None => return Err(crate::Error::unauthorized()),
        };
        check_bounded(
            reauth_timeout,
            crate::ci_checkouts::still_authorized(state, plan.job_id, digest, repo.id, repo.storage_generation),
        )
        .await
    } else {
        let user = identity.ok_or_else(crate::Error::unauthorized)?;
        let action = if write {
            crate::token_scopes::RepoAction::ContentsWrite
        } else {
            crate::token_scopes::RepoAction::ContentsRead
        };
        let role = if write { auth::Role::Write } else { auth::Role::Read };
        match tokio::time::timeout(
            reauth_timeout,
            auth::verify_active_transfer(&state.pool, user, repo.id, repo.storage_generation, action, role),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(crate::Error(axum::http::StatusCode::SERVICE_UNAVAILABLE, "authority check timed out")),
        }
    }
}

/// Stream-loop wrapper returning `io::Result<()>` on revocation or authority outage.
pub(crate) async fn transfer_authorized(
    state: &AppState,
    identity: Option<&Identity>,
    job_plan: Option<&crate::ci_checkouts::Plan>,
    job_principal: Option<&crate::ci_checkouts::authority::CheckoutPrincipal>,
    repo: &Repository,
    write: bool,
    reauth_timeout: Duration,
) -> io::Result<()> {
    verify_transfer_authority(state, identity, job_plan, job_principal, repo, write, reauth_timeout)
        .await
        .map_err(|error| io::Error::other(error.1))
}

/// Races `op` against periodic reauthorization checks and an overall `deadline`.
pub(crate) async fn await_with_reauth<T, Op, Check, CheckFut>(
    bound: RevocationBound,
    deadline: Instant,
    op: Op,
    mut check: Check,
) -> BoundedOutcome<T>
where
    Op: Future<Output = T>,
    Check: FnMut() -> CheckFut,
    CheckFut: Future<Output = Result<(), crate::Error>>,
{
    tokio::pin!(op);
    let mut tick = tokio::time::interval_at(Instant::now() + bound.check_interval, bound.check_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let sleep = tokio::time::sleep_until(deadline);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            value = &mut op => return BoundedOutcome::Ready(value),
            _ = tick.tick() => {
                if let Err(error) = check().await {
                    return BoundedOutcome::Revoked(error);
                }
            }
            _ = &mut sleep => return BoundedOutcome::TimedOut,
        }
    }
}

/// Collects subprocess stdout up to `limit` while rechecking authorization on `bound.check_interval`.
pub(crate) async fn collect_git_output_reauthorized<Check, CheckFut>(
    mut command: tokio::process::Command,
    limit: usize,
    timeout: Duration,
    bound: RevocationBound,
    mut check: Check,
) -> anyhow::Result<Vec<u8>>
where
    Check: FnMut() -> CheckFut,
    CheckFut: Future<Output = io::Result<()>>,
{
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = child.id().ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let drain = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        while matches!(stderr.read(&mut bytes).await, Ok(n) if n > 0) {}
    });
    let mut process = Process { child, input: None, stderr: drain, pid };
    let deadline = Instant::now() + timeout;
    let mut tick = tokio::time::interval_at(Instant::now() + bound.check_interval, bound.check_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut output = Vec::new();
    let mut buf = [0u8; 8192];
    let result: anyhow::Result<()> = async {
        loop {
            let n = tokio::select! {
                res = stdout.read(&mut buf) => res?,
                _ = tick.tick() => {
                    check().await?;
                    continue;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(anyhow::Error::new(io::Error::other("maintenance Git command timed out")));
                }
            };
            if n == 0 {
                break;
            }
            if output.len().saturating_add(n) > limit {
                return Err(anyhow::Error::new(io::Error::other("maintenance output exceeds limit")));
            }
            output.extend_from_slice(&buf[..n]);
        }
        let status = match await_with_reauth(bound, deadline, process.finish(), || {
            let fut = check();
            async move { fut.await.map_err(crate::Error::internal) }
        })
        .await
        {
            BoundedOutcome::Ready(res) => res?,
            BoundedOutcome::Revoked(err) => return Err(anyhow::Error::new(io::Error::other(err.1))),
            BoundedOutcome::TimedOut => {
                return Err(anyhow::Error::new(io::Error::other("maintenance Git command timed out")));
            }
        };
        if !status.success() {
            return Err(anyhow::Error::new(GitCommandFailed { exit: status.code() }));
        }
        check().await?;
        Ok(())
    }
    .await;
    process.stop_with_grace(bound.stop_grace).await;
    result?;
    Ok(output)
}

/// Streams a download `Body` while rechecking authorization on `bound.check_interval` and backpressure.
pub(crate) fn stream_body_with_reauth<Check, CheckFut>(
    state: Arc<AppState>,
    body: Body,
    bound: RevocationBound,
    check: Check,
) -> Body
where
    Check: FnMut() -> CheckFut + Send + 'static,
    CheckFut: Future<Output = io::Result<()>> + Send,
{
    stream_body_with_counters(state.transfer_metrics.clone(), body, bound, check)
}

fn stream_body_with_counters<Check, CheckFut>(
    metrics: Arc<crate::metrics::TransferCounters>,
    body: Body,
    bound: RevocationBound,
    mut check: Check,
) -> Body
where
    Check: FnMut() -> CheckFut + Send + 'static,
    CheckFut: Future<Output = io::Result<()>> + Send,
{
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, io::Error>>(8);
    let aborted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let aborted_tx = aborted.clone();
    tokio::spawn(async move {
        let mut source = body.into_data_stream();
        let mut tick = tokio::time::interval_at(Instant::now() + bound.check_interval, bound.check_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut pending = None;
        let mut failure: Option<io::Error> = None;
        loop {
            if let Some(bytes) = pending.take() {
                tokio::select! {
                    _ = tick.tick() => {
                        pending = Some(bytes);
                        if let Err(err) = check().await {
                            failure = Some(err);
                            break;
                        }
                    }
                    permit = sender.reserve() => match permit {
                        Ok(permit) => {
                            if let Err(err) = check().await {
                                failure = Some(err);
                                break;
                            }
                            permit.send(Ok(bytes));
                        }
                        Err(_) => break,
                    },
                }
            } else {
                tokio::select! {
                    _ = tick.tick() => {
                        if let Err(err) = check().await {
                            failure = Some(err);
                            break;
                        }
                    }
                    _ = sender.closed() => break,
                    next = source.next() => match next {
                        Some(Ok(bytes)) => pending = Some(bytes),
                        Some(Err(err)) => {
                            failure = Some(io::Error::other(err));
                            break;
                        }
                        None => break,
                    },
                }
            }
        }
        if let Some(err) = failure {
            aborted_tx.store(true, std::sync::atomic::Ordering::Release);
            metrics.record_failure();
            let _ = sender.try_send(Err(err));
        }
    });
    let stream = futures_util::stream::unfold((receiver, aborted, false), |(mut receiver, aborted, done)| async move {
        if done {
            return None;
        }
        if aborted.load(std::sync::atomic::Ordering::Acquire) {
            return Some((Err(io::Error::other("transfer authorization changed")), (receiver, aborted, true)));
        }
        match receiver.recv().await {
            Some(Ok(_)) if aborted.load(std::sync::atomic::Ordering::Acquire) => {
                Some((Err(io::Error::other("transfer authorization changed")), (receiver, aborted, true)))
            }
            Some(item @ Err(_)) => Some((item, (receiver, aborted, true))),
            Some(item) => Some((item, (receiver, aborted, false))),
            None if aborted.load(std::sync::atomic::Ordering::Acquire) => {
                Some((Err(io::Error::other("transfer authorization changed")), (receiver, aborted, true)))
            }
            None => None,
        }
    });
    Body::from_stream(stream)
}

#[cfg(test)]
#[path = "revocation_tests.rs"]
mod tests;
