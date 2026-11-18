//! Private source-only barrier, fault and waiter scoping for snapshot cases.
//!
//! An armed barrier is matched by exact repository, exact production phase and
//! the owned per-case application_name nonce. Unrelated B2 repack cases use a
//! different repository/application_name and therefore bypass this module
//! without writing or reading an owned release file.

use anyhow::{Result, bail, ensure};
use std::{
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use tokio_postgres::Client;
use uuid::Uuid;

static BARRIER: Mutex<Option<BarrierSpec>> = Mutex::new(None);
static FAULT: Mutex<Option<FaultSpec>> = Mutex::new(None);
static TEST_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

#[derive(Clone)]
struct BarrierSpec {
    dir: PathBuf,
    repo: Uuid,
    point: String,
    appname: String,
    nonce: String,
}

impl BarrierSpec {
    fn marker(&self, suffix: &str) -> PathBuf {
        self.dir.join(format!("{}.{}.{}.{}", self.point, self.nonce, self.repo, suffix))
    }

    fn matches(&self, point: &str, repo: Uuid, appname: &str) -> bool {
        self.point == point && self.repo == repo && self.appname == appname
    }
}

#[derive(Clone)]
struct FaultSpec {
    point: String,
    repo: Uuid,
}

pub(super) struct BarrierCase {
    spec: BarrierSpec,
}

impl BarrierCase {
    pub(super) fn arm(dir: PathBuf, repo: Uuid, point: &str, appname: &str, nonce: &str) -> Self {
        let spec =
            BarrierSpec { dir, repo, point: point.to_owned(), appname: appname.to_owned(), nonce: nonce.to_owned() };
        *BARRIER.lock().expect("snapshot retention barrier lock") = Some(spec.clone());
        Self { spec }
    }

    pub(super) async fn wait_ready(&self) {
        let marker = self.spec.marker("ready");
        for _ in 0..3000 {
            if marker.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("snapshot retention barrier point '{}' was not reached by the owned actor", self.spec.point);
    }

    pub(super) fn assert_read_committed(&self) {
        let isolation = std::fs::read_to_string(self.spec.marker("isolation"))
            .expect("the production barrier must record actual transaction isolation");
        assert_eq!(isolation.trim(), "read committed", "actual transaction isolation at {}", self.spec.point);
    }

    pub(super) fn release(&self) {
        let _ = std::fs::write(self.spec.marker("release"), b"");
    }
}

impl Drop for BarrierCase {
    fn drop(&mut self) {
        {
            let mut slot = BARRIER.lock().expect("snapshot retention barrier lock");
            let same = slot.as_ref().is_some_and(|spec| {
                spec.matches(&self.spec.point, self.spec.repo, &self.spec.appname) && spec.nonce == self.spec.nonce
            });
            if same {
                *slot = None;
            }
        }
        self.release();
    }
}

pub(crate) fn arm_fault(point: &str, repo: Uuid) {
    *FAULT.lock().expect("snapshot retention fault lock") = Some(FaultSpec { point: point.to_owned(), repo });
}

pub(crate) fn clear_fault() {
    *FAULT.lock().expect("snapshot retention fault lock") = None;
}

pub(crate) fn fault(point: &str, repo: Uuid) -> Result<()> {
    let fault = { FAULT.lock().expect("snapshot retention fault lock").clone() };
    if fault.as_ref().is_some_and(|fault| fault.point == point && fault.repo == repo) {
        bail!("snapshot retention test fault before commit");
    }
    Ok(())
}

/// Test seam that records actual transaction isolation after matching the
/// exact repository, phase and owned application_name. Unmatched calls return
/// before any filesystem access.
pub(crate) async fn barrier_tx(point: &str, repo: Uuid, transaction: &tokio_postgres::Transaction<'_>) -> Result<()> {
    let spec = { BARRIER.lock().expect("snapshot retention barrier lock").clone() };
    let Some(spec) = spec else {
        return Ok(());
    };
    if spec.point != point || spec.repo != repo {
        return Ok(());
    }
    let appname: String = transaction.query_one("SELECT current_setting('application_name')", &[]).await?.get(0);
    if !spec.matches(point, repo, &appname) {
        return Ok(());
    }
    std::fs::create_dir_all(&spec.dir)?;
    let isolation: String = transaction.query_one("SHOW transaction_isolation", &[]).await?.get(0);
    std::fs::write(spec.marker("isolation"), isolation)?;
    std::fs::write(spec.marker("ready"), b"")?;
    wait_release(&spec).await
}

async fn wait_release(spec: &BarrierSpec) -> Result<()> {
    let release = spec.marker("release");
    let started = Instant::now();
    while !release.exists() {
        ensure!(started.elapsed().as_secs() < 30, "snapshot retention test barrier timeout");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

pub(super) fn case_nonce() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_owned()
}

pub(super) fn actor_appname(nonce: &str, repo: Uuid, role: &str) -> String {
    assert!(!nonce.is_empty() && nonce.len() <= 16, "test application_name nonce must be bounded");
    let appname = format!("rs-{nonce}-{repo}-{role}");
    assert!(appname.len() <= 63, "test application_name exceeds the PostgreSQL limit");
    appname
}

fn exact_actor_wait(
    expected_appname: &str,
    repo: Uuid,
    expected_phase: &str,
    candidate_appname: &str,
    wait_event: Option<&str>,
    query: &str,
) -> bool {
    candidate_appname == expected_appname
        && expected_appname.contains(&repo.to_string())
        && wait_event == Some("Lock")
        && query.contains(expected_phase)
}

/// Observe only the exact controlled actor application_name backend. The repo
/// UUID and nonce are embedded in the application_name, so the admin session
/// and unrelated parallel waiters cannot satisfy the proof.
pub(super) async fn wait_for_actor_lock_wait(
    admin: &Client,
    appname: &str,
    repo: Uuid,
    expected_phase: &str,
    attempts: usize,
) {
    assert!(appname.contains(&repo.to_string()), "actor application_name must bind the repository");
    let phase = format!("%{expected_phase}%");
    for _ in 0..attempts {
        let row = admin
            .query_opt(
                "SELECT pid FROM pg_stat_activity \
                 WHERE datname=current_database() AND application_name=$1 \
                 AND state='active' AND wait_event_type='Lock' AND query ILIKE $2 \
                 ORDER BY backend_start DESC LIMIT 1",
                &[&appname, &phase],
            )
            .await
            .unwrap();
        if let Some(row) = row {
            let pid: i32 = row.get(0);
            let row = admin
                .query_one(
                    "SELECT application_name,wait_event_type,query FROM pg_stat_activity \
                     WHERE pid=$1 AND datname=current_database()",
                    &[&pid],
                )
                .await
                .unwrap();
            let candidate: String = row.get(0);
            let wait_event: Option<String> = row.get(1);
            let query: String = row.get(2);
            if exact_actor_wait(appname, repo, expected_phase, &candidate, wait_event.as_deref(), &query) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not observe the exact actor application_name waiting for {expected_phase}");
}

pub(super) async fn test_lock() -> AsyncMutexGuard<'static, ()> {
    TEST_LOCK.lock().await
}

pub(super) struct HookGuard;

impl HookGuard {
    pub(super) fn new() -> Self {
        *BARRIER.lock().expect("snapshot retention barrier lock") = None;
        clear_fault();
        Self
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        *BARRIER.lock().expect("snapshot retention barrier lock") = None;
        clear_fault();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_unrelated_point_repo_and_actor_are_rejected() {
        let repo = Uuid::new_v4();
        let other = Uuid::new_v4();
        let nonce = case_nonce();
        let appname = actor_appname(&nonce, repo, "snap");
        let spec = BarrierSpec {
            dir: PathBuf::from("unused"),
            repo,
            point: "snapshot-after-select".to_owned(),
            appname: appname.clone(),
            nonce: nonce.clone(),
        };
        assert!(spec.matches("snapshot-after-select", repo, &appname));
        assert!(!spec.matches("repack-after-lock", repo, &appname));
        assert!(!spec.matches("snapshot-after-select", other, &appname));
        assert!(!spec.matches("snapshot-after-select", repo, "rs-unrelated"));
        let mut other_case = spec.clone();
        other_case.nonce = case_nonce();
        assert_ne!(spec.marker("release"), other_case.marker("release"));
    }

    #[test]
    fn negative_unrelated_waiter_is_rejected() {
        let repo = Uuid::new_v4();
        let other = Uuid::new_v4();
        let nonce = case_nonce();
        let appname = actor_appname(&nonce, repo, "snap");
        let query = "SELECT generation FROM pando_lab.repositories WHERE id=$1 FOR SHARE";
        assert!(exact_actor_wait(&appname, repo, "FOR SHARE", &appname, Some("Lock"), query));
        assert!(!exact_actor_wait(&appname, repo, "FOR SHARE", "rs-unrelated", Some("Lock"), query));
        assert!(!exact_actor_wait(&appname, repo, "FOR SHARE", &appname, Some("ClientRead"), query));
        assert!(!exact_actor_wait(&appname, repo, "FOR UPDATE", &appname, Some("Lock"), query));
        assert!(!exact_actor_wait(&appname, other, "FOR SHARE", &appname, Some("Lock"), query));
    }

    #[test]
    fn actor_names_bind_nonce_and_repo_within_limit() {
        let repo = Uuid::new_v4();
        let nonce = case_nonce();
        for role in ["snap", "repack", "admin"] {
            let appname = actor_appname(&nonce, repo, role);
            assert!(appname.contains(&nonce));
            assert!(appname.contains(&repo.to_string()));
            assert!(appname.len() <= 63);
        }
    }
}
