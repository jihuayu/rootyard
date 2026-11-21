//! Regression matrix for terminal-job rechecks and bounded Git child cleanup.
use crate::harness::{self, Cluster, Repository};
use crate::{Auth, info_refs_status, open_pack_stream, post_checkout};
use anyhow::{Result, ensure};
use reqwest::StatusCode;
use std::{
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::{Notify, Semaphore};
use uuid::Uuid;

const STALL_SCRIPT: &str = r#"#!/bin/sh
scratch=""
for arg in "$@"; do
  case "$arg" in
    *rootyard-s4-view*) scratch="$(dirname "$arg")" ;;
  esac
done
for arg in "$@"; do
  if [ "$arg" = "upload-pack" ] || [ "$arg" = "bundle" ]; then
    sh -c 'trap "" TERM; while :; do sleep 1; done' &
    printf '%s %s %s\n' "$$" "$!" "$scratch" > "__PIDFILE__"
    trap "" TERM
    while :; do sleep 1; done
  fi
done
exec "__REAL_GIT__" "$@"
"#;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

async fn cancel(cluster: &Cluster, repo: &Repository, job: Uuid) -> Result<()> {
    let url = format!("{}/api/repos/{}/{}/ci-checkouts/{job}/cancel", cluster.main, cluster.owner.username, repo.name);
    let response = reqwest::Client::new().post(url).bearer_auth(&cluster.owner.token).send().await?;
    ensure!(response.status().is_success(), "cancel returned {}", response.status());
    Ok(())
}

async fn pin_status(cluster: &Cluster, repo: &Repository, job: Uuid, target: &str) -> Result<StatusCode> {
    let url = format!("{}/api/repos/{}/{}/ci-pins", cluster.main, cluster.owner.username, repo.name);
    let body = serde_json::json!({"job_id": job, "target_oid": target, "storage_generation": repo.generation});
    harness::post_status(&url, &cluster.owner.token, body).await
}

async fn pin_rows_for_job(cluster: &Cluster, repo: &Repository, job: Uuid) -> Result<i64> {
    let sql = "SELECT count(*) FROM s4_ci_retention.ci_pins WHERE repository_id=$1 AND job_id=$2";
    let row = cluster.pool.get().await?.query_one(sql, &[&repo.id, &job]).await?;
    Ok(row.get(0))
}

async fn orphan_active_roots(cluster: &Cluster, repo: &Repository) -> Result<i64> {
    let sql = "SELECT count(*) FROM ref_store_core_root_heads h \
        WHERE h.repository_id=$1 AND h.state='active' \
        AND NOT EXISTS (SELECT 1 FROM s4_ci_retention.ci_pins p \
        WHERE p.repository_id=h.repository_id AND p.retention_root_id=h.root_id AND p.state='pinned')";
    let row = cluster.pool.get().await?.query_one(sql, &[&repo.id]).await?;
    Ok(row.get(0))
}

async fn active_pins(cluster: &Cluster, repo: &Repository) -> Result<i64> {
    let sql = "SELECT count(*) FROM ref_store_core_pins WHERE repository_id=$1 AND state='active'";
    let row = cluster.pool.get().await?.query_one(sql, &[&repo.id]).await?;
    Ok(row.get(0))
}

async fn checkout_status(cluster: &Cluster, repo: &Repository, job: Uuid, target: &str) -> Result<StatusCode> {
    post_checkout(cluster, repo, job, target, now()).await
}

pub async fn terminal_job_race() -> Result<()> {
    let cluster = Cluster::setup().await?;
    let outcome = async {
        let repo = cluster.create_repository("hold-repo", "sha1").await?;
        let base = cluster.push_initial(&repo, &[("a.txt", "retained\n")]).await?;
        let cancelled_job = Uuid::new_v4();
        cancel(&cluster, &repo, cancelled_job).await?;
        let pin = pin_status(&cluster, &repo, cancelled_job, &base).await?;
        ensure!(pin == StatusCode::CONFLICT, "pre-cancelled pin was accepted: {pin}");
        ensure!(pin_rows_for_job(&cluster, &repo, cancelled_job).await? == 0, "pre-cancelled pin left a ci_pins row");
        ensure!(orphan_active_roots(&cluster, &repo).await? == 0, "pre-cancelled pin left an orphan root");
        ensure!(active_pins(&cluster, &repo).await? == 0, "pre-cancelled pin left an active pin");
        let pre = checkout_status(&cluster, &repo, cancelled_job, &base).await?;
        ensure!(pre == StatusCode::CONFLICT, "pre-cancelled plan reissued: {pre}");
        let raced_pin = Uuid::new_v4();
        cluster.set_s3_get_delay_ms(400);
        let pin_request = pin_status(&cluster, &repo, raced_pin, &base);
        let cancel_race = async {
            for _ in 0..300 {
                if active_pins(&cluster, &repo).await? > 0 {
                    return cancel(&cluster, &repo, raced_pin).await;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(anyhow::anyhow!("the raced capture never became visible"))
        };
        let (pin, cancelled) = tokio::join!(pin_request, cancel_race);
        cancelled?;
        cluster.set_s3_get_delay_ms(0);
        let pin = pin?;
        ensure!(pin == StatusCode::CONFLICT, "captured pin race returned {pin}");
        ensure!(pin_rows_for_job(&cluster, &repo, raced_pin).await? == 0, "captured pin race left a ci_pins row");
        ensure!(orphan_active_roots(&cluster, &repo).await? == 0, "captured pin race leaked an orphan root");
        ensure!(active_pins(&cluster, &repo).await? == 0, "captured pin race leaked an active pin");
        let jobs = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        cluster.set_s3_get_delay_ms(120);
        let canceller = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            for job in &jobs {
                cancel(&cluster, &repo, *job).await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let (a, b, c, d, cancelled_all) = tokio::join!(
            pin_status(&cluster, &repo, jobs[0], &base),
            pin_status(&cluster, &repo, jobs[1], &base),
            pin_status(&cluster, &repo, jobs[2], &base),
            pin_status(&cluster, &repo, jobs[3], &base),
            canceller
        );
        cancelled_all?;
        cluster.set_s3_get_delay_ms(0);
        for status in [a?, b?, c?, d?] {
            ensure!(matches!(status, StatusCode::OK | StatusCode::CONFLICT), "concurrent pin race returned {status}");
        }
        ensure!(orphan_active_roots(&cluster, &repo).await? == 0, "a concurrent pin race leaked an orphan root");
        ensure!(active_pins(&cluster, &repo).await? == 0, "a concurrent pin race leaked an active pin");
        Ok(())
    }
    .await;
    cluster.finish(outcome).await
}

async fn cancel_layer(
    axum::extract::State(notify): axum::extract::State<Arc<Notify>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    tokio::select! {
        response = next.run(request) => response,
        () = notify.notified() => axum::response::IntoResponse::into_response(axum::http::StatusCode::REQUEST_TIMEOUT),
    }
}

async fn spawn_view_server(
    cluster: &Cluster,
    tag: &str,
    git: PathBuf,
    git_timeout: Duration,
    cancel: Option<Arc<Notify>>,
) -> Result<(String, Arc<Semaphore>, tokio::task::JoinHandle<()>)> {
    let config = rootyard::config::Config {
        database_url: std::env::var("ROOTYARD_TEST_DATABASE_URL")?,
        data_dir: cluster.scratch.join(tag),
        bind: "127.0.0.1:0".parse()?,
        git,
        max_request_bytes: 64 * 1024 * 1024,
        max_output_bytes: 64 * 1024 * 1024,
        max_concurrent_git: 4,
        git_timeout,
        git_memory_bytes: 1024 * 1024 * 1024,
        max_repo_bytes: 128 * 1024 * 1024,
        max_pending_deliveries: 1000,
        outbox_worker: false,
        metrics_bind: None,
    };
    let storage = rootyard::storage::Storage::open(&config)?;
    let slots = Arc::new(Semaphore::new(2));
    let state = Arc::new(rootyard::AppState {
        mirror_primary: None,
        dispatch: rootyard::dispatch::Signals::default(),
        config,
        pool: cluster.pool.clone(),
        storage,
        hooks: None,
        transfer_metrics: Arc::new(rootyard::metrics::TransferCounters::default()),
        git_slots: slots.clone(),
    });
    let mut router = rootyard::router(state);
    if let Some(notify) = cancel {
        router = router.layer(axum::middleware::from_fn_with_state(notify, cancel_layer));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((base, slots, task))
}

#[cfg(unix)]
async fn wait_pids(path: &FsPath, tries: usize) -> Result<(String, String, String)> {
    for _ in 0..tries {
        if let Ok(text) = std::fs::read_to_string(path) {
            let mut parts = text.split_whitespace();
            if let (Some(leader), Some(grandchild), Some(scratch)) = (parts.next(), parts.next(), parts.next()) {
                return Ok((leader.to_owned(), grandchild.to_owned(), scratch.to_owned()));
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err(anyhow::anyhow!("the stalled Git child never wrote {}", path.display()))
}

#[cfg(unix)]
async fn wait_scratch_gone(scratch: &str, pids: &[String]) -> Result<()> {
    ensure!(!scratch.is_empty(), "the stalled Git child did not publish its scratch directory");
    let root = PathBuf::from(scratch);
    for _ in 0..200 {
        if !root.exists() {
            let alive = pids.iter().filter(|pid| PathBuf::from(format!("/proc/{pid}")).exists()).count();
            ensure!(alive == 0, "a Git view child survived scratch deletion: {}", child_states(pids));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err(anyhow::anyhow!("the Git view scratch directory was never removed: {}", root.display()))
}
#[cfg(unix)]
fn child_state(pid: &str) -> &'static str {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(err) => return if err.kind() == std::io::ErrorKind::NotFound { "missing" } else { "unknown" },
    };
    let Some((_, tail)) = stat.rsplit_once(')') else { return "unknown" };
    match tail.split_whitespace().next() {
        Some("Z") => "zombie",
        Some("X" | "x") => "dead",
        Some("R" | "S" | "D" | "T" | "t" | "W" | "K" | "P" | "I") => "live",
        _ => "unknown",
    }
}
#[cfg(unix)]
fn child_states(pids: &[String]) -> String {
    pids.iter().enumerate().map(|(slot, pid)| format!("slot{slot}={}", child_state(pid))).collect::<Vec<_>>().join(",")
}

pub async fn bounded_child_lifecycle() -> Result<()> {
    let cluster = Cluster::setup().await?;
    let outcome = async {
        let repo = cluster.create_repository("child-repo", "sha1").await?;
        let big = harness::incompressible(1_200_000);
        let oid = cluster.push_initial(&repo, &[("big.txt", big.as_str())]).await?;
        let job = Uuid::new_v4();
        cluster.pin(&repo, job, &oid).await?;
        let token = cluster.checkout(&repo, job, &oid).await?;
        let mut stream = open_pack_stream(&cluster, &repo, &oid, &token).await?;
        let Some(_chunk) = stream.chunk().await?.filter(|chunk| !chunk.is_empty()) else {
            return Err(anyhow::anyhow!("upload-pack produced no first chunk"));
        };
        drop(stream);
        tokio::time::sleep(Duration::from_millis(250)).await;
        ensure!(cluster.ci_clone(&repo, &oid, &token).await? == oid, "cancelled stream leaked a Git slot");
        let auth = Auth::Basic { user: &cluster.owner.username, password: &token };
        let after = info_refs_status(&cluster, &repo, &oid, auth).await?;
        ensure!(after == StatusCode::OK, "cancelled stream wedged CI transport: {after}");

        let view_repo = cluster.create_repository("view-child-repo", "sha1").await?;
        let view_oid =
            cluster.push_initial(&view_repo, &[("root.txt", "root\n"), ("dir/b.txt", "projected\n")]).await?;
        let namespace = cluster.namespace(&view_repo, &view_oid, "src").await?;
        let view = cluster.view(&namespace, "src", "dir").await?;
        let git = cluster.git.binary().to_path_buf();
        let pidfile = cluster.scratch.join("stall-git.pids");
        let wrapper = cluster.scratch.join("stall-git.sh");
        let script = STALL_SCRIPT.replace("__PIDFILE__", &pidfile.display().to_string());
        let script = script.replace("__REAL_GIT__", &git.display().to_string());
        std::fs::write(&wrapper, script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700))?;
        }
        let (timeout_url, _, timeout_server) =
            spawn_view_server(&cluster, "timeout", wrapper.clone(), Duration::from_millis(1200), None).await?;
        let _ = std::fs::remove_file(&pidfile);
        let url = format!("{timeout_url}/git/views/{view}.git/info/refs?service=git-upload-pack");
        let status = reqwest::Client::new()
            .get(url)
            .basic_auth(&cluster.owner.username, Some(&cluster.owner.token))
            .send()
            .await?
            .status();
        ensure!(status == StatusCode::GATEWAY_TIMEOUT, "stalled Git view returned {status}");
        #[cfg(unix)]
        let (leader, grandchild, scratch_dir) = wait_pids(&pidfile, 60).await?;
        #[cfg(unix)]
        wait_scratch_gone(&scratch_dir, &[leader, grandchild]).await?;
        let _ = std::fs::remove_file(&pidfile);
        let url = format!("{timeout_url}/api/views/{view}/bundle");
        let status = reqwest::Client::new().get(url).bearer_auth(&cluster.owner.token).send().await?.status();
        ensure!(status == StatusCode::GATEWAY_TIMEOUT, "stalled bundle returned {status}");
        #[cfg(unix)]
        let (leader, grandchild, scratch_dir) = wait_pids(&pidfile, 60).await?;
        #[cfg(unix)]
        wait_scratch_gone(&scratch_dir, &[leader, grandchild]).await?;
        timeout_server.abort();

        let notify = Arc::new(Notify::new());
        let (cancel_url, slots, cancel_server) =
            spawn_view_server(&cluster, "cancel", wrapper, Duration::from_secs(30), Some(notify.clone())).await?;
        let _ = std::fs::remove_file(&pidfile);
        let url = format!("{cancel_url}/git/views/{view}.git/info/refs?service=git-upload-pack");
        let request =
            reqwest::Client::new().get(url).basic_auth(&cluster.owner.username, Some(&cluster.owner.token)).send();
        let response = tokio::spawn(async move {
            let response = request.await?;
            Ok::<_, reqwest::Error>(response.status())
        });
        #[cfg(unix)]
        let pids = wait_pids(&pidfile, 600).await;
        notify.notify_waiters();
        #[cfg(unix)]
        let (leader, grandchild, scratch_dir) = pids?;
        let status = response.await??;
        ensure!(status == StatusCode::REQUEST_TIMEOUT, "cancelled Git view returned {status}");
        #[cfg(unix)]
        wait_scratch_gone(&scratch_dir, &[leader, grandchild]).await?;
        ensure!(slots.available_permits() == 2, "a cancelled Git view leaked a Git slot");
        cancel_server.abort();
        Ok(())
    }
    .await;
    cluster.finish(outcome).await
}

async fn cluster_authority_state(pool: &deadpool_postgres::Pool) -> Result<(Uuid, SystemTime)> {
    let sql = "SELECT incarnation, rotated_at FROM public.cluster_authority WHERE singleton=true";
    let row = pool.get().await?.query_one(sql, &[]).await?;
    Ok((row.get(0), row.get(1)))
}

const AUTHORITY_ROTATE: &str = "UPDATE public.cluster_authority \
    SET incarnation=$1, rotated_at=GREATEST(clock_timestamp(), rotated_at + interval '1 millisecond') \
    WHERE singleton=true";
const AUTHORITY_RESTORE: &str =
    "UPDATE public.cluster_authority SET incarnation=$1, rotated_at=$2 WHERE singleton=true";

/// Restores `public.cluster_authority` even when a test fails early.
pub struct ClusterAuthorityRestoreGuard {
    db_url: String,
    original_incarnation: Uuid,
    original_rotated_at: SystemTime,
    disarmed: bool,
}
impl ClusterAuthorityRestoreGuard {
    pub async fn rotate(pool: &deadpool_postgres::Pool, next: Uuid) -> Result<Self> {
        let db_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
        let (original_incarnation, original_rotated_at) = cluster_authority_state(pool).await?;
        let guard = Self { db_url, original_incarnation, original_rotated_at, disarmed: false };
        pool.get().await?.execute(AUTHORITY_ROTATE, &[&next]).await?;
        Ok(guard)
    }

    pub async fn restore(&mut self, pool: &deadpool_postgres::Pool) -> Result<()> {
        let client = pool.get().await?;
        client.execute(AUTHORITY_RESTORE, &[&self.original_incarnation, &self.original_rotated_at]).await?;
        self.disarmed = true;
        Ok(())
    }
}

impl Drop for ClusterAuthorityRestoreGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let db_url = self.db_url.clone();
        let incarnation = self.original_incarnation;
        let rotated_at = self.original_rotated_at;
        let handle = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                return;
            };
            runtime.block_on(async move {
                let Ok((client, connection)) = tokio_postgres::connect(&db_url, tokio_postgres::NoTls).await else {
                    return;
                };
                let task = tokio::spawn(connection);
                let _ = client.execute(AUTHORITY_RESTORE, &[&incarnation, &rotated_at]).await;
                drop(client);
                let _ = task.await;
            });
        });
        let _ = handle.join();
    }
}

const GATE_UPDATE: &str = "WITH g AS (UPDATE ref_store_core_gates SET authority_epoch=$1, \
     history_incarnation=$2 WHERE repository_id=$3), p AS (UPDATE ref_store_core_protocol_repos \
     SET authority_epoch=$1, history_incarnation=$2 WHERE repository_id=$3), s AS (UPDATE \
     ref_store_serving_repositories SET authority_epoch=$1, history_incarnation=$2 \
     WHERE repository_id=$3) SELECT 1";
const GATE_STATE: &str = "SELECT current_schema(), authority_epoch, history_incarnation \
     FROM ref_store_core_gates WHERE repository_id=$1";

async fn apply_gate_epoch(pool: &deadpool_postgres::Pool, repo_id: Uuid, epoch: i64, incarnation: Uuid) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("SET LOCAL session_replication_role = replica", &[]).await?;
    tx.execute(GATE_UPDATE, &[&epoch, &incarnation, &repo_id]).await?;
    tx.commit().await?;
    Ok(())
}

/// Restores the gate epoch/history triple even when a test fails early.
pub struct GateEpochRestoreGuard {
    db_url: String,
    schema: String,
    repo_id: Uuid,
    old_epoch: i64,
    old_incarnation: Uuid,
    disarmed: bool,
}
impl GateEpochRestoreGuard {
    pub async fn rotate(pool: &deadpool_postgres::Pool, repo_id: Uuid, epoch: i64, incarnation: Uuid) -> Result<Self> {
        let db_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
        let row = pool.get().await?.query_one(GATE_STATE, &[&repo_id]).await?;
        let (schema, old_epoch, old_incarnation): (String, i64, Uuid) = (row.get(0), row.get(1), row.get(2));
        let guard = Self { db_url, schema, repo_id, old_epoch, old_incarnation, disarmed: false };
        apply_gate_epoch(pool, repo_id, epoch, incarnation).await?;
        Ok(guard)
    }

    pub async fn restore(&mut self, pool: &deadpool_postgres::Pool) -> Result<()> {
        apply_gate_epoch(pool, self.repo_id, self.old_epoch, self.old_incarnation).await?;
        self.disarmed = true;
        Ok(())
    }
}
impl Drop for GateEpochRestoreGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let db_url = self.db_url.clone();
        let schema = self.schema.clone();
        let setup = format!("SET LOCAL search_path TO {schema}; SET LOCAL session_replication_role = replica");
        let (repo_id, old_epoch, old_incarnation) = (self.repo_id, self.old_epoch, self.old_incarnation);
        let handle = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                return;
            };
            runtime.block_on(async move {
                let Ok((mut client, conn)) = tokio_postgres::connect(&db_url, tokio_postgres::NoTls).await else {
                    return;
                };
                let task = tokio::spawn(conn);
                let Ok(tx) = client.transaction().await else {
                    return;
                };
                let _ = tx.batch_execute(&setup).await;
                let _ = tx.execute(GATE_UPDATE, &[&old_epoch, &old_incarnation, &repo_id]).await;
                let _ = tx.commit().await;
                drop(client);
                let _ = task.await;
            });
        });
        let _ = handle.join();
    }
}

pub async fn cluster_authority_restores_on_failure_and_panic() -> Result<()> {
    let cluster = Cluster::setup().await?;
    let baseline = cluster_authority_state(&cluster.pool).await?;
    let rotated = Uuid::new_v4();
    let mut guard = ClusterAuthorityRestoreGuard::rotate(&cluster.pool, rotated).await?;
    let during = cluster_authority_state(&cluster.pool).await?;
    ensure!(during.0 == rotated && during.1 != baseline.1, "rotation did not mutate both authority columns");
    guard.restore(&cluster.pool).await?;
    let restored = cluster_authority_state(&cluster.pool).await?;
    ensure!(restored.0 == baseline.0 && restored.1 == baseline.1, "explicit restore lost authority state");
    let failed: Result<()> = async {
        let fail_inc = Uuid::new_v4();
        let _guard = ClusterAuthorityRestoreGuard::rotate(&cluster.pool, fail_inc).await?;
        let mutated = cluster_authority_state(&cluster.pool).await?;
        ensure!(mutated.0 == fail_inc && mutated.1 != baseline.1, "error path did not mutate both columns");
        Err(anyhow::anyhow!("simulated failure before explicit restore"))
    }
    .await;
    ensure!(failed.is_err(), "the simulated failure returned Ok");
    let after_err = cluster_authority_state(&cluster.pool).await?;
    ensure!(after_err.0 == baseline.0 && after_err.1 == baseline.1, "error path failed to restore both columns");
    let panicked = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        let panic_inc = Uuid::new_v4();
        let _guard = ClusterAuthorityRestoreGuard::rotate(&cluster.pool, panic_inc).await.expect("rotate");
        let mutated = cluster_authority_state(&cluster.pool).await.expect("state");
        assert!(mutated.0 == panic_inc && mutated.1 != baseline.1, "panic path did not mutate both columns");
        panic!("simulated panic before explicit restore");
    }))
    .await;
    ensure!(panicked.is_err(), "the simulated panic did not unwind");
    let after_panic = cluster_authority_state(&cluster.pool).await?;
    ensure!(after_panic.0 == baseline.0 && after_panic.1 == baseline.1, "panic path failed to restore both columns");
    cluster.finish(Ok(())).await
}
