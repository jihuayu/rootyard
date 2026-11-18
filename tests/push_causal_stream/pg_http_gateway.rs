//! Full authoritative PostgreSQL 17 + `LoopbackS3` + `blob_git_gateway::router` + stock `git`
//! Smart HTTP `receive-pack` acceptance suite (#183 Merge Gates 1–4 + concurrent CAS 200 `ng`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_git_gateway::{BlobGitConfig, BlobGitState};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db;
use rootyard::namespace_service::push_causal_stream::*;
use rootyard::ref_store::CommitRejectCode;
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, RealmExpectation};
use rootyard::ref_store::core::types::GitObjectFormat;
use rootyard::ref_store::serving::lookup;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

use super::pg_scoped_producer::{PgScopedTestEnv, exercise_pg_scoped_producer};
use super::support::{LoopbackS3, build_receive_wire, mk_commit, run_git};

#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

struct PgSchemaGuard {
    admin: Pool,
    pool: Pool,
    schema: String,
}

impl PgSchemaGuard {
    async fn setup() -> Result<Self> {
        let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")
            .context("ROOTYARD_TEST_DATABASE_URL must be set for PG17 gateway acceptance")?;
        let admin = db::pool(&url)?;
        let schema = format!("push_causal_183_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let mut cfg: tokio_postgres::Config = url.parse()?;
        cfg.options(format!(
            "{} -c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000",
            cfg.get_options().unwrap_or("")
        ));
        let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(16)
            .build()?;
        db::migrate(&pool).await?;
        pool.get()
            .await?
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS public.cluster_authority (
                     singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
                     incarnation UUID NOT NULL DEFAULT gen_random_uuid(),
                     rotated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
                 );
                 INSERT INTO public.cluster_authority(singleton) VALUES(true) ON CONFLICT DO NOTHING;",
            )
            .await?;
        Ok(Self { admin, pool, schema })
    }

    async fn teardown(&self) -> Result<()> {
        self.admin.get().await?.batch_execute(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema)).await?;
        Ok(())
    }
}

struct LiveGateway {
    addr: SocketAddr,
    scratch: TempDir,
    stop: tokio::sync::oneshot::Sender<()>,
}

impl LiveGateway {
    async fn start(pool: Pool, store: BlobStore, op_deadline: Duration) -> Result<Self> {
        let scratch = tempfile::tempdir()?;
        let git_bin = resolve_git_binary()?;
        let state = Arc::new(
            BlobGitState::new(BlobGitConfig {
                pool,
                store,
                git_binary: git_bin,
                scratch_root: scratch.path().to_path_buf(),
                max_concurrent_requests: 8,
                max_request_bytes: 16 * 1024 * 1024,
                max_response_bytes: 32 * 1024 * 1024,
                max_inflight_bytes: 64 * 1024 * 1024,
                operation_deadline: op_deadline,
                native_limits: Default::default(),
            })
            .map_err(|e| anyhow!("BlobGitState::new failed: {e}"))?,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let app = rootyard::blob_git_gateway::router(state);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });
        Ok(Self { addr, scratch, stop: tx })
    }
}

pub fn resolve_git_binary() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("ROOTYARD_TEST_GIT") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
    }
    for cand in ["/usr/bin/git", "/usr/local/bin/git"] {
        let pb = PathBuf::from(cand);
        if pb.is_file() {
            return Ok(pb);
        }
    }
    Err(anyhow!("stock git binary not found at /usr/bin/git"))
}

async fn git_http(cwd: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let dir = cwd.to_path_buf();
    let owned_args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        let out = Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-C"])
            .arg(&dir)
            .args(&owned_args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_HTTP_LOW_SPEED_LIMIT", "1")
            .env("GIT_HTTP_LOW_SPEED_TIME", "25")
            .stdin(Stdio::null())
            .output()?;
        ensure!(out.status.success(), "git {owned_args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        Ok(out.stdout)
    })
    .await?
}

pub struct PgActor {
    pub identity: db::Identity,
    pub username: String,
    pub token: String,
}

async fn issue_writable_actor(pool: &Pool, prefix: &str) -> Result<PgActor> {
    let username = format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..10]);
    let val = db::issue_token(pool, &username, true, false).await.map_err(|e| anyhow!("{e}"))?;
    let token = val["token"].as_str().ok_or_else(|| anyhow!("missing token"))?.to_owned();
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
    let identity = rootyard::auth::authenticate(pool, &headers).await.map_err(|e| anyhow!("{}", e.1))?;
    Ok(PgActor { identity, username, token })
}

pub async fn create_and_provision_repo(
    addr: SocketAddr,
    pool: &Pool,
    store: &BlobStore,
    actor: &PgActor,
    name: &str,
    fmt: &str,
) -> Result<Uuid> {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/repos"))
        .bearer_auth(&actor.token)
        .json(&json!({"name": name, "object_format": fmt}))
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    ensure!(status.is_success(), "create_repo failed {status}: {body}");
    let repo_id = Uuid::parse_str(body["id"].as_str().ok_or_else(|| anyhow!("missing repo id"))?)?;

    let dl = TokioInstant::now() + Duration::from_secs(30);
    let serving = lookup(pool, &actor.identity, &actor.username, name, true, store.backend_identity(), dl).await?;
    let gate = serving.gate;
    let exp = RealmExpectation::new(
        gate.repository_id(),
        gate.tenant_id(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let mut client = pool.get().await?;
    PgDecisionProtocol.provision(&mut client, &exp, dl).await?;
    Ok(repo_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires PG17, LoopbackS3, and stock Git"]
async fn production_gateway_http_stock_git_push_sha1_sha256_pg_producer_and_slowloris_deadline() -> Result<()> {
    let pg = PgSchemaGuard::setup().await?;
    let run_res = tokio::time::timeout(Duration::from_secs(120), run_gateway_and_pg_producer_suite(&pg))
        .await
        .map_err(|_| anyhow!("PG17 gateway acceptance timed out after 120s"))
        .and_then(|r| r);
    let td_res = pg.teardown().await;
    run_res?;
    td_res
}

async fn run_gateway_and_pg_producer_suite(pg: &PgSchemaGuard) -> Result<()> {
    let s3 = LoopbackS3::shared();
    let store = s3.open_store()?;
    let gw = LiveGateway::start(pg.pool.clone(), store.clone(), Duration::from_secs(60)).await?;
    let actor = issue_writable_actor(&pg.pool, "push183").await?;
    let backend_hex = store.backend_identity().as_hex().to_owned();
    let git_bin = resolve_git_binary()?;

    // 1. Real production `POST /git/{owner}/{name}.git/git-receive-pack` with stock `git` (`sha1` & `sha256`).
    for (fmt_str, git_fmt) in [("sha1", GitObjectFormat::Sha1), ("sha256", GitObjectFormat::Sha256)] {
        let repo_name = format!("gw-{fmt_str}-{}", &Uuid::new_v4().simple().to_string()[..8]);
        let repo_id = create_and_provision_repo(gw.addr, &pg.pool, &store, &actor, &repo_name, fmt_str).await?;
        let remote_url =
            format!("http://{}:{}@{}/git/{}/{repo_name}.git", actor.username, actor.token, gw.addr, actor.username);

        let tmp = TempDir::new()?;
        let clone1 = tmp.path().join("clone1");
        git_http(tmp.path(), &["clone", "--no-hardlinks", &remote_url, clone1.to_str().unwrap()]).await?;
        let base_text = "shared-line-for-thin-delta-\n".repeat(150);
        let c1 = mk_commit(&clone1, "app.txt", &base_text, "initial commit")?;
        git_http(&clone1, &["push", "origin", "HEAD:refs/heads/main"]).await?;

        // Incremental push over non-empty repository (triggers #183 Merge Gate 2 base snapshot closure!).
        let c2 = mk_commit(&clone1, "app.txt", &format!("{base_text}incremental-v2\n"), "incremental delta commit")?;
        let op_hdr = Uuid::new_v4();
        let extra_hdr = format!("http.extraHeader=X-Rootyard-Operation: {op_hdr}");
        git_http(&clone1, &["-c", &extra_hdr, "push", "origin", "HEAD:refs/heads/main"]).await?;

        let receipt = recent_gateway_push_receipt(op_hdr)
            .ok_or_else(|| anyhow!("missing CausalPushProofReceipt for production HTTP push {op_hdr}"))?;
        ensure!(receipt.object_format == git_fmt && receipt.repository_id == repo_id, "receipt scope mismatch");
        ensure!(
            receipt.committed_gate_revision == Some(3),
            "expected rev 3, got {:?}",
            receipt.committed_gate_revision
        );
        ensure!(
            receipt.accepted_updates.len() == 1
                && receipt.accepted_updates[0].old_oid.as_deref() == Some(c1.as_str())
                && receipt.accepted_updates[0].new_oid.as_deref() == Some(c2.as_str())
        );
        receipt.verify_digest()?;

        let db_client = pg.pool.get().await?;
        let d: i64 = db_client
            .query_one(
                "SELECT COUNT(*) FROM ref_store_publication_decisions WHERE repository_id=$1 AND state='CONSUMED'",
                &[&repo_id],
            )
            .await?
            .get(0);
        let h: i64 = db_client
            .query_one("SELECT COUNT(*) FROM artifact_holds WHERE repository_id=$1", &[&repo_id])
            .await?
            .get(0);
        let m: i64 = db_client
            .query_one("SELECT COUNT(*) FROM ref_store_core_pack_memberships WHERE repository_id=$1", &[&repo_id])
            .await?
            .get(0);
        ensure!(d >= 2 && h >= 4 && m >= 2, "PG17 ledger counts unexpected: d={d} h={h} m={m}");

        for _ in 0..30 {
            if std::fs::read_dir(gw.scratch.path())?.next().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ensure!(std::fs::read_dir(gw.scratch.path())?.next().is_none(), "scratch_root must stay empty after push");

        let clone2 = tmp.path().join("clone2");
        git_http(tmp.path(), &["clone", "--no-hardlinks", &remote_url, clone2.to_str().unwrap()]).await?;
        let head2 = String::from_utf8(run_git(&clone2, &["rev-parse", "HEAD"], None)?)?.trim().to_owned();
        ensure!(head2 == c2, "fresh clone HEAD mismatch: {head2} != {c2}");
        run_git(&clone2, &["fsck", "--full", "--strict"], None)?;
    }

    // 2. Concurrent same-ref race on non-empty repo: loser MUST return HTTP 200 OK `ng` (never HTTP 500!).
    exercise_concurrent_same_ref_http_race(gw.addr, &pg.pool, &store, &actor).await?;

    // 3. Direct `commit_push_on_pg` scoped decision + durable A3 hold + `AcceptedSubset` receipt rebinding.
    exercise_pg_scoped_producer(PgScopedTestEnv {
        pool: &pg.pool,
        store: &store,
        gw_addr: gw.addr,
        actor: &actor,
        git_binary: &git_bin,
        backend_hex: &backend_hex,
    })
    .await?;

    // 4. Real TCP HTTP slowloris command-phase stall against production `git-receive-pack` (#183 Merge Gate 1).
    let stall_repo = format!("stall-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let stall_repo_id = create_and_provision_repo(gw.addr, &pg.pool, &store, &actor, &stall_repo, "sha1").await?;
    let tight_gw = LiveGateway::start(pg.pool.clone(), store.clone(), Duration::from_millis(250)).await?;
    let auth_b64 = base64_basic(&actor.username, &actor.token);
    let mut stream = TcpStream::connect(tight_gw.addr).await?;
    let req_head = format!(
        "POST /git/{}/{stall_repo}.git/git-receive-pack HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: Basic {auth_b64}\r\n\
         Content-Type: application/x-git-receive-pack-request\r\n\
         Content-Length: 4096\r\n\
         Connection: close\r\n\r\n",
        actor.username, tight_gw.addr
    );
    stream.write_all(req_head.as_bytes()).await?;
    stream.write_all(b"0067000000000000").await?;
    stream.flush().await?;
    tokio::time::sleep(Duration::from_millis(420)).await;
    let mut resp_buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut resp_buf)).await;
    let resp_str = String::from_utf8_lossy(&resp_buf);
    ensure!(
        resp_str.starts_with("HTTP/1.1 504 ") || resp_str.starts_with("HTTP/1.1 408 "),
        "expected HTTP 504/408 timeout on command-phase stall, got: {resp_str}"
    );
    let ref_cnt: i64 = pg
        .pool
        .get()
        .await?
        .query_one("SELECT COUNT(*) FROM ref_store_core_refs WHERE repository_id=$1", &[&stall_repo_id])
        .await?
        .get(0);
    ensure!(ref_cnt == 0, "stalled command stream must never mutate refs");

    let _ = tight_gw.stop.send(());
    let _ = gw.stop.send(());
    Ok(())
}

async fn exercise_concurrent_same_ref_http_race(
    addr: SocketAddr,
    pool: &Pool,
    store: &BlobStore,
    actor: &PgActor,
) -> Result<()> {
    let repo_name = format!("race-{}", &Uuid::new_v4().simple().to_string()[..8]);
    create_and_provision_repo(addr, pool, store, actor, &repo_name, "sha1").await?;
    let remote_url = format!("http://{}:{}@{addr}/git/{}/{repo_name}.git", actor.username, actor.token, actor.username);

    let tmp = TempDir::new()?;
    let seed = tmp.path().join("seed");
    git_http(tmp.path(), &["clone", "--no-hardlinks", &remote_url, seed.to_str().unwrap()]).await?;
    let base_oid = mk_commit(&seed, "seed.txt", "race-seed\n", "seed")?;
    git_http(&seed, &["push", "origin", "HEAD:refs/heads/race"]).await?;

    let mut wires = Vec::new();
    for tag in ["a", "b"] {
        let dir = tmp.path().join(format!("c-{tag}"));
        git_http(tmp.path(), &["clone", "--branch", "race", "--no-hardlinks", &remote_url, dir.to_str().unwrap()])
            .await?;
        let new_oid = mk_commit(&dir, &format!("{tag}.txt"), &format!("racer-{tag}\n"), &format!("race {tag}"))?;
        let pack = run_git(&dir, &["--no-pager", "pack-objects", "--stdout", "--all"], Some(b""))?;
        wires.push((
            Uuid::new_v4(),
            build_receive_wire(&[(base_oid.as_str(), new_oid.as_str(), "refs/heads/race")], "report-status", &pack),
        ));
    }

    let url = format!("http://{addr}/git/{}/{repo_name}.git/git-receive-pack", actor.username);
    let auth_hdr = format!("Basic {}", base64_basic(&actor.username, &actor.token));
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for (op_id, body) in wires {
        let (u, a, bar) = (url.clone(), auth_hdr.clone(), Arc::clone(&barrier));
        handles.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            bar.wait().await;
            for attempt in 0..2 {
                let resp = client
                    .post(&u)
                    .header(header::AUTHORIZATION, &a)
                    .header(header::CONTENT_TYPE, "application/x-git-receive-pack-request")
                    .header("X-Rootyard-Operation", op_id.to_string())
                    .body(body.clone())
                    .send()
                    .await?;
                let st = resp.status();
                let bytes = resp.bytes().await?.to_vec();
                if st == StatusCode::CONFLICT && attempt == 0 {
                    continue;
                }
                return Ok::<(Uuid, StatusCode, Vec<u8>), anyhow::Error>((op_id, st, bytes));
            }
            Err(anyhow!("unexpected repeated 409 on race operation {op_id}"))
        }));
    }

    let (mut ok_cnt, mut ng_cnt) = (0usize, 0usize);
    for h in handles {
        let (op_id, st, bytes) = h.await??;
        ensure!(st == StatusCode::OK, "expected HTTP 200 OK on concurrent push {op_id}, got {st}");
        let txt = String::from_utf8_lossy(&bytes);
        let receipt = recent_gateway_push_receipt(op_id).ok_or_else(|| anyhow!("missing race receipt {op_id}"))?;
        receipt.verify_digest()?;
        if txt.contains("ok refs/heads/race\n") {
            ensure!(receipt.committed_gate_revision.is_some() && receipt.accepted_updates.len() == 1);
            ok_cnt += 1;
        } else {
            ensure!(txt.contains("ng refs/heads/race stale info\n"), "unexpected loser report: {txt}");
            ensure!(
                receipt.committed_gate_revision.is_none()
                    && receipt.accepted_updates.is_empty()
                    && receipt.rejected_updates.len() == 1
                    && receipt.rejected_updates[0].code == CommitRejectCode::OldOidMismatch
            );
            ng_cnt += 1;
        }
    }
    ensure!(ok_cnt == 1 && ng_cnt == 1, "expected 1 winner and 1 CAS loser, got ok={ok_cnt} ng={ng_cnt}");
    Ok(())
}

fn base64_basic(user: &str, token: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{token}");
    let mut out = String::new();
    for chunk in raw.as_bytes().chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((triple >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(triple & 0x3f) as usize] as char } else { '=' });
    }
    out
}
