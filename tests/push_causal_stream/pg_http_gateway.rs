//! Full authoritative PostgreSQL 17 + `LoopbackS3` + `blob_git_gateway::router` + stock `git`
//! Smart HTTP `receive-pack` acceptance suite (#183 Merge Gates 1–4).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use axum::http::{HeaderMap, HeaderValue, header};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_git_gateway::{BlobGitConfig, BlobGitState};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db;
use rootyard::namespace_service::push_causal_stream::quarantine::HoldLifecycleState;
use rootyard::namespace_service::push_causal_stream::*;
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, RealmExpectation};
use rootyard::ref_store::core::pack_commit::PgPackCommit;
use rootyard::ref_store::core::ref_version::{AuthorityKind, RefVersionRealm};
use rootyard::ref_store::core::types::GitObjectFormat;
use rootyard::ref_store::serving::lookup;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

use super::support::{LoopbackS3, active_auth, mk_commit, run_git};

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
        let client = pool.get().await?;
        client
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

fn resolve_git_binary() -> Result<PathBuf> {
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

struct PgActor {
    identity: db::Identity,
    username: String,
    token: String,
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

async fn create_and_provision_repo(
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

#[tokio::test]
#[ignore = "requires PG17, LoopbackS3, and stock Git"]
async fn production_gateway_http_stock_git_push_sha1_sha256_pg_producer_and_slowloris_deadline() -> Result<()> {
    let pg = PgSchemaGuard::setup().await?;
    let run_res = run_gateway_and_pg_producer_suite(&pg).await;
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

    // 1. Exercise real production `POST /git/{owner}/{name}.git/git-receive-pack` with stock `git` (`sha1` & `sha256`).
    for (fmt_str, git_fmt) in [("sha1", GitObjectFormat::Sha1), ("sha256", GitObjectFormat::Sha256)] {
        let repo_name = format!("gw-{fmt_str}-{}", &Uuid::new_v4().simple().to_string()[..8]);
        let repo_id = create_and_provision_repo(gw.addr, &pg.pool, &store, &actor, &repo_name, fmt_str).await?;
        let remote_url =
            format!("http://{}:{}@{}/git/{}/{repo_name}.git", actor.username, actor.token, gw.addr, actor.username);

        let tmp = TempDir::new()?;
        let clone1 = tmp.path().join("clone1");
        run_git(tmp.path(), &["clone", "--no-hardlinks", &remote_url, clone1.to_str().unwrap()], None)?;
        let base_text = "shared-line-for-thin-delta-\n".repeat(150);
        let c1 = mk_commit(&clone1, "app.txt", &base_text, "initial commit")?;
        run_git(&clone1, &["push", "origin", "HEAD:refs/heads/main"], None)?;

        // Incremental push over non-empty repository (triggers #183 Merge Gate 2 base snapshot closure verification!).
        let c2 = mk_commit(&clone1, "app.txt", &format!("{base_text}incremental-v2\n"), "incremental delta commit")?;
        let op_hdr = Uuid::new_v4();
        let extra_hdr = format!("http.extraHeader=X-Rootyard-Operation: {op_hdr}");
        run_git(&clone1, &["-c", &extra_hdr, "push", "origin", "HEAD:refs/heads/main"], None)?;

        let receipt = recent_gateway_push_receipt(op_hdr)
            .ok_or_else(|| anyhow!("missing CausalPushProofReceipt for production HTTP push {op_hdr}"))?;
        ensure!(receipt.object_format == git_fmt && receipt.repository_id == repo_id, "receipt scope mismatch");
        ensure!(
            receipt.committed_gate_revision == Some(3),
            "expected revision 3, got {:?}",
            receipt.committed_gate_revision
        );
        ensure!(
            receipt.accepted_updates.len() == 1
                && receipt.accepted_updates[0].old_oid.as_deref() == Some(c1.as_str())
                && receipt.accepted_updates[0].new_oid.as_deref() == Some(c2.as_str())
        );
        receipt.verify_digest()?;

        // Verify PG17 durable scoped decisions + durable A3 artifact holds + pack memberships.
        let db_client = pg.pool.get().await?;
        let (decisions, holds, memberships): (i64, i64, i64) = {
            let d: i64 = db_client
                .query_one(
                    "SELECT COUNT(*) FROM ref_store_core_decisions WHERE repository_id=$1 AND state='committed'",
                    &[&repo_id],
                )
                .await?
                .get(0);
            let h: i64 = db_client
                .query_one("SELECT COUNT(*) FROM ref_store_artifact_holds WHERE repository_id=$1", &[&repo_id])
                .await?
                .get(0);
            let m: i64 = db_client
                .query_one("SELECT COUNT(*) FROM ref_store_core_pack_memberships WHERE repository_id=$1", &[&repo_id])
                .await?
                .get(0);
            (d, h, m)
        };
        ensure!(
            decisions >= 2 && holds >= 4 && memberships >= 2,
            "PG17 ledger counts unexpected: d={decisions} h={holds} m={memberships}"
        );

        // Scratch dir must have zero lingering compute views; fresh clone + fsck proves remote Blob durability.
        for _ in 0..30 {
            if std::fs::read_dir(gw.scratch.path())?.next().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ensure!(std::fs::read_dir(gw.scratch.path())?.next().is_none(), "scratch_root must stay empty after push");

        let clone2 = tmp.path().join("clone2");
        run_git(tmp.path(), &["clone", "--no-hardlinks", &remote_url, clone2.to_str().unwrap()], None)?;
        let head2 = String::from_utf8(run_git(&clone2, &["rev-parse", "HEAD"], None)?)?.trim().to_owned();
        ensure!(head2 == c2, "fresh clone HEAD mismatch: {head2} != {c2}");
        run_git(&clone2, &["fsck", "--full", "--strict"], None)?;
    }

    // 2. Direct `commit_push_on_pg` acceptance: proves PG producer gates on scoped decision + durable holds
    //    and rebinds `CausalPushProofReceipt` to the actual `AcceptedSubset` CAS outcome (#183 Merge Gate 3).
    exercise_pg_scoped_producer(pg, &store, gw.addr, &actor, &backend_hex).await?;

    // 3. Real TCP HTTP slowloris command-phase stall against production `git-receive-pack` (#183 Merge Gate 1).
    let tight_gw = LiveGateway::start(pg.pool.clone(), store.clone(), Duration::from_millis(250)).await?;
    let stall_repo = format!("stall-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let stall_repo_id = create_and_provision_repo(tight_gw.addr, &pg.pool, &store, &actor, &stall_repo, "sha1").await?;
    let auth_b64 = base64_basic(&actor.username, &actor.token);
    let mut stream = TcpStream::connect(tight_gw.addr).await?;
    let partial_pkt = b"0067000000000000"; // incomplete pkt-line command (stalls before `0000` flush!)
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
    stream.write_all(partial_pkt).await?;
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

async fn exercise_pg_scoped_producer(
    pg: &PgSchemaGuard,
    store: &BlobStore,
    addr: SocketAddr,
    actor: &PgActor,
    backend_hex: &str,
) -> Result<()> {
    let repo_name = format!("pgprod-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let repo_id = create_and_provision_repo(addr, &pg.pool, store, actor, &repo_name, "sha1").await?;
    let dl = TokioInstant::now() + Duration::from_secs(30);
    let mut db_client = pg.pool.get().await?;
    let repo_owner_id: Uuid =
        db_client.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repo_id]).await?.get(0);
    let serving =
        lookup(&pg.pool, &actor.identity, &actor.username, &repo_name, true, store.backend_identity(), dl).await?;
    let gate = serving.gate;
    let baseline = PgPackCommit.capture_baseline(&mut db_client, repo_id, gate.tenant_id(), dl).await?;
    drop(db_client);

    let tmp = TempDir::new()?;
    let (work, bare) = (tmp.path().join("w"), tmp.path().join("b"));
    run_git(tmp.path(), &["init", "-b", "main", work.to_str().unwrap()], None)?;
    run_git(tmp.path(), &["init", "--bare", bare.to_str().unwrap()], None)?;
    let c1 = mk_commit(&work, "p.txt", "pg-scoped-v1\n", "c1")?;
    let raw_pack = run_git(&work, &["pack-objects", "--revs", "--stdout"], Some(format!("{c1}\n").as_bytes()))?;
    let p_path = bare.join("objects/pack/p1.pack");
    let idx_path = bare.join("objects/pack/p1.idx");
    run_git(&bare, &["index-pack", "--stdin", "--strict", p_path.to_str().unwrap()], Some(&raw_pack))?;

    let realm = RefVersionRealm::new(
        gate.tenant_id(),
        repo_id,
        gate.history_incarnation(),
        AuthorityKind::Pg,
        gate.authority_epoch(),
        0,
        gate.group_epoch(),
        GitObjectFormat::Sha1,
    );
    let snapshot = AuthorizedSnapshotState {
        realm,
        tenant_id: gate.tenant_id(),
        repository_id: repo_id,
        history_incarnation: gate.history_incarnation(),
        authority_epoch: gate.authority_epoch(),
        group_epoch: gate.group_epoch(),
        expected_gate_revision: baseline.gate().revision(),
        object_format: GitObjectFormat::Sha1,
        snapshot_seq: baseline.gate().revision(),
        root_version_id: None,
        current_refs: BTreeMap::new(),
        authorized_base_packs: Vec::new(),
    };
    let op_id = Uuid::new_v4();
    let ticket =
        OperationTicket { issuer_id: actor.identity.id, lane: "pg-push".into(), sequence: 1, operation_id: op_id };
    let auth = active_auth(actor.identity.id, true);
    let caps = ReceiveCapabilities { report_status: true, atomic: false, ..ReceiveCapabilities::default() };

    // Two updates in `AcceptedSubset`: `refs/heads/main` (Absent -> c1, succeeds) + `refs/heads/stale` (Present(fake) -> c1, rejected).
    let accepted = vec![
        AcceptedRefProof {
            ref_name: "refs/heads/main".into(),
            old_oid: None,
            new_oid: Some(c1.clone()),
            target_kind: "commit".into(),
        },
        AcceptedRefProof {
            ref_name: "refs/heads/stale".into(),
            old_oid: Some("1".repeat(40)),
            new_oid: Some(c1.clone()),
            target_kind: "commit".into(),
        },
    ];
    let sub_dig =
        rootyard::namespace_service::push_causal_stream::receipt::compute_accepted_subset_digest(&accepted, &[]);
    let mut receipt = CausalPushProofReceipt {
        receipt_version: 2,
        tenant_id: snapshot.tenant_id,
        repository_id: repo_id,
        history_incarnation: snapshot.history_incarnation,
        authority_epoch: snapshot.authority_epoch,
        group_epoch: snapshot.group_epoch,
        object_format: GitObjectFormat::Sha1,
        operation_id: op_id,
        issuer_id: actor.identity.id,
        lane: ticket.lane.clone(),
        sequence: 1,
        base_snapshot_seq: snapshot.snapshot_seq,
        expected_gate_revision: snapshot.expected_gate_revision,
        committed_gate_revision: None,
        base_version_ids: vec![],
        required_ancestor_oids: vec![],
        resolved_thin_base_oids: vec![],
        base_closure_digest: "0".repeat(64),
        pack_sha256: None,
        pack_bytes: 0,
        idx_sha256: None,
        idx_bytes: 0,
        pack_locator: None,
        idx_locator: None,
        blob_backend_identity: backend_hex.to_owned(),
        object_count: 3,
        delta_object_count: 0,
        max_delta_chain_depth: 0,
        duplicate_object_count: 0,
        blob_closure_digest: "0".repeat(64),
        accepted_updates: accepted,
        rejected_updates: vec![],
        accepted_subset_digest: sub_dig,
        proof_digest: String::new(),
    };
    receipt.proof_digest = receipt.recompute_digest();

    let reclaim = QuarantineReclaimLedger::open(tmp.path().join("reclaim"))?;
    let mut hold_guard = OperationHoldGuard::acquire(op_id, vec![], vec![]);
    let git_bin = resolve_git_binary()?;
    let outcome = commit_push_on_pg(PgScopedPushParams {
        pool: &pg.pool,
        store,
        git_binary: &git_bin,
        actor: &actor.identity,
        owner_id: repo_owner_id,
        snapshot: &snapshot,
        ticket: &ticket,
        auth: &auth,
        capabilities: &caps,
        staged_pack_pair: Some((&p_path, &idx_path)),
        reclaim_ledger: Some(&reclaim),
        receipt: &mut receipt,
        hold_guard: &mut hold_guard,
        deadline: dl,
    })
    .await?;

    ensure!(hold_guard.state == HoldLifecycleState::ConsumedCommitted && hold_guard.hold_ids.len() == 2);
    ensure!(reclaim.load(op_id)?.unwrap().state == UploadReclaimState::VerifiedPromoted);
    receipt.verify_commit_binding(&snapshot, &ticket, backend_hex, &outcome.terminal_refs)?;
    ensure!(receipt.accepted_updates.len() == 1 && receipt.rejected_updates.len() == 1);
    let wire_txt = String::from_utf8_lossy(&outcome.report_status_wire);
    ensure!(wire_txt.contains("ok refs/heads/main\n") && wire_txt.contains("ng refs/heads/stale"));
    Ok(())
}

fn base64_basic(user: &str, token: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{token}");
    let bytes = raw.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
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
