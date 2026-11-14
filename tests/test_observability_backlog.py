#!/usr/bin/env python3
"""Native E2E regression for structured worker error correlation, redaction, and backlog metrics."""
from __future__ import annotations

import argparse, hashlib, http.server, json, os, shutil, socket, subprocess, sys, tempfile, threading, time, unittest, urllib.error, urllib.parse, urllib.request, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import e2e  # noqa: E402
import metrics as metrics_suite  # noqa: E402
import native_evidence  # noqa: E402

LFS_MIME = "application/vnd.git-lfs+json"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _valid_uuid(value: object) -> str:
    return str(uuid.UUID(str(value)))


def _events_in(log_path: Path) -> list[dict]:
    if not log_path.is_file():
        return []
    out = []
    for raw in log_path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("{"):
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict) and item.get("event") == "rootyard_error":
                out.append(item)
    return out


def _wait_event(log_path: Path, predicate, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for ev in _events_in(log_path):
            if predicate(ev):
                return ev
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for structured event; seen={_events_in(log_path)!r}")


class _GatedLoopbackServer:
    """Loopback HTTP server for S3/webhook fault & repair-backlog gating; never logs headers."""

    def __init__(self, status_code: int = 503) -> None:
        self.status_code, self.gate_head = status_code, False
        self.head_arrived, self.release_head = threading.Event(), threading.Event()
        self.release_head.set()
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *args) -> None: pass
            def _reply(self, code: int) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()
            def do_HEAD(self) -> None:
                if parent.gate_head:
                    parent.head_arrived.set()
                    parent.release_head.wait(timeout=15.0)
                self._reply(parent.status_code)
            def do_GET(self) -> None: self._reply(parent.status_code)
            def do_PUT(self) -> None: self._reply(parent.status_code)
            def do_POST(self) -> None: self._reply(200)
            def do_DELETE(self) -> None: self._reply(204)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.release_head.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5.0)


def _scrape_metrics(port: int) -> tuple[int, str, dict[str, str]]:
    try:
        resp = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/metrics"), timeout=10)
    except urllib.error.HTTPError as err:
        resp = err
    with resp:
        return resp.status, resp.read().decode("utf-8", "replace"), {k.lower(): v for k, v in resp.headers.items()}


class ObservabilityBacklogE2ETest(unittest.TestCase):
    binary: Path
    db_secret_sentinel: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
        raw_target = Path(os.environ.get("CARGO_TARGET_DIR") or (ROOT / "target")).expanduser()
        target_dir = (raw_target if raw_target.is_absolute() else ROOT / raw_target).resolve()
        cls.binary = (target_dir / "debug" / "rootyard").resolve()
        db_url = os.environ.get("ROOTYARD_TEST_DATABASE_URL")
        if in_ci:
            if not cls.binary.is_file() or not db_url:
                raise RuntimeError("CI requires prebuilt target/debug/rootyard and ROOTYARD_TEST_DATABASE_URL")
            return
        need_build = not cls.binary.is_file()
        if not need_build:
            try:
                native_evidence.build_record(cls.binary)
            except Exception:
                need_build = True
        if need_build:
            build_env = {**os.environ, "CARGO_FORK_AUTO_UPDATE": "0"}
            subprocess.run([sys.executable, str(ROOT / "scripts" / "build_native.py")],
                           cwd=ROOT, env=build_env, check=True, timeout=240)
        if not cls.binary.is_file():
            raise RuntimeError(f"Failed to locate built binary at {cls.binary}")
        if not db_url:
            pg_root = Path(tempfile.mkdtemp(prefix="obs80-pg-"))
            cls.addClassCleanup(shutil.rmtree, pg_root, True)
            pgdata, sockdir, pglog = pg_root / "data", pg_root / "sock", pg_root / "postgres.log"
            sockdir.mkdir(parents=True, exist_ok=True)
            port = _free_port()
            cls.db_secret_sentinel = "obs80-dbpass-" + uuid.uuid4().hex
            subprocess.run(["initdb", "-D", str(pgdata), "-U", "postgres", "-A", "trust", "--no-instructions",
                            "--encoding=UTF8", "--lc-collate=C", "--lc-ctype=C"],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            with (pgdata / "postgresql.conf").open("a", encoding="utf-8") as conf:
                conf.write(f"\nlisten_addresses = '127.0.0.1'\nport = {port}\nunix_socket_directories = '{sockdir}'\n"
                           "max_connections = 64\nfsync = off\nsynchronous_commit = off\n")
            prev_db = os.environ.get("ROOTYARD_TEST_DATABASE_URL")

            def _cleanup_pg() -> None:
                if prev_db is None:
                    os.environ.pop("ROOTYARD_TEST_DATABASE_URL", None)
                else:
                    os.environ["ROOTYARD_TEST_DATABASE_URL"] = prev_db
                subprocess.run(["pg_ctl", "-D", str(pgdata), "-m", "immediate", "stop"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)

            cls.addClassCleanup(_cleanup_pg)  # LIFO: stops PostgreSQL before shutil.rmtree(pg_root, True).
            subprocess.run(["pg_ctl", "-D", str(pgdata), "-l", str(pglog), "-w", "start"],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "-d", "postgres",
                            "-v", "ON_ERROR_STOP=1", "-c", "CREATE DATABASE rootyard_obs80"],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            os.environ["ROOTYARD_TEST_DATABASE_URL"] = f"postgresql://postgres:{cls.db_secret_sentinel}@127.0.0.1:{port}/rootyard_obs80"

    def _new_harness(self, **env_overrides: str) -> e2e.Harness:
        h = e2e.Harness(argparse.Namespace(binary=str(self.binary), keep=False))
        self.addCleanup(h.cleanup)
        h.env.update(env_overrides)
        return h

    def _assert_log_redacted(self, h: e2e.Harness, extra_secrets: list[str]) -> None:
        log_path = h.root / "server.log"
        log_text = log_path.read_text(errors="replace")
        db_passwords: list[str] = []
        for db_url in (h.base_db, h.db):
            pw = urllib.parse.urlsplit(db_url).password
            if pw:
                db_passwords.extend([pw, urllib.parse.unquote(pw)])
        forbidden = [s for s in ([self.db_secret_sentinel, h.base_db, h.db] + db_passwords + h.secrets + extra_secrets) if s]
        for secret in forbidden:
            self.assertNotIn(secret, log_text, "Sensitive value leaked into server.log")
        for ev in _events_in(log_path):
            raw = json.dumps(ev)
            for secret in forbidden:
                self.assertNotIn(secret, raw)
            if ev.get("scope") == "worker":
                for bad_key in ("request_id", "route", "actor_id", "repository_id", "tenant_id", "job_id", "token"):
                    self.assertNotIn(bad_key, ev)

    def test_claimed_storage_lifecycle_execute_emits_attempt_and_generation(self) -> None:
        tag = uuid.uuid4().hex
        sentinel = f"obs80-exec-{tag}-postgres://u:pw-{tag}@127.0.0.1:1/db?token=tok-{tag} Authorization: Bearer b-{tag}"
        h = self._new_harness(ROOTYARD_STORAGE_MAINTENANCE="true", ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS="1",
                              ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS="3600", ROOTYARD_OUTBOX_WORKER="false", ROOTYARD_SESSION_GC="false")
        h.setup()
        repo_id = h.create_repository({"name": "exec-corr"}, token=h.alice)["id"]
        tenant_id, job_id = h.alice["user_id"], str(uuid.uuid4())
        # Seed attempt=2, repository_generation=7, claim_generation=6 -> jobs::claim increments attempt->3, claim_generation->7.
        h.sql(f"""
            UPDATE repositories SET storage_generation=7 WHERE id='{repo_id}';
            INSERT INTO storage_maintenance_repo_state(repository_id,tenant_id,last_scan_at,last_scan_generation)
            VALUES ('{repo_id}','{tenant_id}',clock_timestamp(),7)
            ON CONFLICT (repository_id) DO UPDATE SET last_scan_at=clock_timestamp(),last_scan_generation=7;
            CREATE FUNCTION "obs80_exec_fn_{tag}"() RETURNS trigger LANGUAGE plpgsql AS $fn$
            BEGIN RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = '{sentinel}'; END $fn$;
            CREATE TRIGGER "obs80_exec_trg_{tag}" BEFORE UPDATE ON storage_maintenance_repo_state
            FOR EACH ROW WHEN (NEW.last_repack_at IS DISTINCT FROM OLD.last_repack_at AND NEW.repository_id = '{repo_id}'::uuid)
            EXECUTE FUNCTION "obs80_exec_fn_{tag}"();
            INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,state,repository_generation,attempt,claim_generation)
            VALUES ('{job_id}','{repo_id}','{tenant_id}','gitfs_repack','queued',7,2,6);
        """)
        ev = _wait_event(h.root / "server.log", lambda e: e.get("scope") == "worker"
                         and e.get("worker") == "storage_lifecycle" and e.get("phase") == "execute")
        row = h.sql(f"SELECT attempt,repository_generation,claim_generation FROM storage_maintenance_jobs WHERE id='{job_id}'")
        claimed_attempt, repo_gen, claim_gen = [int(x) for x in row.split("|")]
        self.assertEqual((claimed_attempt, repo_gen, claim_gen), (3, 7, 7))
        self.assertEqual((ev.get("kind"), ev.get("status"), ev.get("sqlstate")), ("database", 503, "23503"))
        self.assertNotEqual(_valid_uuid(ev.get("operation_id")), _valid_uuid(ev.get("event_id")))
        self.assertEqual((ev.get("attempt"), ev.get("generation")), (claimed_attempt, repo_gen))
        self._assert_log_redacted(h, [sentinel, f"tok-{tag}", f"b-{tag}"])

    def test_remaining_four_scoped_workers_emit_redacted_native_faults(self) -> None:
        tag = uuid.uuid4().hex
        stub = _GatedLoopbackServer(status_code=200)
        self.addCleanup(stub.close)
        s3_key, s3_secret, s3_bucket = f"AKIAOBS80KEY{tag[:12].upper()}", f"obs80-s3-sec-{tag}", f"obs80-bkt-{tag[:12]}"
        wh_secret, wh_url = f"obs80-whsec-{tag}", f"{stub.url}/hook?wh_query_secret={tag}"
        sentinel = f"obs80-w4-{tag}-postgres://dbu:dbp-{tag}@127.0.0.1:1/x?q=leak-{tag} Authorization: Bearer tok-{tag} {s3_secret} {wh_secret}"
        h = self._new_harness(
            ROOTYARD_OUTBOX_WORKER="true", ROOTYARD_WORKER_POLL_MS="200", ROOTYARD_WEBHOOK_ALLOW_LOOPBACK="true",
            ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE="true", ROOTYARD_WORKSPACE_MOUNT_MODE="direct",
            ROOTYARD_STORAGE_MAINTENANCE="false", ROOTYARD_SESSION_GC="false",
            ROOTYARD_OBJECT_STORE_ENDPOINT=stub.url, ROOTYARD_OBJECT_STORE_BUCKET=s3_bucket,
            ROOTYARD_OBJECT_STORE_REGION="us-east-1", ROOTYARD_OBJECT_STORE_ACCESS_KEY=s3_key,
            ROOTYARD_OBJECT_STORE_SECRET_KEY=s3_secret,
        )
        # Seed workspace_remote_gc rows + trigger before start() so its immediate startup tick fires.
        h.sql(f'CREATE SCHEMA "{h.schema}"', isolated=False)
        h.schema_created = True
        h.cli("migrate")
        h.alice, h.bob, h.reader = h.account("create-user", "alice"), h.account("create-user", "bob"), h.account("create-token", "alice", "--read-only")
        alice_id, gc_repo, gc_ws = h.alice["user_id"], str(uuid.uuid4()), str(uuid.uuid4())
        cp_failed, cp_active, digest = str(uuid.uuid4()), str(uuid.uuid4()), "a" * 64
        h.sql(f"""
            INSERT INTO repositories(id,owner_id,name,state) VALUES ('{gc_repo}','{alice_id}','gc-seed','ready');
            INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,state,host_id,lease_until)
            VALUES ('{gc_ws}','{gc_repo}','alice','gc-seed','gc-agent','{alice_id}','ready','{uuid.uuid4()}',clock_timestamp()+interval '1 hour');
            INSERT INTO workspace_checkpoints(id,workspace_id,repository_id,captured_revision,lease_epoch,state)
            VALUES ('{cp_failed}','{gc_ws}','{gc_repo}',0,1,'failed'),('{cp_active}','{gc_ws}','{gc_repo}',0,1,'committed');
            INSERT INTO workspace_remote_staging_objects(checkpoint_id,tenant_id,digest,size,kind)
            VALUES ('{cp_failed}','{alice_id}','{digest}',16,'file'),('{cp_active}','{alice_id}','{digest}',16,'file');
            CREATE FUNCTION "fn_fk_{tag}"() RETURNS trigger LANGUAGE plpgsql AS $fn$
            BEGIN RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = '{sentinel}'; END $fn$;
            CREATE FUNCTION "fn_to_{tag}"() RETURNS trigger LANGUAGE plpgsql AS $fn$
            BEGIN PERFORM pg_sleep(6); RETURN NEW; END $fn$;
            CREATE TRIGGER "trg_rgc_{tag}" BEFORE DELETE ON workspace_remote_staging_objects FOR EACH ROW EXECUTE FUNCTION "fn_fk_{tag}"();
        """)
        h.start()
        log_path = h.root / "server.log"

        ev_rgc = _wait_event(log_path, lambda e: e.get("scope") == "worker" and e.get("worker") == "workspace_remote_gc")
        self.assertEqual((ev_rgc.get("phase"), ev_rgc.get("kind"), ev_rgc.get("sqlstate")), ("collect", "database", "23503"))
        h.sql(f'DROP TRIGGER IF EXISTS "trg_rgc_{tag}" ON workspace_remote_staging_objects')

        ws_repo = h.create_repository({"name": "ws-live"}, token=h.alice)
        work = h.root / "ws-seed"
        h.git("init", "-q", "-b", "main", str(work))
        h.git("-C", str(work), "config", "user.name", "Alice")
        h.git("-C", str(work), "config", "user.email", "alice@example.invalid")
        (work / "readme.txt").write_text("payload-" + tag, encoding="utf-8")
        h.git("-C", str(work), "add", "readme.txt")
        h.git("-C", str(work), "commit", "-q", "-m", "init")
        h.git("-C", str(work), "push", "-q", f"{h.base}/git/alice/ws-live.git", "HEAD:refs/heads/main", token=h.alice)
        status, body, _ = h.http("/api/workspaces", token=h.alice, method="POST",
                                 body={"owner": "alice", "repository": "ws-live", "agent_id": "obs80-agent"},
                                 extra_headers={"Idempotency-Key": str(uuid.uuid4())})
        self.assertEqual(status, 201, body)
        ws_id = json.loads(body)["id"]
        h.sql(f'CREATE TRIGGER "trg_wsc_{tag}" BEFORE INSERT OR UPDATE ON workspace_capture_state '
              f"FOR EACH ROW WHEN (NEW.workspace_id = '{ws_id}'::uuid) EXECUTE FUNCTION \"fn_to_{tag}\"();")
        ev_wsc = _wait_event(log_path, lambda e: e.get("scope") == "worker"
                             and e.get("worker") == "workspace_capture" and e.get("sqlstate") == "57014", timeout=25.0)
        self.assertEqual((ev_wsc.get("phase"), ev_wsc.get("kind")), ("reconcile", "database"))
        h.sql(f'DROP TRIGGER IF EXISTS "trg_wsc_{tag}" ON workspace_capture_state')

        hook_id, deliv_id, wh_digest = str(uuid.uuid4()), str(uuid.uuid4()), hashlib.sha256(wh_secret.encode()).hexdigest()
        h.sql(f"""
            INSERT INTO forge_webhooks(id,tenant_id,repository_id,url,secret,secret_sha256,events,ci_contexts,auto_ci_pin,active,max_attempts,timeout_ms)
            VALUES ('{hook_id}','{alice_id}','{ws_repo['id']}','{wh_url}','{wh_secret}','{wh_digest}','["ping"]'::jsonb,'[]'::jsonb,false,true,5,5000);
            INSERT INTO forge_webhook_deliveries(id,webhook_id,tenant_id,repository_id,event_id,event_type,payload,request_headers,signature_256,state,attempts,next_attempt_unix,max_attempts)
            VALUES ('{deliv_id}','{hook_id}','{alice_id}','{ws_repo['id']}','{uuid.uuid4()}','ping','{{}}'::jsonb,'{{}}'::jsonb,'sha256='||repeat('b',64),'pending',0,0,5);
            CREATE TRIGGER "trg_wh_{tag}" BEFORE UPDATE ON forge_webhook_deliveries FOR EACH ROW WHEN (NEW.id = '{deliv_id}'::uuid) EXECUTE FUNCTION "fn_fk_{tag}"();
        """)
        ev_wh = _wait_event(log_path, lambda e: e.get("scope") == "worker" and e.get("worker") == "webhooks_background" and e.get("phase") == "deliver")
        self.assertEqual((ev_wh.get("kind"), ev_wh.get("sqlstate")), ("database", "23503"))
        h.sql(f'DROP TRIGGER IF EXISTS "trg_wh_{tag}" ON forge_webhook_deliveries')

        op_row, ev_sha = str(uuid.uuid4()), "c" * 64
        h.sql(f"""
            CREATE TRIGGER "trg_dd_{tag}" BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION "fn_fk_{tag}"();
            INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,evidence,outcome)
            VALUES ('{op_row}','{ws_repo['id']}','{alice_id}','{h.alice['token_id']}','alice',99,1,'{{}}','recorded');
            INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid)
            VALUES ('{ev_sha}','{op_row}','{ws_repo['id']}',1,99,1,'refs/heads/obs80','{'0'*40}','{'1'*40}');
            INSERT INTO event_deliveries(event_id,consumer,state) VALUES ('{ev_sha}','audit-log','pending');
        """)
        ev_dd = _wait_event(log_path, lambda e: e.get("scope") == "worker" and e.get("worker") == "durable_dispatch" and e.get("phase") == "dispatch")
        self.assertEqual((ev_dd.get("kind"), ev_dd.get("sqlstate")), ("database", "23503"))
        h.sql(f'DROP TRIGGER IF EXISTS "trg_dd_{tag}" ON audit_events')

        self.assertEqual(len({_valid_uuid(ev["operation_id"]) for ev in (ev_rgc, ev_wsc, ev_wh, ev_dd)}), 4)
        self._assert_log_redacted(h, [sentinel, s3_key, s3_secret, s3_bucket, stub.url, wh_secret, wh_url, f"wh_query_secret={tag}", f"payload-{tag}"])

    def test_metrics_auto_discovers_backlog_starvation_remote_repair_and_db_degradation(self) -> None:
        tag = uuid.uuid4().hex
        s3, metrics_port = _GatedLoopbackServer(status_code=503), _free_port()
        self.addCleanup(s3.close)
        s3_key, s3_secret, s3_bucket, wh_secret = f"AKIAOBS80M{tag[:10].upper()}", f"s3m-sec-{tag}", f"obs80m-{tag[:10]}", f"whm-sec-{tag}"
        h = self._new_harness(ROOTYARD_METRICS_BIND=f"127.0.0.1:{metrics_port}", ROOTYARD_OUTBOX_WORKER="false",
                              ROOTYARD_STORAGE_MAINTENANCE="false", ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS="60",
                              ROOTYARD_SESSION_GC="false", ROOTYARD_WORKSPACE_MOUNT_MODE="fuse-helper",
                              ROOTYARD_OBJECT_STORE_ENDPOINT=s3.url, ROOTYARD_OBJECT_STORE_BUCKET=s3_bucket,
                              ROOTYARD_OBJECT_STORE_REGION="us-east-1", ROOTYARD_OBJECT_STORE_ACCESS_KEY=s3_key, ROOTYARD_OBJECT_STORE_SECRET_KEY=s3_secret)
        h.setup()
        repo_id, alice_id = h.create_repository({"name": "metrics-obs80"}, token=h.alice)["id"], h.alice["user_id"]
        volume_id = (h.root / "data" / ".volume-id").read_text(encoding="utf-8").strip()
        hook_id, op_id, ev_id = str(uuid.uuid4()), str(uuid.uuid4()), "d" * 64
        ws_unsampled, ws_stale, ws_expired = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        h.sql(f"""
            INSERT INTO forge_webhooks(id,tenant_id,repository_id,url,secret,secret_sha256,events,ci_contexts,auto_ci_pin,active,max_attempts,timeout_ms)
            VALUES ('{hook_id}','{alice_id}','{repo_id}','https://hooks.example.invalid/obs80','{wh_secret}','{hashlib.sha256(wh_secret.encode()).hexdigest()}','["ping"]'::jsonb,'[]'::jsonb,false,true,5,5000);
            INSERT INTO forge_webhook_deliveries(id,webhook_id,tenant_id,repository_id,event_id,event_type,payload,request_headers,signature_256,state,attempts,next_attempt_unix,max_attempts,created_at)
            VALUES ('{uuid.uuid4()}','{hook_id}','{alice_id}','{repo_id}','{uuid.uuid4()}','ping','{{}}'::jsonb,'{{}}'::jsonb,'sha256='||repeat('a',64),'pending',0,0,5,clock_timestamp()-interval '240 seconds');
            INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,evidence,outcome)
            VALUES ('{op_id}','{repo_id}','{alice_id}','{h.alice['token_id']}','alice',1,1,'{{}}','unknown');
            INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid,created_at)
            VALUES ('{ev_id}','{op_id}','{repo_id}',1,1,1,'refs/heads/main','{'0'*40}','{'1'*40}',clock_timestamp()-interval '150 seconds');
            INSERT INTO event_deliveries(event_id,consumer,state) VALUES ('{ev_id}','audit-log','pending');
            INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,state,host_id,lease_until) VALUES
              ('{ws_unsampled}','{repo_id}','alice','metrics-obs80','agent','{alice_id}','ready','{volume_id}',clock_timestamp()+interval '1 hour'),
              ('{ws_stale}','{repo_id}','alice','metrics-obs80','agent','{alice_id}','ready','{volume_id}',clock_timestamp()+interval '1 hour'),
              ('{ws_expired}','{repo_id}','alice','metrics-obs80','agent','{alice_id}','ready','{volume_id}',clock_timestamp()-interval '90 seconds');
            INSERT INTO workspace_capture_state(workspace_id,fingerprint,scanned_at)
            VALUES ('{ws_stale}','fp-obs80',clock_timestamp()-interval '1200 seconds');
            INSERT INTO storage_maintenance_repo_state(repository_id,tenant_id,last_scan_at,last_scan_generation)
            VALUES ('{repo_id}','{alice_id}',clock_timestamp()-interval '200 seconds',1);
            INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,state,repository_generation,not_before,created_at)
            VALUES ('{uuid.uuid4()}','{repo_id}','{alice_id}','gitfs_repack','queued',1,clock_timestamp()-interval '10 seconds',clock_timestamp()-interval '600 seconds');
            INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,state,repository_generation,attempt,claim_generation,lease_owner,lease_until)
            VALUES ('{uuid.uuid4()}','{repo_id}','{alice_id}','gitfs_stage_cleanup','running',1,1,1,'{uuid.uuid4()}',clock_timestamp()-interval '30 seconds');
        """)

        cold_bytes = b"obs80-cold-lfs-" + tag.encode()
        cold_oid = hashlib.sha256(cold_bytes).hexdigest()
        h.sql(f"INSERT INTO lfs_objects(tenant_id,repository_id,oid,size,state) VALUES ('{alice_id}','{repo_id}','{cold_oid}',{len(cold_bytes)},'ready')")
        code_lfs, _, lfs_hdrs = h.http(f"/git/alice/metrics-obs80.git/info/lfs/objects/{cold_oid}/{len(cold_bytes)}", token=h.reader)
        self.assertEqual(code_lfs, 503)
        req_id = _valid_uuid(next(v for k, v in lfs_hdrs.items() if k.lower() == "x-request-id"))
        ev_s3 = _wait_event(h.root / "server.log", lambda e: e.get("request_id") == req_id)
        self.assertEqual((ev_s3.get("kind"), ev_s3.get("remote_op"), ev_s3.get("remote_status")), ("remote_store", "head", 503))

        warm_bytes = b"obs80-warm-lfs-" + tag.encode()
        warm_oid = hashlib.sha256(warm_bytes).hexdigest()
        lfs_root, lfs_repo_dir = h.root / "data" / "lfs", h.root / "data" / "lfs" / repo_id
        lfs_repo_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(lfs_root, 0o700)
        os.chmod(lfs_repo_dir, 0o700)
        (lfs_repo_dir / warm_oid).write_bytes(warm_bytes)
        os.chmod(lfs_repo_dir / warm_oid, 0o600)
        h.sql(f"INSERT INTO lfs_objects(tenant_id,repository_id,oid,size,state) VALUES ('{alice_id}','{repo_id}','{warm_oid}',{len(warm_bytes)},'ready')")

        s3.gate_head = True
        s3.head_arrived.clear()
        s3.release_head.clear()
        st_batch, _, _ = h.http("/git/alice/metrics-obs80.git/info/lfs/objects/batch", token=h.alice, method="POST",
                                body=json.dumps({"operation": "upload", "transfers": ["basic"], "objects": [{"oid": warm_oid, "size": len(warm_bytes)}], "hash_algo": "sha256"}).encode(),
                                content_type=LFS_MIME, extra_headers={"Accept": LFS_MIME})
        self.assertEqual(st_batch, 200)
        self.assertTrue(s3.head_arrived.wait(timeout=10.0), "Deferred LFS repair did not contact S3")

        code_ok, text_ok, hdrs_ok = _scrape_metrics(metrics_port)
        self.assertEqual((code_ok, hdrs_ok.get("cache-control")), (200, "no-store"))
        values = dict(line.split(" ", 1) for line in text_ok.splitlines() if line and not line.startswith("#"))
        self.assertEqual(len(values), 94)
        allowed_labels = metrics_suite.fixed_labels()
        for series, val in values.items():
            self.assertGreaterEqual(float(val), 0.0)
            base, rest = series.split("{", 1) if "{" in series else (series, None)
            self.assertRegex(base, r"^rootyard_[a-z_]+$")
            if rest is not None:
                self.assertIn(rest[:-1], allowed_labels, f"Unbounded or unexpected label in {series}")
        for leak in (alice_id, repo_id, volume_id, cold_oid, warm_oid, wh_secret, s3_key, s3_secret, s3_bucket) + tuple(h.secrets):
            self.assertNotIn(leak, text_ok)

        self.assertEqual((values["rootyard_postgres_up"], values["rootyard_operations_unresolved"]), ("1", "1"))
        self.assertEqual(values['rootyard_event_deliveries{state="pending"}'], "1")
        self.assertGreaterEqual(float(values["rootyard_event_delivery_oldest_age_seconds"]), 140.0)
        self.assertGreaterEqual(float(values["rootyard_webhook_delivery_oldest_age_seconds"]), 230.0)
        self.assertEqual((values["rootyard_workspace_capture_never_sampled"], values["rootyard_workspace_lease_expired"]), ("1", "1"))
        self.assertGreaterEqual(float(values["rootyard_workspace_capture_oldest_age_seconds"]), 1190.0)
        self.assertEqual(values['rootyard_storage_maintenance_jobs{backend="gitfs",kind="gitfs_repack",state="due_queued"}'], "1")
        self.assertGreaterEqual(float(values['rootyard_storage_maintenance_oldest_queued_age_seconds{backend="gitfs",kind="gitfs_repack"}']), 590.0)
        self.assertEqual(values['rootyard_storage_maintenance_jobs{backend="gitfs",kind="gitfs_stage_cleanup",state="expired_running_lease"}'], "1")
        self.assertEqual(values['rootyard_storage_maintenance_repos{backend="gitfs",state="due_scan"}'], "1")
        self.assertGreaterEqual(float(values['rootyard_storage_maintenance_oldest_overdue_scan_age_seconds{backend="gitfs"}']), 130.0)
        self.assertGreaterEqual(int(values["rootyard_lfs_remote_failures_total"]), 1)
        self.assertEqual(values["rootyard_lfs_remote_repair_backlog"], "1")

        s3.gate_head = False
        s3.release_head.set()
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            _, drain_txt, _ = _scrape_metrics(metrics_port)
            drain_vals = dict(line.split(" ", 1) for line in drain_txt.splitlines() if line and not line.startswith("#"))
            if drain_vals["rootyard_lfs_remote_repair_backlog"] == "0" and int(drain_vals["rootyard_lfs_remote_failures_total"]) >= 2:
                break
            time.sleep(0.1)
        else:
            self.fail(f"Repair backlog did not drain and record failure: {drain_vals!r}")

        # Induce real 4s PostgreSQL statement_timeout on /metrics via ACCESS EXCLUSIVE lock; verify 503 + preserved local counters.
        locker = subprocess.Popen(["psql", "--dbname", h.db, "-X", "-v", "ON_ERROR_STOP=1", "-qAt"],
                                  env=dict(h.env, PGDATABASE=h.db), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert locker.stdin is not None and locker.stdout is not None and locker.stderr is not None
        try:
            locker.stdin.write("BEGIN;\nLOCK TABLE event_deliveries IN ACCESS EXCLUSIVE MODE;\nSELECT 'LOCKED';\n")
            locker.stdin.flush()
            self.assertEqual(locker.stdout.readline().strip(), "LOCKED")
            code_503, text_503, _ = _scrape_metrics(metrics_port)
            self.assertEqual(code_503, 503)
            vals_503 = dict(line.split(" ", 1) for line in text_503.splitlines() if line and not line.startswith("#"))
            self.assertEqual(vals_503["rootyard_postgres_up"], "0")
            for kept in ("rootyard_error_log_dropped_total", "rootyard_lfs_remote_failures_total",
                         "rootyard_lfs_remote_repair_backlog", "rootyard_db_pool_max_size", "rootyard_session_gc_cycles_total"):
                self.assertIn(kept, vals_503)
            self.assertGreaterEqual(int(vals_503["rootyard_lfs_remote_failures_total"]), 2)
            for omitted in ("rootyard_repositories", "rootyard_operations_unresolved", "rootyard_event_deliveries",
                            "rootyard_webhook_delivery_oldest_age_seconds", "rootyard_workspace_", "rootyard_storage_maintenance"):
                self.assertFalse(any(k.startswith(omitted) for k in vals_503), f"SQL gauge {omitted} leaked on 503")
        finally:
            if not locker.stdin.closed:
                locker.stdin.write("ROLLBACK;\n\\q\n")
                locker.stdin.close()
            locker.stdout.close()
            locker.stderr.close()
            if locker.poll() is None:
                try:
                    locker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    locker.kill()
                    locker.wait()

        code_rec, text_rec, _ = _scrape_metrics(metrics_port)
        self.assertEqual(code_rec, 200)
        self.assertIn("rootyard_postgres_up 1\n", text_rec)
        self._assert_log_redacted(h, [wh_secret, s3_key, s3_secret, s3_bucket, s3.url])


if __name__ == "__main__":
    unittest.main()
