#!/usr/bin/env python3
"""Per-PR live Rust storage_lifecycle worker fence regression (#90).

Runs under ``python3 -m unittest discover -s tests -p 'test_*.py'`` after CI
builds ``target/debug/rootyard``. When ``GITHUB_ACTIONS=true``, missing
``ROOTYARD_TEST_DATABASE_URL`` or missing ``target/debug/rootyard`` fails hard
rather than skipping. Locally, unset configuration builds ``rootyard`` and
starts an ephemeral PostgreSQL cluster under ``TMPDIR``.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema_baseline  # noqa: E402
from test_storage_identity_fks import (  # noqa: E402
    JOBS_OWNER_FK,
    psql_exec,
    resolve_database_url,
    sql_scalar,
    start_ephemeral_pg,
)

DEFAULT_BINARY = schema_baseline.ROOT / "target" / "debug" / "rootyard"
FENCE_DIAGNOSTIC = "maintenance claim or repository generation changed"


def resolve_binary_path(environ, default_binary, build_local):
    raw = (environ.get("ROOTYARD_TEST_BINARY") or "").strip()
    candidate = Path(raw) if raw else Path(default_binary)
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate.resolve()
    if environ.get("GITHUB_ACTIONS") == "true":
        raise RuntimeError(
            f"Executable rootyard binary is required when GITHUB_ACTIONS=true ({candidate}); "
            "refusing to silently skip runtime worker regression in CI"
        )
    return build_local(candidate)


class StorageIdentityRuntimeTest(unittest.TestCase):
    _psql = staticmethod(psql_exec)
    _sql = staticmethod(sql_scalar)

    @classmethod
    def setUpClass(cls):
        for tool in ("psql", "git"):
            if not shutil.which(tool):
                raise RuntimeError(f"{tool} is required for live storage_lifecycle regression")
        cls.binary = resolve_binary_path(os.environ, DEFAULT_BINARY, cls._build_binary)
        cls.base_db = resolve_database_url(
            os.environ,
            lambda: start_ephemeral_pg(cls.addClassCleanup, prefix="rootyard-fk90-rt-pg-"),
        )
        if cls._sql(cls.base_db, "SELECT 1") != "1":
            raise RuntimeError("PostgreSQL connectivity check failed")

    @classmethod
    def _build_binary(cls, target_path):
        if not shutil.which("cargo"):
            raise RuntimeError("target/debug/rootyard is missing and cargo is unavailable")
        subprocess.run(
            ["cargo", "build", "--locked", "--bin", "rootyard"],
            cwd=schema_baseline.ROOT,
            check=True,
            timeout=300,
        )
        if not (target_path.is_file() and os.access(target_path, os.X_OK)):
            raise RuntimeError(f"cargo build succeeded but {target_path} is not executable")
        return target_path.resolve()

    @staticmethod
    def _stop_server(holder):
        proc = holder.get("proc")
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
        holder["proc"] = None
        log_handle = holder.get("log")
        if log_handle is not None:
            log_handle.close()
            holder["log"] = None

    def _start_server(self, holder, env, base_url, root):
        self._stop_server(holder)
        holder["log"] = open(root / "server.log", "ab")
        holder["proc"] = subprocess.Popen(
            [str(self.binary), "serve"],
            env=env, stdout=holder["log"], stderr=holder["log"], start_new_session=True,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if holder["proc"].poll() is not None:
                tail = (root / "server.log").read_bytes()[-3000:].decode(errors="replace")
                raise RuntimeError(f"rootyard serve exited early:\n{tail}")
            try:
                with urllib.request.urlopen(base_url + "/health/ready", timeout=2) as resp:
                    if resp.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise RuntimeError("Timed out waiting for /health/ready")

    def _http_json(self, base_url, path, token, method="GET", payload=None):
        headers = {"Authorization": "Bearer " + token["token"]}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())

    def _create_ready_repo(self, base_url, token, name):
        status, created = self._http_json(base_url, "/api/repos", token, method="POST", payload={"name": name})
        self.assertIn(status, (201, 202))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            code, view = self._http_json(base_url, f"/api/repos/{token['username']}/{name}", token)
            self.assertEqual(code, 200)
            if view.get("state") == "ready":
                return view
            time.sleep(0.1)
        self.fail(f"Repository {name} did not reach ready")

    def _git(self, env, *args, cwd=None, token=None, stdin_bytes=None):
        cmd = ["git"]
        if token is not None:
            basic = base64.b64encode(f"{token['username']}:{token['token']}".encode()).decode()
            cmd.extend(["-c", f"http.extraHeader=Authorization: Basic {basic}"])
        cmd.extend(args)
        proc = subprocess.run(cmd, cwd=cwd, env=env, input=stdin_bytes, capture_output=True, timeout=60)
        if proc.returncode != 0:
            stderr = proc.stderr.decode(errors="replace")
            if token is not None:
                stderr = stderr.replace(token["token"], "[REDACTED]")
            raise AssertionError(f"git failed (rc={proc.returncode}): {stderr[-2000:]}")
        return proc.stdout.decode().strip()

    def _assert_fk_rejected(self, db_url, insert_sql, expected_constraint):
        probe = (
            "BEGIN;\nCREATE TEMP TABLE fk90_rt_probe(st text, cn text) ON COMMIT DROP;\n"
            f"DO $$ DECLARE s text; c text; BEGIN BEGIN {insert_sql}; EXCEPTION WHEN OTHERS THEN "
            "GET STACKED DIAGNOSTICS s = RETURNED_SQLSTATE, c = CONSTRAINT_NAME; "
            "INSERT INTO fk90_rt_probe VALUES (s, c); END; END $$;\n"
            "SELECT COALESCE(st, '') || '|' || COALESCE(cn, '') FROM fk90_rt_probe;\nCOMMIT;\n"
        )
        observed = self._psql(db_url, stdin_sql=probe).stdout.strip()
        self.assertEqual(observed, f"23503|{expected_constraint}")

    def _enqueue_and_wait_terminal(self, db_url, repo_id, tenant_id, kind, generation, timeout_secs=25):
        job_id = str(uuid.uuid4())
        self._sql(
            db_url,
            "INSERT INTO storage_maintenance_jobs(id, repository_id, tenant_id, kind, repository_generation) "
            f"VALUES ('{job_id}', '{repo_id}', '{tenant_id}', '{kind}', {generation})",
        )
        deadline = time.monotonic() + timeout_secs
        while time.monotonic() < deadline:
            row = self._sql(
                db_url,
                "SELECT state || '|' || attempt::text || '|' || COALESCE(last_error, '') || '|' || "
                f"COALESCE(result::text, '{{}}') FROM storage_maintenance_jobs WHERE id='{job_id}'",
            )
            state, attempt, last_error, result_raw = row.split("|", 3)
            if state in ("succeeded", "failed"):
                return state, int(attempt), last_error, json.loads(result_raw)
            time.sleep(0.15)
        self.fail(f"Job {job_id} ({kind}) did not reach terminal state within {timeout_secs}s")

    def _wait_sql(self, db_url, query, expected, timeout_secs=20):
        deadline = time.monotonic() + timeout_secs
        while time.monotonic() < deadline:
            if self._sql(db_url, query) == expected:
                return
            time.sleep(0.1)
        self.fail(f"Query did not reach {expected!r}: {self._sql(db_url, query)!r}")

    def test_ci_requires_explicit_database_url_and_prebuilt_binary(self):
        with self.assertRaisesRegex(RuntimeError, "GITHUB_ACTIONS=true"):
            resolve_database_url({"GITHUB_ACTIONS": "true"}, lambda: self.fail("started PG in CI"))
        with self.assertRaisesRegex(RuntimeError, "GITHUB_ACTIONS=true"):
            resolve_binary_path(
                {"GITHUB_ACTIONS": "true"},
                Path("/nonexistent/rootyard-missing-90"),
                lambda _: self.fail("ran cargo build in CI"),
            )

    def test_live_worker_fences_and_valid_progression_for_gitfs_and_pando(self):
        schema = "rootyard_fk90_rt_" + uuid.uuid4().hex
        parts = urllib.parse.urlsplit(self.base_db)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if any(k == "options" for k, _ in query):
            raise RuntimeError("ROOTYARD_TEST_DATABASE_URL must not preset options")
        query.append(("options", f"-csearch_path={schema}"))
        db_url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))

        root = Path(tempfile.mkdtemp(prefix="rootyard-fk90-rt-"))
        holder = {"proc": None, "log": None}
        self.addCleanup(self._sql, self.base_db, f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        self.addCleanup(shutil.rmtree, root, True)
        self.addCleanup(self._stop_server, holder)
        self._sql(self.base_db, f'CREATE SCHEMA "{schema}"')

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base_url = f"http://127.0.0.1:{port}"
        env = {k: v for k, v in os.environ.items() if not k.startswith("ROOTYARD_OBJECT_STORE_")}
        env.update(
            DATABASE_URL=db_url,
            ROOTYARD_DATA_DIR=str(root / "data"),
            ROOTYARD_BIND=f"127.0.0.1:{port}",
            ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE="1000",
            ROOTYARD_STORAGE_MAINTENANCE="false",
            ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS="1",
            ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS="3600",
            ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS="30",
            ROOTYARD_STORAGE_MAINTENANCE_MAX_ATTEMPTS="1",
            ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS="1",
            ROOTYARD_PANDO_REMOTE_DELETE="true",
            GIT_TERMINAL_PROMPT="0",
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            LC_ALL="C",
        )

        subprocess.run([str(self.binary), "migrate"], env=env, check=True, capture_output=True, timeout=60)
        installed = [int(v) for v in self._sql(db_url, "SELECT version FROM schema_migrations ORDER BY version").splitlines()]
        self.assertEqual(installed, schema_baseline.SCHEMA_VERSIONS)
        alice = json.loads(subprocess.run(
            [str(self.binary), "create-user", "alice"], env=env, check=True, capture_output=True, text=True, timeout=30
        ).stdout)
        bob = json.loads(subprocess.run(
            [str(self.binary), "create-user", "bob"], env=env, check=True, capture_output=True, text=True, timeout=30
        ).stdout)
        alice_id, bob_id = alice["user_id"], bob["user_id"]

        # Phase 1: create real repositories & Git history before starting the maintenance loop.
        self._start_server(holder, env, base_url, root)
        gitfs_repo = self._create_ready_repo(base_url, alice, "gitfs-fenced")
        pando_repo = self._create_ready_repo(base_url, alice, "pando-fenced")
        gitfs_id, pando_id = gitfs_repo["id"], pando_repo["id"]

        work = root / "gitfs-work"
        self._git(env, "clone", base_url + gitfs_repo["clone_path"], str(work), token=alice)
        self._git(env, "config", "user.name", "Alice", cwd=work)
        self._git(env, "config", "user.email", "alice@rootyard.local", cwd=work)
        (work / "README.md").write_text("reachable gitfs baseline\n")
        self._git(env, "add", "README.md", cwd=work)
        self._git(env, "commit", "-m", "baseline", cwd=work)
        reachable_oid = self._git(env, "rev-parse", "HEAD", cwd=work)
        self._git(env, "push", "origin", "HEAD:main", cwd=work, token=alice)
        self._wait_sql(
            db_url,
            f"SELECT count(*) FROM outbox_events e JOIN event_deliveries d USING(event_id) "
            f"WHERE e.repository_id='{gitfs_id}' AND d.consumer='ref-index' AND d.state<>'delivered'",
            "0",
        )
        self._stop_server(holder)

        bare = root / "data" / "repos" / f"{gitfs_id}.git"
        self._git(env, "--git-dir", str(bare), "repack", "-a", "-d")
        pack_files = sorted((bare / "objects" / "pack").glob("pack-*.pack"))
        self.assertEqual(len(pack_files), 1)
        orphan_a = self._git(env, "--git-dir", str(bare), "hash-object", "-w", "--stdin", stdin_bytes=b"orphan-a\n")
        orphan_b = self._git(env, "--git-dir", str(bare), "hash-object", "-w", "--stdin", stdin_bytes=b"orphan-b\n")
        loose_a = bare / "objects" / orphan_a[:2] / orphan_a[2:]
        loose_b = bare / "objects" / orphan_b[:2] / orphan_b[2:]
        self.assertTrue(loose_a.is_file() and loose_b.is_file())

        authority_id = self._sql(db_url, "SELECT authority_id::text FROM pando_storage_authorities WHERE singleton")
        manifest_serv, manifest_orph = str(uuid.uuid4()), str(uuid.uuid4())
        sha_serv = uuid.uuid4().hex + uuid.uuid4().hex
        sha_orph = uuid.uuid4().hex + uuid.uuid4().hex
        rel_serv = f"tenants/{alice_id}/authorities/{authority_id}/g1/pando-cipher/{sha_serv}"
        rel_orph = f"tenants/{alice_id}/authorities/{authority_id}/g1/pando-cipher/{sha_orph}"
        pando_work = root / "data" / "pando-pack-work"
        serv_file, orph_file = pando_work / rel_serv, pando_work / rel_orph
        for target_file, content in ((serv_file, b"serving-cipher"), (orph_file, b"orphan-cipher")):
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_bytes(content)

        self._psql(db_url, stdin_sql=(
            f"UPDATE repositories SET storage_generation=2 WHERE id IN ('{gitfs_id}', '{pando_id}');\n"
            f"UPDATE repositories SET storage_backend='pando', transition_state='stable' WHERE id='{pando_id}';\n"
            f"INSERT INTO pando_remote_artifacts(authority_id, tenant_id, namespace, sha256, size, object_generation, remote_path, state) VALUES "
            f"('{authority_id}', '{alice_id}', 'pando-cipher', '{sha_serv}', 14, 1, '{rel_serv}', 'active'), "
            f"('{authority_id}', '{alice_id}', 'pando-cipher', '{sha_orph}', 13, 1, '{rel_orph}', 'active');\n"
            f"INSERT INTO pando_pack_manifests(id, repository_id, tenant_id, storage_generation, object_format, manifest) VALUES "
            f"('{manifest_serv}', '{pando_id}', '{alice_id}', 2, 'sha1', '{{}}'::jsonb), "
            f"('{manifest_orph}', '{pando_id}', '{alice_id}', 2, 'sha1', '{{}}'::jsonb);\n"
            f"INSERT INTO pando_manifest_artifacts VALUES "
            f"('{manifest_serv}', '{pando_id}', '{authority_id}', '{alice_id}', 'pando-cipher', '{sha_serv}', 'pack-cipher'), "
            f"('{manifest_orph}', '{pando_id}', '{authority_id}', '{alice_id}', 'pando-cipher', '{sha_orph}', 'pack-cipher');\n"
            f"INSERT INTO pando_repository_states(repository_id, tenant_id, storage_generation, ref_generation, object_format, state, head_ref, pack_ids) "
            f"VALUES ('{pando_id}', '{alice_id}', 2, 1, 'sha1', 'serving', 'refs/heads/main', ARRAY['{manifest_serv}'::uuid]);\n"
            f"INSERT INTO storage_maintenance_repo_state(repository_id, tenant_id, last_scan_at, last_scan_generation) VALUES "
            f"('{gitfs_id}', '{alice_id}', clock_timestamp(), 2), ('{pando_id}', '{alice_id}', clock_timestamp(), 2);\n"
        ))

        env["ROOTYARD_STORAGE_MAINTENANCE"] = "true"
        self._start_server(holder, env, base_url, root)

        # 1. Wrong-owner rows are rejected at PostgreSQL (23503) on mark & delete for both backends.
        for repo_id, kinds in (
            (gitfs_id, ("gitfs_unreachable_mark", "gitfs_tombstone_delete")),
            (pando_id, ("pando_unreachable_mark", "pando_tombstone_delete")),
        ):
            for kind in kinds:
                self._assert_fk_rejected(
                    db_url,
                    f"INSERT INTO storage_maintenance_jobs(id, repository_id, tenant_id, kind, repository_generation) "
                    f"VALUES ('{uuid.uuid4()}', '{repo_id}', '{bob_id}', '{kind}', 2)",
                    JOBS_OWNER_FK,
                )

        def run_fenced_matrix(repo_id, true_backend, wrong_backend, kind, check_side_effects):
            fenced_cases = (
                (1, None, None),
                (2, f"UPDATE repositories SET storage_backend='{wrong_backend}' WHERE id='{repo_id}'",
                 f"UPDATE repositories SET storage_backend='{true_backend}' WHERE id='{repo_id}'"),
                (2, f"UPDATE repositories SET state='recovering', recovery_reason='manual_fence' WHERE id='{repo_id}'",
                 f"UPDATE repositories SET state='ready', recovery_reason=NULL WHERE id='{repo_id}'"),
                (2, f"UPDATE repositories SET state='provisioning', recovery_reason=NULL, next_retry_at=clock_timestamp()+interval '1 hour' WHERE id='{repo_id}'",
                 f"UPDATE repositories SET state='ready', next_retry_at=clock_timestamp() WHERE id='{repo_id}'"),
            )
            for job_gen, mutate_sql, restore_sql in fenced_cases:
                if mutate_sql:
                    self._sql(db_url, mutate_sql)
                try:
                    state, attempt, last_error, _ = self._enqueue_and_wait_terminal(
                        db_url, repo_id, alice_id, kind, job_gen
                    )
                    self.assertEqual((state, attempt), ("failed", 1))
                    self.assertIn(FENCE_DIAGNOSTIC, last_error)
                    check_side_effects()
                finally:
                    if restore_sql:
                        self._sql(db_url, restore_sql)

        # 2a & 3a. GitFS mark fenced cases -> zero tombstones, then valid mark succeeds.
        run_fenced_matrix(
            gitfs_id, "gitfs", "pando", "gitfs_unreachable_mark",
            lambda: self.assertEqual(
                self._sql(db_url, f"SELECT count(*) FROM storage_maintenance_tombstones WHERE repository_id='{gitfs_id}'"), "0"
            ),
        )
        state, attempt, last_error, res = self._enqueue_and_wait_terminal(
            db_url, gitfs_id, alice_id, "gitfs_unreachable_mark", 2
        )
        self.assertEqual((state, attempt, last_error), ("succeeded", 1, ""))
        self.assertEqual((res.get("candidates"), res.get("new_tombstones")), (2, 2))
        self.assertEqual(
            self._sql(db_url, f"SELECT count(*) FROM storage_maintenance_tombstones WHERE repository_id='{gitfs_id}' AND state='pending'"),
            "2",
        )
        self._sql(
            db_url,
            f"UPDATE storage_maintenance_tombstones SET delete_after=clock_timestamp()-interval '1 second' WHERE repository_id='{gitfs_id}'",
        )

        # 2b & 3b. GitFS delete fenced cases -> tombstones stay pending & files untouched, then valid delete succeeds.
        def assert_gitfs_intact():
            self.assertEqual(
                self._sql(db_url, f"SELECT count(*) FROM storage_maintenance_tombstones WHERE repository_id='{gitfs_id}' AND state='pending'"),
                "2",
            )
            self.assertTrue(loose_a.is_file() and loose_b.is_file() and pack_files[0].is_file())

        run_fenced_matrix(gitfs_id, "gitfs", "pando", "gitfs_tombstone_delete", assert_gitfs_intact)
        state, attempt, last_error, res = self._enqueue_and_wait_terminal(
            db_url, gitfs_id, alice_id, "gitfs_tombstone_delete", 2
        )
        self.assertEqual((state, attempt, last_error), ("succeeded", 1, ""))
        self.assertEqual(res.get("deleted"), 2)
        self.assertEqual(
            self._sql(db_url, f"SELECT count(*) FROM storage_maintenance_tombstones WHERE repository_id='{gitfs_id}' AND state='deleted'"),
            "2",
        )
        self.assertFalse(loose_a.exists() or loose_b.exists())
        self.assertTrue(pack_files[0].is_file())
        self._git(env, "--git-dir", str(bare), "cat-file", "-e", reachable_oid)
        self._git(env, "--git-dir", str(bare), "fsck", "--full")

        # 2c & 3c. Pando mark fenced cases -> orphan artifact stays active, then valid mark retires only orphan.
        run_fenced_matrix(
            pando_id, "pando", "gitfs", "pando_unreachable_mark",
            lambda: self.assertEqual(
                self._sql(db_url, f"SELECT state FROM pando_remote_artifacts WHERE sha256='{sha_orph}'"), "active"
            ),
        )
        state, attempt, last_error, res = self._enqueue_and_wait_terminal(
            db_url, pando_id, alice_id, "pando_unreachable_mark", 2
        )
        self.assertEqual((state, attempt, last_error), ("succeeded", 1, ""))
        self.assertEqual((res.get("marked_retired"), res.get("protected_serving")), (1, 1))
        self.assertEqual(self._sql(db_url, f"SELECT state FROM pando_remote_artifacts WHERE sha256='{sha_orph}'"), "retired")
        self.assertEqual(self._sql(db_url, f"SELECT state FROM pando_remote_artifacts WHERE sha256='{sha_serv}'"), "active")
        self._sql(
            db_url,
            f"UPDATE pando_remote_artifacts SET delete_after=clock_timestamp()-interval '1 second' WHERE sha256='{sha_orph}'",
        )

        # 2d & 3d. Pando delete fenced cases -> orphan stays retired & file untouched, then valid delete removes only orphan.
        def assert_pando_intact():
            self.assertEqual(self._sql(db_url, f"SELECT state FROM pando_remote_artifacts WHERE sha256='{sha_orph}'"), "retired")
            self.assertTrue(orph_file.is_file() and serv_file.is_file())

        run_fenced_matrix(pando_id, "pando", "gitfs", "pando_tombstone_delete", assert_pando_intact)
        state, attempt, last_error, res = self._enqueue_and_wait_terminal(
            db_url, pando_id, alice_id, "pando_tombstone_delete", 2
        )
        self.assertEqual((state, attempt, last_error), ("succeeded", 1, ""))
        self.assertEqual((res.get("deleted"), res.get("remote_deleted")), (1, True))
        self.assertEqual(self._sql(db_url, f"SELECT state FROM pando_remote_artifacts WHERE sha256='{sha_orph}'"), "deleted")
        self.assertEqual(self._sql(db_url, f"SELECT state FROM pando_remote_artifacts WHERE sha256='{sha_serv}'"), "active")
        self.assertFalse(orph_file.exists())
        self.assertTrue(serv_file.is_file())


if __name__ == "__main__":
    unittest.main()
