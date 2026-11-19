#!/usr/bin/env python3
"""Live multi-mirror and multi-controller HA qualification for CI mirror scheduling (#34).

Orchestrates real Rootyard daemons against a disposable PostgreSQL 17 schema and
real native Git repositories (zero synthetic loopback mirror mocks):
  * 2 real ``rootyard serve`` controllers (``controller-1``, ``controller-2``)
  * 1 ``rootyard worker`` process + ``rootyard reconcile`` crash recovery
  * >= 3 real ``rootyard serve-mirror`` daemons (``mirror-1``, ``mirror-2``
    allowlisted for prewarm; ``mirror-3`` deliberately outside allowlist)

Scenarios covered:
  A. PR synchronization -> live prewarm & ``GET /ci-mirrors`` readiness ->
     attempt-1 claim on live ``serve-mirror`` -> stock ``git clone`` &
     ``git fsck --strict`` -> attempt-bound report.
  B. Simultaneous ``SIGKILL`` of active ``serve-mirror`` #1 and ``controller-1``
     -> surviving ``controller-2`` + ``worker`` / ``reconcile`` + failover
     rotation onto ``serve-mirror`` #2 with immutable ``target_oid``, ``409``
     rejection of stale attempt #1, clean attempt #2 clone & completion.
  C. Coalesced allowlisted prewarming & ``X-Rootyard-CI-State`` coverage
     (``ready``, ``waiting``, ``denied``, ``missing``, ``overloaded``), all
     ``serve-mirror`` daemons killed -> simultaneous burst exercising global
     (4) and per-repo (2) origin fallback budgets and bounded wait wakeup, zero
     ``ROOTYARD_CI_MIRROR_SOURCE_TOKEN`` leaks, and zero leaked child processes.
  D. A fresh unlisted real ``serve-mirror`` is alive but cannot serve a fresh
     target -> ``claim`` returns a genuine ``202`` ``waiting`` with no lease or
     checkout grant; an explicit named-mirror auto-fetch commits target-OID
     readiness through the same controller/PostgreSQL/storage, after which the
     same durable queued run claims ``200`` from that exact mirror with the
     persisted ``(attempt, lease_generation, grant)`` bound to
     repository/target/storage generation.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
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
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid


# Conservative bounds for fixture-owned HTTP responses and the final report.
# Existing qualification responses and reports are far below these caps.
MAX_HTTP_RESPONSE_BYTES = 1 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024


class HttpTransportError(OSError):
    """Fixed-message transport failure carrying no URL or credential detail."""


def read_bounded(stream, limit: int = MAX_HTTP_RESPONSE_BYTES) -> bytes:
    """Read at most ``limit`` bytes, rejecting oversized responses without echoing them."""
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise AssertionError(f"HTTP response exceeded {limit} byte bounded cap")
    return data


def scan_token_in_logs(log_paths: list[Path], token: str) -> dict[str, object]:
    """Return only a closed state and scanned count; never return log text or filenames."""
    if not token:
        return {"state": "unavailable", "scanned": 0}
    scanned = 0
    for log_path in log_paths:
        if not log_path.is_file():
            return {"state": "missing", "scanned": scanned}
        try:
            text = log_path.read_text(errors="replace")
        except OSError:
            return {"state": "unreadable", "scanned": scanned}
        scanned += 1
        if token in text:
            return {"state": "leaked", "scanned": scanned}
    return {"state": "clean", "scanned": scanned}


def bounded_report_payload(payload: str, limit: int = MAX_REPORT_BYTES) -> tuple[str, bool]:
    """Report whether the complete payload fits; never truncate a report."""
    return payload, len(payload.encode("utf-8")) <= limit


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def live_pgid_processes(pgids: set[int]) -> list[tuple[int, int, int, str]]:
    """Inspect Linux /proc for any non-zombie process still inside tracked PGIDs."""
    if not is_linux() or not pgids:
        return []
    leaked: list[tuple[int, int, int, str]] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(errors="replace")
            head, tail = stat.split("(", 1)
            comm, rest = tail.rsplit(") ", 1)
            fields = rest.split()
            state = fields[0]
            pgrp = int(fields[2])
            sess = int(fields[3])
            if state in ("Z", "X"):
                continue
            if pgrp in pgids or sess in pgids:
                leaked.append((int(head.strip()), pgrp, sess, comm))
        except (OSError, ValueError, IndexError):
            continue
    return leaked


class HaQualificationHarness:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-ci-mirror-ha-"))
        self.schema = "rootyard_ha_" + uuid.uuid4().hex
        self.schema_created = False
        self.base_db = os.environ["ROOTYARD_TEST_DATABASE_URL"]
        parts = urllib.parse.urlsplit(self.base_db)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if any(k == "options" for k, _ in query):
            raise RuntimeError(
                "ROOTYARD_TEST_DATABASE_URL must not already specify options; HA isolation owns search_path"
            )
        query.append(("options", "-csearch_path=" + self.schema))
        self.db = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))

        self.audience = str(uuid.uuid4())
        self.m1_id = str(uuid.uuid4())
        self.m2_id = str(uuid.uuid4())
        self.m3_id = str(uuid.uuid4())
        self.m4_id = str(uuid.uuid4())

        self.c1_port = free_port()
        self.c2_port = free_port()
        self.m1_port = free_port()
        self.m2_port = free_port()
        self.m3_port = free_port()
        self.m4_port = free_port()
        for _ in range(32):
            if self.m4_port not in {self.c1_port, self.c2_port, self.m1_port, self.m2_port, self.m3_port}:
                break
            self.m4_port = free_port()
        else:
            raise AssertionError("could not allocate a distinct mirror-4 port")

        self.c1_base = f"http://127.0.0.1:{self.c1_port}"
        self.c2_base = f"http://127.0.0.1:{self.c2_port}"
        self.m1_base = f"http://127.0.0.1:{self.m1_port}"
        self.m2_base = f"http://127.0.0.1:{self.m2_port}"
        self.m3_base = f"http://127.0.0.1:{self.m3_port}"
        self.m4_base = f"http://127.0.0.1:{self.m4_port}"

        self.ctrl1_data = self.root / "ctrl1-data"
        self.ctrl2_data = self.root / "ctrl2-data"
        self.mirror1_data = self.root / "mirror1-data"
        self.mirror2_data = self.root / "mirror2-data"
        self.mirror3_data = self.root / "mirror3-data"
        self.mirror4_data = self.root / "mirror4-data"

        self.base_env = os.environ.copy()
        self.base_env.update(
            DATABASE_URL=self.db,
            GIT_TERMINAL_PROMPT="0",
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            LC_ALL="C",
            ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE="1000",
            ROOTYARD_WEBHOOK_ALLOW_LOOPBACK="true",
            ROOTYARD_CI_MIRROR_AUDIENCE=self.audience,
            ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL="4",
            ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO="2",
            ROOTYARD_CI_CHECKOUT_WAIT_QUEUE="4",
        )
        pw = urllib.parse.urlsplit(self.base_db).password
        self.secrets: list[str] = []
        if pw:
            self.secrets.extend([pw, urllib.parse.unquote(pw)])

        self.procs: dict[str, dict] = {}
        self.tracked_pgids: set[int] = set()
        self.results: list[dict] = []

        self.alice: dict = {}
        self.bob: dict = {}
        self.prewarm_pat: dict = {}
        self.source_pat: dict = {}
        self.hook_secret = "whsec_ha_qual_secret_0123456789abcdef"
        self.secrets.append(self.hook_secret)

    def redact(self, value: object) -> str:
        text = str(value)
        for sec in self.secrets:
            if sec:
                text = text.replace(sec, "[REDACTED]")
        return text.replace(self.base_db, "[DATABASE_URL]").replace(self.db, "[DATABASE_URL]")

    def add_secret(self, value: str) -> None:
        if value and value not in self.secrets:
            self.secrets.append(value)

    def register_checkout_token(self, claimed: object) -> str:
        """Register the claim credential before any assertion can stringify the response."""
        checkout = claimed.get("checkout") if isinstance(claimed, dict) else None
        token = checkout.get("token") if isinstance(checkout, dict) else None
        if (
            not isinstance(token, str)
            or not token.startswith("ryj_")
            or len(token) > 256
            or not token.isascii()
            or not token.isprintable()
        ):
            raise AssertionError("claim response did not contain a bounded checkout token")
        self.add_secret(token)
        return token

    def run(self, argv: list[str], cwd: Path | None = None, check: bool = True, env: dict | None = None):
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env or self.base_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,
        )
        if check and proc.returncode != 0:
            raise AssertionError(
                self.redact(
                    f"Command failed ({proc.returncode}): {proc.stderr.decode(errors='replace')[-4000:]}"
                )
            )
        return proc

    def sql(self, query: str, isolated: bool = True) -> str:
        dsn = self.db if isolated else self.base_db
        return (
            self.run(
                ["psql", "--dbname", dsn, "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", query]
            )
            .stdout.decode()
            .strip()
        )

    def cli(self, *cmd_args: str, data_dir: Path | None = None) -> str:
        env = self.base_env.copy()
        env["ROOTYARD_DATA_DIR"] = str(data_dir or (self.root / "cli-data"))
        return self.run([self.args.binary, *cmd_args], env=env).stdout.decode().strip()

    def create_account(self, *cmd_args: str) -> dict:
        doc = json.loads(self.cli(*cmd_args))
        self.add_secret(doc["token"])
        self.add_secret(base64.b64encode((doc["username"] + ":" + doc["token"]).encode()).decode())
        return doc

    def http(
        self,
        base: str,
        path: str,
        *,
        token: dict | None = None,
        bearer: str | None = None,
        method: str = "GET",
        body: dict | bytes | None = None,
        extra_headers: dict | None = None,
        timeout: float = 20.0,
    ) -> tuple[int, bytes, dict[str, str]]:
        headers: dict[str, str] = {}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        elif token:
            headers["Authorization"] = f"Bearer {token['token']}"
        payload = body
        if isinstance(payload, dict):
            payload = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, read_bounded(resp), {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as err:
            try:
                raw = read_bounded(err)
            finally:
                try:
                    err.close()
                except OSError:
                    pass
            return err.code, raw, {k.lower(): v for k, v in err.headers.items()}
        except (urllib.error.URLError, OSError):
            raise HttpTransportError("HTTP request failed") from None

    def document(self, base: str, path: str, expected: int | tuple[int, ...] = 200, **kwargs) -> tuple[dict, dict[str, str]]:
        codes = expected if isinstance(expected, tuple) else (expected,)
        status, raw, hdrs = self.http(base, path, **kwargs)
        assert status in codes, f"{method_of(kwargs)} request returned HTTP {status}, expected one of {codes}"
        return json.loads(raw.decode("utf-8")), hdrs

    def git(
        self,
        *args: str,
        cwd: Path | None = None,
        token: dict | None = None,
        bearer: str | None = None,
        check: bool = True,
    ):
        prefix = ["git"]
        if bearer:
            prefix += ["-c", f"http.extraHeader=Authorization: Bearer {bearer}"]
        elif token:
            auth = base64.b64encode((token["username"] + ":" + token["token"]).encode()).decode()
            prefix += ["-c", f"http.extraHeader=Authorization: Basic {auth}"]
        return self.run(prefix + list(args), cwd=cwd, check=check)

    def controller_env(self, port: int, data_dir: Path) -> dict[str, str]:
        env = self.base_env.copy()
        env.update(
            ROOTYARD_BIND=f"127.0.0.1:{port}",
            ROOTYARD_DATA_DIR=str(data_dir),
            ROOTYARD_OUTBOX_WORKER="true",
            ROOTYARD_CI_MIRROR_PREWARM_ORIGINS=f"{self.m1_base},{self.m2_base}",
            ROOTYARD_CI_MIRROR_PREWARM_TOKEN=self.prewarm_pat["token"],
        )
        env.pop("ROOTYARD_CI_MIRROR_SOURCE_TOKEN", None)
        return env

    def mirror_env(self, mirror_id: str, port: int, data_dir: Path, primary_base: str) -> dict[str, str]:
        env = self.base_env.copy()
        env.update(
            ROOTYARD_BIND=f"127.0.0.1:{port}",
            ROOTYARD_DATA_DIR=str(data_dir),
            ROOTYARD_PRIMARY_URL=primary_base,
            ROOTYARD_CI_MIRROR_ID=mirror_id,
            ROOTYARD_CI_MIRROR_PUBLIC_URL=f"http://127.0.0.1:{port}",
            ROOTYARD_CI_MIRROR_CAPACITY="4",
            ROOTYARD_CI_MIRROR_SOURCE_TOKEN=self.source_pat["token"],
        )
        return env

    def worker_env(self) -> dict[str, str]:
        env = self.base_env.copy()
        no_git = self.root / "empty-path"
        no_git.mkdir(exist_ok=True)
        not_a_dir = self.root / "worker-no-volume"
        not_a_dir.touch(exist_ok=True)
        env.update(
            ROOTYARD_GIT=str(self.root / "missing-git"),
            ROOTYARD_DATA_DIR=str(not_a_dir / "unused"),
            PATH=str(no_git),
            ROOTYARD_WORKER_CONSUMERS="audit-log,ref-index",
            ROOTYARD_WORKER_POLL_MS="100",
            ROOTYARD_WORKER_BATCH="8",
            ROOTYARD_WORKER_LEASE_SECONDS="3",
            ROOTYARD_WAKE_TRANSPORT="poll",
        )
        return env

    def start_daemon(self, name: str, subcmd: str, env: dict[str, str], ready_base: str | None = None) -> dict:
        log_path = self.root / f"{name}.log"
        log_fp = open(log_path, "ab")
        popen_kwargs: dict = dict(env=env, stdout=log_fp, stderr=log_fp)
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen([self.args.binary, subcmd], **popen_kwargs)
        pgid = proc.pid
        self.tracked_pgids.add(pgid)
        entry = {"name": name, "proc": proc, "pgid": pgid, "log": log_fp, "log_path": log_path}
        self.procs[name] = entry
        deadline = time.monotonic() + 30.0
        if ready_base:
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise AssertionError(f"{name} exited early ({proc.returncode}); check {log_path}")
                try:
                    st, _, _ = self.http(ready_base, "/health/ready", timeout=2.0)
                    if st == 200:
                        return entry
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.1)
            raise AssertionError(f"{name} readiness timeout at {ready_base}/health/ready")
        time.sleep(0.4)
        if proc.poll() is not None:
            raise AssertionError(f"{name} exited early ({proc.returncode}); check {log_path}")
        return entry

    def stop_daemon(self, name: str, hard: bool = False) -> int | None:
        entry = self.procs.get(name)
        if not entry:
            return None
        proc = entry["proc"]
        code = proc.poll()
        if code is None:
            sig = signal.SIGKILL if hard else signal.SIGTERM
            if os.name == "posix":
                os.killpg(entry["pgid"], sig)
            else:
                proc.kill() if hard else proc.terminate()
            try:
                code = proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(entry["pgid"], signal.SIGKILL)
                else:
                    proc.kill()
                code = proc.wait(timeout=5)
        if entry["log"]:
            entry["log"].close()
            entry["log"] = None
        return code

    def create_repo(self, base: str, name: str, token: dict) -> dict:
        doc, _ = self.document(base, "/api/repos", (201, 202), token=token, method="POST", body={"name": name})
        owner = doc["owner"]
        deadline = time.monotonic() + 20.0
        while True:
            cur, _ = self.document(base, f"/api/repos/{owner}/{name}", 200, token=token)
            if cur["state"] == "ready":
                return cur
            assert cur["state"] == "provisioning", cur
            if time.monotonic() >= deadline:
                raise AssertionError(f"Repository {owner}/{name} did not become ready")
            time.sleep(0.1)

    def setup_daemons(self) -> None:
        self.sql(f'CREATE SCHEMA "{self.schema}"', isolated=False)
        self.schema_created = True
        self.cli("migrate")

        self.alice = self.create_account("create-user", "alice")
        self.bob = self.create_account("create-user", "bob")
        self.prewarm_pat = self.create_account("create-token", "alice", "--read-only")
        self.source_pat = self.create_account("create-token", "alice")
        assert self.prewarm_pat["token"] != self.source_pat["token"]

        self.start_daemon("controller-1", "serve", self.controller_env(self.c1_port, self.ctrl1_data), self.c1_base)
        self.start_daemon("controller-2", "serve", self.controller_env(self.c2_port, self.ctrl2_data), self.c2_base)
        self.start_daemon("worker", "worker", self.worker_env())
        self.start_daemon(
            "mirror-1", "serve-mirror",
            self.mirror_env(self.m1_id, self.m1_port, self.mirror1_data, self.c1_base), self.m1_base,
        )
        self.start_daemon(
            "mirror-2", "serve-mirror",
            self.mirror_env(self.m2_id, self.m2_port, self.mirror2_data, self.c1_base), self.m2_base,
        )
        # mirror-3 is intentionally NOT listed in ROOTYARD_CI_MIRROR_PREWARM_ORIGINS.
        self.start_daemon(
            "mirror-3", "serve-mirror",
            self.mirror_env(self.m3_id, self.m3_port, self.mirror3_data, self.c1_base), self.m3_base,
        )

    def wait_for_runs(self, repo_id: str, pull_number: int, head_oid: str, expected_contexts: tuple[str, ...]) -> dict[str, str]:
        deadline = time.monotonic() + 15.0
        while True:
            rows = self.sql(
                f"SELECT id::text||','||context FROM ci_runs WHERE repository_id='{repo_id}' "
                f"AND pull_number={pull_number} AND head_oid='{head_oid}' ORDER BY context"
            ).splitlines()
            runs = {line.split(",", 1)[1]: line.split(",", 1)[0] for line in rows if "," in line}
            if set(runs) == set(expected_contexts):
                return runs
            if time.monotonic() >= deadline:
                raise AssertionError(f"Expected runs {expected_contexts} for PR #{pull_number}, got {runs}")
            time.sleep(0.15)

    def verify_git_checkout(self, clone_url: str, dest: Path, expected_oid: str, ryj_token: str) -> None:
        if dest.exists():
            shutil.rmtree(dest)
        self.git("clone", clone_url, str(dest), bearer=ryj_token)
        head = self.git("rev-parse", "HEAD", cwd=dest).stdout.decode().strip()
        assert head == expected_oid, f"Clone HEAD {head} != expected {expected_oid}"
        self.git("fsck", "--strict", cwd=dest)

    def scenario_a_pr_prewarm_and_live_mirror_checkout(self) -> dict:
        self.repo1 = self.create_repo(self.c1_base, "forge", self.alice)
        self.work1 = self.root / "work-forge"
        self.git("clone", self.c1_base + self.repo1["clone_path"], str(self.work1), token=self.alice)
        self.git("config", "user.name", "HA Qualifier", cwd=self.work1)
        self.git("config", "user.email", "ha-qual@example.invalid", cwd=self.work1)

        (self.work1 / "base.txt").write_text("base commit\n")
        self.git("add", "base.txt", cwd=self.work1)
        self.git("commit", "-m", "base", cwd=self.work1)
        self.base_oid = self.git("rev-parse", "HEAD", cwd=self.work1).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=self.work1, token=self.alice)

        self.feat_oids: dict[str, str] = {}
        for branch in ("feat-a", "feat-b", "feat-c", "feat-d", "feat-burst"):
            self.git("checkout", "-b", branch, "main", cwd=self.work1)
            (self.work1 / f"{branch}.txt").write_text(f"payload for {branch}\n")
            self.git("add", f"{branch}.txt", cwd=self.work1)
            self.git("commit", "-m", f"commit {branch}", cwd=self.work1)
            oid = self.git("rev-parse", "HEAD", cwd=self.work1).stdout.decode().strip()
            self.git("push", "origin", f"HEAD:refs/heads/{branch}", cwd=self.work1, token=self.alice)
            self.feat_oids[branch] = oid

        hook_doc, _ = self.document(
            self.c1_base, "/api/repos/alice/forge/webhooks", 201,
            token=self.alice, method="POST",
            body={
                "url": "http://127.0.0.1:9/unused-hook",
                "secret": self.hook_secret,
                "events": ["check_run"],
                "ci_contexts": ["ci/test", "ci/lint"],
                "auto_ci_pin": True,
            },
        )
        self.hook1_id = hook_doc["id"]
        for ctx in ("ci/test", "ci/lint"):
            self.document(
                self.c1_base,
                f"/api/repos/alice/forge/integrations/{self.hook1_id}/trusted-contexts",
                200, token=self.alice, method="PUT", body={"context": ctx},
            )

        for mid, murl in ((self.m1_id, self.m1_base), (self.m2_id, self.m2_base), (self.m3_id, self.m3_base)):
            self.document(
                self.c1_base, f"/api/repos/alice/forge/ci-mirrors/{mid}/heartbeat", 200,
                token=self.alice, method="POST",
                body={
                    "audience": self.audience, "url": murl, "storage_generation": 1,
                    "ready_oids": [], "capacity": 4, "active": True,
                },
            )

        feat_a_oid = self.feat_oids["feat-a"]
        pr1, _ = self.document(
            self.c1_base, "/api/repos/alice/forge/pulls", 201,
            token=self.alice, method="POST",
            body={
                "title": "Scenario A HA verification", "body": "pr1",
                "head_ref": "refs/heads/feat-a", "base_ref": "refs/heads/main",
            },
        )
        assert pr1["head_oid"] == feat_a_oid, pr1
        self.pr1_num = pr1["number"]
        runs1 = self.wait_for_runs(self.repo1["id"], self.pr1_num, feat_a_oid, ("ci/test", "ci/lint"))

        # Query GET /ci-mirrors from controller-2 to verify cross-controller view and
        # Bug #1 (UUID mirror_id publish_ready_oid) + Bug #2 (mirrors::list UUID get).
        deadline = time.monotonic() + 20.0
        mirrors_by_id: dict[str, dict] = {}
        while time.monotonic() < deadline:
            listing, _ = self.document(
                self.c2_base,
                f"/api/repos/alice/forge/ci-mirrors?target_oid={feat_a_oid}",
                200, token=self.alice,
            )
            mirrors_by_id = {m["mirror_id"]: m for m in listing["mirrors"]}
            if (
                mirrors_by_id.get(self.m1_id, {}).get("target_ready") is True
                and mirrors_by_id.get(self.m2_id, {}).get("target_ready") is True
            ):
                break
            time.sleep(0.2)
        assert mirrors_by_id[self.m1_id]["alive"] and mirrors_by_id[self.m1_id]["target_ready"], mirrors_by_id
        assert mirrors_by_id[self.m2_id]["alive"] and mirrors_by_id[self.m2_id]["target_ready"], mirrors_by_id
        assert mirrors_by_id[self.m3_id]["target_ready"] is False, mirrors_by_id
        st_m3, raw_m3, _ = self.http(self.m3_base, "/metrics")
        assert st_m3 == 200 and b"rootyard_mirror_sync_total 0\n" in raw_m3, raw_m3.decode(errors="replace")

        prefix1 = f"/api/repos/alice/forge/integrations/{self.hook1_id}/runs/"
        inspected, insp_hdrs = self.document(self.c1_base, prefix1 + runs1["ci/test"], 200, bearer=self.hook_secret)
        assert insp_hdrs.get("x-rootyard-ci-state") == "ready" and inspected["classification"] == "ready", inspected

        claimed, claim_hdrs = self.document(
            self.c1_base, prefix1 + runs1["ci/test"] + "/claim", 200,
            bearer=self.hook_secret, method="POST",
            body={"runner_id": "runner-a1", "prefer_mirror": True, "wait_for_ready_ms": 5000, "exclude_sources": [self.m2_base]},
        )
        assert claim_hdrs.get("x-rootyard-ci-state") == "ready", claim_hdrs
        assert claimed["source"] == self.m1_base, claimed
        assert claimed["attempt"] == 1 and claimed["lease_generation"] == 1, claimed
        ryj1 = claimed["checkout"]["token"]
        assert ryj1.startswith("ryj_")
        self.add_secret(ryj1)

        self.verify_git_checkout(
            f"{self.m1_base}/ci/{feat_a_oid}/git/alice/forge.git",
            self.root / "clone-a1", feat_a_oid, ryj1,
        )
        reported, _ = self.document(
            self.c1_base, prefix1 + runs1["ci/test"] + "/report", 200,
            bearer=self.hook_secret, method="POST",
            body={"attempt": 1, "lease_generation": 1, "conclusion": "success", "output": "scenario a passed"},
        )
        assert reported["replay"] is False, reported
        checks, _ = self.document(self.c1_base, f"/api/repos/alice/forge/pulls/{self.pr1_num}/checks", 200, token=self.alice)
        by_ctx = {c["context"]: c for c in checks["items"]}
        assert by_ctx["ci/test"]["status"] == "completed" and by_ctx["ci/test"]["conclusion"] == "success", by_ctx

        return {
            "pr_number": self.pr1_num,
            "target_oid": feat_a_oid,
            "mirror1_ready_via_controller2": True,
            "mirror2_prewarmed_in_parallel": True,
            "unlisted_mirror3_syncs": 0,
            "attempt1_clone_fsck": "strict_passed",
        }

    def scenario_b_sigkill_dual_crash_and_failover(self) -> dict:
        feat_b_oid = self.feat_oids["feat-b"]
        pr2, _ = self.document(
            self.c1_base, "/api/repos/alice/forge/pulls", 201,
            token=self.alice, method="POST",
            body={
                "title": "Scenario B Dual Crash Failover", "body": "pr2",
                "head_ref": "refs/heads/feat-b", "base_ref": "refs/heads/main",
            },
        )
        assert pr2["head_oid"] == feat_b_oid
        self.pr2_num = pr2["number"]
        runs2 = self.wait_for_runs(self.repo1["id"], self.pr2_num, feat_b_oid, ("ci/test", "ci/lint"))

        # Wait until BOTH mirror-1 and mirror-2 prewarm feat-b and record readiness on controller-2.
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            listing, _ = self.document(
                self.c2_base, f"/api/repos/alice/forge/ci-mirrors?target_oid={feat_b_oid}", 200, token=self.alice
            )
            by_id = {m["mirror_id"]: m for m in listing["mirrors"]}
            if by_id.get(self.m1_id, {}).get("target_ready") and by_id.get(self.m2_id, {}).get("target_ready"):
                break
            time.sleep(0.2)
        else:
            raise AssertionError(f"mirrors did not prewarm {feat_b_oid} before dual kill")

        prefix1 = f"/api/repos/alice/forge/integrations/{self.hook1_id}/runs/"
        c_b1, _ = self.document(
            self.c1_base, prefix1 + runs2["ci/test"] + "/claim", 200,
            bearer=self.hook_secret, method="POST",
            body={"runner_id": "runner-b1", "prefer_mirror": True, "exclude_sources": [self.m2_base]},
        )
        assert c_b1["source"] == self.m1_base and c_b1["attempt"] == 1 and c_b1["lease_generation"] == 1
        ryj_stale = c_b1["checkout"]["token"]
        self.add_secret(ryj_stale)

        # Claim ci/lint on mirror-1 as well, then expire its lease timestamp so controller-2's
        # reconcile_runs proves automated lease reaping preserves immutable target_oid.
        c_b2, _ = self.document(
            self.c1_base, prefix1 + runs2["ci/lint"] + "/claim", 200,
            bearer=self.hook_secret, method="POST",
            body={"runner_id": "runner-b2", "prefer_mirror": True, "exclude_sources": [self.m2_base]},
        )
        assert c_b2["source"] == self.m1_base
        self.sql(f"UPDATE ci_runs SET lease_expires_unix=0 WHERE id='{runs2['ci/lint']}'")

        # Mid-job SIGKILL of BOTH active serve-mirror #1 AND controller-1 simultaneously.
        m1_code = self.stop_daemon("mirror-1", hard=True)
        c1_code = self.stop_daemon("controller-1", hard=True)
        if os.name == "posix":
            assert m1_code == -signal.SIGKILL and c1_code == -signal.SIGKILL, (m1_code, c1_code)
        assert self.procs["controller-1"]["proc"].poll() is not None

        # Verify live surviving controller-2 (still running alongside worker) handles:
        # 1) automated reconcile_runs lease reap on ci/lint preserving feat_b_oid;
        # 2) immediate control-plane failover (requeue_only) on ci/test clearing dead mirror-1;
        # 3) 409 rejection of stale attempt=1 heartbeat/report.
        deadline = time.monotonic() + 15.0
        reaped = ""
        while time.monotonic() < deadline:
            reaped = self.sql(f"SELECT state||','||head_oid FROM ci_runs WHERE id='{runs2['ci/lint']}'")
            if reaped == f"queued,{feat_b_oid}":
                break
            time.sleep(0.2)
        assert reaped == f"queued,{feat_b_oid}", f"reconcile_runs on controller-2 failed to reap: {reaped}"

        fo_wait, fo_wait_hdrs = self.document(
            self.c2_base, prefix1 + runs2["ci/test"] + "/failover", 200,
            bearer=self.hook_secret, method="POST",
            body={
                "attempt": 1, "lease_generation": 1, "runner_id": "runner-b1",
                "failed_source": self.m1_base, "reason": "dual sigkill mirror-1+controller-1",
                "requeue_only": True,
            },
        )
        assert fo_wait_hdrs.get("x-rootyard-ci-state") == "waiting" and fo_wait["lease_generation"] == 2, fo_wait

        self.document(
            self.c2_base, prefix1 + runs2["ci/test"] + "/heartbeat", 409,
            bearer=self.hook_secret, method="POST",
            body={"attempt": 1, "lease_generation": 1, "runner_id": "runner-b1"},
        )
        self.document(
            self.c2_base, prefix1 + runs2["ci/test"] + "/report", 409,
            bearer=self.hook_secret, method="POST",
            body={"attempt": 1, "lease_generation": 1, "conclusion": "success", "output": "stale"},
        )

        # Recover crashed controller-1 volume with real `rootyard reconcile` and bind controller-2 to it
        # while controller-1 remains permanently dead.
        self.stop_daemon("controller-2", hard=False)
        self.cli("reconcile", data_dir=self.ctrl1_data)
        self.start_daemon("controller-2", "serve", self.controller_env(self.c2_port, self.ctrl1_data), self.c2_base)
        assert self.procs["controller-1"]["proc"].poll() is not None, "controller-1 must remain dead"

        # Mark killed mirror-1 inactive and claim ci/test onto live serve-mirror #2.
        self.document(
            self.c2_base, f"/api/repos/alice/forge/ci-mirrors/{self.m1_id}/heartbeat", 200,
            token=self.alice, method="POST",
            body={
                "audience": self.audience, "url": self.m1_base, "storage_generation": 1,
                "ready_oids": [], "capacity": 4, "active": False,
            },
        )
        c2_test, c2_hdrs = self.document(
            self.c2_base, prefix1 + runs2["ci/test"] + "/claim", 200,
            bearer=self.hook_secret, method="POST",
            body={"runner_id": "runner-b1-retry", "prefer_mirror": True, "wait_for_ready_ms": 5000},
        )
        assert c2_hdrs.get("x-rootyard-ci-state") == "ready"
        assert c2_test["source"] == self.m2_base, c2_test
        assert c2_test["head_oid"] == feat_b_oid, c2_test
        assert c2_test["attempt"] == 2 and c2_test["lease_generation"] == 3, c2_test
        ryj2 = c2_test["checkout"]["token"]
        self.add_secret(ryj2)

        # Stale attempt #1 ryj token must fail against live mirror-2 AND controller-2 report.
        stale_git = self.git(
            "ls-remote", f"{self.m2_base}/ci/{feat_b_oid}/git/alice/forge.git",
            bearer=ryj_stale, check=False,
        )
        assert stale_git.returncode != 0, "Stale attempt #1 ryj token unexpectedly authorized clone"
        self.document(
            self.c2_base, prefix1 + runs2["ci/test"] + "/report", 409,
            bearer=self.hook_secret, method="POST",
            body={"attempt": 1, "lease_generation": 1, "conclusion": "success", "output": "stale"},
        )

        # Attempt #2 clones from live serve-mirror #2 independently of dead controller-1 and passes strict fsck.
        self.verify_git_checkout(
            f"{self.m2_base}/ci/{feat_b_oid}/git/alice/forge.git",
            self.root / "clone-b2", feat_b_oid, ryj2,
        )
        self.document(
            self.c2_base, prefix1 + runs2["ci/test"] + "/report", 200,
            bearer=self.hook_secret, method="POST",
            body={"attempt": 2, "lease_generation": 3, "conclusion": "success", "output": "failover attempt 2 ok"},
        )

        # Also exercise non-requeue immediate failover on ci/lint: claim onto mirror-2 then failover off mirror-2 -> origin.
        c_lint, _ = self.document(
            self.c2_base, prefix1 + runs2["ci/lint"] + "/claim", 200,
            bearer=self.hook_secret, method="POST",
            body={"runner_id": "runner-b2-retry", "prefer_mirror": True},
        )
        assert c_lint["source"] == self.m2_base and c_lint["head_oid"] == feat_b_oid
        fo_direct, fo_hdrs = self.document(
            self.c2_base, prefix1 + runs2["ci/lint"] + "/failover", 200,
            bearer=self.hook_secret, method="POST",
            body={
                "attempt": c_lint["attempt"], "lease_generation": c_lint["lease_generation"],
                "runner_id": "runner-b2-retry", "failed_source": self.m2_base, "reason": "rotate to origin",
            },
        )
        assert fo_hdrs.get("x-rootyard-ci-state") == "ready"
        assert fo_direct["source"] == "origin" and fo_direct["head_oid"] == feat_b_oid
        assert fo_direct["attempt"] == c_lint["attempt"] + 1 and fo_direct["lease_generation"] == c_lint["lease_generation"] + 1
        ryj_lint2 = fo_direct["checkout"]["token"]
        self.add_secret(ryj_lint2)
        self.document(
            self.c2_base, prefix1 + runs2["ci/lint"] + "/report", 409,
            bearer=self.hook_secret, method="POST",
            body={"attempt": c_lint["attempt"], "lease_generation": c_lint["lease_generation"], "conclusion": "success", "output": "stale"},
        )
        self.verify_git_checkout(
            f"{self.c2_base}/ci/{feat_b_oid}/git/alice/forge.git",
            self.root / "clone-b-lint", feat_b_oid, ryj_lint2,
        )
        self.document(
            self.c2_base, prefix1 + runs2["ci/lint"] + "/report", 200,
            bearer=self.hook_secret, method="POST",
            body={"attempt": fo_direct["attempt"], "lease_generation": fo_direct["lease_generation"], "conclusion": "success", "output": "ok"},
        )
        checks2, _ = self.document(self.c2_base, f"/api/repos/alice/forge/pulls/{self.pr2_num}/checks", 200, token=self.alice)
        by_ctx2 = {c["context"]: c["conclusion"] for c in checks2["items"]}
        assert by_ctx2 == {"ci/test": "success", "ci/lint": "success"}, by_ctx2

        return {
            "controller1_and_mirror1_sigkilled": True,
            "reconcile_reaped_expired_lease": True,
            "stale_attempt1_409_and_ryj_rejected": True,
            "failover_mirror2_and_origin_fsck_strict": True,
            "target_oid_preserved": feat_b_oid,
        }

    def scenario_c_coalesced_prewarm_and_origin_burst(self) -> dict:
        observed_states: set[str] = set()

        # Repoint surviving mirrors mirror-2 (allowlisted) & mirror-3 (unlisted) at controller-2
        # cleanly via legitimate restarts on existing mirror volumes.
        for name in ("mirror-2", "mirror-3"):
            self.stop_daemon(name, hard=False)
        self.start_daemon(
            "mirror-2", "serve-mirror",
            self.mirror_env(self.m2_id, self.m2_port, self.mirror2_data, self.c2_base), self.m2_base,
        )
        self.start_daemon(
            "mirror-3", "serve-mirror",
            self.mirror_env(self.m3_id, self.m3_port, self.mirror3_data, self.c2_base), self.m3_base,
        )
        for mid, murl in ((self.m2_id, self.m2_base), (self.m3_id, self.m3_base)):
            self.document(
                self.c2_base, f"/api/repos/alice/forge/ci-mirrors/{mid}/heartbeat", 200,
                token=self.alice, method="POST",
                body={
                    "audience": self.audience, "url": murl, "storage_generation": 1,
                    "ready_oids": [], "capacity": 4, "active": True,
                },
            )

        # Verify singleflight coalesced auto-fetch on live mirror-2 and waiting->ready classification.
        feat_c_oid = self.feat_oids["feat-c"]
        with ThreadPoolExecutor(max_workers=6) as pool:
            futs = [
                pool.submit(
                    self.document,
                    self.m2_base,
                    "/api/repos/alice/forge/mirror-auto-fetch",
                    200,
                    token=self.prewarm_pat,
                    method="POST",
                    body={"target_oid": feat_c_oid, "storage_generation": 1, "wait_ms": 5000},
                )
                for _ in range(6)
            ]
            autofetch_results = [f.result(timeout=30) for f in futs]
        assert any(doc.get("coalesced") or doc.get("cache_status") in ("coalesced_wait", "hit") for doc, _ in autofetch_results), autofetch_results
        for _, hdrs in autofetch_results:
            if "x-rootyard-ci-state" in hdrs:
                assert hdrs["x-rootyard-ci-state"] == "ready", hdrs

        # Verify PR #3 prewarm warms allowlisted mirror-2 only and leaves mirror-3 untouched.
        feat_d_oid = self.feat_oids["feat-d"]
        self.document(
            self.c2_base, f"/api/repos/alice/forge/ci-mirrors/{self.m2_id}/heartbeat", 200,
            token=self.alice, method="POST",
            body={
                "audience": self.audience, "url": self.m2_base, "storage_generation": 1,
                "ready_oids": [], "capacity": 4, "active": True,
            },
        )
        pr3, _ = self.document(
            self.c2_base, "/api/repos/alice/forge/pulls", 201,
            token=self.alice, method="POST",
            body={
                "title": "Scenario C Prewarm + Waiting", "body": "pr3",
                "head_ref": "refs/heads/feat-d", "base_ref": "refs/heads/main",
            },
        )
        runs3 = self.wait_for_runs(self.repo1["id"], pr3["number"], feat_d_oid, ("ci/test", "ci/lint"))
        prefix1 = f"/api/repos/alice/forge/integrations/{self.hook1_id}/runs/"

        # Exercise `waiting` classification either on immediate prewarm miss (202 waiting)
        # or via requeue_only failover (200 waiting) once prewarm settles.
        waiting_doc, waiting_hdrs = self.document(
            self.c2_base, prefix1 + runs3["ci/test"] + "/claim", (200, 202),
            bearer=self.hook_secret, method="POST",
            body={"runner_id": "runner-c-wait", "prefer_mirror": True, "wait_for_ready_ms": 0},
        )
        if waiting_hdrs.get("x-rootyard-ci-state") == "waiting":
            observed_states.add("waiting")
        # Trigger failover requeue_only on any run or wait cleanly for prewarm convergence.
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            listing, _ = self.document(
                self.c2_base, f"/api/repos/alice/forge/ci-mirrors?target_oid={feat_d_oid}", 200, token=self.alice
            )
            by_id = {m["mirror_id"]: m for m in listing["mirrors"]}
            if by_id.get(self.m2_id, {}).get("target_ready"):
                break
            time.sleep(0.2)
        assert by_id[self.m2_id]["target_ready"] is True and by_id[self.m3_id]["target_ready"] is False, by_id
        st_m3, raw_m3, _ = self.http(self.m3_base, "/metrics")
        assert st_m3 == 200 and b"rootyard_mirror_sync_total 0\n" in raw_m3, (st_m3, raw_m3.decode(errors="replace"))

        if waiting_doc.get("source"):
            # Requeue so all queued slots start fresh below, capturing explicit `waiting`.
            rq, rq_hdrs = self.document(
                self.c2_base, prefix1 + runs3["ci/test"] + "/failover", 200,
                bearer=self.hook_secret, method="POST",
                body={"attempt": waiting_doc["attempt"], "lease_generation": waiting_doc["lease_generation"],
                      "runner_id": "runner-c-wait", "requeue_only": True},
            )
            assert rq_hdrs.get("x-rootyard-ci-state") == "waiting", (rq, rq_hdrs)
            observed_states.add("waiting")

        # Hard-kill ALL remaining serve-mirror daemons (`mirror-2`, `mirror-3`) and verify origin budgets.
        self.stop_daemon("mirror-2", hard=True)
        self.stop_daemon("mirror-3", hard=True)
        for mid, murl in ((self.m2_id, self.m2_base), (self.m3_id, self.m3_base)):
            self.document(
                self.c2_base, f"/api/repos/alice/forge/ci-mirrors/{mid}/heartbeat", 200,
                token=self.alice, method="POST",
                body={
                    "audience": self.audience, "url": murl, "storage_generation": 1,
                    "ready_oids": [], "capacity": 4, "active": False,
                },
            )

        # Exercise `denied` and `missing` classifications explicitly.
        denied_doc, denied_hdrs = self.document(
            self.c2_base, prefix1 + runs3["ci/test"] + "/claim", 401,
            bearer="wrong-hook-secret", method="POST", body={"runner_id": "runner-denied"},
        )
        assert denied_hdrs.get("x-rootyard-ci-state") == "denied", (denied_doc, denied_hdrs)
        observed_states.add("denied")

        miss_id_doc, miss_id_hdrs = self.document(
            self.c2_base, prefix1 + runs3["ci/test"] + "/claim", 429,
            bearer=self.hook_secret, method="POST",
            body={"runner_id": "runner-missing", "prefer_mirror": True, "wait_for_ready_ms": 0},
        )
        assert miss_id_hdrs.get("x-rootyard-ci-state") == "missing" and miss_id_doc["classification"] == "missing", (miss_id_doc, miss_id_hdrs)
        observed_states.add("missing")

        unk_doc, unk_hdrs = self.document(
            self.c2_base, prefix1 + str(uuid.uuid4()), 404,
            bearer=self.hook_secret, method="GET",
        )
        assert unk_hdrs.get("x-rootyard-ci-state") == "missing", (unk_doc, unk_hdrs)

        # Set up burst across 2 repos (forge + forge2), each with >= 3 queued runs so
        # per_repo_limit=2 and global_limit=4 are deterministically exercised under simultaneous bursts.
        cur_h1, _ = self.document(self.c2_base, f"/api/repos/alice/forge/webhooks/{self.hook1_id}", 200, token=self.alice)
        self.document(
            self.c2_base, f"/api/repos/alice/forge/webhooks/{self.hook1_id}", 200,
            token=self.alice, method="PATCH",
            body={"expected_version": cur_h1["version"], "ci_contexts": ["ci/test", "ci/lint", "ci/b3"]},
        )
        self.document(
            self.c2_base, f"/api/repos/alice/forge/integrations/{self.hook1_id}/trusted-contexts",
            200, token=self.alice, method="PUT", body={"context": "ci/b3"},
        )
        burst_oid1 = self.feat_oids["feat-burst"]
        pr_b1, _ = self.document(
            self.c2_base, "/api/repos/alice/forge/pulls", 201,
            token=self.alice, method="POST",
            body={"title": "Burst Repo 1", "body": "b1", "head_ref": "refs/heads/feat-burst", "base_ref": "refs/heads/main"},
        )
        burst_runs1 = self.wait_for_runs(self.repo1["id"], pr_b1["number"], burst_oid1, ("ci/test", "ci/lint", "ci/b3"))

        repo2 = self.create_repo(self.c2_base, "forge2", self.alice)
        work2 = self.root / "work-forge2"
        self.git("clone", self.c2_base + repo2["clone_path"], str(work2), token=self.alice)
        self.git("config", "user.name", "HA Qualifier", cwd=work2)
        self.git("config", "user.email", "ha-qual@example.invalid", cwd=work2)
        (work2 / "r2.txt").write_text("repo2 base\n")
        self.git("add", "r2.txt", cwd=work2)
        self.git("commit", "-m", "r2 base", cwd=work2)
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work2, token=self.alice)
        self.git("checkout", "-b", "feat-r2", cwd=work2)
        (work2 / "r2.txt").write_text("repo2 head\n")
        self.git("add", "r2.txt", cwd=work2)
        self.git("commit", "-m", "r2 head", cwd=work2)
        burst_oid2 = self.git("rev-parse", "HEAD", cwd=work2).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/feat-r2", cwd=work2, token=self.alice)

        hook2_doc, _ = self.document(
            self.c2_base, "/api/repos/alice/forge2/webhooks", 201,
            token=self.alice, method="POST",
            body={
                "url": "http://127.0.0.1:9/unused-hook2", "secret": self.hook_secret,
                "events": ["check_run"], "ci_contexts": ["ci/test", "ci/lint", "ci/b3"],
                "auto_ci_pin": True,
            },
        )
        hook2_id = hook2_doc["id"]
        for ctx in ("ci/test", "ci/lint", "ci/b3"):
            self.document(
                self.c2_base, f"/api/repos/alice/forge2/integrations/{hook2_id}/trusted-contexts",
                200, token=self.alice, method="PUT", body={"context": ctx},
            )
        pr_b2, _ = self.document(
            self.c2_base, "/api/repos/alice/forge2/pulls", 201,
            token=self.alice, method="POST",
            body={"title": "Burst Repo 2", "body": "b2", "head_ref": "refs/heads/feat-r2", "base_ref": "refs/heads/main"},
        )
        burst_runs2 = self.wait_for_runs(repo2["id"], pr_b2["number"], burst_oid2, ("ci/test", "ci/lint", "ci/b3"))
        prefix2 = f"/api/repos/alice/forge2/integrations/{hook2_id}/runs/"

        # Burst repo 1 (per_repo_limit=2): 3 concurrent claims -> 2 ready (origin), 1 overloaded (429).
        with ThreadPoolExecutor(max_workers=3) as pool:
            futs1 = [
                pool.submit(
                    self.http, self.c2_base, prefix1 + rid + "/claim",
                    bearer=self.hook_secret, method="POST",
                    body={"runner_id": f"burst-r1-{i}", "wait_for_ready_ms": 0},
                )
                for i, rid in enumerate(burst_runs1.values())
            ]
            res1 = [(st, json.loads(raw), hdrs) for st, raw, hdrs in (f.result(timeout=20) for f in futs1)]
        ready1 = [r for r in res1 if r[0] == 200]
        over1 = [r for r in res1 if r[0] == 429]
        assert len(ready1) == 2 and len(over1) == 1, res1
        assert all(d["source"] == "origin" and h.get("x-rootyard-ci-state") == "ready" for _, d, h in ready1), ready1
        assert over1[0][2].get("x-rootyard-ci-state") == "overloaded" and over1[0][1]["classification"] == "overloaded", over1
        observed_states.update({"ready", "overloaded"})

        # Burst repo 2 -> 2 more ready (origin), hitting global_limit=4, 3rd returns 429 overloaded.
        with ThreadPoolExecutor(max_workers=3) as pool:
            futs2 = [
                pool.submit(
                    self.http, self.c2_base, prefix2 + rid + "/claim",
                    bearer=self.hook_secret, method="POST",
                    body={"runner_id": f"burst-r2-{i}", "wait_for_ready_ms": 0},
                )
                for i, rid in enumerate(burst_runs2.values())
            ]
            res2 = [(st, json.loads(raw), hdrs) for st, raw, hdrs in (f.result(timeout=20) for f in futs2)]
        ready2 = [r for r in res2 if r[0] == 200]
        over2 = [r for r in res2 if r[0] == 429]
        assert len(ready2) == 2 and len(over2) == 1, res2
        assert all(d["source"] == "origin" and h.get("x-rootyard-ci-state") == "ready" for _, d, h in ready2), ready2
        assert over2[0][2].get("x-rootyard-ci-state") == "overloaded", over2

        # Test bounded wait wakeup when an origin slot is released: wait_for_ready_ms=5000 blocks until
        # one of forge2's leased origin runs reports completion, then clones strictly from origin.
        leased2_ids = {d["run_id"]: d for _, d, _ in ready2}
        remaining2_id = next(rid for rid in burst_runs2.values() if rid not in leased2_ids)
        release_id, release_doc = next(iter(leased2_ids.items()))
        with ThreadPoolExecutor(max_workers=2) as pool:
            waiter = pool.submit(
                self.document, self.c2_base, prefix2 + remaining2_id + "/claim", 200,
                bearer=self.hook_secret, method="POST",
                body={"runner_id": "burst-waiter", "wait_for_ready_ms": 6000},
            )
            time.sleep(0.35)
            self.document(
                self.c2_base, prefix2 + release_id + "/report", 200,
                bearer=self.hook_secret, method="POST",
                body={"attempt": release_doc["attempt"], "lease_generation": release_doc["lease_generation"],
                      "conclusion": "success", "output": "slot freed"},
            )
            woken_doc, woken_hdrs = waiter.result(timeout=15)
        assert woken_hdrs.get("x-rootyard-ci-state") == "ready" and woken_doc["source"] == "origin", woken_doc
        ryj_origin = woken_doc["checkout"]["token"]
        self.add_secret(ryj_origin)
        self.verify_git_checkout(
            f"{self.c2_base}/ci/{burst_oid2}/git/alice/forge2.git",
            self.root / "clone-c-origin", burst_oid2, ryj_origin,
        )

        # Verify bounded wait-queue cap (ROOTYARD_CI_CHECKOUT_WAIT_QUEUE=4): open a separate PR
        # without cancelling pr_b1/pr_b2 so all 4 global origin slots remain leased, then burst 6 long waits.
        cur_h2, _ = self.document(self.c2_base, f"/api/repos/alice/forge2/webhooks/{hook2_id}", 200, token=self.alice)
        self.document(
            self.c2_base, f"/api/repos/alice/forge2/webhooks/{hook2_id}", 200,
            token=self.alice, method="PATCH",
            body={"expected_version": cur_h2["version"], "ci_contexts": ["ci/test", "ci/lint", "ci/b3", "ci/q1", "ci/q2", "ci/q3"]},
        )
        for qctx in ("ci/q1", "ci/q2", "ci/q3"):
            self.document(
                self.c2_base, f"/api/repos/alice/forge2/integrations/{hook2_id}/trusted-contexts",
                200, token=self.alice, method="PUT", body={"context": qctx},
            )
        self.git("checkout", "-b", "feat-r2-wq", "main", cwd=work2)
        (work2 / "r2wq.txt").write_text("repo2 wait queue head\n")
        self.git("add", "r2wq.txt", cwd=work2)
        self.git("commit", "-m", "r2 waitq head", cwd=work2)
        wq_oid = self.git("rev-parse", "HEAD", cwd=work2).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/feat-r2-wq", cwd=work2, token=self.alice)
        pr_wq, _ = self.document(
            self.c2_base, "/api/repos/alice/forge2/pulls", 201,
            token=self.alice, method="POST",
            body={"title": "Wait Queue Saturation", "body": "wq", "head_ref": "refs/heads/feat-r2-wq", "base_ref": "refs/heads/main"},
        )
        wq_runs = self.wait_for_runs(repo2["id"], pr_wq["number"], wq_oid, ("ci/test", "ci/lint", "ci/b3", "ci/q1", "ci/q2", "ci/q3"))
        with ThreadPoolExecutor(max_workers=6) as pool:
            wq_futs = [
                pool.submit(
                    self.http, self.c2_base, prefix2 + rid + "/claim",
                    bearer=self.hook_secret, method="POST",
                    body={"runner_id": f"wq-{i}", "wait_for_ready_ms": 2500},
                )
                for i, rid in enumerate(wq_runs.values())
            ]
            wq_res = [(st, json.loads(raw), hdrs) for st, raw, hdrs in (f.result(timeout=20) for f in wq_futs)]
        assert any(st == 429 and h.get("x-rootyard-ci-state") == "overloaded" for st, _, h in wq_res), wq_res

        assert observed_states == {"ready", "waiting", "denied", "missing", "overloaded"}, observed_states

        # Verify ROOTYARD_CI_MIRROR_SOURCE_TOKEN never leaked into any controller/mirror log.
        source_tok = self.source_pat["token"]
        for name, entry in self.procs.items():
            log_text = entry["log_path"].read_text(errors="replace")
            assert source_tok not in log_text, f"ROOTYARD_CI_MIRROR_SOURCE_TOKEN leaked into {name}.log"

        return {
            "states_verified": sorted(observed_states),
            "coalesced_autofetch_requests": len(autofetch_results),
            "allowlisted_prewarm_only": True,
            "per_repo_and_global_origin_budgets_enforced": True,
            "origin_wait_wakeup_clone_fsck": "strict_passed",
            "wait_queue_overload_429": True,
            "source_token_zero_leak": True,
        }

    def scenario_d_controlled_readiness_claim_transition(self) -> dict:
        # Scenarios B/C leave every allowlisted mirror killed and inactive. This
        # fresh unlisted mirror is therefore the only live mirror that can be
        # made ready, and only by the explicit auto-fetch below.
        self.git("checkout", "-b", "feat-e", "main", cwd=self.work1)
        (self.work1 / "feat-e.txt").write_text("controlled readiness\n")
        self.git("add", "feat-e.txt", cwd=self.work1)
        self.git("commit", "-m", "commit feat-e", cwd=self.work1)
        target_oid = self.git("rev-parse", "HEAD", cwd=self.work1).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/feat-e", cwd=self.work1, token=self.alice)

        self.start_daemon(
            "mirror-4", "serve-mirror",
            self.mirror_env(self.m4_id, self.m4_port, self.mirror4_data, self.c2_base), self.m4_base,
        )
        heartbeat = {
            "audience": self.audience, "url": self.m4_base, "storage_generation": 1,
            "ready_oids": [], "capacity": 4, "active": True,
        }
        self.document(
            self.c2_base, f"/api/repos/alice/forge/ci-mirrors/{self.m4_id}/heartbeat", 200,
            token=self.alice, method="POST", body=heartbeat,
        )
        st_m4, raw_m4, _ = self.http(self.m4_base, "/metrics")
        assert st_m4 == 200, "scenario D: mirror metrics request failed"
        assert b"rootyard_mirror_sync_total 0\n" in raw_m4, "scenario D: mirror synced before the explicit fetch"

        pr4, _ = self.document(
            self.c2_base, "/api/repos/alice/forge/pulls", 201,
            token=self.alice, method="POST",
            body={
                "title": "Scenario D Controlled Readiness", "body": "pr4",
                "head_ref": "refs/heads/feat-e", "base_ref": "refs/heads/main",
            },
        )
        assert pr4.get("head_oid") == target_oid, "scenario D: PR head OID mismatch"
        pr_number = pr4.get("number")
        if not isinstance(pr_number, int):
            raise AssertionError("scenario D: PR number is not an integer")
        runs4 = self.wait_for_runs(
            self.repo1["id"], pr_number, target_oid, ("ci/test", "ci/lint", "ci/b3")
        )
        prefix1 = f"/api/repos/alice/forge/integrations/{self.hook1_id}/runs/"
        run_id = runs4.get("ci/test")
        if not isinstance(run_id, str):
            raise AssertionError("scenario D: ci/test run is absent")

        # Refresh the only live mirror and prove it is alive but not ready.
        self.document(
            self.c2_base, f"/api/repos/alice/forge/ci-mirrors/{self.m4_id}/heartbeat", 200,
            token=self.alice, method="POST", body=heartbeat,
        )
        before, _ = self.document(
            self.c2_base, f"/api/repos/alice/forge/ci-mirrors?target_oid={target_oid}", 200, token=self.alice
        )
        before_mirrors = before.get("mirrors")
        if not isinstance(before_mirrors, list):
            raise AssertionError("scenario D: pre-claim mirror listing is not a list")
        by_id = {m.get("mirror_id"): m for m in before_mirrors if isinstance(m, dict)}
        mirror_before = by_id.get(self.m4_id)
        if not isinstance(mirror_before, dict):
            raise AssertionError("scenario D: mirror-4 is absent from the pre-claim listing")
        assert mirror_before.get("alive") is True, "scenario D: mirror-4 is not alive before claim"
        assert mirror_before.get("target_ready") is False, "scenario D: mirror-4 already serves the target"
        assert all(
            not (m.get("alive") and m.get("target_ready"))
            for mid, m in by_id.items()
            if mid != self.m4_id and isinstance(m, dict)
        ), "scenario D: an unselected mirror already serves the target"
        assert self.sql(
            f"SELECT count(*) FROM ci_mirror_nodes WHERE repository_id='{self.repo1['id']}' "
            f"AND mirror_id<>'{self.m4_id}' AND active=true"
        ) == "0", "scenario D: an allowlisted mirror is still active"

        # First real claim: the live target mirror cannot serve the target, so
        # the only correct answer is a genuine 202 waiting with no lease/grant.
        waiting_doc, waiting_hdrs = self.document(
            self.c2_base, prefix1 + run_id + "/claim", 202,
            bearer=self.hook_secret, method="POST",
            body={"runner_id": "runner-d-wait", "prefer_mirror": True, "wait_for_ready_ms": 0},
        )
        assert waiting_hdrs.get("x-rootyard-ci-state") == "waiting", "scenario D: first claim state header is not waiting"
        assert waiting_doc.get("classification") == "waiting", "scenario D: first claim classification is not waiting"
        assert "checkout" not in waiting_doc and "source" not in waiting_doc, "scenario D: first claim published checkout data"
        availability = waiting_doc.get("availability")
        if not isinstance(availability, dict):
            raise AssertionError("scenario D: first claim availability is not an object")
        assert availability.get("ready_available_mirrors") == 0, "scenario D: an unavailable ready mirror was counted"
        assert availability.get("ready_total_mirrors") == 0, "scenario D: a ready mirror was counted before fetch"
        healthy_unready = availability.get("healthy_unready_mirrors")
        if not isinstance(healthy_unready, int):
            raise AssertionError("scenario D: first claim unready count is not an integer")
        assert healthy_unready >= 1, "scenario D: no healthy unready mirror was counted"
        queued = self.sql(
            f"SELECT state||','||attempt||','||lease_generation||','||coalesce(source_url,'')||','||coalesce(runner_id,'') "
            f"FROM ci_runs WHERE id='{run_id}'"
        )
        assert queued == "queued,0,0,,", "scenario D: first claim published a lease or changed the queued run"
        assert self.sql(
            f"SELECT count(*) FROM ci_integration_checkout_jobs WHERE run_id='{run_id}'"
        ) == "0", "scenario D: first claim published a checkout grant"
        assert self.sql(
            f"SELECT count(*) FROM ci_mirror_nodes WHERE repository_id='{self.repo1['id']}' "
            f"AND active=true AND heartbeat_unix>extract(epoch FROM clock_timestamp())::bigint-30 "
            f"AND ready_oids ? '{target_oid}'"
        ) == "0", "scenario D: target became ready without the explicit auto-fetch"
        st_m4, raw_m4, _ = self.http(self.m4_base, "/metrics")
        assert st_m4 == 200, "scenario D: mirror metrics request failed after first claim"
        assert b"rootyard_mirror_sync_total 0\n" in raw_m4, "scenario D: mirror synced before the explicit fetch"

        # The explicit named-mirror auto-fetch is a real isolate mirror sync on
        # the same controller/PostgreSQL/storage. Its response is returned only
        # after publish_ready_oid commits the exact target OID.
        fetched, fetch_hdrs = self.document(
            self.m4_base, "/api/repos/alice/forge/mirror-auto-fetch", 200,
            token=self.prewarm_pat, method="POST", timeout=30.0,
            body={"target_oid": target_oid, "storage_generation": 1, "wait_ms": 5000, "mirror_id": self.m4_id},
        )
        assert fetch_hdrs.get("x-rootyard-ci-state") == "ready", "scenario D: auto-fetch state header is not ready"
        assert fetched.get("target_oid") == target_oid, "scenario D: auto-fetch target OID mismatch"
        assert fetched.get("classification") == "ready", "scenario D: auto-fetch classification is not ready"
        assert fetched.get("cache_status") == "miss_fetched", "scenario D: auto-fetch did not perform a fresh fetch"
        after, _ = self.document(
            self.c2_base, f"/api/repos/alice/forge/ci-mirrors?target_oid={target_oid}", 200, token=self.alice
        )
        after_mirrors = after.get("mirrors")
        if not isinstance(after_mirrors, list):
            raise AssertionError("scenario D: post-fetch mirror listing is not a list")
        after_by_id = {m.get("mirror_id"): m for m in after_mirrors if isinstance(m, dict)}
        mirror_after = after_by_id.get(self.m4_id)
        if not isinstance(mirror_after, dict):
            raise AssertionError("scenario D: mirror-4 is absent from the post-fetch listing")
        assert mirror_after.get("alive") is True, "scenario D: mirror-4 is not alive after fetch"
        assert mirror_after.get("target_ready") is True, "scenario D: mirror-4 did not publish target readiness"
        assert self.sql(
            f"SELECT active::text||','||(ready_oids ? '{target_oid}')::text||','||"
            f"(heartbeat_unix>extract(epoch FROM clock_timestamp())::bigint-30)::text "
            f"FROM ci_mirror_nodes WHERE repository_id='{self.repo1['id']}' AND mirror_id='{self.m4_id}'"
        ) == "true,true,true", "scenario D: explicit auto-fetch did not commit readiness"
        st_m4, raw_m4, _ = self.http(self.m4_base, "/metrics")
        assert st_m4 == 200, "scenario D: mirror metrics request failed after fetch"
        assert b"rootyard_mirror_sync_total 0\n" not in raw_m4, "scenario D: mirror sync counter did not advance"

        # The same durable queued run must now claim the exact ready mirror and
        # persist attempt/lease/grant against this repository, target and generation.
        claimed, claim_hdrs = self.document(
            self.c2_base, prefix1 + run_id + "/claim", 200,
            bearer=self.hook_secret, method="POST",
            body={"runner_id": "runner-d-ready", "prefer_mirror": True, "wait_for_ready_ms": 0},
        )
        # Register the credential before any assertion can stringify the response.
        checkout_token = self.register_checkout_token(claimed)
        assert claim_hdrs.get("x-rootyard-ci-state") == "ready", "scenario D: claim state header is not ready"
        assert claimed.get("run_id") == run_id, "scenario D: claim returned a different run"
        assert claimed.get("source") == self.m4_base, "scenario D: claim selected an unexpected source"
        assert claimed.get("head_oid") == target_oid, "scenario D: claim target OID mismatch"
        assert claimed.get("storage_generation") == 1, "scenario D: claim storage generation mismatch"
        assert claimed.get("attempt") == 1, "scenario D: claim attempt mismatch"
        assert claimed.get("lease_generation") == 1, "scenario D: claim lease generation mismatch"
        checkout = claimed.get("checkout")
        if not isinstance(checkout, dict):
            raise AssertionError("scenario D: claim checkout is not an object")
        plan = checkout.get("plan")
        if not isinstance(plan, dict):
            raise AssertionError("scenario D: claim plan is not an object")
        claimed_job_id = claimed.get("job_id")
        if not isinstance(claimed_job_id, str):
            raise AssertionError("scenario D: claim job id is not a string")
        try:
            uuid.UUID(claimed_job_id)
        except ValueError:
            raise AssertionError("scenario D: claim job id is not a UUID") from None
        assert plan.get("repository_id") == self.repo1["id"], "scenario D: plan repository mismatch"
        assert plan.get("job_id") == claimed_job_id, "scenario D: plan job mismatch"
        assert plan.get("target_oid") == target_oid, "scenario D: plan target OID mismatch"
        assert plan.get("storage_generation") == 1, "scenario D: plan storage generation mismatch"
        persisted = self.sql(
            f"SELECT state||','||attempt||','||lease_generation||','||source_url||','||runner_id||','||"
            f"storage_generation||','||head_oid||','||repository_id::text||','||job_id::text "
            f"FROM ci_runs WHERE id='{run_id}'"
        )
        assert persisted == (
            f"leased,1,1,{self.m4_base},runner-d-ready,1,{target_oid},{self.repo1['id']},{claimed_job_id}"
        ), "scenario D: persisted lease does not match the claimed run"
        assert self.sql(
            f"SELECT count(*) FROM ci_integration_checkout_jobs WHERE run_id='{run_id}'"
        ) == "1", "scenario D: checkout grant count is not exactly one"
        assert self.sql(
            f"SELECT count(*) FROM ci_integration_checkout_jobs WHERE run_id='{run_id}' "
            f"AND attempt=1 AND lease_generation=1 AND repository_id='{self.repo1['id']}' "
            f"AND job_id='{claimed_job_id}' AND plan->>'target_oid'='{target_oid}' "
            f"AND plan->>'storage_generation'='1'"
        ) == "1", "scenario D: checkout grant is not bound to repo/target/generation"
        assert self.sql(
            f"SELECT encode(credential_digest,'hex') FROM ci_integration_checkout_jobs WHERE run_id='{run_id}'"
        ) == hashlib.sha256(checkout_token.encode()).hexdigest(), "scenario D: grant token digest mismatch"
        assert self.sql(
            f"SELECT (r.lease_expires_unix>extract(epoch FROM clock_timestamp())::bigint)::text||','||"
            f"(g.expires_unix>r.lease_expires_unix)::text||','||"
            f"(g.expires_unix=(g.plan->>'expires_unix')::bigint)::text "
            f"FROM ci_runs r JOIN ci_integration_checkout_jobs g ON g.run_id=r.id WHERE r.id='{run_id}'"
        ) == "true,true,true", "scenario D: lease/grant expiry is not coherent"

        self.verify_git_checkout(
            f"{self.m4_base}/ci/{target_oid}/git/alice/forge.git",
            self.root / "clone-d", target_oid, checkout_token,
        )

        return {
            "first_claim_http": 202,
            "first_claim_state": "waiting",
            "lease_or_grant_before_ready": False,
            "explicit_autofetch_cache_status": "miss_fetched",
            "target_ready_via_controller": True,
            "second_claim_http": 200,
            "persisted_attempt": 1,
            "persisted_lease_generation": 1,
            "persisted_grant_bound_repo_target_generation": True,
            "checkout_clone_fsck": "strict_passed",
            "target_oid": target_oid,
            "mirror_id": self.m4_id,
        }

    def case(self, name: str, fn) -> None:
        t0 = time.monotonic()
        try:
            detail = fn()
            self.results.append({"name": name, "status": "passed", "seconds": round(time.monotonic() - t0, 4), "detail": detail})
            print(f"{name}: passed", flush=True)
        except Exception as err:
            tb = self.redact(traceback.format_exc())
            msg = self.redact(f"{type(err).__name__}: {err}")
            self.results.append({"name": name, "status": "failed", "seconds": round(time.monotonic() - t0, 4), "error": msg, "traceback": tb})
            raise

    def stop_all_daemons(self) -> None:
        for name in list(self.procs):
            self.stop_daemon(name, hard=False)

    def scan_source_token_logs(self) -> dict[str, object]:
        paths = [entry["log_path"] for entry in self.procs.values() if entry.get("log_path")]
        if not paths:
            return {"state": "unavailable", "scanned": 0}
        return scan_token_in_logs(paths, self.source_pat.get("token", ""))

    def cleanup(self) -> None:
        self.stop_all_daemons()
        leaked = live_pgid_processes(self.tracked_pgids)
        if leaked:
            for pid, _, _, _ in leaked:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            raise AssertionError(f"Leaked child processes detected after shutdown: {leaked}")
        if self.schema_created:
            try:
                self.sql(f'DROP SCHEMA IF EXISTS "{self.schema}" CASCADE', isolated=False)
            except Exception:
                pass
        if not self.args.keep:
            shutil.rmtree(self.root, ignore_errors=True)


def method_of(kwargs: dict) -> str:
    return str(kwargs.get("method", "GET"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard", help="Path to compiled rootyard binary")
    parser.add_argument("--report", type=Path, help="Optional JSON report output path")
    parser.add_argument("--keep", action="store_true", help="Retain temporary workdir and logs after run")
    args = parser.parse_args(argv)
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a disposable dedicated database")

    harness = HaQualificationHarness(args)
    success = False
    failure_trace: str | None = None
    try:
        harness.case("setup_daemons", harness.setup_daemons)
        harness.case("scenario_a_pr_prewarm_and_live_mirror_checkout", harness.scenario_a_pr_prewarm_and_live_mirror_checkout)
        harness.case("scenario_b_sigkill_dual_crash_and_failover", harness.scenario_b_sigkill_dual_crash_and_failover)
        harness.case("scenario_c_coalesced_prewarm_and_origin_burst", harness.scenario_c_coalesced_prewarm_and_origin_burst)
        harness.case("scenario_d_controlled_readiness_claim_transition", harness.scenario_d_controlled_readiness_claim_transition)
        success = True
    except Exception:
        failure_trace = harness.redact(traceback.format_exc())
    finally:
        try:
            harness.stop_all_daemons()
        except Exception:
            harness.results.append({
                "name": "stop_daemons",
                "status": "failed",
                "error": "daemon shutdown failed",
            })
            success = False
        try:
            leak_scan = harness.scan_source_token_logs()
        except Exception:
            leak_scan = {"state": "unreadable", "scanned": 0}
        leak_state = str(leak_scan.get("state", "unreadable"))
        if leak_state not in {"clean", "leaked", "missing", "unreadable", "unavailable"}:
            leak_state = "unreadable"
        leak_logs = leak_scan.get("scanned", 0)
        if not isinstance(leak_logs, int) or leak_logs < 0:
            leak_logs = 0
        leak_clean = leak_state == "clean"
        harness.results.append({
            "name": "final_source_token_leak_scan",
            "status": "passed" if leak_clean else "failed",
            "detail": {"state": leak_state, "logs": leak_logs},
        })
        print(f"final source-token leak scan: {leak_state}", file=sys.stderr)
        if not leak_clean:
            success = False
        try:
            harness.cleanup()
        except Exception:
            harness.results.append({
                "name": "cleanup",
                "status": "failed",
                "error": "cleanup failed",
            })
            success = False
        if failure_trace:
            print(failure_trace, file=sys.stderr)
        report = {
            "passed": success,
            "cases": harness.results,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
            if Path(args.binary).is_file()
            else None,
            "limitations": [
                "Single-host loopback processes and isolated PostgreSQL 17 schema, not a multi-host network or power-loss test.",
                "Automatic lease expiry in Scenario B resets lease_expires_unix in the run-owned schema so expiry reconciliation finishes within the CI timeout budget.",
                "Scenario D commits target readiness only through an explicit named-mirror auto-fetch on an unlisted live mirror; it does not inject a production race or substitute scheduler authority.",
            ],
        }
        report["passed"] = success
        payload = json.dumps(report, indent=2) + "\n"
        if any(secret and secret in payload for secret in harness.secrets):
            report["passed"] = False
            success = False
            payload = harness.redact(json.dumps(report, indent=2) + "\n")
        payload, within_limit = bounded_report_payload(payload)
        if not within_limit:
            success = False
            payload = json.dumps({
                "passed": False,
                "cases": [{
                    "name": "report_size_limit",
                    "status": "failed",
                    "error": "qualification report exceeded the bounded size cap",
                }],
                "final_source_token_leak_scan": {"state": leak_state, "logs": leak_logs},
            }, indent=2) + "\n"
            print("qualification report exceeded the bounded size cap", file=sys.stderr)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(payload, encoding="utf-8", newline="\n")
        print(payload)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
