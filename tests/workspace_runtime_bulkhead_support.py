"""Shared test fixtures for workspace runtime bulkhead and rollback regressions (#73)."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tests.e2e import Harness

MAX_FIXTURE_BODY = 32 * 1024 * 1024


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class _DaemonHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class LoopbackS3Fixture:
    """Bounded loopback path-style S3 fixture used when ROOTYARD_OBJECT_STORE_ENDPOINT is unset."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._objects: dict[tuple[str, str], bytes] = {}
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:
                pass

            def do_HEAD(self) -> None:
                self._serve()

            def do_GET(self) -> None:
                self._serve()

            def do_PUT(self) -> None:
                self._serve()

            def do_DELETE(self) -> None:
                self._serve()

            def _reply(self, code: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
                self.send_response_only(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                if body and self.command != "HEAD":
                    self.wfile.write(body)

            def _serve(self) -> None:
                raw_path = self.path.split("?", 1)[0].lstrip("/")
                bucket, _, key = raw_path.partition("/")
                if not bucket:
                    self._reply(200, b"<ListAllMyBucketsResult/>", {"Content-Type": "application/xml"})
                    return
                if self.command == "PUT":
                    length = int(self.headers.get("Content-Length") or 0)
                    if length > MAX_FIXTURE_BODY:
                        self._reply(413, b"<Error><Code>EntityTooLarge</Code></Error>")
                        return
                    payload = self.rfile.read(length) if length else b""
                    if not key:
                        self._reply(200)
                        return
                    etag = f'"{hashlib.md5(payload).hexdigest()}"'
                    with fixture._lock:
                        if self.headers.get("If-None-Match") == "*" and (bucket, key) in fixture._objects:
                            self._reply(
                                412,
                                b"<Error><Code>PreconditionFailed</Code><Message>exists</Message></Error>",
                                {"Content-Type": "application/xml"},
                            )
                            return
                        fixture._objects[(bucket, key)] = payload
                    self._reply(200, b"", {"ETag": etag})
                elif self.command in ("GET", "HEAD"):
                    if not key:
                        xml = (
                            f'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                            f"<Name>{bucket}</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated>"
                            f"</ListBucketResult>"
                        ).encode()
                        self._reply(200, xml, {"Content-Type": "application/xml"})
                        return
                    with fixture._lock:
                        stored = fixture._objects.get((bucket, key))
                    if stored is None:
                        self._reply(
                            404,
                            b"<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>",
                            {"Content-Type": "application/xml"},
                        )
                        return
                    etag = f'"{hashlib.md5(stored).hexdigest()}"'
                    if self.command == "HEAD":
                        self.send_response_only(200)
                        self.send_header("ETag", etag)
                        self.send_header("Content-Length", str(len(stored)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.close_connection = True
                    else:
                        self._reply(200, stored, {"ETag": etag})
                elif self.command == "DELETE":
                    with fixture._lock:
                        fixture._objects.pop((bucket, key), None)
                    self._reply(204)
                else:
                    self._reply(405)

        self._server = _DaemonHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class BulkheadHarness(Harness):
    def __init__(self, args: argparse.Namespace, require_s3: bool = False) -> None:
        super().__init__(args)
        self._loopback_s3: LoopbackS3Fixture | None = None
        if require_s3 and not self.env.get("ROOTYARD_OBJECT_STORE_ENDPOINT"):
            self._loopback_s3 = LoopbackS3Fixture()
            self.env["ROOTYARD_OBJECT_STORE_ENDPOINT"] = self._loopback_s3.endpoint
            self.env["ROOTYARD_OBJECT_STORE_BUCKET"] = "rootyard-ws-bulkhead"
            self.env["ROOTYARD_OBJECT_STORE_REGION"] = "us-east-1"
            self.env["ROOTYARD_OBJECT_STORE_ACCESS_KEY"] = "loopback-access"
            self.env["ROOTYARD_OBJECT_STORE_SECRET_KEY"] = "loopback-secret"

    def cleanup(self) -> None:
        try:
            super().cleanup()
        finally:
            if self._loopback_s3 is not None:
                self._loopback_s3.close()
                self._loopback_s3 = None


def new_harness(require_s3: bool = False) -> BulkheadHarness:
    return BulkheadHarness(
        argparse.Namespace(
            binary="target/debug/rootyard",
            keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1",
        ),
        require_s3=require_s3,
    )


def wait_for_capture_scan(h: Harness, wid: str, after_ts: str, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scanned = h.sql(
            f"SELECT COALESCE(scanned_at > '{after_ts}'::timestamptz, false) "
            f"FROM workspace_capture_state WHERE workspace_id = '{wid}'"
        ).strip()
        if scanned == "t":
            return
        time.sleep(0.1)
    raise AssertionError(f"workspace {wid} was not scanned by capture worker after {after_ts}")


def start_psql_tx(h: Harness) -> subprocess.Popen:
    env = h.env.copy()
    env["PGDATABASE"] = h.db
    return subprocess.Popen(
        ["psql", "--dbname", h.db, "-X", "-v", "ON_ERROR_STOP=1", "-qAt"],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def stop_psql_tx(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=5)
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is not None and not stream.closed:
            stream.close()


def git_object_files(repo: Path) -> set[str]:
    obj_root = repo / ".git/objects"
    if not obj_root.is_dir():
        return set()
    return {str(p.relative_to(obj_root)) for p in obj_root.rglob("*") if p.is_file()}


def make_git_gate(h: Harness):
    real_git = shutil.which("git", path=h.env["PATH"])
    assert real_git, "git binary required in PATH"
    gate_dir = h.root / "git-gate"
    gate_dir.mkdir(exist_ok=True)
    pause_flag = gate_dir / "pause-add"
    hang_lock_flag = gate_dir / "hang-with-lock"
    entered_dir = gate_dir / "entered"
    entered_dir.mkdir(exist_ok=True)
    wrapper = h.root / "gated-workspace-git"
    wrapper.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, sys, time\n"
        "args = sys.argv[1:]\n"
        f"pause = pathlib.Path({str(pause_flag)!r})\n"
        f"hang_lock = pathlib.Path({str(hang_lock_flag)!r})\n"
        f"entered = pathlib.Path({str(entered_dir)!r})\n"
        "repo = None\n"
        "for i, tok in enumerate(args):\n"
        "    if tok == '-C' and i + 1 < len(args):\n"
        "        repo = pathlib.Path(args[i + 1])\n"
        "if 'add' in args and hang_lock.exists() and repo is not None:\n"
        "    git_dir = repo / '.git'\n"
        "    (git_dir / 'index.lock').write_bytes(b'stranded-timeout-lock')\n"
        "    loose_dir = git_dir / 'objects/fe'\n"
        "    loose_dir.mkdir(parents=True, exist_ok=True)\n"
        "    loose = loose_dir / 'deadbeef'\n"
        "    loose.write_bytes(b'stranded-loose')\n"
        "    loose.chmod(0o444)\n"
        "    (entered / str(os.getpid())).write_text('lock')\n"
        "    time.sleep(30)\n"
        "if 'add' in args and pause.exists():\n"
        "    (entered / str(os.getpid())).write_text('1')\n"
        "    while pause.exists():\n"
        "        time.sleep(0.02)\n"
        f"os.execv({real_git!r}, [{real_git!r}] + args)\n"
    )
    wrapper.chmod(0o700)
    return wrapper, pause_flag, hang_lock_flag, entered_dir


def create_ws(h: Harness, agent: str, key: str) -> dict:
    return json.loads(
        h.expect(
            "/api/workspaces",
            201,
            token=h.alice,
            method="POST",
            body={"owner": "alice", "repository": "demo", "agent_id": agent, "base_oid": h.second},
            extra_headers={"Idempotency-Key": key},
        )
    )


def put_hello(h: Harness, wid: str, data: bytes, entry_ver: int, rev: int, key: str, epoch: int = 1):
    return h.expect(
        f"/api/workspaces/{wid}/files?path=hello.txt",
        200,
        token=h.alice,
        method="PUT",
        body={
            "content_base64": b64(data),
            "expected_entry_version": entry_ver,
            "expected_workspace_revision": rev,
            "lease_epoch": epoch,
        },
        extra_headers={"Idempotency-Key": key},
    )


def git_add_body(gen: int, rev: int, epoch: int = 1) -> dict:
    return {
        "action": "add",
        "paths": ["hello.txt"],
        "expected_git_generation": gen,
        "expected_workspace_revision": rev,
        "lease_epoch": epoch,
    }
