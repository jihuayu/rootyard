"""Shared test fixtures for workspace runtime bulkhead and rollback regressions (#73)."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from tests.e2e import Harness


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def new_harness() -> Harness:
    return Harness(
        argparse.Namespace(
            binary="target/debug/rootyard",
            keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1",
        )
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
