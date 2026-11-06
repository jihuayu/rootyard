"""Native Git/PostgreSQL proof for overlapping exact-ref receives and crash recovery."""

import argparse
import base64
import hashlib
import http.client
import json
import os
import random
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from e2e import Harness


def new_commit(h, name, seed):
    (h.work / name).write_bytes(random.Random(seed).randbytes(4 * 1024 * 1024))
    h.git("add", name, cwd=h.work)
    h.git("commit", "-m", name, cwd=h.work)
    oid = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
    pack = h.run(["git", "pack-objects", "--stdout", "--revs"], cwd=h.work,
                 data=(oid + "\n^" + h.first + "\n").encode()).stdout
    assert pack.startswith(b"PACK") and len(pack) > 1024 * 1024
    return oid, pack


def paused_push(h, ref, oid, pack):
    command = h.pkt(("0" * 40 + " " + oid + " " + ref).encode()
                    + b"\0report-status side-band-64k\n") + b"0000"
    body = command + pack
    token = base64.b64encode(("alice:" + h.alice["token"]).encode()).decode()
    path = h.repo["clone_path"] + "/git-receive-pack"
    header = (f"POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {token}\r\n"
              f"Content-Type: application/x-git-receive-pack-request\r\n"
              f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    entered = threading.Event()
    release = threading.Event()
    result = {}

    def send():
        stage = "connect"
        try:
            with socket.create_connection(("127.0.0.1", h.port), timeout=10) as sock:
                sock.settimeout(20)
                stage = "prefix"
                sock.sendall(header + body[:len(command) + 65536])
                entered.set()
                assert release.wait(15), "paused upload was never released"
                stage = "pack-tail"
                sock.sendall(body[len(command) + 65536:])
                response = http.client.HTTPResponse(sock)
                stage = "response-headers"
                response.begin()
                result["status"] = response.status
                result["headers"] = dict(response.getheaders())
                stage = "response-body"
                result["body"] = response.read()
        except Exception as error:
            if isinstance(error, http.client.IncompleteRead):
                result["body"] = error.partial
            result["error"] = f"{stage}: {error}; status={result.get('status')}; headers={result.get('headers')}"
            entered.set()

    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    assert entered.wait(10), "upload did not reach paused pack transfer"
    journal_dir = h.root / "data" / "journal" / h.repo["id"]
    until = time.monotonic() + 5
    while not list(journal_dir.glob("*/active.lock")):
        assert time.monotonic() < until, "native receiver did not admit paused ref"
        time.sleep(.01)
    return release, thread, result


def assert_push(release, thread, result, ref):
    release.set()
    thread.join(20)
    assert not thread.is_alive(), "native receive did not finish"
    assert "error" not in result, (result.get("error"), result.get("body", b"")[-500:])
    assert result["status"] == 200, result["status"]
    assert b"ok " + ref.encode() in result["body"], result["body"][-400:]


def overlap(h):
    oid, pack = new_commit(h, "overlap.bin", 610)
    ref = "refs/heads/slow-independent"
    release, thread, result = paused_push(h, ref, oid, pack)
    try:
        started = time.monotonic()
        h.git("push", "origin", h.first + ":refs/heads/other-independent",
              cwd=h.work, token=h.alice)
        elapsed = time.monotonic() - started
        assert not release.is_set() and thread.is_alive(), "slow upload ended before unrelated push"
        assert elapsed < 4, f"unrelated ref push serialized for {elapsed:.2f}s"
    finally:
        release.set()
    assert_push(release, thread, result, ref)
    refs = h.git("ls-remote", h.remote, token=h.alice).stdout
    assert oid.encode() + b"\t" + ref.encode() in refs
    assert h.first.encode() + b"\trefs/heads/other-independent" in refs
    return {"slow_pack_bytes": len(pack), "unrelated_push_seconds": round(elapsed, 3)}


def atomic_conflict(h):
    oid, pack = new_commit(h, "atomic-race.bin", 611)
    ref = "refs/heads/slow-conflict"
    release, thread, result = paused_push(h, ref, oid, pack)
    competing = {}

    def atomic_push():
        competing["result"] = h.git("push", "--atomic", "origin",
            h.first + ":" + ref, h.first + ":refs/heads/atomic-other",
            cwd=h.work, token=h.alice, check=False)

    contender = threading.Thread(target=atomic_push, daemon=True)
    contender.start()
    time.sleep(.4)
    assert contender.is_alive(), "same-ref atomic contender escaped ref lease"
    try:
        assert_push(release, thread, result, ref)
        contender.join(15)
        assert not contender.is_alive(), "atomic contender stayed blocked after ref publication"
        assert competing["result"].returncode != 0, "stale atomic compare-and-swap succeeded"
        refs = h.git("ls-remote", h.remote, token=h.alice).stdout
        assert oid.encode() + b"\t" + ref.encode() in refs
        assert b"refs/heads/atomic-other" not in refs, "atomic rejection partly published"
    finally:
        release.set()
    return {"same_ref_waited": True, "atomic_conflict_published_none": True}


def crash_before_grant(h):
    path = h.repo["clone_path"] + "/git-receive-pack"
    token = base64.b64encode(("alice:" + h.alice["token"]).encode()).decode()
    command = h.pkt(("0" * 40 + " " + "f" * 40 + " refs/heads/ungranted").encode()
                    + b"\0report-status\n") + b"0000"
    wire = (f"POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {token}\r\n"
            f"Content-Type: application/x-git-receive-pack-request\r\n"
            f"Content-Length: 100000\r\nConnection: close\r\n\r\n").encode() + command + b"PACK"
    sock = socket.create_connection(("127.0.0.1", h.port), timeout=10)
    try:
        sock.sendall(wire)
        journal_dir = h.root / "data" / "journal" / h.repo["id"]
        until = time.monotonic() + 5
        while not list(journal_dir.glob("*/active.lock")):
            assert time.monotonic() < until, "incomplete native upload was not admitted"
            time.sleep(.01)
        assert not list(journal_dir.glob("*/publication.grant")), "truncated upload got a grant"
        crash_server_and_git(h)
    finally:
        sock.close()
    h.start()
    refs = h.git("ls-remote", h.remote, token=h.alice).stdout
    assert b"refs/heads/ungranted" not in refs
    outcome = h.sql("SELECT outcome || ':' || COALESCE(evidence->>'ungranted_without_hooks','') "
                    "FROM git_operations WHERE repository_id='" + h.repo["id"] + "' "
                    "ORDER BY sequence DESC LIMIT 1")
    assert outcome == "no_ref_changes:true", outcome
    return {"interrupted_without_grant": outcome, "repository_remained_ready": True}


def crash_server_and_git(h):
    groups = set()
    for pid in h.descendants():
        try:
            group = os.getpgid(pid)
            if group != h.proc.pid:
                groups.add(group)
        except ProcessLookupError:
            pass
    h.stop(hard=True)
    # Native Git has a separate process group and inherits the volume lock.
    # A host-level crash terminates it before another writer can start.
    for group in groups:
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass


def crash_after_grant_is_uncertain(h):
    repo = json.loads(h.expect("/api/repos", 201, method="POST", token=h.alice,
                               body={"name": "grant-uncertain"}))
    relation = "forge_branch_rules"
    locker = subprocess.Popen(["psql", "--dbname", h.db, "-X", "-q", "-v", "ON_ERROR_STOP=1",
        "-c", f"BEGIN; LOCK TABLE {relation} IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(15); COMMIT"],
        env=h.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        until = time.monotonic() + 5
        query = ("SELECT count(*) FROM pg_locks WHERE locktype='relation' "
                 f"AND relation='{relation}'::regclass AND mode='AccessExclusiveLock' AND granted")
        while h.sql(query) != "1":
            assert time.monotonic() < until and locker.poll() is None, "policy lock was not held"
            time.sleep(.02)
        pack = h.run(["git", "pack-objects", "--stdout", "--revs"], cwd=h.work,
                     data=(h.first + "\n").encode()).stdout
        command = h.pkt(("0" * 40 + " " + h.first + " refs/heads/main").encode()
                        + b"\0report-status side-band-64k\n") + b"0000"
        token = base64.b64encode(("alice:" + h.alice["token"]).encode()).decode()
        path = repo["clone_path"] + "/git-receive-pack"
        body = command + pack
        wire = (f"POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {token}\r\n"
                f"Content-Type: application/x-git-receive-pack-request\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        sock = socket.create_connection(("127.0.0.1", h.port), timeout=10)
        try:
            sock.sendall(wire)
            journal_dir = h.root / "data" / "journal" / repo["id"]
            until = time.monotonic() + 5
            while not list(journal_dir.glob("*/publication.grant")):
                assert time.monotonic() < until, "native pre-receive did not get parent grant"
                time.sleep(.01)
            assert h.sql("SELECT count(*) FROM pg_locks WHERE locktype='relation' "
                         f"AND relation='{relation}'::regclass AND mode='AccessShareLock' "
                         "AND NOT granted") != "0", "hook did not stall after grant"
            crash_server_and_git(h)
        finally:
            sock.close()
    finally:
        locker.terminate()
        locker.wait(timeout=5)
    h.start()
    status, _, _ = h.http(repo["clone_path"] + "/info/refs?service=git-upload-pack",
                          token=h.alice)
    assert status == 503, f"granted uncertain receive was exposed: {status}"
    state = h.sql("SELECT state || ':' || recovery_reason FROM repositories WHERE id='" + repo["id"] + "'")
    outcome = h.sql("SELECT outcome FROM git_operations WHERE repository_id='" + repo["id"] + "' "
                    "ORDER BY sequence DESC LIMIT 1")
    assert state == "recovering:push_outcome_unknown" and outcome == "unknown", (state, outcome)
    return {"real_native_grant": True, "policy_lock_stalled_hook": True,
            "recovery_state": state, "operation_outcome": outcome}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    h = Harness(args)
    try:
        h.case("setup", h.setup)
        h.case("repository", h.api)
        h.case("stock_git_roundtrip", h.roundtrip)
        h.case("slow_unrelated_refs_overlap", lambda: overlap(h))
        h.case("same_ref_atomic_conflict", lambda: atomic_conflict(h))
        h.case("sigkill_before_grant_recovery", lambda: crash_before_grant(h))
        h.case("sigkill_after_grant_remains_unknown", lambda: crash_after_grant_is_uncertain(h))
    except Exception as error:
        print(h.redact(error), file=sys.stderr)
    finally:
        h.cleanup()
    passed = all(case["status"] == "passed" for case in h.results)
    report = {"passed": passed, "cases": h.results,
              "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
