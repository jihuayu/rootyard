#!/usr/bin/env python3
"""Live local-host process fence, measured replica, stale-data rejection, takeover."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.error
import uuid

from e2e import Harness
from cluster_workload_native import free_port, request


def wait_ready(base, token, process):
    until = time.monotonic() + 30
    while time.monotonic() < until:
        if process.poll() is not None:
            raise AssertionError("storage process exited before readiness")
        try:
            if request(base, "/health/ready", token)[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.1)
    raise AssertionError("storage process readiness timeout")


def session_groups(session_id):
    groups = set()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
            if int(stat[3]) == session_id and stat[0] not in ("Z", "X"):
                groups.add(int(stat[2]))
        except (OSError, IndexError, ValueError):
            continue
    return groups


def has_native_writer_child(group_id):
    return any(group != group_id for group in session_groups(group_id))


def pause_session(session_id):
    for group in sorted(session_groups(session_id), key=lambda group: group == session_id):
        try:
            os.killpg(group, signal.SIGSTOP)
        except ProcessLookupError:
            pass


def resume_session(session_id):
    for group in session_groups(session_id):
        try:
            os.killpg(group, signal.SIGCONT)
        except ProcessLookupError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    h = Harness(args)
    fence_dir = h.root / "controller-fences"
    fence_dir.mkdir(mode=0o700)
    h.env["ROOTYARD_LOCAL_FENCE_DIR"] = str(fence_dir)
    h.env["ROOTYARD_NODE_ID"] = "shard-primary-0"
    h.env["ROOTYARD_CLUSTER_HMAC_KEY"] = base64.b64encode(os.urandom(32)).decode()
    target = None
    log = None
    try:
        h.setup()
        h.sql("INSERT INTO cluster_operator_tokens(token_id,granted_by) VALUES ('" + h.alice["token_id"] + "','native-takeover')")
        status, _ = request(h.base, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "shard-primary-0", "endpoint": h.base, "role": "primary", "status": "healthy", "lease_ttl_seconds": 2})
        assert status in (200, 201), status
        h.api()
        h.roundtrip()
        duplicate_env = h.env.copy()
        duplicate_env["ROOTYARD_DATA_DIR"] = str(h.root / "duplicate-node-volume")
        duplicate = h.run([args.binary, "serve"], env=duplicate_env, check=False)
        assert duplicate.returncode != 0 and b"node identity already has an active process" in duplicate.stderr
        old_pid = h.proc.pid
        target_port = free_port()
        target_base = f"http://127.0.0.1:{target_port}"
        target_data = h.root / "data-target"
        env = h.env.copy()
        env.update(ROOTYARD_NODE_ID="node1", ROOTYARD_BIND=f"127.0.0.1:{target_port}",
                   ROOTYARD_DATA_DIR=str(target_data), ROOTYARD_OUTBOX_WORKER="false")
        log = open(h.root / "target.log", "ab")
        target = subprocess.Popen([args.binary, "serve"], env=env, stdout=log, stderr=log, start_new_session=True)
        wait_ready(target_base, h.alice, target)
        status, _ = request(h.base, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "node1", "endpoint": target_base, "role": "replica", "status": "healthy", "lease_ttl_seconds": 2})
        assert status in (200, 201), status
        path = "/api/repos/alice/demo/shard-migrate"
        route_path = "/api/repos/alice/demo/shard-route"
        initial = json.loads(h.expect(route_path, 200, token=h.alice))
        operation_id = str(uuid.uuid4())
        request_body = {"target_node_id": "node1", "operation_id": operation_id,
                        "expected_route_epoch": initial["route_epoch"], "replicate_only": True}
        first = json.loads(h.expect(path, 200, token=h.alice, method="POST", body=request_body))
        assert first["state"] == "verified" and first["new_route_epoch"] == initial["route_epoch"]
        assert json.loads(h.expect(route_path, 200, token=h.alice))["primary_node_id"] == "shard-primary-0"
        target_repo = target_data / "repos" / (h.repo["id"] + ".git")
        assert h.git("--git-dir=" + str(target_repo), "rev-parse", "refs/heads/main").stdout.decode().strip() == h.second

        # A source write after replication makes the measured target stale. Even
        # after the source lease expires, the controller must not kill/promote.
        (h.work / "hello.txt").write_text("acknowledged after first replica snapshot\n")
        h.git("commit", "-am", "later source write", cwd=h.work)
        later_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
        pause_session(old_pid)
        time.sleep(7)
        assert h.proc.poll() is None, "stale replica caused unsafe source fencing"
        status, raw = request(target_base, route_path, h.alice)
        assert status == 200 and json.loads(raw)["primary_node_id"] == "shard-primary-0"
        assert not (fence_dir / "shard-primary-0.blocked").exists()
        os.killpg(old_pid, signal.SIGCONT)

        second = json.loads(h.expect(path, 200, token=h.alice, method="POST", body=request_body))
        assert second["state"] == "verified"
        assert h.git("--git-dir=" + str(target_repo), "rev-parse", "refs/heads/main").stdout.decode().strip() == later_tip
        # Observe an admitted native Git child while a new, unacknowledged
        # upload is in flight. It has its own process group in the server session.
        (h.work / "inflight.bin").write_bytes(os.urandom(16 * 1024 * 1024))
        h.git("add", "inflight.bin", cwd=h.work)
        h.git("commit", "-m", "in-flight writer", cwd=h.work)
        auth = base64.b64encode((h.alice["username"] + ":" + h.alice["token"]).encode()).decode()
        push = subprocess.Popen(["git", "-c", "http.extraHeader=Authorization: Basic " + auth,
                                 "push", "origin", "HEAD:main"], cwd=h.work, env=h.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        until = time.monotonic() + 15
        while time.monotonic() < until and push.poll() is None and not has_native_writer_child(old_pid):
            time.sleep(.005)
        assert push.poll() is None and has_native_writer_child(old_pid), "native Git writer did not remain in flight"
        pause_session(old_pid)
        time.sleep(7)
        status, raw = request(target_base, route_path, h.alice)
        assert status == 200 and json.loads(raw)["primary_node_id"] == "shard-primary-0", "admitted writer promoted without resolved data"
        assert push.poll() is None and not (fence_dir / "shard-primary-0.blocked").exists()
        resume_session(old_pid)
        _, push_err = push.communicate(timeout=60)
        assert push.returncode == 0, h.redact(push_err.decode(errors="replace")[-500:])
        acknowledged_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        third = json.loads(h.expect(path, 200, token=h.alice, method="POST", body=request_body))
        assert third["state"] == "verified"
        assert h.git("--git-dir=" + str(target_repo), "rev-parse", "refs/heads/main").stdout.decode().strip() == acknowledged_tip
        os.killpg(old_pid, signal.SIGSTOP)
        started = time.monotonic_ns()
        until = time.monotonic() + 20
        promoted = None
        while time.monotonic() < until:
            status, raw = request(target_base, route_path, h.alice)
            if status == 200 and json.loads(raw)["primary_node_id"] == "node1":
                promoted = json.loads(raw)
                break
            time.sleep(.1)
        assert promoted is not None, "controller did not fence and promote measured replica"
        takeover_ms = round((time.monotonic_ns() - started) / 1e6, 3)
        assert h.proc.wait(timeout=5) == -signal.SIGKILL, "old writer group was not killed"
        assert (fence_dir / "shard-primary-0.blocked").is_file()
        h.git("fetch", target_base + h.repo["clone_path"], "refs/heads/main", cwd=h.copy, token=h.reader)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == acknowledged_tip
        h.git("--git-dir=" + str(target_repo), "fsck", "--full", "--strict")
        stale_volume_tip = h.git("--git-dir=" + str(h.bare), "rev-parse", "refs/heads/main").stdout.decode().strip()
        h.stop(hard=True)
        rejected = h.run([args.binary, "serve"], check=False)
        assert rejected.returncode != 0 and b"durable physical fence" in rejected.stderr
        # Even a misconfigured process that omits the local fence deployment
        # variable cannot use the retired source volume as a writer.
        (h.work / "hello.txt").write_text("stale-volume bypass attempt\n")
        h.git("commit", "-am", "stale volume attempt", cwd=h.work)
        for fake_node in (None, "node1"):
            bypass_env = h.env.copy()
            bypass_env.pop("ROOTYARD_LOCAL_FENCE_DIR")
            if fake_node is None:
                bypass_env.pop("ROOTYARD_NODE_ID")
            else:
                bypass_env["ROOTYARD_NODE_ID"] = fake_node
            with open(h.root / "bypass.log", "ab") as bypass_log:
                bypass = subprocess.Popen([args.binary, "serve"], env=bypass_env,
                                          stdout=bypass_log, stderr=bypass_log, start_new_session=True)
                try:
                    until = time.monotonic() + 5
                    while time.monotonic() < until and bypass.poll() is None:
                        try:
                            if request(h.base, "/health/ready", h.alice)[0] == 200:
                                failed_push = h.git("push", h.base + h.repo["clone_path"],
                                                    "HEAD:main", cwd=h.work, token=h.alice, check=False)
                                assert failed_push.returncode != 0, "retired source volume accepted a write"
                                break
                        except (OSError, urllib.error.URLError):
                            pass
                        time.sleep(.1)
                finally:
                    if bypass.poll() is None:
                        os.killpg(bypass.pid, signal.SIGKILL)
                        bypass.wait(timeout=10)
        assert h.git("--git-dir=" + str(h.bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == stale_volume_tip
        report = {"kind": "native_local_host_takeover", "result": "passed", "driver": "local_process_session_v1",
                  "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                  "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "postgres_version": h.sql("SHOW server_version"),
                  "old_session_id": old_pid, "replication_operation_id": operation_id,
                  "takeover_ms": takeover_ms,
                  "stale_replica_rejected": True, "old_writer_sigstop_then_killed": True,
                          "admitted_native_writer_paused_and_promotion_rejected": True,
                          "duplicate_live_node_identity_rejected": True,
                          "retired_source_volume_write_rejected_without_fence_env": True,
                          "old_writer_restart_blocked": True, "acknowledged_tip": acknowledged_tip,
                          "target_fsck": "passed", "new_epoch": promoted["route_epoch"],
                  "limits": ["single-host isolated process session driver", "no cross-host storage fence or PostgreSQL HA"]}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    finally:
        if target and target.poll() is None:
            os.killpg(target.pid, signal.SIGKILL)
            target.wait(timeout=10)
        if log:
            log.close()
        h.cleanup()


if __name__ == "__main__":
    main()
