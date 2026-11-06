#!/usr/bin/env python3
"""Exercise verified Git bundle migration between disjoint Rust storage processes."""
import argparse
import base64
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    h = Harness(args)
    h.env["ROOTYARD_NODE_ID"] = "shard-primary-0"
    h.env["ROOTYARD_CLUSTER_HMAC_KEY"] = base64.b64encode(os.urandom(32)).decode()
    target = None
    target_log = None
    try:
        h.setup()
        h.sql("INSERT INTO cluster_operator_tokens(token_id, granted_by) VALUES ('" + h.alice["token_id"] + "', 'native-migration')")
        node0 = h.base
        status, _ = request(node0, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "shard-primary-0", "endpoint": node0, "role": "primary", "status": "healthy"})
        assert status in (200, 201), status
        h.api()
        h.roundtrip()
        port = free_port()
        node1 = "http://127.0.0.1:" + str(port)
        node1_data = h.root / "data-node1"
        env = h.env.copy()
        env.update(ROOTYARD_NODE_ID="node1", ROOTYARD_BIND="127.0.0.1:" + str(port),
                   ROOTYARD_DATA_DIR=str(node1_data), ROOTYARD_OUTBOX_WORKER="false",
                   ROOTYARD_MAX_REPO_BYTES="1024")
        target_log = open(h.root / "node1.log", "ab")
        target = subprocess.Popen([args.binary, "serve"], env=env, stdout=target_log, stderr=target_log, start_new_session=True)
        until = time.monotonic() + 30
        while time.monotonic() < until:
            if target.poll() is not None:
                raise AssertionError("target storage process exited")
            try:
                if request(node1, "/health/ready", h.alice)[0] == 200:
                    break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(.1)
        else:
            raise AssertionError("target storage readiness timeout")
        status, _ = request(node0, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "node1", "endpoint": node1, "role": "replica", "status": "healthy"})
        assert status in (200, 201), status
        route = json.loads(h.expect("/api/repos/alice/demo/shard-route", 200, token=h.alice))
        assert route["primary_node_id"] == "shard-primary-0"
        assert not (node1_data / "repos" / (h.repo["id"] + ".git")).exists()
        operation_id = str(uuid.uuid4())
        h.expect("/api/repos/alice/demo/shard-migrate", 409, token=h.alice, method="POST",
                 body={"target_node_id": "node1", "expected_route_epoch": route["route_epoch"], "operation_id": operation_id})
        unchanged = json.loads(h.expect("/api/repos/alice/demo/shard-route", 200, token=h.alice))
        assert unchanged["primary_node_id"] == "shard-primary-0" and unchanged["route_epoch"] == route["route_epoch"]
        assert not (node1_data / "repos" / (h.repo["id"] + ".git")).exists()
        os.killpg(target.pid, signal.SIGKILL)
        target.wait(timeout=10)
        env.pop("ROOTYARD_MAX_REPO_BYTES")
        target = subprocess.Popen([args.binary, "serve"], env=env, stdout=target_log, stderr=target_log, start_new_session=True)
        until = time.monotonic() + 30
        while time.monotonic() < until:
            if target.poll() is not None:
                raise AssertionError("target storage process exited on resume")
            try:
                if request(node1, "/health/ready", h.alice)[0] == 200:
                    break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(.1)
        else:
            raise AssertionError("target storage resume readiness timeout")
        dest_repo = node1_data / "repos" / (h.repo["id"] + ".git")
        dest_repo.mkdir()
        sentinel = dest_repo / "existing-target-sentinel"
        sentinel.write_bytes(b"preserve old target on rejected transfer\n")
        journal_dir = node1_data / "journal" / h.repo["id"]
        journal_dir.mkdir(parents=True)
        sequence = journal_dir / "sequence"
        sequence.write_text("999999")
        h.expect("/api/repos/alice/demo/shard-migrate", 409, token=h.alice, method="POST",
                 body={"target_node_id": "node1", "expected_route_epoch": route["route_epoch"], "operation_id": operation_id})
        assert sentinel.read_bytes() == b"preserve old target on rejected transfer\n"
        unchanged = json.loads(h.expect("/api/repos/alice/demo/shard-route", 200, token=h.alice))
        assert unchanged["primary_node_id"] == "shard-primary-0"
        sequence.unlink()
        started = time.monotonic_ns()
        receipt = json.loads(h.expect("/api/repos/alice/demo/shard-migrate", 200, token=h.alice,
                                      method="POST", body={"target_node_id": "node1", "expected_route_epoch": route["route_epoch"], "operation_id": operation_id}))
        duration_ms = round((time.monotonic_ns() - started) / 1e6, 3)
        assert receipt["state"] == "completed" and receipt["target_node_id"] == "node1" and receipt["operation_id"] == operation_id
        new_route = json.loads(h.expect("/api/repos/alice/demo/shard-route", 200, token=h.alice))
        assert new_route["primary_node_id"] == "node1" and new_route["route_epoch"] > route["route_epoch"]
        assert dest_repo.is_dir() and dest_repo.resolve() != h.bare.resolve()
        h.git("--git-dir=" + str(dest_repo), "fsck", "--full", "--strict")
        initial = h.git("--git-dir=" + str(dest_repo), "rev-parse", "refs/heads/main").stdout.decode().strip()
        assert initial == h.second
        (h.work / "hello.txt").write_text("commit after migration\n")
        h.git("commit", "-am", "post migration", cwd=h.work)
        final_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", node1 + h.repo["clone_path"], "HEAD:main", cwd=h.work, token=h.alice)
        h.git("fetch", node1 + h.repo["clone_path"], "refs/heads/main", cwd=h.copy, token=h.reader)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == final_tip
        assert h.git("--git-dir=" + str(dest_repo), "rev-parse", "refs/heads/main").stdout.decode().strip() == final_tip
        assert h.git("--git-dir=" + str(h.bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == initial
        print(json.dumps({"result": "passed", "operation_id": receipt["operation_id"], "transfer_ms": duration_ms,
                          "partial_copy_rejected_before_cutover": True, "same_operation_resumed_after_target_restart": True,
                          "ahead_journal_rejected_without_replacing_target": True,
                          "source_oid": initial, "destination_oid_after_push": final_tip,
                          "source_volume": str(h.bare), "destination_volume": str(dest_repo)}))
    finally:
        if target and target.poll() is None:
            os.killpg(target.pid, signal.SIGKILL)
            target.wait(timeout=10)
        if target_log:
            target_log.close()
        h.cleanup()


if __name__ == "__main__":
    main()
