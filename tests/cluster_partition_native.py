#!/usr/bin/env python3
"""Cut the old writer's actual PostgreSQL TCP path and verify fenced takeover."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.error
from urllib.parse import urlsplit, urlunsplit

from e2e import Harness
from cluster_workload_native import free_port, request


class TcpPartition:
    def __init__(self, target_host, target_port):
        self.target = target_host, target_port
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.closed = threading.Event()
        self.connections = []
        self.threads = []
        self.acceptor = threading.Thread(target=self.accept, daemon=True)
        self.acceptor.start()

    def accept(self):
        while not self.closed.is_set():
            try:
                left, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                right = socket.create_connection(self.target, timeout=2)
            except OSError:
                left.close()
                continue
            self.connections.extend((left, right))
            task = threading.Thread(target=self.pump, args=(left, right), daemon=True)
            self.threads.append(task)
            task.start()

    def pump(self, left, right):
        try:
            while not self.closed.is_set():
                ready, _, _ = select.select([left, right], [], [], .2)
                for src in ready:
                    dst = right if src is left else left
                    data = src.recv(128 * 1024)
                    if not data:
                        return
                    dst.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (left, right):
                try:
                    sock.close()
                except OSError:
                    pass

    def cut(self):
        self.closed.set()
        self.listener.close()
        for sock in self.connections:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        self.acceptor.join(timeout=2)


def ready(base, token, proc):
    until = time.monotonic() + 30
    while time.monotonic() < until:
        if proc.poll() is not None:
            raise AssertionError("target process exited")
        try:
            if request(base, "/health/ready", token)[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.1)
    raise AssertionError("target readiness timeout")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    h = Harness(args)
    fence_dir = h.root / "fences"
    fence_dir.mkdir(mode=0o700)
    direct = urlsplit(h.db)
    proxy = TcpPartition(direct.hostname, direct.port)
    userinfo = direct.netloc.rsplit("@", 1)[0] + "@" if "@" in direct.netloc else ""
    proxy_url = urlunsplit(direct._replace(netloc=f"{userinfo}127.0.0.1:{proxy.port}"))
    h.env.update(DATABASE_URL=proxy_url, ROOTYARD_NODE_ID="shard-primary-0",
                 ROOTYARD_LOCAL_FENCE_DIR=str(fence_dir), ROOTYARD_CLUSTER_HMAC_KEY=base64.b64encode(os.urandom(32)).decode())
    target = None
    target_log = None
    try:
        h.setup()
        h.sql("INSERT INTO cluster_operator_tokens(token_id,granted_by) VALUES ('" + h.alice["token_id"] + "','native-partition')")
        status, _ = request(h.base, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "shard-primary-0", "endpoint": h.base, "role": "primary", "status": "healthy", "lease_ttl_seconds": 2})
        assert status in (200, 201), status
        h.api()
        h.roundtrip()
        ack = h.second
        target_port = free_port()
        target_base = f"http://127.0.0.1:{target_port}"
        target_data = h.root / "target-volume"
        env = h.env.copy()
        env.update(DATABASE_URL=h.db, ROOTYARD_NODE_ID="node1", ROOTYARD_BIND=f"127.0.0.1:{target_port}",
                   ROOTYARD_DATA_DIR=str(target_data), ROOTYARD_OUTBOX_WORKER="false")
        target_log = open(h.root / "target.log", "ab")
        target = subprocess.Popen([args.binary, "serve"], env=env, stdout=target_log,
                                  stderr=target_log, start_new_session=True)
        ready(target_base, h.alice, target)
        status, _ = request(h.base, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "node1", "endpoint": target_base, "role": "replica", "status": "healthy", "lease_ttl_seconds": 2})
        assert status in (200, 201), status
        route_path = "/api/repos/alice/demo/shard-route"
        route = json.loads(h.expect(route_path, 200, token=h.alice))
        replicated = json.loads(h.expect("/api/repos/alice/demo/shard-migrate", 200, token=h.alice,
                                      method="POST", body={"target_node_id": "node1", "replicate_only": True,
                                                           "expected_route_epoch": route["route_epoch"]}))
        assert replicated["state"] == "verified"
        target_repo = target_data / "repos" / (h.repo["id"] + ".git")
        assert h.git("--git-dir=" + str(target_repo), "rev-parse", "refs/heads/main").stdout.decode().strip() == ack
        old_pid = h.proc.pid
        cut_at = time.monotonic_ns()
        proxy.cut()
        try:
            source_status, _ = request(h.base, "/api/repos/alice/demo", h.alice)
        except (OSError, urllib.error.URLError):
            source_status = 0
        assert source_status == 0 or source_status >= 500, "isolated writer kept serving authoritative metadata"
        until = time.monotonic() + 20
        promoted = None
        while time.monotonic() < until:
            status, raw = request(target_base, route_path, h.alice)
            if status == 200 and json.loads(raw)["primary_node_id"] == "node1":
                promoted = json.loads(raw)
                break
            time.sleep(.1)
        assert promoted, "partitioned old writer was not physically fenced and replaced"
        takeover_ms = round((time.monotonic_ns() - cut_at) / 1e6, 3)
        assert h.proc.wait(timeout=5) == -signal.SIGKILL
        assert (fence_dir / "shard-primary-0.blocked").is_file()
        h.git("fetch", target_base + h.repo["clone_path"], "refs/heads/main", cwd=h.copy, token=h.reader)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == ack
        (h.work / "hello.txt").write_text("write after source DB partition\n")
        h.git("commit", "-am", "post partition takeover", cwd=h.work)
        new_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        auth = base64.b64encode((h.alice["username"] + ":" + h.alice["token"]).encode()).decode()
        push = subprocess.Popen(["git", "-c", "http.extraHeader=Authorization: Basic " + auth,
                                 "push", target_base + h.repo["clone_path"], "HEAD:main"],
                                cwd=h.work, env=h.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            _, push_error = push.communicate(timeout=18)
        except subprocess.TimeoutExpired:
            os.killpg(push.pid, signal.SIGKILL)
            push.wait(timeout=5)
            activity = h.sql("SELECT application_name||':'||coalesce(state,'')||':'||coalesce(wait_event_type,'')||':'||coalesce(wait_event,'') FROM pg_stat_activity WHERE datname=current_database()")
            pending = h.sql("SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id='" + h.repo["id"] + "' AND state='pending'")
            raise AssertionError("post-partition target push timed out; PG activity=" + activity + "; pending=" + pending) from None
        assert push.returncode == 0, h.redact(push_error.decode(errors="replace")[-500:])
        assert h.git("--git-dir=" + str(target_repo), "rev-parse", "refs/heads/main").stdout.decode().strip() == new_tip
        assert h.git("--git-dir=" + str(h.bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == ack
        report = {"kind": "native_tcp_partition_takeover", "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                  "fault": "closed source-only PostgreSQL TCP proxy and all its live sockets",
                  "source_metadata_status_after_partition": source_status,
                  "old_source_session_killed": True, "durable_restart_block": True,
                  "acknowledged_oid_before_partition": ack, "rpo_lost_acknowledged_commits": 0,
                  "takeover_ms": takeover_ms, "new_route_epoch": promoted["route_epoch"],
                  "post_takeover_oid": new_tip,
                  "limits": ["single-host TCP isolation; no kernel network namespace partition", "local process-session fence only"]}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "passed", "report": str(args.report), "takeover_ms": takeover_ms}))
    finally:
        proxy.cut()
        if target and target.poll() is None:
            os.killpg(target.pid, signal.SIGKILL)
            target.wait(timeout=10)
        if target_log:
            target_log.close()
        h.cleanup()


if __name__ == "__main__":
    main()
