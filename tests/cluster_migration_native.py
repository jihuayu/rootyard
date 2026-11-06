#!/usr/bin/env python3
"""Exercise verified Git bundle migration between disjoint Rust storage processes."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.error
from urllib.parse import unquote, urlsplit
import uuid

from e2e import Harness
from cluster_workload_native import free_port, request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    h = Harness(args)
    h.env["ROOTYARD_NODE_ID"] = "shard-primary-0"
    h.env["ROOTYARD_CLUSTER_HMAC_KEY"] = base64.b64encode(os.urandom(32)).decode()
    target = None
    target_log = None
    held_reader = None
    try:
        h.setup()
        h.sql("INSERT INTO cluster_operator_tokens(token_id, granted_by) VALUES ('" + h.alice["token_id"] + "', 'native-migration')")
        node0 = h.base
        status, _ = request(node0, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "shard-primary-0", "endpoint": node0, "role": "primary", "status": "healthy"})
        assert status in (200, 201), status
        h.api()
        h.roundtrip()
        second_repo = json.loads(h.expect("/api/repos", 201, method="POST", token=h.alice,
                                          body={"name": "independent"}))
        source_sequence_file = h.root / "data" / "journal" / h.repo["id"] / "sequence"
        initial_sequence = int(source_sequence_file.read_text())
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
        second_route = json.loads(h.expect("/api/repos/alice/independent/shard-route", 200, token=h.alice))
        assert second_route["primary_node_id"] == route["primary_node_id"]
        assert second_route["route_epoch"] == route["route_epoch"]
        first_generation = h.sql("SELECT storage_generation FROM repositories WHERE id='" + h.repo["id"] + "'")
        second_generation = h.sql("SELECT storage_generation FROM repositories WHERE id='" + second_repo["id"] + "'")
        assert first_generation == second_generation, "collision fixture must match source generation"
        h.expect("/api/repos/alice/independent/shard-migrate", 409, token=h.alice, method="POST",
                 body={"target_node_id": "node1", "expected_route_epoch": second_route["route_epoch"],
                       "operation_id": operation_id})
        second_unchanged = json.loads(h.expect("/api/repos/alice/independent/shard-route", 200, token=h.alice))
        assert second_unchanged["draining"] is False, "foreign operation UUID drained another repository"
        assert h.sql("SELECT COUNT(*) FROM shard_replication_operations WHERE repository_id='" + second_repo["id"] + "'") == "0"
        assert int(source_sequence_file.read_text()) == initial_sequence, "partial transfer wrote source journal"
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
        assert int(source_sequence_file.read_text()) == initial_sequence, "ahead target transfer wrote source journal"
        assert sentinel.read_bytes() == b"preserve old target on rejected transfer\n"
        unchanged = json.loads(h.expect("/api/repos/alice/demo/shard-route", 200, token=h.alice))
        assert unchanged["primary_node_id"] == "shard-primary-0"
        sequence.unlink()
        journal_dir.rmdir()
        assert unchanged["draining"] is True, "failed transfer released its durable write drain"
        advert_status, advert_body = request(node0, h.repo["clone_path"] +
                                              "/info/refs?service=git-receive-pack", h.alice)
        assert advert_status == 409, ("drained source advertised receive-pack", advert_status, advert_body[:150])
        journal_before = int((h.root / "data" / "journal" / h.repo["id"] / "sequence").read_text())
        (h.work / "hello.txt").write_text("commit held until safe cutover\n")
        h.git("commit", "-am", "blocked by migration drain", cwd=h.work)
        blocked_push = h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice, check=False)
        assert blocked_push.returncode != 0, "source accepted a write during failed migration drain"
        journal_after = int((h.root / "data" / "journal" / h.repo["id"] / "sequence").read_text())
        assert journal_after == journal_before, ("drained push allocated journal operation", journal_before,
                                                 journal_after, blocked_push.stderr.decode(errors="replace")[-250:])
        repo_state = h.sql("SELECT state || ':' || COALESCE(recovery_reason,'') FROM repositories WHERE id='" + h.repo["id"] + "'")
        assert repo_state == "ready:", "failed drained push poisoned repository state: " + repo_state
        assert h.git("--git-dir=" + str(h.bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == h.second
        # Pause the real target process so source can finish its exclusive
        # drain/snapshot and release that lease. Then acquire a native PG
        # reader before resuming the target. The target's exclusive install
        # must wait while that independent reader holds the data barrier.
        hold_env = h.env.copy()
        db_url = urlsplit(h.db)
        hold_env.update(PGHOST=db_url.hostname, PGPORT=str(db_url.port or 5432),
                        PGUSER=unquote(db_url.username or "agent"),
                        PGDATABASE=db_url.path.lstrip("/") or "postgres",
                        PGAPPNAME="rootyard-migration-held-reader")
        if db_url.password:
            hold_env["PGPASSWORD"] = unquote(db_url.password)
        lock_sql = ("BEGIN; SELECT pg_advisory_xact_lock_shared(hashtextextended("
                    "'rootyard-data-v1:' || '" + h.repo["id"] + "'::uuid::text,0)); "
                    "SELECT pg_sleep(4); COMMIT;")
        source_bundle = h.root / "data" / "shard-staging" / (operation_id + ".bundle")
        if source_bundle.exists():
            source_bundle.unlink()
        os.killpg(target.pid, signal.SIGSTOP)
        started = time.monotonic_ns()
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(h.http, "/api/repos/alice/demo/shard-migrate", token=h.alice,
                                  method="POST", body={"target_node_id": "node1", "expected_route_epoch": route["route_epoch"], "operation_id": operation_id})
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not source_bundle.exists():
                assert not pending.done(), "migration failed before source bundle"
                time.sleep(.02)
            assert source_bundle.exists(), "source did not start a real Git bundle"
            held_reader = subprocess.Popen(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-c", lock_sql],
                                           env=hold_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if held_reader.poll() is not None:
                    _, error = held_reader.communicate()
                    raise AssertionError("native PG shared lock command failed: " + error.decode(errors="replace")[-300:])
                acquired = h.sql("SELECT COUNT(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid "
                                 "WHERE a.application_name='rootyard-migration-held-reader' AND l.locktype='advisory' "
                                 "AND l.mode='ShareLock' AND l.granted")
                if acquired == "1":
                    break
                time.sleep(.02)
            else:
                raise AssertionError("native reader failed to acquire PostgreSQL shared object lease")
            os.killpg(target.pid, signal.SIGCONT)
            time.sleep(.6)
            assert not pending.done(), "migration bypassed held PostgreSQL reader"
            assert sentinel.is_file(), "target path replaced before exclusive data barrier"
            held_output, held_error = held_reader.communicate(timeout=10)
            assert held_reader.returncode == 0, held_error.decode(errors="replace")[-300:]
            held_reader = None
            status, raw, _ = pending.result(timeout=20)
        assert status == 200, (status, raw[:300],
                               str(h.root), initial_sequence,
                               sorted(path.name for path in source_sequence_file.parent.iterdir()),
                               h.sql("SELECT state || ':' || COALESCE(recovery_reason,'') FROM repositories WHERE id='" + h.repo["id"] + "'"),
                               h.sql("SELECT outcome || ':' || COUNT(*) FROM git_operations WHERE repository_id='" + h.repo["id"] + "' GROUP BY outcome"))
        receipt = json.loads(raw)
        duration_ms = round((time.monotonic_ns() - started) / 1e6, 3)
        assert duration_ms >= 1000, "migration did not wait on native PostgreSQL reader"
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
        routed_refs = json.loads(h.expect("/api/repos/alice/demo/refs", 200, token=h.reader))
        assert routed_refs["head"]["oid"] == final_tip, "retired source served stale browse refs"
        routed_blob = json.loads(h.expect("/api/repos/alice/demo/blob?oid=" + final_tip +
                                          "&path=hello.txt", 200, token=h.reader))
        assert routed_blob["content"] == "commit after migration\n"
        h.expect("/api/repos/alice/demo/refs", (403, 404), token=h.bob)
        assert h.git("--git-dir=" + str(dest_repo), "rev-parse", "refs/heads/main").stdout.decode().strip() == final_tip
        assert h.git("--git-dir=" + str(h.bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == initial
        retired = json.loads((h.bare / "rootyard-shard-fence.json").read_text())
        assert retired["primary_node_id"] == "shard-primary-0" and retired["read_only_degraded"] is True
        assert retired["route_epoch"] == new_route["route_epoch"]
        report = {"kind": "native_cluster_staged_migration", "result": "passed",
                          "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                          "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                          "postgres_version": h.sql("SHOW server_version"),
                          "operation_id": receipt["operation_id"], "transfer_ms": duration_ms,
                          "partial_copy_rejected_before_cutover": True, "same_operation_resumed_after_target_restart": True,
                          "ahead_journal_rejected_without_replacing_target": True,
                          "failed_transfer_drained_source_writes": True,
                          "target_exclusive_barrier_waited_for_native_reader": True,
                          "target_process_paused_until_source_barrier_released": True,
                          "foreign_repository_operation_uuid_rejected_without_drain": True,
                          "browse_read_from_retired_ingress_reached_new_owner": True,
                          "source_oid": initial, "destination_oid_after_push": final_tip,
                          "source_volume": str(h.bare), "destination_volume": str(dest_repo),
                          "limits": ["one PostgreSQL authority, two Rust processes on one Linux host",
                                     "physical cross-host fencing remains external"]}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    finally:
        if held_reader and held_reader.poll() is None:
            held_reader.kill()
            held_reader.communicate(timeout=5)
        if target and target.poll() is None:
            os.killpg(target.pid, signal.SIGKILL)
            target.wait(timeout=10)
        if target_log:
            target_log.close()
        h.cleanup()


if __name__ == "__main__":
    main()
