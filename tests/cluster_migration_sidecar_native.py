#!/usr/bin/env python3
"""Native migrated CI-pin sidecar handoff and bounded crash matrix.

This script creates its own disposable PostgreSQL database before starting any
service. It exercises real SIGKILL at deterministic durable boundaries for the
target receive/verify stages, the source final drain/delta, the cutover commit,
and startup recovery. Stock Git push/fetch/fsck verify acknowledged commits,
retained CI/backup roots and a single writable primary. A fresh checkout plan is
issued on the new primary; old cancelled/released grants stay tombstones and an
old-generation pin is never rebound by the sidecar copy.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.error
from urllib.parse import urlsplit, urlunsplit
import uuid

from e2e import Harness
from cluster_workload_native import free_port, request


def admin_psql(url, statement):
    env = os.environ.copy()
    result = subprocess.run(["psql", url, "-X", "-v", "ON_ERROR_STOP=1", "-c", statement],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace")[-800:])


def disposable_database(admin_url):
    name = "rootyard_migration_sidecar_" + uuid.uuid4().hex
    admin_psql(admin_url, 'CREATE DATABASE "' + name + '" TEMPLATE template0')
    parts = urlsplit(admin_url)
    return name, urlunsplit(parts._replace(path="/" + name))


class MigrationHarness(Harness):
    pass


def wait_ready(url, token, process=None, timeout=30):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if process is not None and process.poll() is not None:
            raise AssertionError("service exited before readiness")
        try:
            if request(url, "/health/ready", token)[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.05)
    raise AssertionError("service readiness timeout")


def start_target(h, args, node_url, data, extra=None, log=None):
    env = h.env.copy()
    env.update(
        ROOTYARD_NODE_ID="node1",
        ROOTYARD_BIND=node_url.rsplit("//", 1)[1],
        ROOTYARD_DATA_DIR=str(data),
        ROOTYARD_OUTBOX_WORKER="false",
        ROOTYARD_TEST_FAULT_ALLOW="1",
    )
    env.update(extra or {})
    log = log or open(data.parent / "node1.log", "ab")
    process = subprocess.Popen([args.binary, "serve"], env=env, stdout=log,
                               stderr=log, start_new_session=True)
    wait_ready(node_url, h.alice, process)
    return process


def kill(process):
    if process and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def marker(data, phase):
    path = data / ".native-test-faults" / (phase + ".json")
    until = time.monotonic() + 20
    while time.monotonic() < until:
        if path.is_file():
            return json.loads(path.read_text())
        time.sleep(.02)
    raise AssertionError("fault marker did not persist: " + phase)


def wait_marker_or_response(data, phase, pending, h, timeout=20):
    path = data / ".native-test-faults" / (phase + ".json")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return json.loads(path.read_text())
        if pending.done():
            try:
                result = pending.result()
            except Exception as error:  # noqa: BLE001 - sanitized diagnostic
                raise AssertionError(
                    "migration request failed before fault phase " + phase + ": "
                    + h.redact(repr(error))) from error
            status, raw = result[0], result[1]
            raise AssertionError(
                "migration request completed before fault phase " + phase
                + ": status=" + str(status) + " body=" + h.redact(raw[:500].decode(errors="replace")))
        time.sleep(.02)
    raise AssertionError("fault marker did not persist (request still pending): " + phase)


def clear_marker(data, phase):
    path = data / ".native-test-faults" / (phase + ".json")
    if path.exists():
        path.unlink()


def assert_marker_binding(marker_data, phase, repo_id, operation_id=None):
    detail = marker_data.get("detail") or {}
    assert detail.get("repository_id") == repo_id, \
        ("fault marker belongs to another repository", phase, detail, repo_id)
    if detail.get("operation_id") is not None:
        assert detail.get("operation_id") == operation_id, \
            ("fault marker belongs to another operation", phase, detail, operation_id)


def create_repository(h, name):
    status, raw, _ = h.http("/api/repos", token=h.alice, method="POST",
                            body={"name": name})
    assert status in (201, 202), (status, raw[:300])
    repo = json.loads(raw)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status, raw, _ = h.http("/api/repos/alice/" + name, token=h.alice)
        assert status == 200, (status, raw[:300])
        repo = json.loads(raw)
        if repo["state"] == "ready":
            return repo
        time.sleep(.05)
    raise AssertionError("repository provisioning did not become ready: " + name)


def create_repo(h, name):
    repo = create_repository(h, name)
    work = h.root / ("work-" + name)
    remote = h.base + repo["clone_path"]
    h.git("clone", remote, str(work), token=h.alice)
    h.git("config", "user.name", "Native", cwd=work)
    h.git("config", "user.email", "native@example.invalid", cwd=work)
    (work / "state.txt").write_text("acknowledged before migration\n")
    h.git("add", "state.txt", cwd=work)
    h.git("commit", "-m", "initial", cwd=work)
    tip = h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    h.git("push", "origin", "HEAD:main", cwd=work, token=h.alice)
    return repo, work, remote, tip


def push_commit(h, work, text):
    (work / "state.txt").write_text(text)
    h.git("add", "state.txt", cwd=work)
    h.git("commit", "-m", text.strip(), cwd=work)
    tip = h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    h.git("push", "origin", "HEAD:main", cwd=work, token=h.alice)
    return tip


def commit_only(h, work, text):
    (work / "state.txt").write_text(text)
    h.git("add", "state.txt", cwd=work)
    h.git("commit", "-m", text.strip(), cwd=work)
    return h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()


def fenced_source_push(h, source_url, old_bare, target_url, target_bare,
                       work, clone_path, text):
    tip = commit_only(h, work, text)
    old_before = h.git("--git-dir=" + str(old_bare), "rev-parse",
                       "refs/heads/main").stdout.decode().strip()
    result = h.git("push", source_url + clone_path, "HEAD:main", cwd=work,
                   token=h.alice, check=False)
    old_after = h.git("--git-dir=" + str(old_bare), "rev-parse",
                      "refs/heads/main").stdout.decode().strip()
    assert old_after == old_before, "retired source native volume changed"
    proxied = result.returncode == 0
    if not proxied:
        h.git("push", target_url + clone_path, "HEAD:main", cwd=work,
              token=h.alice, check=True)
    target_tip = h.git("--git-dir=" + str(target_bare), "rev-parse",
                       "refs/heads/main").stdout.decode().strip()
    assert target_tip == tip, "new owner did not hold the fresh acknowledged commit"
    git_ok(h, target_bare)
    return tip, proxied


def pin(h, name, job, oid, generation):
    return json.loads(h.expect("/api/repos/alice/" + name + "/ci-pins", 200,
                               token=h.alice, method="POST",
                               body={"job_id": job, "target_oid": oid,
                                     "storage_generation": generation}))


def pin_at(h, url, name, job, oid, generation):
    status, raw = request(url, "/api/repos/alice/" + name + "/ci-pins", h.alice,
                          "POST", {"job_id": job, "target_oid": oid,
                                   "storage_generation": generation})
    assert status in (200, 201), (status, raw[:400])
    return json.loads(raw)


def refresh_lease(h, node_id):
    status, raw, _ = h.http("/api/shards/nodes/" + node_id + "/lease",
                            token=h.alice, method="POST",
                            body={"lease_ttl_seconds": 120, "bump_epoch": False})
    assert status == 200, (status, raw[:200])


def issue_checkout(h, url, name, job, oid, generation, audience, token=None):
    return request(url, "/api/repos/alice/" + name + "/ci-checkouts", token or h.alice,
                   "POST", {"job_id": job, "target_oid": oid,
                            "storage_generation": generation,
                            "mirror_audience": audience,
                            "expires_unix": int(time.time()) + 1800})


def migrate(h, name, body, expect=200):
    status, raw, _ = h.http("/api/repos/alice/" + name + "/shard-migrate",
                            token=h.alice, method="POST", body=body)
    assert status == expect, (status, raw[:400])
    return json.loads(raw) if status == 200 else raw


def git_ok(h, bare):
    h.git("--git-dir=" + str(bare), "fsck", "--full", "--strict")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    admin_url = os.environ.get("ROOTYARD_TEST_DATABASE_URL")
    if not admin_url:
        raise SystemExit("ROOTYARD_TEST_DATABASE_URL must point at a disposable admin database")
    database, database_url = disposable_database(admin_url)
    os.environ["ROOTYARD_TEST_DATABASE_URL"] = database_url
    audience = str(uuid.uuid4())
    h = MigrationHarness(args)
    h.env["ROOTYARD_NODE_ID"] = "shard-primary-0"
    h.env["ROOTYARD_CLUSTER_HMAC_KEY"] = base64.b64encode(os.urandom(32)).decode()
    h.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = audience
    h.env["ROOTYARD_TEST_FAULT_ALLOW"] = "1"
    target = None
    target_log = None
    try:
        h.setup()
        h.sql("INSERT INTO cluster_operator_tokens(token_id, granted_by) VALUES ('"
              + h.alice["token_id"] + "', 'native-migration-sidecar')")
        node0 = h.base
        status, _ = request(node0, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "shard-primary-0", "endpoint": node0, "role": "primary",
            "status": "healthy", "lease_ttl_seconds": 120})
        assert status in (200, 201), status
        h.api()
        h.roundtrip()

        demo_generation = int(h.sql("SELECT storage_generation FROM repositories WHERE id='"
                                    + h.repo["id"] + "'"))
        job_keep = str(uuid.uuid4())
        job_cancelled = str(uuid.uuid4())
        job_released = str(uuid.uuid4())
        pin(h, "demo", job_keep, h.second, demo_generation)
        pin(h, "demo", job_cancelled, h.first, demo_generation)
        issued = issue_checkout(h, node0, "demo", job_cancelled, h.first,
                                demo_generation, audience)
        assert issued[0] in (200, 201), issued
        old_plan = json.loads(issued[1])["plan"]
        assert old_plan["storage_generation"] == demo_generation
        h.expect("/api/repos/alice/demo/ci-checkouts/" + job_cancelled + "/cancel",
                 200, token=h.alice, method="POST", body=b"")
        pin(h, "demo", job_released, h.second, demo_generation)
        h.expect("/api/repos/alice/demo/ci-pins/" + job_released, 200,
                 token=h.alice, method="DELETE", body=b"")
        for root in ("refs/rootyard-snapshots/backup-1",
                     "refs/rootyard-backup/snapshot-1"):
            h.git("--git-dir=" + str(h.bare), "update-ref", root, h.second)

        # Create freshrace while node0 is still the only primary so its route
        # defaults to the source. It has zero pre-existing CI roots.
        freshrace, freshrace_work, _, freshrace_tip = create_repo(h, "freshrace")
        freshrace_route = json.loads(h.expect(
            "/api/repos/alice/freshrace/shard-route", 200, token=h.alice))
        assert freshrace_route["primary_node_id"] == "shard-primary-0", freshrace_route
        freshrace_generation = int(h.sql(
            "SELECT storage_generation FROM repositories WHERE id='" + freshrace["id"] + "'"))
        chaos, chaos_work, chaos_remote, chaos_tip = create_repo(h, "chaosharness")
        chaos_route = json.loads(h.expect("/api/repos/alice/chaosharness/shard-route",
                                          200, token=h.alice))
        assert chaos_route["primary_node_id"] == "shard-primary-0", chaos_route
        recover, recover_work, _, recover_tip = create_repo(h, "recoverharness")
        recover_route = json.loads(h.expect("/api/repos/alice/recoverharness/shard-route",
                                            200, token=h.alice))
        assert recover_route["primary_node_id"] == "shard-primary-0", recover_route
        multihop, multihop_work, _, multihop_tip = create_repo(h, "multihop")
        multihop_route = json.loads(h.expect("/api/repos/alice/multihop/shard-route",
                                              200, token=h.alice))
        assert multihop_route["primary_node_id"] == "shard-primary-0", multihop_route
        multihop_job1 = str(uuid.uuid4())
        pin(h, "multihop", multihop_job1, multihop_tip, 1)

        port = free_port()
        node1 = "http://127.0.0.1:" + str(port)
        node1_data = h.root / "data-node1"
        target = start_target(h, args, node1, node1_data)
        target_log = open(node1_data.parent / "node1.log", "ab")
        status, _ = request(node0, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "node1", "endpoint": node1, "role": "replica",
            "status": "healthy", "lease_ttl_seconds": 120})
        assert status in (200, 201), status
        route = json.loads(h.expect("/api/repos/alice/demo/shard-route", 200,
                                    token=h.alice))
        assert route["primary_node_id"] == "shard-primary-0"

        # Sidecar fail-closed checks happen before any drain or operation row.
        intent_path = h.root / "data" / "ci-pins" / h.repo["id"] / (job_keep + ".json")
        original = intent_path.read_bytes()
        outside = h.root / "outside-pin.json"
        outside.write_bytes(original)
        intent_path.unlink()
        intent_path.symlink_to(outside)
        h.expect("/api/repos/alice/demo/shard-migrate", 409, token=h.alice,
                 method="POST", body={"target_node_id": "node1",
                                      "expected_route_epoch": route["route_epoch"],
                                      "operation_id": str(uuid.uuid4())})
        intent_path.unlink()
        intent_path.write_bytes(original)
        forged = json.loads(original)
        forged["owner_id"] = h.bob["user_id"]
        intent_path.write_bytes(json.dumps(forged).encode())
        h.expect("/api/repos/alice/demo/shard-migrate", 409, token=h.alice,
                 method="POST", body={"target_node_id": "node1",
                                      "expected_route_epoch": route["route_epoch"],
                                      "operation_id": str(uuid.uuid4())})
        intent_path.write_bytes(original)
        unchanged = json.loads(h.expect("/api/repos/alice/demo/shard-route", 200,
                                        token=h.alice))
        assert unchanged["draining"] is False and unchanged["primary_node_id"] == "shard-primary-0"
        assert h.sql("SELECT COUNT(*) FROM shard_replication_operations WHERE repository_id='"
                     + h.repo["id"] + "'") == "0"

        # Target dies after receiving the initial bundle and again after
        # installing/verifying it but before durable publication.
        op = str(uuid.uuid4())
        kill(target)
        target = start_target(h, args, node1, node1_data,
                              {"ROOTYARD_TEST_FAULT": "target-copy-after-receive",
                               "ROOTYARD_TEST_FAULT_ACTION": "kill"})
        fault_phase = None
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(h.http, "/api/repos/alice/demo/shard-migrate",
                                  token=h.alice, method="POST",
                                  body={"target_node_id": "node1",
                                        "expected_route_epoch": route["route_epoch"],
                                        "operation_id": op})
            wait_marker_or_response(node1_data, "target-copy-after-receive", pending, h)
            target.wait(timeout=20)
            assert target.returncode == -signal.SIGKILL
            try:
                pending.result(timeout=10)
            except Exception:
                pass
        fault_phase = "target-copy-after-receive"
        assert h.sql("SELECT state FROM shard_replication_operations WHERE id='" + op
                     + "'") == "copying"
        assert not (node1_data / "repos" / (h.repo["id"] + ".git")).exists()
        target_log.close()
        target_log = open(node1_data.parent / "node1.log", "ab")
        target = start_target(h, args, node1, node1_data,
                              {"ROOTYARD_TEST_FAULT": "target-verify-before-publish",
                               "ROOTYARD_TEST_FAULT_ACTION": "kill"},
                              log=target_log)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(h.http, "/api/repos/alice/demo/shard-migrate",
                                  token=h.alice, method="POST",
                                  body={"target_node_id": "node1",
                                        "expected_route_epoch": route["route_epoch"],
                                        "operation_id": op})
            wait_marker_or_response(node1_data, "target-verify-before-publish", pending, h)
            target.wait(timeout=20)
            assert target.returncode == -signal.SIGKILL
            try:
                pending.result(timeout=10)
            except Exception:
                pass
        assert h.sql("SELECT state FROM shard_replication_operations WHERE id='" + op
                     + "'") == "copying"
        assert json.loads(h.expect("/api/repos/alice/demo/shard-route", 200,
                                   token=h.alice))["primary_node_id"] == "shard-primary-0"

        # Resume the same operation to completion against a fresh target
        # process. A real write after the measured standby snapshot must be
        # carried by the final delta before cutover.
        target_log.close()
        target_log = open(node1_data.parent / "node1.log", "ab")
        h.stop(hard=True)
        h.env["ROOTYARD_TEST_FAULT"] = "cutover-before-sidecar-finalize"
        h.env["ROOTYARD_TEST_FAULT_ACTION"] = "pause"
        h.env["ROOTYARD_TEST_FAULT_PAUSE_MS"] = "4000"
        h.start()
        h.env.pop("ROOTYARD_TEST_FAULT_ACTION", None)
        h.env.pop("ROOTYARD_TEST_FAULT_PAUSE_MS", None)
        stale_marker = node1_data / ".native-test-faults" / "target-sidecar-before-publish.json"
        if stale_marker.exists():
            stale_marker.unlink()
        target = start_target(h, args, node1, node1_data,
                              {"ROOTYARD_TEST_FAULT": "target-sidecar-before-publish",
                               "ROOTYARD_TEST_FAULT_ACTION": "pause",
                               "ROOTYARD_TEST_FAULT_PAUSE_MS": "6000"},
                              log=target_log)
        acknowledged = [h.second]
        acknowledged.append(push_commit(h, h.work, "acknowledged while target restarts\n"))
        concurrent_job = str(uuid.uuid4())
        concurrent_oid = acknowledged[-1]
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(h.http, "/api/repos/alice/demo/shard-migrate",
                                  token=h.alice, method="POST",
                                  body={"target_node_id": "node1",
                                        "expected_route_epoch": route["route_epoch"],
                                        "operation_id": op})
            wait_marker_or_response(h.root / "data", "cutover-before-sidecar-finalize",
                                    pending, h)
            merged_job = str(uuid.uuid4())
            merged_status, merged_raw = request(
                node1, "/api/repos/alice/demo/ci-pins", h.alice, "POST",
                {"job_id": merged_job, "target_oid": concurrent_oid,
                 "storage_generation": demo_generation + 1})
            assert merged_status == 503, (merged_status, merged_raw[:300])
            wait_marker_or_response(node1_data, "target-sidecar-before-publish", pending, h)
            pin_status, pin_raw = request(
                node1, "/api/repos/alice/demo/ci-pins", h.alice, "POST",
                {"job_id": concurrent_job, "target_oid": concurrent_oid,
                 "storage_generation": demo_generation + 1})
            assert pin_status in (200, 201, 409, 503), (pin_status, pin_raw[:300])
            status, raw, _ = pending.result(timeout=40)
        assert status == 200, (status, raw[:500])
        if pin_status not in (200, 201):
            pin_status, pin_raw = request(
                node1, "/api/repos/alice/demo/ci-pins", h.alice, "POST",
                {"job_id": concurrent_job, "target_oid": concurrent_oid,
                 "storage_generation": demo_generation + 1})
            assert pin_status in (200, 201), (pin_status, pin_raw[:300])
        concurrent_sidecar = node1_data / "ci-pins" / h.repo["id"] / (concurrent_job + ".json")
        assert concurrent_sidecar.is_file(), "accepted post-cutover pin was lost by finalization"
        assert (concurrent_sidecar.parent / (concurrent_job + ".pinned.json")).is_file()
        dest_repo_id = node1_data / "repos" / (h.repo["id"] + ".git")
        assert h.git("--git-dir=" + str(dest_repo_id), "rev-parse",
                     "refs/rootyard-ci/jobs/" + concurrent_job
                     ).stdout.decode().strip() == concurrent_oid
        merged_retry, merged_retry_raw = request(
            node1, "/api/repos/alice/demo/ci-pins", h.alice, "POST",
            {"job_id": merged_job, "target_oid": concurrent_oid,
             "storage_generation": demo_generation + 1})
        assert merged_retry in (200, 201), (merged_retry, merged_retry_raw[:300])
        merged_sidecar = concurrent_sidecar.parent / (merged_job + ".json")
        assert merged_sidecar.is_file(), "pre-finalize bounded 503 retry was not honored"
        assert (merged_sidecar.parent / (merged_job + ".pinned.json")).is_file()
        assert h.git("--git-dir=" + str(dest_repo_id), "rev-parse",
                     "refs/rootyard-ci/jobs/" + merged_job
                     ).stdout.decode().strip() == concurrent_oid
        receipt = json.loads(raw)
        assert receipt["state"] == "completed" and receipt["target_node_id"] == "node1"
        dest = node1_data / "repos" / (h.repo["id"] + ".git")
        git_ok(h, dest)
        assert h.git("--git-dir=" + str(dest), "rev-parse", "refs/heads/main"
                     ).stdout.decode().strip() == acknowledged[-1]
        for root in ("refs/rootyard-ci/jobs/" + job_keep,
                     "refs/rootyard-ci/jobs/" + job_cancelled,
                     "refs/rootyard-snapshots/backup-1",
                     "refs/rootyard-backup/snapshot-1"):
            h.git("--git-dir=" + str(dest), "rev-parse", root)
        assert not h.git("--git-dir=" + str(dest), "rev-parse",
                         "refs/rootyard-ci/jobs/" + job_released, check=False
                         ).returncode == 0
        old_source = h.bare / "rootyard-shard-fence.json"
        assert json.loads(old_source.read_text())["read_only_degraded"] is True
        new_route = json.loads(h.expect("/api/repos/alice/demo/shard-route", 200,
                                        token=h.alice))
        assert new_route["primary_node_id"] == "node1"
        new_generation = int(h.sql("SELECT storage_generation FROM repositories WHERE id='"
                                   + h.repo["id"] + "'"))
        assert new_generation == demo_generation + 1
        sidecar_dir = node1_data / "ci-pins" / h.repo["id"]
        evidence = json.loads((sidecar_dir / (job_keep + ".json")).read_bytes())
        assert evidence["storage_generation"] == demo_generation
        assert not (sidecar_dir / (job_released + ".json")).exists()

        # Old plan/grant cannot be rebound or re-authorized by the copy.
        assert h.sql("SELECT cancelled::text FROM ci_checkout_jobs WHERE repository_id='"
                     + h.repo["id"] + "' AND job_id='" + job_cancelled + "'") == "true"
        status, _ = issue_checkout(h, node1, "demo", job_cancelled, h.first,
                                   new_generation, audience)
        assert status == 409, "cancelled checkout job was resurrected"
        status, _ = issue_checkout(h, node1, "demo", job_keep, h.second,
                                   new_generation, audience)
        assert status == 409, "old-generation pin was rebound by sidecar copy"
        status, _ = issue_checkout(h, node1, "demo", job_released, h.second,
                                   new_generation, audience)
        assert status == 409, "released pin was resurrected"
        status, concurrent_raw = issue_checkout(h, node1, "demo", concurrent_job,
                                                concurrent_oid, new_generation, audience)
        assert status in (200, 201), (status, concurrent_raw[:400])
        assert json.loads(concurrent_raw)["plan"]["target_oid"] == concurrent_oid
        # A fresh job/attempt/generation issues a fresh durable pin and plan.
        fresh_job = str(uuid.uuid4())
        pinned = pin_at(h, node1, "demo", fresh_job, acknowledged[-1], new_generation)
        assert pinned["state"] == "pinned"
        status, raw = issue_checkout(h, node1, "demo", fresh_job, acknowledged[-1],
                                     new_generation, audience)
        assert status in (200, 201), (status, raw[:400])
        fresh = json.loads(raw)
        plan = fresh["plan"]
        receipt_path = sidecar_dir / (fresh_job + ".pinned.json")
        assert plan["storage_generation"] == new_generation
        assert plan["target_oid"] == acknowledged[-1]
        assert plan["source_receipt_sha256"] == hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        h.git("fetch", node1 + h.repo["clone_path"], "refs/heads/main",
              cwd=h.copy, token=h.alice)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == acknowledged[-1]
        git_ok(h, dest)
        status, _ = request(node1, "/api/repos/alice/demo/shard-migrate/abort",
                            h.alice, "POST",
                            {"operation_id": op,
                             "expected_route_epoch": new_route["route_epoch"]})
        assert status == 409, "committed cutover was reopened by abort"
        fresh_tip, old_proxied = fenced_source_push(
            h, node0, h.bare, node1, dest, h.work, h.repo["clone_path"],
            "fresh acknowledged commit after cutover\n")
        acknowledged.append(fresh_tip)
        old_volume_unchanged = True

        kill(target)
        target_log.close()
        target_log = open(node1_data.parent / "node1.log", "ab")
        target = start_target(h, args, node1, node1_data, log=target_log)
        h.env.pop("ROOTYARD_TEST_FAULT", None)
        h.stop(hard=True)
        h.start()

        # A repository with zero pre-existing CI roots allows a fresh pin while
        # the committed cutover is paused before the first finalize RPC. The
        # empty source image has nothing to hand off, and finalize must merge
        # the accepted fresh pin instead of replacing the live directory.
        pause_marker = h.root / "data" / ".native-test-faults" / "cutover-before-sidecar-finalize.json"
        if pause_marker.exists():
            pause_marker.unlink()
        h.stop(hard=True)
        h.env["ROOTYARD_TEST_FAULT"] = "cutover-before-sidecar-finalize"
        h.env["ROOTYARD_TEST_FAULT_ACTION"] = "pause"
        h.env["ROOTYARD_TEST_FAULT_PAUSE_MS"] = "4000"
        h.start()
        freshrace_op = str(uuid.uuid4())
        freshrace_job = str(uuid.uuid4())
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(
                h.http, "/api/repos/alice/freshrace/shard-migrate",
                token=h.alice, method="POST",
                body={"target_node_id": "node1",
                      "expected_route_epoch": freshrace_route["route_epoch"],
                      "operation_id": freshrace_op})
            wait_marker_or_response(h.root / "data", "cutover-before-sidecar-finalize",
                                    pending, h)
            fresh_status, fresh_raw = request(
                node1, "/api/repos/alice/freshrace/ci-pins", h.alice, "POST",
                {"job_id": freshrace_job, "target_oid": freshrace_tip,
                 "storage_generation": freshrace_generation + 1})
            assert fresh_status in (200, 201), (fresh_status, fresh_raw[:300])
            status, raw, _ = pending.result(timeout=40)
        assert status == 200, (status, raw[:400])
        assert json.loads(raw)["state"] == "completed"
        h.env.pop("ROOTYARD_TEST_FAULT", None)
        h.env.pop("ROOTYARD_TEST_FAULT_ACTION", None)
        h.env.pop("ROOTYARD_TEST_FAULT_PAUSE_MS", None)
        h.stop(hard=True)
        h.start()
        freshrace_dest = node1_data / "repos" / (freshrace["id"] + ".git")
        freshrace_sidecar = node1_data / "ci-pins" / freshrace["id"] / (freshrace_job + ".json")
        assert freshrace_sidecar.is_file(), "zero-root fresh pin was lost by finalize"
        assert h.git("--git-dir=" + str(freshrace_dest), "rev-parse",
                     "refs/rootyard-ci/jobs/" + freshrace_job
                     ).stdout.decode().strip() == freshrace_tip
        git_ok(h, freshrace_dest)

        # Second repository: source SIGKILL at final drain, before cutover
        # commit, and immediately after the cutover commit. The old source is
        # non-writer from the true drain onwards; abort cannot reopen it.
        chaos_gen = int(h.sql("SELECT storage_generation FROM repositories WHERE id='"
                              + chaos["id"] + "'"))
        chaos_op = str(uuid.uuid4())
        chaos_dest = node1_data / "repos" / (chaos["id"] + ".git")
        acknowledged = [chaos_tip]

        def source_killed(phase, body, repo="chaosharness", repo_id=None, recover_phase=None):
            clear_marker(h.root / "data", phase)
            h.stop(hard=True)
            h.env["ROOTYARD_TEST_FAULT"] = phase
            h.env["ROOTYARD_TEST_FAULT_ACTION"] = "kill"
            h.start()
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(h.http, "/api/repos/alice/" + repo + "/shard-migrate",
                                      token=h.alice, method="POST", body=body)
                marker_data = wait_marker_or_response(h.root / "data", phase, pending, h)
                assert_marker_binding(marker_data, phase, repo_id,
                                      body.get("operation_id"))
                h.proc.wait(timeout=20)
                assert h.proc.returncode == -signal.SIGKILL
                try:
                    pending.result(timeout=10)
                except Exception:
                    pass
            h.env.pop("ROOTYARD_TEST_FAULT", None)
            h.env.pop("ROOTYARD_TEST_FAULT_ACTION", None)
            if recover_phase:
                clear_marker(h.root / "data", recover_phase)
                h.env["ROOTYARD_TEST_FAULT"] = recover_phase
                h.env["ROOTYARD_TEST_FAULT_ACTION"] = "pause"
                h.env["ROOTYARD_TEST_FAULT_PAUSE_MS"] = "1500"
                h.start()
                recovered = marker(h.root / "data", recover_phase)
                assert_marker_binding(recovered, recover_phase, repo_id,
                                      body.get("operation_id"))
                h.env.pop("ROOTYARD_TEST_FAULT", None)
                h.env.pop("ROOTYARD_TEST_FAULT_ACTION", None)
                h.env.pop("ROOTYARD_TEST_FAULT_PAUSE_MS", None)
            else:
                h.start()

        body = {"target_node_id": "node1",
                "expected_route_epoch": chaos_route["route_epoch"],
                "operation_id": chaos_op}
        source_killed("final-delta-before-transfer", body, repo="chaosharness", repo_id=chaos["id"])
        assert h.sql("SELECT draining::text FROM repository_shard_routes WHERE repository_id='"
                     + chaos["id"] + "'") == "true"
        source_killed("cutover-before-commit", body, repo="chaosharness", repo_id=chaos["id"])
        assert h.sql("SELECT draining::text FROM repository_shard_routes WHERE repository_id='"
                     + chaos["id"] + "'") == "true"
        kill(target)
        target_log.close()
        target_log = open(node1_data.parent / "node1.log", "ab")
        target = start_target(h, args, node1, node1_data, log=target_log)
        assert (node1_data / "shard-staging" / (chaos_op + ".sidecar")).is_dir(), \
            "verified staged sidecar was deleted by startup reconciliation"
        status, raw, _ = h.http("/api/repos/alice/chaosharness/shard-migrate",
                                token=h.alice, method="POST", body=body)
        assert status == 200, (status, raw[:400])
        assert json.loads(raw)["state"] == "completed"
        chaos_route2 = json.loads(h.expect("/api/repos/alice/chaosharness/shard-route",
                                           200, token=h.alice))
        assert chaos_route2["primary_node_id"] == "node1"
        git_ok(h, chaos_dest)
        assert h.git("--git-dir=" + str(chaos_dest), "rev-parse", "refs/heads/main"
                     ).stdout.decode().strip() == acknowledged[-1]
        chaos_old = h.root / "data" / "repos" / (chaos["id"] + ".git")
        chaos_fresh, chaos_proxied = fenced_source_push(
            h, node0, chaos_old, node1, chaos_dest, chaos_work,
            chaos["clone_path"], "fresh commit after chaos cutover\n")
        acknowledged.append(chaos_fresh)

        # A second migration back is not needed: exercise the committed-cutover
        # recovery boundary on a third repository so the post-commit source
        # SIGKILL and target startup sidecar reconciliation are independent.
        recover_op = str(uuid.uuid4())
        recover_body = {"target_node_id": "node1",
                        "expected_route_epoch": recover_route["route_epoch"],
                        "operation_id": recover_op}
        source_killed("cutover-after-commit", recover_body, repo="recoverharness", repo_id=recover["id"], recover_phase="recover-before-reconcile")
        assert h.sql("SELECT state FROM shard_replication_operations WHERE id='"
                     + recover_op + "'") == "completed"
        # The target was never asked to finalize (source died in the marker
        # publish). Its startup reconcile republishes the staged sidecars.
        kill(target)
        target_log.close()
        target_log = open(node1_data.parent / "node1.log", "ab")
        target = start_target(h, args, node1, node1_data, log=target_log)
        recover_dest = node1_data / "repos" / (recover["id"] + ".git")
        git_ok(h, recover_dest)
        assert h.git("--git-dir=" + str(recover_dest), "rev-parse", "refs/heads/main"
                     ).stdout.decode().strip() == recover_tip
        assert (node1_data / "ci-pins" / recover["id"]).is_dir()
        recovered_marker = h.root / "data" / "repos" / (recover["id"] + ".git") / "rootyard-shard-fence.json"
        assert json.loads(recovered_marker.read_text())["read_only_degraded"] is True
        h.expect("/api/repos/alice/recoverharness/shard-migrate/abort", 409,
                 token=h.alice, method="POST",
                 body={"operation_id": recover_op,
                       "expected_route_epoch": recover_route["route_epoch"] + 1})
        recover_old = h.root / "data" / "repos" / (recover["id"] + ".git")
        _, recover_proxied = fenced_source_push(
            h, node0, recover_old, node1, recover_dest, recover_work,
            recover["clone_path"], "fresh commit after recovered cutover\n")

        # Two-hop real migration with retained CI evidence: gen1 pin, move
        # 0->1, fresh gen2 pin and write, move 1->0, then gen3 authorization.
        refresh_lease(h, "shard-primary-0")
        refresh_lease(h, "node1")
        multihop_op1 = str(uuid.uuid4())
        status, raw, _ = h.http("/api/repos/alice/multihop/shard-migrate", token=h.alice,
                                method="POST",
                                body={"target_node_id": "node1",
                                      "expected_route_epoch": multihop_route["route_epoch"],
                                      "operation_id": multihop_op1})
        assert status == 200, (status, raw[:400])
        assert json.loads(raw)["state"] == "completed"
        mid_route = json.loads(h.expect("/api/repos/alice/multihop/shard-route", 200,
                                        token=h.alice))
        assert mid_route["primary_node_id"] == "node1"
        assert int(h.sql("SELECT storage_generation FROM repositories WHERE id='"
                         + multihop["id"] + "'")) == 2
        (multihop_work / "state.txt").write_text("second generation write\n")
        h.git("commit", "-am", "second generation", cwd=multihop_work)
        multihop_tip2 = h.git("rev-parse", "HEAD", cwd=multihop_work).stdout.decode().strip()
        h.git("push", node1 + multihop["clone_path"], "HEAD:main",
              cwd=multihop_work, token=h.alice)
        multihop_job2 = str(uuid.uuid4())
        pin_at(h, node1, "multihop", multihop_job2, multihop_tip2, 2)
        assert (node1_data / "ci-pins" / multihop["id"] / (multihop_job1 + ".json")).is_file()
        stale_target = h.root / "data" / "repos" / (multihop["id"] + ".git")
        assert (h.git("--git-dir=" + str(stale_target), "rev-parse", "refs/heads/main"
                      ).stdout.decode().strip() == multihop_tip), \
            "old target volume bytes were incorrectly treated as current"
        refresh_lease(h, "shard-primary-0")
        refresh_lease(h, "node1")
        second_route = json.loads(h.expect("/api/repos/alice/multihop/shard-route", 200,
                                           token=h.alice))
        multihop_op2 = str(uuid.uuid4())
        status, raw = request(node1, "/api/repos/alice/multihop/shard-migrate", h.alice,
                              "POST", {"target_node_id": "shard-primary-0",
                                       "expected_route_epoch": second_route["route_epoch"],
                                       "operation_id": multihop_op2})
        assert status == 200, (status, raw[:500])
        assert json.loads(raw)["state"] == "completed"
        final_route = json.loads(h.expect("/api/repos/alice/multihop/shard-route", 200,
                                          token=h.alice))
        assert final_route["primary_node_id"] == "shard-primary-0"
        assert int(h.sql("SELECT storage_generation FROM repositories WHERE id='"
                         + multihop["id"] + "'")) == 3
        multihop_dest = h.root / "data" / "repos" / (multihop["id"] + ".git")
        git_ok(h, multihop_dest)
        assert h.git("--git-dir=" + str(multihop_dest), "rev-parse", "refs/heads/main"
                     ).stdout.decode().strip() == multihop_tip2
        assert h.git("--git-dir=" + str(multihop_dest), "rev-parse",
                     "refs/rootyard-ci/jobs/" + multihop_job1
                     ).stdout.decode().strip() == multihop_tip
        assert h.git("--git-dir=" + str(multihop_dest), "rev-parse",
                     "refs/rootyard-ci/jobs/" + multihop_job2
                     ).stdout.decode().strip() == multihop_tip2
        multihop_sidecars = h.root / "data" / "ci-pins" / multihop["id"]
        old_intent = json.loads((multihop_sidecars / (multihop_job1 + ".json")).read_bytes())
        mid_intent = json.loads((multihop_sidecars / (multihop_job2 + ".json")).read_bytes())
        assert old_intent["storage_generation"] == 1
        assert mid_intent["storage_generation"] == 2
        assert (multihop_sidecars / (multihop_job1 + ".pinned.json")).is_file()
        assert (multihop_sidecars / (multihop_job2 + ".pinned.json")).is_file()
        status, _ = issue_checkout(h, node0, "multihop", multihop_job1,
                                   multihop_tip, 3, audience)
        assert status == 409, "gen1 evidence was regranted at gen3"
        status, _ = issue_checkout(h, node0, "multihop", multihop_job2,
                                   multihop_tip2, 3, audience)
        assert status == 409, "gen2 evidence was regranted at gen3"
        multihop_job3 = str(uuid.uuid4())
        pin(h, "multihop", multihop_job3, multihop_tip2, 3)
        status, raw = issue_checkout(h, node0, "multihop", multihop_job3,
                                     multihop_tip2, 3, audience)
        assert status in (200, 201), (status, raw[:400])
        assert json.loads(raw)["plan"]["storage_generation"] == 3

        # Focused reconcile-window fixture (metadata/staging only, not a claim
        # of 34 whole migrations): completed and verified staged bundles beyond
        # the previous LIMIT 32 window must survive a target restart.
        dummy_ops = []
        for index in range(34):
            dummy_repo = create_repository(h, "window" + str(index))
            dummy_op = str(uuid.uuid4())
            dummy_ops.append((dummy_repo["id"], dummy_op))
            h.sql("UPDATE repositories SET storage_generation=2 WHERE id='" + dummy_repo["id"] + "'")
            h.sql("INSERT INTO repository_shard_routes(tenant_id,repository_id,bucket_id,"
                  "primary_node_id,route_epoch,fencing_token,required_generation) VALUES ('"
                  + h.alice["user_id"] + "','" + dummy_repo["id"] + "',0,'node1',2,2,2) "
                  "ON CONFLICT (tenant_id,repository_id) DO UPDATE SET primary_node_id='node1',"
                  "route_epoch=2,fencing_token=2,required_generation=2")
            state_name = "completed" if index % 2 == 0 else "verified"
            h.sql("INSERT INTO shard_replication_operations(id,repository_id,source_node_id,"
                  "target_node_id,source_route_epoch,source_generation,refs_sha256,state) "
                  "VALUES ('" + dummy_op + "','" + dummy_repo["id"] + "','shard-primary-0','node1',1,1,"
                  "'" + "a" * 64 + "','" + state_name + "')")
            staged = node1_data / "shard-staging" / (dummy_op + ".sidecar")
            staged.mkdir(parents=True)
            (staged / "incomplete-exchange-marker").write_text("metadata-only fixture\n")
        kill(target)
        target_log.close()
        target_log = open(node1_data.parent / "node1.log", "ab")
        target = start_target(h, args, node1, node1_data, log=target_log)
        surviving = sum(1 for _, dummy_op in dummy_ops
                        if (node1_data / "shard-staging" / (dummy_op + ".sidecar")).is_dir())
        assert surviving == len(dummy_ops), \
            "reconcile deleted staged sidecars outside its previous window"

        report = {
            "kind": "native_migration_sidecar_crash_matrix",
            "result": "passed",
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "postgres_version": h.sql("SHOW server_version"),
            "disposable_database": database,
            "hooks_registered": 15,
            "phases_actual": [fault_phase, "target-verify-before-publish",
                              "target-sidecar-before-publish+concurrent-fresh-pin",
                              "cutover-before-sidecar-finalize+pre-finalize-pin",
                              "verified-restart-with-staged-sidecar",
                              "final-delta-before-transfer", "cutover-before-commit",
                              "cutover-after-commit", "recover-before-reconcile",
                              "startup-sidecar-reconcile"],
            "hooks_unexercised": ["copy-before-transfer", "copy-after-transfer",
                                   "target-delta-before-verified",
                                   "takeover-after-source-verify",
                                   "takeover-before-promote",
                                   "takeover-after-source-marker",
                                   "transition-before-commit"],
            "sidecar_symlink_fail_closed": True,
            "sidecar_foreign_tenant_fail_closed": True,
            "cancelled_grant_denied_after_handoff": True,
            "released_pin_tombstone_preserved": True,
            "old_generation_pin_not_rebound": True,
            "fresh_checkout_after_handoff": True,
            "fresh_pin_accepted_during_finalize_survives": True,
            "pre_finalize_pin_bounded_503_then_retry": True,
            "zero_preexisting_root_fresh_pin_merged_by_finalize": True,
            "two_hop_historical_generation_retention": True,
            "two_hop_old_generation_grants_denied": True,
            "two_hop_fresh_generation_authorized": True,
            "verified_staged_sidecar_survives_target_restart": True,
            "reconcile_window_fixture_34_retained": surviving,
            "reconcile_window_fixture_is_metadata_only": True,
            "retained_ci_backup_snapshot_roots": True,
            "stock_git_fsck_and_acknowledged_commits": True,
            "old_source_nonwriter_after_true_fence": True,
            "old_native_volume_unchanged_after_cutover_push": old_volume_unchanged,
            "retired_source_push_directly_rejected": not old_proxied,
            "retired_source_push_supported_proxy_ack": old_proxied,
            "limits": ["one PostgreSQL authority; two Rust processes on one Linux host",
                       "physical cross-host fencing remains unqualified outside this role"]}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    finally:
        kill(target)
        if target_log:
            target_log.close()
        h.cleanup()
        try:
            admin_psql(admin_url, 'DROP DATABASE IF EXISTS "' + database + '" WITH (FORCE)')
        except Exception as error:  # noqa: BLE001 - preserve the real test failure
            print("database cleanup deferred:", type(error).__name__, file=sys.stderr)


if __name__ == "__main__":
    main()
