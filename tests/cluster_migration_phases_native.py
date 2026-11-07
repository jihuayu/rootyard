#!/usr/bin/env python3
"""Genuine SIGKILL/restart acceptance for the five residual migration phases.

This harness owns a disposable PostgreSQL database and its own temporary Git
volumes. Each case drives the public migration or takeover flow, uses the
opt-in native fault hook to SIGKILL a real Rust process at one exact durable
boundary, inspects durable operation state, then resumes the same operation
through the public API after restart. No SQL route/replica readiness is forged
and hook registration alone is never treated as coverage.
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

FAULT_ALLOW = "ROOTYARD_TEST_FAULT_ALLOW"
FAULT = "ROOTYARD_TEST_FAULT"
FAULT_ACTION = "ROOTYARD_TEST_FAULT_ACTION"
FAULT_PAUSE = "ROOTYARD_TEST_FAULT_PAUSE_MS"
SYSTEM = "shard-primary-0"
TARGET = "node1"


def admin_psql(url, statement):
    result = subprocess.run(["psql", url, "-X", "-v", "ON_ERROR_STOP=1", "-c", statement],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=60, env=os.environ.copy())
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace")[-800:])
    return result.stdout.decode(errors="replace").strip()


def disposable_database(admin_url):
    name = "rootyard_migration_phases_" + uuid.uuid4().hex
    admin_psql(admin_url, 'CREATE DATABASE "' + name + '" TEMPLATE template0')
    parts = urlsplit(admin_url)
    return name, urlunsplit(parts._replace(path="/" + name))


def wait_ready(url, token, process=None, timeout=30):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if process is not None and process.poll() is not None:
            raise AssertionError("native process exited before readiness")
        try:
            if request(url, "/health/ready", token)[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.05)
    raise AssertionError("native process readiness timeout")


def start_child(h, args, node_id, url, data, extra=None, tag="node"):
    env = h.env.copy()
    env.update(ROOTYARD_NODE_ID=node_id, ROOTYARD_BIND=url.rsplit("//", 1)[1],
               ROOTYARD_DATA_DIR=str(data), ROOTYARD_OUTBOX_WORKER="false")
    env.update(extra or {})
    log = open(data.parent / (tag + ".log"), "ab")
    child = subprocess.Popen([args.binary, "serve"], env=env, stdout=log,
                             stderr=log, start_new_session=True)
    try:
        wait_ready(url, h.alice, child)
    except Exception:
        kill_child(child, log)
        raise
    return child, log


def kill_child(child, log=None):
    if child is not None and child.poll() is None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=15)
    if log is not None:
        log.close()


def marker_file(data, phase):
    return data / ".native-test-faults" / (phase + ".json")


def clear_marker(data, phase):
    path = marker_file(data, phase)
    if path.exists():
        path.unlink()


def wait_marker_or_pending(data, phase, pending, h, timeout=30):
    path = marker_file(data, phase)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return json.loads(path.read_text())
        if pending.done():
            try:
                result = pending.result()
            except Exception as error:  # noqa: BLE001 - redacted diagnostic
                raise AssertionError("request failed before fault marker " + phase + ": "
                                     + h.redact(repr(error))) from error
            status, raw = result[0], result[1]
            raise AssertionError("request completed before fault marker " + phase
                                 + ": status=" + str(status) + " body="
                                 + h.redact(raw[:300].decode(errors="replace")))
        time.sleep(.02)
    raise AssertionError("fault marker did not persist: " + phase)


def wait_marker_alive(data, phase, child, timeout=40):
    path = marker_file(data, phase)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return json.loads(path.read_text())
        if child.poll() is not None:
            raise AssertionError("controller exited before fault marker " + phase)
        time.sleep(.02)
    raise AssertionError("fault marker did not persist: " + phase)


def assert_marker_binding(marker, phase, repo_id, operation_id=None, process_pid=None):
    assert marker.get("phase") == phase, ("wrong fault marker phase", phase, marker)
    detail = marker.get("detail") or {}
    assert detail.get("repository_id") == repo_id, \
        ("fault marker belongs to another repository", phase, detail, repo_id)
    if operation_id is not None:
        assert detail.get("operation_id") == operation_id, \
            ("fault marker belongs to another operation", phase, detail, operation_id)
    if process_pid is not None:
        assert marker.get("pid") == process_pid, \
            ("fault marker belongs to another process", phase, marker.get("pid"), process_pid)


def git_ok(h, bare):
    h.git("--git-dir=" + str(bare), "fsck", "--full", "--strict")


def rev(h, bare, ref):
    return h.git("--git-dir=" + str(bare), "rev-parse", ref).stdout.decode().strip()


def route(h, name):
    return json.loads(h.expect("/api/repos/alice/" + name + "/shard-route", 200, token=h.alice))


def sql_route(h, repo_id):
    row = h.sql("SELECT primary_node_id,route_epoch,draining::text,read_only_degraded::text "
                "FROM repository_shard_routes WHERE repository_id='" + repo_id + "'")
    primary, epoch, draining, degraded = row.split("|")
    return {"primary_node_id": primary, "route_epoch": int(epoch),
            "draining": draining == "true", "read_only_degraded": degraded == "true"}


def sql_op(h, operation_id):
    return h.sql("SELECT state FROM shard_replication_operations WHERE id='" + operation_id + "'")


def failover_count(h, repo_id):
    return int(h.sql("SELECT COUNT(*) FROM shard_failover_operations WHERE repository_id='"
                     + repo_id + "' AND state='promoted'"))


def source_bare(h, repo_id):
    return h.root / "data" / "repos" / (repo_id + ".git")


def target_bare(data, repo_id):
    return data / "repos" / (repo_id + ".git")


def create_repo(h, name):
    status, raw, _ = h.http("/api/repos", token=h.alice, method="POST", body={"name": name})
    assert status in (201, 202), (status, raw[:300])
    deadline = time.monotonic() + 30
    repo = None
    while time.monotonic() < deadline:
        status, raw, _ = h.http("/api/repos/alice/" + name, token=h.alice)
        assert status == 200, (status, raw[:300])
        repo = json.loads(raw)
        if repo["state"] == "ready":
            break
        time.sleep(.05)
    assert repo is not None and repo["state"] == "ready", "repository did not become ready"
    work = h.root / ("work-" + name)
    h.git("clone", h.base + repo["clone_path"], str(work), token=h.alice)
    h.git("config", "user.name", "Native", cwd=work)
    h.git("config", "user.email", "native@example.invalid", cwd=work)
    (work / "state.txt").write_text("acknowledged before " + name + "\n")
    h.git("add", "state.txt", cwd=work)
    h.git("commit", "-m", "initial " + name, cwd=work)
    tip = h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    h.git("push", "origin", "HEAD:main", cwd=work, token=h.alice)
    return repo, work, tip


def push_commit(h, work, text):
    (work / "state.txt").write_text(text)
    h.git("add", "state.txt", cwd=work)
    h.git("commit", "-m", text.strip(), cwd=work)
    return h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()


def pin(h, name, job, oid, generation):
    status, raw, _ = h.http("/api/repos/alice/" + name + "/ci-pins", token=h.alice,
                            method="POST", body={"job_id": job, "target_oid": oid,
                                                 "storage_generation": generation})
    assert status in (200, 201), (status, raw[:400])
    return json.loads(raw)


def add_retained_roots(h, bare, oid):
    for ref in ("refs/rootyard-snapshots/backup-1", "refs/rootyard-backup/snapshot-1"):
        h.git("--git-dir=" + str(bare), "update-ref", ref, oid)


def assert_retained(h, bare, job, oid):
    assert rev(h, bare, "refs/rootyard-ci/jobs/" + job) == oid, "CI job root was lost"
    for ref in ("refs/rootyard-snapshots/backup-1", "refs/rootyard-backup/snapshot-1"):
        assert rev(h, bare, ref) == oid, "retained root was lost: " + ref


def migrate_http(h, name, body):
    return h.http("/api/repos/alice/" + name + "/shard-migrate", token=h.alice,
                  method="POST", body=body)


def redacted_tails(h):
    for path in sorted(h.root.glob("*.log")):
        try:
            tail = path.read_text(errors="replace")[-4000:]
        except OSError:
            continue
        print("native diagnostic " + path.name + ":\n" + h.redact(tail), flush=True)


def wait_route_primary(url, h, name, node, timeout=40):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        status, raw = request(url, "/api/repos/alice/" + name + "/shard-route", h.alice)
        if status == 200:
            last = json.loads(raw)
            if last.get("primary_node_id") == node and last.get("draining") is False:
                return last
        time.sleep(.1)
    raise AssertionError("controller did not promote measured target; last=" + h.redact(json.dumps(last)))


def prepare_repo(h, name):
    repo, work, tip = create_repo(h, name)
    prior = generation(h, repo["id"])
    job = str(uuid.uuid4())
    pin(h, name, job, tip, prior)
    add_retained_roots(h, source_bare(h, repo["id"]), tip)
    return {"name": name, "repo": repo, "work": work, "tip": tip, "prior": prior,
            "job": job, "route0": route(h, name)}


def generation(h, repo_id):
    return int(h.sql("SELECT storage_generation FROM repositories WHERE id='" + repo_id + "'"))


def assert_migrated(h, name, repo, work, job, tip, route0, node1_data, target_url, prior_generation):
    dest = target_bare(node1_data, repo["id"])
    bare = source_bare(h, repo["id"])
    assert rev(h, dest, "refs/heads/main") == tip, "target did not hold the acknowledged commit"
    git_ok(h, dest)
    assert_retained(h, dest, job, tip)
    sidecar = node1_data / "ci-pins" / repo["id"]
    assert (sidecar / (job + ".json")).is_file(), "CI pin sidecar was not published"
    assert (sidecar / (job + ".pinned.json")).is_file(), "CI pin receipt was not published"
    new_route = route(h, name)
    assert new_route["primary_node_id"] == TARGET, ("cutover did not promote target", new_route)
    assert new_route["route_epoch"] > route0["route_epoch"], ("route epoch did not advance", new_route)
    assert new_route["draining"] is False
    assert generation(h, repo["id"]) == prior_generation + 1, "storage generation did not advance once"
    marker = json.loads((bare / "rootyard-shard-fence.json").read_text())
    assert marker["read_only_degraded"] is True, "old source volume is not read-only"
    assert marker["primary_node_id"] == SYSTEM
    assert marker["route_epoch"] == new_route["route_epoch"]
    raised = push_commit(h, work, "fresh acknowledged write after " + name + "\n")
    h.git("push", target_url + repo["clone_path"], "HEAD:main", cwd=work, token=h.alice)
    assert rev(h, dest, "refs/heads/main") == raised, "new primary did not accept a fresh push"
    assert rev(h, bare, "refs/heads/main") == tip, "retired source volume changed after cutover"
    git_ok(h, dest)
    assert_retained(h, dest, job, tip)
    return {"new_route_epoch": new_route["route_epoch"], "storage_generation": prior_generation + 1,
            "acknowledged_oid": tip, "post_recovery_acknowledged_oid": raised,
            "target_fsck": "passed", "retained_ci_backup_snapshot_roots": True,
            "old_source_read_only_marker": True,
            "old_source_volume_unchanged_after_new_push": True}


def case_copy_before(h, target_url, node1_data, fixture):
    phase = "copy-before-transfer"
    name = fixture["name"]
    repo, work, tip = fixture["repo"], fixture["work"], fixture["tip"]
    prior, job, route0 = fixture["prior"], fixture["job"], fixture["route0"]
    op = str(uuid.uuid4())
    body = {"target_node_id": TARGET, "expected_route_epoch": route0["route_epoch"],
            "operation_id": op}
    clear_marker(h.root / "data", phase)
    h.stop(hard=True)
    h.env[FAULT] = phase
    h.env[FAULT_ACTION] = "kill"
    h.start()
    fault_pid = h.proc.pid
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(migrate_http, h, name, body)
        marker = wait_marker_or_pending(h.root / "data", phase, pending, h)
        assert_marker_binding(marker, phase, repo["id"], op, fault_pid)
        h.proc.wait(timeout=20)
        assert h.proc.returncode == -signal.SIGKILL
        killed_rc = h.proc.returncode
        try:
            pending.result(timeout=10)
        except Exception:
            pass
    h.env.pop(FAULT, None)
    h.env.pop(FAULT_ACTION, None)
    after = {"operation_state": sql_op(h, op), "route": sql_route(h, repo["id"]),
             "target_repo_present": target_bare(node1_data, repo["id"]).exists()}
    assert after["operation_state"] == "copying", after
    assert after["route"]["primary_node_id"] == SYSTEM and not after["route"]["draining"], after
    assert after["target_repo_present"] is False, "killed source left a partial target repo"
    clear_marker(h.root / "data", phase)
    started = time.monotonic_ns()
    h.start()
    status, raw, _ = migrate_http(h, name, body)
    assert status == 200, (status, raw[:500])
    recovery_ms = round((time.monotonic_ns() - started) / 1e6, 3)
    receipt = json.loads(raw)
    assert receipt["state"] == "completed" and receipt["operation_id"] == op, receipt
    result = {"phase": phase, "scope": "source Rust process in public migration API",
              "fault_marker": {"phase": marker["phase"], "pid": marker["pid"],
                               "repository_bound": True, "operation_bound": True},
              "fault_pid": marker["pid"], "process_returncode": killed_rc,
              "durable_state_after_fault": after, "stale_target_not_promoted": True,
              "recovery_ms": recovery_ms, "recovery_result": "completed",
              "recovery_used_same_operation_id": receipt["operation_id"] == op}
    result.update(assert_migrated(h, name, repo, work, job, tip, route0, node1_data,
                                  target_url, prior))
    return result


def case_copy_after(h, target_url, node1_data, fixture):
    phase = "copy-after-transfer"
    name = fixture["name"]
    repo, work, tip = fixture["repo"], fixture["work"], fixture["tip"]
    prior, job, route0 = fixture["prior"], fixture["job"], fixture["route0"]
    op = str(uuid.uuid4())
    body = {"target_node_id": TARGET, "expected_route_epoch": route0["route_epoch"],
            "operation_id": op}
    clear_marker(h.root / "data", phase)
    h.stop(hard=True)
    h.env[FAULT] = phase
    h.env[FAULT_ACTION] = "kill"
    h.start()
    fault_pid = h.proc.pid
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(migrate_http, h, name, body)
        marker = wait_marker_or_pending(h.root / "data", phase, pending, h)
        assert_marker_binding(marker, phase, repo["id"], op, fault_pid)
        h.proc.wait(timeout=20)
        assert h.proc.returncode == -signal.SIGKILL
        killed_rc = h.proc.returncode
        try:
            pending.result(timeout=10)
        except Exception:
            pass
    h.env.pop(FAULT, None)
    h.env.pop(FAULT_ACTION, None)
    dest = target_bare(node1_data, repo["id"])
    after = {"operation_state": sql_op(h, op), "route": sql_route(h, repo["id"]),
             "target_repo_present": dest.is_dir()}
    assert after["operation_state"] == "verified", after
    assert after["route"]["primary_node_id"] == SYSTEM and not after["route"]["draining"], after
    assert after["target_repo_present"] is True
    assert rev(h, dest, "refs/heads/main") == tip
    git_ok(h, dest)
    clear_marker(h.root / "data", phase)
    started = time.monotonic_ns()
    h.start()
    status, raw, _ = migrate_http(h, name, body)
    assert status == 200, (status, raw[:500])
    recovery_ms = round((time.monotonic_ns() - started) / 1e6, 3)
    receipt = json.loads(raw)
    assert receipt["state"] == "completed" and receipt["operation_id"] == op, receipt
    result = {"phase": phase, "scope": "source Rust process in public migration API",
              "fault_marker": {"phase": marker["phase"], "pid": marker["pid"],
                               "repository_bound": True, "operation_bound": True},
              "fault_pid": marker["pid"], "process_returncode": killed_rc,
              "durable_state_after_fault": after,
              "verified_target_was_not_promoted_without_cutover": True,
              "recovery_ms": recovery_ms, "recovery_result": "completed",
              "recovery_used_same_operation_id": receipt["operation_id"] == op}
    result.update(assert_migrated(h, name, repo, work, job, tip, route0, node1_data,
                                  target_url, prior))
    return result


def case_target_delta(h, args, target_url, node1_data, holder, fixture):
    phase = "target-delta-before-verified"
    name = fixture["name"]
    repo, work, tip = fixture["repo"], fixture["work"], fixture["tip"]
    prior, job, route0 = fixture["prior"], fixture["job"], fixture["route0"]
    op = str(uuid.uuid4())
    body = {"target_node_id": TARGET, "expected_route_epoch": route0["route_epoch"],
            "operation_id": op}
    clear_marker(node1_data, phase)
    kill_child(holder["target"], holder["log"])
    holder["target"], holder["log"] = start_child(
        h, args, TARGET, target_url, node1_data, tag="node1",
        extra={FAULT: phase, FAULT_ACTION: "kill"})
    fault_pid = holder["target"].pid
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(migrate_http, h, name, body)
        marker = wait_marker_or_pending(node1_data, phase, pending, h)
        assert_marker_binding(marker, phase, repo["id"], op, fault_pid)
        holder["target"].wait(timeout=20)
        assert holder["target"].returncode == -signal.SIGKILL
        killed_rc = holder["target"].returncode
        status, raw, _ = pending.result(timeout=20)
    holder["log"].close()
    assert status == 502, ("killed target did not fail the source transfer as 502", status, raw[:300])
    dest = target_bare(node1_data, repo["id"])
    after = {"operation_state": sql_op(h, op), "route": sql_route(h, repo["id"]),
             "target_repo_present": dest.is_dir(),
             "promotion_rows": failover_count(h, repo["id"])}
    assert after["operation_state"] == "verified", after
    assert after["route"]["primary_node_id"] == SYSTEM, after
    assert after["route"]["draining"] is True, "source was not fenced before the delta"
    assert after["target_repo_present"] is True
    assert after["promotion_rows"] == 0, "killed target was promoted"
    assert rev(h, dest, "refs/heads/main") == tip
    git_ok(h, dest)
    clear_marker(node1_data, phase)
    started = time.monotonic_ns()
    holder["target"], holder["log"] = start_child(h, args, TARGET, target_url,
                                                  node1_data, tag="node1")
    status, raw, _ = migrate_http(h, name, body)
    assert status == 200, (status, raw[:500])
    recovery_ms = round((time.monotonic_ns() - started) / 1e6, 3)
    receipt = json.loads(raw)
    assert receipt["state"] == "completed" and receipt["operation_id"] == op, receipt
    result = {"phase": phase, "scope": "target Rust process in public migration API",
              "fault_marker": {"phase": marker["phase"], "pid": marker["pid"],
                               "repository_bound": True, "operation_bound": True},
              "fault_pid": marker["pid"], "process_returncode": killed_rc,
              "source_transfer_status": status,
              "durable_state_after_fault": after,
              "drained_source_was_not_promoted_while_target_dead": True,
              "recovery_ms": recovery_ms, "recovery_result": "completed",
              "recovery_used_same_operation_id": receipt["operation_id"] == op}
    result.update(assert_migrated(h, name, repo, work, job, tip, route0, node1_data,
                                  target_url, prior))
    return result


def migration_phases(args):
    h = Harness(args)
    holder = {"target": None, "log": None}
    h.env[FAULT_ALLOW] = "1"
    h.env["ROOTYARD_NODE_ID"] = SYSTEM
    h.env["ROOTYARD_CLUSTER_HMAC_KEY"] = base64.b64encode(os.urandom(32)).decode()
    try:
        h.setup()
        h.sql("INSERT INTO cluster_operator_tokens(token_id, granted_by) VALUES ('"
              + h.alice["token_id"] + "', 'native-migration-phases')")
        node0 = h.base
        status, _ = request(node0, "/api/shards/nodes", h.alice, "POST", {
            "node_id": SYSTEM, "endpoint": node0, "role": "primary", "status": "healthy",
            "lease_ttl_seconds": 120})
        assert status in (200, 201), status
        h.api()
        h.roundtrip()
        port = free_port()
        target_url = "http://127.0.0.1:" + str(port)
        node1_data = h.root / "data-node1"
        holder["target"], holder["log"] = start_child(h, args, TARGET, target_url,
                                                      node1_data, tag="node1")
        status, _ = request(node0, "/api/shards/nodes", h.alice, "POST", {
            "node_id": TARGET, "endpoint": target_url, "role": "replica",
            "status": "healthy", "lease_ttl_seconds": 120})
        assert status in (200, 201), status
        fixtures = {key: prepare_repo(h, key)
                    for key in ("copybefore", "copyafter", "targetdelta")}
        records = [case_copy_before(h, target_url, node1_data, fixtures["copybefore"]),
                   case_copy_after(h, target_url, node1_data, fixtures["copyafter"])]
        records.append(case_target_delta(h, args, target_url, node1_data, holder,
                                         fixtures["targetdelta"]))
        return h, records
    except Exception:
        redacted_tails(h)
        h.stop(hard=True)
        raise
    finally:
        kill_child(holder["target"], holder["log"])


def takeover_case(args, phase):
    h = Harness(args)
    target = None
    tlog = None
    fence_dir = h.root / "controller-fences"
    fence_dir.mkdir(mode=0o700)
    h.env["ROOTYARD_LOCAL_FENCE_DIR"] = str(fence_dir)
    h.env["ROOTYARD_NODE_ID"] = SYSTEM
    h.env["ROOTYARD_CLUSTER_HMAC_KEY"] = base64.b64encode(os.urandom(32)).decode()
    h.env[FAULT_ALLOW] = "1"
    try:
        h.setup()
        h.sql("INSERT INTO cluster_operator_tokens(token_id, granted_by) VALUES ('"
              + h.alice["token_id"] + "', 'native-migration-phases-takeover')")
        status, _ = request(h.base, "/api/shards/nodes", h.alice, "POST", {
            "node_id": SYSTEM, "endpoint": h.base, "role": "primary",
            "status": "healthy", "lease_ttl_seconds": 2})
        assert status in (200, 201), status
        h.api()
        h.roundtrip()
        tip = h.second
        prior = generation(h, h.repo["id"])
        job = str(uuid.uuid4())
        pin(h, "demo", job, tip, prior)
        add_retained_roots(h, h.bare, tip)
        route0 = route(h, "demo")
        port = free_port()
        target_url = "http://127.0.0.1:" + str(port)
        node1_data = h.root / "data-node1"
        target, tlog = start_child(h, args, TARGET, target_url, node1_data, tag="node1")
        status, _ = request(h.base, "/api/shards/nodes", h.alice, "POST", {
            "node_id": TARGET, "endpoint": target_url, "role": "replica",
            "status": "healthy", "lease_ttl_seconds": 2})
        assert status in (200, 201), status
        op = str(uuid.uuid4())
        body = {"target_node_id": TARGET, "operation_id": op,
                "expected_route_epoch": route0["route_epoch"], "replicate_only": True}
        status, raw, _ = h.http("/api/repos/alice/demo/shard-migrate", token=h.alice,
                                method="POST", body=body)
        assert status == 200, (status, raw[:400])
        assert json.loads(raw)["state"] == "verified"
        active_dest = target_bare(node1_data, h.repo["id"])
        assert rev(h, active_dest, "refs/heads/main") == tip
        git_ok(h, active_dest)
        # Keep the old process alive but stop its heartbeat/controller so the
        # real lease expires. This is a process pause, not a SQL heartbeat edit.
        os.killpg(h.proc.pid, signal.SIGSTOP)
        clear_marker(node1_data, phase)
        kill_child(target, tlog)
        target, tlog = start_child(h, args, TARGET, target_url, node1_data, tag="node1",
                                   extra={FAULT: phase, FAULT_ACTION: "pause",
                                          FAULT_PAUSE: "8000"})
        marker = wait_marker_alive(node1_data, phase, target, timeout=40)
        assert_marker_binding(marker, phase, h.repo["id"], op, target.pid)
        killed_rc = None
        target_pid = target.pid
        os.killpg(target.pid, signal.SIGKILL)
        target.wait(timeout=20)
        assert target.returncode == -signal.SIGKILL
        killed_rc = target.returncode
        tlog.close()
        blocked = (fence_dir / (SYSTEM + ".blocked")).is_file()
        after = {"route": sql_route(h, h.repo["id"]),
                 "operation_state": sql_op(h, op),
                 "promotion_rows": failover_count(h, h.repo["id"]),
                 "old_process_alive": h.proc.poll() is None,
                 "blocked_marker_present": blocked,
                 "source_volume_marker_present": (h.bare / "rootyard-shard-fence.json").exists()}
        assert after["route"]["primary_node_id"] == SYSTEM, after
        assert after["route"]["route_epoch"] == route0["route_epoch"], after
        assert after["route"]["draining"] is False, after
        assert after["operation_state"] == "verified", after
        assert after["promotion_rows"] == 0, "killed controller recorded a promotion"
        assert after["source_volume_marker_present"] is False
        if phase == "takeover-after-source-verify":
            assert after["old_process_alive"] is True, "old process died before physical fence"
            assert after["blocked_marker_present"] is False
        else:
            h.proc.wait(timeout=20)
            assert h.proc.returncode == -signal.SIGKILL, "old source was not killed before promote"
            assert after["blocked_marker_present"] is True
        started = time.monotonic_ns()
        target, tlog = start_child(h, args, TARGET, target_url, node1_data, tag="node1")
        promoted = wait_route_primary(target_url, h, "demo", TARGET, timeout=40)
        recovery_ms = round((time.monotonic_ns() - started) / 1e6, 3)
        if phase == "takeover-after-source-verify":
            h.proc.wait(timeout=20)
            assert h.proc.returncode == -signal.SIGKILL, "recovered controller did not fence old writer"
        assert promoted["route_epoch"] == route0["route_epoch"] + 1, promoted
        assert generation(h, h.repo["id"]) == prior + 1
        assert failover_count(h, h.repo["id"]) == 1
        dest = target_bare(node1_data, h.repo["id"])
        assert rev(h, dest, "refs/heads/main") == tip
        git_ok(h, dest)
        assert_retained(h, dest, job, tip)
        marker_data = json.loads((h.bare / "rootyard-shard-fence.json").read_text())
        assert marker_data["read_only_degraded"] is True
        assert marker_data["primary_node_id"] == SYSTEM
        assert marker_data["route_epoch"] == promoted["route_epoch"]
        assert (fence_dir / (SYSTEM + ".blocked")).is_file()
        rejected = h.run([args.binary, "serve"], check=False)
        assert rejected.returncode != 0, "old writer restarted after durable fence"
        assert (b"durable physical fence" in rejected.stderr
                or b"physical fence" in rejected.stderr), h.redact(
                    rejected.stderr.decode(errors="replace")[-400:])
        raised = push_commit(h, h.work, "fresh acknowledged write after " + phase + "\n")
        h.git("push", target_url + h.repo["clone_path"], "HEAD:main",
              cwd=h.work, token=h.alice)
        assert rev(h, dest, "refs/heads/main") == raised
        assert rev(h, h.bare, "refs/heads/main") == tip
        git_ok(h, dest)
        assert_retained(h, dest, job, tip)
        result = {"phase": phase, "scope": "target controller Rust process in takeover",
                  "fault_marker": {"phase": marker["phase"], "pid": marker["pid"],
                                   "repository_bound": True, "operation_bound": True},
                  "fault_pid": marker["pid"], "controller_pid": target_pid,
                  "process_returncode": killed_rc,
                  "durable_state_after_fault": after,
                  "stale_target_not_promoted": True,
                  "old_writer_fenced_after_recovery": True,
                  "old_writer_restart_rejected": True,
                  "recovery_ms": recovery_ms, "recovery_result": "promoted",
                  "new_route_epoch": promoted["route_epoch"],
                  "storage_generation": prior + 1,
                  "acknowledged_oid": tip,
                  "post_recovery_acknowledged_oid": raised,
                  "target_fsck": "passed",
                  "retained_ci_backup_snapshot_roots": True,
                  "old_source_volume_unchanged_after_new_push": True}
        kill_child(target, tlog)
        target, tlog = None, None
        h.cleanup()
        return result
    except Exception:
        redacted_tails(h)
        h.stop(hard=True)
        raise
    finally:
        kill_child(target, tlog)


def write_report(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, indent=2) + "\n").encode()
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def source_revision():
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"],
                                cwd=Path(__file__).resolve().parent.parent,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        return result.stdout.decode().strip() if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    admin_url = os.environ.get("ROOTYARD_TEST_DATABASE_URL")
    if not admin_url:
        raise SystemExit("ROOTYARD_TEST_DATABASE_URL must point at a disposable admin database")
    os.environ["TMPDIR"] = "/tmp"
    database, database_url = disposable_database(admin_url)
    os.environ["ROOTYARD_TEST_DATABASE_URL"] = database_url
    success = False
    try:
        migration_harness, records = migration_phases(args)
        postgres_version = migration_harness.sql("SHOW server_version")
        migration_harness.cleanup()
        records.append(takeover_case(args, "takeover-after-source-verify"))
        records.append(takeover_case(args, "takeover-before-promote"))
        binary = Path(args.binary)
        report = {
            "kind": "native_migration_residual_phase_crash_acceptance",
            "result": "passed",
            "source_base_commit": source_revision(),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "binary_size_bytes": binary.stat().st_size,
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "postgres_version": postgres_version,
            "disposable_database": database,
            "topology": "one PostgreSQL authority and separate Rust storage processes on one Linux host",
            "port_allocation": "OS-assigned ephemeral loopback free_port; fixed HA/infra ports not used",
            "fault_hook_env_gated": True,
            "hooks_registered": 5,
            "hooks_exercised": [record["phase"] for record in records],
            "phases_actual": [record["phase"] for record in records],
            "hooks_unexercised": [],
            "hook_registration_counted_as_pass": False,
            "artificial_sql_route_or_replica_readiness": False,
            "public_migration_or_takeover_flow_used": True,
            "each_case_own_repo_and_durable_operation": True,
            "cases": records,
            "limits": [
                "single trusted Linux host; no cross-host storage fence or PostgreSQL HA",
                "takeover cases use SIGSTOP to let the real node lease expire, then a real SIGKILL",
                "old generic 409 takeover transient observed historically remains unclassified and is not claimed fixed",
            ],
        }
        if args.report:
            write_report(args.report, report)
        print(json.dumps(report))
        success = True
    finally:
        if success:
            try:
                admin_psql(admin_url, 'DROP DATABASE IF EXISTS "' + database + '" WITH (FORCE)')
            except Exception as error:  # noqa: BLE001 - preserve the real test failure
                print("database cleanup deferred:", type(error).__name__, file=sys.stderr)
        else:
            print("retained disposable database for failure evidence:", database, file=sys.stderr)


if __name__ == "__main__":
    main()
