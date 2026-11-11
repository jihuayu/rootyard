#!/usr/bin/env python3
"""Genuine SIGKILL/restart acceptance for migration and shard-marker transitions.

The matrix covers three migration-phase crashes (`copy-before-transfer`,
`copy-after-transfer`, `target-delta-before-verified`), three takeover-phase
crashes (`takeover-after-source-verify`, `takeover-before-promote`,
`takeover-after-source-marker`), and both sides of every explicit shard marker
transition (`degrade`, `recover`, `fence`, `unfence`): a kill after the marker
intent is staged but before PostgreSQL commit must roll back without moving the
volume marker, and a kill after commit but before marker publication must leave
a pending transition that blocks writes until restart reconciliation publishes
the exact committed marker.

This harness owns a disposable PostgreSQL database and its own temporary Git
volumes. Each case drives the public migration, takeover or transition flow,
uses the opt-in native fault hook to SIGKILL a real Rust process at one exact
durable boundary, inspects durable operation state (including the still-running
target's public shard-fence status, sampled while the target process is paused
at the pre-commit fault boundary and before SIGKILL), then recovers. Migration
cases retry the same operation through the public migration API after restart;
takeover cases do not call a public resume API, but restart the target
controller and verify its automatic retry/reconciliation promotes the node. Both
then accept one fresh Git push through the recovered primary. No SQL
route/replica readiness is forged and hook registration alone is never treated
as coverage.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
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
    row = h.sql("SELECT primary_node_id,route_epoch,fencing_token,fenced_epoch,"
                "draining::text,read_only_degraded::text "
                "FROM repository_shard_routes WHERE repository_id='" + repo_id + "'")
    primary, epoch, token, fenced, draining, degraded = row.split("|")
    return {"primary_node_id": primary, "route_epoch": int(epoch),
            "fencing_token": int(token), "fenced_epoch": int(fenced),
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


def wait_bounded_admission(url, h, name, deadline_seconds=20, interval=.1):
    deadline = time.monotonic() + deadline_seconds
    last = None
    while time.monotonic() < deadline:
        try:
            status, raw = request(url, "/api/repos/alice/" + name + "/shard-fence", h.alice)
        except (OSError, urllib.error.URLError) as error:
            last = {"status": "unreachable", "error": h.redact(repr(error))}
        else:
            if status == 200:
                try:
                    last = json.loads(raw)
                except ValueError:
                    last = {"status": status,
                            "body": h.redact(raw[:200].decode(errors="replace"))}
                else:
                    # Only the real target status may end the wait; a pending
                    # marker transition keeps write_admitted false, so it can
                    # never be mistaken for recovery.
                    if last.get("write_admitted") is True:
                        return last
            else:
                last = {"status": status, "body": h.redact(raw[:200].decode(errors="replace"))}
        time.sleep(interval)
    summary = {}
    if isinstance(last, dict):
        if "status" not in last:
            summary["status"] = 200
        for key in ("status", "error", "body", "write_admitted", "primary_node_id",
                    "route_epoch", "fenced_epoch", "storage_generation",
                    "draining", "read_only_degraded"):
            if key in last:
                summary[key] = last[key]
        marker = last.get("volume_marker")
        if isinstance(marker, dict):
            summary["volume_marker"] = {key: marker.get(key) for key in
                                        ("primary_node_id", "route_epoch",
                                         "storage_generation", "read_only_degraded")}
    raise AssertionError("target " + name + " did not admit writes within "
                         + str(deadline_seconds) + "s after recovery; last="
                         + h.redact(json.dumps(summary)))


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
    crash_status = status
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
              "source_transfer_status": crash_status,
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
                                          FAULT_PAUSE: "20000"})
        marker = wait_marker_alive(node1_data, phase, target, timeout=40)
        assert_marker_binding(marker, phase, h.repo["id"], op, target.pid)
        if phase == "takeover-after-source-marker":
            assert marker["detail"].get("old_node") == SYSTEM, \
                ("fault marker belongs to another old node", marker["detail"])
        # The target process is still paused inside the fault hook at the exact
        # pre-commit takeover boundary, so only it can answer this query. The
        # status sampled here is therefore the pre-commit boundary status. The
        # write barrier is evaluated from durable route/generation state (it does
        # not block on the paused hook's in-flight transaction), so it is the
        # boundary view even if the paused thread has not fsynced its sidecar.
        fence_status, fence_raw = request(target_url, "/api/repos/alice/demo/shard-fence", h.alice)
        assert fence_status == 200, (fence_status, fence_raw[:300])
        fence = json.loads(fence_raw)
        assert fence["write_admitted"] is False, \
            ("target admitted writes at the pre-commit boundary", fence)
        assert fence["primary_node_id"] == SYSTEM, fence
        killed_rc = None
        target_pid = target.pid
        os.killpg(target.pid, signal.SIGKILL)
        target.wait(timeout=20)
        assert target.returncode == -signal.SIGKILL
        killed_rc = target.returncode
        tlog.close()
        blocked = (fence_dir / (SYSTEM + ".blocked")).is_file()
        pending_rows = int(h.sql("SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id='"
                                 + h.repo["id"] + "' AND state='pending'"))
        after = {"target_fence_status_at_pre_commit_boundary": {
                     "write_admitted": fence["write_admitted"],
                     "primary_node_id": fence["primary_node_id"],
                     "route_epoch": fence["route_epoch"]},
                 "route": sql_route(h, h.repo["id"]),
                 "operation_state": sql_op(h, op),
                 "promotion_rows": failover_count(h, h.repo["id"]),
                 "pending_marker_transition_rows": pending_rows,
                 "old_process_alive": h.proc.poll() is None,
                 "blocked_marker_present": blocked,
                 "source_volume_marker_present": (h.bare / "rootyard-shard-fence.json").exists()}
        assert after["route"]["primary_node_id"] == SYSTEM, after
        assert after["route"]["route_epoch"] == route0["route_epoch"], after
        assert after["route"]["draining"] is False, after
        assert after["operation_state"] == "verified", after
        assert after["promotion_rows"] == 0, "killed controller recorded a promotion"
        expected_pending = 1 if phase == "takeover-after-source-marker" else 0
        assert after["pending_marker_transition_rows"] == expected_pending, \
            ("killed controller left the wrong pending marker intent count", after)
        if phase == "takeover-after-source-marker":
            # The retired source marker and its durable intent were fsynced
            # before the promotion transaction was killed. Read the marker from
            # the old volume and the intent from PostgreSQL, never process memory.
            assert after["source_volume_marker_present"] is True, \
                "durable source volume marker was not published before the kill"
            source_pending = int(h.sql(
                "SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id='"
                + h.repo["id"] + "' AND state='pending' AND target_marker->>'primary_node_id'='"
                + SYSTEM + "'"))
            assert source_pending == 1, ("source marker intent is not bound to its volume", source_pending)
            retired = json.loads((h.bare / "rootyard-shard-fence.json").read_text())
            after["source_volume_marker"] = {"primary_node_id": retired["primary_node_id"],
                                             "route_epoch": retired["route_epoch"],
                                             "read_only_degraded": retired["read_only_degraded"],
                                             "fenced_node_id": retired.get("fenced_node_id")}
            assert retired["read_only_degraded"] is True, "durable source marker is not read-only"
            assert retired["primary_node_id"] == SYSTEM, retired
            assert retired["route_epoch"] == route0["route_epoch"] + 1, retired
            assert retired.get("fenced_node_id") == SYSTEM, retired
            h.proc.wait(timeout=20)
            assert h.proc.returncode == -signal.SIGKILL, "old source survived the physical fence"
            assert after["blocked_marker_present"] is True, "physical fence .blocked marker missing"
        elif phase == "takeover-after-source-verify":
            assert after["source_volume_marker_present"] is False
            assert after["old_process_alive"] is True, "old process died before physical fence"
            assert after["blocked_marker_present"] is False
        else:
            assert after["source_volume_marker_present"] is False
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
        # The old-volume marker above is the intentionally read-only retired
        # marker; it is not claimed to match the new target route byte for byte.
        post = {}
        if phase == "takeover-after-source-marker":
            # wait_route_primary can see the committed route before the target
            # controller finishes reconcile_pending, so wait (bounded) for the
            # real status endpoint to admit writes before checking markers.
            fence = wait_bounded_admission(target_url, h, "demo", deadline_seconds=20)
            post["target_fence_status_after_recovery"] = {
                "write_admitted": fence["write_admitted"],
                "primary_node_id": fence["primary_node_id"],
                "route_epoch": fence["route_epoch"]}
            assert fence["primary_node_id"] == TARGET, fence
            assert fence["route_epoch"] == promoted["route_epoch"], fence
            target_gen = generation(h, h.repo["id"])
            target_marker = json.loads((dest / "rootyard-shard-fence.json").read_text())
            post["target_marker_matches_committed_route"] = (
                target_marker["repository_id"] == h.repo["id"]
                and target_marker["primary_node_id"] == TARGET
                and target_marker["route_epoch"] == promoted["route_epoch"]
                and target_marker["storage_generation"] == target_gen
                and target_marker["read_only_degraded"] is False
                and target_marker["fenced_epoch"] == promoted["fenced_epoch"])
            assert post["target_marker_matches_committed_route"], \
                ("target volume marker differs from committed route", target_marker, promoted)
            post["pending_marker_transition_rows"] = int(h.sql(
                "SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id='"
                + h.repo["id"] + "' AND state='pending'"))
            post["complete_marker_transition_rows"] = int(h.sql(
                "SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id='"
                + h.repo["id"] + "' AND state='complete'"))
            assert post["pending_marker_transition_rows"] == 0, post
            # One restored rollback intent from the interrupted promotion, then
            # the retried source and target marker transitions.
            assert post["complete_marker_transition_rows"] == 3, \
                ("expected the rollback intent plus retried source/target transitions", post)
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
        result = {"name": phase, "status": "passed",
                  "phase": phase, "scope": "target controller Rust process in takeover",
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
        result.update(post)
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


def registered_hooks():
    source = (Path(__file__).resolve().parent.parent / "src/sharding/faults.rs").read_text()
    block = source.split("const PHASES: &[&str] = &[", 1)[1].split("];", 1)[0]
    return re.findall(r'"([^"]+)"', block)


def volume_marker(h):
    path = h.bare / "rootyard-shard-fence.json"
    return json.loads(path.read_text()) if path.is_file() else None


def route_view(route):
    return {key: route[key] for key in (
        "primary_node_id", "route_epoch", "fencing_token",
        "fenced_epoch", "draining", "read_only_degraded")}


def expected_after(route, action, body):
    result = dict(route)
    if action == "fence":
        fenced = body.get("fenced_epoch", route["route_epoch"])
        result["fenced_epoch"] = max(route["fenced_epoch"], fenced)
        result["route_epoch"] = max(route["route_epoch"], result["fenced_epoch"])
        result["fencing_token"] = max(route["fencing_token"], result["route_epoch"]) + 1
    elif action in ("unfence", "recover"):
        result["route_epoch"] = max(route["route_epoch"], route["fenced_epoch"]) + 1
        result["fencing_token"] = max(route["fencing_token"], result["route_epoch"]) + 1
        result["read_only_degraded"] = False
    elif action == "degrade":
        result["read_only_degraded"] = True
    return result


def expected_fenced_node(action, route, previous):
    if action == "fence":
        return route["primary_node_id"]
    if action == "unfence":
        return None
    return (previous or {}).get("fenced_node_id")


def assert_volume_marker(h, route, fenced_node, present):
    marker = volume_marker(h)
    if not present:
        assert marker is None, ("unexpected volume marker after rollback", marker)
        return None
    assert marker is not None, "committed transition did not publish a volume marker"
    generation = int(h.sql("SELECT storage_generation FROM repositories WHERE id='"
                            + h.repo["id"] + "'"))
    expected = {
        "repository_id": h.repo["id"],
        "primary_node_id": route["primary_node_id"],
        "route_epoch": route["route_epoch"],
        "fencing_token": route["fencing_token"],
        "fenced_epoch": route["fenced_epoch"],
        "storage_generation": max(generation, route["required_generation"]),
        "read_only_degraded": route["read_only_degraded"],
        "fenced_node_id": fenced_node,
    }
    observed = {key: marker.get(key) for key in expected}
    assert observed == expected, ("volume marker differs from committed route", observed, expected)
    return marker


def pending_transition_rows(h):
    return int(h.sql("SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id='"
                     + h.repo["id"] + "' AND state='pending'"))


def fence_status(h):
    status, raw, _ = h.http("/api/repos/alice/demo/shard-fence", token=h.alice)
    assert status == 200, (status, raw[:300])
    return json.loads(raw)


def route_admits(route_value):
    return not route_value["read_only_degraded"] and \
        route_value["fenced_epoch"] < route_value["route_epoch"]


def probe_write(h, expected_admitted, label):
    push_commit(h, h.work, "barrier probe " + label + "\n")
    attempted = h.git("push", "origin", "HEAD:main", cwd=h.work,
                      token=h.alice, check=False)
    if attempted.returncode:
        h.git("reset", "--hard", "HEAD~1", cwd=h.work)
    assert (attempted.returncode == 0) == expected_admitted, (
        "actual write barrier disagrees with route", label, expected_admitted,
        attempted.returncode, attempted.stderr.decode(errors="replace")[-500:])
    return attempted.returncode


def audit_rollback_case(h, action, body, before_route, before_marker):
    endpoint = "/api/repos/alice/demo/shard-" + (
        "degrade" if action in ("degrade", "recover") else "fence")
    function = "native_audit_rollback"
    try:
        h.sql("CREATE OR REPLACE FUNCTION " + function
              + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
              + "RAISE EXCEPTION 'native audit rollback'; END $$")
        h.sql("CREATE TRIGGER " + function + " BEFORE INSERT ON repository_audit_log "
              + "FOR EACH ROW EXECUTE FUNCTION " + function + "()")
        status, raw, _ = h.http(endpoint, token=h.alice, method="POST", body=body)
    finally:
        h.sql("DROP FUNCTION IF EXISTS " + function + "() CASCADE")
    assert status >= 500, ("audit failure did not abort the transition", status, raw[:300])
    assert sql_route(h, h.repo["id"]) == route_view(before_route)
    assert volume_marker(h) == before_marker
    assert pending_transition_rows(h) == 0
    h.stop()
    h.start()
    expected_admitted = route_admits(before_route)
    fence = fence_status(h)
    assert fence["write_admitted"] == expected_admitted, \
        ("audit rollback restart admitted writes unexpectedly", action, fence)
    push_rc = probe_write(h, expected_admitted, action + " audit rollback")
    return {
        "name": action + "-audit-rollback",
        "status": "passed",
        "phase": "audit-rollback",
        "action": action,
        "http_status": status,
        "durable_state_after_fault": {
            "route": sql_route(h, h.repo["id"]),
            "marker": before_marker,
            "pending_marker_transition_rows": 0,
            "postgresql_committed": False,
        },
        "restart_reconciliation": {
            "route": route_view(route(h, "demo")),
            "marker": volume_marker(h),
            "pending_marker_transition_rows": 0,
            "write_admitted": fence["write_admitted"],
            "push_returncode": push_rc,
        },
    }


def crash_transition(h, action, body, phase):
    endpoint = "/api/repos/alice/demo/shard-" + (
        "degrade" if action in ("degrade", "recover") else "fence")
    # Phases repeat across actions; a leftover marker from the previous action
    # would otherwise be mistaken for this process's fault boundary.
    clear_marker(h.root / "data", phase)
    h.env[FAULT] = phase
    h.env[FAULT_ACTION] = "kill"
    h.stop(hard=True)
    h.start()
    fault_pid = h.proc.pid
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(h.http, endpoint, token=h.alice, method="POST", body=body)
        marker = wait_marker_alive(h.root / "data", phase, h.proc, timeout=30)
        assert_marker_binding(marker, phase, h.repo["id"])
        assert marker.get("pid") == fault_pid, (marker.get("pid"), fault_pid)
        detail = marker.get("detail") or {}
        assert detail.get("route_epoch") is not None and detail.get("transition_id"), marker
        h.proc.wait(timeout=20)
        assert h.proc.returncode == -signal.SIGKILL, h.proc.returncode
        killed_rc = h.proc.returncode
        try:
            pending.result(timeout=5)
        except Exception:  # noqa: BLE001 - the process was intentionally killed
            pass
    h.stop(hard=True)
    return marker, killed_rc


def transition_cases(args):
    h = Harness(args)
    h.env[FAULT_ALLOW] = "1"
    records = []
    try:
        h.setup()
        h.api()
        h.roundtrip()
        for action in ("fence", "unfence", "degrade", "recover"):
            before_route = route(h, "demo")
            before_marker = volume_marker(h)
            if action == "fence":
                body = {"action": "fence", "fenced_epoch": before_route["route_epoch"]}
            elif action == "unfence":
                body = {"action": "unfence"}
            elif action == "degrade":
                body = {"mode": "degrade", "reason": "transition crash matrix"}
            else:
                body = {"mode": "recover"}
            committed_route = expected_after(before_route, action, body)
            fenced_node = expected_fenced_node(action, before_route, before_marker)
            records.append(audit_rollback_case(
                h, action, body, before_route, before_marker))
            before_admitted = route_admits(before_route)
            committed_admitted = route_admits(committed_route)
            for phase in ("transition-before-commit", "cutover-after-commit"):
                marker, killed_rc = crash_transition(h, action, body, phase)
                after_route = sql_route(h, h.repo["id"])
                after_marker = volume_marker(h)
                pending = pending_transition_rows(h)
                committed = phase == "cutover-after-commit"
                expected_route = committed_route if committed else before_route
                if committed:
                    assert after_route == route_view(expected_route), (
                        "committed transition differs from the durable route", after_route,
                        route_view(expected_route))
                    assert pending == 1, ("committed transition lost its pending marker intent", pending)
                else:
                    assert after_route == route_view(before_route), (
                        "rolled-back transition changed PostgreSQL state", after_route,
                        route_view(before_route))
                    assert pending == 0, ("rolled-back transition left a pending intent", pending)
                assert after_marker == before_marker, (
                    "fault mutated the volume marker before the durable boundary", after_marker,
                    before_marker)
                h.env.pop(FAULT, None)
                h.env.pop(FAULT_ACTION, None)
                h.start()
                final_route = route(h, "demo")
                assert route_view(final_route) == route_view(expected_route), (
                    "restart reconciliation route mismatch", route_view(final_route),
                    route_view(expected_route))
                restored_fenced_node = (before_marker or {}).get("fenced_node_id")
                final_marker = assert_volume_marker(
                    h, final_route, fenced_node if committed else restored_fenced_node,
                    committed or before_marker is not None)
                assert pending_transition_rows(h) == 0, \
                    "restart reconciliation left a pending marker transition"
                expected_admitted = committed_admitted if committed else before_admitted
                fence = fence_status(h)
                assert fence["write_admitted"] == expected_admitted, (
                    "shard-fence admission disagrees with durable transition boundary",
                    action, phase, fence)
                push_rc = probe_write(h, expected_admitted, action + " " + phase)
                barrier = {"write_admitted": fence["write_admitted"],
                           "push_returncode": push_rc}
                records.append({
                    "name": action + "-" + phase,
                    "status": "passed",
                    "phase": phase,
                    "action": action,
                    "fault_marker": {"phase": marker["phase"], "pid": marker["pid"],
                                     "repository_bound": True, "transition_bound": True},
                    "process_returncode": killed_rc,
                    "durable_state_after_fault": {
                        "route": after_route,
                        "marker": after_marker,
                        "pending_marker_transition_rows": pending,
                        "marker_mutated_before_commit": after_marker != before_marker,
                        "postgresql_committed": committed,
                    },
                    "restart_reconciliation": {
                        "route": route_view(final_route),
                        "marker": final_marker,
                        "pending_marker_transition_rows": 0,
                    },
                    "write_barrier_after_recovery": barrier,
                })
            # The committed phase is the observable state for the next action.
            assert route_view(route(h, "demo")) == route_view(committed_route)
        return records
    finally:
        h.cleanup()


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


def isolated_tmpdir(args):
    """Return a writable TMPDIR outside the shared temporary root."""
    configured = os.environ.get("TMPDIR")
    if configured and Path(configured).resolve() != Path(os.path.sep, "tmp").resolve():
        return Path(configured), False
    base = args.report.parent if args.report else Path.cwd() / "test-results"
    base.mkdir(parents=True, exist_ok=True)
    path = base / ("native-migration-tmp-" + uuid.uuid4().hex)
    path.mkdir(mode=0o700)
    return path, True


def normalize_cases(records):
    cases = []
    for record in records:
        case = dict(record)
        case.setdefault("name", str(record.get("phase", "unknown")))
        case["status"] = "passed" if case.get("status") in (None, "passed") else case["status"]
        cases.append(case)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--transitions-only", action="store_true",
                        help="run only the explicit shard marker transition crash matrix")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    revision = source_revision()
    if not revision:
        raise SystemExit("source revision could not be resolved; refusing to emit an unbound report")
    admin_url = os.environ.get("ROOTYARD_TEST_DATABASE_URL")
    if not admin_url:
        raise SystemExit("ROOTYARD_TEST_DATABASE_URL must point at a disposable admin database")
    tmpdir, created_tmpdir = isolated_tmpdir(args)
    os.environ["TMPDIR"] = str(tmpdir)
    database, database_url = disposable_database(admin_url)
    os.environ["ROOTYARD_TEST_DATABASE_URL"] = database_url
    records = []
    failure = None
    postgres_version = None
    try:
        if args.transitions_only:
            records.append(takeover_case(args, "takeover-after-source-marker"))
            records.extend(transition_cases(args))
            postgres_version = admin_psql(database_url, "SHOW server_version")
        else:
            migration_harness, migration_records = migration_phases(args)
            records.extend(migration_records)
            postgres_version = migration_harness.sql("SHOW server_version")
            migration_harness.cleanup()
            records.append(takeover_case(args, "takeover-after-source-verify"))
            records.append(takeover_case(args, "takeover-before-promote"))
            records.append(takeover_case(args, "takeover-after-source-marker"))
            records.extend(transition_cases(args))
    except Exception as error:  # noqa: BLE001 - a failed matrix must still emit a failed report
        failure = error
        records.append({"name": "__main__", "status": "failed", "phase": "__main__",
                        "error": str(error)[:2000]})
    cleanup_ok = False
    cleanup_error = None
    try:
        admin_psql(admin_url, 'DROP DATABASE IF EXISTS "' + database + '" WITH (FORCE)')
        cleanup_ok = True
    except Exception as error:  # noqa: BLE001 - report the cleanup failure and exit non-zero
        cleanup_error = type(error).__name__
        print("database cleanup failed:", cleanup_error, file=sys.stderr)
    success = failure is None and cleanup_ok
    cases = normalize_cases(records)
    hooks = registered_hooks()
    phases = [case["phase"] for case in cases if case.get("phase") not in (None, "__main__")]
    exercised = [phase for phase in phases if phase in hooks]
    binary = Path(args.binary)
    report = {
        "kind": "native_migration_residual_phase_crash_acceptance",
        "result": "passed" if success else "failed",
        "passed": success,
        "source_head": revision,
        "source_base_commit": revision,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest() if binary.is_file() else None,
        "binary_size_bytes": binary.stat().st_size if binary.is_file() else None,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "postgres_version": postgres_version,
        "disposable_database": database,
        "database_cleanup_succeeded": cleanup_ok,
        "topology": "one PostgreSQL authority and separate Rust storage processes on one Linux host",
        "port_allocation": "OS-assigned ephemeral loopback free_port; fixed HA/infra ports not used",
        "fault_hook_env_gated": True,
        "hooks_registered": len(hooks),
        "hooks_exercised": exercised,
        "phases_actual": phases,
        "hooks_unexercised": [hook for hook in hooks if hook not in exercised],
        "hook_registration_counted_as_pass": False,
        "artificial_sql_route_or_replica_readiness": False,
        "public_migration_or_takeover_flow_used": True,
        "transition_matrix_uses_real_public_fence_and_degrade_routes": True,
        "each_case_own_repo_and_durable_operation": not args.transitions_only,
        "cases": cases,
        "limits": [
            "single trusted Linux host; no cross-host storage fence or PostgreSQL HA",
            "takeover cases use SIGSTOP to let the real node lease expire, then a real SIGKILL",
            "old generic 409 takeover transient observed historically remains unclassified and is not claimed fixed",
            "transition cases share one real repository; each crash/reconcile cycle is separately asserted",
        ],
    }
    if failure is not None:
        report["error"] = str(failure)[:2000]
    if cleanup_error is not None:
        report["database_cleanup_error"] = cleanup_error
    if args.report:
        write_report(args.report, report)
    print(json.dumps(report))
    if created_tmpdir:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
