#!/usr/bin/env python3
"""Native acceptance: supported external automatic PostgreSQL HA (#43).

Topology for this run (honest scope): three etcd members, three
Patroni-managed PostgreSQL 17 nodes and one HAProxy stable endpoint, all on a
single Linux host with dedicated data directories and loopback ports.  Rootyard
uses the stable endpoint; a complete primary node (Patroni *and* its
unmanaged postmaster session) is hard-killed and Patroni must promote a
successor without any manual pg_ctl promote or patronictl failover.  The same
run also exercises DCS quorum loss (no unsafe promotion; old PostgreSQL must be
read-only) and a fresh-authority restore of the real Rootyard backup closure.

This is not cross-host, rack or power-loss evidence and the host has no
hardware watchdog, so the production watchdog/fencing requirement is validated
only as a configuration gate, never certified here.
"""
import argparse
import base64
import json
import os
import re
import socket
import uuid
import urllib.request
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error

from e2e import Harness
import ha_fixture
import ops_provenance

TABLE_COUNTS = ("repositories", "git_operations", "tokens", "outbox_events", "event_deliveries", "ci_checkout_jobs")
REPO_ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def mirror_http(base, path, token=None, method="GET", body=None):
    """Minimal mirror request helper; tokens stay in headers, never in argv."""
    headers = {}
    if token:
        headers["Authorization"] = "Basic " + base64.b64encode(
            (token["username"] + ":" + token["token"]).encode()).decode()
    if isinstance(body, dict):
        body = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except (OSError, urllib.error.URLError):
        return 0, b""


def start_mirror(binary, env, log_path, base):
    log = open(log_path, "ab")
    proc = subprocess.Popen([binary, "serve-mirror"], env=env, stdout=log, stderr=log,
                            start_new_session=True)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"mirror exited early; inspect {log_path}")
        if mirror_http(base, "/health/ready")[0] == 200:
            return proc, log
        time.sleep(0.2)
    raise AssertionError(f"mirror readiness timeout; inspect {log_path}")


def stop_mirror(proc, log):
    if proc and proc.poll() is None:
        try:
            os.killpg(proc.pid, 15)
            proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(proc.pid, 9)
            except OSError:
                pass
    if log:
        log.close()



def readme_json_examples():
    """Parse every fenced JSON block in the HA README (bounded doc check)."""
    text = (REPO_ROOT / "deployment" / "ha" / "README.md").read_text()
    blocks, current = [], None
    sep = chr(10)
    for line in text.splitlines():
        if line.strip().startswith("```json"):
            current = []
        elif current is not None and line.strip() == "```":
            blocks.append(sep.join(current))
            current = None
        elif current is not None:
            current.append(line)
    parsed = []
    for index, block in enumerate(blocks):
        try:
            parsed.append(json.loads(block))
        except ValueError as error:
            raise AssertionError(f"README fenced JSON block {index} is invalid: {error}") from error
    return parsed



def redact(text, secrets):
    for value in secrets:
        text = text.replace(str(value), "[REDACTED]")
    return text


def count_rows(h):
    counts = {}
    for table in TABLE_COUNTS:
        counts[table] = int(h.sql(f"SELECT COUNT(*) FROM {table}"))
    return counts


def pending_keys(query):
    """Exact durable delivery identities (event_id, consumer) still pending."""
    rows = query("SELECT event_id || '|' || consumer FROM event_deliveries "
                 "WHERE state <> 'delivered' ORDER BY 1")
    return {line.strip() for line in rows.splitlines() if line.strip()}


def delivery_states(query, keys):
    """Current state of the exact tracked delivery identities."""
    if not keys:
        return {}
    literals = ",".join("'" + key.replace("'", "''") + "'" for key in sorted(keys))
    rows = query("SELECT (event_id || '|' || consumer) || '=' || state FROM event_deliveries "
                 f"WHERE (event_id || '|' || consumer) IN ({literals})")
    return dict(row.split("=", 1) for row in rows.splitlines() if "=" in row)


def drain_deliveries(worker, query, keys, rounds=120):
    """Call the real worker until every tracked pre-fault delivery is delivered.

    Only the exact pre-fault identity set is tracked; the global pending count
    is intentionally not used because new writes after the fault legitimately
    add new deliveries. Nothing is marked delivered by SQL.
    """
    processed = 0
    for _ in range(rounds):
        states = delivery_states(query, keys)
        if states and len(states) == len(keys) and all(state == "delivered" for state in states.values()):
            return processed
        processed += worker()
        time.sleep(0.1)
    return processed


def ref_map(git_dir):
    """Exact refname -> object id map for one repository."""
    result = subprocess.run(["git", f"--git-dir={git_dir}", "for-each-ref",
                             "--format=%(refname) %(objectname)"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    refs = {}
    for line in result.stdout.decode().splitlines():
        name, _, oid = line.partition(" ")
        if name:
            refs[name] = oid
    return refs


def ref_count(git_dir):
    return len(ref_map(git_dir))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--port-base", type=int, default=26000)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    root = Path(tempfile.mkdtemp(prefix="rootyard-ha43-"))
    fx = ha_fixture.HAFixture(root / "cluster", port_base=args.port_base)
    h = None
    restored = None
    restored_pg_started = False
    results = []
    started = time.monotonic()
    old_env = os.environ.copy()
    secrets = list(fx.secrets.values())
    try:
        # ---- reference profile rendering and negative security gates -----
        code, output = fx.render()
        assert code == 0, output
        rendered = json.loads(output)
        assert rendered["synchronous_commit"] == "remote_apply" and rendered["watchdog"] is False
        env_file = (fx.render_dir / "rootyard.env").read_text()
        assert "sslmode=require" in env_file and "ROOTYARD_PG_CA_PEM=" in env_file
        assert oct((fx.render_dir / "rootyard.env").stat().st_mode & 0o777) == "0o600"
        negative = {}
        readme_examples = readme_json_examples()
        assert readme_examples, "deployment/ha/README.md has no fenced JSON example"
        negative["readme_json_examples_valid"] = len(readme_examples)
        prod = json.loads(fx.spec_path.read_text())
        prod["environment"] = "production"
        (root / "prod-spec.json").write_text(json.dumps(prod))
        code, output = fx.render(spec=root / "prod-spec.json", check=True)
        negative["production_without_watchdog_rejected"] = code == 2 and "watchdog" in output
        assert negative["production_without_watchdog_rejected"], output
        weak = dict(fx.secrets)
        weak["rootyard_password"] = "password"
        (root / "weak.json").write_text(json.dumps(weak))
        os.chmod(root / "weak.json", 0o600)
        code, output = fx.render(secrets=root / "weak.json", check=True)
        negative["weak_password_rejected"] = code == 2
        assert negative["weak_password_rejected"], output
        shared = dict(fx.secrets)
        shared["replication_password"] = shared["rootyard_password"]
        (root / "shared.json").write_text(json.dumps(shared))
        os.chmod(root / "shared.json", 0o600)
        code, output = fx.render(secrets=root / "shared.json", check=True)
        negative["shared_password_rejected"] = code == 2
        assert negative["shared_password_rejected"], output
        no_dcs_cert = json.loads(fx.spec_path.read_text())
        no_dcs_cert["etcd"]["client_cert"] = ""
        (root / "no-dcs-cert.json").write_text(json.dumps(no_dcs_cert))
        code, output = fx.render(spec=root / "no-dcs-cert.json", check=True)
        negative["dcs_client_certificate_required"] = code == 2
        assert negative["dcs_client_certificate_required"], output
        missing_server_cert = json.loads(fx.spec_path.read_text())
        missing_server_cert["etcd"]["server_cert"] = ""
        (root / "no-dcs-server-cert.json").write_text(json.dumps(missing_server_cert))
        code, output = fx.render(spec=root / "no-dcs-server-cert.json", check=True)
        negative["missing_dcs_server_certificate_rejected"] = code == 2
        assert negative["missing_dcs_server_certificate_rejected"], output
        key_copy = root / "world-readable-server.key"
        shutil.copyfile(fx.pki / "server.key", key_copy)
        os.chmod(key_copy, 0o644)
        readable_key = json.loads(fx.spec_path.read_text())
        readable_key["etcd"]["server_key"] = str(key_copy)
        (root / "world-readable-key.json").write_text(json.dumps(readable_key))
        code, output = fx.render(spec=root / "world-readable-key.json", check=True)
        negative["world_readable_dcs_server_key_rejected"] = code == 2
        assert negative["world_readable_dcs_server_key_rejected"], output
        for device in ("/dev/null", "/dev/urandom"):
            fake = json.loads(fx.spec_path.read_text())
            fake["environment"] = "production"
            fake["watchdog"] = {"device": device, "safety_margin": 5}
            path = root / ("watchdog-" + device.rsplit("/", 1)[-1] + ".json")
            path.write_text(json.dumps(fake))
            code, output = fx.render(spec=path, check=True)
            key = "dev_" + device.rsplit("/", 1)[-1] + "_watchdog_rejected"
            negative[key] = code == 2 and "watchdog" in output
            assert negative[key], output
        env = fx.env({"PATH": fx.pg + ":" + os.environ.get("PATH", "")})
        rootyard_downgrade = subprocess.run(
            [args.binary, "migrate"],
            env={**env, "DATABASE_URL": "postgresql://rootyard:x@127.0.0.1:"
                 f"{fx.ports['haproxy_primary']}/rootyard_ha?sslmode=disable",
                 "ROOTYARD_PG_CA_PEM": str(fx.pki / "ca.crt")},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        negative["rootyard_tls_downgrade_rejected"] = (
            rootyard_downgrade.returncode != 0
            and b"refusing PostgreSQL TLS downgrade" in rootyard_downgrade.stderr)
        assert negative["rootyard_tls_downgrade_rejected"], rootyard_downgrade.stderr[-600:]

        # ---- native etcd quorum + Patroni cluster ------------------------
        fx.start_etcd()
        for node in fx.spec["nodes"]:
            result = subprocess.run([sys.executable, "-m", "patroni", "--validate-config",
                                     str(fx.render_dir / f"patroni-{node['name']}.yml")],
                                    env=fx.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
            assert result.returncode == 0, result.stdout.decode()[-900:] + result.stderr.decode()[-900:]
        etcd_no_cert = fx.etcdctl("endpoint", "health", nodes=[fx.ports["etcd_client"][0]], cert=False,
                                  check=False)
        assert etcd_no_cert.returncode != 0, "etcd accepted a client without mTLS"
        negative["dcs_mtls_required"] = True
        fx.start_patroni()
        synchronous = fx.wait_synchronous()
        fx.start_haproxy()
        leader = fx.leader()
        assert leader, "no Patroni leader after startup"
        endpoint_role = fx.wait_endpoint_primary()
        assert endpoint_role == "f:" + str(fx.pg_port(leader))
        replica_before = fx.wait_replica_endpoint(fx.pg_port(leader))
        assert replica_before.startswith("t:") and replica_before.split(":", 1)[1] != str(fx.pg_port(leader))
        assert fx.sql(leader, "SELECT pg_is_in_recovery()") == "f"
        # Patroni protects management endpoints with basic auth; its health and
        # read-only GET endpoints are unauthenticated by design, so network
        # access control is the loopback-only bind (checked below).
        rest_unauth = fx.rest(leader, path="/restart", auth=False, method="DELETE")
        assert rest_unauth[0] == 401, "Patroni REST management endpoint accepted unauthenticated access"
        rest_auth = fx.rest(leader, path="/restart", auth=True, method="DELETE")
        assert rest_auth[0] == 404, "Patroni REST management endpoint rejected authenticated access"
        rest_health = fx.rest(leader, auth=False)
        assert rest_health[0] == 200
        rest_listeners = {node["name"]: sorted(fx.listener_addresses(node["rest_port"]))
                          for node in fx.spec["nodes"]}
        for name, addresses in rest_listeners.items():
            assert "127.0.0.1" in addresses and "0.0.0.0" not in addresses                 and fx.host_ip not in addresses, f"Patroni REST not loopback-only on {name}: {addresses}"
        negative["patroni_rest_authentication"] = {
            "unauthenticated_management": rest_unauth[0], "authenticated_management": rest_auth[0],
            "read_only_health_http": rest_health[0], "loopback_only": rest_listeners,
            "note": "Patroni health/GET endpoints are unauthenticated by design; management endpoints need basic auth; REST binds loopback only"}
        role_attrs = fx.sql(leader, "SELECT rolname||'|'||rolsuper||'|'||rolcreatedb||'|'||rolreplication "
                                    "FROM pg_roles WHERE rolname IN ('repl','rootyard') ORDER BY rolname")
        assert "repl|false|false|true" in role_attrs, role_attrs
        assert "rootyard|false|true|false" in role_attrs, role_attrs
        password_kinds = fx.sql(leader, "SELECT rolname||'|'||split_part(rolpassword,'$',1) FROM pg_authid "
                                        "WHERE rolname IN ('postgres','repl','rootyard') ORDER BY rolname")
        assert password_kinds.count("SCRAM-SHA-256") == 3, password_kinds
        no_plaintext = fx.sql(leader, "SELECT COUNT(*) FROM pg_authid WHERE rolname IN "
                                      "('postgres','repl','rootyard') AND rolpassword !~ '^SCRAM-SHA-256\\$'")
        assert no_plaintext == "0"
        assert fx.sql(leader, "SELECT count(*) FROM pg_database WHERE datname='rootyard_ha'") == "1"
        assert fx.sql(leader, "SELECT count(*) FROM pg_roles WHERE rolname='rootyard'") == "1"
        assert fx.sql(leader, "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'") == "2"
        tls_negative = {}
        wrong = fx.env({"PGPASSWORD": fx.secrets["superuser_password"], "PGSSLMODE": "verify-full",
                        "PGSSLROOTCERT": str(fx.wrong_pki / "ca.crt")})
        wrong_ca = subprocess.run(["psql", "-h", fx.host_ip, "-p", str(fx.pg_port(leader)), "-U", "postgres",
                                   "-d", "postgres", "-X", "-c", "SELECT 1"], env=wrong,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        assert wrong_ca.returncode != 0, "PostgreSQL accepted an untrusted CA"
        tls_negative["untrusted_ca_rejected"] = True
        no_ssl = fx.env({"PGPASSWORD": fx.secrets["superuser_password"], "PGSSLMODE": "disable"})
        rejected = subprocess.run(["psql", "-h", fx.host_ip, "-p", str(fx.pg_port(leader)), "-U", "postgres",
                                   "-d", "postgres", "-X", "-c", "SELECT 1"], env=no_ssl,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        assert rejected.returncode != 0, "plaintext PostgreSQL connection was accepted"
        tls_negative["plaintext_rejected"] = True

        # ---- Rootyard against the stable HAProxy primary endpoint --------
        require_dsn = (f"postgresql://rootyard:{fx.secrets['rootyard_password']}@127.0.0.1:"
                       f"{fx.ports['haproxy_primary']}/rootyard_ha?sslmode=require")
        verify_dsn = (f"postgresql://rootyard:{fx.secrets['rootyard_password']}@127.0.0.1:"
                      f"{fx.ports['haproxy_primary']}/rootyard_ha?sslmode=verify-full&sslrootcert="
                      f"{fx.pki / 'ca.crt'}")
        os.environ["ROOTYARD_TEST_DATABASE_URL"] = verify_dsn
        h = Harness(args)
        h.base_db = verify_dsn
        h.db = verify_dsn
        ci_audience = str(uuid.uuid4())
        h.env.update({"DATABASE_URL": require_dsn, "ROOTYARD_PG_CA_PEM": str(fx.pki / "ca.crt"),
                      "PGSSLMODE": "verify-full", "PGSSLROOTCERT": str(fx.pki / "ca.crt"),
                      "ROOTYARD_OUTBOX_WORKER": "false",
                      "ROOTYARD_CI_MIRROR_AUDIENCE": ci_audience})
        fx.wait_endpoint_primary()
        h.cli("migrate")
        h.alice = h.account("create-user", "alice")
        h.bob = h.account("create-user", "bob")
        h.reader = h.account("create-token", "alice", "--read-only")
        revoked = h.account("create-token", "alice")
        h.cli("revoke-token", revoked["token_id"])
        h.start()
        assert h.http("/api/repos/alice/demo", token=revoked)[0] in (401, 404)
        h.case("ha_endpoint_repository_api", h.api)
        h.case("ha_git_roundtrip", h.roundtrip)
        acked = []
        fault_base = time.monotonic_ns()
        acked.append({"oid": h.first, "ack_ns": fault_base, "phase": "roundtrip"})
        acked.append({"oid": h.second, "ack_ns": fault_base, "phase": "roundtrip"})
        git_dir = str(h.bare)
        baseline = {"refs": ref_count(git_dir), "counts": count_rows(h),
                    "sync": synchronous, "leader": leader,
                    "server_port": fx.endpoint_sql("SELECT inet_server_port()")}
        assert baseline["server_port"] == str(fx.pg_port(leader))
        outbox_before = int(h.sql("SELECT COUNT(*) FROM outbox_events"))
        pre_fault_pending = pending_keys(h.sql)
        assert outbox_before > 0 and pre_fault_pending, "fixture produced no durable worker backlog"

        def push_commit(message, marker):
            (h.work / marker).write_text(message + "\n")
            h.git("add", marker, cwd=h.work)
            h.git("commit", "-m", message, cwd=h.work)
            oid = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
            h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
            return oid, time.monotonic_ns()

        for index in range(4):
            oid, stamp = push_commit(f"pre-failure acknowledged push {index}", f"load-{index}.txt")
            acked.append({"oid": oid, "ack_ns": stamp, "phase": "pre_failure"})
        h.git("fetch", "origin", cwd=h.copy, token=h.reader)
        pre_failure_tip = h.git("rev-parse", "origin/main", cwd=h.copy).stdout.decode().strip()
        assert pre_failure_tip == acked[-1]["oid"]
        # Re-capture the exact pending delivery identities at the failure
        # boundary, including deliveries created by the pre-failure pushes.
        pre_fault_pending = pending_keys(h.sql)
        assert pre_fault_pending, "no pending deliveries at the failure boundary"
        rootyard_pid = h.proc.pid

        # ---- hard crash of the complete old primary node -----------------
        old_primary = fx.leader()
        old_port = fx.pg_port(old_primary)
        assert fx.endpoint_role() == "f:" + str(old_port)
        crash_at = time.monotonic_ns()
        fx.kill_node(old_primary)
        crashed = time.monotonic_ns()
        assert not ha_fixture.wait_port(old_port, timeout=3, host=fx.host_ip), "old primary PostgreSQL port still open"
        assert not fx.node_processes(old_primary), "old primary node processes survived the hard crash"
        successor = fx.wait_promotion(old_primary, timeout=90)
        promoted_at = time.monotonic_ns()
        assert successor != old_primary
        assert fx.sql(successor, "SELECT pg_is_in_recovery()") == "f"
        role_after = fx.cluster_state()
        assert role_after.get("leader") == successor

        def first_endpoint_read(timeout=120):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    if fx.endpoint_sql("SELECT pg_is_in_recovery()", timeout=6) == "f":
                        return time.monotonic_ns()
                except AssertionError:
                    pass
                time.sleep(0.2)
            raise AssertionError("stable endpoint did not reach the promoted primary")

        read_recovered_at = first_endpoint_read()
        health_statuses = []
        health_at = None
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                status, _, _ = h.http("/health/ready")
            except (OSError, urllib.error.URLError):
                status = 0
            health_statuses.append(status)
            if status == 200:
                health_at = time.monotonic_ns()
                break
            time.sleep(0.25)
        assert health_at, f"Rootyard never became ready through the stable endpoint: {health_statuses[-10:]}"
        assert h.proc is not None and h.proc.pid == rootyard_pid, "Rootyard was restarted; pool reconnection not proved"
        h.git("fetch", "origin", cwd=h.work, token=h.reader)
        fetched_tip = h.git("rev-parse", "FETCH_HEAD", cwd=h.work).stdout.decode().strip()
        history = set(h.git("rev-list", "FETCH_HEAD", cwd=h.work).stdout.decode().splitlines())
        missing = [item["oid"] for item in acked if item["oid"] not in history]
        assert not missing, f"acknowledged commits lost after automatic promotion: {missing}"
        post_failover_clone = h.root / "post-failover"
        h.git("clone", h.remote, str(post_failover_clone), token=h.reader)
        h.git("fsck", "--full", "--strict", cwd=post_failover_clone)
        post_oid, write_recovered_at = push_commit("write after automatic Patroni promotion",
                                                   "post-promotion.txt")
        h.git("fetch", "origin", cwd=post_failover_clone, token=h.reader)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=post_failover_clone).stdout.decode().strip() == post_oid
        assert fx.endpoint_role() == "f:" + str(fx.pg_port(successor))
        replica_after = fx.wait_replica_endpoint(fx.pg_port(successor), timeout=90)
        assert replica_after.startswith("t:") and replica_after.split(":", 1)[1] != str(fx.pg_port(successor))
        assert h.http("/api/repos/alice/demo", token=revoked)[0] == 401
        assert h.http("/api/repos/alice/demo", token=h.bob)[0] in (403, 404)
        # Track the exact pre-failure delivery identities: post-failure writes
        # legitimately create new deliveries, so a global count cannot prove
        # that the retained backlog advanced.
        worker_processed = drain_deliveries(lambda: int(h.cli("worker-once")), h.sql, pre_fault_pending)
        pre_fault_states = delivery_states(h.sql, pre_fault_pending)
        assert len(pre_fault_states) == len(pre_fault_pending), (
            f"pre-failure deliveries disappeared after failover: "
            f"{len(pre_fault_states)}/{len(pre_fault_pending)} retained")
        undelivered = sorted(key for key, state in pre_fault_states.items() if state != "delivered")
        assert not undelivered, f"worker did not deliver pre-failure deliveries: {undelivered[:5]}"
        assert worker_processed > 0, "real worker processed no pre-failure deliveries after failover"
        post_crash_commands = [entry for entry in fx.commands if "promote" in " ".join(entry).lower()
                               or "failover" in " ".join(entry).lower()]
        assert not post_crash_commands, "operator/script promotion was invoked during automatic failover"
        promotion_log = fx.promotion_log_lines()
        failover = {
            "old_primary": old_primary, "successor": successor, "manual_promotion_invoked": False,
            "old_node_processes_after_crash": 0, "old_pg_port_closed": True,
            "crash_to_successor_elected_ms": round((promoted_at - crashed) / 1e6, 1),
            "acked_oids": [item["oid"] for item in acked],
            "acked_ack_timestamps_ns": [item["ack_ns"] for item in acked],
            "crash_at_ns": crash_at,
            "missing_acked_oids": missing,
            "worker_processed_after_promotion": worker_processed,
            "pre_failure_delivery_ids": len(pre_fault_pending),
            "pre_failure_deliveries_delivered": len(pre_fault_states) - len(undelivered),
            "worker_accounting": "exact pre-failure (event_id,consumer) identity set; global pending "
                                 "total excluded because new acknowledged writes add new deliveries",
            "worker_invocation": "worker-once processes a bounded per-consumer batch; the real binary "
                                 "was invoked repeatedly until every tracked pre-failure delivery was delivered",
            "rootyard_pid_before": rootyard_pid, "rootyard_pid_after": h.proc.pid,
            "rootyard_health_statuses": health_statuses,
            "promotion_log_excerpt": promotion_log,
            "post_promotion_oid": post_oid,
            "endpoint_primary_pg_port_before": old_port,
            "endpoint_primary_pg_port_after": fx.pg_port(successor),
        }
        assert not missing

        # ---- DCS quorum loss: measured role history and write rejection ----
        dcs_leader = fx.leader()
        alice_user_id = h.sql("SELECT id::text FROM users WHERE username='alice'")
        assert re.fullmatch(r"[0-9a-f-]{36}", alice_user_id), f"unexpected alice id: {alice_user_id!r}"

        def durable_write_probe():
            """No-op real write with the app identity on the fixture application DB."""
            try:
                out = fx.endpoint_sql("UPDATE users SET username=username WHERE id='"
                                      + alice_user_id + "'", db="rootyard_ha")
                return True, out[:200]
            except AssertionError as error:
                return False, str(error)[:300]

        # Prove this exact app-identity write is permitted before faulting DCS.
        # Otherwise a schema/permission error could imitate a read-only result.
        healthy_write_accepted, healthy_write_detail = durable_write_probe()
        assert healthy_write_accepted and healthy_write_detail.strip() == "UPDATE 1", (
            "healthy durable write probe failed before DCS loss: " + healthy_write_detail)

        stopped = [node["name"] for node in fx.spec["etcd"]["nodes"][:2]]
        dcs_loss_at = time.monotonic_ns()
        fx.stop_etcd(stopped)
        role_history = []
        demotion_detected_at = None
        verification_deadline = None
        valid_lease_writes = 0
        post_demotion_probes = 0
        post_demotion_rejected = 0
        last_probe = None
        api_during_quorum_loss = "unknown"
        while True:
            now = time.monotonic_ns()
            elapsed = (now - dcs_loss_at) / 1e9
            node_roles = {}
            for node in fx.spec["nodes"]:
                name = node["name"]
                try:
                    recovery = fx.sql(name, "SELECT pg_is_in_recovery()")
                    role = "standby" if recovery == "t" else "primary"
                except AssertionError:
                    role = "unavailable"
                status, _ = fx.rest(name)
                node_roles[name] = {"pg": role, "patroni_rest_status": status}
            role_history.append({"elapsed_s": round(elapsed, 2), "nodes": node_roles})
            unsafe = sorted(name for name, observation in node_roles.items()
                            if name != dcs_leader and observation["pg"] == "primary")
            if unsafe:
                raise AssertionError(
                    f"standby promoted while the DCS quorum was absent: {unsafe}; "
                    f"recent history={role_history[-5:]}")
            old_role = node_roles[dcs_leader]["pg"]
            accepted, detail = durable_write_probe()
            last_probe = {"accepted": accepted, "detail": detail,
                          "old_primary_pg": old_role, "elapsed_s": round(elapsed, 2)}
            if demotion_detected_at is None:
                if old_role in ("standby", "unavailable"):
                    demotion_detected_at = now
                    verification_deadline = now + 5_000_000_000
                elif accepted:
                    # The old leader may legitimately accept writes while its
                    # still-valid lease has not expired. Record, do not judge.
                    valid_lease_writes += 1
            else:
                post_demotion_probes += 1
                if accepted:
                    raise AssertionError(
                        "stable endpoint accepted a durable write after the old primary was "
                        f"read-only/stopped while the DCS quorum was absent: probe={last_probe}; "
                        f"roles={node_roles}")
                post_demotion_rejected += 1
                if now >= verification_deadline and post_demotion_probes >= 3:
                    break
            if elapsed > 75 and demotion_detected_at is None:
                raise AssertionError(
                    f"old primary was not demoted within 75s of quorum loss: {role_history[-5:]}")
            time.sleep(0.5)
        assert demotion_detected_at is not None
        assert post_demotion_probes >= 3 and post_demotion_rejected == post_demotion_probes, (
            f"post-demotion write probes: {post_demotion_probes} total, "
            f"{post_demotion_rejected} rejected; last={last_probe}")
        promoted_without_quorum = sorted({name for sample in role_history
                                          for name, observation in sample["nodes"].items()
                                          if name != dcs_leader and observation["pg"] == "primary"})
        assert not promoted_without_quorum, (
            f"promotion observed without quorum: {promoted_without_quorum}")
        demotion_index = next(index for index, sample in enumerate(role_history)
                              if sample["nodes"][dcs_leader]["pg"] in ("standby", "unavailable"))
        old_primary_states_after_demotion = [sample["nodes"][dcs_leader]["pg"]
                                             for sample in role_history[demotion_index:]]
        assert all(state in ("standby", "unavailable") for state in old_primary_states_after_demotion), (
            f"old primary returned to primary while quorum was absent: {old_primary_states_after_demotion}")
        old_primary_readonly_or_stopped = role_history[-1]["nodes"][dcs_leader]["pg"] in (
            "standby", "unavailable")
        try:
            h.http("/api/repos/alice/demo", token=h.reader)
            api_during_quorum_loss = "200"
        except (OSError, urllib.error.URLError):
            api_during_quorum_loss = "unreachable"
        no_quorum_seconds = (time.monotonic_ns() - dcs_loss_at) / 1e9
        demotion_detection_seconds = (demotion_detected_at - dcs_loss_at) / 1e9
        post_demotion_window_seconds = (time.monotonic_ns() - demotion_detected_at) / 1e9
        role_transitions = []
        for sample in role_history:
            if not role_transitions or role_transitions[-1]["nodes"] != sample["nodes"]:
                role_transitions.append(sample)
        fx.start_etcd_members(stopped)
        dcs_recovered_at = None
        try:
            endpoint_after_quorum = fx.wait_endpoint_primary(timeout=150)
            dcs_recovered_at = time.monotonic_ns()
        except AssertionError as error:
            raise AssertionError(
                "cluster did not regain a writable primary after the DCS quorum returned: "
                f"role_history={role_history[-5:]} detail='{error}'")
        nodes_after_recovery = {}
        for node in fx.spec["nodes"]:
            try:
                recovery = fx.sql(node["name"], "SELECT pg_is_in_recovery()")
                role = "standby" if recovery == "t" else "primary"
            except AssertionError:
                role = "unavailable"
            nodes_after_recovery[node["name"]] = role
        recovered_primaries = sorted(name for name, role in nodes_after_recovery.items()
                                     if role == "primary")
        assert len(recovered_primaries) == 1, (
            f"unexpected PostgreSQL primary set after quorum recovery: {nodes_after_recovery}")
        recovered_primary = recovered_primaries[0]
        dcs_oid, _ = push_commit("write after DCS quorum recovery", "post-quorum.txt")
        dcs = {"stopped_etcd_members": stopped, "old_primary_during_loss": dcs_leader,
               "old_primary_pg_during_loss": role_history[-1]["nodes"][dcs_leader]["pg"],
               "nodes_during_loss": role_history[-1]["nodes"],
               "role_history_samples": len(role_history),
               "role_transitions": role_transitions[-10:],
               "standby_nodes_promoted_without_quorum": promoted_without_quorum,
               "promotion_without_quorum": bool(promoted_without_quorum),
               "old_primary_readonly_or_stopped": old_primary_readonly_or_stopped,
               "old_primary_states_after_demotion": old_primary_states_after_demotion[-5:],
               "endpoint_writes_rejected": post_demotion_rejected == post_demotion_probes,
               "api_during_quorum_loss": api_during_quorum_loss,
               "demotion_detection_seconds": round(demotion_detection_seconds, 2),
               "post_demotion_verification_window_seconds_target": 5.0,
               "post_demotion_verification_window_seconds_observed": round(post_demotion_window_seconds, 2),
               "post_demotion_write_probes": post_demotion_probes,
               "post_demotion_write_rejections": post_demotion_rejected,
               "valid_lease_write_probes_accepted": valid_lease_writes,
               "healthy_write_probe": {"accepted": healthy_write_accepted,
                                       "result": healthy_write_detail},
               "last_write_probe": {"accepted": last_probe["accepted"] if last_probe else None,
                                    "old_primary_pg": last_probe["old_primary_pg"] if last_probe else None,
                                    "result": (last_probe["detail"][:120] if last_probe else None)},
               "quorum_loss_detection_seconds": round(no_quorum_seconds, 2),
               "quorum_restored_writable_ms": round((dcs_recovered_at - dcs_loss_at) / 1e6, 1),
               "nodes_after_recovery": nodes_after_recovery,
               "recovered_primary": recovered_primary,
               "old_primary_recovered_as_primary": recovered_primary == dcs_leader,
               "endpoint_after_quorum": endpoint_after_quorum,
               "post_quorum_recovery_oid": dcs_oid}

        # ---- real backup closure and fresh-authority restore -------------
        # ---- genuine pinned CI job and issued plan before the backup ------
        ci_generation = int(h.sql("SELECT storage_generation FROM repositories WHERE id='" + h.repo["id"] + "'"))
        ci_target = acked[-1]["oid"]
        ci_job = str(uuid.uuid4())
        ci_pin_body = {"job_id": ci_job, "target_oid": ci_target, "storage_generation": ci_generation}
        ci_pin = json.loads(h.expect("/api/repos/alice/demo/ci-pins", (200, 201), token=h.alice,
                                     method="POST", body=ci_pin_body))
        assert ci_pin["job_id"] == ci_job and ci_pin["target_oid"] == ci_target
        ci_expires = int(time.time()) + 1800
        ci_grant = json.loads(h.expect("/api/repos/alice/demo/ci-checkouts", (200, 201), token=h.alice,
                                       method="POST", body={**ci_pin_body,
                                                           "mirror_audience": ci_audience,
                                                           "expires_unix": ci_expires}))
        ci_token = {"username": "alice", "token": ci_grant["token"]}
        h.secrets.extend([ci_grant["token"],
                          base64.b64encode(("alice:" + ci_grant["token"]).encode()).decode()])
        assert ci_grant["plan"]["job_id"] == ci_job
        assert ci_grant["plan"]["target_oid"] == ci_target
        assert ci_grant["plan"]["mirror_audience"] == ci_audience
        ci_source_state = h.sql("SELECT revoked::text || '|' || cancelled::text || '|' || expires_unix || "
                                "'|' || (plan->>'mirror_audience') FROM ci_checkout_jobs WHERE repository_id='"
                                + h.repo["id"] + "' AND job_id='" + ci_job + "'")
        ci_revoked, ci_cancelled, ci_expiry, ci_aud = ci_source_state.split("|", 3)
        assert ci_revoked == "false" and ci_cancelled == "false", ci_source_state
        assert int(ci_expiry) > int(time.time()) and ci_aud == ci_audience, ci_source_state
        ci_pin_file = Path(h.env["ROOTYARD_DATA_DIR"]) / "ci-pins" / h.repo["id"] / (ci_job + ".json")
        assert ci_pin_file.is_file(), "CI source pin descriptor missing before backup"
        ci_mirror_base = "http://127.0.0.1:" + str(free_port())
        ci_mirror_env = {**h.env, "ROOTYARD_BIND": ci_mirror_base.rsplit("/", 1)[-1],
                         "ROOTYARD_DATA_DIR": str(root / "source-mirror-data"),
                         "ROOTYARD_PRIMARY_URL": h.base,
                         "ROOTYARD_CI_MIRROR_AUDIENCE": ci_audience}
        ci_mirror_proc = ci_mirror_log = None
        try:
            ci_mirror_proc, ci_mirror_log = start_mirror(args.binary, ci_mirror_env,
                                                         root / "source-mirror.log", ci_mirror_base)
            status, body = mirror_http(ci_mirror_base, "/api/repos/alice/demo/mirror-sync",
                                       token=h.reader, method="POST", body=b"")
            assert status == 200, (status, body[:200])
            ci_clone = root / "ci-job-clone-before-backup"
            h.git("clone", ci_mirror_base + "/ci/" + ci_target + "/git/alice/demo.git",
                  str(ci_clone), token=ci_token)
            assert h.git("rev-parse", "HEAD", cwd=ci_clone).stdout.decode().strip() == ci_target
            h.git("fsck", "--full", cwd=ci_clone)
        finally:
            stop_mirror(ci_mirror_proc, ci_mirror_log)
        ci_before_backup = {"job_id": ci_job, "target_oid": ci_target,
                            "storage_generation": ci_generation,
                            "pin_descriptor_retained": True,
                            "grant_state": {"revoked": False, "cancelled": False,
                                            "expires_in_future": True,
                                            "mirror_audience_matches": True},
                            "job_token_clone_head": ci_target}

        pre_backup_counts = count_rows(h)
        pre_backup_pending = pending_keys(h.sql)
        assert pre_backup_pending, "no durable delivery backlog before the backup boundary"
        pre_backup_refs_map = ref_map(git_dir)
        pre_backup_refs = len(pre_backup_refs_map)
        pre_backup_main = pre_backup_refs_map.get("refs/heads/main")
        assert pre_backup_main, f"pre-backup refs/heads/main missing: {sorted(pre_backup_refs_map)}"
        pre_backup_oids = [item["oid"] for item in acked] + [post_oid, dcs_oid]
        pre_backup_authority = h.sql("SELECT incarnation::text FROM cluster_authority WHERE singleton=true")
        h.stop()
        backup_dir = root / "backup-set"
        backup_env = {**h.env, "DATABASE_URL": require_dsn,
                      "ROOTYARD_PG_CA_PEM": str(fx.pki / "ca.crt")}
        backup_env.pop("PGOPTIONS", None)
        started_backup = time.monotonic()
        subprocess.run([args.binary, "backup", str(backup_dir), "--offline"], env=backup_env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1200, check=True)
        verify_result = subprocess.run([args.binary, "backup-verify", str(backup_dir)], env=backup_env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600,
                                       check=True)
        backup_seconds = time.monotonic() - started_backup
        backup_verify = json.loads(verify_result.stdout.decode())
        manifest = json.loads((backup_dir / "manifest.json").read_text())
        backup_manifest = {"format": manifest.get("format"),
                           "schema_versions": manifest.get("schema_versions"),
                           "backup_id": manifest.get("backup_id"),
                           "rootyard_version": manifest.get("rootyard_version")}
        assert isinstance(backup_manifest["format"], int), backup_manifest
        assert isinstance(backup_manifest["schema_versions"], list) and backup_manifest["schema_versions"]
        assert backup_verify.get("checksums_verified") is True, backup_verify
        assert backup_verify.get("authenticity_verified") is False, backup_verify
        # An acknowledged write after the backup boundary must be absent from a
        # fresh-authority restore; it is measured disaster RPO, not zero.
        h.start()
        post_backup_oid, _ = push_commit("write after backup boundary", "after-boundary.txt")
        h.stop()
        post_boundary_refs = ref_map(git_dir)
        changed_refs = {ref for ref in set(pre_backup_refs_map) | set(post_boundary_refs)
                        if pre_backup_refs_map.get(ref) != post_boundary_refs.get(ref)}
        assert changed_refs == {"refs/heads/main"}, (
            f"post-boundary acknowledged write must only advance refs/heads/main: {changed_refs}")
        assert post_boundary_refs["refs/heads/main"] == post_backup_oid
        post_boundary_parent = h.git("--git-dir=" + git_dir, "rev-parse", post_backup_oid + "^")
        assert post_boundary_parent.stdout.decode().strip() == pre_backup_main, (
            "post-boundary commit does not extend the pre-backup acknowledged tip")
        assert len(post_boundary_refs) == pre_backup_refs, (
            "a committing write must not change the number of refs: "
            f"{pre_backup_refs} -> {len(post_boundary_refs)}")

        # Fresh, unused PostgreSQL 17 deployment for the restored authority.
        restored_pg_dir = root / "restored-pg"
        restored_pg_socket = root / "restored-socket"
        restored_pg_socket.mkdir(mode=0o700)
        ha_fixture.run(["initdb", "--no-instructions", "--auth=trust", "-U", "postgres",
                        "-D", str(restored_pg_dir)])
        (restored_pg_dir / "pg_hba.conf").write_text(
            "local all all trust\nlocal replication all trust\n"
            "hostssl all all 127.0.0.1/32 scram-sha-256\n"
            "hostssl replication all 127.0.0.1/32 scram-sha-256\n"
            "hostnossl all all 127.0.0.1/32 reject\n")
        with (restored_pg_dir / "postgresql.conf").open("a") as cfg:
            cfg.write(f"\nlisten_addresses='127.0.0.1'\nport={fx.ports['restored_pg']}\n"
                      f"unix_socket_directories='{restored_pg_socket}'\nssl=on\n"
                      f"ssl_cert_file='{fx.pki / 'server.crt'}'\nssl_key_file='{fx.pki / 'server.key'}'\n"
                      "ssl_min_protocol_version='TLSv1.3'\n")
        ha_fixture.run(["pg_ctl", "-D", str(restored_pg_dir), "-l", str(root / "restored-pg.log"),
                        "-w", "start"])
        restored_pg_started = True
        restored_db = "rootyard_restored"
        ha_fixture.run(["psql", "-h", str(restored_pg_socket), "-p", str(fx.ports["restored_pg"]),
                        "-U", "postgres", "-d", "postgres", "-X", "-v", "ON_ERROR_STOP=1", "-f", "-"],
                       data=(f"SET password_encryption='scram-sha-256';\n"
                             f"CREATE ROLE rootyard LOGIN CREATEDB PASSWORD '{fx.secrets['rootyard_password']}';\n"
                             f"CREATE DATABASE {restored_db} OWNER rootyard;\n").encode(),
                       env=fx.env())
        restored_require = (f"postgresql://rootyard:{fx.secrets['rootyard_password']}@127.0.0.1:"
                            f"{fx.ports['restored_pg']}/{restored_db}?sslmode=require")
        restored_verify = (f"postgresql://rootyard:{fx.secrets['rootyard_password']}@127.0.0.1:"
                           f"{fx.ports['restored_pg']}/{restored_db}?sslmode=verify-full&sslrootcert="
                           f"{fx.pki / 'ca.crt'}")
        restored_data = root / "restored-deployment-data"
        restore_env = {**fx.env(), "DATABASE_URL": restored_require,
                       "ROOTYARD_PG_CA_PEM": str(fx.pki / "ca.crt"),
                       "ROOTYARD_DATA_DIR": str(restored_data)}
        # Writes are held: no Rootyard process exists for the restored
        # authority until the offline checks below pass.
        assert not restored_data.exists()
        restore_started = time.monotonic()
        subprocess.run([args.binary, "restore", str(backup_dir), "--isolated", "--trust-backup"],
                       env=restore_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=1200, check=True)
        restore_seconds = time.monotonic() - restore_started
        restored_counts = {}
        restored_sql_env = {**fx.env(), "PGPASSWORD": fx.secrets["rootyard_password"],
                            "PGSSLMODE": "verify-full", "PGSSLROOTCERT": str(fx.pki / "ca.crt")}

        def restored_sql(query):
            result = ha_fixture.run(["psql", "-h", "127.0.0.1", "-p", str(fx.ports["restored_pg"]),
                                     "-U", "rootyard", "-d", restored_db, "-X", "-At", "-v",
                                     "ON_ERROR_STOP=1", "-c", query], env=restored_sql_env)
            return result.stdout.decode().strip()

        for table in TABLE_COUNTS:
            restored_counts[table] = int(restored_sql(f"SELECT COUNT(*) FROM {table}"))
        assert restored_counts == pre_backup_counts, (
            f"restored metadata counts differ: {restored_counts} != {pre_backup_counts}")
        # `rootyard restore --isolated` rotates the delegation authority and
        # clears transport nonces itself (src/backup/authority.rs); the test
        # must observe that behavior, not synthesize it with SQL.
        restored_authority = restored_sql(
            "SELECT incarnation::text FROM cluster_authority WHERE singleton=true")
        assert restored_authority and restored_authority != pre_backup_authority, (
            "restore --isolated did not rotate the delegation authority automatically")
        assert restored_sql("SELECT COUNT(*) FROM cluster_transport_nonces") == "0"
        assert restored_sql(
            "SELECT rotated_at IS NOT NULL FROM cluster_authority WHERE singleton=true") == "t"
        restored_repo = restored_data / "repos" / (h.repo["id"] + ".git")
        restored_refs_map = ref_map(str(restored_repo))
        assert restored_refs_map == pre_backup_refs_map, (
            "restored ref/OID map differs from the pre-backup closure: "
            f"source={sorted(pre_backup_refs_map.items())} restored={sorted(restored_refs_map.items())}")
        assert post_backup_oid not in set(restored_refs_map.values()), (
            "post-boundary acknowledged OID is reachable from a restored ref")
        assert ref_count(str(restored_repo)) == pre_backup_refs
        subprocess.run(["git", f"--git-dir={restored_repo}", "fsck", "--full", "--strict"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        for oid in pre_backup_oids:
            subprocess.run(["git", f"--git-dir={restored_repo}", "cat-file", "-e", oid + "^{commit}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        absent = subprocess.run(["git", f"--git-dir={restored_repo}", "cat-file", "-e",
                                 post_backup_oid + "^{commit}"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert absent.returncode != 0, "post-boundary write survived the offline backup closure"
        worker_restored = drain_deliveries(
            lambda: int(ha_fixture.run(
                [args.binary, "worker-once"],
                env={**restore_env, "DATABASE_URL": restored_require}).stdout.decode().strip()),
            restored_sql, pre_backup_pending)
        restored_states = delivery_states(restored_sql, pre_backup_pending)
        assert len(restored_states) == len(pre_backup_pending), (
            f"pre-backup deliveries missing from the restored authority: "
            f"{len(restored_states)}/{len(pre_backup_pending)}")
        restored_undelivered = sorted(key for key, state in restored_states.items()
                                      if state != "delivered")
        assert not restored_undelivered, (
            f"restored worker did not deliver retained deliveries: {restored_undelivered[:5]}")
        assert worker_restored > 0, "restored authority worker processed no retained deliveries"
        # Only now may the restored deployment open ingress.
        restored_bind = f"127.0.0.1:{fx.ports['restored_rootyard']}"
        restored = Harness(args)
        restored.env.update({"DATABASE_URL": restored_require, "ROOTYARD_DATA_DIR": str(restored_data),
                             "ROOTYARD_BIND": restored_bind,
                             "ROOTYARD_PG_CA_PEM": str(fx.pki / "ca.crt"),
                             "ROOTYARD_CI_MIRROR_AUDIENCE": ci_audience})
        restored.base_db = restored_verify
        restored.db = restored_verify
        restored.base = "http://" + restored_bind
        restored.repo = h.repo
        restored.remote = restored.base + h.repo["clone_path"]
        restored.work = h.work
        restored.copy = h.copy
        restored.start()
        clone = root / "restored-clone"
        restored.git("clone", restored.remote, str(clone), token=h.reader)
        restored.git("fsck", "--full", "--strict", cwd=clone)
        clone_tip = restored.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip()
        assert clone_tip in set(pre_backup_oids)
        clone_history = set(restored.git("rev-list", "HEAD", cwd=clone).stdout.decode().splitlines())
        assert set(pre_backup_oids) <= clone_history
        assert post_backup_oid not in clone_history
        assert restored.http("/api/repos/alice/demo", token=revoked)[0] == 401
        assert restored.http("/api/repos/alice/demo", token=h.bob)[0] in (403, 404)
        assert restored.http("/api/repos/alice/demo", token=h.reader)[0] == 200
        # ---- restored authority revokes the old CI grant; new fenced plan ---
        ci_state_after = restored_sql(
            "SELECT revoked::text || '|' || cancelled::text || '|' || expires_unix || '|' || "
            "(plan->>'mirror_audience') FROM ci_checkout_jobs WHERE job_id='" + ci_job + "'")
        r_revoked, r_cancelled, r_expiry, r_audience = ci_state_after.split("|", 3)
        assert r_revoked == "true", ci_state_after
        assert r_cancelled == "false", ci_state_after
        assert int(r_expiry) > int(time.time()), "old grant denial must not be expiry"
        assert r_audience == ci_audience, "old grant denial must not be audience/config"
        assert (restored_data / "ci-pins" / h.repo["id"] / (ci_job + ".json")).is_file(),             "historical CI source pin was not retained by the restore"
        restored_mirror_base = "http://127.0.0.1:" + str(free_port())
        restored_mirror_env = {**restored.env,
                               "ROOTYARD_BIND": restored_mirror_base.rsplit("/", 1)[-1],
                               "ROOTYARD_DATA_DIR": str(root / "restored-mirror-data"),
                               "ROOTYARD_PRIMARY_URL": restored.base,
                               "ROOTYARD_CI_MIRROR_AUDIENCE": ci_audience}
        restored_mirror_proc = restored_mirror_log = None
        try:
            restored_mirror_proc, restored_mirror_log = start_mirror(
                args.binary, restored_mirror_env, root / "restored-mirror.log", restored_mirror_base)
            status, body = mirror_http(restored_mirror_base,
                                       "/api/repos/alice/demo/mirror-sync",
                                       token=h.reader, method="POST", body=b"")
            assert status == 200, (status, body[:200])
            old_status, old_body = mirror_http(
                restored_mirror_base, "/ci/" + ci_target
                + "/git/alice/demo.git/info/refs?service=git-upload-pack", token=ci_token)
            assert old_status in (401, 403), (old_status, old_body[:200])
            new_job = str(uuid.uuid4())
            new_pin_body = {"job_id": new_job, "target_oid": ci_target,
                            "storage_generation": ci_generation}
            new_pin = json.loads(restored.expect("/api/repos/alice/demo/ci-pins", (200, 201),
                                                 token=h.alice, method="POST", body=new_pin_body))
            assert new_pin["job_id"] == new_job
            new_grant = json.loads(restored.expect(
                "/api/repos/alice/demo/ci-checkouts", (200, 201), token=h.alice, method="POST",
                body={**new_pin_body, "mirror_audience": ci_audience,
                      "expires_unix": int(time.time()) + 1800}))
            new_token = {"username": "alice", "token": new_grant["token"]}
            h.secrets.extend([new_grant["token"],
                              base64.b64encode(("alice:" + new_grant["token"]).encode()).decode()])
            new_clone = root / "ci-job-clone-restored"
            restored.git("clone", restored_mirror_base + "/ci/" + ci_target
                         + "/git/alice/demo.git", str(new_clone), token=new_token)
            new_head = restored.git("rev-parse", "HEAD", cwd=new_clone).stdout.decode().strip()
            assert new_head == ci_target
            restored.git("fsck", "--full", cwd=new_clone)
            new_state = restored_sql(
                "SELECT revoked::text FROM ci_checkout_jobs WHERE job_id='" + new_job + "'")
            assert new_state == "false", new_state
            job_revocation = {
                "old_job_id": ci_job, "target_oid": ci_target,
                "old_grant_active_before_backup": True,
                "old_grant_automatically_revoked_by_restore": True,
                "old_grant_cancelled": False,
                "old_grant_expiry_still_future": True,
                "old_grant_audience_unchanged": True,
                "old_token_http_status": old_status,
                "historical_pin_descriptor_retained": True,
                "new_job_id": new_job, "new_grant_revoked": False,
                "new_checkout_head": new_head, "new_checkout_fsck": "passed",
                "source_and_restore_mirror_audience_configured": True,
            }
        finally:
            stop_mirror(restored_mirror_proc, restored_mirror_log)
        restored.git("fetch", restored.remote, "refs/heads/main", cwd=clone, token=h.reader)
        restored.git("reset", "--hard", "FETCH_HEAD", cwd=clone)
        (clone / "restored.txt").write_text("new write on restored authority\n")
        restored.git("add", "restored.txt", cwd=clone)
        restored.git("commit", "-m", "write on restored authority", cwd=clone)
        restored_tip = restored.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip()
        restored.git("push", "origin", "HEAD:main", cwd=clone, token=h.alice)
        assert restored.git("ls-remote", restored.remote, "main", token=h.reader).stdout.decode().startswith(
            restored_tip)
        restore = {
            "backup_closure_seconds": round(backup_seconds, 2),
            "restore_seconds": round(restore_seconds, 2),
            "source_counts": pre_backup_counts, "restored_counts": restored_counts,
            "backup_manifest": backup_manifest, "backup_verify": backup_verify,
            "authority": {"source_incarnation": pre_backup_authority,
                          "restored_incarnation": restored_authority,
                          "rotated_automatically_by_restore": True,
                          "transport_nonces_cleared": True},
            "job_before_backup": ci_before_backup,
            "job_revocation": job_revocation,
            "source_refs": pre_backup_refs, "restored_refs": ref_count(str(restored_repo)),
            "source_ref_map": pre_backup_refs_map, "restored_ref_map": restored_refs_map,
            "restored_ref_map_equals_source": restored_refs_map == pre_backup_refs_map,
            "post_boundary_ref_change": {"ref": "refs/heads/main",
                                         "before": pre_backup_main, "after": post_backup_oid,
                                         "parent": pre_backup_main,
                                         "ref_count_unchanged": len(post_boundary_refs) == pre_backup_refs},
            "retained_acknowledged_oids": pre_backup_oids,
            "post_boundary_oid_intentionally_absent": post_backup_oid,
            "delegation_authority_rotated_by_restore": True,
            "worker_drained_before_ingress": worker_restored,
            "pre_backup_delivery_ids": len(pre_backup_pending),
            "pre_backup_deliveries_delivered": len(restored_states) - len(restored_undelivered),
            "worker_accounting": "exact pre-backup (event_id,consumer) identity set on the restored "
                                 "authority; global pending total excluded",
            "restored_endpoint": restored_bind, "restored_new_data_directory": str(restored_data),
            "writes_held_until_offline_checks_passed": True,
            "reader_access_and_token_revocation_and_tenant_denial": "passed",
            "git_fsck": "passed", "restored_push_oid": restored_tip,
        }

        total_seconds = time.monotonic() - started
        report = ops_provenance.base(
            args.binary, __file__,
            topology=("one Linux host: 3 etcd members with mutual TLS, 3 Patroni-managed PostgreSQL 17 nodes "
                      "with TLS/SCRAM and strict synchronous_mode, 1 HAProxy stable primary endpoint, "
                      "1 Rootyard server on the stable endpoint; no second physical host and no hardware watchdog"),
            dataset=("one private repository with acknowledged Git pushes before the crash, a post-failover "
                     "push, an observed DCS-quorum-loss probe and a real "
                     f"format-{backup_manifest["format"]} (schema {backup_manifest["schema_versions"]}) "
                     "backup/restore closure derived from the verified manifest"),
            workload=("native Git clone/push/fetch/fsck and HTTP browse through the stable primary endpoint; "
                      "complete old primary node (Patroni + unmanaged postmaster session) hard-killed; automatic "
                      "Patroni promotion without pg_ctl promote; two-of-three etcd quorum loss; offline backup and "
                      "fresh-deployment restore with ingress held until checks pass"),
            limits=[
                "single Linux host for all etcd and PostgreSQL nodes; same kernel, no cross-host/rack/zone claim",
                "no hardware watchdog or physical fencing available; production profile rejects such a host",
                "process/port/session crash injection, not power loss or kernel network partitions",
                "two-of-three etcd quorum loss on one host, not a multi-host network partition",
                "HAProxy is a single local stable-endpoint process; its own failover is out of scope",
                "restore target is a fresh local PostgreSQL 17 cluster with a local unencrypted backup closure",
                "single-broker Kafka and multi-broker failover are not covered by this run",
            ])
        report.update({
            "kind": "native_external_patroni_etcd_haproxy_failover_and_restore",
            "supported_stack": {"dcs": "etcd v3.5.17 (3 members, mutual TLS)",
                                "ha_controller": "Patroni 4.0.4",
                                "stable_endpoint": "HAProxy 3.0.11 role-health routing",
                                "database": "PostgreSQL 17"},
            "physical_scope": {"hosts": 1, "cross_host_failover": False, "hardware_watchdog": False,
                               "production_certified": False,
                               "note": "same-host process scope only; production requires real fencing"},
            "configuration": {"rendered_by": "deployment/ha/render.py", "environment": "lab",
                              "synchronous_commit": synchronous["synchronous_commit"],
                              "synchronous_standby_names": synchronous["synchronous_standby_names"],
                              "synchronous_standbys": synchronous["synchronous_standbys"],
                              "postgres_tls": "verify-full + SCRAM-SHA-256, ssl_min_protocol_version TLSv1.3",
                              "dcs_tls": "mutual TLS with client certificate authentication",
                              "patroni_rest": negative["patroni_rest_authentication"],
                              "negative_gates": negative, "tls_negative_runtime": tls_negative,
                              "role_attributes": role_attrs},
            "baseline": baseline,
            "automatic_failover": failover,
            "dcs_quorum_loss": dcs,
            "replica_endpoint": {"before_promotion": replica_before,
                                 "after_promotion": replica_after,
                                 "tls_scram_verified": "sslmode=verify-full plus SCRAM through the replica frontend",
                                 "primary_excluded_from_replica_backend": True},
            "rpo": {"lost_acknowledged_commits_after_automatic_promotion": len(missing),
                    "acked_commits_verified": len(acked)},
            "rto": {"read_ms": round((read_recovered_at - crashed) / 1e6, 1),
                    "write_ms": round((write_recovered_at - crashed) / 1e6, 1),
                    "rootyard_ready_ms": round((health_at - crashed) / 1e6, 1)},
            "restore": restore,
            "total_pipeline_seconds": round(total_seconds, 1),
        })
        args.report.parent.mkdir(parents=True, exist_ok=True)
        temp = args.report.with_suffix(".tmp")
        temp.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temp, args.report)
        print(json.dumps({"result": "passed", "report": str(args.report),
                          "rto_write_ms": report["rto"]["write_ms"],
                          "failover_seconds": round((promoted_at - crashed) / 1e9, 2)}))
        results.append("passed")
    finally:
        try:
            if h:
                h.cleanup()
            if restored:
                restored.stop()
                if not args.keep:
                    shutil.rmtree(restored.root, ignore_errors=True)
        finally:
            fx.stop()
            if restored_pg_started:
                subprocess.run(["pg_ctl", "-D", str(root / "restored-pg"), "-m", "immediate", "stop"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            os.environ.clear()
            os.environ.update(old_env)
            if not args.keep:
                shutil.rmtree(root, ignore_errors=True)
    return 0 if results else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:  # noqa: BLE001 - redact any accidental credential text
        print(redact(f"FAILED: {type(error).__name__}: {error}", []), file=sys.stderr)
        raise
