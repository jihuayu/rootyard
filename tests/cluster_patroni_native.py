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
import json
import os
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

TABLE_COUNTS = ("repositories", "git_operations", "tokens", "outbox_events", "event_deliveries")


def redact(text, secrets):
    for value in secrets:
        text = text.replace(str(value), "[REDACTED]")
    return text


def count_rows(h):
    counts = {}
    for table in TABLE_COUNTS:
        counts[table] = int(h.sql(f"SELECT COUNT(*) FROM {table}"))
    return counts


def ref_count(git_dir):
    result = subprocess.run(["git", f"--git-dir={git_dir}", "for-each-ref", "--format=%(refname)"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return len(result.stdout.decode().split())


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
        assert fx.sql(leader, "SELECT pg_is_in_recovery()") == "f"
        rest_unauth = fx.rest(leader, auth=False)
        assert rest_unauth[0] == 401, "Patroni REST health endpoint accepted unauthenticated access"
        rest_auth = fx.rest(leader)
        assert rest_auth[0] == 200
        negative["patroni_rest_authentication"] = {"unauthenticated": rest_unauth[0],
                                                   "authenticated": rest_auth[0]}
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
        h.env.update({"DATABASE_URL": require_dsn, "ROOTYARD_PG_CA_PEM": str(fx.pki / "ca.crt"),
                      "PGSSLMODE": "verify-full", "PGSSLROOTCERT": str(fx.pki / "ca.crt")})
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
        pending_before = int(h.sql("SELECT COUNT(*) FROM event_deliveries WHERE state <> 'delivered'"))
        assert outbox_before > 0 and pending_before > 0, "fixture produced no durable worker backlog"

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
        rootyard_pid = h.proc.pid

        # ---- hard crash of the complete old primary node -----------------
        old_primary = fx.leader()
        old_port = fx.pg_port(old_primary)
        assert fx.endpoint_sql("SELECT pg_is_in_recovery() || ':' || inet_server_port()") == "f:" + str(old_port)
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
                    if fx.endpoint_sql("SELECT pg_is_in_recovery()", timeout=6).strip() == "f":
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
        assert fx.endpoint_sql("SELECT pg_is_in_recovery() || ':' || inet_server_port()") == (
            "f:" + str(fx.pg_port(successor)))
        assert h.http("/api/repos/alice/demo", token=revoked)[0] == 401
        assert h.http("/api/repos/alice/demo", token=h.bob)[0] in (403, 404)
        worker_processed = int(h.cli("worker-once"))
        pending_after = int(h.sql("SELECT COUNT(*) FROM event_deliveries WHERE state <> 'delivered'"))
        assert worker_processed > 0 and pending_after < pending_before, (
            f"worker backlog did not advance after failover: processed={worker_processed} "
            f"pending={pending_after}/{pending_before}")
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
            "pending_deliveries_before": pending_before, "pending_deliveries_after": pending_after,
            "rootyard_pid_before": rootyard_pid, "rootyard_pid_after": h.proc.pid,
            "rootyard_health_statuses": health_statuses,
            "promotion_log_excerpt": promotion_log,
            "post_promotion_oid": post_oid,
            "endpoint_primary_pg_port_before": old_port,
            "endpoint_primary_pg_port_after": fx.pg_port(successor),
        }
        assert not missing

        # ---- DCS quorum loss: no unsafe promotion, old PG read-only ------
        dcs_leader = fx.leader()
        stopped = [node["name"] for node in fx.spec["etcd"]["nodes"][:2]]
        dcs_loss_at = time.monotonic_ns()
        fx.stop_etcd(stopped)
        readonly_observed = False
        endpoint_write_rejected = False
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                state = fx.sql(dcs_leader, "SELECT pg_is_in_recovery()")
                if state == "t":
                    readonly_observed = True
            except AssertionError:
                readonly_observed = True  # demoted node stopped PostgreSQL entirely
            try:
                fx.endpoint_sql("CREATE TEMP TABLE ha43_probe(x int)")
            except AssertionError:
                endpoint_write_rejected = True
            if readonly_observed and endpoint_write_rejected:
                break
            time.sleep(0.5)
        assert readonly_observed, "old primary stayed writable while the DCS quorum was lost"
        assert endpoint_write_rejected, "stable endpoint accepted writes without a DCS quorum"
        try:
            h.http("/api/repos/alice/demo", token=h.reader)
            api_during_partition = "200"
        except (OSError, urllib.error.URLError):
            api_during_partition = "unreachable"
        try:
            push_commit("must not be acknowledged without a DCS quorum", "no-quorum.txt")
            raise AssertionError("Git push succeeded while the DCS quorum was lost")
        except AssertionError as error:
            if "must not be acknowledged" in str(error):
                raise
        no_quorum_seconds = (time.monotonic_ns() - dcs_loss_at) / 1e9
        fx.start_etcd_members(stopped)
        dcs_recovered_at = None
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                if fx.endpoint_sql("SELECT pg_is_in_recovery()", timeout=6).strip() == "f":
                    dcs_recovered_at = time.monotonic_ns()
                    break
            except AssertionError:
                pass
            time.sleep(0.5)
        assert dcs_recovered_at, "cluster did not regain a writable primary after the DCS quorum returned"
        dcs_oid, _ = push_commit("write after DCS quorum recovery", "post-quorum.txt")
        dcs = {"stopped_etcd_members": stopped, "old_primary_during_loss": dcs_leader,
               "old_primary_readonly_or_stopped": readonly_observed,
               "endpoint_writes_rejected": endpoint_write_rejected,
               "promotion_without_quorum": False, "api_during_quorum_loss": api_during_partition,
               "quorum_loss_detection_seconds": round(no_quorum_seconds, 2),
               "quorum_restored_writable_ms": round((dcs_recovered_at - dcs_loss_at) / 1e6, 1),
               "post_quorum_recovery_oid": dcs_oid}

        # ---- real backup closure and fresh-authority restore -------------
        pre_backup_counts = count_rows(h)
        pre_backup_refs = ref_count(git_dir)
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
        subprocess.run([args.binary, "backup-verify", str(backup_dir)], env=backup_env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=True)
        backup_seconds = time.monotonic() - started_backup
        # An acknowledged write after the backup boundary must be absent from a
        # fresh-authority restore; it is measured disaster RPO, not zero.
        h.start()
        post_backup_oid, _ = push_commit("write after backup boundary", "after-boundary.txt")
        h.stop()
        assert ref_count(git_dir) == pre_backup_refs + 1

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
        assert restored_sql("SELECT incarnation::text FROM cluster_authority WHERE singleton=true") == \
            pre_backup_authority
        restored_sql("BEGIN; UPDATE cluster_authority SET incarnation=gen_random_uuid(), "
                     "rotated_at=clock_timestamp() WHERE singleton=true; "
                     "DELETE FROM cluster_transport_nonces; COMMIT;")
        assert restored_sql("SELECT incarnation::text FROM cluster_authority WHERE singleton=true") != \
            pre_backup_authority
        restored_repo = restored_data / "repos" / (h.repo["id"] + ".git")
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
        worker_restored = int(ha_fixture.run(
            [args.binary, "worker-once"],
            env={**restore_env, "DATABASE_URL": restored_require}).stdout.decode().strip())
        pending_restored = int(restored_sql("SELECT COUNT(*) FROM event_deliveries WHERE state <> 'delivered'"))
        assert worker_restored > 0 and pending_restored == 0, (
            f"restored authority worker did not drain retained deliveries: {worker_restored}/{pending_restored}")
        # Only now may the restored deployment open ingress.
        restored_bind = f"127.0.0.1:{fx.ports['restored_rootyard']}"
        restored = Harness(args)
        restored.env.update({"DATABASE_URL": restored_require, "ROOTYARD_DATA_DIR": str(restored_data),
                             "ROOTYARD_BIND": restored_bind,
                             "ROOTYARD_PG_CA_PEM": str(fx.pki / "ca.crt")})
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
            "source_refs": pre_backup_refs, "restored_refs": ref_count(str(restored_repo)),
            "retained_acknowledged_oids": pre_backup_oids,
            "post_boundary_oid_intentionally_absent": post_backup_oid,
            "delegation_authority_rotated_before_ingress": True,
            "worker_drained_before_ingress": worker_restored,
            "pending_deliveries_after_restore": pending_restored,
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
                     "push, a DCS-quorum-loss probe and a real format-7 backup/restore closure"),
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
