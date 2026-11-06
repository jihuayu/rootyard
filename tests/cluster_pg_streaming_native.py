#!/usr/bin/env python3
"""Real PostgreSQL 17 streaming standby, synchronous ACKs, manual promote, Git recovery."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
from urllib.parse import quote

from e2e import Harness
import ops_provenance


def run(args, env=None, data=None, check=True):
    result = subprocess.run(args, env=env, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    if check and result.returncode:
        raise AssertionError(f"{args[0]} failed: {result.stderr.decode(errors='replace')[-800:]}")
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def sql(port, root, query):
    return run(["psql", "--host", str(root), "--port", str(port), "--dbname", "postgres",
                "-X", "-At", "-v", "ON_ERROR_STOP=1", "-c", query]).stdout.decode().strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    root = Path(tempfile.mkdtemp(prefix="rootyard-pg-streaming-"))
    primary, standby = root / "primary", root / "standby"
    p_port, s_port = free_port(), free_port()
    h = None
    old_env = os.environ.copy()
    started_primary = started_standby = False
    stop_reads = threading.Event()
    read_events = []
    reader = None
    stop_writes = threading.Event()
    load_acked = []
    load_failures = []
    writer = None
    try:
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"),
             "-subj", "/CN=Rootyard streaming test CA", "-addext", "basicConstraints=critical,CA:TRUE"])
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"), "-subj", "/CN=localhost"])
        (root / "leaf.ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n")
        run(["openssl", "x509", "-req", "-in", str(root / "server.csr"),
             "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial",
             "-out", str(root / "server.crt"), "-days", "1", "-extfile", str(root / "leaf.ext")])
        (root / "server.key").chmod(0o600)
        run(["initdb", "--no-instructions", "--auth=trust", "-D", str(primary)])
        (primary / "pg_hba.conf").write_text(
            "local all all trust\n"
            "hostssl replication repl 127.0.0.1/32 scram-sha-256\n"
            "hostssl replication repl ::1/128 scram-sha-256\n"
            "hostssl all all 127.0.0.1/32 scram-sha-256\n"
            "hostssl all all ::1/128 scram-sha-256\n"
            "hostnossl all all 127.0.0.1/32 reject\n")
        with (primary / "postgresql.conf").open("a") as cfg:
            cfg.write(f"\nlisten_addresses='127.0.0.1'\nport={p_port}\nunix_socket_directories='{root}'\n"
                      "wal_level=replica\nmax_wal_senders=5\nmax_replication_slots=5\nhot_standby=on\n"
                      "synchronous_commit=remote_apply\nssl=on\n"
                      f"ssl_cert_file='{root / 'server.crt'}'\nssl_key_file='{root / 'server.key'}'\n")
        run(["pg_ctl", "-D", str(primary), "-l", str(root / "primary.log"), "start"])
        started_primary = True
        db_password, repl_password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        run(["psql", "--host", str(root), "--port", str(p_port), "--dbname", "postgres",
             "-X", "-v", "ON_ERROR_STOP=1", "-f", "-"],
            data=("SET password_encryption='scram-sha-256';\nALTER ROLE agent PASSWORD '" + db_password
                  + "';\nCREATE ROLE repl WITH REPLICATION LOGIN PASSWORD '" + repl_password + "';\n").encode())
        replication_env = os.environ.copy()
        replication_env.update(PGPASSWORD=repl_password, PGSSLMODE="verify-full", PGSSLROOTCERT=str(root / "ca.crt"))
        run(["pg_basebackup", "-h", "localhost", "-p", str(p_port), "-U", "repl", "-D", str(standby),
             "-X", "stream", "-R", "--checkpoint=fast"], env=replication_env)
        with (standby / "postgresql.conf").open("a") as cfg:
            cfg.write(f"\nport={s_port}\nsynchronous_standby_names=''\n")
        with (standby / "postgresql.auto.conf").open("a") as cfg:
            cfg.write("\nprimary_conninfo = 'host=localhost port=" + str(p_port) + " user=repl password="
                      + repl_password + " sslmode=verify-full sslrootcert=" + str(root / "ca.crt")
                      + " application_name=standby1'\n")
        run(["pg_ctl", "-D", str(standby), "-l", str(root / "standby.log"), "start"])
        started_standby = True
        sql(p_port, root, "ALTER SYSTEM SET synchronous_standby_names TO 'standby1'")
        sql(p_port, root, "SELECT pg_reload_conf()")
        until = time.monotonic() + 20
        while time.monotonic() < until:
            if sql(p_port, root, "SELECT count(*) FROM pg_stat_replication WHERE application_name='standby1' AND sync_state='sync'") == "1":
                break
            time.sleep(.1)
        else:
            raise AssertionError("synchronous PostgreSQL standby did not connect")
        observed_commit = sql(p_port, root, "SHOW synchronous_commit")
        assert observed_commit == "remote_apply", "primary is not synchronously applying standby WAL"

        primary_url = f"postgresql://agent:{quote(db_password)}@localhost:{p_port}/postgres?sslmode=require"
        standby_url = f"postgresql://agent:{quote(db_password)}@localhost:{s_port}/postgres?sslmode=require"
        os.environ.update(ROOTYARD_TEST_DATABASE_URL=primary_url, ROOTYARD_PG_CA_PEM=str(root / "ca.crt"),
                          PGSSLROOTCERT=str(root / "ca.crt"), ROOTYARD_OUTBOX_WORKER="false")
        h = Harness(args)
        h.setup()
        h.api()
        h.roundtrip()
        ack = h.second
        assert sql(s_port, root, "SELECT pg_is_in_recovery()") == "t"

        load_work = h.root / "write-load"
        h.git("clone", h.remote, str(load_work), token=h.alice)
        h.git("config", "user.name", "Streaming Load", cwd=load_work)
        h.git("config", "user.email", "streaming-load@example.invalid", cwd=load_work)

        def write_loop():
            index = 0
            while not stop_writes.is_set():
                try:
                    (load_work / "load.txt").write_text(f"streaming load {index}\n")
                    h.git("add", "load.txt", cwd=load_work)
                    h.git("commit", "-m", f"streaming load {index}", cwd=load_work)
                    oid = h.git("rev-parse", "HEAD", cwd=load_work).stdout.decode().strip()
                    h.git("push", "origin", "HEAD:main", cwd=load_work, token=h.alice)
                    load_acked.append(oid)
                except Exception as error:
                    load_failures.append(str(error)[:240])
                    time.sleep(.02)
                index += 1

        def read_loop():
            while not stop_reads.is_set():
                try:
                    code, _, _ = h.http("/api/repos/alice/demo", token=h.reader)
                    read_events.append(code)
                except (OSError, urllib.error.URLError):
                    read_events.append(0)
                time.sleep(.05)
        writer = threading.Thread(target=write_loop, daemon=True)
        writer.start()
        reader = threading.Thread(target=read_loop, daemon=True)
        reader.start()
        deadline = time.monotonic() + 30
        while len(load_acked) < 3 and time.monotonic() < deadline:
            time.sleep(.1)
        assert len(load_acked) >= 3, (
            f"only {len(load_acked)} acknowledged writes under concurrent load before failure; "
            + "; ".join(load_failures[:2]))
        acknowledged_before_failure = list(load_acked)
        time.sleep(.1)
        failure_at = time.monotonic_ns()
        run(["pg_ctl", "-D", str(primary), "-m", "immediate", "stop"])
        started_primary = False
        until = time.monotonic() + 8
        while time.monotonic() < until and not any(code != 200 for code in read_events):
            time.sleep(.1)
        stop_reads.set()
        stop_writes.set()
        reader.join(timeout=5)
        if writer:
            writer.join(timeout=15)
        assert any(code != 200 for code in read_events), "metadata loss did not affect live service"
        assert len(acknowledged_before_failure) >= 1, "write load produced no acknowledged operation"
        h.stop(hard=True)
        run(["pg_ctl", "-D", str(standby), "-w", "promote"])
        assert sql(s_port, root, "SELECT pg_is_in_recovery()") == "f"
        h.env["DATABASE_URL"] = h.db = h.db.replace(f":{p_port}/", f":{s_port}/")
        h.base_db = standby_url
        h.start()
        read_statuses_after_restart = []
        repository_path = h.repo["clone_path"] + "/info/refs?service=git-upload-pack"
        for _ in range(50):
            status, _, _ = h.http(repository_path, token=h.reader)
            read_statuses_after_restart.append(status)
            if status == 200:
                break
            time.sleep(.1)
        repository_state = h.sql("SELECT state || ':' || COALESCE(recovery_reason,'') "
                                  "FROM repositories WHERE id='" + h.repo["id"] + "'")
        operator_recovery = {"repository_state_after_promotion_restart": repository_state,
                             "http_statuses_after_promotion_restart": read_statuses_after_restart,
                             "required": repository_state != "ready:"}
        assert read_statuses_after_restart[-1] in (200, 503), read_statuses_after_restart
        if operator_recovery["required"]:
            # An in-flight native writer interrupted by metadata loss is an
            # intentionally unknown outcome.  The service must fail closed
            # until an operator explicitly acknowledges the audit gap offline.
            assert read_statuses_after_restart[-1] == 503, read_statuses_after_restart
            h.stop()
            inspection = json.loads(h.cli("inspect-recovery", h.repo["id"]))
            assert inspection["state"] == "recovering" and inspection["unknown_operations"]
            resolution = h.cli("resolve-unknown", h.repo["id"],
                               "--expected-generation", str(inspection["storage_generation"]),
                               "--fingerprint", inspection["fingerprint"],
                               "--acknowledge-audit-gap",
                               "streaming failover drill: unacknowledged in-flight push")
            operator_recovery["inspection_unknown_operations"] = len(inspection["unknown_operations"])
            operator_recovery["resolution"] = json.loads(resolution) if resolution else None
            h.start()
            for _ in range(50):
                status, _, _ = h.http(repository_path, token=h.reader)
                if status == 200:
                    break
                time.sleep(.1)
            assert status == 200, "repository did not reopen after explicit unknown-operation resolution"
        h.git("fetch", h.base + h.repo["clone_path"], "refs/heads/main", cwd=h.copy, token=h.reader)
        read_recovered_at = time.monotonic_ns()
        fetched_tip = h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip()
        fetched_history = set(h.git("rev-list", "FETCH_HEAD", cwd=h.copy).stdout.decode().splitlines())
        assert ack in fetched_history, "pre-failure acknowledged commit is not in the promoted history"
        assert fetched_tip in ({ack} | set(acknowledged_before_failure)), (
            "promoted ref contains an unacknowledged in-flight push: " + fetched_tip)
        # The concurrent load advanced main after this checkout was cloned.
        # Rebase the post-failure write on the acknowledged surviving tip.
        h.git("fetch", "origin", cwd=h.work, token=h.reader)
        h.git("reset", "--hard", "FETCH_HEAD", cwd=h.work)
        (h.work / "hello.txt").write_text("write after streaming standby promotion\n")
        h.git("commit", "-am", "post PostgreSQL promote", cwd=h.work)
        new_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
        write_recovered_at = time.monotonic_ns()
        h.git("fetch", h.base + h.repo["clone_path"], "refs/heads/main", cwd=h.copy, token=h.reader)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == new_tip
        history = set(h.git("rev-list", "FETCH_HEAD", cwd=h.copy).stdout.decode().splitlines())
        missing_load = [oid for oid in acknowledged_before_failure if oid not in history]
        assert not missing_load, "acknowledged write under load was lost after promotion"
        report = ops_provenance.base(
            args.binary, __file__,
            topology="one Rootyard writer, separate PostgreSQL 17 primary and synchronous streaming standby, real TLS/SCRAM",
            dataset="one private repository with an initial push plus concurrent one-file Git pushes during primary failure",
            workload="continuous native Git reads plus native Git push commits while the synchronous primary is stopped; manual standby promotion and Rootyard restart",
            limits=["manual local-host PostgreSQL promotion and Rootyard restart",
                    "no DCS/elected automatic PG leader and no automatic client reconfiguration",
                    "PITR/archive restore tested separately, not integrated with standby promotion",
                    "no cross-host storage fencing; old primary is stopped, not fenced by a shared DCS"])
        report.update({
                  "kind": "native_postgresql_streaming_promote",
                  "postgres_version": sql(s_port, root, "SHOW server_version"), "synchronous_commit": observed_commit,
                  "standby_sync_state_before_failure": "sync", "postgresql_failure": "pg_ctl immediate stop",
                  "read_statuses_during_failure": read_events,
                  "acknowledged_oid_before_failure": ack,
                  "operator_recovery": operator_recovery,
                  "write_load": {"acknowledged_before_failure": len(acknowledged_before_failure),
                                 "failed_or_unacknowledged_during_outage": len(load_failures),
                                 "acknowledged_oids": acknowledged_before_failure,
                                 "failure_excerpt": load_failures[:3]},
                  "rpo_lost_acknowledged_commits": 0,
                  "rpo_lost_acknowledged_writes_under_load": len(missing_load),
                  "rto_read_ms": round((read_recovered_at - failure_at) / 1e6, 3),
                  "rto_write_ms": round((write_recovered_at - failure_at) / 1e6, 3),
                  "post_promote_oid": new_tip, "standby_promoted": True})
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "passed", "report": str(args.report), "rto_write_ms": report["rto_write_ms"]}))
    finally:
        stop_reads.set()
        stop_writes.set()
        if reader:
            reader.join(timeout=5)
        if writer:
            writer.join(timeout=15)
        if h:
            h.cleanup()
        os.environ.clear()
        os.environ.update(old_env)
        if started_standby:
            run(["pg_ctl", "-D", str(standby), "-m", "immediate", "stop"], check=False)
        if started_primary:
            run(["pg_ctl", "-D", str(primary), "-m", "immediate", "stop"], check=False)
        if not args.keep:
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
