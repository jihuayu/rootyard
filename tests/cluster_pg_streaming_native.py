#!/usr/bin/env python3
"""Real PostgreSQL 17 streaming standby, synchronous ACKs, manual promote, Git recovery."""
import argparse
import hashlib
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

        def read_loop():
            while not stop_reads.is_set():
                try:
                    code, _, _ = h.http("/api/repos/alice/demo", token=h.reader)
                    read_events.append(code)
                except (OSError, urllib.error.URLError):
                    read_events.append(0)
                time.sleep(.05)
        reader = threading.Thread(target=read_loop, daemon=True)
        reader.start()
        time.sleep(.2)
        failure_at = time.monotonic_ns()
        run(["pg_ctl", "-D", str(primary), "-m", "immediate", "stop"])
        started_primary = False
        until = time.monotonic() + 8
        while time.monotonic() < until and not any(code != 200 for code in read_events):
            time.sleep(.1)
        stop_reads.set()
        reader.join(timeout=5)
        assert any(code != 200 for code in read_events), "metadata loss did not affect live service"
        h.stop(hard=True)
        run(["pg_ctl", "-D", str(standby), "-w", "promote"])
        assert sql(s_port, root, "SELECT pg_is_in_recovery()") == "f"
        h.env["DATABASE_URL"] = h.db = h.db.replace(f":{p_port}/", f":{s_port}/")
        h.base_db = standby_url
        h.start()
        h.git("fetch", h.base + h.repo["clone_path"], "refs/heads/main", cwd=h.copy, token=h.reader)
        read_recovered_at = time.monotonic_ns()
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == ack
        (h.work / "hello.txt").write_text("write after streaming standby promotion\n")
        h.git("commit", "-am", "post PostgreSQL promote", cwd=h.work)
        new_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
        write_recovered_at = time.monotonic_ns()
        h.git("fetch", h.base + h.repo["clone_path"], "refs/heads/main", cwd=h.copy, token=h.reader)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == new_tip
        report = {"kind": "native_postgresql_streaming_promote", "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                  "postgres_version": sql(s_port, root, "SHOW server_version"), "synchronous_commit": observed_commit,
                  "standby_sync_state_before_failure": "sync", "postgresql_failure": "pg_ctl immediate stop",
                  "read_statuses_during_failure": read_events, "acknowledged_oid_before_failure": ack,
                  "rpo_lost_acknowledged_commits": 0,
                  "rto_read_ms": round((read_recovered_at - failure_at) / 1e6, 3),
                  "rto_write_ms": round((write_recovered_at - failure_at) / 1e6, 3),
                  "post_promote_oid": new_tip, "standby_promoted": True,
                  "limits": ["manual local-host PostgreSQL promotion and Rootyard restart", "no DCS/elected automatic PG leader",
                             "no tested PITR/archive restore", "no cross-host storage fencing"]}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "passed", "report": str(args.report), "rto_write_ms": report["rto_write_ms"]}))
    finally:
        stop_reads.set()
        if reader:
            reader.join(timeout=5)
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
