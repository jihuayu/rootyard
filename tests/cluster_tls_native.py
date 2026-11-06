#!/usr/bin/env python3
"""Start PostgreSQL 17 with TLS and prove Rootyard validates CA and hostname."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
from urllib.parse import quote


def run(args, env=None, check=True, data=None):
    result = subprocess.run(args, env=env, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    if check and result.returncode:
        raise AssertionError(f"{args[0]} failed ({result.returncode}): {result.stderr.decode(errors='replace')[-800:]}")
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="rootyard-pg-tls-"))
    data = root / "pgdata"
    port = free_port()
    started = False
    try:
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"),
             "-subj", "/CN=Rootyard test CA", "-addext", "basicConstraints=critical,CA:TRUE"])
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"),
             "-subj", "/CN=localhost"])
        (root / "leaf.ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n")
        run(["openssl", "x509", "-req", "-in", str(root / "server.csr"),
             "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial",
             "-out", str(root / "server.crt"), "-days", "1", "-extfile", str(root / "leaf.ext")])
        (root / "server.key").chmod(0o600)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(root / "wrong.key"), "-out", str(root / "wrong.crt"),
             "-subj", "/CN=wrong", "-addext", "subjectAltName=DNS:wrong"])
        run(["initdb", "--no-instructions", "--auth=trust", "-D", str(data)])
        (data / "pg_hba.conf").write_text(
            "local all all trust\n"
            "hostssl all all 127.0.0.1/32 scram-sha-256\n"
            "hostssl all all ::1/128 scram-sha-256\n"
            "hostnossl all all 127.0.0.1/32 reject\n"
            "hostnossl all all ::1/128 reject\n")
        with (data / "postgresql.conf").open("a") as cfg:
            cfg.write(f"\nlisten_addresses='127.0.0.1'\nport={port}\nunix_socket_directories='{root}'\nssl=on\n"
                      f"ssl_cert_file='{root / 'server.crt'}'\nssl_key_file='{root / 'server.key'}'\n")
        startup = run(["pg_ctl", "-D", str(data), "-l", str(root / "postgres.log"), "start"], check=False)
        if startup.returncode:
            raise AssertionError((root / "postgres.log").read_text(errors="replace")[-1600:])
        started = True
        password = secrets.token_urlsafe(24)
        run(["psql", "--host", str(root), "--port", str(port), "--dbname", "postgres",
             "-X", "-v", "ON_ERROR_STOP=1", "-f", "-"],
            data=("SET password_encryption='scram-sha-256';\nALTER ROLE agent PASSWORD '" + password + "';\n").encode())
        env = os.environ.copy()
        env["DATABASE_URL"] = f"postgresql://agent:{quote(password)}@localhost:{port}/postgres?sslmode=require"
        env["ROOTYARD_PG_CA_PEM"] = str(root / "ca.crt")
        env["ROOTYARD_DATA_DIR"] = str(root / "storage")
        env["ROOTYARD_OUTBOX_WORKER"] = "false"
        binary = str(args.binary.resolve())
        run([binary, "migrate"], env=env)
        pg_env = env.copy()
        pg_env["PGSSLROOTCERT"] = str(root / "ca.crt")
        pg_env["PGPASSWORD"] = password
        observed = run(["psql", f"postgresql://agent@localhost:{port}/postgres?sslmode=verify-full",
                        "-X", "-At", "-c", "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"], env=pg_env)
        assert observed.stdout.decode().strip() == "t", "PostgreSQL did not negotiate TLS"
        wrong_password = env.copy()
        wrong_password["DATABASE_URL"] = f"postgresql://agent:wrong@localhost:{port}/postgres?sslmode=require"
        assert run([binary, "migrate"], env=wrong_password, check=False).returncode != 0
        bad_ca = env.copy()
        bad_ca["ROOTYARD_PG_CA_PEM"] = str(root / "wrong.crt")
        assert run([binary, "migrate"], env=bad_ca, check=False).returncode != 0
        bad_host = env.copy()
        bad_host["DATABASE_URL"] = f"postgresql://agent:{quote(password)}@127.0.0.1:{port}/postgres?sslmode=require"
        assert run([binary, "migrate"], env=bad_host, check=False).returncode != 0
        downgraded = env.copy()
        downgraded["DATABASE_URL"] = f"postgresql://agent:{quote(password)}@localhost:{port}/postgres?sslmode=disable"
        assert run([binary, "migrate"], env=downgraded, check=False).returncode != 0
        report = {"kind": "native_postgresql_tls", "postgres_version": "17", "encrypted": True,
                  "scram_sha256_authenticated": True, "wrong_password_rejected": True,
                  "ca_validation_rejected_wrong_root": True, "hostname_validation_rejected_ip_mismatch": True,
                  "explicit_downgrade_rejected": True, "binary": binary}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "passed", "report": str(args.report)}))
    finally:
        if started:
            run(["pg_ctl", "-D", str(data), "-m", "immediate", "stop"], check=False)
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
