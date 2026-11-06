#!/usr/bin/env python3
"""Native Smart HTTP push with a managed hook using PostgreSQL TLS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from cluster_tls_native import free_port, run
from e2e import Harness


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    root = Path(tempfile.mkdtemp(prefix="rootyard-tls-push-"))
    data = root / "pgdata"
    port = free_port()
    started = False
    harness = None
    original = {name: os.environ.get(name) for name in
                ("ROOTYARD_TEST_DATABASE_URL", "ROOTYARD_PG_CA_PEM", "PGSSLROOTCERT")}
    try:
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"),
             "-subj", "/CN=Rootyard test CA", "-addext", "basicConstraints=critical,CA:TRUE"])
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"),
             "-subj", "/CN=localhost"])
        (root / "leaf.ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n")
        run(["openssl", "x509", "-req", "-in", str(root / "server.csr"),
             "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"),
             "-CAcreateserial", "-out", str(root / "server.crt"), "-days", "1",
             "-extfile", str(root / "leaf.ext")])
        (root / "server.key").chmod(0o600)
        run(["initdb", "--no-instructions", "--auth=trust", "-D", str(data)])
        with (data / "postgresql.conf").open("a") as config:
            config.write(f"\nlisten_addresses='127.0.0.1'\nport={port}\n"
                         f"unix_socket_directories='{root}'\nssl=on\n"
                         f"ssl_cert_file='{root / 'server.crt'}'\n"
                         f"ssl_key_file='{root / 'server.key'}'\n")
        result = run(["pg_ctl", "-D", str(data), "-l", str(root / "postgres.log"), "start"], check=False)
        if result.returncode:
            raise AssertionError((root / "postgres.log").read_text(errors="replace")[-1000:])
        started = True
        os.environ["ROOTYARD_TEST_DATABASE_URL"] = f"postgresql://agent@localhost:{port}/postgres?sslmode=require"
        os.environ["ROOTYARD_PG_CA_PEM"] = str(root / "ca.crt")
        os.environ["PGSSLROOTCERT"] = str(root / "ca.crt")
        harness = Harness(args)
        harness.setup()
        harness.api()
        harness.roundtrip()
        head = harness.git("--git-dir=" + str(harness.bare), "rev-parse", "refs/heads/main").stdout.decode().strip()
        assert head == harness.second, "native hook did not publish TLS-backed push"
        report = {"passed": True, "git_push_with_tls_hook": True,
                  "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(args.report)
    finally:
        if harness is not None:
            harness.cleanup()
        if started:
            run(["pg_ctl", "-D", str(data), "-m", "immediate", "stop"], check=False)
        shutil.rmtree(root)
        for name, value in original.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


if __name__ == "__main__":
    sys.exit(main())
