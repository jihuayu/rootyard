#!/usr/bin/env python3
"""Generate catalog receipts from real fresh, dump/restored, and upgraded DBs.

Creates and drops only random databases owned by this invocation. Requires a
dedicated PostgreSQL role with CREATEDB and ROOTYARD_TEST_DATABASE_URL. No copied
prior fixture is used as proof of a new migration.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.parse
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--legacy-binary", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    base = os.environ["ROOTYARD_TEST_DATABASE_URL"]
    parts = urllib.parse.urlsplit(base)
    if parts.query:
        parser.error("Use a dedicated database URL without query options")
    latest = max(int(p.name.split("_")[0]) for p in (args.root / "migrations").glob("*.sql"))
    query = (args.root / "schema/060_catalog.sql").read_text()
    created = []

    def run(command, database=base, **kwargs):
        env = os.environ.copy()
        env["DATABASE_URL"] = database
        if command[0] in ("psql", "pg_dump"):
            command = [command[0], "--dbname", database, *command[1:]]
        result = subprocess.run(command, env=env, capture_output=True, timeout=120, **kwargs)
        if result.returncode:
            error = result.stderr.decode(errors="replace").replace(base, "[DATABASE_URL]").replace(database, "[DATABASE_URL]")
            raise RuntimeError(error[-3000:])
        return result.stdout

    def database():
        name = "rootyard_catalog_" + uuid.uuid4().hex
        run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-c", f'CREATE DATABASE "{name}"'])
        created.append(name)
        return urllib.parse.urlunsplit(parts._replace(path="/" + name))

    def capture(database_url, suffix):
        data = json.loads(run(["psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-c", "SET search_path=pg_catalog;" + query], database_url))
        path = args.root / "schema" / f"{latest:03d}_{suffix}.json"
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        print(path)

    try:
        with tempfile.TemporaryDirectory(prefix="rootyard-catalog-") as directory:
            root = Path(directory)
            fresh = database()
            run([str(args.binary.resolve()), "migrate"], fresh)
            capture(fresh, "catalog")
            dump = root / "fresh.dump"
            run(["pg_dump", "--format=custom", "--file", str(dump)], fresh)
            restored = database()
            run(["pg_restore", "--dbname", restored, "--exit-on-error", str(dump)], restored)
            capture(restored, "restored_catalog")
            if args.legacy_binary:
                upgraded = database()
                run([str(args.legacy_binary.resolve()), "migrate"], upgraded)
                run([str(args.binary.resolve()), "migrate"], upgraded)
                capture(upgraded, "upgraded_catalog")
            (args.root / "schema" / f"{latest:03d}_catalog.sql").write_text(query)
            # The accepted upgraded fixture is specifically a restored schema003
            # upgrade. An in-place schema060 upgrade has a different PostgreSQL
            # CHECK-expression parse tree. Exercise both, then regenerate the
            # canonical fixture from the documented legacy restore paths.
            subprocess.run([sys.executable, str(args.root / "tests/schema_contract.py"),
                            "--binary", str(args.binary.resolve()), "--write"],
                           cwd=args.root, check=True)
    finally:
        for name in reversed(created):
            run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-c", f'DROP DATABASE "{name}" WITH (FORCE)'])


if __name__ == "__main__":
    main()
