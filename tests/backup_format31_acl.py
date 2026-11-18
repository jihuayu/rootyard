#!/usr/bin/env python3
"""Opt-in format 31/ACL drill for the GitHub-hosted job's PostgreSQL 17 service.

Use the CI loopback service coordinate and a source-bound prebuilt Rootyard
CLI. The only output is one bounded JSON report on stdout.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import uuid

from backup import BackupHarness
from schema_baseline import ROOT, SCHEMA_VERSIONS
import source_bound_binary


CASES = ("format31_metadata_roundtrip", "public_execute_refused_before_publication", "restored_cancellation_acl")
SIGNATURE = "public.rootyard_ref_store_private_cancellation_evidence()"
ACL_SQL = f"""
SELECT p.prosecdef, p.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype,
       pg_catalog.has_function_privilege(p.proowner, p.oid, 'EXECUTE'),
       pg_catalog.has_function_privilege('pg_read_all_data', p.oid, 'EXECUTE'),
       EXISTS (SELECT FROM pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
               WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')
FROM pg_catalog.pg_proc p WHERE p.oid = pg_catalog.to_regprocedure('{SIGNATURE}')
"""
RESTRICTED = "t|t|t|f|f"
PUBLIC = "t|t|t|t|t"
MAX_OUTPUT = 16 * 1024


def require(ok):
    if not ok:
        raise RuntimeError("qualification assertion failed")


def fixture_coordinates(environ):
    require(environ.get("GITHUB_ACTIONS") == "true" and environ.get("RUNNER_ENVIRONMENT") == "github-hosted")
    admin = environ.get("ROOTYARD_TEST_DATABASE_URL", "")
    url = urlsplit(admin)
    require(url.scheme == "postgresql" and url.hostname == "127.0.0.1" and url.port == 55432
            and url.username == "rootyard" and url.path == "/rootyard_test"
            and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", url.password or "")
            and not url.query and not url.fragment and "?" not in admin and "#" not in admin)
    temp = Path(environ["RUNNER_TEMP"])
    require(temp.is_absolute() and temp.is_dir() and temp.resolve() == temp
            and temp != ROOT and ROOT not in temp.parents)
    return url.geturl(), temp


def run_bounded(argv, *, env, deadline, timeout=60, cwd=None):
    end = min(deadline, time.monotonic() + timeout)
    require(end > time.monotonic())
    child = subprocess.Popen(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    output = bytearray()
    settled = False
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            while True:
                left = end - time.monotonic()
                require(left > 0 and ready.select(left))
                block = os.read(child.stdout.fileno(), MAX_OUTPUT + 1 - len(output))
                if not block:
                    break
                output.extend(block)
                require(len(output) <= MAX_OUTPUT)
        left = end - time.monotonic()
        require(left > 0)
        code = child.wait(timeout=left)
        settled = True
        return subprocess.CompletedProcess(argv, code, bytes(output))
    finally:
        child.stdout.close()
        if not settled:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)


def child_env(environ):
    return {"PATH": environ["PATH"], "LC_ALL": "C", "PGSSLMODE": "disable", "PGCONNECT_TIMEOUT": "5",
            "PGOPTIONS": "-c statement_timeout=6000 -c lock_timeout=5000",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}


def capture_binding(binary, expected, env, deadline):
    require(re.fullmatch(r"[0-9a-f]{40}", expected))

    def git(*args):
        proc = run_bounded(["git", *args], env=env, cwd=ROOT, deadline=deadline)
        require(proc.returncode == 0)
        return proc.stdout.decode().strip()

    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    require(head == expected and re.fullmatch(r"[0-9a-f]{40}", tree))
    require(not git("status", "--porcelain=v1", "--untracked-files=all"))
    evidence = source_bound_binary.bind(binary, expected_commit=expected)
    require(evidence["attested"] is True and evidence["workspace_commit"] == head
            and evidence["current_head"] == head and evidence["production_inputs_bound"] is True
            and evidence["receipt_immutable"] is True
            and evidence["receipt_binary_sha256"] == evidence["binary_sha256"])
    keys = ("binary_sha256", "receipt_sha256", "source_inputs_sha256")
    require(all(re.fullmatch(r"[0-9a-f]{64}", evidence[key]) for key in keys))
    return {"source_head": head, "source_tree": tree, **{key: evidence[key] for key in keys}}


def archive_manifest(archive, binary_sha):
    require({path.name for path in archive.iterdir()} == {"COMPLETE", "manifest.json", "metadata.dump", "volume", "pando"})
    with (archive / "manifest.json").open("rb") as stream:
        raw = stream.read(MAX_OUTPUT + 1)
    require(len(raw) <= MAX_OUTPUT)
    manifest = json.loads(raw)
    require(manifest["format"] == 31 and max(SCHEMA_VERSIONS) == 152
            and manifest["schema_versions"] == SCHEMA_VERSIONS and manifest["binary_sha256"] == binary_sha
            and manifest["repositories"] == [] and manifest["lfs_objects"] == []
            and not {"blob_closure", "blob_artifacts", "refstore"} & manifest.keys())
    return manifest


class Format31Harness(BackupHarness):
    def __init__(self, binary, admin, root, env, work_deadline, cleanup_deadline):
        self.args = argparse.Namespace(binary=str(binary))
        self.root = root
        self.admin = admin
        self.env = {**env, "TMPDIR": str(root), "ROOTYARD_DATA_DIR": str(root / "data")}
        self.deadline = work_deadline
        self.cleanup_deadline = cleanup_deadline
        self.created = []
        self.backup = root / "backup"
        self.target = root / "restored-data"

    def run(self, argv, *, env=None, check=True):
        result = run_bounded(argv, env=self.env if env is None else env,
                             deadline=self.deadline, timeout=10 if argv[0] == "psql" else 60)
        require(not check or result.returncode == 0)
        return result

    def database_exists(self, name):
        require(re.fullmatch(r"rootyard_b31_[0-9a-f]{32}", name))
        result = self.query(self.admin, f"SELECT EXISTS (SELECT FROM pg_database WHERE datname='{name}')")
        require(result in ("t", "f"))
        return result == "t"

    def new_database(self, admin):
        require(admin == self.admin)
        name = "rootyard_b31_" + uuid.uuid4().hex
        require(not self.database_exists(name))
        self.created.append(name)
        self.query(admin, f'CREATE DATABASE "{name}" TEMPLATE template0')
        return urlsplit(admin)._replace(path="/" + name).geturl()

    def prepare(self):
        for tool in ("psql", "pg_dump", "pg_restore"):
            version = self.run([tool, "--version"]).stdout.strip()
            require(re.fullmatch(tool.encode() + rb" \(PostgreSQL\) 17\.[0-9]+(?: [^\r\n]+)?", version))
        version = self.query(self.admin, "SHOW server_version_num")
        require(re.fullmatch(r"17[0-9]{4}", version))
        require(self.query(self.admin, "SELECT current_database() = 'rootyard_test' AND session_user = 'rootyard'") == "t")
        self.source_db = self.new_database(self.admin)
        self.target_db = self.new_database(self.admin)
        self.env["DATABASE_URL"] = self.source_db
        self.cli("reconcile")
        require(self.query(self.source_db, ACL_SQL) == RESTRICTED)

    def refuse_public_execute(self, binary_sha):
        control = self.root / "control-backup"
        self.backup_command(control)
        archive_manifest(control, binary_sha)
        before = {path.name for path in self.root.iterdir()}
        require(not os.path.lexists(self.backup))
        try:
            self.query(self.source_db, f"GRANT EXECUTE ON FUNCTION {SIGNATURE} TO PUBLIC")
            require(self.query(self.source_db, ACL_SQL) == PUBLIC)
            refused = self.backup_command(check=False)
            require(refused.returncode == 1 and refused.stdout == b"" and not os.path.lexists(self.backup)
                    and {path.name for path in self.root.iterdir()} == before)
        finally:
            deadline = self.deadline
            self.deadline = self.cleanup_deadline
            try:
                self.query(self.source_db, f"REVOKE EXECUTE ON FUNCTION {SIGNATURE} FROM PUBLIC")
                require(self.query(self.source_db, ACL_SQL) == RESTRICTED)
            finally:
                self.deadline = deadline

    def roundtrip_archive(self, binary_sha):
        self.backup_command()
        manifest = archive_manifest(self.backup, binary_sha)
        checked = json.loads(self.cli("backup-verify", str(self.backup)))
        require(checked["checksums_verified"] is True and checked["backup_id"] == manifest["backup_id"])
        restored = json.loads(self.restore_command().stdout)
        require(restored["restored"] is True and restored["started_service"] is False
                and restored["backup_id"] == manifest["backup_id"] and restored["blob_artifacts"] == 0)
        require((self.target / ".volume-id").read_bytes() == manifest["volume_id"].encode())
        roster = self.query(self.target_db, "SELECT version FROM public.schema_migrations ORDER BY version")
        require(roster.splitlines() == [str(version) for version in SCHEMA_VERSIONS])

    def cleanup(self):
        self.deadline = self.cleanup_deadline
        removed = True
        for name in reversed(self.created):
            try:
                require(re.fullmatch(r"rootyard_b31_[0-9a-f]{32}", name))
                self.query(self.admin, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
                removed &= not self.database_exists(name)
            except Exception:
                removed = False
        return removed


def qualify(args, environ):
    deadline = time.monotonic() + 180
    cleanup_deadline = deadline + 75
    passed = set()
    identity = None
    harness = None
    root = None
    cleaned = False
    rebound = False
    failure = "preflight"
    try:
        require(args.job_owned_postgres)
        admin, temp = fixture_coordinates(environ)
        env = child_env(environ)
        binary = Path(args.binary).resolve(strict=True)
        identity = capture_binding(binary, args.expected_commit, env, deadline)
        failure = "setup"
        root = Path(tempfile.mkdtemp(prefix="rootyard-format31-", dir=temp))
        harness = Format31Harness(binary, admin, root, env, deadline, cleanup_deadline)
        harness.prepare()
        failure = "acl_refusal"
        harness.refuse_public_execute(identity["binary_sha256"])
        passed.add(CASES[1])
        failure = "archive_roundtrip"
        harness.roundtrip_archive(identity["binary_sha256"])
        passed.add(CASES[0])
        failure = "restored_acl"
        require(harness.query(harness.target_db, ACL_SQL) == RESTRICTED)
        passed.add(CASES[2])
        failure = None
    except Exception:
        pass
    finally:
        if root is not None:
            databases_removed = False
            try:
                databases_removed = harness is None or harness.cleanup()
            except Exception:
                pass
            try:
                shutil.rmtree(root)
                cleaned = databases_removed and not os.path.lexists(root)
            except Exception:
                pass
            if not cleaned and failure is None:
                failure = "owned_cleanup"
        if identity is not None:
            try:
                current = Path(args.binary).resolve(strict=True)
                rebound = current == binary and capture_binding(current, args.expected_commit, env, cleanup_deadline) == identity
            except Exception:
                pass
            if not rebound and failure is None:
                failure = "post_binding"
    return {"schema": "rootyard/issue42-format31-acl/v1", "passed": failure is None, "failure_phase": failure,
            **(identity or {}), "binding_rechecked": rebound, "owned_cleanup_verified": cleaned,
            "cases": [{"name": name, "status": "passed" if name in passed else "failed"} for name in CASES]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--job-owned-postgres", action="store_true")
    args = parser.parse_args(argv)

    def interrupted(_signum, _frame):
        raise InterruptedError("qualification interrupted")

    handlers = {signum: signal.signal(signum, interrupted) for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        report = qualify(args, os.environ)
    finally:
        for signum, previous in handlers.items():
            signal.signal(signum, previous)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
