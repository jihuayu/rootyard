#!/usr/bin/env python3
"""Bounded evidence driver for the Issue 42 native hosted slot-zero workflow.

The workflow qualifies only the unswitched library layer.  It does not change
the production path and does not claim the original #42 acceptance.

This module owns three deliberately small pieces:

* a strict parser for one libtest invocation;
* receipt/provenance projection that keeps only allowlisted fields; and
* the CLI orchestration used by the hosted workflow (psql and git calls).

The parser and the projector are pure and are exercised by
``tests/test_issue42_native_hosted_slot0.py`` without a database, Cargo, the
network or a real receipt.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import subprocess
import sys
import time

SCHEMA = "rootyard/issue42-native-hosted-slot0/v1"
QUALIFICATION_REF = "refs/heads/codex/goal-issue42-original-ac-source-audit-20261117"
WORKFLOW_PATH = ".github/workflows/issue42-native-hosted-slot0-postgres.yml"
CARGO_FORK = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
CARGO_RELEASE = "1.101.0"
RUSTC_RELEASE = "1.99.1"
TARGET = "x86_64-unknown-linux-gnu"
CASE_TIMEOUT_SECONDS = 180
CASE_DEADLINE_SECONDS = 900
OUTPUT_LIMIT = 65536
REPORT_LIMIT = 8192
JOB_TIMEOUT_MINUTES = 110
DATABASE_PREFIX = "slot0_native_"
SLOT_ZERO_DATABASE = re.compile(r"slot_zero_[0-9a-f]{32}")
DATABASE_FULL = re.compile(rf"{DATABASE_PREFIX}[0-9a-f]{{32}}")
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
FORBIDDEN_KEY = {
    "command", "commands", "environment", "env", "path", "paths", "directory",
    "workdir", "stdout", "stderr", "log", "logs", "url", "dsn", "database_url",
    "receipt", "receipts", "raw", "output",
}
FORBIDDEN_TEXT = re.compile(
    r"(?:/Users/|/home/|/tmp/|/runner/|/workspace/|postgres(?:ql)?://|"
    r"\$RUNNER|@127\.0\.0\.1|password=|BEGIN [A-Z ]*PRIVATE KEY)",
    re.IGNORECASE,
)

INTEGRATION = "ref_store_operations"
LIB = "slot_zero_lib"
ALL_CASES = (
    (INTEGRATION, "fresh_lane_creation_waits_for_an_uncommitted_creator", True),
    (LIB, "ref_store::pg::slot_zero::tests::slot_zero_admission_commits_then_exact_retry_replays", True),
    (LIB, "ref_store::pg::slot_zero::tests::slot_zero_rejects_equal_ids_private_conflict_and_wire_rebinding", True),
    (LIB, "ref_store::pg::slot_zero::tests::slot_zero_replay_rejects_missing_or_wrong_producer_binding", True),
    (LIB, "ref_store::pg::slot_zero::tests::slot_zero_rollback_leaves_no_sequence_or_half_binding_and_rejects_overflow", True),
    (LIB, "ref_store::pg::slot_zero::tests::slot_zero_request_rejects_equal_ids_and_noncanonical_backend", False),
    (LIB, "ref_store::pg::slot_zero::tests::slot_zero_proof_binds_sequence_plan_and_wire", False),
)
TOOLCHAIN_EXPECTATION = {
    "cargo": {"release": CARGO_RELEASE, "commit_hash": CARGO_FORK},
    "rustc": {"release": RUSTC_RELEASE},
}

RUNNING = re.compile(r"^running (\d+) tests?$")
TEST_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)$")
SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in [0-9.]+s$"
)


class EvidenceError(ValueError):
    """A failed qualification check with a fixed, non-secret class."""

    def __init__(self, kind, message="qualification check failed"):
        super().__init__(message)
        self.kind = kind


def require(condition, kind):
    if not condition:
        raise EvidenceError(kind)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def expected_command(kind):
    """The exact command ``build_native_test.py`` records for each target."""
    base = [
        "cargo",
        "--config", "profile.dev.package.rootyard.debug=0",
        "--config", "profile.test.package.rootyard.debug=0",
        "--config", 'profile.dev.package.rootyard.strip="debuginfo"',
        "--config", 'profile.test.package.rootyard.strip="debuginfo"',
    ]
    if kind == "integration":
        return base + [
            "rustc", "--locked", "--profile", "test", "--test", INTEGRATION,
            "--features", "pando-lab", "--no-default-features",
            "--message-format=json-render-diagnostics", "--jobs", "2",
        ]
    require(kind == "lib", "invalid-kind")
    return base + [
        "test", "--locked", "--no-default-features", "--features", "pando-lab",
        "--lib", "--no-run", "--message-format=json-render-diagnostics", "--jobs", "2",
    ]


def parse_case_output(raw, expected_name):
    """Require exactly one executed, passed, non-ignored test with that name."""
    require(isinstance(raw, (bytes, bytearray)), "invalid-output")
    require(len(raw) <= OUTPUT_LIMIT, "output-too-large")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("non-utf8-output") from error
    require("\x00" not in text and "\x1b" not in text, "invalid-output")
    lines = text.splitlines()
    running = [line for line in lines if RUNNING.match(line)]
    tests = [TEST_LINE.match(line) for line in lines if TEST_LINE.match(line)]
    results = [SUMMARY.match(line) for line in lines if SUMMARY.match(line)]
    require(len(running) == 1 and int(RUNNING.match(running[0]).group(1)) == 1, "case-count")
    require(len(tests) == 1, "case-count")
    name, status = tests[0].group(1), tests[0].group(2)
    require(name == expected_name, "case-name")
    require(status == "ok", "case-status")
    require(len(results) == 1, "case-summary")
    result = results[0]
    require(result.group(1) == "ok", "case-status")
    counts = {
        "passed": int(result.group(2)),
        "failed": int(result.group(3)),
        "ignored": int(result.group(4)),
        "measured": int(result.group(5)),
        "filtered_out": int(result.group(6)),
    }
    require(counts["passed"] == 1, "case-count")
    require(counts["failed"] == 0 and counts["ignored"] == 0 and counts["measured"] == 0, "case-status")
    return {"name": name, "status": "passed", **counts}


def receipt_summary(loader, *, receipt_path, binary_path, source_root, product_commit,
                    product_tree, kind):
    """Validate one v2 receipt with trust anchors and return allowlisted fields."""
    expected = expected_command(kind)
    result = loader(
        Path(receipt_path),
        source_root=Path(source_root),
        binary_path=Path(binary_path),
        expected_commit=product_commit,
        expected_command=expected,
        expected_toolchain=TOOLCHAIN_EXPECTATION,
        verify_source_files=True,
    )
    require(result.schema == "v2", "receipt-schema")
    payload = result.payload
    require(payload.get("kind") == ("rust-integration-test" if kind == "integration" else "rust-library-test"),
            "receipt-kind")
    require(payload.get("git_head") == product_commit, "receipt-head")
    require(payload.get("working_tree") == {"tree": product_tree, "status": ""}, "receipt-tree")
    require(payload.get("features") == {"enabled": ["pando-lab"], "no_default_features": True},
            "receipt-features")
    require(payload.get("profile") == "test" and payload.get("target_triple") == TARGET, "receipt-profile")
    require(payload.get("relocated_artifact") is True, "receipt-relocation")

    toolchain = payload.get("toolchain") or {}
    cargo, rustc = toolchain.get("cargo") or {}, toolchain.get("rustc") or {}
    require(cargo.get("release") == CARGO_RELEASE and cargo.get("commit_hash") == CARGO_FORK,
            "receipt-cargo")
    require(rustc.get("release") == RUSTC_RELEASE, "receipt-rustc")

    binary_sha256 = sha256_file(binary_path)
    require(result.binary_sha256 == binary_sha256, "receipt-binary")
    require(payload.get("original_artifact_sha256") == binary_sha256, "receipt-original")
    require(HEX64.fullmatch(result.receipt_sha256 or ""), "receipt-digest")
    require(payload.get("cargo_lock_sha256") == sha256_file(Path(source_root) / "Cargo.lock"),
            "receipt-lock")
    bound = payload.get("bound_inputs") or {}
    require(HEX64.fullmatch(bound.get("digest") or ""), "receipt-bound")

    lock_sha256 = payload["cargo_lock_sha256"]
    if kind == "integration":
        source = Path(source_root) / "tests" / (INTEGRATION + ".rs")
        require(payload.get("integration_test_source") == source.relative_to(source_root).as_posix(),
                "receipt-source")
        require(payload.get("integration_test_source_sha256") == sha256_file(source),
                "receipt-source")
        test_closure_sha256 = payload["integration_test_source_sha256"]
    else:
        test_closure_sha256 = payload.get("lib_test_support_inputs_sha256")
        require(HEX64.fullmatch(test_closure_sha256 or ""), "receipt-support")

    summary = {
        "kind": payload["kind"],
        "binary_sha256": binary_sha256,
        "receipt_sha256": result.receipt_sha256,
        "source_inputs_sha256": result.source_inputs_sha256,
        "config_digest": result.config_digest,
        "bound_inputs_sha256": bound["digest"],
        "cargo_lock_sha256": lock_sha256,
        "test_closure_sha256": test_closure_sha256,
        "command_sha256": sha256_bytes(canonical(expected)),
    }
    require(HEX64.fullmatch(summary["config_digest"] or ""), "receipt-config")
    summary["summary_sha256"] = sha256_bytes(canonical(summary))
    return summary


def _git(root, *args):
    try:
        process = subprocess.run(
            ["git", "-C", str(root), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError("source") from error
    if process.returncode != 0:
        raise EvidenceError("source")
    return process.stdout.decode("utf-8").strip()


def _git_ok(root, *args):
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def verify_sources(workflow_source, product, environ):
    """Bind the workflow checkout and the second, exact product checkout."""
    workflow_source, product = Path(workflow_source), Path(product)
    expected_product = environ.get("PRODUCT_SHA", "")
    expected_tree = environ.get("PRODUCT_TREE", "")
    require(environ.get("GITHUB_EVENT_NAME") == "push", "event")
    require(environ.get("GITHUB_REF") == QUALIFICATION_REF, "ref")
    require(environ.get("GITHUB_WORKFLOW_REF")
            == f"{environ.get('GITHUB_REPOSITORY')}/{WORKFLOW_PATH}@{QUALIFICATION_REF}", "workflow-ref")
    require(environ.get("GITHUB_WORKFLOW_SHA") == environ.get("GITHUB_SHA"), "workflow-sha")
    require(HEX40.fullmatch(expected_product or "") and HEX40.fullmatch(expected_tree or ""), "pin")

    head = _git(workflow_source, "rev-parse", "HEAD")
    tree = _git(workflow_source, "rev-parse", "HEAD^{tree}")
    require(head == environ.get("GITHUB_SHA") and _git(workflow_source, "status", "--porcelain=v1",
                                                       "--untracked-files=all") == "", "workflow-clean")
    try:
        committed = subprocess.run(
            ["git", "-C", str(workflow_source), "show", f"HEAD:{WORKFLOW_PATH}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise EvidenceError("source") from error
    require(sha256_file(workflow_source / WORKFLOW_PATH) == sha256_bytes(committed), "workflow-bytes")

    product_head = _git(product, "rev-parse", "HEAD")
    product_tree = _git(product, "rev-parse", "HEAD^{tree}")
    require(product_head == expected_product and product_tree == expected_tree, "product-pin")
    require(_git(product, "status", "--porcelain=v1", "--untracked-files=all") == "", "product-clean")
    require(_git_ok(workflow_source, "cat-file", "-e", expected_product + "^{commit}"), "product-missing")
    require(_git_ok(workflow_source, "merge-base", "--is-ancestor", expected_product, head), "product-unreachable")
    require(_git(workflow_source, "rev-parse", expected_product + "^{tree}") == expected_tree, "product-tree")

    return {
        "repository": environ.get("GITHUB_REPOSITORY", ""),
        "ref": QUALIFICATION_REF,
        "run_id": int(environ.get("GITHUB_RUN_ID", "0")),
        "run_attempt": int(environ.get("GITHUB_RUN_ATTEMPT", "0")),
        "workflow_path": WORKFLOW_PATH,
        "workflow_commit": head,
        "workflow_tree": tree,
        "workflow_sha256": sha256_file(workflow_source / WORKFLOW_PATH),
        "event_head": environ.get("GITHUB_SHA", ""),
        "event_tree": tree,
        "product_commit": product_head,
        "product_tree": product_tree,
        "product_clean": True,
        "product_reachable": True,
        "cargo_lock_sha256": sha256_file(product / "Cargo.lock"),
    }


def expected_rows(statuses, observed=None):
    observed = observed or {}
    rows = []
    for target, name, ignored in ALL_CASES:
        key = (target, name)
        rows.append({
            "target": target,
            "name": name,
            "ignored": ignored,
            "status": statuses.get(key, "not_run"),
            "observed": observed.get(key),
        })
    return rows


def case_counts(rows):
    values = [row["status"] for row in rows]
    return {
        "expected": len(ALL_CASES),
        "executed": sum(value in {"passed", "failed"} for value in values),
        "passed": values.count("passed"),
        "failed": values.count("failed"),
        "not_run": values.count("not_run"),
        "ignored": values.count("ignored"),
    }


def assert_allowlisted(value):
    """Reject unknown keys and strings that look like paths, DSNs or secrets."""
    if isinstance(value, dict):
        for key, item in value.items():
            require(isinstance(key, str) and re.fullmatch(r"[a-z][a-z0-9_]*", key), "evidence-key")
            require(key not in FORBIDDEN_KEY, "evidence-key")
            assert_allowlisted(item)
    elif isinstance(value, list):
        for item in value:
            assert_allowlisted(item)
    elif isinstance(value, str):
        require(len(value) <= 512 and "\n" not in value and "\r" not in value, "evidence-string")
        require(not FORBIDDEN_TEXT.search(value), "evidence-string")
    elif isinstance(value, bool):
        return
    elif isinstance(value, int):
        require(value >= 0, "evidence-number")
    else:
        require(value is None, "evidence-type")


def make_report(*, provenance, validator_sha256, binaries, postgres, cases,
                source_recheck, cleanup, stage, failure_class):
    """Project the final allowlist document; no receipt, command or path is copied."""
    rows = []
    require(isinstance(cases, list) and len(cases) == len(ALL_CASES), "evidence-cases")
    for row, (target, name, ignored) in zip(cases, ALL_CASES, strict=True):
        require(set(row) == {"target", "name", "ignored", "status", "observed"}, "evidence-cases")
        require(row["target"] == target and row["name"] == name and row["ignored"] is ignored,
                "evidence-cases")
        require(row["status"] in {"passed", "failed", "not_run", "ignored"}, "evidence-cases")
        if row["status"] == "passed":
            observed = row["observed"]
            require(isinstance(observed, dict)
                    and set(observed) == {"passed", "failed", "ignored", "filtered_out"}
                    and observed["passed"] == 1 and observed["failed"] == 0 and observed["ignored"] == 0,
                    "evidence-counts")
        else:
            require(row["observed"] is None, "evidence-counts")
        rows.append({key: row[key] for key in ("target", "name", "ignored", "status", "observed")})
    counts = case_counts(rows)
    pg = postgres if isinstance(postgres, dict) else {}
    cleanup = cleanup if isinstance(cleanup, dict) else {}
    require(set(cleanup) == {"database_removed", "roster_restored", "work_removed", "evidence_clean"},
            "evidence-cleanup")
    require(all(type(value) is bool for value in cleanup.values()), "evidence-cleanup")

    checks = (
        failure_class is None,
        provenance is not None,
        isinstance(binaries, dict) and set(binaries) == {INTEGRATION, LIB},
        pg.get("major") == 17 and pg.get("server_version_num", 0) // 10000 == 17,
        counts["passed"] == len(ALL_CASES) and counts["failed"] == 0 and counts["not_run"] == 0,
        source_recheck is True,
        all(cleanup.values()),
    )
    passed = all(checks)
    if not passed and failure_class is None:
        failure_class = "incomplete"

    report = {
        "schema": SCHEMA,
        "scope": "library-layer-only",
        "product_acceptance_complete": False,
        "declaration": "Qualifies the unswitched library layer only; it does not claim #42 original acceptance.",
        "qualification": {
            "surface": "unswitched-library-layer",
            "production_path_switched": False,
            "issue42_original_acceptance": False,
        },
        "passed": passed,
        "stage": stage,
        "failure_class": failure_class,
        "validator_sha256": validator_sha256,
        "product": {
            "commit": provenance["product_commit"],
            "tree": provenance["product_tree"],
            "clean": provenance["product_clean"],
            "reachable": provenance["product_reachable"],
            "cargo_lock_sha256": provenance["cargo_lock_sha256"],
        },
        "workflow": {
            "file": provenance["workflow_path"],
            "commit": provenance["workflow_commit"],
            "head": provenance["workflow_commit"],
            "tree": provenance["workflow_tree"],
            "sha256": provenance["workflow_sha256"],
        },
        "run": {"id": provenance["run_id"], "attempt": provenance["run_attempt"]},
        "event_head": provenance["event_head"],
        "event_tree": provenance["event_tree"],
        "repository": provenance["repository"],
        "event": "push",
        "ref": provenance["ref"],
        "toolchain": {
            "rustc": RUSTC_RELEASE,
            "cargo": CARGO_RELEASE,
            "cargo_commit": CARGO_FORK,
            "target": TARGET,
        },
        "binaries": {
            name: {key: binaries[name][key] for key in (
                "kind", "binary_sha256", "receipt_sha256", "source_inputs_sha256",
                "config_digest", "bound_inputs_sha256", "cargo_lock_sha256",
                "test_closure_sha256", "command_sha256", "summary_sha256")}
            for name in (INTEGRATION, LIB)
        } if isinstance(binaries, dict) and set(binaries) == {INTEGRATION, LIB} else {},
        "postgres": {
            "server_version_num": int(pg.get("server_version_num", 0)),
            "major": int(pg.get("major", 0)),
            "client_major": int(pg.get("client_major", 0)),
            "baseline_database_count": int(pg.get("baseline_database_count", 0)),
            "owned_database_created": bool(pg.get("owned_database_created", False)),
        },
        "cases": rows,
        "counts": counts,
        "source_recheck": source_recheck is True,
        "bounds": {
            "case_timeout_seconds": CASE_TIMEOUT_SECONDS,
            "case_deadline_seconds": CASE_DEADLINE_SECONDS,
            "job_timeout_minutes": JOB_TIMEOUT_MINUTES,
        },
        "cleanup": cleanup,
    }
    assert_allowlisted(report)
    return report


def write_json(path, document, limit=None):
    data = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    if limit is not None:
        require(len(data) <= limit, "evidence-size")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(data, encoding="ascii")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def read_json(path):
    try:
        with Path(path).open(encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, ValueError) as error:
        raise EvidenceError("evidence") from error
    require(isinstance(value, dict), "evidence")
    return value


def _psql_binary():
    found = shutil.which("psql")
    require(found is not None, "postgres")
    return found


def _psql_env(database):
    names = ("PATH", "HOME", "LC_ALL", "PGHOST", "PGPORT", "PGUSER", "PGSSLMODE",
             "PGCONNECT_TIMEOUT")
    environment = {name: os.environ[name] for name in names if name in os.environ}
    environment["LC_ALL"] = "C"
    environment["PGDATABASE"] = database
    environment["PGOPTIONS"] = "-c statement_timeout=20000 -c lock_timeout=5000"
    return environment


def psql(sql, *, database="postgres", limit=20):
    try:
        process = subprocess.run(
            [_psql_binary(), "-XqAtw", "-v", "ON_ERROR_STOP=1", "-c", sql],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_psql_env(database),
            timeout=limit,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError("postgres") from error
    if process.returncode != 0:
        raise EvidenceError("postgres")
    return process.stdout.decode("utf-8").strip()


def client_major():
    try:
        process = subprocess.run([_psql_binary(), "--version"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=10, env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError("postgres") from error
    match = re.fullmatch(r"psql \(PostgreSQL\) (17)\.[0-9]{1,3}(?: .*)?", process.stdout.decode().strip())
    require(process.returncode == 0 and match is not None, "postgres")
    return 17


def server_version_num():
    value = psql("SHOW server_version_num;")
    require(re.fullmatch(r"17[0-9]{4}", value), "postgres")
    return int(value)


def roster():
    return sorted(filter(None, psql("SELECT datname FROM pg_database ORDER BY datname COLLATE \"C\";").splitlines()))


def database_exists(name):
    require(DATABASE_FULL.fullmatch(name), "postgres")
    return psql(f"SELECT count(*) FROM pg_database WHERE datname = '{name}';") != "0"


def create_database():
    name = DATABASE_PREFIX + secrets.token_hex(16)
    require(DATABASE_FULL.fullmatch(name), "postgres")
    require(not database_exists(name), "database-exists")
    psql(f'CREATE DATABASE "{name}" TEMPLATE template0;')
    owner = psql(f"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '{name}';")
    require(owner == os.environ.get("PGUSER"), "postgres")
    return name


def drop_database(name):
    require(DATABASE_FULL.fullmatch(name) or SLOT_ZERO_DATABASE.fullmatch(name), "postgres")
    psql(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE);', limit=30)


def cleanup_databases(owned, baseline):
    """Drop only the database this run created and its exact slot-zero children."""
    baseline = set(baseline)
    current = set(roster())
    for name in sorted(current - baseline):
        if name == owned or SLOT_ZERO_DATABASE.fullmatch(name):
            drop_database(name)
        else:
            return False, False
    after = set(roster())
    return (owned is None or owned not in after), after == baseline


def check_postgres(baseline):
    require(int(baseline.get("server_version_num", 0)) // 10000 == 17, "postgres")
    version = server_version_num()
    require(version == baseline["server_version_num"], "postgres")
    require(client_major() == 17, "postgres")
    require(roster() == baseline["databases"], "preexisting-database")
    require(psql("SELECT (rolcreatedb OR rolsuper)::text FROM pg_roles WHERE rolname = current_user;")
            == "t", "postgres")
    return {
        "server_version_num": version,
        "major": version // 10000,
        "client_major": 17,
        "baseline_database_count": len(baseline["databases"]),
        "owned_database_created": False,
    }


def _database_url(name):
    return "postgresql://{}@{}:{}/{}".format(
        os.environ["PGUSER"], os.environ["PGHOST"], os.environ["PGPORT"], name)


def execute_case(binary, name, ignored, *, database, timeout, cwd):
    environment = os.environ.copy()
    environment["ROOTYARD_TEST_DATABASE_URL"] = _database_url(database)
    environment["RUST_BACKTRACE"] = "0"
    environment["RUST_TEST_THREADS"] = "1"
    arguments = [str(binary)]
    if ignored:
        arguments.append("--ignored")
    arguments += ["--exact", name, "--test-threads=1"]
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            cwd=str(cwd),
            env=environment,
        )
    except OSError as error:
        raise EvidenceError("case") from error
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        raise EvidenceError("timeout")
    require(process.returncode == 0, "case")
    require(len(stderr) <= 8192 and b"panicked" not in stderr, "case")
    return stdout


def run_cases(*, binaries, database, deadline, cwd):
    statuses, observed = {}, {}
    failure = None
    for target, name, ignored in ALL_CASES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            failure = "timeout"
            break
        key = (target, name)
        try:
            raw = execute_case(binaries[target], name, ignored, database=database,
                               timeout=min(CASE_TIMEOUT_SECONDS, remaining), cwd=cwd)
            parsed = parse_case_output(raw, name)
            observed[key] = {field: parsed[field] for field in
                             ("passed", "failed", "ignored", "filtered_out")}
            statuses[key] = "passed"
        except EvidenceError as error:
            statuses[key] = "failed"
            failure = error.kind
            break
    return expected_rows(statuses, observed), failure


def cmd_pg_baseline(args):
    baseline = {
        "server_version_num": server_version_num(),
        "databases": roster(),
        "client_major": client_major(),
    }
    require(baseline["databases"] == sorted(["postgres", "template0", "template1"]),
            "preexisting-database")
    require(baseline["server_version_num"] // 10000 == 17, "postgres")
    require(psql("SELECT (rolcreatedb OR rolsuper)::text FROM pg_roles WHERE rolname = current_user;")
            == "t", "postgres")
    write_json(Path(args.work) / "pg-baseline.json", baseline)
    print("[slot0-native] stage=postgres status=ok")
    return 0


def cmd_bind(args):
    work, product = Path(args.work), Path(args.product)
    provenance = verify_sources(Path(args.workflow_source), product, os.environ)
    sys.path.insert(0, str(product / "scripts"))
    try:
        import native_build_receipt
    except ImportError as error:
        raise EvidenceError("receipt") from error
    loader = native_build_receipt.load_receipt
    try:
        binaries = {
            INTEGRATION: receipt_summary(
                loader, receipt_path=Path(args.integration).with_suffix(".build.json"),
                binary_path=args.integration, source_root=product,
                product_commit=provenance["product_commit"], product_tree=provenance["product_tree"],
                kind="integration"),
            LIB: receipt_summary(
                loader, receipt_path=Path(args.lib).with_suffix(".build.json"),
                binary_path=args.lib, source_root=product,
                product_commit=provenance["product_commit"], product_tree=provenance["product_tree"],
                kind="lib"),
        }
    except EvidenceError:
        raise
    except Exception as error:
        raise EvidenceError("receipt") from error
    require(binaries[INTEGRATION]["source_inputs_sha256"] == binaries[LIB]["source_inputs_sha256"],
            "receipt-source")
    require(binaries[INTEGRATION]["cargo_lock_sha256"] == provenance["cargo_lock_sha256"],
            "receipt-lock")
    binding = {
        "provenance": provenance,
        "binaries": binaries,
        "validator_sha256": sha256_file(Path(__file__).resolve()),
    }
    write_json(work / "binding.json", binding, limit=32768)
    print("[slot0-native] stage=bind status=ok")
    return 0


def cmd_run(args):
    work, product = Path(args.work), Path(args.product)
    binding = read_json(work / "binding.json")
    provenance = binding.get("provenance") or {}
    baseline = read_json(work / "pg-baseline.json")
    statuses = {}
    failure = None
    database = None
    pg = {
        "server_version_num": baseline.get("server_version_num", 0),
        "major": baseline.get("server_version_num", 0) // 10000,
        "client_major": baseline.get("client_major", 0),
        "baseline_database_count": len(baseline.get("databases") or []),
        "owned_database_created": False,
    }
    deadline = time.monotonic() + CASE_DEADLINE_SECONDS
    try:
        require(verify_sources(Path(args.workflow_source), product, os.environ) == provenance, "source")
        try:
            for name, path in ((INTEGRATION, args.integration), (LIB, args.lib)):
                attested = binding["binaries"][name]
                require(sha256_file(path) == attested["binary_sha256"], "binary")
                require(sha256_file(Path(str(path) + ".build.json")) == attested["receipt_sha256"],
                        "receipt")
        except OSError as error:
            raise EvidenceError("binary") from error
        pg = check_postgres(baseline)
        database = create_database()
        pg["owned_database_created"] = True
        (work / "owned-db").write_text(database + "\n", encoding="ascii")
        rows, failure = run_cases(
            binaries={INTEGRATION: args.integration, LIB: args.lib},
            database=database, deadline=deadline, cwd=product)
    except EvidenceError as error:
        failure = error.kind
        rows = expected_rows(statuses)
    finally:
        try:
            current = roster()
            baseline_databases = baseline.get("databases") or []
            if database is None:
                database_removed, roster_restored = True, sorted(current) == sorted(baseline_databases)
            else:
                database_removed, roster_restored = cleanup_databases(database, baseline_databases)
        except EvidenceError:
            database_removed, roster_restored = False, False
        if not (database_removed and roster_restored):
            failure = failure or "cleanup"
        try:
            source_recheck = verify_sources(Path(args.workflow_source), product, os.environ) == provenance
        except EvidenceError:
            source_recheck = False
    candidate = {
        "provenance": provenance,
        "binaries": binding.get("binaries") or {},
        "validator_sha256": binding.get("validator_sha256"),
        "cases": rows,
        "postgres": pg,
        "source_recheck": source_recheck,
        "cleanup": {"database_removed": database_removed, "roster_restored": roster_restored},
        "failure_class": failure,
        "stage": "test" if failure is not None else "complete",
    }
    candidate["passed"] = (
        failure is None and source_recheck and all(row["status"] == "passed" for row in rows)
        and database_removed and roster_restored
    )
    write_json(work / "candidate.json", candidate, limit=32768)
    if candidate["passed"]:
        print("[slot0-native] stage=test status=ok")
        return 0
    print(f"[slot0-native] stage=test status=failed class={failure or 'incomplete'}", file=sys.stderr)
    return 1


def _read_optional(path):
    try:
        return Path(path).read_text(encoding="ascii").strip()
    except OSError:
        return ""


def cmd_finalize(args):
    work, evidence, product = Path(args.work), Path(args.evidence), Path(args.product)
    stage = _read_optional(evidence / "stage") or "finalize"
    if stage not in {"source", "toolchain", "build", "bind", "postgres", "test", "finalize"}:
        stage = "finalize"
    candidate = {}
    binding = {}
    baseline = {}
    owned = _read_optional(work / "owned-db") or None
    try:
        candidate = read_json(work / "candidate.json")
    except EvidenceError:
        pass
    try:
        binding = read_json(work / "binding.json")
    except EvidenceError:
        pass
    try:
        baseline = read_json(work / "pg-baseline.json")
    except EvidenceError:
        pass

    try:
        provenance = verify_sources(Path(args.workflow_source), product, os.environ)
    except EvidenceError:
        provenance = None

    database_removed, roster_restored = True, False
    if baseline:
        try:
            current = set(roster())
            if owned and owned in current:
                drop_database(owned)
            for name in sorted(current - set(baseline.get("databases") or [])):
                if name == owned or SLOT_ZERO_DATABASE.fullmatch(name):
                    drop_database(name)
            after = set(roster())
            database_removed = owned is None or owned not in after
            roster_restored = sorted(after) == sorted(baseline.get("databases") or [])
        except EvidenceError:
            database_removed, roster_restored = False, False

    rows = candidate.get("cases") or expected_rows({})
    source_recheck = bool(candidate.get("source_recheck")) and bool(provenance) \
        and candidate.get("provenance") == provenance
    binaries = binding.get("binaries") or {}
    pg = candidate.get("postgres") or {
        "server_version_num": baseline.get("server_version_num", 0),
        "major": baseline.get("server_version_num", 0) // 10000,
        "client_major": baseline.get("client_major", 0),
        "baseline_database_count": len(baseline.get("databases") or []),
        "owned_database_created": bool(owned),
    }
    failure = candidate.get("failure_class")
    if provenance is None:
        failure = "source"
    elif candidate and not source_recheck:
        failure = "source-changed"
    elif not candidate:
        failure = stage
    if not (database_removed and roster_restored):
        failure = failure or "cleanup"

    try:
        shutil.rmtree(work)
    except OSError:
        pass
    work_removed = not work.exists()
    entries = list(evidence.iterdir()) if evidence.exists() else []
    for entry in entries:
        try:
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
        except OSError:
            pass
    evidence_clean = evidence.is_dir() and not any(evidence.iterdir())
    cleanup = {
        "database_removed": database_removed,
        "roster_restored": roster_restored,
        "work_removed": work_removed,
        "evidence_clean": evidence_clean,
    }
    if provenance is None:
        report = {
            "schema": SCHEMA,
            "scope": "library-layer-only",
            "product_acceptance_complete": False,
            "declaration": "Qualifies the unswitched library layer only; it does not claim #42 original acceptance.",
            "qualification": {
                "surface": "unswitched-library-layer",
                "production_path_switched": False,
                "issue42_original_acceptance": False,
            },
            "passed": False,
            "stage": "source",
            "failure_class": "source",
            "repository": os.environ.get("GITHUB_REPOSITORY", ""),
            "event": "push",
            "ref": QUALIFICATION_REF,
            "run": {"id": int(os.environ.get("GITHUB_RUN_ID", "0")),
                    "attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "0"))},
            "cases": [],
            "counts": {"expected": len(ALL_CASES), "executed": 0, "passed": 0,
                       "failed": 0, "not_run": len(ALL_CASES), "ignored": 0},
            "bounds": {
                "case_timeout_seconds": CASE_TIMEOUT_SECONDS,
                "case_deadline_seconds": CASE_DEADLINE_SECONDS,
                "job_timeout_minutes": JOB_TIMEOUT_MINUTES,
            },
            "cleanup": cleanup,
        }
        assert_allowlisted(report)
    else:
        validator_sha256 = sha256_file(Path(__file__).resolve())
        try:
            report = make_report(
                provenance=provenance,
                validator_sha256=validator_sha256,
                binaries=binaries if source_recheck else {},
                postgres=pg,
                cases=rows,
                source_recheck=source_recheck,
                cleanup=cleanup,
                stage="complete" if failure is None else stage,
                failure_class=failure,
            )
        except Exception:
            report = make_report(
                provenance=provenance,
                validator_sha256=validator_sha256,
                binaries={},
                postgres=pg if isinstance(pg, dict) else {},
                cases=expected_rows({}),
                source_recheck=False,
                cleanup=cleanup,
                stage=stage,
                failure_class=failure or "incomplete",
            )
    write_json(evidence / "qualification.json", report, limit=REPORT_LIMIT)
    if report["passed"]:
        print("[slot0-native] stage=finalize status=ok")
        return 0
    print(f"[slot0-native] stage=finalize status=failed class={report['failure_class']}", file=sys.stderr)
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    pg = subparsers.add_parser("pg-baseline")
    pg.add_argument("--work", required=True)
    pg.set_defaults(func=cmd_pg_baseline)

    bind = subparsers.add_parser("bind")
    bind.add_argument("--work", required=True)
    bind.add_argument("--product", required=True)
    bind.add_argument("--workflow-source", required=True)
    bind.add_argument("--integration", required=True)
    bind.add_argument("--lib", required=True)
    bind.set_defaults(func=cmd_bind)

    run = subparsers.add_parser("run")
    run.add_argument("--work", required=True)
    run.add_argument("--product", required=True)
    run.add_argument("--workflow-source", required=True)
    run.add_argument("--integration", required=True)
    run.add_argument("--lib", required=True)
    run.set_defaults(func=cmd_run)

    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--work", required=True)
    finalize.add_argument("--evidence", required=True)
    finalize.add_argument("--product", required=True)
    finalize.add_argument("--workflow-source", required=True)
    finalize.set_defaults(func=cmd_finalize)

    arguments = parser.parse_args(argv)
    stages = {"pg-baseline": "postgres", "bind": "bind", "run": "test", "finalize": "finalize"}
    stage = stages[arguments.mode]
    try:
        return arguments.func(arguments)
    except EvidenceError as error:
        print(f"[slot0-native] stage={stage} status=failed class={error.kind}", file=sys.stderr)
        return 1
    except Exception:
        print(f"[slot0-native] stage={stage} status=failed class=internal", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
