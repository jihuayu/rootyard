#!/usr/bin/env python3
"""Fail-closed W1-C native receipt validator and memory-only acceptance runner.

Validates the prebuilt ``tests/blob_store_w1c_contract.rs`` test executable and
its v1/v2 build receipt through ``scripts/native_build_receipt.py``
(``load_receipt(..., verify_source_files=True, forbid_implicit_build=True)``),
verifies sealed CAS immutability when ``artifact_store`` metadata is present,
rechecks source/config/Cargo.lock/worktree invariance before and after running
the binary, and executes ``--ignored --list`` and ``--ignored --test-threads=1``
strictly in memory.

Raw Rust stdout and stderr are never printed, saved to disk, or included in
uploaded reports. On both pass and failure, only allowlisted test identifiers,
counts, exit codes, and closed failure stage/code classifications are emitted.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import collect_evidence_receipts as receipt_collector  # noqa: E402
import native_build_receipt as receipt_contract  # noqa: E402

# Exposed as module attributes so focused tests can stub probes cleanly.
git_state = receipt_contract.git_state
source_digest = receipt_contract.source_digest
sha256_file = receipt_contract.sha256_file
sha256_bytes = receipt_contract.sha256_bytes
bound_input_inventory = receipt_contract.bound_input_inventory
bound_inputs_summary = receipt_contract.bound_inputs_summary
config_digest = receipt_contract.config_digest
load_receipt_contract = receipt_contract.load_receipt
collect_raw_receipt = receipt_collector.collect_raw_receipt
run_subprocess = subprocess.run

TARGET_NAME = "blob_store_w1c_contract"
TEST_SOURCE = "tests/blob_store_w1c_contract.rs"
EXPECTED_CASES = (
    "pg_protected_uploader_preflight_preserves_unconsumed_holds",
    "pg_protected_uploader_consume_and_upload_encrypted_against_real_provider",
)
EXPECTED_CASE_SET = frozenset(EXPECTED_CASES)
REPORT_KIND = "rootyard/w1c-blob-store-acceptance"
SUMMARY_PASS_MARKER = "w1c native acceptance: passed (2 cases)"
STORE_SCHEMA = "rootyard/native-artifact-store/v1"

CARGO_FORK_COMMIT = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
CARGO_FORK_RELEASE = "1.101.0"
RUSTC_RELEASE = "1.99.1"

REQUIRED_BLOB_ENV = (
    "ROOTYARD_BLOB_DRIVER",
    "ROOTYARD_BLOB_SERVICE",
    "ROOTYARD_BLOB_ENDPOINT",
    "ROOTYARD_BLOB_BUCKET",
    "ROOTYARD_BLOB_REGION",
    "ROOTYARD_BLOB_ACCESS_KEY_ID",
    "ROOTYARD_BLOB_SECRET_ACCESS_KEY",
    "ROOTYARD_BLOB_ROOT",
)

STAGES = frozenset(
    (
        "environment",
        "receipt",
        "source",
        "inventory",
        "execute",
        "parse",
        "immutable",
        "report",
        "internal",
    )
)
CODES = frozenset(
    (
        "missing_database_url",
        "database_url_mismatch",
        "missing_blob_env",
        "invalid_blob_env",
        "timeout_invalid",
        "binary_missing",
        "receipt_missing",
        "receipt_invalid",
        "receipt_kind",
        "receipt_not_relocated",
        "receipt_command",
        "receipt_features",
        "receipt_profile",
        "receipt_toolchain",
        "receipt_artifacts",
        "receipt_artifact_store",
        "receipt_copy_failed",
        "build_report_mismatch",
        "stale_receipt",
        "binary_mismatch",
        "source_drift",
        "config_drift",
        "cargo_lock_drift",
        "worktree_dirty",
        "git_unavailable",
        "source_unavailable",
        "immutable_drift",
        "inventory_spawn_failed",
        "inventory_timeout",
        "inventory_nonzero",
        "inventory_mismatch",
        "spawn_failed",
        "timeout",
        "lock_timeout",
        "pg_error",
        "s3_error",
        "assertion_failed",
        "test_failed",
        "zero_tests",
        "ignored_tests",
        "case_identity",
        "output_invalid",
        "report_write_failed",
        "internal_error",
    )
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_LIST_TEST_RE = re.compile(r"^([^\s:]+): test$")
_LIST_SUMMARY_RE = re.compile(r"^\d+ tests?, \d+ benchmarks?$")
_RUNNING_RE = re.compile(r"^running (\d+) tests?$", re.MULTILINE)
_RESULT_RE = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
    re.MULTILINE,
)
_CASE_RE = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)$", re.MULTILINE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_PRE_SUBCOMMAND_VALUE_OPTS = frozenset({"--config", "-c"})
_PRE_SUBCOMMAND_BOOL_OPTS = frozenset({"--locked", "--offline", "--frozen", "--quiet", "-q"})
_CARGO_VALUE_OPTS = frozenset(
    {
        "--config",
        "-c",
        "--features",
        "--profile",
        "--target",
        "--test",
        "--jobs",
        "-j",
        "--message-format",
        "--manifest-path",
        "--target-dir",
        "--package",
        "-p",
    }
)
_CARGO_BOOL_OPTS = frozenset(
    {
        "--locked",
        "--offline",
        "--frozen",
        "--quiet",
        "-q",
        "--verbose",
        "-v",
        "--no-default-features",
        "--all-features",
        "--no-run",
        "--release",
        "--lib",
        "--bins",
        "--tests",
        "--benches",
        "--examples",
    }
)
_DISALLOWED_TARGETS = frozenset({"--lib", "--bin", "--bins", "--tests", "--benches", "--examples"})
_OUTCOME_MAP = {"ok": "passed", "FAILED": "failed", "ignored": "ignored"}


class GateError(RuntimeError):
    """Fail-closed error carrying strictly an allowlisted stage, code, and exit code."""

    def __init__(
        self,
        stage: str,
        code: str,
        *,
        exit_code: int | None = None,
        counts: dict[str, int] | None = None,
        case_statuses: dict[str, str] | None = None,
    ):
        if stage not in STAGES or code not in CODES:
            raise ValueError("unregistered W1-C failure stage/code")
        super().__init__(f"{stage}/{code}")
        self.stage = stage
        self.code = code
        self.exit_code = exit_code
        self.counts = counts
        self.case_statuses = case_statuses


@dataclass(frozen=True)
class CommandSelection:
    subcommand: str
    config_values: tuple[str, ...]
    tests: tuple[str, ...]
    features: tuple[str, ...]
    profiles: tuple[str, ...]
    targets: tuple[str, ...]
    message_formats: tuple[str, ...]
    locked: bool
    no_default_features: bool
    all_features: bool
    no_run: bool
    disallowed_target: bool


def _need(
    condition: bool,
    stage: str,
    code: str,
    *,
    exit_code: int | None = None,
    counts: dict[str, int] | None = None,
    case_statuses: dict[str, str] | None = None,
) -> None:
    if not condition:
        raise GateError(
            stage,
            code,
            exit_code=exit_code,
            counts=counts,
            case_statuses=case_statuses,
        )


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _require_timeout(value: float, max_seconds: float = 3600.0) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value <= 0
        or value > max_seconds
    ):
        raise GateError("environment", "timeout_invalid")
    return float(value)


def require_runtime_environment(environ: dict[str, str] | None = None) -> None:
    """Ensure PG and controlled Garage S3 environment variables are bound."""
    env = os.environ if environ is None else environ
    test_db = env.get("ROOTYARD_TEST_DATABASE_URL")
    _need(isinstance(test_db, str) and bool(test_db.strip()), "environment", "missing_database_url")
    db_url = env.get("DATABASE_URL")
    if isinstance(db_url, str) and db_url.strip():
        _need(db_url == test_db, "environment", "database_url_mismatch")
    for name in REQUIRED_BLOB_ENV:
        value = env.get(name)
        _need(isinstance(value, str) and bool(value.strip()), "environment", "missing_blob_env")
    _need(env.get("ROOTYARD_BLOB_DRIVER") == "opendal", "environment", "invalid_blob_env")
    _need(env.get("ROOTYARD_BLOB_SERVICE") == "s3", "environment", "invalid_blob_env")


def _read_regular_bytes(path: Path, stage: str, missing_code: str, invalid_code: str) -> bytes:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise GateError(stage, missing_code) from None
    except OSError:
        raise GateError(stage, invalid_code) from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise GateError(stage, invalid_code)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            return stream.read()
    except OSError:
        raise GateError(stage, invalid_code) from None


def _require_regular_binary(path: Path, code: str = "binary_missing") -> None:
    try:
        info = os.lstat(path)
    except OSError:
        raise GateError("receipt", code) from None
    _need(
        not stat.S_ISLNK(info.st_mode)
        and stat.S_ISREG(info.st_mode)
        and os.access(path, os.X_OK),
        "receipt",
        code,
    )


def _require_readonly_regular(path: Path, *, executable: bool = False, code: str) -> bytes | None:
    try:
        info = os.lstat(path)
    except OSError:
        raise GateError("receipt", code) from None
    _need(not stat.S_ISLNK(info.st_mode) and stat.S_ISREG(info.st_mode), "receipt", code)
    if hasattr(os, "geteuid"):
        _need(info.st_uid == os.geteuid(), "receipt", code)
    _need((stat.S_IMODE(info.st_mode) & 0o222) == 0, "receipt", code)
    if executable:
        _need(os.access(path, os.X_OK), "receipt", code)
        return None
    return _read_regular_bytes(path, "receipt", code, code)


def _parse_cargo_command(command: object) -> CommandSelection:
    _need(
        isinstance(command, list)
        and len(command) >= 2
        and all(isinstance(part, str) and bool(part) for part in command),
        "receipt",
        "receipt_command",
    )
    _need(command[0] == "cargo", "receipt", "receipt_command")
    index = 1
    config_values: list[str] = []
    locked = False

    while index < len(command):
        token = command[index]
        if not token.startswith("-"):
            break
        opt, has_eq, opt_val = token.partition("=")
        if opt in _PRE_SUBCOMMAND_VALUE_OPTS:
            if has_eq:
                _need(bool(opt_val), "receipt", "receipt_command")
                val = opt_val
                index += 1
            else:
                _need(index + 1 < len(command) and bool(command[index + 1]), "receipt", "receipt_command")
                val = command[index + 1]
                index += 2
            if opt in ("--config", "-c"):
                config_values.append(val)
            continue
        _need(not has_eq and opt in _PRE_SUBCOMMAND_BOOL_OPTS, "receipt", "receipt_command")
        if opt == "--locked":
            locked = True
        index += 1

    _need(index < len(command), "receipt", "receipt_command")
    subcommand = command[index]
    _need(subcommand in ("rustc", "test"), "receipt", "receipt_command")
    index += 1

    tests: list[str] = []
    features: list[str] = []
    profiles: list[str] = []
    targets: list[str] = []
    message_formats: list[str] = []
    no_default_features = False
    all_features = False
    no_run = False
    disallowed_target = False

    while index < len(command):
        token = command[index]
        if token == "--":
            raise GateError("receipt", "receipt_command")
        if token in _DISALLOWED_TARGETS:
            disallowed_target = True
            index += 1
            continue
        if token.startswith("--bin="):
            disallowed_target = True
            index += 1
            continue
        opt, has_eq, opt_val = token.partition("=")
        if opt == "--bin":
            disallowed_target = True
            _need(index + 1 < len(command), "receipt", "receipt_command")
            index += 2
            continue
        if opt in _CARGO_VALUE_OPTS or (opt.startswith("-j") and len(opt) > 2):
            if opt.startswith("-j") and len(opt) > 2 and not has_eq:
                val = opt[2:]
                index += 1
            elif has_eq:
                _need(bool(opt_val), "receipt", "receipt_command")
                val = opt_val
                index += 1
            else:
                _need(index + 1 < len(command) and bool(command[index + 1]), "receipt", "receipt_command")
                val = command[index + 1]
                index += 2
            if opt in ("--config", "-c"):
                config_values.append(val)
            elif opt == "--test":
                tests.append(val)
            elif opt == "--features":
                features.extend(part for part in re.split(r"[\s,]+", val.strip()) if part)
            elif opt == "--profile":
                profiles.append(val)
            elif opt == "--target":
                targets.append(val)
            elif opt == "--message-format":
                message_formats.append(val)
            continue
        _need(not has_eq and opt in _CARGO_BOOL_OPTS, "receipt", "receipt_command")
        if opt == "--locked":
            locked = True
        elif opt == "--no-default-features":
            no_default_features = True
        elif opt == "--all-features":
            all_features = True
        elif opt == "--no-run":
            no_run = True
        elif opt == "--release":
            profiles.append("release")
        index += 1

    return CommandSelection(
        subcommand=subcommand,
        config_values=tuple(config_values),
        tests=tuple(tests),
        features=tuple(features),
        profiles=tuple(profiles),
        targets=tuple(targets),
        message_formats=tuple(message_formats),
        locked=locked,
        no_default_features=no_default_features,
        all_features=all_features,
        no_run=no_run,
        disallowed_target=disallowed_target,
    )


def _validate_command_contract(
    command: object,
    *,
    schema: str,
    expected_target_triple: str | None,
    require_package_debug_zero: bool,
    require_strip_debuginfo: bool,
) -> None:
    parsed = _parse_cargo_command(command)
    _need(not parsed.disallowed_target, "receipt", "receipt_command")
    _need(parsed.tests == (TARGET_NAME,), "receipt", "receipt_command")
    _need(parsed.locked, "receipt", "receipt_command")
    _need(not parsed.all_features and parsed.no_default_features, "receipt", "receipt_features")
    _need(sorted(parsed.features) == ["pando-lab"], "receipt", "receipt_features")
    _need("json-render-diagnostics" in parsed.message_formats, "receipt", "receipt_command")
    if parsed.targets:
        _need(expected_target_triple is not None, "receipt", "receipt_command")
        _need(parsed.targets == (expected_target_triple,), "receipt", "receipt_command")
    if schema == "v2":
        _need(parsed.subcommand == "rustc", "receipt", "receipt_command")
        _need(parsed.profiles == ("test",), "receipt", "receipt_profile")
        if require_package_debug_zero:
            for key in (
                "profile.dev.package.rootyard.debug=0",
                "profile.test.package.rootyard.debug=0",
            ):
                _need(key in parsed.config_values, "receipt", "receipt_profile")
        if require_strip_debuginfo:
            for key in (
                'profile.dev.package.rootyard.strip="debuginfo"',
                'profile.test.package.rootyard.strip="debuginfo"',
            ):
                _need(key in parsed.config_values, "receipt", "receipt_profile")
    else:
        _need(parsed.subcommand in ("rustc", "test"), "receipt", "receipt_command")
        if parsed.subcommand == "test":
            _need(parsed.no_run, "receipt", "receipt_command")
        if parsed.profiles:
            _need(parsed.profiles == ("test",), "receipt", "receipt_profile")


def _validate_cas_store(
    payload: dict,
    *,
    raw_receipt_bytes: bytes,
    raw_receipt_sha256: str,
    alias_binary: Path | None,
    expected_store_root: Path | None,
    require_cas: bool,
) -> tuple[Path, str]:
    store = payload.get("artifact_store")
    if store is None:
        _need(not require_cas, "receipt", "receipt_artifact_store")
        _need(alias_binary is not None, "receipt", "binary_missing")
        _require_regular_binary(alias_binary)
        return alias_binary, sha256_file(alias_binary)

    _need(isinstance(store, dict), "receipt", "receipt_artifact_store")
    _need(store.get("schema") == STORE_SCHEMA, "receipt", "receipt_artifact_store")
    raw_root = store.get("root")
    _need(isinstance(raw_root, str) and bool(raw_root), "receipt", "receipt_artifact_store")
    store_root = Path(raw_root)
    _need(store_root.is_absolute() and ".." not in store_root.parts, "receipt", "receipt_artifact_store")
    _need(not store_root.is_symlink() and store_root.is_dir(), "receipt", "receipt_artifact_store")
    if expected_store_root is not None:
        _need(
            store_root.resolve() == expected_store_root.expanduser().resolve(),
            "receipt",
            "receipt_artifact_store",
        )

    recorded_sha = store.get("binary_sha256")
    _need(_is_sha256(recorded_sha), "receipt", "receipt_artifact_store")
    _need(recorded_sha == payload.get("binary_sha256"), "receipt", "receipt_artifact_store")

    def resolve_cas_path(field: str) -> Path:
        raw_val = store.get(field)
        _need(isinstance(raw_val, str) and bool(raw_val), "receipt", "receipt_artifact_store")
        candidate = Path(raw_val)
        _need(candidate.is_absolute() and ".." not in candidate.parts, "receipt", "receipt_artifact_store")
        _need(_inside(candidate, store_root), "receipt", "receipt_artifact_store")
        return candidate

    obj_path = resolve_cas_path("object")
    bin_path = resolve_cas_path("binary")
    canonical_receipt_path = resolve_cas_path("receipt")
    build_receipt_path = resolve_cas_path("build_receipt")
    _need(bin_path.name == TARGET_NAME, "receipt", "receipt_artifact_store")
    _need(canonical_receipt_path.name == f"{TARGET_NAME}.receipt.json", "receipt", "receipt_artifact_store")
    _need(build_receipt_path.name == f"{TARGET_NAME}.build.json", "receipt", "receipt_artifact_store")

    _require_readonly_regular(obj_path, code="receipt_artifact_store")
    _require_readonly_regular(bin_path, executable=True, code="receipt_artifact_store")
    canonical_receipt_bytes = _require_readonly_regular(canonical_receipt_path, code="receipt_artifact_store")
    build_receipt_bytes = _require_readonly_regular(build_receipt_path, code="receipt_artifact_store")
    _need(canonical_receipt_bytes == raw_receipt_bytes, "receipt", "receipt_artifact_store")
    _need(build_receipt_bytes == raw_receipt_bytes, "receipt", "receipt_artifact_store")
    _need(sha256_bytes(canonical_receipt_bytes) == raw_receipt_sha256, "receipt", "receipt_artifact_store")

    _need(sha256_file(obj_path) == recorded_sha, "receipt", "binary_mismatch")
    bin_sha = sha256_file(bin_path)
    _need(bin_sha == recorded_sha, "receipt", "binary_mismatch")
    if alias_binary is not None:
        _require_regular_binary(alias_binary)
        _need(sha256_file(alias_binary) == recorded_sha, "receipt", "binary_mismatch")
    return bin_path, bin_sha


def _validate_v2_contract(
    validated: receipt_contract.ValidatedReceipt,
    *,
    root: Path,
    require_ci_pins: bool,
    require_package_debug_zero: bool,
    require_strip_debuginfo: bool,
) -> None:
    payload = validated.payload
    _need(payload.get("kind") == "rust-integration-test", "receipt", "receipt_kind")
    _need(payload.get("relocated_artifact") is True, "receipt", "receipt_not_relocated")
    _need(payload.get("original_artifact_sha256") == validated.binary_sha256, "receipt", "binary_mismatch")
    _need(payload.get("integration_test_source") == TEST_SOURCE, "receipt", "receipt_artifacts")
    test_source_path = root / TEST_SOURCE
    _need(test_source_path.is_file(), "source", "source_unavailable")
    _need(
        payload.get("integration_test_source_sha256") == sha256_file(test_source_path),
        "receipt",
        "source_drift",
    )
    _need(
        payload.get("features") == {"enabled": ["pando-lab"], "no_default_features": True},
        "receipt",
        "receipt_features",
    )
    _need(payload.get("profile") == "test", "receipt", "receipt_profile")
    _need(len(validated.artifacts) == 1, "receipt", "receipt_artifacts")
    artifact = validated.artifacts[0]
    _need(
        artifact.get("kind") == "test"
        and artifact.get("target") == TARGET_NAME
        and artifact.get("source") == TEST_SOURCE
        and artifact.get("source_sha256") == payload.get("integration_test_source_sha256")
        and artifact.get("executable_sha256") == validated.binary_sha256
        and isinstance(artifact.get("profile"), dict)
        and artifact["profile"].get("test") is True,
        "receipt",
        "receipt_artifacts",
    )
    toolchain = validated.toolchain or {}
    cargo = toolchain.get("cargo") or {}
    rustc = toolchain.get("rustc") or {}
    target_triple = payload.get("target_triple")
    _need(isinstance(target_triple, str) and rustc.get("host") == target_triple, "receipt", "receipt_toolchain")
    if require_ci_pins:
        _need(
            cargo.get("commit_hash") == CARGO_FORK_COMMIT
            and cargo.get("release") == CARGO_FORK_RELEASE
            and rustc.get("release") == RUSTC_RELEASE,
            "receipt",
            "receipt_toolchain",
        )
    _validate_command_contract(
        payload.get("command"),
        schema="v2",
        expected_target_triple=target_triple,
        require_package_debug_zero=require_package_debug_zero,
        require_strip_debuginfo=require_strip_debuginfo,
    )


def _validate_v1_contract(
    validated: receipt_contract.ValidatedReceipt,
    *,
    require_package_debug_zero: bool,
    require_strip_debuginfo: bool,
) -> None:
    payload = validated.payload
    if "kind" in payload:
        _need(payload.get("kind") == "rust-integration-test", "receipt", "receipt_kind")
    if "relocated_artifact" in payload:
        _need(payload.get("relocated_artifact") is True, "receipt", "receipt_not_relocated")
    if "original_artifact_sha256" in payload:
        _need(payload.get("original_artifact_sha256") == validated.binary_sha256, "receipt", "binary_mismatch")
    for row in validated.artifacts:
        _need(row.get("target") == TARGET_NAME and row.get("kind") == "test", "receipt", "receipt_artifacts")
    _validate_command_contract(
        payload.get("command"),
        schema="v1",
        expected_target_triple=None,
        require_package_debug_zero=require_package_debug_zero,
        require_strip_debuginfo=require_strip_debuginfo,
    )


def load_and_verify_receipt(
    receipt_path: Path,
    *,
    root: Path,
    alias_binary: Path | None,
    build_report_path: Path | None,
    expected_store_root: Path | None,
    expected_commit: str | None,
    require_cas: bool,
    require_ci_pins: bool,
    require_package_debug_zero: bool,
    require_strip_debuginfo: bool,
) -> tuple[receipt_contract.ValidatedReceipt, Path, bytes, str]:
    """Load and verify the receipt strictly via shared ``native_build_receipt.load_receipt``."""
    raw_bytes = _read_regular_bytes(receipt_path, "receipt", "receipt_missing", "receipt_invalid")
    receipt_sha256 = sha256_bytes(raw_bytes)
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GateError("receipt", "receipt_invalid") from None
    _need(isinstance(payload, dict), "receipt", "receipt_invalid")

    if build_report_path is not None:
        report_bytes = _read_regular_bytes(
            build_report_path, "receipt", "build_report_mismatch", "build_report_mismatch"
        )
        try:
            report_payload = json.loads(report_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GateError("receipt", "build_report_mismatch") from None
        _need(report_payload == payload, "receipt", "build_report_mismatch")

    exec_binary, _bin_sha = _validate_cas_store(
        payload,
        raw_receipt_bytes=raw_bytes,
        raw_receipt_sha256=receipt_sha256,
        alias_binary=alias_binary,
        expected_store_root=expected_store_root,
        require_cas=require_cas,
    )
    if expected_commit is not None:
        _need(payload.get("workspace_commit") == expected_commit, "receipt", "stale_receipt")

    try:
        validated = load_receipt_contract(
            receipt_path,
            source_root=root,
            binary_path=exec_binary,
            infer_binary=False,
            expected_commit=expected_commit,
            expected_profile="test" if "receipt_schema" in payload else None,
            verify_source_files=True,
            forbid_implicit_build=True,
            receipt_sha256=receipt_sha256,
        )
    except receipt_contract.ReceiptError as exc:
        msg = str(exc)
        if "binary digest" in msg:
            raise GateError("receipt", "binary_mismatch") from None
        if "workspace_commit" in msg:
            raise GateError("receipt", "stale_receipt") from None
        if "cargo_lock_sha256" in msg or "Cargo.lock" in msg:
            raise GateError("source", "cargo_lock_drift") from None
        if "config_digest" in msg:
            raise GateError("source", "config_drift") from None
        if "source_inputs_sha256" in msg or "bound input" in msg or "bound_input" in msg or "source root" in msg:
            raise GateError("source", "source_drift") from None
        raise GateError("receipt", "receipt_invalid") from None

    if validated.schema == "v2":
        _validate_v2_contract(
            validated,
            root=root,
            require_ci_pins=require_ci_pins,
            require_package_debug_zero=require_package_debug_zero,
            require_strip_debuginfo=require_strip_debuginfo,
        )
    else:
        _validate_v1_contract(
            validated,
            require_package_debug_zero=require_package_debug_zero,
            require_strip_debuginfo=require_strip_debuginfo,
        )
    return validated, exec_binary, raw_bytes, receipt_sha256


def capture_source_snapshot(
    validated: receipt_contract.ValidatedReceipt,
    *,
    root: Path,
    receipt_path: Path,
    exec_binary: Path,
    expected_commit: str | None,
) -> dict[str, object]:
    """Sample HEAD, worktree cleanliness, bound digests, binary, and receipt hashes."""
    try:
        state = git_state(root)
    except Exception:
        raise GateError("source", "git_unavailable") from None
    head = state.get("head") if isinstance(state, dict) else None
    status = state.get("status") if isinstance(state, dict) else None
    _need(isinstance(head, str) and bool(head) and status is not None, "source", "git_unavailable")
    _need(not str(status).strip(), "source", "worktree_dirty")
    if expected_commit is not None:
        _need(head == expected_commit, "source", "stale_receipt")
    _need(head == validated.workspace_commit, "source", "stale_receipt")

    try:
        current_source = source_digest(root)
        lock_file = root / "Cargo.lock"
        current_lock = sha256_file(lock_file) if lock_file.is_file() else None
        binary_digest = sha256_file(exec_binary)
        receipt_digest = sha256_file(receipt_path)
    except Exception:
        raise GateError("source", "source_unavailable") from None

    _need(current_source == validated.source_inputs_sha256, "source", "source_drift")
    payload = validated.payload
    if "cargo_lock_sha256" in payload:
        _need(current_lock == payload["cargo_lock_sha256"], "source", "cargo_lock_drift")
    _need(binary_digest == validated.binary_sha256, "source", "binary_mismatch")

    current_config = None
    bound_digest = None
    if validated.schema == "v2":
        try:
            entries, blobs = bound_input_inventory(root)
            summary = bound_inputs_summary(entries, blobs)
            current_config = config_digest(entries, blobs)
        except Exception:
            raise GateError("source", "source_unavailable") from None
        _need(summary == payload.get("bound_inputs"), "source", "source_drift")
        _need(current_config == validated.config_digest, "source", "config_drift")
        bound_digest = summary["digest"]

    return {
        "schema": validated.schema,
        "head": head,
        "binary_sha256": binary_digest,
        "source_inputs_sha256": current_source,
        "receipt_source_inputs_sha256": validated.source_inputs_sha256,
        "cargo_lock_sha256": current_lock,
        "config_digest": current_config,
        "bound_inputs_digest": bound_digest,
        "receipt_sha256": receipt_digest,
    }


def compare_immutable(
    start: dict[str, object],
    end: dict[str, object],
    *,
    receipt_copy_path: Path | None,
    expected_receipt_sha256: str,
) -> dict[str, bool]:
    checks = {
        "binary": start["binary_sha256"] == end["binary_sha256"],
        "source": start["source_inputs_sha256"] == end["source_inputs_sha256"],
        "cargo_lock": start["cargo_lock_sha256"] == end["cargo_lock_sha256"],
        "config": start["config_digest"] == end["config_digest"],
        "bound_inputs": start["bound_inputs_digest"] == end["bound_inputs_digest"],
        "receipt": start["receipt_sha256"] == end["receipt_sha256"],
        "head": start["head"] == end["head"],
        "schema": start["schema"] == end["schema"],
        "receipt_source": start["receipt_source_inputs_sha256"] == end["receipt_source_inputs_sha256"],
    }
    if receipt_copy_path is not None:
        copied = _read_regular_bytes(receipt_copy_path, "immutable", "immutable_drift", "immutable_drift")
        checks["receipt_copy"] = sha256_bytes(copied) == expected_receipt_sha256
    if not all(checks.values()):
        raise GateError("immutable", "immutable_drift")
    return checks


def parse_ignored_inventory(text: str) -> list[str]:
    """Parse ``--ignored --list`` output strictly against EXPECTED_CASE_SET without retaining lines."""
    cleaned = _ANSI_RE.sub("", text)
    discovered: list[str] = []
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if not line or _LIST_SUMMARY_RE.fullmatch(line):
            continue
        match = _LIST_TEST_RE.fullmatch(line)
        _need(match is not None, "inventory", "inventory_mismatch")
        name = match.group(1)
        _need(name in EXPECTED_CASE_SET, "inventory", "inventory_mismatch")
        _need(name not in discovered, "inventory", "inventory_mismatch")
        discovered.append(name)
    _need(set(discovered) == EXPECTED_CASE_SET, "inventory", "inventory_mismatch")
    return discovered


def _classify_failure_code(text: str) -> str:
    lowered = text.lower()
    if "lock timeout" in lowered or "canceling statement due to lock timeout" in lowered:
        return "lock_timeout"
    if "sqlx" in lowered or "postgres" in lowered or "database" in lowered:
        return "pg_error"
    if "garage" in lowered or "opendal" in lowered or "s3" in lowered:
        return "s3_error"
    if "assertion" in lowered or "panicked" in lowered:
        return "assertion_failed"
    return "test_failed"


def _extract_case_statuses(text: str) -> dict[str, str]:
    statuses = {name: "not_run" for name in EXPECTED_CASES}
    for raw_name, outcome in _CASE_RE.findall(text):
        if raw_name in EXPECTED_CASE_SET:
            statuses[raw_name] = _OUTCOME_MAP[outcome]
    return statuses


def parse_test_execution(
    stdout_text: str, stderr_text: str, returncode: int
) -> tuple[dict[str, int], dict[str, str]]:
    """Parse libtest execution in memory; raise an allowlisted code cleanly on failure."""
    cleaned_stdout = _ANSI_RE.sub("", stdout_text)
    combined = f"{cleaned_stdout}\n{_ANSI_RE.sub('', stderr_text)}"
    statuses = _extract_case_statuses(cleaned_stdout)

    running = _RUNNING_RE.findall(cleaned_stdout)
    results = _RESULT_RE.findall(cleaned_stdout)
    parsed_counts: dict[str, int] | None = None
    if len(results) == 1:
        status_word, passed_s, failed_s, ignored_s = results[0]
        parsed_counts = {
            "passed": int(passed_s),
            "failed": int(failed_s),
            "ignored": int(ignored_s),
        }
    else:
        status_word = ""

    if returncode != 0:
        code = _classify_failure_code(combined)
        raise GateError(
            "execute",
            code,
            exit_code=returncode,
            counts=parsed_counts,
            case_statuses=statuses,
        )

    cases = _CASE_RE.findall(cleaned_stdout)
    _need(
        len(running) == 1,
        "parse",
        "output_invalid",
        exit_code=returncode,
        counts=parsed_counts,
        case_statuses=statuses,
    )
    _need(
        int(running[0]) == len(EXPECTED_CASES),
        "parse",
        "zero_tests",
        exit_code=returncode,
        counts=parsed_counts,
        case_statuses=statuses,
    )
    _need(
        parsed_counts is not None,
        "parse",
        "output_invalid",
        exit_code=returncode,
        case_statuses=statuses,
    )
    passed = parsed_counts["passed"]
    failed = parsed_counts["failed"]
    ignored = parsed_counts["ignored"]
    _need(
        not (passed == 0 and failed == 0 and ignored == 0),
        "parse",
        "zero_tests",
        exit_code=returncode,
        counts=parsed_counts,
        case_statuses=statuses,
    )
    _need(
        ignored == 0,
        "parse",
        "ignored_tests",
        exit_code=returncode,
        counts=parsed_counts,
        case_statuses=statuses,
    )
    _need(
        failed == 0 and status_word == "ok",
        "parse",
        "test_failed",
        exit_code=returncode,
        counts=parsed_counts,
        case_statuses=statuses,
    )
    _need(
        passed == len(EXPECTED_CASES),
        "parse",
        "zero_tests",
        exit_code=returncode,
        counts=parsed_counts,
        case_statuses=statuses,
    )
    _need(
        len(cases) == len(EXPECTED_CASES),
        "parse",
        "case_identity",
        exit_code=returncode,
        counts=parsed_counts,
        case_statuses=statuses,
    )
    _need(
        {name for name, _ in cases} == EXPECTED_CASE_SET,
        "parse",
        "case_identity",
        exit_code=returncode,
        counts=parsed_counts,
        case_statuses=statuses,
    )
    for _name, outcome in cases:
        _need(
            outcome == "ok",
            "parse",
            "test_failed",
            exit_code=returncode,
            counts=parsed_counts,
            case_statuses=statuses,
        )
    return parsed_counts, statuses


def run_in_memory_acceptance(
    exec_binary: Path,
    *,
    root: Path,
    list_timeout: float,
    timeout: float,
) -> tuple[int, int, dict[str, int], dict[str, str]]:
    """Run ``--ignored --list`` and ``--ignored --test-threads=1`` strictly in memory."""
    try:
        listed = run_subprocess(
            [str(exec_binary), "--ignored", "--list"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=list_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise GateError("inventory", "inventory_timeout") from None
    except OSError:
        raise GateError("inventory", "inventory_spawn_failed") from None
    _need(listed.returncode == 0, "inventory", "inventory_nonzero", exit_code=listed.returncode)
    discovered = parse_ignored_inventory(listed.stdout or "")

    try:
        executed = run_subprocess(
            [str(exec_binary), "--ignored", "--test-threads=1"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise GateError("execute", "timeout") from None
    except OSError:
        raise GateError("execute", "spawn_failed") from None

    counts, statuses = parse_test_execution(executed.stdout or "", executed.stderr or "", executed.returncode)
    return len(discovered), executed.returncode, counts, statuses


def _receipt_summary(validated: receipt_contract.ValidatedReceipt | None) -> dict | None:
    if validated is None:
        return None
    payload = validated.payload
    summary: dict[str, object] = {
        "schema": validated.schema,
        "kind": payload.get("kind"),
        "relocated_artifact": payload.get("relocated_artifact"),
        "command": list(payload.get("command") or []),
    }
    if validated.schema == "v1":
        summary["fresh"] = False
        summary["rustc"] = payload.get("rustc")
        return summary
    artifacts = [
        {
            "target": row.get("target"),
            "kind": row.get("kind"),
            "fresh": row.get("fresh"),
            "source": row.get("source"),
        }
        for row in validated.artifacts
    ]
    fresh_vals = {row["fresh"] for row in artifacts}
    fresh_rollup = next(iter(fresh_vals)) if len(fresh_vals) == 1 else "mixed"
    toolchain = validated.toolchain or {}
    summary.update(
        {
            "fresh": fresh_rollup,
            "cargo_artifacts": artifacts,
            "features": dict(payload.get("features") or {}),
            "profile": payload.get("profile"),
            "target_triple": payload.get("target_triple"),
            "toolchain": {
                tool: {k: (toolchain.get(tool) or {}).get(k) for k in ("release", "commit_hash")}
                for tool in ("cargo", "rustc")
            },
        }
    )
    return summary


def build_report(
    *,
    passed: bool,
    validated: receipt_contract.ValidatedReceipt | None,
    start: dict[str, object] | None,
    end: dict[str, object] | None,
    discovered_count: int,
    test_exit_code: int | None,
    counts: dict[str, int] | None,
    case_statuses: dict[str, str],
    timeout: float,
    failure: dict[str, object] | None = None,
    immutable: dict[str, bool] | None = None,
) -> dict[str, object]:
    snapshot = start or end
    cases = [
        {
            "name": name,
            "status": "passed" if passed else case_statuses.get(name, "failed"),
        }
        for name in EXPECTED_CASES
    ]
    if not passed and failure is not None:
        for row in cases:
            if row["status"] != "passed":
                row["error_code"] = failure["code"]
    return {
        "kind": REPORT_KIND,
        "passed": bool(passed),
        "cases": cases,
        "failure": failure,
        "binary_sha256": snapshot["binary_sha256"] if snapshot else (validated.binary_sha256 if validated else None),
        "source_head": snapshot["head"] if snapshot else None,
        "source_inputs_sha256": snapshot["source_inputs_sha256"] if snapshot else None,
        "receipt_schema": snapshot["schema"] if snapshot else (validated.schema if validated else None),
        "receipt_source_inputs_sha256": (
            snapshot["receipt_source_inputs_sha256"]
            if snapshot
            else (validated.source_inputs_sha256 if validated else None)
        ),
        "config_digest": snapshot["config_digest"] if snapshot else None,
        "cargo_lock_sha256": snapshot["cargo_lock_sha256"] if snapshot else None,
        "build_receipt_sha256": snapshot["receipt_sha256"] if snapshot else (validated.receipt_sha256 if validated else None),
        "receipt_workspace_commit": validated.workspace_commit if validated else None,
        "receipt": _receipt_summary(validated),
        "inventory": {
            "discovered_count": discovered_count,
            "expected_count": len(EXPECTED_CASES),
        },
        "test": {
            "exit_code": test_exit_code,
            "timeout_seconds": timeout,
            "passed": counts["passed"] if counts else 0,
            "failed": counts["failed"] if counts else 0,
            "ignored": counts["ignored"] if counts else 0,
        },
        "start": snapshot,
        "end": end,
        "immutable": immutable,
    }


def format_allowlisted_summary(report: dict[str, object]) -> str:
    """Render strictly bounded ASCII summary lines with zero raw Rust lines or env values."""
    passed = bool(report["passed"])
    lines: list[str] = []
    if passed:
        lines.append(SUMMARY_PASS_MARKER)
    else:
        failure = report.get("failure") or {}
        lines.append(f"w1c native acceptance: failed ({failure.get('stage')}/{failure.get('code')})")
    test_info = report.get("test") or {}
    inv = report.get("inventory") or {}
    lines.append(
        " ".join(
            [
                f"stage={'complete' if passed else (report.get('failure') or {}).get('stage')}",
                f"exit_code={test_info.get('exit_code')}",
                f"list_cases={inv.get('discovered_count')}",
                f"passed={test_info.get('passed')}",
                f"failed={test_info.get('failed')}",
                f"ignored={test_info.get('ignored')}",
            ]
        )
    )
    for case in report.get("cases") or ():
        lines.append(f"case={case['name']} status={case['status']}")
    receipt = report.get("receipt") or {}
    lines.append(
        f"receipt_schema={receipt.get('schema')} kind={receipt.get('kind')} fresh={receipt.get('fresh')}"
    )
    return "\n".join(lines) + "\n"


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def run_gate(
    args: argparse.Namespace,
    *,
    root: Path | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[int, dict[str, object]]:
    workspace_root = ROOT if root is None else Path(root)
    validated: receipt_contract.ValidatedReceipt | None = None
    start: dict[str, object] | None = None
    end: dict[str, object] | None = None
    immutable: dict[str, bool] | None = None
    counts: dict[str, int] | None = None
    discovered_count = 0
    test_exit_code: int | None = None
    case_statuses = {name: "not_run" for name in EXPECTED_CASES}
    timeout = float(args.timeout)

    try:
        timeout = _require_timeout(args.timeout)
        list_timeout = _require_timeout(args.list_timeout, max_seconds=300.0)
        require_runtime_environment(environ)
        receipt_path = Path(args.build_receipt).expanduser().resolve()
        alias_binary = Path(args.binary).expanduser().resolve() if args.binary else None
        build_report_path = Path(args.build_report).expanduser().resolve() if args.build_report else None
        expected_store_root = (
            Path(args.expected_store_root).expanduser() if args.expected_store_root else None
        )
        validated, exec_binary, raw_bytes, receipt_sha256 = load_and_verify_receipt(
            receipt_path,
            root=workspace_root,
            alias_binary=alias_binary,
            build_report_path=build_report_path,
            expected_store_root=expected_store_root,
            expected_commit=args.expected_commit,
            require_cas=bool(args.require_cas),
            require_ci_pins=bool(args.require_ci_pins),
            require_package_debug_zero=bool(args.require_package_debug_zero),
            require_strip_debuginfo=bool(args.require_strip_debuginfo),
        )
        start = capture_source_snapshot(
            validated,
            root=workspace_root,
            receipt_path=receipt_path,
            exec_binary=exec_binary,
            expected_commit=args.expected_commit,
        )
        copy_path: Path | None = None
        if args.receipt_copy:
            copy_path = Path(args.receipt_copy).expanduser().resolve()
            copy_path.parent.mkdir(parents=True, exist_ok=True)
            if hasattr(os, "fchmod"):
                try:
                    collect_raw_receipt(receipt_path, copy_path, receipt_sha256)
                except receipt_collector.CollectionError:
                    raise GateError("receipt", "receipt_copy_failed") from None
            else:
                try:
                    if copy_path.exists():
                        existing = _read_regular_bytes(
                            copy_path, "receipt", "receipt_copy_failed", "receipt_copy_failed"
                        )
                        _need(existing == raw_bytes, "receipt", "receipt_copy_failed")
                    else:
                        fd = os.open(copy_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(raw_bytes)
                        os.chmod(copy_path, 0o444)
                except GateError:
                    raise
                except OSError:
                    raise GateError("receipt", "receipt_copy_failed") from None
        if args.canonical_path_out:
            _atomic_write_text(Path(args.canonical_path_out).expanduser(), f"{exec_binary}\n")

        discovered_count, test_exit_code, counts, case_statuses = run_in_memory_acceptance(
            exec_binary, root=workspace_root, list_timeout=list_timeout, timeout=timeout
        )
        try:
            end = capture_source_snapshot(
                validated,
                root=workspace_root,
                receipt_path=receipt_path,
                exec_binary=exec_binary,
                expected_commit=args.expected_commit,
            )
            immutable = compare_immutable(
                start,
                end,
                receipt_copy_path=copy_path,
                expected_receipt_sha256=receipt_sha256,
            )
        except GateError:
            raise GateError("immutable", "immutable_drift") from None
        report = build_report(
            passed=True,
            validated=validated,
            start=start,
            end=end,
            discovered_count=discovered_count,
            test_exit_code=test_exit_code,
            counts=counts,
            case_statuses=case_statuses,
            timeout=timeout,
            immutable=immutable,
        )
        return 0, report
    except GateError as error:
        if error.stage in ("execute", "parse") and discovered_count == 0:
            discovered_count = len(EXPECTED_CASES)
        if error.exit_code is not None:
            test_exit_code = error.exit_code
        if error.counts is not None:
            counts = error.counts
        if error.case_statuses is not None:
            case_statuses = error.case_statuses
        report = build_report(
            passed=False,
            validated=validated,
            start=start,
            end=end,
            discovered_count=discovered_count,
            test_exit_code=test_exit_code,
            counts=counts,
            case_statuses=case_statuses,
            timeout=timeout,
            failure={
                "stage": error.stage,
                "code": error.code,
                "exit_code": error.exit_code,
            },
            immutable=immutable,
        )
        return 1, report
    except Exception:
        report = build_report(
            passed=False,
            validated=validated,
            start=start,
            end=end,
            discovered_count=discovered_count,
            test_exit_code=test_exit_code,
            counts=counts,
            case_statuses=case_statuses,
            timeout=timeout,
            failure={"stage": "internal", "code": "internal_error", "exit_code": None},
            immutable=immutable,
        )
        return 1, report


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", required=True, help="prebuilt .build.json receipt path")
    parser.add_argument("--build-report", help="optional stdout JSON report from build_native_test.py")
    parser.add_argument("--binary", help="optional compatibility alias binary path to verify")
    parser.add_argument("--expected-store-root", help="optional expected artifact_store CAS root directory")
    parser.add_argument("--receipt-copy", help="optional idempotent readonly raw receipt destination")
    parser.add_argument("--canonical-path-out", help="optional file to write verified canonical binary path")
    parser.add_argument("--report", type=Path, required=True, help="allowlisted JSON acceptance report")
    parser.add_argument("--summary-log", type=Path, required=True, help="allowlisted ASCII summary log")
    parser.add_argument("--expected-commit", help="require receipt and HEAD commit match this SHA")
    parser.add_argument("--timeout", type=float, default=300.0, help="test execution timeout in seconds")
    parser.add_argument("--list-timeout", type=float, default=30.0, help="inventory list timeout in seconds")
    parser.add_argument("--require-cas", action="store_true", help="require sealed artifact_store CAS receipt")
    parser.add_argument("--require-ci-pins", action="store_true", help="require pinned CI rustc/cargo metadata")
    parser.add_argument(
        "--require-package-debug-zero",
        action="store_true",
        help="require profile.{dev,test}.package.rootyard.debug=0 config options",
    )
    parser.add_argument(
        "--require-strip-debuginfo",
        action="store_true",
        help='require profile.{dev,test}.package.rootyard.strip="debuginfo" config options',
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    status, report = run_gate(args)
    summary_text = format_allowlisted_summary(report)
    try:
        _atomic_write_text(args.report, json.dumps(report, indent=2, sort_keys=True) + "\n")
        _atomic_write_text(args.summary_log, summary_text)
    except OSError:
        print("w1c native acceptance: failed (report/report_write_failed)", file=sys.stderr, flush=True)
        return 1
    print(summary_text, end="", flush=True)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
