"""Safe, pure support for the Issue #85 literal acceptance runner.

This module deliberately contains no service, database, Git, LFS, network or
Cargo execution.  It only classifies failures, allowlists report detail,
reads the immutable source identity, and validates the adjacent canonical
build receipt through the existing ``scripts/native_build_receipt.py`` reader.

Checkpoint 2 inventory is exactly the four plan case IDs: the three DB-backed
hold cases plus the real rename-alias Git/LFS write case.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import uuid

REPORT_SCHEMA = "issue85-repository-lifecycle-acceptance-v1"

# Checkpoint 2 inventory: exactly the four plan case IDs, in plan order.
PLAN_CASE_NAMES = (
    "backup_root_blocks_purge",
    "serving_read_header_blocks_purge",
    "ci_pin_blocks_purge",
    "rename_alias_accepts_real_git_and_lfs_writes",
)

# Report details are fixed constants/counts only.  Raw response bodies, SQL,
# DSNs, environment values, tokens, service logs and arbitrary assertion
# dictionaries are never admitted by this allowlist.
CASE_DETAIL_KEYS = frozenset(
    {
        "fixture",
        "fixture_scope",
        "producer_claim",
        "hold_kind",
        "hold_count",
        "control_purge",
        "git_retained",
        "lfs_retained",
        "native_head_retained",
        "alias_git_write",
        "alias_lfs_write",
        "restricted_read",
        "restricted_write",
        "denied_mutation",
        "canonical_head",
        "canonical_bytes",
    }
)


def fresh_key(prefix: str) -> str:
    """Return a bounded idempotency key containing only the accepted alphabet."""
    return f"{prefix}-{uuid.uuid4().hex}"


def safe_detail(detail):
    """Project a case return value onto the fixed report-detail allowlist.

    Non-mapping values, unknown keys, nested objects, booleans represented as
    integers and long/unsafe strings are dropped rather than serialized.
    """
    if not isinstance(detail, dict):
        return {}
    projected = {}
    for key, value in detail.items():
        if key not in CASE_DETAIL_KEYS:
            continue
        if isinstance(value, bool):
            projected[key] = value
        elif isinstance(value, int) and not isinstance(value, bool):
            if 0 <= value <= 1_000_000:
                projected[key] = value
        elif isinstance(value, str):
            if 0 < len(value) <= 80 and all(
                character.isascii() and (character.isalnum() or character in "._:-")
                for character in value
            ):
                projected[key] = value
    return projected


def classify_error(error) -> str:
    """Map an exception to a fixed error class; never emit its message."""
    if isinstance(error, AssertionError):
        return "assertion"
    if isinstance(error, subprocess.TimeoutExpired):
        return "timeout"
    if isinstance(error, subprocess.CalledProcessError):
        return "command"
    if isinstance(error, json.JSONDecodeError):
        return "decode"
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, OSError):
        return "io"
    return "other"


def _git(root, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        text=True,
        stderr=subprocess.PIPE,
        timeout=30,
    ).strip()


def source_identity(root):
    """Return the read-only Git source commit/tree/parents and dirty marker."""
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    parents = _git(root, "show", "-s", "--format=%P", "HEAD").split()
    dirty = bool(_git(root, "status", "--porcelain", "--untracked-files=no"))
    return {
        "commit": commit,
        "tree": tree,
        "parents": parents,
        "working_tree_dirty": dirty,
    }


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_receipt(binary, explicit=None, environ=None):
    """Select the canonical build receipt without mutating the checkout."""
    environ = os.environ if environ is None else environ
    if explicit is not None:
        return Path(explicit), "cli"
    configured = environ.get("ROOTYARD_BUILD_RECEIPT")
    if configured:
        return Path(configured), "environment"
    return Path(binary).resolve().with_suffix(".build.json"), "adjacent"


_RECEIPT_MODULES = {}


def _receipt_module(root):
    key = str(Path(root).resolve())
    module = _RECEIPT_MODULES.get(key)
    if module is None:
        path = Path(root) / "scripts" / "native_build_receipt.py"
        spec = importlib.util.spec_from_file_location(
            "rootyard_acceptance_native_build_receipt", path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("canonical receipt module is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _RECEIPT_MODULES[key] = module
    return module


def bind_build_receipt(binary, receipt_path, expected_commit, source_root):
    """Validate the canonical receipt through the existing public reader.

    The call is metadata-only: ``validate_receipt`` hashes the supplied binary,
    checks the receipt schema and enforces the expected source commit.  It
    never invokes Cargo, rustc, rustup or any builder.
    """
    result = {
        "present": False,
        "bound": False,
        "error_class": "build_receipt_missing",
    }
    path = Path(receipt_path)
    if not path.is_file() or path.is_symlink():
        return result
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("receipt payload is not an object")
        receipts = _receipt_module(source_root)
        validated = receipts.validate_receipt(
            payload,
            receipt_path=path,
            binary_path=Path(binary),
            expected_commit=expected_commit,
            verify_source_files=False,
        )
    except Exception:
        return {
            "present": True,
            "bound": False,
            "error_class": "build_receipt_invalid",
        }
    receipt_sha256 = validated.receipt_sha256 or hashlib.sha256(raw).hexdigest()
    binary_sha256 = sha256_file(binary)
    bound = (
        validated.binary_sha256 == binary_sha256
        and expected_commit is not None
        and validated.workspace_commit == expected_commit
    )
    result = {
        "present": True,
        "bound": bound,
        "schema": validated.schema,
        "receipt_sha256": receipt_sha256,
        "binary_sha256": validated.binary_sha256,
        "workspace_commit": validated.workspace_commit,
        "source_inputs_sha256": validated.source_inputs_sha256,
        "expected_commit": expected_commit,
    }
    if validated.config_digest is not None:
        result["config_digest"] = validated.config_digest
    return result


def summarize(case_results, expected_names, cleanup_ok, binding_ok):
    """Return the exact-inventory/no-skip decision for the report."""
    names = [row.get("name") for row in case_results]
    missing = [name for name in expected_names if name not in names]
    unexpected = [name for name in names if name not in expected_names]
    duplicate = len(names) != len(set(names))
    exact = (
        not missing
        and not unexpected
        and not duplicate
        and len(names) == len(expected_names)
    )
    all_passed = bool(case_results) and all(
        row.get("status") == "passed" for row in case_results
    )
    return {
        "passed": bool(exact and all_passed and cleanup_ok and binding_ok),
        "exact": exact,
        "missing": missing,
        "unexpected": unexpected,
        "duplicate": duplicate,
        "all_passed": all_passed,
        "cleanup_ok": bool(cleanup_ok),
        "binding_ok": bool(binding_ok),
    }
