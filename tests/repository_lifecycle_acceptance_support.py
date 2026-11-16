"""Safe, pure support for the Issue #85 literal acceptance runner.

This module deliberately contains no service, database, Git clone/push, LFS
network, Docker, compiler or Cargo execution.  It classifies failures,
allowlists report detail, reads the immutable source identity, captures the
new acceptance-input manifest, and validates the canonical build receipt
through the existing ``scripts/native_build_receipt.py`` reader with source
files re-verified against the exact current source root.

The four-case inventory is exactly the reviewed plan IDs.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

REPORT_SCHEMA = "issue85-repository-lifecycle-acceptance-v1"

# Exactly the four plan case IDs, in plan order.
PLAN_CASE_NAMES = (
    "backup_root_blocks_purge",
    "serving_read_header_blocks_purge",
    "ci_pin_blocks_purge",
    "rename_alias_accepts_real_git_and_lfs_writes",
)

# All new acceptance inputs are bound by the helper manifest.  The fixed list
# is intentionally explicit: an untracked or modified helper cannot silently
# become part of the acceptance oracle.
ACCEPTANCE_INPUT_PATHS = (
    "tests/repository_lifecycle_acceptance.py",
    "tests/repository_lifecycle_acceptance_support.py",
    "tests/repository_lifecycle_acceptance_holds.py",
    "tests/repository_lifecycle_acceptance_alias.py",
    "tests/test_repository_lifecycle_acceptance_contract.py",
    "tests/test_repository_lifecycle_acceptance_provenance.py",
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
    """Project a case return value onto the fixed report-detail allowlist."""
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


def is_full_commit(value) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    return len(text) in (40, 64) and all(character in "0123456789abcdef" for character in text)


def is_sha256(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value.lower()
    )


def expected_source_commit(explicit=None, environ=None):
    """Return the externally supplied expected commit and a fixed error class.

    The checkout HEAD is never silently substituted for the trusted run
    context; the caller must supply this anchor through the CLI, the CI
    environment or ``GITHUB_SHA``.
    """
    environ = os.environ if environ is None else environ
    value = explicit or environ.get("ROOTYARD_EXPECTED_SOURCE_COMMIT") or environ.get("GITHUB_SHA")
    if not value:
        return None, "expected_source_commit_missing"
    normalized = str(value).strip().lower()
    if not is_full_commit(normalized):
        return normalized, "expected_source_commit_invalid"
    return normalized, None


def expected_receipt_sha256(explicit=None, environ=None):
    """Return an optional externally trusted receipt digest anchor."""
    environ = os.environ if environ is None else environ
    value = explicit or environ.get("ROOTYARD_EXPECTED_BUILD_RECEIPT_SHA256")
    if not value:
        return None, "receipt_anchor_missing"
    normalized = str(value).strip().lower()
    if not is_sha256(normalized):
        return normalized, "receipt_anchor_invalid"
    return normalized, None


def source_identity(root, receipts=None):
    """Return commit/tree/parents plus full tracked and untracked Git state.

    ``git_state`` is the existing receipt-reader helper: it reports tracked
    changes and non-ignored untracked files while keeping ignored build/cache
    outputs out of the dirty state.  Only counts and booleans are projected;
    untracked paths are never emitted.
    """
    module = receipts or _receipt_module(root)
    state = module.git_state(root)
    parents = _git(root, "show", "-s", "--format=%P", "HEAD").split()
    return {
        "commit": state["commit"],
        "tree": state["tree"],
        "parents": parents,
        "working_tree_dirty": state["dirty"],
        "tracked_dirty": state["tracked_dirty"],
        "untracked_count": state["untracked_count"],
        "clean": state["clean"],
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
        module_name = (
            "rootyard_acceptance_native_build_receipt_"
            + hashlib.sha256(key.encode()).hexdigest()[:16]
        )
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError("canonical receipt module is unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _RECEIPT_MODULES[key] = module
    return module


def _git_blob(root, relative):
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "cat-file", "blob", f"HEAD:{relative}"],
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def helper_input_manifest(root, committed_reader=None):
    """Hash every new acceptance input and compare it with the HEAD blob.

    The reader is injectable only so pure tests can supply file data without a
    repository.  Production always uses ``git cat-file HEAD:<path>``; a
    missing, untracked or modified helper makes ``bound`` false.
    """
    root = Path(root)
    reader = committed_reader or (lambda relative: _git_blob(root, relative))
    files = []
    bound = True
    for relative in ACCEPTANCE_INPUT_PATHS:
        path = root / relative
        if not path.is_file():
            bound = False
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        committed = reader(relative)
        if committed is None or hashlib.sha256(committed).hexdigest() != digest:
            bound = False
        files.append({"path": relative, "sha256": digest, "bytes": len(data)})
    files.sort(key=lambda item: item["path"])
    manifest = {"version": 1, "files": files}
    manifest_sha256 = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "bound": bound,
        "manifest_sha256": manifest_sha256,
        "count": len(files),
        "expected_count": len(ACCEPTANCE_INPUT_PATHS),
        "files": files,
        "error_class": None if bound else "helper_inputs_invalid",
    }


def receipt_covers_helper_inputs(payload, helper_files):
    """Whether the canonical receipt's bound inventory already names the helpers."""
    if not isinstance(payload, dict) or not helper_files:
        return False
    inventory = payload.get("bound_input_inventory")
    if not isinstance(inventory, list):
        return False
    recorded = {}
    for entry in inventory:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            recorded[entry["path"]] = entry.get("sha256")
    return all(
        recorded.get(item.get("path")) == item.get("sha256") for item in helper_files
    )


def bind_build_receipt(
    binary,
    receipt_path,
    expected_commit,
    source_root,
    *,
    module_root=None,
    validator=None,
    helper_files=None,
    expected_receipt_sha256=None,
):
    """Validate the canonical receipt against the exact current source root.

    The receipt bytes are read once, hashed, and parsed from that same buffer;
    the caller-supplied digest is passed as ``receipt_sha256`` so the reader
    cannot silently re-read a racing file.  A post-validation byte comparison
    additionally rejects a file mutated during validation.  Validation uses
    ``source_root=<current source>`` and ``verify_source_files=True``; there is
    no weak ``verify_source_files=False`` fallback.  No Cargo/rustc/builder is
    invoked.
    """
    result = {
        "present": False,
        "bound": False,
        "error_class": "build_receipt_missing",
        "receipt_anchor_present": expected_receipt_sha256 is not None,
    }
    path = Path(receipt_path)
    if not path.is_file() or path.is_symlink():
        return result
    if expected_receipt_sha256 is not None and not is_sha256(expected_receipt_sha256):
        return {
            **result,
            "present": True,
            "error_class": "receipt_anchor_invalid",
        }
    try:
        raw = path.read_bytes()
        receipt_sha256 = hashlib.sha256(raw).hexdigest()
        if expected_receipt_sha256 is not None and receipt_sha256 != expected_receipt_sha256:
            return {
                **result,
                "present": True,
                "receipt_sha256": receipt_sha256,
                "expected_receipt_sha256": expected_receipt_sha256,
                "receipt_anchor_matches": False,
                "error_class": "build_receipt_anchor_mismatch",
            }
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("receipt payload is not an object")
        receipts = validator or _receipt_module(module_root or source_root)
        validated = receipts.validate_receipt(
            payload,
            source_root=Path(source_root),
            receipt_path=path,
            receipt_sha256=receipt_sha256,
            binary_path=Path(binary),
            expected_commit=expected_commit,
            verify_source_files=True,
        )
        immutability_check = hashlib.sha256(path.read_bytes()).hexdigest()
        if immutability_check != receipt_sha256 or validated.receipt_sha256 != receipt_sha256:
            raise ValueError("receipt bytes changed during validation")
    except Exception:
        return {
            **result,
            "present": True,
            "error_class": "build_receipt_invalid",
        }
    binary_sha256 = sha256_file(binary)
    bound = (
        expected_commit is not None
        and validated.binary_sha256 == binary_sha256
        and validated.workspace_commit == expected_commit
        and (
            expected_receipt_sha256 is None
            or receipt_sha256 == expected_receipt_sha256
        )
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
        "source_root_verified": True,
        "receipt_byte_stable": True,
        "receipt_anchor_present": expected_receipt_sha256 is not None,
        "receipt_anchor_matches": (
            expected_receipt_sha256 is None or receipt_sha256 == expected_receipt_sha256
        ),
        "receipt_covers_helper_inputs": receipt_covers_helper_inputs(
            payload, helper_files or []
        ),
    }
    working_tree = payload.get("working_tree")
    if isinstance(working_tree, dict):
        if isinstance(working_tree.get("tree"), str):
            result["recorded_tree"] = working_tree["tree"]
        if "clean" in working_tree:
            result["recorded_tree_clean"] = bool(working_tree["clean"])
    if validated.config_digest is not None:
        result["config_digest"] = validated.config_digest
    return result


def evaluate_binding(source, expected_commit, receipt, binary_sha256, helper_inputs):
    """Pure policy: clean exact-source, verified receipt and helper inputs."""
    recorded_tree = receipt.get("recorded_tree")
    recorded_tree_clean = receipt.get("recorded_tree_clean")
    checks = {
        "source_commit_present": isinstance(source.get("commit"), str)
        and bool(source.get("commit")),
        "source_tree_present": isinstance(source.get("tree"), str)
        and bool(source.get("tree")),
        "source_clean": source.get("clean") is True,
        "expected_commit_present": isinstance(expected_commit, str)
        and bool(expected_commit),
        "expected_matches_head": bool(expected_commit)
        and expected_commit == source.get("commit"),
        "receipt_present": receipt.get("present") is True,
        "receipt_bound": receipt.get("bound") is True,
        "receipt_commit_matches_head": receipt.get("workspace_commit")
        == source.get("commit"),
        "receipt_binary_matches": receipt.get("binary_sha256") == binary_sha256,
        "receipt_tree_matches": (not recorded_tree) or recorded_tree == source.get("tree"),
        "receipt_working_tree_clean": recorded_tree_clean is not False,
        "receipt_anchor": receipt.get("receipt_anchor_matches") is not False,
        "helper_inputs_bound": helper_inputs.get("bound") is True,
        "helper_inputs_count": helper_inputs.get("count")
        == len(ACCEPTANCE_INPUT_PATHS),
    }
    return {
        "bound": all(checks.values()),
        "checks": checks,
        "error_class": None if all(checks.values()) else "source_binding_failed",
    }


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
