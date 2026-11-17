"""Source and same-source receipt preflight for the producer PG runner.

The snapshot binds the clean expected commit/tree, the shared production and
bound-input inventories, ``Cargo.lock``, the actual Pando schema, and every
runner/support/test source file.  It is sampled before artifact selection and
again after every case; the orchestration retains the first trusted snapshot and
never rewrites it from a later read.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sys
import time

SCRIPTS = Path(__file__).resolve().parents[1]
ROOT = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import native_build_receipt as receipts  # noqa: E402

from .errors import RunnerError, require  # noqa: E402

SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
SCHEMA_REL = "experimental/pando/schema.sql"

# The merged Rust target's producer/snapshot sources plus the approved fixture
# ownership helpers and this runner.  Missing entries fail closed.
EXPLICIT_INPUTS = (
    "src/bin/rootyard-pando-lab.rs",
    "src/pando_lab/mod.rs",
    "src/pando_lab/migration.rs",
    "src/pando_lab/migration/producer.rs",
    "src/pando_lab/migration/pg_tests.rs",
    "src/pando_lab/migration/pg_test_support.rs",
    "src/pando_lab/repack.rs",
    "src/pando_lab/repack/authority.rs",
    "src/pando_lab/repack/pg_tests.rs",
    "src/pando_lab/repack/test_support.rs",
    "src/pando_lab/store.rs",
    "src/pando_lab/store/snapshot_retention.rs",
    "src/pando_lab/store/snapshot_pg_tests.rs",
    "src/pando_lab/store/snapshot_race_pg_tests.rs",
    "src/pando_lab/store/snapshot_pg_support.rs",
    "src/pando_lab/store/snapshot_pg_barrier.rs",
    SCHEMA_REL,
    "tests/pando_vault_rotation_fixture_resources.py",
    "tests/pando_vault_rotation_fixture.py",
    "scripts/run_pando_producer_pg.py",
    "tests/test_pando_producer_pg_runner.py",
)
SUPPORT_GLOBS = ("scripts/pando_producer_pg/*.py",)
TEST_GLOBS = ("tests/test_pando_producer_pg*.py",)
COMPARE_KEYS = (
    "source_commit",
    "source_tree",
    "source_clean",
    "source_inputs_sha256",
    "bound_inputs_sha256",
    "bound_inputs_present_count",
    "bound_inputs_absent_count",
    "cargo_lock_sha256",
    "config_digest",
    "schema_sha256",
    "input_hashes",
    "runner_source_hashes",
)

# These two are module attributes so the pure tests can replace the probes with
# deterministic fixtures without importing a builder or invoking Git.
git_state = receipts.git_state
capture_bound_inputs = receipts.capture_bound_inputs
load_receipt = receipts.load_receipt


def _sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _deadline_hit(deadline, clock):
    return deadline is not None and clock() >= deadline


def _sha256_file(path, deadline=None, clock=time.monotonic):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            if _deadline_hit(deadline, clock):
                raise RunnerError("source", "source_capture_deadline_exceeded")
            digest.update(chunk)
    return digest.hexdigest()


def _hash_rows(root, deadline=None, clock=time.monotonic):
    rows = {}
    for relative in EXPLICIT_INPUTS:
        if _deadline_hit(deadline, clock):
            raise RunnerError("source", "source_capture_deadline_exceeded")
        path = root / relative
        require(path.is_file(), "source", "source_capture_failed")
        rows[relative] = _sha256_file(path, deadline=deadline, clock=clock)
    for pattern in SUPPORT_GLOBS + TEST_GLOBS:
        for path in sorted(root.glob(pattern)):
            if _deadline_hit(deadline, clock):
                raise RunnerError("source", "source_capture_deadline_exceeded")
            if path.is_file():
                rows[path.relative_to(root).as_posix()] = _sha256_file(
                    path, deadline=deadline, clock=clock
                )
    return [
        {"path": relative, "sha256": rows[relative]}
        for relative in sorted(rows)
    ]


def _runner_rows(rows):
    result = []
    for row in rows:
        path = row["path"]
        if (
            path == "scripts/run_pando_producer_pg.py"
            or path.startswith("scripts/pando_producer_pg/")
            or path.startswith("tests/test_pando_producer_pg")
        ):
            result.append(dict(row))
    return result


def capture(
    source_root,
    expected_commit,
    *,
    expected_tree=None,
    environ=None,
    deadline=None,
    clock=time.monotonic,
):
    """Return the trusted binding snapshot or a fixed failure."""
    root = Path(source_root).resolve()
    require(root.is_dir(), "source", "source_root_missing")
    if _deadline_hit(deadline, clock):
        raise RunnerError("source", "source_capture_deadline_exceeded")
    require(
        isinstance(expected_commit, str) and SHA_RE.fullmatch(expected_commit) is not None,
        "input",
        "missing_expected_commit",
    )
    if expected_tree is not None:
        require(
            isinstance(expected_tree, str) and SHA_RE.fullmatch(expected_tree) is not None,
            "input",
            "invalid_arguments",
        )
    try:
        state = git_state(root)
    except Exception:
        raise RunnerError("source", "git_unavailable") from None
    if _deadline_hit(deadline, clock):
        raise RunnerError("source", "source_capture_deadline_exceeded")
    require(isinstance(state, dict), "source", "source_capture_failed")
    require(state.get("commit") == expected_commit, "source", "commit_mismatch")
    if expected_tree is not None:
        require(state.get("tree") == expected_tree, "source", "tree_mismatch")
    require(state.get("clean") is True, "source", "source_not_clean")
    try:
        bound = capture_bound_inputs(root, environ=environ)
    except receipts.ReceiptError:
        raise RunnerError("source", "source_capture_failed") from None
    except (OSError, ValueError, TypeError):
        raise RunnerError("source", "source_capture_failed") from None
    if _deadline_hit(deadline, clock):
        raise RunnerError("source", "source_capture_deadline_exceeded")
    try:
        summary = bound["bound_inputs"]
        source_inputs = bound["source_inputs_sha256"]
        cargo_lock = bound["cargo_lock_sha256"]
        config_digest = bound["config_digest"]
        present = summary["present_count"]
        absent = summary["absent_count"]
        bound_digest = summary["digest"]
    except (KeyError, TypeError):
        raise RunnerError("source", "source_capture_failed") from None
    try:
        rows = _hash_rows(root, deadline=deadline, clock=clock)
    except RunnerError:
        raise
    except (OSError, ValueError, TypeError):
        raise RunnerError("source", "source_capture_failed") from None
    if _deadline_hit(deadline, clock):
        raise RunnerError("source", "source_capture_deadline_exceeded")
    schema = next(
        (row["sha256"] for row in rows if row["path"] == SCHEMA_REL), None
    )
    require(schema is not None, "source", "schema_missing")
    return {
        "source_commit": state["commit"],
        "source_tree": state["tree"],
        "source_clean": True,
        "expected_commit": expected_commit,
        "expected_tree": expected_tree or state["tree"],
        "source_inputs_sha256": source_inputs,
        "bound_inputs_sha256": bound_digest,
        "bound_inputs_present_count": present,
        "bound_inputs_absent_count": absent,
        "cargo_lock_sha256": cargo_lock,
        "config_digest": config_digest,
        "schema_sha256": schema,
        "input_hashes": rows,
        "runner_source_hashes": _runner_rows(rows),
    }


def same(before, after):
    """True only when every trusted source binding is byte-identical."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    return all(before.get(key) == after.get(key) for key in COMPARE_KEYS)


def verify_unchanged(before, after):
    if not same(before, after):
        raise RunnerError("binding", "source_drift")
    return True


def validate_product_receipt(path, source_root, expected_commit, expected_source_inputs):
    """Validate the exported Pando product receipt as same-source evidence only.

    The receipt is never treated as the selected bin-unit-test receipt.  No
    product binary is inferred, hashed or attached to the test harness, and the
    helper records that boundary explicitly.
    """
    if path is None:
        return {
            "provided": False,
            "same_source": False,
            "used_as_test_binary_receipt": False,
            "attached_to_native_gate": False,
        }
    receipt = Path(path)
    require(receipt.is_file(), "source", "product_receipt_missing")
    try:
        validated = load_receipt(
            receipt,
            source_root=source_root,
            infer_binary=False,
            expected_commit=expected_commit,
            forbid_implicit_build=True,
        )
    except receipts.ReceiptError:
        raise RunnerError("source", "product_receipt_invalid") from None
    except (OSError, ValueError, TypeError):
        raise RunnerError("source", "product_receipt_invalid") from None
    require(
        validated.workspace_commit == expected_commit,
        "source",
        "product_receipt_source_mismatch",
    )
    require(
        validated.source_inputs_sha256 == expected_source_inputs,
        "source",
        "product_receipt_source_mismatch",
    )
    artifacts = [
        row
        for row in (validated.artifacts or ())
        if isinstance(row, dict)
        and row.get("target") == "rootyard-pando-lab"
        and row.get("kind") == "bin"
    ]
    require(bool(artifacts), "source", "product_receipt_artifact_missing")
    return {
        "provided": True,
        "same_source": True,
        "receipt_sha256": validated.receipt_sha256,
        "workspace_commit": validated.workspace_commit,
        "source_inputs_sha256": validated.source_inputs_sha256,
        "pando_artifact_present": True,
        "used_as_test_binary_receipt": False,
        "attached_to_native_gate": False,
    }
