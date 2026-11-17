#!/usr/bin/env python3
"""Private bounded child for one Vault source/receipt binding read.

The parent owns this helper through the approved Popen runner and kills only
that exact child/group when the shared absolute deadline expires.  The child
runs the unchanged ``native_build_receipt`` Git/receipt semantics and emits one
small fixed-shape JSON object.  It never prints argv, environment values,
paths, SQL, provider bodies, child output or exception text.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "tests"), str(ROOT / "scripts")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import native_build_receipt as receipts  # noqa: E402

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
PANDO_TARGET = "rootyard-pando-lab"


def _payload(ok, code=None, stage="binding", **fields):
    value = {"ok": bool(ok), "code": code, "stage": stage}
    value.update(fields)
    return value


def _fail(code, stage="binding"):
    return _payload(False, code=code, stage=stage)


def _pando_artifact(receipt, binary_sha256):
    """Require the modern v2 per-bin Pando artifact, not a v1 secondary row."""
    if getattr(receipt, "schema", None) != "v2":
        return "receipt_pando_receipt_not_v2"
    payload = getattr(receipt, "payload", None)
    if not isinstance(payload, dict) or payload.get(
            "receipt_schema") != receipts.RECEIPT_SCHEMA_V2:
        return "receipt_pando_schema_mismatch"
    rows = [
        row for row in getattr(receipt, "artifacts", ())
        if isinstance(row, dict) and row.get("kind") == "bin"
        and row.get("target") == PANDO_TARGET
    ]
    if not rows:
        return "receipt_pando_artifact_missing"
    if len(rows) != 1:
        return "receipt_pando_artifact_ambiguous"
    value = rows[0].get("executable_sha256")
    if not isinstance(value, str) or value != binary_sha256:
        return "receipt_pando_artifact_mismatch"
    return None


def _validate(argv):
    if len(argv) != 5:
        return _fail("invalid_arguments", "input")
    source_root, expected_commit, binary, receipt, expected_sha = argv
    try:
        state = receipts.require_clean_git_state(source_root)
    except receipts.ReceiptError:
        return _fail("source_not_clean")
    except (OSError, ValueError, TypeError):
        return _fail("source_unreadable")
    if not isinstance(state, dict) or SHA_RE.fullmatch(
            str(state.get("commit"))) is None:
        return _fail("source_unreadable")
    if state.get("commit") != expected_commit:
        return _fail("expected_commit_mismatch")
    try:
        binary_sha256 = receipts.sha256_file(binary)
    except (OSError, ValueError, TypeError):
        return _fail("binary_unreadable")
    try:
        validated = receipts.load_receipt(
            receipt,
            source_root=source_root,
            binary_path=binary,
            expected_commit=expected_commit,
            expected_binary_sha256=(
                None if expected_sha == "-" else expected_sha),
            forbid_implicit_build=True,
        )
    except receipts.ReceiptError:
        return _fail("receipt_rejected")
    except (OSError, ValueError, TypeError):
        return _fail("receipt_unavailable")
    except Exception:
        return _fail("receipt_rejected")
    if validated.binary_sha256 != binary_sha256:
        return _fail("receipt_binary_digest_mismatch")
    if validated.workspace_commit != expected_commit:
        return _fail("receipt_commit_mismatch")
    artifact_code = _pando_artifact(validated, binary_sha256)
    if artifact_code is not None:
        return _fail(artifact_code)
    receipt_sha256 = getattr(validated, "receipt_sha256", None)
    if not isinstance(receipt_sha256, str) or SHA256_RE.fullmatch(
            receipt_sha256) is None:
        return _fail("receipt_unavailable")
    return _payload(
        True,
        source_commit=state["commit"],
        source_tree=str(state.get("tree")),
        source_clean=bool(state.get("clean")),
        binary_sha256=binary_sha256,
        receipt_sha256=receipt_sha256,
    )


def _snapshot(argv):
    if len(argv) != 7:
        return _fail("invalid_arguments", "input")
    (source_root, expected_commit, expected_tree,
     binary, expected_binary_sha, receipt, expected_receipt_sha) = argv
    try:
        state = receipts.git_state(source_root)
    except receipts.ReceiptError:
        return _fail("binding_unavailable")
    except (OSError, ValueError, TypeError):
        return _fail("binding_unavailable")
    if not isinstance(state, dict):
        return _fail("binding_unavailable")
    if state.get("commit") != expected_commit or state.get("tree") != expected_tree:
        return _fail("source_binding_changed")
    if not state.get("clean"):
        return _fail("source_became_dirty")
    try:
        binary_sha256 = receipts.sha256_file(binary)
        receipt_sha256 = receipts.sha256_file(receipt)
    except (OSError, ValueError, TypeError):
        return _fail("binding_unavailable")
    if binary_sha256 != expected_binary_sha:
        return _fail("binary_binding_changed")
    if receipt_sha256 != expected_receipt_sha:
        return _fail("receipt_binding_changed")
    return _payload(
        True,
        source_commit=state["commit"],
        source_tree=state["tree"],
        source_clean=bool(state.get("clean")),
        binary_sha256=binary_sha256,
        receipt_sha256=receipt_sha256,
    )


def run(argv):
    if len(argv) < 2:
        return _payload(False, code="invalid_arguments", stage="input")
    mode = argv[1]
    if mode == "validate":
        return _validate(argv[2:])
    if mode == "snapshot":
        return _snapshot(argv[2:])
    return _payload(False, code="invalid_arguments", stage="input")


def main(argv=None):
    argv = sys.argv if argv is None else argv
    try:
        payload = run(argv)
    except Exception:
        payload = _fail("binding_unavailable")
    try:
        sys.stdout.write(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
