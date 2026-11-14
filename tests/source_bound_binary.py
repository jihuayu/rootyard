"""Bind an executed binary to the candidate's production source bytes.

``native_evidence.build_record`` only proves that an adjacent
``<binary>.build.json`` receipt describes *some* build whose digest equals the
binary.  This module adds the source binding, reusing the shared v1/v2 receipt
reader instead of re-inventing it:

* v2 receipts carry a self-consistent ``bound_input_inventory`` with the
  production source, Cargo.lock, config/toolchain and selected artifact source
  hashes.  Acceptance therefore uses the recorded digest and does not require
  the mutable original source tree, original executable or historical compiler
  installation.
* v1 receipts retain their historical behaviour: production inputs are
  compared against ``scripts/build_native.source_digest()`` in this checkout.
* in both schemas the supplied ``--binary`` is the one hashed, an
  ``expected_commit`` is exact and the receipt bytes are never rewritten.

Nothing here claims a native run happened; it only decides whether a native
run would be attributable to the supplied source-bound binary.  No Cargo,
rustc, rustup, builder or toolchain probe is invoked.
"""
import json
import os
from pathlib import Path
import subprocess

import native_evidence
import ops_provenance

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FIELDS = ("binary_sha256", "source_inputs_sha256", "workspace_commit", "rustc", "command")


class SourceBindingError(RuntimeError):
    pass


def _need(condition, message):
    if not condition:
        raise SourceBindingError(message)


def production_source_digest():
    """The reviewed build-time digest of production source bytes only."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("rootyard_build_native", ROOT / "scripts" / "build_native.py")
    _need(spec is not None and spec.loader is not None, "scripts/build_native.py is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.source_digest()


def _git(*args):
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True, timeout=30).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _v1_record(validated, record, path, expected):
    missing = [name for name in REQUIRED_FIELDS if not record.get(name)]
    _need(not missing, "build receipt is missing " + ", ".join(missing))
    digest = ops_provenance.sha256_file(path)
    _need(len(str(record["source_inputs_sha256"])) == 64, "receipt source_inputs_sha256 is not a SHA-256")
    current_digest = production_source_digest()
    _need(current_digest == record["source_inputs_sha256"], (
        "the executed binary does not match this checkout's production source inputs "
        "(receipt " + record["source_inputs_sha256"][:16] + "..., current " + current_digest[:16] + "...)"))
    if expected:
        _need(record["workspace_commit"] == expected,
              "stale build receipt: workspace_commit differs from the expected source commit")
    head = _git("rev-parse", "HEAD")
    dirty = _git("status", "--porcelain")
    production_dirty = [line for line in (dirty or "").splitlines()
                        if _production_path(line[3:] if len(line) > 3 else "")]
    return {
        "schema": validated.schema,
        "attested": True,
        "binary_sha256": digest,
        "receipt_binary_sha256": record["binary_sha256"],
        "source_inputs_sha256": record["source_inputs_sha256"],
        "current_source_inputs_sha256": current_digest,
        "production_inputs_bound": True,
        "workspace_commit": record["workspace_commit"],
        "expected_commit": expected,
        "current_head": head,
        "head_differs_from_receipt": head != record["workspace_commit"],
        "current_head_production_dirty": production_dirty,
        "receipt_sha256": validated.receipt_sha256,
        "receipt_immutable": True,
        "receipt_toolchain": {"rustc": record["rustc"], "command": record["command"]},
    }


def _v2_record(validated, record, path, expected):
    """Accept a copied/CAS snapshot bound by the receipt, without a probe."""
    _need(validated.toolchain is not None, "v2 build receipt has no toolchain metadata")
    _need(len(str(validated.source_inputs_sha256)) == 64,
          "receipt source_inputs_sha256 is not a SHA-256")
    if expected:
        _need(validated.workspace_commit == expected,
              "stale build receipt: workspace_commit differs from the expected source commit")
    digest = ops_provenance.sha256_file(path)
    _need(digest == validated.binary_sha256,
          "the supplied binary does not match the receipt's bound SHA-256")
    head = _git("rev-parse", "HEAD")
    dirty = _git("status", "--porcelain")
    production_dirty = [line for line in (dirty or "").splitlines()
                        if _production_path(line[3:] if len(line) > 3 else "")]
    return {
        "schema": validated.schema,
        "attested": True,
        "binary_sha256": digest,
        "receipt_binary_sha256": validated.binary_sha256,
        "source_inputs_sha256": validated.source_inputs_sha256,
        "config_digest": validated.config_digest,
        "cargo_lock_sha256": record.get("cargo_lock_sha256"),
        "production_inputs_bound": True,
        "source_snapshot_bound": True,
        "workspace_commit": validated.workspace_commit,
        "expected_commit": expected,
        "current_head": head,
        "head_differs_from_receipt": head != validated.workspace_commit,
        "current_head_production_dirty": production_dirty,
        "receipt_sha256": validated.receipt_sha256,
        "receipt_immutable": True,
        "receipt_toolchain": {
            "rustc": validated.toolchain["rustc"]["version"],
            "cargo": validated.toolchain["cargo"]["version"],
            "target_triple": validated.toolchain["target_triple"],
            "command": record["command"],
        },
    }


def bind(binary, expected_commit=None, environ=None):
    """Return evidence binding ``binary`` to its recorded source, or raise.

    ``expected_commit`` (or ``ROOTYARD_EXPECTED_SOURCE_COMMIT``) additionally
    requires the receipt's ``workspace_commit`` to be that commit.  For v2 the
    current checkout HEAD is recorded for audit but is never required to equal
    it: an immutable copied/CAS snapshot remains valid if the mutable original
    later changes.  v1 keeps its historical current-production-source check.
    """
    environ = os.environ if environ is None else environ
    path = Path(binary).resolve()
    _need(path.is_file() and os.access(path, os.X_OK), "binary is not an executable file: " + str(path))
    try:
        validated = native_evidence.load_validated(path)
    except Exception as error:  # receipt/binary digest mismatch is a hard failure
        raise SourceBindingError("build receipt rejected: " + type(error).__name__) from None
    _need(validated is not None, "no matching adjacent receipt")
    expected = expected_commit or environ.get("ROOTYARD_EXPECTED_SOURCE_COMMIT") or environ.get("GITHUB_SHA")
    if expected:
        _need(validated.workspace_commit == expected,
              "stale build receipt: workspace_commit differs from the expected source commit")
    record = validated.payload
    if validated.schema == "v2":
        return _v2_record(validated, record, path, expected)
    return _v1_record(validated, record, path, expected)


def _production_path(raw):
    """True when a ``git status --porcelain`` path is a production input.

    Paths are compared against the exact set ``build_native.source_digest()``
    hashes, so a test/doc-only edit is never mistaken for a production change.
    Renames keep their destination after `` -> ``.
    """
    name = raw.split(" -> ")[-1].strip().strip('"')
    if name in ("Cargo.toml", "Cargo.lock", "build.rs"):
        return True
    return any(name == top or name.startswith(top + "/") for top in ("src", "migrations", "schema", "vendor"))


def dump(evidence, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
