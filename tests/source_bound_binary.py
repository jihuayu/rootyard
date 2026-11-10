"""Bind an executed binary to the candidate's current production source bytes.

``native_evidence.build_record`` only proves that an adjacent
``<binary>.build.json`` receipt describes *some* build whose digest equals the
binary.  That is a neighbour-JSON claim: it says nothing about this checkout.
This module adds the missing binding, reusing the reviewed definitions instead
of re-inventing them:

* the source-input digest is ``scripts/build_native.source_digest()`` itself --
  production inputs only (``Cargo.toml``, ``Cargo.lock``, ``build.rs``,
  ``src/``, ``migrations/``, ``schema/``, ``vendor/``), so a different HEAD that
  only moved tests or docs is acceptable when those bytes are identical;
* the binary digest is ``ops_provenance.sha256_file`` and the process identity
  check mirrors ``blob_only_service.NativeProfile``'s receipt rules.

Nothing here claims a native run happened; it only decides whether a native
run would be attributable to the current source.
"""
import importlib.util
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


def bind(binary, expected_commit=None, environ=None):
    """Return evidence binding ``binary`` to the current source, or raise.

    ``expected_commit`` (or ``ROOTYARD_EXPECTED_SOURCE_COMMIT``) additionally
    requires the receipt's ``workspace_commit`` to be that commit.  The current
    checkout HEAD is recorded for audit but never required to equal it: a
    test/doc-only commit legitimately changes HEAD without changing production
    bytes.
    """
    environ = os.environ if environ is None else environ
    path = Path(binary).resolve()
    _need(path.is_file() and os.access(path, os.X_OK), "binary is not an executable file: " + str(path))
    try:
        record = native_evidence.build_record(path)
    except Exception as error:  # receipt/binary digest mismatch is a hard failure
        raise SourceBindingError("build receipt rejected: " + type(error).__name__) from None
    _need(record.get("attested") is True, "no matching adjacent receipt: " + str(record.get("reason")))
    missing = [name for name in REQUIRED_FIELDS if not record.get(name)]
    _need(not missing, "build receipt is missing " + ", ".join(missing))
    digest = ops_provenance.sha256_file(path)
    _need(len(str(record["source_inputs_sha256"])) == 64, "receipt source_inputs_sha256 is not a SHA-256")
    current_digest = production_source_digest()
    _need(current_digest == record["source_inputs_sha256"], (
        "the executed binary does not match this checkout's production source inputs "
        "(receipt " + record["source_inputs_sha256"][:16] + "..., current " + current_digest[:16] + "...)"))
    expected = expected_commit or environ.get("ROOTYARD_EXPECTED_SOURCE_COMMIT") or environ.get("GITHUB_SHA")
    if expected:
        _need(record["workspace_commit"] == expected,
              "stale build receipt: workspace_commit differs from the expected source commit")
    head = _git("rev-parse", "HEAD")
    dirty = _git("status", "--porcelain")
    production_dirty = [line for line in (dirty or "").splitlines()
                        if _production_path(line[3:] if len(line) > 3 else "")]
    return {
        "attested": True,
        "binary_sha256": digest,
        "receipt_binary_sha256": record["binary_sha256"],
        "source_inputs_sha256": record["source_inputs_sha256"],
        "current_source_inputs_sha256": current_digest,
        "production_inputs_bound": True,
        "workspace_commit": record["workspace_commit"],
        "current_head": head,
        "head_differs_from_receipt": head != record["workspace_commit"],
        "current_head_production_dirty": production_dirty,
        "receipt_toolchain": {"rustc": record["rustc"], "command": record["command"]},
    }


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
