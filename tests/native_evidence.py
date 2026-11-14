"""Credential-free evidence written by actual native harness operations."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import native_build_receipt as receipts  # noqa: E402


def record(harness, event, **fields):
    destination = os.environ.get("ROOTYARD_TEST_EVIDENCE_DIR")
    if not destination:
        return
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    payload = {"event": event, "monotonic_ns": time.monotonic_ns(), **fields}
    with (root / (harness.schema + ".jsonl")).open("a") as output:
        output.write(json.dumps(payload, sort_keys=True) + "\n")


def load_validated(binary, expected_commit=None):
    """Read the adjacent receipt through the shared v1/v2 reader.

    This is a metadata-only operation: it never invokes Cargo, rustc, rustup or
    a builder.  The supplied binary is hashed in place, so a copied or
    content-addressed snapshot remains valid when its mutable original changes,
    provided the receipt and the copied bytes still describe the same SHA-256.
    """
    path = Path(binary).resolve()
    receipt = path.with_suffix(".build.json")
    if not receipt.exists():
        return None
    if not receipt.is_file() or receipt.is_symlink():
        raise RuntimeError("build receipt is not a regular file")
    return receipts.load_receipt(
        receipt,
        binary_path=path,
        expected_commit=expected_commit,
        verify_source_files=False,
    )


def build_record(binary):
    binary = Path(binary).resolve()
    validated = load_validated(binary)
    if validated is None:
        return {"attested": False, "reason": "no build receipt; source revision is not inferred"}
    data = validated.payload
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if validated.binary_sha256 != digest:
        raise RuntimeError("build receipt does not match executed binary")
    return {
        "attested": True,
        "validated_schema": validated.schema,
        "receipt_sha256": validated.receipt_sha256,
        "receipt_binary_sha256": validated.binary_sha256,
        **data,
    }


def started(harness):
    binary = Path(harness.args.binary).resolve()
    process_executable = Path(f"/proc/{harness.proc.pid}/exe")
    observed = str(process_executable.resolve()) if process_executable.exists() else None
    with binary.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    record(harness, "native_service_started", binary=str(binary), binary_sha256=digest,
           pid=harness.proc.pid, process_executable=observed, schema=harness.schema,
           build=build_record(binary),
           postgres_version=harness.sql("SELECT version()"),
           git_version=harness.run(["git", "--version"]).stdout.decode().strip())
