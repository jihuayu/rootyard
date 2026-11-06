"""Credential-free evidence written by actual native harness operations."""
import hashlib
import json
import os
from pathlib import Path
import time


def record(harness, event, **fields):
    destination = os.environ.get("ROOTYARD_TEST_EVIDENCE_DIR")
    if not destination:
        return
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    payload = {"event": event, "monotonic_ns": time.monotonic_ns(), **fields}
    with (root / (harness.schema + ".jsonl")).open("a") as output:
        output.write(json.dumps(payload, sort_keys=True) + "\n")


def started(harness):
    binary = Path(harness.args.binary).resolve()
    process_executable = Path(f"/proc/{harness.proc.pid}/exe")
    observed = str(process_executable.resolve()) if process_executable.exists() else None
    with binary.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    record(harness, "native_service_started", binary=str(binary), binary_sha256=digest,
           pid=harness.proc.pid, process_executable=observed, schema=harness.schema,
           postgres_version=harness.sql("SELECT version()"),
           git_version=harness.run(["git", "--version"]).stdout.decode().strip())
