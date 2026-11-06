#!/usr/bin/env python3
"""Secret-free provenance for native operations acceptance reports.

Reports built with this helper declare that every metric came from executed
processes, storage and client traffic.  They cannot be produced from a
request-supplied or model-only receipt.
"""
import hashlib
import os
from pathlib import Path
import platform
import subprocess


REPO = Path(__file__).resolve().parents[1]


def _first_line(argv):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=15, check=False)
        return result.stdout.decode(errors="replace").strip().splitlines()[0]
    except (OSError, IndexError, subprocess.SubprocessError):
        return None


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_commit():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO,
                                       text=True, timeout=15).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def source_dirty():
    try:
        changed = subprocess.check_output(["git", "status", "--porcelain",
                                           "--untracked-files=no"],
                                          cwd=REPO, text=True, timeout=15)
        return bool(changed.strip())
    except (OSError, subprocess.SubprocessError):
        return None


def hardware():
    values = {"kernel": platform.release(), "machine": platform.machine(),
              "logical_cpus": os.cpu_count()}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                values["mem_total_kb"] = int(line.split()[1])
                break
    except (OSError, ValueError):
        pass
    return values


def tool_versions(extra=None):
    versions = {
        "git": _first_line(["git", "--version"]),
        "python": platform.python_version(),
        "openssl": _first_line(["openssl", "version"]),
        "postgres_client": _first_line(["psql", "--version"]),
    }
    versions.update(extra or {})
    return {name: value for name, value in versions.items() if value}


def binary_identity(binary):
    path = Path(binary).resolve(strict=True)
    return {"binary_sha256": sha256_file(path),
            "binary_size_bytes": path.stat().st_size}


def base(binary, harness=None, *, topology, dataset, workload, limits,
         measurement_kind="native_execution"):
    """Return fields shared by every native operations report.

    Callers extend the result with their own measured fields; a caller must
    never replace the provenance fields with caller-supplied values.
    """
    report = {
        "measurement_kind": measurement_kind,
        "simulated_fields": False,
        "source_base_commit": source_commit(),
        "source_worktree_dirty": source_dirty(),
        "tool_versions": tool_versions(),
        "hardware": hardware(),
        "topology": topology,
        "dataset": dataset,
        "workload": workload,
        "limits": list(limits),
    }
    report.update(binary_identity(binary))
    if harness is not None:
        report["harness_sha256"] = sha256_file(Path(harness).resolve(strict=True))
    return report
