#!/usr/bin/env python3
"""Bounded, reproducible W0 baseline for existing local Git costs.

It measures real local Git subprocess work and reports PostgreSQL, HTTP API,
OpenDAL Blob, Raft and Redis costs as unavailable with null values unless the
operator explicitly supplies a permitted PostgreSQL DSN file. It never starts
the Rootyard service and never fabricates a measurement.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import platform
import random
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRIC_REGISTRY = {
    "git.receive_pack.small_pack.latency_ms": {"unit": "ms", "statistics": ["p50", "p95", "max"]},
    "git.update_ref.cas_conflict.latency_ms": {"unit": "ms", "statistics": ["p50", "p95", "max"]},
    "git.fsck.closure.duration_ms": {"unit": "ms", "statistics": ["p50", "p95", "max"]},
    "pg.round_trip.latency_ms": {"unit": "ms", "statistics": ["p50", "p95", "max"]},
    "pg.advisory_lock.acquire_ms": {"unit": "ms", "statistics": ["p50", "p95", "max"]},
    "api.push.e2e.latency_ms": {"unit": "ms", "statistics": ["p50", "p95", "max"]},
    "blob.put.latency_ms": {"unit": "ms", "statistics": ["p50", "p95", "max"]},
    "blob.get.latency_ms": {"unit": "ms", "statistics": ["p50", "p95", "max"]},
    "runner.child_cpu_seconds": {"unit": "s", "statistics": ["value"]},
    "runner.peak_rss_bytes": {"unit": "bytes", "statistics": ["value"]},
    "runner.temp_bytes": {"unit": "bytes", "statistics": ["value"]},
}


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def percentile(samples, q):
    ordered = sorted(samples)
    if not ordered:
        raise ValueError("percentile of empty samples")
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)


def summarize(samples):
    values = [float(sample) for sample in samples]
    return {
        "status": "measured",
        "n": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.fmean(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "value": statistics.fmean(values),
    }


def unavailable(reason):
    return {"status": "unavailable", "value": None, "samples": None, "reason": reason}


def git_output(args, cwd=None):
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()


def source_identity(allow_dirty):
    status = git_output(["status", "--porcelain", "--untracked-files=normal"])
    dirty = bool(status)
    if dirty and not allow_dirty:
        raise SystemExit("source worktree is dirty; rerun with --allow-dirty or commit first")
    diff = subprocess.run(["git", "diff", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
    return {
        "commit": git_output(["rev-parse", "HEAD"]),
        "tree": git_output(["rev-parse", "HEAD^{tree}"]),
        "dirty": dirty,
        "status_sha256": hashlib.sha256(status.encode()).hexdigest(),
        "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
    }


def binary_identity(path):
    if not path:
        return {"provided": False, "sha256": None, "reason": "no --binary path supplied; the runner does not execute a service binary"}
    candidate = Path(path)
    if not candidate.is_file():
        return {"provided": True, "sha256": None, "reason": "binary path does not exist; not executed"}
    return {"provided": True, "sha256": sha256_file(candidate), "executed": False, "path": str(candidate)}


def validate_workload(workload):
    if workload.get("schema") != "rootyard.state-services.workload/v1":
        raise ValueError("unsupported workload schema")
    bounds = workload["bounds"]
    git = workload["git"]
    if git["repo_count"] * git["pushes_per_repo"] > bounds["max_git_push_ops"]:
        raise ValueError("git workload exceeds max_git_push_ops")
    if git["cas_rounds"] * git["cas_concurrency"] > bounds["max_cas_ops"]:
        raise ValueError("CAS workload exceeds max_cas_ops")
    if bounds["wall_clock_seconds"] <= 0:
        raise ValueError("wall_clock_seconds must be positive")

def _cas_attempt(repo, old, new):
    started = time.perf_counter()
    result = subprocess.run(
        ["git", "--git-dir", str(repo), "update-ref", "refs/heads/main", new, old],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return (time.perf_counter() - started) * 1000.0, result.returncode == 0


def _directory_bytes(path):
    total = 0
    for base, _, files in os.walk(path):
        for name in files:
            try:
                total += (Path(base) / name).stat().st_size
            except OSError:
                pass
    return total


def run_git_workload(workload, deadline, seed):
    spec = workload["git"]
    root = Path(tempfile.mkdtemp(prefix="rootyard-w0-git-"))
    push_samples, cas_samples, fsck_samples = [], [], []
    cas_successes = cas_attempts = 0
    truncated = False
    rng = random.Random(seed)
    try:
        for repo_index in range(spec["repo_count"]):
            bare = root / f"repo-{repo_index}.git"
            work = root / f"work-{repo_index}"
            git_output(["init", "--bare", "--quiet", str(bare)])
            git_output(["init", "--quiet", str(work)])
            git_output(["config", "user.email", "w0@example.invalid"], cwd=work)
            git_output(["config", "user.name", "W0 Baseline"], cwd=work)
            for push_index in range(spec["pushes_per_repo"]):
                if time.monotonic() >= deadline:
                    truncated = True
                    break
                for commit_index in range(spec["commits_per_push"]):
                    payload = hashlib.sha256(f"{seed}:{repo_index}:{push_index}:{commit_index}".encode()).digest()
                    (work / "payload.bin").write_bytes((payload * ((spec["file_bytes"] // len(payload)) + 1))[: spec["file_bytes"]])
                    git_output(["add", "payload.bin"], cwd=work)
                    git_output(["commit", "--quiet", "-m", f"c{repo_index}-{push_index}-{commit_index}"], cwd=work)
                started = time.perf_counter()
                git_output(["push", "--quiet", str(bare), "HEAD:refs/heads/main"], cwd=work)
                push_samples.append((time.perf_counter() - started) * 1000.0)
            if time.monotonic() >= deadline:
                truncated = True
                continue
            head = git_output(["--git-dir", str(bare), "rev-parse", "refs/heads/main"])
            parent = git_output(["--git-dir", str(bare), "rev-parse", "refs/heads/main~1"])
            for _ in range(spec["cas_rounds"]):
                if time.monotonic() >= deadline:
                    truncated = True
                    break
                git_output(["--git-dir", str(bare), "update-ref", "refs/heads/main", head])
                with concurrent.futures.ThreadPoolExecutor(max_workers=spec["cas_concurrency"]) as pool:
                    results = list(pool.map(lambda _: _cas_attempt(bare, head, parent), range(spec["cas_concurrency"])))
                cas_samples.extend(item[0] for item in results)
                cas_attempts += len(results)
                cas_successes += sum(1 for item in results if item[1])
            if spec.get("fsck"):
                started = time.perf_counter()
                subprocess.run(["git", "--git-dir", str(bare), "fsck", "--no-dangling"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                fsck_samples.append((time.perf_counter() - started) * 1000.0)
    finally:
        temp_bytes = _directory_bytes(root)
        shutil.rmtree(root, ignore_errors=True)
    metrics = {
        "git.receive_pack.small_pack.latency_ms": summarize(push_samples) if push_samples else unavailable("no pushes executed"),
        "git.update_ref.cas_conflict.latency_ms": summarize(cas_samples) if cas_samples else unavailable("no CAS attempts executed"),
        "git.fsck.closure.duration_ms": summarize(fsck_samples) if fsck_samples else unavailable("fsck disabled or not reached"),
        "runner.temp_bytes": summarize([temp_bytes]),
    }
    metrics["git.update_ref.cas_conflict.latency_ms"]["cas_successes"] = cas_successes
    metrics["git.update_ref.cas_conflict.latency_ms"]["cas_attempts"] = cas_attempts
    return metrics, truncated

def run_pg_workload(workload, deadline, dsn_file):
    if not dsn_file:
        reason = "no --pg-dsn-file supplied; W0 has no permitted PostgreSQL service and does not read ambient credentials"
        return {"pg.round_trip.latency_ms": unavailable(reason), "pg.advisory_lock.acquire_ms": unavailable(reason)}
    psql = shutil.which("psql")
    if not psql:
        reason = "psql client unavailable; PostgreSQL not measured"
        return {"pg.round_trip.latency_ms": unavailable(reason), "pg.advisory_lock.acquire_ms": unavailable(reason)}
    try:
        dsn = Path(dsn_file).read_text(encoding="utf-8").strip()
        if not dsn:
            raise ValueError("empty DSN file")
    except (OSError, ValueError):
        reason = "DSN file unreadable; PostgreSQL not measured"
        return {"pg.round_trip.latency_ms": unavailable(reason), "pg.advisory_lock.acquire_ms": unavailable(reason)}
    samples, lock_samples = [], []
    count = max(1, int(workload.get("pg", {}).get("sample_count", 3)))
    for _ in range(count):
        if time.monotonic() >= deadline:
            break
        started = time.perf_counter()
        result = subprocess.run([psql, "-Atq", "-d", dsn, "-c", "SELECT 1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            return {"pg.round_trip.latency_ms": unavailable("psql query failed; details suppressed"), "pg.advisory_lock.acquire_ms": unavailable("psql query failed; details suppressed")}
        samples.append((time.perf_counter() - started) * 1000.0)
        started = time.perf_counter()
        result = subprocess.run([psql, "-Atq", "-d", dsn, "-c", "SELECT pg_advisory_lock(106); SELECT pg_advisory_unlock(106)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            lock_samples.append((time.perf_counter() - started) * 1000.0)
    return {
        "pg.round_trip.latency_ms": summarize(samples) if samples else unavailable("no PostgreSQL samples completed"),
        "pg.advisory_lock.acquire_ms": summarize(lock_samples) if lock_samples else unavailable("no advisory-lock samples completed"),
    }


def evaluate_budgets(budgets, metrics):
    evaluations = []
    for budget in budgets["budgets"]:
        observed = metrics.get(budget["metric"], {})
        if budget["decision"] == "not_frozen":
            evaluations.append({"budget_id": budget["id"], "status": "not_frozen", "observed": None, "bound": None})
            continue
        if observed.get("status") != "measured":
            evaluations.append({"budget_id": budget["id"], "status": "unmeasured", "observed": None, "bound": budget["bound"]})
            continue
        value = observed[budget["statistic"]]
        evaluations.append({"budget_id": budget["id"], "status": "pass" if value <= budget["bound"] else "fail", "observed": value, "bound": budget["bound"]})
    return evaluations


def build_report(workload, workload_path, budgets, args, git_metrics, truncated, child_cpu):
    unavailable_api = "no native HTTP service was executed in W0; API push-end-to-end is unmeasured"
    unavailable_blob = "no OpenDAL BlobStore exists at the baseline; S3/Local adapter is not a Blob authority and no provider credentials were used"
    metrics = {key: unavailable("not measured by this bounded runner") for key in METRIC_REGISTRY}
    for key in ("api.push.e2e.latency_ms",):
        metrics[key] = unavailable(unavailable_api)
    for key in ("blob.put.latency_ms", "blob.get.latency_ms"):
        metrics[key] = unavailable(unavailable_blob)
    metrics.update(git_metrics)
    metrics.update(run_pg_workload(workload, time.monotonic() + workload["bounds"]["wall_clock_seconds"], args.pg_dsn_file))
    metrics["runner.child_cpu_seconds"] = summarize([child_cpu])
    metrics["runner.peak_rss_bytes"] = summarize([resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024])
    return {
        "schema": "rootyard.state-services.baseline/v1",
        "kind": "bounded_local_git",
        "scope": "local ephemeral Git only; not a production, multi-host or target-architecture baseline",
        "produced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "identity": {
            "source": source_identity(args.allow_dirty),
            "binary": binary_identity(args.binary),
            "workload": {"id": workload["id"], "sha256": sha256_file(workload_path)},
            "runner": {"sha256": sha256_file(Path(__file__)), "python": sys.version.split()[0], "git": git_output(["--version"]), "platform": platform.platform()},
        },
        "metrics": metrics,
        "budget_evaluation": evaluate_budgets(budgets, metrics),
        "truncated": truncated,
        "limitations": [
            "local /tmp Git fixture only; do not extrapolate to production",
            "PostgreSQL/API/Blob/Raft/Redis are null or unavailable",
            "no Rootyard binary or native service was executed",
            "CAS latency is local git update-ref contention, not RefStore commit latency",
            "this smoke runner does not satisfy issue #106 runtime baseline by itself",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", default=str(ROOT / "docs/design/state-services/workloads/w0-bounded.json"))
    parser.add_argument("--budgets", default=str(ROOT / "docs/design/state-services/budgets.json"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--binary")
    parser.add_argument("--pg-dsn-file")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    workload_path = Path(args.workload)
    workload = json.loads(workload_path.read_text(encoding="utf-8"))
    budgets = json.loads(Path(args.budgets).read_text(encoding="utf-8"))
    validate_workload(workload)
    seed = int(workload["seed"])
    child_start = resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime
    deadline = time.monotonic() + workload["bounds"]["wall_clock_seconds"]
    git_metrics, truncated = run_git_workload(workload, deadline, seed)
    child_cpu = resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime - child_start
    report = build_report(workload, workload_path, budgets, args, git_metrics, truncated, child_cpu)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
