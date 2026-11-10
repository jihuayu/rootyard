#!/usr/bin/env python3
"""Bounded, reproducible W0 baseline for existing local Git costs.

It measures real local Git subprocess work and reports PostgreSQL, HTTP API,
OpenDAL Blob, Raft and Redis costs as unavailable with null values unless the
operator explicitly supplies a permitted PostgreSQL DSN file. It never starts
the Rootyard service and never fabricates a measurement.

Resource contract:

* One absolute runner deadline is armed before source identity is read and
  covers every Git and PostgreSQL subprocess. Each child's stop time is fixed
  before it is spawned as ``min(global deadline, start + stall cap)``; on
  either limit its whole process group is SIGTERMed, then SIGKILLed after a
  bounded grace window and reaped. That grace is charged after the stop time
  and reported, not claimed to end by the workload deadline.
* ``validate_workload`` rejects the workload before any subprocess, directory
  or output file exists unless every factor is an integer within hard runner
  limits, every product is exactly computable and within declared bounds, and
  the conservative temp admission estimate fits ``bounds.max_temp_bytes``.
* Resource accounting and cleanup are confined to one private fixture root
  created with ``mkdtemp`` before any child exists. Child processes and the
  runner's own stdio get ``<root>/tmp`` as TMPDIR/TMP/TEMP, so temporary files
  they create are inside the observed tree. Nothing outside that root is
  attributed, changed or deleted; observing a write elsewhere would not grant
  ownership of it.
* ``TempBudget.admit`` is a separate pre-run feasibility check: the admission
  estimate for the workload actually returned must fit ``max_temp_bytes``.
  At runtime each checkpoint measures the owned tree and compares it directly
  with ``max_temp_bytes``; nothing is clamped and no OS quota is claimed. The
  peak is the largest observed size. A breach after the first push truncates
  the run with a recorded reason; the same budget instance is reported either
  way.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import platform
import random
import re
import resource
import shutil
import signal
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
WORKLOAD_SCHEMA = "rootyard.state-services.workload/v1"
REPORT_SCHEMA = "rootyard.state-services.baseline/v1"
GIT_METRICS = ("git.receive_pack.small_pack.latency_ms", "git.update_ref.cas_conflict.latency_ms",
              "git.fsck.closure.duration_ms", "runner.temp_bytes")

# Hard runner ceilings. A workload may ask for less than its declared bounds;
# it can never ask for more than these, even with an edited workload file.
RUNNER_LIMITS = {
    "max_wall_clock_seconds": 3600.0,
    "max_git_repos": 32,
    "max_pushes_per_repo": 1000,
    "max_commits_per_push": 32,
    "max_cas_rounds": 1000,
    "max_cas_concurrency": 32,
    "max_file_bytes": 1048576,
    "max_pg_samples": 100,
    "max_seed": 2**31 - 1,
    "max_temp_bytes": 1073741824,
}
# Conservative admission model, in logical bytes, calibrated against native
# Git measurements (each fixed or per-object term is above the measured
# value, measured on native Git 2.52). Both git inits copy the full
# hook-sample template (~25 KiB each), so the fixed per-repository cost
# dominates tiny fixtures.
ADMISSION = {
    "git_init_fixed_bytes": 57344,  # two inits: hook samples, configs, HEAD, empty dirs
    "object_bytes": 512,  # loose object: type/size header, zlib stream, checksum
    "work_index_bytes": 256,  # empty index (~140 B) plus header and slack
    "index_entry_bytes": 96,  # one entry, checksum growth and padding per commit
    "work_reflog_bytes": 1024,  # commit reflog rewritten per commit cycle
    "ref_lock_bytes": 64,  # ref and update-ref lock written and rewritten
    "receive_reflog_bytes": 1024,  # bare reflog line appended per push (and short CAS lines)
    "pack_write_bytes": 1024,  # loose-to-pack rewrite at push, measured (3, 65, 900 B)
    "repo_state_bytes": 4096,  # refs, packed-refs, HEAD, description and lock files
    "run_slack_bytes": 65536,  # per-run fixed costs: fixture root directory and probes
}
DEFAULT_STALL_SECONDS = 120.0
KILL_GRACE_SECONDS = 5.0
GENTLE_FAILURE = 1  # exit status an opt-in read-only probe may use to report absence
SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|credential|api[_-]?key)")
SECRET_PATTERNS = (
    (re.compile(r"(?i)\b(password|pgpassword|sslkey|sslcert|sslrootcert)\s*=\s*\S+"), "secret_assignment"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*)://[^/\s@]*:[^/\s@]+@"), "uri_userinfo"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*)://([^/\s@/]+@)"), "uri_with_userinfo"),
)


class LimitExceeded(RuntimeError):
    """A hard limit (deadline, temp budget, concurrency) was reached mid-run."""


class RunnerTimeout(LimitExceeded):
    def __init__(self, label):
        super().__init__(f"{label}: deadline reached; child cancelled")
        self.label = label


class ChildFailed(RuntimeError):
    def __init__(self, label, command):
        super().__init__(f"{label}: {Path(command[0]).name} exited non-zero; stderr suppressed")
        self.label = label


class BudgetViolation(LimitExceeded):
    pass


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
    if not values or not all(math.isfinite(value) for value in values):
        raise ValueError("measurement samples must be non-empty and finite")
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


def _integer(value, name, minimum, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} exceeds hard runner limit {maximum}")
    return value


def _object(parent, name):
    if not isinstance(parent, dict):
        raise ValueError(f"{name} must be an object")
    return parent


def validate_workload(workload, limits=None):
    """Validate a parsed workload; raise ValueError before any side effect."""
    limits = limits or RUNNER_LIMITS
    _object(workload, "workload")
    if workload.get("schema") != WORKLOAD_SCHEMA:
        raise ValueError("unsupported workload schema")
    if not isinstance(workload.get("id"), str) or not workload["id"]:
        raise ValueError("workload id must be a non-empty string")
    if workload.get("description") is not None and not isinstance(workload["description"], str):
        raise ValueError("workload description must be a string")
    seed = workload.get("seed")
    _integer(seed, "seed", 0, limits["max_seed"])
    bounds = _object(workload.get("bounds"), "workload.bounds")
    git = _object(workload.get("git"), "workload.git")
    factors = {
        "repo_count": (1, limits["max_git_repos"]),
        "pushes_per_repo": (1, limits["max_pushes_per_repo"]),
        "commits_per_push": (1, limits["max_commits_per_push"]),
        "file_bytes": (0, limits["max_file_bytes"]),
        "cas_rounds": (0, limits["max_cas_rounds"]),
        "cas_concurrency": (1, limits["max_cas_concurrency"]),
    }
    for key, (minimum, maximum) in factors.items():
        _integer(git.get(key), f"git.{key}", minimum, maximum)
    if not isinstance(git.get("fsck"), bool):
        raise ValueError("git.fsck must be a boolean")
    wall = bounds.get("wall_clock_seconds")
    if isinstance(wall, bool) or not isinstance(wall, (int, float)) or not math.isfinite(wall) or wall <= 0:
        raise ValueError("wall_clock_seconds must be a finite positive number")
    if wall > limits["max_wall_clock_seconds"]:
        raise ValueError(f"wall_clock_seconds exceeds hard runner limit {limits['max_wall_clock_seconds']}")
    _integer(bounds.get("max_temp_bytes"), "bounds.max_temp_bytes", 1, limits["max_temp_bytes"])
    _integer(bounds.get("max_git_push_ops"), "bounds.max_git_push_ops", 0)
    _integer(bounds.get("max_cas_ops"), "bounds.max_cas_ops", 0)
    if git["cas_rounds"] == 0 and git["cas_concurrency"] != 1:
        raise ValueError("git.cas_concurrency must be 1 when git.cas_rounds is 0")
    # Compare factored products. No huge intermediate count is ever formed:
    # outside factors are rejected exactly, not saturating into a passing value.
    if git["repo_count"] > bounds["max_git_push_ops"] // git["pushes_per_repo"]:
        raise ValueError(f"git workload exceeds max_git_push_ops {bounds['max_git_push_ops']}")
    if git["cas_rounds"] > bounds["max_cas_ops"] // git["cas_concurrency"]:
        raise ValueError(f"CAS workload exceeds max_cas_ops {bounds['max_cas_ops']}")
    pg = _object(workload.get("pg"), "workload.pg")
    if not isinstance(pg.get("enabled"), bool):
        raise ValueError("pg.enabled must be a boolean")
    _integer(pg.get("sample_count"), "pg.sample_count", 0, limits["max_pg_samples"])
    if pg["enabled"] != (pg["sample_count"] > 0):
        raise ValueError("pg.sample_count must be positive exactly when pg.enabled is true")
    for name in ("api", "blob"):
        section = _object(workload.get(name), f"workload.{name}")
        for key, value in section.items():
            if key == "enabled":
                if not isinstance(value, bool):
                    raise ValueError(f"{name}.enabled must be a boolean")
            else:
                _integer(value, f"{name}.{key}", 0)
    if workload.get("notes") is not None and not isinstance(workload["notes"], list):
        raise ValueError("workload notes must be a list")
    return workload


def returned_pushes(workload, returned=None):
    requested = workload["git"]["pushes_per_repo"]
    return requested if returned is None else min(returned, requested)


def estimate_temp_bytes(workload, returned=None):
    """Conservative promised upper bound for a run's logical temp bytes."""
    git = workload["git"]
    pushes = returned_pushes(workload, returned)
    commits = git["commits_per_push"]
    # Loose object and one index entry per commit; per push the loose-to-pack
    # rewrite, a work reflog line and a bare reflog line appended by
    # receive-pack. The index and both reflogs are live files: reflog lines
    # and the lock are charged once per repository at their worst case, and
    # concurrent CAS attempts only append short lines to the same bare reflog
    # and rewrite the same lock, so they stay inside this allowance.
    per_commit = ADMISSION["object_bytes"] + ADMISSION["index_entry_bytes"]
    per_push = ADMISSION["pack_write_bytes"] + ADMISSION["receive_reflog_bytes"]
    live = (ADMISSION["work_index_bytes"] + ADMISSION["index_entry_bytes"]
            + ADMISSION["work_reflog_bytes"] + ADMISSION["ref_lock_bytes"])
    # The work tree keeps one payload file of file_bytes, charged in full.
    payload = git["file_bytes"]
    per_repo = (ADMISSION["git_init_fixed_bytes"] + ADMISSION["repo_state_bytes"] + live + payload
                + pushes * (commits * per_commit + per_push)
                + ADMISSION["receive_reflog_bytes"])
    # The slack covers only per-run fixed costs; per-repository costs are
    # inside per_repo.
    total = git["repo_count"] * per_repo + ADMISSION["run_slack_bytes"]
    if total > ADMISSION_BOUND:
        raise ValueError("temp admission estimate is outside the addressable range")
    return total


ADMISSION_BOUND = (2**62) // RUNNER_LIMITS["max_git_repos"]


def admission(workload, returned=None):
    """Feasibility check: does the returned workload's worst case fit the budget?

    This is a separate admission decision made before any effect; at runtime
    the monitored tree is compared directly against ``max_temp_bytes``.
    """
    budget = workload["bounds"]["max_temp_bytes"]
    estimate = estimate_temp_bytes(workload, returned)
    if estimate <= budget:
        return {"estimate_bytes": estimate, "budget_bytes": budget,
                "returned_pushes_per_repo": returned_pushes(workload, returned)}
    reduced = estimate_temp_bytes(workload, 1)
    message = (f"workload temp admission estimate {estimate} exceeds max_temp_bytes {budget};"
               f" one push per repository estimates {reduced}")
    if returned is None and reduced <= budget:
        message += " and can be admitted with --returned-pushes-per-repo 1"
    elif returned is None:
        message += " and cannot fit either; raise the declared max_temp_bytes or shrink the workload"
    else:
        message += f" and still cannot fit with --returned-pushes-per-repo {returned}"
    raise ValueError(message)


class Runner:
    """Runs subprocesses against one absolute deadline with process-group cleanup.

    Each child's own stop time is ``min(global deadline, its start time +
    stall_seconds)``, fixed before it is spawned. On either limit the child's
    whole process group is SIGTERMed, then SIGKILLed after a bounded grace
    window and reaped. That cleanup grace is charged after the stop time and
    is reported (``max_cleanup_grace_seconds``) rather than being claimed to
    end by the workload deadline.

    Children get private file-backed stdio inside the run's owned ``tmpdir``
    (also exported as TMPDIR/TMP/TEMP), so their temporary files stay in the
    monitored tree. ``popen``/``clock`` are seams for tests.
    """

    def __init__(self, deadline, *, tmpdir, stall_seconds=DEFAULT_STALL_SECONDS, kill_grace=KILL_GRACE_SECONDS,
                 popen=None, clock=time.monotonic):
        if isinstance(stall_seconds, bool) or not isinstance(stall_seconds, (int, float)) \
                or not math.isfinite(stall_seconds) or stall_seconds <= 0:
            raise ValueError("stall_seconds must be a finite positive number")
        if isinstance(kill_grace, bool) or not isinstance(kill_grace, (int, float)) \
                or not math.isfinite(kill_grace) or kill_grace <= 0:
            raise ValueError("kill_grace must be a finite positive number")
        self.deadline = deadline
        self.tmpdir = Path(tmpdir)
        self.child_env = {**os.environ, **{name: str(self.tmpdir) for name in ("TMPDIR", "TMP", "TEMP")}}
        self.stall_seconds = stall_seconds
        self.kill_grace = kill_grace
        self.popen = popen or subprocess.Popen
        self.clock = clock
        self.runs = 0
        self.timeouts = 0
        self.stall_timeouts = 0
        self.failures = 0
        self.skipped = 0
        self.live_runs = 0
        self.max_live_runs = 0
        self.groups_killed = 0
        self.max_cleanup_grace_seconds = 0.0
        self.retained = []  # pgids cancelled earlier, re-signalled when their cleanup grace ends

    def remaining(self):
        return max(0.0, self.deadline - self.clock())

    def expired(self):
        return self.remaining() <= 0

    def enforce_deadline(self, label):
        if self.expired():
            self.skipped += 1
            raise RunnerTimeout(label)

    def _spawn(self, command, cwd):
        # Children get unique private file-backed streams inside the owned
        # tmpdir. With pipes, an unrelated process inheriting the write end (the
        # harness's own log pipe during a concurrent spawn, or a not-yet-reaped
        # survivor of an earlier group kill) makes the drain wait on someone
        # else: that was observed here as a 30 s `git status` measured against a
        # 30 s wall-clock budget, corrupting wall-clock measurements.
        out = tempfile.TemporaryFile(dir=self.tmpdir)
        err = tempfile.TemporaryFile(dir=self.tmpdir)
        options = {"stdin": subprocess.DEVNULL, "stdout": out, "stderr": err, "start_new_session": True,
                   "env": self.child_env}
        if cwd is not None:
            options["cwd"] = cwd
        try:
            process = self.popen(command, **options)
        except OSError:
            out.close()
            err.close()
            raise
        process._baseline_outputs = (out, err)
        return process

    def _close_outputs(self, process):
        for stream in getattr(process, "_baseline_outputs", ()):
            stream.close()

    def run(self, command, *, label, cwd=None, text=False, gentle=False):
        self.enforce_deadline(label)
        # Start is read before spawning; the child may run for at most
        # stall_seconds from it, and never past the one global deadline.
        started = self.clock()
        child_stop = min(self.deadline, started + self.stall_seconds)
        try:
            process = self._spawn(command, cwd)
        except OSError as error:
            self.failures += 1
            raise ChildFailed(label, command) from error
        self.runs += 1
        self.live_runs += 1
        self.max_live_runs = max(self.max_live_runs, self.live_runs)
        try:
            while True:
                left = child_stop - self.clock()
                if left <= 0:
                    timed_out = True
                    break
                try:
                    process.wait(timeout=left)
                    timed_out = False
                    break
                except subprocess.TimeoutExpired:
                    continue
            if timed_out:
                self.timeouts += 1
                if child_stop < self.deadline:
                    self.stall_timeouts += 1
                self._kill_tree(process)
                raise RunnerTimeout(label)
            if gentle and process.returncode == GENTLE_FAILURE:
                # Read-only opt-in probes (history lookup) report absence this way.
                return None
            if process.returncode != 0:
                self.failures += 1
                raise ChildFailed(label, command)
            out, _ = process._baseline_outputs
            out.seek(0)
            data = out.read()
        finally:
            self.live_runs -= 1
            self._close_outputs(process)
        return _decode(data) if text else data

    def _signal_group(self, pgid, sig):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def _group_alive(self, pgid):
        """Whether pgid still has non-zombie members, via /proc/<pid>/stat.

        Zombies count as dead (they hold no resources and cannot hold pipes).
        Returns None when /proc is unavailable, in which case the group is
        signalled anyway (a signal to a gone group is harmless).
        """
        if not Path("/proc").is_dir():
            return None
        try:
            entries = os.listdir("/proc")
        except OSError:
            return None
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                fields = Path(f"/proc/{entry}/stat").read_text().rsplit(")", 1)[1].split()
            except (OSError, IndexError):
                continue  # exited while scanning
            if len(fields) > 2 and fields[2] == str(pgid) and fields[0] != "Z":
                return True
        return False

    def _kill_tree(self, process):
        """SIGTERM the child's group, SIGKILL it after the grace window, and reap.

        SIGTERM is not trusted to end the child: after the grace window the
        whole group, including same-group descendants a child may have
        spawned (e.g. a stalled shell), receives SIGKILL, and the leader is
        reaped so no zombie is left behind. Groups whose grace is still open are
        retained and re-signalled by the next cancellation.
        """
        start = self.clock()
        for pgid, _ in self.retained:
            self._signal_group(pgid, signal.SIGTERM)
        self._signal_group(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=self.kill_grace)
        except subprocess.TimeoutExpired:
            pass
        self._signal_group(process.pid, signal.SIGKILL)
        held = []
        for pgid, cancelled_at in [(process.pid, start)] + self.retained:
            if pgid != process.pid:
                if self._group_alive(pgid) is False:
                    continue  # nothing left in this group
                self._signal_group(pgid, signal.SIGKILL)
            if self.clock() - cancelled_at <= 3 * self.kill_grace:
                held.append((pgid, cancelled_at))
        self.retained = held
        if process.returncode is None:
            try:
                process.wait(timeout=self.kill_grace)
            except subprocess.TimeoutExpired:
                raise LimitExceeded("child ignored SIGKILL; aborting runner") from None
        self.groups_killed += 1
        self.max_cleanup_grace_seconds = max(self.max_cleanup_grace_seconds,
                                             self.clock() - start + self.kill_grace)

    def happenings(self):
        return {"subprocess_runs": self.runs, "max_live_subprocesses": self.max_live_runs,
                "timeouts": self.timeouts, "stall_timeouts": self.stall_timeouts,
                "failures": self.failures, "skipped_after_deadline": self.skipped,
                "process_groups_killed": self.groups_killed,
                "stall_seconds": self.stall_seconds, "kill_grace_seconds": self.kill_grace,
                "max_cleanup_grace_seconds": self.max_cleanup_grace_seconds}


def _decode(data):
    return data.decode("utf-8", "replace")


def _command(*args):
    return [shutil.which("git") or "git", *args] if args and args[0] != "git" else list(args)


def git_output(runner, args, cwd=None, gentle=False):
    return runner.run(_command("git", *args), label=f"git {args[0]}", cwd=cwd, text=True, gentle=gentle).strip()


def source_identity(runner, allow_dirty):
    status = git_output(runner, ["status", "--porcelain", "--untracked-files=normal"])
    dirty = bool(status)
    if dirty and not allow_dirty:
        raise SystemExit("source worktree is dirty; rerun with --allow-dirty or commit first")
    diff = runner.run(_command("git", "diff", "HEAD"), label="git diff", text=True)
    return {
        "commit": git_output(runner, ["rev-parse", "HEAD"]),
        "tree": git_output(runner, ["rev-parse", "HEAD^{tree}"]),
        "dirty": dirty,
        "status_sha256": hashlib.sha256(status.encode()).hexdigest(),
        "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
    }


def binary_identity(runner, path):
    """Hash a supplied binary; the work is a subprocess under the shared deadline."""
    if not path:
        return {"provided": False, "sha256": None, "reason": "no --binary path supplied; the runner does not execute a service binary"}
    if not Path(path).is_file():
        return {"provided": True, "sha256": None, "reason": "binary path does not exist; not executed"}
    digest = runner.run([shutil.which("sha256sum") or "sha256sum", path], label="binary sha256", text=True).strip()
    return {"provided": True, "sha256": digest.split()[0], "executed": False, "path": str(path)}


def _directory_bytes(path):
    total = 0
    for base, _, files in os.walk(path):
        for name in files:
            try:
                total += (Path(base) / name).stat().st_size
            except OSError:
                pass
    return total


class TempBudget:
    """Runtime monitor for one run's own private, self-controlled fixture tree.

    The runner creates one top-level root with ``mkdtemp`` (an exclusive name,
    so ownership is proven, not inferred). Child processes and the run's own
    stdio get ``<root>/tmp`` as TMPDIR, so temporary files they create are
    inside the tree. Each ``check`` measures the whole tree; the peak is the
    largest observed size and a value above ``budget`` is a violation. Nothing
    outside this root is read as owned, changed or deleted, and no OS or
    filesystem-wide quota is claimed.

    ``admit`` is the separate feasibility decision: the admission estimate for
    the workload actually returned (``estimate``) must fit ``budget``. Runtime
    checks compare observed bytes with the budget directly; they never add
    observed bytes to the admission estimate.
    """

    def __init__(self, budget, estimate):
        self.budget = budget
        self.estimate = estimate
        self.root = None
        self.observed = 0
        self.peak = 0
        self.checkpoints = 0
        self.admitted = False
        self.child_trees_dropped = False

    def admit(self):
        """Record feasibility for the effective workload; raise if it cannot fit."""
        if self.estimate > self.budget:
            raise ValueError(f"admission estimate {self.estimate} exceeds max_temp_bytes {self.budget}")
        self.admitted = True

    def open(self, label):
        """Create the run's own private fixture root."""
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-w0-git-"))
        self.check(label)

    def repository_dir(self, index, label):
        path = Path(tempfile.mkdtemp(prefix=f"repo-{index}-", dir=self.root))
        self.check(label)
        return path

    def finish(self):
        """Final accounting after every child is gone; it bounds work, not write reports.

        Only when that work reported the child trees as dropped does it measure
        just the run's own observations, which writing the bounded report needs.
        """
        if self.root is not None:
            self.check("temp budget final check", gentle=True)

    def cleanup(self):
        """Remove only the run's own fixture root; return an error string on failure."""
        self.child_trees_dropped = self.root is not None
        if self.root is None:
            return None
        try:
            # Default symlinks=False: an entry linked elsewhere is unlinked, not followed.
            shutil.rmtree(self.root)
        except OSError as failure:
            # Keep the root so the caller can report what remains.
            self.child_trees_dropped = False
            return f"{type(failure).__name__} removing the owned fixture root"
        self.root = None
        return None

    def check(self, label, gentle=False):
        """Measure the owned tree; a size beyond the declared budget is a breach.

        The peak records every observation, including a breaching one; it is
        never clamped to the budget to imply a quota the OS did not enforce.
        """
        if self.root is None:
            return
        self.observed = _directory_bytes(self.root)
        self.peak = max(self.peak, self.observed)
        self.checkpoints += 1
        if self.observed > self.budget and not gentle:
            raise BudgetViolation(f"{label}: owned fixture tree holds {self.observed} bytes, beyond "
                                  f"max_temp_bytes {self.budget}")


def _isolated_worktree_parent(root=None):
    """Parent directory outside the source repository for the fixture work trees.

    Git searches upward for a ``.git`` directory, so a fixture created under a
    /tmp that lives inside another repository would treat that repository's
    index and history as its own. A temp root that belongs to a repository is
    therefore not used.
    """
    root = Path(tempfile.gettempdir() if root is None else root).resolve()
    probe = root
    while True:
        if (probe / ".git").exists():
            return None
        if probe.parent == probe:
            return root
        probe = probe.parent


def client_fixture(budget):
    """Create the run's private fixture root and its TMPDIR, or refuse.

    The root is a ``mkdtemp`` directory, created once before any child or
    report exists. Child processes and the run's own stdio get ``<root>/tmp``
    as TMPDIR; the budget then monitors that whole tree.
    """
    if _isolated_worktree_parent(tempfile.gettempdir()) is None:
        # Refuse before any effect: a bounded private fixture is impossible here.
        raise LimitExceeded("temp directory is inside a Git repository; fixture work trees would inherit it, "
                            "so the workload cannot run (set TMPDIR outside any repository)")
    budget.open("git fixture admission")
    budget.root.joinpath("tmp").mkdir()
    return budget.root / "tmp"


def _write_bounded(path, payload, size, runner, budget):
    """Write a payload in cancellable chunks, checking the live temp budget."""
    budget.check("git payload")
    full = payload * (size // len(payload) + 1)
    with open(path, "wb") as handle:
        written = 0
        while written < size:
            if runner.expired():
                raise RunnerTimeout("git payload write")
            chunk = full[written:written + 65536]
            handle.write(chunk)
            written += len(chunk)
        handle.flush()
        os.fsync(handle.fileno())
    budget.check("git payload")


def _cas_attempt(runner, repo, old, new):
    start = time.perf_counter()
    try:
        runner.run(_command("git", "--git-dir", str(repo), "update-ref", "refs/heads/main", new, old),
                   label="git cas")
        return (time.perf_counter() - start) * 1000.0, True, "won"
    except RunnerTimeout:
        return None, False, "timeout"
    except ChildFailed:
        return (time.perf_counter() - start) * 1000.0, False, "cas_conflict"


def _cas_targets(runner, bare):
    """Choose a losing CAS from the pushed history.

    Pushes are sequential, so every push after the first lowers the ref. A
    single-push repository only proves the winning CAS path: the target is
    the current tip itself, which no concurrent update can beat.
    """
    head = git_output(runner, ["--git-dir", str(bare), "rev-parse", "refs/heads/main"])
    parent = git_output(runner, ["--git-dir", str(bare), "rev-parse", "refs/heads/main~1"], gentle=True)
    if parent is None:
        return head, head, "same_tip"
    return head, parent, "losing_parent"


def temp_metric(budget, extra=None):
    """The temp metric and report fields for the single budget instance."""
    metric = {"status": "measured", "value": budget.observed, "budget_bytes": budget.budget,
              "admission_estimate_bytes": budget.estimate, "peak_charged_bytes": budget.peak,
              "observed_bytes": budget.observed, "checkpoints": budget.checkpoints}
    metric.update(extra or {})
    return metric


def run_git_workload(workload, runner, seed, returned=None, budget=None):
    """Run Git; the deadline and temp budget gate every expensive step.

    ``budget`` must be the same ``TempBudget`` a ``client_fixture`` created
    before the runner was constructed, and must already be admitted for the
    effective workload. Returns ``(metrics, truncated, budget)`` with that
    instance and leaves the fixture in place; the caller removes it after its
    own final accounting. A timeout or budget breach after the first push
    truncates the run and keeps the measured samples.
    """
    if budget is None or budget.root is None:
        raise ValueError("run_git_workload requires the opened budget from client_fixture")
    spec = workload["git"]
    pushes = returned_pushes(workload, returned)
    push_samples, cas_samples, fsck_samples = [], [], []
    cas_outcomes, cas_modes = {}, {}
    bare_repos = []
    progressed = truncated = False
    stop_reason = None
    try:
        runner.enforce_deadline("git fixture admission")
        budget.check("git fixture admission")
        workers = max(1, min(RUNNER_LIMITS["max_cas_concurrency"], spec["cas_concurrency"]))
        # fsck is deferred until the CAS pool is closed so a pool exit can never
        # wait on a cancelled fsck child while the deadline has already passed.
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for repo_index in range(spec["repo_count"]):
                repo_dir = budget.repository_dir(repo_index, "git init")
                bare = repo_dir / "bare.git"
                work = repo_dir / "work"
                bare_repos.append(bare)
                git_output(runner, ["init", "--bare", "--quiet", str(bare)])
                git_output(runner, ["init", "--quiet", str(work)])
                budget.check("git init")
                # Configure before committing so the run does not depend on an
                # ambient identity from the operator's environment.
                for key, value in (("user.email", "w0@example.invalid"), ("user.name", "W0 Baseline")):
                    git_output(runner, ["config", key, value], cwd=work)
                budget.check("git config")
                git_output(runner, ["commit", "--quiet", "--allow-empty", "-m", "root"], cwd=work)
                for push_index in range(pushes):
                    runner.enforce_deadline("git push fixture")
                    for commit_index in range(spec["commits_per_push"]):
                        # The fixture writes fixed content on purpose; the
                        # measured cost is the commit cycle, not payload bytes.
                        payload = hashlib.sha256(f"{seed}:{repo_index}:{push_index}:{commit_index}".encode()).digest()
                        _write_bounded(work / "payload.bin", payload, spec["file_bytes"], runner, budget)
                        git_output(runner, ["add", "--force", "payload.bin"], cwd=work)
                        git_output(runner, ["commit", "--quiet", "--allow-empty",
                                            "-m", f"c{repo_index}-{push_index}-{commit_index}"], cwd=work)
                        budget.check("git commit")
                    started_push = time.perf_counter()
                    git_output(runner, ["push", "--quiet", str(bare), "HEAD:refs/heads/main"], cwd=work)
                    push_samples.append((time.perf_counter() - started_push) * 1000.0)
                    progressed = True
                    budget.check("git push")
                head, parent, mode = _cas_targets(runner, bare)
                cas_modes[mode] = cas_modes.get(mode, 0) + 1
                for _ in range(spec["cas_rounds"]):
                    runner.enforce_deadline("git cas round")
                    git_output(runner, ["--git-dir", str(bare), "update-ref", "refs/heads/main", head])
                    futures = [pool.submit(_cas_attempt, runner, bare, head, parent)
                               for _ in range(spec["cas_concurrency"])]
                    timed_out = False
                    for future in futures:
                        elapsed, _, outcome = future.result()
                        cas_outcomes[outcome] = cas_outcomes.get(outcome, 0) + 1
                        timed_out = timed_out or outcome == "timeout"
                        if elapsed is not None:
                            cas_samples.append(elapsed)
                    if timed_out:
                        raise RunnerTimeout("git cas")
                    budget.check("git cas")
        if spec.get("fsck"):
            for repo_index in range(spec["repo_count"]):
                runner.enforce_deadline("git fsck")
                started_fsck = time.perf_counter()
                # --no-dangling only reads reachable objects: no new writes.
                git_output(runner, ["--git-dir", str(bare_repos[repo_index]), "fsck", "--no-dangling"])
                fsck_samples.append((time.perf_counter() - started_fsck) * 1000.0)
                budget.check("git fsck")
    except (RunnerTimeout, BudgetViolation, LimitExceeded) as error:
        if not progressed:
            raise
        truncated = True
        stop_reason = str(error)
        if isinstance(error, RunnerTimeout):
            cas_outcomes["timeout"] = max(1, cas_outcomes.get("timeout", 0))
    metrics = {
        "git.receive_pack.small_pack.latency_ms": summarize(push_samples) if push_samples else unavailable("no pushes executed"),
        "git.update_ref.cas_conflict.latency_ms": summarize(cas_samples) if cas_samples else unavailable(
            "no CAS attempts executed"),
        "git.fsck.closure.duration_ms": summarize(fsck_samples) if fsck_samples else unavailable(
            "fsck disabled, or stopped by the remaining-time/temp budget"),
        "runner.temp_bytes": temp_metric(budget, {"returned_pushes_per_repo": pushes}),
    }
    cas = metrics["git.update_ref.cas_conflict.latency_ms"]
    cas["cas_successes"] = cas_outcomes.get("won", 0)
    cas["cas_attempts"] = sum(count for name, count in cas_outcomes.items() if name != "timeout")
    cas["cas_outcomes"] = {name: cas_outcomes.get(name, 0) for name in ("won", "cas_conflict", "failed", "timeout")}
    cas["cas_targets"] = cas_modes
    if stop_reason and truncated:
        metrics["runner.temp_bytes"]["stop_reason"] = stop_reason
    return metrics, truncated, budget


def run_pg_workload(workload, runner, dsn_file, budget):
    keys = ("pg.round_trip.latency_ms", "pg.advisory_lock.acquire_ms")
    if not dsn_file:
        return {key: unavailable("no --pg-dsn-file supplied; W0 has no permitted PostgreSQL service and does not "
                                 "read ambient credentials") for key in keys}
    psql = shutil.which("psql")
    if not psql:
        return {key: unavailable("psql client unavailable; PostgreSQL not measured") for key in keys}
    try:
        dsn = Path(dsn_file).read_text(encoding="utf-8").strip()
        if not dsn:
            raise ValueError("empty DSN file")
    except (OSError, ValueError):
        return {key: unavailable("DSN file unreadable; PostgreSQL not measured") for key in keys}
    samples, lock_samples = [], []
    pg = workload["pg"]
    count = pg["sample_count"] if pg["enabled"] else 3
    try:
        for _ in range(count):
            for statement, target, label in (
                ("SELECT 1", samples, "psql round trip"),
                ("SELECT pg_advisory_lock(106); SELECT pg_advisory_unlock(106)", lock_samples, "psql advisory lock"),
            ):
                runner.enforce_deadline(label)
                started = time.perf_counter()
                runner.run([psql, "-Atq", "-d", dsn, "-c", statement], label=label)
                target.append((time.perf_counter() - started) * 1000.0)
    except RunnerTimeout:
        pass
    except ChildFailed:
        return {key: unavailable("psql query failed; details suppressed") for key in keys}
    finally:
        # psql writes its temporary files under the run's owned TMPDIR.
        budget.finish()
    return {
        "pg.round_trip.latency_ms": summarize(samples) if samples else unavailable("no PostgreSQL samples completed"),
        "pg.advisory_lock.acquire_ms": summarize(lock_samples) if lock_samples else unavailable("no advisory-lock samples completed"),
    }


def evaluate_budgets(budgets, metrics):
    evaluations = []
    for budget in budgets["budgets"]:
        observed = metrics.get(budget["metric"], {})
        if budget["decision"] != "frozen":
            evaluations.append({"budget_id": budget["id"], "status": "not_frozen", "observed": None, "bound": None})
            continue
        bound = budget.get("bound")
        if isinstance(bound, bool) or not isinstance(bound, (int, float)) or not math.isfinite(bound):
            raise ValueError(f"{budget['id']}: frozen budget needs a finite numeric bound")
        if observed.get("status") != "measured" or budget["statistic"] not in observed:
            evaluations.append({"budget_id": budget["id"], "status": "unmeasured", "observed": None, "bound": bound})
            continue
        value = observed[budget["statistic"]]
        evaluations.append({"budget_id": budget["id"], "status": "pass" if value <= bound else "fail",
                            "observed": value, "bound": bound})
    return evaluations


def redact(value):
    """Remove credential-shaped values (URI userinfo and secret assignments) from report data."""
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        for pattern, name in SECRET_PATTERNS:
            if name == "uri_with_userinfo":
                value = pattern.sub(lambda match: f"{match.group(1)}://[redacted]@", value)
            elif name == "uri_userinfo":
                value = pattern.sub(lambda match: f"{match.group(1)}://[redacted]@", value)
            else:
                value = pattern.sub("[redacted]", value)
        return value
    return value


def scan_report_text(text, raw_dsn=None):
    """Return secret-shaped finding names for an already-redacted report; never the secret."""
    findings = set()
    if raw_dsn:
        if raw_dsn in text:
            findings.add("dsn_file_contents")
        password = re.search(r"(?i)(?:password|pwd)\s*=\s*([^\s&'\"]+)", raw_dsn)
        if password and password.group(1) and password.group(1) in text:
            findings.add("dsn_password")
    for pattern, name in SECRET_PATTERNS:
        if pattern.search(text):
            findings.add(name)
    return findings


def build_report(workload, workload_path, budgets, args, git_metrics, truncated, child_cpu, runner,
                 deadline, source, admission_facts, git_version, pg_metrics=None, elapsed=None):
    unavailable_api = "no native HTTP service was executed in W0; API push-end-to-end is unmeasured"
    unavailable_blob = "no OpenDAL BlobStore exists at the baseline; S3/Local adapter is not a Blob authority and no provider credentials were used"
    metrics = {key: unavailable("not measured by this bounded runner") for key in METRIC_REGISTRY}
    metrics["api.push.e2e.latency_ms"] = unavailable(unavailable_api)
    for key in ("blob.put.latency_ms", "blob.get.latency_ms"):
        metrics[key] = unavailable(unavailable_blob)
    metrics.update(git_metrics)
    metrics.update(pg_metrics)
    metrics["runner.child_cpu_seconds"] = summarize([child_cpu])
    metrics["runner.peak_rss_bytes"] = summarize([resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024])
    report = {
        "schema": REPORT_SCHEMA,
        "kind": "bounded_local_git",
        "scope": "local ephemeral Git only; not a production, multi-host or target-architecture baseline",
        "produced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(elapsed if elapsed is not None
                                 else time.monotonic() - (deadline - workload["bounds"]["wall_clock_seconds"]), 3),
        "identity": {
            "source": source,
            "binary": binary_identity(runner, args.binary),
            "workload": {"id": workload["id"], "sha256": sha256_file(workload_path),
                         "bounds": {key: workload["bounds"].get(key) for key in
                                    ("wall_clock_seconds", "max_git_push_ops", "max_cas_ops", "max_temp_bytes")}},
            "budgets": {"sha256": sha256_file(args.budgets), "status": budgets.get("status")},
            "runner": {"sha256": sha256_file(Path(__file__)), "python": sys.version.split()[0],
                       "git": git_version,
                       "platform": platform.platform()},
        },
        "limits": {"runner_limits": dict(RUNNER_LIMITS), "admission_params": dict(ADMISSION),
                   "stall_seconds": runner.stall_seconds, "admission": admission_facts},
        "subprocess": runner.happenings(),
        "metrics": metrics,
        "budget_evaluation": evaluate_budgets(budgets, metrics),
        "truncated": truncated,
        "limitations": [
            "local /tmp Git fixture only; do not extrapolate to production",
            "PostgreSQL/API/Blob/Raft/Redis are null or unavailable",
            "no Rootyard binary or native service was executed",
            "CAS latency is local git update-ref contention, not RefStore commit latency",
            "this smoke runner does not satisfy issue #106 runtime baseline by itself",
            "runner.temp_bytes measures only the runner's own fixture tree (including the owned TMPDIR given to children); "
            "admission_estimate_bytes is the separate pre-run feasibility estimate for the returned workload and "
            "peak_charged_bytes is the largest measured size of the owned tree; this is not an OS or filesystem-wide quota",
            "PostgreSQL is only measured with an explicit --pg-dsn-file and a local psql; its DSN is never written to the report",
        ],
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workload", default=str(ROOT / "docs/design/state-services/workloads/w0-bounded.json"))
    parser.add_argument("--budgets", default=str(ROOT / "docs/design/state-services/budgets.json"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--binary")
    parser.add_argument("--pg-dsn-file")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--stall-seconds", type=float, default=DEFAULT_STALL_SECONDS,
                        help="per-child cap from its own start, itself capped by the absolute runner deadline")
    parser.add_argument("--returned-pushes-per-repo", type=int,
                        help="reduce pushes per repo (at least 1) when the full run is not admitted")
    args = parser.parse_args(argv)
    workload = json.loads(Path(args.workload).read_text(encoding="utf-8"))
    budgets = json.loads(Path(args.budgets).read_text(encoding="utf-8"))
    try:
        validate_workload(workload)
        returned = None if args.returned_pushes_per_repo is None else _integer(
            args.returned_pushes_per_repo, "--returned-pushes-per-repo", 1, RUNNER_LIMITS["max_pushes_per_repo"])
        facts = admission(workload, returned)
    except ValueError as error:
        raise SystemExit(f"workload rejected before any measurement: {error}")
    seed = int(workload["seed"])
    # One budget instance for the whole run, created before any child, fixture
    # or report directory, so its facts survive every outcome.
    budget = TempBudget(workload["bounds"]["max_temp_bytes"],
                        facts["estimate_bytes"] if returned is None else estimate_temp_bytes(workload, returned))
    budget.admit()
    # One absolute deadline: it covers source identity, Git, PostgreSQL and
    # every version/cleanup subprocess that follows.
    deadline = time.monotonic() + workload["bounds"]["wall_clock_seconds"]
    child_start = resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime
    truncated = False
    try:
        tmpdir = client_fixture(budget)
    except LimitExceeded as error:
        # Refused before any effect: no child, fixture or report directory exists.
        raise SystemExit(f"run refused before measurement: {error}")
    runner = Runner(deadline, tmpdir=tmpdir, stall_seconds=args.stall_seconds)
    version = unavailable("git version not probed within the runner deadline")
    source = {"status": "unavailable", "reason": "source identity not collected before the run stopped"}
    git_metrics = {}

    def aborted(error):
        """Work started and stopped abnormally: no false success, budget facts kept."""
        nonlocal truncated
        truncated = True
        metrics = {key: unavailable(f"run stopped before this metric completed: {error}") for key in GIT_METRICS}
        metrics["runner.temp_bytes"] = temp_metric(
            budget, {"returned_pushes_per_repo": returned_pushes(workload, returned), "stop_reason": str(error)})
        return metrics

    try:
        if not runner.expired():
            version = git_output(runner, ["--version"])
        source = source_identity(runner, args.allow_dirty)
        git_metrics, truncated, budget = run_git_workload(workload, runner, seed, facts["returned_pushes_per_repo"],
                                                          budget)
    except RunnerTimeout as error:
        git_metrics = aborted(error)
    except (BudgetViolation, LimitExceeded) as error:
        # A budget breach or a child that survived SIGKILL before the first
        # push: the same budget instance is still reported and removed below.
        git_metrics = aborted(error)
    try:
        pg_metrics = run_pg_workload(workload, runner, args.pg_dsn_file, budget)
    except RunnerTimeout:
        # PostgreSQL consumed the remaining deadline: record that honestly
        # instead of retrying beyond the budget.
        truncated = True
        pg_metrics = {key: unavailable("absolute runner deadline reached; PostgreSQL not measured")
                      for key in ("pg.round_trip.latency_ms", "pg.advisory_lock.acquire_ms")}
    child_cpu = resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime - child_start
    git_metrics.setdefault("runner.temp_bytes",
                           temp_metric(budget, {"returned_pushes_per_repo": returned_pushes(workload, returned)}))
    temp = git_metrics["runner.temp_bytes"]
    # Final accounting; the root is removed in the finally even when that
    # accounting refuses, so no owned fixture survives an error.
    try:
        budget.finish()
    except BudgetViolation as error:
        # No report claims success over a breach; cleanup still runs below.
        raise SystemExit(f"refusing to write report: {error}")
    finally:
        cleanup_error = budget.cleanup()
        temp.update(temp_metric(budget))
        temp["cleaned"] = cleanup_error is None
        if cleanup_error:
            temp["cleanup_error"] = cleanup_error
    elapsed = time.monotonic() - (deadline - workload["bounds"]["wall_clock_seconds"])
    report = build_report(workload, Path(args.workload), budgets, args, git_metrics, truncated, child_cpu,
                          runner, deadline, source, facts, version, pg_metrics=pg_metrics, elapsed=elapsed)
    # Provenance for the budget instance that actually governed the run.
    report["limits"]["temp_budget"] = dict(temp_metric(budget),
                                           estimate_bytes=budget.estimate,
                                           returned_pushes_per_repo=temp["returned_pushes_per_repo"])
    if cleanup_error:
        report["limits"]["temp_budget"]["cleanup_error"] = cleanup_error
    text = json.dumps(redact(report), indent=2, sort_keys=True)
    raw_dsn = None
    if args.pg_dsn_file and Path(args.pg_dsn_file).is_file():
        try:
            raw_dsn = Path(args.pg_dsn_file).read_text(encoding="utf-8").strip() or None
        except OSError:
            raw_dsn = None
    findings = scan_report_text(text, raw_dsn)
    if findings:
        raise SystemExit(f"refusing to write report: secret-shaped content detected ({', '.join(sorted(findings))})")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
