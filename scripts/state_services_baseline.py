#!/usr/bin/env python3
"""Bounded, reproducible W0 baseline for existing local Git costs.

It measures real local Git subprocess work and reports PostgreSQL, HTTP API,
OpenDAL Blob, Raft and Redis costs as unavailable with null values unless the
operator explicitly supplies a permitted PostgreSQL DSN file. It never starts
the Rootyard service and never fabricates a measurement.

Resource contract:

* One absolute runner deadline is armed before source identity is read and
  covers every Git, PostgreSQL and cleanup subprocess. Each child is given the
  remaining time (capped by a per-subprocess stall cap), cancelled with that
  remaining time, sent SIGTERM/SIGKILL in its own process group, and reaped.
* ``validate_workload`` rejects the workload before any subprocess, directory
  or output file exists unless every factor is an integer within hard runner
  limits, every product is exactly computable and within declared bounds, and
  the conservative temp admission estimate fits ``bounds.max_temp_bytes``.
* The temp budget is checked during the run: the full estimate is reserved
  before the fixture directory is created, every expensive step is charged as
  live observed bytes plus the not-yet-performed estimate, and a breach after
  the first push truncates the run with a recorded reason.
"""
from __future__ import annotations

import argparse
import builtins
import concurrent.futures
import errno
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
    returned = git.get("returned_pushes_per_repo", git["pushes_per_repo"])
    _integer(returned, "git.returned_pushes_per_repo", 1, git["pushes_per_repo"])
    if git["cas_rounds"] == 0 and git["cas_concurrency"] != 1:
        raise ValueError("git.cas_concurrency must be 1 when git.cas_rounds is 0")
    # Compare factored products. No huge intermediate count is ever formed:
    # outside factors are rejected exactly, not saturating into a passing value.
    if git["repo_count"] > bounds["max_git_push_ops"] // git["pushes_per_repo"]:
        raise ValueError(f"git workload exceeds max_git_push_ops {bounds['max_git_push_ops']}")
    if returned > 1 and git["repo_count"] > bounds["max_git_push_ops"] // returned:
        raise ValueError("reduced git workload exceeds max_git_push_ops")
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
    """Return admission facts or raise ValueError when the run cannot be admitted."""
    budget = workload["bounds"]["max_temp_bytes"]
    estimate = estimate_temp_bytes(workload, returned)
    if estimate <= budget:
        return {"estimate_bytes": estimate, "budget_bytes": budget, "returned_pushes_per_repo": returned_pushes(workload, returned)}
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

    Children get private file-backed stdio, are never given more than the
    remaining deadline, are killed with SIGTERM/SIGKILL in their own process
    group when that expires, and are reaped. ``popen``/``clock`` are seams for
    deterministic tests; ``kill_grace`` bounds the SIGTERM window.
    """

    def __init__(self, deadline, *, stall_seconds=DEFAULT_STALL_SECONDS, kill_grace=KILL_GRACE_SECONDS,
                 popen=None, clock=time.monotonic):
        if isinstance(stall_seconds, bool) or not isinstance(stall_seconds, (int, float)) \
                or not math.isfinite(stall_seconds) or stall_seconds <= 0:
            raise ValueError("stall_seconds must be a finite positive number")
        if not isinstance(kill_grace, (int, float)) or not math.isfinite(kill_grace) or kill_grace <= 0:
            raise ValueError("kill_grace must be a finite positive number")
        self.deadline = deadline
        self.stall_seconds = stall_seconds
        self.kill_grace = kill_grace
        self.popen = popen or subprocess.Popen
        self.clock = clock
        self.runs = 0
        self.timeouts = 0
        self.failures = 0
        self.skipped = 0
        self.live_runs = 0
        self.max_live_runs = 0
        self.groups_killed = 0
        self.cancel_window = 0.0
        self.retained = []  # pgids cancelled earlier; re-signalled when a later child is cancelled

    def remaining(self):
        return max(0.0, self.deadline - self.clock())

    def expired(self):
        return self.remaining() <= 0

    def enforce_deadline(self, label):
        if self.expired():
            self.skipped += 1
            raise RunnerTimeout(label)

    def _spawn(self, command, cwd):
        # Children get unique private file-backed streams. With pipes, an
        # unrelated process inheriting the write end (the harness's own log
        # pipe during a concurrent spawn, or a not-yet-reaped survivor of an
        # earlier group kill) makes the drain wait on someone else: that was
        # observed here as a 30 s `git status` measured against a 30 s
        # wall-clock budget, corrupting wall-clock measurements.
        out = tempfile.TemporaryFile()
        err = tempfile.TemporaryFile()
        options = {"stdin": subprocess.DEVNULL, "stdout": out, "stderr": err, "start_new_session": True}
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
        limit = self.remaining()
        try:
            process = self._spawn(command, cwd)
        except OSError as error:
            self.failures += 1
            raise ChildFailed(label, command) from error
        self.runs += 1
        self.live_runs += 1
        self.max_live_runs = max(self.max_live_runs, self.live_runs)
        try:
            stop = self.clock() + limit
            while True:
                left = stop - self.clock()
                if left <= 0:
                    timed_out = True
                    break
                try:
                    process.wait(timeout=min(left, self.stall_seconds))
                    timed_out = False
                    break
                except subprocess.TimeoutExpired:
                    continue
            if timed_out:
                self.timeouts += 1
                self._kill_tree(process)
                self.retained.append((process.pid, self.clock()))
                raise RunnerTimeout(label)
            if gentle and process.returncode == GENTLE_FAILURE:
                # Read-only opt-in probes (history lookup) report absence this way.
                return None
            if process.returncode != 0:
                self.failures += 1
                raise ChildFailed(label, command)
            self.retained = [(pgid, when) for pgid, when in self.retained
                             if self._group_alive(pgid) is not False]
            out, _ = process._baseline_outputs
            out.seek(0)
            data = out.read()
        finally:
            self.live_runs -= 1
            self._close_outputs(process)
        return data.decode("utf-8", "replace") if text else data

    def _signal_group(self, process, sig):
        try:
            os.killpg(process.pid, sig)
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

    def _signal_retained(self, sig):
        held = []
        for pgid, cancelled_at in self.retained:
            if self._group_alive(pgid) is False:
                continue  # nothing left in this group
            try:
                os.killpg(pgid, sig)
            except (ProcessLookupError, PermissionError):
                continue
            if self.clock() - cancelled_at <= 3 * self.kill_grace:
                held.append((pgid, cancelled_at))
        self.retained = held

    def _watchdog(self, process, timeout):
        if timeout < 0:
            process.wait()
        else:
            process.wait(timeout=timeout)

    def _kill_tree(self, process):
        """SIGTERM the child's process group, force SIGKILL, and reap it.

        SIGTERM is not trusted to end the child: after the grace window the
        whole group, including same-group descendants a child may have
        spawned (e.g. a stalled shell), receives SIGKILL, and the leader is
        reaped so no zombie is left behind.
        """
        start = self.clock()
        self._signal_retained(signal.SIGTERM)
        self._signal_group(process, signal.SIGTERM)
        try:
            self._watchdog(process, self.kill_grace)
        except subprocess.TimeoutExpired:
            pass
        self._signal_group(process, signal.SIGKILL)
        self._signal_retained(signal.SIGKILL)
        if process.returncode is None:
            try:
                self._watchdog(process, self.kill_grace)
            except subprocess.TimeoutExpired:
                raise LimitExceeded("child ignored SIGKILL; aborting runner") from None
        self.groups_killed += 1
        self.cancel_window = max(self.cancel_window, self.clock() - start)

    def happenings(self):
        return {"subprocess_runs": self.runs, "max_live_subprocesses": self.max_live_runs,
                "timeouts": self.timeouts, "failures": self.failures, "skipped_after_deadline": self.skipped,
                "process_groups_killed": self.groups_killed, "kill_grace_seconds": self.kill_grace}


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


def binary_identity(path):
    if not path:
        return {"provided": False, "sha256": None, "reason": "no --binary path supplied; the runner does not execute a service binary"}
    candidate = Path(path)
    if not candidate.is_file():
        return {"provided": True, "sha256": None, "reason": "binary path does not exist; not executed"}
    return {"provided": True, "sha256": sha256_file(candidate), "executed": False, "path": str(candidate)}


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
    """Live temp accounting against a conservative promised estimate.

    The runner creates its own top-level fixture root and one subdirectory per
    repository with ``mkdtemp`` (exclusive creation, so each adopted name is
    proven to be ours). Temporary files the standard library creates in the
    shared temp directory are adopted by ``_AttributingOpen`` and removed with
    the fixture, so a cancelled run cannot leave them unaccounted.

    ``reserve`` charges the full estimate before the fixture exists. After a
    step, ``check`` charges live observed bytes plus the estimate for steps not
    yet performed (``held``). Live files (the work index and reflogs) are
    charged once per repository inside the estimate; once the first one exists
    their per-repository share leaves ``held`` because the file is now
    observed. At the start of a later repository that share is still in
    ``held`` while an earlier repository's file is observed, so ``owed_live``
    projects it back instead of double-booking.
    """

    def __init__(self, budget, estimate, returned_estimate=None, live_share=0):
        self.budget = budget
        self.estimate = estimate
        self.returned_estimate = estimate if returned_estimate is None else returned_estimate
        self.live_share = live_share
        self.root = None
        self.held = estimate
        self.live_charged = False
        self.owed_live = 0
        self.observed = 0
        self.peak = 0
        self.checkpoints = 0
        self.owned_dirs = []
        self.owned_files = []
        self.open_files = []
        self.attributed_writes = False
        self.refused = None

    def reserve(self, label):
        self._charge(self.held, label)

    def open(self, label):
        """Create the run's own private fixture root and adopt it."""
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-w0-git-"))
        self.owned_dirs.append(self.root)
        self.check(label)

    def repository_dir(self, index, label):
        path = Path(tempfile.mkdtemp(prefix=f"repo-{index}-", dir=self.root))
        self.owned_dirs.append(path)
        self.check(label)
        return path

    def begin_repository(self, first):
        self.owed_live = 0 if first else self.live_share

    def own(self, path):
        """Register a file the run created outside the fixture for removal."""
        candidate = Path(path)
        if candidate not in self.owned_files:
            self.owned_files.append(candidate)

    def attach_file(self, handle):
        for stream in (handle, getattr(handle, "file", None)):
            if stream is not None and hasattr(stream, "fileno"):
                self.open_files.append(stream)
                return

    def finalize(self):
        """Close run-owned handles and record whether they ever held data."""
        for stream in self.open_files:
            try:
                stream.close()
            except OSError:
                pass
        self.open_files = []
        for path in self.owned_files:
            try:
                if path.stat().st_size > 0:
                    self.attributed_writes = True
                    break
            except OSError:
                continue
        return self.peak

    def cleanup(self):
        """Remove every run-owned file and directory, deepest first.

        Returns an error string when something could not be removed; the
        report surfaces it instead of claiming a clean fixture.
        """
        errors = []
        for path in sorted(set(self.owned_files), key=lambda item: len(str(item)), reverse=True):
            try:
                path.unlink()
            except FileNotFoundError:
                continue
            except OSError as error:
                errors.append(f"{type(error).__name__} removing {path.name}")
        for path in sorted(set(self.owned_dirs), key=lambda item: len(str(item)), reverse=True):
            try:
                shutil.rmtree(path)
            except FileNotFoundError:
                continue
            except OSError as error:
                errors.append(f"{type(error).__name__} removing {path.name}")
        self.owned_files = []
        self.owned_dirs = []
        return "; ".join(sorted(set(errors))) or None

    def _charge(self, value, label):
        if value > self.budget:
            raise BudgetViolation(f"{label}: temp charge {value} would exceed max_temp_bytes {self.budget}")
        self.peak = max(self.peak, value)

    def check(self, label):
        """Observe the fixture root and charge live bytes plus pending estimate."""
        if self.root is None:
            self._charge(self.held, label)
            return
        self.observed = _directory_bytes(self.root)
        if not self.live_charged and (self.root / "repo-0" / "work" / ".git" / "index").is_file():
            self.held = max(0, self.held - self.live_share)
            self.live_charged = True
        projected = self.held + self.observed + self.owed_live
        if projected > self.budget:
            raise BudgetViolation(f"{label}: temp budget exceeded ({self.held} pending + "
                                  f"{self.observed} observed + {self.owed_live} owed)")
        self._charge(projected, label)
        self.checkpoints += 1


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


_REAL_OPEN = open
# The budget currently enforcing a run; ``_AttributingOpen`` instances created
# around a run resolve to it instead of holding a private copy.
_active_budget = None


def _inside(path, root):
    """Lexical containment: entries created in tempdir itself are run-owned."""
    try:
        Path(os.path.abspath(os.fsdecode(path))).relative_to(Path(os.path.abspath(str(root))))
        return True
    except (ValueError, OSError, TypeError):
        return False


class _AttributingOpen:
    """Attribute temp files created outside the fixture to the run that made them.

    The standard library creates its temporary files by name in the shared
    temp directory (``tempfile._TemporaryFileWrapper`` opens the wrapped file
    through an opener it captured at import time). Those files often outlive
    the code that created them until a garbage collector notices, so they can
    pile up unaccounted. While a run is active, the run's budget adopts every
    such file: it is charged and refused when it would breach the budget, and
    removed when the run ends. Everything else is delegated unchanged, so the
    proxy is transparent to callers and to ``unittest.mock.patch``, whose own
    context manager is delegated as well.
    """

    def __init__(self, budget=None):
        self._budget = budget

    @property
    def budget(self):
        return _active_budget if _active_budget is not None else self._budget

    @budget.setter
    def budget(self, value):
        self._budget = value

    def __call__(self, file, mode="r", *args, **kwargs):
        budget = self.budget
        writing = isinstance(file, (str, bytes, os.PathLike)) and any(flag in mode for flag in "wax+")
        if budget is None or not writing or budget.root is None or _inside(file, budget.root):
            return _REAL_OPEN(file, mode, *args, **kwargs)
        candidate = Path(os.fsdecode(file))
        budget.own(candidate)
        try:
            handle = _REAL_OPEN(file, mode, *args, **kwargs)
        except OSError as error:
            budget.owned_files = [path for path in budget.owned_files if path != candidate]
            if error.errno == errno.ENOSPC:
                raise BudgetViolation(f"{error.filename}: temp directory full while creating a run-owned file") from error
            raise
        budget.attach_file(handle)
        try:
            budget.check("temp file")
        except BudgetViolation:
            # A refused write breaks the run even though nothing was charged;
            # the report must say the run was budget-stopped.
            budget.refused = "temp file creates bytes beyond the admitted budget"
            raise
        return handle

    def __enter__(self):
        return _REAL_OPEN.__enter__(self)

    def __exit__(self, *exc):
        return _REAL_OPEN.__exit__(self, *exc)

    def __getattr__(self, name):
        return getattr(_REAL_OPEN, name)


def _write_bounded(path, payload, size, runner, budget):
    """Write a payload in cancellable chunks, checking the live temp budget."""
    budget.check("git payload")
    full = payload * (size // len(payload) + 1)
    with _REAL_OPEN(path, "wb") as handle:
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


def run_git_workload(workload, runner, seed, returned=None):
    """Run Git; the deadline and temp budget gate every expensive step.

    Returns ``(metrics, truncated, budget)`` with the same ``TempBudget``
    instance that enforced every checkpoint, and removes the fixture before
    returning. A deadline or budget hit after the first push truncates the run;
    workload rejection happens before any effect.
    """
    spec = workload["git"]
    pushes = returned_pushes(workload, returned)
    full_estimate = estimate_temp_bytes(workload)
    returned_estimate = estimate_temp_bytes(workload, pushes)
    live_share = (ADMISSION["work_index_bytes"] + 2 * ADMISSION["index_entry_bytes"]
                  + ADMISSION["work_reflog_bytes"] + ADMISSION["ref_lock_bytes"])
    budget = TempBudget(workload["bounds"]["max_temp_bytes"], full_estimate, returned_estimate,
                        live_share=live_share)
    push_samples, cas_samples, fsck_samples = [], [], []
    cas_outcomes, cas_modes = {}, {}
    bare_repos = []
    progressed = truncated = False
    stop_reason = None
    real_open = getattr(builtins, "open", _REAL_OPEN)
    _active_budget = budget
    builtins.open = _AttributingOpen(budget)
    try:
        runner.enforce_deadline("git fixture admission")
        if _isolated_worktree_parent(tempfile.gettempdir()) is None:
            # Fail before any effect: a bounded report is impossible here.
            raise LimitExceeded("temp directory is inside a Git repository; fixture work trees would inherit it, "
                                "so the workload cannot run (set TMPDIR outside any repository)")
        budget.reserve("git fixture admission")
        budget.open("git fixture admission")
        root = budget.root
        workers = max(1, min(RUNNER_LIMITS["max_cas_concurrency"], spec["cas_concurrency"]))
        # fsck is deferred until the CAS pool is closed so a pool exit can never
        # wait on a cancelled fsck child while the deadline has already passed.
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for repo_index in range(spec["repo_count"]):
                budget.begin_repository(repo_index == 0)
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
    except (RunnerTimeout, BudgetViolation) as error:
        if not progressed:
            raise
        truncated = True
        stop_reason = str(error) if budget.refused is None else f"{error} ({budget.refused})"
        if isinstance(error, RunnerTimeout):
            cas_outcomes["timeout"] = max(1, cas_outcomes.get("timeout", 0))
    finally:
        _active_budget = None
        vars(builtins)["open"] = real_open
        temp_bytes = _directory_bytes(budget.root) if budget.root is not None else 0
        peak = budget.finalize()
        removal_error = budget.cleanup()
    metrics = {
        "git.receive_pack.small_pack.latency_ms": summarize(push_samples) if push_samples else unavailable("no pushes executed"),
        "git.update_ref.cas_conflict.latency_ms": summarize(cas_samples) if cas_samples else unavailable(
            "no CAS attempts executed"),
        "git.fsck.closure.duration_ms": summarize(fsck_samples) if fsck_samples else unavailable(
            "fsck disabled, or stopped by the remaining-time/temp budget"),
        "runner.temp_bytes": summarize([temp_bytes]),
    }
    cas = metrics["git.update_ref.cas_conflict.latency_ms"]
    cas["cas_successes"] = cas_outcomes.get("won", 0)
    cas["cas_attempts"] = sum(count for name, count in cas_outcomes.items() if name != "timeout")
    cas["cas_outcomes"] = {name: cas_outcomes.get(name, 0) for name in ("won", "cas_conflict", "failed", "timeout")}
    cas["cas_targets"] = cas_modes
    temp = metrics["runner.temp_bytes"]
    temp.update({"budget_bytes": budget.budget, "admission_estimate_bytes": full_estimate,
                 "returned_estimate_bytes": returned_estimate, "peak_charged_bytes": peak,
                 "checkpoints": budget.checkpoints, "attributed_writes": budget.attributed_writes})
    if removal_error:
        temp["cleanup_error"] = removal_error
    if stop_reason and truncated:
        temp["stop_reason"] = stop_reason
    return metrics, truncated, budget


def run_pg_workload(workload, runner, dsn_file):
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
        return {"pg.round_trip.latency_ms": unavailable("psql query failed; details suppressed"),
                "pg.advisory_lock.acquire_ms": unavailable("psql query failed; details suppressed")}
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
                 deadline, source, admission_facts, *, pg_metrics=None, version=None, elapsed=None):
    unavailable_api = "no native HTTP service was executed in W0; API push-end-to-end is unmeasured"
    unavailable_blob = "no OpenDAL BlobStore exists at the baseline; S3/Local adapter is not a Blob authority and no provider credentials were used"
    metrics = {key: unavailable("not measured by this bounded runner") for key in METRIC_REGISTRY}
    metrics["api.push.e2e.latency_ms"] = unavailable(unavailable_api)
    for key in ("blob.put.latency_ms", "blob.get.latency_ms"):
        metrics[key] = unavailable(unavailable_blob)
    metrics.update(git_metrics)
    metrics.update(pg_metrics or run_pg_workload(workload, runner, args.pg_dsn_file))
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
            "binary": binary_identity(args.binary),
            "workload": {"id": workload["id"], "sha256": sha256_file(workload_path),
                         "bounds": {key: workload["bounds"].get(key) for key in
                                    ("wall_clock_seconds", "max_git_push_ops", "max_cas_ops", "max_temp_bytes")}},
            "budgets": {"sha256": sha256_file(args.budgets), "status": budgets.get("status")},
            "runner": {"sha256": sha256_file(Path(__file__)), "python": sys.version.split()[0],
                       "git": version if version is not None else git_output(runner, ["--version"]),
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
            "runner.temp_bytes is post-run stored bytes; admission_estimate_bytes is the conservative pre-run reservation and "
            "peak_charged_bytes is the live high-water of observed plus pending bytes, which can exceed the estimate only when "
            "a live file is charged both as an existing byte and as a not-yet-created one (for example the work index at the "
            "start of a later repository); the budget still rejects any breach",
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
                        help="per-subprocess cap, itself capped by the remaining absolute deadline")
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
    child_start = resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime
    # One absolute deadline: it covers source identity, Git, PostgreSQL and
    # every version/cleanup subprocess that follows.
    deadline = time.monotonic() + workload["bounds"]["wall_clock_seconds"]
    runner = Runner(deadline, stall_seconds=args.stall_seconds)
    truncated = False
    budget = None
    source = {"status": "unavailable", "reason": "source identity not collected before the run stopped"}
    try:
        source = source_identity(runner, args.allow_dirty)
        git_metrics, truncated, budget = run_git_workload(workload, runner, seed, facts["returned_pushes_per_repo"])
    except RunnerTimeout:
        truncated = True
        git_metrics = {key: unavailable("absolute runner deadline reached; remaining steps cancelled")
                       for key in GIT_METRICS}
    except BudgetViolation as error:
        git_metrics = {key: unavailable(f"temp budget stopped the run: {error}") for key in GIT_METRICS}
    except LimitExceeded as error:
        # Pre-push refusal (for example a temp root inside a repository) or a
        # child that survived SIGKILL: no bounded measurement is possible.
        git_metrics = {key: unavailable(f"run refused before measurement: {error}") for key in GIT_METRICS}
    child_cpu = resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime - child_start
    try:
        pg_metrics = run_pg_workload(workload, runner, args.pg_dsn_file)
        version = git_output(runner, ["--version"])
    except RunnerTimeout:
        # PostgreSQL or the version probe consumed the remaining deadline:
        # record that honestly instead of retrying beyond the budget.
        truncated = True
        pg_metrics = {key: unavailable("absolute runner deadline reached; PostgreSQL not measured")
                      for key in ("pg.round_trip.latency_ms", "pg.advisory_lock.acquire_ms")}
        version = unavailable("git version not probed within the runner deadline")
    elapsed = time.monotonic() - (deadline - workload["bounds"]["wall_clock_seconds"])
    report = build_report(workload, Path(args.workload), budgets, args, git_metrics, truncated, child_cpu,
                          runner, deadline, source, facts, pg_metrics=pg_metrics, version=version, elapsed=elapsed)
    # Provenance for the budget that actually enforced the run (not a copy).
    if budget is not None:
        report["limits"]["temp_budget"] = {
            "budget_bytes": budget.budget,
            "estimate_bytes": budget.estimate,
            "returned_estimate_bytes": budget.returned_estimate,
            "peak_charged_bytes": budget.peak,
            "checkpoints": budget.checkpoints,
            "attributed_writes": budget.attributed_writes,
        }
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
