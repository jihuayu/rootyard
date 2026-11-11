#!/usr/bin/env python3
"""Rerunnable native baseline for the current fresh-install Blob-only service.

Measured profile: only ``rootyard serve-blob`` (HTTP API plus stock Smart HTTP
Git on the fixture's loopback origin). The legacy/Pando baseline is neither
used nor extended.

Rerun (from the repository root; load the dedicated fixture profile yourself,
this runner never reads or prints profile files)::

    scripts/state_services_blob_baseline.py \
        --binary "$PWD/target/release/rootyard" \
        --git /absolute/trusted/git \
        --report /tmp/blob-baseline/report.json [--keep]

Inputs
    --binary  absolute attested executable with an adjacent ``<binary>.build.json``
              receipt; the reused ``blob_only_service.NativeProfile`` check binds
              it to the current source inputs and candidate commit.
    --git     optional trusted absolute Git (falls back to ROOTYARD_GIT /
              ROOTYARD_TEST_GIT); the same binary serves the service and the
              stock Git clients.
    --report  required credential-free JSON report destination.
    --keep    retain the harness-owned fixture directory (the random PostgreSQL
              schema is still dropped, as in every harness run).

The strict OpenDAL S3 profile (``check_blob_profile``) and
``ROOTYARD_TEST_DATABASE_URL`` are required; every run migrates one isolated
random schema through ``BlobOnlyHarness``. Linux ``/proc``, a CSPRNG and the
tools in ``REQUIRED_TOOLS`` must exist, otherwise the run fails closed before
anything is started (the tools are also re-checked before the first process).

Order of a run (setup is reported separately from every measured case):

setup      schema migration, fixture accounts and serve-blob start/readiness.
1. provision         one repository via ``POST /api/repos`` under the live
                     process; SQL never seeds a ready repository.
2. seed_push         the deterministic repository below (exactly 256 KiB)
                     pushed once by Smart HTTP; ``push_wall_seconds`` times that
                     ``git push`` alone and ``ls_remote_seconds`` the separate
                     ``ls-remote`` acknowledgement.
3. concurrent_read_clones
                     two concurrent read-only clones of that single seed
                     repository into two distinct destinations; per-worker and
                     aggregate wall times cover ``git clone`` only. The report
                     records the effective service admission settings (read
                     only, never overridden) and checks that the configured
                     capacity covers these two concurrent clones.
4. restart           graceful stop/start of this harness's own process group.
                     Not a sampled case: sampling is finished for the old PID
                     before the stop and the new epoch begins at cold_clone.
5. cold_clone        service-local scratch emptied, recreated and verified
                     empty, then one cold clone of the seed repository.

Every clone is issued exactly once; its working tree is then checked in place
(HEAD, object format, exact file bytes) and ``git fsck --full --strict`` runs
after the timer stops. Before the first serve-blob start (once before setup and
again right after setup's schema migration and account CLI steps, checked inside
a temporary ``harness.start`` wrapper that is restored in ``finally``) and right
before the restart's start, the same fixed SQL must report zero named sessions;
any existing session fails closed. For each sampled case the runner reads PostgreSQL every
250 ms for sessions owned by the actual service process: only sockets held by
that process (``/proc/<pid>/fd`` socket inodes joined with its own
``/proc/<pid>/net/tcp{,6}``, ESTABLISHED only) whose remote endpoint is the
configured database address and DSN port (resolved once) are counted.
``pg_stat_activity`` rows are selected by the current test database and the two
application names the current Rust sources set for serve-blob (``rootyard``
pool and ``rootyard-blob-barrier``); sessions, active, idle and Lock waiters
come from those rows only. Every sample must see that count equal (and
nonzero) to the PID's own endpoint socket count. Client address and port are
never compared: NAT or a Docker host port publication rewrites them between
the host and the server. Counts are observed lower bounds on a fixed grid,
reset per process and never differenced across the restart; short lock waits
can be missed and exact lock-wait milliseconds are never invented. A sampling
error fails the run.

Cold means a process-local materialized view after that restart only; the
backing object-store/provider cache state is unknown and was not observed.
OpenDAL GET byte/phase metrics are reported as explicitly unmeasured because
the current service exposes no such counters. Reports never contain an
environment dump, DSN, endpoint/bucket/root value, credential,
request/response body or raw server log; exception text only passes through
``BlobOnlyHarness.redact``. This is a baseline entry for #106: it neither marks
the issue complete nor freezes any budget.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import secrets
import shutil
import socket
import sys
import threading
import time
import traceback
import urllib.parse

if not __debug__:
    raise RuntimeError("Blob-only baseline requires Python assertions; do not use -O or PYTHONOPTIMIZE")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import blob_only_service as serving  # noqa: E402
import ops_provenance  # noqa: E402

KIND = "rootyard/state-services-blob-baseline"
REPORT_VERSION = 3
MEASURED_PROFILE = "blob-only-serve-blob-fresh-install"
WORKLOAD_VERSION = 1
SAMPLE_INTERVAL_SECONDS = 0.25
STARTUP_SAMPLE_TIMEOUT_SECONDS = 10.0
READ_BARRIER_TIMEOUT_SECONDS = 30
AGGREGATE_SLACK_SECONDS = 0.005
# The aggregate may sit fractionally below the slowest worker (it closes on the
# last-returning clone, whose timer starts microseconds after the release).
AGGREGATE_SLACK_RATIO = 0.25
MAX_PAYLOAD_BYTES = 256 * 1024
CONCURRENCY = 2
READ_MODE = "single_repository_independent_read_clones"
REPOSITORY_NAME = "blob-baseline"
# One measured seed repository; every concurrent worker clones it into its own destination.
WORKER_REPOSITORIES = (REPOSITORY_NAME,) * CONCURRENCY
CASE_ORDER = ("provision", "seed_push", "concurrent_read_clones", "restart", "cold_clone")
PUSH_REF = "refs/heads/main"
REQUIRED_TOOLS = ("psql", "hostname")
# The service sessions are identified, never by client address/port (NAT
# rewrites both), by rows in the current test database whose application_name
# is one of the two identities the Rust sources set: ``src/db.rs`` sets the
# application pool to ``rootyard`` and ``src/standalone.rs`` sets the held
# lifecycle barrier session to ``rootyard-blob-barrier``. Runner/psql helper
# and admin connections carry neither name. The literal SQL below is fixed.
PG_STAT_QUERY = ("SELECT count(*),"
                 "count(*) FILTER (WHERE state='active'),"
                 "count(*) FILTER (WHERE state='idle'),"
                 "count(*) FILTER (WHERE wait_event_type='Lock') "
                 "FROM pg_stat_activity WHERE datname=current_database() "
                 "AND application_name IN ('rootyard', 'rootyard-blob-barrier')")
# The identities ``PG_STAT_QUERY`` selects, as named by the current Rust sources.
SERVICE_APPLICATION_NAMES = ("rootyard", "rootyard-blob-barrier")
# Why the ownership samples mean anything: one dedicated baseline database, one
# isolated random schema, and no other Rootyard CLI/service or pooler/shared
# database touching named sessions. Never a per-socket four-tuple claim.
PG_OWNERSHIP_SCOPE = ("Issue106 lane dedicated baseline PostgreSQL database + harness isolated random schema; "
                      "requires no concurrent same-name Rootyard CLI/service on that database and no PostgreSQL "
                      "pooler or shared database. A pre-start check requires zero named sessions and every sample "
                      "requires the named session count to equal the service PID's endpoint socket count (nonzero), "
                      "so an extra same-name session is rejected.")
# The fixed seed workload: exactly MAX_PAYLOAD_BYTES of deterministic bytes.
# Kept as an invariable map so the independent worker repositories receive
# byte-identical copies and their commits are reproducible.
WORKLOAD_FILES = {
    "README.txt": b"Blob-only baseline fixture.\n",
    "config/settings.toml": b'mode = "baseline"\nvalue = 106\n',
    "src/\u4e2d\u6587.txt": "UTF-8: \u4e2d\u6587\n".encode(),
}
WORKLOAD_PAYLOAD = "payload.bin"
# Harness/tool sources whose bytes qualify the run; hashed into the report.
INPUT_FILES = ("tests/blob_only_service.py", "tests/e2e.py", "tests/native_evidence.py",
               "tests/ops_provenance.py", "tests/owned_fuse_cleanup.py", "scripts/build_native.py")
# Names whose values must never reach a report (checked before writing, not trusted).
SENSITIVE_PATTERN = re.compile(r"BLOB|DATABASE|DSN|PASS|SECRET|TOKEN|KEY|CREDENTIAL", re.IGNORECASE)
CONNECTION_ESTABLISHED = "01"
LISTEN = "0A"
WILDCARD = ("0.0.0.0", "::")
COLD_SEMANTICS = ("cold = process-local materialized view after this run's graceful service restart with an "
                  "emptied and freshly recreated service-local scratch root; the scratch root was verified empty "
                  "immediately before and immediately after the cold read. Backing object-store/provider cache "
                  "state is unknown and was not observed; this is not provider-cold.")
LIMITS = [
    "One loopback HTTP origin, one PostgreSQL server and one configured OpenDAL S3 provider on one host; no HA, "
    "multi-host, physical durability or production-latency claim. PostgreSQL scope: " + PG_OWNERSHIP_SCOPE,
    "The restart is a SIGTERM to this harness's own serve-blob process group; kernel/power-loss behavior is not tested.",
    "The concurrent case times " + str(CONCURRENCY) + " independent read-clone destinations from the same "
    "single seeded repository; receive-pack writes are not measured.",
    "PostgreSQL counts are 250 ms point samples of current-database sessions named by the serve-blob sources "
    "(application_name 'rootyard'/'rootyard-blob-barrier'), cross-checked against the service PID's own "
    "ESTABLISHED sockets to the configured database endpoint: observed lower bounds only; short waits can be "
    "missed and exact lock-wait milliseconds are unmeasured. Scope: " + PG_OWNERSHIP_SCOPE,
    "The scope is a COUNT of named sessions and of PID-owned sockets (count equality per sample): it is never "
    "a per-socket four-tuple or PID-to-backend mapping, and NAT-rewritten client address/port pairs are never "
    "compared or attributed.",
    "OpenDAL GET byte/phase metrics are unmeasured: the current service exposes no such counters to this runner.",
    COLD_SEMANTICS,
    "Workload is one small deterministic repository bounded to 256 KiB plus three identical read-only "
    "repositories; no throughput, percentile or regression budget is inferred.",
    "This report is a baseline entry for #106; it does not claim #106 complete and freezes no budget.",
    "Blob deletion stays disabled; objects uploaded under the fixture root are not reclaimed by this harness.",
]


class BaselineError(RuntimeError):
    """Fail-closed preflight or validation failure; messages are already redacted."""


def need(condition, message):
    if not condition:
        raise BaselineError(message)


def sha256_file(path):
    return ops_provenance.sha256_file(Path(path))


def safe_write_report(path, payload):
    """Write one JSON payload atomically; return '' on success or a safe error string."""
    if not path:
        return ""
    destination = Path(path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary.replace(destination)
        return ""
    except (OSError, TypeError, ValueError) as error:
        return type(error).__name__ + " while writing the report"


# --- workload -------------------------------------------------------------------
def select_workload():
    """The fixed deterministic repository: bounded payloads, identical bytes on every run."""
    headroom = MAX_PAYLOAD_BYTES - sum(len(data) for data in WORKLOAD_FILES.values())
    need(headroom >= 1024, "workload text files leave no bounded payload room")
    files = dict(WORKLOAD_FILES)
    files[WORKLOAD_PAYLOAD] = random.Random(106).randbytes(headroom)
    need(sum(len(data) for data in files.values()) == MAX_PAYLOAD_BYTES, "workload payload is not exactly the bound")
    return files


def workload_fingerprint(files):
    """Digest of the exact bytes pushed to every fixture repository."""
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + len(files[name]).to_bytes(8, "big") + files[name])
    return digest.hexdigest()


def describe_workload(files):
    return {"files": [{"path": name, "bytes": len(files[name])} for name in sorted(files)],
            "total_bytes": sum(len(data) for data in files.values())}


def validate_workload(workload):
    """Validate the fixed, bounded workload declaration; reject anything else."""
    need(isinstance(workload, dict), "workload must be an object")
    need(workload.get("version") == WORKLOAD_VERSION, "unsupported workload version")
    need(workload.get("total_bytes") == MAX_PAYLOAD_BYTES, "workload payload bound changed")
    need(workload.get("concurrency") == CONCURRENCY, "workload concurrency changed")
    need(workload.get("mode") == READ_MODE, "workload mode changed")
    need(workload.get("repositories_provisioned_via") == "POST /api/repos", "workload provisioning route changed")
    fingerprint = workload.get("fingerprint_sha256")
    need(isinstance(fingerprint, str) and len(fingerprint) == 64, "workload fingerprint is missing")
    files = workload.get("files")
    need(isinstance(files, list) and files, "workload lists no files")
    names, total = set(), 0
    for entry in files:
        need(isinstance(entry, dict), "workload file entry must be an object")
        name, size = entry.get("path"), entry.get("bytes")
        need(isinstance(name, str) and name and not name.startswith("/") and "\\" not in name
             and "\0" not in name and all(part not in ("", ".", "..") for part in name.split("/")),
             "workload path must be a relative POSIX path")
        need(name not in names, "duplicate workload path")
        names.add(name)
        need(isinstance(size, int) and not isinstance(size, bool) and size >= 0,
             "workload file size must be a non-negative integer")
        total += size
    need(0 < total <= MAX_PAYLOAD_BYTES, "workload payload exceeds its bound")
    return {"total_bytes": total, "files": len(files), "paths": sorted(names)}


# --- pure validation helpers (unit-tested without network or service) -----------
def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def validate_push_result(result):
    """Validate the ``run_push`` measurement: raw exit code, stdout and OIDs are still present.

    A summary that dropped the raw push evidence never passes, so a report can
    only be assembled from the measurement that actually checked the push.
    """
    need(isinstance(result, dict), "push result must be an object")
    need(isinstance(result.get("stdout"), str) and "returncode" in result,
         "raw git push output is missing")


def validate_push_summary(result):
    """Check a push that exited zero, reported exactly one accepted PUSH_REF, and was read back.

    ``push_wall_seconds`` times only the ``git push`` invocation; the separate
    ``ls-remote`` acknowledgement check is timed by ``ls_remote_seconds`` and is
    never folded into the push duration (nor into setup).
    """
    if result.get("returncode") != 0:
        raise BaselineError("git push exited non-zero")
    seconds = result.get("push_wall_seconds")
    need(_number(seconds) and seconds >= 0, "push wall time is missing or invalid")
    entries = serving.parse_push(result.get("stdout") or "")
    targets = [entry["target"] for entry in entries]
    need(targets.count(PUSH_REF) == 1, "git push reported something other than one " + PUSH_REF)
    need(serving.push_success(entries, PUSH_REF), "git push did not accept " + PUSH_REF)
    oid, expected = result.get("oid"), result.get("expected_oid")
    need(isinstance(oid, str) and len(oid) == 40 and expected == oid, "push OID is not the expected SHA-1")
    need(result.get("remote_oid") == oid, "remote advertisement does not acknowledge the pushed OID")
    confirmation = result.get("ls_remote_seconds")
    need(confirmation is None or _number(confirmation) and confirmation >= 0, "ls-remote time is invalid")
    payload = result.get("payload_bytes")
    need(payload is None or isinstance(payload, int) and not isinstance(payload, bool) and payload >= 0,
         "push payload size is invalid")
    return {"ref": PUSH_REF, "oid": oid, "expected_oid": expected, "push_wall_seconds": round(float(seconds), 6),
            "ls_remote_seconds": None if confirmation is None else round(float(confirmation), 6),
            "payload_bytes": payload}


def validate_worker(label, entry, seed_oid):
    """One concurrent clone: distinct destination, seed OID, verification outside the timer."""
    need(isinstance(entry, dict), "worker record must be an object")
    need(entry.get("label") == label, "worker label mismatch")
    need(entry.get("kind") == "read_clone", "worker kind must be read_clone")
    need(entry.get("repository") == REPOSITORY_NAME, "each read must clone the single seed repository")
    need(entry.get("expected_oid") == seed_oid, "worker clone expected a different OID than the seed push")
    seconds = entry.get("seconds")
    need(_number(seconds) and seconds >= 0, "worker wall time is invalid")
    need(entry.get("head_oid") is not None and entry.get("head_oid") == entry.get("expected_oid"),
         "worker clone HEAD differs from the expected OID")
    need(entry.get("files_verified") is True and entry.get("fsck") is True, "worker clone was not verified")
    return {"label": label, "kind": "read_clone", "destination": entry.get("destination"),
            "seconds": round(float(seconds), 6), "verification_seconds": entry.get("verification_seconds")}


def aggregate_wall(workers, aggregate_seconds, seed_oid):
    """Aggregate and per-worker clone wall times plus the observed concurrency window.

    The aggregate spans from the first clone start to the last clone return, so
    it normally exceeds the slowest worker but may sit fractionally below it: a
    clone that started slightly later may return slightly later. Small
    differences are legitimate; a materially shorter aggregate means the window
    stopped before the clones finished and is rejected.
    """
    need(isinstance(workers, list) and len(workers) == CONCURRENCY,
         "expected exactly " + str(CONCURRENCY) + " workers")
    destinations = [worker.get("destination") for worker in workers if isinstance(worker, dict)]
    need(len(set(destinations)) == len(workers), "concurrent workers share a clone destination")
    validated = [validate_worker("worker-" + str(index + 1), worker, seed_oid) for index, worker in enumerate(workers)]
    need(_number(aggregate_seconds) and aggregate_seconds >= 0, "aggregate wall time is invalid")
    longest = max(worker["seconds"] for worker in validated)
    need(aggregate_seconds + max(AGGREGATE_SLACK_SECONDS, AGGREGATE_SLACK_RATIO * longest) >= longest,
         "aggregate wall time is materially shorter than one worker's clone; the aggregate must span "
         "from the first clone start to the last clone return")
    return {"mode": READ_MODE,
            "concurrent_write_pushes": False,
            "workers": validated,
            "worker_seconds": [worker["seconds"] for worker in validated],
            "aggregate_seconds": round(float(aggregate_seconds), 6),
            "aggregate_definition": "max(clone end) - min(clone start): from the first git clone call start "
                                    "to the last git clone call return; local OID/content/object-format/fsck "
                                    "verification runs only after the window closes",
            "timed_scope": "git clone only, for every worker and for the aggregate: the aggregate runs from the "
                           "first clone start to the last clone return, and every local "
                           "OID/content/object-format/fsck check runs afterwards on the main thread, outside "
                           "every timed boundary",
            "verification_scope": "per-worker verification_seconds are informational only: with a fixed worker "
                                  "pool later workers verify after their clone timer stops, so these are never "
                                  "compared or summed",
            "includes_local_verification": False,
            "repositories_cloned_per_worker": 1,
            "concurrency_window_ratio": round(aggregate_seconds / longest, 6) if longest > 0 else None}


def validate_case(entry, name):
    """A case must have actually executed with a finite, non-negative duration."""
    need(isinstance(entry, dict) and entry.get("name") == name and entry.get("status") == "passed",
         "case is not passed: " + name)
    seconds = entry.get("seconds")
    need(_number(seconds) and seconds >= 0, "case duration is missing or invalid: " + name)
    return entry


RESTART = CASE_ORDER.index("restart")


def validate_restart(entry, before_epoch):
    """The restart is infrastructure: it owns no samples and never merges two processes."""
    need(isinstance(entry, dict), "restart record is missing")
    validate_case(entry, "restart")
    need(entry.get("sampled") is False, "restart must not claim PostgreSQL samples")
    need(entry.get("pg_samples") is None, "restart must not carry samples")
    need(isinstance(entry.get("skip_reason"), str) and entry["skip_reason"], "restart skip reason is missing")
    need(entry.get("from_epoch") == before_epoch and entry.get("service_epoch") == before_epoch + 1,
         "restart did not advance exactly one service epoch")
    old_pid, new_pid = entry.get("old_pid"), entry.get("new_pid")
    need(isinstance(old_pid, int) and isinstance(new_pid, int) and old_pid != new_pid,
         "restart did not create a new service process")
    need(entry.get("samples_stopped_before_stop") is True,
         "old-process sampling was not finished before the stop")
    return {"seconds": round(float(entry["seconds"]), 6), "sampled": False, "pg_samples": None,
            "skip_reason": entry["skip_reason"], "from_epoch": before_epoch, "service_epoch": before_epoch + 1,
            "pid_changed": True}


def validate_cases(cases, epochs):
    """Exactly CASE_ORDER under one PID per epoch; only the restart may be unsampled."""
    need(isinstance(cases, list) and len(cases) == len(CASE_ORDER), "case inventory mismatch")
    entries = [validate_case(case, name) for name, case in zip(CASE_ORDER, cases)]
    need([case["name"] for case in entries] == list(CASE_ORDER), "case inventory mismatch")
    need(isinstance(epochs, list) and len(epochs) == len(CASE_ORDER), "service epoch inventory mismatch")
    for epoch in epochs:
        need(isinstance(epoch, int) and not isinstance(epoch, bool) and epoch >= 0, "service epoch is invalid")
    need(all(left <= right for left, right in zip(epochs, epochs[1:])), "service epochs are out of order")
    before, after = epochs[0], epochs[RESTART]
    need(after == before + 1, "restart did not advance exactly one service epoch")
    need(all(epoch == before for epoch in epochs[:RESTART]), "restart merged two processes inside one epoch")
    need(all(epoch == after for epoch in epochs[RESTART + 1:]), "cold clone ran outside the restarted epoch")
    validate_restart(entries[RESTART], before)
    for index, (entry, epoch) in enumerate(zip(entries, epochs)):
        need(entry.get("service_epoch") == epoch, "case records a stale service epoch: " + entry["name"])
        if index != RESTART:
            need(entry.get("sampled") is True, "a measured case must be sampled: " + entry["name"])
            validate_summary(entry.get("pg_samples"))
    return entries


def validate_summary(summary):
    """A per-case sampling summary must be a real observed lower bound on a fixed grid."""
    need(isinstance(summary, dict), "pg sampling summary is missing")
    for name in ("samples", "samples_with_connection", "scans_without_connection", "sessions_nonzero_samples"):
        value = summary.get(name)
        need(isinstance(value, int) and not isinstance(value, bool) and value >= 0, "sampling count is invalid: " + name)
    need(summary["samples"] >= 1 and summary["samples_with_connection"] >= 1,
         "no owned service PostgreSQL sessions were sampled")
    need(summary["samples_with_connection"] <= summary["samples"], "sampled counts are inconsistent")
    need(summary["sessions_nonzero_samples"] <= summary["samples"], "sampled counts are inconsistent")
    for name in ("peak_sessions", "peak_active", "peak_idle", "peak_lock_waiters"):
        value = summary.get(name)
        need(isinstance(value, int) and not isinstance(value, bool) and value >= 0, "peak count is invalid: " + name)
    need(summary["peak_lock_waiters"] <= summary["peak_sessions"], "lock waiters exceed sessions")
    need(summary["peak_active"] + summary["peak_idle"] <= summary["peak_sessions"], "peak states exceed sessions")
    interval = summary.get("interval_seconds")
    need(_number(interval) and interval >= SAMPLE_INTERVAL_SECONDS, "sampling interval is not bounded")
    need(summary.get("observed_lower_bound") is True, "sampling is not labelled a lower bound")
    need("exact_lock_wait_ms" in summary and summary["exact_lock_wait_ms"] is None, "lock waits must stay unmeasured")
    need(summary.get("errors", []) == [], "sampling errors must fail the case")
    return summary


def validate_cold(entry):
    """Cold clone must follow the restart, see an empty scratch view, and verify exact bytes."""
    need(isinstance(entry, dict), "cold clone record is missing")
    need(entry.get("service_restarted") is True, "cold clone did not follow a service restart")
    need(entry.get("scratch_empty_before") is True and entry.get("scratch_empty_after") is True,
         "service-local scratch was not empty around the cold read")
    expected = entry.get("expected_oid")
    need(isinstance(expected, str) and expected and entry.get("head_oid") == expected,
         "cold clone HEAD differs from the expected OID")
    need(entry.get("files_verified") is True and entry.get("fsck") is True, "cold clone was not verified")
    seconds = entry.get("seconds")
    need(_number(seconds) and seconds >= 0, "cold clone duration is invalid")
    need(entry.get("samples_across_restart", False) is False, "cold samples must never span the restart")
    return {"seconds": round(float(seconds), 6), "service_restarted": True,
            "scratch_empty_before": True, "scratch_empty_after": True, "fsck": True,
            "files_verified": True, "head_oid": expected, "expected_oid": expected,
            "semantics": COLD_SEMANTICS, "cold_scope": "process_local_materialized_view_only",
            "provider_cache_state": "unknown", "provider_cache_observed": False,
            "verification_seconds": None, "samples_across_restart": False,
            "includes_local_verification": False,
            "verification_scope": "local OID/bytes/fsck checks follow the clone timer and are excluded, exactly "
                                  "as for every concurrent worker"}


UNAVAILABLE = "unavailable"
# /proc/cpuinfo fields that carry a CPU model, in preference order (x86, ARM, POWER, s390, ...).
CPU_MODEL_FIELDS = ("model name", "Model", "Hardware", "cpu model", "cpu", "Processor", "machine")
CGROUP_FILES = {"cpu.max": "cpu_max", "cpuset.cpus.effective": "cpuset_cpus_effective",
                "memory.max": "memory_max"}


def cpu_model(text, machine=None):
    """CPU model from Linux /proc/cpuinfo, or ``unavailable`` (never the architecture).

    Bounded and cleaned: at most one 200-character line, no control characters,
    and a value that merely repeats ``machine`` (some /proc/cpuinfo "cpu" or
    "Processor" fields hold an architecture) is reported as ``unavailable``.
    """
    if not isinstance(text, str):
        return UNAVAILABLE
    for field in CPU_MODEL_FIELDS:
        for line in text.splitlines():
            key, separator, value = line.partition(":")
            if not separator or key.strip() != field:
                continue
            cleaned = " ".join(value.replace("\0", " ").split())[:200]
            if not cleaned or cleaned == machine:
                continue
            return cleaned
    return UNAVAILABLE


def _decimal(text):
    """True for a plain decimal integer literal (no sign, spaces, underscores or exponents)."""
    return bool(text) and text.isascii() and text.isdigit()


def parse_cpu_max(raw):
    """A cgroup-v2 ``cpu.max`` value: ``('limited', raw, True)``, ``('unlimited', raw, False)`` or None."""
    parts = raw.split()
    if len(parts) != 2:
        return None
    quota, period = parts
    if not _decimal(period) or int(period) <= 0:
        return None
    if quota == "max":
        return "unlimited", raw, False
    if _decimal(quota):
        return "limited", raw, True
    return None


def parse_memory_max(raw):
    """A cgroup-v2 ``memory.max`` value: a single ``max`` token or decimal digits, inside a u64."""
    if raw == "max":
        return "unlimited", raw, False
    if _decimal(raw) and int(raw) <= 2 ** 64 - 1:
        return "limited", raw, True
    return None


def parse_cpuset(raw):
    """A cgroup-v2 ``cpuset.cpus.effective`` CPU set: ``(cpu_count, observed)`` or None.

    The list is validated strictly as ordered ``N`` / ``N-M`` items (``N <= M``)
    so an observation always describes a well-formed CPU set.
    """
    count, previous_end = 0, -1
    for item in raw.split(","):
        if not item or item != item.strip():
            return None
        first, dash, last = item.partition("-")
        if not _decimal(first) or (dash and not _decimal(last)):
            return None
        low = int(first)
        high = int(last) if dash else low
        if high < low or low <= previous_end:
            return None
        count += high - low + 1
        previous_end = high
    return count


def read_cgroup_view(root=None):
    """The runner's own cgroup-v2 resource evidence; no path is ever reported.

    Each field is validated against its documented v2 format. ``status`` is
    ``observed``, ``unlimited`` or ``unavailable``; malformed or missing content
    is ``unavailable`` and never becomes a claimed limit. ``cpu.max`` and
    ``memory.max`` carry an explicit ``limited`` boolean; ``cpuset.cpus.effective``
    is an observed CPU set (``cpu_count``), which has no unlimited meaning.
    """
    base = Path(root) if root is not None else Path("/sys/fs/cgroup")

    def unavailable(key):
        return {"status": UNAVAILABLE, "raw": UNAVAILABLE, "format": "cgroup-v2", "source": "unavailable"}

    view = {"version": "v2"}
    for filename, key in CGROUP_FILES.items():
        try:
            text = (base / filename).read_text()
        except OSError:
            view[key] = unavailable(key)
            continue
        raw = " ".join(text.split())[:64]
        parsed = None if not raw else (
            parse_cpuset(raw) if key == "cpuset_cpus_effective" else
            parse_cpu_max(raw) if key == "cpu_max" else parse_memory_max(raw))
        if parsed is None:
            view[key] = {**unavailable(key), "source": "malformed" if raw else "empty"}
        elif key == "cpuset_cpus_effective":
            view[key] = {"status": "observed", "raw": raw, "format": "cgroup-v2", "source": "cgroup-v2",
                         "cpu_count": parsed}
        else:
            view[key] = {"status": parsed[0], "raw": raw, "format": "cgroup-v2", "source": "cgroup-v2",
                         "limited": parsed[2]}
    return view


CGROUP_LIMITS = ("cpu_max", "memory_max")
CGROUP_FIELDS = ("cpu_max", "cpuset_cpus_effective", "memory_max")


def validate_cgroup_view(view):
    """Validate the cgroup evidence; a missing or malformed value is never unlimited."""
    need(isinstance(view, dict), "cgroup evidence is missing")
    need(view.get("version") == "v2", "cgroup evidence is malformed")
    need(set(view) == {"version"} | set(CGROUP_FIELDS), "cgroup evidence has unexpected fields")
    for key in CGROUP_FIELDS:
        entry = view.get(key)
        # An observed limit/cpuset carries its value key; an unavailable one carries none.
        value_key = ("cpu_count",) if key == "cpuset_cpus_effective" else ("limited",)
        expected = {"status", "raw", "format", "source"}
        if isinstance(entry, dict) and entry.get("status") != UNAVAILABLE:
            expected |= set(value_key)
        need(isinstance(entry, dict) and set(entry) == expected, "cgroup field shape is invalid: " + key)
        raw = entry["raw"]
        need(isinstance(raw, str) and raw and len(raw) <= 64 and "\n" not in raw, "cgroup raw value is invalid: " + key)
        need(entry["format"] == "cgroup-v2", "cgroup format label is invalid: " + key)
        if entry["status"] == UNAVAILABLE:
            need(raw == UNAVAILABLE and entry["source"] in ("unavailable", "malformed", "empty"),
                 "an unavailable cgroup field must not carry a value: " + key)
            if key in CGROUP_LIMITS:
                need("limited" not in entry, "an unavailable field must not claim a limit: " + key)
            else:
                need("cpu_count" not in entry, "an unavailable cpuset must not carry a CPU count: " + key)
            continue
        need(entry["source"] == "cgroup-v2", "an observed cgroup field must have a v2 source: " + key)
        if key == "cpuset_cpus_effective":
            need(entry["status"] == "observed", "a cpuset is an observation, never limited/unlimited: " + key)
            count = entry.get("cpu_count")
            need(isinstance(count, int) and not isinstance(count, bool) and count > 0,
                 "cpuset CPU count is invalid: " + key)
            need(parse_cpuset(raw) == entry["cpu_count"], "cpuset raw value does not match its count: " + key)
            continue
        parsed = parse_cpu_max(raw) if key == "cpu_max" else parse_memory_max(raw)
        need(parsed is not None, "cgroup raw value is malformed: " + key)
        need(entry["status"] == parsed[0], "cgroup status disagrees with its value: " + key)
        need(entry.get("limited") is parsed[2], "cgroup limited flag disagrees with its value: " + key)
    return view


def validate_runtime(runtime):
    """Require every environment fact the report binds itself to."""
    need(isinstance(runtime, dict), "runtime facts are missing")
    for name in ("git_version", "psql_version", "postgres_server_version", "python", "kernel", "machine",
                 "architecture", "hostname"):
        value = runtime.get(name)
        need(isinstance(value, str) and value.strip() and "\n" not in value, "runtime fact is missing: " + name)
    for name in ("logical_cpus", "host_memory_total_kb"):
        value = runtime.get(name)
        need(isinstance(value, int) and not isinstance(value, bool) and value > 0, "runtime fact is missing: " + name)
    need(runtime.get("procfs") is True, "procfs is not available")
    # A CPU model is a /proc/cpuinfo fact; when absent it is "unavailable", never the architecture.
    model = runtime.get("cpu_model")
    need(isinstance(model, str) and model.strip() and "\n" not in model, "cpu_model is missing")
    need(model != runtime["machine"], "cpu_model must never merely repeat the machine architecture")
    validate_cgroup_view(runtime.get("cgroup"))
    return dict(runtime)


def validate_binding(binding):
    """Bind the report to an attested binary, its source inputs and every qualifying input hash."""
    need(isinstance(binding, dict), "build binding is missing")
    need(binding.get("attested") is True and binding.get("inputs_unchanged") is True,
         "build/source binding is not attested")
    for field in ("binary_sha256", "source_inputs_sha256", "build_receipt_sha256", "runner_sha256",
                  "harness_sha256", "trusted_git_sha256"):
        value = binding.get(field)
        need(isinstance(value, str) and len(value) == 64, "binding hash is missing: " + field)
    for field in ("workspace_commit", "rustc"):
        value = binding.get(field)
        need(isinstance(value, str) and value.strip(), "binding field is missing: " + field)
    inputs = binding.get("inputs")
    need(isinstance(inputs, dict) and inputs.get("runner") == binding["runner_sha256"]
         and inputs.get("tests/blob_only_service.py") == binding["harness_sha256"],
         "binding is missing qualifying input hashes")
    return binding


def validate_no_secrets(value, sensitive_values):
    """Reject any report payload containing a configured sensitive value or credential-shaped URL."""
    text = json.dumps(value, sort_keys=True)
    for secret in sensitive_values or ():
        if isinstance(secret, str) and len(secret) >= 4 and secret in text:
            raise BaselineError("report contains a configured sensitive value; refusing to write it")
    lowered = text.lower()
    for marker in ("://user:", "password=", "secret_access_key", "authorization:"):
        need(marker not in lowered, "report contains a credential-shaped marker: " + marker)
    return True


# --- /proc ownership derivation -------------------------------------------------
def decode_socket_address(value):
    """Decode one /proc/net/tcp{,6} hex endpoint into (family, address, port).

    Linux prints the raw struct fields: an inet address is one u32 and an inet6
    address four u32 words, each printed with "%08X" in the host's native byte
    order. On the little-endian x86_64 runner ::1 therefore reads
    ``00000000000000000000000001000000`` and never ``...00000001``.
    """
    if not isinstance(value, str):
        raise ValueError("socket address must be text")
    raw, separator, port = value.rpartition(":")
    if not separator or len(port) != 4 or len(raw) not in (8, 32):
        raise ValueError("malformed /proc socket address")
    if any(character not in "0123456789abcdefABCDEF" for character in raw + port):
        raise ValueError("malformed /proc socket address")
    words = [bytes.fromhex(raw[index:index + 8])[::-1] for index in range(0, len(raw), 8)]
    address = ipaddress.IPv4Address(words[0]) if len(words) == 1 else ipaddress.IPv6Address(b"".join(words))
    return ("inet" if len(words) == 1 else "inet6"), str(address), int(port, 16)


def parse_proc_net_tcp(text):
    """Parse one /proc/net/tcp or tcp6 table (header line required) into socket records."""
    lines = text.splitlines()
    if not lines or "local_address" not in lines[0]:
        raise ValueError("/proc net table has no header")
    sockets = []
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 10 or not fields[9].isdigit():
            raise ValueError("malformed /proc net row")
        family, local_address, local_port = decode_socket_address(fields[1])
        peer_family, peer_address, peer_port = decode_socket_address(fields[2])
        if family != peer_family:
            raise ValueError("/proc net row mixes address families")
        queue_parts = fields[4].split(":")
        try:
            if len(queue_parts) != 2:
                raise ValueError
            for part in queue_parts:
                int(part, 16)
        except ValueError:
            raise ValueError("malformed /proc net queue") from None
        state = fields[3].upper()
        if len(state) != 2 or any(character not in "0123456789ABCDEF" for character in state):
            raise ValueError("malformed /proc net socket state")
        sockets.append({"inode": fields[9], "family": family, "local_address": local_address,
                        "local_port": local_port, "peer_address": peer_address, "peer_port": peer_port,
                        "state": state})
    return sockets


def parse_fd_links(links):
    """The socket inode set referenced by the readlink values of one /proc/<pid>/fd."""
    inodes = set()
    for link in links:
        if isinstance(link, bytes):
            link = link.decode(errors="surrogateescape")
        if not isinstance(link, str):
            raise ValueError("/proc fd link must be text")
        if link.startswith("socket:"):
            inode = link[len("socket:["):-1] if link.startswith("socket:[") and link.endswith("]") else ""
            if not inode.isdigit():
                raise ValueError("malformed socket link in /proc/<pid>/fd")
            inodes.add(inode)
    return inodes


def client_address(address):
    """Canonical validated client address; an IPv4-mapped IPv6 peer is reported as IPv4."""
    value = ipaddress.ip_address(address)
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped is not None:
        value = value.ipv4_mapped
    return str(value)


def pg_endpoint_sockets(fd_links, tcp_tables, pg_endpoint):
    """Endpoint identities of the service PID's own ESTABLISHED sockets to the configured database.

    Returns a sorted list of ``(family, remote_address, remote_port)`` with exact
    multiplicity: only socket inodes referenced by the process's own fd links are
    considered, only ESTABLISHED rows whose remote port is the client-configured
    DSN port and whose remote address is one of the resolved endpoint addresses.
    Local address/port are never used, so a rewritten NAT client address/port
    cannot drop an owned socket.
    """
    addresses, dsn_port = validate_pg_endpoint(pg_endpoint)
    targets = set(addresses)
    owned = parse_fd_links(fd_links)
    if not owned:
        return []
    entries = [entry for entries in tcp_tables.values() for entry in entries]
    sockets = []
    for entry in entries:
        if entry["inode"] not in owned or entry["state"] != CONNECTION_ESTABLISHED:
            continue
        # Match the client-configured DSN destination port (host/NAT may differ from the server's listen port).
        if entry["peer_port"] == dsn_port and entry["peer_address"] in targets:
            sockets.append((entry["family"], entry["peer_address"], int(entry["peer_port"])))
    # Multiplicity is kept: every owned ESTABLISHED endpoint socket must be
    # accounted for by exactly one named server-side session.
    return sorted(sockets)


def resolve_pg_endpoint(db_url, resolver=None):
    """Resolve the configured database's host to mapped IPv4/IPv6 addresses and port.

    The hostname is resolved exactly once through ``socket.getaddrinfo`` (no
    second lookup inside ``psql``) and every result must be a supported IPv4 or
    IPv6 TCP endpoint; anything else fails closed with an address-free message."""
    need(isinstance(db_url, str) and db_url, "the database URL is missing")
    parts = urllib.parse.urlsplit(db_url)
    if parts.scheme not in ("postgres", "postgresql"):
        raise ScanFailure("the database URL is not PostgreSQL")
    host = parts.hostname
    if not host:
        raise ScanFailure("the database URL has no TCP host; /proc ownership needs a supported TCP endpoint")
    port = parts.port or 5432
    if not 0 < port < 65536:
        raise ScanFailure("the database URL has an invalid port")
    resolver = resolver or socket.getaddrinfo
    try:
        results = resolver(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception as error:
        # Never echo the host or resolver text; only the error family is reported.
        raise ScanFailure("the configured database host does not resolve: " + type(error).__name__) from None
    addresses = set()
    for result in results or ():
        if not isinstance(result, tuple) or len(result) < 5:
            raise ScanFailure("the database resolver returned no usable endpoint")
        family, socktype, proto, _, sockaddr = result[:5]
        if socktype != socket.SOCK_STREAM or proto not in (0, socket.IPPROTO_TCP):
            raise ScanFailure("the configured database endpoint is not a TCP stream endpoint")
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ScanFailure("the configured database endpoint is not a supported IPv4/IPv6 TCP endpoint")
        if not isinstance(sockaddr, tuple) or len(sockaddr) < 2 or sockaddr[1] != port:
            raise ScanFailure("the resolved database port differs from the configured port")
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except (TypeError, ValueError):
            raise ScanFailure("the configured database endpoint is not an IP address") from None
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        addresses.add(str(address))
    if not addresses:
        raise ScanFailure("the configured database host resolved to no supported endpoint")
    return sorted(addresses), port


def validate_pg_endpoint(endpoint):
    """The configured database endpoint as (sorted address list, client-configured DSN port).

    ``port`` is the client-configured destination port from the DSN (the peer
    port of every owned /proc socket); it may differ from the PostgreSQL
    server's internal listen port behind a Docker host/NAT port mapping.
    """
    need(isinstance(endpoint, tuple) and len(endpoint) == 2, "the database endpoint is malformed")
    addresses, port = endpoint
    need(isinstance(addresses, (list, tuple, set)) and addresses, "the configured database has no resolved address")
    # Canonical text form so configured and /proc-decoded peers always compare exactly;
    # an IPv4-mapped configured address compares as its IPv4 form.
    mapped = sorted({client_address(address) for address in addresses})
    need(isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536,
         "the client-configured database DSN port is unknown")
    return mapped, port


def count_consistency(owned, named):
    """The service PID's endpoint socket count versus the named current-database sessions.

    Both sides are validated and the sample fails closed when the named count is
    zero or differs from the owned socket count: a mismatch means an owned
    socket has no server-side session of the declared identity (or the reverse),
    so neither side alone can claim ownership.
    """
    for name, value in (("owned service endpoint sockets", owned), ("named service sessions", named)):
        need(isinstance(value, int) and not isinstance(value, bool) and value >= 0, name + " count is invalid")
    need(named > 0, "the service owns no named PostgreSQL session in the current database")
    need(named == owned, "named service sessions (" + str(named) + ") differ from the service PID's owned "
                         "database endpoint sockets (" + str(owned) + ")")
    return owned


def sample_row(sessions, active, idle, lock):
    """One validated point sample of service-owned PostgreSQL sessions."""
    for name, value in (("sessions", sessions), ("active", active), ("idle", idle), ("lock", lock)):
        need(isinstance(value, int) and not isinstance(value, bool) and value >= 0, "sample count is invalid: " + name)
    need(active + idle <= sessions, "active+idle exceeds sampled sessions")
    need(lock <= sessions, "lock waiters exceed sampled sessions")
    return {"sessions": sessions, "active": active, "idle": idle, "lock": lock}


def parse_session_count(row):
    """The named current-database session count of one ``PG_STAT_QUERY`` row.

    The row must carry exactly four non-negative integer fields (the query
    never returns NULL: ``count(*)`` and its FILTERs are 0 for an empty grid).
    Anything else fails closed with a fixed message that never echoes the row.
    """
    need(isinstance(row, str), "the session check row must carry four non-negative integers")
    text = row.strip()
    values = text.split("|")
    need(len(values) == 4 and all(_decimal(part.strip()) for part in values),
         "the session check row must carry four non-negative integers")
    return int(values[0].strip())


def require_no_service_sessions(harness):
    """Fail closed unless no serve-blob session exists before a service start.

    Calls the fixed literal ``PG_STAT_QUERY`` through the harness's isolated
    helper and requires the sessions column to be zero. The error is fixed
    text: no row content is echoed.
    """
    row = harness.sql(PG_STAT_QUERY)
    sessions = parse_session_count(row)
    need(sessions == 0, "service sessions already exist before a service start: " + str(sessions))
    return sessions


def summarize_samples(samples, *, scans_without_connection, interval=SAMPLE_INTERVAL_SECONDS):
    """Per-process observed lower bounds; samples are never differenced across processes."""
    need(isinstance(samples, list) and samples, "no owned service PostgreSQL sessions were sampled")
    need(isinstance(scans_without_connection, int) and scans_without_connection >= 0,
         "scans without connection must be a non-negative count")
    need(_number(interval) and interval >= SAMPLE_INTERVAL_SECONDS, "sampling interval is not bounded")
    for value in samples:
        sample_row(value["sessions"], value["active"], value["idle"], value["lock"])
    with_sessions = [value for value in samples if value["sessions"]]
    need(with_sessions, "no owned service PostgreSQL sessions were sampled")
    return {
        "samples": len(samples),
        "samples_with_connection": len(with_sessions),
        "scans_without_connection": scans_without_connection,
        "sessions_nonzero_samples": len(with_sessions),
        "peak_sessions": max(value["sessions"] for value in samples),
        "peak_active": max(value["active"] for value in samples),
        "peak_idle": max(value["idle"] for value in samples),
        "peak_lock_waiters": max(value["lock"] for value in samples),
        "observed_lower_bound": True,
        "exact_lock_wait_ms": None,
        "interval_seconds": interval,
        "errors": [],
        "matched_by": "two-layer ownership: PID-owned sockets (service /proc/<pid>/fd inodes joined with "
                      "/proc/<pid>/net/tcp{,6}, ESTABLISHED only) whose remote address and DSN port hit the "
                      "configured database endpoint are filtered and counted only; pg_stat_activity rows in the "
                      "current database are identified by the source-defined application_name IN "
                      "('rootyard', 'rootyard-blob-barrier'), and every sample requires that named count to "
                      "equal the PID's endpoint socket count (nonzero); local socket address:port is never "
                      "compared with client_addr/client_port, which NAT rewrites",
        "sql_helper": "BlobOnlyHarness.sql against the dedicated baseline database in the harness isolated "
                      "random schema (no pooler, no shared database)",
        "note": "observed lower bounds; waits shorter than one sampling interval can be missed; "
                "no exact lock-wait milliseconds are derived",
    }


class ScanFailure(BaselineError):
    """A /proc ownership scan could not be completed; fail the run, never skip it."""


class PgPortIndex:
    """Count the service process's own ESTABLISHED sockets to the configured database endpoint.

    This side is a kernel ownership filter and count only: a socket counts only
    if its inode is held by the sampled process and its peer is the configured
    database endpoint. It never claims which server session a socket became;
    that is established on the server side by application_name and cross-checked
    by count equality.
    """

    def __init__(self, pid, pg_endpoint, *, proc=Path("/proc")):
        need(isinstance(pid, int) and not isinstance(pid, bool) and pid > 0, "service pid must be positive")
        self.pg_endpoint = validate_pg_endpoint(pg_endpoint)
        self.pid = pid
        self.proc = Path(proc)
        self.tcp, self.fd_links, self.sockets = self._scan()

    def _tables(self):
        tables = {}
        for name in ("tcp", "tcp6"):
            path = self.proc / str(self.pid) / "net" / name
            try:
                tables[name] = parse_proc_net_tcp(path.read_text())
            except (OSError, ValueError) as error:
                raise ScanFailure("cannot read " + name + " of the service process: " + str(error)) from None
        return tables

    def _fd_links(self):
        directory = self.proc / str(self.pid) / "fd"
        try:
            entries = list(directory.iterdir())
        except OSError as error:
            raise ScanFailure("cannot list service file descriptors: " + str(error)) from None
        links = []
        for entry in entries:
            try:
                links.append(os.readlink(entry))
            except FileNotFoundError:
                continue
            except OSError as error:
                raise ScanFailure("cannot read a service file descriptor: " + str(error)) from None
        return links

    def _scan(self):
        tables, links = self._tables(), self._fd_links()
        try:
            sockets = pg_endpoint_sockets(links, tables, self.pg_endpoint)
        except ValueError as error:
            raise ScanFailure("service socket scan is malformed: " + str(error)) from None
        return tables, links, sockets

    @property
    def count(self):
        """Number of the process's own ESTABLISHED sockets to the configured database endpoint."""
        return len(self.sockets)

    def rescan(self):
        self.tcp, self.fd_links, self.sockets = self._scan()
        return self.count


class PgSampler:
    """Bounded-interval sampler of sessions owned by exactly one service process."""

    def __init__(self, helper, pid, pg_endpoint, *, interval=SAMPLE_INTERVAL_SECONDS, proc=Path("/proc")):
        need(_number(interval) and interval >= SAMPLE_INTERVAL_SECONDS, "sampling interval must stay bounded at >= 250 ms")
        self.helper = helper
        self.pid = pid
        self.interval = float(interval)
        self.scanner = PgPortIndex(pid, pg_endpoint, proc=proc)
        self.samples, self.errors, self.scans_without_connection = [], [], 0
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = None
        self._failing = False

    def query(self):
        """Count current-database sessions carrying a serve-blob application_name (fixed literal SQL)."""
        return self.helper.sql(PG_STAT_QUERY)

    def scan_once(self):
        """One sample. Scan or SQL errors are recorded and raised: they are never skipped."""
        if self._failing:
            raise BaselineError("PostgreSQL sampler already failed: " + self.errors[0])
        try:
            owned = self.scanner.rescan()
            if not owned:
                self.scans_without_connection += 1
                return None
            values = self.query().split("|")
            need(len(values) == 4 and all(part.strip().isdigit() for part in values),
                 "sampled row has the wrong shape")
            sessions, active, idle, lock = [int(part) for part in values]
            # Cross-check kernel ownership against the server-side identity: the
            # named current-database session count must equal, and be nonzero.
            count_consistency(owned, sessions)
            sample = sample_row(sessions, active, idle, lock)
        except BaselineError as error:
            message = self.helper.redact(str(error))
            self._failing = True
            self.errors.append(message)
            raise BaselineError(message) from None
        except Exception as error:
            message = self.helper.redact(type(error).__name__ + ": " + str(error))
            self._failing = True
            self.errors.append(message)
            raise BaselineError("PostgreSQL ownership sampling failed: " + message) from None
        with self._lock:
            self.samples.append(sample)
        return sample

    def _run(self):
        while not self._stop.is_set():
            begin = time.monotonic()
            try:
                self.scan_once()
            except BaselineError:
                return
            self._stop.wait(max(0.0, self.interval - (time.monotonic() - begin)))

    def start(self, timeout=STARTUP_SAMPLE_TIMEOUT_SECONDS):
        """Take a first owned sample, waiting <= timeout for the service pool to connect."""
        deadline = time.monotonic() + timeout
        while True:
            first = self.scan_once()
            if first is not None and first["sessions"] > 0:
                break
            need(time.monotonic() < deadline,
                 "the service owns no live PostgreSQL session at the start of a case")
            time.sleep(self.interval)
        self._thread = threading.Thread(target=self._run, name="pg-ownership-sampler", daemon=True)
        self._thread.start()

    def finish(self):
        """Stop sampling and summarize; a boundary scan with no owned session fails the run."""
        if self._thread is not None:
            self._stop.set()
            self._thread.join(10)
            need(not self._thread.is_alive(), "PostgreSQL sampler did not stop")
        last = self.scan_once()
        need(last is not None, "no service-owned PostgreSQL session at the end of the case")
        return summarize_samples(self.samples, scans_without_connection=self.scans_without_connection,
                                 interval=self.interval)


# --- case execution -------------------------------------------------------------
def verify_worktree(harness, destination, oid, files, fmt="sha1"):
    """Verify an already-cloned working tree; never clones again.

    Checks HEAD, object format, exact file bytes and ``git fsck --full --strict``
    in place. Returns the measured local verification wall time separately so a
    read's reported duration stays the network operation alone.
    """
    begin = time.monotonic()
    need(destination.is_dir() and (destination / ".git").exists(), "clone destination is not a working tree")
    actual_format = harness.object_format(destination)
    need(actual_format == fmt, "cloned object format differs from the pushed format")
    head = harness.git("rev-parse", "HEAD", cwd=destination).stdout.decode().strip()
    need(head == oid, "cloned HEAD differs from the expected OID")
    for name, expected in files.items():
        expected = expected.encode() if isinstance(expected, str) else expected
        need((destination / name).read_bytes() == expected, "cloned content differs: " + name)
    harness.git("fsck", "--full", "--strict", cwd=destination)
    return {"head_oid": head, "files_verified": True, "fsck": True,
            "verification_seconds": round(time.monotonic() - begin, 6)}


def clone_once(harness, remote, destination, token, *, clock=time.monotonic):
    """Run exactly one ``git clone``; return its destination, start, end and duration.

    Nothing else happens inside the timed call, so ``seconds`` is clone-only.
    On failure the clone still returns its timing (the aggregate window closes
    on every call), and the error is carried to the caller to raise later.
    """
    start = clock()
    try:
        harness.clone(remote, destination, token)
        error = None
    except BaseException as caught:
        error = caught
    end = clock()
    seconds = end - start
    need(seconds >= 0, "clone timing went backwards")
    return {"destination": Path(destination), "start": start, "end": end,
            "seconds": round(seconds, 6), "error": error}


def read_record(clone, oid, kind, label, checked=None, **labels):
    """One clone's report record, plus its (post-window) verification when available."""
    record = {"label": label, "kind": kind, "destination": clone["destination"].name,
              "seconds": clone["seconds"], "expected_oid": oid,
              "timed_scope": "git clone over HTTP only; OID/file/fsck checks happen after the timer stops",
              **labels}
    if checked is not None:
        record.update({"head_oid": checked["head_oid"], "files_verified": checked["files_verified"],
                       "fsck": checked["fsck"], "verification_seconds": checked["verification_seconds"]})
    return record


def measured_clone(harness, remote, destination, oid, files, token, kind, label, *, clock=time.monotonic,
                   **labels):
    """One timed clone followed by in-place verification (sequential reads)."""
    clone = clone_once(harness, remote, destination, token, clock=clock)
    if clone["error"] is not None:
        raise clone["error"]
    checked = verify_worktree(harness, clone["destination"], oid, files)
    return read_record(clone, oid, kind, label, checked, **labels)


def run_push(harness, remote, work, files):
    """One Smart HTTP push; the push and the ls-remote confirmation are timed apart."""
    oid = harness.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    begin = time.monotonic()
    pushed = harness.git("push", "--porcelain", "origin", "HEAD:" + PUSH_REF, cwd=work, token=harness.alice, check=False)
    push_seconds = time.monotonic() - begin
    if pushed.returncode != 0:
        # Failure diagnostics only for a failed push: later parsing assumes stdout text.
        raise BaselineError("git push failed: " + json.dumps(serving.git_failure(pushed)))
    confirm = time.monotonic()
    remote_oid = harness.remote_refs(remote, harness.alice).get(PUSH_REF)
    confirm_seconds = time.monotonic() - confirm
    raw = {"returncode": pushed.returncode, "stdout": pushed.stdout.decode(errors="replace"),
           "oid": oid, "expected_oid": oid, "remote_oid": remote_oid, "push_wall_seconds": push_seconds}
    validate_push_result(raw)
    result = validate_push_summary(raw)
    # Keep the raw evidence alongside the summary so the report re-checks the push.
    return {**raw, **result, "ls_remote_seconds": round(confirm_seconds, 6),
            "payload_bytes": sum(len(data) for data in files.values())}


def run_read_worker(harness, index, seed, clock=time.monotonic):
    """Phase 1 of a concurrent read: exactly one timed ``git clone``, nothing else."""
    return clone_once(harness, seed["remote"], harness.root / ("concurrent-worker-" + str(index + 1)),
                      harness.reader, clock=clock)


def run_concurrent_reads(harness, seed):
    """Two concurrent clones in two phases: (records, clone-only aggregate, report).

    Phase 1 runs one timed ``git clone`` per worker and nothing else; phase 2
    starts only after every clone call has returned, and verifies each cloned
    worktree on this thread (HEAD, content, object format, ``git fsck``). The
    aggregate is ``max(clone end) - min(clone start)``, i.e. from the first
    clone call start to the last clone call return, so no local verification can
    extend it. A failed clone lets the other clone calls settle and is then
    raised as one clear batch failure; nothing verifies or is measured then.
    """
    clock = getattr(harness, "clone_clock", None) or time.monotonic
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(run_read_worker, harness, index, seed, clock) for index in range(CONCURRENCY)]
        clones = [future.result() for future in futures]  # every clone call has settled here
    need(all(future.done() for future in futures), "a clone call has not settled")
    failures = [(index + 1, clone["error"]) for index, clone in enumerate(clones) if clone["error"] is not None]
    if failures:
        first = failures[0][1]
        names = ", ".join(str(index) for index, _ in failures)
        raise BaselineError("concurrent read batch failed (worker " + names + "): "
                            + type(first).__name__ + ": " + harness.redact(str(first))) from None
    aggregate_seconds = max(0.0, max(clone["end"] for clone in clones) - min(clone["start"] for clone in clones))
    records = []
    for index, clone in enumerate(clones):
        checked = verify_worktree(harness, clone["destination"], seed["oid"], seed["files"])
        records.append(read_record(clone, seed["oid"], "read_clone", "worker-" + str(index + 1), checked,
                                   repository=REPOSITORY_NAME))
    return records, aggregate_seconds, aggregate_wall(records, aggregate_seconds, seed["oid"])


def empty_scratch(harness):
    """Empty and recreate this fixture's own service-local scratch root."""
    need(harness.scratch.is_dir() and not harness.scratch.is_symlink(), "service-local scratch root is missing")
    need(harness.scratch.parent.resolve() == harness.root.resolve(), "scratch root escaped its owned fixture")
    shutil.rmtree(harness.scratch)
    harness.scratch.mkdir(mode=0o700)
    return scratch_empty(harness)


def scratch_empty(harness):
    need(harness.scratch.is_dir() and next(harness.scratch.iterdir(), None) is None,
         "service-local scratch root is not empty")
    return True


def run_cold_clone(harness, seed, *, restarted):
    """Empty the service-local scratch view, then one cold clone of the seed repository."""
    need(restarted, "cold clone requires a restarted service")
    empty_scratch(harness)
    record = measured_clone(harness, seed["remote"], harness.root / "cold-clone", seed["oid"], seed["files"],
                            harness.reader, "cold_clone", label="cold_clone")
    # Immediately after the clone timer (and before local verification): any
    # service scratch materialization would still be visible here.
    empty_after = scratch_empty(harness)
    return validate_cold({"seconds": record["seconds"], "service_restarted": True, "scratch_empty_before": True,
                          "scratch_empty_after": empty_after, "head_oid": record["head_oid"],
                          "expected_oid": seed["oid"], "files_verified": True, "fsck": True,
                          "verification_seconds": None})


# --- environment facts ----------------------------------------------------------
def runtime_facts(harness, profile, *, cpuinfo=None, meminfo=None, cgroup_root=None, procfs=None):
    """Bind the report to the real environment; missing facts fail the run.

    ``cpuinfo``, ``meminfo``, ``cgroup_root`` and ``procfs`` default to this
    host's files and exist only so tests can inject fixtures; the reported
    fields are plain values.
    """
    memory = None
    meminfo = Path("/proc/meminfo").read_text() if meminfo is None else meminfo
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            memory = int(line.split()[1])
            break
    machine = platform.machine()
    return validate_runtime({
        "git_version": harness.run([str(profile.git), "--version"]).stdout.decode().strip(),
        "psql_version": harness.run(["psql", "--version"]).stdout.decode().strip(),
        "postgres_server_version": harness.sql("SHOW server_version"),
        "python": platform.python_version(),
        "kernel": platform.release(),
        "machine": machine,
        "architecture": machine,
        "cpu_model": cpu_model(Path("/proc/cpuinfo").read_text(errors="replace") if cpuinfo is None else cpuinfo,
                               machine),
        "logical_cpus": os.cpu_count(),
        "host_memory_total_kb": memory,
        "cgroup": read_cgroup_view(cgroup_root),
        "procfs": (Path("/proc/self/fd").is_dir() and Path("/proc/net/tcp").is_file())
                  if procfs is None else procfs,
        "hostname": harness.run(["hostname"]).stdout.decode().strip(),
    })


def pg_endpoint(harness):
    """Resolve the configured database endpoint once; its value never enters a report.

    The returned port is the client-configured destination (the DSN port the
    harness connects to), not the PostgreSQL server's internal listen port. A
    Docker published port such as host 127.0.0.1:55433 -> container :5432 is a
    legitimate host/NAT mapping, so it is never compared with
    ``current_setting('port')``; the strict DSN host/TCP/port/address checks in
    ``resolve_pg_endpoint`` and ``validate_pg_endpoint`` still apply.
    """
    return validate_pg_endpoint(resolve_pg_endpoint(harness.db))


def binding_record(profile):
    """Attested build/source receipt plus every qualifying input hash."""
    inputs = fixture_input_hashes()
    need(inputs["tests/blob_only_service.py"] == profile.harness_sha256,
         "harness source changed after attestation")
    need(profile.source_digest() == profile.build["source_inputs_sha256"],
         "production source no longer matches the receipt")
    need(sha256_file(profile.binary) == profile.build["binary_sha256"], "binary changed after attestation")
    need(sha256_file(profile.git) == profile.git_sha256, "trusted Git changed after attestation")
    need(profile.working_tree_clean, "a baseline run requires a clean candidate tree")
    return {
        "attested": True, "inputs_unchanged": True,
        "binary_sha256": profile.build["binary_sha256"],
        "source_inputs_sha256": profile.build["source_inputs_sha256"],
        "workspace_commit": profile.build["workspace_commit"],
        "rustc": profile.build["rustc"], "build_receipt_sha256": profile.receipt_sha256,
        "runner_sha256": inputs["runner"], "harness_sha256": profile.harness_sha256,
        "trusted_git_sha256": profile.git_sha256, "inputs": inputs,
    }


def fixture_input_hashes(root=ROOT):
    """sha256 of every harness/tool source qualifying the run, plus this runner."""
    paths = dict((name, Path(root) / name) for name in INPUT_FILES)
    hashes = {name: sha256_file(path) for name, path in paths.items()}
    hashes["runner"] = sha256_file(Path(__file__).resolve())
    return hashes


# --- service admission (configured, never overridden) ---------------------------
MAX_CONCURRENT_GIT_SETTING = ("ROOTYARD_MAX_CONCURRENT_GIT", 8, 1, 256)
MAX_REQUEST_BYTES_SETTING = ("ROOTYARD_MAX_REQUEST_BYTES", 128 << 20, 64 << 10, 4 << 30)
MAX_INFLIGHT_BYTES_SETTING = ("ROOTYARD_MAX_INFLIGHT_BYTES", 256 << 20, 64 << 10, 16 << 30)
DEFAULT_SOURCE = "src/standalone/config.rs default"
OVERRIDE_SOURCE = "environment_override"
UPLOAD_PACK_RESERVATION_SOURCE = ("one full ROOTYARD_MAX_REQUEST_BYTES admission lease per upload-pack body "
                                 "before spooling (src/blob_git_gateway/smart_http.rs)")
# Why the admission capacity is a derived configuration fact, not a measurement.
ADMISSION_SCOPE = ("configured admission only: the values are read, never overridden or widened; this is neither "
                   "a measured throughput nor a frozen performance budget")

_ASCII_DECIMAL = re.compile(r"[0-9]+")


def _admission_number(env, setting):
    """One configured admission number and its source; invalid values are never echoed."""
    name, default, low, high = setting
    if not isinstance(env, dict):
        raise BaselineError("service admission environment is missing")
    if name not in env:
        return default, DEFAULT_SOURCE
    raw = env[name]
    need(isinstance(raw, str) and _ASCII_DECIMAL.fullmatch(raw) is not None,
         name + " must be an ASCII decimal integer")
    value = int(raw)
    need(low <= value <= high, name + " is outside its supported range")
    return value, OVERRIDE_SOURCE


def service_admission_facts(env):
    """Effective admission settings of the configured service plus the derived clone capacity.

    Only ``ROOTYARD_MAX_CONCURRENT_GIT``, ``ROOTYARD_MAX_REQUEST_BYTES`` and
    ``ROOTYARD_MAX_INFLIGHT_BYTES`` are read, with the defaults and ranges of the
    current ``src/standalone/config.rs``; ``env`` is never written or overridden.
    Each upload-pack body reserves one full ``max_request_bytes`` admission lease
    before it is spooled, so the number of concurrent clones the configured
    admission covers is bounded by both the concurrent-Git limit and the
    inflight byte budget. Fails closed unless that capacity covers
    ``CONCURRENCY``. This describes configured admission, never measured
    throughput or a frozen budget.
    """
    max_git, git_source = _admission_number(env, MAX_CONCURRENT_GIT_SETTING)
    request, request_source = _admission_number(env, MAX_REQUEST_BYTES_SETTING)
    inflight, inflight_source = _admission_number(env, MAX_INFLIGHT_BYTES_SETTING)
    need(inflight >= request, "ROOTYARD_MAX_INFLIGHT_BYTES must be at least ROOTYARD_MAX_REQUEST_BYTES")
    byte_capacity = inflight // request
    effective = min(max_git, byte_capacity)
    need(effective >= CONCURRENCY,
         "configured service admission covers fewer than " + str(CONCURRENCY) + " concurrent upload-pack bodies")
    return validate_service_admission({
        "settings": {
            "max_concurrent_git": {"value": max_git, "source": git_source, "range": [1, 256]},
            "max_request_bytes": {"value": request, "source": request_source, "range": [64 << 10, 4 << 30]},
            "max_inflight_bytes": {"value": inflight, "source": inflight_source, "range": [64 << 10, 16 << 30]},
        },
        "upload_pack_reservation_bytes": request,
        "upload_pack_reservation_source": UPLOAD_PACK_RESERVATION_SOURCE,
        "byte_budget_capacity": byte_capacity,
        "effective_upload_pack_capacity": effective,
        "capacity_covers_measured_concurrency": True,
        "measured_clone_concurrency": CONCURRENCY,
        "scope": ADMISSION_SCOPE,
        "explanation": "smart_http reserves max_request_bytes per upload-pack body before spooling it; "
                       "byte_budget_capacity = max_inflight_bytes // max_request_bytes and effective capacity "
                       "= min(max_concurrent_git, byte_budget_capacity); measured concurrency must fit",
    })


def validate_service_admission(admission):
    """Re-check admission facts (recomputing the derived capacity) before they enter a report."""
    need(isinstance(admission, dict), "service admission facts are missing")
    settings = admission.get("settings")
    need(isinstance(settings, dict), "service admission settings are missing")
    values = {}
    for key, setting in (("max_concurrent_git", MAX_CONCURRENT_GIT_SETTING),
                         ("max_request_bytes", MAX_REQUEST_BYTES_SETTING),
                         ("max_inflight_bytes", MAX_INFLIGHT_BYTES_SETTING)):
        entry = settings.get(key)
        need(isinstance(entry, dict), "service admission setting is missing: " + key)
        value, source = entry.get("value"), entry.get("source")
        need(isinstance(value, int) and not isinstance(value, bool)
             and (source == DEFAULT_SOURCE and value == setting[1] or
                  source == OVERRIDE_SOURCE and setting[2] <= value <= setting[3]),
             "service admission setting is invalid: " + key)
        need(entry.get("range") == [setting[2], setting[3]], "service admission range changed: " + key)
        values[key] = value
    need(values["max_inflight_bytes"] >= values["max_request_bytes"],
         "ROOTYARD_MAX_INFLIGHT_BYTES must be at least ROOTYARD_MAX_REQUEST_BYTES")
    byte_capacity = values["max_inflight_bytes"] // values["max_request_bytes"]
    effective = min(values["max_concurrent_git"], byte_capacity)
    need(effective >= CONCURRENCY,
         "configured service admission covers fewer than " + str(CONCURRENCY) + " concurrent upload-pack bodies")
    need(admission.get("upload_pack_reservation_bytes") == values["max_request_bytes"],
         "upload-pack reservation does not equal max_request_bytes")
    need(admission.get("upload_pack_reservation_source") == UPLOAD_PACK_RESERVATION_SOURCE,
         "upload-pack reservation source is missing")
    need(admission.get("byte_budget_capacity") == byte_capacity, "byte-budget capacity was not derived")
    need(admission.get("effective_upload_pack_capacity") == effective, "effective capacity was not derived")
    need(admission.get("measured_clone_concurrency") == CONCURRENCY, "measured clone concurrency changed")
    need(admission.get("capacity_covers_measured_concurrency") is True,
         "configured capacity does not cover the measured clone concurrency")
    need(admission.get("scope") == ADMISSION_SCOPE, "service admission scope changed")
    need(isinstance(admission.get("explanation"), str) and "before spooling" in admission["explanation"],
         "service admission explanation is missing")
    return json.loads(json.dumps(admission))


def sensitive_values(env):
    """Values a report must never contain: credentials and connection/endpoint material."""
    values = [value for name, value in env.items() if value and SENSITIVE_PATTERN.search(name)]
    values.extend(serving.sensitive_values(env))
    return sorted({value for value in values if isinstance(value, str)})


# --- report assembly ------------------------------------------------------------
UNMEASURED = {
    "opendal_get_bytes": None, "opendal_get_phase_ms": None, "exact_lock_wait_ms": None,
    "provider_cache_state": None, "throughput": None,
    "opendal_reason": "the current serve-blob process exposes no OpenDAL GET byte/phase counters to this runner",
    "provider_cache_reason": "no provider or service counter distinguishes cache hits; object-store cache state is unknown",
}


def report_payload(*, binding, blob_profile, runtime, workload, cases, setup, seeding, concurrent, cold,
                   service_admission):
    """Assemble the redaction-safe baseline report from measured pieces only."""
    validate_binding(binding)
    facts = validate_workload(workload)
    admission = validate_service_admission(service_admission)
    epochs = [case.get("service_epoch") for case in cases]
    validated = validate_cases(cases, epochs)
    cold_record = validate_cold(cold)
    seed_push = validate_push_summary(seeding["push"])
    for case in validated:
        if case["name"] == "seed_push":
            await_push = validate_push_summary(case["detail"]["push"])
            need(await_push == seed_push, "the seed push case and the reported push disagree")
    need(cold_record["expected_oid"] == seed_push["oid"], "cold clone read a different repository state")
    need(concurrent["worker_oid"] == seed_push["oid"], "concurrent reads did not clone the seed OID")
    concurrent_record = aggregate_wall(concurrent["workers"], concurrent["aggregate_seconds"], seed_push["oid"])
    concurrent_record.update({"expected_oid": seed_push["oid"], "repositories": list(WORKER_REPOSITORIES),
                              "identical_commit_oid_by_construction": True, "read_only_token": True})
    setup_record = validate_setup(setup)
    provision = validated[0]["detail"]
    return {
        "kind": KIND, "report_version": REPORT_VERSION, "status": "passed",
        "source_head": binding["workspace_commit"],
        "source_inputs_sha256": binding["source_inputs_sha256"],
        "binary_sha256": binding["binary_sha256"],
        "harness_sha256": binding["harness_sha256"],
        "git_sha256": binding["trusted_git_sha256"],
        "runner_sha256": binding["runner_sha256"],
        "issue": {"number": 106, "claim": "baseline_entry_only", "issue_complete": False, "budgets_frozen": False,
                  "statement": "Native Blob-only baseline entry; it neither marks #106 complete nor freezes budgets."},
        "measured_profile": MEASURED_PROFILE,
        "prior_baseline_used": False, "legacy_pando_profile_used": False,
        "qualification_kind": "clean-candidate",
        "measurement_kind": "native_execution", "simulated_fields": False,
        "transport": {"server": "rootyard serve-blob", "service_argv": ["serve-blob"],
                      "git_client": "stock Git Smart HTTP", "scheme": "http", "origin": "fixture loopback",
                      "ssh_exercised": False},
        "native_profile": {key: value for key, value in binding.items() if key != "inputs"},
        "input_sha256": dict(binding["inputs"]),
        "blob_profile": dict(blob_profile),
        "runtime": validate_runtime(runtime),
        "setup": setup_record,
        "workload": {
            "version": WORKLOAD_VERSION, "mode": workload["mode"], "concurrency": workload["concurrency"],
            "repositories_provisioned_via": workload["repositories_provisioned_via"],
            "seed_repository": REPOSITORY_NAME, "read_repositories": list(WORKER_REPOSITORIES),
            "provision": {"status": provision.get("provision_status"), "storage_backend": provision.get("storage_backend"),
                          "object_format": provision.get("object_format")},
            "files": facts["files"], "total_bytes": facts["total_bytes"], "payload_bound_bytes": MAX_PAYLOAD_BYTES,
            "fingerprint_sha256": workload["fingerprint_sha256"],
        },
        "seed_push": {**seed_push, "object_format": seeding.get("object_format")},
        "cases": [{"name": case["name"], "status": case["status"], "seconds": case["seconds"],
                   "service_epoch": case["service_epoch"], "sampled": case["name"] != "restart",
                   "pg_samples": case.get("pg_samples")} for case in validated],
        "concurrent": concurrent_record,
        "service_admission": admission,
        "cold_clone": cold_record,
        "cache_semantics": {"cold": COLD_SEMANTICS, "cold_scope": "process_local_materialized_view_only",
                            "provider_cache_state": "unknown", "provider_cache_observed": False,
                            "scratch_empty_before_read": True, "scratch_empty_after_read": True},
        "pg_ownership_samples": {
            "ownership_layers": {
                "process_sockets": "kernel ownership: ESTABLISHED sockets of socket inodes held by the service "
                                   "PID (/proc/<pid>/fd) in its own /proc/<pid>/net/tcp{,6} whose remote "
                                   "address and DSN-configured port are the resolved database endpoint; used "
                                   "only to filter and count the configured database endpoint",
                "server_sessions": "server identity: pg_stat_activity rows of the current test database with "
                                   "application_name IN ('rootyard', 'rootyard-blob-barrier'), the application "
                                   "pool and lifecycle barrier names set by the current Rust sources; runner "
                                   "and psql helper connections are not counted; scope: dedicated baseline "
                                   "database + harness isolated random schema, no pooler/shared database",
                "cross_check": "each sample requires the named session count to be nonzero and exactly equal "
                               "to the PID's ESTABLISHED endpoint socket count; client_addr/client_port are "
                               "never compared with local socket address:port because NAT or a published "
                               "port rewrites them; additional same-name sessions break the equality and are "
                               "rejected (count only, never a per-socket four-tuple or PID mapping)",
            },
            "procedure": "two-layer ownership per sample: filter/count the service PID's own ESTABLISHED sockets "
                         "to the configured database endpoint from /proc/<pid>/fd and /proc/<pid>/net/tcp{,6}, "
                         "then count current-database pg_stat_activity sessions by the source-defined "
                         "application_name names and require zero-free count equality, read through the "
                         "isolated psql helper; before the first start (after setup migrations/accounts) and "
                         "before the restart's start, the same fixed SQL must return zero named sessions",
            "scope": PG_OWNERSHIP_SCOPE,
            "sql_helper": "BlobOnlyHarness.sql (dedicated baseline database + isolated random schema; fixed literal "
                          "PG_STAT_QUERY, no pooler, no shared database)",
            "prestart_requires_zero_sessions": True,
            "per_socket_four_tuple_attribution": False,
            "pid_to_backend_mapping": False,
            "reset_per_process": True, "differenced_across_processes": False, "exact_lock_wait_ms": None,
            "per_case": True, "observed_lower_bound": True, "restart_case_sampled": False,
            "configured_database_endpoint_reported": False,
        },
        "unmeasured": dict(UNMEASURED),
        "limits": list(LIMITS), "limitations": list(LIMITS),
    }


def validate_setup(setup):
    """Fixture setup precedes provisioning; its duration is reported apart from measured cases."""
    need(isinstance(setup, dict), "setup record is missing")
    need(setup.get("ordered_before") == "provision", "setup did not precede provisioning")
    seconds = setup.get("seconds")
    need(_number(seconds) and seconds >= 0, "setup duration is invalid")
    need(setup.get("service_running_before_provision") is True, "provisioning started without a live service")
    return {"seconds": round(float(seconds), 6), "ordered_before": "provision",
            "service_running_before_provision": True, "provisioning_sampled": True,
            "scope": "schema migration, fixture accounts and serve-blob start/readiness; never a measured case"}


def run(args, profile, blob_profile):
    report = {"kind": KIND, "report_version": REPORT_VERSION, "status": "failed", "cases": [],
              "limitations": list(LIMITS)}
    harness, binding = None, None
    try:
        missing = [tool for tool in REQUIRED_TOOLS if not shutil.which(tool)]
        need(not missing, "required tool(s) missing: " + ", ".join(missing))
        files = select_workload()
        # Attest once, before any fixture exists; re-verified after the run.
        binding = binding_record(profile)
        harness = serving.BlobOnlyHarness(args, profile, blob_profile)
        # Effective admission settings of this profile, read once and never overridden.
        admission_facts = service_admission_facts(harness.env)
        workload = {**describe_workload(files), "version": WORKLOAD_VERSION,
                    "mode": READ_MODE, "concurrency": CONCURRENCY,
                    "repositories_provisioned_via": "POST /api/repos",
                    "fingerprint_sha256": workload_fingerprint(files)}
        validate_workload(workload)
        endpoint = pg_endpoint(harness)
        epoch, cases, context = 0, [], {}
        seed = {"files": files}

        def new_sampler():
            pid = harness.proc.pid if harness.proc is not None else None
            need(pid is not None, "no running service process to sample")
            return PgSampler(harness, pid, endpoint)

        def sampled(name, action):
            """Run one case under the live process; sampling never crosses a process boundary."""
            pid = harness.proc.pid
            sampler = new_sampler()
            sampler.start()
            begin = time.monotonic()
            try:
                value = action()
            except BaseException:
                try:
                    sampler.finish()
                except BaselineError as sampling:
                    report["sampling_error"] = sampler.errors[0] if sampler.errors else str(sampling)
                raise
            samples = sampler.finish()
            need(harness.proc is not None and harness.proc.pid == pid,
                 "the service process changed inside a sampled case: " + name)
            cases.append({"name": name, "status": "passed", "seconds": round(time.monotonic() - begin, 6),
                          "service_epoch": epoch, "sampled": True, "pg_samples": samples,
                          "detail": value})
            return value

        # Setup starts serve-blob before any sampled case runs. No serve-blob session may
        # exist before the very first start, neither before setup nor after its
        # schema migration and account CLI steps (checked immediately before start).
        require_no_service_sessions(harness)
        begin = time.monotonic()
        original_start = harness.start

        def checked_start(*args, **kwargs):
            require_no_service_sessions(harness)
            return original_start(*args, **kwargs)

        harness.start = checked_start
        try:
            harness.prepare()
        finally:
            harness.start = original_start
        need(harness.proc is not None and harness.proc.poll() is None, "serve-blob is not running after setup")
        setup = {"seconds": time.monotonic() - begin, "ordered_before": "provision",
                 "service_running_before_provision": True}

        # 1. API provisioning under the live process.
        def provision():
            repo, status = harness.create(REPOSITORY_NAME, harness.alice)
            need(status in (201, 202), "POST /api/repos returned an unexpected status")
            binding_row = harness.db_repo(repo["id"]).split("|")
            need(binding_row[0] == "pg_refstore" and binding_row[2] == "sha1",
                 "repository was not provisioned as pg_refstore/sha1")
            seed["remote"] = harness.base + repo["clone_path"]
            return {"provision_status": int(status), "storage_backend": binding_row[0],
                    "object_format": binding_row[2]}

        sampled("provision", provision)

        # 2. Deterministic 256 KiB repository pushed once by real Smart HTTP.
        def seeding_case():
            work = harness.root / (REPOSITORY_NAME + "-work")
            harness.clone(seed["remote"], work, harness.alice)
            harness.configure(work)
            seed["oid"] = harness.commit_files(work, "blob baseline seed", files)
            return {"push": run_push(harness, seed["remote"], work, files),
                    "object_format": harness.object_format(work)}

        seeding = sampled("seed_push", seeding_case)

        # 3. Two concurrent read-clone destinations from the same single seed repository.
        def concurrent_batch():
            # Keep the raw worker records and the measured window: the report re-validates them.
            workers, aggregate_seconds, aggregate = run_concurrent_reads(harness, seed)
            concurrent_batch.raw = {"workers": workers, "aggregate_seconds": aggregate_seconds,
                                    "worker_oid": seed["oid"]}
            return aggregate

        concurrent_record = sampled("concurrent_read_clones", concurrent_batch)

        # 4. Restart: all old-process sampling is finished before the stop; not a sampled case.
        # The new process may only start once the stopped one left no named session.
        pid_before = harness.proc.pid
        begin = time.monotonic()
        harness.stop()
        require_no_service_sessions(harness)
        harness.start()
        restart_seconds = time.monotonic() - begin
        need(harness.proc.pid != pid_before, "restart did not create a new service process")
        epoch += 1
        cases.append({"name": "restart", "status": "passed", "seconds": round(restart_seconds, 6),
                      "service_epoch": epoch, "sampled": False, "pg_samples": None, "detail": {},
                      "from_epoch": epoch - 1,
                      "old_pid": pid_before, "new_pid": harness.proc.pid, "samples_stopped_before_stop": True,
                      "skip_reason": "infrastructure case: the service process (and therefore the only sockets "
                                     "owned sampling can attribute) is replaced; no sample is taken across the "
                                     "stop/start and the new epoch starts with cold_clone"})

        # 5. Cold clone from an empty service-local scratch view of the new process.
        cold_record = sampled("cold_clone", lambda: run_cold_clone(harness, seed, restarted=True))
        cold_record["samples_across_restart"] = False
        runtime = runtime_facts(harness, profile)
        need(binding_record(profile)["inputs"] == binding["inputs"],
             "a qualifying input changed during the run; refusing to report")
        payload = report_payload(binding=binding, blob_profile=blob_profile, runtime=runtime, workload=workload,
                                 cases=cases, setup=setup, seeding=seeding,
                                 concurrent=concurrent_batch.raw,
                                 cold=cold_record, service_admission=admission_facts)
        validate_no_secrets(payload, sensitive_values(harness.env))
        report.update(payload)
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = harness.redact(error) if harness is not None else str(error)
        report["error_type"] = type(error).__name__
        if harness is not None and not isinstance(error, (BaselineError, serving.ProfileError, AssertionError)):
            # Validation failures are expected and stay single-line; unexpected
            # failures keep a redacted trace. Raw bodies and server logs never enter it.
            report["error_traceback"] = harness.redact("".join(
                traceback.format_exception(type(error), error, error.__traceback__))[-4000:])
        print(report["error"], file=sys.stderr)
    finally:
        if harness is not None:
            try:
                harness.cleanup()
            except Exception as error:
                report["status"] = "failed"
                report["cleanup_error"] = harness.redact(error)
            report["fixture_retention"] = {
                "keep_requested": bool(args.keep),
                "retained": harness.root.exists(),
                "root": str(harness.root) if harness.root.exists() else None,
                "reason": "--keep requested" if args.keep else (
                    "failed run retained for diagnosis" if report["status"] != "passed"
                    else "passed run removes its owned temporary fixture; the random schema is always dropped"),
            }
    write_error = safe_write_report(args.report, report)
    if write_error:
        print("report: " + write_error, file=sys.stderr)
        return 2
    return 0 if report["status"] == "passed" else 1


# --- entry point ----------------------------------------------------------------
def _redact_without_fixture(text, env):
    """Remove every configured sensitive value from preflight text (no harness exists yet)."""
    for secret in sorted(sensitive_values(env), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def preflight_failed(report, message):
    print("preflight failed: " + message, file=sys.stderr)
    error = safe_write_report(report, {"kind": KIND, "report_version": REPORT_VERSION, "status": "failed",
                                       "preflight_failed": True, "error": message, "cases": [],
                                       "limitations": list(LIMITS)})
    if error:
        print("report: " + error, file=sys.stderr)
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True,
                        help="absolute attested rootyard binary with an adjacent <binary>.build.json receipt")
    parser.add_argument("--git", help="absolute trusted Git for the service and stock clients (defaults to ROOTYARD_GIT)")
    parser.add_argument("--report", required=True, type=Path, help="write the credential-free JSON report here")
    parser.add_argument("--keep", action="store_true",
                        help="retain the harness-owned fixture directory (the random PostgreSQL schema is still dropped)")
    args = parser.parse_args(argv)
    env = os.environ.copy()
    try:
        profile = serving.NativeProfile(args.binary, args.git, env)
        blob_profile = serving.check_blob_profile(env)
        need(bool(env.get("ROOTYARD_TEST_DATABASE_URL")), "ROOTYARD_TEST_DATABASE_URL is required")
        need(Path("/proc/self/fd").is_dir(), "Linux procfs (/proc/<pid>/fd) is required")
        need(Path("/proc/net/tcp").is_file(), "Linux procfs network tables are required")
        missing = [tool for tool in REQUIRED_TOOLS if not shutil.which(tool)]
        need(not missing, "required tool(s) missing: " + ", ".join(missing))
        need(len(secrets.token_hex(8)) == 16, "a cryptographic random source is required")
    except (serving.ProfileError, BaselineError) as error:
        return preflight_failed(args.report, _redact_without_fixture(str(error), env))
    except Exception as error:
        return preflight_failed(args.report, "preflight failed: " + type(error).__name__)
    return run(args, profile, blob_profile)


if __name__ == "__main__":
    sys.exit(main())
