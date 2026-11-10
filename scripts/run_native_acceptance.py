#!/usr/bin/env python3
"""
Run a small declarative plan of native acceptance suites on grouped resources.

The runner coordinates existing acceptance campaigns. It only executes each
suite's ``argv`` and coordinates declared flock resource keys; it does not reuse
or configure a PostgreSQL 17 / Garage instance and never creates or drops
databases or objects. Each suite's harness owns its service, data setup and
cleanup. What this runner adds is ordering: eligible suites run in plan order
subject to dependencies, ``max_workers`` and resource locks, so no smoke work is
guaranteed to finish before a full job starts.

* suites that use the same resource key never overlap unless every participant
  explicitly declares the key ``shared`` and its harness isolation;
* a failed/timed-out smoke suite blocks its full dependants; ``blocked`` is
  never a pass;
* the same resource keys are flocked in an operator-owned lock directory, so
  independent runner processes serialize on them too;
* the report carries only ids, statuses, exit codes, timings, hashed resource
  keys, summaries and log paths. Only the supervisor pre-spawn refusal uses a
  fixed summary; other suite summaries are redacted output. Known sensitive
  values are redacted from summaries and a self-test scans the rendered report.
  Keep credentials out of plans; raw private mode-0600 logs may still contain
  secret output.

Plan shape (JSON)::

    {"version": 1, "max_workers": 2, "total_timeout_seconds": 1800,
     "lock_dir": "/operator/outside/checkout/locks",
     "suites": [{"id": "smoke-http-pg", "phase": "smoke",
                 "profile": "portable-service",
                 "argv": ["python3", "tests/web_sessions.py", "--binary",
                          "target/debug/rootyard", "--report", "{run_dir}/smoke.json"],
                 "depends_on": [],
                 "resources": {"instance:pg17": "exclusive", "loopback-ports": "exclusive"},
                 "timeout_seconds": 600,
                 "isolation": {"database": "owned_schema",
                               "object_prefix": "rootyard/{run_id}/{suite_id}/",
                               "blob_root": "{run_id}/{suite_id}"},
                 "environment": {"ROOTYARD_DATA_DIR": "{run_dir}/data"}}],
     "not_run": [{"suite": "browser-native", "reason": "no smoke command exists"}]}

``argv`` runs with ``shell=False`` under ``scripts/native_acceptance_supervisor.py``.
``{run_id}``, ``{suite_id}`` and ``{run_dir}`` are substituted in argv, suite
environment and isolation values. Sensitive credentials and credential URLs
belong to the runner process environment, never to the plan. Validation only
refuses URI-like values under sensitive top-level environment keys. Inherited
sensitive values are redacted from the report, but suite logs (mode 0600) may
contain secrets and must stay private. ``--dry-run`` starts nothing and creates
no run directory; a real run creates the run directory and report parent. The
lock directory must already exist, and lock, run, log and report paths must
resolve outside ``--verify-host`` (the plan file need not).

Owned-descendant lifecycle (Linux only): the runner passes suite argv to the
supervisor. The Linux supervisor is a child subreaper, so orphaned descendants are reparented to it or to an intermediate descendant subreaper rather than to init, remaining within the supervisor's descendant tree. It builds a ``/proc`` parent-child
census of its descendants and signals them only through pidfds with an identity
check, with no raw-PID, PGID or session fallback. The runner passes already
flocked resource FDs, and the supervisor keeps its copies open until ``waitpid``
reports ECHILD and the census shows no live descendant remains; only then does
the supervisor send a final quit. The runner unlocks the resource keys only
after it has validated the final quit, the supervisor status EOF and the
supervisor exit. If that state is unknown, the keys stay locked forever and no
final report or pass is produced. A missing readable ``/proc`` or a missing or
unsupported pidfd interface prevents the suite from starting. The qualified
Ubuntu host workflow is unchanged.

Pre-spawn refusal: the supervisor's own preflight (pidfd, child subreaper,
``/proc`` census, descriptor checks) runs before ``ready`` and before the suite
CLI is forked. When it refuses, the supervisor sends exactly one
``{"event": "refused", "reason": "preflight-failed", "leader_started": false,
"supervisor_pid": PID}`` frame instead of the CLI being started. The runner
accepts that frame only in ``before_ready`` from the supervisor PID it spawned,
only with that fixed reason and ``leader_started`` false, and only once the
status pipe has hit EOF and the supervisor has exited ``3``. Only then is the
suite recorded as ``failed`` with ``cleanup: not-started``, ``exit_code: null``
and a fixed refusal summary, and its own lock copies released -- no CLI ran, so
nothing else can hold them. Any other EOF, frame, exit code or ordering stays
fail-closed: no proof, so the locks stay held and no final report is written.
"""
import argparse
import concurrent.futures
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
import uuid

DEFAULT_MAX_WORKERS = 2
MAX_WORKERS = 8
PHASES = ("smoke", "full")
PROFILES = ("portable-service",)
STATEFUL_PREFIXES = ("global", "kernel", "lifecycle")
MODES = ("exclusive", "shared")
TERM_GRACE_SECONDS = 3.0
BREATHER_SECONDS = 2.0  # leader exited, owned group still finishing its own readers
QUIESCE_SECONDS = 20.0
POLL_SECONDS = 0.02
COLLECT_INTERVAL = 0.25   # full /proc count cadence while draining a suite
SUMMARY_LIMIT = 1200
RESOURCE_KEY = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,95}$")
SUITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
RELATIVE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/{}-]{0,240}$")
SELF_ENV = ("ROOTYARD_ACCEPTANCE_RUN_ID", "ROOTYARD_ACCEPTANCE_SUITE", "ROOTYARD_ACCEPTANCE_LOCK_DIR")
# Object-store settings are supplied by the plan itself; an inherited endpoint,
# bucket or credential must not silently reach a suite that did not declare it.
LEASE_ENV_PREFIXES = ("ROOTYARD_OBJECT_STORE_", "ROOTYARD_BLOB_")
SENSITIVE_ENV = re.compile(r"SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY|API_KEY"
                           r"|DATABASE_URL|POSTGRES_URL", re.I)
URL_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@]+@")
AUTH_HEADER = re.compile(r"(?i)((?:authorization|proxy-authorization)\s*:\s*)(?:basic|bearer|token)\s+\S+")
SENSITIVE_ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9_])((?=[A-Z0-9_]*[A-Z](?:[A-Z0-9_]|$))(?=[A-Z0-9_]*"
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|ACCESS_KEY|PRIVATE_KEY|API_KEY"
    r"|DATABASE_URL|POSTGRES_URL))"
    r"[A-Z0-9_]*[ \t]*[=:][ \t]*)(\"[^\"]*\"|'[^']*'|[^\s,;]*)")
KNOWN_TOKEN = re.compile(r"\b(?:ryt|ghp|gho|glpat|xox[abp])_[A-Za-z0-9._-]{8,}")
# The supervisor's only pre-spawn refusal code, the exact frame key set, and the
# supervisor exit the runner requires before accepting a refusal.
SUPERVISOR_REFUSAL_REASON = "preflight-failed"
SUPERVISOR_REFUSAL_EXIT = 3
SUPERVISOR_REFUSAL_KEYS = frozenset({"event", "reason", "leader_started", "supervisor_pid"})
REFUSAL_SUMMARY = ("suite not started: the supervisor refused its pre-spawn preflight "
                   "(reason preflight-failed) before forking the CLI; details are in the suite log")
INTERESTING = re.compile(r"(?i)traceback|error|fail|assert|exception|panic|timed out|denied")


class PlanError(Exception):
    """The plan is malformed; nothing is executed."""

    exit_code = 2


class RunError(Exception):
    """The plan cannot run here (bad lock dir, refused profile); nothing is executed."""

    exit_code = 3


def require(condition, message, error=PlanError):
    if not condition:
        raise error(message)


def safe_key(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


def stateful(key):
    return key.split(":", 1)[0] in STATEFUL_PREFIXES


class Redactor:
    def __init__(self, known=()):
        self.known = sorted({value for value in known if isinstance(value, str) and len(value) >= 4},
                            key=len, reverse=True)

    def text(self, value):
        value = str(value)
        for secret in self.known:
            value = value.replace(secret, "[REDACTED]")
        value = URL_USERINFO.sub(r"\1[REDACTED]@", value)
        value = AUTH_HEADER.sub(r"\1[REDACTED]", value)
        value = SENSITIVE_ASSIGNMENT.sub(r"\1[REDACTED]", value)
        return KNOWN_TOKEN.sub("[REDACTED]", value)

    def summary(self, text):
        """Bounded redacted failing lines plus the tail; argv is never read into a summary."""
        lines = text.splitlines()
        picked = [line for line in lines if INTERESTING.search(line)][-15:]
        picked += [line for line in lines[-15:] if line.strip() and line not in picked]
        return self.text("\n".join(picked))[:SUMMARY_LIMIT]


def render(template, run_id, suite_id, run_dir):
    return (str(template).replace("{run_id}", run_id).replace("{suite_id}", suite_id)
            .replace("{run_dir}", str(run_dir)))


def load_plan(path):
    try:
        plan = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise PlanError(f"cannot read plan: {error}") from None
    require(isinstance(plan, dict), "plan must be a JSON object")
    require(plan.get("version", 1) == 1, "unsupported plan version")
    return plan


def validate_suite(suite, seen):
    require(isinstance(suite, dict), "every suite must be an object")
    suite_id = suite.get("id")
    require(isinstance(suite_id, str) and SUITE_ID.match(suite_id), "invalid suite id")
    require(suite_id not in seen, f"duplicate suite id {suite_id!r}")
    seen.add(suite_id)
    require(suite.get("phase") in PHASES, f"{suite_id}: phase must be smoke or full")
    argv = suite.get("argv")
    require(isinstance(argv, list) and argv and all(isinstance(item, str) and item for item in argv),
            f"{suite_id}: argv must be a non-empty array of strings")
    timeout = suite.get("timeout_seconds")
    require(isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and 0 < timeout <= 86400,
            f"{suite_id}: timeout_seconds must be a positive number")
    profile = suite.get("profile")
    if profile is not None and profile not in PROFILES:
        # A plan asking for kernel/FUSE/host qualification is an unknown profile to
        # a portable runner: refuse loudly, before ids and paths are even graded.
        raise RunError(f"{suite_id}: profile {profile!r} is refused; this runner only runs portable-service "
                       "suites. Kernel/FUSE/cgroup/PID-1/host-namespace qualification stays in the qualified "
                       "host workflow (native-kernel-acceptance.yml on Ubuntu 22.04), never relabelled here")
    require(isinstance(suite.get("depends_on", []), list), f"{suite_id}: depends_on must be an array")
    require(isinstance(suite.get("environment", {}), dict), f"{suite_id}: environment must be an object")
    return suite_id


def validate_resources(suite_id, resources, isolation):
    require(isinstance(resources, dict) and resources, f"{suite_id}: resources must be a non-empty object")
    require(isinstance(isolation, dict), f"{suite_id}: isolation must be an object")
    for name, value in isolation.items():
        if name == "database":
            require(value == "owned_schema", f"{suite_id}: database isolation must be owned_schema")
        elif name in ("object_prefix", "blob_root"):
            require(isinstance(value, str) and RELATIVE_PREFIX.match(value) and ".." not in value.split("/"),
                    f"{suite_id}: {name} must be a relative prefix (no absolute path, no '..')")
        else:
            # Any other name is a per-key harness-isolation declaration.
            require(RESOURCE_KEY.match(name), f"{suite_id}: invalid isolation key {name!r}")
            require(isinstance(value, str) and value and not os.path.isabs(value) and ".." not in value.split("/"),
                    f"{suite_id}: isolation {name} must name a relative isolated resource")
    modes = {}
    for key, mode in resources.items():
        require(isinstance(key, str) and RESOURCE_KEY.match(key), f"{suite_id}: invalid resource key")
        mode = "exclusive" if mode is None else mode
        require(mode in MODES, f"{suite_id}: {key} mode must be exclusive or shared")
        if mode == "shared":
            require(key in isolation or (isolation.get("database") == "owned_schema" and not stateful(key)),
                    f"{suite_id}: shared {key} needs a declaration that the harness isolates it "
                    "(isolation.database=owned_schema, or isolation[name]); global/kernel/lifecycle keys "
                    "always need their own isolation entry")
        modes[key] = mode
    return modes


def validate_plan(plan):
    suites = plan.get("suites")
    require(isinstance(suites, list) and suites, "plan must contain a non-empty suites array")
    workers = plan.get("max_workers", DEFAULT_MAX_WORKERS)
    require(isinstance(workers, int) and not isinstance(workers, bool) and 1 <= workers <= MAX_WORKERS,
            f"max_workers must be an integer in 1..{MAX_WORKERS}")
    total = plan.get("total_timeout_seconds")
    require(total is None or (isinstance(total, (int, float)) and not isinstance(total, bool) and total > 0),
            "total_timeout_seconds must be a positive number")
    for field in ("environment", "environment_from_plan"):
        require(isinstance(plan.get(field, {}), dict), f"{field} must be an object")
        for key, value in plan.get(field, {}).items():
            # A malformed plan raises messages the operator sees; never echo a secret.
            require(not (SENSITIVE_ENV.search(key) and isinstance(value, str) and "://" in value),
                    "credential URLs must not be stored in the plan (it may be logged); pass them "
                    "through the runner environment, for example systemd-run --setenv")
    require(plan.get("lock_dir") is None or isinstance(plan["lock_dir"], str), "lock_dir must be a string")
    not_run = plan.get("not_run", [])
    require(isinstance(not_run, list) and all(isinstance(item, dict) and isinstance(item.get("suite"), str)
                                              for item in not_run), "not_run must be an array of {suite, reason}")
    seen = set()
    for suite in suites:
        validate_suite(suite, seen)
        suite["_modes"] = validate_resources(suite["id"], suite["resources"], suite.get("isolation", {}))
    by_id = {suite["id"]: suite for suite in suites}
    for suite in suites:
        for dep in suite.get("depends_on", []):
            require(isinstance(dep, str) and dep in by_id, f"{suite['id']}: unknown depends_on")
            require(dep != suite["id"], f"{suite['id']}: depends on itself")
        if suite["phase"] == "full":
            require(any(by_id[dep]["phase"] == "smoke" for dep in ancestors(suite["id"], by_id)),
                    f"{suite['id']}: a full suite must depend (directly or transitively) on a smoke "
                    "suite; a matrix is never expanded from an unproven command")
    visiting, done = set(), set()

    def visit(suite_id):
        require(suite_id not in visiting, "dependency cycle in plan")
        if suite_id not in done:
            visiting.add(suite_id)
            for dep in by_id[suite_id].get("depends_on", []):
                visit(dep)
            visiting.discard(suite_id)
            done.add(suite_id)

    for suite_id in sorted(by_id):
        visit(suite_id)
    return plan


def require_dependencies_kept(plan):
    """Every remaining dependency must still be in the plan; a removed prerequisite refuses the run."""
    present = {suite["id"] for suite in plan["suites"]}
    for suite in plan["suites"]:
        for dep in suite.get("depends_on", []):
            require(dep in present,
                    f"{suite['id']}: depends_on {dep!r}, which --exclude removed; refusing to run a dependant "
                    "whose prerequisite is not in the plan")


def ancestors(suite_id, by_id):
    seen, stack = set(), list(by_id[suite_id].get("depends_on", []))
    while stack:
        current = stack.pop()
        if current not in seen:
            seen.add(current)
            stack.extend(by_id[current].get("depends_on", []))
    return seen


SECRET_OPTION = re.compile(r"(?i)pass|secret|token|key|auth|credential|dsn|url")


def sensitive_values(plan, run_id, run_dir):
    """Values that must never appear verbatim in a report (ids and paths already are there).

    ``run_dir`` is deliberately not listed: the report itself names it (log
    paths), so listing it would fail the self-test on every run.
    """
    values = []
    values.extend(value for name, value in os.environ.items() if SENSITIVE_ENV.search(name))
    for field in ("environment", "environment_from_plan"):
        values.extend(str(value) for value in plan.get(field, {}).values())
    for suite in plan["suites"]:
        argv = suite["argv"]
        values.extend(str(value) for value in suite.get("environment", {}).values() if value != suite["id"])
        # Credentials usually travel as ``--flag value``: keep option values, not
        # every bare argument (suite ids and paths are already in the report).
        values.extend(argv[index + 1] for index, item in enumerate(argv[:-1])
                      if item.startswith("--") and SECRET_OPTION.search(item))
    # ``run-x``/``instance-a`` are deliberately matched below by the log paths.
    covered = {run_id, *(suite["id"] for suite in plan["suites"])}
    return [value for value in values if isinstance(value, str) and len(value) >= 6 and value not in covered]


def outside(path, root, label):
    resolved = Path(path).expanduser().resolve()
    require(resolved != root and root not in resolved.parents, f"{label} must be outside the checkout", RunError)
    return resolved


class LockSet:
    """flock every resource key (LOCK_EX for exclusive, LOCK_SH for shared); polled, never blocking."""

    def __init__(self, directory, modes):
        self.directory = Path(directory)
        self.modes = dict(modes)
        self.fds = []

    def try_acquire(self):
        for key in sorted(self.modes):
            name = "acceptance-" + hashlib.sha256(key.encode()).hexdigest()[:24] + ".lock"
            fd = os.open(self.directory / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
            flag = fcntl.LOCK_SH if self.modes[key] == "shared" else fcntl.LOCK_EX
            try:
                fcntl.flock(fd, flag | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                self.release()
                return False
            self.fds.append(fd)
        return True

    def release(self):
        while self.fds:
            fd = self.fds.pop()
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


class PlatformUnsupported(RunError):
    """Descendant quiescence cannot be proven on this platform, so nothing is spawned."""

    exit_code = 3


def require_supervisor_support():
    """Descendant quiescence is provable only where /proc exposes each process's PID, parent PID, and state, letting the supervisor reconstruct the process tree.

    The Linux supervisor is a child subreaper, so orphaned descendants are
    adopted and appear in a /proc parent-child census; it signals only
    identity-checked pidfds, never a raw PID, PGID, or session. On hosts
    without a readable /proc or working pidfd support this code could neither
    tell a live grandchild from a dead leader nor stop descendants without
    signalling a raw identifier. Refuse before any Popen; never start a child
    this runner could not stop or vouch for.
    """
    if not sys.platform.startswith("linux") or not os.path.isdir("/proc/self"):
        raise PlatformUnsupported(
            f"owned descendant quiescence needs a Linux /proc census; {sys.platform!r} cannot prove that a suite's "
            "grandchildren exited, and this runner never starts a child it cannot stop. Run suite plans in "
            "the Linux runner (rootyard-native-env runner image; the qualified Ubuntu workflow is unchanged); "
            "Mac and other hosts are refused before any child starts")
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if not callable(pidfd_open) or not callable(pidfd_send_signal):
        raise PlatformUnsupported(
            "owned descendant quiescence also requires Linux pidfd support (os.pidfd_open and "
            "signal.pidfd_send_signal); this host cannot prove it can stop a suite's descendants, so the "
            "suite is refused before any suite starts. Run suite plans on a Linux kernel with pidfd support "
            "(5.1+ for pidfd_open, 5.3+ for pidfd_send_signal)")
    # Probe pidfd creation and signal-0 delivery on this process only; never
    # signal a raw PID, so nothing outside this runner can be touched.
    try:
        pidfd = pidfd_open(os.getpid(), 0)
    except OSError as exc:
        raise PlatformUnsupported(
            f"owned descendant quiescence requires Linux pidfd support, but os.pidfd_open failed "
            f"({exc}); the suite is refused before any suite starts") from exc
    try:
        try:
            pidfd_send_signal(pidfd, 0)
        except OSError as exc:
            raise PlatformUnsupported(
                f"owned descendant quiescence requires Linux pidfd support, but signal.pidfd_send_signal(fd, 0) "
                f"failed ({exc}); the suite is refused before any suite starts") from exc
    finally:
        try:
            os.close(pidfd)
        except OSError as exc:
            raise PlatformUnsupported(
                f"owned descendant quiescence requires reliable pidfd lifecycle control, but closing the probe "
                f"pidfd failed ({exc}); the suite is refused before any suite starts") from exc

class Child:
    _MAX_LINE_BYTES = 65536
    _POLL_TIMEOUT = 0.05
    _IDLE_SLEEP = 0.05

    def __init__(self, argv, env, log_path, timeout, resource_fds):
        self._argv = [str(part) for part in argv]
        self._env = dict(env)
        self._log_path = Path(log_path)
        self._timeout = timeout
        self._resource_fds = [int(fd) for fd in resource_fds]
        self._control_r = -1
        self._control_w = -1
        self._status_r = -1
        self._status_w = -1
        self._log_fd = -1
        self._control_closed = False
        self._buffer = bytearray()
        self._proc = None
        self.proc = None
        try:
            self._control_r, self._control_w = os.pipe()
            self._status_r, self._status_w = os.pipe()
            self._log_fd = os.open(
                os.fspath(self._log_path),
                os.O_WRONLY
                | os.O_CREAT
                | os.O_TRUNC
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            os.fchmod(self._log_fd, 0o600)
            supervisor_path = (
                Path(__file__).resolve().parent.parent
                / "scripts"
                / "native_acceptance_supervisor.py"
            )
            command = [
                sys.executable,
                str(supervisor_path),
                "--timeout",
                repr(float(self._timeout)),
            ]
            for fd in self._resource_fds:
                command.extend(["--resource-fd", str(fd)])
            command.extend(
                [
                    "--parent-control-fd",
                    str(self._control_r),
                    "--status-fd",
                    str(self._status_w),
                    "--",
                ]
            )
            command.extend(self._argv)
            pass_fds = [
                self._control_r,
                self._status_w,
                *self._resource_fds,
            ]
            self._proc = subprocess.Popen(
                command,
                env=self._env,
                stdin=subprocess.DEVNULL,
                stdout=self._log_fd,
                stderr=subprocess.STDOUT,
                close_fds=True,
                pass_fds=pass_fds,
            )
        except BaseException:
            for fd in (
                self._control_r,
                self._control_w,
                self._status_r,
                self._status_w,
                self._log_fd,
            ):
                self._close_fd_safely(fd)
            self._control_r = -1
            self._control_w = -1
            self._status_r = -1
            self._status_w = -1
            self._log_fd = -1
            raise
        self.proc = self._proc
        self._close_fd_safely(self._log_fd)
        self._log_fd = -1
        self._close_fd_safely(self._control_r)
        self._control_r = -1
        self._close_fd_safely(self._status_w)
        self._status_w = -1

    @staticmethod
    def _close_fd_safely(fd):
        if fd is None or fd < 0:
            return
        try:
            os.close(fd)
        except OSError:
            pass

    def _close_control_once(self):
        if self._control_closed:
            return
        self._control_closed = True
        self._close_fd_safely(self._control_w)
        self._control_w = -1

    def _request_cancel(self):
        self._close_control_once()

    @staticmethod
    def _is_int(value):
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _deadline_reached(value):
        if value is None:
            return False
        try:
            return time.monotonic() >= float(value)
        except (TypeError, ValueError):
            return False

    def _invalidate(self, state):
        state["phase"] = "invalid"
        state["quit_frame"] = None
        state["refusal_frame"] = None

    @staticmethod
    def _refusal_shape(frame, supervisor_pid):
        """The exact fixed refusal frame: exact key set, event, allowlisted reason, no CLI, our PID."""
        return (type(frame) is dict
                and frozenset(frame) == SUPERVISOR_REFUSAL_KEYS
                and type(frame.get("event")) is str
                and frame.get("event") == "refused"
                and type(frame.get("reason")) is str
                and frame.get("reason") == SUPERVISOR_REFUSAL_REASON
                and frame.get("leader_started") is False
                and Child._is_int(frame.get("supervisor_pid"))
                and frame.get("supervisor_pid") == supervisor_pid)

    def _validate_frame(self, frame, state):
        if state["phase"] == "invalid":
            return
        if not isinstance(frame, dict):
            self._invalidate(state)
            return
        event = frame.get("event")
        supervisor_pid = frame.get("supervisor_pid")
        if not self._is_int(supervisor_pid):
            self._invalidate(state)
            return
        if self._proc is None or supervisor_pid != self._proc.pid:
            self._invalidate(state)
            return
        if state["phase"] == "before_ready":
            if event == "refused":
                # Pre-spawn refusal: accepted only with the fixed shape, and only
                # here (before ready/CLI). It is proof of nothing yet; _finish()
                # also needs status EOF and the supervisor's own exit.
                if not self._refusal_shape(frame, supervisor_pid):
                    self._invalidate(state)
                    return
                state["saw_refusal"] = True
                state["refusal_frame"] = {
                    "event": "refused",
                    "reason": SUPERVISOR_REFUSAL_REASON,
                    "leader_started": False,
                    "supervisor_pid": supervisor_pid,
                }
                state["phase"] = "refusal_seen"
                return
            if event != "ready":
                self._invalidate(state)
                return
            resource_count = frame.get("resource_fds")
            if not self._is_int(resource_count):
                self._invalidate(state)
                return
            if resource_count != len(self._resource_fds):
                self._invalidate(state)
                return
            state["saw_ready"] = True
            state["phase"] = "after_ready"
            return
        if state["phase"] == "after_ready":
            if event == "progress":
                return
            if event == "quit":
                cleanup = frame.get("cleanup")
                resources_closed = frame.get("resources_closed")
                leader_exit = frame.get("leader_exit")
                reason = frame.get("reason")
                if cleanup != "quiescent":
                    self._invalidate(state)
                    return
                if resources_closed is not True:
                    self._invalidate(state)
                    return
                if not self._is_int(leader_exit):
                    self._invalidate(state)
                    return
                if not isinstance(reason, str):
                    self._invalidate(state)
                    return
                state["saw_quit"] = True
                state["quit_frame"] = {
                    "event": "quit",
                    "cleanup": cleanup,
                    "resources_closed": resources_closed,
                    "leader_exit": leader_exit,
                    "reason": reason,
                    "supervisor_pid": supervisor_pid,
                }
                state["phase"] = "quit_seen"
                return
            self._invalidate(state)
            return
        # refusal_seen: the refusal was the protocol's last frame; anything after
        # it (even ready) is ambiguous.
        self._invalidate(state)

    def _parse_status_data(self, data, state):
        if not data:
            return
        if state["phase"] == "invalid":
            self._buffer.clear()
            return
        self._buffer.extend(data)
        while True:
            if state["phase"] == "invalid":
                self._buffer.clear()
                return
            newline_index = self._buffer.find(b"\n")
            if newline_index < 0:
                if len(self._buffer) > self._MAX_LINE_BYTES:
                    self._invalidate(state)
                    self._buffer.clear()
                return
            if newline_index > self._MAX_LINE_BYTES:
                self._invalidate(state)
                self._buffer.clear()
                return
            line = bytes(self._buffer[:newline_index])
            del self._buffer[: newline_index + 1]
            if not line:
                self._invalidate(state)
                self._buffer.clear()
                return
            try:
                frame = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, TypeError):
                self._invalidate(state)
                self._buffer.clear()
                return
            self._validate_frame(frame, state)

    def _read_status_once(self, state):
        if self._status_r < 0 or state["eof"]:
            return
        try:
            data = os.read(self._status_r, self._MAX_LINE_BYTES + 1)
        except BlockingIOError:
            return
        except InterruptedError:
            return
        except OSError:
            self._invalidate(state)
            state["eof"] = True
            self._buffer.clear()
            return
        if data:
            self._parse_status_data(data, state)
            return
        state["eof"] = True
        if self._buffer:
            self._invalidate(state)
            self._buffer.clear()
        # A refusal line is complete once its newline is consumed: EOF right after
        # it is the expected end of that protocol. Anything else is invalid.
        if state["phase"] not in ("quit_seen", "refusal_seen"):
            self._invalidate(state)

    def _finish(self, state):
        """Strict proof only: the final frame, status EOF and (refusal) supervisor exit.

        A validated refusal line is not proof by itself: before it is accepted the
        supervisor must also have closed the status pipe (EOF) and exited with
        ``SUPERVISOR_REFUSAL_EXIT``. Until both hold this returns None, which
        keeps the caller fail-closed (no release, no final report).
        """
        if not state.get("eof"):
            return None
        if self._buffer:
            return None
        if state["returncode"] is None:
            return None
        if state["phase"] == "refusal_seen":
            if not state.get("saw_refusal") or state["refusal_frame"] is None:
                return None
            if state["returncode"] != SUPERVISOR_REFUSAL_EXIT:
                return None
            return state["refusal_frame"], state["returncode"]
        if state["phase"] != "quit_seen":
            return None
        if not state.get("saw_quit"):
            return None
        return state["quit_frame"], state["returncode"]

    def _fail_closed(self):
        """Unknown state never returns: no release, no final report, no pass.

        The caller's ``hold()`` then keeps this suite's locks for the life of the
        runner process. Only a proven refusal or quit frame may end ``wait()``.
        """
        while True:
            time.sleep(self._IDLE_SLEEP)

    def _collect_returncode(self, state):
        if state["returncode"] is not None:
            return
        if self._proc is None:
            return
        returncode = self._proc.poll()
        if returncode is not None:
            state["returncode"] = returncode

    def _wait_status(self, state):
        if self._status_r >= 0 and not state["eof"]:
            self._read_status_once(state)

    def wait(self, suite_deadline, stop_event):
        import json
        import select

        state = {
            "phase": "before_ready",
            "saw_ready": False,
            "saw_quit": False,
            "quit_frame": None,
            "saw_refusal": False,
            "refusal_frame": None,
            "eof": False,
            "returncode": None,
        }
        try:
            os.set_blocking(self._status_r, False)
        except OSError:
            self._invalidate(state)
        try:
            while True:
                if state["phase"] == "invalid":
                    return self._fail_closed()  # no proof: locks stay held
                if not self._control_closed and self._proc is not None:
                    if (stop_event is not None and stop_event.is_set()) or self._deadline_reached(
                        suite_deadline
                    ):
                        self._close_control_once()
                if state["phase"] != "invalid" and self._status_r >= 0 and not state["eof"]:
                    try:
                        selected, _, _ = select.select(
                            [self._status_r], [], [], self._POLL_TIMEOUT
                        )
                    except InterruptedError:
                        selected = []
                    except (OSError, ValueError):
                        self._invalidate(state)
                        selected = []
                    if selected:
                        self._wait_status(state)
                else:
                    time.sleep(self._IDLE_SLEEP)
                self._collect_returncode(state)
                result = self._finish(state)
                if result is not None:
                    return result
                if state["phase"] == "invalid" or state["returncode"] is not None:
                    if state["eof"]:
                        self._close_fd_safely(self._status_r)
                        self._status_r = -1
                    time.sleep(self._IDLE_SLEEP)
        finally:
            self._close_control_once()
            self._close_fd_safely(self._status_r)
            self._status_r = -1

class Runner:
    def __init__(self, plan, run_id, lock_dir, run_dir, base_env, redactor, total_timeout=None):
        self.plan = plan
        self.run_id = run_id
        self.lock_dir = lock_dir
        self.run_dir = run_dir
        self.base_env = base_env
        self.redactor = redactor
        self.total_timeout = total_timeout
        self.suites = {suite["id"]: suite for suite in plan["suites"]}
        self.results = {}
        self.stop = threading.Event()   # internal clock: total timeout reached
        self.interrupt = False          # SIGINT/SIGTERM received
        self.stuck = []                 # suites whose owned group never went quiescent
        self.waiting = set()            # (suite id, key modes) blocked on another runner's flock
        self.waited = {}                # suite id -> first time it was seen waiting on a flock
        self.started = time.monotonic()

    def request_stop(self, signum=None):
        if signum is not None:
            self.interrupt = True
        self.stop.set()

    @property
    def stop_reason(self):
        return "cancelled"

    def environment(self, suite):
        """Plan and per-suite values reach the child and override the inherited environment."""
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(LEASE_ENV_PREFIXES) and key not in SELF_ENV}
        for field in ("environment", "environment_from_plan"):
            env.update({key: render(value, self.run_id, suite["id"], self.run_dir)
                        for key, value in self.plan.get(field, {}).items()})
        env.update({key: render(value, self.run_id, suite["id"], self.run_dir)
                    for key, value in suite.get("environment", {}).items()})
        env.update(self.base_env)
        env.update({"ROOTYARD_ACCEPTANCE_RUN_ID": self.run_id,
                    "ROOTYARD_ACCEPTANCE_SUITE": suite["id"],
                    "ROOTYARD_ACCEPTANCE_LOCK_DIR": str(self.lock_dir)})
        return env

    def argv(self, suite):
        return [render(item, self.run_id, suite["id"], self.run_dir) for item in suite["argv"]]

    def execute(self, suite, locks):
        result = self.results[suite["id"]]
        result["cleanup"] = "not-started"
        log_path = self.run_dir / "logs" / (suite["id"] + ".log")
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            result["log"] = str(log_path)
            suite_timeout = float(suite["timeout_seconds"])
            deadline = time.monotonic() + suite_timeout
            child = Child(
                self.argv(suite),
                self.environment(suite),
                log_path,
                suite_timeout,
                locks.fds,
            )
        except OSError:
            result.update(status="failed", exit_code=None, cleanup="not-started")
            return  # nothing was spawned, so nothing owns the keys
        except BaseException:
            result["cleanup"] = "not-started"
            raise
        # Child is live (or at least something may be owned): never claim
        # quiescence again unless wait() returns its validated proof.
        result["cleanup"] = "in-progress"
        # Internal, never reported: only a validated refusal proof sets this.
        result["_refusal_proven"] = False
        frame, supervisor_returncode = child.wait(deadline, self.stop)
        if frame["event"] == "refused":
            # Proven pre-spawn refusal: the supervisor sent its one fixed frame,
            # closed the status pipe and exited 3 before ready and before the CLI
            # fork. No CLI (or anything it spawned) exists, so this suite's own
            # lock copies may be released; there is no CLI exit to report.
            # finalize() keeps this fixed summary: the diagnostic text stays in
            # the private suite log.
            result.update(status="failed", cleanup="not-started", exit_code=None, summary=REFUSAL_SUMMARY,
                          _refusal_proven=True)
            return
        # wait() only returns on strict proof: quit frame, status EOF and
        # supervisor exit. Only now may cleanup be declared quiescent.
        quit_frame = frame
        result["cleanup"] = "quiescent"
        exit_code = quit_frame["leader_exit"]
        reason = quit_frame["reason"]
        result["exit_code"] = exit_code
        if self.stop.is_set():
            result["status"] = "cancelled"
        elif reason == "timeout" or time.monotonic() >= deadline:
            result["status"] = "timed_out"
        elif reason == "cli-exit" and exit_code == 0 and supervisor_returncode == 0:
            result["status"] = "passed"
        else:
            result["status"] = "failed"

    def finalize(self, suite, result):
        result["duration_seconds"] = round(time.time() - result["started_at"], 3)
        log = Path(result["log"]) if result.get("log") else None
        text = log.read_text(errors="replace") if log and log.exists() else ""
        if result.pop("_refusal_proven", False) is True:
            # The only failed case whose summary is not raw log text: the suite
            # never started, and its diagnostic text belongs to the private log.
            result["summary"] = REFUSAL_SUMMARY
        elif result["status"] == "passed":
            last = next((line for line in reversed(text.splitlines()) if line.strip()), "")
            result["summary"] = self.redactor.text(last)[:SUMMARY_LIMIT]
        else:
            result["summary"] = self.redactor.summary(text)
        if result.get("cleanup") == "group-still-active":
            result["summary"] = "owned process group did not go quiescent; locks remain held"

    def run(self):
        workers = self.plan.get("max_workers", DEFAULT_MAX_WORKERS)
        order = [suite["id"] for suite in self.plan["suites"]]
        status = {suite_id: "pending" for suite_id in order}
        running = {}  # suite id -> (future, modes)
        pending = set(order)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            while True:
                for suite_id in [sid for sid, job in running.items() if job[0].done()]:
                    running.pop(suite_id)[0].result()
                    status[suite_id] = self.results[suite_id]["status"]
                if self.total_timeout is not None and time.monotonic() - self.started >= self.total_timeout:
                    self.request_stop()
                self.settle_pending(pending, status)
                if not pending and not running:
                    return self.report()
                held = [modes for _, modes in running.values()]
                for suite_id in order:
                    if status[suite_id] != "pending" or len(running) >= workers or self.stop.is_set():
                        continue
                    if any(status[dep] != "passed" for dep in self.suites[suite_id].get("depends_on", [])):
                        continue
                    modes = self.suites[suite_id]["_modes"]
                    if any(conflicts(key, mode, other) for other in held for key, mode in modes.items()):
                        continue
                    locks = LockSet(self.lock_dir, modes)
                    if not locks.try_acquire():
                        # An independent runner owns a key: wait, and say so in the report.
                        self.waiting.add((suite_id, tuple(sorted(modes))))
                        self.waited.setdefault(suite_id, time.time())
                        continue
                    waited = self.waited.get(suite_id)
                    pending.discard(suite_id)
                    status[suite_id] = "running"
                    self.results[suite_id] = {"status": "running", "started_at": time.time(),
                                              "wait_seconds": round(time.time() - waited, 3) if waited
                                              else round(time.monotonic() - self.started, 3)}
                    running[suite_id] = (pool.submit(self.hold, suite_id, locks), modes)
                time.sleep(POLL_SECONDS)

    def settle_pending(self, pending, status):
        for suite_id in list(pending):
            suite = self.suites[suite_id]
            broken = [dep for dep in suite.get("depends_on", [])
                      if status[dep] in ("failed", "timed_out", "cancelled", "blocked")]
            if broken:
                pending.discard(suite_id)
                status[suite_id] = "blocked"
                self.results[suite_id] = {"status": "blocked", "started_at": time.time(),
                                          "wait_seconds": 0.0, "duration_seconds": None,
                                          "exit_code": None, "cleanup": "not-started",
                                          "summary": "not started: dependency did not pass; "
                                                     + ", ".join(f"{dep}={status[dep]}" for dep in broken)}
            elif self.stop.is_set():
                pending.discard(suite_id)
                status[suite_id] = "not_run"
                self.results[suite_id] = {"status": "not_run", "started_at": time.time(),
                                          "wait_seconds": 0.0, "duration_seconds": None,
                                          "exit_code": None, "cleanup": "not-started",
                                          "summary": "not started: " + self.stop_reason}

    def hold(self, suite_id, locks):
        result = self.results[suite_id]
        try:
            self.execute(self.suites[suite_id], locks)
            self.finalize(self.suites[suite_id], result)
        except BaseException:
            # Fail closed: if the owned group was not proven quiescent, keep the
            # locks held for the life of the process instead of releasing them.
            if result.get("cleanup") not in ("quiescent", "not-started"):
                while True:
                    time.sleep(1.0)
            raise
        finally:
            # Released only when the group was proven quiescent (leader included)
            # or no child was ever started.
            if result.get("cleanup") in ("quiescent", "not-started"):
                locks.release()

    def report(self):
        entries = []
        for suite in self.plan["suites"]:
            result = self.results[suite["id"]]
            entries.append({
                "id": suite["id"],
                "phase": suite["phase"],
                "status": result["status"],
                "exit_code": result.get("exit_code"),
                # started_at is the wall clock (epoch) start; the test contract
                # reads it to compare suite spans.
                "timing": {"started_at": result.get("started_at"),
                           "wait_seconds": result.get("wait_seconds"),
                           "duration_seconds": result.get("duration_seconds")},
                "resources": {safe_key(key): mode for key, mode in sorted(suite["_modes"].items())},
                "cleanup": result.get("cleanup", "not-started"),
                "summary": result.get("summary", ""),
                "log": result.get("log"),
            })
        return {"kind": "rootyard/native-acceptance-run", "version": 1, "run_id": self.run_id,
                "max_workers": self.plan.get("max_workers", DEFAULT_MAX_WORKERS),
                "aborted": "cancelled" if self.stop.is_set() else None,
                "waiting_on_locks": sorted({suite_id for suite_id, _ in self.waiting}),
                "interrupted": self.interrupt, "non_quiescent": self.stuck,
                "suites": entries, "not_run": self.plan.get("not_run", [])}


def conflicts(key, mode, other):
    return key in other and not (mode == "shared" and other[key] == "shared")


def self_test(plan, run_id, run_dir, report):
    """Every known sensitive value must be absent from the rendered report."""
    rendered = json.dumps(report, sort_keys=True)
    leaked = [safe_key(value) for value in set(sensitive_values(plan, run_id, run_dir)) if value in rendered]
    return {"status": "failed" if leaked else "passed", "matches": leaked}


def wait_locked_ready(lock_dir, key, timeout):
    """Test hook: block while an independent runner takes the exclusive key."""
    target = lock_dir / ("acceptance-" + hashlib.sha256(key.encode()).hexdigest()[:24] + ".lock")
    ready = lock_dir / ("acceptance-ready-" + hashlib.sha256(key.encode()).hexdigest()[:24])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            fd = os.open(target, os.O_RDONLY)
        except OSError:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return
        except BlockingIOError:
            ready.touch()
            time.sleep(POLL_SECONDS)
        finally:
            os.close(fd)


def wait_commands(dry_run, lock_dir, plan):
    """Everything before the first child process starts: validation, paths, freeze, readiness."""
    if not dry_run:
        barrier = os.environ.get("ROOTYARD_ACCEPTANCE_WAIT_FOR")
        if barrier:
            # Operator/test hook: an independent runner already holds this key.
            wait_locked_ready(lock_dir, barrier, float(os.environ.get("ROOTYARD_ACCEPTANCE_WAIT_SECONDS", 300)))
        ready = os.environ.get("ROOTYARD_ACCEPTANCE_READY_FILE")
        if ready:
            Path(ready).write_text(json.dumps({"plan_digest": plan_digest(plan)}))


def plan_digest(plan):
    return hashlib.sha256(json.dumps(copy_plan(plan), sort_keys=True).encode()).hexdigest()


def copy_plan(plan):
    return copy.deepcopy({key: value for key, value in plan.items() if key != "suites"}) | {
        "suites": [{key: value for key, value in suite.items() if not key.startswith("_")}
                   for suite in plan["suites"]]}


def install_signal_handlers(runner):
    def handler(signum, frame):
        # Only a flag and an event: children are stopped by their owner thread.
        runner.request_stop(signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run a grouped native acceptance plan.")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--lock-dir", default=os.environ.get("ROOTYARD_ACCEPTANCE_LOCK_DIR"))
    parser.add_argument("--log-dir", help="run directory (default: <lock-dir>/runs/<run_id>)")
    parser.add_argument("--report", help="report path (default: <run-dir>/report.json)")
    parser.add_argument("--run-id")
    parser.add_argument("--verify-host", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--exclude", action="append", default=[], metavar="SUITE",
                        help="drop a suite (the outer runner passes its own id)")
    parser.add_argument("--dry-run", action="store_true", help="validate the plan; start nothing")
    args = parser.parse_args(argv)
    try:
        plan = load_plan(args.plan)
        require(isinstance(plan.get("suites"), list) and all(isinstance(suite, dict) for suite in plan["suites"]),
                "plan must contain an array of suites")
        # Plan-level credential values are refused before any secret can be echoed
        # by a later structural error.
        for field in ("environment", "environment_from_plan"):
            values = plan.get(field) or {}
            require(isinstance(values, dict), f"{field} must be an object")
            for key, value in values.items():
                require(not (SENSITIVE_ENV.search(key) and isinstance(value, str) and "://" in value),
                        "credential URLs must not be stored in the plan (it may be logged); pass them "
                        "through the runner environment, for example systemd-run --setenv")
        # Refuse host/kernel profiles before anything else: they need the
        # qualified host workflow, not a relabelled portable run.
        for suite in plan["suites"]:
            profile = suite.get("profile")
            if profile is not None and profile not in PROFILES:
                raise RunError(f"profile {profile!r} is refused; this runner only runs portable-service "
                               "suites. Kernel/FUSE/cgroup/PID-1/host-namespace qualification stays in the "
                               "qualified host workflow (native-kernel-acceptance.yml), never relabelled here")
        plan = validate_plan(plan)
        known = {suite["id"] for suite in plan["suites"]}
        require(all(suite_id in known for suite_id in args.exclude), "--exclude names an unknown suite")
        plan["suites"] = [suite for suite in plan["suites"] if suite["id"] not in args.exclude]
        # Before the host preflight, lock dir or any spawn: a dependant whose
        # prerequisite --exclude removed can never run (and must not run unlocked).
        require_dependencies_kept(plan)
        root = Path(args.verify_host).expanduser().resolve()
        run_id = args.run_id or "run-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
        require(RUN_ID.match(run_id), "run id must be 1-64 characters of [A-Za-z0-9-]")
        lock_dir = outside(args.lock_dir or plan.get("lock_dir") or "", root, "lock_dir")
        require(lock_dir.is_dir() and not lock_dir.is_symlink(),
                "lock_dir must be an existing, operator-created directory", RunError)
        # Scratch paths, not sensitive corpus: the run dir and its log paths are
        # named in every report, so treating them as redaction needles would fail
        # the self-test on every run.
        run_dir = outside(args.log_dir, root, "log_dir") if args.log_dir else lock_dir / "runs" / run_id
        report_path = outside(args.report, root, "report path") if args.report else run_dir / "report.json"
        # Nothing is spawned (not even in --dry-run) where a group cannot be proven gone.
        require_supervisor_support()
        if not args.dry_run:
            run_dir.mkdir(parents=True, exist_ok=True)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            wait_commands(False, lock_dir, plan)
        else:
            wait_commands(True, lock_dir, plan)
            print(json.dumps({"plan": "valid", "run_id": run_id, "suites": [s["id"] for s in plan["suites"]],
                              "lock_dir": str(lock_dir), "run_dir": str(run_dir)}))
            return 0
        runner = Runner(plan, run_id, lock_dir, run_dir, {},
                        Redactor(sensitive_values(plan, run_id, run_dir)),
                        plan.get("total_timeout_seconds"))
        install_signal_handlers(runner)
        report = runner.run()
        report["selftest"] = self_test(plan, run_id, run_dir, report)
        failing = [entry["id"] for entry in report["suites"] if entry["status"] != "passed"]
        report["gate"] = "failed" if failing or report["selftest"]["status"] != "passed" else "passed"
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if report["selftest"]["status"] == "passed":
            report_path.write_text(rendered)
        else:
            # Never persist a leaking report; the hashed match list is the only output.
            report_path.write_text(json.dumps({"kind": report["kind"], "version": 1, "run_id": run_id,
                                               "selftest": report["selftest"], "gate": "failed"}) + "\n")
        sys.stdout.write(rendered)
        for suite_id in failing:
            print(f"suite {suite_id}: {runner.results[suite_id]['status']}", file=sys.stderr)
        if report["selftest"]["status"] != "passed":
            print("report self-test failed: a sensitive value reached the report", file=sys.stderr)
        return 0 if report["gate"] == "passed" else 1
    except (PlanError, RunError) as error:
        print(f"error: {error}", file=sys.stderr)
        return error.exit_code


if __name__ == "__main__":
    sys.exit(main())
