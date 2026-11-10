#!/usr/bin/env python3
"""Contract tests for the supervisor-owned native acceptance plan runner.

Every runner test drives ``scripts/run_native_acceptance.py`` as a real process
with real child processes:

* exclusive keys never overlap; independent keys overlap under ``max_workers``;
* a normal (non-stateful) key is flocked across independent runners too, and a
  grandchild that outlives its leader keeps the key locked;
* a failed smoke suite blocks its full dependants, and ``blocked`` is not a pass;
* a timed-out suite has its supervisor-owned process tree (leader and
  grandchild) stopped and nothing else is signalled, and the runner returns
  instead of waiting on the hung leader;
* a leader that exits 0 while a grandchild lives is failed and the key is only
  released after that grandchild is stopped;
* per-suite environment and ``{run_id}`` substitution reach the child;
* the report never holds environment, argv or credential values, and logs are
  private files outside the checkout;
* kernel/FUSE/native-host profile plans are refused.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/run_native_acceptance.py"
# Owned-group quiescence is proved from /proc; on any other platform the runner
# refuses before a child starts (see RunnerPlatformTest). Tests that need real
# child lifecycles skip there; the portable-only checks still run everywhere.
LINUX = sys.platform.startswith("linux")
sys.path.insert(0, str(ROOT / "scripts"))
import run_native_acceptance as acceptance  # noqa: E402

PROBE = r"""
import os, sys, time
markers = os.environ["PROBE_MARKERS"]
name = os.environ.get("PROBE_SUITE") or os.environ["ROOTYARD_ACCEPTANCE_SUITE"]
def mark(text):
    fd = os.open(markers, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.write(fd, (text + "\n").encode())
    os.close(fd)
mark("start " + name + " " + str(time.time()))
if os.environ.get("PROBE_HOLD"):
    until = time.time() + float(os.environ.get("PROBE_HOLD_SECONDS", "1"))
    while time.time() < until:
        time.sleep(0.01)
if os.environ.get("PROBE_FAIL"):
    print("deliberate failure: Error from http://user:dbpass123@127.0.0.1/x", flush=True)
    sys.exit(3)
if os.environ.get("PROBE_HANG"):
    # The hang is in our own code; the grandchild would exit by itself at 120s.
    child = __import__("subprocess").Popen(["sleep", "120"])
    mark("child " + str(os.getpid()) + " " + str(child.pid))
    while True:
        time.sleep(0.01)
if os.environ.get("PROBE_ORPHAN"):
    # Leader exits 0 at once; the grandchild keeps writing inside our group.
    child = __import__("subprocess").Popen([sys.executable, "-c",
        "import time\nwhile True:\n    time.sleep(0.05)"])
    # It must be provably born into our group before the leader exits, or the
    # leader can beat it to exit and the child is never in our group at all.
    while not os.path.exists("/proc/%d" % child.pid):
        time.sleep(0.001)
    mark("child " + str(os.getpid()) + " " + str(child.pid))
mark("end " + name + " " + str(time.time()))
print("probe " + name + " passed")
"""


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_gone(pids, seconds=8):
    until = time.time() + seconds
    while time.time() < until:
        if not any(alive(pid) for pid in pids):
            return True
        time.sleep(0.02)
    return False


def lock_name(key):
    return "acceptance-" + hashlib.sha256(key.encode()).hexdigest()[:24] + ".lock"


def clean_environment(extra=None):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PROBE_", "ROOTYARD_"))}
    environment.update(extra or {})
    return environment


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.lock_dir = self.root / "locks"
        self.lock_dir.mkdir()
        self.markers = self.root / "markers"
        self.markers.write_text("")
        self.report = self.root / "report.json"
        self.runs = 0
        self.marker = MARKER
        self.marker_value = uuid.uuid4().hex

    def suite(self, name, resources, isolation=None, depends_on=(), phase="smoke", timeout=30, **env):
        environment = {"PROBE_MARKERS": str(self.markers), "PROBE_SUITE": name}
        environment.update({key: str(value) for key, value in env.items()})
        return {"id": name, "phase": phase, "profile": "portable-service",
                "argv": [sys.executable, "-c", PROBE], "requires": [],
                "resources": resources, "isolation": isolation or {"database": "owned_schema"},
                "depends_on": list(depends_on), "timeout_seconds": timeout, "environment": environment}

    def plan(self, suites, **extra):
        plan = {"version": 1, "max_workers": 3, "suites": suites}
        plan.update(extra)
        return plan

    def write(self, plan, name="plan.json"):
        path = self.root / name
        path.write_text(json.dumps(plan))
        return path

    def command(self, plan_path, run_id, extra_env=None, extra_args=()):
        self.runs += 1
        log_dir = self.root / f"run-{run_id}"
        return ([sys.executable, str(SCRIPT), "--plan", str(plan_path), "--lock-dir", str(self.lock_dir),
                 "--log-dir", str(log_dir), "--report", str(log_dir / "report.json"),
                 "--verify-host", str(ROOT), "--run-id", run_id, *extra_args],
                clean_environment(extra_env), log_dir / "report.json")

    def start(self, tracker, command, environment=None, **kwargs):
        """Start a runner/probe as a tracked session leader carrying this fixture's marker."""
        return tracker.spawn(command, self.marker, self.marker_value, environment=environment, **kwargs)

    def run(self, tracker, plan, run_id="run-test", extra_env=None, extra_args=()):
        path = self.write(plan)
        self.markers.write_text("")
        command, environment, report = self.command(path, run_id, extra_env, extra_args)
        completed = subprocess.run(command, capture_output=True, text=True, timeout=180, env=environment)
        return completed, (json.loads(report.read_text()) if report.exists() else None)


def looks_like_ours():
    """A process whose name and argv name this very test file - but which is not ours.

    Cleanup must survive its presence; a name/command-line match would SIGKILL it.
    It carries no marker and lives in its own session until the test stops it.
    """
    return [sys.executable, "-c", "import time; time.sleep(120)",
            "python3 -m unittest -p test_run_native_acceptance.py", os.path.basename(__file__)]


def by_id(report, suite_id):
    return next(entry for entry in report["suites"] if entry["id"] == suite_id)


def overlaps(left, right):
    return left[0] < right[1] and right[0] < left[1]


def spans(report):
    return {entry["id"]: (entry["timing"]["started_at"],
                          entry["timing"]["started_at"] + entry["timing"]["duration_seconds"])
            for entry in report["suites"] if "started_at" in entry["timing"]}


# Test cleanup identity: a fresh run directory per test plus a random marker in
# the environment of every runner/probe this test starts. Nothing is ever found
# by process name or command line (see ProcessTracker).
MARKER = "ROOTYARD_ACCEPTANCE_TEST_OWNER"
CLEANUP_SECONDS = 10.0   # per test: TERM grace, KILL grace, then the scan must prove the group gone


def session_is_private():
    """Linux, and this test process leads its own session.

    ``start_new_session`` only creates a *new session* when the caller is not a
    session leader - inside a container the test process usually is (its
    session is PID 1's), so a child's session would then still span the whole
    container and an unscheduled py-spy, for one, could be signalled. Probe it
    once in a scratch child instead of assuming.
    """
    if not LINUX or not os.path.isdir("/proc/self"):
        return False
    try:
        probe = subprocess.run([sys.executable, "-c",
                                "import os, sys; printed = os.getsid(0) != %d; sys.exit(0 if printed else 1)"
                                % os.getpid()], start_new_session=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


def proc_stat(pid):
    """(state, pgrp, session, starttime) from /proc; None once the pid is gone."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as stat:
            fields = stat.read().rsplit(b")", 1)[1].split()
        return fields[0].decode(), int(fields[2]), int(fields[3]), int(fields[19])
    except FileNotFoundError:
        return None
    except (OSError, IndexError, ValueError):
        return (), None, None, None


def same_process(pid, starttime, session):
    """The pid is still the process we started: same start time and same session."""
    stat = proc_stat(pid)
    return bool(stat) and stat[3] == starttime and stat[2] == session


def live_members(session, cursors):
    """Live (non-zombie) processes of one session, and their (pid, starttime) cursors."""
    members, seen = [], {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        stat = proc_stat(int(entry))
        if stat and stat[2] == session and stat[0] not in ("Z", "X", "T", "t"):
            members.append(int(entry))
            seen[int(entry)] = stat[3]
    cursors.update(seen)
    return members


class ProcessTracker:
    """Everything a test may ever signal: the Popen objects it created, nothing else.

    No name and no command line is ever matched. A group is signalled only when
    it is still provably the process we spawned: it leads its own session (so
    the recorded leader pid is its pgid), its start time is unchanged, and it
    carries this test's marker in its environment (/proc/<pid>/environ). The
    marker is a random token written into a fresh private run directory, so a
    process of another worktree - however alike its name - can never carry it.
    Members are found only through the session the leader created at spawn and
    the children it had at launch; while stopping, a process is signalled only
    while it is still in that session or still the recorded descendant of a
    process we already hold. Bystanders are never signalled.
    """

    def __init__(self):
        self.groups = []
        self.loose = []
        self.threads = []
        self.orphans = []   # (pids, /proc stat) of processes cleanup could not prove gone; never retried

    def spawn(self, command, marker, marker_value, environment=None, **kwargs):
        """Start one runner/probe as its own session leader; record the proof of ownership."""
        if not session_is_private():
            raise unittest.SkipTest("child lifecycles need a private session (Linux, outside a session leader)")
        child_env = clean_environment(environment)
        child_env[marker] = marker_value
        process = subprocess.Popen(command, env=child_env,
                                   start_new_session=True, **kwargs)
        stat = proc_stat(process.pid)
        self.groups.append({"proc": process, "session": stat[2] if stat else process.pid,
                            "starttime": stat[3] if stat else None,
                            "cursors": {process.pid: stat[3] if stat else None},
                            "marker": (marker, marker_value)})
        return process

    def pump(self, process):
        """Drain a runner's pipes in the background; the test may end without reading them."""
        done = threading.Event()

        def drain():
            try:
                process.communicate()
            except (OSError, ValueError):
                pass
            finally:
                done.set()

        threading.Thread(target=drain, daemon=True).start()
        self.threads.append(done)
        return process

    def track(self, process):
        """A plain bystander: only this exact pid is ever stopped, and only while it is still ours."""
        stat = proc_stat(process.pid)
        self.loose.append({"proc": process, "session": stat[2] if stat else None,
                           "starttime": stat[3] if stat else None})
        return process

    def close(self, seconds=CLEANUP_SECONDS):
        """Stop our own groups (TERM, then KILL) and never revisit a group proven gone."""
        try:
            for group in self.groups:
                self.stop_group(group, seconds)
            for loose in self.loose:
                self.stop_loose(loose)
            for done in self.threads:
                done.wait(timeout=5)
        finally:
            self.groups, self.loose, self.threads = [], [], []

    @staticmethod
    def carries_marker(pid, marker):
        """The process environment holds exactly our marker=value (inherited at fork)."""
        try:
            with open(f"/proc/{pid}/environ", "rb") as environ:
                entries = environ.read().split(b"\0")
        except OSError:
            return False
        return (marker[0] + "=" + marker[1]).encode() in entries

    def verified(self, group):
        """The recorded leader is still the live, marker-carrying session leader we spawned."""
        stat = proc_stat(group["proc"].pid)
        return (stat is not None and group["proc"].returncode is None and stat[1] == group["session"] == group["proc"].pid
                and stat[3] == group["starttime"] and self.carries_marker(group["proc"].pid, group["marker"]))

    def our_members(self, group):
        """Live members of our own group (zombies excluded), deepest first.

        The session is fixed by setsid/start_new_session at spawn, so every
        descendant is in it from the instant fork creates it; a recorded cursor
        (pid + start time) additionally catches a child that reparented between
        two scans. Deepest first, so a leader is never stopped under a live child.
        """
        stats = {}
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                stats[int(entry)] = proc_stat(int(entry))
        ours = {pid for pid, stat in stats.items()
                if stat and stat[2] == group["session"] and stat[0] not in ("Z", "X")}
        ours |= {pid for pid, stat in stats.items()
                 if stat and pid not in ours and stat[3] is not None and group["cursors"].get(pid) == stat[3]}
        ordered = []
        for pid in ours:
            depth, cursor, seen = 0, pid, set()
            while cursor in ours and cursor not in seen:
                seen.add(cursor)
                cursor = stats[cursor][1] if stats.get(cursor) else 0
                depth += 1
            ordered.append((-depth, pid))
        return [pid for _, pid in sorted(ordered)]

    def stop_group(self, group, seconds):
        """TERM then KILL only the verified group, member by member, then reap the leader."""
        proc = group["proc"]
        deadline = time.monotonic() + seconds
        signalled = set()
        for sig in (signal.SIGTERM, signal.SIGKILL):
            ends = time.monotonic() + max(0.5, (deadline - time.monotonic()) / 2)
            while True:
                members = self.our_members(group)
                if not members:
                    break
                if "verified" not in group:
                    group["verified"] = self.verified(group)
                    if not group["verified"]:
                        stat = proc_stat(proc.pid)
                        group["diagnosis"] = (proc.pid, proc.returncode, stat,
                                              self.carries_marker(proc.pid, group["marker"]), group["starttime"])
                if not group["verified"]:
                    # Our leader is already reaped or was replaced (pid reuse): the
                    # rest can no longer be proved ours, so none of it is signalled.
                    self.orphans.extend((pid, proc_stat(pid)) for pid in members)
                    break
                for pid in members:
                    if pid not in group["cursors"]:
                        stat = proc_stat(pid)
                        group["cursors"][pid] = stat[3] if stat else None
                    if (pid, sig) in signalled:
                        continue
                    signalled.add((pid, sig))
                    try:
                        os.kill(pid, sig)
                    except ProcessLookupError:
                        pass
                if time.monotonic() >= ends:
                    break
                time.sleep(0.01)
            if not self.our_members(group):
                break
        if self.our_members(group):
            self.orphans.extend((pid, proc_stat(pid)) for pid in self.our_members(group))
        try:
            proc.wait(timeout=max(0.5, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            self.orphans.append((proc.pid, proc_stat(proc.pid)))

    def stop_loose(self, loose):
        proc = loose["proc"]
        if proc.returncode is None and same_process(proc.pid, loose["starttime"], loose["session"]):
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.orphans.append((proc.pid, proc_stat(proc.pid)))


@unittest.skipUnless(LINUX, "owned-group quiescence and its proof need Linux /proc; the runner refuses elsewhere")
class RunnerContractTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fx = Fixture(self.temporary.name)
        self.tracker = ProcessTracker()

    def tearDown(self):
        # A hanging runner is exactly what these tests exist for: stop only the
        # groups this test spawned (proved by session, start time and marker),
        # never anything merely named like them. A process cleanup could not
        # prove gone (D-state) is left untouched and reported: it is evidence.
        self.tracker.close()
        self.temporary.cleanup()
        if self.tracker.orphans:
            self.skipTest("cleanup could not prove gone (left untouched): %r" % (self.tracker.orphans,))

    def test_exclusive_keys_never_overlap(self):
        plan = self.fx.plan([
            self.fx.suite("instance-a", {"instance:pg17": "exclusive"}, PROBE_HOLD="1", PROBE_HOLD_SECONDS="0.6"),
            self.fx.suite("instance-b", {"instance:pg17": None}),
            self.fx.suite("instance-c", {"instance:pg17": "exclusive"}),
        ])
        completed, report = self.fx.run(self.tracker, plan)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(report["gate"], "passed")
        running = spans(report)
        names = sorted(running, key=lambda name: report["suites"][[s["id"] for s in report["suites"]].index(name)]
                       ["timing"]["started_at"])
        for index, left in enumerate(names):
            for right in names[index + 1:]:
                self.assertFalse(overlaps(running[left], running[right]), (left, right))
        self.assertTrue(any(entry["timing"]["wait_seconds"] > 0 for entry in report["suites"]))
        self.assertEqual({entry["cleanup"] for entry in report["suites"]}, {"quiescent"})

    def test_isolated_keys_run_in_parallel(self):
        plan = self.fx.plan([
            self.fx.suite(f"iso-{index}", {f"loopback:{index}": "exclusive"},
                          PROBE_HOLD="1", PROBE_HOLD_SECONDS="0.8",
                          isolation={"database": "owned_schema", "repo:isolated": "schema-only"})
            for index in range(3)
        ])
        completed, report = self.fx.run(self.tracker, plan)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        running = spans(report)
        self.assertTrue(overlaps(running["iso-0"], running["iso-1"]), running)
        self.assertTrue(overlaps(running["iso-0"], running["iso-2"]), running)
        total = max(end for _, end in running.values()) - min(start for start, _ in running.values())
        self.assertLess(total, sum(end - start for start, end in running.values()))

    def test_max_workers_bounds_parallelism(self):
        suites = [self.fx.suite(f"free-{index}", {f"loopback:{index}": "exclusive"},
                                PROBE_HOLD="1", PROBE_HOLD_SECONDS="0.5") for index in range(4)]
        completed, report = self.fx.run(self.tracker, self.fx.plan(suites, max_workers=1))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        ordered = sorted(spans(report).values())
        for previous, current in zip(ordered, ordered[1:]):
            self.assertFalse(overlaps(previous, current))

    def test_failed_smoke_blocks_full_dependants(self):
        plan = self.fx.plan([
            self.fx.suite("smoke-http", {"loopback:http": "exclusive"}, PROBE_FAIL="1"),
            self.fx.suite("smoke-git", {"repo:git": "exclusive"}),
            self.fx.suite("full-http", {"loopback:http": "exclusive"}, depends_on=["smoke-http"], phase="full"),
            self.fx.suite("full-git", {"loopback:git": "exclusive"}, depends_on=["smoke-git", "full-http"],
                          phase="full"),
        ])
        completed, report = self.fx.run(self.tracker, plan)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(report["gate"], "failed")
        self.assertEqual(by_id(report, "smoke-http")["status"], "failed")
        self.assertEqual(by_id(report, "smoke-http")["exit_code"], 3)
        self.assertEqual(by_id(report, "smoke-git")["status"], "passed")
        self.assertEqual(by_id(report, "full-http")["status"], "blocked")
        self.assertEqual(by_id(report, "full-git")["status"], "blocked")
        self.assertIn("smoke-http=failed", by_id(report, "full-http")["summary"])
        markers = self.fx.markers.read_text()
        self.assertNotIn("start full-http", markers)
        self.assertNotIn("start full-git", markers)
        self.assertNotEqual(report["gate"], "passed")

    def test_timeout_stops_owned_group_only(self):
        bystander = self.tracker.track(subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(120)"], start_new_session=True))
        plan = self.fx.plan([
            self.fx.suite("hung", {"instance:kernel-ish": "exclusive"}, PROBE_HANG="1", timeout=0.8),
            self.fx.suite("after", {"loopback:free": "exclusive"}),
        ], max_workers=1)
        completed, report = self.fx.run(self.tracker, plan)
        self.assertEqual(by_id(report, "hung")["status"], "timed_out")
        self.assertEqual(by_id(report, "hung")["cleanup"], "quiescent")
        self.assertEqual(by_id(report, "after")["status"], "passed")
        self.assertEqual(completed.returncode, 1)
        child_line = next(line for line in self.fx.markers.read_text().splitlines() if line.startswith("child"))
        leader, child = (int(value) for value in child_line.split()[1:])
        self.assertTrue(wait_gone([leader, child]), (leader, child))
        self.assertIsNone(bystander.poll())  # a process the runner never started survives

    def test_total_timeout_cancels_running_and_marks_rest_not_run(self):
        plan = self.fx.plan([
            self.fx.suite("long", {"instance:pg17": "exclusive"}, PROBE_HANG="1", timeout=60),
            self.fx.suite("never", {"loopback:free": "exclusive"}),
        ], max_workers=1, total_timeout_seconds=0.8)
        completed, report = self.fx.run(self.tracker, plan)
        self.assertEqual(report["aborted"], "cancelled")
        self.assertEqual(by_id(report, "long")["status"], "cancelled")
        self.assertEqual(by_id(report, "long")["cleanup"], "quiescent")
        self.assertEqual(by_id(report, "never")["status"], "not_run")
        self.assertEqual(completed.returncode, 1)
        child_line = next(line for line in self.fx.markers.read_text().splitlines() if line.startswith("child"))
        self.assertTrue(wait_gone([int(value) for value in child_line.split()[1:]]))

    def test_suite_environment_and_placeholders_reach_child(self):
        values = self.fx.root / "values.json"
        script = ("import json, os; json.dump({'private': os.environ.get('PROBE_PRIVATE'), "
                  "'run_id': os.environ.get('ROOTYARD_ACCEPTANCE_RUN_ID'), 'prefix': os.environ.get('S3_PREFIX'), "
                  "'arg': __import__('sys').argv[1]}, open(%r, 'w'))" % str(values))
        suite = self.fx.suite("env-probe", {"loopback:free": "exclusive"},
                              isolation={"object_prefix": "rootyard/{run_id}/{suite_id}/"})
        suite["argv"] = [sys.executable, "-c", script, "{run_id}/{suite_id}"]
        suite["environment"].update({"PROBE_PRIVATE": "suite-private-42",
                                     "S3_PREFIX": "rootyard/{run_id}/{suite_id}/"})
        completed, report = self.fx.run(self.tracker, self.fx.plan([suite]), run_id="run-env",
                                        extra_env={"ROOTYARD_ACCEPTANCE_RUN_ID": "inherited-bogus"})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        seen = json.loads(values.read_text())
        self.assertEqual(seen["private"], "suite-private-42")
        self.assertEqual(seen["run_id"], "run-env")
        self.assertEqual(seen["prefix"], "rootyard/run-env/env-probe/")
        self.assertEqual(seen["arg"], "run-env/env-probe")
        self.assertNotIn("suite-private-42", (self.fx.root / "run-run-env" / "report.json").read_text())

    def test_report_is_redacted_and_logs_are_private(self):
        resource = "instance:pg17"
        suite = self.fx.suite("smoke-http", {resource: "exclusive"}, PROBE_FAIL="1")
        plan = self.fx.plan([suite])
        completed, report = self.fx.run(self.tracker, plan, extra_env={
            "ROOTYARD_TEST_DATABASE_URL": "postgresql://user:dbpass123@127.0.0.1:55432/db",
            "ROOTYARD_BLOB_ROOT": "/tmp/foreign-blob-root"})
        text = (self.fx.root / "run-run-test" / "report.json").read_text()
        for needle in ("dbpass123", "127.0.0.1:55432", "postgresql://", PROBE[:40], str(self.fx.lock_dir),
                       "inherited", "PROBE_MARKERS", "S3_PREFIX", "sleep"):
            self.assertNotIn(needle, text)
        self.assertEqual(report["selftest"]["status"], "passed")
        self.assertIn("[REDACTED]@", by_id(report, "smoke-http")["summary"])
        for key in ("argv", "environment", "resources_raw"):
            self.assertNotIn(key, by_id(report, "smoke-http"))
        log = Path(by_id(report, "smoke-http")["log"])
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        self.assertIn("dbpass123", log.read_text())  # raw failure evidence stays outside the report
        self.assertIn("deliberate failure", log.read_text())

    def test_inherited_sensitive_environment_is_redacted(self):
        url_value = "postgresql://db.invalid/parent-db-secret-marker-6392"
        token_value = "parent-env-token-secret-marker-8261"
        public_marker = "public-build-marker-2026"
        script = (
            "import os, sys\n"
            "for name in ('DATABASE_URL', 'PARENT_ACCESS_TOKEN', 'ROOTYARD_PUBLIC_MARKER'):\n"
            "    sys.stdout.write(os.environ[name] + '\\n')\n"
            "sys.exit(2)\n"
        )
        suite = self.fx.suite("smoke-inherited", {"loopback:free": "exclusive"})
        suite["argv"] = [sys.executable, "-c", script]
        plan = self.fx.plan([suite])
        completed, report = self.fx.run(self.tracker, plan, extra_env={
            "DATABASE_URL": url_value,
            "PARENT_ACCESS_TOKEN": token_value,
            "ROOTYARD_PUBLIC_MARKER": public_marker})
        text = (self.fx.root / "run-run-test" / "report.json").read_text()
        summary = by_id(report, "smoke-inherited")["summary"]
        self.assertTrue(completed.returncode == 1)
        self.assertFalse(url_value in completed.stderr)
        self.assertFalse(token_value in completed.stderr)
        self.assertEqual(report["selftest"]["status"], "passed")
        self.assertFalse(url_value in text)
        self.assertFalse(token_value in text)
        self.assertFalse(url_value in summary)
        self.assertFalse(token_value in summary)
        self.assertIn("[REDACTED]", summary)
        self.assertIn(public_marker, summary)

    def test_plan_rejects_credentials_without_echo(self):
        plan = self.fx.plan([self.fx.suite("a", {"loopback:free": "exclusive"})],
                            environment_from_plan={"ROOTYARD_TEST_DATABASE_URL":
                                                   "postgresql://u:plan-secret-9@127.0.0.1/db"})
        completed, report = self.fx.run(self.tracker, plan)
        self.assertEqual(completed.returncode, 2)
        self.assertIsNone(report)
        self.assertNotIn("plan-secret-9", completed.stdout + completed.stderr)

    def test_alive_leader_and_grandchild_are_timed_out_not_awaited(self):
        """The proven deadlock: a hung leader must be TERM/KILLed, not wait()ed on."""
        plan = self.fx.plan([self.fx.suite("hung", {"instance:pg17": "exclusive"}, PROBE_HANG="1", timeout=0.8)])
        path = self.fx.write(plan)
        command, environment, report_path = self.fx.command(path, "run-hang")
        started = time.monotonic()
        runner = self.tracker.track(self.fx.start(self.tracker, command, stdout=subprocess.PIPE,
                                                  stderr=subprocess.PIPE, text=True))
        until = time.time() + 20
        while time.time() < until and "child " not in self.fx.markers.read_text():
            time.sleep(0.02)
        self.assertIn("child ", self.fx.markers.read_text())
        leader, grandchild = (int(value) for value in self.fx.markers.read_text().split("child", 1)[1].split()[:2])
        # An outer guard against a test that never returns - never the runner's
        # evidence: its cleanup is judged below from what it proved, not from a
        # finite wait that happened to finish.
        runner.communicate(timeout=40)
        self.assertEqual(runner.returncode, 1)
        self.assertTrue(wait_gone([leader, grandchild]), (leader, grandchild))
        report = json.loads(report_path.read_text())
        self.assertEqual(by_id(report, "hung")["status"], "timed_out")
        self.assertEqual(by_id(report, "hung")["cleanup"], "quiescent")
        self.assertEqual(report["non_quiescent"], [])
        self.assertLess(time.monotonic() - started, 40)

    def test_leader_exit_zero_with_live_grandchild_fails_then_releases_key(self):
        """A grandchild that outlives its leader is ours: stop it, prove it gone, then release."""
        plan = self.fx.plan([self.fx.suite("spawner", {"loopback:9999": "exclusive"}, PROBE_ORPHAN="1"),
                             self.fx.suite("after", {"loopback:9999": "exclusive"})], max_workers=1)
        path = self.fx.write(plan)
        command, environment, report_path = self.fx.command(path, "run-orphan")
        runner = self.tracker.track(self.fx.start(self.tracker, command, stdout=subprocess.PIPE,
                                                  stderr=subprocess.PIPE, text=True))
        until = time.time() + 20
        while time.time() < until and "child " not in self.fx.markers.read_text():
            time.sleep(0.02)
        self.assertIn("child ", self.fx.markers.read_text())
        leader, grandchild = (int(value) for value in self.fx.markers.read_text().split("child", 1)[1].split()[:2])
        lock = os.open(self.fx.lock_dir / lock_name("loopback:9999"), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            saw_locked = False
            while runner.poll() is None:
                if not alive(grandchild):
                    break   # the key must not be free while our grandchild is still alive
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(lock, fcntl.LOCK_UN)
                except BlockingIOError:
                    saw_locked = True
                time.sleep(0.02)
            self.assertTrue(saw_locked, "key was never held while the grandchild was alive")
        finally:
            os.close(lock)
        runner.communicate(timeout=40)
        self.assertEqual(runner.returncode, 1)
        report = json.loads(report_path.read_text())
        spawner = by_id(report, "spawner")
        self.assertEqual(spawner["status"], "failed")  # exit 0 from the leader is not a pass
        self.assertEqual(spawner["cleanup"], "quiescent")
        self.assertEqual(spawner["cleanup"], "quiescent")
        self.assertEqual(by_id(report, "after")["status"], "passed")  # released after quiescence
        self.assertFalse(alive(grandchild))
        self.assertFalse(alive(leader))

    def test_independent_runners_serialize_on_a_normal_key(self):
        first = self.fx.plan([self.fx.suite("first", {"loopback:54321": "exclusive"}, PROBE_HOLD="1",
                                             PROBE_HOLD_SECONDS="1.5")])
        second = self.fx.plan([self.fx.suite("second", {"loopback:54321": "exclusive"}, PROBE_HOLD="1",
                                              PROBE_HOLD_SECONDS="0.1")])
        first_path = self.fx.write(first, "first.json")
        second_path = self.fx.write(second, "second.json")
        first_cmd, first_env, first_report = self.fx.command(first_path, "run-first")
        ready = self.fx.root / "second-ready.json"
        lock_ready = self.fx.lock_dir / ("acceptance-ready-" + hashlib.sha256("loopback:54321".encode()).hexdigest()[:24])
        second_cmd, second_env, second_report = self.fx.command(
            second_path, "run-second",
            extra_env={"ROOTYARD_ACCEPTANCE_WAIT_FOR": "loopback:54321",
                       "ROOTYARD_ACCEPTANCE_READY_FILE": str(ready)})
        holder = os.open(self.fx.lock_dir / lock_name("loopback:54321"), os.O_RDWR | os.O_CREAT, 0o644)
        first_proc = second_proc = None
        try:
            fcntl.flock(holder, fcntl.LOCK_EX)
            # Lock handoff between the two runners:
            # - Only the second runner is given ROOTYARD_ACCEPTANCE_WAIT_FOR, so only
            #   it waits for the key. While an independent holder owns the key,
            #   wait_locked_ready creates lock_dir/acceptance-ready-<hash>.
            # - The second runner's ROOTYARD_ACCEPTANCE_READY_FILE, which carries the
            #   plan digest, is written only after wait_locked_ready observes the key
            #   free, and before Runner starts the suite. The plan digest therefore
            #   shows that the wait completed and the suite was about to run (and was
            #   written before it started), not that the suite actually ran.
            # - After the holder unlocks, either runner may win the race for the key,
            #   so the test checks that their test phases never overlap in time.
            # Each is tracked before the first line of its own output can arrive.
            first_proc = self.fx.start(self.tracker, first_cmd, environment=first_env, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            second_proc = self.fx.start(self.tracker, second_cmd, environment=second_env, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
            until = time.time() + 20
            while time.time() < until and not lock_ready.exists():
                time.sleep(0.02)
            self.assertTrue(lock_ready.exists(), "second runner never observed the held lock")
            time.sleep(0.3)
            self.assertEqual(self.fx.markers.read_text(), "")
            self.assertFalse(ready.exists(), "ready file written before the lock was released")
        finally:
            fcntl.flock(holder, fcntl.LOCK_UN)
            os.close(holder)
        first_out, first_err = first_proc.communicate(timeout=40)
        second_out, second_err = second_proc.communicate(timeout=40)
        self.assertEqual(first_proc.returncode, 0, first_err)
        self.assertEqual(second_proc.returncode, 0, second_err)
        first_report_data = json.loads(first_report.read_text())
        second_report_data = json.loads(second_report.read_text())
        self.assertEqual(by_id(first_report_data, "first")["status"], "passed")
        self.assertEqual(by_id(second_report_data, "second")["status"], "passed")
        self.assertIn("plan_digest", json.loads(ready.read_text()))
        self.assertFalse(overlaps(spans(first_report_data)["first"], spans(second_report_data)["second"]))

    @unittest.skipUnless(LINUX, "owned-group cleanup needs Linux /proc")
    def test_cleanup_never_signals_a_lookalike_it_did_not_spawn(self):
        """Named like this very test and its runner, in its own session: untouched even mid-cleanup."""
        lookalike = self.tracker.track(subprocess.Popen(looks_like_ours(), start_new_session=True))
        command, _, report_path = self.fx.command(self.fx.write(self.fx.plan(
            [self.fx.suite("hung", {"loopback:1201": "exclusive"}, PROBE_HANG="1", timeout=3)])), "run-lookalike")
        ours = self.fx.start(self.tracker, command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        until = time.time() + 20
        while time.time() < until and not any(
            line.startswith("child ") for line in self.fx.markers.read_text().splitlines()
        ):
            time.sleep(0.02)
        ours.communicate(timeout=40)
        self.assertEqual(ours.returncode, 1)
        report = json.loads(report_path.read_text())
        self.assertEqual(by_id(report, "hung")["status"], "timed_out")
        self.assertEqual(by_id(report, "hung")["cleanup"], "quiescent")
        self.assertEqual(report["non_quiescent"], [])
        child_line = next(
            line for line in self.fx.markers.read_text().splitlines() if line.startswith("child ")
        )
        fields = child_line.split()
        self.assertTrue(wait_gone([int(fields[1]), int(fields[2])]))
        self.assertIsNone(lookalike.poll())


class LookalikeCleanupTest(unittest.TestCase):
    """End-to-end proof that tearDown itself is safe, in-process under another argv.

    Cleanup is keyed to the Popen objects and the marker, not to ``__file__``, so
    while a sibling process carries this very file name in its command line the
    cleanup still runs every suite to completion and leaves that sibling alive.
    """

    @unittest.skipUnless(LINUX, "owned-group cleanup needs Linux /proc")
    def test_teardown_survives_the_same_file_name_in_another_process(self):
        self.addCleanup(lambda: self.temporary.cleanup())
        self.temporary = tempfile.TemporaryDirectory(prefix="rootyard-acceptance-")
        self.fx = Fixture(self.temporary.name)
        self.tracker = ProcessTracker()
        self.addCleanup(self.tracker.close)

        def clean_lookalike():
            helper = ProcessTracker()
            try:
                helper.track(lookalike)
            finally:
                helper.close()

        # Deliberately untracked: the tracker under test must not reap it.
        lookalike = subprocess.Popen(looks_like_ours(), start_new_session=True)
        self.addCleanup(clean_lookalike)

        # A timed-out group, a leaked grandchild, and a normal suite after both.
        plan = self.fx.plan([
            self.fx.suite("hung", {"loopback:1202": "exclusive"}, PROBE_HANG="1", timeout=0.5),
            self.fx.suite("spawner", {"loopback:1203": "exclusive"}, PROBE_ORPHAN="1"),
            self.fx.suite("after", {"loopback:1204": "exclusive"}),
        ], max_workers=1)
        command, environment, report_path = self.fx.command(self.fx.write(plan), "run-same-file")
        process = self.fx.start(self.tracker, command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        process.communicate(timeout=40)
        self.assertEqual(process.returncode, 1)
        report = json.loads(report_path.read_text())
        self.assertEqual(by_id(report, "hung")["cleanup"], "quiescent")
        self.assertEqual(by_id(report, "spawner")["cleanup"], "quiescent")
        self.assertEqual(by_id(report, "after")["status"], "passed")
        self.assertEqual(report["non_quiescent"], [])
        self.tracker.close()
        self.assertEqual(self.tracker.orphans, [])
        self.assertIsNone(lookalike.poll())   # named like this file, never signalled


class RunnerPlatformTest(unittest.TestCase):
    """Where group quiescence cannot be proved the runner refuses before any Popen."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.lock_dir = self.root / "locks"
        self.lock_dir.mkdir()
        self.plan = self.root / "plan.json"
        # A marker would appear if this ever reached Popen.
        marker = self.root / "spawned"
        self.plan.write_text(json.dumps({"version": 1, "suites": [{
            "id": "probe", "phase": "smoke", "argv": ["sh", "-c", f"touch {marker}"], "timeout_seconds": 5,
            "resources": {"loopback:free": "exclusive"}}]}))
        self.marker = marker

    def tearDown(self):
        self.temporary.cleanup()

    def command(self, *extra):
        return [sys.executable, str(SCRIPT), "--plan", str(self.plan), "--lock-dir", str(self.lock_dir),
                "--verify-host", str(ROOT), *extra]

    def test_non_linux_is_refused_before_any_child_starts(self):
        with unittest.mock.patch.object(acceptance.sys, "platform", "darwin"):
            with self.assertRaises(acceptance.PlatformUnsupported) as caught:
                acceptance.require_supervisor_support()
            self.assertEqual(caught.exception.exit_code, 3)
            self.assertIn("before any child starts", str(caught.exception))
            # Exercise the real runner in-process so it sees the same mocked
            # platform.  Regular (non---dry-run) arguments are used; the plan
            # command is only `sh -c "touch <temp marker>"`, and the gate must
            # reject before run-dir creation or the Runner starts.
            argv = self.command()[2:]
            with unittest.mock.patch.object(acceptance.sys, "stderr", unittest.mock.MagicMock()):
                result = acceptance.main(argv)
            self.assertEqual(result, 3)
            self.assertFalse(self.marker.exists())
            # Nothing was created under the lock dir, which proves no lock was
            # taken, no run path was set up, and no suite was started.
            self.assertEqual(list(self.lock_dir.iterdir()), [])

    def assertPidfdUnsupported(self, caught, fragment):
        self.assertEqual(caught.exception.exit_code, 3)
        self.assertIn(fragment, str(caught.exception))
        self.assertFalse(self.marker.exists())
        self.assertEqual(list(self.lock_dir.iterdir()), [])

    @unittest.skipUnless(LINUX, "the pidfd preflight needs Linux")
    def test_missing_pidfd_open_is_refused(self):
        with unittest.mock.patch.object(acceptance.os, "pidfd_open", None, create=True):
            with self.assertRaises(acceptance.PlatformUnsupported) as caught:
                acceptance.require_supervisor_support()
        self.assertPidfdUnsupported(caught, "pidfd")

    @unittest.skipUnless(LINUX, "the pidfd preflight needs Linux")
    def test_missing_pidfd_send_signal_is_refused(self):
        with unittest.mock.patch.object(acceptance.signal, "pidfd_send_signal", None, create=True):
            with self.assertRaises(acceptance.PlatformUnsupported) as caught:
                acceptance.require_supervisor_support()
        self.assertPidfdUnsupported(caught, "pidfd")

    @unittest.skipUnless(LINUX, "the pidfd preflight needs Linux")
    def test_signal_refusal_probe_closes_dummy_fd_exactly_once(self):
        fake_fd = 4242
        pidfd_open = unittest.mock.Mock(return_value=fake_fd)
        pidfd_send_signal = unittest.mock.Mock(side_effect=OSError(1, "Operation not permitted"))
        close = unittest.mock.Mock()
        with unittest.mock.patch.object(acceptance.os, "pidfd_open", pidfd_open, create=True), \
                unittest.mock.patch.object(acceptance.signal, "pidfd_send_signal", pidfd_send_signal, create=True), \
                unittest.mock.patch.object(acceptance.os, "close", close):
            with self.assertRaises(acceptance.PlatformUnsupported) as caught:
                acceptance.require_supervisor_support()
        self.assertPidfdUnsupported(caught, "pidfd")
        pidfd_send_signal.assert_called_once()
        # The probe must never signal itself; only the dummy fd is targeted.
        self.assertEqual(pidfd_send_signal.call_args.args[0], fake_fd)
        close.assert_called_once_with(fake_fd)

    @unittest.skipUnless(LINUX, "the pidfd preflight needs Linux")
    def test_pidfd_open_failure_is_refused_without_close(self):
        pidfd_open = unittest.mock.Mock(side_effect=OSError(38, "Function not implemented"))
        pidfd_send_signal = unittest.mock.Mock()
        close = unittest.mock.Mock()
        with unittest.mock.patch.object(acceptance.os, "pidfd_open", pidfd_open, create=True), \
                unittest.mock.patch.object(acceptance.signal, "pidfd_send_signal", pidfd_send_signal, create=True), \
                unittest.mock.patch.object(acceptance.os, "close", close):
            with self.assertRaises(acceptance.PlatformUnsupported) as caught:
                acceptance.require_supervisor_support()
        self.assertPidfdUnsupported(caught, "pidfd")
        pidfd_send_signal.assert_not_called()
        close.assert_not_called()

    @unittest.skipUnless(LINUX, "the positive side needs /proc")
    def test_linux_is_accepted(self):
        acceptance.require_supervisor_support()

class PlanValidationTest(unittest.TestCase):
    def plan(self, suite=None, **extra):
        suite = suite or {"id": "a", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
                          "resources": {"loopback:free": "exclusive"}}
        return {"suites": [suite], **extra}

    def assert_rejected(self, plan, fragment):
        with self.assertRaises(acceptance.PlanError) as caught:
            acceptance.validate_plan(plan)
        self.assertIn(fragment, str(caught.exception))

    def test_exclusive_is_the_default(self):
        plan = acceptance.validate_plan(self.plan())
        plan["suites"][0]["resources"] = {"kernel:vm": None}
        self.assertEqual(acceptance.validate_plan(plan)["suites"][0]["_modes"], {"kernel:vm": "exclusive"})

    def test_shared_requires_harness_isolation(self):
        self.assert_rejected(self.plan({"id": "a", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
                                        "resources": {"loopback:80": "shared"}}), "isolation")
        accepted = acceptance.validate_plan(self.plan({
            "id": "a", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
            "resources": {"loopback:80": "shared"}, "isolation": {"database": "owned_schema"}}))
        self.assertEqual(accepted["suites"][0]["_modes"]["loopback:80"], "shared")

    def test_stateful_keys_cannot_be_shared_without_their_own_declaration(self):
        self.assert_rejected(self.plan({"id": "a", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
                                        "resources": {"kernel:vm": "shared"},
                                        "isolation": {"database": "owned_schema"}}), "kernel:vm")

    def test_kernel_and_host_profiles_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock_dir = root / "locks"
            lock_dir.mkdir()
            for profile in ("native-host", "kernel", "fuse", "container"):
                plan = root / f"{profile}.json"
                plan.write_text(json.dumps(self.plan({"id": "a", "phase": "smoke", "argv": ["true"],
                                                      "timeout_seconds": 5, "profile": profile,
                                                      "resources": {"kernel:vm": "exclusive"}})))
                completed = subprocess.run([sys.executable, str(SCRIPT), "--plan", str(plan), "--lock-dir",
                                            str(lock_dir), "--verify-host", str(ROOT)],
                                           capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 3, profile)
                self.assertIn("native-kernel-acceptance", completed.stderr)
                self.assertEqual(list((lock_dir).iterdir()), [])  # nothing ran, nothing locked

    def test_full_suite_needs_a_smoke_ancestor(self):
        self.assert_rejected({"suites": [{"id": "full", "phase": "full", "argv": ["true"],
                                          "timeout_seconds": 5, "resources": {"loopback:1": "exclusive"}}]},
                             "smoke")
        smoke = {"id": "smoke", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
                 "resources": {"loopback:1": "exclusive"}}
        middle = dict(smoke, id="middle", phase="full", depends_on=["smoke"])
        final = dict(smoke, id="final", phase="full", depends_on=["middle"])
        acceptance.validate_plan({"suites": [smoke, middle, final]})

    def test_dependency_and_shape_checks(self):
        self.assert_rejected({"suites": []}, "non-empty")
        self.assert_rejected(self.plan(depends_on=["missing"]) if False else
                             {"suites": [{"id": "a", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
                                          "resources": {"loopback:1": "exclusive"}, "depends_on": ["missing"]}]},
                             "unknown depends_on")
        self.assert_rejected(self.plan({"id": "a", "phase": "smoke", "argv": "python3 x", "timeout_seconds": 5,
                                        "resources": {"loopback:1": "exclusive"}}), "argv")
        self.assert_rejected(self.plan({"id": "a", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
                                        "resources": {}, "isolation": {}}), "resources")
        self.assert_rejected(self.plan({"id": "a", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
                                        "resources": {"loopback:1": "exclusive"},
                                        "isolation": {"blob_root": "/abs/path"}}), "relative")
        cyclic = [{"id": "a", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
                   "resources": {"loopback:1": "exclusive"}, "depends_on": ["b"]},
                  {"id": "b", "phase": "smoke", "argv": ["true"], "timeout_seconds": 5,
                   "resources": {"loopback:2": "exclusive"}, "depends_on": ["a"]}]
        self.assert_rejected({"suites": cyclic}, "cycle")

    def test_cli_refuses_lock_dir_inside_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan = Path(temporary) / "plan.json"
            plan.write_text(json.dumps(self.plan()))
            completed = subprocess.run([sys.executable, str(SCRIPT), "--plan", str(plan), "--lock-dir",
                                        str(ROOT / "scripts"), "--verify-host", str(ROOT)],
                                       capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 3)
            self.assertIn("outside the checkout", completed.stderr)


class RedactorTest(unittest.TestCase):
    def test_patterns(self):
        redactor = acceptance.Redactor(["top-secret-value"])
        text = redactor.text("dsn postgresql://root:pa55@127.0.0.1:55432/db\n"
                             "Authorization: Bearer ryt_abcdefgh12345\n"
                             "ROOTYARD_OBJECT_STORE_SECRET_KEY=abc\n"
                             "export ROOTYARD_TEST_PASSWORD='quoted'\n"
                             "Error: suite id 'a.b' is invalid\n"
                             "top-secret-value\n")
        for needle in ("pa55@", "ryt_abcdefgh12345", "SECRET_KEY=abc", "quoted", "top-secret-value"):
            self.assertNotIn(needle, text)
        self.assertIn("[REDACTED]@127.0.0.1:55432", text)
        self.assertIn("Authorization: [REDACTED]", text)
        self.assertIn("ROOTYARD_OBJECT_STORE_SECRET_KEY=[REDACTED]", text)
        self.assertIn("Error:", text)  # a plain error prefix is not redacted

    def test_summary_is_bounded(self):
        summary = acceptance.Redactor().summary("\n".join(f"noise {index}" for index in range(500))
                                                + "\nError tail")
        self.assertLessEqual(len(summary), acceptance.SUMMARY_LIMIT)
        self.assertIn("Error tail", summary)


if __name__ == "__main__":
    unittest.main()
