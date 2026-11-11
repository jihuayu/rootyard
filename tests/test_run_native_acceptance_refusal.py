#!/usr/bin/env python3
"""End-to-end pre-spawn refusal tests: real runner, real supervisor, real seccomp.

The supervisor's ``check()`` can refuse (pidfd, ``PR_SET_CHILD_SUBREAPER``,
``/proc``, descriptor checks) strictly before it sends ``ready`` and before it
forks the suite CLI. That is a bounded, fail-closed answer, not a hang and not a
pass: the supervisor writes exactly one fixed refusal frame and exits 3; the
runner accepts it only with the exact frame, status EOF and that exit, then
records the suite as an ordinary failed suite (``cleanup: not-started``,
``exit_code: null``, the fixed refusal summary), releases its own locks, writes
a final failed report and exits 1 -- never the supervisor's 3.

Nothing here is mocked. Each test writes a launcher that runs the real
``scripts/run_native_acceptance.py`` with ``sys.executable`` pointed, in that
runner interpreter only, at an executable wrapper; the runner itself keeps the
real interpreter for the plan's CLI. The runner starts the supervisor with
``sys.executable``, so the wrapper is that supervisor child: ``sys.argv[1]`` is
the real supervisor script, ``sys.argv[2:]`` its real arguments, and
``ROOTYARD_TEST_SECCOMP_MODE`` (inherited through the runner) picks the denial.
The wrapper imports the real ``native_acceptance_supervisor`` module, sets
``PR_SET_NO_NEW_PRIVS``, installs a four-instruction classic BPF seccomp filter
that denies exactly one native syscall with an errno, writes its evidence with
``os.write`` to its already-open stdout, and calls the real ``main(args)``.
The plan's CLI command writes a marker file if it ever starts; it never must.
No LD_PRELOAD, no fake supervisor or status frames, no pre-recorded evidence,
no privileges and no host or container policy: only the wrapper's own process
is filtered.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RUNNER = SCRIPTS / "run_native_acceptance.py"
SUPERVISOR = SCRIPTS / "native_acceptance_supervisor.py"
RESOURCE = "loopback:61337"
LINUX = sys.platform.startswith("linux") and os.path.isdir("/proc/self")

# Supported native syscall tables. Any other machine is skipped: the filter is
# only ever built for x86_64 or aarch64.
AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
SYSCALLS = {"x86_64": {"prctl": 157, "openat": 257},
            "aarch64": {"prctl": 167, "openat": 56}}
MACHINE = platform.machine().lower()
ARCH = "aarch64" if MACHINE in ("aarch64", "arm64") else MACHINE

# CLI exit code that means a refused/unstarted suite (ordinary failed suite).
REFUSAL_SUMMARY = ("suite not started: the supervisor refused its pre-spawn preflight "
                   "(reason preflight-failed) before forking the CLI; details are in the suite log")
BOUND_SECONDS = 30
TIMEOUT_SECONDS = 60

# The executable helper used only for the supervisor child of the runner.
# Arguments: SUPERVISOR --timeout ... --parent-control-fd ... --status-fd ...
#            -- [resource-fd ...] -- CLI ARG...
# The denial is chosen by the inherited environment, never by extra argv.
# Openat mode also demonstrates the lazy argparse import before install().
SUPERVISOR_WRAPPER = '''#!@PYTHON@
import argparse
import ctypes
import errno
import os
import struct
import sys

MODE = os.environ.get("ROOTYARD_TEST_SECCOMP_MODE")
SYS = @SYS_TABLE@
AUDIT_ARCH = @AUDIT_ARCH@
DENY = {"prctl": ("prctl", errno.EPERM), "openat": ("openat", errno.EACCES)}
NO_NEW_PRIVS = 38
SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
PR_SET_CHILD_SUBREAPER = 36
LD_W_ABS, JEQ_K, RET_K = 0x20, 0x15, 0x06
RET_ALLOW, RET_ERRNO = 0x7FFF0000, 0x00050000
INSN = struct.Struct("=HBBI")
Nr, Arch = 0, 4  # seccomp_data offsets
argv = sys.argv[1:]
# This file lives in a temporary directory, so the supervisor module is found
# next to the real supervisor script the runner passed as argv[0].
HERE = os.path.dirname(os.path.abspath(argv[0])) if argv else ""

if MODE not in DENY:
    os.write(1, ("wrapper: unsupported ROOTYARD_TEST_SECCOMP_MODE %r; skipping\\n" % (MODE,)).encode())
    sys.exit(77)

# The real supervisor module first: filtering a bare interpreter would deny the
# import's own file opens and prove nothing about the supervisor.
sys.path.insert(0, HERE)
import native_acceptance_supervisor as native
# argparse's help formatter imports shutil lazily (an openat of its .py), and
# the filter below denies that too. Preload exactly that lazy module and bind
# argparse's ``from shutil import get_terminal_size`` to it now; otherwise the
# PermissionError would surface before check() reaches the /proc census.
import shutil
argparse._shutil = shutil

mode_syscall, errno_code = DENY[MODE]
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte),
                ("k", ctypes.c_uint)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def install():
    # Four instructions: load the syscall number, jump to deny/allow on the
    # one denied number, and two terminal returns already in the parent's open
    # stdout/stderr descriptors only (nothing is created or written after this).
    code = [
        (LD_W_ABS, 0, 0, Nr),
        (JEQ_K, 0, 1, SYS[mode_syscall]),  # equal -> next insn (deny); else skip to allow
        (RET_K, 0, 0, RET_ERRNO | errno_code),
        (RET_K, 0, 0, RET_ALLOW),
    ]
    program = (SockFilter * len(code))(*[SockFilter(*insn) for insn in code])
    fprog = SockFprog(len(code), ctypes.cast(program, ctypes.POINTER(SockFilter)))
    if libc.prctl(NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
    if libc.prctl(SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(fprog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP(SECCOMP_MODE_FILTER)")


def say(text):
    os.write(1, ("supervisor-wrapper: " + text + "\\n").encode())


install()
# Direct evidence that the real call the supervisor makes is now denied; only
# afterwards does the real main() run so its own check() observes the same.
if MODE == "prctl":
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != -1 or ctypes.get_errno() != errno.EPERM:
        say("FAIL: PR_SET_CHILD_SUBREAPER was not denied with EPERM")
        sys.exit(70)
    say("evidence: prctl(PR_SET_CHILD_SUBREAPER) -> EPERM (errno %d)" % errno.EPERM)
else:
    try:
        os.scandir("/proc").close()
    except PermissionError as exc:
        if exc.errno != errno.EACCES:
            say("FAIL: /proc census got errno %d, not EACCES" % (exc.errno or -1))
            sys.exit(70)
        say("evidence: os.scandir('/proc') -> EACCES (errno %d)" % errno.EACCES)
    else:
        say("FAIL: openat on /proc was not denied")
        sys.exit(70)

# Keep argv[0] only for locating the module above; the real script's own
# entry point is main(sys.argv[1:]), so hand it just the supervisor arguments.
sys.exit(native.main(argv[1:]))
'''


def wrapper_text():
    return (SUPERVISOR_WRAPPER
            .replace("@PYTHON@", sys.executable)
            .replace("@SYS_TABLE@", repr(SYSCALLS[ARCH]))
            .replace("@AUDIT_ARCH@", hex(AUDIT_ARCH[ARCH])))


# Runs the real runner with sys.executable pointed at the wrapper in this
# interpreter only. Suite argv still holds the real interpreter, as written
# into the plan by the test.
LAUNCHER = '''\
import os, runpy, sys
wrapper, script = sys.argv[1], sys.argv[2]
sys.argv = sys.argv[2:]
sys.executable = wrapper
os.environ["ROOTYARD_TEST_SECCOMP_MODE"] = os.environ["REFUSAL_TEST_MODE"]
runpy.run_path(script, run_name="__main__")
'''

SUITE_CLI = """\
import os, sys
with open(os.environ["MARKER"], "w") as handle:
    handle.write("suite-cli-started")
sys.exit(0)
"""


def lock_path(lock_dir, key):
    return Path(lock_dir) / ("acceptance-" + hashlib.sha256(key.encode()).hexdigest()[:24] + ".lock")


def reacquire(path):
    """True when this process can take the exclusive key again (locks released)."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    except BlockingIOError:
        return False
    finally:
        os.close(fd)


@unittest.skipUnless(LINUX, "the runner and its supervisor are Linux-only")
@unittest.skipUnless(ARCH in AUDIT_ARCH, "the seccomp filter supports x86_64 and aarch64 only")
class PreSpawnRefusalTest(unittest.TestCase):
    """The supervisor refuses in check(); the runner reports an ordinary failure."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-refusal-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.lock_dir = self.root / "locks"
        self.lock_dir.mkdir()
        self.marker = self.root / "suite-cli-started"
        suite = self.root / "suite_cli.py"
        suite.write_text(SUITE_CLI)
        self.plan = self.root / "plan.json"
        self.plan.write_text(json.dumps({"version": 1, "suites": [{
            "id": "refused", "phase": "smoke", "profile": "portable-service",
            "argv": [sys.executable, str(suite)], "timeout_seconds": 20,
            "resources": {RESOURCE: "exclusive"},
            "environment": {"MARKER": str(self.marker)}}]}))
        self.run_dir = self.root / "run"
        self.report = self.run_dir / "report.json"
        self.log_path = self.run_dir / "logs" / "refused.log"

    def start_runner(self, mode):
        wrapper = self.root / "python"
        launcher = self.root / "launcher.py"
        wrapper.write_text(wrapper_text())
        wrapper.chmod(0o755)
        launcher.write_text(LAUNCHER)
        env = {key: value for key, value in os.environ.items() if not key.startswith("ROOTYARD_")}
        env["REFUSAL_TEST_MODE"] = mode
        process = subprocess.Popen(
            [sys.executable, str(launcher), str(wrapper), str(RUNNER), "--plan", str(self.plan),
             "--lock-dir", str(self.lock_dir), "--log-dir", str(self.run_dir),
             "--report", str(self.report), "--verify-host", str(ROOT), "--run-id", "run-refused"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=str(self.root),
            start_new_session=True)
        return process

    def run_runner(self, mode):
        """Run the owned runner session; a timeout kills only that test-owned group."""
        process = self.start_runner(mode)
        started = time.monotonic()
        try:
            stdout, stderr = process.communicate(timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            self.fail(f"{mode}: the runner did not return within {TIMEOUT_SECONDS}s")
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
        return process.returncode, stdout, stderr, time.monotonic() - started

    def refuse(self, mode):
        if mode == "openat":
            # Denying openat needs a readable /proc in the first place.
            self.assertTrue(os.listdir("/proc"), "openat denial needs a readable /proc")
        returncode, stdout, stderr, elapsed = self.run_runner(mode)
        log = self.log_path.read_text() if self.log_path.exists() else ""
        # No CLI ever ran: the marker is absent and no generic runner error appeared.
        self.assertFalse(self.marker.exists(), "the suite CLI started despite the refusal")
        self.assertNotIn("supervisor-wrapper: FAIL", log, log)
        self.assertNotIn("wrapper: unsupported", log, log)
        # The real filter denial and the supervisor diagnostic are in the private log. The
        # accepted refusal frame travels on Child's dedicated status pipe and is consumed by
        # the runner, so it is intentionally never logged.
        evidence = {"prctl": "supervisor-wrapper: evidence: prctl(PR_SET_CHILD_SUBREAPER) -> EPERM",
                    "openat": "supervisor-wrapper: evidence: os.scandir('/proc') -> EACCES"}[mode]
        self.assertIn(evidence, log, log)
        self.assertIn("supervisor refused:", log, log)
        # The runner returns bounded, as the runner's own failed-suite exit (1).
        self.assertLess(elapsed, BOUND_SECONDS)
        self.assertEqual(returncode, 1, f"{mode}: stdout={stdout!r} stderr={stderr!r} log={log!r}")
        self.assertIn("suite refused: failed", stderr)
        data = json.loads(stdout)  # stdout is the final rendered report
        self.assertEqual(data, json.loads(self.report.read_text()), "stdout != --report")
        self.assertEqual(data["gate"], "failed")
        self.assertEqual(data["selftest"]["status"], "passed")
        self.assertIsNone(data["aborted"])
        self.assertEqual(data["not_run"], [])
        (suite,) = data["suites"]
        self.assertEqual(suite["id"], "refused")
        self.assertEqual(suite["status"], "failed")
        self.assertEqual(suite["cleanup"], "not-started")
        self.assertIsNone(suite["exit_code"])
        self.assertEqual(suite["summary"], REFUSAL_SUMMARY)
        # Detailed diagnostics exist only in the private suite log.
        for public in (suite["summary"], stdout, self.report.read_text()):
            self.assertNotIn("supervisor refused:", public)
            self.assertNotIn(evidence, public)
            self.assertNotIn("PR_SET_CHILD_SUBREAPER", public)
        self.assertEqual(str(self.log_path), suite["log"])
        # The exact exclusive lock is reacquirable: no CLI and nothing else holds it.
        self.assertTrue(reacquire(lock_path(self.lock_dir, RESOURCE)), "exclusive lock still held")

    def test_prctl_set_child_subreaper_eperm_refused_before_spawn(self):
        self.refuse("prctl")

    def test_openat_denied_census_proc_refused_before_spawn(self):
        self.refuse("openat")


if __name__ == "__main__":
    unittest.main()
