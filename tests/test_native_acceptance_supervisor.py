#!/usr/bin/env python3
"""Real Linux process tests for scripts/native_acceptance_supervisor.py.

The harness mirrors the future runner: it flocks one resource file EX and
another SH (both passed with ``pass_fds``; the supervisor never unlocks them),
plus a dedicated parent-control pipe (parent write -> supervisor read) and a
separate status pipe (supervisor write -> parent read).  These helpers read
/proc for their own inspection only; the supervisor is never mocked.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "native_acceptance_supervisor.py"
LINUX = sys.platform.startswith("linux") and os.path.isdir("/proc/self")
sys.path.insert(0, str(ROOT / "scripts"))
import native_acceptance_supervisor as boss  # noqa: E402

FAST = {"NATIVE_ACCEPTANCE_SUPERVISOR_GRACE": "0.2",
        "NATIVE_ACCEPTANCE_SUPERVISOR_PROGRESS": "0.05"}
TREE_CLI = r"""
import json, os, signal, sys, time
spec = json.loads(sys.argv[1])
signal.signal(signal.SIGTERM, signal.SIG_IGN)  # only SIGKILL stops these servers
with open(spec["report"], "w") as f:
    own = f.fileno()
    json.dump({"pid": os.getpid(),
               "fds": [fd for fd in range(3, 4096)
                       if fd != own and os.path.exists("/proc/self/fd/%d" % fd)]}, f)
if not spec.get("no_children"):
    for _ in range(2):  # two servers, each setsid'd and double-forked out of the tree
        if os.fork() == 0:
            os.setsid()
            if os.fork():
                os._exit(0)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(120)
            os._exit(0)
time.sleep(spec.get("run", 120))
sys.exit(spec.get("exit", 0))
"""


def proc(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            tail = f.read().rsplit(b")", 1)[-1].split()
        return int(tail[1]), tail[0] not in (b"Z", b"X", b"x"), int(tail[19])
    except FileNotFoundError:
        return None


def cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read()
    except OSError:
        return b""


def descendants(pid):
    table = {int(p): s for p in os.listdir("/proc") if p.isdigit() and (s := proc(int(p)))}
    seen, frontier = set(), [pid]
    while frontier:
        current = frontier.pop()
        kids = [p for p, (pp, _, _) in table.items() if pp == current]
        seen.update(p for p in kids if p in table and table[p][1])
        frontier.extend(kids)
    return {p for p in seen if p in table and table[p][1]}


def live(pid):
    state = proc(pid)
    return state is not None and state[1]


@unittest.skipUnless(LINUX, "needs Linux /proc, flock and PR_SET_CHILD_SUBREAPER")
class SupervisorTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="supervisor-test-"))
        self.ex_path = self.dir / "resource-ex"
        self.sh_path = self.dir / "resource-sh"
        self.resources = []
        self.resources_held = False
        self.inodes = []
        self.acquire_resources()
        self.script = self.dir / "cli.py"
        self.script.write_text(TREE_CLI)
        self.seen = self.dir / "seen.json"
        self.buffer = b""
        self.proc = self.control = self.status = None

    def acquire_resources(self):
        """Open and flock both resource files, keeping integer fds."""
        if self.resources_held:
            return
        ex_fd = os.open(self.ex_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(ex_fd, fcntl.LOCK_EX)
            sh_fd = os.open(self.sh_path, os.O_RDWR | os.O_CREAT, 0o600)
        except BaseException:
            os.close(ex_fd)
            raise
        try:
            fcntl.flock(sh_fd, fcntl.LOCK_SH)
        except BaseException:
            os.close(ex_fd)
            os.close(sh_fd)
            raise
        self.resources = [ex_fd, sh_fd]
        self.inodes = [os.fstat(fd).st_ino for fd in self.resources]
        self.resources_held = True

    def close_resource_copies(self):
        """Close parent fd copies without LOCK_UN; call at most once."""
        if not self.resources_held:
            return
        self.resources_held = False
        for fd in self.resources:
            try:
                os.close(fd)
            except OSError:
                pass
        self.resources = []

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        for pid in descendants(os.getpid()):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.close_resource_copies()
        for fd in (self.control, self.status):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        shutil.rmtree(self.dir, ignore_errors=True)

    def start(self, spec, timeout=60, control=True):
        self.acquire_resources()
        cr, cw = os.pipe()  # parent-control: writer here, reader in supervisor
        sr, sw = os.pipe()  # status: writer in supervisor, reader here
        args = [sys.executable, str(self.script), json.dumps(spec)]
        fds = []
        for fd in self.resources:
            fds += ["--resource-fd", str(fd)]
        self.proc = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--timeout", str(timeout)] + fds
            + ["--parent-control-fd", str(cr), "--status-fd", str(sw), "--"] + args,
            pass_fds=[cr, sw] + self.resources, stdin=subprocess.DEVNULL,
            env={**os.environ, **FAST})
        os.close(cr)
        os.close(sw)
        self.control, self.status = cw, sr
        if not control:
            os.close(cw)
            self.control = None

    def next_frame(self, timeout=60):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.status], [], [], left)[0]:
                self.fail("no status frame")
            chunk = os.read(self.status, 65536)
            if not chunk:
                self.fail(f"status pipe closed without quit; {self.proc.wait(5)!r}")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def quit(self):
        frames = [self.next_frame()]
        while frames[-1]["event"] != "quit":
            frames.append(self.next_frame())
        self.assertEqual(frames[0]["event"], "ready")  # ready precedes everything
        self.assertEqual([f["event"] for f in frames].count("quit"), 1)
        return frames

    def wait_until(self, check, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(0.02)
        self.fail("condition not reached")

    def locked(self, path):
        probe = os.open(path, os.O_RDWR)
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        else:
            return False
        finally:
            os.close(probe)

    def servers(self, exclude=()):
        """Live double-forked CLI servers reparented away from the supervisor."""
        tag = str(self.script).encode()
        skip = {os.getpid(), *(exclude or ())}
        if self.proc is not None and self.proc.pid in skip:
            skip.add(self.proc.pid)
        found = set()
        for pid in descendants(self.proc.pid):
            if pid in skip or not live(pid):
                continue
            if tag in cmdline(pid).split(b"\0"):
                found.add(pid)
        return found

    def report(self):
        def complete():
            try:
                return isinstance(json.loads(self.seen.read_text()), dict)
            except (FileNotFoundError, ValueError):
                return False
        self.wait_until(complete, timeout=15)
        return json.loads(self.seen.read_text())

    def test_flock_resource_held_through_setsid_descendant(self):
        self.start({"report": str(self.seen)}, timeout=20)
        seen = self.report()
        # CLOEXEC: the CLI saw no resource/control/status descriptor at all
        self.assertEqual(seen["fds"], [])
        # two servers escaped via setsid/double-fork: distinct sessions, not leader's
        self.wait_until(lambda: len(self.servers(exclude=(seen["pid"],))) == 2)
        escapes = self.servers(exclude=(seen["pid"],))
        leader_sid = os.getsid(seen["pid"])
        sessions = {os.getsid(pid) for pid in escapes}
        self.assertEqual(len(sessions), 2)
        self.assertNotIn(leader_sid, sessions)
        # equal to the creating harness process: drop parent copies, locks persist
        # through the supervisor's inherited fds only
        self.close_resource_copies()
        self.assertTrue(self.locked(self.ex_path))
        self.assertTrue(self.locked(self.sh_path))
        frame = self.quit()[-1]  # drain the final status before waiting on self.proc
        self.assertEqual(frame["cleanup"], "quiescent")
        self.assertEqual(frame["reason"], "timeout")
        self.assertEqual(frame["leader_exit"], -signal.SIGKILL)
        self.assertTrue(frame["resources_closed"])
        self.assertEqual(self.proc.wait(10), 3)
        self.assertFalse(self.locked(self.ex_path))
        self.assertFalse(self.locked(self.sh_path))
        self.assertEqual(self.servers(), set())

    def test_timeout_and_control_eof_clean_tree_and_preserve_leader(self):
        for mode in ("timeout", "eof"):
            with self.subTest(mode=mode):
                self.seen.unlink(missing_ok=True)
                self.acquire_resources()
                self.start({"report": str(self.seen)},
                           timeout=1 if mode == "timeout" else 20, control=True)
                self.report()
                if mode == "eof":
                    time.sleep(0.3)  # let the double-forks escape, then cancel
                    if self.control is not None:
                        os.close(self.control)
                        self.control = None
                    reason = "parent-control-eof"
                else:
                    reason = "timeout"
                frame = self.quit()[-1]
                self.assertEqual((frame["cleanup"], frame["reason"]), ("quiescent", reason))
                self.assertEqual(frame["leader_exit"], -signal.SIGKILL)
                self.assertGreaterEqual(frame["signals"]["TERM"], 1)
                self.assertGreaterEqual(frame["signals"]["KILL"], 3)  # leader + 2 servers
                self.assertTrue(frame["resources_closed"])
                self.assertEqual(self.proc.wait(10), 3)  # supervisor's own status
                self.assertEqual(self.servers(), set())
                self.assertEqual(descendants(self.proc.pid), set())
                # parent copies still open: probes stay blocked
                self.assertTrue(self.resources_held)
                self.assertTrue(self.locked(self.ex_path))
                self.assertTrue(self.locked(self.sh_path))
                self.close_resource_copies()
                self.assertFalse(self.locked(self.ex_path))
                self.assertFalse(self.locked(self.sh_path))
                for fd in (self.control, self.status):
                    if fd is not None:
                        os.close(fd)
                self.control = self.status = None  # pipes closed with this run

    def test_pidfd_signal_requires_matching_starttime(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(120)"],
            start_new_session=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            state = proc(child.pid)
            self.assertIsNotNone(state)
            supervisor = boss.Supervisor([sys.executable, "-c", "pass"], 10, [], -1, -1)
            supervisor.stop({child.pid: state[2] + 1}, signal.SIGKILL)
            self.assertTrue(live(child.pid))
            self.assertEqual(supervisor.signals["KILL"], 0)
            supervisor.stop({child.pid: state[2]}, signal.SIGKILL)
            self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
            self.assertEqual(supervisor.signals["KILL"], 1)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_nonzero_exit_and_unknown_census_never_quit_or_drop_fd(self):
        self.start({"report": str(self.seen), "run": 0.2, "exit": 7,
                    "no_children": True}, timeout=5)
        frame = self.quit()[-1]
        self.assertEqual((frame["cleanup"], frame["reason"]), ("quiescent", "cli-exit"))
        self.assertEqual(frame["leader_exit"], 7)  # not mistaken for success
        self.assertTrue(frame["resources_closed"])
        self.assertEqual(self.proc.wait(30), 3)  # supervisor never adopts CLI's code
        for name in ("control", "status"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

        # A supervisor subclass whose census can never see a stable /proc.  The
        # proxy must keep retrying without a final quit, without closing the
        # resource fds and without exiting.
        class Unknown(boss.Supervisor):
            def targets(self):
                raise boss.Ambiguous("injected")

        self.acquire_resources()
        resources = list(self.resources)  # integer parent resources before fork
        control_r, control_w = os.pipe()  # parent-control: writer here
        status_r, status_w = os.pipe()  # status: reader here
        proxy = None
        try:
            proxy = os.fork()
            if proxy == 0:
                os.close(control_w)
                os.close(status_r)
                control_fd = fcntl.fcntl(control_r, fcntl.F_DUPFD, 100)
                status_fd = fcntl.fcntl(status_w, fcntl.F_DUPFD, 102)
                os.close(control_r)
                os.close(status_w)
                os.set_inheritable(control_fd, True)
                os.set_inheritable(status_fd, True)
                for fd in resources:
                    os.set_inheritable(fd, True)
                boss.check(argparse.ArgumentParser(), 30, resources,
                           control_fd, status_fd)
                sup = Unknown([sys.executable, "-c", "import time; time.sleep(0.3)"],
                              30, resources, control_fd, status_fd)
                sup.main()
                os._exit(99)  # a normal return is a failure
            os.close(control_r)
            control_r = None
            os.close(status_w)
            status_w = None
            os.close(control_w)  # parent gone: EOF without a quit
            control_w = None
            self.close_resource_copies()  # no LOCK_UN; locks live in the proxy
            self.assertTrue(self.locked(self.ex_path))
            self.assertTrue(self.locked(self.sh_path))
            os.set_blocking(status_r, False)
            buf, frames = b"", []
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    frames.append(json.loads(line))
                    continue
                if (len(frames) >= 2 and {f["event"] for f in frames}
                        >= {"ready", "progress"}):
                    break
                if not select.select([status_r], [], [], 0.1)[0]:
                    continue
                chunk = os.read(status_r, 65536)
                self.assertTrue(chunk, "status pipe closed unexpectedly")
                buf += chunk
            # ready, then a progress frame while its census keeps failing
            self.assertEqual(frames[0]["event"], "ready")
            progress = [f for f in frames if f["event"] == "progress"]
            self.assertTrue(progress)
            self.assertTrue(all(f["ambiguity"] == "injected" for f in progress))
            self.assertNotIn("quit", {f["event"] for f in frames})
            # leader adopted + reaped (zombies included) while still ambiguous
            def leader_reaped():
                for name in os.listdir("/proc"):
                    if not name.isdigit():
                        continue
                    info = proc(int(name))
                    if info is not None and info[0] == proxy:
                        return False
                return True

            self.wait_until(leader_reaped)
            deadline = time.monotonic() + 0.1
            while time.monotonic() < deadline:
                if select.select([status_r], [], [], deadline - time.monotonic())[0]:
                    data = os.read(status_r, 65536)
                    self.assertTrue(data, "status pipe closed without quit")
                    frames += [json.loads(line) for line in data.splitlines()]
                if {f["event"] for f in frames} & {"quit"}:
                    break
            self.assertNotIn("quit", {f["event"] for f in frames})
            self.assertNotIn("unknown", {f.get("result") for f in frames})
            self.assertTrue(live(proxy))
            self.assertTrue(self.locked(self.ex_path))
            self.assertTrue(self.locked(self.sh_path))
        finally:
            for pid in sorted(descendants(proxy) if proxy else ()):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if proxy is not None:
                try:
                    os.kill(proxy, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(proxy, 0)
            for name, fd in (("control_r", control_r), ("control_w", control_w),
                             ("status_r", status_r), ("status_w", status_w)):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                locals()[name] = None
            control_r = control_w = status_r = status_w = None
            self.close_resource_copies()
        self.assertFalse(self.locked(self.ex_path))
        self.assertFalse(self.locked(self.sh_path))


if __name__ == "__main__":
    unittest.main()
