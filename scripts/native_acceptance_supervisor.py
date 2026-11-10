#!/usr/bin/env python3
"""Small stdlib-only Linux child-subreaper supervisor for one CLI tree.

Protocol (every descriptor arrives already open from the parent)::

    --timeout SEC --resource-fd FD (repeatable) --parent-control-fd READ_FD
    --status-fd WRITE_FD -- CLI ARG...

``--resource-fd`` descriptors are held by the parent with ``flock`` (SH or
EX).  We only inherit and hold them open: never lock, unlock or write them,
and close our copies only once quiescence is *proven*; the parent unlocks
after it has consumed the final ``quit``.  ``--parent-control-fd`` is the read
end of a dedicated pipe: EOF (parent gone / cancel) is the only cancel-by-file
signal, never a regular file.  ``--status-fd`` is the write end of a separate
pipe and gets JSON lines: ``ready`` after /proc, PR_SET_CHILD_SUBREAPER and the
descriptor checks but before the CLI is forked, ``progress`` frames while
anything is stuck, then exactly one final ``quit`` with ``cleanup``, ``reason``,
``leader_exit`` (the exact CLI exit code, negative for a signal) and signal
counts.  The supervisor exits with its own status, never the CLI's, and never
0 without a quiescent quit.

Every child (setsid leaders, double-forked orphans) is adopted by this
subreaper and reaped by one single-threaded ``waitpid(-1, WNOHANG)`` owner.
Quiescence is ``ECHILD`` from that ``waitpid`` plus a subsequent descendant
census proving no live descendants.  Timeout, control EOF, SIGTERM/SIGINT or
leftovers after the CLI exits cancel: TERM the owned tree, KILL it after GRACE,
and keep reaping and rescanning until ECHILD and that one descendant census
prove no live descendants.
Only descendants of this supervisor (the PPID tree built from ``/proc``) are
signalled.  Every signal is delivered through a pidfd: after opening the pidfd
the ``/proc/<pid>/stat`` starttime identity is re-verified, and only that
pidfd is used -- never a raw PID, group or session.  A gone or mismatched
identity is skipped; there is no raw-PID (``os.kill``) fallback, and if pidfds
are unavailable or the identity is unknown nothing is signalled.  The CLI is
exec'd with the resource/control/status fds closed and all are CLOEXEC, so
nothing it spawns inherits them.  If census or quiescence stays unknown the
supervisor never final-quits, never closes the resources and never exits: it
keeps retrying (reporting progress) and holding them.
"""
import argparse
import ctypes
import fcntl
import json
import math
import os
import select
import signal
import stat
import sys
import time

GRACE = float(os.environ.get("NATIVE_ACCEPTANCE_SUPERVISOR_GRACE", "2.0"))
PROGRESS_EVERY = float(os.environ.get("NATIVE_ACCEPTANCE_SUPERVISOR_PROGRESS", "1.0"))
PR_SET_CHILD_SUBREAPER = 36
SUPERVISOR_EXIT = 3  # never the CLI's code, and never 0 without quiescence


class Ambiguous(Exception):
    """Ownership or liveness cannot be proven; stay non-quiescent."""


def census(me):
    """{pid: (ppid, dead, starttime)} from one /proc pass."""
    table = {}
    try:
        with os.scandir("/proc") as it:
            names = [e.name for e in it
                     if e.name.isdigit() and e.is_dir(follow_symlinks=False)]
        if str(me) not in names:
            raise Ambiguous("/proc census lacks the supervisor")
        for name in names:
            if name == str(me):
                continue  # we cannot validate ourselves; we never count as owned
            try:
                tail = stat_fields(name)
            except FileNotFoundError:
                continue  # exited between the directory scan and this read
            if len(tail) < 20:
                raise Ambiguous(f"/proc/{name}/stat truncated")
            table[int(name)] = (int(tail[1]), tail[0] in (b"Z", b"X", b"x"), int(tail[19]))
    except Ambiguous:
        raise
    except OSError as exc:  # /proc unreadable or changed under us
        raise Ambiguous(f"/proc: {exc}") from None
    except ValueError as exc:
        raise Ambiguous(f"/proc stat: {exc}") from None
    return table


def stat_fields(name):
    with open(f"/proc/{name}/stat", "rb") as f:
        return f.read().rsplit(b")", 1)[-1].split()


def owned_by(table, me):
    kids = {}
    for pid, (ppid, _, _) in table.items():
        kids.setdefault(ppid, []).append(pid)
    seen, frontier = set(kids.get(me, ())), list(kids.get(me, ()))
    while frontier:
        for child in kids.get(frontier.pop(), ()):
            if child not in seen:
                seen.add(child)
                frontier.append(child)
    return {pid: table[pid][2] for pid in seen if not table[pid][1]}


def still(pid, start):
    """True/False for one PID + starttime identity; None if /proc cannot answer."""
    try:
        tail = stat_fields(pid)
        return tail[0] not in (b"Z", b"X", b"x") and int(tail[19]) == start
    except FileNotFoundError:
        return False
    except (OSError, ValueError, IndexError):
        return None


def pidfd_api():
    return (getattr(os, "pidfd_open", None), getattr(signal, "pidfd_send_signal", None))


def cli_code(status):
    if status is None:
        return 0
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128


class Supervisor:
    def __init__(self, cli, timeout, resource_fds, control, status):
        self.cli, self.timeout = cli, timeout
        self.control, self.status = control, status
        self.resources = list(dict.fromkeys(resource_fds))
        self.me = os.getpid()
        self.cli_pid = self.cli_status = self.reason = None
        self.status_unavailable = False
        self.signals = {"TERM": 0, "KILL": 0, f"signal-{signal.SIGINT}": 0,
                        f"signal-{signal.SIGTERM}": 0}
        self.deadline = time.monotonic() + timeout

    def frame(self, **fields):
        if self.status_unavailable:
            return
        fields["supervisor_pid"] = self.me
        data = json.dumps(fields, sort_keys=True).encode() + b"\n"
        try:
            while data:
                data = data[os.write(self.status, data):]
        except (BrokenPipeError, OSError):
            self.status_unavailable = True  # no reader: never retry, clean up

    def cancel(self, why):
        if self.reason is None:
            self.reason = why
            self.deadline = min(self.deadline, time.monotonic())

    def on_signal(self, signum, _frame):
        self.signals[f"signal-{signum}"] += 1
        self.cancel(f"signal-{signal.Signals(signum).name}")

    def reap(self):
        """The one waitpid point; True means ECHILD, nothing left unreaped."""
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return True
            if not pid:
                return False
            if pid == self.cli_pid:
                self.cli_status = status

    def consume(self):
        """Drain parent-control (non-blocking): bytes mean present, EOF cancels."""
        try:
            data = os.read(self.control, 4096)
        except (BlockingIOError, InterruptedError):
            return  # spurious readable: nothing to do yet
        if data == b"":
            self.cancel("parent-control-eof")

    def targets(self):
        table = census(self.me)
        return owned_by(table, self.me)

    def stop(self, ours, sig):
        key = "KILL" if sig == signal.SIGKILL else "TERM"
        for pid, start in ours.items():
            pidfd_open, pidfd_send_signal = pidfd_api()
            if pidfd_open is None or pidfd_send_signal is None:
                continue  # no pidfd: fail closed, never signal by raw PID
            try:
                pidfd = pidfd_open(pid, 0)
            except OSError:
                continue  # gone or unopenable: never fall back to raw PID
            try:
                # Re-verify the /proc starttime identity after the pidfd is
                # pinned, so a reused PID is never signalled.
                if still(pid, start) is not True:
                    continue  # gone or mismatched: skip, keep going
                try:
                    pidfd_send_signal(pidfd, sig)
                except OSError:
                    continue  # gone or API error: no raw-PID fallback
                self.signals[key] += 1  # only after a successful pidfd send
            finally:
                try:
                    os.close(pidfd)
                except OSError:
                    pass

    def main(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self.on_signal)
        os.set_blocking(self.control, False)
        # Let the CLI inherit only stdio + whatever the caller passes: every
        # protocol descriptor we hold becomes CLOEXEC (read() still works).
        for fd in self.resources + [self.control, self.status]:
            os.set_inheritable(fd, False)
        poller = select.poll()
        poller.register(self.control, select.POLLIN)
        self.frame(event="ready", resource_fds=len(self.resources))
        self.cli_pid = os.fork()
        if self.cli_pid == 0:
            try:
                os.close(self.control)  # never handed to the CLI or its children
                os.close(self.status)
                os.execvp(self.cli[0], self.cli)
            finally:
                os._exit(127)
        kill_at = reported = self.progress = None
        while True:
            now = time.monotonic()
            if self.reason is None and now >= self.deadline:
                self.cancel("timeout")
            exited = self.reap()  # drain before looking, so ECHILD is not stale
            try:
                ours = self.targets()
                ambiguity = None
            except Ambiguous as exc:
                ours, ambiguity = {}, str(exc)
            if self.reason is None and exited and ours:
                self.cancel("leaked-descendants")  # the CLI ended, this did not
            stuck = bool(ours) or ambiguity is not None
            if not stuck:
                kill_at = None
            elif self.reason is not None:  # cancel: TERM now, KILL after grace
                kill_at = kill_at or now + GRACE
                self.stop(ours, signal.SIGKILL if now >= kill_at else signal.SIGTERM)
                progress = (len(ours), ambiguity, self.reason)
                if (progress != self.progress or reported is None
                        or now - reported >= PROGRESS_EVERY):
                    reported, self.progress = now, progress
                    self.frame(event="progress", owned=progress[0],
                               ambiguity=ambiguity, reason=self.reason)
            if exited and not stuck:  # ECHILD plus one descendant census after it
                for fd in self.resources:
                    os.close(fd)  # our copies only; the parent unlocks later
                return "quiescent", self.reason or "cli-exit"
            # Unknown or stuck: never final-quit, never close or unlock a
            # resource and never exit -- retry until ECHILD and the descendant
            # census prove nothing is left.
            if self.reason is not None:  # need_ms = 0 -> wait 50ms, re-TERM
                need_ms = 0
            else:
                need_ms = int(max(0, math.ceil(
                    (self.deadline - time.monotonic()) * 1000)))
            wait_ms = 50 if self.reason is not None else min(50 if stuck else 100, need_ms)
            poller.poll(max(1, wait_ms))  # select.poll() takes milliseconds
            self.consume()  # level-triggered read end: drain until empty or EOF


def check(parser, timeout, resource_fds, control, status):
    """Subreaper, /proc and descriptor checks; runs before the CLI is forked."""
    if not math.isfinite(timeout) or timeout <= 0:
        parser.error("a positive --timeout and '-- CLI ARG...' are required")
    pidfd_open, pidfd_send_signal = pidfd_api()
    if pidfd_open is None or pidfd_send_signal is None:
        raise OSError(0, "pidfd support (os.pidfd_open, signal.pidfd_send_signal) is required")
    pidfd = None
    try:
        try:
            pidfd = pidfd_open(os.getpid(), 0)  # prove the kernel supports pidfds
            pidfd_send_signal(pidfd, 0)  # harmless: signal 0 through the pidfd
        except OSError as exc:
            raise OSError(exc.errno or 0, "kernel pidfd support check failed") from None
    finally:
        if pidfd is not None:
            try:
                os.close(pidfd)
            except OSError:
                pass
    if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER)")
    census(os.getpid())  # /proc must be readable before any spawn
    ends = [(control, "parent-control", os.O_RDONLY), (status, "status", os.O_WRONLY)]
    for fd, what, want in ends + [(fd, "resource", None) for fd in resource_fds]:
        if not os.get_inheritable(fd):
            raise OSError(0, f"{what} fd {fd} is not inheritable")
        mode = os.fstat(fd).st_mode
        if want is None and not stat.S_ISREG(mode):
            raise OSError(0, f"{what} fd {fd} is not a regular file")
        if want is not None:
            if not stat.S_ISFIFO(mode):
                raise OSError(0, f"{what} fd {fd} is not a FIFO")
            flags = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
            if flags != want:
                raise OSError(0, f"{what} fd {fd} direction {flags} != {want}")
        os.set_inheritable(fd, False)  # CLOEXEC: the CLI never inherits them


def main(argv):
    parser = argparse.ArgumentParser(description="Linux child-subreaper for one CLI tree")
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--resource-fd", type=int, action="append", required=True)
    parser.add_argument("--parent-control-fd", type=int, required=True)
    parser.add_argument("--status-fd", type=int, required=True)
    parser.add_argument("cli", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    cli = args.cli[1:] if args.cli[:1] == ["--"] else args.cli
    if not cli:
        parser.error("a positive --timeout and '-- CLI ARG...' are required")
    try:
        check(parser, args.timeout, args.resource_fd, args.parent_control_fd, args.status_fd)
        sup = Supervisor(cli, args.timeout, args.resource_fd,
                         args.parent_control_fd, args.status_fd)
    except (OSError, Ambiguous) as exc:
        print(f"supervisor refused: {exc}", file=sys.stderr)
        return SUPERVISOR_EXIT
    cleanup, reason = sup.main()
    sup.frame(event="quit", leader_exit=cli_code(sup.cli_status), cleanup=cleanup,
              reason=reason, signals=sup.signals, resources_closed=cleanup == "quiescent")
    return 0 if cleanup == "quiescent" and cli_code(sup.cli_status) == 0 else SUPERVISOR_EXIT


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
