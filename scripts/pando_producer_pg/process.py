"""Bounded process execution with immediate Popen ownership.

Pipe readers enforce one aggregate in-memory budget while draining, so a child
cannot make the parent accumulate unbounded stdout/stderr.  Ordinary commands
retain the existing per-stream truncation result; callers can request a fixed
failure as soon as the aggregate ceiling is crossed.  On any failure the owned
process group is killed and reaped before a bounded reader join; pipes are
closed only after their readers have actually stopped.  No argv, environment,
DSN, SQL or raw child text is retained in an exception or printed.
"""
from __future__ import annotations

import math
import os
import signal
import subprocess
import threading
import time

from .errors import RunnerError, require

MAX_STDOUT = 2 * 1024 * 1024
MAX_STDERR = 256 * 1024
MAX_TOTAL_OUTPUT = MAX_STDOUT + MAX_STDERR
READ_CHUNK = 64 * 1024
READER_JOIN_SECONDS = 1.0
KILL_WAIT_SECONDS = 2.0
POLL_SECONDS = 0.05


class Completed:
    def __init__(
        self,
        argv,
        returncode,
        stdout,
        stderr,
        output_exceeded=False,
        stdout_truncated=False,
        stderr_truncated=False,
    ):
        self.argv = tuple(argv)
        self.returncode = returncode
        self.stdout = stdout[:MAX_STDOUT]
        self.stderr = stderr[:MAX_STDERR]
        self.output_exceeded = bool(output_exceeded)
        self.stdout_truncated = bool(stdout_truncated)
        self.stderr_truncated = bool(stderr_truncated)


class _OutputBudget:
    """One aggregate stored-byte budget shared by both pipe readers."""

    def __init__(self, max_stdout, max_stderr, max_total, fail_on_exceeded):
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.max_stdout = max_stdout
        self.max_stderr = max_stderr
        self.max_total = max_total
        self.fail_on_exceeded = fail_on_exceeded
        self.stored_total = 0
        self.received_total = 0
        self.exceeded = False
        self.reader_error = False
        self.stream_truncated = {"stdout": False, "stderr": False}

    def append(self, name, chunk):
        if not chunk:
            return
        with self.lock:
            self.received_total += len(chunk)
            if self.received_total > self.max_total:
                self.exceeded = True
                if self.fail_on_exceeded:
                    self.stopped.set()
            buffer = self.stdout if name == "stdout" else self.stderr
            stream_cap = self.max_stdout if name == "stdout" else self.max_stderr
            room = min(stream_cap - len(buffer), self.max_total - self.stored_total)
            if room <= 0:
                self.stream_truncated[name] = True
                return
            take = min(len(chunk), room)
            buffer.extend(chunk[:take])
            self.stored_total += take
            if take < len(chunk):
                self.stream_truncated[name] = True

    def fail_reader(self):
        with self.lock:
            self.reader_error = True
            self.stopped.set()

    def snapshot(self):
        with self.lock:
            return (
                bytes(self.stdout),
                bytes(self.stderr),
                self.exceeded,
                dict(self.stream_truncated),
            )


class _Reader:
    def __init__(self, stream, name, budget):
        self.stream = stream
        self.name = name
        self.budget = budget

    def run(self):
        try:
            while not self.budget.stopped.is_set():
                chunk = self.stream.read(READ_CHUNK)
                if not chunk:
                    break
                if not isinstance(chunk, (bytes, bytearray)):
                    raise TypeError("pipe returned non-bytes")
                self.budget.append(self.name, bytes(chunk))
                if self.budget.stopped.is_set():
                    break
        except Exception:
            self.budget.fail_reader()


class _Writer:
    """Owned stdin writer; a child closed early is not a writer failure."""

    def __init__(self, stream, data):
        self.stream = stream
        self.data = data
        self.failed = False

    def run(self):
        try:
            self.stream.write(self.data)
            self.stream.flush()
        except BrokenPipeError:
            pass
        except Exception:
            self.failed = True
        finally:
            try:
                self.stream.close()
            except (OSError, ValueError):
                pass


class ProcessRunner:
    """One immediate ``Popen`` per call, always reaped before returning."""

    def __init__(
        self,
        clock=time.monotonic,
        popen=subprocess.Popen,
        thread_factory=threading.Thread,
        killpg=os.killpg,
    ):
        self.clock = clock
        self._popen = popen
        self._thread_factory = thread_factory
        self._killpg = killpg

    def run(
        self,
        argv,
        *,
        env=None,
        input=None,
        timeout=30,
        cwd=None,
        stage="internal",
        timeout_code="process_timeout",
        spawn_code="process_spawn_failed",
        max_stdout=MAX_STDOUT,
        max_stderr=MAX_STDERR,
        max_total=MAX_TOTAL_OUTPUT,
        fail_on_output_exceeded=False,
        output_code="process_output_exceeded",
    ):
        require(
            isinstance(argv, (list, tuple))
            and bool(argv)
            and all(isinstance(item, str) and item for item in argv),
            stage,
            "invalid_arguments",
        )
        require(
            isinstance(timeout, (int, float))
            and not isinstance(timeout, bool)
            and math.isfinite(timeout)
            and timeout > 0,
            stage,
            "timeout_invalid",
        )
        require(
            type(max_stdout) is int
            and type(max_stderr) is int
            and type(max_total) is int
            and max_stdout >= 0
            and max_stderr >= 0
            and max_total > 0,
            stage,
            "invalid_arguments",
        )
        budget = _OutputBudget(
            max_stdout, max_stderr, max_total, bool(fail_on_output_exceeded)
        )
        try:
            process = self._popen(
                [str(item) for item in argv],
                stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=None if cwd is None else str(cwd),
                start_new_session=True,
            )
        except (OSError, ValueError, TypeError):
            raise RunnerError(stage, spawn_code) from None
        entries = []
        writer = None
        try:
            if input is not None:
                stdin = getattr(process, "stdin", None)
                if stdin is None:
                    raise ValueError("missing stdin pipe")
                writer = _Writer(stdin, input)
                entries.append(
                    {
                        "reader": writer,
                        "thread": self._thread_factory(
                            target=writer.run,
                            name="producer-pg-stdin",
                            daemon=True,
                        ),
                        "start_attempted": False,
                        "started": False,
                        "start_failed": False,
                    }
                )
            for name, stream in (
                ("stdout", getattr(process, "stdout", None)),
                ("stderr", getattr(process, "stderr", None)),
            ):
                if stream is None:
                    continue
                reader = _Reader(stream, name, budget)
                thread = self._thread_factory(
                    target=reader.run, name="producer-pg-" + name, daemon=True
                )
                entries.append(
                    {
                        "reader": reader,
                        "thread": thread,
                        "start_attempted": False,
                        "started": False,
                        "start_failed": False,
                    }
                )
            for entry in entries:
                entry["start_attempted"] = True
                try:
                    entry["thread"].start()
                except (RuntimeError, OSError, ValueError):
                    entry["start_failed"] = True
                    raise
                entry["started"] = True
        except Exception:
            raise self._cleanup_failure(
                process, entries, stage, "process_failed"
            ) from None
        deadline = self.clock() + float(timeout)
        while True:
            if budget.reader_error or (writer is not None and writer.failed):
                raise self._cleanup_failure(
                    process, entries, stage, "process_failed"
                ) from None
            if fail_on_output_exceeded and budget.exceeded:
                raise self._cleanup_failure(
                    process, entries, stage, output_code
                ) from None
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise self._cleanup_failure(
                    process, entries, stage, timeout_code
                ) from None
            try:
                process.wait(timeout=min(remaining, POLL_SECONDS))
            except subprocess.TimeoutExpired:
                continue
            except (OSError, ValueError, subprocess.SubprocessError):
                raise self._cleanup_failure(
                    process, entries, stage, "process_failed"
                ) from None
            if process.poll() is not None:
                break
            raise self._cleanup_failure(
                process, entries, stage, "process_unreaped"
            ) from None
        if budget.reader_error or (writer is not None and writer.failed):
            raise self._cleanup_failure(
                process, entries, stage, "process_failed"
            ) from None
        if fail_on_output_exceeded and budget.exceeded:
            raise self._cleanup_failure(
                process, entries, stage, output_code
            ) from None
        if not self._join_readers(
            entries, self.clock() + READER_JOIN_SECONDS
        ):
            raise self._cleanup_failure(
                process, entries, stage, "process_unreaped"
            ) from None
        self._close_streams(process)
        if type(process.returncode) is not int:
            raise RunnerError(stage, "process_failed")
        stdout, stderr, exceeded, truncated = budget.snapshot()
        return Completed(
            argv,
            process.returncode,
            stdout,
            stderr,
            output_exceeded=exceeded,
            stdout_truncated=truncated["stdout"],
            stderr_truncated=truncated["stderr"],
        )

    def _cleanup_failure(self, process, entries, stage, primary):
        deadline = self.clock() + KILL_WAIT_SECONDS
        try:
            outcome = self._terminate(process, deadline)
        except Exception:
            outcome = {"direct_reaped": False, "group_verified": False}
        try:
            joined = self._join_readers(entries, deadline)
        except Exception:
            joined = False
        if joined:
            self._close_streams(process)
        if not outcome.get("group_verified"):
            return RunnerError(
                stage, "process_group_unverified", primary_code=primary
            )
        if not outcome.get("direct_reaped") or not joined:
            return RunnerError(stage, "process_unreaped", primary_code=primary)
        return RunnerError(stage, primary)

    def _terminate(self, process, deadline):
        # The owned child is a new-session leader, so its PID is the group ID.
        # ESRCH for that exact owned group proves absence; EPERM/other failures
        # remain unverified even when the direct child is reaped.
        pgid = getattr(process, "pid", None)
        group_signal_sent = False
        group_verified = False
        if isinstance(pgid, int) and pgid > 0 and pgid != os.getpid():
            try:
                self._killpg(pgid, signal.SIGKILL)
                group_signal_sent = True
            except ProcessLookupError:
                group_verified = True
            except (OSError, ValueError, TypeError):
                group_verified = False
        try:
            process.kill()
        except (OSError, ValueError, AttributeError):
            pass
        remaining = max(0.0, deadline - self.clock())
        try:
            process.wait(timeout=remaining)
        except (subprocess.TimeoutExpired, OSError, ValueError, AttributeError):
            pass
        try:
            direct_reaped = process.poll() is not None
        except (OSError, ValueError, AttributeError):
            direct_reaped = False
        if group_signal_sent:
            group_verified = self._group_absent(pgid)
        return {
            "direct_reaped": direct_reaped,
            "group_verified": group_verified,
        }

    def _group_absent(self, pgid):
        try:
            self._killpg(pgid, 0)
        except ProcessLookupError:
            return True
        except (OSError, ValueError, TypeError):
            return False
        return False

    def _join_readers(self, entries, deadline):
        for entry in entries:
            if not entry.get("start_attempted"):
                continue
            thread = entry["thread"]
            if entry.get("start_failed"):
                try:
                    if not thread.is_alive():
                        continue
                except (RuntimeError, OSError, ValueError, AttributeError):
                    return False
            remaining = max(0.0, deadline - self.clock())
            try:
                thread.join(timeout=remaining)
            except (RuntimeError, OSError, ValueError, AttributeError):
                return False
            try:
                if thread.is_alive():
                    return False
            except (RuntimeError, OSError, ValueError, AttributeError):
                return False
        return True

    def _close_streams(self, process):
        for stream in (
            getattr(process, "stdin", None),
            getattr(process, "stdout", None),
            getattr(process, "stderr", None),
        ):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError, AttributeError):
                    pass
