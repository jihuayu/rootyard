"""Bounded process execution with immediate Popen ownership.

Output is held in RAM up to a fixed cap.  A timed-out or failed child is killed
and polled to a reaped state before the fixed failure is raised; an unreapable
child is itself a fixed failure.  No argv, environment, DSN or output is
retained in an exception or printed by this module.
"""
from __future__ import annotations

import math
import os
import signal
import subprocess
import time

from .errors import RunnerError, require

MAX_STDOUT = 2 * 1024 * 1024
MAX_STDERR = 256 * 1024
KILL_WAIT_SECONDS = 2.0


class Completed:
    def __init__(self, argv, returncode, stdout, stderr):
        self.argv = tuple(argv)
        self.returncode = returncode
        self.stdout = stdout[:MAX_STDOUT]
        self.stderr = stderr[:MAX_STDERR]


class ProcessRunner:
    """One immediate ``Popen`` per call, always reaped before returning."""

    def __init__(self, clock=time.monotonic, popen=subprocess.Popen):
        self.clock = clock
        self._popen = popen

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
        try:
            stdout, stderr = process.communicate(input=input, timeout=timeout)
        except subprocess.TimeoutExpired:
            reaped = self._terminate(process)
            try:
                process.communicate(timeout=KILL_WAIT_SECONDS)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                pass
            if not reaped or process.poll() is None:
                raise RunnerError(stage, "process_unreaped") from None
            raise RunnerError(stage, timeout_code) from None
        except (OSError, ValueError, subprocess.SubprocessError):
            self._terminate(process)
            raise RunnerError(stage, "process_failed") from None
        if process.poll() is None:
            self._terminate(process)
            raise RunnerError(stage, "process_unreaped")
        if type(process.returncode) is not int:
            raise RunnerError(stage, "process_failed")
        return Completed(argv, process.returncode, stdout or b"", stderr or b"")

    def _terminate(self, process):
        # The child is started in its own session, so killing the group also
        # terminates any helper Git/psql descendants instead of detaching them.
        pid = getattr(process, "pid", None)
        killed_group = False
        if isinstance(pid, int) and pid > 0 and pid != os.getpid():
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
                killed_group = True
            except (OSError, ValueError):
                killed_group = False
        if not killed_group:
            try:
                process.kill()
            except (OSError, ValueError):
                pass
        try:
            process.wait(timeout=KILL_WAIT_SECONDS)
        except (subprocess.TimeoutExpired, OSError):
            pass
        try:
            return process.poll() is not None
        except (OSError, ValueError):
            return False
