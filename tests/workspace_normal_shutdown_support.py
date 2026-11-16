#!/usr/bin/env python3
"""Private helpers for the focused helper-backend normal-SIGTERM case.

Everything here is owned by the one test that imports it:

* the ``ROOTYARD_GIT`` wrapper executes the host's real Git and records only a
  fixed exit code and byte counts/digests, never Git output, paths or bodies;
* the raw FIFO is a real filesystem object used to hold the production capture
  freeze through its ordinary snapshot read; it is not a FUSE/helper fake;
* the raw HTTP PUT client sends request headers plus only part of a valid JSON
  body, so the handler cannot reach its PUT-capacity admission before the test
  observes shutdown.

There is no mock Git, fake helper, fake mount or reference implementation in
this module.  The wrapper holds only the one ``add -- parked.bin`` invocation
created by the test; every other Git call is forwarded unchanged.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import sys
import time
from pathlib import Path

from tests import fuse_helper_native_support as support


class NormalShutdownError(RuntimeError):
    """A bounded fixture precondition failed (never a skipped assertion)."""


_GIT_WRAPPER_TEMPLATE = r'''#!__PYTHON__
import hashlib
import json
import os
import subprocess
import sys
import time

REAL_GIT = __REAL_GIT__
MARKER = __MARKER__
args = sys.argv[1:]
result = subprocess.run(
    [REAL_GIT, *args],
    stdin=sys.stdin.buffer,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
held = (
    os.path.exists(MARKER + ".trigger")
    and "add" in args
    and "parked.bin" in args
)


def _starttime():
    try:
        fields = open("/proc/self/stat", encoding="utf-8").read().rsplit(")", 1)[-1].split()
        return int(fields[19])
    except (OSError, IndexError, ValueError):
        return 0


STARTTIME = _starttime()


def status(release_seen, timed_out=False):
    payload = {
        "exit": int(result.returncode),
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "pid": os.getpid(),
        "starttime": STARTTIME,
        "release_seen": bool(release_seen),
    }
    if timed_out:
        payload["hold_timeout"] = True
    temporary = MARKER + ".status.tmp"
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, MARKER + ".status.json")


if held:
    status(False)
    with open(MARKER + ".done", "w", encoding="utf-8"):
        pass
    deadline = time.monotonic() + 30.0
    while not os.path.exists(MARKER + ".release"):
        if time.monotonic() >= deadline:
            status(False, timed_out=True)
            sys.stderr.write("normal-sigterm Git wrapper hold deadline expired\n")
            sys.exit(125)
        time.sleep(0.01)
    status(True)

sys.stdout.buffer.write(result.stdout)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(result.stderr)
sys.stderr.buffer.flush()
sys.exit(result.returncode)
'''


def install_git_wrapper(root: Path, real_git: str, marker: Path) -> Path:
    """Install the small test-only ``ROOTYARD_GIT`` wrapper.

    The wrapper is intentionally a real process replacement, not a Git model:
    every invocation runs the supplied absolute real Git path, and the one
    trigger-matching ``add -- parked.bin`` call additionally holds its already
    completed result until the test releases the marker.
    """
    real_git = str(Path(real_git).resolve())
    if not Path(real_git).is_file() or not os.access(real_git, os.X_OK):
        raise NormalShutdownError("real Git is not an executable file")
    marker = str(Path(marker).resolve())
    wrapper = Path(root) / "normal-sigterm-git-wrapper"
    source = (
        _GIT_WRAPPER_TEMPLATE
        .replace("__PYTHON__", str(Path(sys.executable).resolve()))
        .replace("__REAL_GIT__", json.dumps(real_git))
        .replace("__MARKER__", json.dumps(marker))
    )
    wrapper.write_text(source, encoding="utf-8")
    wrapper.chmod(0o700)
    return wrapper


def _status_path(marker: Path) -> Path:
    return Path(str(marker) + ".status.json")


def read_git_hold_status(marker: Path):
    """Read the wrapper's safe status, or ``None`` when it is not complete."""
    try:
        data = json.loads(_status_path(marker).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    for name in ("exit", "stdout_bytes", "stderr_bytes", "pid", "starttime"):
        value = data.get(name)
        if not isinstance(value, int) or isinstance(value, bool):
            return None
    for name in ("stdout_sha256", "stderr_sha256"):
        value = data.get(name)
        if not isinstance(value, str) or len(value) != 64:
            return None
    if not isinstance(data.get("release_seen"), bool):
        return None
    if "hold_timeout" in data and not isinstance(data["hold_timeout"], bool):
        return None
    return data


def wait_for_git_hold(marker: Path, timeout: float = 10.0) -> dict:
    """Wait until the real Git command completed and the wrapper is holding."""
    done = Path(str(marker) + ".done")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = read_git_hold_status(marker)
        if status is not None and status.get("hold_timeout"):
            raise NormalShutdownError("Git wrapper hold timed out")
        if done.exists() and status is not None:
            return status
        time.sleep(0.02)
    raise NormalShutdownError("Git wrapper did not reach its owned hold marker")


def git_hold_active(marker: Path) -> bool:
    """True only while the wrapper's real result is still held."""
    status = read_git_hold_status(marker)
    return (
        Path(str(marker) + ".done").exists()
        and not Path(str(marker) + ".release").exists()
        and status is not None
        and not status.get("hold_timeout")
    )


def release_git_hold(marker: Path) -> None:
    Path(str(marker) + ".release").touch()


def clear_git_markers(marker: Path) -> None:
    for suffix in (".trigger", ".done", ".release", ".status.json", ".status.tmp"):
        path = Path(str(marker) + suffix)
        if path.exists() or path.is_symlink():
            path.unlink()


class RawFifoGate:
    """A real FIFO that holds the production raw-snapshot read.

    The capture scanner enters ``with_frozen`` before ``Raw::load``; creating
    the FIFO at the upper ``.git/index`` path makes that ordinary snapshot read
    wait for a writer.  While the actual helper gate is frozen, the pending
    FUSE writer is parked by the real frozen dispatch queue.  Releasing the
    FIFO only lets the capture producer leave the freeze; it is never used as
    mount-removal or helper-exit evidence.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.fd: int | None = None

    def install(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()
        os.mkfifo(self.path, 0o600)
        if not stat.S_ISFIFO(self.path.lstat().st_mode):
            raise NormalShutdownError("owned capture gate is not a FIFO")

    def release(self) -> None:
        if self.fd is None:
            self.fd = os.open(self.path, os.O_RDWR | os.O_NONBLOCK)

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            finally:
                self.fd = None

    def remove(self) -> None:
        self.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def wait_for_writer_writing(process, status_path: Path, timeout: float = 10.0) -> dict:
    """Require the real pending writer to have published its writing phase."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code = process.poll()
        if code is not None:
            raise NormalShutdownError(f"pending writer exited {code} before its writing phase")
        status = support.writer_status(status_path)
        if status is not None:
            if status["phase"] in ("error", "setup_error"):
                raise NormalShutdownError(
                    f"pending writer failed before its writing phase (errno {status['errno']})")
            if status["phase"] == "writing":
                return status
        time.sleep(0.02)
    raise NormalShutdownError("pending writer did not publish its writing phase")


def _socket_table(pid: int):
    for table in ("tcp", "tcp6"):
        try:
            text = Path(f"/proc/{int(pid)}/net/{table}").read_text(encoding="utf-8")
        except OSError as error:
            raise NormalShutdownError("server TCP table is unavailable") from error
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 5:
                continue
            local, remote, state = fields[1], fields[2], fields[3]
            try:
                local_port = int(local.rsplit(":", 1)[1], 16)
                remote_port = int(remote.rsplit(":", 1)[1], 16)
                queue = fields[4].split(":", 1)[1]
                rx_queue = int(queue, 16)
            except (IndexError, ValueError):
                continue
            yield state, local_port, remote_port, rx_queue


def wait_for_tcp_accepted(api_pid: int, server_port: int, client_port: int,
                          timeout: float = 5.0) -> None:
    """Wait for the server to accept and consume the partial request bytes.

    ``rx_queue == 0`` on the established accepted socket is direct evidence
    that the service read the headers and the partial body already sent, so the
    handler is the owner waiting for the remainder.  It is not a sleep window.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for state, local_port, remote_port, rx_queue in _socket_table(api_pid):
            if (state == "01" and local_port == int(server_port)
                    and remote_port == int(client_port) and rx_queue == 0):
                return
        time.sleep(0.02)
    raise NormalShutdownError("partial PUT was not accepted and consumed by the API")


class PartialPut:
    """One raw HTTP PUT whose valid JSON body is delivered in two parts."""

    def __init__(self, host: str, port: int, path: str, token: str, body: bytes):
        self.host = host
        self.port = int(port)
        self.path = path
        self.token = token
        self.body = bytes(body)
        self.sock: socket.socket | None = None
        self.client_port: int | None = None
        self.rest = b""
        if len(self.body) < 2:
            raise NormalShutdownError("partial PUT body is too small")

    def start(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=5.0)
        self.sock.settimeout(5.0)
        self.client_port = int(self.sock.getsockname()[1])
        cut = max(1, min(len(self.body) - 1, len(self.body) // 2))
        self.rest = self.body[cut:]
        headers = (
            f"PUT {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: Bearer {self.token}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(self.body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        self.sock.sendall(headers + self.body[:cut])

    def wait_accepted(self, api_pid: int, timeout: float = 5.0) -> None:
        if self.sock is None or self.client_port is None:
            raise NormalShutdownError("partial PUT was not started")
        wait_for_tcp_accepted(api_pid, self.port, self.client_port, timeout)

    def finish(self, timeout: float) -> dict:
        """Deliver the remainder and return a fixed status/closed outcome."""
        if self.sock is None:
            raise NormalShutdownError("partial PUT was not started")
        try:
            self.sock.sendall(self.rest)
        except ConnectionError:
            self.close()
            return {"status": None, "closed": True, "response_bytes": 0}
        self.sock.settimeout(timeout)
        data = bytearray()
        try:
            while b"\r\n\r\n" not in data:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return {"status": None, "closed": True, "response_bytes": len(data)}
                data.extend(chunk)
                if len(data) > 65536:
                    raise NormalShutdownError("partial PUT response headers are oversized")
            head, _body = bytes(data).split(b"\r\n\r\n", 1)
            try:
                status = int(head.split(b"\r\n", 1)[0].split()[1])
            except (IndexError, ValueError):
                raise NormalShutdownError("partial PUT returned an invalid status line") from None
            return {"status": status, "closed": False, "response_bytes": 0}
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return {"status": None, "closed": True, "response_bytes": len(data)}
        except socket.timeout:
            raise NormalShutdownError("partial PUT did not resolve within the deadline") from None
        finally:
            self.close()

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
