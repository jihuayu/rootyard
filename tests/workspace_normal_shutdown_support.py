#!/usr/bin/env python3
"""Private helpers for the focused helper-backend normal-SIGTERM case.

Everything here is owned by the one test that imports it:

* the ``ROOTYARD_GIT`` wrapper executes the host's real Git and records only a
  fixed exit code and byte counts/digests, never Git output, paths or bodies;
* the capture target is a real regular ``.git/index`` exposed through a
  test-owned symlink proxy for the existing exact-path read barrier; it is not
  a FUSE/helper fake or a special file;
* the raw HTTP PUT client sends request headers plus only part of a valid JSON
  body, so the handler cannot reach its PUT-capacity admission before the test
  observes shutdown;
* the optional bounded busy witness is compiled only into this harness's own
  children and records the exact helper ``umount2(..., 0)`` and parked writer
  ``close`` ordering; if it cannot be built or injected, projection is
  ``unknown`` and the original acceptance assertions are unchanged.

There is no mock Git, fake helper, fake mount or reference implementation in
this module.  The wrapper holds only the one ``add -- parked.bin`` invocation
created by the test; every other Git call is forwarded unchanged.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import socket
import stat
import sys
import time
from pathlib import Path

from tests import fuse_helper_native_support as support


ADMISSION_CLOSED_ERROR = "workspace admission is closed for shutdown"
MAX_ERROR_BODY_BYTES = 8192
TESTS_DIR = Path(__file__).resolve().parent
BUSY_WITNESS_ENV = (
    "LD_PRELOAD",
    "ROOTYARD_TEST_FUSE_WITNESS_ROLE",
    "ROOTYARD_TEST_FUSE_WITNESS_DIR",
    "ROOTYARD_TEST_FUSE_WITNESS_LIBRARY",
    "ROOTYARD_TEST_FUSE_WITNESS_CLOSE_FD",
)
RECEIPT_FILENAMES = ("helper.receipt", "writer.receipt")
RECEIPT_MODE = 0o600
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def _create_private_receipt(path):
    """Create one empty fixture-owned 0600 regular receipt file."""
    if not _O_NOFOLLOW or not _O_CLOEXEC:
        return False
    try:
        path = Path(path)
        if path.is_symlink() or path.exists():
            path.unlink()
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
            RECEIPT_MODE,
        )
        try:
            os.fchmod(descriptor, RECEIPT_MODE)
            info = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        return (
            stat.S_ISREG(info.st_mode)
            and (info.st_mode & 0o7777) == RECEIPT_MODE
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and info.st_size == 0
        )
    except (OSError, TypeError, ValueError):
        return False


class NormalShutdownError(RuntimeError):
    """A bounded fixture precondition failed (never a skipped assertion)."""


def install_busy_witness(h, witness_dir):
    """Build and install the optional bounded passive witness.

    The witness is diagnostic-only.  Every unavailability (non-Linux, no
    compiler, fixture missing, build failure) returns ``None`` and leaves the
    service environment untouched, so the original normal-SIGTERM acceptance
    remains the only pass condition and the diagnostic stays ``unknown``.
    """
    witness_dir = Path(witness_dir)
    if not sys.platform.startswith("linux") or not Path("/proc/self/fd").is_dir():
        return None
    compiler = shutil.which("gcc")
    if compiler is None:
        return None
    source = TESTS_DIR / "fixtures" / "fuse_busy_witness.c"
    if not source.is_file():
        return None
    build = Path(h.root) / "fuse-busy-witness"
    try:
        build.mkdir(parents=True, exist_ok=True)
        library = build / "fuse_busy_witness.so"
        build_env = dict(h.env)
        for name in BUSY_WITNESS_ENV:
            build_env.pop(name, None)
        h.run(
            [compiler, "-shared", "-fPIC", "-O2", "-pthread", "-o",
             str(library), str(source), "-ldl"],
            env=build_env,
        )
        if not library.is_file():
            return None
        witness_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(witness_dir, 0o700)
        for name in RECEIPT_FILENAMES:
            if not _create_private_receipt(witness_dir / name):
                return None
    except Exception:
        return None
    existing = h.env.get("LD_PRELOAD")
    h.env["LD_PRELOAD"] = (
        f"{existing}:{library}" if existing else str(library))
    h.env["ROOTYARD_TEST_FUSE_WITNESS_ROLE"] = "api"
    h.env["ROOTYARD_TEST_FUSE_WITNESS_DIR"] = str(witness_dir)
    h.env["ROOTYARD_TEST_FUSE_WITNESS_LIBRARY"] = str(library)
    return library


def busy_witness_writer_env(library, witness_dir):
    """Return only the writer-child witness environment, or ``None``."""
    if library is None:
        return None
    return {
        "LD_PRELOAD": str(library),
        "ROOTYARD_TEST_FUSE_WITNESS_ROLE": "writer",
        "ROOTYARD_TEST_FUSE_WITNESS_DIR": str(witness_dir),
    }


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


def enable_capture_proxy(proxy: Path, target_file: Path, source_file: Path) -> None:
    """Make the exact production raw read match the installed capture gate.

    The interposer resolves its configured target at read time.  Until this
    function runs the proxy is absent, so setup/checkpoint reads cannot match.
    The proxy is a test-owned symlink to a real regular upper ``.git/index``
    copied from the workspace lower index; ``core::inventory`` therefore
    accepts it as a file before the real ``read`` is intercepted.  No FIFO or
    other special file is used.
    """
    target_file = Path(target_file)
    target_file.parent.mkdir(parents=True, exist_ok=True)
    if target_file.exists() or target_file.is_symlink():
        mode = target_file.lstat().st_mode
        if stat.S_ISDIR(mode):
            raise NormalShutdownError("capture target is a directory")
        target_file.unlink()
    data = Path(source_file).read_bytes()
    target_file.write_bytes(data)
    target_file.chmod(0o600)
    if not stat.S_ISREG(target_file.lstat().st_mode):
        raise NormalShutdownError("capture target is not a regular file")
    proxy = Path(proxy)
    proxy.parent.mkdir(parents=True, exist_ok=True)
    if proxy.exists() or proxy.is_symlink():
        proxy.unlink()
    os.symlink(target_file.resolve(), proxy)


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


def _hash_regular_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def checkpoint_tree_digest(root: Path) -> str:
    """Digest every checkpoint path, type, mode, byte and symlink identity.

    The manifest is built privately and only its SHA-256 is returned, so a
    mismatch fails with fixed text rather than dumping file contents.  Symlink
    identities are compared as exact target bytes through their digest/length;
    file bytes, sizes and modes are all covered.  This is a full tree proof, not
    a single ``hello.txt`` sample.
    """
    root = Path(root)
    entries = []
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise NormalShutdownError("checkpoint root is unreadable") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise NormalShutdownError("checkpoint root is not a directory")
    entries.append({"path": ".", "kind": "dir",
                    "mode": stat.S_IMODE(root_metadata.st_mode)})

    def visit(directory: Path, relative: Path) -> None:
        try:
            with os.scandir(directory) as iterator:
                children = sorted(((entry.name, Path(entry.path)) for entry in iterator),
                                  key=lambda pair: pair[0])
        except OSError as error:
            raise NormalShutdownError("checkpoint tree is unreadable") from error
        for name, full in children:
            rel = (relative / name).as_posix()
            try:
                metadata = full.lstat()
            except OSError as error:
                raise NormalShutdownError("checkpoint entry is unreadable") from error
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(full)
                target_bytes = os.fsencode(target)
                entries.append({
                    "path": rel,
                    "kind": "symlink",
                    "mode": mode,
                    "target_bytes": len(target_bytes),
                    "target_sha256": hashlib.sha256(target_bytes).hexdigest(),
                })
            elif stat.S_ISDIR(metadata.st_mode):
                entries.append({"path": rel, "kind": "dir", "mode": mode})
                visit(full, relative / name)
            elif stat.S_ISREG(metadata.st_mode):
                try:
                    sha256, size = _hash_regular_file(full)
                except OSError as error:
                    raise NormalShutdownError("checkpoint file is unreadable") from error
                entries.append({
                    "path": rel,
                    "kind": "file",
                    "mode": mode,
                    "size": size,
                    "sha256": sha256,
                })
            else:
                entries.append({"path": rel, "kind": "special", "mode": mode})

    visit(root, Path())
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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

    def finish(self, remaining) -> dict:
        """Deliver the remainder and require the fixed admission rejection.

        The caller's absolute remaining-budget function is applied immediately
        before the body send and again before the response read, so neither a
        blocked send nor a blocked read can start a fresh wait.  Only the
        route-level 503 with the exact static error string is accepted; a
        closed connection, a different status, or a different 503 body fails
        with a fixed safe message and never exposes response bytes.
        """
        if self.sock is None:
            raise NormalShutdownError("partial PUT was not started")
        self.sock.settimeout(remaining())
        try:
            self.sock.sendall(self.rest)
        except socket.timeout:
            raise NormalShutdownError(
                "partial PUT send exceeded the shared shutdown deadline") from None
        except ConnectionError:
            raise NormalShutdownError(
                "partial PUT closed before the fixed admission response") from None
        self.sock.settimeout(remaining())
        data = bytearray()
        try:
            while b"\r\n\r\n" not in data:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise NormalShutdownError(
                        "partial PUT closed before the fixed admission response")
                data.extend(chunk)
                if len(data) > 65536:
                    raise NormalShutdownError("partial PUT response headers are oversized")
            head, body = bytes(data).split(b"\r\n\r\n", 1)
            lines = head.split(b"\r\n")
            try:
                status = int(lines[0].split()[1])
            except (IndexError, ValueError):
                raise NormalShutdownError("partial PUT returned an invalid status line") from None
            if status != 503:
                return {"status": status, "admission_closed": False}
            length = None
            for line in lines[1:]:
                if b":" not in line:
                    continue
                name, value = line.split(b":", 1)
                if name.strip().lower() == b"content-length":
                    try:
                        length = int(value.strip())
                    except ValueError:
                        raise NormalShutdownError(
                            "partial PUT returned an invalid body length") from None
            if length is not None:
                if length < 0 or length > MAX_ERROR_BODY_BYTES:
                    raise NormalShutdownError(
                        "partial PUT admission body exceeded the safe bound")
                while len(body) < length:
                    chunk = self.sock.recv(length - len(body))
                    if not chunk:
                        raise NormalShutdownError(
                            "partial PUT closed before the fixed admission response")
                    body += chunk
            else:
                while True:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                    if len(body) > MAX_ERROR_BODY_BYTES:
                        raise NormalShutdownError(
                            "partial PUT admission body exceeded the safe bound")
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise NormalShutdownError(
                    "partial PUT 503 body was not the fixed admission response") from None
            closed = isinstance(payload, dict) and payload.get("error") == ADMISSION_CLOSED_ERROR
            return {"status": 503, "admission_closed": closed}
        except socket.timeout:
            raise NormalShutdownError(
                "partial PUT did not resolve within the shared deadline") from None
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            raise NormalShutdownError(
                "partial PUT closed before the fixed admission response") from None
        finally:
            self.close()

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None


# ---------------------------------------------------------------------------
# Bounded passive busy-witness projection
#
# The observer is the fixture-only tests/fixtures/fuse_busy_witness.c preload.
# It records only a helper umount2(flags=0) that returned -1/EBUSY, with the
# mount identity observed for that exact path, and only the parked writer's
# successful close entry/result.  Both use CLOCK_MONOTONIC.  Receipts are
# fixture-created 0600 regular files opened without following links.  These
# functions project the bounded local receipts to the two fixed diagnostic
# values; they never return a path, PID, descriptor, argv, errno body, log
# line or event.
# ---------------------------------------------------------------------------
BUSY_TARGETS = frozenset((
    "writer",
    "git",
    "put",
    "other_owned",
    "unknown",
))
WRITER_CLOSE_STATES = frozenset((
    "completed_before_unmount_entry",
    "began_after_busy_return",
    "overlapping",
    "unknown",
))
UNKNOWN = "unknown"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_RECEIPTS = 128
_FNV_OFFSET = 14695981039346656037
_FNV_PRIME = 1099511628211
_REQUIRED_KEYS = frozenset((
    "kind", "role", "entry_ns", "result_ns", "mount_id", "path_hash",
    "proc_tag", "rc", "errno", "flags", "owned",
))


def fnv1a64(data: bytes) -> int:
    """Return the FNV-1a 64-bit identity used by the C fixture."""
    value = _FNV_OFFSET
    for byte in data:
        value ^= byte
        value = (value * _FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return value


def process_tag(pid: int, starttime: int) -> int:
    """Return the opaque process tag; never return the raw pid/starttime."""
    if (type(pid) is not int or type(starttime) is not int
            or pid <= 0 or starttime <= 0):
        return 0
    return fnv1a64(f"{pid}:{starttime}".encode("ascii"))


def path_tag(path) -> int:
    """Return an opaque identity for one exact fixture path."""
    try:
        raw = os.fsencode(os.fspath(path))
    except (TypeError, ValueError, OSError):
        return 0
    if not raw:
        return 0
    return fnv1a64(raw)


def _parse_uint(text: str, maximum: int):
    if not text or not text.isdigit():
        return None
    value = int(text, 10)
    return value if 0 <= value <= maximum else None


def _parse_hex(text: str, digits: int):
    if len(text) != digits:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _parse_int(text: str, minimum: int, maximum: int):
    if not text:
        return None
    try:
        value = int(text, 10)
    except ValueError:
        return None
    return value if minimum <= value <= maximum else None


def _parse_witness_line(line: bytes):
    if not line.startswith(b"W1 ") or len(line) > 512:
        return None
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        return None
    fields = {}
    for part in text[3:].split(" "):
        if not part or "=" not in part:
            return None
        name, value = part.split("=", 1)
        if name in fields or name not in _REQUIRED_KEYS:
            return None
        fields[name] = value
    if set(fields) != _REQUIRED_KEYS:
        return None
    kind = fields["kind"]
    role = fields["role"]
    if kind not in ("umount", "close"):
        return None
    if (kind == "umount" and role != "helper") or (kind == "close" and role != "writer"):
        return None
    entry_ns = _parse_uint(fields["entry_ns"], 2 ** 63 - 1)
    result_ns = _parse_uint(fields["result_ns"], 2 ** 63 - 1)
    mount_id = _parse_uint(fields["mount_id"], 2 ** 64 - 1)
    path_hash = _parse_hex(fields["path_hash"], 16)
    proc_tag = _parse_hex(fields["proc_tag"], 16)
    flags = _parse_uint(fields["flags"], 1)
    owned = _parse_uint(fields["owned"], 1)
    rc = _parse_int(fields["rc"], -(2 ** 31), 2 ** 31 - 1)
    error = _parse_uint(fields["errno"], 4095)
    if None in (entry_ns, result_ns, mount_id, path_hash, proc_tag,
                flags, owned, rc, error):
        return None
    if entry_ns <= 0 or result_ns < entry_ns or flags != 0:
        return None
    if kind == "close":
        if mount_id != 0 or path_hash != 0 or owned != 0:
            return None
    return {
        "kind": kind,
        "role": role,
        "entry_ns": entry_ns,
        "result_ns": result_ns,
        "mount_id": mount_id,
        "path_hash": path_hash,
        "proc_tag": proc_tag,
        "rc": rc,
        "errno": error,
        "flags": flags,
        "owned": owned,
    }


def _read_private_receipt(path):
    """Read one bounded fixture-owned 0600 regular receipt.

    The open is non-blocking and does not follow links, so a replaced FIFO or
    symlink cannot stall or redirect the diagnostic.  Ownership, type, mode,
    link count and size are checked on the opened inode, never by pathname.
    """
    if not _O_NOFOLLOW or not _O_NONBLOCK or not _O_CLOEXEC:
        return None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC,
        )
    except (OSError, TypeError, ValueError):
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None
        if (info.st_mode & 0o7777) != RECEIPT_MODE:
            return None
        if info.st_uid != os.geteuid():
            return None
        if info.st_nlink != 1:
            return None
        if info.st_size < 0 or info.st_size > MAX_RECEIPT_BYTES:
            return None
        data = bytearray()
        while len(data) <= MAX_RECEIPT_BYTES:
            chunk = os.read(
                descriptor,
                min(8192, MAX_RECEIPT_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)
    except (OSError, ValueError):
        return None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def parse_witness_receipt(path) -> list[dict] | None:
    """Parse one bounded receipt, or return ``None`` for any unsafe shape."""
    data = _read_private_receipt(path)
    if data is None or not data or len(data) > MAX_RECEIPT_BYTES:
        return None
    if not data.endswith(b"\n"):
        return None
    records = []
    for line in data.splitlines():
        if not line:
            return None
        if len(records) >= MAX_RECEIPTS:
            return None
        record = _parse_witness_line(line)
        if record is None:
            return None
        records.append(record)
    return records or None


def _identity(value):
    """Return one closed ``(mount_id, path_hash)`` pair, or ``None``."""
    if not isinstance(value, (tuple, list)) or len(value) != 2:
        return None
    mount_id, path_hash = value
    if (type(mount_id) is not int or type(path_hash) is not int
            or mount_id <= 0 or path_hash <= 0):
        return None
    return (mount_id, path_hash)


def _witness_target(record, expected_mounts, owned_mounts):
    """Attribute only an independently owned, distinct route identity.

    All three route bindings must be present, independently owned and
    physically distinct.  A missing or ambiguous binding cannot imply an
    owner, and therefore cannot turn an otherwise unknown identity into
    ``other_owned``.
    """
    labels = ("writer", "git", "put")
    expected = {}
    for label in labels:
        identity = _identity(expected_mounts.get(label))
        if identity is None:
            return UNKNOWN
        expected[label] = identity
    if len(set(expected.values())) != 3:
        return UNKNOWN
    if len({identity[0] for identity in expected.values()}) != 3:
        return UNKNOWN
    if len({identity[1] for identity in expected.values()}) != 3:
        return UNKNOWN
    owned = set()
    for value in owned_mounts:
        identity = _identity(value)
        if identity is not None:
            owned.add(identity)
    if any(identity not in owned for identity in expected.values()):
        return UNKNOWN
    identity = (record["mount_id"], record["path_hash"])
    for label in labels:
        if identity == expected[label]:
            return label if record["owned"] == 1 else UNKNOWN
    if record["owned"] == 1 and identity in owned:
        return "other_owned"
    return UNKNOWN


def project_busy_witness(records, *, helper_tag, writer_tag,
                         expected_mounts, owned_mounts):
    """Project receipts to ``(busy_target, writer_close)`` fixed values.

    Exactly one matched-ID ``umount2(flags=0)`` EBUSY return and exactly one
    successful parked-FD close are required.  Anything else is ``unknown``;
    this function never guesses or promotes a failed close to success.
    """
    if not isinstance(records, list) or not records:
        return UNKNOWN, UNKNOWN
    if (type(helper_tag) is not int or type(writer_tag) is not int
            or helper_tag <= 0 or writer_tag <= 0):
        return UNKNOWN, UNKNOWN
    if not isinstance(expected_mounts, dict):
        return UNKNOWN, UNKNOWN
    if not isinstance(owned_mounts, (set, frozenset, list, tuple)):
        return UNKNOWN, UNKNOWN
    owned = set(owned_mounts)
    umounts = [
        record for record in records
        if record["kind"] == "umount"
        and record["role"] == "helper"
        and record["proc_tag"] == helper_tag
        and record["flags"] == 0
    ]
    busy = [
        record for record in umounts
        if record["rc"] == -1 and record["errno"] == errno.EBUSY
    ]
    if len(busy) != 1:
        return UNKNOWN, UNKNOWN
    busy_record = busy[0]
    target = _witness_target(busy_record, expected_mounts, owned)
    closes = [
        record for record in records
        if record["kind"] == "close"
        and record["role"] == "writer"
        and record["proc_tag"] == writer_tag
    ]
    if len(closes) != 1:
        return target, UNKNOWN
    close = closes[0]
    # Only a successful close is evidence of a completed writer close.
    if close["rc"] != 0:
        return target, UNKNOWN
    # Equal samples are uncertain: only a strictly earlier completion is
    # "before", and only a strictly later start is "after".
    if close["result_ns"] < busy_record["entry_ns"]:
        state = "completed_before_unmount_entry"
    elif close["entry_ns"] > busy_record["result_ns"]:
        state = "began_after_busy_return"
    else:
        state = "overlapping"
    return target, state


def project_busy_witness_receipts(witness_dir, *, helper_tag, writer_tag,
                                  expected_mounts, owned_mounts):
    """Read both bounded receipts and project them, defaulting to unknown."""
    try:
        directory = Path(witness_dir)
        helper = parse_witness_receipt(directory / "helper.receipt")
        writer = parse_witness_receipt(directory / "writer.receipt")
    except (OSError, TypeError, ValueError):
        return UNKNOWN, UNKNOWN
    if helper is None or writer is None:
        return UNKNOWN, UNKNOWN
    return project_busy_witness(
        helper + writer,
        helper_tag=helper_tag,
        writer_tag=writer_tag,
        expected_mounts=expected_mounts,
        owned_mounts=owned_mounts,
    )
