#!/usr/bin/env python3
"""Support primitives for tests/fuse_helper_lifecycle.py.

This module is *only* a harness: it speaks the length-prefixed helper control
protocol, spawns the real binary in ``--workspace-fuse-helper`` mode, owns the
temporary storage root and records mount-namespace/mountinfo evidence.  It does
not contain a fake helper, a fake FUSE mount or a fallback that would let a
lifecycle case pass without the real native mount.

No database URL, token, credential or environment dump is stored or printed.
The child environment is a minimal allow-list built from scratch.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import random
import re
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 16 * 1024
HEARTBEAT_INTERVAL = 0.20
HEARTBEAT_DEADLINE = 1.5
# Harness-side deadlines are deliberately generous compared with the child's
# own protocol deadlines, but every wait is still bounded.
CALL_DEADLINE = 8.0
MOUNT_DEADLINE = 25.0
FREEZE_DEADLINE = 12.0
EXIT_DEADLINE = 12.0
THREAD_DEADLINE = 15.0

_HEX = re.compile(r"[0-9a-f]{32,}", re.I)
_SECRET_HINT = re.compile(r"(?i)(postgres(?:ql)?://[^\s]+|password=\S+|secret=\S+|token=\S+)")


class HarnessError(RuntimeError):
    """A harness precondition or protocol failure (never a skipped assertion)."""


class RpcError(HarnessError):
    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


class ChildExited(HarnessError):
    pass


def redact(text: object) -> str:
    value = str(text)
    value = _SECRET_HINT.sub("[REDACTED]", value)
    value = _HEX.sub("[REDACTED-HEX]", value)
    return value[-4000:]


def digest_files(paths: list[Path]) -> tuple[str, list[dict]]:
    """Deterministic digest over candidate inputs (path + bytes)."""
    rows = []
    for path in sorted({p.resolve() for p in paths}, key=str):
        if path.is_file():
            data = path.read_bytes()
            rows.append({"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    h = hashlib.sha256()
    for row in rows:
        h.update(row["path"].encode())
        h.update(b"\0")
        h.update(bytes.fromhex(row["sha256"]))
        h.update(b"\0")
    return h.hexdigest(), rows


def binary_receipt(binary: Path) -> dict:
    st = binary.stat()
    data = binary.read_bytes()
    return {
        "path": str(binary),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "executable": os.access(binary, os.X_OK),
    }


def ns_inode(which: str = "mnt") -> int:
    return os.stat(f"/proc/self/ns/{which}").st_ino


def parse_mountinfo(text: str | None = None) -> list[dict]:
    if text is None:
        text = Path("/proc/self/mountinfo").read_text()
    out = []
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        fields = left.split()
        if len(fields) < 6:
            continue
        opt = right.split()
        out.append({
            "mount_id": int(fields[0]),
            "parent_id": int(fields[1]),
            "major_minor": fields[2],
            "root": unescape(fields[3]),
            "mountpoint": unescape(fields[4]),
            "options": fields[5],
            "fstype": opt[0] if opt else "",
            "source": opt[1] if len(opt) > 1 else "",
            "super_options": " ".join(opt[2:]),
        })
    return out


def unescape(field: str) -> str:
    def repl(match: re.Match) -> str:
        return chr(int(match.group(1), 8))

    return re.sub(r"\\([0-7]{3})", repl, field)


def owned_mounts(root: Path, entries: list[dict] | None = None) -> list[dict]:
    root = str(root.resolve())
    rows = entries if entries is not None else parse_mountinfo()
    return [row for row in rows if row["mountpoint"] == root or row["mountpoint"].startswith(root + "/")]


def new_entries(before: list[dict], after: list[dict]) -> list[dict]:
    old = {row["mountpoint"] for row in before}
    return [row for row in after if row["mountpoint"] not in old]


class Frame:
    __slots__ = ("protocol", "generation", "request_id", "workspace", "db_epoch", "op", "args")

    def __init__(self, generation: int, request_id: int, op: str, args=None,
                 workspace: str | None = None, db_epoch: int = 0, protocol: int = PROTOCOL_VERSION):
        self.protocol = protocol
        self.generation = generation
        self.request_id = request_id
        self.workspace = workspace
        self.db_epoch = db_epoch
        self.op = op
        self.args = args

    def object(self) -> dict:
        # Exactly the production Frame fields; no extra field may be smuggled.
        return {
            "protocol": self.protocol,
            "generation": self.generation,
            "request_id": self.request_id,
            "workspace": self.workspace,
            "db_epoch": self.db_epoch,
            "op": self.op,
            "args": self.args,
        }

    def encode(self) -> bytes:
        raw = json.dumps(self.object(), separators=(",", ":")).encode()
        if not raw or len(raw) > MAX_FRAME_BYTES:
            raise HarnessError(f"test frame is {len(raw)} bytes, limit is {MAX_FRAME_BYTES}")
        return struct.pack(">I", len(raw)) + raw


def raw_frame(payload: bytes, declared_len: int | None = None) -> bytes:
    """Build an intentionally malformed frame for negative protocol cases."""
    length = len(payload) if declared_len is None else declared_len
    return struct.pack(">I", length) + payload


class SocketReader:
    """One-frame-at-a-time reader with an absolute deadline per frame."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self, want: int, deadline: float) -> None:
        while len(self.buf) < want:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("helper reply deadline expired")
            readable, _, _ = select.select([self.sock], [], [], remaining)
            if not readable:
                raise TimeoutError("helper reply deadline expired")
            chunk = self.sock.recv(want - len(self.buf))
            if not chunk:
                raise ChildExited("helper control socket closed (EOF)")
            self.buf.extend(chunk)

    def read(self, deadline: float) -> dict:
        self._fill(4, deadline)
        length = struct.unpack(">I", bytes(self.buf[:4]))[0]
        del self.buf[:4]
        if length == 0 or length > MAX_FRAME_BYTES:
            raise RpcError(f"invalid helper reply frame length {length}")
        self._fill(length, deadline)
        raw = bytes(self.buf[:length])
        del self.buf[:length]
        try:
            frame = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RpcError(f"invalid helper reply JSON: {error}") from None
        if not isinstance(frame, dict):
            raise RpcError("helper reply is not a JSON object")
        return frame


class Reply:
    def __init__(self, frame: dict, request_id: int):
        self.frame = frame
        self.request_id = request_id
        self.op = frame.get("op")
        self.args = frame.get("args")
        self.workspace = frame.get("workspace")
        self.db_epoch = frame.get("db_epoch")
        self.generation = frame.get("generation")

    @property
    def ok(self) -> bool:
        return self.op not in ("error",)

    @property
    def code(self) -> int | None:
        if self.op == "error" and isinstance(self.args, dict):
            return self.args.get("code")
        return None

    @property
    def message(self) -> str:
        if self.op == "error" and isinstance(self.args, dict):
            return redact(self.args.get("message", ""))
        return ""

    def __repr__(self) -> str:
        return f"Reply(op={self.op}, code={self.code}, workspace={self.workspace})"


class HelperProcess:
    """The real ``<binary> --workspace-fuse-helper`` child and its two sockets."""

    def __init__(self, binary: Path, log_dir: Path, label: str):
        self.binary = binary
        self.label = label
        self.generation = random.randrange(1, 1 << 62)
        self.next_id = 1000
        self.lock = threading.Lock()
        self.alive = True
        self.stop_heartbeat = threading.Event()
        self.heartbeat_error: str | None = None
        self.exit_code: int | None = None
        self._tmp_log = log_dir / f"helper-{label}.log"
        self.log_path = self._tmp_log
        control_parent, control_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        hb_parent, hb_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LC_ALL": "C",
        }
        self._log = open(self._tmp_log, "wb")
        try:
            self.proc = subprocess.Popen(
                [str(binary), "--workspace-fuse-helper"],
                stdin=control_child,
                stdout=hb_child,
                stderr=self._log,
                env=env,
                close_fds=True,
                start_new_session=True,
            )
        except Exception:
            control_parent.close()
            hb_parent.close()
            control_child.close()
            hb_child.close()
            self._log.close()
            raise
        control_child.close()
        hb_child.close()
        self.control = control_parent
        self.heartbeat = hb_parent
        self.reader = SocketReader(control_parent)
        self.heartbeat.settimeout(1.0)
        self._hb_thread = threading.Thread(target=self._heartbeat_loop, name=f"hb-{label}", daemon=True)
        self._hb_thread.start()

    def _heartbeat_loop(self) -> None:
        seq = 0
        while not self.stop_heartbeat.is_set():
            seq += 1
            frame = Frame(self.generation, 0, "heartbeat", {"seq": seq})
            try:
                with self.lock:
                    self.heartbeat.sendall(frame.encode())
            except OSError as error:
                self.heartbeat_error = redact(error)
                return
            self.stop_heartbeat.wait(HEARTBEAT_INTERVAL)

    def request_id(self) -> int:
        with self.lock:
            self.next_id += 1
            return self.next_id

    def send(self, op: str, args=None, workspace: str | None = None,
             db_epoch: int = 0, request_id: int | None = None) -> tuple[int, float]:
        rid = request_id if request_id is not None else self.request_id()
        frame = Frame(self.generation, rid, op, args, workspace, db_epoch)
        with self.lock:
            self.control.sendall(frame.encode())
        return rid, time.monotonic()

    def send_frame(self, frame: Frame) -> None:
        with self.lock:
            self.control.sendall(frame.encode())

    def read(self, timeout: float = CALL_DEADLINE) -> dict:
        return self.reader.read(time.monotonic() + timeout)

    def call(self, op: str, args=None, workspace: str | None = None,
             db_epoch: int = 0, timeout: float = CALL_DEADLINE) -> Reply:
        rid, _ = self.send(op, args, workspace, db_epoch)
        try:
            frame = self.read(timeout)
        except ChildExited:
            self.alive = False
            raise
        if frame.get("request_id") != rid:
            raise RpcError(f"reply request_id {frame.get('request_id')} does not match {rid}")
        return Reply(frame, rid)

    def hello(self, version: int = PROTOCOL_VERSION, timeout: float = CALL_DEADLINE) -> Reply:
        return self.call("hello", {"pid": os.getpid(), "version": version}, timeout=timeout)

    def mount(self, root: Path, workspace: str, epoch: int = 1,
              lease_until: int | None = None, lazy: bool = False,
              timeout: float = MOUNT_DEADLINE) -> Reply:
        args = {
            "root": str(root.resolve()),
            "workspace": workspace,
            "lease_until": lease_until if lease_until is not None else int(time.time()) + 3600,
            "lazy": lazy,
        }
        return self.call("mount", args, workspace=workspace, db_epoch=epoch, timeout=timeout)

    def freeze_begin(self, workspace: str, epoch: int, op_id: int,
                     timeout: float = FREEZE_DEADLINE) -> Reply:
        return self.call("freeze_begin", {"op_id": op_id}, workspace=workspace,
                         db_epoch=epoch, timeout=timeout)

    def freeze_finish(self, workspace: str, epoch: int, op_id: int, thaw: bool,
                      timeout: float = FREEZE_DEADLINE) -> tuple[Reply, float]:
        started = time.monotonic()
        reply = self.call("freeze_finish", {"op_id": op_id, "epoch": epoch, "thaw": thaw},
                          workspace=workspace, db_epoch=epoch, timeout=timeout)
        return reply, time.monotonic() - started

    def marker(self, workspace: str, epoch: int, timeout: float = CALL_DEADLINE) -> Reply:
        return self.call("marker", None, workspace=workspace, db_epoch=epoch, timeout=timeout)

    def state_phase(self, workspace: str, epoch: int, timeout: float = CALL_DEADLINE) -> str:
        reply = self.marker(workspace, epoch, timeout)
        if not reply.ok or not isinstance(reply.args, dict):
            raise RpcError(f"marker failed: {reply.message or reply.op}")
        return str(reply.args.get("phase", "")).lower()

    def handoff(self, workspace: str, epoch: int, until: int | None = None,
                timeout: float = CALL_DEADLINE) -> Reply:
        return self.call("handoff", {"epoch": epoch, "until": until if until is not None else int(time.time()) + 3600},
                         workspace=workspace, db_epoch=epoch, timeout=timeout)

    def shutdown(self, timeout: float = CALL_DEADLINE) -> Reply:
        return self.call("shutdown", None, timeout=timeout)

    def close_heartbeat(self) -> None:
        self.stop_heartbeat.set()
        try:
            self.heartbeat.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.heartbeat.close()

    def stop(self) -> None:
        self.alive = False
        self.stop_heartbeat.set()
        try:
            self.heartbeat.close()
        except OSError:
            pass
        try:
            self.control.close()
        except OSError:
            pass
        try:
            self._hb_thread.join(2)
        except RuntimeError:
            pass
        try:
            self._log.flush()
            self._log.close()
        except OSError:
            pass

    def kill(self) -> None:
        try:
            os.kill(self.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.wait_exit(EXIT_DEADLINE)

    def signal(self, sig: int) -> None:
        os.kill(self.proc.pid, sig)

    def wait_exit(self, timeout: float = EXIT_DEADLINE) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.exit_code = code
                self.alive = False
                return code
            time.sleep(0.02)
        raise HarnessError(f"helper {self.label} did not exit within {timeout}s")

    def log_tail(self) -> str:
        try:
            data = self.log_path.read_bytes()
        except OSError:
            return ""
        return redact(data.decode(errors="replace")[-2000:])


class ParkedWriter(threading.Thread):
    """A real pwrite/write loop through the native FUSE mount.

    While the mount gate is frozen the dispatch actor parks the next write
    request and holds its reply, so this thread is genuinely blocked in a write
    syscall; after a thaw it resumes, after a fence it returns EROFS.
    """

    def __init__(self, path: Path, chunk: int = 64 * 1024, limit_bytes: int = 256 * 1024 * 1024):
        super().__init__(name=f"writer-{path.name}", daemon=True)
        self.path = path
        self.chunk = b"x" * chunk
        self.limit_bytes = limit_bytes
        self.bytes = 0
        self.error: OSError | None = None
        self.started = threading.Event()
        self.stop = threading.Event()
        self.fd: int | None = None
        self.finished = threading.Event()

    def run(self) -> None:
        try:
            self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            self.started.set()
            while not self.stop.is_set() and self.bytes < self.limit_bytes:
                written = os.write(self.fd, self.chunk)
                if written <= 0:
                    raise OSError(errno.EIO, "short write")
                self.bytes += written
        except OSError as error:
            self.error = error
        finally:
            if self.fd is not None:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
            self.finished.set()

    def wait_started(self, timeout: float = 5.0) -> None:
        if not self.started.wait(timeout):
            raise HarnessError(f"writer for {self.path} did not start")
        deadline = time.monotonic() + timeout
        while self.bytes <= 0 and time.monotonic() < deadline:
            time.sleep(0.005)
        if self.bytes <= 0:
            raise HarnessError(f"writer for {self.path} wrote nothing")

    def quiesce(self, settle: float = 0.4) -> int:
        time.sleep(settle)
        return self.bytes

    def finish(self, timeout: float = THREAD_DEADLINE) -> None:
        self.stop.set()
        self.join(timeout)
        if self.is_alive():
            raise HarnessError(f"writer for {self.path} stayed blocked after release")


class WorkFixture:
    """Owned private root with real ``git init`` lowers and fixed helper paths."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-fuse-helper-"))
        self.service = self.root / "workspace-service"
        for name in ("workspaces", "uppers", "mounts"):
            (self.service / name).mkdir(mode=0o700)
        self.workspaces: dict[str, Path] = {}
        self.mounts: dict[str, Path] = {}

    def workspace(self, name: str) -> str:
        import uuid

        wid = str(uuid.uuid4())
        lower = self.service / "workspaces" / wid
        lower.mkdir(mode=0o700)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
        subprocess.run(["git", "init", "-q", "-b", "main", str(lower)], env=env, check=True, timeout=30)
        (lower / f"{name}.txt").write_text(f"lower-{name}\n")
        subprocess.run(["git", "-c", "commit.gpgsign=false", "add", f"{name}.txt"], cwd=lower,
                       env=env, check=True, timeout=30)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture"],
                       cwd=lower, env=env, check=True, timeout=30)
        self.workspaces[wid] = lower
        self.mounts[wid] = self.service / "mounts" / wid
        return wid

    def cleanup(self, mount_check) -> dict:
        evidence = {"mounts_before": [row["mountpoint"] for row in owned_mounts(self.root)]}
        mount_check()
        evidence["mounts_after"] = [row["mountpoint"] for row in owned_mounts(self.root)]
        evidence["temp_root_removed"] = False
        if not evidence["mounts_after"]:
            shutil.rmtree(self.root, ignore_errors=True)
            evidence["temp_root_removed"] = not self.root.exists()
        return evidence


def umount_owned(root: Path) -> list[dict]:
    """Non-lazy umount backstop for owned mountpoints only.

    The helper is SIGKILLed first so its FUSE descriptors are gone; a normal
    umount is used only if the kernel still shows an owned mountpoint.  Lazy
    detach is deliberately never used: it could leave a blocked request in D.
    """
    results = []
    libc = ctypes.CDLL(None, use_errno=True)
    for row in owned_mounts(root):
        point = row["mountpoint"]
        rc = libc.umount2(point.encode(), 0)
        results.append({"mountpoint": point, "rc": rc, "errno": ctypes.get_errno() if rc else 0})
    return results


def ensure_namespace(script: Path, argv: list[str]) -> None:
    """Re-exec the whole harness inside a private owned mount namespace."""
    token = os.environ.get("ROOTYARD_FUSE_HELPER_NS_TOKEN")
    caller = os.environ.get("ROOTYARD_FUSE_HELPER_CALLER_NS")
    if token and caller:
        current = str(ns_inode("mnt"))
        if current == caller:
            raise HarnessError("unshare did not change the mount namespace")
        return
    if shutil.which("unshare") is None:
        raise HarnessError("unshare is required for the private owned namespace")
    token = hashlib.sha256(os.urandom(32)).hexdigest()
    caller_ns = str(ns_inode("mnt"))
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LC_ALL": "C",
        "ROOTYARD_FUSE_HELPER_NS_TOKEN": token,
        "ROOTYARD_FUSE_HELPER_CALLER_NS": caller_ns,
        "ROOTYARD_FUSE_HELPER_OWNED_NS": str(ns_inode("mnt")),
    }
    argv = ["unshare", "-Urm", "--propagation", "private", sys.executable, str(script), *argv]
    os.execvpe("unshare", argv, env)


def process_state(pid: int) -> str | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    return text.rsplit(")", 1)[-1].split()[0]


def wait_pid_gone(pid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = process_state(pid)
        if state is None or state == "Z":
            return True
        time.sleep(0.05)
    return False


def preconditions(binary: Path) -> dict:
    facts = {
        "binary_exists": binary.is_file(),
        "binary_executable": os.access(binary, os.X_OK),
        "fuse_device": Path("/dev/fuse").exists(),
        "fuse_device_char": False,
        "unshare": shutil.which("unshare") is not None,
        "git": shutil.which("git") is not None,
        "mount_ns": str(ns_inode("mnt")),
        "pid_ns": str(ns_inode("pid")),
    }
    try:
        facts["fuse_device_char"] = stat.S_ISCHR(Path("/dev/fuse").stat().st_mode)
    except OSError:
        pass
    missing = [name for name in ("binary_exists", "binary_executable", "fuse_device",
                                 "fuse_device_char", "unshare", "git") if not facts[name]]
    facts["missing"] = missing
    return facts
