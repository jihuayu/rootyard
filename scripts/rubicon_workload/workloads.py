"""Wire-level S3 telemetry proxy, /proc + PG samplers, and HTTP/Git client helpers (Refs #164)."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

READ_CHUNK = 65536


class BufferedConn:
    """Line-and-chunk buffered wrapper around a blocking TCP socket."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self._buf = bytearray()

    def read_until(self, delimiter: bytes, max_bytes: int = 262144) -> bytes:
        while True:
            idx = self._buf.find(delimiter)
            if idx != -1:
                end = idx + len(delimiter)
                out = bytes(self._buf[:end])
                del self._buf[:end]
                return out
            if len(self._buf) >= max_bytes:
                raise ValueError("HTTP header exceeded bound")
            chunk = self.sock.recv(READ_CHUNK)
            if not chunk:
                if not self._buf:
                    return b""
                raise EOFError("unexpected EOF before delimiter")
            self._buf.extend(chunk)

    def read_exact(self, length: int) -> bytes:
        chunks: list[bytes] = []
        remaining = length
        if self._buf:
            take = min(remaining, len(self._buf))
            chunks.append(bytes(self._buf[:take]))
            del self._buf[:take]
            remaining -= take
        while remaining > 0:
            chunk = self.sock.recv(min(READ_CHUNK, remaining))
            if not chunk:
                raise EOFError("unexpected EOF inside fixed-length HTTP body")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def forward_exact(self, dst: socket.socket, length: int) -> int:
        remaining = length
        if self._buf and remaining > 0:
            take = min(remaining, len(self._buf))
            dst.sendall(self._buf[:take])
            del self._buf[:take]
            remaining -= take
        while remaining > 0:
            chunk = self.sock.recv(min(READ_CHUNK, remaining))
            if not chunk:
                raise EOFError("unexpected EOF while forwarding fixed-length HTTP body")
            dst.sendall(chunk)
            remaining -= len(chunk)
        return length

    def forward_chunked(self, dst: socket.socket) -> int:
        total_payload = 0
        while True:
            line = self.read_until(b"\r\n")
            if not line:
                raise EOFError("unexpected EOF reading chunk size")
            dst.sendall(line)
            size_hex = line[:-2].split(b";", 1)[0].strip()
            size = int(size_hex, 16)
            if size == 0:
                while True:
                    trailer = self.read_until(b"\r\n")
                    if not trailer:
                        raise EOFError("unexpected EOF reading chunk trailers")
                    dst.sendall(trailer)
                    if trailer == b"\r\n":
                        return total_payload
            self.forward_exact(dst, size)
            total_payload += size
            crlf = self.read_exact(2)
            if crlf != b"\r\n":
                raise ValueError("malformed HTTP chunk delimiter")
            dst.sendall(crlf)

    def forward_until_eof(self, dst: socket.socket) -> int:
        total = 0
        if self._buf:
            dst.sendall(self._buf)
            total += len(self._buf)
            self._buf.clear()
        while True:
            chunk = self.sock.recv(READ_CHUNK)
            if not chunk:
                return total
            dst.sendall(chunk)
            total += len(chunk)


def _parse_http_head(raw_head: bytes) -> tuple[str, str, str, dict[str, str]]:
    text = raw_head.decode("latin-1")
    lines = text.split("\r\n")
    parts = lines[0].split(" ", 2)
    first = parts[0]
    second = parts[1] if len(parts) > 1 else ""
    third = parts[2] if len(parts) > 2 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()
        if key in headers:
            headers[key] = f"{headers[key]}, {val}"
        else:
            headers[key] = val
    return first, second, third, headers


class S3MeterProxy:
    """Byte-transparent loopback HTTP/1.1 proxy preserving all headers (including Host for SigV4)."""

    def __init__(self, upstream_host: str, upstream_port: int) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen.bind(("127.0.0.1", 0))
        self._listen.listen(128)
        self._listen.settimeout(0.25)
        self.port: int = self._listen.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._req_counts: dict[str, int] = {}
        self._req_bytes: dict[str, int] = {}
        self._resp_bytes: dict[str, int] = {}
        self._status_counts: dict[str, int] = {}
        self._error_responses = 0
        self._threads: list[threading.Thread] = []
        self._accept_thread: threading.Thread | None = None

    def start(self) -> None:
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listen.close()
        except OSError:
            pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
        for t in self._threads:
            t.join(timeout=0.5)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client_sock, _ = self._listen.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(client_sock,), daemon=True)
            t.start()
            with self._lock:
                self._threads = [item for item in self._threads if item.is_alive()]
                self._threads.append(t)

    def _record(self, method: str, req_bytes: int, resp_bytes: int, status: int) -> None:
        with self._lock:
            self._req_counts[method] = self._req_counts.get(method, 0) + 1
            self._req_bytes[method] = self._req_bytes.get(method, 0) + req_bytes
            self._resp_bytes[method] = self._resp_bytes.get(method, 0) + resp_bytes
            s_key = str(status)
            self._status_counts[s_key] = self._status_counts.get(s_key, 0) + 1
            if status >= 400:
                self._error_responses += 1

    def _handle_conn(self, client_sock: socket.socket) -> None:
        upstream_sock: socket.socket | None = None
        try:
            client_sock.settimeout(30.0)
            upstream_sock = socket.create_connection((self.upstream_host, self.upstream_port), timeout=15.0)
            upstream_sock.settimeout(30.0)
            client_stream = BufferedConn(client_sock)
            upstream_stream = BufferedConn(upstream_sock)

            while not self._stop.is_set():
                raw_req_head = client_stream.read_until(b"\r\n\r\n")
                if not raw_req_head:
                    break
                method, _, req_version, req_headers = _parse_http_head(raw_req_head)
                method = method.upper()
                upstream_sock.sendall(raw_req_head)

                expect_100 = "100-continue" in req_headers.get("expect", "").lower()
                early_final = False
                req_body_bytes = 0
                raw_resp_head = b""

                if expect_100:
                    raw_resp_head = upstream_stream.read_until(b"\r\n\r\n")
                    if not raw_resp_head:
                        break
                    _, status_str, _, resp_headers = _parse_http_head(raw_resp_head)
                    status_code = int(status_str) if status_str.isdigit() else 500
                    client_sock.sendall(raw_resp_head)
                    if status_code >= 200:
                        early_final = True

                if not early_final:
                    te_req = req_headers.get("transfer-encoding", "").lower()
                    if "chunked" in te_req:
                        req_body_bytes = client_stream.forward_chunked(upstream_sock)
                    elif "content-length" in req_headers:
                        cl = int(req_headers["content-length"])
                        if cl > 0:
                            req_body_bytes = client_stream.forward_exact(upstream_sock, cl)

                    while True:
                        raw_resp_head = upstream_stream.read_until(b"\r\n\r\n")
                        if not raw_resp_head:
                            break
                        _, status_str, _, resp_headers = _parse_http_head(raw_resp_head)
                        status_code = int(status_str) if status_str.isdigit() else 500
                        client_sock.sendall(raw_resp_head)
                        if not (100 <= status_code < 200):
                            break
                    if not raw_resp_head:
                        break
                else:
                    _, status_str, _, resp_headers = _parse_http_head(raw_resp_head)
                    status_code = int(status_str) if status_str.isdigit() else 500

                resp_body_bytes = 0
                te_resp = resp_headers.get("transfer-encoding", "").lower()
                conn_resp = resp_headers.get("connection", "").lower()
                conn_req = req_headers.get("connection", "").lower()
                close_after = "close" in conn_resp or "close" in conn_req or req_version == "HTTP/1.0"

                if method != "HEAD" and status_code not in (204, 304):
                    if "chunked" in te_resp:
                        resp_body_bytes = upstream_stream.forward_chunked(client_sock)
                    elif "content-length" in resp_headers:
                        cl_resp = int(resp_headers["content-length"])
                        if cl_resp > 0:
                            resp_body_bytes = upstream_stream.forward_exact(client_sock, cl_resp)
                    elif "close" in conn_resp:
                        resp_body_bytes = upstream_stream.forward_until_eof(client_sock)
                        close_after = True

                self._record(method, req_body_bytes, resp_body_bytes, status_code)
                if close_after:
                    break
        except (OSError, ValueError, EOFError):
            pass
        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            if upstream_sock is not None:
                try:
                    upstream_sock.close()
                except OSError:
                    pass

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "observed": True,
                "get_requests": self._req_counts.get("GET", 0),
                "get_bytes": self._resp_bytes.get("GET", 0),
                "put_requests": self._req_counts.get("PUT", 0),
                "put_bytes": self._req_bytes.get("PUT", 0),
                "head_requests": self._req_counts.get("HEAD", 0),
                "other_requests": sum(
                    v for k, v in self._req_counts.items() if k not in ("GET", "PUT", "HEAD")
                ),
                "total_requests": sum(self._req_counts.values()),
                "error_responses": self._error_responses,
                "status_counts": dict(self._status_counts),
            }

    @staticmethod
    def delta(after: dict[str, Any], before: dict[str, Any]) -> dict[str, Any]:
        return {
            "observed": True,
            "get_requests": after["get_requests"] - before["get_requests"],
            "get_bytes": after["get_bytes"] - before["get_bytes"],
            "put_requests": after["put_requests"] - before["put_requests"],
            "put_bytes": after["put_bytes"] - before["put_bytes"],
            "head_requests": after["head_requests"] - before["head_requests"],
            "other_requests": after["other_requests"] - before["other_requests"],
            "total_requests": after["total_requests"] - before["total_requests"],
            "error_responses": after["error_responses"] - before["error_responses"],
        }


def _sum_dir_bytes(dirs: list[Path], exclude_roots: set[Path] | None = None) -> int:
    """Recursively sum regular non-symlink file sizes without double-counting excluded subtrees."""
    total = 0
    seen_roots: set[Path] = set()
    excluded = exclude_roots or set()
    for dpath in dirs:
        if not dpath.exists():
            continue
        try:
            resolved_dir = dpath.resolve()
        except OSError:
            continue
        if resolved_dir in seen_roots or resolved_dir in excluded:
            continue
        seen_roots.add(resolved_dir)
        try:
            for root, dirnames, filenames in os.walk(resolved_dir, followlinks=False):
                root_path = Path(root)
                dirnames[:] = [dn for dn in dirnames if (root_path / dn).resolve() not in excluded]
                for fname in filenames:
                    fpath = root_path / fname
                    try:
                        if not fpath.is_symlink():
                            total += fpath.stat().st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return total


def read_proc_metrics(
    pids: list[int],
    scratch_dirs: list[Path],
    worktree_dirs: list[Path] | None = None,
) -> dict[str, Any]:
    """Read Linux /proc metrics for active serve-blob PIDs plus server scratch and client worktree disk."""
    total_rss_kib = 0
    total_hwm_kib = 0
    total_cpu_ticks = 0
    total_read_bytes = 0
    total_write_bytes = 0
    alive = 0
    for pid in pids:
        proc_dir = Path("/proc") / str(pid)
        if not proc_dir.is_dir():
            continue
        try:
            status_text = (proc_dir / "status").read_text(encoding="utf-8", errors="replace")
            stat_text = (proc_dir / "stat").read_text(encoding="utf-8", errors="replace")
            alive += 1
            for line in status_text.splitlines():
                if line.startswith("VmRSS:"):
                    total_rss_kib += int(line.split()[1])
                elif line.startswith("VmHWM:"):
                    total_hwm_kib += int(line.split()[1])
            rparen = stat_text.rfind(")")
            if rparen != -1:
                fields = stat_text[rparen + 2 :].split()
                total_cpu_ticks += int(fields[11]) + int(fields[12])
            io_path = proc_dir / "io"
            if io_path.is_file():
                for line in io_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("read_bytes:"):
                        total_read_bytes += int(line.split()[1])
                    elif line.startswith("write_bytes:"):
                        total_write_bytes += int(line.split()[1])
        except (OSError, ValueError, IndexError):
            continue

    server_scratch_bytes = _sum_dir_bytes(scratch_dirs)
    scratch_resolved = {d.resolve() for d in scratch_dirs if d.exists()}
    client_worktree_bytes = _sum_dir_bytes(worktree_dirs or [], exclude_roots=scratch_resolved)
    temp_disk_bytes = server_scratch_bytes + client_worktree_bytes

    clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    return {
        "alive_pids": alive,
        "rss_kib": total_rss_kib,
        "hwm_kib": total_hwm_kib,
        "cpu_seconds": round(total_cpu_ticks / float(clk_tck), 4),
        "io_read_bytes": total_read_bytes,
        "io_write_bytes": total_write_bytes,
        "temp_disk_bytes": temp_disk_bytes,
        "server_scratch_bytes": server_scratch_bytes,
        "client_worktree_bytes": client_worktree_bytes,
    }


def query_pg_snapshot_json(pg_url: str, base_env: dict[str, str]) -> dict[str, int]:
    """Query exact RefStore pack counts, serving vs coexisting bytes, backlog, and lock waits."""
    sql = (
        "SELECT json_build_object("
        "'pack_count', (SELECT COUNT(*)::bigint FROM ref_store_core_pack_memberships),"
        "'serving_pack_bytes', (SELECT COALESCE(SUM(a.content_length), 0)::bigint "
        "FROM ref_store_core_pack_artifacts a "
        "JOIN (SELECT DISTINCT repository_id, registration_id, pack_id FROM ref_store_core_pack_memberships) m "
        "ON m.repository_id = a.repository_id AND m.registration_id = a.registration_id AND m.pack_id = a.pack_id),"
        "'publication_count', (SELECT COUNT(*)::bigint FROM ref_store_core_pack_publications),"
        "'coexisting_pack_bytes', (SELECT COALESCE(SUM(content_length), 0)::bigint FROM ref_store_core_pack_artifacts),"
        "'active_serving_reads', (SELECT COUNT(*)::bigint FROM ref_store_core_serving_reads WHERE expires_at > clock_timestamp()),"
        "'pending_ops', (SELECT COUNT(*)::bigint FROM ref_store_operations WHERE state = 'pending'),"
        "'pg_active', (SELECT COUNT(*)::bigint FROM pg_stat_activity WHERE datname = current_database() AND state = 'active' AND pid <> pg_backend_pid()),"
        "'pg_lock_waiters', (SELECT COUNT(*)::bigint FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid())"
        ")::text;"
    )
    proc = subprocess.run(
        ["psql", "--dbname", pg_url, "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql],
        env=base_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"psql snapshot failed ({proc.returncode}): {proc.stderr.decode(errors='replace')[:300]}")
    raw = proc.stdout.decode("utf-8").strip()
    return {k: int(v) for k, v in json.loads(raw).items()}


@dataclass
class ResourceSampler:
    """Periodic Linux /proc + PG time-series sampler active across workload execution."""

    pg_url: str
    base_env: dict[str, str]
    interval_seconds: float = 0.5
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _pids: list[int] = field(default_factory=list)
    _scratch_dirs: list[Path] = field(default_factory=list)
    _worktree_dirs: list[Path] = field(default_factory=list)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    _started_mono: float = 0.0
    time_series: list[dict[str, Any]] = field(default_factory=list)
    max_rss_kib: int = 0
    max_hwm_kib: int = 0
    max_temp_disk_bytes: int = 0
    max_server_scratch_bytes: int = 0
    max_client_worktree_bytes: int = 0
    max_pg_active: int = 0
    max_pg_lock_waiters: int = 0
    last_cpu_seconds_by_epoch: dict[int, float] = field(default_factory=dict)
    completed_cpu_seconds: float = 0.0
    _epoch: int = 0
    errors: list[str] = field(default_factory=list)

    def set_targets(
        self,
        pids: list[int],
        scratch_dirs: list[Path],
        new_epoch: bool = False,
        worktree_dirs: list[Path] | None = None,
    ) -> None:
        with self._lock:
            if new_epoch and self._epoch in self.last_cpu_seconds_by_epoch:
                self.completed_cpu_seconds += self.last_cpu_seconds_by_epoch[self._epoch]
                self._epoch += 1
            self._pids = list(pids)
            self._scratch_dirs = list(scratch_dirs)
            if worktree_dirs is not None:
                self._worktree_dirs = list(worktree_dirs)

    def start(self) -> None:
        self._started_mono = time.monotonic()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        self.sample_once()

    def sample_once(self) -> None:
        with self._lock:
            pids = list(self._pids)
            dirs = list(self._scratch_dirs)
            worktree_dirs = list(self._worktree_dirs)
            epoch = self._epoch
        if not pids:
            return
        try:
            proc_snap = read_proc_metrics(pids, dirs, worktree_dirs=worktree_dirs)
            pg_snap = query_pg_snapshot_json(self.pg_url, self.base_env)
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self.errors.append(str(exc)[:200])
            return
        t_ms = int((time.monotonic() - self._started_mono) * 1000.0)
        with self._lock:
            self.max_rss_kib = max(self.max_rss_kib, proc_snap["rss_kib"])
            self.max_hwm_kib = max(self.max_hwm_kib, proc_snap["hwm_kib"])
            self.max_temp_disk_bytes = max(self.max_temp_disk_bytes, proc_snap["temp_disk_bytes"])
            self.max_server_scratch_bytes = max(self.max_server_scratch_bytes, proc_snap["server_scratch_bytes"])
            self.max_client_worktree_bytes = max(self.max_client_worktree_bytes, proc_snap["client_worktree_bytes"])
            self.max_pg_active = max(self.max_pg_active, pg_snap["pg_active"])
            self.max_pg_lock_waiters = max(self.max_pg_lock_waiters, pg_snap["pg_lock_waiters"])
            if proc_snap["alive_pids"] > 0:
                self.last_cpu_seconds_by_epoch[epoch] = max(
                    self.last_cpu_seconds_by_epoch.get(epoch, 0.0), proc_snap["cpu_seconds"]
                )
            self.time_series.append(
                {
                    "t_ms": t_ms,
                    **pg_snap,
                    "rss_kib": proc_snap["rss_kib"],
                    "temp_disk_bytes": proc_snap["temp_disk_bytes"],
                    "server_scratch_bytes": proc_snap["server_scratch_bytes"],
                    "client_worktree_bytes": proc_snap["client_worktree_bytes"],
                }
            )

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.sample_once()
            self._stop.wait(self.interval_seconds)

    def total_cpu_seconds(self) -> float:
        with self._lock:
            current = self.last_cpu_seconds_by_epoch.get(self._epoch, 0.0)
            return round(self.completed_cpu_seconds + current, 4)


def http_json(
    base_url: str,
    path: str,
    token: dict[str, str] | None = None,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: int = 20,
) -> tuple[int | None, bytes, dict[str, str], float]:
    """Perform a single HTTP JSON API call and measure wall latency cleanly."""
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token['token']}"
    data: bytes | None = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, raw, dict(resp.headers), (time.monotonic() - start) * 1000.0
    except urllib.error.HTTPError as err:
        raw = err.read()
        return err.code, raw, dict(err.headers), (time.monotonic() - start) * 1000.0
    except Exception:  # noqa: BLE001
        return None, b"", {}, (time.monotonic() - start) * 1000.0
