"""Wire-transparent loopback S3 HTTP/1.1 metering proxy preserving SigV4 headers (Refs #178)."""

from __future__ import annotations

import socket
import threading
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
        headers[key] = f"{headers[key]}, {val}" if key in headers else val
    return first, second, third, headers


class S3MeterProxy:
    """Byte-transparent loopback HTTP/1.1 proxy preserving Host for SigV4 metering."""

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

    def reset_counters(self) -> None:
        with self._lock:
            self._req_counts.clear()
            self._req_bytes.clear()
            self._resp_bytes.clear()
            self._status_counts.clear()
            self._error_responses = 0

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "observed": True,
                "get_requests": self._req_counts.get("GET", 0),
                "get_bytes": self._resp_bytes.get("GET", 0),
                "put_requests": self._req_counts.get("PUT", 0),
                "put_bytes": self._req_bytes.get("PUT", 0),
                "head_requests": self._req_counts.get("HEAD", 0),
                "delete_requests": self._req_counts.get("DELETE", 0),
                "req_counts_by_method": dict(self._req_counts),
                "req_bytes_by_method": dict(self._req_bytes),
                "resp_bytes_by_method": dict(self._resp_bytes),
                "status_counts": dict(self._status_counts),
                "error_responses": self._error_responses,
            }

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
            sk = str(status)
            self._status_counts[sk] = self._status_counts.get(sk, 0) + 1
            if status >= 400:
                self._error_responses += 1

    def _handle_conn(self, client_sock: socket.socket) -> None:
        upstream_sock: socket.socket | None = None
        try:
            client_sock.settimeout(30.0)
            upstream_sock = socket.create_connection((self.upstream_host, self.upstream_port), timeout=15.0)
            upstream_sock.settimeout(30.0)
            c_stream = BufferedConn(client_sock)
            u_stream = BufferedConn(upstream_sock)

            while not self._stop.is_set():
                raw_req_head = c_stream.read_until(b"\r\n\r\n")
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
                    raw_resp_head = u_stream.read_until(b"\r\n\r\n")
                    if not raw_resp_head:
                        break
                    _, status_str, _, _ = _parse_http_head(raw_resp_head)
                    status_code = int(status_str) if status_str.isdigit() else 500
                    client_sock.sendall(raw_resp_head)
                    if status_code >= 200:
                        early_final = True

                if not early_final:
                    if "chunked" in req_headers.get("transfer-encoding", "").lower():
                        req_body_bytes = c_stream.forward_chunked(upstream_sock)
                    elif req_headers.get("content-length"):
                        req_len = int(req_headers["content-length"])
                        if req_len > 0:
                            req_body_bytes = c_stream.forward_exact(upstream_sock, req_len)

                while True:
                    if early_final:
                        early_final = False
                    else:
                        raw_resp_head = u_stream.read_until(b"\r\n\r\n")
                        if not raw_resp_head:
                            return
                        client_sock.sendall(raw_resp_head)
                    _, status_str, _, resp_headers = _parse_http_head(raw_resp_head)
                    status = int(status_str) if status_str.isdigit() else 500
                    if 100 <= status < 200 and status != 101:
                        continue
                    resp_body_bytes = 0
                    close_conn = (
                        req_headers.get("connection", "").lower() == "close"
                        or resp_headers.get("connection", "").lower() == "close"
                        or req_version == "HTTP/1.0"
                    )
                    if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
                        pass
                    elif "chunked" in resp_headers.get("transfer-encoding", "").lower():
                        resp_body_bytes = u_stream.forward_chunked(client_sock)
                    elif resp_headers.get("content-length"):
                        resp_len = int(resp_headers["content-length"])
                        if resp_len > 0:
                            resp_body_bytes = u_stream.forward_exact(client_sock, resp_len)
                    else:
                        resp_body_bytes = u_stream.forward_until_eof(client_sock)
                        close_conn = True
                    self._record(method, req_body_bytes, resp_body_bytes, status)
                    if close_conn:
                        return
                    break
        except (OSError, EOFError, ValueError):
            pass
        finally:
            for s in (client_sock, upstream_sock):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
