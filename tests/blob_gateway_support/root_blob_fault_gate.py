#!/usr/bin/env python3
"""Bounded loopback S3 forward gate for one run-owned registered-pack GET.

The gate is a test fixture only. It forwards every ordinary S3 request to the
configured loopback HTTP endpoint with the original method, path, Host and
headers; in armed mode it immediately refuses only a full canonical pack locator
GET. It never writes logs, reports, headers, bodies or URLs.
"""
from __future__ import annotations

import http.client
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
CONNECT_TIMEOUT = 5.0
IO_TIMEOUT = 5.0
MAX_HANDLERS = 8
STOP_TIMEOUT = 10.0
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding",
              "te", "trailer", "upgrade", "content-length", "expect"}


class RootBlobFaultGate:
    @staticmethod
    def validate_endpoint(endpoint):
        parts = urllib.parse.urlsplit(str(endpoint))
        if parts.scheme != "http":
            raise ValueError("gate upstream must be loopback HTTP")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("gate upstream must not carry credentials/query/fragment")
        if parts.path not in ("", "/"):
            raise ValueError("gate upstream must be an origin")
        host = (parts.hostname or "").lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("gate upstream must be loopback")
        try:
            port = parts.port or 80
        except ValueError:
            raise ValueError("gate upstream port is invalid") from None
        if not (1 <= port <= 65535):
            raise ValueError("gate upstream port is invalid")
        return host, port

    @staticmethod
    def full_path_matches(method, path, armed, target_suffix):
        if not armed or method != "GET" or not target_suffix:
            return False
        path = str(path).split("?", 1)[0]
        suffix = "/" + str(target_suffix).lstrip("/")
        return path == suffix or path.endswith(suffix)

    @staticmethod
    def bounded_body_length(raw_length):
        if raw_length is None:
            return 0
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            raise ValueError("invalid request length") from None
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request length is out of bounds")
        return length

    @staticmethod
    def remaining(deadline):
        return max(0.0, deadline - time.monotonic())

    def __init__(self, upstream_endpoint):
        self.upstream = self.validate_endpoint(upstream_endpoint)
        self.armed = False
        self.target_suffix = None
        self.lock = threading.Lock()
        self.target_gets = 0
        self.forwarded_methods = {}
        self.upstream_errors = 0
        gate = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = IO_TIMEOUT

            def log_message(self, *args):
                pass

            def log_error(self, *args):
                pass

            def do_GET(self):
                gate._serve(self)

            def do_HEAD(self):
                gate._serve(self)

            def do_PUT(self):
                gate._serve(self)

            def do_POST(self):
                gate._serve(self)

            def do_DELETE(self):
                gate._serve(self)

        self.server = _BoundedServer(("127.0.0.1", 0), Handler, gate, MAX_HANDLERS)
        self.port = self.server.server_address[1]
        self.endpoint = "http://127.0.0.1:" + str(self.port)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=False)
        self.started = False

    def start(self):
        if self.started:
            return
        self.thread.start()
        self.started = True

    def arm(self, target_suffix):
        suffix = str(target_suffix).lstrip("/")
        if not suffix or "?" in suffix or "#" in suffix:
            raise ValueError("invalid full pack suffix")
        with self.lock:
            self.target_suffix = suffix
            self.armed = True

    def disarm(self):
        with self.lock:
            self.armed = False

    def snapshot(self):
        with self.lock:
            return {
                "armed": self.armed,
                "target_gets": self.target_gets,
                "forwarded_methods": dict(self.forwarded_methods),
                "upstream_errors": self.upstream_errors,
            }

    def stop(self, deadline=None):
        deadline = time.monotonic() + STOP_TIMEOUT if deadline is None else deadline
        self.disarm()
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.server.server_close()
        except Exception:
            pass
        if self.started:
            self.thread.join(timeout=self.remaining(deadline))
        return (not self.started) or not self.thread.is_alive()

    def _fixed(self, handler, status):
        try:
            handler.send_response_only(status)
            handler.send_header("Content-Length", "0")
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.close_connection = True
            handler.wfile.flush()
        except Exception:
            handler.close_connection = True

    def _serve(self, handler):
        method = handler.command
        path = handler.path
        target = self.full_path_matches(method, path, self.armed, self.target_suffix)
        if target:
            with self.lock:
                self.target_gets += 1
            self._fixed(handler, 503)
            return
        try:
            length = self.bounded_body_length(handler.headers.get("Content-Length"))
            if length and method not in ("PUT", "POST"):
                self._fixed(handler, 400)
                return
            body = handler.rfile.read(length) if length else b""
            if len(body) != length:
                self._fixed(handler, 400)
                return
            headers = [(name, value) for name, value in handler.headers.items()
                       if name.lower() not in HOP_BY_HOP]
            conn = http.client.HTTPConnection(*self.upstream,
                                              timeout=min(CONNECT_TIMEOUT, IO_TIMEOUT))
            try:
                conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
                for name, value in headers:
                    conn.putheader(name, value)
                if body or method in ("PUT", "POST"):
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(body if body else None)
                response = conn.getresponse()
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    self._fixed(handler, 502)
                    return
                response_headers = response.getheaders()
            finally:
                conn.close()
            with self.lock:
                self.forwarded_methods[method] = self.forwarded_methods.get(method, 0) + 1
            self._relay(handler, method, response.status, response_headers, payload)
        except Exception:
            with self.lock:
                self.upstream_errors += 1
            self._fixed(handler, 502)

    @staticmethod
    def _relay(handler, method, status, headers, payload):
        handler.send_response_only(status)
        declared = None
        for name, value in headers:
            if name.lower() == "content-length":
                declared = value
                continue
            if name.lower() in HOP_BY_HOP:
                continue
            handler.send_header(name, value)
        length = len(payload) if method != "HEAD" else (declared or "0")
        handler.send_header("Content-Length", str(length))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.close_connection = True
        if method != "HEAD" and payload:
            handler.wfile.write(payload)
        handler.wfile.flush()


class _BoundedServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True

    def __init__(self, address, handler, gate, max_handlers):
        self.gate = gate
        self._slots = threading.BoundedSemaphore(max_handlers)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.close()
            except Exception:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()
