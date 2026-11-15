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
HANDLER_TIMEOUT = 20.0
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

    @staticmethod
    def join_handlers(threads, listener, deadline):
        """Join owned handler/listener threads only for the remaining budget."""
        while True:
            remaining = RootBlobFaultGate.remaining(deadline)
            alive = [thread for thread in threads if thread.is_alive()]
            listener_alive = listener is not None and listener.is_alive()
            if not alive and not listener_alive:
                return True
            if remaining <= 0:
                return False
            for thread in alive:
                thread.join(timeout=min(0.05, remaining))
            if listener_alive:
                listener.join(timeout=min(0.05, remaining))

    def __init__(self, upstream_endpoint):
        self.upstream = self.validate_endpoint(upstream_endpoint)
        self.armed = False
        self.target_suffix = None
        self.lock = threading.Lock()
        self.target_gets = 0
        self.forwarded_methods = {}
        self.upstream_errors = 0
        self._handlers = {}
        self._connections = set()
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
                                       kwargs={"poll_interval": 0.05}, daemon=True)
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
        with self.lock:
            handlers = list(self._handlers)
            requests = list(self._handlers.values())
            connections = list(self._connections)
        for request in requests:
            try:
                request.shutdown(2)
            except Exception:
                pass
            try:
                request.close()
            except Exception:
                pass
        for connection in connections:
            try:
                connection.close()
            except Exception:
                pass
        if self.started:
            self.thread.join(timeout=self.remaining(deadline))
        return self.join_handlers(handlers, self.thread if self.started else None, deadline)

    def _set_timeout(self, handler, deadline):
        remaining = self.remaining(deadline)
        if remaining <= 0:
            raise TimeoutError("gate handler deadline exhausted")
        try:
            handler.connection.settimeout(min(IO_TIMEOUT, remaining))
        except Exception:
            pass

    def _read_exact(self, handler, length, deadline):
        body = bytearray()
        while len(body) < length:
            self._set_timeout(handler, deadline)
            remaining = min(65536, length - len(body))
            chunk = handler.rfile.read1(remaining)
            if not chunk:
                break
            body.extend(chunk)
        if len(body) != length:
            raise ValueError("short gate request body")
        return bytes(body)

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

    def _note_forward(self, method):
        with self.lock:
            self.forwarded_methods[method] = self.forwarded_methods.get(method, 0) + 1

    def _expire_handler(self, handler):
        try:
            handler.connection.shutdown(2)
        except Exception:
            pass
        try:
            handler.connection.close()
        except Exception:
            pass
        conn = getattr(handler, "_upstream_conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    def _serve(self, handler):
        expiration = threading.Timer(HANDLER_TIMEOUT, self._expire_handler, args=(handler,))
        expiration.daemon = True
        expiration.start()
        try:
            self._serve_bounded(handler)
        finally:
            expiration.cancel()

    def _serve_bounded(self, handler):
        deadline = time.monotonic() + HANDLER_TIMEOUT
        method = handler.command
        path = handler.path
        target = self.full_path_matches(method, path, self.armed, self.target_suffix)
        if target:
            with self.lock:
                self.target_gets += 1
            self._fixed(handler, 503)
            return
        conn = None
        try:
            length = self.bounded_body_length(handler.headers.get("Content-Length"))
            if length and method not in ("PUT", "POST"):
                self._fixed(handler, 400)
                return
            body = self._read_exact(handler, length, deadline) if length else b""
            headers = [(name, value) for name, value in handler.headers.items()
                       if name.lower() not in HOP_BY_HOP]
            self._note_forward(method)
            conn = http.client.HTTPConnection(*self.upstream, timeout=min(CONNECT_TIMEOUT, IO_TIMEOUT))
            with self.lock:
                self._connections.add(conn)
            handler._upstream_conn = conn
            try:
                self._set_timeout(handler, deadline)
                conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
                for name, value in headers:
                    conn.putheader(name, value)
                if body or method in ("PUT", "POST"):
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(body if body else None)
                if conn.sock is not None:
                    conn.sock.settimeout(min(IO_TIMEOUT, self.remaining(deadline)))
                response = conn.getresponse()
                payload = bytearray()
                while True:
                    if self.remaining(deadline) <= 0:
                        raise TimeoutError("gate upstream response deadline exhausted")
                    if conn.sock is not None:
                        conn.sock.settimeout(min(IO_TIMEOUT, self.remaining(deadline)))
                    chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - len(payload)))
                    if not chunk:
                        break
                    payload.extend(chunk)
                    if len(payload) > MAX_RESPONSE_BYTES:
                        self._fixed(handler, 502)
                        return
                response_headers = response.getheaders()
            finally:
                with self.lock:
                    self._connections.discard(conn)
                conn.close()
            self._relay(handler, method, response.status, response_headers, bytes(payload), deadline)
        except Exception:
            with self.lock:
                self.upstream_errors += 1
            self._fixed(handler, 502)
        finally:
            handler._upstream_conn = None
            if conn is not None:
                with self.lock:
                    self._connections.discard(conn)
                try:
                    conn.close()
                except Exception:
                    pass

    @staticmethod
    def _relay(handler, method, status, headers, payload, deadline):
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
            try:
                handler.connection.settimeout(max(0.1, deadline - time.monotonic()))
            except Exception:
                pass
            handler.wfile.write(payload)
        handler.wfile.flush()


class _BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
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
        thread = threading.Thread(target=self.process_request_thread,
                                  args=(request, client_address), daemon=True)
        with self.gate.lock:
            self.gate._handlers[thread] = request
        try:
            thread.start()
        except Exception:
            with self.gate.lock:
                self.gate._handlers.pop(thread, None)
            self._slots.release()
            try:
                request.close()
            except Exception:
                pass
            raise

    def process_request_thread(self, request, client_address):
        thread = threading.current_thread()
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.gate.lock:
                self.gate._handlers.pop(thread, None)
            self._slots.release()
