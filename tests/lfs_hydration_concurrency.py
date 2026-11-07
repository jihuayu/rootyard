#!/usr/bin/env python3
"""Concurrent cold-node LFS hydration against the real S3/Garage backend.

A loopback control proxy forwards every request unchanged to the configured
Garage endpoint, preserving the client Host and SigV4 headers and never logging
headers, credentials or payloads. For one synthetic 8 MiB LFS object it gates
the two backend GETs so both native download requests begin while the local
bytes are missing, and so the second hydration overlaps the first reader's
in-flight body. Both reads must return the exact SHA-256 and size.
"""
import argparse
import hashlib
import http.client
import json
import os
import socket
import stat
import sys
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness  # noqa: E402
from lfs import LfsHarness  # noqa: E402

PAYLOAD_BYTES = 8 * 1024 * 1024
FIRST_CHUNK = 16 * 1024
EVENT_TIMEOUT = 60
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding",
              "te", "trailer", "upgrade"}


class S3ControlProxy:
    """Threaded pass-through proxy with deterministic GET gating for one oid."""

    def __init__(self, target_host, target_port):
        self.target = (target_host, target_port)
        self.oid = None
        self.armed = False
        self.lock = threading.Lock()
        self.target_gets = 0
        self.e_get1_received = threading.Event()
        self.e_get2_received = threading.Event()
        self.e_client_headers = threading.Event()
        self.e_first_client_done = threading.Event()
        self.e_second_first_chunk = threading.Event()
        self.errors = []
        self.events = []
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self): self._handle()
            def do_HEAD(self): self._handle()
            def do_PUT(self): self._handle()
            def do_POST(self): self._handle()
            def do_DELETE(self): self._handle()

            def _handle(self):
                try:
                    proxy.serve(self)
                except Exception as error:
                    proxy.errors.append(type(error).__name__ + ": " + str(error)[:200])
                    self.close_connection = True
                    try:
                        if not self.wfile.closed:
                            self.send_error(502)
                    except Exception:
                        pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def arm(self, oid, watch_path=None):
        self.oid = oid
        self.watch_path = watch_path
        self.armed = True

    def disarm(self):
        self.armed = False

    def note(self, kind, **fields):
        with self.lock:
            self.events.append({"kind": kind, "monotonic": round(time.monotonic(), 6), **fields})

    def is_target_get(self, method, path):
        if not (self.armed and method == "GET"):
            return False
        leaf = path.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        return leaf == self.oid

    def serve(self, handler):
        method, path = handler.command, handler.path
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length) if length else b""
        headers = [(name, value) for name, value in handler.headers.items()
                   if name.lower() not in HOP_BY_HOP
                   and name.lower() not in ("expect", "content-length")]
        number = 0
        if self.is_target_get(method, path):
            with self.lock:
                self.target_gets += 1
                number = self.target_gets
            if number == 1:
                self.e_get1_received.set()
                self.note("first_backend_get_received")
            elif number == 2:
                exists = bool(self.watch_path and self.watch_path.exists())
                self.note("second_backend_get_received", local_final_exists=exists)
                self.e_get2_received.set()
        conn = http.client.HTTPConnection(*self.target, timeout=EVENT_TIMEOUT)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for name, value in headers:
                conn.putheader(name, value)
            if body or method in ("PUT", "POST"):
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body if body else None)
            response = conn.getresponse()
            status, response_headers = response.status, response.getheaders()
            if number and status == 200:
                self.note("target_backend_response", number=number, status=status)
                return self.serve_target_stream(handler, number, response_headers, response)
            payload = response.read()
        finally:
            conn.close()
        if number:
            self.note("target_backend_response", number=number, status=status, bytes=len(payload))
            return self.relay(handler, "GET", status, response_headers, payload)
        self.relay(handler, method, status, response_headers, payload)
        self.note("pass_through", method=method, status=status, bytes=len(payload))

    def relay(self, handler, method, status, headers, payload):
        keep_length = None
        for name, value in headers:
            if name.lower() == "content-length":
                keep_length = int(value)
        handler.send_response_only(status)
        for name, value in headers:
            if name.lower() in HOP_BY_HOP or name.lower() == "content-length":
                continue
            handler.send_header(name, value)
        length = keep_length if method == "HEAD" or status in (204, 304) else len(payload)
        handler.send_header("Content-Length", str(length if length is not None else 0))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.close_connection = True
        if method != "HEAD" and payload:
            handler.wfile.write(payload)
        handler.wfile.flush()

    def serve_target_stream(self, handler, number, headers, response):
        length = None
        for name, value in headers:
            if name.lower() == "content-length":
                length = int(value)
        if length is None:
            return self.relay(handler, "GET", 200, headers, response.read())
        if number == 2 and not self.e_client_headers.wait(EVENT_TIMEOUT):
            raise RuntimeError("first client response headers never observed")
        self.relay_headers(handler, 200, headers, length)
        sent = 0
        first = response.read(FIRST_CHUNK)
        handler.wfile.write(first)
        handler.wfile.flush()
        sent += len(first)
        if number == 1:
            self.note("first_backend_first_chunk", chunk=len(first))
            if not self.e_get2_received.wait(EVENT_TIMEOUT):
                raise RuntimeError("second hydrating GET never reached the proxy")
        else:
            self.e_second_first_chunk.set()
            self.note("second_backend_first_chunk_while_first_reading",
                      chunk=len(first), first_client_done=self.e_first_client_done.is_set())
            if not self.e_first_client_done.wait(EVENT_TIMEOUT):
                raise RuntimeError("first client never finished reading its body")
        while sent < length:
            chunk = response.read(min(64 * 1024, length - sent))
            if not chunk:
                break
            handler.wfile.write(chunk)
            handler.wfile.flush()
            sent += len(chunk)
        if sent != length:
            raise RuntimeError("backend body length mismatch")
        self.note("first_backend_body_complete" if number == 1 else "second_backend_body_complete",
                  bytes=sent)

    def relay_headers(self, handler, status, headers, content_length):
        handler.send_response_only(status)
        for name, value in headers:
            if name.lower() in HOP_BY_HOP or name.lower() == "content-length":
                continue
            handler.send_header(name, value)
        handler.send_header("Content-Length", str(content_length))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.close_connection = True

def read_headers(sock):
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("client connection closed before response headers")
        buffer += chunk
        if len(buffer) > 65536:
            raise RuntimeError("client response headers exceeded limit")
    head, rest = buffer.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers[name.strip().lower().decode()] = value.strip().decode()
    return status, headers, rest


def paused_lfs_get(harness_port, path, token, proxy=None):
    """GET with a small receive buffer; the first reader pauses after 16 KiB."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    sock.settimeout(EVENT_TIMEOUT)
    sock.connect(("127.0.0.1", harness_port))
    request = (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{harness_port}\r\n"
               f"Authorization: Bearer {token}\r\nAccept: */*\r\n"
               "Connection: close\r\n\r\n")
    sock.sendall(request.encode())
    status, headers, buffered = read_headers(sock)
    body = bytearray(buffered)
    if proxy is not None:
        proxy.e_client_headers.set()
        while len(body) < FIRST_CHUNK:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body.extend(chunk)
        if not proxy.e_second_first_chunk.wait(EVENT_TIMEOUT):
            raise RuntimeError("second hydration never overlapped the first body")
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > PAYLOAD_BYTES:
            raise RuntimeError("response exceeded expected object size")
    sock.close()
    if proxy is not None:
        proxy.e_first_client_done.set()
    return status, headers, bytes(body)


class HydrationHarness(LfsHarness):
    def concurrent_cold_hydration(self):
        endpoint = os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT")
        assert endpoint, "S3 object-store fixture environment is required"
        parsed = urllib.parse.urlsplit(endpoint)
        assert parsed.scheme == "http", "loopback Garage endpoint must be plain HTTP"
        assert parsed.hostname in ("127.0.0.1", "::1", "localhost"), "loopback Garage required"
        assert not parsed.path and not parsed.query
        assert not parsed.username and not parsed.password
        backend_port = parsed.port or 80
        with socket.create_connection((parsed.hostname, backend_port), timeout=5):
            pass
        proxy = S3ControlProxy(parsed.hostname, backend_port)
        proxy.start()
        self.env["ROOTYARD_OBJECT_STORE_ENDPOINT"] = f"http://127.0.0.1:{proxy.port}"
        try:
            return self._run_concurrent(proxy, parsed.hostname, backend_port)
        finally:
            proxy.stop()

    def _run_concurrent(self, proxy, backend_host, backend_port):
        self.setup()
        self.api()
        payload = os.urandom(PAYLOAD_BYTES)
        oid = hashlib.sha256(payload).hexdigest()
        size = len(payload)
        batch = self.lfs_batch("upload", [{"oid": oid, "size": size}], token=self.alice)
        actions = batch["objects"][0]["actions"]
        self.lfs_put(actions["upload"]["href"], payload, token=self.alice, code=200)
        self.lfs_verify(actions["verify"]["href"], oid, size, token=self.alice, code=200)
        row = self.sql(
            f"SELECT state || '|' || size FROM lfs_objects "
            f"WHERE repository_id='{self.repo['id']}' AND oid='{oid}'")
        assert row == f"ready|{size}", row
        repo_dir = Path(self.env["ROOTYARD_DATA_DIR"]) / "lfs" / self.repo["id"]
        final = repo_dir / oid
        assert final.is_file()
        uploaded = final.stat()
        assert stat.S_IMODE(uploaded.st_mode) == 0o600 and uploaded.st_nlink == 1
        assert hashlib.sha256(final.read_bytes()).hexdigest() == oid
        final.unlink()
        assert not final.exists()
        proxy.arm(oid, final)
        path = f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}"
        results, failures = {}, []

        def fetch(name, first):
            try:
                results[name] = paused_lfs_get(
                    self.port, path, self.alice["token"], proxy if first else None)
            except Exception as error:
                failures.append(f"{name}: {type(error).__name__}: {str(error)[:300]}")
                proxy.e_get2_received.set()
                proxy.e_client_headers.set()
                proxy.e_second_first_chunk.set()
                proxy.e_first_client_done.set()

        first = threading.Thread(target=fetch, args=("first", True), daemon=True)
        second = threading.Thread(target=fetch, args=("second", False), daemon=True)
        first.start()
        assert proxy.e_get1_received.wait(EVENT_TIMEOUT), "first hydration never reached the backend"
        second.start()
        first.join(EVENT_TIMEOUT * 2)
        second.join(EVENT_TIMEOUT * 2)
        assert not first.is_alive() and not second.is_alive(), "controlled hydration threads hung"
        assert not failures, failures
        assert not proxy.errors, proxy.errors
        assert proxy.target_gets == 2, proxy.target_gets
        observed = {}
        for name in ("first", "second"):
            status, headers, body = results[name]
            assert status == 200, f"{name} status {status}"
            assert int(headers.get("content-length", "-1")) == size, headers
            assert len(body) == size, (name, len(body))
            assert hashlib.sha256(body).hexdigest() == oid, name
            observed[name] = {"status": status, "bytes": len(body),
                              "sha256": hashlib.sha256(body).hexdigest()}
        assert proxy.e_second_first_chunk.is_set() and proxy.e_first_client_done.is_set()
        by_kind = {event["kind"]: event for event in proxy.events}
        assert by_kind["second_backend_get_received"]["local_final_exists"] is False
        assert by_kind["second_backend_first_chunk_while_first_reading"][
            "first_client_done"] is False
        kinds = [event["kind"] for event in proxy.events]
        assert kinds.index("second_backend_get_received") < kinds.index(
            "first_backend_body_complete"), kinds
        assert kinds.index("first_backend_body_complete") < kinds.index(
            "second_backend_first_chunk_while_first_reading"), kinds
        final_state = final.stat()
        assert stat.S_IMODE(final_state.st_mode) == 0o600, oct(final_state.st_mode)
        assert final_state.st_nlink == 1 and final_state.st_size == size
        assert hashlib.sha256(final.read_bytes()).hexdigest() == oid
        leftovers = sorted(p.name for p in repo_dir.iterdir()
                           if p.name.startswith((".tmp-", ".rootyard-object-")))
        assert leftovers == [], leftovers
        proxy.disarm()
        final.unlink()
        status, body, _ = self.lfs_get(path, token=self.alice, code=200)
        assert status == 200 and hashlib.sha256(body).hexdigest() == oid
        rehydrated = hashlib.sha256(final.read_bytes()).hexdigest()
        assert rehydrated == oid
        return {
            "s3_backend": {"host": backend_host, "port": backend_port, "kind": "garage"},
            "oid": oid, "size": size, "cold_start_local_missing": True,
            "backend_get_count": proxy.target_gets,
            "first_download": observed["first"], "second_download": observed["second"],
            "second_hydration_overlapped_first_body": True,
            "local_final_sha256": hashlib.sha256(final.read_bytes()).hexdigest(),
            "local_final_mode": oct(stat.S_IMODE(final.stat().st_mode)),
            "local_final_nlink": final.stat().st_nlink,
            "staging_leftovers": leftovers,
            "rehydration_after_disarm_sha256": rehydrated,
            "proxy_events": proxy.events,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    if not os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"):
        parser.error("real S3/Garage fixture environment is required")
    harness = HydrationHarness(args)
    passed = False
    try:
        harness.case("concurrent_cold_hydration", harness.concurrent_cold_hydration)
        passed = True
    except Exception:
        print(harness.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        harness.cleanup()
        report = {"passed": passed, "cases": harness.results,
                  "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
