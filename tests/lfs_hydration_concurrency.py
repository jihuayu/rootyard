#!/usr/bin/env python3
"""Concurrent cold-node LFS hydration against the real S3/Garage backend.

A loopback control proxy forwards every request unchanged to the configured
Garage endpoint, preserving the client Host and SigV4 headers and never logging
headers, credentials or payloads. The first target GET is gated while the local
final path is still absent. A second native download is then started and given
time to join the in-flight hydration; only after that gate is released may the
proxy forward bytes. Exactly one backend GET and one HEAD are allowed, and both
readers must receive the exact SHA-256 and size from overlapping responses.

The same harness also covers:
* a failed flight returning explicit failures to every waiter, followed by a
  clean retry that issues exactly one new backend GET;
* client cancellation while hydration is gated: no partial final file appears,
  the detached hydration completes with correct bytes, no staging files survive,
  and a later cold read starts a fresh flight instead of reusing a stale map
  entry.
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
from lfs import LfsHarness  # noqa: E402

PAYLOAD_BYTES = 8 * 1024 * 1024
FIRST_CHUNK = 16 * 1024
EVENT_TIMEOUT = 60
FOLLOWER_JOIN_GRACE = 2.0
FLIGHT_SETTLE = 0.5
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding",
              "te", "trailer", "upgrade"}


class S3ControlProxy:
    """Threaded pass-through proxy with one-shot GET gating and request counts."""

    def __init__(self, target_host, target_port):
        self.target = (target_host, target_port)
        self.oid = None
        self.watch_path = None
        self.armed = False
        self.lock = threading.Lock()
        self.get_condition = threading.Condition(self.lock)
        self.counts = {}
        self.target_gets = 0
        self.target_heads = 0
        self.gate_next_get = False
        self.fail_gets_remaining = 0
        self.release = threading.Event()
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
        self.release.set()
        self.server.shutdown()
        self.server.server_close()

    def arm(self, oid, watch_path):
        self.oid = oid
        self.watch_path = watch_path
        self.armed = True

    def disarm(self):
        self.armed = False

    def prepare_gate(self, fail=False):
        with self.get_condition:
            self.gate_next_get = True
            # The Rust S3 client retries a 5xx up to three attempts. Fail every
            # attempt so a failed flight is deterministic; otherwise a retry
            # could silently turn the scenario into a success.
            self.fail_gets_remaining = 3 if fail else 0
            self.release.clear()

    def release_gated(self):
        self.release.set()

    def wait_for_gets(self, count, timeout=EVENT_TIMEOUT):
        deadline = time.monotonic() + timeout
        with self.get_condition:
            while self.target_gets < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(f"timed out waiting for target GET #{count}")
                self.get_condition.wait(remaining)

    def snapshot(self):
        with self.lock:
            return self.target_heads, self.target_gets

    def note(self, kind, **fields):
        with self.lock:
            self.events.append({"kind": kind, "monotonic": round(time.monotonic(), 6), **fields})

    def is_target(self, method, path):
        if not self.armed:
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
        target = self.is_target(method, path)
        gated = fail = False
        if target:
            with self.get_condition:
                self.counts[method] = self.counts.get(method, 0) + 1
                if method == "GET":
                    self.target_gets += 1
                    self.get_condition.notify_all()
                    gated = self.gate_next_get
                    self.gate_next_get = False
                    if self.fail_gets_remaining > 0:
                        self.fail_gets_remaining -= 1
                        fail = True
                elif method == "HEAD":
                    self.target_heads += 1
            # `note` re-acquires the non-reentrant lock, so it must run after
            # leaving the condition block or the handler deadlocks itself.
            if method == "GET":
                self.note("target_get_received", local_final_exists=bool(
                    self.watch_path and self.watch_path.exists()))
            elif method == "HEAD":
                self.note("target_head_received")
        if gated and not self.release.wait(EVENT_TIMEOUT):
            raise RuntimeError("test never released the gated backend GET")
        if fail:
            self.note("target_get_failed")
            self.relay(handler, "GET", 502, [], b"", 0)
            return
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
            payload = response.read()
        finally:
            conn.close()
        declared = None
        for name, value in response_headers:
            if name.lower() == "content-length":
                declared = int(value)
        self.relay(handler, method, status, response_headers, payload, declared)
        if target:
            self.note("target_response", method=method, status=status, bytes=len(payload))
        else:
            self.note("pass_through", method=method, status=status, bytes=len(payload))

    def relay(self, handler, method, status, headers, payload, declared):
        handler.send_response_only(status)
        for name, value in headers:
            if name.lower() in HOP_BY_HOP or name.lower() == "content-length":
                continue
            handler.send_header(name, value)
        length = declared if method == "HEAD" or status in (204, 304) else len(payload)
        handler.send_header("Content-Length", str(length if length is not None else 0))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.close_connection = True
        if method != "HEAD" and payload:
            handler.wfile.write(payload)
        handler.wfile.flush()


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


def raw_lfs_get(port, path, token, first_chunks=None, sent=None,
                cancel_ready=None, error_limit=PAYLOAD_BYTES):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    sock.settimeout(EVENT_TIMEOUT)
    sock.connect(("127.0.0.1", port))
    request = (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
               f"Authorization: Bearer {token}\r\nAccept: */*\r\n"
               "Connection: close\r\n\r\n")
    sock.sendall(request.encode())
    if sent is not None:
        sent.set()
    if cancel_ready is not None:
        if not cancel_ready.wait(EVENT_TIMEOUT):
            raise RuntimeError("test never allowed client cancellation")
        sock.close()
        return "cancelled", {}, b""
    status, headers, buffered = read_headers(sock)
    body = bytearray(buffered)
    if first_chunks is not None:
        while len(body) < FIRST_CHUNK:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body.extend(chunk)
        first_chunks[threading.current_thread().name].set()
        for event in first_chunks.values():
            if not event.wait(EVENT_TIMEOUT):
                raise RuntimeError("the other reader never received response bytes")
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > error_limit:
            raise RuntimeError("response exceeded expected object size")
    sock.close()
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
            return self._run(proxy, parsed.hostname, backend_port)
        finally:
            proxy.release_gated()
            proxy.stop()

    def _repo_dir(self):
        return Path(self.env["ROOTYARD_DATA_DIR"]) / "lfs" / self.repo["id"]

    def _clear(self, final):
        if final.exists() or final.is_symlink():
            final.unlink()
        leftovers = sorted(p.name for p in self._repo_dir().iterdir()
                           if p.name.startswith((".tmp-", ".rootyard-object-")))
        assert leftovers == [], leftovers

    def _assert_final(self, final, oid, size):
        assert final.is_file() and not final.is_symlink()
        meta = final.stat()
        assert stat.S_IMODE(meta.st_mode) == 0o600, oct(meta.st_mode)
        assert meta.st_nlink == 1 and meta.st_size == size
        assert hashlib.sha256(final.read_bytes()).hexdigest() == oid
        leftovers = sorted(p.name for p in self._repo_dir().iterdir()
                           if p.name.startswith((".tmp-", ".rootyard-object-")))
        assert leftovers == [], leftovers

    def _run(self, proxy, backend_host, backend_port):
        self.setup()
        self.api()
        payload = os.urandom(PAYLOAD_BYTES)
        oid = hashlib.sha256(payload).hexdigest()
        size = len(payload)
        batch = self.lfs_batch("upload", [{"oid": oid, "size": size}], token=self.alice)
        actions = batch["objects"][0]["actions"]
        self.lfs_put(actions["upload"]["href"], payload, token=self.alice, code=200)
        self.lfs_verify(actions["verify"]["href"], oid, size, token=self.alice, code=200)
        assert self.sql(
            f"SELECT state || '|' || size FROM lfs_objects "
            f"WHERE repository_id='{self.repo['id']}' AND oid='{oid}'") == f"ready|{size}"
        final = self._repo_dir() / oid
        self._assert_final(final, oid, size)
        path = f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}"
        proxy.arm(oid, final)

        def run_pair(prefix):
            first_chunks = {f"{prefix}-leader": threading.Event(),
                            f"{prefix}-follower": threading.Event()}
            sent = threading.Event()
            results, failures = {}, []

            def fetch(name, follower):
                try:
                    results[name] = raw_lfs_get(
                        self.port, path, self.alice["token"], first_chunks,
                        sent if follower else None, error_limit=size)
                except Exception as error:
                    failures.append(f"{name}: {type(error).__name__}: {str(error)[:300]}")
                    for event in first_chunks.values():
                        event.set()
                    sent.set()

            threads = {
                "leader": threading.Thread(target=fetch, args=(f"{prefix}-leader", False),
                                           name=f"{prefix}-leader", daemon=True),
                "follower": threading.Thread(target=fetch, args=(f"{prefix}-follower", True),
                                             name=f"{prefix}-follower", daemon=True),
            }
            threads["leader"].start()
            return threads, first_chunks, sent, results, failures

        # 1. Successful flight: gate the first backend GET while local bytes are
        # absent, then establish that the follower is waiting rather than
        # starting another flight.
        self._clear(final)
        proxy.prepare_gate()
        heads_before, gets_before = proxy.snapshot()
        threads, first_chunks, sent, results, failures = run_pair("ok")
        proxy.wait_for_gets(gets_before + 1)
        assert not final.exists(), "local final existed while hydration was gated"
        threads["follower"].start()
        assert sent.wait(EVENT_TIMEOUT), "follower request was never sent"
        time.sleep(FOLLOWER_JOIN_GRACE)
        assert proxy.snapshot() == (heads_before + 1, gets_before + 1), (
            "follower did not join the single-flight hydration", proxy.snapshot())
        assert threads["follower"].is_alive(), "follower completed without the gated GET"
        assert not final.exists()
        proxy.release_gated()
        for thread in threads.values():
            thread.join(EVENT_TIMEOUT * 2)
        assert not failures, failures
        assert not proxy.errors, proxy.errors
        assert proxy.snapshot() == (heads_before + 1, gets_before + 1)
        for name in first_chunks:
            status, headers, body = results[name]
            assert status == 200, (name, status)
            assert int(headers.get("content-length", "-1")) == size, headers
            assert len(body) == size and hashlib.sha256(body).hexdigest() == oid, name
        assert all(event.is_set() for event in first_chunks.values())
        self._assert_final(final, oid, size)
        time.sleep(FLIGHT_SETTLE)

        # 2. Failed flight: both waiters observe explicit failure, no partial
        # final appears, and the next request performs a clean retry.
        self._clear(final)
        proxy.prepare_gate(fail=True)
        heads_before, gets_before = proxy.snapshot()
        threads, _, sent, results, failures = run_pair("fail")
        proxy.wait_for_gets(gets_before + 1)
        threads["follower"].start()
        assert sent.wait(EVENT_TIMEOUT), "failure follower was never sent"
        time.sleep(FOLLOWER_JOIN_GRACE)
        assert proxy.snapshot() == (heads_before + 1, gets_before + 1), proxy.snapshot()
        proxy.release_gated()
        for thread in threads.values():
            thread.join(EVENT_TIMEOUT * 2)
        assert not failures, failures
        assert not proxy.errors, proxy.errors
        assert proxy.snapshot() == (heads_before + 1, gets_before + 3), proxy.snapshot()
        for name, (status, _, _) in results.items():
            assert status in (500, 503), (name, status)
        assert not final.exists()
        assert sorted(p.name for p in self._repo_dir().iterdir()
                      if p.name.startswith((".tmp-", ".rootyard-object-"))) == []
        heads_before, gets_before = proxy.snapshot()
        status, body, _ = self.lfs_get(path, token=self.alice, code=200)
        assert status == 200 and body == payload
        assert proxy.snapshot() == (heads_before + 1, gets_before + 1), (
            proxy.snapshot(), proxy.events[-12:])
        self._assert_final(final, oid, size)
        time.sleep(FLIGHT_SETTLE)

        # 3. Cancellation: abort the only reader while the backend GET is gated.
        # Detached hydration may finish, but it must publish only complete
        # verified bytes and leave no staging files. The flight map must then be
        # empty so a later cold read starts exactly one new GET.
        self._clear(final)
        proxy.prepare_gate()
        cancel_ready = threading.Event()
        cancelled = {}

        def canceling_fetch():
            try:
                cancelled["result"] = raw_lfs_get(
                    self.port, path, self.alice["token"], cancel_ready=cancel_ready)
            except Exception as error:
                cancelled["error"] = f"{type(error).__name__}: {str(error)[:300]}"

        thread = threading.Thread(target=canceling_fetch, name="cancelled", daemon=True)
        thread.start()
        heads_before, gets_before = proxy.snapshot()
        proxy.wait_for_gets(gets_before + 1)
        assert not final.exists(), "cancelled hydration published before backend bytes"
        cancel_ready.set()
        thread.join(EVENT_TIMEOUT)
        assert not thread.is_alive()
        assert "error" not in cancelled, cancelled
        assert cancelled["result"][0] == "cancelled"
        time.sleep(0.2)
        assert not final.exists(), "cancellation published a partial final file"
        proxy.release_gated()
        deadline = time.monotonic() + 30
        while not final.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert final.exists(), "detached hydration did not finish after client cancellation"
        self._assert_final(final, oid, size)
        time.sleep(FLIGHT_SETTLE)
        heads_before, gets_before = proxy.snapshot()
        status, body, _ = self.lfs_get(path, token=self.alice, code=200)
        assert status == 200 and body == payload
        assert proxy.snapshot() == (heads_before, gets_before), "warm read touched remote"
        self._clear(final)
        heads_before, gets_before = proxy.snapshot()
        status, body, _ = self.lfs_get(path, token=self.alice, code=200)
        assert status == 200 and body == payload
        assert proxy.snapshot() == (heads_before + 1, gets_before + 1), (
            "stale flight entry prevented a fresh hydration", proxy.snapshot())
        self._assert_final(final, oid, size)

        proxy.disarm()
        return {
            "s3_backend": {"host": backend_host, "port": backend_port, "kind": "garage"},
            "oid": oid, "size": size, "cold_start_local_missing": True,
            "successful_singleflight": {
                "backend_gets": 1, "backend_heads": 1,
                "follower_joined_before_release": True,
                "both_client_bodies_overlapped": True,
            },
            "failed_flight": {"waiters_failed_explicitly": 2, "retry_backend_gets": 1},
            "cancellation": {
                "partial_final_never_published": True,
                "detached_hydration_completed_valid_bytes": True,
                "staging_leftovers": 0,
                "fresh_flight_after_completion": True,
            },
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
