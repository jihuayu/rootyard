#!/usr/bin/env python3
"""Native LFS read-amplification and offline-remote regression probe.

Runs the real Rust service with an owned, controlled S3-compatible counting
fixture. It records every backend HEAD/GET/PUT and reads the server process's
``/proc/<pid>/io`` ``rchar`` counter, so hot-read read amplification is measured
from the native process rather than inferred from request logs.

Covered invariants:
* upload acknowledgement still performs remote PUT + HEAD + readback before the
  metadata row becomes ``ready``;
* verified warm Batch+GET reads hash/read the object at most once and issue zero
  object-store requests;
* with the configured endpoint returning 503, a verified local GET is still 200
  and a missing/corrupt/truncated/replaced local object fails explicitly;
* concurrent cold readers of the same OID coalesce to one backend GET;
* restarting without the endpoint restores verified local 200 responses.
"""
import argparse
import hashlib
import json
import os
import stat
import sys
import threading
import time
import traceback
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lfs import LfsHarness  # noqa: E402

PAYLOAD_BYTES = 4 * 1024 * 1024
CONCURRENT_READERS = 4


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class CountingS3:
    """Minimal S3-compatible object fixture with fixed-cardinality counters."""

    def __init__(self):
        self.lock = threading.Lock()
        self.objects = {}
        self.counts = Counter()
        self.offline = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_HEAD(self): self._handle()
            def do_GET(self): self._handle()
            def do_PUT(self): self._handle()
            def do_POST(self): self._handle()
            def do_DELETE(self): self._handle()

            def _handle(self):
                with fixture.lock:
                    fixture.counts[self.command] += 1
                    offline = fixture.offline
                if offline:
                    self.send_response_only(503)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True
                    return
                key = self.path.split("?", 1)[0].lstrip("/").split("/", 1)[-1]
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with fixture.lock:
                    if self.command == "PUT":
                        fixture.objects[key] = body
                    stored = fixture.objects.get(key)
                if self.command == "PUT":
                    self.send_response_only(200)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True
                elif self.command in ("HEAD", "GET"):
                    if stored is None:
                        self.send_response_only(404)
                        self.send_header("Content-Length", "0")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.close_connection = True
                    else:
                        self.send_response_only(200)
                        self.send_header("Content-Length", str(len(stored)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.close_connection = True
                        if self.command == "GET":
                            self.wfile.write(stored)
                elif self.command == "DELETE":
                    with fixture.lock:
                        fixture.objects.pop(key, None)
                    self.send_response_only(204)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True
                else:
                    self.send_response_only(405)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True

        self.server = _Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def snapshot(self):
        with self.lock:
            return Counter(self.counts)


class ReadAmplificationHarness(LfsHarness):
    def _process_io(self):
        values = {}
        for line in Path(f"/proc/{self.proc.pid}/io").read_text().splitlines():
            name, _, value = line.partition(": ")
            values[name] = int(value)
        return values

    def _remote_delta(self, before, after):
        return {method: after.get(method, 0) - before.get(method, 0)
                for method in ("HEAD", "GET", "PUT", "POST", "DELETE")}

    def _repo_dir(self):
        return Path(self.env["ROOTYARD_DATA_DIR"]) / "lfs" / self.repo["id"]

    def _final(self, oid):
        return self._repo_dir() / oid

    def _assert_layout(self, path, expected_size):
        assert path.is_file() and not path.is_symlink(), path
        meta = path.stat()
        assert stat.S_IMODE(meta.st_mode) == 0o600, oct(meta.st_mode)
        assert meta.st_nlink == 1, meta.st_nlink
        assert meta.st_size == expected_size, meta.st_size
        leftovers = sorted(p.name for p in self._repo_dir().iterdir()
                           if p.name.startswith((".tmp-", ".rootyard-object-")))
        assert leftovers == [], leftovers

    def _concurrent_gets(self, path, count):
        barrier = threading.Barrier(count)
        results, failures = {}, []
        lock = threading.Lock()

        def worker(number):
            try:
                barrier.wait(timeout=15)
                results[number] = self.lfs_get(path, token=self.reader, code=200)
            except Exception as error:
                with lock:
                    failures.append(f"{number}: {type(error).__name__}: {str(error)[:300]}")

        threads = [threading.Thread(target=worker, args=(n,), daemon=True)
                   for n in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        assert all(not thread.is_alive() for thread in threads), "concurrent GET hung"
        return results, failures

    def read_amplification_and_offline_remote(self):
        fixture = CountingS3()
        fixture.start()
        self.env.update({
            "ROOTYARD_OBJECT_STORE_ENDPOINT": fixture.endpoint,
            "ROOTYARD_OBJECT_STORE_BUCKET": "rootyard-lfs-test",
            "ROOTYARD_OBJECT_STORE_REGION": "us-east-1",
            "ROOTYARD_OBJECT_STORE_ACCESS_KEY": "test-access",
            "ROOTYARD_OBJECT_STORE_SECRET_KEY": "test-secret",
        })
        try:
            self.setup_lfs()
            payload = os.urandom(PAYLOAD_BYTES)
            oid = hashlib.sha256(payload).hexdigest()
            size = len(payload)
            batch = self.lfs_batch("upload", [{"oid": oid, "size": size}], token=self.alice)
            actions = batch["objects"][0]["actions"]
            before_upload = fixture.snapshot()
            self.lfs_put(actions["upload"]["href"], payload, token=self.alice, code=200)
            self.lfs_verify(actions["verify"]["href"], oid, size, token=self.alice, code=200)
            assert self.sql(
                f"SELECT state || '|' || size FROM lfs_objects "
                f"WHERE repository_id='{self.repo['id']}' AND oid='{oid}'"
            ) == f"ready|{size}"
            upload_counts = self._remote_delta(before_upload, fixture.snapshot())
            assert upload_counts["PUT"] >= 1, upload_counts
            assert upload_counts["HEAD"] >= 1, upload_counts
            assert upload_counts["GET"] >= 1, "acknowledged upload must read back remote bytes"
            final = self._final(oid)
            self._assert_layout(final, size)
            get_path = f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}"

            # Restart with the endpoint still configured but the process
            # verification cache empty. The first local Batch+GET must hash the
            # object once for admission and then stream it once, with no remote
            # HEAD at all. A second Batch+GET is the steady-state one-read pass.
            self.stop()
            self.start()
            remote_before = fixture.snapshot()
            io_before = self._process_io()
            batch_dl = self.lfs_batch("download", [{"oid": oid, "size": size}], token=self.reader)
            assert "download" in batch_dl["objects"][0]["actions"]
            status, body, headers = self.lfs_get(get_path, token=self.reader, code=200)
            io_after = self._process_io()
            remote_after = fixture.snapshot()
            assert body == payload
            assert headers.get("content-length") == str(size)
            first_delta = io_after["rchar"] - io_before["rchar"]
            assert size * 2 <= first_delta < size * 3, (
                f"cache-empty first read amplified to {first_delta} bytes for a {size}-byte object")
            assert self._remote_delta(remote_before, remote_after) == {
                "HEAD": 0, "GET": 0, "PUT": 0, "POST": 0, "DELETE": 0
            }

            remote_before = fixture.snapshot()
            io_before = self._process_io()
            batch_dl = self.lfs_batch("download", [{"oid": oid, "size": size}], token=self.reader)
            assert "download" in batch_dl["objects"][0]["actions"]
            status, body, headers = self.lfs_get(get_path, token=self.reader, code=200)
            io_after = self._process_io()
            remote_after = fixture.snapshot()
            assert body == payload
            assert headers.get("content-length") == str(size)
            hot_delta = io_after["rchar"] - io_before["rchar"]
            assert hot_delta >= size, hot_delta
            assert hot_delta < size * 2, (
                f"warm read amplified to {hot_delta} bytes for a {size}-byte object")
            assert self._remote_delta(remote_before, remote_after) == {
                "HEAD": 0, "GET": 0, "PUT": 0, "POST": 0, "DELETE": 0
            }

            # Configured but failing remote: verified local bytes stay readable.
            fixture.offline = True
            remote_before = fixture.snapshot()
            io_before = self._process_io()
            self.lfs_batch("download", [{"oid": oid, "size": size}], token=self.reader)
            status, body, _ = self.lfs_get(get_path, token=self.reader, code=200)
            io_after = self._process_io()
            assert status == 200 and body == payload
            offline_delta = io_after["rchar"] - io_before["rchar"]
            assert offline_delta < size * 2, offline_delta
            assert self._remote_delta(remote_before, fixture.snapshot()) == {
                "HEAD": 0, "GET": 0, "PUT": 0, "POST": 0, "DELETE": 0
            }

            # Local corruption must fail closed while the remote is unavailable.
            corrupt = bytearray(payload)
            corrupt[123] ^= 0xFF
            final.write_bytes(corrupt)
            os.chmod(final, 0o600)
            self.lfs_get(get_path, token=self.reader, code=(422, 500, 503))
            final.write_bytes(payload)
            os.chmod(final, 0o600)
            self.lfs_get(get_path, token=self.reader, code=200)

            final.write_bytes(payload[:-1])
            os.chmod(final, 0o600)
            self.lfs_get(get_path, token=self.reader, code=(422, 500, 503))
            final.write_bytes(payload)
            os.chmod(final, 0o600)
            self.lfs_get(get_path, token=self.reader, code=200)

            replacement = self._repo_dir() / "replacement"
            replacement.write_bytes(b"R" * size)
            os.chmod(replacement, 0o600)
            os.replace(replacement, final)
            self.lfs_get(get_path, token=self.reader, code=(422, 500, 503))
            final.write_bytes(payload)
            os.chmod(final, 0o600)
            self.lfs_get(get_path, token=self.reader, code=200)

            symlink_target = self._repo_dir() / "symlink-target"
            symlink_target.write_bytes(payload)
            os.chmod(symlink_target, 0o600)
            final.unlink()
            os.symlink(symlink_target, final)
            self.lfs_get(get_path, token=self.reader, code=(422, 500, 503))
            final.unlink()
            symlink_target.unlink()
            final.write_bytes(payload)
            os.chmod(final, 0o600)
            self.lfs_get(get_path, token=self.reader, code=200)

            final.unlink()
            self.lfs_get(get_path, token=self.reader, code=(422, 500, 503))
            assert not final.exists()
            leftovers = sorted(p.name for p in self._repo_dir().iterdir()
                               if p.name.startswith((".tmp-", ".rootyard-object-")))
            assert leftovers == [], leftovers

            # Restore the object store: concurrent cold readers of one OID must
            # coalesce onto one backend GET and all receive intact bytes.
            fixture.offline = False
            remote_before = fixture.snapshot()
            results, failures = self._concurrent_gets(get_path, CONCURRENT_READERS)
            assert not failures, failures
            assert len(results) == CONCURRENT_READERS
            for number, (status, body, headers) in results.items():
                assert status == 200, number
                assert headers.get("content-length") == str(size), number
                assert hashlib.sha256(body).hexdigest() == oid, number
            cold_counts = self._remote_delta(remote_before, fixture.snapshot())
            assert cold_counts["GET"] == 1, cold_counts
            self._assert_layout(final, size)

            # Warm reads with the endpoint failing again: all concurrent GETs
            # succeed without a single object-store request.
            fixture.offline = True
            remote_before = fixture.snapshot()
            results, failures = self._concurrent_gets(get_path, CONCURRENT_READERS)
            assert not failures, failures
            assert all(status == 200 and body == payload
                       for status, body, _ in results.values())
            assert self._remote_delta(remote_before, fixture.snapshot()) == {
                "HEAD": 0, "GET": 0, "PUT": 0, "POST": 0, "DELETE": 0
            }

            # Removing the endpoint entirely must also restore verified local
            # 200 responses (the #71 regression).
            self.stop()
            for name in ("ROOTYARD_OBJECT_STORE_ENDPOINT", "ROOTYARD_OBJECT_STORE_BUCKET",
                         "ROOTYARD_OBJECT_STORE_REGION", "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
                         "ROOTYARD_OBJECT_STORE_SECRET_KEY"):
                self.env.pop(name, None)
            self.start()
            status, body, _ = self.lfs_get(get_path, token=self.reader, code=200)
            assert status == 200 and body == payload
            final.unlink()
            self.lfs_get(get_path, token=self.reader, code=(422, 500, 503))
            final.write_bytes(payload)
            os.chmod(final, 0o600)
            self.lfs_get(get_path, token=self.reader, code=200)
            self._assert_layout(final, size)

            return {
                "fixture": "owned S3-compatible counting HTTP fixture",
                "oid": oid,
                "size": size,
                "upload_remote_requests": dict(upload_counts),
                "measurement": {
                    "full_bytes_read_source": "/proc/<server-pid>/io rchar",
                    "limitations": [
                        "rchar counts all process read syscalls, including small request and database noise",
                        "loopback functional timings are not a scalability benchmark",
                    ],
                },
                "cache_empty_first_local_read": {
                    "full_bytes_read": first_delta,
                    "object_size": size,
                    "read_amplification_ratio": round(first_delta / size, 4),
                    "remote_requests": {k: 0 for k in ("HEAD", "GET", "PUT")},
                },
                "warm_read": {
                    "full_bytes_read": hot_delta,
                    "object_size": size,
                    "read_amplification_ratio": round(hot_delta / size, 4),
                    "remote_requests": {k: 0 for k in ("HEAD", "GET", "PUT")},
                },
                "offline_remote_warm_read": {
                    "status": 200,
                    "full_bytes_read": offline_delta,
                    "read_amplification_ratio": round(offline_delta / size, 4),
                    "remote_requests": {k: 0 for k in ("HEAD", "GET", "PUT")},
                },
                "local_failure_modes": ["corrupt", "truncated", "replaced", "symlink", "missing"],
                "concurrent_cold_reads": {
                    "readers": CONCURRENT_READERS,
                    "backend_gets": cold_counts["GET"],
                    "all_bytes_intact": True,
                },
                "concurrent_warm_reads_with_failing_remote": CONCURRENT_READERS,
                "endpoint_removed_restores_200": True,
            }
        finally:
            fixture.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = ReadAmplificationHarness(args)
    passed = False
    try:
        harness.case("read_amplification_and_offline_remote",
                     harness.read_amplification_and_offline_remote)
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
