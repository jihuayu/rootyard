#!/usr/bin/env python3
"""Native acceptance for bounded workspace capture and Git execution (#73/#68).

The suite runs the real Rust service against a disposable PostgreSQL schema. It
uses real workspaces, real Git clones and real filesystem inventories:
* more than 100 valid workspaces capture UUIDs beyond a fixed prefix even when
  an earlier workspace is permanently bad and another is deliberately slow;
* a large inventory does not block the sole Tokio worker for health requests;
* a scan in progress does not hold the workspace row lock, and a revision or
  lease-epoch change during that scan is never overwritten by the stale result;
* SSE reconnect honors the native Last-Event-ID cursor and retention gaps
  terminate at the live durable revision without replaying unseen events.
* the lease-epoch case also proves through the real PostgreSQL lock graph that
  the held stale scan rejects before an observer row lock can hand off to a
  fresh committing scan.
"""
import argparse
import base64
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import threading
import time
import unittest
import urllib.request

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from e2e import Harness

BULK_COUNT = 90000
BULK_SIZE = 1024

_TEST_BINARY = None
_TEST_KEEP = False
_GATE_FACTS = {}


def harness():
    """Build a Harness for the binary selected on the command line."""
    if not _TEST_BINARY:
        raise RuntimeError("workspace capture tests must run through main() with --binary")
    return Harness(argparse.Namespace(binary=_TEST_BINARY, keep=_TEST_KEEP))


def create(h, index):
    body = {"owner": "alice", "repository": "demo", "agent_id": f"agent-{index}", "base_oid": h.second}
    return json.loads(
        h.expect(
            "/api/workspaces",
            201,
            token=h.alice,
            method="POST",
            body=body,
            extra_headers={"Idempotency-Key": f"capture-create-{index}"},
        )
    )


def repo(h, workspace):
    return h.root / "data/workspace-service/workspaces" / workspace["id"]


def install_capture_read_gate(h, target):
    """Compile the real-read gate and configure only this harness child.

    The library is inert unless both gate variables are set. The exact target
    path is only known after the API-created workspace exists, so the durable
    service is restarted once with the preload already in place. It is
    compiled in this harness's owned temp root before that process starts.
    """
    if not sys.platform.startswith("linux") or not Path("/proc/self/fd").is_dir():
        raise RuntimeError("capture read gate requires Linux /proc/self/fd support")
    compiler = shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("capture read gate requires gcc on PATH")
    source = TESTS_DIR / "fixtures" / "capture_read_gate.c"
    if not source.is_file():
        raise RuntimeError(f"capture read gate fixture is missing: {source}")
    build = h.root / "capture-read-gate"
    build.mkdir(parents=True, exist_ok=True)
    library = build / "capture_read_gate.so"
    build_env = dict(h.env)
    build_env.pop("LD_PRELOAD", None)
    h.run(
        [compiler, "-shared", "-fPIC", "-O2", "-pthread", "-o", str(library), str(source), "-ldl"],
        env=build_env,
    )
    if not library.is_file():
        raise RuntimeError(f"capture read gate did not produce {library}")
    prefix = h.root / "capture-gate"
    h.env.update(
        LD_PRELOAD=str(library),
        ROOTYARD_TEST_CAPTURE_GATE=str(prefix),
        ROOTYARD_TEST_CAPTURE_TARGET=str(target),
    )
    return prefix


def wait_capture_gate(hit, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if hit.exists():
            return
        time.sleep(0.05)
    raise AssertionError(f"real capture read was not paused at {hit} within {timeout}s")


def events(h, workspace, after=0):
    body = json.loads(
        h.expect(f"/api/workspaces/{workspace['id']}/events?after_revision={after}", 200, token=h.alice)
    )
    return body.get("events", [])


def write_event(h, workspace, index):
    """Create one real durable workspace event through the write API."""
    path = f"/api/workspaces/{workspace['id']}/files?path=event-{index}.txt"
    for _ in range(10):
        current = json.loads(h.expect(f"/api/workspaces/{workspace['id']}", 200, token=h.alice))
        body = {
            "content_base64": base64.b64encode(f"event {index}\n".encode()).decode(),
            "expected_entry_version": 0,
            "expected_workspace_revision": current["revision"],
            "lease_epoch": current["lease_epoch"],
        }
        status, raw, _ = h.http(
            path,
            token=h.alice,
            method="PUT",
            body=body,
            extra_headers={"Idempotency-Key": f"sse-event-{index}"},
        )
        if status == 200:
            return json.loads(raw)
        if status != 409:
            raise AssertionError(f"workspace event write failed: {status}: {raw[:300]!r}")
        time.sleep(0.05)
    raise AssertionError(f"workspace event write for event-{index}.txt kept conflicting")


def sse_frames(h, workspace, after=None, last_event_id=None, max_frames=1, timeout=8.0, on_open=None):
    """Read a bounded number of real SSE frames from one response and close it."""
    suffix = "" if after is None else f"?after_revision={after}"
    headers = {
        "Authorization": "Bearer " + h.alice["token"],
        "Accept": "text/event-stream",
    }
    if last_event_id is not None:
        headers["Last-Event-ID"] = str(last_event_id)
    request = urllib.request.Request(
        f"{h.base}/api/workspaces/{workspace['id']}/events/stream{suffix}",
        headers=headers,
    )
    frames = []
    frame = {"event": None, "id": None, "data": []}
    line = b""
    consumed = 0

    def finish():
        if frame["event"] is not None or frame["id"] is not None or frame["data"]:
            frames.append(
                {
                    "event": frame["event"] or "message",
                    "id": frame["id"],
                    "data": "\n".join(frame["data"]),
                }
            )
        frame.update(event=None, id=None, data=[])

    with urllib.request.urlopen(request, timeout=timeout) as response:
        try:
            if on_open is not None:
                on_open()
            while len(frames) < max_frames and consumed < 65536:
                try:
                    chunk = response.read(1)
                except TimeoutError:
                    break
                if not chunk:
                    break
                consumed += 1
                if chunk != b"\n":
                    line += chunk
                    continue
                text = line.rstrip(b"\r").decode("utf-8")
                line = b""
                if not text:
                    finish()
                    continue
                if text.startswith(":"):
                    continue
                field, _, value = text.partition(":")
                if value.startswith(" "):
                    value = value[1:]
                if field == "event":
                    frame["event"] = value
                elif field == "id":
                    frame["id"] = value
                elif field == "data":
                    frame["data"].append(value)
            if line:
                text = line.rstrip(b"\r").decode("utf-8")
                if text and not text.startswith(":"):
                    field, _, value = text.partition(":")
                    if value.startswith(" "):
                        value = value[1:]
                    if field == "data":
                        frame["data"].append(value)
                    elif field == "event":
                        frame["event"] = value
                    elif field == "id":
                        frame["id"] = value
            if len(frames) < max_frames:
                finish()
        finally:
            response.close()
    return frames


def wait_event(h, workspace, timeout=30.0, after=0, kind="external_capture"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [event for event in events(h, workspace, after) if event["kind"] == kind]
        if found:
            return found[0]
        time.sleep(0.2)
    raise AssertionError(f"workspace {workspace['id']} did not emit {kind} within {timeout}s")


def wait_durable_capture(h, workspace, after=0, timeout=30.0):
    """Read the committed event row directly.

    The public events API must answer a synthetic revision gap with
    RESYNC_REQUIRED and cannot page across it, but the scan still commits its
    guarded revision and event durably. CAS assertions therefore read the
    durable log instead of weakening the public gap semantics.
    """
    deadline = time.monotonic() + timeout
    query = (
        "SELECT max(revision) FROM workspace_events WHERE workspace_id='%s' "
        "AND kind='external_capture' AND revision>%d" % (workspace["id"], after)
    )
    while time.monotonic() < deadline:
        value = h.sql(query)
        if value:
            return {"kind": "external_capture", "revision": int(value)}
        time.sleep(0.2)
    raise AssertionError(
        "workspace %s did not commit a durable external_capture within %ss"
        % (workspace["id"], timeout)
    )


def bulk(repo_path, count, size=512):
    for index in range(count):
        directory = repo_path / "bulk" / f"{index // 1000:03d}"
        if not directory.is_dir():
            directory.mkdir(parents=True)
        (directory / f"{index:06d}.bin").write_bytes(b"x" * size)


def row_lock_nowait(h, workspace):
    h.sql(
        "BEGIN; SELECT 1 FROM workspaces WHERE id='%s' FOR UPDATE NOWAIT; COMMIT;"
        % workspace["id"]
    )


def sql_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


class PsqlSession:
    """One owned psql transaction synchronized through stdout markers.

    The session is only ever rolled back or terminated by the exact PID and
    application name it started; it never terminates an unrelated backend.
    """

    def __init__(self, h, application_name):
        self.h = h
        self.application_name = application_name
        self.pid = None
        self.proc = None
        self.pending = b""
        env = h.env.copy()
        env["PGDATABASE"] = h.db
        env["PGAPPNAME"] = application_name
        self.proc = subprocess.Popen(
            ["psql", "--dbname", h.db, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def send(self, sql):
        if self.proc is None or self.proc.stdin is None:
            raise AssertionError("owned psql session is not running")
        self.proc.stdin.write(sql.encode() + b"\n")
        self.proc.stdin.flush()

    def marker(self, name, timeout=15.0):
        prefix = (name + "|").encode()
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" in self.pending:
                line, self.pending = self.pending.split(b"\n", 1)
                line = line.strip()
                if line.startswith(prefix):
                    return line[len(prefix):].decode()
            if self.proc is None or self.proc.poll() is not None:
                error = ""
                if self.proc is not None and self.proc.stderr is not None:
                    error = self.h.redact(
                        self.proc.stderr.read()[-500:].decode(errors="replace")
                    )
                raise AssertionError(
                    "owned psql session exited before %s: %s" % (name, error)
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    "owned psql session did not reach %s within %ss" % (name, timeout)
                )
            ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(self.proc.stdout.fileno(), 4096)
            if not chunk:
                raise AssertionError("owned psql session closed stdout before %s" % name)
            self.pending += chunk

    def close(self):
        if self.proc is None:
            return
        proc = self.proc
        self.proc = None
        try:
            if proc.poll() is None and proc.stdin is not None:
                try:
                    proc.stdin.write(b"ROLLBACK;\n\\q\n")
                    proc.stdin.flush()
                except (BrokenPipeError, OSError, ValueError):
                    pass
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if self.pid is not None:
                    try:
                        self.h.sql(
                            "SELECT pg_terminate_backend(%d) FROM pg_stat_activity "
                            "WHERE pid=%d AND application_name=%s"
                            % (self.pid, self.pid, sql_quote(self.application_name))
                        )
                    except Exception:
                        pass
                try:
                    proc.kill()
                except (OSError, ProcessLookupError):
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


def assert_owned_session(h, pid, application_name, state, timeout=5.0):
    query = (
        "SELECT state FROM pg_stat_activity WHERE pid=%d AND application_name=%s "
        "AND datname=current_database()" % (pid, sql_quote(application_name))
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if h.sql(query) == state:
            return
        time.sleep(0.02)
    raise AssertionError("owned psql session %s is not %s" % (application_name, state))


def wait_scanner_commit_block(h, holder_pid, timeout=10.0):
    pattern = (
        "SELECT pid FROM pg_stat_activity "
        "WHERE datname=current_database() AND state='active' "
        "AND wait_event_type='Lock' AND pid<>" + str(holder_pid) + " "
        "AND " + str(holder_pid) + " = ANY(pg_blocking_pids(pid)) "
        "AND query LIKE '%FROM workspaces%host_id=$2%state=''ready''%"
        "lease_until>clock_timestamp()%FOR UPDATE%'"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = h.sql(pattern)
        pids = [int(line) for line in value.splitlines() if line.strip()]
        if len(pids) == 1:
            return pids[0]
        if len(pids) > 1:
            raise AssertionError(
                "multiple candidate capture commit backends; refusing ambiguous identity"
            )
        time.sleep(0.02)
    raise AssertionError("capture commit did not block behind the held workspace row")


def wait_observer_blocked(h, observer_pid, scanner_pid, timeout=10.0):
    query = (
        "SELECT count(*) FROM pg_stat_activity "
        "WHERE pid=" + str(observer_pid) + " AND datname=current_database() "
        "AND state='active' AND wait_event_type='Lock' "
        "AND " + str(scanner_pid) + " = ANY(pg_blocking_pids(pid)) "
        "AND query LIKE '%SELECT 1 FROM workspaces%FOR UPDATE%'"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if h.sql(query) == "1":
            return
        time.sleep(0.02)
    raise AssertionError(
        "observer transaction did not queue behind the capture commit backend"
    )


def assert_blocking_chain(h, holder_pid, scanner_pid, observer_pid):
    value = h.sql(
        "SELECT "
        "CASE WHEN " + str(holder_pid) + " = ANY(pg_blocking_pids("
        + str(scanner_pid) + ")) THEN 't' ELSE 'f' END, "
        "CASE WHEN " + str(scanner_pid) + " = ANY(pg_blocking_pids("
        + str(observer_pid) + ")) THEN 't' ELSE 'f' END, "
        "(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
        "AND pid IN (" + str(holder_pid) + "," + str(scanner_pid) + ","
        + str(observer_pid) + "))::text"
    )
    assert value == "t|t|3", (
        "authoritative holder -> scanner -> observer blocking chain was not proven"
    )


class TimedTextTestResult(unittest.TextTestResult):
    """TextTestResult that also records how long each test ran."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seconds = {}
        self._started = {}

    def startTest(self, test):
        self._started[test.id()] = time.monotonic()
        super().startTest(test)

    def stopTest(self, test):
        super().stopTest(test)
        started = self._started.pop(test.id(), None)
        if started is not None:
            self.seconds[test.id()] = round(time.monotonic() - started, 4)


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def selected_suite(loader, names, module):
    if not names:
        return loader.loadTestsFromTestCase(WorkspaceCaptureAcceptance)
    suite = unittest.TestSuite()
    for name in names:
        short = name
        if short.startswith(module.__name__ + "."):
            short = short[len(module.__name__) + 1:]
        if short == WorkspaceCaptureAcceptance.__name__ or short.startswith(
            WorkspaceCaptureAcceptance.__name__ + "."
        ):
            suite.addTests(loader.loadTestsFromName(short, module))
        elif short.startswith("test_"):
            suite.addTests(
                loader.loadTestsFromName(f"{WorkspaceCaptureAcceptance.__name__}.{short}", module)
            )
        else:
            suite.addTests(loader.loadTestsFromName(name, module))
    return suite


def scheduled_test_ids(suite):
    """Snapshot every scheduled test ID before execution.

    ``unittest.TestSuite`` replaces each executed entry with ``None`` to free
    memory, so a suite can no longer be inspected after ``run``. Reporting must
    use this snapshot, otherwise every result (including failures) is lost and
    the report itself raises instead of recording the run.
    """
    return [test.id() for test in flatten(suite)]


def result_entries(result, scheduled_ids):
    failures = {test.id(): detail for test, detail in result.failures}
    errors = {test.id(): detail for test, detail in result.errors}
    skipped = {test.id(): reason for test, reason in result.skipped}
    expected = {test.id(): detail for test, detail in result.expectedFailures}
    unexpected = {test.id(): detail for test, detail in result.unexpectedSuccesses}
    entries = []
    for test_id in scheduled_ids:
        if test_id in failures:
            status, detail = "failure", failures[test_id]
        elif test_id in errors:
            status, detail = "error", errors[test_id]
        elif test_id in skipped:
            status, detail = "skipped", skipped[test_id]
        elif test_id in expected:
            status, detail = "expected_failure", expected[test_id]
        elif test_id in unexpected:
            status, detail = "unexpected_success", unexpected[test_id]
        else:
            status, detail = "success", None
        entry = {
            "name": test_id,
            "status": status,
            "seconds": result.seconds.get(test_id),
        }
        if detail is not None:
            entry["detail"] = detail
        entries.append(entry)
    return entries


def build_report(result, scheduled_ids, binary, binary_sha256):
    entries = result_entries(result, scheduled_ids) if result is not None else []
    cases = [
        {
            "name": entry["name"],
            "status": "passed" if entry["status"] == "success" else entry["status"],
        }
        for entry in entries
    ]
    counts = Counter(entry["status"] for entry in entries)
    total_scheduled = len(scheduled_ids)
    passed = (
        result is not None
        and result.wasSuccessful()
        and result.testsRun == total_scheduled
        and counts["skipped"] == 0
    )
    report = {
        "passed": passed,
        "binary": str(binary),
        "binary_sha256": binary_sha256,
        "tests": entries,
        "cases": cases,
        "summary": {
            "total_scheduled": total_scheduled,
            "tests_run": result.testsRun if result is not None else 0,
            "success": counts["success"],
            "failure": counts["failure"],
            "error": counts["error"],
            "skipped": counts["skipped"],
            "expected_failure": counts["expected_failure"],
            "unexpected_success": counts["unexpected_success"],
        },
        "limitations": [
            "The large-inventory cases create 90000 small files and can take minutes on slow disks.",
            "Loopback functional timings are not a scalability benchmark.",
        ],
    }
    if _GATE_FACTS:
        report["capture_read_gate"] = dict(_GATE_FACTS)
    return report


class _SyntheticReportTests(unittest.TestCase):
    """Fixed outcomes used only by the report unit; not selected natively."""

    def synthetic_pass(self):
        self.assertTrue(True)

    def synthetic_fail(self):
        self.fail("intentional failure for report coverage")


class ReportUnitTests(unittest.TestCase):
    def test_report_records_every_outcome_after_suite_consumption(self):
        suite = unittest.TestSuite(
            [_SyntheticReportTests("synthetic_pass"), _SyntheticReportTests("synthetic_fail")]
        )
        scheduled = scheduled_test_ids(suite)
        self.assertEqual(len(scheduled), 2)
        stream = io.StringIO()
        result = unittest.TextTestRunner(
            stream=stream, verbosity=0, resultclass=TimedTextTestResult
        ).run(suite)
        # unittest.TestSuite consumes its entries; this is exactly why the
        # report needs the pre-run snapshot.
        self.assertEqual([test for test in flatten(suite)], [None, None])
        report = build_report(result, scheduled, Path("/nonexistent/rootyard"), "0" * 64)
        statuses = {entry["name"]: entry["status"] for entry in report["tests"]}
        self.assertEqual(statuses[scheduled[0]], "success")
        self.assertEqual(statuses[scheduled[1]], "failure")
        self.assertFalse(report["passed"])
        self.assertEqual(report["summary"]["total_scheduled"], 2)
        self.assertEqual(report["summary"]["tests_run"], 2)
        self.assertEqual(report["summary"]["failure"], 1)
        self.assertIn("intentional failure", report["tests"][1]["detail"])


class WorkspaceCaptureAcceptance(unittest.TestCase):
    def test_capture_reaches_ids_beyond_fixed_prefix(self):
        h = harness()
        h.env.update(
            ROOTYARD_WORKSPACE_SCAN_WORKERS="2",
            ROOTYARD_WORKSPACE_SCAN_QUEUE="8",
            ROOTYARD_WORKSPACE_SCAN_TIMEOUT_MS="5000",
        )
        try:
            h.setup()
            h.api()
            h.roundtrip()
            workspaces = [create(h, index) for index in range(120)]
            ordered = sorted(workspaces, key=lambda item: item["id"])
            bad, slow, target = ordered[0], ordered[1], ordered[-1]
            # A FIFO makes this workspace's inventory fail every round without
            # consuming a worker for long. It sorts before the target UUID.
            os.mkfifo(repo(h, bad) / "permanently-bad.fifo")
            bulk(repo(h, slow), 6000, 128)
            for workspace in ordered[:5] + [target]:
                (repo(h, workspace) / "external.txt").write_bytes(
                    b"external editor save\n" + workspace["id"].encode()
                )
            event = wait_event(h, target, timeout=30)
            self.assertEqual(event["kind"], "external_capture")
            self.assertGreaterEqual(event["revision"], 1)
            # The target really is outside the old ORDER BY id LIMIT 100 prefix.
            self.assertGreater(ordered.index(target), 100)
        finally:
            h.cleanup()

    def test_api_write_baseline_does_not_emit_spurious_capture(self):
        h = harness()
        try:
            h.setup()
            h.api()
            h.roundtrip()
            workspace = create(h, "api-baseline")
            import base64

            put = {
                "content_base64": base64.b64encode(b"api only\n").decode(),
                "expected_entry_version": 0,
                "expected_workspace_revision": 0,
                "lease_epoch": workspace["lease_epoch"],
            }
            first = json.loads(
                h.expect(
                    f"/api/workspaces/{workspace['id']}/files?path=hello.txt",
                    200,
                    token=h.alice,
                    method="PUT",
                    body=put,
                    extra_headers={"Idempotency-Key": "capture-api-only"},
                )
            )
            time.sleep(3)
            kinds = [event["kind"] for event in events(h, workspace)]
            self.assertEqual(kinds, ["file_put"], "API edit was reported as an external capture")
            self.assertEqual(events(h, workspace)[0]["revision"], first["workspace_revision"])
            (repo(h, workspace) / "native.txt").write_bytes(b"later native edit\n")
            event = wait_event(h, workspace, timeout=30, after=first["workspace_revision"])
            self.assertEqual(event["kind"], "external_capture")
            self.assertEqual(event["revision"], first["workspace_revision"] + 1)
        finally:
            h.cleanup()

    def test_large_inventory_keeps_single_tokio_worker_responsive(self):
        h = harness()
        h.env.update(
            TOKIO_WORKER_THREADS="1",
            ROOTYARD_WORKSPACE_SCAN_WORKERS="1",
            ROOTYARD_WORKSPACE_SCAN_TIMEOUT_MS="60000",
        )
        try:
            h.setup()
            h.api()
            h.roundtrip()
            workspace = create(h, "responsive")
            bulk(repo(h, workspace), BULK_COUNT, BULK_SIZE)
            samples = []
            stop = threading.Event()

            def probe():
                while not stop.is_set():
                    started = time.monotonic()
                    try:
                        with urllib.request.urlopen(h.base + "/health/live", timeout=3) as response:
                            response.read()
                        samples.append(time.monotonic() - started)
                    except Exception:
                        samples.append(99.0)
                    time.sleep(0.01)

            thread = threading.Thread(target=probe, daemon=True)
            thread.start()
            try:
                (repo(h, workspace) / "external.txt").write_bytes(b"capture me\n")
                event = wait_event(h, workspace, timeout=40)
                self.assertEqual(event["kind"], "external_capture")
            finally:
                stop.set()
                thread.join(timeout=5)
            self.assertGreaterEqual(len(samples), 20, "health probe did not overlap the scan window")
            slowest = max(samples)
            self.assertLess(
                slowest,
                1.0,
                f"health/live was blocked for {slowest:.3f}s by inventory scanning",
            )
        finally:
            h.cleanup()

    def test_sse_reconnect_and_retention_gap_uses_live_revision(self):
        h = harness()
        try:
            h.setup()
            h.api()
            h.roundtrip()
            workspace = create(h, "sse")
            for index in range(4):
                write_event(h, workspace, index)

            replay = json.loads(
                h.expect(f"/api/workspaces/{workspace['id']}/events?after_revision=0", 200, token=h.alice)
            )
            replayed = replay["events"]
            self.assertGreaterEqual(len(replayed), 4, replayed)
            latest = replay["snapshot_revision"]
            self.assertEqual(latest, replayed[-1]["revision"])
            first, second = replayed[0], replayed[1]

            # A native EventSource keeps the original query string on reconnect
            # and sends Last-Event-ID. The header must not replay first again.
            frames = sse_frames(h, workspace, after=0, last_event_id=first["revision"], max_frames=1)
            self.assertEqual(len(frames), 1, frames)
            self.assertEqual(frames[0]["event"], "workspace")
            self.assertEqual(frames[0]["id"], str(second["revision"]))
            self.assertEqual(json.loads(frames[0]["data"])["revision"], second["revision"])
            self.assertNotEqual(json.loads(frames[0]["data"])["revision"], first["revision"])

            # A malformed/overflowing header falls back to the query cursor.
            frames = sse_frames(
                h, workspace, after=first["revision"], last_event_id="9" * 40, max_frames=1
            )
            self.assertEqual(len(frames), 1, frames)
            self.assertEqual(json.loads(frames[0]["data"])["revision"], second["revision"])

            # Deleting this workspace's own third event models durable
            # retention. The page starts contiguous after the cursor and has an
            # internal discontinuity before later events.
            cursor = first["revision"]
            h.sql(
                "DELETE FROM workspace_events WHERE workspace_id='%s' AND revision=%d"
                % (workspace["id"], replayed[2]["revision"])
            )
            self.assertEqual(
                h.sql("SELECT revision FROM workspaces WHERE id='%s'" % workspace["id"]),
                str(latest),
            )
            resync = json.loads(
                h.expect(
                    f"/api/workspaces/{workspace['id']}/events?after_revision={cursor}",
                    200,
                    token=h.alice,
                )
            )
            self.assertEqual(resync.get("kind"), "RESYNC_REQUIRED")
            self.assertEqual(resync.get("snapshot_revision"), latest)
            self.assertNotIn("events", resync)

            frames = sse_frames(h, workspace, after=cursor, max_frames=4)
            self.assertEqual(len(frames), 1, frames)
            self.assertEqual(frames[0]["event"], "RESYNC_REQUIRED")
            self.assertIsNone(frames[0]["id"], "resync must not acknowledge an unseen mutation")
            self.assertEqual(json.loads(frames[0]["data"]), {"snapshot_revision": latest})
            self.assertFalse(any(frame["event"] == "workspace" for frame in frames))

            # A contiguous short page ending below the same durable watermark
            # is a trailing gap, even though its retained rows are contiguous.
            h.sql(
                "DELETE FROM workspace_events WHERE workspace_id='%s' AND revision>%d"
                % (workspace["id"], second["revision"])
            )
            self.assertEqual(
                h.sql(
                    "SELECT count(*) FROM workspace_events WHERE workspace_id='%s' AND revision>%d"
                    % (workspace["id"], cursor)
                ),
                "1",
                "short-page fixture did not retain exactly one trailing row",
            )
            self.assertEqual(
                h.sql("SELECT revision FROM workspaces WHERE id='%s'" % workspace["id"]),
                str(latest),
            )
            resync = json.loads(
                h.expect(
                    f"/api/workspaces/{workspace['id']}/events?after_revision={cursor}",
                    200,
                    token=h.alice,
                )
            )
            self.assertEqual(resync.get("kind"), "RESYNC_REQUIRED")
            self.assertEqual(resync.get("snapshot_revision"), latest)
            self.assertNotIn("events", resync)

            frames = sse_frames(h, workspace, after=cursor, max_frames=4)
            self.assertEqual(len(frames), 1, frames)
            self.assertEqual(frames[0]["event"], "RESYNC_REQUIRED")
            self.assertEqual(json.loads(frames[0]["data"]), {"snapshot_revision": latest})
            self.assertFalse(any(frame["event"] == "workspace" for frame in frames))

            # Retaining nothing after the cursor while the durable revision is
            # ahead is also a gap, not an idle stream.
            h.sql(
                "DELETE FROM workspace_events WHERE workspace_id='%s' AND revision>%d"
                % (workspace["id"], cursor)
            )
            resync = json.loads(
                h.expect(
                    f"/api/workspaces/{workspace['id']}/events?after_revision={cursor}",
                    200,
                    token=h.alice,
                )
            )
            self.assertEqual(resync.get("kind"), "RESYNC_REQUIRED")
            self.assertEqual(resync.get("snapshot_revision"), latest)

            frames = sse_frames(h, workspace, after=cursor, max_frames=4)
            self.assertEqual(len(frames), 1, frames)
            self.assertEqual(frames[0]["event"], "RESYNC_REQUIRED")
            self.assertEqual(json.loads(frames[0]["data"]), {"snapshot_revision": latest})
            self.assertFalse(any(frame["event"] == "workspace" for frame in frames))

            # At the live revision, empty retention is just an idle stream.
            idle = json.loads(
                h.expect(
                    f"/api/workspaces/{workspace['id']}/events?after_revision={latest}",
                    200,
                    token=h.alice,
                )
            )
            self.assertEqual(idle.get("events"), [])
            self.assertEqual(idle.get("snapshot_revision"), latest)
            self.assertNotEqual(idle.get("kind"), "RESYNC_REQUIRED")

            # A fresh future cursor is still a bad request for JSON and SSE.
            future = latest + 1
            status, _, _ = h.http(
                f"/api/workspaces/{workspace['id']}/events?after_revision={future}",
                token=h.alice,
            )
            self.assertEqual(status, 400)
            status, _, _ = h.http(
                f"/api/workspaces/{workspace['id']}/events/stream?after_revision={future}",
                token=h.alice,
            )
            self.assertEqual(status, 400)

            # The connected stream may outlive a durable revision rollback. It
            # must terminate at the lower watermark without first emitting any
            # stale workspace frame.
            self.assertEqual(
                h.sql(
                    "SELECT count(*) FROM workspace_events WHERE workspace_id='%s' AND revision>%d"
                    % (workspace["id"], latest)
                ),
                "0",
                "active-stream fixture has an unread event above its cursor",
            )
            lower = first["revision"]
            self.assertLess(lower, latest)

            def rollback():
                h.sql(
                    "UPDATE workspaces SET revision=%d WHERE id='%s'"
                    % (lower, workspace["id"])
                )
                self.assertEqual(
                    h.sql("SELECT revision FROM workspaces WHERE id='%s'" % workspace["id"]),
                    str(lower),
                )

            frames = sse_frames(
                h,
                workspace,
                after=latest,
                max_frames=4,
                on_open=rollback,
            )
            self.assertEqual(len(frames), 1, frames)
            self.assertEqual(frames[0]["event"], "RESYNC_REQUIRED")
            self.assertIsNone(frames[0]["id"], "rolled-back resync must not carry an event ID")
            self.assertEqual(json.loads(frames[0]["data"]), {"snapshot_revision": lower})
            self.assertFalse(any(frame["event"] == "workspace" for frame in frames))
        finally:
            h.cleanup()

    def test_scan_does_not_hold_row_lock_and_rejects_stale_revision(self):
        h = harness()
        h.env.update(
            ROOTYARD_WORKSPACE_SCAN_WORKERS="2",
            ROOTYARD_WORKSPACE_SCAN_TIMEOUT_MS="60000",
        )
        gate = None
        try:
            h.setup()
            h.api()
            h.roundtrip()
            workspace = create(h, "race")
            # The gate names one exact file, and the workspace id only exists
            # after the API call. Workspace rows and repositories are durable,
            # so restart the service once with the preload configured. The
            # scanner and database logic under test are unchanged.
            h.stop()
            target = repo(h, workspace) / "capture-gated.bin"
            gate_names = ("LD_PRELOAD", "ROOTYARD_TEST_CAPTURE_GATE", "ROOTYARD_TEST_CAPTURE_TARGET")
            prior_env = {name: h.env.get(name) for name in gate_names}
            gate = install_capture_read_gate(h, target)
            try:
                h.start()
            finally:
                # Popen copied the environment; later psql/CLI children should
                # use the original environment without the service read gate.
                for name, value in prior_env.items():
                    if value is None:
                        h.env.pop(name, None)
                    else:
                        h.env[name] = value
            base_revision = json.loads(
                h.expect(f"/api/workspaces/{workspace['id']}", 200, token=h.alice)
            )["revision"]
            _GATE_FACTS.clear()
            hit = gate.with_suffix(".hit")
            release = gate.with_suffix(".release")
            _GATE_FACTS.update(
                target=str(target), marker=str(hit), hit=False, released=False
            )
            # The external file appears only after the API baseline was read.
            # The next scanner pass opens this exact file and pauses inside the
            # real read, before its fingerprint can be committed.
            target.write_bytes(b"revision race\n" * 64)
            wait_capture_gate(hit)
            self.assertFalse(gate.with_suffix(".timeout").exists(), "read gate expired before observation")
            _GATE_FACTS["hit"] = True
            # The scan owns no workspace row lock while its real read is held.
            row_lock_nowait(h, workspace)
            idle = h.sql(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                "AND state='idle in transaction' AND query LIKE '%FROM workspaces%FOR UPDATE%'"
            )
            self.assertEqual(idle, "0", "capture left a workspace row locked while scanning")
            self.assertEqual(
                h.sql(
                    "SELECT count(*) FROM workspace_events WHERE workspace_id='%s' "
                    "AND kind='external_capture'" % workspace["id"]
                ),
                "0",
                "the bounded scan finished before the revision fence was injected",
            )
            # Jump the revision while the real read is still held. The scan
            # captured base_revision before the gate, so its guarded commit
            # must now be discarded as stale.
            h.sql(
                "UPDATE workspaces SET revision=revision+100 WHERE id='%s'" % workspace["id"]
            )
            watermark = int(
                h.sql("SELECT revision FROM workspaces WHERE id='%s'" % workspace["id"])
            )
            self.assertGreaterEqual(watermark, base_revision + 100)
            self.assertFalse(gate.with_suffix(".timeout").exists(), "read gate expired before the fence")
            release.touch()
            _GATE_FACTS["released"] = True
            # Releasing lets the stale first scan finish; the following small
            # scan can commit a new capture within the existing 30s bound.
            event = wait_durable_capture(h, workspace, after=base_revision, timeout=30)
            self.assertEqual(event["kind"], "external_capture")
            self.assertGreaterEqual(
                event["revision"],
                watermark,
                "stale scan overwrote a newer API revision",
            )
            stale = h.sql(
                "SELECT count(*) FROM workspace_events WHERE workspace_id='%s' "
                "AND kind='external_capture' AND revision>%d AND revision<%d"
                % (workspace["id"], base_revision, base_revision + 100)
            )
            self.assertEqual(stale, "0", "scan committed an event from before the revision CAS")
            # Product gap semantics stay intact: a reader that has not seen the
            # jumped revisions must be told to resync, not silently continue.
            resync = json.loads(
                h.expect(
                    f"/api/workspaces/{workspace['id']}/events?after_revision={base_revision}",
                    200,
                    token=h.alice,
                )
            )
            self.assertEqual(
                resync.get("kind"),
                "RESYNC_REQUIRED",
                "an artificial revision gap was not reported as RESYNC_REQUIRED",
            )
            self.assertGreaterEqual(resync.get("snapshot_revision", 0), watermark)
            self.assertFalse(gate.with_suffix(".timeout").exists(), "read gate released without test authorization")
            _GATE_FACTS["held_through_revision_fence"] = True
        finally:
            if gate is not None:
                # Never leave the service child blocked in the gate.
                gate.with_suffix(".release").touch()
                if _GATE_FACTS:
                    _GATE_FACTS["released"] = True
            h.cleanup()

    def test_scan_revalidates_lease_epoch_before_committing(self):
        h = harness()
        h.env.update(
            ROOTYARD_WORKSPACE_SCAN_WORKERS="2",
            ROOTYARD_WORKSPACE_SCAN_TIMEOUT_MS="60000",
        )
        gate = None
        holder = None
        observer = None
        try:
            h.setup()
            h.api()
            h.roundtrip()
            workspace = create(h, "epoch")
            target = repo(h, workspace) / "epoch-gated.txt"
            # The exact-file gate replaces the old process-wide rchar window,
            # so this case no longer needs the 90000-file inventory used only
            # to make that window reachable; the large-inventory case remains
            # a separate acceptance test.
            # The gate names one exact file, and the workspace id only exists
            # after the API call. Write the external file while the service is
            # stopped so every fingerprint pass of the first scan after restart
            # sees the same bytes; only the lease epoch then changes across the
            # scan. Workspace rows and repositories are durable, so restart the
            # service once with the preload configured. The scanner and
            # database logic under test are unchanged.
            h.stop()
            target.write_bytes(b"lease epoch race\n" * 64)
            gate_names = ("LD_PRELOAD", "ROOTYARD_TEST_CAPTURE_GATE", "ROOTYARD_TEST_CAPTURE_TARGET")
            prior_env = {name: h.env.get(name) for name in gate_names}
            gate = install_capture_read_gate(h, target)
            hit = gate.with_suffix(".hit")
            release = gate.with_suffix(".release")
            _GATE_FACTS.update(
                epoch_target=str(target),
                epoch_marker=str(hit),
                epoch_hit=False,
                epoch_released=False,
            )
            try:
                h.start()
            finally:
                # Popen copied the environment; later psql/CLI children should
                # use the original environment without the service read gate.
                for name, value in prior_env.items():
                    if value is None:
                        h.env.pop(name, None)
                    else:
                        h.env[name] = value
            # The first scan after restart opens this exact file and pauses
            # inside the real read, before its fingerprint can be committed.
            wait_capture_gate(hit)
            self.assertFalse(gate.with_suffix(".timeout").exists(), "read gate expired before observation")
            _GATE_FACTS["epoch_hit"] = True
            before = json.loads(
                h.expect(f"/api/workspaces/{workspace['id']}", 200, token=h.alice)
            )
            base_revision = before["revision"]
            seeded = h.sql(
                "SELECT fingerprint FROM workspace_capture_state WHERE workspace_id='%s'"
                % workspace["id"]
            )
            self.assertNotEqual(seeded, "", "workspace create did not seed a capture baseline")
            # The scan owns no workspace row lock while its real read is held,
            # and it has not advanced the seeded capture baseline or committed
            # an event yet.
            row_lock_nowait(h, workspace)
            idle = h.sql(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                "AND state='idle in transaction' AND query LIKE '%FROM workspaces%FOR UPDATE%'"
            )
            self.assertEqual(idle, "0", "capture left a workspace row locked while scanning")
            held_events = h.sql(
                "SELECT count(*) FROM workspace_events WHERE workspace_id='%s' "
                "AND kind='external_capture' AND revision>%d" % (workspace["id"], base_revision)
            )
            self.assertEqual(
                held_events,
                "0",
                "the bounded scan committed before the lease epoch fence was injected",
            )
            self.assertEqual(
                h.sql(
                    "SELECT fingerprint FROM workspace_capture_state WHERE workspace_id='%s'"
                    % workspace["id"]
                ),
                seeded,
                "the scan advanced capture state before the lease epoch fence",
            )
            # Move only this row's lease epoch. No revision mutation is
            # allowed: a revision jump would reject the stale scan for the
            # wrong reason and would be visible in the row before T2, so the
            # assertions below fail rather than pass.
            new_epoch = before["lease_epoch"] + 100
            suffix = workspace["id"][:8]
            holder_name = "ry-epoch-holder-" + suffix
            observer_name = "ry-epoch-observer-" + suffix
            # T holds the exact workspace row while the first scanner is still
            # paused inside its real read. The scanner cannot reach commit
            # until the gate is released.
            holder = PsqlSession(h, holder_name)
            holder.send(
                "BEGIN; SET application_name=" + sql_quote(holder_name) + "; "
                "SELECT 'holder-ready', pg_backend_pid(); "
                "SELECT 1 FROM workspaces WHERE id='%s' FOR UPDATE; "
                "SELECT 'holder-locked', pg_backend_pid();" % workspace["id"]
            )
            holder_pid = int(holder.marker("holder-ready"))
            holder.pid = holder_pid
            self.assertEqual(int(holder.marker("holder-locked")), holder_pid)
            assert_owned_session(h, holder_pid, holder_name, "idle in transaction")
            # Release the real read. The old scanner must finish both stable
            # fingerprint passes and block at commit_reconciled's exact
            # SELECT ... FOR UPDATE behind T.
            self.assertFalse(gate.with_suffix(".timeout").exists(), "read gate expired before the fence")
            release.touch()
            _GATE_FACTS["epoch_released"] = True
            scanner_pid = wait_scanner_commit_block(h, holder_pid)
            self.assertNotEqual(scanner_pid, holder_pid)
            # Queue T2 behind the identified scanner. T2 is not allowed to be
            # blocked directly by T; the authoritative PG graph below proves
            # holder -> scanner -> observer before T advances the epoch.
            observer = PsqlSession(h, observer_name)
            observer.send(
                "BEGIN; SET application_name=" + sql_quote(observer_name) + "; "
                "SELECT 'observer-ready', pg_backend_pid(); "
                "SELECT 1 FROM workspaces WHERE id='%s' FOR UPDATE; "
                "SELECT 'observer-locked', pg_backend_pid();" % workspace["id"]
            )
            observer_pid = int(observer.marker("observer-ready"))
            observer.pid = observer_pid
            wait_observer_blocked(h, observer_pid, scanner_pid)
            assert_blocking_chain(h, holder_pid, scanner_pid, observer_pid)
            # T changes only lease_epoch. The baseline, revision and live
            # deadline stay untouched, so the old scan is still eligible but
            # must reject its pre-fence result.
            holder.send(
                "UPDATE workspaces SET lease_epoch=lease_epoch+100 WHERE id='%s'; "
                "SELECT 'holder-updated', state, lease_epoch, revision, "
                "lease_until>clock_timestamp() FROM workspaces WHERE id='%s'; "
                "COMMIT; SELECT 'holder-committed', pg_backend_pid();"
                % (workspace["id"], workspace["id"])
            )
            updated = holder.marker("holder-updated").split("|")
            self.assertEqual(len(updated), 4, "holder row did not project four fields")
            self.assertEqual(updated[0], "ready")
            self.assertEqual(int(updated[1]), new_epoch)
            self.assertEqual(
                int(updated[2]),
                base_revision,
                "a revision-only mutation was visible before T2",
            )
            self.assertEqual(updated[3], "t", "fixture lease expired before the epoch fence")
            self.assertEqual(int(holder.marker("holder-committed")), holder_pid)
            _GATE_FACTS["held_through_lease_fence"] = True
            _GATE_FACTS["blocking_chain_verified"] = True
            # T2 can acquire only after the old scanner's transaction has
            # released the row lock. The scanner therefore finished and
            # rejected before T2 could hold the row.
            self.assertEqual(int(observer.marker("observer-locked")), observer_pid)
            assert_owned_session(h, observer_pid, observer_name, "idle in transaction")
            # While T2 holds the exact row lock, no fresh scanner can commit.
            # A row from the old scan (or any revision-only mutation) makes
            # this check fail.
            while_held = h.sql(
                "SELECT state,lease_epoch,revision,lease_until>clock_timestamp(),"
                "(SELECT count(*) FROM workspace_events WHERE workspace_id='%s' "
                "AND kind='external_capture' AND revision>%d),"
                "(SELECT fingerprint FROM workspace_capture_state WHERE workspace_id='%s') "
                "FROM workspaces WHERE id='%s'"
                % (workspace["id"], base_revision, workspace["id"], workspace["id"])
            ).split("|")
            self.assertEqual(len(while_held), 6, "held workspace row did not project six fields")
            self.assertEqual(while_held[0], "ready")
            self.assertEqual(int(while_held[1]), new_epoch)
            self.assertEqual(while_held[3], "t", "fixture lease expired while T2 held the row")
            self.assertEqual(
                while_held[4],
                "0",
                "the old gated scan committed before T2 acquired the row lock",
            )
            self.assertEqual(
                while_held[5],
                seeded,
                "the old gated scan advanced the baseline before T2 acquired the row lock",
            )
            self.assertEqual(
                int(while_held[2]),
                base_revision,
                "a revision-only mutation was visible before T2",
            )
            _GATE_FACTS["old_scan_rejected_before_observer_acquired"] = True
            _GATE_FACTS["no_old_epoch_durable_capture"] = True
            # Release T2. Exactly one fresh new-epoch capture may commit.
            observer.send("ROLLBACK; SELECT 'observer-released', pg_backend_pid();")
            self.assertEqual(int(observer.marker("observer-released")), observer_pid)
            event = wait_durable_capture(h, workspace, after=base_revision, timeout=30)
            self.assertEqual(event["kind"], "external_capture")
            self.assertEqual(
                event["revision"],
                base_revision + 1,
                "post-fence capture did not advance exactly one revision",
            )
            count = h.sql(
                "SELECT count(*) FROM workspace_events WHERE workspace_id='%s' "
                "AND kind='external_capture' AND revision>%d"
                % (workspace["id"], base_revision)
            )
            self.assertEqual(count, "1", "expected exactly one post-fence capture")
            durable = h.sql(
                "SELECT payload->>'lease_epoch',payload->>'fingerprint' FROM workspace_events "
                "WHERE workspace_id='%s' AND revision=%d"
                % (workspace["id"], event["revision"])
            ).split("|")
            self.assertEqual(len(durable), 2, "durable capture row did not expose lease epoch and fingerprint")
            self.assertEqual(
                int(durable[0]),
                new_epoch,
                "stale scan committed an event under a fenced lease epoch",
            )
            self.assertNotEqual(
                durable[1],
                seeded,
                "post-fence capture replayed the seeded fingerprint instead of the new file",
            )
            self.assertEqual(
                h.sql(
                    "SELECT fingerprint FROM workspace_capture_state WHERE workspace_id='%s'"
                    % workspace["id"]
                ),
                durable[1],
                "durable capture event and capture baseline diverged",
            )
            stale = h.sql(
                "SELECT count(*) FROM workspace_events WHERE workspace_id='%s' "
                "AND kind='external_capture' AND revision>%d "
                "AND COALESCE((payload->>'lease_epoch')::bigint, -1) < %d"
                % (workspace["id"], base_revision, new_epoch)
            )
            self.assertEqual(stale, "0", "scan committed a capture from the pre-fence lease epoch")
            _GATE_FACTS["new_epoch_durable_capture"] = True
            # Check the public event projection separately, but only when it is
            # contiguous. A synthetic gap keeps the existing RESYNC_REQUIRED
            # contract and is never used as a substitute for the durable row.
            public = json.loads(
                h.expect(
                    f"/api/workspaces/{workspace['id']}/events?after_revision={base_revision}",
                    200,
                    token=h.alice,
                )
            )
            self.assertGreaterEqual(public.get("snapshot_revision", 0), event["revision"])
            if public.get("kind") == "RESYNC_REQUIRED":
                _GATE_FACTS["public_events_contiguous"] = False
            else:
                projected = [
                    item
                    for item in public.get("events", [])
                    if item["kind"] == "external_capture" and item["revision"] == event["revision"]
                ]
                self.assertTrue(projected, "public events API omitted the durable capture")
                self.assertEqual(
                    int(projected[0]["payload"]["lease_epoch"]),
                    new_epoch,
                    "public events API exposed a stale lease epoch",
                )
                _GATE_FACTS["public_events_contiguous"] = True
            self.assertFalse(gate.with_suffix(".timeout").exists(), "read gate released without test authorization")
        finally:
            if gate is not None:
                # Never leave the service child blocked in the gate.
                gate.with_suffix(".release").touch()
                if "epoch_marker" in _GATE_FACTS:
                    _GATE_FACTS["epoch_released"] = True
            # Release owned row-lock sessions before the schema is dropped.
            for session in (holder, observer):
                if session is not None:
                    session.close()
            h.cleanup()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        metavar="PATH",
        help="native rootyard binary to exercise (resolved to an absolute path)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        metavar="PATH",
        help="optional JSON path for per-test results and the binary SHA-256",
    )
    parser.add_argument("--keep", action="store_true", help="keep disposable test directories")
    parser.add_argument(
        "--report-unit",
        action="store_true",
        help="run only the in-memory report unit (needs no binary or database)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose unittest output")
    parser.add_argument(
        "tests",
        nargs="*",
        metavar="TEST",
        help="optional unittest names, e.g. WorkspaceCaptureAcceptance.test_scan_revalidates_lease_epoch_before_committing",
    )
    args = parser.parse_args(argv)

    if args.report_unit:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReportUnitTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    if args.binary is None:
        parser.error("--binary is required")
    binary = args.binary.resolve()
    if not binary.is_absolute():
        parser.error(f"--binary did not resolve to an absolute path: {binary}")
    if not binary.is_file():
        parser.error(f"--binary does not exist or is not a file: {binary}")
    if not os.access(binary, os.X_OK):
        parser.error(f"--binary is not executable: {binary}")
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")

    global _TEST_BINARY, _TEST_KEEP
    _TEST_BINARY, _TEST_KEEP = str(binary), args.keep

    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    loader = unittest.TestLoader()
    suite = selected_suite(loader, args.tests, sys.modules[__name__])
    scheduled_ids = scheduled_test_ids(suite)
    if not scheduled_ids:
        parser.error("no tests selected")

    result = None
    try:
        runner = unittest.TextTestRunner(
            verbosity=2 if args.verbose else 1,
            resultclass=TimedTextTestResult,
        )
        result = runner.run(suite)
    finally:
        report = build_report(result, scheduled_ids, binary, binary_sha256)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
