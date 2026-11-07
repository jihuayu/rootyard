#!/usr/bin/env python3
"""Native acceptance for bounded workspace capture and Git execution (#73/#68).

The suite runs the real Rust service against a disposable PostgreSQL schema. It
uses real workspaces, real Git clones and real filesystem inventories:
* more than 100 valid workspaces capture UUIDs beyond a fixed prefix even when
  an earlier workspace is permanently bad and another is deliberately slow;
* a large inventory does not block the sole Tokio worker for health requests;
* a scan in progress does not hold the workspace row lock, and a revision or
  lease-epoch change during that scan is never overwritten by the stale result.
"""
import argparse
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
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
SCAN_IO_DELTA = 5_000_000

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


def io_read_bytes(h):
    try:
        with open(f"/proc/{h.proc.pid}/io", "rb") as stream:
            for line in stream:
                if line.startswith(b"rchar:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def wait_scan_io(h, baseline, delta, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = io_read_bytes(h)
        if current is not None and current - baseline > delta:
            return current
        time.sleep(0.01)
    raise AssertionError("workspace inventory did not start within the bounded scan window")


def row_lock_nowait(h, workspace):
    h.sql(
        "BEGIN; SELECT 1 FROM workspaces WHERE id='%s' FOR UPDATE NOWAIT; COMMIT;"
        % workspace["id"]
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
            _GATE_FACTS["held_through_revision_fence"] = True
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
        try:
            h.setup()
            h.api()
            h.roundtrip()
            workspace = create(h, "epoch")
            bulk(repo(h, workspace), BULK_COUNT, BULK_SIZE)
            before = json.loads(h.expect(f"/api/workspaces/{workspace['id']}", 200, token=h.alice))
            baseline = io_read_bytes(h)
            (repo(h, workspace) / "epoch.txt").write_bytes(b"lease epoch race\n")
            wait_scan_io(h, baseline, SCAN_IO_DELTA)
            row_lock_nowait(h, workspace)
            new_epoch = before["lease_epoch"] + 100
            h.sql(
                "UPDATE workspaces SET lease_epoch=lease_epoch+100, "
                "lease_until=clock_timestamp()+interval '5 minutes' WHERE id='%s'" % workspace["id"]
            )
            event = wait_event(h, workspace, timeout=30, after=before["revision"])
            self.assertEqual(event["kind"], "external_capture")
            self.assertGreaterEqual(
                event["payload"]["lease_epoch"],
                new_epoch,
                "stale scan committed an event under a fenced lease epoch",
            )
        finally:
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
