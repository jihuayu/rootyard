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
import json
import os
import threading
import time
import unittest
import urllib.request

from tests.e2e import Harness

BULK_COUNT = 90000
BULK_SIZE = 1024
SCAN_IO_DELTA = 5_000_000


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


class WorkspaceCaptureAcceptance(unittest.TestCase):
    def test_capture_reaches_ids_beyond_fixed_prefix(self):
        h = Harness(argparse.Namespace(binary="target/debug/rootyard", keep=False))
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
        h = Harness(argparse.Namespace(binary="target/debug/rootyard", keep=False))
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
        h = Harness(argparse.Namespace(binary="target/debug/rootyard", keep=False))
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
        h = Harness(argparse.Namespace(binary="target/debug/rootyard", keep=False))
        h.env.update(
            ROOTYARD_WORKSPACE_SCAN_WORKERS="2",
            ROOTYARD_WORKSPACE_SCAN_TIMEOUT_MS="60000",
        )
        try:
            h.setup()
            h.api()
            h.roundtrip()
            workspace = create(h, "race")
            bulk(repo(h, workspace), BULK_COUNT, BULK_SIZE)
            base_revision = json.loads(h.expect(f"/api/workspaces/{workspace['id']}", 200, token=h.alice))["revision"]
            baseline = io_read_bytes(h)
            (repo(h, workspace) / "race.txt").write_bytes(b"revision race\n")
            wait_scan_io(h, baseline, SCAN_IO_DELTA)
            # The scan owns no workspace row lock: both probes must succeed while
            # the bounded reader is still hashing the large inventory.
            row_lock_nowait(h, workspace)
            idle = h.sql(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                "AND state='idle in transaction' AND query LIKE '%FROM workspaces%FOR UPDATE%'"
            )
            self.assertEqual(idle, "0", "capture left a workspace row locked while scanning")
            h.sql(
                "UPDATE workspaces SET revision=revision+100 WHERE id='%s'" % workspace["id"]
            )
            event = wait_event(h, workspace, timeout=30, after=base_revision)
            self.assertEqual(event["kind"], "external_capture")
            self.assertGreaterEqual(
                event["revision"],
                base_revision + 100,
                "stale scan overwrote a newer API revision",
            )
            stale = [
                item
                for item in events(h, workspace)
                if item["kind"] == "external_capture"
                and base_revision < item["revision"] < base_revision + 100
            ]
            self.assertEqual(stale, [], "scan committed an event from before the revision CAS")
        finally:
            h.cleanup()

    def test_scan_revalidates_lease_epoch_before_committing(self):
        h = Harness(argparse.Namespace(binary="target/debug/rootyard", keep=False))
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


if __name__ == "__main__":
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        raise SystemExit("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    unittest.main()
