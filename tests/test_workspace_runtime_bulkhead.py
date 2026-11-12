"""Workspace runtime bulkhead, rollback, timeout cleanup, and takeover regressions (#73).

Proves against a real PostgreSQL 15 cluster, Garage 2.1.0 S3, and live `rootyard`:
1. 16 concurrent stalled workspace Git mutations (`max_size(16)` DB pool) hold
   zero `idle in transaction` PostgreSQL connections during Phase 2 execution,
   never starve bystander reads, fail fast with `503` on the 17th slot, and
   replay disconnect-interrupted owned jobs with zero spurious capture events.
2. Phase 3 pre-`COMMIT` `409 Conflict` rejections in both `PUT /files` and
   `POST /git` roll back working-tree files, `.git/index`, and newly created
   `.git/objects` loose blobs so subsequent `capture::reconcile_one` scans see
   an unchanged baseline and emit zero `external_capture` events.
3. A timed-out (`504`) `POST /git` cleans up `.git/index.lock` and loose blobs,
   emits zero `external_capture` events, and allows the next `POST /git` to
   succeed; unreadable `.git/objects` subdirectories fail closed before spawning
   `git`; and `POST /checkpoints` reconciles native edits on the foreground
   bulkhead even when all background scan workers are configured tightly.
4. A cross-volume `POST /lease` takeover that loses a Phase 3 race cleans up its
   uncommitted `workspaces/<id>` tree instead of wedging a later `cp2` takeover.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
import shutil
import time
import unittest
import urllib.parse

from tests.workspace_runtime_bulkhead_support import (
    b64,
    create_ws,
    git_add_body,
    git_object_files,
    make_git_gate,
    new_harness,
    put_hello,
    start_psql_tx,
    stop_psql_tx,
    wait_for_capture_scan,
)


class WorkspaceRuntimeBulkheadTest(unittest.TestCase):
    def test_sixteen_stalled_mutations_never_starve_postgres_pool_or_strand_locks(self):
        h = new_harness()
        try:
            h.setup()
            h.api()
            h.roundtrip()
            wrapper, pause_flag, _, entered_dir = make_git_gate(h)
            h.stop()
            h.env["ROOTYARD_GIT"] = str(wrapper)
            h.env["ROOTYARD_MAX_CONCURRENT_GIT"] = "16"
            h.start()

            workspaces = []
            for idx in range(17):
                ws = create_ws(h, f"bh-{idx}", f"bh-create-{idx}")
                put_hello(h, ws["id"], f"payload-{idx}\n".encode(), 0, 0, f"bh-put-{idx}", ws["lease_epoch"])
                workspaces.append(ws)

            bystander = workspaces[16]
            pause_flag.write_text("hold\n")

            def stage_one(idx: int):
                return h.http(
                    f"/api/workspaces/{workspaces[idx]['id']}/git",
                    token=h.alice,
                    method="POST",
                    body=git_add_body(0, 1),
                    extra_headers={"Idempotency-Key": f"bh-add-{idx}"},
                )

            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = [pool.submit(stage_one, idx) for idx in range(16)]
                deadline = time.monotonic() + 10.0
                while len(list(entered_dir.iterdir())) < 16:
                    self.assertLess(time.monotonic(), deadline, "not all 16 git add workers entered gate")
                    time.sleep(0.02)

                time.sleep(0.2)
                idle_in_tx = int(
                    h.sql(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE datname = current_database() AND pid <> pg_backend_pid() "
                        "AND state = 'idle in transaction' "
                        "AND xact_start <= clock_timestamp() - interval '150 milliseconds'"
                    ).strip()
                )
                self.assertEqual(idle_in_tx, 0, "workspace mutations held PostgreSQL transactions across Git I/O")

                t0 = time.monotonic()
                for _ in range(5):
                    info = json.loads(h.expect(f"/api/workspaces/{bystander['id']}", 200, token=h.alice))
                    self.assertEqual(info["revision"], 1)
                    got = json.loads(
                        h.expect(f"/api/workspaces/{bystander['id']}/files?path=hello.txt", 200, token=h.alice)
                    )
                    self.assertEqual(base64.b64decode(got["content_base64"]), b"payload-16\n")
                self.assertLess(time.monotonic() - t0, 2.5)

                status_17, raw_17, _ = stage_one(16)
                self.assertEqual(status_17, 503, raw_17)

                pause_flag.unlink()
                for idx, fut in enumerate(futures):
                    st, raw, _ = fut.result(timeout=15)
                    self.assertEqual(st, 200, f"worker {idx} failed: {raw}")

            self.assertEqual(stage_one(16)[0], 200)

            for marker in entered_dir.iterdir():
                marker.unlink()
            put_hello(h, bystander["id"], b"disconnect-safe\n", 1, 2, "disconnect-prep-put")
            pause_flag.write_text("hold-disconnect\n")
            parsed = urllib.parse.urlparse(h.base)
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
            disconnect_body = git_add_body(1, 3)
            conn.request(
                "POST",
                f"/api/workspaces/{bystander['id']}/git",
                body=json.dumps(disconnect_body).encode(),
                headers={
                    "Authorization": f"Bearer {h.alice['token']}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": "disconnect-git-key",
                },
            )
            deadline = time.monotonic() + 8.0
            while not list(entered_dir.iterdir()):
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
            conn.close()
            pause_flag.unlink()

            deadline = time.monotonic() + 8.0
            replayed = None
            while time.monotonic() < deadline:
                st, raw, _ = h.http(
                    f"/api/workspaces/{bystander['id']}/git",
                    token=h.alice,
                    method="POST",
                    body=disconnect_body,
                    extra_headers={"Idempotency-Key": "disconnect-git-key"},
                )
                if st == 200:
                    replayed = json.loads(raw)
                    break
                time.sleep(0.05)
            self.assertIsNotNone(replayed)
            self.assertEqual(replayed["workspace_revision"], 4)

            repo_dir = h.root / "data/workspace-service/workspaces" / bystander["id"]
            self.assertFalse((repo_dir / ".git/index.lock").exists())

            marker_ts = h.sql("SELECT clock_timestamp()::text")
            wait_for_capture_scan(h, bystander["id"], marker_ts)
            events = json.loads(
                h.expect(f"/api/workspaces/{bystander['id']}/events?after_revision=0", 200, token=h.alice)
            )["events"]
            self.assertEqual([e["kind"] for e in events], ["file_put", "git", "file_put", "git"])
        finally:
            h.cleanup()

    def test_phase3_rejected_put_and_git_roll_back_disk_and_emit_zero_external_captures(self):
        h = new_harness()
        try:
            h.setup()
            h.api()
            h.roundtrip()
            wrapper, pause_flag, _, entered_dir = make_git_gate(h)
            h.stop()
            h.env["ROOTYARD_GIT"] = str(wrapper)
            h.start()

            ws = create_ws(h, "rb-agent", "rb-create")
            wid = ws["id"]
            repo_dir = h.root / "data/workspace-service/workspaces" / wid

            put_hello(h, wid, b"staged-v1\n", 0, 0, "rb-put-1")
            h.expect(
                f"/api/workspaces/{wid}/git",
                200,
                token=h.alice,
                method="POST",
                body=git_add_body(0, 1),
                extra_headers={"Idempotency-Key": "rb-add-1"},
            )
            put_hello(h, wid, b"unstaged-v2\n", 1, 2, "rb-put-2")

            locker = start_psql_tx(h)
            try:
                locker.stdin.write(
                    f"BEGIN;\nSELECT 'LOCKED' FROM workspace_entries WHERE workspace_id='{wid}' AND path='hello.txt' FOR UPDATE;\n"
                )
                locker.stdin.flush()
                self.assertEqual(locker.stdout.readline().strip(), "LOCKED")

                with ThreadPoolExecutor(max_workers=1) as pool:
                    put_fut = pool.submit(
                        h.http,
                        f"/api/workspaces/{wid}/files?path=hello.txt",
                        token=h.alice,
                        method="PUT",
                        body={
                            "content_base64": b64(b"rejected-put-bytes\n"),
                            "expected_entry_version": 2,
                            "expected_workspace_revision": 3,
                            "lease_epoch": 1,
                        },
                        extra_headers={"Idempotency-Key": "rb-put-rejected"},
                    )
                    deadline = time.monotonic() + 8.0
                    while not (
                        int(h.sql("SELECT count(*) FROM pg_locks WHERE NOT granted").strip()) > 0
                        and (repo_dir / "hello.txt").read_bytes() == b"rejected-put-bytes\n"
                    ):
                        self.assertLess(time.monotonic(), deadline, "PUT never reached Phase 3 row lock")
                        time.sleep(0.02)

                    locker.stdin.write(
                        f"UPDATE workspace_entries SET entry_version = 99 WHERE workspace_id='{wid}' AND path='hello.txt';\nCOMMIT;\n"
                    )
                    locker.stdin.close()
                    locker.wait(timeout=5)
                    st_put, raw_put, _ = put_fut.result(timeout=10)
                    self.assertEqual(st_put, 409, raw_put)
            finally:
                stop_psql_tx(locker)

            h.sql(f"UPDATE workspace_entries SET entry_version = 2 WHERE workspace_id='{wid}' AND path='hello.txt'")
            working = json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt", 200, token=h.alice))
            self.assertEqual(base64.b64decode(working["content_base64"]), b"unstaged-v2\n")
            self.assertEqual(working["entry_version"], 2)
            wait_for_capture_scan(h, wid, h.sql("SELECT clock_timestamp()::text"))
            self.assertEqual(json.loads(h.expect(f"/api/workspaces/{wid}", 200, token=h.alice))["revision"], 3)

            objs_before = git_object_files(repo_dir)
            for m in entered_dir.iterdir():
                m.unlink()
            pause_flag.write_text("hold-git-rb\n")
            with ThreadPoolExecutor(max_workers=1) as pool:
                git_fut = pool.submit(
                    h.http,
                    f"/api/workspaces/{wid}/git",
                    token=h.alice,
                    method="POST",
                    body=git_add_body(1, 3),
                    extra_headers={"Idempotency-Key": "rb-git-rejected"},
                )
                deadline = time.monotonic() + 8.0
                while not list(entered_dir.iterdir()):
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
                h.sql(f"UPDATE workspaces SET lease_epoch = 2 WHERE id = '{wid}'")
                pause_flag.unlink()
                st_git, raw_git, _ = git_fut.result(timeout=10)
                self.assertEqual(st_git, 409, raw_git)

            self.assertEqual(git_object_files(repo_dir), objs_before)
            idx_view = json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt&view=index", 200, token=h.alice))
            self.assertEqual(base64.b64decode(idx_view["content_base64"]), b"staged-v1\n")
            wait_for_capture_scan(h, wid, h.sql("SELECT clock_timestamp()::text"))
            self.assertEqual(json.loads(h.expect(f"/api/workspaces/{wid}", 200, token=h.alice))["revision"], 3)
            events = json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0", 200, token=h.alice))["events"]
            self.assertEqual([e["kind"] for e in events], ["file_put", "git", "file_put"])
        finally:
            h.cleanup()

    def test_timed_out_git_cleans_index_lock_and_checkpoints_reconcile_foreground(self):
        h = new_harness()
        try:
            h.setup()
            h.api()
            h.roundtrip()
            wrapper, _, hang_lock_flag, entered_dir = make_git_gate(h)
            h.stop()
            h.env["ROOTYARD_GIT"] = str(wrapper)
            h.env["ROOTYARD_GIT_TIMEOUT_SECONDS"] = "1"
            h.start()

            ws = create_ws(h, "timeout-agent", "timeout-create")
            wid = ws["id"]
            repo_dir = h.root / "data/workspace-service/workspaces" / wid
            put_hello(h, wid, b"timeout-stage-v1\n", 0, 0, "timeout-put-1")
            objs_before = git_object_files(repo_dir)

            # (a) Unreadable .git/objects subdir fails GitRollback::capture closed before spawning git.
            if os.geteuid() != 0:
                bad_dir = repo_dir / ".git/objects/aa"
                bad_dir.mkdir(parents=True, exist_ok=True)
                bad_dir.chmod(0o000)
                try:
                    st_bad, _, _ = h.http(
                        f"/api/workspaces/{wid}/git",
                        token=h.alice,
                        method="POST",
                        body=git_add_body(0, 1),
                        extra_headers={"Idempotency-Key": "unreadable-git-objects"},
                    )
                    self.assertEqual(st_bad, 503)
                    self.assertEqual(list(entered_dir.iterdir()), [])
                finally:
                    bad_dir.chmod(0o755)
                    bad_dir.rmdir()

            # (b) Timed-out POST /git cleans .git/index.lock + loose objects and emits zero external_capture events.
            hang_lock_flag.write_text("hang\n")
            st_to, raw_to, _ = h.http(
                f"/api/workspaces/{wid}/git",
                token=h.alice,
                method="POST",
                body=git_add_body(0, 1),
                extra_headers={"Idempotency-Key": "timed-out-git-add"},
            )
            self.assertEqual(st_to, 504, raw_to)
            hang_lock_flag.unlink()
            self.assertFalse((repo_dir / ".git/index.lock").exists(), "timed-out git left .git/index.lock")
            self.assertEqual(git_object_files(repo_dir), objs_before)

            wait_for_capture_scan(h, wid, h.sql("SELECT clock_timestamp()::text"))
            self.assertEqual(json.loads(h.expect(f"/api/workspaces/{wid}", 200, token=h.alice))["revision"], 1)
            events = json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0", 200, token=h.alice))["events"]
            self.assertEqual([e["kind"] for e in events], ["file_put"])

            # Subsequent POST /git succeeds cleanly with no stranded index.lock.
            staged = json.loads(
                h.expect(
                    f"/api/workspaces/{wid}/git",
                    200,
                    token=h.alice,
                    method="POST",
                    body=git_add_body(0, 1),
                    extra_headers={"Idempotency-Key": "recovered-git-add"},
                )
            )
            self.assertEqual(staged["workspace_revision"], 2)

            # (c) Immediate POST /checkpoints reconciles uncaptured native edit on foreground bulkhead.
            (repo_dir / "hello.txt").write_bytes(b"native-edit-before-cp\n")
            st_stale, _, _ = h.http(
                f"/api/workspaces/{wid}/checkpoints",
                token=h.alice,
                method="POST",
                body={"expected_workspace_revision": 2, "lease_epoch": 1},
                extra_headers={"Idempotency-Key": "cp-stale"},
            )
            self.assertEqual(st_stale, 409)
            cp = json.loads(
                h.expect(
                    f"/api/workspaces/{wid}/checkpoints",
                    201,
                    token=h.alice,
                    method="POST",
                    body={"expected_workspace_revision": 3, "lease_epoch": 1},
                    extra_headers={"Idempotency-Key": "cp-fresh"},
                )
            )
            self.assertEqual(cp["captured_revision"], 3)
        finally:
            h.cleanup()

    def test_cross_volume_lease_takeover_and_lost_race_recovery_with_live_s3(self):
        h = new_harness(require_s3=True)
        try:
            h.setup()
            h.api()
            h.roundtrip()
            ws = create_ws(h, "cross-vol", "cross-vol-create")
            wid = ws["id"]
            put_hello(h, wid, b"cp1 payload\n", 0, 0, "cross-vol-put-1")
            cp1 = json.loads(
                h.expect(
                    f"/api/workspaces/{wid}/checkpoints",
                    201,
                    token=h.alice,
                    method="POST",
                    body={"expected_workspace_revision": 1, "lease_epoch": 1},
                    extra_headers={"Idempotency-Key": "cross-vol-cp-1"},
                )
            )
            self.assertEqual(
                json.loads(h.expect(f"/api/checkpoints/{cp1['checkpoint_id']}/publish", 200, token=h.alice, method="POST"))["state"],
                "COMMITTED",
            )

            h.stop(hard=True)
            vol1, vol2 = h.root / "data", h.root / "volume-two"
            h.env["ROOTYARD_DATA_DIR"] = str(vol2)
            h.start()

            h.sql(f"UPDATE workspaces SET lease_until = clock_timestamp() - interval '1 second' WHERE id = '{wid}'")
            locker = start_psql_tx(h)
            try:
                locker.stdin.write(f"BEGIN;\nSELECT 'LOCKED' FROM workspaces WHERE id = '{wid}' FOR UPDATE;\n")
                locker.stdin.flush()
                self.assertEqual(locker.stdout.readline().strip(), "LOCKED")

                with ThreadPoolExecutor(max_workers=1) as pool:
                    lease_fut = pool.submit(
                        h.http, f"/api/workspaces/{wid}/lease", token=h.alice, method="POST", body={"expected_lease_epoch": 1}
                    )
                    deadline = time.monotonic() + 10.0
                    while not (
                        int(h.sql("SELECT count(*) FROM pg_locks WHERE NOT granted").strip()) > 0
                        and (vol2 / "workspace-service/workspaces" / wid).exists()
                    ):
                        self.assertLess(time.monotonic(), deadline, "takeover never materialized cp1 before Phase 3")
                        time.sleep(0.02)

                    locker.stdin.write(
                        f"UPDATE workspaces SET lease_until = clock_timestamp() + interval '5 minutes' WHERE id = '{wid}';\nCOMMIT;\n"
                    )
                    locker.stdin.close()
                    locker.wait(timeout=5)
                    st_race, raw_race, _ = lease_fut.result(timeout=10)
                    self.assertEqual(st_race, 409, raw_race)
            finally:
                stop_psql_tx(locker)

            self.assertFalse((vol2 / "workspace-service/workspaces" / wid).exists())

            h.stop(hard=True)
            h.env["ROOTYARD_DATA_DIR"] = str(vol1)
            h.start()
            put_hello(h, wid, b"cp2 newer payload\n", 1, 2, "cross-vol-put-2")
            cp2 = json.loads(
                h.expect(
                    f"/api/workspaces/{wid}/checkpoints",
                    201,
                    token=h.alice,
                    method="POST",
                    body={"expected_workspace_revision": 3, "lease_epoch": 1},
                    extra_headers={"Idempotency-Key": "cross-vol-cp-2"},
                )
            )
            self.assertEqual(
                json.loads(h.expect(f"/api/checkpoints/{cp2['checkpoint_id']}/publish", 200, token=h.alice, method="POST"))["state"],
                "COMMITTED",
            )

            h.stop(hard=True)
            shutil.rmtree(vol1)
            h.env["ROOTYARD_DATA_DIR"] = str(vol2)
            h.start()
            h.sql(f"UPDATE workspaces SET lease_until = clock_timestamp() - interval '1 second' WHERE id = '{wid}'")
            self.assertEqual(
                h.http(f"/api/workspaces/{wid}/lease", token=h.bob, method="POST", body={"expected_lease_epoch": 1})[0], 404
            )
            taken = json.loads(
                h.expect(f"/api/workspaces/{wid}/lease", 200, token=h.alice, method="POST", body={"expected_lease_epoch": 1})
            )
            self.assertEqual(taken["lease_epoch"], 2)
            got = json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt", 200, token=h.alice))
            self.assertEqual(base64.b64decode(got["content_base64"]), b"cp2 newer payload\n")
        finally:
            h.cleanup()


if __name__ == "__main__":
    unittest.main()
