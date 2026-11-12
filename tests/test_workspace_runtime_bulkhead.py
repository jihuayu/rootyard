"""Workspace runtime bulkhead, short-transaction, and non-starvation regression (#73).

Proves against a real PostgreSQL 15 cluster and live `rootyard` server that:
1. 16 concurrent stalled workspace Git mutations (`max_size(16)` DB pool) hold
   zero `idle in transaction` PostgreSQL connections during Phase 2 execution.
2. Unrelated workspace/API reads stay responsive (`200 OK` under tight timeout)
   even when all 16 workspace Git slots are parked mid-mutation.
3. A 17th concurrent Git mutation fails fast with `503 Service Unavailable`
   before opening a DB transaction, and succeeds cleanly once capacity frees up.
4. Client disconnect while `git add` is mid-flight preserves the owned job,
   commits cleanly on release, leaves no `.git/index.lock`, records the exact
   post-write capture baseline (zero spurious `external_capture` events), and
   replays `200 OK` when retried with the same `Idempotency-Key`.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
import shutil
import time
import unittest
import urllib.parse

from tests.e2e import Harness


class WorkspaceRuntimeBulkheadTest(unittest.TestCase):
    def test_sixteen_stalled_mutations_never_starve_postgres_pool_or_strand_locks(self):
        h = Harness(
            argparse.Namespace(
                binary="target/debug/rootyard",
                keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1",
            )
        )
        try:
            h.setup()
            h.api()
            h.roundtrip()
            real_git = shutil.which("git", path=h.env["PATH"])
            self.assertTrue(real_git)

            gate_dir = h.root / "git-gate"
            gate_dir.mkdir()
            pause_flag = gate_dir / "pause-add"
            entered_dir = gate_dir / "entered"
            entered_dir.mkdir()
            wrapper = h.root / "gated-workspace-git"
            wrapper.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, sys, time\n"
                "args = sys.argv[1:]\n"
                f"pause = pathlib.Path({str(pause_flag)!r})\n"
                f"entered = pathlib.Path({str(entered_dir)!r})\n"
                "if 'add' in args and pause.exists():\n"
                "    (entered / str(os.getpid())).write_text('1')\n"
                "    while pause.exists():\n"
                "        time.sleep(0.02)\n"
                f"os.execv({real_git!r}, [{real_git!r}] + args)\n"
            )
            wrapper.chmod(0o700)

            h.stop()
            h.env["ROOTYARD_GIT"] = str(wrapper)
            h.env["ROOTYARD_MAX_CONCURRENT_GIT"] = "16"
            h.start()

            # Create 17 independent workspaces (16 to saturate all Git slots ==
            # deadpool max_size(16), plus 1 bystander workspace for reads/503).
            workspaces = []
            for idx in range(17):
                ws = json.loads(
                    h.expect(
                        "/api/workspaces",
                        201,
                        token=h.alice,
                        method="POST",
                        body={
                            "owner": "alice",
                            "repository": "demo",
                            "agent_id": f"bulkhead-{idx}",
                            "base_oid": h.second,
                        },
                        extra_headers={"Idempotency-Key": f"bulkhead-create-{idx}"},
                    )
                )
                put_body = {
                    "content_base64": base64.b64encode(f"payload-{idx}\n".encode()).decode(),
                    "expected_entry_version": 0,
                    "expected_workspace_revision": 0,
                    "lease_epoch": ws["lease_epoch"],
                }
                h.expect(
                    f"/api/workspaces/{ws['id']}/files?path=hello.txt",
                    200,
                    token=h.alice,
                    method="PUT",
                    body=put_body,
                    extra_headers={"Idempotency-Key": f"bulkhead-put-{idx}"},
                )
                workspaces.append(ws)

            bystander = workspaces[16]
            pause_flag.write_text("hold\n")

            def stage_one(idx: int):
                wid = workspaces[idx]["id"]
                return h.http(
                    f"/api/workspaces/{wid}/git",
                    token=h.alice,
                    method="POST",
                    body={
                        "action": "add",
                        "paths": ["hello.txt"],
                        "expected_git_generation": 0,
                        "expected_workspace_revision": 1,
                        "lease_epoch": 1,
                    },
                    extra_headers={"Idempotency-Key": f"bulkhead-add-{idx}"},
                )

            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = [pool.submit(stage_one, idx) for idx in range(16)]
                deadline = time.monotonic() + 10.0
                while len(list(entered_dir.iterdir())) < 16:
                    self.assertLess(time.monotonic(), deadline, "not all 16 git add workers entered gate")
                    time.sleep(0.02)

                # 1. Zero `idle in transaction` PostgreSQL backends while all 16
                #    mutations are parked inside Phase 2!
                idle_in_tx = int(
                    h.sql(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE datname = current_database() AND state = 'idle in transaction'"
                    ).strip()
                )
                self.assertEqual(
                    idle_in_tx,
                    0,
                    "workspace mutations held open PostgreSQL transactions across Git execution",
                )

                # 2. Bystander DB + filesystem reads succeed promptly despite all
                #    16 Git slots (== deadpool max_size(16)) being parked!
                t0 = time.monotonic()
                for _ in range(5):
                    info = json.loads(
                        h.expect(f"/api/workspaces/{bystander['id']}", 200, token=h.alice)
                    )
                    self.assertEqual(info["revision"], 1)
                    file_resp = json.loads(
                        h.expect(
                            f"/api/workspaces/{bystander['id']}/files?path=hello.txt",
                            200,
                            token=h.alice,
                        )
                    )
                    self.assertEqual(
                        base64.b64decode(file_resp["content_base64"]),
                        b"payload-16\n",
                    )
                self.assertLess(time.monotonic() - t0, 2.5, "bystander reads stalled under Git saturation")

                # 3. 17th concurrent Git mutation fails fast with 503 Service Unavailable.
                status_17, raw_17, _ = stage_one(16)
                self.assertEqual(status_17, 503, raw_17)

                # Release all 16 parked `git add` invocations.
                pause_flag.unlink()
                for idx, fut in enumerate(futures):
                    st, raw, _ = fut.result(timeout=15)
                    self.assertEqual(st, 200, f"worker {idx} failed: {raw}")
                    body = json.loads(raw)
                    self.assertEqual(body["workspace_revision"], 2)
                    self.assertEqual(body["git_generation"], 1)

            # Once capacity is released, the 17th workspace succeeds cleanly too.
            st_17, raw_17, _ = stage_one(16)
            self.assertEqual(st_17, 200, raw_17)

            # 4. Client disconnect mid-flight still finishes owned job cleanly
            #    and replays on Idempotency-Key retry without spurious capture!
            for marker in entered_dir.iterdir():
                marker.unlink()
            put_disconnect = {
                "content_base64": base64.b64encode(b"disconnect-safe\n").decode(),
                "expected_entry_version": 1,
                "expected_workspace_revision": 2,
                "lease_epoch": 1,
            }
            h.expect(
                f"/api/workspaces/{bystander['id']}/files?path=hello.txt",
                200,
                token=h.alice,
                method="PUT",
                body=put_disconnect,
                extra_headers={"Idempotency-Key": "disconnect-prep-put"},
            )
            pause_flag.write_text("hold-disconnect\n")
            parsed = urllib.parse.urlparse(h.base)
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
            disconnect_body = json.dumps(
                {
                    "action": "add",
                    "paths": ["hello.txt"],
                    "expected_git_generation": 1,
                    "expected_workspace_revision": 3,
                    "lease_epoch": 1,
                }
            ).encode()
            conn.request(
                "POST",
                f"/api/workspaces/{bystander['id']}/git",
                body=disconnect_body,
                headers={
                    "Authorization": f"Bearer {h.alice['token']}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": "disconnect-git-key",
                },
            )
            deadline = time.monotonic() + 8.0
            while not list(entered_dir.iterdir()):
                self.assertLess(time.monotonic(), deadline, "disconnect git add never entered gate")
                time.sleep(0.02)
            # Abruptly close the client TCP socket before reading any response!
            conn.close()
            pause_flag.unlink()

            # Retry with the identical Idempotency-Key: must replay the committed 200 OK result!
            deadline = time.monotonic() + 8.0
            replayed = None
            while time.monotonic() < deadline:
                st, raw, _ = h.http(
                    f"/api/workspaces/{bystander['id']}/git",
                    token=h.alice,
                    method="POST",
                    body=json.loads(disconnect_body.decode()),
                    extra_headers={"Idempotency-Key": "disconnect-git-key"},
                )
                if st == 200:
                    replayed = json.loads(raw)
                    break
                time.sleep(0.05)
            self.assertIsNotNone(replayed, "disconnected owned git job did not replay 200 OK")
            self.assertEqual(replayed["workspace_revision"], 4)
            self.assertEqual(replayed["git_generation"], 2)

            repo_dir = h.root / "data/workspace-service/workspaces" / bystander["id"]
            self.assertFalse((repo_dir / ".git/index.lock").exists())

            # Wait over one capture cycle to verify no spurious external_capture
            # event was emitted after the API mutations recorded their baselines.
            time.sleep(1.5)
            events = json.loads(
                h.expect(f"/api/workspaces/{bystander['id']}/events?after_revision=0", 200, token=h.alice)
            )["events"]
            self.assertEqual([e["kind"] for e in events], ["file_put", "git", "file_put", "git"])
        finally:
            h.cleanup()

    @unittest.skipUnless(os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"), "live S3 fixture required")
    def test_cross_volume_lease_takeover_from_remote_checkpoint_without_db_lock_retention(self):
        h = Harness(
            argparse.Namespace(
                binary="target/debug/rootyard",
                keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1",
            )
        )
        try:
            h.setup()
            h.api()
            h.roundtrip()
            ws = json.loads(
                h.expect(
                    "/api/workspaces",
                    201,
                    token=h.alice,
                    method="POST",
                    body={
                        "owner": "alice",
                        "repository": "demo",
                        "agent_id": "cross-vol",
                        "base_oid": h.second,
                    },
                    extra_headers={"Idempotency-Key": "cross-vol-create"},
                )
            )
            wid = ws["id"]
            payload = b"cross-volume takeover payload\n"
            h.expect(
                f"/api/workspaces/{wid}/files?path=hello.txt",
                200,
                token=h.alice,
                method="PUT",
                body={
                    "content_base64": base64.b64encode(payload).decode(),
                    "expected_entry_version": 0,
                    "expected_workspace_revision": 0,
                    "lease_epoch": 1,
                },
                extra_headers={"Idempotency-Key": "cross-vol-put"},
            )
            h.expect(
                f"/api/workspaces/{wid}/git",
                200,
                token=h.alice,
                method="POST",
                body={
                    "action": "add",
                    "paths": ["hello.txt"],
                    "expected_git_generation": 0,
                    "expected_workspace_revision": 1,
                    "lease_epoch": 1,
                },
                extra_headers={"Idempotency-Key": "cross-vol-add"},
            )
            cp = json.loads(
                h.expect(
                    f"/api/workspaces/{wid}/checkpoints",
                    201,
                    token=h.alice,
                    method="POST",
                    body={"expected_workspace_revision": 2, "lease_epoch": 1},
                    extra_headers={"Idempotency-Key": "cross-vol-cp"},
                )
            )
            pub = json.loads(
                h.expect(
                    f"/api/checkpoints/{cp['checkpoint_id']}/publish",
                    200,
                    token=h.alice,
                    method="POST",
                )
            )
            self.assertEqual(pub["state"], "COMMITTED")

            # Destroy volume 1 completely and start server on fresh volume 2.
            h.stop(hard=True)
            shutil.rmtree(h.root / "data")
            h.env["ROOTYARD_DATA_DIR"] = str(h.root / "volume-two")
            h.start()

            # Unexpired foreign lease must fail with 409; non-member must get 404.
            self.assertEqual(
                h.http(
                    f"/api/workspaces/{wid}/lease",
                    token=h.alice,
                    method="POST",
                    body={"expected_lease_epoch": 1},
                )[0],
                409,
            )
            h.sql(f"UPDATE workspaces SET lease_until = clock_timestamp() - interval '1 second' WHERE id = '{wid}'")
            self.assertEqual(
                h.http(
                    f"/api/workspaces/{wid}/lease",
                    token=h.bob,
                    method="POST",
                    body={"expected_lease_epoch": 1},
                )[0],
                404,
            )

            taken = json.loads(
                h.expect(
                    f"/api/workspaces/{wid}/lease",
                    200,
                    token=h.alice,
                    method="POST",
                    body={"expected_lease_epoch": 1},
                )
            )
            self.assertEqual(taken["lease_epoch"], 2)
            for view in ("working", "index"):
                got = json.loads(
                    h.expect(
                        f"/api/workspaces/{wid}/files?path=hello.txt&view={view}",
                        200,
                        token=h.alice,
                    )
                )
                self.assertEqual(base64.b64decode(got["content_base64"]), payload)
        finally:
            h.cleanup()


if __name__ == "__main__":
    unittest.main()
