#!/usr/bin/env python3
"""Regression tests for Git LFS split-transaction races, re-authorization, and repair deduplication.

Covers Issue #79 R3 invariants:
1. Concurrent `pending -> ready` transition during `batch_upload` on a cold node
   hydrates/verifies via `ensure_readable` and deduplicates (`actions: None`)
   without clobbering the committed `'ready'` row back to `'pending'`, rejects
   same-size corrupt local/remote bytes, and fails closed with `409 Conflict`
   after 3 passes of continuous `ready -> new ready` churn.
2. Token revocation, role downgrade, collaborator removal, or repository
   `recovering` transition while `ensure_readable` is in flight fails closed
   (`401`/`403`/`404`/`409`) across `batch_download`, `batch_upload` dedup,
   `verify_object`, and `PUT` upload dedup without scheduling remote repairs.
3. Duplicate OIDs in `batch_upload` deduplicate `(oid, size)` before calling
   `schedule_remote_repair` so `MAX_CONCURRENT_REPAIRS = 2` is not exhausted.
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
from lfs import LFS_MIME, LfsHarness  # noqa: E402


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class GatedCountingS3:
    """Loopback S3-compatible fixture with per-OID GET gating and HEAD hooks."""

    def __init__(self):
        self.lock = threading.Lock()
        self.objects = {}
        self.op_counts = Counter()
        self.gated_get_oid = None
        self.get_entered = threading.Event()
        self.get_release = threading.Event()
        self.head_hook = None
        self.head_delay_s = 0.0
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_HEAD(self): self._handle()
            def do_GET(self): self._handle()
            def do_PUT(self): self._handle()
            def do_DELETE(self): self._handle()

            def _reply(self, code, payload=b""):
                self.send_response_only(code)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                if payload and self.command != "HEAD":
                    self.wfile.write(payload)

            def _handle(self):
                key = self.path.split("?", 1)[0].lstrip("/").split("/", 1)[-1]
                oid = key.rsplit("/", 1)[-1]
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""

                hook = None
                delay = 0.0
                gate = False
                with fixture.lock:
                    fixture.op_counts[(self.command, oid)] += 1
                    if self.command == "HEAD":
                        hook = fixture.head_hook
                        delay = fixture.head_delay_s
                    elif self.command == "GET" and fixture.gated_get_oid == oid:
                        fixture.gated_get_oid = None
                        gate = True

                if hook is not None:
                    hook(oid)
                if delay > 0:
                    time.sleep(delay)
                if gate:
                    fixture.get_entered.set()
                    if not fixture.get_release.wait(timeout=30):
                        return self._reply(504)

                if self.command == "PUT":
                    with fixture.lock:
                        fixture.objects[key] = body
                    self._reply(200)
                elif self.command in ("HEAD", "GET"):
                    with fixture.lock:
                        stored = fixture.objects.get(key)
                    self._reply(404) if stored is None else self._reply(200, stored)
                elif self.command == "DELETE":
                    with fixture.lock:
                        fixture.objects.pop(key, None)
                    self._reply(204)
                else:
                    self._reply(405)

        self.server = _Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self.thread.start()

    def stop(self):
        self.get_release.set()
        self.server.shutdown()
        self.server.server_close()

    def arm_get_gate(self, oid):
        with self.lock:
            self.gated_get_oid = oid
            self.get_entered.clear()
            self.get_release.clear()

    def key_for(self, tenant_id, oid):
        return f"tenants/{tenant_id}/lfs/{oid}"

    def put_raw(self, tenant_id, oid, data):
        with self.lock:
            self.objects[self.key_for(tenant_id, oid)] = bytes(data)

    def delete_raw(self, tenant_id, oid):
        with self.lock:
            self.objects.pop(self.key_for(tenant_id, oid), None)

    def get_raw(self, tenant_id, oid):
        with self.lock:
            return self.objects.get(self.key_for(tenant_id, oid))

    def snapshot_oid(self, oid):
        with self.lock:
            return {m: self.op_counts[(m, oid)] for m in ("HEAD", "GET", "PUT")}

    def delta_oid(self, oid, before):
        after = self.snapshot_oid(oid)
        return {m: after[m] - before[m] for m in ("HEAD", "GET", "PUT")}


class SplitTxRacesHarness(LfsHarness):
    def _final(self, oid):
        return Path(self.env["ROOTYARD_DATA_DIR"]) / "lfs" / self.repo["id"] / oid

    def _tenant_id(self):
        return self.sql(f"SELECT owner_id::text FROM repositories WHERE id='{self.repo['id']}'")

    def _upload_ready_object(self, payload):
        oid, size = hashlib.sha256(payload).hexdigest(), len(payload)
        actions = self.lfs_batch("upload", [{"oid": oid, "size": size}], token=self.alice)["objects"][0]["actions"]
        self.lfs_put(actions["upload"]["href"], payload, token=self.alice, code=200)
        self.lfs_verify(actions["verify"]["href"], oid, size, token=self.alice, code=200)
        return oid, size

    def _raw_batch(self, operation, objects, token):
        payload = {"operation": operation, "transfers": ["basic"], "objects": objects, "hash_algo": "sha256"}
        status, body, _ = self.http(
            "/git/alice/demo.git/info/lfs/objects/batch", token=token, method="POST",
            body=json.dumps(payload).encode(), content_type=LFS_MIME, extra_headers={"Accept": LFS_MIME},
        )
        return status, body

    def _raw_verify(self, oid, size, token):
        status, body, _ = self.http(
            "/git/alice/demo.git/info/lfs/verify", token=token, method="POST",
            body=json.dumps({"oid": oid, "size": size}).encode(),
            content_type=LFS_MIME, extra_headers={"Accept": LFS_MIME},
        )
        return status, body

    def _raw_put(self, oid, size, payload, token):
        status, body, _ = self.http(
            f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}", token=token,
            method="PUT", body=payload, content_type="application/octet-stream",
        )
        return status, body

    def _gated_batch_upload(self, fixture, oid_gate, size_gate, oid_second, size_second, on_gated):
        if self._final(oid_gate).exists():
            self._final(oid_gate).unlink()
        fixture.arm_get_gate(oid_gate)
        out, objs = {}, [{"oid": oid_gate, "size": size_gate}, {"oid": oid_second, "size": size_second}]
        worker = threading.Thread(target=lambda: out.setdefault("resp", self._raw_batch("upload", objs, self.alice)), daemon=True)
        worker.start()
        assert fixture.get_entered.wait(timeout=15), "Phase 2 never entered S3 GET gate"
        meta = on_gated()
        fixture.get_release.set()
        worker.join(timeout=30)
        assert not worker.is_alive()
        return out["resp"], meta

    def run_all_split_tx_checks(self):
        fixture = GatedCountingS3()
        fixture.start()
        self.env.update({
            "ROOTYARD_OBJECT_STORE_ENDPOINT": fixture.endpoint,
            "ROOTYARD_OBJECT_STORE_BUCKET": "rootyard-lfs-r3",
            "ROOTYARD_OBJECT_STORE_REGION": "us-east-1",
            "ROOTYARD_OBJECT_STORE_ACCESS_KEY": "test-access",
            "ROOTYARD_OBJECT_STORE_SECRET_KEY": "test-secret",
        })
        try:
            self.setup_lfs()
            tenant_id = self._tenant_id()
            repo_id = self.repo["id"]
            oid_gate, size_gate = self._upload_ready_object(os.urandom(32 * 1024))

            # 1a. Cold concurrent `pending -> ready`: hydrates/verifies & deduplicates without clobbering.
            cold_payload = os.urandom(32 * 1024)
            oid_cold, size_cold = hashlib.sha256(cold_payload).hexdigest(), len(cold_payload)
            assert "upload" in self.lfs_batch(
                "upload", [{"oid": oid_cold, "size": size_cold}], token=self.alice
            )["objects"][0]["actions"]

            def promote_cold_valid():
                fixture.put_raw(tenant_id, oid_cold, cold_payload)
                self.sql(
                    f"UPDATE lfs_objects SET state='ready', updated_at=clock_timestamp() + interval '5 milliseconds' "
                    f"WHERE repository_id='{repo_id}' AND oid='{oid_cold}'"
                )
                return self.sql(
                    f"SELECT updated_at::text FROM lfs_objects WHERE repository_id='{repo_id}' AND oid='{oid_cold}'"
                )

            (status, body), ready_ts = self._gated_batch_upload(
                fixture, oid_gate, size_gate, oid_cold, size_cold, promote_cold_valid
            )
            assert status == 200, (status, body)
            parsed = json.loads(body)
            assert all("actions" not in obj for obj in parsed["objects"]), parsed
            actual_row = self.sql(
                f"SELECT state || '|' || updated_at::text FROM lfs_objects "
                f"WHERE repository_id='{repo_id}' AND oid='{oid_cold}'"
            )
            assert actual_row == f"ready|{ready_ts}", (actual_row, ready_ts)
            cold_file = self._final(oid_cold)
            assert cold_file.is_file() and stat.S_IMODE(cold_file.stat().st_mode) == 0o600
            assert cold_file.read_bytes() == cold_payload

            # 1b. Same-size corrupt local bytes on concurrent `pending -> ready`: rejected from dedup.
            corrupt_good = os.urandom(32 * 1024)
            oid_corrupt, size_corrupt = hashlib.sha256(corrupt_good).hexdigest(), len(corrupt_good)
            self.lfs_batch("upload", [{"oid": oid_corrupt, "size": size_corrupt}], token=self.alice)
            corrupt_path = self._final(oid_corrupt)

            def promote_corrupt_local():
                bad = bytearray(corrupt_good)
                bad[0] ^= 0xFF
                corrupt_path.write_bytes(bad)
                os.chmod(corrupt_path, 0o600)
                self.sql(
                    f"UPDATE lfs_objects SET state='ready', updated_at=clock_timestamp() + interval '5 milliseconds' "
                    f"WHERE repository_id='{repo_id}' AND oid='{oid_corrupt}'"
                )

            (status, body), _ = self._gated_batch_upload(
                fixture, oid_gate, size_gate, oid_corrupt, size_corrupt, promote_corrupt_local
            )
            assert status == 200, (status, body)
            parsed = json.loads(body)
            assert "actions" not in parsed["objects"][0]
            assert "upload" in parsed["objects"][1].get("actions", {}), parsed["objects"][1]
            assert self.sql(
                f"SELECT state FROM lfs_objects WHERE repository_id='{repo_id}' AND oid='{oid_corrupt}'"
            ) == "pending"
            if corrupt_path.exists():
                corrupt_path.unlink()

            # 1c. Same-size corrupt remote bytes on concurrent `pending -> ready`: fail closed.
            bad_rem_good = os.urandom(32 * 1024)
            oid_bad_rem, size_bad_rem = hashlib.sha256(bad_rem_good).hexdigest(), len(bad_rem_good)
            self.lfs_batch("upload", [{"oid": oid_bad_rem, "size": size_bad_rem}], token=self.alice)

            def promote_corrupt_remote():
                bad = bytearray(bad_rem_good)
                bad[7] ^= 0xFF
                fixture.put_raw(tenant_id, oid_bad_rem, bad)
                self.sql(
                    f"UPDATE lfs_objects SET state='ready', updated_at=clock_timestamp() + interval '5 milliseconds' "
                    f"WHERE repository_id='{repo_id}' AND oid='{oid_bad_rem}'"
                )

            (status, _), _ = self._gated_batch_upload(
                fixture, oid_gate, size_gate, oid_bad_rem, size_bad_rem, promote_corrupt_remote
            )
            assert status in (500, 503), status
            assert not self._final(oid_bad_rem).exists()
            fixture.delete_raw(tenant_id, oid_bad_rem)

            # 1d. Continuous `ready -> new ready` churn across 3 passes -> 409 Conflict.
            oid_churn, size_churn = "a1" * 32, 4096
            self.sql(
                f"INSERT INTO lfs_objects (tenant_id, repository_id, oid, size, state) "
                f"VALUES ('{tenant_id}', '{repo_id}', '{oid_churn}', {size_churn}, 'ready')"
            )
            churn_bumps = {"n": 0}

            def bump_on_head(target_oid):
                if target_oid == oid_churn:
                    churn_bumps["n"] += 1
                    ms = churn_bumps["n"] * 10
                    self.sql(
                        f"UPDATE lfs_objects SET state='ready', updated_at=clock_timestamp() + interval '{ms} milliseconds' "
                        f"WHERE repository_id='{repo_id}' AND oid='{oid_churn}'"
                    )

            fixture.head_hook = bump_on_head
            try:
                status, _ = self._raw_batch("upload", [{"oid": oid_churn, "size": size_churn}], self.alice)
                assert status == 409 and churn_bumps["n"] == 3, (status, churn_bumps)
                assert self.sql(
                    f"SELECT state FROM lfs_objects WHERE repository_id='{repo_id}' AND oid='{oid_churn}'"
                ) == "ready"
            finally:
                fixture.head_hook = None

            # 2. Post-`ensure_readable` DB re-authorization across all 4 split-TX paths.
            reauth_payload = os.urandom(32 * 1024)
            oid_reauth, size_reauth = self._upload_ready_object(reauth_payload)

            def run_inflight(req_fn, mutate_fn, cleanup_fn=None):
                if self._final(oid_reauth).exists():
                    self._final(oid_reauth).unlink()
                fixture.arm_get_gate(oid_reauth)
                holder = {}
                t = threading.Thread(target=lambda: holder.setdefault("res", req_fn()), daemon=True)
                t.start()
                assert fixture.get_entered.wait(timeout=15), "request never entered cold ensure_readable"
                mutate_fn()
                before_rel = fixture.snapshot_oid(oid_reauth)
                fixture.get_release.set()
                t.join(timeout=30)
                assert not t.is_alive()
                time.sleep(0.12)
                delta = fixture.delta_oid(oid_reauth, before_rel)
                if cleanup_fn:
                    cleanup_fn()
                return holder["res"][0], delta

            def set_collab(role):
                self.expect("/api/repos/alice/demo/collaborators/bob", (200, 201),
                            token=self.alice, method="PUT", body={"role": role})

            def del_collab():
                self.expect("/api/repos/alice/demo/collaborators/bob", 200, token=self.alice, method="DELETE")

            def set_repo_state(st):
                self.sql(f"UPDATE repositories SET state='{st}' WHERE id='{repo_id}'")

            # 2a. batch_download (read role): revoked -> 401, collaborator removed -> 404, recovering -> 409
            dl_obj = [{"oid": oid_reauth, "size": size_reauth}]
            tok = self.account("create-token", "alice", "--read-only")
            code, _ = run_inflight(
                lambda: self._raw_batch("download", dl_obj, tok),
                lambda: self.sql(f"UPDATE tokens SET revoked=true WHERE id='{tok['token_id']}'"),
            )
            assert code == 401, code
            set_collab("read")
            code, _ = run_inflight(lambda: self._raw_batch("download", dl_obj, self.bob), del_collab)
            assert code == 404, code
            code, _ = run_inflight(
                lambda: self._raw_batch("download", dl_obj, self.reader),
                lambda: set_repo_state("recovering"),
                lambda: set_repo_state("ready"),
            )
            assert code == 409, code

            # 2b–2d. Write split-TX endpoints: batch_upload dedup, verify_object, PUT upload dedup
            write_endpoints = [
                ("batch_upload_dedup", lambda t: self._raw_batch("upload", dl_obj, t), True),
                ("verify_object", lambda t: self._raw_verify(oid_reauth, size_reauth, t), False),
                ("put_upload_dedup", lambda t: self._raw_put(oid_reauth, size_reauth, reauth_payload, t), True),
            ]
            for label, call_with_tok, check_no_repair in write_endpoints:
                tok = self.account("create-token", "alice")
                code, delta = run_inflight(
                    lambda fn=call_with_tok, tk=tok: fn(tk),
                    lambda tk=tok: self.sql(f"UPDATE tokens SET revoked=true WHERE id='{tk['token_id']}'"),
                )
                assert code == 401, (label, code)
                if check_no_repair:
                    assert delta["HEAD"] == 0 and delta["PUT"] == 0, (label, delta)

                set_collab("write")
                code, delta = run_inflight(
                    lambda fn=call_with_tok: fn(self.bob),
                    lambda: set_collab("read"),
                    del_collab,
                )
                assert code == 403, (label, code)
                if check_no_repair:
                    assert delta["HEAD"] == 0 and delta["PUT"] == 0, (label, delta)

                code, delta = run_inflight(
                    lambda fn=call_with_tok: fn(self.alice),
                    lambda: set_repo_state("recovering"),
                    lambda: set_repo_state("ready"),
                )
                assert code == 409, (label, code)
                if check_no_repair:
                    assert delta["HEAD"] == 0 and delta["PUT"] == 0, (label, delta)

            # 3. Duplicate OIDs in `batch_upload` deduplicate `schedule_remote_repair`.
            rep_p1, rep_p2 = os.urandom(16 * 1024), os.urandom(16 * 1024)
            oid_r1, sz_r1 = self._upload_ready_object(rep_p1)
            oid_r2, sz_r2 = self._upload_ready_object(rep_p2)
            fixture.delete_raw(tenant_id, oid_r1)
            fixture.delete_raw(tenant_id, oid_r2)
            before_r1, before_r2 = fixture.snapshot_oid(oid_r1), fixture.snapshot_oid(oid_r2)
            fixture.head_delay_s = 0.15
            try:
                dup_specs = [{"oid": oid_r1, "size": sz_r1}] * 4 + [{"oid": oid_r2, "size": sz_r2}]
                dup_resp = self.lfs_batch("upload", dup_specs, token=self.alice)
                assert all("actions" not in item for item in dup_resp["objects"]), dup_resp
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    d1, d2 = fixture.delta_oid(oid_r1, before_r1), fixture.delta_oid(oid_r2, before_r2)
                    if d1["GET"] >= 1 and d2["GET"] >= 1:
                        break
                    time.sleep(0.05)
                assert fixture.get_raw(tenant_id, oid_r1) == rep_p1
                assert fixture.get_raw(tenant_id, oid_r2) == rep_p2
                d1, d2 = fixture.delta_oid(oid_r1, before_r1), fixture.delta_oid(oid_r2, before_r2)
                assert d1 == {"HEAD": 2, "GET": 1, "PUT": 1}, d1
                assert d2 == {"HEAD": 2, "GET": 1, "PUT": 1}, d2
            finally:
                fixture.head_delay_s = 0.0

            return {
                "cold_concurrent_ready_dedup": True,
                "corrupt_local_and_remote_rejected": True,
                "three_pass_conflict_bound_verified": True,
                "post_ensure_readable_reauth_paths": [
                    "batch_download",
                    "batch_upload_dedup",
                    "verify_object",
                    "put_upload_dedup",
                ],
                "duplicate_oid_repair_deduplicated": {"oid1": d1, "oid2": d2},
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
    harness = SplitTxRacesHarness(args)
    passed = False
    try:
        harness.case("split_tx_races_reauth_and_repair_dedup", harness.run_all_split_tx_checks)
        passed = True
    except Exception:
        print(harness.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        harness.cleanup()
        report = {
            "passed": passed,
            "cases": harness.results,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
