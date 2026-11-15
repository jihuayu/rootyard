#!/usr/bin/env python3
"""Workspace remote-delete policy: safe default versus explicit legacy opt-in.

The native case owns a disposable PostgreSQL schema and a loopback counting
proxy in front of the real Garage endpoint. It publishes one committed
checkpoint, then writes a single unique random file (``!orphan.bin``) through the
real workspace files API and creates a second checkpoint. That second
publication is killed after one real object upload (exit 77). Because the first
checkpoint already uploaded every shared object, the only new upload is the
unique orphan, so the failed checkpoint must genuinely own a staged digest that
the retained checkpoint does not reference.

Under the default policy, abandoning that checkpoint must:

* mark the SQL checkpoint ``failed`` and return ``objects_collected == 0``;
* report pending remote cleanup instead of pretending the object was reclaimed;
* retain every failed-checkpoint staging row (the retryable key reference);
* issue zero S3 DELETE requests even though a real failed object exists;
* have performed a real S3 PUT for the failed publication (PUT delta > 0);
* expose the unique orphan digest in failed staging and not in retained staging,
  where the digest equals SHA-256 of the bytes written through the files API;
* leave that unique orphan readable by a real SigV4 S3 GET after abandon (a
  failed checkpoint cannot be restored, so the bytes are fetched directly and
  only the digest is reported); and
* leave the committed checkpoint's exact bytes readable by restore; and
* keep replay idempotent without losing either the rows or the key.

This is deliberately **not** a PITR proof. A PostgreSQL clone/PITR rollback can
rewind workspace roots while the shared bucket keeps or loses objects; the
external delete broker with its own epoch and isolated PUT credentials is not
implemented here. The full PITR broker is unimplemented, and the legacy
``ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE=true`` path is exercised only by the
isolated synthetic fixture in ``test_workspace_remote.py``.

The proxy forwards requests unchanged and records only method counts. It never
logs headers, URLs, tokens or payloads, and neither does the direct S3 read.
"""
import argparse
import base64
from datetime import datetime, timezone
import errno
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time
import traceback
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness  # noqa: E402
import fuse_helper_native_support as support  # noqa: E402
from lfs_hydration_concurrency import S3ControlProxy  # noqa: E402
from workspace_capture_acceptance import (  # noqa: E402
    install_capture_read_gate, wait_capture_gate,
)

UNSAFE_ENV = "ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE"
KILL_ENV = "ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_OBJECTS"
ORPHAN_NAME = "!orphan.bin"
PENDING_FUSE_MODE = "fuse-helper"
REQUIRED_CASES = (
    "invalid_optin_rejected_at_startup",
    "default_retains_failed_remote_cleanup",
    "exit77_with_pending_fuse_request",
)


def _hmac_sha256(key, message):
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def s3_get_bytes(host, port, bucket, key, region, access_key, secret_key,
                 session_token=None, timeout=30):
    """Minimal SigV4 GET mirroring the native ``ObjectKey``/``S3Store`` signer.

    Payloads use ``UNSIGNED-PAYLOAD`` exactly like the Rust client. The caller
    must never print the key, headers, credentials or response body; only the
    returned bytes (whose SHA-256 is safe to report) leave this helper.
    """
    now = datetime.now(timezone.utc)
    date, timestamp = now.strftime("%Y%m%d"), now.strftime("%Y%m%dT%H%M%SZ")
    host_header = "[" + host + "]" if ":" in host else host
    if port:
        host_header += ":" + str(port)
    path = "/" + bucket + "/" + key
    headers = [
        ("host", host_header),
        ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ("x-amz-date", timestamp),
    ]
    if session_token:
        headers.append(("x-amz-security-token", session_token))
    headers.sort(key=lambda item: item[0])
    canonical_headers = "".join(f"{name}:{value.strip()}\n" for name, value in headers)
    signed_headers = ";".join(name for name, _ in headers)
    canonical = "\n".join(["GET", path, "", canonical_headers, signed_headers,
                           "UNSIGNED-PAYLOAD"])
    scope = f"{date}/{region}/s3/aws4_request"
    string_to_sign = "AWS4-HMAC-SHA256\n{}\n{}\n{}".format(
        timestamp, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest())
    k_date = _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, "s3")
    k_signing = _hmac_sha256(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"),
                         hashlib.sha256).hexdigest()
    authorization = (
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}"
        .format(access_key, scope, signed_headers, signature))
    request_headers = {"Authorization": authorization}
    for name, value in headers:
        request_headers[name] = value
    connection = http.client.HTTPConnection(host, port or 80, timeout=timeout)
    try:
        connection.request("GET", path, headers=request_headers)
        response = connection.getresponse()
        status, body = response.status, response.read()
    finally:
        connection.close()
    assert status == 200, f"S3 GET of the retained orphan returned HTTP {status}"
    return body


class CountingProxy(S3ControlProxy):
    """The shared pass-through proxy plus an all-method request counter."""

    def __init__(self, target_host, target_port):
        super().__init__(target_host, target_port)
        self.method_counts = {}

    def serve(self, handler):
        with self.lock:
            self.method_counts[handler.command] = self.method_counts.get(handler.command, 0) + 1
        return super().serve(handler)


class PolicyHarness(Harness):
    def case_invalid_optin(self):
        # This case needs no database connection: strict startup parsing must
        # fail before storage or serving begins.
        h = Harness(self.args)
        try:
            h.env[UNSAFE_ENV] = "yes"
            result = h.run([h.args.binary, "serve"], check=False)
            assert result.returncode != 0, "invalid unsafe opt-in was accepted"
            assert b"ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE must be true or false" in result.stderr, (
                result.stderr.decode(errors="replace")[-500:]
            )
            return {"invalid_value": "yes", "startup_rejected": True,
                    "safe_default_not_assumed": True}
        finally:
            h.cleanup()

    def case_default_retains(self):
        endpoint = os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT")
        assert endpoint, "real S3/Garage fixture environment is required"
        parsed = urllib.parse.urlsplit(endpoint)
        assert parsed.scheme == "http", "loopback Garage endpoint must be plain HTTP"
        assert parsed.hostname in ("127.0.0.1", "::1", "localhost"), "loopback Garage required"
        assert not parsed.path and not parsed.query
        assert not parsed.username and not parsed.password
        backend_port = parsed.port or 80
        with socket.create_connection((parsed.hostname, backend_port), timeout=5):
            pass
        proxy = CountingProxy(parsed.hostname, backend_port)
        proxy.start()
        self.env["ROOTYARD_OBJECT_STORE_ENDPOINT"] = f"http://127.0.0.1:{proxy.port}"
        # The safe default is the absence of an opt-in, not a per-request guess.
        self.env.pop(UNSAFE_ENV, None)
        try:
            return self._default_retains(proxy)
        finally:
            proxy.release_gated()
            proxy.stop()

    def _default_retains(self, proxy):
        self.setup()
        self.api()
        self.roundtrip()
        ws = json.loads(self.expect("/api/workspaces", 201, token=self.alice, method="POST",
            body={"owner": "alice", "repository": "demo", "agent_id": "policy-a",
                  "base_oid": self.second},
            extra_headers={"Idempotency-Key": "policy-create"}))
        retained = json.loads(self.expect(f"/api/workspaces/{ws['id']}/checkpoints", 201,
            token=self.alice, method="POST",
            body={"expected_workspace_revision": 0, "lease_epoch": 1},
            extra_headers={"Idempotency-Key": "policy-retained"}))
        retained_id = retained["checkpoint_id"]
        assert json.loads(self.expect(f"/api/checkpoints/{retained_id}/publish", 200,
            token=self.alice, method="POST"))["state"] == "COMMITTED"

        # Make the second checkpoint genuinely different: write one unique random
        # file through the real files API. Its name sorts first so the kill-after-
        # one-upload window captures this object rather than a shared one.
        orphan_bytes = os.urandom(48)
        orphan_sha = hashlib.sha256(orphan_bytes).hexdigest()
        current = json.loads(self.expect(f"/api/workspaces/{ws['id']}", 200, token=self.alice))
        self.expect(f"/api/workspaces/{ws['id']}/files?path={urllib.parse.quote(ORPHAN_NAME, safe='')}",
            200, token=self.alice, method="PUT",
            body={"content_base64": base64.b64encode(orphan_bytes).decode(),
                  "expected_entry_version": 0,
                  "expected_workspace_revision": current["revision"],
                  "lease_epoch": 1},
            extra_headers={"Idempotency-Key": "policy-orphan"})
        after_write = json.loads(self.expect(f"/api/workspaces/{ws['id']}", 200, token=self.alice))
        failed = json.loads(self.expect(f"/api/workspaces/{ws['id']}/checkpoints", 201,
            token=self.alice, method="POST",
            body={"expected_workspace_revision": after_write["revision"], "lease_epoch": 1},
            extra_headers={"Idempotency-Key": "policy-failed"}))
        failed_id = failed["checkpoint_id"]
        self.stop()
        puts_before = proxy.method_counts.get("PUT", 0)
        self.env[KILL_ENV] = "1"
        self.start()
        try:
            self.http(f"/api/checkpoints/{failed_id}/publish", token=self.alice, method="POST")
        except Exception:
            pass
        assert self.proc.wait(timeout=10) == 77, "publication did not fail after a real object upload"
        put_delta = proxy.method_counts.get("PUT", 0) - puts_before
        assert put_delta > 0, "failed publication issued no real S3 PUT"
        self.stop()
        self.env.pop(KILL_ENV, None)
        self.start()

        rows_before = int(self.sql(
            f"SELECT COUNT(*) FROM workspace_remote_staging_objects WHERE checkpoint_id='{failed_id}'"))
        pending_before = int(self.sql(
            "SELECT COUNT(*) FROM (SELECT DISTINCT tenant_id,digest FROM workspace_remote_staging_objects "
            f"WHERE checkpoint_id='{failed_id}') pending"))
        assert rows_before > 0, "the failed real upload left no staging reference"
        assert pending_before > 0

        # The retained checkpoint must not reference the orphan; the failed one
        # must, and its digest must be the SHA-256 of the bytes we just wrote.
        assert orphan_sha == hashlib.sha256(orphan_bytes).hexdigest()
        retained_has = self.sql(
            "SELECT COUNT(*) FROM workspace_remote_staging_objects "
            f"WHERE checkpoint_id='{retained_id}' AND digest='{orphan_sha}'")
        assert retained_has == "0", "the first retained checkpoint already referenced the unique orphan"
        new_digests = set(self.sql(
            "SELECT digest FROM ("
            " SELECT DISTINCT tenant_id,digest FROM workspace_remote_staging_objects "
            f" WHERE checkpoint_id='{failed_id}'"
            " EXCEPT"
            " SELECT DISTINCT tenant_id,digest FROM workspace_remote_staging_objects "
            f" WHERE checkpoint_id='{retained_id}') failed_only").split())
        assert orphan_sha in new_digests, (
            "failed staging has no digest unique to the uploaded orphan", sorted(new_digests))
        tenant = self.sql(
            "SELECT tenant_id FROM workspace_remote_staging_objects "
            f"WHERE checkpoint_id='{failed_id}' AND digest='{orphan_sha}'")
        assert tenant, "unique orphan digest is not staged for the failed checkpoint"

        deletes_before = proxy.method_counts.get("DELETE", 0)
        abandoned = json.loads(self.expect(f"/api/checkpoints/{failed_id}/abandon", 200,
            token=self.alice, method="POST"))
        assert abandoned["state"] == "failed"
        assert abandoned["objects_collected"] == 0
        assert abandoned["cleanup_pending"] is True
        assert abandoned["cleanup_pending_objects"] == pending_before
        assert proxy.method_counts.get("DELETE", 0) == deletes_before, "default policy issued an S3 DELETE"

        rows_after = int(self.sql(
            f"SELECT COUNT(*) FROM workspace_remote_staging_objects WHERE checkpoint_id='{failed_id}'"))
        assert rows_after == rows_before, "default policy discarded retryable staging rows"

        replay = json.loads(self.expect(f"/api/checkpoints/{failed_id}/abandon", 200,
            token=self.alice, method="POST"))
        assert replay["objects_collected"] == 0
        assert replay["cleanup_pending"] is True
        assert int(self.sql(
            f"SELECT COUNT(*) FROM workspace_remote_staging_objects WHERE checkpoint_id='{failed_id}'")) == rows_before
        assert self.http(f"/api/checkpoints/{failed_id}/publish", token=self.alice, method="POST")[0] == 409

        # A failed checkpoint cannot be restored, so prove the orphan bytes are
        # really in the bucket with a direct SigV4 GET of the unique key. Only
        # the digest is reported; the key and credentials are never printed.
        bucket = self.env.get("ROOTYARD_OBJECT_STORE_BUCKET")
        region = self.env.get("ROOTYARD_OBJECT_STORE_REGION")
        access_key = self.env.get("ROOTYARD_OBJECT_STORE_ACCESS_KEY")
        secret_key = self.env.get("ROOTYARD_OBJECT_STORE_SECRET_KEY")
        assert bucket and region and access_key and secret_key, (
            "real object-store credentials are required for the post-abandon GET")
        backend = urllib.parse.urlsplit(os.environ["ROOTYARD_OBJECT_STORE_ENDPOINT"])
        fetched = s3_get_bytes(backend.hostname, backend.port or 80, bucket,
                               f"tenants/{tenant}/workspace/{orphan_sha}", region,
                               access_key, secret_key,
                               self.env.get("ROOTYARD_OBJECT_STORE_SESSION_TOKEN"))
        orphan_fetch_sha = hashlib.sha256(fetched).hexdigest()
        assert fetched == orphan_bytes, "real S3 GET of the unique failed orphan returned different bytes"
        assert orphan_fetch_sha == orphan_sha

        # The committed checkpoint shares the failed upload's shared keys; remove
        # its local copy so restore must read those exact bytes from Garage.
        local_retained = Path(self.env["ROOTYARD_DATA_DIR"]) / "workspace-service/checkpoints" / retained_id
        import shutil
        shutil.rmtree(local_retained)
        recovered = json.loads(self.expect(f"/api/checkpoints/{retained_id}/restore", 201,
            token=self.alice, method="POST", body={"agent_id": "policy-restore"}))
        content = json.loads(self.expect(f"/api/workspaces/{recovered['id']}/files?path=hello.txt",
            200, token=self.alice))
        restored = base64.b64decode(content["content_base64"])
        assert restored == b"second\n", restored

        assert not proxy.errors, proxy.errors
        return {
            "legacy_unsafe_optin": False,
            "failed_publication_exit": 77,
            "failed_publish_put_delta": put_delta,
            "unique_orphan_digest": orphan_sha,
            "unique_orphan_only_in_failed_staging": True,
            "unique_orphan_s3_get_sha256": orphan_fetch_sha,
            "unique_orphan_bytes_recovered": True,
            "staging_rows_retained": rows_after,
            "cleanup_pending": abandoned["cleanup_pending"],
            "cleanup_pending_objects": abandoned["cleanup_pending_objects"],
            "objects_collected": abandoned["objects_collected"],
            "s3_delete_requests_during_abandon": proxy.method_counts.get("DELETE", 0) - deletes_before,
            "active_checkpoint_restore_sha256": hashlib.sha256(restored).hexdigest(),
            "replay_preserved_keys": True,
            "pitr_proof": False,
            "limitations": [
                "Loopback, single-host PostgreSQL/Garage fixture only.",
                "No external delete broker, epoch, or isolated PUT credentials are tested.",
                "The full PITR delete broker is unimplemented and not exercised here.",
                "A raw PG clone/PITR rollback against the shared bucket remains unsupported and undetected.",
            ],
        }


    def case_exit77_with_pending_fuse_request(self):
        endpoint = os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT")
        assert endpoint, "real S3/Garage fixture environment is required"
        parsed = urllib.parse.urlsplit(endpoint)
        assert parsed.scheme == "http", "loopback Garage endpoint must be plain HTTP"
        assert parsed.hostname in ("127.0.0.1", "::1", "localhost"), "loopback Garage required"
        assert not parsed.path and not parsed.query
        assert not parsed.username and not parsed.password
        backend_port = parsed.port or 80
        with socket.create_connection((parsed.hostname, backend_port), timeout=5):
            pass
        proxy = CountingProxy(parsed.hostname, backend_port)
        proxy.start()
        harness = PolicyHarness(self.args)
        harness.env["ROOTYARD_OBJECT_STORE_ENDPOINT"] = f"http://127.0.0.1:{proxy.port}"
        harness.env.pop(UNSAFE_ENV, None)
        harness.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = PENDING_FUSE_MODE
        try:
            return harness._exit77_with_pending(proxy)
        finally:
            proxy.release_gated()
            proxy.stop()
            harness.cleanup()

    def _exit77_with_pending(self, proxy):
        self.setup()
        self.api()
        self.roundtrip()
        ws = json.loads(self.expect("/api/workspaces", 201, token=self.alice, method="POST",
            body={"owner": "alice", "repository": "demo", "agent_id": "policy-pending-fuse",
                  "base_oid": self.second},
            extra_headers={"Idempotency-Key": "policy-pending-fuse-create"}))
        wid = ws["id"]
        current = json.loads(self.expect(f"/api/workspaces/{wid}", 200, token=self.alice))
        retained = json.loads(self.expect(f"/api/workspaces/{wid}/checkpoints", 201,
            token=self.alice, method="POST",
            body={"expected_workspace_revision": current["revision"], "lease_epoch": 1},
            extra_headers={"Idempotency-Key": "policy-pending-fuse-retained"}))
        retained_id = retained["checkpoint_id"]
        assert json.loads(self.expect(f"/api/checkpoints/{retained_id}/publish", 200,
            token=self.alice, method="POST"))["state"] == "COMMITTED"

        orphan_bytes = os.urandom(48)
        orphan_sha = hashlib.sha256(orphan_bytes).hexdigest()
        current = json.loads(self.expect(f"/api/workspaces/{wid}", 200, token=self.alice))
        self.expect(
            f"/api/workspaces/{wid}/files?path={urllib.parse.quote(ORPHAN_NAME, safe='')}",
            200, token=self.alice, method="PUT",
            body={"content_base64": base64.b64encode(orphan_bytes).decode(),
                  "expected_entry_version": 0,
                  "expected_workspace_revision": current["revision"],
                  "lease_epoch": 1},
            extra_headers={"Idempotency-Key": "policy-pending-fuse-orphan"})
        after_write = json.loads(self.expect(f"/api/workspaces/{wid}", 200, token=self.alice))
        failed = json.loads(self.expect(f"/api/workspaces/{wid}/checkpoints", 201,
            token=self.alice, method="POST",
            body={"expected_workspace_revision": after_write["revision"], "lease_epoch": 1},
            extra_headers={"Idempotency-Key": "policy-pending-fuse-failed"}))
        failed_id = failed["checkpoint_id"]
        assert failed["state"] == "local_complete"
        base_events = int(self.sql(
            "SELECT count(*) FROM workspace_events "
            f"WHERE workspace_id='{wid}' AND kind='external_capture'"))
        base_revision = int(self.sql(f"SELECT revision FROM workspaces WHERE id='{wid}'"))

        self.stop()
        gate_target = (Path(self.root) / "data/workspace-service/uppers"
                       / wid / "gate-target.txt")
        gate_names = ("LD_PRELOAD", "ROOTYARD_TEST_CAPTURE_GATE",
                      "ROOTYARD_TEST_CAPTURE_TARGET")
        prior_env = {name: self.env.get(name) for name in gate_names}
        gate = None
        holder = None
        writer = None
        helper_pid = None
        helper_identity = None
        api_pidfd = helper_pidfd = writer_pidfd = None
        mount_id = None
        mountpoint = None
        try:
            gate = install_capture_read_gate(self, gate_target)
            self.env[KILL_ENV] = "1"
            self.start()
            for name, value in prior_env.items():
                if value is None:
                    self.env.pop(name, None)
                else:
                    self.env[name] = value

            api_pid = self.proc.pid
            assert os.getpgid(api_pid) == api_pid, (
                "production API is not the owned process-group leader")
            api_identity = support.process_identity(api_pid)
            assert api_identity is not None, "production API identity is unavailable"
            assert api_identity["starttime"] > 0
            api_pidfd = support.open_pidfd(api_pid)

            mountpoint = Path(self.root) / "data/workspace-service/mounts" / wid
            mount = support.wait_for_fuse_mount(api_pid, mountpoint)
            mount_id = int(mount["mount_id"])
            assert mount_id > 0
            helper_pid = support.find_api_helper_pid(api_pid)
            helper_identity = support.process_identity(helper_pid)
            assert helper_identity is not None, "FUSE helper identity is unavailable"
            assert helper_identity["pgid"] == helper_pid, (
                "FUSE helper is not in its own owned process group")
            assert helper_identity["starttime"] > api_identity["starttime"]
            helper_pidfd = support.open_pidfd(helper_pid)

            holder = support.spawn_api_namespace_holder(api_pid)
            holder_identity = support.process_identity(holder.pid)
            assert holder_identity is not None, "API namespace holder identity is unavailable"
            visible = support.wait_for_fuse_mount(holder.pid, mountpoint, timeout=5)
            assert int(visible["mount_id"]) == mount_id, (
                "holder namespace does not see the exact API mount")

            writer_script = Path(self.root) / "pending-fuse-writer.py"
            writer_script.write_text(support.PENDING_WRITER_SCRIPT, encoding="utf-8")
            writer_status = Path(self.root) / "pending-fuse-writer.json"
            writer = support.spawn_api_namespace_writer(
                api_pid, writer_script, mountpoint, writer_status)
            writer_identity = support.process_identity(writer.pid)
            assert writer_identity is not None, "pending writer identity is unavailable"
            assert writer_identity["starttime"] > 0
            writer_pidfd = support.open_pidfd(writer.pid)

            hit = gate.with_suffix(".hit")
            wait_capture_gate(hit, timeout=30)
            assert not gate.with_suffix(".timeout").exists(), (
                "capture read gate expired before observation")
            evidence = support.wait_for_kernel_wait(
                writer.pid, mountpoint, writer_status, timeout=10)
            assert not gate.with_suffix(".timeout").exists(), (
                "capture read gate expired before exit-77 publication")
            assert evidence["attempts"] == evidence["writes"] + 1

            puts_before = proxy.method_counts.get("PUT", 0)
            kill_ns = time.time_ns()
            try:
                self.http(f"/api/checkpoints/{failed_id}/publish", token=self.alice,
                          method="POST")
            except Exception:
                pass
            assert self.proc.wait(timeout=10) == 77, (
                "publication did not exit 77 after a real object upload")
            put_delta = proxy.method_counts.get("PUT", 0) - puts_before
            assert put_delta > 0, "exit-77 publication issued no real S3 PUT"

            writer_exit = support.wait_process_exit(writer, timeout=support.EXIT_DEADLINE)
            assert writer_exit == 23, (
                f"pending writer exit {writer_exit}, expected errno failure")
            status = support.writer_status(writer_status)
            assert status is not None, "pending writer wrote no safe error status"
            assert status["phase"] == "error"
            assert status["errno"] in (
                errno.EIO, errno.ENOTCONN, errno.EROFS,
                errno.ECONNABORTED, errno.ENOENT), (
                f"pending writer error {status['errno']} is not an I/O/fence error")
            assert status["success_ns"] < kill_ns, (
                "a write succeeded after the exit-77 publication")
            assert status["writes"] >= evidence["writes"], (
                "completed-byte count regressed after the parked attempt")

            assert support.wait_pid_gone(helper_pid, support.EXIT_DEADLINE), (
                "production FUSE helper did not exit after publication exit 77")
            assert support.wait_for_mount_id_gone(
                holder.pid, mountpoint, mount_id, support.EXIT_DEADLINE), (
                f"BLOCKED: {PENDING_FUSE_MODE} did not remove exact owned mount ID "
                f"{mount_id} before cleanup")
            state = self.sql(
                f"SELECT state FROM workspace_checkpoints WHERE id='{failed_id}'")
            assert state == "local_complete", (
                f"interrupted checkpoint state {state!r} was falsely confirmed")
            rows_before = int(self.sql(
                "SELECT COUNT(*) FROM workspace_remote_staging_objects "
                f"WHERE checkpoint_id='{failed_id}'"))
            pending_before = int(self.sql(
                "SELECT COUNT(*) FROM (SELECT DISTINCT tenant_id,digest "
                "FROM workspace_remote_staging_objects "
                f"WHERE checkpoint_id='{failed_id}') pending"))
            assert rows_before > 0, "the failed real upload left no staging reference"
            assert pending_before > 0
            assert int(self.sql(
                "SELECT COUNT(*) FROM workspace_remote_staging_objects "
                f"WHERE checkpoint_id='{failed_id}' AND digest='{orphan_sha}'")) > 0, (
                "failed staging omitted the uploaded unique orphan")
            assert self.sql(
                "SELECT COUNT(*) FROM workspace_remote_staging_objects "
                f"WHERE checkpoint_id='{retained_id}' AND digest='{orphan_sha}'") == "0", (
                "the first retained checkpoint already referenced the unique orphan")
            assert int(self.sql(
                "SELECT count(*) FROM workspace_events "
                f"WHERE workspace_id='{wid}' AND kind='external_capture'")) == base_events, (
                "a blocked capture was reported committed after exit 77")
            assert int(self.sql(f"SELECT revision FROM workspaces WHERE id='{wid}'")) \
                == base_revision, "workspace revision advanced after exit 77"

            support.terminate_process(holder)
            holder = None
            self.stop()
            self.env.pop(KILL_ENV, None)
            self.start()
            remount = support.wait_for_fuse_mount(self.proc.pid, mountpoint)
            assert int(remount["mount_id"]) != mount_id, (
                "restarted API reused the crashed mount ID")

            deletes_before = proxy.method_counts.get("DELETE", 0)
            abandoned = json.loads(self.expect(f"/api/checkpoints/{failed_id}/abandon", 200,
                token=self.alice, method="POST"))
            assert abandoned["state"] == "failed"
            assert abandoned["objects_collected"] == 0
            assert abandoned["cleanup_pending"] is True
            assert abandoned["cleanup_pending_objects"] == pending_before
            assert proxy.method_counts.get("DELETE", 0) == deletes_before, (
                "default policy issued an S3 DELETE during pending cleanup")
            rows_after = int(self.sql(
                "SELECT COUNT(*) FROM workspace_remote_staging_objects "
                f"WHERE checkpoint_id='{failed_id}'"))
            assert rows_after == rows_before, (
                "default policy discarded retryable staging rows")
            replay = json.loads(self.expect(f"/api/checkpoints/{failed_id}/abandon", 200,
                token=self.alice, method="POST"))
            assert replay["objects_collected"] == 0
            assert replay["cleanup_pending"] is True
            assert self.http(f"/api/checkpoints/{failed_id}/publish", token=self.alice,
                             method="POST")[0] == 409
            assert not proxy.errors, "loopback proxy recorded a forwarding error"

            return {
                "qualified_mount_mode": PENDING_FUSE_MODE,
                "api_pid": api_pid,
                "api_starttime": api_identity["starttime"],
                "helper_pid": helper_pid,
                "helper_starttime": helper_identity["starttime"],
                "holder_pid": holder_identity["pid"],
                "holder_starttime": holder_identity["starttime"],
                "writer_pid": writer_identity["pid"],
                "writer_starttime": writer_identity["starttime"],
                "owned_mount_id": mount_id,
                "failed_publication_exit": 77,
                "pending_writer_exit": writer_exit,
                "failed_publish_put_delta": put_delta,
                "pending_writer_errno": status["errno"],
                "pending_writer_completed_bytes": status["writes"],
                "pending_kernel_wait": {
                    "wchan": evidence["wchan"],
                    "fd_target": evidence["fd_target"],
                    "plateau_seconds": evidence["plateau_seconds"],
                },
                "helper_exit": True,
                "owned_mount_id_removed": True,
                "failed_checkpoint_state_before_abandon": state,
                "staging_rows_retained": rows_after,
                "cleanup_pending": abandoned["cleanup_pending"],
                "cleanup_pending_objects": abandoned["cleanup_pending_objects"],
                "objects_collected": abandoned["objects_collected"],
                "s3_delete_requests_during_abandon":
                    proxy.method_counts.get("DELETE", 0) - deletes_before,
                "retry_replay": "conflict",
                "unique_orphan_digest": orphan_sha,
                "unique_orphan_only_in_failed_staging": True,
                "pitr_proof": False,
                "limitations": [
                    "Loopback, single-host PostgreSQL/Garage fixture only.",
                    "Pending FUSE evidence requires a qualified Linux FUSE host.",
                    "The full PITR delete broker is unimplemented and not exercised here.",
                    "A raw PG clone/PITR rollback against the shared bucket remains unsupported.",
                ],
            }
        finally:
            if gate is not None:
                gate.with_suffix(".release").touch()
            for process in (writer, holder):
                try:
                    support.terminate_process(process)
                except Exception:
                    pass
            if helper_pid is not None:
                current = support.process_identity(helper_pid)
                if (helper_identity is not None and current is not None
                        and current["state"] != "Z"
                        and current["starttime"] == helper_identity["starttime"]):
                    try:
                        os.killpg(helper_pid, signal.SIGKILL)
                    except OSError:
                        pass
                    support.wait_pid_gone(helper_pid, support.EXIT_DEADLINE)
            support.close_fd(api_pidfd)
            support.close_fd(helper_pidfd)
            support.close_fd(writer_pidfd)
            self.env.pop(KILL_ENV, None)
            if prior_env:
                for name, value in prior_env.items():
                    if value is None:
                        self.env.pop(name, None)
                    else:
                        self.env[name] = value
            try:
                self.stop()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required for the native policy case")
    if not os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"):
        parser.error("a real S3/Garage fixture is required for the native policy case")
    if not Path(args.binary).is_file():
        parser.error("binary not found: " + args.binary)
    harness = PolicyHarness(args)
    passed = False
    try:
        harness.case("invalid_optin_rejected_at_startup", harness.case_invalid_optin)
        harness.case("default_retains_failed_remote_cleanup", harness.case_default_retains)
        harness.case("exit77_with_pending_fuse_request",
                     harness.case_exit77_with_pending_fuse_request)
        if tuple(case["name"] for case in harness.results) != REQUIRED_CASES:
            raise AssertionError("required case inventory mismatch")
        passed = True
    except Exception:
        print(harness.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        harness.cleanup()
        report = {
            "passed": passed,
            "cases": harness.results,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "global_legacy_optin": False,
            "pitr_safety_claimed": False,
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
