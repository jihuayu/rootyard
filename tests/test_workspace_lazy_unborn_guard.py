"""FUSE lazy materialization provenance and typed-unborn regressions.

The fixture is opt-in and requires a disposable Linux host with real PostgreSQL
17, Garage/S3 and ``/dev/fuse``. It drives the ordinary restore and lease
takeover entry points, not internal helpers:

* a committed checkpoint is restored cold after the local data directory is
  removed, then taken over cold and taken over again through the already-ready
  cached lower;
* an already-ready committed cache is taken over while the configured object
  store endpoint is unreachable, proving that a provably valid ready lower does
  not acquire a new global S3 requirement;
* a manifest whose captured revision no longer binds to the checkpoint row is
  refused before a workspace row, lower or sidecar is published;
* a frozen manifest whose real ``.git/HEAD`` is genuinely unborn is refused on
  a fresh cold restore and on an already-ready warm takeover, with no workspace,
  lease, lower or sidecar change.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
import unittest
import uuid

from tests.e2e import Harness
from tests.runtime_binary import select_runtime_binary
from tests.test_workspace_fuse_service import MOUNT_MODE


def _dir_entries(path):
    return sorted(item.name for item in path.iterdir()) if path.is_dir() else []


def _snapshot(harness):
    data = Path(harness.env["ROOTYARD_DATA_DIR"])
    return {
        "workspaces": _dir_entries(data / "workspace-service/workspaces"),
        "lazy": _dir_entries(data / "workspace-service/lazy"),
        "rows": harness.sql("SELECT count(*) FROM workspaces"),
        "checkpoints": harness.sql("SELECT count(*) FROM workspace_checkpoints"),
    }


def _create_workspace(harness, agent, key, base_oid):
    return json.loads(
        harness.expect(
            "/api/workspaces",
            201,
            token=harness.alice,
            method="POST",
            body={"owner": "alice", "repository": "demo", "agent_id": agent, "base_oid": base_oid},
            extra_headers={"Idempotency-Key": key},
        )
    )


def _checkpoint_and_publish(harness, workspace, expected_revision, key):
    checkpoint = json.loads(
        harness.expect(
            f"/api/workspaces/{workspace['id']}/checkpoints",
            201,
            token=harness.alice,
            method="POST",
            body={"expected_workspace_revision": expected_revision, "lease_epoch": workspace["lease_epoch"]},
            extra_headers={"Idempotency-Key": key},
        )
    )
    published = json.loads(
        harness.expect(
            f"/api/checkpoints/{checkpoint['checkpoint_id']}/publish",
            200,
            token=harness.alice,
            method="POST",
        )
    )
    assert published["state"] == "COMMITTED", published
    return checkpoint


def _s3_client():
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=os.environ["ROOTYARD_OBJECT_STORE_ENDPOINT"],
        region_name=os.environ["ROOTYARD_OBJECT_STORE_REGION"],
        aws_access_key_id=os.environ["ROOTYARD_OBJECT_STORE_ACCESS_KEY"],
        aws_secret_access_key=os.environ["ROOTYARD_OBJECT_STORE_SECRET_KEY"],
        config=Config(s3={"addressing_style": "path"}),
    )


def _checkpoint_manifest(harness, client, checkpoint_id):
    tenant = harness.sql(
        "SELECT r.owner_id FROM workspace_checkpoints c JOIN repositories r ON r.id=c.repository_id "
        f"WHERE c.id='{checkpoint_id}'"
    )
    digest = harness.sql(f"SELECT manifest_digest FROM workspace_checkpoints WHERE id='{checkpoint_id}'")
    key = f"tenants/{tenant}/workspace/{digest}"
    body = client.get_object(Bucket=os.environ["ROOTYARD_OBJECT_STORE_BUCKET"], Key=key)["Body"].read()
    return tenant, key, json.loads(body)


def _put_workspace_object(client, tenant, body):
    digest = hashlib.sha256(body).hexdigest()
    client.put_object(
        Bucket=os.environ["ROOTYARD_OBJECT_STORE_BUCKET"], Key=f"tenants/{tenant}/workspace/{digest}", Body=body
    )
    return digest


def _tamper_manifest_unborn(harness, client, checkpoint_id):
    tenant, _old_key, manifest = _checkpoint_manifest(harness, client, checkpoint_id)
    entries = []
    for entry in manifest["entries"]:
        path = base64.b64decode(entry["path_base64"])
        if path == b".git/HEAD":
            raw = b"ref: refs/heads/unborn-guard\n"
            _put_workspace_object(client, tenant, raw)
            entry = dict(entry, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        elif path.startswith(b".git/refs/") or path == b".git/packed-refs":
            continue
        entries.append(entry)
    manifest["entries"] = entries
    raw = json.dumps(manifest, separators=(",", ":")).encode()
    digest = _put_workspace_object(client, tenant, raw)
    harness.sql(
        "UPDATE workspace_checkpoints SET manifest_digest='%s', manifest_size=%d WHERE id='%s'"
        % (digest, len(raw), checkpoint_id)
    )


class WorkspaceLazyUnbornGuardTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"), "live S3 fixture required")
    @unittest.skipUnless(
        sys.platform.startswith("linux") and Path("/dev/fuse").exists(), "Linux /dev/fuse fixture required"
    )
    def test_restore_and_takeover_guard_fresh_and_ready_fuse_materialization(self):
        binary, _ = select_runtime_binary()
        with tempfile.TemporaryDirectory(prefix="rootyard-lazy-guard-wrapper-") as wrapper_dir:
            wrapper = Path(wrapper_dir) / "rootyard-userns"
            wrapper.write_text(f"#!/bin/sh\nexec unshare -Urm {shlex.quote(str(binary))} \"$@\"\n")
            wrapper.chmod(0o700)
            h = Harness(argparse.Namespace(binary=str(wrapper), keep=False))
            try:
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = MOUNT_MODE
                h.setup()
                h.api()
                h.roundtrip()
                client = _s3_client()

                valid_ws = _create_workspace(h, "lazy-valid", "lazy-valid-create", h.second)
                valid_cp = _checkpoint_and_publish(h, valid_ws, valid_ws["revision"], "lazy-valid-cp")
                valid_id = valid_cp["checkpoint_id"]

                invalid_ws = _create_workspace(h, "lazy-invalid", "lazy-invalid-create", h.second)
                invalid_cp = _checkpoint_and_publish(h, invalid_ws, invalid_ws["revision"], "lazy-invalid-cp")
                invalid_id = invalid_cp["checkpoint_id"]
                invalid_revision = int(
                    h.sql(f"SELECT captured_revision FROM workspace_checkpoints WHERE id='{invalid_id}'")
                )
                h.sql(
                    "UPDATE workspace_checkpoints SET captured_revision=%d WHERE id='%s'"
                    % (invalid_revision + 1, invalid_id)
                )

                unborn_cp = _checkpoint_and_publish(h, invalid_ws, 1, "lazy-unborn-cp")
                unborn_id = unborn_cp["checkpoint_id"]
                _tamper_manifest_unborn(h, client, unborn_id)

                # Force a genuinely cold restore/takeover: only PostgreSQL and
                # the remote object store survive.
                h.stop(hard=True)
                source = Path(h.env["ROOTYARD_DATA_DIR"])
                shutil.rmtree(source)
                h.env["ROOTYARD_DATA_DIR"] = str(h.root / "second-data")
                h.start()

                restored = json.loads(
                    h.expect(
                        f"/api/checkpoints/{valid_id}/restore",
                        201,
                        token=h.alice,
                        method="POST",
                        body={"agent_id": "lazy-valid-restore"},
                        extra_headers={"Idempotency-Key": "lazy-valid-restore"},
                    )
                )
                data = Path(h.env["ROOTYARD_DATA_DIR"])
                restored_lower = data / "workspace-service/workspaces" / restored["id"]
                restored_sidecar = data / "workspace-service/lazy" / (restored["id"] + ".json")
                self.assertTrue((restored_lower / ".git").is_dir())
                self.assertTrue(restored_sidecar.is_file())
                restored_file = json.loads(
                    h.expect(f"/api/workspaces/{restored['id']}/files?path=hello.txt", 200, token=h.alice)
                )
                self.assertEqual(base64.b64decode(restored_file["content_base64"]), b"second\n")
                self.assertEqual(
                    h.git("symbolic-ref", "-q", "HEAD", cwd=restored_lower).stdout.strip(), b"refs/heads/main"
                )

                before_rejections = _snapshot(h)
                status, body, _ = h.http(
                    f"/api/checkpoints/{invalid_id}/restore",
                    token=h.alice,
                    method="POST",
                    body={"agent_id": "lazy-invalid-restore"},
                    extra_headers={"Idempotency-Key": "lazy-invalid-restore"},
                )
                self.assertEqual(status, 400, body)
                self.assertEqual(
                    h.sql("SELECT count(*) FROM workspaces WHERE agent_id='lazy-invalid-restore'"), "0"
                )
                self.assertEqual(_snapshot(h), before_rejections)

                status, body, _ = h.http(
                    f"/api/checkpoints/{unborn_id}/restore",
                    token=h.alice,
                    method="POST",
                    body={"agent_id": "lazy-unborn-restore"},
                    extra_headers={"Idempotency-Key": "lazy-unborn-restore"},
                )
                self.assertEqual(status, 409, body)
                self.assertIn(b"HEAD", body)
                self.assertEqual(h.sql("SELECT count(*) FROM workspaces WHERE agent_id='lazy-unborn-restore'"), "0")
                self.assertEqual(_snapshot(h), before_rejections)

                # Cold takeover of the original committed workspace through the
                # same lazy preparation that restore uses.
                valid_wid = valid_ws["id"]
                stale_host = str(uuid.uuid4())
                h.sql(
                    "UPDATE workspaces SET host_id='%s', lease_until=clock_timestamp()-interval '1 second' "
                    "WHERE id='%s'" % (stale_host, valid_wid)
                )
                attached = json.loads(
                    h.expect(
                        f"/api/workspaces/{valid_wid}/lease",
                        200,
                        token=h.alice,
                        method="POST",
                        body={"expected_lease_epoch": valid_ws["lease_epoch"]},
                    )
                )
                self.assertEqual(attached["lease_epoch"], valid_ws["lease_epoch"] + 1)
                takeover_lower = data / "workspace-service/workspaces" / valid_wid
                takeover_sidecar = data / "workspace-service/lazy" / (valid_wid + ".json")
                self.assertTrue((takeover_lower / ".git").is_dir())
                sidecar_bytes = takeover_sidecar.read_bytes()
                head_mtime = (takeover_lower / ".git/HEAD").stat().st_mtime_ns

                # The already-ready cache must be accepted without contacting S3.
                h.stop()
                h.env["ROOTYARD_OBJECT_STORE_ENDPOINT"] = "http://127.0.0.1:1"
                h.sql(
                    "UPDATE workspaces SET host_id='%s', lease_until=clock_timestamp()-interval '1 second' "
                    "WHERE id='%s'" % (stale_host, valid_wid)
                )
                h.start()
                warm = json.loads(
                    h.expect(
                        f"/api/workspaces/{valid_wid}/lease",
                        200,
                        token=h.alice,
                        method="POST",
                        body={"expected_lease_epoch": attached["lease_epoch"]},
                    )
                )
                self.assertEqual(warm["lease_epoch"], attached["lease_epoch"] + 1)
                self.assertEqual(takeover_sidecar.read_bytes(), sidecar_bytes)
                self.assertEqual((takeover_lower / ".git/HEAD").stat().st_mtime_ns, head_mtime)

                # A preexisting ready lower that is genuinely unborn must fail
                # closed on the warm path with no row, lease, lower or sidecar
                # change.
                h.stop()
                (takeover_lower / ".git/HEAD").write_text("ref: refs/heads/unborn-guard\n")
                ref = takeover_lower / ".git/refs/heads/main"
                if ref.exists():
                    ref.unlink()
                h.sql(
                    "UPDATE workspaces SET host_id='%s', lease_until=clock_timestamp()-interval '1 second' "
                    "WHERE id='%s'" % (stale_host, valid_wid)
                )
                before_warm_reject = h.sql(
                    "SELECT host_id || '|' || lease_epoch FROM workspaces WHERE id='%s'" % valid_wid
                )
                h.start()
                status, body, _ = h.http(
                    f"/api/workspaces/{valid_wid}/lease",
                    token=h.alice,
                    method="POST",
                    body={"expected_lease_epoch": warm["lease_epoch"]},
                )
                self.assertEqual(status, 409, body)
                self.assertIn(b"HEAD", body)
                self.assertEqual(
                    h.sql("SELECT host_id || '|' || lease_epoch FROM workspaces WHERE id='%s'" % valid_wid),
                    before_warm_reject,
                )
                self.assertEqual(takeover_sidecar.read_bytes(), sidecar_bytes)
                self.assertEqual((takeover_lower / ".git/HEAD").read_text(), "ref: refs/heads/unborn-guard\n")
            finally:
                h.cleanup()


if __name__ == "__main__":
    unittest.main()
