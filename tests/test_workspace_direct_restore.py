"""Direct checkpoint restore with the production server and an owned loopback S3 fixture."""

import base64
import hashlib
import json
import unittest
from urllib.request import Request, urlopen

from tests.workspace_runtime_bulkhead_support import create_ws, new_harness, put_hello


class WorkspaceDirectRestoreTest(unittest.TestCase):
    def test_committed_restore_requires_remote_bytes_with_local_cache_present(self):
        h = new_harness()
        self.addCleanup(h.cleanup)
        h.use_loopback_s3()
        h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = "direct"
        h.setup()
        h.api()
        h.roundtrip()
        workspace = create_ws(h, "direct-remote", "create-direct-remote")
        wid = workspace["id"]
        authoritative = b"authoritative remote checkpoint bytes\n"
        put_hello(h, wid, authoritative, 0, 0, "direct-remote-put")
        checkpoint = json.loads(
            h.expect(
                f"/api/workspaces/{wid}/checkpoints",
                201,
                token=h.alice,
                method="POST",
                body={"expected_workspace_revision": 1, "lease_epoch": 1},
                extra_headers={"Idempotency-Key": "direct-remote-checkpoint"},
            )
        )
        cp = checkpoint["checkpoint_id"]
        cached = h.root / "data" / "workspace-service" / "checkpoints" / cp / "hello.txt"
        self.assertEqual(cached.read_bytes(), authoritative)

        def restore(key):
            return h.http(
                f"/api/checkpoints/{cp}/restore",
                token=h.alice,
                method="POST",
                body={"agent_id": "direct-remote-restored"},
                extra_headers={"Idempotency-Key": key},
            )

        def restored_bytes(body):
            new_id = json.loads(body)["id"]
            result = json.loads(h.expect(f"/api/workspaces/{new_id}/files?path=hello.txt", 200, token=h.alice))
            return base64.b64decode(result["content_base64"])

        self.assertEqual(checkpoint["state"], "local_complete")
        status, body, _ = restore("legacy-local-restore")
        self.assertEqual(status, 201, body)
        self.assertEqual(restored_bytes(body), authoritative)

        published = json.loads(h.expect(f"/api/checkpoints/{cp}/publish", 200, token=h.alice, method="POST"))
        self.assertEqual(published["state"], "COMMITTED")
        stale_local = b"untrusted local checkpoint cache\n"
        cached.write_bytes(stale_local)
        tenant = h.sql(f"SELECT owner_id FROM repositories WHERE id = '{h.repo['id']}'")
        store = h.env["ROOTYARD_OBJECT_STORE_ENDPOINT"] + "/" + h.env["ROOTYARD_OBJECT_STORE_BUCKET"]
        copies = f"SELECT count(*) FROM workspaces WHERE parent_checkpoint_id = '{cp}'"
        baseline = h.sql(copies)
        staging = h.root / "data" / "workspace-service" / "staging"
        for digest in (published["manifest_sha256"], hashlib.sha256(authoritative).hexdigest()):
            url = f"{store}/tenants/{tenant}/workspace/{digest}"
            with urlopen(url, timeout=5) as response:
                original = response.read()
            self.assertEqual(hashlib.sha256(original).hexdigest(), digest)
            with urlopen(Request(url, method="DELETE"), timeout=5) as response:
                self.assertEqual(response.status, 204)
            try:
                status, body, _ = restore("committed-remote-restore")
                self.assertEqual(status, 409, (digest, body))
                self.assertEqual(json.loads(body)["error"], "remote checkpoint incomplete")
                self.assertEqual(h.sql(copies), baseline)
                self.assertEqual(cached.read_bytes(), stale_local)
                self.assertFalse(any(staging.glob(f"restore-{cp}-*")))
            finally:
                with urlopen(Request(url, method="PUT", data=original), timeout=5) as response:
                    self.assertEqual(response.status, 200)

        status, body, _ = restore("committed-remote-restore")
        self.assertEqual(status, 201, body)
        self.assertEqual(restored_bytes(body), authoritative)
        self.assertEqual(cached.read_bytes(), stale_local)


if __name__ == "__main__":
    unittest.main()
