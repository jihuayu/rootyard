"""Committed-checkpoint workspace takeover onto a second volume and FUSE mount."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from tests.e2e import Harness


@unittest.skipUnless(os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"),"live S3 fixture required")
class WorkspaceHandoffTest(unittest.TestCase):
    def test_expired_host_reattach_from_remote_checkpoint(self):
        binary=Path("target/debug/rootyard").resolve()
        with tempfile.TemporaryDirectory(prefix="rootyard-handoff-wrapper-") as wrapper_dir:
            wrapper=Path(wrapper_dir)/"rootyard-userns"
            wrapper.write_text(f"#!/bin/sh\nexec unshare -Urm {binary} \"$@\"\n")
            wrapper.chmod(0o700)
            h=Harness(argparse.Namespace(binary=str(wrapper),keep=False))
            try:
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"]="fuse"
                h.setup();h.api();h.roundtrip()
                ws=json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                    body={"owner":"alice","repository":"demo","agent_id":"handoff","base_oid":h.second},
                    extra_headers={"Idempotency-Key":"handoff-create"}))
                wid=ws["id"]
                path=f"/api/workspaces/{wid}/files?path=hello.txt"
                changed=b"durable across hosts\n"
                h.expect(path,200,token=h.alice,method="PUT",body={
                    "content_base64":base64.b64encode(changed).decode(),"expected_entry_version":0,
                    "expected_workspace_revision":0,"lease_epoch":1},
                    extra_headers={"Idempotency-Key":"handoff-edit"})
                cp=json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,
                    method="POST",body={"expected_workspace_revision":1,"lease_epoch":1},
                    extra_headers={"Idempotency-Key":"handoff-checkpoint"}))
                self.assertEqual(json.loads(h.expect(f"/api/checkpoints/{cp['checkpoint_id']}/publish",
                    200,token=h.alice,method="POST"))["state"],"COMMITTED")
                h.stop(hard=True)
                source=h.root/"data"
                shutil.rmtree(source)
                h.env["ROOTYARD_DATA_DIR"]=str(h.root/"second-volume")
                h.start()
                self.assertEqual(h.http(f"/api/workspaces/{wid}/lease",token=h.alice,
                    method="POST",body={"expected_lease_epoch":1})[0],409)
                h.sql(f"UPDATE workspaces SET lease_until=clock_timestamp()-interval '1 second' WHERE id='{wid}'")
                self.assertEqual(h.http(f"/api/workspaces/{wid}/lease",token=h.bob,
                    method="POST",body={"expected_lease_epoch":1})[0],404)
                attached=json.loads(h.expect(f"/api/workspaces/{wid}/lease",200,token=h.alice,
                    method="POST",body={"expected_lease_epoch":1}))
                self.assertEqual(attached["lease_epoch"],2)
                self.assertEqual(base64.b64decode(json.loads(h.expect(path,200,token=h.alice))["content_base64"]),changed)
                lower=Path(h.env["ROOTYARD_DATA_DIR"])/"workspace-service/workspaces"/wid
                self.assertEqual((lower/"hello.txt").read_bytes(),changed)
                self.assertFalse(source.exists())
                stale={"content_base64":base64.b64encode(b"stale").decode(),
                    "expected_entry_version":1,"expected_workspace_revision":2,"lease_epoch":1}
                self.assertEqual(h.http(path,token=h.alice,method="PUT",body=stale,
                    extra_headers={"Idempotency-Key":"stale-handoff"})[0],409)
            finally:h.cleanup()


if __name__=="__main__":unittest.main()
