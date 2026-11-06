"""Native API, bubblewrap and checkpoint integration over a real FUSE mount."""
import argparse
import base64
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from tests.e2e import Harness


class WorkspaceFuseServiceTest(unittest.TestCase):
    def test_live_editor_capture_checkpoint_and_remount(self):
        binary=Path("target/debug/rootyard").resolve()
        self.assertTrue(binary.is_file())
        with tempfile.TemporaryDirectory(prefix="rootyard-userns-wrapper-") as wrapper_dir:
            wrapper=Path(wrapper_dir)/"rootyard-userns"
            wrapper.write_text(f"#!/bin/sh\nexec unshare -Urm {binary} \"$@\"\n")
            wrapper.chmod(0o700)
            h=Harness(argparse.Namespace(binary=str(wrapper),keep=False))
            try:
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"]="fuse"
                h.env["ROOTYARD_SANDBOX_MODE"]="dev"
                h.setup();h.api();h.roundtrip()
                ws=json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                    body={"owner":"alice","repository":"demo","agent_id":"live-fuse","base_oid":h.second},
                    extra_headers={"Idempotency-Key":"live-fuse-create"}))
                wid=ws["id"]
                lower=h.root/"data/workspace-service/workspaces"/wid
                upper=h.root/"data/workspace-service/uppers"/wid
                self.assertEqual((lower/"hello.txt").read_bytes(),b"second\n")
                before=json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt",200,token=h.alice))
                self.assertEqual(base64.b64decode(before["content_base64"]),b"second\n")
                job=json.loads(h.expect(f"/api/workspaces/{wid}/sandbox-jobs",201,token=h.alice,
                    method="POST",body={"argv":["/bin/sh","-c",
                        "printf 'normal editor save\n' > hello.tmp; mv hello.tmp hello.txt; git add hello.txt"],
                        "timeout_seconds":15,"lease_epoch":1,"workspace_access":"live"}))
                deadline=time.monotonic()+20
                while time.monotonic()<deadline:
                    result=json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}",200,token=h.alice))
                    if result["state"] not in ("queued","running"):break
                    time.sleep(.1)
                self.assertEqual(result["state"],"succeeded")
                self.assertEqual((lower/"hello.txt").read_bytes(),b"second\n")
                self.assertEqual((upper/"hello.txt").read_bytes(),b"normal editor save\n")
                visible=json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt",200,token=h.alice))
                self.assertEqual(base64.b64decode(visible["content_base64"]),b"normal editor save\n")
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    current=json.loads(h.expect(f"/api/workspaces/{wid}",200,token=h.alice))
                    if current["revision"]>0:break
                    time.sleep(.2)
                self.assertGreater(current["revision"],0)
                event=json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0",200,token=h.alice))
                self.assertIn("external_capture",[e["kind"] for e in event["events"]])
                checkpoint=json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,
                    method="POST",body={"expected_workspace_revision":current["revision"],"lease_epoch":1},
                    extra_headers={"Idempotency-Key":"live-fuse-checkpoint"}))
                self.assertEqual(checkpoint["state"],"local_complete")
                cid=checkpoint["checkpoint_id"]
                self.assertEqual((h.root/"data/workspace-service/checkpoints"/cid/"hello.txt").read_bytes(),
                    b"normal editor save\n")
                late=json.loads(h.expect(f"/api/workspaces/{wid}/sandbox-jobs",201,token=h.alice,
                    method="POST",body={"argv":["/bin/sh","-c","sleep 4; printf stale > blocked.txt"],
                        "timeout_seconds":10,"lease_epoch":1,"workspace_access":"live"}))
                self.assertEqual(h.http(f"/api/workspaces/{wid}/lease",token=h.alice,
                    method="POST",body={"expected_lease_epoch":1})[0],409)
                h.sql(f"UPDATE workspaces SET lease_epoch=lease_epoch+1, "
                    f"lease_until=clock_timestamp()-interval '1 second' WHERE id='{wid}'")
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    late_state=json.loads(h.expect(f"/api/sandbox-jobs/{late['id']}",200,token=h.alice))
                    if late_state["state"] not in ("queued","running"):break
                    time.sleep(.1)
                self.assertEqual(late_state["state"],"cancelled")
                self.assertFalse((upper/"blocked.txt").exists())
                h.stop(hard=True)
                h.start()
                after=json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt",200,token=h.alice))
                self.assertEqual(base64.b64decode(after["content_base64"]),b"normal editor save\n")
                self.assertEqual((lower/"hello.txt").read_bytes(),b"second\n")
            finally:h.cleanup()


if __name__=="__main__":unittest.main()
