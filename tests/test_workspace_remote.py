"""Native S3 checkpoint publication and second-volume recovery regression."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import unittest

from tests.e2e import Harness


@unittest.skipUnless(os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"),"live S3 test requires Garage or MinIO")
class WorkspaceRemoteTest(unittest.TestCase):
    def test_abandoned_upload_collects_staged_s3_key(self):
        h=Harness(argparse.Namespace(binary="target/debug/rootyard",keep=False))
        try:
            h.setup();h.api();h.roundtrip()
            ws=json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                body={"owner":"alice","repository":"demo","agent_id":"orphan-a","base_oid":h.second},
                extra_headers={"Idempotency-Key":"orphan-create"}))
            retained=json.loads(h.expect(f"/api/workspaces/{ws['id']}/checkpoints",201,
                token=h.alice,method="POST",body={"expected_workspace_revision":0,"lease_epoch":1},
                extra_headers={"Idempotency-Key":"retained-cp"}))
            retained_id=retained["checkpoint_id"]
            self.assertEqual(json.loads(h.expect(f"/api/checkpoints/{retained_id}/publish",200,
                token=h.alice,method="POST"))["state"],"COMMITTED")
            cp=json.loads(h.expect(f"/api/workspaces/{ws['id']}/checkpoints",201,
                token=h.alice,method="POST",body={"expected_workspace_revision":1,"lease_epoch":1},
                extra_headers={"Idempotency-Key":"orphan-cp"}))
            cid=cp["checkpoint_id"]
            h.stop()
            h.env["ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_OBJECTS"]="1"
            h.start()
            try: h.http(f"/api/checkpoints/{cid}/publish",token=h.alice,method="POST")
            except Exception: pass
            self.assertEqual(h.proc.wait(timeout=10),77)
            self.assertNotEqual(h.sql(f"SELECT COUNT(*) FROM workspace_remote_staging_objects WHERE checkpoint_id='{cid}'"),"0")
            h.stop()
            h.env.pop("ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_OBJECTS")
            h.start()
            self.assertEqual(h.http(f"/api/checkpoints/{cid}/abandon",token=h.bob,method="POST")[0],404)
            abandoned=json.loads(h.expect(f"/api/checkpoints/{cid}/abandon",200,token=h.alice,method="POST"))
            self.assertEqual(abandoned["state"],"failed")
            self.assertGreaterEqual(abandoned["objects_collected"],0)
            self.assertEqual(h.sql(f"SELECT COUNT(*) FROM workspace_remote_staging_objects WHERE checkpoint_id='{cid}'"),"0")
            shutil.rmtree(h.root/"data/workspace-service/checkpoints"/retained_id)
            recovered=json.loads(h.expect(f"/api/checkpoints/{retained_id}/restore",201,
                token=h.alice,method="POST",body={"agent_id":"retained-restore"}))
            content=json.loads(h.expect(f"/api/workspaces/{recovered['id']}/files?path=hello.txt",
                200,token=h.alice))
            self.assertEqual(base64.b64decode(content["content_base64"]),b"second\n")
            self.assertEqual(h.http(f"/api/checkpoints/{cid}/publish",token=h.alice,method="POST")[0],409)
            replay=json.loads(h.expect(f"/api/checkpoints/{cid}/abandon",200,token=h.alice,method="POST"))
            self.assertEqual(replay["objects_collected"],0)
        finally:h.cleanup()

    def test_commit_retry_and_restore_without_source_volume(self):
        h=Harness(argparse.Namespace(binary="target/debug/rootyard",keep=False))
        try:
            h.setup();h.api();h.roundtrip()
            ws=json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                body={"owner":"alice","repository":"demo","agent_id":"remote-a","base_oid":h.second},
                extra_headers={"Idempotency-Key":"remote-create"}))
            wid=ws["id"]
            path=f"/api/workspaces/{wid}/files?path=hello.txt"
            value=b"remote dirty file\n"
            h.expect(path,200,token=h.alice,method="PUT",body={"content_base64":base64.b64encode(value).decode(),
                "expected_entry_version":0,"expected_workspace_revision":0,"lease_epoch":1},extra_headers={"Idempotency-Key":"dirty"})
            cp=json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,method="POST",
                body={"expected_workspace_revision":1,"lease_epoch":1},extra_headers={"Idempotency-Key":"cp"}))
            cid=cp["checkpoint_id"]
            self.assertEqual(cp["state"],"local_complete")
            self.assertEqual(h.http(f"/api/checkpoints/{cid}/publish",token=h.bob,method="POST")[0],404)
            h.stop()
            h.env["ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_OBJECTS"]="1"
            h.start()
            try: h.http(f"/api/checkpoints/{cid}/publish",token=h.alice,method="POST")
            except Exception: pass
            self.assertEqual(h.proc.wait(timeout=10),77)
            self.assertEqual(h.sql(f"SELECT state FROM workspace_checkpoints WHERE id='{cid}'"),"local_complete")
            self.assertNotEqual(h.sql(f"SELECT COUNT(*) FROM workspace_remote_staging_objects WHERE checkpoint_id='{cid}'"),"0")
            h.stop()
            h.env.pop("ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_OBJECTS")
            h.start()
            committed=json.loads(h.expect(f"/api/checkpoints/{cid}/publish",200,token=h.alice,method="POST"))
            self.assertEqual(committed["state"],"COMMITTED")
            replay=json.loads(h.expect(f"/api/checkpoints/{cid}/publish",200,token=h.alice,method="POST"))
            self.assertEqual(replay["manifest_sha256"],committed["manifest_sha256"])
            self.assertEqual(h.sql(f"SELECT COUNT(*) FROM workspace_checkpoints WHERE id='{cid}'"),"1")
            current=json.loads(h.expect(f"/api/workspaces/{wid}",200,token=h.alice))
            cp2=json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,method="POST",
                body={"expected_workspace_revision":current["revision"],"lease_epoch":1},
                extra_headers={"Idempotency-Key":"cp-after-commit"}))
            cid2=cp2["checkpoint_id"]
            h.stop()
            h.env["ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_COMMIT"]="1"
            h.start()
            try: h.http(f"/api/checkpoints/{cid2}/publish",token=h.alice,method="POST")
            except Exception: pass
            self.assertEqual(h.proc.wait(timeout=10),78)
            self.assertEqual(h.sql(f"SELECT state FROM workspace_checkpoints WHERE id='{cid2}'"),"committed")
            h.stop()
            h.env.pop("ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_COMMIT")
            h.start()
            second=json.loads(h.expect(f"/api/checkpoints/{cid2}/publish",200,token=h.alice,method="POST"))
            self.assertEqual(second["state"],"COMMITTED")
            self.assertEqual(h.sql(f"SELECT COUNT(*) FROM workspace_checkpoints WHERE id='{cid2}'"),"1")
            h.stop(hard=True)
            source=h.root/"data"
            shutil.rmtree(source)
            h.env["ROOTYARD_DATA_DIR"]=str(h.root/"second-data")
            h.start()
            restored=json.loads(h.expect(f"/api/checkpoints/{cid}/restore",201,token=h.alice,method="POST",body={"agent_id":"remote-b"}))
            contents=json.loads(h.expect(f"/api/workspaces/{restored['id']}/files?path=hello.txt",200,token=h.alice))
            self.assertEqual(base64.b64decode(contents["content_base64"]),value)
            native=Path(h.env["ROOTYARD_DATA_DIR"])/"workspace-service/workspaces"/restored["id"]
            self.assertEqual(h.git("status","--porcelain",cwd=native).returncode,0)
            self.assertFalse(source.exists())
        finally:h.cleanup()


if __name__=="__main__":unittest.main()
