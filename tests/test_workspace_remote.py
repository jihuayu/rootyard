"""Native S3 checkpoint publication and second-volume recovery regression."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import unittest

from tests.e2e import Harness
from tests.runtime_binary import select_runtime_binary


@unittest.skipUnless(os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"),"live S3 test requires Garage or MinIO")
class WorkspaceRemoteTest(unittest.TestCase):
    def test_abandoned_upload_collects_staged_s3_key(self):
        # ISOLATED LEGACY-PATH FIXTURE: this case explicitly opts into the old
        # unsafe physical delete to verify the legacy collector only. It is NOT
        # a PITR-safety proof, and the flag must never be enabled for the whole
        # suite (the default policy case lives in
        # tests/workspace_remote_delete_policy.py).
        binary,_=select_runtime_binary()
        h=Harness(argparse.Namespace(binary=str(binary),keep=False))
        h.env["ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE"]="true"
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
            self.assertFalse(abandoned["cleanup_pending"])
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
        binary,_=select_runtime_binary()
        h=Harness(argparse.Namespace(binary=str(binary),keep=False))
        try:
            h.setup();h.api();h.roundtrip()
            bob_repo=h.create_repository({"name":"bob-source"},token=h.bob)
            bob_work=h.root/"bob-work"
            h.git("clone",h.base+bob_repo["clone_path"],str(bob_work),token=h.bob)
            h.git("config","user.name","Bob",cwd=bob_work)
            h.git("config","user.email","bob@example.invalid",cwd=bob_work)
            (bob_work/"bob.txt").write_text("bob source\n")
            h.git("add","bob.txt",cwd=bob_work)
            h.git("commit","-m","bob initial",cwd=bob_work)
            bob_oid=h.git("rev-parse","HEAD",cwd=bob_work).stdout.decode().strip()
            h.git("push","origin","HEAD:main",cwd=bob_work,token=h.bob)
            bob_ws=json.loads(h.expect("/api/workspaces",201,token=h.bob,method="POST",
                body={"owner":"bob","repository":"bob-source","agent_id":"bob-source","base_oid":bob_oid},
                extra_headers={"Idempotency-Key":"bob-source-create"}))
            self.assertEqual(bob_ws["repository_id"],bob_repo["id"])
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
            self.assertEqual(committed["checkpoint_id"],cid)
            self.assertEqual(committed["state"],"COMMITTED")
            self.assertEqual(committed["durability"],"remote_verified")
            self.assertEqual(committed["captured_revision"],1)
            self.assertRegex(committed["manifest_sha256"],r"^[0-9a-f]{64}$")
            self.assertGreater(committed["manifest_size"],0)
            self.assertEqual(h.sql(f"SELECT state||':'||manifest_digest||':'||manifest_size FROM workspace_checkpoints WHERE id='{cid}'"),
                f"committed:{committed['manifest_sha256']}:{committed['manifest_size']}")
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
            self.assertEqual(second["checkpoint_id"],cid2)
            self.assertEqual(second["state"],"COMMITTED")
            self.assertEqual(second["durability"],"remote_verified")
            self.assertEqual(second["captured_revision"],2)
            self.assertRegex(second["manifest_sha256"],r"^[0-9a-f]{64}$")
            self.assertGreater(second["manifest_size"],0)
            self.assertEqual(h.sql(f"SELECT state||':'||manifest_digest||':'||manifest_size FROM workspace_checkpoints WHERE id='{cid2}'"),
                f"committed:{second['manifest_sha256']}:{second['manifest_size']}")
            self.assertEqual(h.sql(f"SELECT COUNT(*) FROM workspace_checkpoints WHERE id='{cid2}'"),"1")
            h.stop(hard=True)
            source=h.root/"data"
            shutil.rmtree(source)
            h.env["ROOTYARD_DATA_DIR"]=str(h.root/"second-data")
            h.start()
            second_data=Path(h.env["ROOTYARD_DATA_DIR"])
            service=second_data/"workspace-service"
            def inventory():
                return sorted(str(p.relative_to(service)) for p in service.rglob("*")) if service.exists() else []
            hydrated=inventory()
            durable_counts=(h.sql("SELECT COUNT(*) FROM workspaces"),
                h.sql("SELECT COUNT(*) FROM workspace_checkpoints"),
                h.sql("SELECT COUNT(*) FROM workspace_events"),
                h.sql("SELECT COUNT(*) FROM workspace_operations"),
                h.sql("SELECT COUNT(*) FROM workspace_creations"))
            bob_before=json.loads(h.expect(f"/api/workspaces/{bob_ws['id']}",200,token=h.bob))
            self.assertEqual(h.http(f"/api/checkpoints/{cid}/restore",token=h.bob,method="POST",
                body={"agent_id":"bob-deny-restore"},
                extra_headers={"Idempotency-Key":"bob-deny-restore"})[0],404)
            self.assertEqual(h.http(f"/api/workspaces/{bob_ws['id']}/fork",token=h.bob,method="POST",
                body={"checkpoint_id":cid,"new_agent_id":"bob-deny-fork"},
                extra_headers={"Idempotency-Key":"bob-deny-fork"})[0],404)
            self.assertEqual(inventory(),hydrated)
            self.assertFalse((service/"checkpoints"/str(cid)).exists())
            self.assertEqual((h.sql("SELECT COUNT(*) FROM workspaces"),
                h.sql("SELECT COUNT(*) FROM workspace_checkpoints"),
                h.sql("SELECT COUNT(*) FROM workspace_events"),
                h.sql("SELECT COUNT(*) FROM workspace_operations"),
                h.sql("SELECT COUNT(*) FROM workspace_creations")),durable_counts)
            self.assertEqual(h.sql(f"SELECT COUNT(*) FROM workspace_checkpoints WHERE workspace_id='{bob_ws['id']}'"),"0")
            self.assertEqual(h.sql("SELECT COUNT(*) FROM workspaces WHERE agent_id IN ('bob-deny-restore','bob-deny-fork')"),"0")
            self.assertEqual(h.sql("SELECT COUNT(*) FROM workspace_creations WHERE idempotency_key IN ('bob-deny-restore','bob-deny-fork')"),"0")
            bob_after=json.loads(h.expect(f"/api/workspaces/{bob_ws['id']}",200,token=h.bob))
            self.assertEqual((bob_after["revision"],bob_after["last_checkpoint_id"]),
                (bob_before["revision"],bob_before["last_checkpoint_id"]))
            self.assertEqual(h.sql(f"SELECT state FROM workspace_checkpoints WHERE id='{cid}'"),"committed")
            restored=json.loads(h.expect(f"/api/checkpoints/{cid}/restore",201,token=h.alice,method="POST",body={"agent_id":"remote-b"}))
            current=json.loads(h.expect(f"/api/workspaces/{wid}",200,token=h.alice))
            self.assertEqual(current["last_checkpoint_id"],cid2)
            events=json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0",200,token=h.alice))
            self.assertEqual([(e["kind"],e["payload"].get("checkpoint_id")) for e in events["events"] if e["kind"]=="checkpoint"],
                [("checkpoint",cid),("checkpoint",cid2)])
            self.assertEqual(h.sql(f"SELECT parent_checkpoint_id FROM workspaces WHERE id='{restored['id']}'"),cid)
            contents=json.loads(h.expect(f"/api/workspaces/{restored['id']}/files?path=hello.txt",200,token=h.alice))
            self.assertEqual(base64.b64decode(contents["content_base64"]),value)
            native=second_data/"workspace-service/workspaces"/restored["id"]
            self.assertEqual((native/"hello.txt").read_bytes(),value)
            status=h.git("status","--porcelain",cwd=native)
            self.assertEqual(status.returncode,0)
            self.assertEqual(status.stdout,b" M hello.txt\n")
            self.assertTrue((service/"checkpoints"/str(cid)).is_dir())
            self.assertFalse(source.exists())
            self.assertTrue(second_data.is_dir())
        finally:h.cleanup()


if __name__=="__main__":unittest.main()
