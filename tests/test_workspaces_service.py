"""Native HTTP/PostgreSQL workspace lifecycle and revision fencing regression."""
import argparse
import base64
import json
import time
import unittest

from tests.e2e import Harness


class WorkspaceServiceTest(unittest.TestCase):
    def test_create_edit_checkpoint_fork_restore_restart(self):
        h = Harness(argparse.Namespace(binary="target/debug/rootyard", keep=False))
        try:
            h.setup()
            h.api()
            h.roundtrip()
            create = {"owner":"alice","repository":"demo","agent_id":"agent-one","base_oid":h.second}
            key = {"Idempotency-Key":"create-1"}
            status, raw, _ = h.http("/api/workspaces",token=h.alice,method="POST",body=create,extra_headers=key)
            self.assertEqual(status,201,raw)
            ws = json.loads(raw)
            wid = ws["id"]
            self.assertEqual(json.loads(h.expect("/api/workspaces",200,token=h.alice,method="POST",body=create,extra_headers=key))["id"],wid)
            self.assertEqual(h.http(f"/api/workspaces/{wid}",token=h.bob)[0],404)
            put = {"content_base64":base64.b64encode(b"v1\n").decode(),"expected_entry_version":0,
                   "expected_workspace_revision":0,"lease_epoch":ws["lease_epoch"]}
            path = f"/api/workspaces/{wid}/files?path=hello.txt"
            self.assertEqual(h.http(path,token=h.bob,method="PUT",body=put,extra_headers={"Idempotency-Key":"put-1"})[0],404)
            first = json.loads(h.expect(path,200,token=h.alice,method="PUT",body=put,extra_headers={"Idempotency-Key":"put-1"}))
            self.assertEqual(first["entry_version"],1)
            self.assertEqual(h.http(path,token=h.alice,method="PUT",body=put,extra_headers={"Idempotency-Key":"put-2"})[0],409)
            self.assertEqual(json.loads(h.expect(path,200,token=h.alice,method="PUT",body=put,extra_headers={"Idempotency-Key":"put-1"})),first)
            self.assertEqual(base64.b64decode(json.loads(h.expect(path,200,token=h.alice))["content_base64"]),b"v1\n")
            staged = json.loads(h.expect(f"/api/workspaces/{wid}/git",200,token=h.alice,method="POST",
                body={"action":"add","paths":["hello.txt"],"expected_git_generation":0,
                      "expected_workspace_revision":1,"lease_epoch":1},extra_headers={"Idempotency-Key":"git-add-1"}))
            self.assertEqual(staged["git_generation"],1)
            put2 = {"content_base64":base64.b64encode(b"v2 unstaged\n").decode(),"expected_entry_version":1,
                    "expected_workspace_revision":2,"lease_epoch":1}
            h.expect(path,200,token=h.alice,method="PUT",body=put2,extra_headers={"Idempotency-Key":"put-3"})
            checkpoint = json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,method="POST",
                body={"expected_workspace_revision":3,"lease_epoch":1},extra_headers={"Idempotency-Key":"checkpoint-1"}))
            cid = checkpoint["checkpoint_id"]
            self.assertEqual(checkpoint["state"],"local_complete")
            h.stop(hard=True)
            h.start()
            fork = json.loads(h.expect(f"/api/workspaces/{wid}/fork",201,token=h.alice,method="POST",
                body={"checkpoint_id":cid,"new_agent_id":"agent-two"},
                extra_headers={"Idempotency-Key":"fork-one"}))
            fork_replay=json.loads(h.expect(f"/api/workspaces/{wid}/fork",200,token=h.alice,method="POST",
                body={"checkpoint_id":cid,"new_agent_id":"agent-two"},
                extra_headers={"Idempotency-Key":"fork-one"}))
            self.assertEqual(fork_replay["id"],fork["id"])
            self.assertEqual(h.http(f"/api/workspaces/{wid}/fork",token=h.alice,method="POST",
                body={"checkpoint_id":cid,"new_agent_id":"different"},
                extra_headers={"Idempotency-Key":"fork-one"})[0],409)
            fork_path=f"/api/workspaces/{fork['id']}/files?path=hello.txt"
            self.assertEqual(base64.b64decode(json.loads(h.expect(fork_path,200,token=h.alice))["content_base64"]),b"v2 unstaged\n")
            self.assertEqual(base64.b64decode(json.loads(h.expect(fork_path+"&view=index",200,token=h.alice))["content_base64"]),b"v1\n")
            self.assertEqual(base64.b64decode(json.loads(h.expect(fork_path+"&view=head",200,token=h.alice))["content_base64"]),b"second\n")
            changed = {"content_base64":base64.b64encode(b"fork-only\n").decode(),"expected_entry_version":0,
                       "expected_workspace_revision":0,"lease_epoch":fork["lease_epoch"]}
            h.expect(fork_path,200,token=h.alice,method="PUT",body=changed,extra_headers={"Idempotency-Key":"fork-put"})
            self.assertEqual(base64.b64decode(json.loads(h.expect(path,200,token=h.alice))["content_base64"]),b"v2 unstaged\n")
            restored = json.loads(h.expect(f"/api/checkpoints/{cid}/restore",201,token=h.alice,method="POST",
                body={"agent_id":"restored"},extra_headers={"Idempotency-Key":"restore-one"}))
            self.assertEqual(json.loads(h.expect(f"/api/checkpoints/{cid}/restore",200,token=h.alice,method="POST",
                body={"agent_id":"restored"},extra_headers={"Idempotency-Key":"restore-one"}))["id"],restored["id"])
            self.assertNotEqual(restored["id"],wid)
            self.assertEqual(base64.b64decode(json.loads(h.expect(f"/api/workspaces/{restored['id']}/files?path=hello.txt",200,token=h.alice))["content_base64"]),b"v2 unstaged\n")
            events = json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0",200,token=h.alice))
            self.assertEqual([e["revision"] for e in events["events"]],[1,2,3,4])
            live_repo = h.root / "data/workspace-service/workspaces" / wid
            (live_repo / "hello.txt").write_bytes(b"normal editor save\n")
            deadline = time.monotonic()+8
            while time.monotonic()<deadline:
                replay = json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=4",200,token=h.alice))
                if replay["events"]: break
                time.sleep(.2)
            self.assertEqual(replay["events"][0]["kind"],"external_capture")
            self.assertEqual(replay["events"][0]["revision"],5)
            lease=json.loads(h.expect(f"/api/workspaces/{wid}/lease",200,token=h.alice,method="POST",
                body={"expected_lease_epoch":1}))
            self.assertEqual(lease["lease_epoch"],2)
            stale={"content_base64":base64.b64encode(b"stale\n").decode(),"expected_entry_version":2,
                   "expected_workspace_revision":5,"lease_epoch":1}
            self.assertEqual(h.http(path,token=h.alice,method="PUT",body=stale,extra_headers={"Idempotency-Key":"stale-epoch"})[0],409)
        finally:
            h.cleanup()


if __name__ == "__main__": unittest.main()
