"""Native PostgreSQL and Git integration for reviewed cross-repository changesets."""
import argparse
import json
import unittest

from tests.e2e import Harness


class ChangeSetServiceTest(unittest.TestCase):
    def test_crash_after_first_ref_and_recover(self):
        h=Harness(argparse.Namespace(binary="target/debug/rootyard",keep=False))
        try:
            h.setup();h.api();h.roundtrip()
            other=json.loads(h.expect("/api/repos",201,token=h.alice,method="POST",body={"name":"other"}))
            other_work=h.root/"other-work"
            h.git("clone",h.base+other["clone_path"],str(other_work),token=h.alice)
            h.git("config","user.name","E2E",cwd=other_work)
            h.git("config","user.email","e2e@example.invalid",cwd=other_work)
            (other_work/"second.txt").write_text("original\n")
            h.git("add","second.txt",cwd=other_work)
            h.git("commit","-m","original",cwd=other_work)
            old_other=h.git("rev-parse","HEAD",cwd=other_work).stdout.decode().strip()
            h.git("push","origin","HEAD:main",cwd=other_work,token=h.alice)
            (other_work/"second.txt").write_text("candidate\n")
            h.git("commit","-am","candidate",cwd=other_work)
            new_other=h.git("rev-parse","HEAD",cwd=other_work).stdout.decode().strip()
            h.git("push","origin","HEAD:refs/heads/candidate",cwd=other_work,token=h.alice)
            (h.work/"hello.txt").write_text("candidate-one\n")
            h.git("commit","-am","candidate one",cwd=h.work)
            new_demo=h.git("rev-parse","HEAD",cwd=h.work).stdout.decode().strip()
            h.git("push","origin","HEAD:refs/heads/candidate",cwd=h.work,token=h.alice)
            for name in ("demo","other"):
                h.expect(f"/api/repos/alice/{name}/collaborators",201,token=h.alice,
                    method="POST",body={"username":"bob","role":"maintain"})
            ns=json.loads(h.expect("/api/namespaces",201,token=h.alice,method="POST",
                body={"name":"cross-repo","mounts":[
                    {"path":"one","owner":"alice","repository":"demo","base_oid":h.second},
                    {"path":"two","owner":"alice","repository":"other","base_oid":old_other}]}))
            self.assertEqual(h.http(f"/api/namespaces/{ns['id']}",token=h.bob)[0],200)
            steps=[
                {"mount_path":"one","ref_name":"refs/heads/main","old_oid":h.second,
                 "new_oid":new_demo,"storage_generation":h.repo["storage_generation"]},
                {"mount_path":"two","ref_name":"refs/heads/main","old_oid":old_other,
                 "new_oid":new_other,"storage_generation":other["storage_generation"]}]
            cs=json.loads(h.expect(f"/api/namespaces/{ns['id']}/changesets",201,token=h.alice,
                method="POST",body={"steps":steps}))
            cid=cs["id"]
            self.assertEqual(h.http(f"/api/changesets/{cid}/review",token=h.alice,method="POST")[0],403)
            self.assertEqual(json.loads(h.expect(f"/api/changesets/{cid}/review",200,
                token=h.bob,method="POST"))["state"],"reviewed")
            h.stop()
            h.env["ROOTYARD_CHANGESET_KILL_AFTER_STEP"]="1"
            h.start()
            response=None
            try: response=h.http(f"/api/changesets/{cid}/integrate",token=h.alice,method="POST")
            except Exception: pass
            state_value=h.sql(f"SELECT state FROM workspace_changesets WHERE id='{cid}'")
            server_log=(h.root/"server.log").read_text()
            self.assertIsNotNone(h.proc.poll(),
                f"integrate response: {response}; state: {state_value}; log: {server_log[-3000:]}")
            self.assertEqual(h.proc.wait(timeout=10),79)
            self.assertEqual(h.sql(f"SELECT state FROM workspace_changesets WHERE id='{cid}'"),"partial")
            self.assertEqual(h.git("--git-dir="+str(h.bare),"rev-parse","refs/heads/main").stdout.decode().strip(),new_demo)
            other_bare=h.root/"data/repos"/(other["id"]+".git")
            self.assertEqual(h.git("--git-dir="+str(other_bare),"rev-parse","refs/heads/main").stdout.decode().strip(),old_other)
            h.stop()
            h.env.pop("ROOTYARD_CHANGESET_KILL_AFTER_STEP")
            h.start()
            self.assertEqual(h.http(f"/api/changesets/{cid}/integrate",token=h.alice,method="POST")[0],409)
            done=json.loads(h.expect(f"/api/changesets/{cid}/recover",200,token=h.alice,method="POST"))
            self.assertEqual(done["state"],"complete")
            self.assertEqual([s["applied"] for s in done["steps"]],[True,True])
            self.assertEqual(h.git("--git-dir="+str(other_bare),"rev-parse","refs/heads/main").stdout.decode().strip(),new_other)
            self.assertEqual(json.loads(h.expect(f"/api/changesets/{cid}",200,token=h.bob))["state"],"complete")
            (other_work/"second.txt").write_text("later candidate\n")
            h.git("commit","-am","later candidate",cwd=other_work)
            later=h.git("rev-parse","HEAD",cwd=other_work).stdout.decode().strip()
            h.git("push","origin","HEAD:refs/heads/candidate-later",cwd=other_work,token=h.alice)
            stale=json.loads(h.expect(f"/api/namespaces/{ns['id']}/changesets",201,token=h.alice,
                method="POST",body={"steps":[dict(steps[1],new_oid=later)]}))
            h.expect(f"/api/changesets/{stale['id']}/review",200,token=h.bob,method="POST")
            self.assertEqual(h.http(f"/api/changesets/{stale['id']}/integrate",token=h.alice,method="POST")[0],409)
            self.assertEqual(json.loads(h.expect(f"/api/changesets/{stale['id']}",200,token=h.alice))["state"],"conflict")
            self.assertEqual(h.git("--git-dir="+str(other_bare),"rev-parse","refs/heads/main").stdout.decode().strip(),new_other)
        finally:h.cleanup()


if __name__=="__main__":unittest.main()
