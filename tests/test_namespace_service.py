"""Native authorized namespace projection and stock-Git bundle regression."""
import argparse
import base64
import json
import unittest

from tests.e2e import Harness


class NamespaceServiceTest(unittest.TestCase):
    def test_pinned_subdir_view_and_git_bundle(self):
        h=Harness(argparse.Namespace(binary="target/debug/rootyard",keep=False))
        try:
            h.setup(); h.api(); h.roundtrip()
            (h.work/"pkg").mkdir()
            (h.work/"pkg/lib.rs").write_text("pub fn value() -> u32 { 7 }\n")
            h.git("add","pkg/lib.rs",cwd=h.work)
            h.git("commit","-m","add package",cwd=h.work)
            base=h.git("rev-parse","HEAD",cwd=h.work).stdout.decode().strip()
            h.git("push","origin","HEAD:main",cwd=h.work,token=h.alice)
            ns=json.loads(h.expect("/api/namespaces",201,token=h.alice,method="POST",
                body={"name":"company","mounts":[{"path":"payments","owner":"alice","repository":"demo","base_oid":base}]}))
            self.assertEqual(h.http(f"/api/namespaces/{ns['id']}",token=h.bob)[0],404)
            view=json.loads(h.expect(f"/api/namespaces/{ns['id']}/views",201,token=h.alice,method="POST",
                body={"mount_path":"payments","subdir":"pkg"}))
            self.assertEqual(view["source_oid"],base)
            self.assertEqual(h.http(f"/api/views/{view['id']}/bundle",token=h.bob)[0],404)
            bundle=h.expect(f"/api/views/{view['id']}/bundle",200,token=h.alice)
            path=h.root/"projected.bundle"; path.write_bytes(bundle)
            clone=h.root/"projected"
            h.git("clone",str(path),str(clone))
            self.assertEqual((clone/"lib.rs").read_text(),"pub fn value() -> u32 { 7 }\n")
            self.assertFalse((clone/"hello.txt").exists())
            self.assertEqual(h.git("rev-parse","HEAD",cwd=clone).stdout.decode().strip(),view["projected_oid"])
            self.assertNotEqual(h.git("cat-file","-e",base+"^{commit}",cwd=clone,check=False).returncode,0)
            h.git("config","user.name","View author",cwd=clone)
            h.git("config","user.email","view@example.invalid",cwd=clone)
            (clone/"lib.rs").write_text("pub fn value() -> u32 { 11 }\n")
            h.git("commit","-am","change projected package",cwd=clone)
            proposal=h.root/"proposal.bundle"
            h.git("bundle","create",str(proposal),"--all",cwd=clone)
            h.expect("/api/repos/alice/demo/collaborators",201,token=h.alice,
                method="POST",body={"username":"bob","role":"maintain"})
            cs=json.loads(h.expect(f"/api/views/{view['id']}/changesets",201,token=h.alice,
                method="POST",body={"bundle_base64":base64.b64encode(proposal.read_bytes()).decode(),
                    "bundle_ref":"refs/heads/projected","source_ref":"refs/heads/main",
                    "message":"Update package value"}))
            self.assertEqual(cs["state"],"proposed")
            self.assertEqual(h.git("--git-dir="+str(h.bare),"rev-parse","refs/heads/main").stdout.decode().strip(),base)
            h.expect(f"/api/changesets/{cs['id']}/review",200,token=h.bob,method="POST")
            done=json.loads(h.expect(f"/api/changesets/{cs['id']}/integrate",200,token=h.alice,method="POST"))
            self.assertEqual(done["state"],"complete")
            new_source=done["steps"][0]["new_oid"]
            self.assertEqual(h.git("--git-dir="+str(h.bare),"rev-parse","refs/heads/main").stdout.decode().strip(),new_source)
            self.assertEqual(h.git("--git-dir="+str(h.bare),"show",new_source+":pkg/lib.rs").stdout.decode(),
                "pub fn value() -> u32 { 11 }\n")
            self.assertEqual(h.git("--git-dir="+str(h.bare),"show",new_source+":hello.txt").stdout.decode(),"second\n")
        finally: h.cleanup()


if __name__=="__main__": unittest.main()
