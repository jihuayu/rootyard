"""Native authorized namespace projection and stock-Git bundle regression."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

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
            # A real source Git child must stop when its PostgreSQL reader
            # backend dies; another process may then acquire the GC lock.
            real_git=shutil.which("git",path=h.env["PATH"])
            wrapper_dir=h.root/"reverse-bin";wrapper_dir.mkdir()
            wrapper=wrapper_dir/"git"
            wrapper_pid=h.root/"reverse-parent.pid"
            source_child=h.root/"reverse-source.pid"
            wrapper.write_text("#!/usr/bin/env python3\n"
                "import os,pathlib,subprocess,sys,time\n"
                "args=sys.argv[1:]\n"
                f"real={real_git!r}\n"
                f"source={str(h.bare)!r}\n"
                "if '-C' in args and args[args.index('-C')+1]==source "
                "and 'rev-parse' in args and '--verify' in args:\n"
                f" pathlib.Path({str(wrapper_pid)!r}).write_text(str(os.getpid()))\n"
                " child=subprocess.Popen([real,'--git-dir='+source,'cat-file','--batch'],"
                "stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                f" pathlib.Path({str(source_child)!r}).write_text(str(child.pid))\n"
                f" child.stdin.write({(base+chr(10)).encode()!r});child.stdin.flush()\n"
                " while True:time.sleep(.1)\n"
                "os.execv(real,[real]+args)\n")
            wrapper.chmod(0o700)
            old_path=h.env["PATH"]
            h.stop();h.env["PATH"]=str(wrapper_dir)+":"+old_path;h.start()
            def live(pid):
                try:return Path(f"/proc/{pid}/stat").read_text().rsplit(") ",1)[1][0] not in ("Z","X")
                except FileNotFoundError:return False
            proposal_body={"bundle_base64":base64.b64encode(proposal.read_bytes()).decode(),
                "bundle_ref":"refs/heads/projected","source_ref":"refs/heads/main",
                "message":"Update package value"}
            workers=ThreadPoolExecutor(max_workers=2)
            try:
                request=workers.submit(lambda:h.http(f"/api/views/{view['id']}/changesets",
                    token=h.alice,method="POST",body=proposal_body))
                deadline=time.monotonic()+8
                while not source_child.exists():
                    self.assertFalse(request.done(),"reverse import ended before source read")
                    self.assertLess(time.monotonic(),deadline,"reverse source Git did not start")
                    time.sleep(.02)
                repo_id=h.bare.stem
                key=f"hashtextextended('rootyard-data-v1:{repo_id}',0)"
                waiter=workers.submit(lambda:h.sql(f"BEGIN; SELECT pg_advisory_xact_lock({key}); SELECT 1; COMMIT;"))
                pids=[int(x) for x in h.sql("WITH k AS (SELECT "+key+" n) "
                    "SELECT DISTINCT l.pid FROM pg_locks l,k WHERE l.locktype='advisory' "
                    "AND l.mode='ShareLock' AND l.granted AND "
                    "l.classid::bigint=((k.n >> 32) & 4294967295) AND "
                    "l.objid::bigint=(k.n & 4294967295)").splitlines()]
                self.assertTrue(pids,"reverse source has no PostgreSQL read lease")
                self.assertFalse(waiter.done(),"exclusive collector did not wait for source")
                for pid in pids:self.assertEqual(h.sql(f"SELECT pg_terminate_backend({pid})"),"t")
                started=time.monotonic()
                status,raw,_=request.result(timeout=5)
                self.assertEqual(status,503,raw[:300])
                self.assertLess(time.monotonic()-started,4)
                self.assertIn("1",waiter.result(timeout=5))
                for pid in (int(wrapper_pid.read_text()),int(source_child.read_text())):
                    deadline=time.monotonic()+3
                    while live(pid) and time.monotonic()<deadline:time.sleep(.02)
                    self.assertFalse(live(pid),f"reverse source child {pid} outlived lease loss")
            finally:
                if wrapper_pid.exists() and live(int(wrapper_pid.read_text())):
                    os.killpg(int(wrapper_pid.read_text()),signal.SIGKILL)
                workers.shutdown(wait=False,cancel_futures=True)
            h.stop();h.env["PATH"]=old_path;h.start()
            cs=json.loads(h.expect(f"/api/views/{view['id']}/changesets",201,token=h.alice,
                method="POST",body=proposal_body))
            self.assertEqual(cs["state"],"proposed")
            pins=h.git("--git-dir="+str(h.bare),"for-each-ref","--format=%(refname) %(objectname)",
                "refs/heads/rootyard-proposals").stdout.decode().strip().splitlines()
            self.assertEqual(len(pins),1)
            pin, pinned_oid=pins[0].split()
            self.assertEqual(pinned_oid,cs["steps"][0]["new_oid"])
            self.assertNotEqual(h.git("push","origin",":"+pin,cwd=h.work,token=h.alice,check=False).returncode,0)
            self.assertNotEqual(h.git("push","--force","origin","HEAD:"+pin,
                cwd=h.work,token=h.alice,check=False).returncode,0)
            for old_oid,new_oid in ((pinned_oid,"0"*40),(pinned_oid,base)):
                status,_,_=h.http("/api/repos/alice/demo/ref-transactions",token=h.alice,method="POST",
                    body={"atomic":True,"updates":[{"ref_name":pin,"old_oid":old_oid,"new_oid":new_oid}]})
                self.assertEqual(status,400)
            self.assertEqual(h.git("--git-dir="+str(h.bare),"rev-parse",pin).stdout.decode().strip(),pinned_oid)
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
