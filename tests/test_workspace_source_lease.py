"""Native workspace and namespace source reads stop on a lost PostgreSQL lease."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import shutil
import time
import unittest

from tests.e2e import Harness


class SourceLeaseTest(unittest.TestCase):
    def test_clone_and_namespace_git_children_stop_before_retry(self):
        h=Harness(argparse.Namespace(binary="target/debug/rootyard",
            keep=os.environ.get("ROOTYARD_KEEP_TEST")=="1"))
        try:
            h.setup();h.api();h.roundtrip()
            real_git=shutil.which("git",path=h.env["PATH"])
            self.assertTrue(real_git)
            mode=h.root/"pause-mode"
            parent_pid=h.root/"source-parent.pid"
            child_pid=h.root/"source-git.pid"
            wrapper=h.root/"paused-source-git"
            oid_line=(h.second+"\n").encode()
            wrapper.write_text("#!/usr/bin/env python3\n"
                "import os,pathlib,subprocess,sys,time\n"
                "args=sys.argv[1:]\n"
                f"if args==['--version']: os.execv({real_git!r},[{real_git!r}]+args)\n"
                f"mode=pathlib.Path({str(mode)!r}).read_text().strip()\n"
                "pause=(mode=='clone' and 'clone' in args) or "
                "(mode=='cat-file' and 'cat-file' in args and '-e' in args)\n"
                "if pause:\n"
                f" pathlib.Path({str(parent_pid)!r}).write_text(str(os.getpid()))\n"
                f" child=subprocess.Popen([{real_git!r},'--git-dir',{str(h.bare)!r},"
                "'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL)\n"
                f" pathlib.Path({str(child_pid)!r}).write_text(str(child.pid))\n"
                f" child.stdin.write({oid_line!r});child.stdin.flush()\n"
                " while True: time.sleep(.1)\n"
                f"os.execv({real_git!r},[{real_git!r}]+args)\n")
            wrapper.chmod(0o700)
            h.stop();h.env["ROOTYARD_GIT"]=str(wrapper);h.start()

            def live(pid):
                try:rest=Path(f"/proc/{pid}/stat").read_text().rsplit(") ",1)[1]
                except FileNotFoundError:return False
                return rest[0] not in ("Z","X")

            def lost_lease(request):
                parent_pid.unlink(missing_ok=True);child_pid.unlink(missing_ok=True)
                pool=ThreadPoolExecutor(max_workers=1)
                try:
                    future=pool.submit(request)
                    deadline=time.monotonic()+8
                    while not child_pid.exists():
                        self.assertFalse(future.done(),"source request ended before native Git")
                        self.assertLess(time.monotonic(),deadline,"source Git never started")
                        time.sleep(.02)
                    repo_id=h.bare.stem
                    pids=[int(x) for x in h.sql(
                        "WITH k AS (SELECT hashtextextended("+
                        f"'rootyard-data-v1:{repo_id}',0) n) "
                        "SELECT DISTINCT l.pid FROM pg_locks l,k WHERE l.locktype='advisory' "
                        "AND l.mode='ShareLock' AND l.granted AND "
                        "l.classid::bigint=((k.n >> 32) & 4294967295) AND "
                        "l.objid::bigint=(k.n & 4294967295)").splitlines()]
                    self.assertTrue(pids,"source has no PostgreSQL shared read lease")
                    for pid in pids:
                        self.assertEqual(h.sql(f"SELECT pg_terminate_backend({pid})"),"t")
                    started=time.monotonic()
                    status,raw,_=future.result(timeout=5)
                    self.assertEqual(status,503,raw[:300])
                    self.assertLess(time.monotonic()-started,4)
                    deadline=time.monotonic()+3
                    for pid in (int(parent_pid.read_text()),int(child_pid.read_text())):
                        while live(pid) and time.monotonic()<deadline:time.sleep(.05)
                        self.assertFalse(live(pid),f"source process {pid} survived lease loss")
                finally:
                    if parent_pid.exists():
                        pid=int(parent_pid.read_text())
                        cmdline=Path(f"/proc/{pid}/cmdline")
                        if live(pid) and cmdline.exists() and str(wrapper).encode() in cmdline.read_bytes():
                            os.killpg(pid,signal.SIGKILL)
                    pool.shutdown(wait=False,cancel_futures=True)

            mode.write_text("clone")
            body={"owner":"alice","repository":"demo","agent_id":"source-lease",
                "base_oid":h.second}
            lost_lease(lambda:h.http("/api/workspaces",token=h.alice,method="POST",body=body,
                extra_headers={"Idempotency-Key":"lost-clone"}))
            mode.write_text("cat-file")
            ns={"name":"source-lease","mounts":[{"path":"pkg","owner":"alice",
                "repository":"demo","base_oid":h.second}]}
            lost_lease(lambda:h.http("/api/namespaces",token=h.alice,method="POST",body=ns))
            h.stop();h.env.pop("ROOTYARD_GIT",None);h.start()
            self.assertEqual(h.http("/api/workspaces",token=h.alice,method="POST",body=body,
                extra_headers={"Idempotency-Key":"fresh-clone"})[0],201)
            self.assertEqual(h.http("/api/namespaces",token=h.alice,method="POST",body=ns)[0],201)
        finally:h.cleanup()


if __name__=="__main__":unittest.main()
