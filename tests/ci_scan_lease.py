#!/usr/bin/env python3
"""Native CI source-scan lease loss: a paused Git child must stop promptly."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import sys
import time

from ci_job_checkouts import JobCheckoutHarness


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",default="target/debug/rootyard")
    parser.add_argument("--keep",action="store_true")
    args=parser.parse_args();args.binary=str(Path(args.binary).resolve())
    h=JobCheckoutHarness(args)
    try:
        h.setup_mirror()
        body=h.request_body(oid=h.second)
        h.pin(h.pin_body(h.second,body["job_id"],1))
        entered=h.root/"scan-entered.pid"
        real_git=shutil.which("git",path=h.env["PATH"])
        assert real_git
        wrapper=h.root/"paused-git"
        wrapper.write_text("#!/usr/bin/env python3\n"
            "import os,pathlib,sys,time\n"
            "args=sys.argv[1:]\n"
            "if 'ls-tree' in args:\n"
            f" pathlib.Path({str(entered)!r}).write_text(str(os.getpid()))\n"
            " while True: time.sleep(.1)\n"
            f"os.execv({real_git!r},[{real_git!r}]+args)\n")
        wrapper.chmod(0o700)
        h.stop()
        h.env["ROOTYARD_GIT"]=str(wrapper)
        h.start()
        pool=ThreadPoolExecutor(max_workers=1)
        try:
            pending=pool.submit(h.http,h.checkout_path,token=h.alice,
                method="POST",body=body)
            deadline=time.monotonic()+8
            while not entered.exists():
                assert not pending.done(),"CI issuance ended before native source scan"
                assert time.monotonic()<deadline,"source scan did not enter native Git"
                time.sleep(.02)
            pid=int(entered.read_text())
            pids=h.sql("SELECT DISTINCT l.pid FROM pg_locks l JOIN pg_stat_activity a "
                "ON a.pid=l.pid WHERE l.locktype='advisory' AND l.mode='ShareLock' "
                "AND l.granted AND a.datname=current_database() "
                "AND l.pid<>pg_backend_pid()").splitlines()
            assert pids,"CI scan has no durable PostgreSQL read lease"
            terminated=0
            for target in pids:
                if h.sql(f"SELECT pg_terminate_backend({int(target)})")=="t":
                    terminated+=1
            assert terminated>=1,"fixture did not terminate the lease owner"
            started=time.monotonic()
            status,raw,_=pending.result(timeout=5)
            elapsed=time.monotonic()-started
            assert status==503,(status,raw[:200])
            assert elapsed<4,elapsed
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                try:os.kill(pid,0)
                except ProcessLookupError:break
                time.sleep(.05)
            else:raise AssertionError("paused Git source scanner survived lost lease")
        finally:
            h.stop()
            pool.shutdown(wait=False,cancel_futures=True)
            h.env.pop("ROOTYARD_GIT",None)
            h.start()
        grant=h.issue(body)
        assert grant["plan"]["target_oid"]==h.second
        print(json.dumps({"passed":True,"lease_backends_terminated":terminated,
            "abort_seconds":round(elapsed,3),"native_git_reaped":True,
            "fresh_issue_after_loss":True}),flush=True)
        return 0
    finally:h.cleanup()


if __name__=="__main__":sys.exit(main())
