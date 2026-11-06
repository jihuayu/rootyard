#!/usr/bin/env python3
"""Native new-ref LFS lock history and stock verify-body pagination regression."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback

sys.path.insert(0,str(Path(__file__).resolve().parent))
from e2e import Harness

LFS_MIME="application/vnd.git-lfs+json"


class LockPolicyHarness(Harness):
    def setup_repo(self):
        self.setup()
        repo=json.loads(self.expect("/api/repos",201,token=self.alice,method="POST",
                                    body={"name":"lock-policy"}))
        self.repo=repo
        self.remote=self.base+repo["clone_path"]
        self.work=self.root/"alice-work"
        self.git("clone",self.remote,str(self.work),token=self.alice)
        self.git("config","user.name","Alice",cwd=self.work)
        self.git("config","user.email","alice@rootyard.local",cwd=self.work)
        (self.work/"README.md").write_text("base\n")
        self.git("add","README.md",cwd=self.work)
        self.git("commit","-m","base",cwd=self.work)
        self.git("push","origin","HEAD:main",cwd=self.work,token=self.alice)
        self.expect("/api/repos/alice/lock-policy/collaborators/bob",201,
                    token=self.alice,method="PUT",body={"role":"write"})
        self.bob_work=self.work
        self.git("lfs","install","--local",cwd=self.work)
        lock=self.git("lfs","lock","docs/locked.txt",cwd=self.work,token=self.bob)
        assert b"Locked docs/locked.txt" in lock.stdout
        return {"stock_lock_created":True}

    def reject_hidden_earlier_commit(self):
        self.git("checkout","-b","blocked",cwd=self.bob_work)
        docs=self.bob_work/"docs"
        docs.mkdir()
        (docs/"locked.txt").write_text("unauthorized edit in ancestor A\n")
        self.git("add","docs/locked.txt",cwd=self.bob_work)
        self.git("commit","-m","A edits locked path",cwd=self.bob_work)
        ancestor=self.git("rev-parse","HEAD",cwd=self.bob_work).stdout.decode().strip()
        (self.bob_work/"unlocked.txt").write_text("tip B touches another path\n")
        self.git("add","unlocked.txt",cwd=self.bob_work)
        self.git("commit","-m","B edits only unlocked path",cwd=self.bob_work)
        tip=self.git("rev-parse","HEAD",cwd=self.bob_work).stdout.decode().strip()
        # Disable only the local pre-push hook: the server must reject this
        # malicious Git ref update itself, after native receive-pack starts.
        denied=self.git("-c","core.hooksPath=/dev/null","push","origin","HEAD:refs/heads/blocked",cwd=self.bob_work,
                        token=self.alice,check=False)
        assert denied.returncode!=0, "new branch exposed an ancestor edit to locked path"
        remote_refs=self.git("ls-remote",self.remote,"refs/heads/blocked",token=self.alice).stdout
        assert not remote_refs, "rejected branch became visible"
        self.git("checkout","main",cwd=self.bob_work)
        self.git("checkout","-b","allowed",cwd=self.bob_work)
        (self.bob_work/"safe.txt").write_text("safe branch\n")
        self.git("add","safe.txt",cwd=self.bob_work)
        self.git("commit","-m","safe change",cwd=self.bob_work)
        self.git("push","origin","HEAD:refs/heads/allowed",cwd=self.bob_work,token=self.alice)
        unlock=self.git("lfs","unlock","docs/locked.txt",cwd=self.work,token=self.bob)
        assert b"Unlocked docs/locked.txt" in unlock.stdout
        return {"ancestor":ancestor,"tip":tip,"new_ref_denied":True,
                "unlocked_new_ref_allowed":True,"stock_branch_switch_unlock":True}

    def verify_body_cursor(self):
        base="/git/alice/lock-policy.git/info/lfs/locks"
        for path in ["docs/locked.txt","docs/other-one.txt","docs/other-two.txt"]:
            status,body,_=self.http(base,token=self.alice,method="POST",
                                    body=json.dumps({"path":path}).encode(),content_type=LFS_MIME)
            assert status==201,(status,body)
        seen=[]
        cursor=None
        for page in range(3):
            request={"limit":1}
            if cursor: request["cursor"]=cursor
            status,body,_=self.http(base+"/verify",token=self.alice,method="POST",
                                    body=json.dumps(request).encode(),content_type=LFS_MIME)
            assert status==200,(status,body)
            result=json.loads(body)
            assert len(result["ours"])==1 and result["theirs"]==[],result
            seen.append(result["ours"][0]["id"])
            cursor=result["next_cursor"]
            assert (cursor is not None)==(page<2),result
        assert len(set(seen))==3
        for bad in [{"limit":0},{"limit":1,"ignored":True}]:
            status,_,_=self.http(base+"/verify",token=self.alice,method="POST",
                                 body=json.dumps(bad).encode(),content_type=LFS_MIME)
            assert status==400,(bad,status)
        return {"body_limit_pages":3,"unique_locks":3,"unknown_field_rejected":True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",default="target/debug/rootyard")
    parser.add_argument("--report",type=Path)
    parser.add_argument("--keep",action="store_true")
    args=parser.parse_args();args.binary=str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    h=LockPolicyHarness(args);passed=False
    try:
        h.case("setup_repo",h.setup_repo)
        h.case("reject_hidden_earlier_commit",h.reject_hidden_earlier_commit)
        h.case("verify_body_cursor",h.verify_body_cursor)
        passed=True
    except Exception:
        print(h.redact(traceback.format_exc()),file=sys.stderr)
    finally:
        h.cleanup()
    result={"passed":passed,"cases":h.results,
            "binary_sha256":hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
    if args.report: args.report.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
    return 0 if passed else 1


if __name__=="__main__":sys.exit(main())
