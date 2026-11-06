#!/usr/bin/env python3
"""Stock Git LFS remote upload and second-node recovery against an S3-compatible store."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import traceback

sys.path.insert(0,str(Path(__file__).resolve().parent))
from e2e import Harness


class RemoteLfsHarness(Harness):
    def stock_roundtrip_after_volume_loss(self):
        assert os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"),"S3 fixture environment is required"
        self.setup();self.api();self.roundtrip()
        self.git("lfs","install","--local",cwd=self.work)
        self.git("lfs","track","*.dat",cwd=self.work)
        payload=os.urandom(1024*1024)
        oid=hashlib.sha256(payload).hexdigest()
        (self.work/"large.dat").write_bytes(payload)
        self.git("add",".gitattributes","large.dat",cwd=self.work)
        self.git("commit","-m","stock LFS upload",cwd=self.work)
        self.git("push","origin","HEAD:main",cwd=self.work,token=self.alice)
        assert self.sql(f"SELECT state FROM lfs_objects WHERE repository_id='{self.repo['id']}' AND oid='{oid}'") == "ready"
        local_lfs = Path(self.env["ROOTYARD_DATA_DIR"]) / "lfs" / self.repo["id"] / oid
        assert local_lfs.is_file()
        new_payload = os.urandom(1024 * 1024)
        new_oid = hashlib.sha256(new_payload).hexdigest()
        (self.work / "another.dat").write_bytes(new_payload)
        self.git("add", "another.dat", cwd=self.work)
        # Publish bytes before any Git pointer refers to this new OID.
        self.git("lfs", "push", "--object-id", "origin", new_oid,
                 cwd=self.work, token=self.alice)
        assert self.sql(f"SELECT state FROM lfs_objects WHERE repository_id='{self.repo['id']}' AND oid='{new_oid}'") == "ready"
        new_local_lfs = Path(self.env["ROOTYARD_DATA_DIR"]) / "lfs" / self.repo["id"] / new_oid
        assert new_local_lfs.is_file()
        self.git("commit", "-m", "publish remote-only new LFS pointer", cwd=self.work)
        new_head = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        new_local_lfs.unlink()
        assert not new_local_lfs.exists()
        # Suppress only the client-side reupload; the server's managed native
        # pre-receive hook must validate this pointer from remote S3 bytes.
        self.git("-c", "core.hooksPath=/dev/null", "push", "origin", "HEAD:main",
                 cwd=self.work, token=self.alice)
        assert self.git("--git-dir=" + str(self.bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == new_head
        assert (new_local_lfs.is_file() and
                hashlib.sha256(new_local_lfs.read_bytes()).hexdigest() == new_oid), \
            "native hook did not verify and hydrate the new remote-only pointer"
        self.stop()
        source=Path(self.env["ROOTYARD_DATA_DIR"])
        replacement=self.root/"second-node"
        shutil.copytree(source,replacement,ignore=shutil.ignore_patterns("lfs"),symlinks=True)
        shutil.rmtree(source)
        self.env["ROOTYARD_DATA_DIR"]=str(replacement)
        self.start()
        clone=self.root/"second-node-clone"
        self.git("clone",self.remote,str(clone),token=self.alice)
        self.git("lfs","install","--local",cwd=clone)
        self.git("lfs","pull",cwd=clone,token=self.alice)
        assert (clone/"large.dat").read_bytes()==payload
        assert (clone/"another.dat").read_bytes()==new_payload
        assert (replacement/"lfs"/self.repo["id"]/oid).is_file()
        self.expect(f"/git/alice/demo.git/info/lfs/objects/{oid}/{len(payload)}",200,token=self.alice)
        self.expect(f"/git/alice/demo.git/info/lfs/objects/{oid}/{len(payload)}",404,token=self.bob)
        return {"bytes":len(payload),"recovered_after_source_volume_loss":True,
                "remote_only_pointer_push":True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",default="target/debug/rootyard")
    parser.add_argument("--report",type=Path)
    parser.add_argument("--keep",action="store_true")
    args=parser.parse_args();args.binary=str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL") or not os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"):
        parser.error("ROOTYARD_TEST_DATABASE_URL and S3 object-store environment are required")
    harness=RemoteLfsHarness(args);passed=False
    try:
        harness.case("stock_lfs_second_node_recovery",harness.stock_roundtrip_after_volume_loss)
        passed=True
    except Exception as exc:
        print(harness.redact(traceback.format_exc()),file=sys.stderr)
    finally:
        harness.cleanup()
        report={"passed":passed,"cases":harness.results,
                "binary_sha256":hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
        if args.report:
            args.report.parent.mkdir(parents=True,exist_ok=True)
            args.report.write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report,indent=2))
    return 0 if passed else 1

if __name__=="__main__":sys.exit(main())
