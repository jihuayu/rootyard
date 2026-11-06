#!/usr/bin/env python3
"""Cancel a real, backpressured Git LFS download during a CI checkout."""
import argparse
import hashlib
import http.client
from pathlib import Path
import sys
import time
import uuid

from ci_job_checkouts import JobCheckoutHarness


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary",default="target/debug/rootyard")
    parser.add_argument("--keep",action="store_true")
    args=parser.parse_args();args.binary=str(Path(args.binary).resolve())
    h=JobCheckoutHarness(args)
    h.mirror_env["ROOTYARD_CI_MIRROR_PUBLIC_URL"]=h.mirror_base
    try:
        h.setup_mirror()
        h.git("lfs","install","--local",cwd=h.work)
        h.git("lfs","track","large.bin",cwd=h.work)
        payload=b"LFS revocation fixture 32MiB\n"*1157049
        (h.work/"large.bin").write_bytes(payload)
        h.git("add",".gitattributes","large.bin",cwd=h.work)
        h.git("commit","-m","large CI input",cwd=h.work)
        oid=h.git("rev-parse","HEAD",cwd=h.work).stdout.decode().strip()
        h.git("push","origin","HEAD:main",cwd=h.work,token=h.alice)
        object_oid=hashlib.sha256(payload).hexdigest()
        assert h.sql("SELECT state FROM lfs_objects WHERE repository_id='"+h.repo["id"]+
            "' AND oid='"+object_oid+"'")=="ready"
        job=str(uuid.uuid4())
        h.pin(h.pin_body(oid,job,1))
        grant=h.issue(h.request_body(oid=oid,job=job))
        prepare=f"/api/repos/alice/demo/ci-checkouts/{job}/prepare-dependencies"
        h.mirror_expect(prepare,200,token=h.alice,method="POST",body=b"")
        path=f"/ci/{oid}/git/alice/demo.git/info/lfs/objects/{object_oid}"
        connection=http.client.HTTPConnection(h.mirror_env["ROOTYARD_BIND"],timeout=8)
        connection.request("GET",path,headers={"Authorization":"Bearer "+grant["token"]})
        response=connection.getresponse()
        assert response.status==200 and int(response.getheader("Content-Length"))==len(payload)
        first=response.read(1024)
        assert first==payload[:1024]
        started=time.monotonic()
        h.transition(job,"cancel")
        time.sleep(1.5)
        try:
            remainder=response.read()
            received=len(first)+len(remainder)
        except (http.client.IncompleteRead,OSError) as error:
            received=len(first)+len(getattr(error,"partial",b""))
        elapsed=time.monotonic()-started
        connection.close()
        assert received<len(payload),(received,len(payload))
        assert elapsed<5,(elapsed,received)
        denied,_,_=h.mirror_http(path,token={"username":"alice","token":grant["token"]})
        assert denied in (401,403),denied
        print(f"active Git LFS cancellation: {received}/{len(payload)} bytes, {elapsed:.3f}s",flush=True)
        return 0
    finally:h.cleanup()


if __name__=="__main__":sys.exit(main())
