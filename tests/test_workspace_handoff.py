"""Committed-checkpoint workspace takeover onto a second volume and FUSE mount."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import tempfile
import time
import unittest

from tests.e2e import Harness
from tests.test_workspace_fuse_service import MOUNT_MODE


@unittest.skipUnless(os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"),"live S3 fixture required")
class WorkspaceHandoffTest(unittest.TestCase):
    def test_expired_host_reattach_from_remote_checkpoint(self):
        binary=Path(os.environ.get("ROOTYARD_TEST_BINARY", "target/debug/rootyard")).resolve()
        with tempfile.TemporaryDirectory(prefix="rootyard-handoff-wrapper-") as wrapper_dir:
            wrapper=Path(wrapper_dir)/"rootyard-userns"
            wrapper.write_text(f"#!/bin/sh\nexec unshare -Urm {shlex.quote(str(binary))} \"$@\"\n")
            wrapper.chmod(0o700)
            h=Harness(argparse.Namespace(binary=str(wrapper),keep=os.environ.get("ROOTYARD_KEEP_TEST")=="1"))
            try:
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"]=MOUNT_MODE
                h.env["ROOTYARD_SANDBOX_MODE"]="dev"
                h.setup();h.api();h.roundtrip()
                ws=json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                    body={"owner":"alice","repository":"demo","agent_id":"handoff","base_oid":h.second},
                    extra_headers={"Idempotency-Key":"handoff-create"}))
                wid=ws["id"]
                path=f"/api/workspaces/{wid}/files?path=hello.txt"
                changed=b"durable across hosts\n"
                h.expect(path,200,token=h.alice,method="PUT",body={
                    "content_base64":base64.b64encode(changed).decode(),"expected_entry_version":0,
                    "expected_workspace_revision":0,"lease_epoch":1},
                    extra_headers={"Idempotency-Key":"handoff-edit"})
                c_source=("#include <stdio.h>\n#include <fcntl.h>\n#include <sys/mman.h>\n"
                    "#include <string.h>\nint main(void){const char expected[]=\"durable across hosts\\n\";"
                    "int fd=open(\"hello.txt\",O_RDONLY);if(fd<0)return 2;"
                    "char *p=mmap(0,sizeof(expected)-1,PROT_READ,MAP_PRIVATE,fd,0);"
                    "if(p==MAP_FAILED || memcmp(p,expected,sizeof(expected)-1))return 3;"
                    "puts(\"MMAP_OK\");return 0;}\n").encode()
                h.expect(f"/api/workspaces/{wid}/files?path=compile.c",200,token=h.alice,
                    method="PUT",body={"content_base64":base64.b64encode(c_source).decode(),
                        "expected_entry_version":0,"expected_workspace_revision":1,"lease_epoch":1},
                    extra_headers={"Idempotency-Key":"handoff-c-source"})
                cp=json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,
                    method="POST",body={"expected_workspace_revision":2,"lease_epoch":1},
                    extra_headers={"Idempotency-Key":"handoff-checkpoint"}))
                self.assertEqual(json.loads(h.expect(f"/api/checkpoints/{cp['checkpoint_id']}/publish",
                    200,token=h.alice,method="POST"))["state"],"COMMITTED")
                h.stop(hard=True)
                source=h.root/"data"
                shutil.rmtree(source)
                h.env["ROOTYARD_DATA_DIR"]=str(h.root/"second-volume")
                h.start()
                self.assertEqual(h.http(f"/api/workspaces/{wid}/lease",token=h.alice,
                    method="POST",body={"expected_lease_epoch":1})[0],409)
                h.sql(f"UPDATE workspaces SET lease_until=clock_timestamp()-interval '1 second' WHERE id='{wid}'")
                self.assertEqual(h.http(f"/api/workspaces/{wid}/lease",token=h.bob,
                    method="POST",body={"expected_lease_epoch":1})[0],404)
                attached=json.loads(h.expect(f"/api/workspaces/{wid}/lease",200,token=h.alice,
                    method="POST",body={"expected_lease_epoch":1}))
                self.assertEqual(attached["lease_epoch"],2)
                lower=Path(h.env["ROOTYARD_DATA_DIR"])/"workspace-service/workspaces"/wid
                self.assertEqual((lower/"hello.txt").stat().st_blocks,0)
                self.assertEqual((lower/"hello.txt").read_bytes(),b"\0"*len(changed))
                cache=Path(h.env["ROOTYARD_DATA_DIR"])/"workspace-service/lazy-cache"/wid
                self.assertEqual(list(cache.iterdir()),[])
                warmed=json.loads(h.expect(f"/api/workspaces/{wid}/prewarm",200,token=h.alice,
                    method="POST",body={"paths":["compile.c"]}))
                self.assertEqual(warmed["hydrated_files"],1)
                self.assertEqual((cache/hashlib.sha256(c_source).hexdigest()).read_bytes(),c_source)
                endpoint=h.env["ROOTYARD_OBJECT_STORE_ENDPOINT"]
                h.stop();h.env["ROOTYARD_OBJECT_STORE_ENDPOINT"]="http://127.0.0.1:1"
                h.env["ROOTYARD_WORKSPACE_LAZY_TIMEOUT_MS"]="300";h.start()
                self.assertEqual(base64.b64decode(json.loads(h.expect(f"/api/workspaces/{wid}/files?path=compile.c",
                    200,token=h.alice))["content_base64"]),c_source)
                offline_started=time.monotonic()
                self.assertEqual(h.http(path,token=h.alice)[0],503)
                self.assertLess(time.monotonic()-offline_started,5)
                h.stop();h.env.pop("ROOTYARD_WORKSPACE_LAZY_TIMEOUT_MS",None)
                h.env["ROOTYARD_OBJECT_STORE_ENDPOINT"]=endpoint;h.start()
                command="set -e; git grep -q 'durable' -- hello.txt & a=$!; "
                command+="cat hello.txt & b=$!; wait \"$a\"; wait \"$b\"; gcc compile.c -o app; ./app; "
                command+="printf 'dirty\\n' > compile.c; mv hello.txt moved.txt; cat moved.txt"
                job=json.loads(h.expect(f"/api/workspaces/{wid}/sandbox-jobs",201,token=h.alice,
                    method="POST",body={"argv":["/bin/sh","-c",command],"timeout_seconds":20,
                        "lease_epoch":2,"workspace_access":"live"}))
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    result=json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}",200,token=h.alice))
                    if result["state"] not in ("queued","running"):break
                    time.sleep(.1)
                self.assertEqual(result["state"],"succeeded",result)
                logs=json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}/logs",200,token=h.alice))
                self.assertIn(b"MMAP_OK",base64.b64decode(logs["stdout_base64"]))
                self.assertEqual(base64.b64decode(json.loads(h.expect(f"/api/workspaces/{wid}/files?path=moved.txt",
                    200,token=h.alice))["content_base64"]),changed)
                self.assertEqual((lower/"hello.txt").read_bytes(),b"\0"*len(changed))
                self.assertEqual((cache/hashlib.sha256(changed).hexdigest()).read_bytes(),changed)
                self.assertEqual((cache/hashlib.sha256(c_source).hexdigest()).read_bytes(),c_source)
                self.assertFalse(source.exists())
                stale={"content_base64":base64.b64encode(b"stale").decode(),
                    "expected_entry_version":1,"expected_workspace_revision":2,"lease_epoch":1}
                self.assertEqual(h.http(path,token=h.alice,method="PUT",body=stale,
                    extra_headers={"Idempotency-Key":"stale-handoff"})[0],409)
            finally:h.cleanup()


if __name__=="__main__":unittest.main()
