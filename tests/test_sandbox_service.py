"""Native bwrap sandbox lifecycle over the Rust HTTP service and PostgreSQL."""
import argparse
import base64
import json
import time
import unittest

from tests.e2e import Harness


class SandboxServiceTest(unittest.TestCase):
    def test_isolated_jobs_logs_cancel_and_timeout(self):
        h=Harness(argparse.Namespace(binary="target/debug/rootyard",keep=False))
        try:
            h.env["ROOTYARD_SANDBOX_MODE"]="dev"
            h.setup(); h.api(); h.roundtrip()
            h.stop()
            h.sql("ALTER TABLE sandbox_jobs DROP COLUMN terminal; DELETE FROM schema_migrations WHERE version=115")
            h.start()
            self.assertEqual(h.sql("SELECT count(*) FROM information_schema.columns WHERE table_name='sandbox_jobs' AND column_name='terminal'"),"1")
            ws=json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                body={"owner":"alice","repository":"demo","agent_id":"sandbox-parent","base_oid":h.second},
                extra_headers={"Idempotency-Key":"sandbox-parent"}))
            def start(argv,timeout=10,terminal=False):
                return json.loads(h.expect(f"/api/workspaces/{ws['id']}/sandbox-jobs",201,token=h.alice,method="POST",
                    body={"argv":argv,"timeout_seconds":timeout,"lease_epoch":1,"terminal":terminal}))
            jobs=[start(["/bin/sh","-c",f"printf {mark} > task.txt; mkdir artifacts; cp task.txt artifacts/result.txt; ln -s ../task.txt artifacts/escape; cat hello.txt; test ! -e /root; test ! -e /workspace/shared/rootyard-env.sh"])
                  for mark in ("one","two")]
            def done(job):
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    data=json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}",200,token=h.alice))
                    if data["state"] not in ("queued","running"): return data
                    time.sleep(.1)
                self.fail("sandbox did not terminate")
            for job in jobs:
                logs=json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}/logs",200,token=h.alice))
                self.assertEqual(done(job)["state"],"succeeded",base64.b64decode(logs["stderr_base64"]))
                self.assertIn(b"second",base64.b64decode(logs["stdout_base64"]))
                self.assertEqual(h.http(f"/api/sandbox-jobs/{job['id']}/logs",token=h.bob)[0],404)
                artifact=json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}/artifacts?path=result.txt",200,token=h.alice))
                self.assertIn(base64.b64decode(artifact["content_base64"]),(b"one",b"two"))
                self.assertEqual(h.http(f"/api/sandbox-jobs/{job['id']}/artifacts?path=result.txt",token=h.bob)[0],404)
                self.assertEqual(h.http(f"/api/sandbox-jobs/{job['id']}/artifacts?path=escape",token=h.alice)[0],404)
            roots=[h.root/"data/sandbox-jobs"/j["id"]/"workspace" for j in jobs]
            self.assertEqual([(p/"task.txt").read_text() for p in roots],["one","two"])
            self.assertFalse((h.root/"data/workspace-service/workspaces"/ws["id"]/"task.txt").exists())
            slow=start(["/bin/sh","-c","sleep 20"],timeout=10)
            self.assertEqual(json.loads(h.expect(f"/api/sandbox-jobs/{slow['id']}/stop",200,token=h.alice,method="POST"))["state"],"cancelled")
            timed=start(["/bin/sh","-c","sleep 20"],timeout=1)
            self.assertEqual(done(timed)["state"],"timed_out")
            interactive=start(["/bin/sh","-c", "for fd in /proc/self/fd/*; do "
                "case \"$fd\" in /proc/self/fd/[012]) ;; *) "
                "test \"$(readlink \"$fd\")\" != /dev/ptmx || exit 88 ;; esac; done; "
                "printf 'ready\\n'; read line; stty size; printf 'got:%s\\n' \"$line\""],terminal=True)
            self.assertTrue(interactive["terminal"])
            url=f"/api/sandbox-jobs/{interactive['id']}/terminal"
            self.assertEqual(h.http(url+"/output",token=h.bob)[0],404)
            self.assertEqual(h.http(f"/api/sandbox-jobs/{jobs[0]['id']}/terminal/output",token=h.alice)[0],404)
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                output=json.loads(h.expect(url+"/output?offset=0",200,token=h.alice))
                if b"ready" in base64.b64decode(output["data_base64"]):break
                time.sleep(.05)
            else:self.fail("terminal did not produce prompt")
            h.expect(url+"/resize",200,token=h.alice,method="POST",body={"rows":31,"columns":97})
            h.expect(url+"/input",200,token=h.alice,method="POST",
                body={"data_base64":base64.b64encode(b"hello\n").decode()})
            self.assertEqual(done(interactive)["state"],"succeeded")
            output=json.loads(h.expect(url+"/output?offset=0",200,token=h.alice))
            data=base64.b64decode(output["data_base64"])
            self.assertIn(b"31 97",data)
            self.assertIn(b"got:hello",data)
            self.assertEqual(h.http(url+"/input",token=h.alice,method="POST",
                body={"data_base64":base64.b64encode(b"later\n").decode()})[0],409)
        finally:
            h.cleanup()


if __name__=="__main__": unittest.main()
