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
            ws=json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                body={"owner":"alice","repository":"demo","agent_id":"sandbox-parent","base_oid":h.second},
                extra_headers={"Idempotency-Key":"sandbox-parent"}))
            def start(argv,timeout=10):
                return json.loads(h.expect(f"/api/workspaces/{ws['id']}/sandbox-jobs",201,token=h.alice,method="POST",
                    body={"argv":argv,"timeout_seconds":timeout,"lease_epoch":1}))
            jobs=[start(["/bin/sh","-c",f"printf {mark} > task.txt; cat hello.txt; test ! -e /root; test ! -e /workspace/shared/rootyard-env.sh"])
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
            roots=[h.root/"data/sandbox-jobs"/j["id"]/"workspace" for j in jobs]
            self.assertEqual([(p/"task.txt").read_text() for p in roots],["one","two"])
            self.assertFalse((h.root/"data/workspace-service/workspaces"/ws["id"]/"task.txt").exists())
            slow=start(["/bin/sh","-c","sleep 20"],timeout=10)
            self.assertEqual(json.loads(h.expect(f"/api/sandbox-jobs/{slow['id']}/stop",200,token=h.alice,method="POST"))["state"],"cancelled")
            timed=start(["/bin/sh","-c","sleep 20"],timeout=1)
            self.assertEqual(done(timed)["state"],"timed_out")
        finally:
            h.cleanup()


if __name__=="__main__": unittest.main()
