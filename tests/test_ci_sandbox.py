"""Real signed CI claim to isolated local checkout, build, logs and cancellation."""
import argparse
import base64
import json
import os
import socket
import time
import unittest
import urllib.parse
import uuid
from pathlib import Path

from tests.webhooks import WebhooksHarness


class CiSandboxTest(unittest.TestCase):
    def test_claimed_origin_checkout_build_and_cancel(self):
        binary=Path(os.environ.get("ROOTYARD_BINARY","target/debug/rootyard")).resolve()
        h=WebhooksHarness(argparse.Namespace(binary=str(binary),
            keep=os.environ.get("ROOTYARD_KEEP_TEST")=="1"))
        h.env["ROOTYARD_SANDBOX_MODE"]="dev"
        h.env["ROOTYARD_TEST_SANDBOX_GATE_PAUSE_MS"]="750"
        h.env["ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL"]="2"
        h.env["ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO"]="2"
        h.env["ROOTYARD_CI_MIRROR_AUDIENCE"]=str(uuid.uuid4())
        try:
            h.setup()
            secret="ci-sandbox-integration-secret"
            hook=h.document(h.webhookspath,201,method="POST",body={"url":h.receiver.url,
                "secret":secret,"events":["pull_request"],"ci_contexts":["ci/build","ci/cancel"],
                "auto_ci_pin":True})
            for context in ("ci/build","ci/cancel"):
                h.document(f"/api/repos/alice/forge/integrations/{hook['id']}/trusted-contexts",
                    200,method="PUT",body={"context":context})
            pr=h.document(h.pullspath,201,method="POST",body={"title":"CI sandbox",
                "body":"native build","head_ref":"refs/heads/feature","base_ref":"refs/heads/main"})
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                rows=h.sql("SELECT id::text||','||context FROM ci_runs ORDER BY context").splitlines()
                if len(rows)==2:break
                time.sleep(.2)
            self.assertEqual(len(rows),2)
            runs={line.split(',')[1]:line.split(',')[0] for line in rows}
            prefix=f"/api/repos/alice/forge/integrations/{hook['id']}/runs/"
            headers={"Authorization":"Bearer "+secret}

            def claim(run,runner):
                status,raw,_=h.http(prefix+run+"/claim",method="POST",body={"runner_id":runner},
                    extra_headers=headers)
                self.assertEqual(status,200,raw[:300]);return json.loads(raw)
            def tuple_for(value,runner):
                return {"runner_id":runner,"attempt":value["attempt"],
                    "lease_generation":value["lease_generation"],"head_oid":value["head_oid"],
                    "storage_generation":value["storage_generation"]}
            def path(run):return prefix+run+"/sandbox-jobs"
            def wait_done(run,job,params):
                suffix="?"+urllib.parse.urlencode(params)
                deadline=time.monotonic()+25
                while time.monotonic()<deadline:
                    status,raw,_=h.http(path(run)+"/"+job+suffix,extra_headers=headers)
                    self.assertEqual(status,200,raw[:300])
                    result=json.loads(raw)
                    if result["state"] not in ("queued","preparing","running"):return result
                    time.sleep(.1)
                self.fail("CI sandbox did not terminate")

            first=claim(runs["ci/build"],"native-build")
            self.assertEqual(first["source"],"origin")
            params=tuple_for(first,"native-build")
            command=("git rev-parse HEAD; test -f feature.txt; "
                "test -z \"$(git show-ref refs/heads/source-nonff)\"; "
                f"! git cat-file -e {h.diverged_head_oid} 2>/dev/null; "
                "test ! -e /workspace/shared/rootyard-env.sh; "
                "printf 'int main(void){return 0;}\\n' > main.c; "
                "gcc main.c -o app && ./app && echo BUILD_OK; "
                "printf 'CI_TERMINAL_READY\\n'; read line; printf 'CI_INPUT:%s\\n' \"$line\"")
            start_body={**params,"argv":["/bin/sh","-c",command],"timeout_seconds":20,
                "terminal":True}
            encoded=json.dumps(start_body).encode()
            conn=socket.create_connection(("127.0.0.1",h.port),timeout=3)
            request=(f"POST {path(runs['ci/build'])} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                f"Authorization: Bearer {secret}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(encoded)}\r\nConnection: close\r\n\r\n").encode()+encoded
            conn.sendall(request)
            deadline=time.monotonic()+5
            queued=""
            while time.monotonic()<deadline:
                queued=h.sql(f"SELECT state FROM sandbox_jobs WHERE ci_run_id='{runs['ci/build']}'")
                if queued in ("queued","preparing"):break
                time.sleep(.01)
            self.assertIn(queued,("queued","preparing"),"request did not persist before disconnect")
            conn.close()
            status,raw,_=h.http(path(runs["ci/build"]),method="POST",
                body=start_body,extra_headers=headers)
            self.assertEqual(status,201,raw[:300])
            job=json.loads(raw)
            self.assertTrue(job["terminal"])
            terminal_url=path(runs["ci/build"])+"/"+job["id"]+"/terminal"
            suffix="?"+urllib.parse.urlencode(params)
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                status,raw,_=h.http(terminal_url+"/output"+suffix,extra_headers=headers)
                self.assertEqual(status,200,raw[:300])
                if b"CI_TERMINAL_READY" in base64.b64decode(json.loads(raw)["data_base64"]):break
                time.sleep(.05)
            else:self.fail("CI terminal did not reach input prompt")
            self.assertEqual(h.http(terminal_url+"/input"+suffix,method="POST",
                body={"data_base64":base64.b64encode(b"signed-input\n").decode()},
                extra_headers=headers)[0],200)
            outcome=wait_done(runs["ci/build"],job["id"],params)
            self.assertEqual(outcome["state"],"succeeded",(outcome,h.root))
            log_path=path(runs["ci/build"])+"/"+job["id"]+"/logs?"+urllib.parse.urlencode(params)
            status,raw,_=h.http(log_path,extra_headers=headers)
            self.assertEqual(status,200,raw[:300])
            stdout=base64.b64decode(json.loads(raw)["stdout_base64"])
            stderr=base64.b64decode(json.loads(raw)["stderr_base64"])
            self.assertEqual(outcome["state"],"succeeded",(stdout,stderr))
            self.assertIn(first["head_oid"].encode(),stdout)
            self.assertIn(b"BUILD_OK",stdout)
            self.assertIn(b"CI_INPUT:signed-input",stdout)
            self.assertEqual(h.sql(f"SELECT (actor_id IS NULL AND workspace_id IS NULL AND ci_run_id='{runs['ci/build']}')::text "
                f"FROM sandbox_jobs WHERE id='{job['id']}'"),"true")
            self.assertEqual(h.http(f"/api/sandbox-jobs/{job['id']}",token=h.alice)[0],404)
            self.assertEqual(h.http(path(runs["ci/build"]),method="POST",
                body={**params,"lease_generation":params["lease_generation"]+1,
                    "argv":["/bin/true"]},extra_headers=headers)[0],409)
            self.assertNotEqual(h.http(path(runs["ci/build"]),method="POST",
                body={**params,"argv":["/bin/true"]},
                extra_headers={"Authorization":"Bearer "+h.alice["token"]})[0],201)

            second=claim(runs["ci/cancel"],"native-cancel")
            cancel_params=tuple_for(second,"native-cancel")
            status,raw,_=h.http(path(runs["ci/cancel"]),method="POST",
                body={**cancel_params,"argv":["/bin/sh","-c","touch gate-ran; sleep 20"],"timeout_seconds":25},
                extra_headers=headers)
            self.assertEqual(status,201,raw[:300])
            other=json.loads(raw)
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                if h.sql(f"SELECT state FROM sandbox_jobs WHERE id='{other['id']}'")=="running":break
                time.sleep(.02)
            else:self.fail("CI job never reached pre-gate running state")
            suffix="?"+urllib.parse.urlencode(cancel_params)
            self.assertEqual(h.http(path(runs["ci/cancel"])+"/"+other["id"]+suffix,
                method="DELETE",extra_headers=headers)[0],200)
            self.assertEqual(wait_done(runs["ci/cancel"],other["id"],cancel_params)["state"],"cancelled")
            time.sleep(1)
            self.assertFalse((h.root/"data"/"sandbox-jobs"/other["id"]/"workspace"/"gate-ran").exists(),
                "payload ran after cancellation beat the start gate")
        finally:h.cleanup()


if __name__=="__main__":unittest.main()
