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

    def _hook_with_contexts(self, h, contexts):
        secret = "ci-sandbox-integration-secret"
        hook = h.document(h.webhookspath, 201, method="POST", body={"url": h.receiver.url,
            "secret": secret, "events": ["pull_request"], "ci_contexts": contexts,
            "auto_ci_pin": True})
        for context in contexts:
            h.document(f"/api/repos/alice/forge/integrations/{hook['id']}/trusted-contexts",
                200, method="PUT", body={"context": context})
        return hook, secret

    def _claims(self, h, hook, secret, contexts, runners):
        h.document(h.pullspath, 201, method="POST", body={"title": "CI isolation",
            "body": "two tasks", "head_ref": "refs/heads/feature", "base_ref": "refs/heads/main"})
        deadline = time.monotonic() + 10
        rows = []
        while time.monotonic() < deadline:
            rows = h.sql("SELECT id::text||','||context FROM ci_runs ORDER BY context").splitlines()
            if len(rows) == len(contexts):
                break
            time.sleep(.2)
        self.assertEqual(len(rows), len(contexts))
        runs = {line.split(',')[1]: line.split(',')[0] for line in rows}
        headers = {"Authorization": "Bearer " + secret}
        claims = {}
        for context, runner in zip(contexts, runners):
            status, raw, _ = h.http(f"/api/repos/alice/forge/integrations/{hook['id']}/runs/{runs[context]}/claim",
                method="POST", body={"runner_id": runner}, extra_headers=headers)
            self.assertEqual(status, 200, raw[:300])
            claims[context] = (json.loads(raw), runs[context], headers)
        return claims

    @staticmethod
    def _tuple(value):
        return {"runner_id": value["runner_id"], "attempt": value["attempt"],
            "lease_generation": value["lease_generation"], "head_oid": value["head_oid"],
            "storage_generation": value["storage_generation"]}

    def test_two_concurrent_claims_isolated_build_and_export(self):
        binary = Path(os.environ.get("ROOTYARD_BINARY", "target/debug/rootyard")).resolve()
        h = WebhooksHarness(argparse.Namespace(binary=str(binary), keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1"))
        h.env["ROOTYARD_SANDBOX_MODE"] = "dev"
        h.env["ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL"] = "4"
        h.env["ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO"] = "2"
        h.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = str(uuid.uuid4())
        try:
            h.setup()
            hook, secret = self._hook_with_contexts(h, ["ci/a", "ci/b"])
            claims = self._claims(h, hook, secret, ["ci/a", "ci/b"], ["isolate-a", "isolate-b"])
            base = f"/api/repos/alice/forge/integrations/{hook['id']}/runs"
            jobs = {}
            for context, mark, other in (("ci/a", "nonce-a", "own-b.txt"), ("ci/b", "nonce-b", "own-a.txt")):
                value, run, headers = claims[context]
                command = ("git rev-parse HEAD; test -f feature.txt; "
                    f"printf %s {mark} > /workspace/{mark}.txt; mkdir -p /artifacts; "
                    f"printf %s {mark} > /artifacts/who.txt; "
                    "printf 'int main(void){return 0;}\\n' > main.c; gcc main.c -o app && ./app; "
                    f"test ! -e /workspace/{other}; ! grep -qs {other} /workspace /tmp /home; "
                    "env | sort; test ! -e /var/run/docker.sock; test ! -e /root; "
                    "test -z \"$DATABASE_URL\"; test -z \"$ROOTYARD_SANDBOX_MODE\"; echo BUILD_OK")
                status, raw, _ = h.http(base + "/" + run + "/sandbox-jobs", method="POST",
                    body={**self._tuple(value), "argv": ["/bin/sh", "-c", command],
                        "timeout_seconds": 20}, extra_headers=headers)
                self.assertEqual(status, 201, raw[:300])
                jobs[context] = json.loads(raw)
            import concurrent.futures

            def wait(context):
                value, run, headers = claims[context]
                suffix = "?" + urllib.parse.urlencode(self._tuple(value))
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    status, raw, _ = h.http(base + "/" + run + "/sandbox-jobs/" + jobs[context]["id"] + suffix,
                        extra_headers=headers)
                    self.assertEqual(status, 200, raw[:300])
                    result = json.loads(raw)
                    if result["state"] not in ("queued", "preparing", "running"):
                        return result
                    time.sleep(.1)
                self.fail("CI sandbox did not terminate")

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = dict(zip(("ci/a", "ci/b"), pool.map(wait, ("ci/a", "ci/b"))))
            for context, mark in (("ci/a", "nonce-a"), ("ci/b", "nonce-b")):
                value, run, headers = claims[context]
                self.assertEqual(outcomes[context]["state"], "succeeded", h.root)
                suffix = "?" + urllib.parse.urlencode(self._tuple(value))
                status, raw, _ = h.http(base + "/" + run + "/sandbox-jobs/" + jobs[context]["id"] + "/logs" + suffix,
                    extra_headers=headers)
                self.assertEqual(status, 200, raw[:300])
                stdout = base64.b64decode(json.loads(raw)["stdout_base64"])
                self.assertIn(value["head_oid"].encode(), stdout)
                self.assertIn(b"BUILD_OK", stdout)
                self.assertIn(b"PATH=/usr/bin:/bin", stdout)
                self.assertIn(b"TMPDIR=/tmp", stdout)
                self.assertNotIn(b"DATABASE_URL", stdout)
                self.assertNotIn(b"ROOTYARD_", stdout)
                artifact_url = (base + "/" + run + "/sandbox-jobs/" + jobs[context]["id"]
                    + "/artifacts?" + urllib.parse.urlencode({**self._tuple(value), "path": "who.txt"}))
                status, raw, _ = h.http(artifact_url, extra_headers=headers)
                self.assertEqual(status, 200, raw[:300])
                content = base64.b64decode(json.loads(raw)["artifact"]["content_base64"])
                self.assertEqual(content, mark.encode())
                job_root = h.root / "data" / "sandbox-jobs" / jobs[context]["id"]
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and (job_root / "checkout").exists():
                    time.sleep(.05)
                self.assertFalse((job_root / "checkout").exists(), "CI checkout copy was not reclaimed")
                self.assertTrue((job_root / "artifacts" / "who.txt").is_file())
            value_a, run_a, headers_a = claims["ci/a"]
            value_b, run_b, headers_b = claims["ci/b"]
            swapped = "?" + urllib.parse.urlencode(self._tuple(value_b))
            self.assertEqual(h.http(base + "/" + run_a + "/sandbox-jobs/" + jobs["ci/a"]["id"] + swapped,
                extra_headers=headers_a)[0], 409)
            suffix = "?" + urllib.parse.urlencode(self._tuple(value_a))
            status, raw, _ = h.http(base + "/" + run_a + "/sandbox-jobs/" + jobs["ci/a"]["id"] + "/cleanup" + suffix,
                method="POST", extra_headers=headers_a)
            self.assertEqual(status, 200, raw[:300])
            self.assertTrue(json.loads(raw)["removed"])
            self.assertEqual(h.http(base + "/" + run_a + "/sandbox-jobs/" + jobs["ci/a"]["id"] + "/logs" + suffix,
                extra_headers=headers_a)[0], 404)
        finally:
            h.cleanup()

    def test_fenced_retry_requires_new_attempt(self):
        binary = Path(os.environ.get("ROOTYARD_BINARY", "target/debug/rootyard")).resolve()
        h = WebhooksHarness(argparse.Namespace(binary=str(binary), keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1"))
        h.env["ROOTYARD_SANDBOX_MODE"] = "dev"
        h.env["ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL"] = "4"
        h.env["ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO"] = "2"
        h.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = str(uuid.uuid4())
        try:
            h.setup()
            hook, secret = self._hook_with_contexts(h, ["ci/retry"])
            claims = self._claims(h, hook, secret, ["ci/retry"], ["retry-runner"])
            first, run, headers = claims["ci/retry"]
            base = f"/api/repos/alice/forge/integrations/{hook['id']}/runs/{run}/sandbox-jobs"
            first_tuple = self._tuple(first)
            status, raw, _ = h.http(base, method="POST",
                body={**first_tuple, "argv": ["/bin/sh", "-c",
                    "printf 'first-attempt\\n'; mkdir -p /artifacts; printf first > /artifacts/who.txt"],
                    "timeout_seconds": 20}, extra_headers=headers)
            self.assertEqual(status, 201, raw[:300])
            first_job = json.loads(raw)["id"]
            suffix = "?" + urllib.parse.urlencode(first_tuple)
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                status, raw, _ = h.http(base + "/" + first_job + suffix, extra_headers=headers)
                self.assertEqual(status, 200, raw[:300])
                if json.loads(raw)["state"] not in ("queued", "preparing", "running"):
                    break
                time.sleep(.1)
            self.assertEqual(json.loads(raw)["state"], "succeeded")
            self.assertEqual(h.sql(f"SELECT attempt||','||lease_generation FROM ci_runs WHERE id='{run}'"), "1,1")
            h.sql(f"UPDATE ci_runs SET lease_expires_unix=0 WHERE id='{run}'")
            status, raw, _ = h.http(f"/api/repos/alice/forge/integrations/{hook['id']}/runs/{run}/claim",
                method="POST", body={"runner_id": "retry-runner"}, extra_headers=headers)
            self.assertEqual(status, 200, raw[:300])
            second = json.loads(raw)
            self.assertGreater(second["attempt"], first["attempt"])
            self.assertGreater(second["lease_generation"], first["lease_generation"])
            second_tuple = self._tuple(second)
            self.assertEqual(h.http(base + "/" + first_job + suffix, extra_headers=headers)[0], 409)
            new_suffix = "?" + urllib.parse.urlencode(second_tuple)
            self.assertEqual(h.http(base + "/" + first_job + new_suffix, extra_headers=headers)[0], 404)
            self.assertEqual(h.http(base + "/" + first_job + "/logs" + new_suffix, extra_headers=headers)[0], 404)
            self.assertEqual(h.http(base + "/" + first_job + "/cleanup" + new_suffix,
                method="POST", extra_headers=headers)[0], 404)
            status, raw, _ = h.http(base, method="POST",
                body={**second_tuple, "argv": ["/bin/sh", "-c",
                    "printf 'second-attempt\\n'; mkdir -p /artifacts; printf second > /artifacts/who.txt"],
                    "timeout_seconds": 20}, extra_headers=headers)
            self.assertEqual(status, 201, raw[:300])
            second_job = json.loads(raw)["id"]
            self.assertNotEqual(first_job, second_job)
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                status, raw, _ = h.http(base + "/" + second_job + new_suffix, extra_headers=headers)
                self.assertEqual(status, 200, raw[:300])
                if json.loads(raw)["state"] not in ("queued", "preparing", "running"):
                    break
                time.sleep(.1)
            self.assertEqual(json.loads(raw)["state"], "succeeded")
            status, raw, _ = h.http(base + "/" + second_job + "/logs" + new_suffix, extra_headers=headers)
            self.assertIn(b"second-attempt", base64.b64decode(json.loads(raw)["stdout_base64"]))
            self.assertEqual(h.sql(f"SELECT attempt||','||lease_generation FROM ci_runs WHERE id='{run}'"), "2,2")
            self.assertEqual(h.sql(f"SELECT state||','||attempt||','||lease_generation FROM sandbox_jobs WHERE id='{first_job}'"),
                "succeeded,1,1")
            self.assertEqual(h.sql(f"SELECT attempt||','||lease_generation FROM sandbox_jobs WHERE id='{second_job}'"),
                "2,2")
            h.stop()
            h.env["ROOTYARD_SANDBOX_RETENTION_SECONDS"] = "0"
            h.start()
            for job_id in (first_job, second_job):
                root = h.root / "data" / "sandbox-jobs" / job_id
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and root.exists():
                    time.sleep(.05)
                self.assertFalse(root.exists(), "terminal CI root was not reaped")
            self.assertEqual(h.http(base + "/" + second_job + "/logs" + new_suffix, extra_headers=headers)[0], 404)
            self.assertEqual(h.http(base + "/" + second_job + new_suffix, extra_headers=headers)[0], 200)
        finally:
            h.cleanup()


if __name__=="__main__":unittest.main()
