#!/usr/bin/env python3
"""Native PostgreSQL/HTTP tests for trusted CI run claims and stale evidence."""
import argparse
import json
import uuid
from pathlib import Path
import sys
import time

from webhooks import WebhooksHarness


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    h = WebhooksHarness(args)
    h.env["ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL"] = "1"
    h.env["ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO"] = "1"
    h.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = str(uuid.uuid4())
    try:
        h.setup()
        secret = "synthetic-runner-secret-123"
        hook = h.document(h.webhookspath, 201, method="POST", body={
            "url":h.receiver.url,"secret":secret,"events":["pull_request"],
            "ci_contexts":["ci/test","ci/lint"],"auto_ci_pin":True})
        for context in ("ci/test","ci/lint"):
            h.document(h.webhookspath+f"/{hook['id']}", 200)  # registration exists
            h.document(f"/api/repos/alice/forge/integrations/{hook['id']}/trusted-contexts",
                200,method="PUT",body={"context":context})
        h.document(h.rulespath,201,method="POST",body={"branch_ref":"refs/heads/main",
            "required_approvals":0,"required_checks":["ci/test","ci/lint"]})
        pr=h.document(h.pullspath,201,method="POST",body={"title":"CI candidate",
            "body":"fenced run","head_ref":"refs/heads/feature","base_ref":"refs/heads/main"})
        assert pr["head_oid"]==h.feat1_oid
        run_rows=h.sql("SELECT id::text||','||context FROM ci_runs ORDER BY context").splitlines()
        assert len(run_rows)==2,run_rows
        runs={line.split(',')[1]:line.split(',')[0] for line in run_rows}
        direct=h.http(h.checkspath,token=h.alice,method="POST",body={
            "commit_oid":h.feat1_oid,"context":"ci/test","status":"completed",
            "conclusion":"success","attempt":1,"sequence":2,"output":"fake"})
        assert direct[0]==403,direct
        print("direct trusted-context impersonation rejected: passed",flush=True)

        def runner(path,body,code=200):
            status,raw,_=h.http(path,method="POST",body=body,
                extra_headers={"Authorization":"Bearer "+secret})
            assert status==code,(status,raw[:200])
            return json.loads(raw)

        prefix=f"/api/repos/alice/forge/integrations/{hook['id']}/runs/"
        first=runner(prefix+runs["ci/test"]+"/claim",{"runner_id":"runner-a"})
        assert first["head_oid"]==h.feat1_oid and first["source"]=="origin",first
        runner(prefix+runs["ci/lint"]+"/claim",{"runner_id":"runner-b"},429)
        stale=runner(prefix+runs["ci/test"]+"/report",{"attempt":first["attempt"],
            "lease_generation":first["lease_generation"]+1,"conclusion":"success","output":"ok"},409)
        assert stale["error"]
        body={"attempt":first["attempt"],"lease_generation":first["lease_generation"],
            "conclusion":"success","output":"ok"}
        runner(prefix+runs["ci/test"]+"/report",body)
        replay=runner(prefix+runs["ci/test"]+"/report",body)
        assert replay["replay"] is True
        second=runner(prefix+runs["ci/lint"]+"/claim",{"runner_id":"runner-b"})
        runner(prefix+runs["ci/lint"]+"/report",{"attempt":second["attempt"],
            "lease_generation":second["lease_generation"],"conclusion":"success","output":"ok"})
        checks=h.document(f"{h.pullspath}/{pr['number']}/checks")["items"]
        assert {c["context"]:c["conclusion"] for c in checks}.get("ci/test")=="success"
        print("run attempt fence, origin budget, idempotent report: passed",flush=True)

        h.git("checkout","feature",cwd=h.work)
        (h.work/"feature.txt").write_text("new candidate\n")
        h.git("commit","-am","new candidate",cwd=h.work)
        new_oid=h.git("rev-parse","HEAD",cwd=h.work).stdout.decode().strip()
        h.git("push","origin","HEAD:refs/heads/feature",cwd=h.work,token=h.alice)
        until=time.monotonic()+15
        while time.monotonic()<until:
            new_pr=h.document(f"{h.pullspath}/{pr['number']}")
            if new_pr["head_oid"]==new_oid:break
            time.sleep(.2)
        assert new_pr["head_oid"]==new_oid,new_pr
        new_runs=h.sql(f"SELECT count(*) FROM ci_runs WHERE repository_id='{pr['repository_id']}' AND head_oid='{new_oid}'")
        assert new_runs=="2",new_runs
        print("push reconciles PR candidate and creates new runs: passed",flush=True)
        return 0
    finally:
        h.cleanup()


if __name__=="__main__":
    sys.exit(main())
