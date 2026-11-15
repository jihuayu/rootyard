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
        service=h.sql("SELECT count(*) FROM git_operations WHERE repository_id='"+
            pr["repository_id"]+"' AND service_principal_id IS NOT NULL AND actor_id IS NULL "+
            "AND token_id IS NULL AND evidence->>'kind'='observed_immutable_ci_root'")
        assert service=="1",service
        human=h.sql("SELECT count(*) FROM outbox_events e JOIN git_operations o "+
            "ON o.id=e.operation_id WHERE e.repository_id='"+pr["repository_id"]+
            "' AND o.actor_id IS NOT NULL")
        assert int(human)>0,human
        import hashlib
        forged_event=hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        bad_ref=("INSERT INTO outbox_events(event_id,operation_id,repository_id,"
            "storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid) "
            f"SELECT '{forged_event}',id,repository_id,storage_generation,sequence,2,"
            f"'refs/heads/forged',repeat('0',40),'{h.feat1_oid}' FROM git_operations "
            f"WHERE repository_id='{pr['repository_id']}' AND service_principal_id IS NOT NULL")
        try:h.sql(bad_ref)
        except AssertionError:pass
        else:raise AssertionError("CI service journal accepted an unrelated ref")
        principal=h.sql("SELECT service_principal_id FROM git_operations WHERE repository_id='"+
            pr["repository_id"]+"' AND service_principal_id IS NOT NULL")
        bad_operation=("INSERT INTO git_operations(id,repository_id,service_principal_id,actor_name,"
            "sequence,storage_generation,outcome,evidence) VALUES("+
            f"'{uuid.uuid4()}','{pr['repository_id']}','{principal}','ci-scheduler',"
            "(SELECT coalesce(max(sequence),0)+1 FROM git_operations WHERE repository_id='"+
            pr["repository_id"]+"'),1,'unknown','{\"kind\":\"observed_immutable_ci_root\"}'::jsonb)")
        try:h.sql(bad_operation)
        except AssertionError:pass
        else:raise AssertionError("CI service journal accepted missing intent")
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
        assert first["checkout"]["plan"]["target_oid"]==h.feat1_oid
        assert first["checkout"]["token"].startswith("ryj_")
        digest=h.sql("SELECT encode(credential_digest,'hex') FROM ci_integration_checkout_jobs "+
            "WHERE run_id='"+runs["ci/test"]+"' AND attempt=1")
        assert digest==hashlib.sha256(first["checkout"]["token"].encode()).hexdigest()
        runner(prefix+runs["ci/test"]+"/heartbeat",{"attempt":first["attempt"],
            "lease_generation":first["lease_generation"],"runner_id":"runner-a"})
        runner(prefix+runs["ci/test"]+"/heartbeat",{"attempt":first["attempt"],
            "lease_generation":first["lease_generation"],"runner_id":"wrong"},409)
        runner(prefix+runs["ci/lint"]+"/claim",{"runner_id":"runner-b"},429)
        stale=runner(prefix+runs["ci/test"]+"/report",{"attempt":first["attempt"],
            "lease_generation":first["lease_generation"]+1,"conclusion":"success","output":"ok"},409)
        assert stale["error"]
        body={"attempt":first["attempt"],"lease_generation":first["lease_generation"],
            "conclusion":"success","output":"ok"}
        runner(prefix+runs["ci/test"]+"/report",body)
        replay=runner(prefix+runs["ci/test"]+"/report",body)
        assert replay["replay"] is True
        runner(prefix+runs["ci/test"]+"/report",{**body,
            "lease_generation":body["lease_generation"]+1},409)
        runner(prefix+runs["ci/test"]+"/report",{**body,
            "attempt":body["attempt"]+1},409)
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
            new_runs=h.sql(f"SELECT count(*) FROM ci_runs WHERE repository_id='{pr['repository_id']}' AND head_oid='{new_oid}'")
            if new_pr["head_oid"]==new_oid and new_runs=="2":break
            time.sleep(.2)
        assert new_pr["head_oid"]==new_oid,new_pr
        assert new_runs=="2",new_runs
        h.sql(f"DELETE FROM ci_runs WHERE repository_id='{pr['repository_id']}' AND "
              f"pull_number={pr['number']} AND pull_version={new_pr['version']} "
              "AND context='ci/lint'")
        h.sql(f"DELETE FROM ci_pull_sync_progress WHERE repository_id='{pr['repository_id']}' "
              f"AND pull_number={pr['number']} AND pull_version={new_pr['version']}")
        until=time.monotonic()+15
        while time.monotonic()<until:
            repaired=h.sql(f"SELECT count(*) FROM ci_runs WHERE repository_id='{pr['repository_id']}' "
                f"AND pull_number={pr['number']} AND pull_version={new_pr['version']}")
            if repaired=="2":break
            time.sleep(.2)
        assert repaired=="2",repaired
        print("push reconciles PR candidate and creates new runs: passed",flush=True)

        verify_multi_mirror_and_orchestration(h, hook["id"], secret)
        return 0
    finally:
        h.cleanup()


def verify_multi_mirror_and_orchestration(h, hook_id, secret):
    import threading
    h.git("checkout", "-b", "feature-multi", "main", cwd=h.work)
    (h.work / "multi.txt").write_text("multi-mirror fixture\n")
    h.git("add", "multi.txt", cwd=h.work)
    h.git("commit", "-m", "multi-mirror candidate", cwd=h.work)
    m_oid = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
    h.git("push", "origin", "HEAD:refs/heads/feature-multi", cwd=h.work, token=h.alice)
    pr2 = h.document(h.pullspath, 201, method="POST", body={
        "title": "Multi-mirror orchestration", "body": "m2",
        "head_ref": "refs/heads/feature-multi", "base_ref": "refs/heads/main",
    })
    assert pr2["head_oid"] == m_oid
    run_rows = h.sql(
        f"SELECT id::text||','||context FROM ci_runs WHERE repository_id='{pr2['repository_id']}' "
        f"AND pull_number={pr2['number']} AND head_oid='{m_oid}' ORDER BY context"
    ).splitlines()
    assert len(run_rows) == 2, run_rows
    runs2 = {line.split(",")[1]: line.split(",")[0] for line in run_rows}
    prefix = f"/api/repos/alice/forge/integrations/{hook_id}/runs/"
    audience = h.env["ROOTYARD_CI_MIRROR_AUDIENCE"]

    def runner(path, body=None, code=200, method="POST"):
        status, raw, hdrs = h.http(path, method=method, body=body,
                                   extra_headers={"Authorization": "Bearer " + secret})
        assert status == code, (path, status, raw[:240])
        ci_state = {k.lower(): v for k, v in hdrs.items()}.get("x-rootyard-ci-state")
        return json.loads(raw), ci_state

    # 1. Mirror registration rejects spoofed origin URL, paths, metadata SSRF, and audience mismatch.
    m1_id, m2_id, m3_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    for bad_url in ("origin", "https://127.0.0.1:18101/path", "http://169.254.169.254"):
        st, _, _ = h.http(f"/api/repos/alice/forge/ci-mirrors/{m1_id}/heartbeat",
                          method="POST", token=h.alice, body={
                              "audience": audience, "url": bad_url,
                              "storage_generation": 1, "ready_oids": [m_oid],
                              "capacity": 2, "active": True,
                          })
        assert st == 400, (bad_url, st)
    st, _, _ = h.http(f"/api/repos/alice/forge/ci-mirrors/{m1_id}/heartbeat",
                      method="POST", token=h.alice, body={
                          "audience": str(uuid.uuid4()), "url": "http://127.0.0.1:18101",
                          "storage_generation": 1, "ready_oids": [m_oid],
                          "capacity": 2, "active": True,
                      })
    assert st == 409, st

    m1_url, m2_url, m3_url = "http://127.0.0.1:18101", "http://127.0.0.1:18102", "http://127.0.0.1:18103"
    for mid, url, oids in ((m1_id, m1_url, [m_oid]), (m2_id, m2_url, [m_oid]), (m3_id, m3_url, [])):
        h.document(f"/api/repos/alice/forge/ci-mirrors/{mid}/heartbeat", 200,
                   method="POST", body={
                       "audience": audience, "url": url, "storage_generation": 1,
                       "ready_oids": oids, "capacity": 2, "active": True,
                   })
    mirror_list = h.document(f"/api/repos/alice/forge/ci-mirrors?target_oid={m_oid}", 200)
    assert len(mirror_list["mirrors"]) == 3, mirror_list
    # Verify inspect reports explicit X-Rootyard-CI-State: ready.
    inspected, state_hdr = runner(prefix + runs2["ci/test"], method="GET", code=200)
    assert state_hdr == "ready" and inspected["classification"] == "ready", (inspected, state_hdr)

    # 2. Multi-mirror selection load balances active leases across mirror-1 and mirror-2.
    c1, st1 = runner(prefix + runs2["ci/test"] + "/claim", {"runner_id": "r1"})
    c2, st2 = runner(prefix + runs2["ci/lint"] + "/claim", {"runner_id": "r2"})
    assert st1 == "ready" and st2 == "ready"
    assert {c1["source"], c2["source"]} == {m1_url, m2_url}, (c1["source"], c2["source"])

    # 3. Mid-job failover moves run off failed_source onto healthy alternate and fences old attempt.
    other_mirror = m2_url if c1["source"] == m1_url else m1_url
    runner(prefix + runs2["ci/test"] + "/failover", {
        "attempt": c1["attempt"], "lease_generation": c1["lease_generation"],
        "runner_id": "r1", "failed_source": other_mirror,
    }, code=409)
    fo, fo_hdr = runner(prefix + runs2["ci/test"] + "/failover", {
        "attempt": c1["attempt"], "lease_generation": c1["lease_generation"],
        "runner_id": "r1", "failed_source": c1["source"], "reason": "mirror reset",
    }, code=200)
    assert fo_hdr == "ready" and fo["previous_source"] == c1["source"]
    assert fo["source"] == other_mirror and fo["attempt"] == 2 and fo["lease_generation"] == 2
    runner(prefix + runs2["ci/test"] + "/heartbeat", {
        "attempt": c1["attempt"], "lease_generation": c1["lease_generation"], "runner_id": "r1",
    }, code=409)

    # 4. Requeue-only failover returns waiting state and clears lease cleanly.
    rq, rq_hdr = runner(prefix + runs2["ci/test"] + "/failover", {
        "attempt": fo["attempt"], "lease_generation": fo["lease_generation"],
        "runner_id": "r1", "requeue_only": True,
    }, code=200)
    assert rq_hdr == "waiting" and rq["requeued"] is True and rq["state"] == "queued"

    # 5. Disable ready mirrors so m3 (unready) exists, verify prefer_mirror=True classifies waiting (202)
    #    and wait_for_ready_ms wakes immediately once m3 heartbeats readiness.
    for mid, url in ((m1_id, m1_url), (m2_id, m2_url)):
        h.document(f"/api/repos/alice/forge/ci-mirrors/{mid}/heartbeat", 200, method="POST", body={
            "audience": audience, "url": url, "storage_generation": 1,
            "ready_oids": [], "capacity": 2, "active": False,
        })
    wait_resp, wait_hdr = runner(prefix + runs2["ci/test"] + "/claim", {
        "runner_id": "r1", "prefer_mirror": True,
    }, code=202)
    assert wait_hdr == "waiting" and wait_resp["classification"] == "waiting", (wait_resp, wait_hdr)

    wait_result = {}
    def do_wait_claim():
        wait_result["out"] = runner(prefix + runs2["ci/test"] + "/claim", {
            "runner_id": "r1", "prefer_mirror": True, "wait_for_ready_ms": 5000,
        }, code=200)
    th = threading.Thread(target=do_wait_claim, daemon=True)
    th.start()
    time.sleep(0.2)
    h.document(f"/api/repos/alice/forge/ci-mirrors/{m3_id}/heartbeat", 200, method="POST", body={
        "audience": audience, "url": m3_url, "storage_generation": 1,
        "ready_oids": [m_oid], "capacity": 2, "active": True,
    })
    th.join(timeout=6)
    w_body, w_hdr = wait_result["out"]
    assert w_hdr == "ready" and w_body["source"] == m3_url, (w_body, w_hdr)

    # 6. Disable all mirrors + fill single origin fallback -> overloaded (429).
    h.document(f"/api/repos/alice/forge/ci-mirrors/{m3_id}/heartbeat", 200, method="POST", body={
        "audience": audience, "url": m3_url, "storage_generation": 1,
        "ready_oids": [], "capacity": 2, "active": False,
    })
    h.sql(f"UPDATE ci_runs SET state='leased',source_url='origin',runner_id='r-held',"
          f"lease_expires_unix=extract(epoch FROM clock_timestamp())::bigint+60 "
          f"WHERE id='{runs2['ci/lint']}'")
    rq2, _ = runner(prefix + runs2["ci/test"] + "/failover", {
        "attempt": w_body["attempt"], "lease_generation": w_body["lease_generation"],
        "runner_id": "r1", "requeue_only": True,
    }, code=200)
    assert rq2["requeued"] is True
    ov_body, ov_hdr = runner(prefix + runs2["ci/test"] + "/claim", {"runner_id": "r1"}, code=429)
    assert ov_hdr == "overloaded" and ov_body["classification"] == "overloaded", (ov_body, ov_hdr)

    # 7. Background reconcile_runs reaps expired lease back to queued preserving m_oid,
    #    and PR close cancels remaining queued/leased runs durably.
    h.sql(f"UPDATE ci_runs SET lease_expires_unix=0 WHERE id='{runs2['ci/lint']}'")
    until = time.monotonic() + 12
    reaped = ""
    while time.monotonic() < until:
        reaped = h.sql(f"SELECT state||','||head_oid FROM ci_runs WHERE id='{runs2['ci/lint']}'")
        if reaped == f"queued,{m_oid}":
            break
        time.sleep(0.2)
    assert reaped == f"queued,{m_oid}", reaped

    closed = h.document(f"{h.pullspath}/{pr2['number']}", 200, method="PATCH", body={
        "expected_version": pr2["version"], "state": "closed",
    })
    assert closed["state"] == "closed"
    until = time.monotonic() + 12
    cancelled = "0"
    while time.monotonic() < until:
        cancelled = h.sql(
            f"SELECT count(*) FROM ci_runs WHERE repository_id='{pr2['repository_id']}' "
            f"AND pull_number={pr2['number']} AND state='cancelled'"
        )
        if cancelled == "2":
            break
        time.sleep(0.2)
    assert cancelled == "2", cancelled
    print("multi-mirror routing, failover, wait wakeup, overload, reap, cancel: passed", flush=True)


if __name__=="__main__":
    sys.exit(main())
