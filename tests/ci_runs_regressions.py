#!/usr/bin/env python3
"""Native PostgreSQL/HTTP tests for trusted CI run claims and stale evidence."""
import argparse
import json
import subprocess
import uuid
from pathlib import Path
import sys
import time

from webhooks import WebhooksHarness


def _remaining_seconds(deadline, now=None):
    return max(0.0, deadline - (time.monotonic() if now is None else now))


def _statement_timeout_ms(deadline, now=None):
    remaining = _remaining_seconds(deadline, now)
    return 0 if remaining <= 0 else max(1, int(remaining * 1000))


def _receipt(output):
    lines = [line for line in output.splitlines() if line.startswith("pull-sync-receipt=")]
    if len(lines) != 1:
        return None
    return lines[0].split("=", 1)[1]


def _injection_outcome(returncode, output, timed_out=False):
    if timed_out or returncode != 0:
        return "fail"
    receipt = _receipt(output)
    if receipt == "1,1,1,1,0,0":
        return "applied"
    if receipt == "lock_not_available":
        return "retry_lock"
    return "fail"


def _start_prewarm_trap():
    import http.server
    import threading
    records = []
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            with lock:
                records.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, fmt, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", records, lock


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    untrusted_srv, untrusted_url, untrusted_reqs, untrusted_lock = _start_prewarm_trap()
    allow_srv, allow_url, allow_reqs, allow_lock = _start_prewarm_trap()
    source_sentinel = "ryt_" + "a" * 64
    prewarm_token = "ryt_" + "b" * 64
    h = WebhooksHarness(args)
    h.env["ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL"] = "1"
    h.env["ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO"] = "1"
    h.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = str(uuid.uuid4())
    h.env["ROOTYARD_CI_MIRROR_SOURCE_TOKEN"] = source_sentinel
    h.env["ROOTYARD_CI_MIRROR_PREWARM_ORIGINS"] = allow_url
    h.env["ROOTYARD_CI_MIRROR_PREWARM_TOKEN"] = prewarm_token
    h._prewarm_trap = {
        "untrusted_url": untrusted_url,
        "untrusted_reqs": untrusted_reqs,
        "untrusted_lock": untrusted_lock,
        "allow_url": allow_url,
        "allow_reqs": allow_reqs,
        "allow_lock": allow_lock,
        "source_sentinel": source_sentinel,
        "prewarm_token": prewarm_token,
    }
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
        def psql_until(sql, deadline):
            env=h.env.copy()
            env["PGDATABASE"]=h.db
            budget=_statement_timeout_ms(deadline)
            if budget<=0:
                return None,"","deadline exhausted",True
            env["PGOPTIONS"]=(env.get("PGOPTIONS","").strip()+
                f" -c statement_timeout={budget} -c lock_timeout={budget}").strip()
            argv=["psql","-w","--dbname",env["PGDATABASE"],"-X","-v",
                  "ON_ERROR_STOP=1","-At","-c",sql]
            remaining=_remaining_seconds(deadline)
            if remaining<=0:
                return None,"","deadline exhausted",True
            try:
                p=subprocess.run(argv,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 text=True,timeout=remaining)
            except subprocess.TimeoutExpired:
                return None,"","deadline exceeded",True
            return p.returncode,p.stdout,p.stderr,False

        def psql_error(stderr):
            line=next((line.strip() for line in stderr.splitlines() if line.strip()),"")
            return h.redact(line[:240])

        def psql_value(sql, deadline):
            returncode,stdout,stderr,timed_out=psql_until(sql,deadline)
            if timed_out:
                raise AssertionError("pull-sync fixture: psql deadline exceeded")
            if returncode!=0:
                raise AssertionError("pull-sync fixture: psql failed: "+psql_error(stderr))
            return stdout.strip()

        # The producer writes the completion marker last. Wait on one snapshot
        # covering the current tuple, both contexts and the matching marker.
        def pull_sync_snapshot(deadline):
            row=psql_value(
                "SELECT p.state,p.version,p.head_oid,p.base_oid,repo.storage_generation,"
                "count(r.id),count(r.id) FILTER (WHERE r.context='ci/test'),"
                "count(r.id) FILTER (WHERE r.context='ci/lint'),"
                "(SELECT count(*) FROM ci_pull_sync_progress s WHERE s.repository_id=p.repository_id "
                "AND s.pull_number=p.number AND s.pull_version=p.version AND s.head_oid=p.head_oid "
                "AND s.base_oid=p.base_oid AND s.storage_generation=repo.storage_generation) "
                "FROM forge_pulls p JOIN repositories repo ON repo.id=p.repository_id "
                "LEFT JOIN ci_runs r ON r.repository_id=p.repository_id AND r.pull_number=p.number "
                "AND r.pull_version=p.version AND r.head_oid=p.head_oid AND r.base_oid=p.base_oid "
                "AND r.storage_generation=repo.storage_generation "
                f"WHERE p.repository_id='{pr['repository_id']}' AND p.number={pr['number']} "
                "GROUP BY p.state,p.version,p.head_oid,p.base_oid,repo.storage_generation",
                deadline)
            parts=row.split("|")
            if len(parts)!=9:return "missing_pull",None
            state,version,head,base,generation,runs,test,lint,marker=parts
            runs,test,lint,marker=int(runs),int(test),int(lint),int(marker)
            if state!="open":return "not_open",None
            if head!=new_oid:return "head_not_advanced",None
            if runs<2:return "runs_incomplete",None
            if runs>2:return "runs_extra",None
            if test!=1:return "test_mismatch",None
            if lint!=1:return "lint_mismatch",None
            if marker!=1:return "marker_missing",None
            return "ready",(version,head,base,int(generation))

        deadline=time.monotonic()+15
        state,snapshot=None,None
        while time.monotonic()<deadline:
            state,snapshot=pull_sync_snapshot(deadline)
            if state=="ready":break
            time.sleep(.2)
        assert state=="ready",state
        version,head,base,generation=snapshot
        exact=(f"repository_id='{pr['repository_id']}' AND pull_number={pr['number']} "
               f"AND pull_version={version} AND head_oid='{head}' AND base_oid='{base}' "
               f"AND storage_generation={generation}")
        # Recheck the observed tuple, delete one run and one marker, and prove
        # the post-delete state in the same transaction before committing.
        # The exception subtransaction covers lock acquisition only: a 55P03
        # there is before any delete, while every later error aborts the txn.
        injection_sql=(
            "BEGIN; "
            "DO $rootyard_fixture$ DECLARE tuple_ok int; current_generation bigint; "
            "retry_lock boolean := false; lint_returned int; marker_returned int; "
            "lint_deleted bigint; marker_deleted bigint; run_total bigint; test_total bigint; "
            "lint_total bigint; marker_total bigint; BEGIN "
            "BEGIN "
            f"SELECT 1 INTO tuple_ok FROM forge_pulls WHERE repository_id='{pr['repository_id']}' "
            f"AND number={pr['number']} AND state='open' AND version={version} "
            f"AND head_oid='{head}' AND base_oid='{base}' FOR UPDATE NOWAIT; "
            "IF tuple_ok IS NULL THEN RAISE EXCEPTION 'pull-sync fixture: current tuple drifted'; END IF; "
            f"SELECT storage_generation INTO current_generation FROM repositories "
            f"WHERE id='{pr['repository_id']}' FOR SHARE NOWAIT; "
            f"IF current_generation IS DISTINCT FROM {generation} THEN "
            "RAISE EXCEPTION 'pull-sync fixture: generation drifted'; END IF; "
            "EXECUTE 'LOCK TABLE ci_runs IN SHARE ROW EXCLUSIVE MODE NOWAIT'; "
            "EXECUTE 'LOCK TABLE ci_pull_sync_progress IN SHARE ROW EXCLUSIVE MODE NOWAIT'; "
            "EXCEPTION WHEN lock_not_available THEN retry_lock := true; END; "
            "IF retry_lock THEN "
            "PERFORM set_config('rootyard.fixture_pull_sync_receipt','lock_not_available',true); "
            "ELSE "
            "SELECT count(*),count(*) FILTER (WHERE context='ci/test'),"
            f"count(*) FILTER (WHERE context='ci/lint') INTO run_total,test_total,lint_total "
            f"FROM ci_runs WHERE {exact}; "
            f"SELECT count(*) INTO marker_total FROM ci_pull_sync_progress WHERE {exact}; "
            "IF run_total<>2 OR test_total<>1 OR lint_total<>1 OR marker_total<>1 THEN "
            "RAISE EXCEPTION 'pull-sync fixture: ready state changed'; END IF; "
            f"DELETE FROM ci_runs WHERE {exact} AND context='ci/lint' RETURNING 1 INTO lint_returned; "
            "GET DIAGNOSTICS lint_deleted = ROW_COUNT; "
            "IF lint_deleted<>1 OR lint_returned IS DISTINCT FROM 1 THEN "
            "RAISE EXCEPTION 'pull-sync fixture: lint delete not exact'; END IF; "
            f"DELETE FROM ci_pull_sync_progress WHERE {exact} RETURNING 1 INTO marker_returned; "
            "GET DIAGNOSTICS marker_deleted = ROW_COUNT; "
            "IF marker_deleted<>1 OR marker_returned IS DISTINCT FROM 1 THEN "
            "RAISE EXCEPTION 'pull-sync fixture: marker delete not exact'; END IF; "
            "SELECT count(*),count(*) FILTER (WHERE context='ci/test'),"
            f"count(*) FILTER (WHERE context='ci/lint') INTO run_total,test_total,lint_total "
            f"FROM ci_runs WHERE {exact}; "
            f"SELECT count(*) INTO marker_total FROM ci_pull_sync_progress WHERE {exact}; "
            "IF run_total<>1 OR test_total<>1 OR lint_total<>0 OR marker_total<>0 THEN "
            "RAISE EXCEPTION 'pull-sync fixture: post-delete state'; END IF; "
            "PERFORM set_config('rootyard.fixture_pull_sync_receipt',"
            "lint_deleted::text||','||marker_deleted::text||','||run_total::text||','||"
            "test_total::text||','||lint_total::text||','||marker_total::text,true); "
            "END IF; END $rootyard_fixture$; "
            "SELECT 'pull-sync-receipt='||current_setting('rootyard.fixture_pull_sync_receipt'); "
            "COMMIT;")

        # Only the exact pre-delete lock_not_available receipt is retryable,
        # and only inside the remaining original preparation deadline.
        def inject_pull_sync(deadline):
            while True:
                if _remaining_seconds(deadline)<=0:
                    raise AssertionError("pull-sync fixture: injection preparation window exhausted")
                returncode,stdout,stderr,timed_out=psql_until(injection_sql,deadline)
                outcome=_injection_outcome(returncode,stdout,timed_out)
                if outcome=="applied":return
                if outcome!="retry_lock":
                    detail=psql_error(stderr)
                    raise AssertionError("pull-sync fixture: injection failed closed"+
                                         (": "+detail if detail else ""))
                time.sleep(min(.05,max(0.0,deadline-time.monotonic())))

        inject_pull_sync(deadline)

        def pull_sync_final(deadline):
            row=psql_value(
                "SELECT (p.state='open' AND p.version="+str(version)+" AND p.head_oid='"+head+
                "' AND p.base_oid='"+base+"' AND repo.storage_generation="+str(generation)+")::int,"
                "count(r.id),count(r.id) FILTER (WHERE r.context='ci/test'),"
                "count(r.id) FILTER (WHERE r.context='ci/lint'),"
                "(SELECT count(*) FROM ci_pull_sync_progress s WHERE s.repository_id=p.repository_id "
                "AND s.pull_number=p.number AND s.pull_version=p.version AND s.head_oid=p.head_oid "
                "AND s.base_oid=p.base_oid AND s.storage_generation=repo.storage_generation) "
                "FROM forge_pulls p JOIN repositories repo ON repo.id=p.repository_id "
                "LEFT JOIN ci_runs r ON r.repository_id=p.repository_id AND r.pull_number=p.number "
                "AND r.pull_version=p.version AND r.head_oid=p.head_oid AND r.base_oid=p.base_oid "
                "AND r.storage_generation=repo.storage_generation "
                f"WHERE p.repository_id='{pr['repository_id']}' AND p.number={pr['number']} "
                "GROUP BY p.state,p.version,p.head_oid,p.base_oid,repo.storage_generation",
                deadline)
            parts=row.split("|")
            if len(parts)!=5:return "missing_pull"
            identity,total,test,lint,marker=map(int,parts)
            if identity!=1:return "identity_drift"
            # A duplicate late writer is surfaced as marker_without_lint, not
            # assumed away; only the exact restored tuple is accepted.
            return {(2,1,1,1):"ready",(1,1,0,1):"marker_without_lint",
                    (2,1,1,0):"runs_without_marker",(1,1,0,0):"awaiting_repair"}.get(
                        (total,test,lint,marker),"unexpected")

        deadline=time.monotonic()+15
        state=None
        while time.monotonic()<deadline:
            state=pull_sync_final(deadline)
            if state=="ready":break
            time.sleep(.2)
        assert state=="ready",state
        print("push reconciles PR candidate and creates new runs: passed",flush=True)

        verify_multi_mirror_and_orchestration(h, hook["id"], secret)
        return 0
    finally:
        untrusted_srv.shutdown()
        untrusted_srv.server_close()
        allow_srv.shutdown()
        allow_srv.server_close()
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

    # 1. Unauthenticated heartbeat fails 401 before URL/audience checks;
    #    mirror registration rejects spoofed origin URL, paths, metadata SSRF, and audience mismatch.
    m1_id, m2_id, m3_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    unauth_hb, _, _ = h.http(f"/api/repos/alice/forge/ci-mirrors/{m1_id}/heartbeat",
                             method="POST", token=None, body={
                                 "audience": str(uuid.uuid4()), "url": "origin",
                                 "storage_generation": 1, "ready_oids": [m_oid],
                                 "capacity": 2, "active": True,
                             })
    assert unauth_hb == 401, unauth_hb
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

    # Also verify exclude_sources=['origin'] + prefer_mirror=False + wait_for_ready_ms > 0
    # still blocks until mirror readiness instead of bypassing wait because origin has budget.
    h.document(f"/api/repos/alice/forge/ci-mirrors/{m3_id}/heartbeat", 200, method="POST", body={
        "audience": audience, "url": m3_url, "storage_generation": 1,
        "ready_oids": [], "capacity": 2, "active": True,
    })
    rq_ex, _ = runner(prefix + runs2["ci/test"] + "/failover", {
        "attempt": w_body["attempt"], "lease_generation": w_body["lease_generation"],
        "runner_id": "r1", "requeue_only": True,
    }, code=200)
    assert rq_ex["requeued"] is True
    excl_wait = {}
    def do_excl_wait():
        excl_wait["out"] = runner(prefix + runs2["ci/test"] + "/claim", {
            "runner_id": "r1", "prefer_mirror": False,
            "exclude_sources": ["origin"], "wait_for_ready_ms": 5000,
        }, code=200)
    th_excl = threading.Thread(target=do_excl_wait, daemon=True)
    th_excl.start()
    time.sleep(0.2)
    h.document(f"/api/repos/alice/forge/ci-mirrors/{m3_id}/heartbeat", 200, method="POST", body={
        "audience": audience, "url": m3_url, "storage_generation": 1,
        "ready_oids": [m_oid], "capacity": 2, "active": True,
    })
    th_excl.join(timeout=6)
    ex_body, ex_hdr = excl_wait["out"]
    assert ex_hdr == "ready" and ex_body["source"] == m3_url, (ex_body, ex_hdr)
    w_body = ex_body

    # 6. Disable all mirrors + fill single origin fallback -> overloaded (429), including wait_for_ready_ms=0.
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
    ov0_body, ov0_hdr = runner(prefix + runs2["ci/test"] + "/claim", {
        "runner_id": "r1", "wait_for_ready_ms": 0,
    }, code=429)
    assert ov0_hdr == "overloaded" and ov0_body["classification"] == "overloaded", (ov0_body, ov0_hdr)

    # 6b. Prewarm origin allowlist & credential isolation:
    #     untrusted heartbeat URLs must never receive HTTP prewarm calls or ROOTYARD_CI_MIRROR_SOURCE_TOKEN;
    #     only operator-allowlisted origins receive prewarm with ROOTYARD_CI_MIRROR_PREWARM_TOKEN.
    trap = h._prewarm_trap
    untrusted_id, allow_id = str(uuid.uuid4()), str(uuid.uuid4())
    h.document(f"/api/repos/alice/forge/ci-mirrors/{untrusted_id}/heartbeat", 200, method="POST", body={
        "audience": audience, "url": trap["untrusted_url"], "storage_generation": 1,
        "ready_oids": [], "capacity": 2, "active": True,
    })
    runner(prefix + runs2["ci/test"] + "/claim", {
        "runner_id": "r1", "prefer_mirror": True, "wait_for_ready_ms": 0,
    }, code=202)
    time.sleep(0.4)
    with trap["untrusted_lock"]:
        assert len(trap["untrusted_reqs"]) == 0, trap["untrusted_reqs"]
    h.document(f"/api/repos/alice/forge/ci-mirrors/{untrusted_id}/heartbeat", 200, method="POST", body={
        "audience": audience, "url": trap["untrusted_url"], "storage_generation": 1,
        "ready_oids": [], "capacity": 2, "active": False,
    })
    h.document(f"/api/repos/alice/forge/ci-mirrors/{allow_id}/heartbeat", 200, method="POST", body={
        "audience": audience, "url": trap["allow_url"], "storage_generation": 1,
        "ready_oids": [], "capacity": 2, "active": True,
    })
    runner(prefix + runs2["ci/test"] + "/claim", {
        "runner_id": "r1", "prefer_mirror": True, "wait_for_ready_ms": 0,
    }, code=202)
    until = time.monotonic() + 4
    while time.monotonic() < until:
        with trap["allow_lock"]:
            if trap["allow_reqs"]:
                break
        time.sleep(0.05)
    with trap["allow_lock"]:
        assert len(trap["allow_reqs"]) >= 1, "allowlisted mirror prewarm not delivered"
        req_path, req_hdrs, req_body = trap["allow_reqs"][0]
        assert req_path == "/api/repos/alice/forge/mirror-auto-fetch", req_path
        assert req_hdrs.get("authorization") == f"Bearer {trap['prewarm_token']}", req_hdrs
        assert trap["source_sentinel"].encode() not in req_body
        assert trap["source_sentinel"] not in req_hdrs.get("authorization", "")
    with trap["untrusted_lock"]:
        assert len(trap["untrusted_reqs"]) == 0, trap["untrusted_reqs"]
    h.document(f"/api/repos/alice/forge/ci-mirrors/{allow_id}/heartbeat", 200, method="POST", body={
        "audience": audience, "url": trap["allow_url"], "storage_generation": 1,
        "ready_oids": [], "capacity": 2, "active": False,
    })

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
