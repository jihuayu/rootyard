#!/usr/bin/env python3
"""Real HTTP/PostgreSQL maintenance-job observability contract.

Covers role-gated reads, bounded keyset pagination with a repository-scoped
opaque cursor, the optional state filter, detail lookup, cross-repository
isolation, and a job produced by the real scheduler/worker on a native volume.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness

JOB_KEYS = {"id", "kind", "state", "attempt", "repository_generation", "progress",
            "result", "error", "created_at", "updated_at", "completed_at"}
LEAK_KEYS = {"lease_owner", "lease_until", "claim_generation", "tenant_id",
             "not_before", "repository_id"}
KINDS = {"gitfs_stage_cleanup", "gitfs_repack", "gitfs_cache_hydrate",
         "gitfs_cache_evict", "gitfs_unreachable_mark", "gitfs_tombstone_delete"}
STATES = ("queued", "running", "succeeded", "failed")


class MaintenanceJobsHarness(Harness):
    def repo(self, name, token=None):
        return json.loads(self.expect("/api/repos", 201, method="POST",
                                      token=token or self.alice, body={"name": name}))

    def tenant(self, repo_id):
        return self.sql("SELECT owner_id FROM repositories WHERE id='" + repo_id + "'")

    def insert_job(self, repo_id, kind, state="queued", attempt=0, age=0,
                   created=None, progress="{}", result=None, error=None):
        job = str(uuid.uuid4())
        assert kind in KINDS and state in STATES
        lease_owner = "'" + str(uuid.uuid4()) + "'" if state == "running" else "NULL"
        lease_until = "clock_timestamp() + interval '1 hour'" if state == "running" else "NULL"
        completed = "clock_timestamp()" if state in ("succeeded", "failed") else "NULL"
        stamp = "'" + created + "'::timestamptz" if created else \
            "clock_timestamp() - interval '" + str(age) + " seconds'"
        self.sql("INSERT INTO storage_maintenance_jobs (id,repository_id,tenant_id,kind,state,"
                 "repository_generation,attempt,claim_generation,lease_owner,lease_until,"
                 "progress,result,last_error,created_at,updated_at,completed_at) VALUES ('"
                 + job + "','" + repo_id + "','" + self.tenant(repo_id) + "','" + kind + "','"
                 + state + "',1," + str(attempt) + ",7," + lease_owner + "," + lease_until + ",'"
                 + progress + "'::jsonb,"
                 + ("'" + result + "'::jsonb" if result else "NULL") + ","
                 + ("'" + error + "'" if error else "NULL") + "," + stamp
                 + ",clock_timestamp()," + completed + ")")
        return job

    def jobs(self, path, token=None, code=200, **params):
        query = "&".join(f"{k}={v}" for k, v in params.items())
        body = self.expect(path + ("?" + query if query else ""), code,
                           token=token if token is not None else self.alice)
        if code != 200:
            return body
        page = json.loads(body)
        assert set(page) == {"items", "next_after"}, page
        for job in page["items"]:
            assert set(job) == JOB_KEYS, job
            assert not (LEAK_KEYS & set(job)), job
            assert job["state"] in STATES, job
            assert job["kind"] in KINDS, job
            for field in ("created_at", "updated_at"):
                assert isinstance(job[field], str) and job[field], job
            assert job["completed_at"] is None or isinstance(job["completed_at"], str)
            assert isinstance(job["progress"], dict), job
        return page

    def job_detail(self, path, job, token=None, code=200):
        body = self.expect(path + "/" + job, code,
                           token=token if token is not None else self.alice)
        if code != 200:
            return body
        detail = json.loads(body)
        assert set(detail) == JOB_KEYS, detail
        assert not (LEAK_KEYS & set(detail)), detail
        assert detail["id"] == job
        return detail

    def fixtures(self):
        self.maint = self.repo("maint-jobs")
        self.other = self.repo("other-maint")
        bob_repo = self.repo("bob-maint", token=self.bob)
        self.maint_path = "/api/repos/alice/maint-jobs/maintenance-jobs"
        self.other_path = "/api/repos/alice/other-maint/maintenance-jobs"
        self.bob_path = "/api/repos/bob/bob-maint/maintenance-jobs"
        # Two rows share one created_at so the id tiebreak is exercised.
        tie = self.sql("SELECT (clock_timestamp() - interval '500 seconds')::text")
        self.inserted = {}
        self.inserted["succeeded"] = self.insert_job(
            self.maint["id"], "gitfs_repack", "succeeded", attempt=1, age=60,
            progress='{"phase":"succeeded","attempt":1}', result='{"repacked":true}')
        self.inserted["failed"] = self.insert_job(
            self.maint["id"], "gitfs_unreachable_mark", "failed", attempt=5, age=120,
            progress='{"phase":"failed"}', error="synthetic fsck failure")
        self.inserted["queued"] = self.insert_job(
            self.maint["id"], "gitfs_stage_cleanup", "queued", age=30,
            progress='{"phase":"queued"}')
        self.inserted["running"] = self.insert_job(
            self.maint["id"], "gitfs_cache_hydrate", "running", attempt=1, age=10,
            progress='{"phase":"executing","attempt":1}')
        self.tie = [self.insert_job(self.maint["id"], "gitfs_cache_hydrate", "succeeded",
                                    attempt=1, created=tie, result='{"commit_graph":"written"}'),
                    self.insert_job(self.maint["id"], "gitfs_stage_cleanup", "succeeded",
                                    attempt=2, created=tie)]
        # Older successes keep the fixture ordering long enough for offset gaps.
        for index in range(12):
            self.insert_job(self.maint["id"], "gitfs_stage_cleanup", "succeeded",
                            attempt=1, age=600 + index * 10,
                            result='{"staging_files_deleted":0}')
        self.many = self.repo("many-maint")
        for _ in range(30):
            self.insert_job(self.many["id"], "gitfs_stage_cleanup", "succeeded", attempt=1)
        self.other_jobs = [self.insert_job(self.other["id"], "gitfs_repack", "succeeded",
                                          attempt=1, result='{"repacked":true}'),
                           self.insert_job(self.other["id"], "gitfs_stage_cleanup", "queued")]
        self.bob_job = self.insert_job(bob_repo["id"], "gitfs_stage_cleanup", "succeeded", attempt=1)
        return "One repository with all four states plus an exact created_at tie, a 30-row " \
               "repository, and foreign-repository jobs"

    def detail(self):
        for state, job in self.inserted.items():
            detail = self.job_detail(self.maint_path, job)
            assert detail["state"] == state, detail
            assert detail["kind"] in KINDS
            assert detail["repository_generation"] == 1
            assert detail["attempt"] == (0 if state == "queued" else (5 if state == "failed" else 1)), detail
            if state in ("succeeded", "failed"):
                assert detail["completed_at"] is not None, detail
            else:
                assert detail["completed_at"] is None, detail
            if state in ("queued", "running"):
                assert detail["result"] is None, detail
            assert (detail["error"] is not None) == (state == "failed"), detail
        # Foreign and unknown job identities are indistinguishable from absence.
        for path, job in ((self.maint_path, self.other_jobs[0]),
                          (self.maint_path, self.bob_job),
                          (self.maint_path, str(uuid.uuid4()))):
            self.job_detail(path, job, code=404)
        self.job_detail(self.maint_path, "not-a-uuid", code=400)
        return "Detail returns durable identity/progress/result/error/timestamps without lease " \
               "capabilities; foreign and unknown ids are 404"

    def pagination(self):
        # Authoritative durable order: newest first, id descending on a tie.
        ids = self.sql("SELECT string_agg(id::text, ',') FROM (SELECT id FROM "
                       "storage_maintenance_jobs WHERE repository_id='" + self.maint["id"]
                       + "' ORDER BY created_at DESC, id DESC) t").split(",")
        assert len(ids) == 4 + 2 + 12, len(ids)
        reference = self.jobs(self.maint_path, limit=100)["items"]
        assert [job["id"] for job in reference] == ids
        assert set(self.tie) <= set(ids)
        # Every fixed-size page concatenates to the unpaginated ordering.
        for size in (1, 2, 3, 5, 7, 100):
            collected, cursor, pages = [], None, 0
            while True:
                params = {"limit": size}
                if cursor:
                    params["after"] = cursor
                page = self.jobs(self.maint_path, **params)
                pages += 1
                collected.extend(page["items"])
                if page["next_after"] is None:
                    break
                assert pages <= len(reference) + 1, "pagination did not terminate"
                cursor = page["next_after"]
            assert [job["id"] for job in collected] == ids, (size, len(collected))
        last = reference[-1]["id"]
        tail = self.jobs(self.maint_path, after="v1:" + last, limit=3)
        assert tail == {"items": [], "next_after": None}, tail
        # The state filter is applied before limit+1 on every page.
        for state in STATES:
            expected = [job["id"] for job in reference if job["state"] == state]
            collected, cursor = [], None
            while True:
                params = {"limit": 1, "state": state}
                if cursor:
                    params["after"] = cursor
                page = self.jobs(self.maint_path, **params)
                assert all(job["state"] == state for job in page["items"]), page
                collected.extend(job["id"] for job in page["items"])
                if page["next_after"] is None:
                    break
                cursor = page["next_after"]
            assert collected == expected, (state, collected, expected)
        # Bounded default and explicit limits.
        default = self.jobs("/api/repos/alice/many-maint/maintenance-jobs")
        assert len(default["items"]) == 25 and default["next_after"], len(default["items"])
        full = self.jobs("/api/repos/alice/many-maint/maintenance-jobs", limit=100)
        assert len(full["items"]) == 30 and full["next_after"] is None
        single = self.jobs("/api/repos/alice/many-maint/maintenance-jobs", limit=1)
        assert single["next_after"] == "v1:" + single["items"][0]["id"], single
        # Cursors are repository-scoped positions, never other repositories' rows.
        for foreign in (self.other_jobs[0], self.bob_job, str(uuid.uuid4())):
            self.jobs(self.maint_path, after="v1:" + foreign, code=400)
            self.jobs(self.bob_path, after="v1:" + foreign, code=400, token=self.bob)
        return "Pages of every size reproduce one newest-first order including an exact " \
               "timestamp tie; state filter, 25/100 bounds and repository-scoped cursors hold"

    def rejected_queries(self):
        for query in ("limit=0", "limit=101", "limit=-1", "limit=", "limit=1.5",
                      "state=", "state=all", "state=Open", "state=queued&state=running",
                      "after=", "after=1", "after=v1:", "after=v1:not-a-uuid",
                      "after=" + str(uuid.uuid4()), "extra=1", "Limit=1", "state=queued&extra=1"):
            self.expect(self.maint_path + "?" + query, 400, token=self.alice)
        return "Malformed, duplicate, unknown, out-of-range and non-canonical cursor " \
               "queries are rejected before any read"

    def access(self):
        self.jobs(self.maint_path, token=self.alice)
        self.job_detail(self.maint_path, self.inserted["queued"], token=self.alice)
        # No credentials or a mismatched Basic username never authorize.
        self.expect(self.maint_path, 401)
        self.expect(self.maint_path, 401, token={**self.alice, "username": "bob"}, basic=True)
        # A read-only token is refused even for the repository owner.
        self.jobs(self.maint_path, token=self.reader, code=403)
        self.job_detail(self.maint_path, self.inserted["queued"], token=self.reader, code=403)
        # Unrelated private repositories stay 404 for both endpoints.
        self.jobs(self.maint_path, token=self.bob, code=404)
        self.job_detail(self.maint_path, self.bob_job, token=self.bob, code=404)
        self.jobs(self.bob_path, token=self.alice, code=404)
        self.jobs("/api/repos/alice/missing/maintenance-jobs", code=404)
        self.jobs("/api/repos/alice/missing/maintenance-jobs", token=self.bob, code=404)
        # read/triage/write collaborators cannot inspect; maintain/admin can.
        for role, code in (("read", 403), ("triage", 403), ("write", 403),
                           ("maintain", 200), ("admin", 200)):
            self.expect(self.maint_path + "/collaborators/bob",
                        (200, 201), token=self.alice, method="PUT", body={"role": role})
            self.jobs(self.maint_path, token=self.bob, code=code)
            self.job_detail(self.maint_path, self.inserted["queued"], token=self.bob, code=code)
            # Maintain/admin cannot use a cursor from another repository either.
            self.jobs(self.maint_path, token=self.bob, after="v1:" + self.other_jobs[0],
                      code=code if code == 403 else 400)
        # A revoked token is rechecked, not cached.
        token = self.account("create-token", "alice")
        self.sql("UPDATE tokens SET revoked=true WHERE id='" + token["token_id"] + "'")
        self.expect(self.maint_path, 401, token=token)
        headers = dict((k.lower(), v) for k, v in self.http(self.maint_path, token=self.alice)[2].items())
        assert headers.get("cache-control") == "no-store", headers
        return "Owner read-only tokens are 403, read/triage/write collaborators are 403, " \
               "maintain/admin can read, unauthorized private access stays 404"

    def scheduler_visibility(self):
        self.stop()
        self.env.update(ROOTYARD_STORAGE_MAINTENANCE="true",
                        ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS="1",
                        ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS="1",
                        ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS="5")
        self.start()
        repo = self.repo("live-maint")
        remote = self.base + repo["clone_path"]
        work = self.root / "live-work"
        self.git("clone", remote, str(work), token=self.alice)
        self.git("config", "user.name", "Alice", cwd=work)
        self.git("config", "user.email", "alice@rootyard.local", cwd=work)
        (work / "README.md").write_text("durable maintenance\n")
        self.git("add", "README.md", cwd=work)
        self.git("commit", "-m", "maintenance observability", cwd=work)
        self.git("push", "origin", "HEAD:main", cwd=work, token=self.alice)
        path = "/api/repos/alice/live-maint/maintenance-jobs"
        until = time.monotonic() + 30
        found = None
        while time.monotonic() < until and found is None:
            for job in self.jobs(path, limit=100)["items"]:
                if job["kind"] == "gitfs_stage_cleanup" and job["state"] == "succeeded":
                    found = job
                    break
            time.sleep(.2)
        assert found, "scheduler/worker job never became observable: " + self.sql(
            "SELECT coalesce(jsonb_agg(jsonb_build_object('kind',kind,'state',state))::text,'[]') "
            "FROM storage_maintenance_jobs WHERE repository_id='" + repo["id"] + "'")
        assert found["attempt"] >= 1, found
        detail = self.job_detail(path, found["id"])
        assert detail["kind"] == found["kind"] and detail["state"] == "succeeded", detail
        assert detail["progress"].get("phase") == "succeeded", detail
        assert detail["completed_at"], detail
        return {"observable_job": found["id"], "kind": found["kind"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    h = MaintenanceJobsHarness(args)
    passed = False
    try:
        for name in ("setup", "fixtures", "detail", "pagination", "rejected_queries",
                     "access", "scheduler_visibility"):
            h.case(name, getattr(h, name))
        passed = True
    except Exception:
        print(h.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        h.cleanup()
    report = {"passed": passed, "cases": h.results,
              "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
              "limitations": [
                  "Keyset pages are live views, not snapshots across requests.",
                  "The scheduler case covers one native push on a loopback server; it is not a "
                  "throughput or multi-node qualification.",
                  "No index is added for the newest-first ordering, so planner choice is not fixed."]}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
