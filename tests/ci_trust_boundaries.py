#!/usr/bin/env python3
"""Native trusted-issuer, run, lease and callback boundary matrix.

This is a real-service checkpoint over the existing managed PostgreSQL and Git
fixtures in ``WebhooksHarness``. It uses two repositories, two trusted contexts
and two webhook issuers so the same context name must resolve independently by
repository. Positive report and signed-callback flows run first for both
repositories; every negative below then asserts an exact status and error.

Current semantics intentionally covered:
* a write collaborator cannot write a bound check context through the direct API;
* an issuer cannot claim/report outside its own repository, context or run;
* revoking a trusted-context binding or disabling a webhook refuses a current
  lease report, and an exact old signed-callback replay is refused after the
  binding is revoked;
* rotating the webhook secret (the integration bearer credential) refuses the
  old secret for a current lease report and for replaying an old callback;
* changing the PR head invalidates old report/callback replay and old evidence;
* a late report from a superseded attempt cannot overwrite the current attempt,
  while an exact duplicate of the current valid report remains idempotent.

API token revocation is tested only where a token is the acting principal:
revoking an API token denies later webhook-management calls. A registered
webhook has no persisted creator-token binding in this schema, so an API-token
revocation is not represented as revoking the webhook's independent secret.
This harness does not claim that unsupported binding.

Concurrency limitation: the claim/heartbeat, post-Git callback, and merge
rechecks are serialized by the policy advisory fence, but this harness does not
install a test-only pause inside checkout preparation or Git verification.
It proves the end-state refusals and current code paths, not a specific
overlapping interleaving.

Required environment (same as the other native CI harnesses):
ROOTYARD_TEST_DATABASE_URL, a trusted Git executable, and a Linux PostgreSQL 17
fixture. Root can run the focused command:

    python3 tests/ci_trust_boundaries.py --binary target/debug/rootyard

This file deliberately does not edit the shared CI workflow or
tests/ci_runs_regressions.py, which is owned by a parallel task. Report
source/binary binding and the CI gate are a separate integration checkpoint;
do not treat a local syntax check as a native pass.
"""
import argparse
import json
from pathlib import Path
import sys
import threading
import time

from webhooks import WebhooksHarness


REPOSITORIES = ("forge", "other")
CONTEXTS = ("ci/trusted", "ci/aux")


class TrustBoundaryHarness(WebhooksHarness):
    def q(self, value):
        return "'" + str(value).replace("'", "''") + "'"

    def setup(self):
        self.env["ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL"] = "16"
        self.env["ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO"] = "8"
        self.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = "f4b6bac2-3e5c-4d6f-8a4f-4a7c6f2d9e11"
        # Pull reconciliation is performed by the explicit PATCH below, so a
        # background round cannot advance the PR between a read and its use.
        self.env["ROOTYARD_OUTBOX_WORKER"] = "false"
        super().setup()
        self.base_oids = {"forge": self.base_oid, "other": self.other_base_oid}
        self.head_v1 = {"forge": self.feat1_oid, "other": self.other_feat_oid}
        self.work_dirs = {"forge": self.work, "other": self.root / "work-alice-other"}
        self.pull_paths = {
            repo: f"/api/repos/alice/{repo}/pulls" for repo in REPOSITORIES
        }
        self.branch_paths = {
            repo: f"/api/repos/alice/{repo}/branch-rules" for repo in REPOSITORIES
        }
        self.checks_paths = {
            repo: f"/api/repos/alice/{repo}/checks" for repo in REPOSITORIES
        }
        self.issuers = {}
        self.pulls = {}
        self.runs_v1 = {}
        self.callback_v1 = {}

    def pull_path(self, repo, number=None):
        number = self.pulls[repo]["number"] if number is None else number
        return f"{self.pull_paths[repo]}/{number}"

    def hook_path(self, repo, hook):
        return f"/api/repos/alice/{repo}/webhooks/{hook['id']}"

    def bind_path(self, repo, hook):
        return f"/api/repos/alice/{repo}/integrations/{hook['id']}/trusted-contexts"

    def run_path(self, repo, hook, run, action):
        return (
            f"/api/repos/alice/{repo}/integrations/{hook['id']}"
            f"/runs/{run['id']}/{action}"
        )

    def callback_path(self, repo, hook):
        return f"/api/repos/alice/{repo}/integrations/{hook['id']}/check-runs"

    def configure(self):
        self.writer = self.issue_token("writer", create_user=True)
        for repo in REPOSITORIES:
            for index, context in enumerate(CONTEXTS):
                secret = f"trusted-{repo}-{index}-secret-0123456789"
                self.secrets.append(secret)
                hook = self.document(
                    f"/api/repos/alice/{repo}/webhooks",
                    201,
                    method="POST",
                    body={
                        "url": self.receiver.url,
                        "secret": secret,
                        "events": ["pull_request"],
                        "ci_contexts": [context],
                        "auto_ci_pin": True,
                    },
                    extra_headers={"Idempotency-Key": f"trusted-hook-{repo}-{index}"},
                )
                hook["_secret"] = secret
                hook["_context"] = context
                self.document(
                    self.bind_path(repo, hook),
                    200,
                    method="PUT",
                    body={"context": context},
                )
                self.issuers[(repo, context)] = hook
            self.document(
                self.branch_paths[repo],
                201,
                method="POST",
                body={
                    "branch_ref": "refs/heads/main",
                    "required_approvals": 0,
                    "required_checks": list(CONTEXTS),
                    "require_fast_forward": True,
                },
            )
            self.document(
                f"/api/repos/alice/{repo}/collaborators/{self.writer['username']}",
                (200, 201),
                method="PUT",
                body={"role": "write"},
            )
            self.pulls[repo] = self.document(
                self.pull_paths[repo],
                201,
                method="POST",
                body={
                    "title": f"trusted boundary {repo}",
                    "body": "same candidate inputs before negative checks",
                    "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main",
                },
            )
            assert self.pulls[repo]["head_oid"] == self.head_v1[repo], self.pulls[repo]
            assert self.pulls[repo]["base_oid"] == self.base_oids[repo], self.pulls[repo]
            self.runs_v1[repo] = self.wait_runs(repo, self.head_v1[repo], CONTEXTS)

    def runs_for(self, repo, head):
        repo_id = self.repo["id"] if repo == "forge" else self.other["id"]
        raw = self.sql(
            "SELECT coalesce(json_agg(json_build_object("
            "'context',context,'id',id::text,'job_id',job_id::text,"
            "'pull_number',pull_number,'pull_version',pull_version,"
            "'state',state,'attempt',attempt,'lease_generation',lease_generation,"
            "'head_oid',head_oid,'base_oid',base_oid) ORDER BY context),"
            f"'[]'::json)::text FROM ci_runs WHERE repository_id={self.q(repo_id)} "
            f"AND head_oid={self.q(head)}"
        )
        return {row["context"]: row for row in json.loads(raw)}

    def wait_runs(self, repo, head, contexts, deadline=10.0):
        stop = time.monotonic() + deadline
        last = None
        while True:
            last = self.runs_for(repo, head)
            if all(context in last for context in contexts):
                return last
            if time.monotonic() >= stop:
                raise AssertionError(
                    f"{repo} {head} never queued exactly {contexts}: {last}"
                )
            time.sleep(0.05)

    def check_row(self, repo, head, context):
        repo_id = self.repo["id"] if repo == "forge" else self.other["id"]
        raw = self.sql(
            "SELECT coalesce(json_agg(json_build_object("
            "'attempt',attempt,'sequence',sequence,'status',status,"
            "'conclusion',conclusion,'output',output,"
            "'issuer_webhook_id',issuer_webhook_id::text,"
            "'ci_run_id',ci_run_id::text,'ci_base_oid',ci_base_oid,"
            "'ci_lease_generation',ci_lease_generation)),'[]'::json)::text "
            f"FROM forge_check_runs WHERE repository_id={self.q(repo_id)} "
            f"AND commit_oid={self.q(head)} AND context={self.q(context)}"
        )
        rows = json.loads(raw)
        assert len(rows) == 1, (repo, head, context, rows)
        return rows[0]

    def integration(self, path, secret, body, code):
        status, raw, headers = self.http(
            path,
            method="POST",
            body=body,
            extra_headers={"Authorization": "Bearer " + secret},
        )
        norm = {key.lower(): value for key, value in headers.items()}
        assert status == code, (path, status, raw[:300])
        assert norm.get("cache-control") == "no-store", norm
        assert "application/json" in norm.get("content-type", ""), norm
        parsed = json.loads(raw)
        assert isinstance(parsed, dict), (path, status, raw[:200])
        return parsed

    def refuse(self, path, secret, body, code, error):
        parsed = self.integration(path, secret, body, code)
        assert parsed.get("error") == error, (path, code, parsed)
        return parsed

    def claim(self, repo, hook, run, runner):
        return self.integration(
            self.run_path(repo, hook, run, "claim"),
            hook["_secret"],
            {"runner_id": runner},
            200,
        )

    def report_body(self, claimed, conclusion="success", output="trusted report"):
        return {
            "attempt": claimed["attempt"],
            "lease_generation": claimed["lease_generation"],
            "conclusion": conclusion,
            "output": output,
        }

    def callback_body(self, run, claimed, event_id, conclusion="success"):
        return {
            "event_id": event_id,
            "commit_oid": run["head_oid"],
            "context": run["context"],
            "status": "completed",
            "conclusion": conclusion,
            "attempt": claimed["attempt"],
            "sequence": 2,
            "output": "trusted callback",
            "pull_number": run["pull_number"],
            "ci_run_id": run["id"],
            "ci_job_id": run["job_id"],
            "base_oid": run["base_oid"],
            "lease_generation": claimed["lease_generation"],
        }

    def signed_callback(self, repo, hook, body, code):
        return super().signed_callback(
            self.callback_path(repo, hook), hook["_secret"], body, code=code
        )

    def advance(self, repo, label):
        current = self.document(self.pull_path(repo))
        old_head = current["head_oid"]
        work = self.work_dirs[repo]
        self.git("checkout", "feature", cwd=work)
        (work / "trust-boundary.txt").write_text(label + "\n")
        self.git("add", "trust-boundary.txt", cwd=work)
        self.git("commit", "-m", label, cwd=work)
        new_head = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git(
            "push",
            "origin",
            "HEAD:refs/heads/feature",
            cwd=work,
            token=self.alice,
        )
        patched = self.document(
            self.pull_path(repo),
            200,
            method="PATCH",
            body={"expected_version": current["version"], "head_oid": new_head},
        )
        assert patched["head_oid"] == new_head, patched
        assert patched["version"] > current["version"], patched
        runs = self.wait_runs(repo, new_head, CONTEXTS)
        return patched, old_head, new_head, runs

    def positive_matrix(self):
        for repo in REPOSITORIES:
            hook = self.issuers[(repo, "ci/trusted")]
            run = self.runs_v1[repo]["ci/trusted"]
            claimed = self.claim(repo, hook, run, f"report-{repo}")
            self.secrets.append(claimed["checkout"]["token"])
            assert claimed["run_id"] == run["id"], claimed
            assert claimed["head_oid"] == self.head_v1[repo], claimed
            assert claimed["base_oid"] == self.base_oids[repo], claimed
            body = self.report_body(claimed)
            first = self.integration(
                self.run_path(repo, hook, run, "report"),
                hook["_secret"],
                body,
                200,
            )
            assert first == {"run_id": run["id"], "replay": False}, first
            duplicate = self.integration(
                self.run_path(repo, hook, run, "report"),
                hook["_secret"],
                body,
                200,
            )
            assert duplicate == {"run_id": run["id"], "replay": True}, duplicate
            row = self.check_row(repo, self.head_v1[repo], "ci/trusted")
            assert row["attempt"] == claimed["attempt"], row
            assert row["sequence"] == 2 and row["status"] == "completed", row
            assert row["conclusion"] == "success", row
            assert row["issuer_webhook_id"] == hook["id"], row
            assert row["ci_run_id"] == run["id"], row
            assert row["ci_base_oid"] == self.base_oids[repo], row

        for repo in REPOSITORIES:
            hook = self.issuers[(repo, "ci/aux")]
            run = self.runs_v1[repo]["ci/aux"]
            claimed = self.claim(repo, hook, run, f"callback-{repo}")
            self.secrets.append(claimed["checkout"]["token"])
            body = self.callback_body(run, claimed, f"trusted-{repo}-aux-v1")
            first = self.signed_callback(repo, hook, body, 200)
            assert first["status"] == "completed", first
            assert first["conclusion"] == "success", first
            assert first["attempt"] == claimed["attempt"], first
            assert first["sequence"] == 2, first
            duplicate = self.signed_callback(repo, hook, body, 200)
            assert duplicate == first, (duplicate, first)
            self.callback_v1[repo] = {"body": body, "response": first}
            row = self.check_row(repo, self.head_v1[repo], "ci/aux")
            assert row["attempt"] == claimed["attempt"], row
            assert row["status"] == "completed" and row["conclusion"] == "success", row
            assert row["issuer_webhook_id"] == hook["id"], row
            assert row["ci_run_id"] == run["id"], row
            assert row["ci_base_oid"] == self.base_oids[repo], row

    def wait_for_backend_lock(self, marker, deadline=10.0):
        stop = time.monotonic() + deadline
        while time.monotonic() < stop:
            count = int(
                self.sql(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname=current_database() AND state='active' "
                    f"AND query LIKE {self.q('%' + marker + '%')} "
                    "AND wait_event_type='Lock'"
                )
            )
            if count >= 1:
                return
            time.sleep(0.05)
        raise AssertionError(f"no backend reached the {marker!r} lock barrier")

    def revocation_blocks_merge(self):
        hook = self.issuers[("forge", "ci/trusted")]
        pr = self.document(self.pull_path("forge"))
        repo_id = self.repo["id"]
        results = {}

        def revoke():
            results["revoke"] = self.http(
                self.bind_path("forge", hook),
                token=self.alice,
                method="DELETE",
                body={"context": "ci/trusted"},
            )

        def merge():
            results["merge"] = self.http(
                self.pull_path("forge") + "/merge",
                token=self.alice,
                method="POST",
                body={
                    "expected_version": pr["version"],
                    "expected_head_oid": pr["head_oid"],
                    "expected_base_oid": pr["base_oid"],
                },
            )

        # Hold the binding row so the real revoke request acquires the policy
        # fence, then waits on the row. A concurrent merge must wait on that
        # fence rather than evaluating the still-visible active binding.
        with self.held_transaction(
            "SELECT 1 FROM forge_trusted_check_contexts "
            f"WHERE repository_id={self.q(repo_id)} "
            "AND context='ci/trusted' FOR UPDATE"
        ):
            revoker = threading.Thread(target=revoke)
            revoker.start()
            self.wait_for_backend_lock("UPDATE forge_trusted_check_contexts")
            merger = threading.Thread(target=merge)
            merger.start()
            self.wait_for_backend_lock("pg_advisory_xact_lock")
        revoker.join(timeout=15)
        merger.join(timeout=15)
        assert not revoker.is_alive(), "revocation did not finish"
        assert not merger.is_alive(), "merge did not finish"
        revoke_status, revoke_raw, _ = results["revoke"]
        assert revoke_status == 200, (revoke_status, revoke_raw[:300])
        status, raw, _ = results["merge"]
        assert status == 409, (status, raw[:300])
        assert json.loads(raw)["error"] == (
            "required check runs have not succeeded"
        ), raw[:300]
        current = self.document(self.pull_path("forge"))
        assert current["state"] == "open", current
        assert current["head_oid"] == pr["head_oid"], current
        self.document(
            self.bind_path("forge", hook),
            200,
            method="PUT",
            body={"context": "ci/trusted"},
        )

    def ordinary_writer_and_cross_scope_refusals(self):
        protected_before = {
            (repo, context): self.check_row(repo, self.head_v1[repo], context)
            for repo in REPOSITORIES
            for context in CONTEXTS
        }
        for repo in REPOSITORIES:
            for context in CONTEXTS:
                status, raw, headers = self.http(
                    self.checks_paths[repo],
                    token=self.writer,
                    method="POST",
                    body={
                        "commit_oid": self.head_v1[repo],
                        "context": context,
                        "status": "completed",
                        "conclusion": "success",
                        "attempt": 9,
                        "sequence": 9,
                        "output": "forged writable user",
                    },
                )
                assert status == 403, (repo, context, status, raw[:200])
                norm = {key.lower(): value for key, value in headers.items()}
                assert norm.get("cache-control") == "no-store", norm
                assert json.loads(raw)["error"] == (
                    "trusted CI context requires integration evidence"
                )
        # The same collaborator is genuinely writable for an unbound context;
        # the 403 above is context ownership, not a missing write role.
        manual = self.document(
            self.checks_paths["forge"],
            201,
            token=self.writer,
            method="POST",
            body={
                "commit_oid": self.head_v1["forge"],
                "context": "ci/writer-manual",
                "status": "completed",
                "conclusion": "success",
                "attempt": 1,
                "sequence": 1,
                "output": "unprotected manual check",
            },
        )
        assert manual["context"] == "ci/writer-manual", manual
        for (repo, context), before in protected_before.items():
            after = self.check_row(repo, self.head_v1[repo], context)
            assert after == before, (repo, context, before, after)
        # Binding is a maintainer operation; write is insufficient.
        hook = self.issuers[("forge", "ci/trusted")]
        status, raw, _ = self.http(
            self.bind_path("forge", hook),
            token=self.writer,
            method="PUT",
            body={"context": "ci/trusted"},
        )
        assert status == 403, (status, raw[:200])
        assert json.loads(raw)["error"] == "insufficient repository role", raw[:200]

        a1 = self.issuers[("forge", "ci/trusted")]
        a2 = self.issuers[("forge", "ci/aux")]
        run_a1 = self.runs_v1["forge"]["ci/trusted"]
        run_b1 = self.runs_v1["other"]["ci/trusted"]
        self.refuse(
            self.run_path("forge", a2, run_a1, "claim"),
            a2["_secret"],
            {"runner_id": "wrong-context"},
            404,
            "not found",
        )
        self.refuse(
            self.run_path("forge", a2, run_a1, "report"),
            a2["_secret"],
            self.report_body(run_a1 | {
                "attempt": 1,
                "lease_generation": 1,
            }),
            404,
            "not found",
        )
        self.refuse(
            self.run_path("other", a1, run_b1, "claim"),
            a1["_secret"],
            {"runner_id": "wrong-repository"},
            404,
            "not found",
        )
        cross_context = {
            "event_id": "wrong-context-callback",
            "commit_oid": self.head_v1["forge"],
            "context": "ci/trusted",
            "status": "completed",
            "conclusion": "success",
            "attempt": 1,
            "sequence": 2,
            "output": "wrong context",
            "pull_number": run_a1["pull_number"],
            "ci_run_id": run_a1["id"],
            "ci_job_id": run_a1["job_id"],
            "base_oid": run_a1["base_oid"],
            "lease_generation": 1,
        }
        error = self.signed_callback("forge", a2, cross_context, 403)
        assert error["error"] == "integration does not own this CI context", error
        cross_repo = dict(cross_context, event_id="wrong-repository-callback")
        cross_repo.update(
            {
                "commit_oid": self.head_v1["other"],
                "ci_run_id": run_b1["id"],
                "ci_job_id": run_b1["job_id"],
                "base_oid": run_b1["base_oid"],
                "pull_number": run_b1["pull_number"],
            }
        )
        error = self.signed_callback("other", a1, cross_repo, 404)
        assert error["error"] == "not found", error
        status, raw, _ = self.http(
            self.bind_path("forge", a2),
            token=self.alice,
            method="PUT",
            body={"context": "ci/trusted"},
        )
        assert status == 409, (status, raw[:200])
        assert json.loads(raw)["error"] == (
            "integration inactive or context not allowed"
        ), raw[:200]

    def candidate_change_invalidates_evidence(self):
        a1 = self.issuers[("forge", "ci/trusted")]
        a2 = self.issuers[("forge", "ci/aux")]
        old_a1 = self.runs_v1["forge"]["ci/trusted"]

        self.pulls["forge"], old_head, new_head, self.runs_v2_a = self.advance(
            "forge", "candidate v2"
        )
        self.pulls["other"], _, _, self.runs_v2_b = self.advance(
            "other", "candidate v2"
        )
        self.refuse(
            self.run_path("forge", a1, old_a1, "report"),
            a1["_secret"],
            self.report_body(old_a1 | {"attempt": 1, "lease_generation": 1}),
            409,
            "CI run attempt or candidate changed",
        )
        error = self.signed_callback(
            "forge", a2, self.callback_v1["forge"]["body"], 409
        )
        assert error["error"] == "CI run attempt or candidate changed", error
        pr = self.pulls["forge"]
        merge_body = {
            "expected_version": pr["version"],
            "expected_head_oid": new_head,
            "expected_base_oid": pr["base_oid"],
        }
        status, raw, _ = self.http(
            self.pull_path("forge") + "/merge",
            token=self.alice,
            method="POST",
            body=merge_body,
        )
        assert status == 409, (status, raw[:300])
        assert json.loads(raw)["error"] == (
            "required check runs have not succeeded"
        ), raw[:300]
        old_merge = dict(merge_body, expected_head_oid=old_head)
        status, raw, _ = self.http(
            self.pull_path("forge") + "/merge",
            token=self.alice,
            method="POST",
            body=old_merge,
        )
        assert status == 409, (status, raw[:300])
        assert json.loads(raw)["error"] == "pull request head_oid mismatch", raw[:300]
        for run in self.runs_v2_a.values():
            assert run["state"] == "queued", run

    def revocation_and_late_attempt_matrix(self):
        self.pulls["forge"], _, _, runs_a = self.advance("forge", "revocation v3")
        self.pulls["other"], _, _, runs_b = self.advance("other", "revocation v3")

        # Binding revocation refuses a current lease report.
        a1 = self.issuers[("forge", "ci/trusted")]
        run_a1 = runs_a["ci/trusted"]
        claimed_a1 = self.claim("forge", a1, run_a1, "revoked-binding")
        self.secrets.append(claimed_a1["checkout"]["token"])
        self.document(
            self.bind_path("forge", a1),
            200,
            method="DELETE",
            body={"context": "ci/trusted"},
        )
        self.refuse(
            self.run_path("forge", a1, run_a1, "report"),
            a1["_secret"],
            self.report_body(claimed_a1),
            404,
            "not found",
        )

        # An exact old callback replay is refused after its binding is revoked;
        # the same replay while current remains idempotent.
        a2 = self.issuers[("forge", "ci/aux")]
        run_a2 = runs_a["ci/aux"]
        claimed_a2 = self.claim("forge", a2, run_a2, "replay-after-revoke")
        self.secrets.append(claimed_a2["checkout"]["token"])
        callback = self.callback_body(run_a2, claimed_a2, "trusted-a2-v3")
        first = self.signed_callback("forge", a2, callback, 200)
        duplicate = self.signed_callback("forge", a2, callback, 200)
        assert duplicate == first, (duplicate, first)
        self.document(
            self.bind_path("forge", a2),
            200,
            method="DELETE",
            body={"context": "ci/aux"},
        )
        error = self.signed_callback("forge", a2, callback, 403)
        assert error["error"] == "integration does not own this CI context", error

        # Disabling the webhook registration refuses the current lease report.
        b1 = self.issuers[("other", "ci/trusted")]
        run_b1 = runs_b["ci/trusted"]
        claimed_b1 = self.claim("other", b1, run_b1, "disabled-registration")
        self.secrets.append(claimed_b1["checkout"]["token"])
        current = self.document(self.hook_path("other", b1))
        self.document(
            self.hook_path("other", b1),
            200,
            method="PATCH",
            body={"expected_version": current["version"], "active": False},
        )
        self.refuse(
            self.run_path("other", b1, run_b1, "report"),
            b1["_secret"],
            self.report_body(claimed_b1),
            401,
            "valid credentials required",
        )
        current = self.document(self.hook_path("other", b1))
        self.document(
            self.hook_path("other", b1),
            200,
            method="PATCH",
            body={"expected_version": current["version"], "active": True},
        )
        self.sql(
            f"UPDATE ci_runs SET lease_expires_unix=0 WHERE id={self.q(run_b1['id'])}"
        )
        claimed_b1_next = self.claim("other", b1, run_b1, "late-attempt")
        self.secrets.append(claimed_b1_next["checkout"]["token"])
        assert claimed_b1_next["attempt"] == claimed_b1["attempt"] + 1
        assert (
            claimed_b1_next["lease_generation"]
            == claimed_b1["lease_generation"] + 1
        )
        self.refuse(
            self.run_path("other", b1, run_b1, "report"),
            b1["_secret"],
            self.report_body(claimed_b1),
            409,
            "CI run attempt or candidate changed",
        )
        late_callback = self.callback_body(run_b1, claimed_b1, "late-b1-callback")
        error = self.signed_callback("other", b1, late_callback, 409)
        assert error["error"] == "CI run attempt or candidate changed", error
        current_report = self.integration(
            self.run_path("other", b1, run_b1, "report"),
            b1["_secret"],
            self.report_body(claimed_b1_next),
            200,
        )
        assert current_report["replay"] is False, current_report
        duplicate_report = self.integration(
            self.run_path("other", b1, run_b1, "report"),
            b1["_secret"],
            self.report_body(claimed_b1_next),
            200,
        )
        assert duplicate_report["replay"] is True, duplicate_report
        row = self.check_row("other", run_b1["head_oid"], "ci/trusted")
        assert row["attempt"] == claimed_b1_next["attempt"], row
        assert row["status"] == "completed" and row["conclusion"] == "success", row
        assert row["issuer_webhook_id"] == b1["id"], row
        assert row["ci_run_id"] == run_b1["id"], row

        # Rotating the integration bearer refuses the old secret for both the
        # current lease report and an old signed-callback replay.
        b2 = self.issuers[("other", "ci/aux")]
        run_b2 = runs_b["ci/aux"]
        claimed_b2 = self.claim("other", b2, run_b2, "rotated-secret")
        self.secrets.append(claimed_b2["checkout"]["token"])
        rotated = "rotated-b2-secret-0123456789"
        self.secrets.append(rotated)
        current = self.document(self.hook_path("other", b2))
        patched = self.document(
            self.hook_path("other", b2),
            200,
            method="PATCH",
            body={"expected_version": current["version"], "secret": rotated},
        )
        assert patched["version"] > current["version"], patched
        self.refuse(
            self.run_path("other", b2, run_b2, "claim"),
            b2["_secret"],
            {"runner_id": "rotated-old-claim"},
            401,
            "valid credentials required",
        )
        heartbeat = {
            "attempt": claimed_b2["attempt"],
            "lease_generation": claimed_b2["lease_generation"],
            "runner_id": "rotated-secret",
        }
        self.refuse(
            self.run_path("other", b2, run_b2, "heartbeat"),
            b2["_secret"],
            heartbeat,
            401,
            "valid credentials required",
        )
        renewed = self.integration(
            self.run_path("other", b2, run_b2, "heartbeat"),
            rotated,
            heartbeat,
            200,
        )
        assert renewed["lease_generation"] == claimed_b2["lease_generation"], renewed
        self.refuse(
            self.run_path("other", b2, run_b2, "report"),
            b2["_secret"],
            self.report_body(claimed_b2),
            401,
            "valid credentials required",
        )
        error = self.signed_callback(
            "other", b2, self.callback_v1["other"]["body"], 401
        )
        assert error["error"] == "valid credentials required", error
        accepted = self.integration(
            self.run_path("other", b2, run_b2, "report"),
            rotated,
            self.report_body(claimed_b2),
            200,
        )
        assert accepted["replay"] is False, accepted
        duplicate = self.integration(
            self.run_path("other", b2, run_b2, "report"),
            rotated,
            self.report_body(claimed_b2),
            200,
        )
        assert duplicate["replay"] is True, duplicate
        row = self.check_row("other", run_b2["head_oid"], "ci/aux")
        assert row["attempt"] == claimed_b2["attempt"], row
        assert row["status"] == "completed" and row["conclusion"] == "success", row
        assert row["issuer_webhook_id"] == b2["id"], row
        assert row["ci_run_id"] == run_b2["id"], row

    def api_principal_token_revocation(self):
        management = self.issue_token("alice")
        hook = self.issuers[("forge", "ci/trusted")]
        self.document(self.hook_path("forge", hook), token=management)
        status, raw, headers = self.http(
            f"/api/tokens/{management['token_id']}",
            token=self.alice,
            method="DELETE",
        )
        assert status == 204, (status, raw[:200])
        norm = {key.lower(): value for key, value in headers.items()}
        assert norm.get("cache-control") == "no-store", norm
        status, raw, _ = self.http(self.hook_path("forge", hook), token=management)
        assert status == 401, (status, raw[:200])
        assert json.loads(raw)["error"] == "valid credentials required", raw[:200]
        status, raw, _ = self.http(
            self.bind_path("forge", hook),
            token=management,
            method="PUT",
            body={"context": "ci/trusted"},
        )
        assert status == 401, (status, raw[:200])
        assert json.loads(raw)["error"] == "valid credentials required", raw[:200]
        # The repository-owned webhook survives independently of the revoked
        # management token; there is no creator-token-to-registration binding.
        self.document(self.hook_path("forge", hook), token=self.alice)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    harness = TrustBoundaryHarness(args)
    try:
        harness.setup()
        harness.case("trusted two-repository matrix setup", harness.configure)
        harness.case("trusted positive report/callback flows", harness.positive_matrix)
        harness.case(
            "revoked trusted context cannot unlock merge",
            harness.revocation_blocks_merge,
        )
        harness.case(
            "ordinary writer and cross-context/repository refusals",
            harness.ordinary_writer_and_cross_scope_refusals,
        )
        harness.case(
            "changed candidate invalidates prior evidence",
            harness.candidate_change_invalidates_evidence,
        )
        harness.case(
            "revoked registration, rotated secret and late attempt",
            harness.revocation_and_late_attempt_matrix,
        )
        harness.case(
            "API principal token revocation remains management-only",
            harness.api_principal_token_revocation,
        )
        return 0
    finally:
        harness.cleanup()


if __name__ == "__main__":
    sys.exit(main())
