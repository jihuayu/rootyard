#!/usr/bin/env python3
"""Native trusted-issuer, run, lease and callback boundary matrix.

This is a real-service checkpoint over the existing managed PostgreSQL and Git
fixtures in ``WebhooksHarness``. It uses two repositories, two trusted contexts
and two webhook issuers so the same context name must resolve independently by
repository. Positive report and signed-callback flows run first for both
repositories; every negative below then asserts an exact status and error.

Current semantics intentionally covered:
* a write collaborator cannot write a bound check context through the direct API;
* that same non-owner collaborator can create an unbound manual check, which is
  persisted under the repository tenant and is byte-identical in the owner's
  and writer's commit/PR check listings, while an unaffiliated user still gets
  404 and binding management remains maintainer-only;
* an issuer cannot claim/report outside its own repository, context or run;
* revoking a trusted-context binding or disabling a webhook refuses a current
  lease report, and an exact old signed-callback replay is refused after the
  binding is revoked;
* removing a context from an otherwise active webhook revokes that binding and
  advances the run authority epoch, so claim/report/heartbeat and completed
  evidence (including after an explicit re-bind) are refused for the removed
  context;
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

Concurrency coverage: the merge/revocation case uses a fixture-held binding row.
It identifies the real revoke backend by the exact policy advisory key plus the
fixture row-lock blocker, and the publication owner by the exact base-ref
advisory key in ``pg_locks``. It proves the publication owner repeatedly
advances ``query_start`` through the nonblocking enter-window statements on the
same backend, without waiting on a lock, while the revoker still owns the shared
policy fence. Revocation is scheduled first; the case then requires revoke 200,
merge 409 with the exact policy error, and unchanged PR state. The
claim/heartbeat and post-Git callback rechecks do not install a pause inside
checkout preparation or Git verification, so only their end-state refusals, not
a specific overlapping interleaving, are claimed by this harness.

Required environment (same as the other native CI harnesses):
ROOTYARD_TEST_DATABASE_URL, a trusted Git executable, and a Linux PostgreSQL 17
fixture. Root can run the focused command:

    python3 tests/ci_trust_boundaries.py --binary target/debug/rootyard

With ``--report`` this file also writes a credential-free machine report.  A
successful report is accepted only when exactly the eight named cases ran once,
passed, and cleanup succeeded; it binds the executed binary to the adjacent
original build receipt, the current production-source digest, HEAD, a clean
worktree, and the explicit transitive Python/provenance input digests sampled
before and after the run.  A failed run still writes ``passed=false`` with the
redacted completed prefix and the failed case, but it never persists raw HTTP
bodies, headers, SQL, environment, private configuration, or tracebacks.  The
CI gate runs this matrix after the native batch build and binds the report into
``scripts/native_report_manifest.py --mode job``; do not treat a local syntax
check as a native pass.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import urllib.parse

import ops_provenance
import source_bound_binary
from webhooks import WebhooksHarness


REPOSITORIES = ("forge", "other")
CONTEXTS = ("ci/trusted", "ci/aux")
CASE_NAMES = (
    "trusted two-repository matrix setup",
    "trusted positive report/callback flows",
    "revoked trusted context cannot unlock merge",
    "ordinary writer and cross-context/repository refusals",
    "changed candidate invalidates prior evidence",
    "revoked registration, rotated secret and late attempt",
    "removed webhook context revokes claim/report/merge authority",
    "API principal token revocation remains management-only",
)
CASE_METHODS = (
    "configure",
    "positive_matrix",
    "revocation_blocks_merge",
    "ordinary_writer_and_cross_scope_refusals",
    "candidate_change_invalidates_evidence",
    "revocation_and_late_attempt_matrix",
    "context_removal_revokes_authority",
    "api_principal_token_revocation",
)
# Inputs outside build_native.source_digest()'s production Rust tree.  The
# report hashes every one before and after the run so a harness edit cannot
# silently stand in for the reviewed matrix.
PROVENANCE_INPUTS = (
    "tests/ci_trust_boundaries.py",
    "tests/webhooks.py",
    "tests/pulls.py",
    "tests/forge.py",
    "tests/e2e.py",
    "tests/schema_baseline.py",
    "tests/webhook_tenant_matrix.py",
    "tests/native_evidence.py",
    "tests/owned_fuse_cleanup.py",
    "tests/source_bound_binary.py",
    "tests/ops_provenance.py",
    "tests/test_ci_trust_boundaries_privacy.py",
    "scripts/native_report_manifest.py",
    "scripts/native_build_receipt.py",
    "scripts/build_native.py",
    "scripts/build_native_batch.py",
    ".github/workflows/ci.yml",
)
REPORT_KIND = "rootyard/ci-trust-boundaries-report"
ALLOWED_REPORT_CASES = frozenset(CASE_NAMES) | {"harness setup", "cleanup", "report binding"}


class ReportError(RuntimeError):
    """A report binding refusal with a fixed, credential-free code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class TrustBoundaryHarness(WebhooksHarness):
    def q(self, value):
        return "'" + str(value).replace("'", "''") + "'"

    def setup(self):
        parts = urllib.parse.urlsplit(self.db)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        query.append(("application_name", self.schema))
        self.db = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
        self.env["DATABASE_URL"] = self.db
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
            "'repository_id',repository_id::text,'tenant_id',tenant_id::text,"
            "'commit_oid',commit_oid,'context',context,"
            "'attempt',attempt,'sequence',sequence,'status',status,"
            "'conclusion',conclusion,'output',output,"
            "'issuer_webhook_id',issuer_webhook_id::text,"
            "'ci_run_id',ci_run_id::text,'ci_base_oid',ci_base_oid,"
            "'ci_lease_generation',ci_lease_generation,"
            "'created_at',created_at::text,'updated_at',updated_at::text)),'[]'::json)::text "
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

    def new_pull(self, repo, branch, marker):
        """Create an independent PR on top of the fixture's feature head."""
        work = self.work_dirs[repo]
        self.git("checkout", "-B", branch, "feature", cwd=work)
        (work / f"{branch}.txt").write_text(marker + "\n")
        self.git("add", f"{branch}.txt", cwd=work)
        self.git("commit", "-m", marker, cwd=work)
        head = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git(
            "push", "origin", f"HEAD:refs/heads/{branch}", cwd=work, token=self.alice
        )
        pull = self.document(
            self.pull_paths[repo],
            201,
            method="POST",
            body={
                "title": f"context scope {branch}",
                "body": "context-removal regression candidate",
                "head_ref": f"refs/heads/{branch}",
                "base_ref": "refs/heads/main",
            },
        )
        assert pull["head_oid"] == head, pull
        runs = self.wait_runs(repo, head, ("ci/removed",))
        return pull, runs["ci/removed"]

    def context_removal_revokes_authority(self):
        repo = "other"
        hook = self.issuers[(repo, "ci/trusted")]
        secret = hook["_secret"]
        current = self.document(self.hook_path(repo, hook))
        patched = self.document(
            self.hook_path(repo, hook),
            200,
            method="PATCH",
            body={
                "expected_version": current["version"],
                "ci_contexts": ["ci/trusted", "ci/removed"],
            },
        )
        assert patched["ci_contexts"] == ["ci/trusted", "ci/removed"], patched
        self.document(
            self.bind_path(repo, hook),
            200,
            method="PUT",
            body={"context": "ci/removed"},
        )
        rules = self.document(self.branch_paths[repo])["items"]
        rule = next(r for r in rules if r["branch_ref"] == "refs/heads/main")
        self.document(
            self.branch_paths[repo],
            200,
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "expected_version": rule["version"],
                "required_approvals": 0,
                "required_checks": ["ci/removed"],
                "require_fast_forward": True,
            },
        )

        # A positive merge proves the new context is accepted while current.
        pr, _, head4, _ = self.advance(repo, "context removal v4")
        run4 = self.wait_runs(repo, head4, ("ci/removed",))["ci/removed"]
        claimed4 = self.claim(repo, hook, run4, "scope-removal-positive")
        self.secrets.append(claimed4["checkout"]["token"])
        body4 = self.report_body(claimed4)
        first = self.integration(
            self.run_path(repo, hook, run4, "report"), secret, body4, 200
        )
        assert first["replay"] is False, first
        duplicate = self.integration(
            self.run_path(repo, hook, run4, "report"), secret, body4, 200
        )
        assert duplicate["replay"] is True, duplicate
        merged = self.document(
            self.pull_path(repo) + "/merge",
            200,
            method="POST",
            body={
                "expected_version": pr["version"],
                "expected_head_oid": head4,
                "expected_base_oid": pr["base_oid"],
            },
        )
        assert merged["state"] == "merged", merged
        assert merged["merge_commit_oid"] == head4, merged

        # PR A keeps completed evidence on an open candidate. PR B is leased
        # before removal for report/heartbeat refusals; PR C stays queued for
        # the post-removal claim refusal.
        pull_a, run_a = self.new_pull(repo, "scope-report", "context removal report")
        claimed_a = self.claim(repo, hook, run_a, "scope-removal-report")
        self.secrets.append(claimed_a["checkout"]["token"])
        body_a = self.report_body(claimed_a)
        accepted = self.integration(
            self.run_path(repo, hook, run_a, "report"), secret, body_a, 200
        )
        assert accepted["replay"] is False, accepted
        duplicate_a = self.integration(
            self.run_path(repo, hook, run_a, "report"), secret, body_a, 200
        )
        assert duplicate_a["replay"] is True, duplicate_a

        pull_b, run_b = self.new_pull(repo, "scope-lease", "context removal lease")
        claimed_b = self.claim(repo, hook, run_b, "scope-removal-lease")
        self.secrets.append(claimed_b["checkout"]["token"])
        heartbeat = {
            "attempt": claimed_b["attempt"],
            "lease_generation": claimed_b["lease_generation"],
            "runner_id": "scope-removal-lease",
        }
        renewed = self.integration(
            self.run_path(repo, hook, run_b, "heartbeat"), secret, heartbeat, 200
        )
        assert renewed["lease_generation"] == claimed_b["lease_generation"], renewed

        pull_c, run_c = self.new_pull(repo, "scope-claim", "context removal claim")
        assert run_c["state"] == "queued", run_c

        current = self.document(self.hook_path(repo, hook))
        removed = self.document(
            self.hook_path(repo, hook),
            200,
            method="PATCH",
            body={
                "expected_version": current["version"],
                "ci_contexts": ["ci/trusted"],
            },
        )
        assert removed["ci_contexts"] == ["ci/trusted"], removed
        binding = self.sql(
            "SELECT active FROM forge_trusted_check_contexts "
            f"WHERE repository_id={self.q(self.other['id'])} "
            "AND context='ci/removed'"
        )
        assert binding == "f", binding
        old_row = self.check_row(repo, head4, "ci/removed")
        assert old_row["status"] == "completed", old_row
        assert old_row["conclusion"] == "success", old_row

        self.refuse(
            self.run_path(repo, hook, run_c, "claim"),
            secret,
            {"runner_id": "scope-removal-claim"},
            404,
            "not found",
        )
        self.refuse(
            self.run_path(repo, hook, run_b, "report"),
            secret,
            self.report_body(claimed_b),
            404,
            "not found",
        )
        self.refuse(
            self.run_path(repo, hook, run_b, "heartbeat"),
            secret,
            heartbeat,
            409,
            "CI run lease changed",
        )
        self.refuse(
            self.run_path(repo, hook, run_a, "report"),
            secret,
            body_a,
            404,
            "not found",
        )
        merge_a = {
            "expected_version": pull_a["version"],
            "expected_head_oid": pull_a["head_oid"],
            "expected_base_oid": pull_a["base_oid"],
        }
        status, raw, _ = self.http(
            self.pull_path(repo, pull_a["number"]) + "/merge",
            token=self.alice,
            method="POST",
            body=merge_a,
        )
        assert status == 409, (status, raw[:300])
        assert json.loads(raw)["error"] == (
            "required check runs have not succeeded"
        ), raw[:300]

        # Re-binding the same context explicitly restores current authority but
        # must not resurrect the completion recorded before removal.
        current = self.document(self.hook_path(repo, hook))
        readded = self.document(
            self.hook_path(repo, hook),
            200,
            method="PATCH",
            body={
                "expected_version": current["version"],
                "ci_contexts": ["ci/trusted", "ci/removed"],
            },
        )
        assert readded["ci_contexts"] == ["ci/trusted", "ci/removed"], readded
        self.document(
            self.bind_path(repo, hook),
            200,
            method="PUT",
            body={"context": "ci/removed"},
        )
        status, raw, _ = self.http(
            self.pull_path(repo, pull_a["number"]) + "/merge",
            token=self.alice,
            method="POST",
            body=merge_a,
        )
        assert status == 409, (status, raw[:300])
        assert json.loads(raw)["error"] == (
            "required check runs have not succeeded"
        ), raw[:300]

        # The new authority is usable: a fresh claim/report can unlock the
        # queued candidate, proving the refusal above was not a permanent
        # fixture break.
        claimed_c = self.claim(repo, hook, run_c, "scope-removal-new-authority")
        self.secrets.append(claimed_c["checkout"]["token"])
        current_report = self.integration(
            self.run_path(repo, hook, run_c, "report"),
            secret,
            self.report_body(claimed_c),
            200,
        )
        assert current_report["replay"] is False, current_report
        merged_c = self.document(
            self.pull_path(repo, pull_c["number"]) + "/merge",
            200,
            method="POST",
            body={
                "expected_version": pull_c["version"],
                "expected_head_oid": pull_c["head_oid"],
                "expected_base_oid": pull_c["base_oid"],
            },
        )
        assert merged_c["state"] == "merged", merged_c
        assert merged_c["merge_commit_oid"] == pull_c["head_oid"], merged_c

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

    def policy_advisory_key(self, repo_id):
        """The exact repository policy key shared with PublicationWindow."""
        return (
            "hashtextextended('rootyard-publication-v1:' || "
            f"{self.q(repo_id)}::uuid::text, 0)"
        )

    def ref_advisory_key(self, repo_id, ref_name):
        """The exact ref key PublicationGuard acquires before enter_window."""
        return (
            "hashtextextended('rootyard-ref-v1:' || "
            f"{self.q(repo_id)}::uuid::text || ':' || {self.q(ref_name)}, 0)"
        )

    def wait_for_policy_revoker(self, repo_id, fixture_pid, deadline=10.0):
        """Identify the revoke backend by its exact policy key and blocker.

        The backend must hold the same repository advisory domain as
        PublicationWindow and be waiting on the fixture-held binding row
        (``pg_blocking_pids`` names the fixture backend). This uses no query
        text and excludes the observer's own backend.
        """
        key = self.policy_advisory_key(repo_id)
        stop = time.monotonic() + deadline
        while time.monotonic() < stop:
            pid = self.sql(
                "SELECT a.pid::text FROM pg_locks l "
                "JOIN pg_stat_activity a ON a.pid=l.pid "
                "JOIN pg_database d ON d.oid=l.database "
                "WHERE l.locktype='advisory' AND l.granted "
                "AND l.objsubid=1 AND l.mode='ExclusiveLock' "
                "AND d.datname=current_database() "
                f"AND a.application_name={self.q(self.schema)} "
                "AND a.pid<>pg_backend_pid() "
                "AND a.wait_event_type='Lock' "
                f"AND {int(fixture_pid)} = ANY(pg_blocking_pids(a.pid)) "
                f"AND l.classid=((({key})::bigint >> 32) & 4294967295)::oid "
                f"AND l.objid=((({key})::bigint) & 4294967295)::oid "
                "LIMIT 1"
            ).strip()
            if pid:
                return int(pid)
            time.sleep(0.02)
        raise AssertionError(
            "real revoke backend never held the repository policy advisory key "
            "while blocked by the fixture-held binding row"
        )

    def observe_publication_owner_retry(self, repo_id, base_ref, revoker_pid, deadline=1.5):
        """Observe the real publication owner retrying the nonblocking fence.

        The owner is identified only by the granted exact-ref advisory key.
        While the revoker still holds the exact repository policy key, the same
        owner backend must advance query_start through repeated enter-window
        statements and must not wait on a lock. The observer excludes its own
        backend and never acquires either advisory key.
        """
        ref_key = self.ref_advisory_key(repo_id, base_ref)
        policy_key = self.policy_advisory_key(repo_id)
        stop = time.monotonic() + deadline
        owner_pid = None
        backend_start = None
        starts = []
        while time.monotonic() < stop:
            row = self.sql(
                "WITH policy_lock AS ("
                "SELECT l.pid FROM pg_locks l JOIN pg_database d ON d.oid=l.database "
                "WHERE l.locktype='advisory' AND l.granted AND l.objsubid=1 "
                "AND l.mode='ExclusiveLock' AND d.datname=current_database() "
                f"AND l.classid=((({policy_key})::bigint >> 32) & 4294967295)::oid "
                f"AND l.objid=((({policy_key})::bigint) & 4294967295)::oid"
                "), ref_lock AS ("
                "SELECT l.pid FROM pg_locks l JOIN pg_database d ON d.oid=l.database "
                "WHERE l.locktype='advisory' AND l.granted AND l.objsubid=1 "
                "AND l.mode='ExclusiveLock' AND d.datname=current_database() "
                f"AND l.classid=((({ref_key})::bigint >> 32) & 4294967295)::oid "
                f"AND l.objid=((({ref_key})::bigint) & 4294967295)::oid"
                ") SELECT policy_lock.pid::text || '|' || ref_lock.pid::text || '|' || "
                "a.pid::text || '|' || extract(epoch FROM a.backend_start)::text || '|' || "
                "a.state || '|' || coalesce(a.wait_event_type,'') || '|' || "
                "extract(epoch FROM a.query_start)::text || '|' || "
                "CASE "
                "WHEN a.query LIKE '%pg_try_advisory_xact_lock%' "
                "AND a.query LIKE '%rootyard-publication-v1:%' THEN 'try' "
                "WHEN a.query LIKE 'SELECT storage_generation,state,transition_state "
                "FROM repositories WHERE id=$1%' THEN 'row' "
                "ELSE 'other' END "
                "FROM policy_lock CROSS JOIN ref_lock "
                "JOIN pg_stat_activity a ON a.pid=ref_lock.pid "
                "WHERE policy_lock.pid<>ref_lock.pid AND policy_lock.pid<>pg_backend_pid() "
                "AND ref_lock.pid<>pg_backend_pid() "
                f"AND a.application_name={self.q(self.schema)} "
                "LIMIT 1"
            ).strip()
            if row:
                fields = row.split("|")
                assert len(fields) == 8, (len(fields), fields)
                (
                    policy_pid,
                    ref_pid,
                    observed_pid,
                    observed_start,
                    state,
                    wait_event,
                    query_start,
                    shape,
                ) = fields
                assert int(policy_pid) == revoker_pid, (
                    "policy fence changed backend during merge observation",
                    int(policy_pid),
                    revoker_pid,
                )
                assert int(ref_pid) == int(observed_pid)
                assert int(observed_pid) != revoker_pid
                if owner_pid is None:
                    owner_pid = int(observed_pid)
                    backend_start = float(observed_start)
                else:
                    assert int(observed_pid) == owner_pid, (observed_pid, owner_pid)
                    assert float(observed_start) == backend_start, (
                        observed_start,
                        backend_start,
                    )
                if shape in ("try", "row"):
                    assert state in ("active", "idle in transaction"), (state, shape)
                    assert wait_event != "Lock", (state, wait_event, shape)
                    started = float(query_start)
                    if not starts or started > starts[-1]:
                        starts.append(started)
            if len(starts) >= 4:
                break
            time.sleep(0.01)
        assert owner_pid is not None, (
            "publication owner never held the exact base-ref advisory key"
        )
        assert len(starts) >= 4, (len(starts), starts)
        gaps = [later - earlier for earlier, later in zip(starts, starts[1:])]
        assert starts[-1] - starts[0] >= 0.04, starts
        assert max(gaps) <= 0.75, gaps
        return {
            "owner_pid": owner_pid,
            "revoker_pid": revoker_pid,
            "samples": len(starts),
            "span_seconds": starts[-1] - starts[0],
        }

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
        # fence, then waits on the row. Identify that backend by the exact
        # advisory key, start the merge, and prove the real publication owner is
        # retrying the nonblocking repository fence while the revoker still owns
        # it. Release promptly so the revoke stays inside its existing SQL
        # lock_timeout and commits 200 rather than timing out.
        with self.held_transaction(
            "SELECT 1 FROM forge_trusted_check_contexts "
            f"WHERE repository_id={self.q(repo_id)} "
            "AND context='ci/trusted' FOR UPDATE"
        ) as fixture:
            fixture.stdin.write("SELECT 'fixture_pid|' || pg_backend_pid();\n")
            fixture.stdin.flush()
            fixture_line = fixture.stdout.readline().strip()
            assert fixture_line.startswith("fixture_pid|"), fixture_line
            fixture_pid = int(fixture_line.split("|", 1)[1])
            revoker = threading.Thread(target=revoke)
            revoker.start()
            revoker_pid = self.wait_for_policy_revoker(repo_id, fixture_pid)
            merger = threading.Thread(target=merge)
            merger.start()
            self.observe_publication_owner_retry(
                repo_id, pr["base_ref"], revoker_pid
            )
            assert merger.is_alive(), (
                "merge finished before publication-owner contention was observed"
            )
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
        commit_checks = (
            f"/api/repos/alice/forge/commits/{self.head_v1['forge']}/checks"
        )
        pull_checks = self.pull_path("forge") + "/checks"
        manual_body = {
            "commit_oid": self.head_v1["forge"],
            "context": "ci/writer-manual",
            "status": "completed",
            "conclusion": "success",
            "attempt": 1,
            "sequence": 1,
            "output": "unprotected manual check",
        }
        manual = self.document(
            self.checks_paths["forge"],
            201,
            token=self.writer,
            method="POST",
            headers={"Idempotency-Key": "writer-manual-check-1"},
            body=manual_body,
        )
        assert manual["sequence"] == 1, manual
        assert manual["output"] == "unprotected manual check", manual
        replay = self.document(
            self.checks_paths["forge"],
            200,
            token=self.writer,
            method="POST",
            headers={"Idempotency-Key": "writer-manual-check-1"},
            body=manual_body,
        )
        assert replay == manual, (replay, manual)
        manual = self.document(
            self.checks_paths["forge"],
            200,
            token=self.writer,
            method="POST",
            headers={"Idempotency-Key": "writer-manual-check-2"},
            body=manual_body
            | {
                "sequence": 2,
                "output": "unprotected manual check advanced",
            },
        )
        expected_manual = {
            "repository_id": self.repo["id"],
            "commit_oid": self.head_v1["forge"],
            "context": "ci/writer-manual",
            "attempt": 1,
            "sequence": 2,
            "status": "completed",
            "conclusion": "success",
            "output": "unprotected manual check advanced",
        }
        for field, value in expected_manual.items():
            assert manual[field] == value, (field, manual)
        persisted = self.check_row(
            "forge", self.head_v1["forge"], "ci/writer-manual"
        )
        owner_id = self.sql(
            "SELECT owner_id::text FROM repositories "
            f"WHERE id={self.q(self.repo['id'])}"
        )
        assert persisted["tenant_id"] == owner_id, persisted
        assert persisted["tenant_id"] == self.alice["user_id"], persisted
        assert persisted["tenant_id"] != self.writer["user_id"], persisted
        for field, value in expected_manual.items():
            assert persisted[field] == value, (field, persisted)

        def listed_manual(items):
            matches = [
                item for item in items if item["context"] == "ci/writer-manual"
            ]
            assert len(matches) == 1, items
            return matches[0]

        owner_commit = self.document(commit_checks, token=self.alice)
        writer_commit = self.document(commit_checks, token=self.writer)
        owner_pull = self.document(pull_checks, token=self.alice)
        writer_pull = self.document(pull_checks, token=self.writer)
        assert owner_commit["commit_oid"] == self.head_v1["forge"], owner_commit
        assert writer_commit["commit_oid"] == self.head_v1["forge"], writer_commit
        assert owner_pull["pull_number"] == self.pulls["forge"]["number"], owner_pull
        assert writer_pull["pull_number"] == self.pulls["forge"]["number"], writer_pull
        assert owner_pull["head_oid"] == self.head_v1["forge"], owner_pull
        assert writer_pull["head_oid"] == self.head_v1["forge"], writer_pull
        for listed in (owner_commit, writer_commit, owner_pull, writer_pull):
            assert listed_manual(listed["items"]) == manual, listed

        # A user with no membership in alice/forge cannot observe the row through
        # either check listing; this is the unchanged repository scope boundary.
        for protected_path in (commit_checks, pull_checks):
            status, raw, headers = self.http(protected_path, token=self.bob)
            assert status == 404, (protected_path, status, raw[:200])
            norm = {key.lower(): value for key, value in headers.items()}
            assert norm.get("cache-control") == "no-store", norm
            assert json.loads(raw)["error"] == "not found", raw[:200]

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


def _binding_failure_code(error):
    """Map a reviewed SourceBinding refusal to a fixed report code."""
    message = str(error)
    if "not an executable file" in message:
        return "binary_missing"
    if "no matching adjacent receipt" in message:
        return "receipt_missing"
    if "does not match this checkout's production source inputs" in message:
        return "source_drift"
    if "stale build receipt" in message:
        return "stale_receipt"
    if "build receipt rejected" in message or "build receipt is missing" in message:
        return "receipt_invalid"
    return "source_binding_failed"


def _current_head():
    try:
        return source_bound_binary._git("rev-parse", "HEAD")
    except Exception:
        return None


def _collate_inputs(digests):
    digest = hashlib.sha256()
    for name in sorted(digests):
        digest.update(name.encode() + b"\0" + digests[name].encode() + b"\0")
    return digest.hexdigest()


def _digest_provenance_inputs():
    digests = {}
    for name in PROVENANCE_INPUTS:
        path = source_bound_binary.ROOT / name
        if not path.is_file():
            raise ReportError("provenance_input_missing")
        try:
            digests[name] = ops_provenance.sha256_file(path)
        except OSError:
            raise ReportError("provenance_input_missing") from None
    return digests


def capture_provenance(binary, expected_commit=None):
    """Bind ``binary`` to its original receipt, source, HEAD and harness bytes."""
    try:
        binding = source_bound_binary.bind(binary, expected_commit)
    except source_bound_binary.SourceBindingError as error:
        raise ReportError(_binding_failure_code(error)) from None
    except Exception:
        raise ReportError("source_binding_failed") from None
    head = source_bound_binary._git("rev-parse", "HEAD")
    status = source_bound_binary._git("status", "--porcelain")
    if not head or status is None:
        raise ReportError("git_state_unavailable")
    if status:
        raise ReportError("worktree_dirty")
    if expected_commit is not None and head != expected_commit:
        raise ReportError("stale_receipt")
    receipt = Path(binary).resolve().with_suffix(".build.json")
    if not receipt.is_file():
        raise ReportError("receipt_missing")
    try:
        receipt_sha256 = ops_provenance.sha256_file(receipt)
    except OSError:
        raise ReportError("receipt_invalid") from None
    schema = binding.get("schema")
    if schema == "v2":
        # A v2 receipt records an immutable source snapshot.  Record the
        # digest recomputed from this checkout separately; never relabel the
        # receipt's snapshot as the current digest.
        try:
            current_source_inputs = source_bound_binary.production_source_digest()
        except Exception:
            raise ReportError("source_unavailable") from None
        receipt_source_inputs = binding["source_inputs_sha256"]
        if expected_commit is not None and current_source_inputs != receipt_source_inputs:
            raise ReportError("source_drift")
        source_inputs = current_source_inputs
        source_binding = "v2_recorded_snapshot"
    elif schema == "v1":
        source_inputs = binding["current_source_inputs_sha256"]
        receipt_source_inputs = binding["source_inputs_sha256"]
        source_binding = "v1_current_source"
    else:
        raise ReportError("source_binding_failed")
    inputs = _digest_provenance_inputs()
    return {
        "schema": schema,
        "source_binding": source_binding,
        "head": head,
        "clean": True,
        "binary_sha256": binding["binary_sha256"],
        "source_inputs_sha256": source_inputs,
        "receipt_sha256": receipt_sha256,
        "receipt_workspace_commit": binding["workspace_commit"],
        "receipt_source_inputs_sha256": receipt_source_inputs,
        "source_snapshot_matches_current": (
            source_inputs == receipt_source_inputs
        ),
        "inputs": inputs,
        "inputs_sha256": _collate_inputs(inputs),
    }


def compare_provenance(start, end):
    """Return a fixed drift code when the start/end snapshots differ."""
    if start["head"] != end["head"]:
        return "head_changed"
    if start["binary_sha256"] != end["binary_sha256"]:
        return "binary_changed"
    if start["source_inputs_sha256"] != end["source_inputs_sha256"]:
        return "source_changed"
    if start["receipt_sha256"] != end["receipt_sha256"]:
        return "receipt_changed"
    if start["inputs"] != end["inputs"]:
        return "harness_changed"
    return None


def _public_snapshot(snapshot):
    if snapshot is None:
        return None
    return {
        key: snapshot[key]
        for key in (
            "schema",
            "source_binding",
            "head",
            "clean",
            "binary_sha256",
            "source_inputs_sha256",
            "receipt_sha256",
            "receipt_workspace_commit",
            "receipt_source_inputs_sha256",
            "source_snapshot_matches_current",
            "inputs_sha256",
        )
    }


def _safe_case(case):
    """Keep only fixed, redacted case fields; never a message or traceback."""
    name = case.get("name")
    if name not in ALLOWED_REPORT_CASES:
        name = "unknown case"
    status = "passed" if case.get("status") == "passed" else "failed"
    seconds = case.get("seconds")
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or seconds < 0:
        seconds = 0.0
    record = {"name": name, "status": status, "seconds": round(float(seconds), 4)}
    if status == "failed":
        error_type = case.get("error_type")
        record["error_type"] = (
            error_type
            if isinstance(error_type, str) and error_type.isidentifier()
            else "CaseFailure"
        )
        record["diagnostic"] = "case failed; see redacted runner diagnostics"
    return record


def _report_cases(harness, start_error, end_error, run_result):
    raw = list(getattr(harness, "results", []) or []) if harness is not None else []
    cases = [_safe_case(case) for case in raw]
    if not cases:
        error_type = "SourceBindingError" if start_error or end_error else "CaseFailure"
        cases = [
            {
                "name": "report binding",
                "status": "failed",
                "seconds": 0.0,
                "error_type": error_type,
                "diagnostic": "provenance binding failed; see redacted runner diagnostics",
            }
        ]
    return cases


def build_report(start, end, run_result, harness, start_error=None, end_error=None):
    """Build a credential-free report from snapshots and sanitized case rows."""
    cases = _report_cases(harness, start_error, end_error, run_result)
    cleanup_success = bool(run_result and run_result["cleanup_ok"])
    drift = compare_provenance(start, end) if start is not None and end is not None else None
    failure = run_result.get("failure") if run_result else None
    stage = code = error_type = None
    if start_error:
        stage, code, error_type = "binding", start_error, "SourceBindingError"
    elif end_error:
        stage, code, error_type = "provenance", end_error, "SourceBindingError"
    elif failure:
        stage = failure.get("stage") or "cases"
        code = {
            "cases": "case_failed",
            "setup": "setup_failed",
            "cleanup": "cleanup_failed",
        }.get(stage, "case_failed")
        error_type = failure.get("type") or "CaseFailure"
    elif drift:
        stage, code, error_type = "provenance", drift, "ProvenanceDrift"
    elif not run_result or not run_result["success"]:
        stage, code, error_type = "cases", "case_failed", "CaseFailure"
    elif not cleanup_success:
        stage, code, error_type = "cleanup", "cleanup_failed", "CleanupFailure"
    elif [case["name"] for case in cases] != list(CASE_NAMES) or any(
        case["status"] != "passed" for case in cases
    ):
        stage, code, error_type = "cases", "case_set", "CaseSetMismatch"
    passed = (
        start_error is None
        and end_error is None
        and run_result is not None
        and run_result["success"]
        and cleanup_success
        and drift is None
        and len(cases) == len(CASE_NAMES)
        and [case["name"] for case in cases] == list(CASE_NAMES)
        and all(case["status"] == "passed" for case in cases)
    )
    if not passed and code is None:
        stage, code, error_type = "report", "report_failed", "ReportFailure"
    snapshot = start or end
    provenance = {
        "start": _public_snapshot(start),
        "end": _public_snapshot(end),
        "inputs": dict(snapshot["inputs"]) if snapshot is not None else None,
        "inputs_sha256": snapshot["inputs_sha256"] if snapshot is not None else None,
        "head_stable": bool(start and end and start["head"] == end["head"]),
        "binary_stable": bool(start and end and start["binary_sha256"] == end["binary_sha256"]),
        "source_stable": bool(
            start and end and start["source_inputs_sha256"] == end["source_inputs_sha256"]
        ),
        "receipt_stable": bool(
            start and end and start["receipt_sha256"] == end["receipt_sha256"]
        ),
        "inputs_stable": bool(start and end and start["inputs"] == end["inputs"]),
    }
    return {
        "kind": REPORT_KIND,
        "passed": passed,
        "cases": cases,
        "required_cases": list(CASE_NAMES),
        "cleanup_success": cleanup_success,
        "binary_sha256": start["binary_sha256"] if start is not None else None,
        "source_head": (
            start["head"] if start is not None else (end["head"] if end is not None else _current_head())
        ),
        "source_inputs_sha256": (
            start["source_inputs_sha256"] if start is not None else None
        ),
        "receipt_schema": start["schema"] if start is not None else None,
        "source_binding": (
            start["source_binding"] if start is not None else None
        ),
        "receipt_source_inputs_sha256": (
            start["receipt_source_inputs_sha256"] if start is not None else None
        ),
        "build_receipt_sha256": start["receipt_sha256"] if start is not None else None,
        "receipt_workspace_commit": (
            start["receipt_workspace_commit"] if start is not None else None
        ),
        "provenance": provenance,
        "failure": (
            None
            if code is None
            else {"stage": stage, "code": code, "error_type": error_type}
        ),
    }


def write_report(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def bound_cases(harness):
    return [(name, getattr(harness, method)) for name, method in zip(CASE_NAMES, CASE_METHODS)]


def run_cases(harness, cases):
    """Run cases without letting an original exception escape redaction.

    ``PullsHarness.case`` records a redacted failure and prints a redacted
    traceback, then re-raises. If that exception reached the interpreter it
    would print the original assertion payload a second time, including any
    claimed checkout token. This outer boundary prints only redacted
    diagnostics; the failed case result remains in ``harness.results``.
    """
    try:
        for name, fn in cases:
            harness.case(name, fn)
    except Exception as error:
        failure_type = type(error).__name__
        harness.case_failure_type = failure_type
        if getattr(harness, "results", None) and harness.results[-1].get("status") == "failed":
            harness.results[-1]["error_type"] = failure_type
        print(
            harness.redact(f"{failure_type}: {error}"),
            file=sys.stderr,
            flush=True,
        )
        return False
    return True


def run_harness(harness, cases):
    """Run setup, cases and cleanup behind one redaction boundary.

    Returns the success flag, the cleanup result and a fixed failure descriptor
    used by the optional report.  Raw exception text is never returned.
    """
    success = False
    cleanup_ok = True
    failure = None
    try:
        harness.setup()
        success = run_cases(harness, cases)
        if not success:
            failure = {
                "stage": "cases",
                "type": getattr(harness, "case_failure_type", "CaseFailure"),
            }
    except Exception as error:
        failure_type = type(error).__name__
        harness.results.append(
            {
                "name": "harness setup",
                "status": "failed",
                "seconds": 0.0,
                "error": harness.redact(error),
                "error_type": failure_type,
            }
        )
        failure = {"stage": "setup", "type": failure_type}
        print(
            harness.redact(f"{failure_type}: {error}"),
            file=sys.stderr,
            flush=True,
        )
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            failure_type = type(error).__name__
            cleanup_ok = False
            harness.results.append(
                {
                    "name": "cleanup",
                    "status": "failed",
                    "seconds": 0.0,
                    "error": harness.redact(error),
                    "error_type": failure_type,
                }
            )
            failure = {"stage": "cleanup", "type": failure_type}
            print(
                harness.redact(f"cleanup failed: {failure_type}: {error}"),
                file=sys.stderr,
                flush=True,
            )
            success = False
    return {
        "success": success and cleanup_ok,
        "cleanup_ok": cleanup_ok,
        "failure": failure,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument(
        "--report",
        type=Path,
        help="write a credential-free structured report bound to the binary receipt",
    )
    parser.add_argument(
        "--expected-commit",
        help="require the build receipt's workspace_commit to equal this commit",
    )
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if args.report is None:
        harness = TrustBoundaryHarness(args)
        result = run_harness(harness, bound_cases(harness))
        return 0 if result["success"] else 1

    start = None
    start_error = None
    try:
        start = capture_provenance(args.binary, args.expected_commit)
    except ReportError as error:
        start_error = error.code
    except Exception:
        start_error = "source_binding_failed"
    harness = None
    result = None
    if start_error is None:
        harness = TrustBoundaryHarness(args)
        result = run_harness(harness, bound_cases(harness))
    end = None
    end_error = None
    if start is not None:
        try:
            end = capture_provenance(args.binary, args.expected_commit)
        except ReportError as error:
            end_error = error.code
        except Exception:
            end_error = "source_binding_failed"
    report = build_report(start, end, result, harness, start_error, end_error)
    try:
        write_report(args.report, report)
    except OSError:
        print("ci trust boundaries: report write failed", file=sys.stderr, flush=True)
        return 1
    print(
        f"ci trust boundaries: {'passed' if report['passed'] else 'failed'} "
        f"({len(report['cases'])} cases)",
        flush=True,
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
