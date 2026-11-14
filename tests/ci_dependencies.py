#!/usr/bin/env python3
"""Real nested Gitlink and Git LFS checkout from a prepared CI mirror.

The positive path exercises stock Git/Git LFS against a prepared read mirror.
The negative cases freeze each dependency to its exact immutable identity:
moving a submodule branch must not change a planned gitlink, delegated tokens
must not authorize a parent, sibling, or unrelated source, and unsafe
``.gitmodules`` URLs must fail before any request can carry a credential.
"""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import sys
import threading
import traceback
import uuid

from ci_job_checkouts import JobCheckoutHarness

SETUP_CASES = (
    "missing_or_corrupt_dependency_blocks_ready",
    "prepared_mirror_nested_lfs_checkout",
    "unauthorized_dependency_source_is_rejected",
    "dependency_credentials_are_scope_bound",
    "moved_submodule_branch_keeps_pinned_gitlink",
    "cancellation_revokes_all_dependency_credentials",
)
INTEGRATION_CASES = (
    "integration_claim_prepares_exact_dependencies",
    "origin_fallback_dependency_credential_boundaries",
)
FINAL_CASES = (
    "unsafe_gitmodules_url_receives_no_credentials",
)
CASE_NAMES = SETUP_CASES + INTEGRATION_CASES + FINAL_CASES


class CredentialSink(http.server.BaseHTTPRequestHandler):
    """Record, but never echo, any request that could carry a credential."""

    def _record(self):
        self.server.requests.append(
            {"method": self.command, "path": self.path,
             "authorization": self.headers.get("Authorization")})
        self.send_response(500)
        self.end_headers()

    do_GET = _record
    do_POST = _record

    def log_message(self, *_args):
        pass


class DependencyCheckoutHarness(JobCheckoutHarness):
    def __init__(self, args):
        super().__init__(args)
        self.env["ROOTYARD_CI_ORIGIN_PUBLIC_URL"] = self.base
        # The registered hook targets a test-owned loopback listener.
        self.env["ROOTYARD_WEBHOOK_ALLOW_LOOPBACK"] = "true"
        self.mirror_env["ROOTYARD_CI_MIRROR_PUBLIC_URL"] = self.mirror_base
        self.grant = None
        self.second_body = None
        self.second_grant = None
        self.claim = None
        self.origin_lfs_path = None
        self.origin_grand_token = None
        self.origin_child_token = None
        self.service_token = None

    def start_mirror(self):
        # mirror_env is snapshotted into the mirror process at spawn. Alice is
        # created by setup(), so bind the source token at the actual startup
        # (and any later restart), never before fixture initialization.
        self.mirror_env["ROOTYARD_CI_MIRROR_SOURCE_TOKEN"] = self.alice["token"]
        super().start_mirror()

    def make_repo(self, name):
        repo = json.loads(self.expect("/api/repos", 201, token=self.alice,
                                      method="POST", body={"name": name}))
        work = self.root / name
        self.git("clone", self.base + repo["clone_path"], str(work), token=self.alice)
        self.git("config", "user.name", "CI Test", cwd=work)
        self.git("config", "user.email", "ci@example.invalid", cwd=work)
        return repo, work

    def link(self, work, path, name, oid):
        (work / ".gitmodules").write_text(
            f'[submodule "{name}"]\n\tpath = {path}\n\turl = ../{name}.git\n')
        self.git("add", ".gitmodules", cwd=work)
        self.git("update-index", "--add", "--cacheinfo", f"160000,{oid},{path}", cwd=work)
        self.git("commit", "-m", f"pin {name}", cwd=work)
        return self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()

    def mirror_denied(self, path, token):
        status, raw, _ = self.mirror_http(path, token=token)
        assert status in (401, 403, 404, 409), (status, raw[:300])

    def setup_dependency_fixture(self):
        self.setup_mirror()
        self.grand, self.grand_work = self.make_repo("grand")
        self.git("lfs", "install", "--local", cwd=self.grand_work)
        self.git("lfs", "track", "big.bin", cwd=self.grand_work)
        payload = b"nested Git LFS fixture\n" * 8192
        (self.grand_work / "big.bin").write_bytes(payload)
        self.git("add", ".gitattributes", "big.bin", cwd=self.grand_work)
        self.git("commit", "-m", "large immutable input", cwd=self.grand_work)
        self.grand_oid = self.git("rev-parse", "HEAD", cwd=self.grand_work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=self.grand_work, token=self.alice)
        self.lfs_payload = payload
        self.lfs_oid = hashlib.sha256(payload).hexdigest()
        assert self.sql("SELECT state FROM lfs_objects WHERE repository_id='" + self.grand["id"] +
                        "' AND oid='" + self.lfs_oid + "'") == "ready"
        self.child, self.child_work = self.make_repo("child")
        self.child_oid = self.link(self.child_work, "deps/grand", "grand", self.grand_oid)
        self.git("push", "origin", "HEAD:main", cwd=self.child_work, token=self.alice)
        self.root_oid = self.link(self.work, "deps/child", "child", self.child_oid)
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        self.body = self.request_body(oid=self.root_oid, job=str(uuid.uuid4()))
        self.pin(self.pin_body(self.root_oid, self.body["job_id"], 1))

    def missing_or_corrupt_dependency_blocks_ready(self):
        object_path = self.root / "data" / "lfs" / self.grand["id"] / self.lfs_oid
        missing = object_path.with_name(self.lfs_oid + ".temporarily-missing")
        object_path.rename(missing)
        try:
            self.issue(self.body, codes=409)
        finally:
            missing.rename(object_path)
        original = object_path.read_bytes()
        object_path.write_bytes(b"corrupted CI LFS fixture")
        try:
            self.issue(self.body, codes=409)
        finally:
            object_path.write_bytes(original)
        self.grant = self.issue(self.body)
        deps = self.grant["plan"]["dependencies"]
        assert len(deps["submodules"]) == 2 and len(deps["lfs"]) == 1, deps
        assert deps["lfs"][0]["oid"] == self.lfs_oid
        credentials = {item["name"]: item for item in self.grant["submodule_credentials"]}
        assert set(credentials) == {"child", "grand"}
        self.credentials = credentials
        self.root_token = {"username": "alice", "token": self.grant["token"]}
        return dict(missing_lfs_blocks_ready=True, corrupt_lfs_blocks_ready=True,
                    dependencies=len(deps["submodules"]) + len(deps["lfs"]))

    def prepared_mirror_nested_lfs_checkout(self):
        credentials = self.credentials
        prepare = f"{self.checkout_path}/{self.body['job_id']}/prepare-dependencies"
        status, raw, _ = self.mirror_http(prepare, token=self.alice, method="POST", body=b"")
        assert status == 200, (status, raw[:500])
        grand_token = {"username": "alice", "token": credentials["grand"]["token"]}
        grand_base = f"/ci/{self.grand_oid}/git/alice/grand.git/info/lfs/objects"
        batch_status, batch_raw, _ = self.mirror_http(
            grand_base + "/batch", token=grand_token, method="POST",
            body={"operation": "download",
                  "objects": [{"oid": self.lfs_oid, "size": len(self.lfs_payload)}]})
        assert batch_status == 200, (batch_status, batch_raw[:500])
        get_status, get_raw, _ = self.mirror_http(
            grand_base + "/" + self.lfs_oid, token=grand_token)
        assert get_status == 200 and get_raw == self.lfs_payload, (get_status, get_raw[:200])
        clone = self.root / "nested-build"
        self.git("clone", self.mirror_base + self.path(self.root_oid), str(clone),
                 token=self.root_token)
        for name, parent, path in (("child", clone, "deps/child"),
                                   ("grand", clone / "deps/child", "deps/grand")):
            item = credentials[name]
            url = f"{self.mirror_base}/ci/{item['target_oid']}/git/alice/{name}.git"
            self.git("config", f"submodule.{name}.url", url, cwd=parent)
            env = self.env.copy()
            env["GIT_LFS_SKIP_SMUDGE"] = "1"
            self.git("submodule", "update", "--init", path, cwd=parent,
                     token={"username": "alice", "token": item["token"]}, env=env)
        grand_clone = clone / "deps/child/deps/grand"
        self.git("lfs", "install", "--local", cwd=grand_clone)
        self.git("config", "credential.helper",
                 '!f() { if test "$1" = get; then echo username=alice; '
                 'echo password="$CI_JOB_TOKEN"; fi; }; f', cwd=grand_clone)
        env = self.env.copy()
        env["CI_JOB_TOKEN"] = grand_token["token"]
        self.git("lfs", "pull", cwd=grand_clone, token=grand_token, env=env)
        self.git("lfs", "checkout", "big.bin", cwd=grand_clone, token=grand_token, env=env)
        observed = (grand_clone / "big.bin").read_bytes()
        assert observed == self.lfs_payload, (len(observed), len(self.lfs_payload))
        assert self.git("rev-parse", "HEAD", cwd=grand_clone).stdout.decode().strip() == self.grand_oid
        return dict(stock_git_nested_submodules=True, stock_git_lfs=True,
                    lfs_bytes=len(observed), grand_head=self.grand_oid)

    def unauthorized_dependency_source_is_rejected(self):
        bob_repo = self.create_repository({"name": "bob-secret"}, token=self.bob)
        bob_work = self.root / "bob-secret"
        self.git("clone", self.base + bob_repo["clone_path"], str(bob_work), token=self.bob)
        self.git("config", "user.name", "Bob", cwd=bob_work)
        self.git("config", "user.email", "bob@example.invalid", cwd=bob_work)
        (bob_work / "secret.txt").write_text("not visible to alice\n")
        self.git("add", "secret.txt", cwd=bob_work)
        self.git("commit", "-m", "bob private source", cwd=bob_work)
        bob_oid = self.git("rev-parse", "HEAD", cwd=bob_work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=bob_work, token=self.bob)
        self.git("checkout", "-b", "unauthorized-source", cwd=self.work)
        try:
            (self.work / ".gitmodules").write_text(
                '[submodule "bob"]\n\tpath = deps/bob\n'
                '\turl = ../../bob/bob-secret.git\n')
            self.git("add", ".gitmodules", cwd=self.work)
            self.git("update-index", "--add", "--cacheinfo",
                     f"160000,{bob_oid},deps/bob", cwd=self.work)
            self.git("commit", "-m", "link an unauthorized dependency", cwd=self.work)
            unauthorized_oid = self.git("rev-parse", "HEAD",
                                        cwd=self.work).stdout.decode().strip()
            self.git("push", "origin", "HEAD:refs/heads/unauthorized-source",
                     cwd=self.work, token=self.alice)
            job = str(uuid.uuid4())
            self.pin(self.pin_body(unauthorized_oid, job, 1))
            self.issue(self.request_body(oid=unauthorized_oid, job=job),
                       codes=(403, 404, 409))
        finally:
            self.git("checkout", "main", cwd=self.work)
        return dict(independent_dependency_read_required=True,
                    unauthorized_source_not_planned=True)

    def dependency_credentials_are_scope_bound(self):
        child_root = f"/ci/{self.child_oid}/git/alice/child.git"
        grand_root = f"/ci/{self.grand_oid}/git/alice/grand.git"
        advertise = "/info/refs?service=git-upload-pack"
        # A parent, sibling, or arbitrary source cannot reuse another
        # dependency's credential or the root job credential.
        for path, token in (
            (child_root + advertise, self.root_token),
            (grand_root + advertise, self.credentials["child"]),
            (child_root + advertise, self.credentials["grand"]),
            (self.path(self.root_oid) + advertise, self.credentials["child"]),
            (f"/ci/{self.second}/git/alice/child.git" + advertise, self.credentials["child"]),
        ):
            self.mirror_denied(path, {"username": "alice", "token": token["token"]})
        origin_grand = (f"/ci/{self.grand_oid}/git/alice/grand.git/info/lfs/objects/"
                        + self.lfs_oid)
        grand_token = {"username": "alice", "token": self.credentials["grand"]["token"]}
        status, content, _ = self.http(origin_grand, token=grand_token)
        assert status == 200 and content == self.lfs_payload, (status, len(content))
        for token in (self.root_token, self.credentials["child"]):
            status, raw, _ = self.http(origin_grand, token=token)
            assert status in (401, 403), (status, raw[:300])
        # The same delegated token is also bound to the planned target and
        # repository, never to a moved branch tip or a different source.
        for path in (f"/ci/{self.child_oid}/git/alice/grand.git/info/lfs/objects/{self.lfs_oid}",
                     f"/ci/{self.grand_oid}/git/alice/demo.git/info/lfs/objects/{self.lfs_oid}"):
            status, raw, _ = self.http(path, token=grand_token)
            assert status in (401, 403), (status, raw[:300])
        batch = {"operation": "download",
                 "objects": [{"oid": self.lfs_oid, "size": len(self.lfs_payload)}]}
        batch_path = f"/ci/{self.grand_oid}/git/alice/grand.git/info/lfs/objects/batch"
        for token in (self.root_token, self.credentials["child"]):
            status, raw, _ = self.http(batch_path, token=token, method="POST", body=batch)
            assert status in (401, 403), (status, raw[:300])
        status, raw, _ = self.http(batch_path, token=grand_token, method="POST", body=batch)
        assert status == 200, (status, raw[:300])
        action = json.loads(raw)["objects"][0]["actions"]["download"]["href"]
        assert action.startswith(self.base + "/ci/"), action
        return dict(parent_sibling_and_unbound_source_denied=True,
                    dependency_token_bound_to_exact_repo_and_target=True,
                    origin_lfs_href_from_configured_origin=True)

    def moved_submodule_branch_keeps_pinned_gitlink(self):
        moved_payload = b"moved submodule branch only\n" * 512
        moved_lfs_oid = hashlib.sha256(moved_payload).hexdigest()
        (self.grand_work / "moved-only.bin").write_bytes(moved_payload)
        self.git("lfs", "track", "moved-only.bin", cwd=self.grand_work)
        self.git("add", ".gitattributes", "moved-only.bin", cwd=self.grand_work)
        self.git("commit", "-m", "moving branch adds a new LFS input", cwd=self.grand_work)
        moved_grand = self.git("rev-parse", "HEAD", cwd=self.grand_work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=self.grand_work, token=self.alice)
        self.git("update-index", "--add", "--cacheinfo",
                 f"160000,{moved_grand},deps/grand", cwd=self.child_work)
        self.git("commit", "-m", "moving branch moves the pinned gitlink", cwd=self.child_work)
        moved_child = self.git("rev-parse", "HEAD", cwd=self.child_work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=self.child_work, token=self.alice)
        assert moved_grand != self.grand_oid and moved_child != self.child_oid
        # Make the mirror snapshot observe both moved branches. The checkout
        # plan must still be derived from the parent's exact gitlink commits.
        for name in ("child", "grand"):
            self.mirror_expect(f"/api/repos/alice/{name}/mirror-sync", 200,
                               token=self.reader, method="POST", body=b"")
        body = self.request_body(oid=self.root_oid)
        self.pin(self.pin_body(self.root_oid, body["job_id"], 1))
        grant = self.issue(body)
        deps = grant["plan"]["dependencies"]
        child_dep = next(item for item in deps["submodules"] if item["name"] == "child")
        grand_dep = next(item for item in deps["submodules"] if item["name"] == "grand")
        assert child_dep["target_oid"] == self.child_oid, child_dep
        assert grand_dep["target_oid"] == self.grand_oid, grand_dep
        assert len(deps["lfs"]) == 1, deps["lfs"]
        planned_lfs = deps["lfs"][0]
        assert str(planned_lfs["repository_id"]).lower() == str(self.grand["id"]).lower()
        assert planned_lfs["path"] == "deps/child/deps/grand/big.bin", planned_lfs
        assert planned_lfs["oid"] == self.lfs_oid and planned_lfs["size"] == len(self.lfs_payload)
        assert moved_lfs_oid not in json.dumps(deps), "moved branch LFS input entered the plan"
        prepare = f"{self.checkout_path}/{body['job_id']}/prepare-dependencies"
        status, raw, _ = self.mirror_http(prepare, token=self.alice, method="POST", body=b"")
        assert status == 200, (status, raw[:500])
        child_credential = next(item for item in grant["submodule_credentials"]
                                if item["name"] == "child")
        child_token = {"username": "alice", "token": child_credential["token"]}
        clone = self.root / "moved-branch-pinned-child"
        self.git("clone", f"{self.mirror_base}/ci/{self.child_oid}/git/alice/child.git",
                 str(clone), token=child_token)
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == self.child_oid
        assert self.git("cat-file", "-e", moved_child, cwd=clone, check=False).returncode != 0
        assert self.git("cat-file", "-e", moved_grand, cwd=clone, check=False).returncode != 0
        self.mirror_denied(
            f"/ci/{moved_child}/git/alice/child.git/info/refs?service=git-upload-pack",
            child_token)
        self.second_body = body
        self.second_grant = grant
        return dict(moved_child=moved_child, moved_grand=moved_grand,
                    planned_child=self.child_oid, planned_grand=self.grand_oid,
                    moved_lfs_excluded=True)

    def cancellation_revokes_all_dependency_credentials(self):
        child_path = (f"/ci/{self.child_oid}/git/alice/child.git"
                      "/info/refs?service=git-upload-pack")
        grand_path = (f"/ci/{self.grand_oid}/git/alice/grand.git"
                      "/info/refs?service=git-upload-pack")
        origin_grand = (f"/ci/{self.grand_oid}/git/alice/grand.git/info/lfs/objects/"
                        + self.lfs_oid)
        second_credentials = {item["name"]: item
                              for item in self.second_grant["submodule_credentials"]}
        second_child = {"username": "alice",
                        "token": second_credentials["child"]["token"]}
        second_grand = {"username": "alice",
                        "token": second_credentials["grand"]["token"]}
        # The original second-grant credentials and exact planned endpoints
        # must work before cancellation. Reuse these same credentials below;
        # cancellation is not allowed to be masked by a reissued credential.
        self.mirror_expect(child_path, 200, token=second_child)
        self.mirror_expect(grand_path, 200, token=second_grand)
        status, content, _ = self.mirror_http(origin_grand, token=second_grand)
        assert status == 200 and content == self.lfs_payload, (status, len(content))
        status, content, _ = self.http(origin_grand, token=second_grand)
        assert status == 200 and content == self.lfs_payload, (status, len(content))
        self.transition(self.body["job_id"], "cancel")
        self.transition(self.second_body["job_id"], "cancel")
        child_token = {"username": "alice", "token": self.credentials["child"]["token"]}
        grand_token = {"username": "alice", "token": self.credentials["grand"]["token"]}
        for token in (child_token, second_child):
            self.mirror_denied(child_path, token)
        for token in (grand_token, second_grand):
            self.mirror_denied(grand_path, token)
        for token in (grand_token, second_grand):
            status, raw, _ = self.http(origin_grand, token=token)
            assert status in (401, 403), (status, raw[:300])
        self.issue(self.body, codes=409)
        self.issue(self.second_body, codes=409)
        return dict(first_and_second_parent_cancellation_revokes_dependencies=True,
                    second_grant_mirror_and_origin_lfs_revoked=True,
                    exact_pre_cancel_content_reused=True,
                    terminal_jobs_do_not_reissue=True)


    def integration_claim_prepares_exact_dependencies(self):
        hook_secret = "nested-integration-secret-123456"
        self.secrets.append(hook_secret)
        hook = json.loads(self.expect(
            "/api/repos/alice/demo/webhooks", 201, token=self.alice, method="POST",
            body={"url": "http://127.0.0.1:1/hook", "secret": hook_secret,
                  "events": ["pull_request"], "ci_contexts": ["ci/nested"],
                  "auto_ci_pin": True}))
        hook_id = hook["id"]
        self.expect(f"/api/repos/alice/demo/integrations/{hook_id}/trusted-contexts", 200,
                    token=self.alice, method="PUT", body={"context": "ci/nested"})
        for source in ("child", "grand"):
            self.expect(f"/api/repos/alice/{source}/ci-source-grants/{hook_id}", 200,
                        token=self.alice, method="PUT", body={})
        self.git("checkout", "-b", "feature", cwd=self.work)
        self.git("commit", "--allow-empty", "-m", "CI feature", cwd=self.work)
        feature_oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:feature", cwd=self.work, token=self.alice)
        pr = json.loads(self.expect(
            "/api/repos/alice/demo/pulls", 201, token=self.alice, method="POST",
            body={"title": "Nested CI", "body": "real dependencies",
                  "head_ref": "refs/heads/feature", "base_ref": "refs/heads/main"}))
        assert pr["head_oid"] == feature_oid
        run_id = self.sql("SELECT id FROM ci_runs WHERE repository_id='" + self.repo["id"] +
                          "' AND context='ci/nested' AND head_oid='" + feature_oid + "'")
        claim_path = f"/api/repos/alice/demo/integrations/{hook_id}/runs/{run_id}/claim"
        status, raw, _ = self.http(claim_path, method="POST",
                                   body={"runner_id": "nested-runner"},
                                   extra_headers={"Authorization": "Bearer " + hook_secret})
        assert status == 200, (status, raw[:300])
        claim = json.loads(raw)
        self.claim = claim
        assert len(claim["checkout"]["submodule_credentials"]) == 2
        root_job = claim["checkout"]["plan"]["job_id"]
        self.service_token = {"username": "alice", "token": claim["checkout"]["token"]}
        self.secrets.extend([self.service_token["token"]] +
                            [item["token"] for item in claim["checkout"]["submodule_credentials"]])
        service_prep = f"/api/repos/alice/demo/ci-checkouts/{root_job}/prepare-dependencies"
        status, raw, _ = self.mirror_http(service_prep, token=self.service_token,
                                          method="POST", body=b"")
        assert status == 200, (status, raw[:300])
        service_clone = self.root / "integration-build"
        self.git("clone", self.mirror_base + self.path(feature_oid), str(service_clone),
                 token=self.service_token)
        assert self.git("rev-parse", "HEAD", cwd=service_clone).stdout.decode().strip() == feature_oid
        if not self.args.mirror_only:
            origin_clone = self.root / "integration-origin-build"
            self.git("clone", self.base + self.path(feature_oid), str(origin_clone),
                     token=self.service_token)
            assert self.git("rev-parse", "HEAD",
                            cwd=origin_clone).stdout.decode().strip() == feature_oid
            origin_grand = next(item for item in claim["checkout"]["submodule_credentials"]
                                if item["name"] == "grand")
            origin_child = next(item for item in claim["checkout"]["submodule_credentials"]
                                if item["name"] == "child")
            self.origin_grand_token = {"username": "alice", "token": origin_grand["token"]}
            self.origin_child_token = {"username": "alice", "token": origin_child["token"]}
            self.origin_lfs_path = (f"/ci/{self.grand_oid}/git/alice/grand.git/info/lfs/"
                                    f"objects/{self.lfs_oid}")
            status, content, _ = self.http(self.origin_lfs_path, token=self.origin_grand_token)
            assert status == 200 and content == self.lfs_payload, (status, len(content))
            self.git("tag", "-a", "build-input", "-m", "fixed CI input", self.root_oid,
                     cwd=self.work)
            self.git("push", "origin", "refs/tags/build-input", cwd=self.work, token=self.alice)
            tag_oid = self.git("rev-parse", "refs/tags/build-input",
                               cwd=self.work).stdout.decode().strip()
            target_job = str(uuid.uuid4())
            self.pin(self.pin_body(feature_oid, target_job, 1))
            target_grant = self.issue(self.request_body(oid=feature_oid, job=target_job,
                                                        history="target", tags=["build-input"]))
            assert target_grant["plan"]["dependencies"]["tags"] == [
                {"name": "build-input", "object_oid": tag_oid}]
            target_token = {"username": "alice", "token": target_grant["token"]}
            target_clone = self.root / "origin-target-tag-build"
            self.git("clone", self.base + self.path(feature_oid), str(target_clone),
                     token=target_token)
            assert self.git("rev-parse", "HEAD",
                            cwd=target_clone).stdout.decode().strip() == feature_oid
            assert self.git("rev-list", "--count", "HEAD", cwd=target_clone).stdout.strip() == b"1"
            assert self.git("rev-parse", "refs/tags/build-input",
                            cwd=target_clone).stdout.decode().strip() == tag_oid
            self.git("fsck", "--full", cwd=target_clone)
            self.transition(target_job, "cancel")
            status, _, _ = self.http(self.advertise(feature_oid), token=target_token)
            assert status in (401, 403), status
            print("primary scoped target-history/tag clone and cancellation: passed", flush=True)
        print("fenced integration prepared and cloned nested manifest: passed", flush=True)
        return dict(integration_claim=True, mirror_root_exact=True,
                    origin_root_exact=not self.args.mirror_only,
                    origin_lfs_exact=not self.args.mirror_only,
                    tagged_target_exact=not self.args.mirror_only)

    def origin_fallback_dependency_credential_boundaries(self):
        assert not self.args.mirror_only
        assert self.origin_lfs_path and self.origin_grand_token and self.origin_child_token
        status, content, _ = self.http(self.origin_lfs_path, token=self.origin_grand_token)
        assert status == 200 and content == self.lfs_payload, (status, len(content))
        # Each dependency credential is independently authorized: the root CI
        # token and a sibling source token cannot retrieve grand's LFS object.
        for token in (self.service_token, self.origin_child_token):
            status, raw, _ = self.http(self.origin_lfs_path, token=token)
            assert status in (401, 403), (status, raw[:300])
        # The token is bound to the exact planned repository and target OID.
        for path in (f"/ci/{self.child_oid}/git/alice/grand.git/info/lfs/objects/{self.lfs_oid}",
                     f"/ci/{self.grand_oid}/git/alice/demo.git/info/lfs/objects/{self.lfs_oid}"):
            status, raw, _ = self.http(path, token=self.origin_grand_token)
            assert status in (401, 403), (status, raw[:300])
        batch = {"operation": "download",
                 "objects": [{"oid": self.lfs_oid, "size": len(self.lfs_payload)}]}
        batch_path = f"/ci/{self.grand_oid}/git/alice/grand.git/info/lfs/objects/batch"
        for token in (self.service_token, self.origin_child_token):
            status, raw, _ = self.http(batch_path, token=token, method="POST", body=batch)
            assert status in (401, 403), (status, raw[:300])
        status, raw, _ = self.http(batch_path, token=self.origin_grand_token,
                                   method="POST", body=batch)
        assert status == 200, (status, raw[:300])
        href = json.loads(raw)["objects"][0]["actions"]["download"]["href"]
        assert href.startswith(self.base + "/ci/"), href
        assert self.origin_grand_token["token"] not in href
        return dict(parent_and_sibling_origin_lfs_denied=True,
                    origin_target_and_repo_bound=True,
                    origin_action_has_no_credential=True)

    def unsafe_gitmodules_url_receives_no_credentials(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CredentialSink)
        server.requests = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/outside/child.git"
            (self.work / ".gitmodules").write_text(
                f'[submodule "child"]\n\tpath = deps/child\n\turl = {url}\n')
            self.git("add", ".gitmodules", cwd=self.work)
            self.git("commit", "-m", "unsafe URL fixture", cwd=self.work)
            unsafe_oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
            self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
            job = str(uuid.uuid4())
            self.pin(self.pin_body(unsafe_oid, job, 1))
            self.issue(self.request_body(oid=unsafe_oid, job=job), codes=409)
            assert not server.requests, "unsafe .gitmodules URL received a request"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        return dict(unsafe_url_rejected=True, requests_to_unsafe_url=0,
                    credential_forwarded=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--mirror-only", action="store_true",
                        help="Run mirror materialization before the primary scoped Git route is available")
    parser.add_argument("--user-only", action="store_true",
                        help="Run owner-issued nested checkout without signed integration claim")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    harness = DependencyCheckoutHarness(args)
    passed = False
    try:
        harness.setup_dependency_fixture()
        for name in SETUP_CASES:
            harness.case(name, getattr(harness, name))
        if not args.user_only:
            for name in INTEGRATION_CASES:
                if name == "origin_fallback_dependency_credential_boundaries" and args.mirror_only:
                    continue
                harness.case(name, getattr(harness, name))
        for name in FINAL_CASES:
            harness.case(name, getattr(harness, name))
        passed = True
    except Exception:
        print(harness.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(dict(name="cleanup", status="failed",
                                        error=harness.redact(error)))
            passed = False
        report = dict(
            passed=passed,
            cases=harness.results,
            binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            limitations=[
                "Isolated loopback services and synthetic fixtures, not production performance or power-loss validation.",
                "The credential sink proves no request reached an unsafe .gitmodules URL; it is not an external-network firewall test.",
            ])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
