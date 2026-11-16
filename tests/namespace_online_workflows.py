#!/usr/bin/env python3
"""End-to-end online Namespace, Smart HTTP View, RBAC/scope, conflict, and crash recovery tests (Refs #31)."""
import argparse
import base64
import gzip
import hashlib
import http.client
import json
from pathlib import Path
import sys
import traceback
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from e2e import Harness  # noqa: E402
from runtime_binary import select_runtime_binary  # noqa: E402


class NamespaceOnlineHarness(Harness):
    def create_scoped_pat(self, owner_token, name, grants, *, read_only):
        pat = json.loads(
            self.expect(
                "/api/tokens",
                201,
                token=owner_token,
                method="POST",
                body={
                    "display_name": name,
                    "expires_in_days": 1,
                    "read_only": read_only,
                    "repository_grants": grants,
                    "namespace_grants": [],
                },
            )
        )
        self.secrets.append(pat["secret"])
        return {"username": owner_token["username"], "token": pat["secret"], "id": pat["id"]}

    def create_user(self, username):
        return self.account("create-user", username)

    def create_repo(self, token, name):
        return json.loads(
            self.expect(
                "/api/repos",
                201,
                token=token,
                method="POST",
                body={"name": name, "object_format": "sha1"},
            )
        )

    def push_files(self, clone_dir, repo_url, token, branch, files, message):
        self.git("config", "user.name", token["username"], cwd=clone_dir)
        self.git("config", "user.email", f"{token['username']}@example.invalid", cwd=clone_dir)
        for rel, text in files.items():
            target = clone_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
            self.git("add", rel, cwd=clone_dir)
        self.git("commit", "-m", message, cwd=clone_dir)
        oid = self.git("rev-parse", "HEAD", cwd=clone_dir).stdout.decode().strip()
        self.git("push", repo_url, f"HEAD:{branch}", cwd=clone_dir, token=token)
        return oid

    @staticmethod
    def pkt_line(payload: bytes) -> bytes:
        return f"{len(payload) + 4:04x}".encode("ascii") + payload

    def smart_http_clone_boundary_history_and_readonly(self):
        self.setup()
        self.api()
        self.roundtrip()
        self.demo = json.loads(self.expect("/api/repos/alice/demo", 200, token=self.alice))

        (self.work / "pkg").mkdir(exist_ok=True)
        (self.work / "pkg" / "lib.rs").write_text("pub fn v() -> i32 { 7 }\n")
        (self.work / "docs").mkdir(exist_ok=True)
        (self.work / "docs" / "secret.txt").write_text("unmounted-secret\n")
        self.git("add", "pkg/lib.rs", "docs/secret.txt", cwd=self.work)
        self.git("commit", "-m", "add pkg and unmounted docs", cwd=self.work)
        self.base_oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=self.work, token=self.alice)

        self.second_repo = self.create_repo(self.alice, "second")
        work2 = self.root / "work-second"
        self.git("clone", f"{self.base}/git/alice/second.git", str(work2), token=self.alice)
        self.second_base = self.push_files(
            work2,
            f"{self.base}/git/alice/second.git",
            self.alice,
            "refs/heads/main",
            {"api/spec.txt": "v1\n"},
            "init second repo",
        )

        self.ns = json.loads(
            self.expect(
                "/api/namespaces",
                201,
                token=self.alice,
                method="POST",
                body={
                    "name": "online-corp",
                    "mounts": [
                        {
                            "path": "payments",
                            "owner": "alice",
                            "repository": "demo",
                            "base_oid": self.base_oid,
                        },
                        {
                            "path": "services/api",
                            "owner": "alice",
                            "repository": "second",
                            "base_oid": self.second_base,
                        },
                    ],
                },
            )
        )

        # Missing subdir must fail closed rather than silently exposing full root tree.
        bad_st, _, _ = self.http(
            f"/api/namespaces/{self.ns['id']}/views",
            token=self.alice,
            method="POST",
            body={"mount_path": "payments", "subdir": "missing-dir"},
        )
        assert bad_st == 400, f"missing subdir returned {bad_st}"

        self.view = json.loads(
            self.expect(
                f"/api/namespaces/{self.ns['id']}/views",
                201,
                token=self.alice,
                method="POST",
                body={"mount_path": "payments", "subdir": "pkg"},
            )
        )
        vid = self.view["id"]

        # Anonymous probe must return 401 with Basic WWW-Authenticate challenge.
        anon_st, _, anon_hdrs = self.http(f"/git/views/{vid}.git/info/refs?service=git-upload-pack")
        assert anon_st == 401, anon_st
        www_auth = next((v for k, v in anon_hdrs.items() if k.lower() == "www-authenticate"), "")
        assert www_auth.startswith("Basic "), www_auth

        # Unrelated user Bob gets 404 across API, history, bundle, and Smart HTTP endpoints.
        for path, method in (
            (f"/api/views/{vid}", "GET"),
            (f"/api/views/{vid}/history", "GET"),
            (f"/api/views/{vid}/bundle", "GET"),
            (f"/git/views/{vid}.git/info/refs?service=git-upload-pack", "GET"),
            (f"/git/views/{vid}.git/git-receive-pack", "POST"),
        ):
            st, _, _ = self.http(path, token=self.bob, method=method)
            assert st == 404, (path, st)

        # Bad Smart HTTP paths/services fail deterministically.
        assert self.http(f"/git/views/{vid}/info/refs?service=git-upload-pack", token=self.alice)[0] == 404
        assert self.http(f"/git/views/00000000-0000-0000-0000-000000000000.git/info/refs?service=git-upload-pack", token=self.alice)[0] == 404
        assert self.http(f"/git/views/{vid}.git/info/refs", token=self.alice)[0] == 400

        # History endpoint exposes persisted definition, epoch, and source <-> projected mapping.
        hist = json.loads(self.expect(f"/api/views/{vid}/history", 200, token=self.alice))
        assert hist["view"]["id"] == vid
        assert hist["view"]["epoch"] == 1
        assert hist["view"]["source_oid"] == self.base_oid
        assert hist["view"]["projected_oid"] == self.view["projected_oid"]
        assert hist["mappings"] == [
            {
                "epoch": 1,
                "source_oid": self.base_oid,
                "projected_oid": self.view["projected_oid"],
            }
        ]

        # Stock git clone retrieves reproducible projected commits and never exposes unmounted files/commits.
        self.view_clone = self.root / "view-http-clone"
        self.git("clone", f"{self.base}/git/views/{vid}.git", str(self.view_clone), token=self.alice)
        assert (self.view_clone / "lib.rs").read_text() == "pub fn v() -> i32 { 7 }\n"
        assert not (self.view_clone / "secret.txt").exists()
        assert not (self.view_clone / "hello.txt").exists()
        cloned_head = self.git("rev-parse", "HEAD", cwd=self.view_clone).stdout.decode().strip()
        assert cloned_head == self.view["projected_oid"]
        assert self.git("cat-file", "-e", f"{self.base_oid}^{{commit}}", cwd=self.view_clone, check=False).returncode != 0

        # Raw upload-pack request targeting unprojected source commit OID must be rejected.
        want_source = self.pkt_line(f"want {self.base_oid}\n".encode()) + b"0000" + self.pkt_line(b"done\n")
        st_want, _, _ = self.http(
            f"/git/views/{vid}.git/git-upload-pack",
            token=self.alice,
            method="POST",
            body=gzip.compress(want_source),
            content_type="application/x-git-upload-pack-request",
            extra_headers={"Content-Encoding": "gzip"},
        )
        assert st_want == 400, st_want

        # Projected Git views fail closed with 403 on git-receive-pack and stock git push.
        assert self.http(f"/git/views/{vid}.git/info/refs?service=git-receive-pack", token=self.alice)[0] == 403
        assert self.http(f"/git/views/{vid}.git/git-receive-pack", token=self.alice, method="POST")[0] == 403
        self.git("config", "user.name", "alice", cwd=self.view_clone)
        self.git("config", "user.email", "alice@example.invalid", cwd=self.view_clone)
        (self.view_clone / "lib.rs").write_text("pub fn v() -> i32 { 8 }\n")
        self.git("commit", "-am", "view edit", cwd=self.view_clone)
        push_res = self.git("push", f"{self.base}/git/views/{vid}.git", "HEAD:refs/heads/projected", cwd=self.view_clone, token=self.alice, check=False)
        assert push_res.returncode != 0

        # Multi-mount boundary: read access on only one mount keeps View inaccessible until all mounts are authorized.
        self.expect("/api/repos/alice/demo/collaborators", 201, token=self.alice, method="POST", body={"username": "bob", "role": "read"})
        assert self.http(f"/git/views/{vid}.git/info/refs?service=git-upload-pack", token=self.bob)[0] == 404
        self.expect("/api/repos/alice/second/collaborators", 201, token=self.alice, method="POST", body={"username": "bob", "role": "read"})
        bob_clone = self.root / "view-bob-clone"
        self.git("clone", f"{self.base}/git/views/{vid}.git", str(bob_clone), token=self.bob)
        assert (bob_clone / "lib.rs").read_text() == "pub fn v() -> i32 { 7 }\n"
        self.expect("/api/repos/alice/second/collaborators/bob", 200, token=self.alice, method="DELETE")
        assert self.http(f"/git/views/{vid}.git/info/refs?service=git-upload-pack", token=self.bob)[0] == 404
        assert self.http(f"/api/views/{vid}/history", token=self.bob)[0] == 404
        self.expect("/api/repos/alice/demo/collaborators/bob", 200, token=self.alice, method="DELETE")
        return {"smart_http_clone": True, "unmounted_excluded": True, "receive_pack_403": True, "multi_mount_boundary": True}

    def fine_grained_token_scopes_and_repo_availability(self):
        vid = self.view["id"]
        no_contents_pat = self.create_scoped_pat(
            self.alice,
            "no-contents",
            [
                {"repository_id": self.demo["id"], "actions": ["repo_read", "issues_read"]},
                {"repository_id": self.second_repo["id"], "actions": ["repo_read", "issues_read"]},
            ],
            read_only=True,
        )
        for path, method, body in (
            ("/api/namespaces", "POST", {"name": "denied-ns", "mounts": [{"path": "payments", "owner": "alice", "repository": "demo", "base_oid": self.base_oid}]}),
            (f"/api/namespaces/{self.ns['id']}", "GET", None),
            (f"/api/views/{vid}", "GET", None),
            (f"/api/views/{vid}/history", "GET", None),
            (f"/api/views/{vid}/bundle", "GET", None),
            (f"/git/views/{vid}.git/info/refs?service=git-upload-pack", "GET", None),
        ):
            st, _, _ = self.http(path, token=no_contents_pat, method=method, body=body)
            assert st == 403, (path, st)

        read_pat = self.create_scoped_pat(
            self.alice,
            "contents-read-only",
            [
                {"repository_id": self.demo["id"], "actions": ["contents_read"]},
                {"repository_id": self.second_repo["id"], "actions": ["contents_read"]},
            ],
            read_only=True,
        )
        assert self.http(f"/api/views/{vid}/history", token=read_pat)[0] == 200
        scoped_clone = self.root / "view-scoped-read-clone"
        self.git("clone", f"{self.base}/git/views/{vid}.git", str(scoped_clone), token=read_pat)
        assert (scoped_clone / "lib.rs").read_text() == "pub fn v() -> i32 { 7 }\n"

        # Proposal bundle created from the Smart HTTP clone.
        proposal_bundle = self.root / "online-proposal.bundle"
        self.git("bundle", "create", str(proposal_bundle), "--all", cwd=self.view_clone)
        proposal_payload = {
            "bundle_base64": base64.b64encode(proposal_bundle.read_bytes()).decode(),
            "bundle_ref": "refs/heads/projected",
            "source_ref": "refs/heads/main",
            "message": "Update pkg via online Smart HTTP view",
        }
        # ContentsRead-only token must fail 403 on write entrypoints.
        assert self.http(f"/api/views/{vid}/changesets", token=read_pat, method="POST", body=proposal_payload)[0] == 403

        # Grant Bob Maintain collaborator and verify ContentsRead-only PAT cannot review/integrate.
        self.expect("/api/repos/alice/demo/collaborators", 201, token=self.alice, method="POST", body={"username": "bob", "role": "maintain"})
        self.expect("/api/repos/alice/second/collaborators", 201, token=self.alice, method="POST", body={"username": "bob", "role": "maintain"})
        bob_read_pat = self.create_scoped_pat(
            self.bob,
            "bob-read-only",
            [
                {"repository_id": self.demo["id"], "actions": ["contents_read"]},
                {"repository_id": self.second_repo["id"], "actions": ["contents_read"]},
            ],
            read_only=True,
        )

        # ContentsWrite token succeeds on reverse proposal.
        write_pat = self.create_scoped_pat(
            self.alice,
            "contents-write",
            [
                {"repository_id": self.demo["id"], "actions": ["contents_read", "contents_write"]},
                {"repository_id": self.second_repo["id"], "actions": ["contents_read"]},
            ],
            read_only=False,
        )
        cs = json.loads(self.expect(f"/api/views/{vid}/changesets", 201, token=write_pat, method="POST", body=proposal_payload))
        self.cs_reverse = cs
        assert self.http(f"/api/changesets/{cs['id']}/review", token=bob_read_pat, method="POST")[0] == 403
        assert self.http(f"/api/changesets/{cs['id']}/integrate", token=read_pat, method="POST")[0] == 403
        assert self.http(f"/api/changesets/{cs['id']}/recover", token=read_pat, method="POST")[0] == 403

        # Unavailable/non-ready mounted source repo fails closed on view/Git reads.
        self.sql(f"UPDATE repositories SET state='provisioning' WHERE id='{self.second_repo['id']}'")
        try:
            assert self.http(f"/api/views/{vid}", token=self.alice)[0] == 409
            assert self.http(f"/git/views/{vid}.git/info/refs?service=git-upload-pack", token=self.alice)[0] == 409
        finally:
            self.sql(f"UPDATE repositories SET state='ready' WHERE id='{self.second_repo['id']}'")
        assert self.http(f"/git/views/{vid}.git/info/refs?service=git-upload-pack", token=self.alice)[0] == 200
        return {"restricted_pat_enforced": True, "unavailable_repo_blocked": True}

    def reverse_proposal_and_concurrent_source_conflicts(self):
        vid = self.view["id"]
        cs = self.cs_reverse

        # Concurrent push directly to demo refs/heads/main while ChangeSet is reviewed.
        (self.work / "pkg" / "lib.rs").write_text("pub fn v() -> i32 { 99 }\n")
        self.git("commit", "-am", "concurrent source advance", cwd=self.work)
        advanced_oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=self.work, token=self.alice)

        # Independent reviewer approves cs, then integrate detects conflict cleanly without overwriting advanced_oid.
        self.expect(f"/api/changesets/{cs['id']}/review", 200, token=self.bob, method="POST")
        assert self.http(f"/api/changesets/{cs['id']}/integrate", token=self.alice, method="POST")[0] == 409
        cs_after = json.loads(self.expect(f"/api/changesets/{cs['id']}", 200, token=self.alice))
        assert cs_after["state"] == "conflict", cs_after
        assert cs_after["steps"][0]["applied"] is False
        live_main = self.git("--git-dir=" + str(self.bare), "rev-parse", "refs/heads/main").stdout.decode().strip()
        assert live_main == advanced_oid

        # New reverse proposal against advanced source ref also returns 409 Conflict.
        proposal_bundle = self.root / "online-proposal.bundle"
        stale_payload = {
            "bundle_base64": base64.b64encode(proposal_bundle.read_bytes()).decode(),
            "bundle_ref": "refs/heads/projected",
            "source_ref": "refs/heads/main",
            "message": "Stale reverse import",
        }
        assert self.http(f"/api/views/{vid}/changesets", token=self.alice, method="POST", body=stale_payload)[0] == 409
        return {"concurrent_integrate_conflict": True, "reverse_advanced_ref_409": True, "source_preserved": True}

    def crash_recovery_partial_visibility_and_complete_integration(self):
        self.carol = self.create_user("carol")
        repo_a = self.create_repo(self.alice, "crash-a")
        repo_b = self.create_repo(self.alice, "crash-b")
        for repo in ("crash-a", "crash-b"):
            self.expect(f"/api/repos/alice/{repo}/collaborators", 201, token=self.alice, method="POST", body={"username": "bob", "role": "maintain"})
            self.expect(f"/api/repos/alice/{repo}/collaborators", 201, token=self.alice, method="POST", body={"username": "carol", "role": "read"})

        work_a = self.root / "work-crash-a"
        work_b = self.root / "work-crash-b"
        url_a = f"{self.base}/git/alice/crash-a.git"
        url_b = f"{self.base}/git/alice/crash-b.git"
        self.git("clone", url_a, str(work_a), token=self.alice)
        self.git("clone", url_b, str(work_b), token=self.alice)
        old_a = self.push_files(work_a, url_a, self.alice, "refs/heads/main", {"a.txt": "base-a\n"}, "a base")
        old_b = self.push_files(work_b, url_b, self.alice, "refs/heads/main", {"b.txt": "base-b\n"}, "b base")
        new_a = self.push_files(work_a, url_a, self.alice, "refs/heads/stage-a", {"a.txt": "next-a\n"}, "a next")
        new_b = self.push_files(work_b, url_b, self.alice, "refs/heads/stage-b", {"b.txt": "next-b\n"}, "b next")

        ns = json.loads(
            self.expect(
                "/api/namespaces",
                201,
                token=self.alice,
                method="POST",
                body={
                    "name": "multi-crash",
                    "mounts": [
                        {"path": "svc-a", "owner": "alice", "repository": "crash-a", "base_oid": old_a},
                        {"path": "svc-b", "owner": "alice", "repository": "crash-b", "base_oid": old_b},
                    ],
                },
            )
        )
        cs = json.loads(
            self.expect(
                f"/api/namespaces/{ns['id']}/changesets",
                201,
                token=self.alice,
                method="POST",
                body={
                    "steps": [
                        {"mount_path": "svc-a", "ref_name": "refs/heads/main", "old_oid": old_a, "new_oid": new_a, "storage_generation": repo_a["storage_generation"]},
                        {"mount_path": "svc-b", "ref_name": "refs/heads/main", "old_oid": old_b, "new_oid": new_b, "storage_generation": repo_b["storage_generation"]},
                    ]
                },
            )
        )
        self.expect(f"/api/changesets/{cs['id']}/review", 200, token=self.bob, method="POST")

        # Restart with explicit failpoint to exit after step 1 (repo A updated, repo B untouched).
        self.stop()
        self.env["ROOTYARD_CHANGESET_KILL_AFTER_STEP"] = "1"
        try:
            self.start()
            response = None
            try:
                response = self.http(f"/api/changesets/{cs['id']}/integrate", token=self.alice, method="POST")
            except (OSError, urllib.error.URLError, http.client.HTTPException):
                pass
            assert response is None, f"expected failpoint exit, got HTTP {response[0]}: {response[1][:300]!r}"
            rc = self.proc.wait(timeout=10)
            assert rc == 79, f"expected failpoint exit 79, got {rc}"
        finally:
            self.env.pop("ROOTYARD_CHANGESET_KILL_AFTER_STEP", None)
            self.stop()
        self.start()

        # Unrelated reader observes explicit 'partial' state, never a false 'complete'.
        partial = json.loads(self.expect(f"/api/changesets/{cs['id']}", 200, token=self.carol))
        assert partial["state"] == "partial", partial
        assert partial["steps"][0]["applied"] is True
        assert partial["steps"][1]["applied"] is False
        bare_a = self.root / "data" / "repos" / f"{repo_a['id']}.git"
        bare_b = self.root / "data" / "repos" / f"{repo_b['id']}.git"
        assert self.git("--git-dir=" + str(bare_a), "rev-parse", "refs/heads/main").stdout.decode().strip() == new_a
        assert self.git("--git-dir=" + str(bare_b), "rev-parse", "refs/heads/main").stdout.decode().strip() == old_b

        # Regular integrate refuses partial state (409); authorized recover completes remaining step.
        assert self.http(f"/api/changesets/{cs['id']}/integrate", token=self.alice, method="POST")[0] == 409
        assert self.http(f"/api/changesets/{cs['id']}/recover", token=self.carol, method="POST")[0] == 403
        done = json.loads(self.expect(f"/api/changesets/{cs['id']}/recover", 200, token=self.alice, method="POST"))
        assert done["state"] == "complete", done
        assert all(s["applied"] is True for s in done["steps"])
        assert self.git("--git-dir=" + str(bare_a), "rev-parse", "refs/heads/main").stdout.decode().strip() == new_a
        assert self.git("--git-dir=" + str(bare_b), "rev-parse", "refs/heads/main").stdout.decode().strip() == new_b
        reader_done = json.loads(self.expect(f"/api/changesets/{cs['id']}", 200, token=self.carol))
        assert reader_done["state"] == "complete"
        return {"partial_reader_visible": True, "failpoint_exit_79": True, "recover_complete": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=None)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if args.binary is None:
        selected, _ = select_runtime_binary()
        args.binary = str(selected)
    else:
        args.binary = str(Path(args.binary).resolve())

    harness = NamespaceOnlineHarness(args)
    passed = False
    failure_traceback = None
    try:
        for name in (
            "smart_http_clone_boundary_history_and_readonly",
            "fine_grained_token_scopes_and_repo_availability",
            "reverse_proposal_and_concurrent_source_conflicts",
            "crash_recovery_partial_visibility_and_complete_integration",
        ):
            harness.case(name, getattr(harness, name))
        passed = True
    except Exception as error:
        failure_traceback = harness.redact(traceback.format_exc(limit=20))[-8000:]
        print(harness.redact(error), file=sys.stderr)
        print(failure_traceback, file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(dict(name="cleanup", status="failed", error=harness.redact(error)))
            passed = False
        report = {
            "test": "namespace_online_workflows",
            "passed": passed,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "cases": harness.results,
            "failure_traceback": failure_traceback,
            "limitations": [
                "Single loopback server and disposable PostgreSQL schema; does not replace multi-node deployment testing.",
                "Multi-repository ChangeSets update per-repository refs sequentially under advisory locking and report explicit 'partial' visibility across crashes rather than claiming native cross-repo atomic Git commits.",
            ],
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
