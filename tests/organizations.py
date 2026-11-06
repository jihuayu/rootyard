#!/usr/bin/env python3
"""Native organization, team, Git/LFS, Forge, and workspace authorization contract."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness


class OrganizationHarness(Harness):
    def doc(self, path, code, token=None, **kwargs):
        status, body, _ = self.http(path, token=token or self.alice, **kwargs)
        expected = code if isinstance(code, tuple) else (code,)
        assert status in expected, f"{path}: expected {code}, got {status}: {body[:300]!r}"
        return json.loads(body) if body and status < 300 else None

    def inherited_capabilities(self):
        self.setup()
        charlie = self.account("create-user", "charlie")
        org = self.doc("/api/orgs", 201, method="POST", body={"slug": "acme"})
        assert org["slug"] == "acme"
        self.doc("/api/orgs", 409, method="POST", body={"slug": "alice"})
        assert self.run([self.args.binary, "create-user", "acme"], check=False).returncode != 0
        repo = self.doc("/api/repos", 201, method="POST",
                        body={"owner": "acme", "name": "project"})
        assert repo["owner"] == "acme" and repo["clone_path"] == "/git/acme/project.git"
        remote = self.base + repo["clone_path"]
        self.doc("/api/repos/acme/project", 404, token=self.bob)
        self.doc("/api/repos/acme/project", 404, token=charlie)
        self.doc("/api/orgs/acme/members/bob", 201, method="PUT", body={"role": "read"})
        self.doc("/api/repos/acme/project", 200, token=self.bob)

        alice_work = self.root / "org-alice"
        self.git("clone", remote, str(alice_work), token=self.alice)
        self.git("config", "user.name", "Alice", cwd=alice_work)
        self.git("config", "user.email", "alice@rootyard.local", cwd=alice_work)
        (alice_work / "README.md").write_text("organization repository\n")
        self.git("add", "README.md", cwd=alice_work)
        self.git("commit", "-m", "main", cwd=alice_work)
        self.git("push", "origin", "HEAD:main", cwd=alice_work, token=self.alice)
        bob_work = self.root / "org-bob"
        self.git("clone", remote, str(bob_work), token=self.bob)
        denied = self.git("push", "origin", "HEAD:refs/heads/read-only", cwd=bob_work,
                          token=self.bob, check=False)
        assert denied.returncode != 0

        self.doc("/api/orgs/acme/teams", 201, method="POST",
                 body={"slug": "engineers", "name": "Engineers", "role": "write"})
        self.doc("/api/orgs/acme/teams/engineers/members/bob", 200, method="PUT")
        assert self.doc("/api/repos/acme/project/permissions/bob", 200, token=self.bob)["role"] == "write"
        self.git("config", "user.name", "Bob", cwd=bob_work)
        self.git("config", "user.email", "bob@rootyard.local", cwd=bob_work)
        self.git("lfs", "install", "--local", cwd=bob_work)
        self.git("lfs", "track", "*.dat", cwd=bob_work)
        payload = os.urandom(64 * 1024)
        oid = hashlib.sha256(payload).hexdigest()
        (bob_work / "asset.dat").write_bytes(payload)
        self.git("add", ".gitattributes", "asset.dat", cwd=bob_work)
        self.git("commit", "-m", "team LFS upload", cwd=bob_work)
        self.git("push", "origin", "HEAD:main", cwd=bob_work, token=self.bob)
        assert self.sql(f"SELECT state FROM lfs_objects WHERE repository_id='{repo['id']}' AND oid='{oid}'") == "ready"
        path = f"/git/acme/project.git/info/lfs/objects/{oid}/{len(payload)}"
        assert self.expect(path, 200, token=self.alice) == payload
        self.expect(path, 404, token=charlie)

        issue_path = "/api/repos/acme/project/issues"
        issue = self.doc(issue_path, 201, token=self.bob, method="POST",
                         body={"title": "Team issue"})
        assert issue["author_id"] == self.bob["user_id"]
        self.doc(issue_path + "/1", 200, token=self.alice)
        self.git("checkout", "-b", "feature", cwd=bob_work)
        (bob_work / "feature.txt").write_text("team feature\n")
        self.git("add", "feature.txt", cwd=bob_work)
        self.git("commit", "-m", "team feature", cwd=bob_work)
        feature_oid = self.git("rev-parse", "HEAD", cwd=bob_work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:feature", cwd=bob_work, token=self.bob)
        base_oid = self.git("rev-parse", "HEAD~1", cwd=bob_work).stdout.decode().strip()
        pulls = "/api/repos/acme/project/pulls"
        pr = self.doc(pulls, 201, token=self.bob, method="POST",
                      body={"title": "Team PR", "head_ref": "refs/heads/feature",
                            "base_ref": "refs/heads/main"})
        merged = self.doc(f"{pulls}/{pr['number']}/merge", 200, method="POST",
                          body={"expected_version": pr["version"],
                                "expected_head_oid": feature_oid,
                                "expected_base_oid": base_oid,
                                "storage_generation": 1, "strategy": "fast_forward"})
        assert merged["state"] == "merged"

        workspace = self.doc("/api/workspaces", 201, token=self.bob, method="POST",
                             body={"owner": "acme", "repository": "project",
                                   "agent_id": "team-agent", "base_oid": feature_oid},
                             extra_headers={"Idempotency-Key": "org-workspace"})
        file_path = f"/api/workspaces/{workspace['id']}/files?path=team.txt"
        self.doc(file_path, 200, token=self.bob, method="PUT",
                 body={"content_base64": base64.b64encode(b"team workspace\n").decode(),
                       "expected_entry_version": 0, "expected_workspace_revision": 0,
                       "lease_epoch": workspace["lease_epoch"]},
                 extra_headers={"Idempotency-Key": "team-edit"})
        self.doc(file_path, 200, token=self.bob)
        self.doc(file_path, 404, token=self.alice)

        # Membership removal cascades team membership and revokes inherited
        # access across every surface even while the token remains valid.
        self.doc("/api/orgs/acme/members/bob", 200, method="DELETE")
        self.doc("/api/repos/acme/project", 404, token=self.bob)
        self.expect(path, 404, token=self.bob)
        self.doc(issue_path + "/1", 404, token=self.bob)
        self.doc(file_path, 404, token=self.bob)
        assert not self.git("ls-remote", remote, token=self.bob, check=False).returncode == 0
        assert self.sql(f"SELECT count(*) FROM organization_team_members WHERE organization_id='{org['id']}'") == "0"
        self.doc("/api/orgs/acme/members/alice", 409, method="DELETE")
        self.doc("/api/repos/acme/project", 200)
        return {"namespace_collision_rejected": True, "team_role_inherited": True,
                "git_lfs_forge_workspace_authorized": True,
                "revocation_immediate": True, "last_admin_protected": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    h = OrganizationHarness(args)
    passed = False
    try:
        h.case("inherited_capabilities", h.inherited_capabilities)
        passed = True
    except Exception:
        print(h.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        h.cleanup()
        report = {"passed": passed, "cases": h.results,
                  "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
