#!/usr/bin/env python3
"""Root-only real-service HTTP fixture for authorized retention-root browsing.

Source-only until Root executes it with the attested binary, real PostgreSQL/S3/
stock Git and the owned Blob profile. Repository, snapshot, root, pack and
receipt data come only through real API/A3/A4/A5/Git/root endpoints; no ready,
snapshot, root, receipt, grant or byte proof is fabricated.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_only_service as blob  # noqa: E402
import refstore_snapshot_http as snapshot  # noqa: E402
from refstore_roots_http import RootsHttpHarness  # noqa: E402

ROOT_BROWSE_CASE = "roots_http_browse_selected_closures"
ROOT_BROWSE_SHA256_CASE = "roots_http_browse_sha256"

LIMITATIONS = [
    "Root-only real-service HTTP fixture; only py-compiled/static-inspected by the implementation worker.",
    "Repositories, source snapshots, roots, pins, receipts and packs come from real API/A3/A4/A5/Git/root paths; no SQL or fabricated authority rows are used.",
    "The fixture does not claim current native/HTTP/CI acceptance, Root byte session proof, hosted CI inventory or full issue107 closure.",
    "Current repository realm/backend/cluster rejection is not forced here: the real production gate mutation seam needed to hold and narrow all of those live authorities is outside this HTTP fixture. Existing coordinator fixtures cover source-level realm/backend/anchor checks, not this HTTP race.",
    "The deterministic post-JSON ContentsRead-removal race is NOT included. The reusable Python harness has no trusted-Git executable pause seam that can stop only the terminal cat-file after materialization while a test-owned PostgreSQL transaction locks the real token row and observes final authorization waiting on that lock. The Rust GitGate is coordinator-local and does not provide this HTTP/token-lock choreography. Adding a production hook or a pre-T2 race would not prove the post-JSON fence; no substitute is claimed.",
]


class RootBrowseHttpHarness(RootsHttpHarness):
    def _root_tree(self, repo, root, *, oid=None, path=None, after=None, limit=None, token=None):
        suffix = "/" + str(root) + "/tree"
        return self._request("GET", self._query_path(self._roots_path(repo, suffix), {
            "oid": oid, "path": path, "after": after, "limit": limit,
        }), token or self.alice)

    def _root_blob(self, repo, root, oid, *, path=None, token=None):
        suffix = "/" + str(root) + "/blob/" + str(oid)
        return self._request("GET", self._query_path(self._roots_path(repo, suffix), {"path": path}),
                             token or self.alice)

    def _selector_root(self, repo, key, source_snapshot_id, selector):
        create = self._intent(key, source_snapshot_id, selector=selector)
        status, receipt = self._create_root(repo, create)
        assert status == 201, (status, receipt)
        self._assert_receipt(receipt)
        return receipt["root_id"]

    def _assert_no_content(self, status, data):
        assert status >= 400, status
        assert set(data) == {"error"}, data
        assert "content" not in data and "content_base64" not in data and "items" not in data

    def roots_http_browse_selected_closures(self):
        repo, remote, work, _initial = self.seed("roots-http-browse")
        head = self.commit_files(work, "root browse contents", {
            "a.txt": "alpha\n",
            "dir/b.txt": "beta\n",
            "large.bin": b"x" * (1 << 20),
        })
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        assert self.remote_refs(remote).get("refs/heads/main") == head
        tag = self.git("tag", "-a", "root-browse-tag", "-m", "browse tag", cwd=work)
        assert tag.returncode == 0
        tag_oid = self.git("rev-parse", "refs/tags/root-browse-tag", cwd=work).stdout.decode().strip()
        pushed_tag = self.git("push", "origin", "refs/tags/root-browse-tag", cwd=work,
                              token=self.alice, check=False)
        assert pushed_tag.returncode == 0, blob.git_failure(pushed_tag)
        tree_oid = self.git("rev-parse", "HEAD^{tree}", cwd=work).stdout.decode().strip()
        blob_oid = self.git("rev-parse", "HEAD:a.txt", cwd=work).stdout.decode().strip()
        large_oid = self.git("rev-parse", "HEAD:large.bin", cwd=work).stdout.decode().strip()
        snapshot_id = self._create(repo, "roots-http-browse-source", 300)[1]["snapshot_id"]

        snapshot_root = self._selector_root(repo, "roots-http-browse-snapshot",
                                            snapshot_id, {"kind": "snapshot"})
        tree_root = self._selector_root(repo, "roots-http-browse-tree",
                                        snapshot_id, {"kind": "oids", "oids": [tree_oid]})
        blob_root = self._selector_root(repo, "roots-http-browse-blob",
                                        snapshot_id, {"kind": "oids", "oids": [blob_oid]})
        commit_root = self._selector_root(repo, "roots-http-browse-commit",
                                          snapshot_id, {"kind": "oids", "oids": [head]})
        tag_root = self._selector_root(repo, "roots-http-browse-tag-root",
                                       snapshot_id, {"kind": "oids", "oids": [tag_oid]})
        expired_source = self._create(repo, "roots-http-browse-expiring-source", 1)[1]
        expired_root = self._selector_root(repo, "roots-http-browse-expiring-root",
                                           expired_source["snapshot_id"], {"kind": "snapshot"})
        self._await_pin_expiry(repo, expired_source["pin_id"], "roots-http-browse-expiring-source")
        status, _ = self._release(repo, snapshot_id, "roots-http-browse-source-release", 1)
        assert status == 200, ("source pin release", status)

        baseline_ledger = self._ledger(repo)
        baseline_roots = self._root_rows(repo)

        # Snapshot root: exact captured HEAD, path and direct blob reads.
        status, snapshot_tree = self._root_tree(repo, snapshot_root)
        assert status == 200, (status, snapshot_tree)
        self._assert_tree_view(snapshot_tree)
        assert snapshot_tree["oid"] == head, snapshot_tree
        assert self._tree_item(snapshot_tree, "a.txt")["kind"] == "blob"
        status, snapshot_blob = self._root_blob(repo, snapshot_root, "HEAD", path="a.txt")
        assert status == 200 and snapshot_blob["content"] == "alpha\n", (status, snapshot_blob)
        self._assert_blob_view(snapshot_blob)
        status, snapshot_direct = self._root_blob(repo, snapshot_root, blob_oid)
        assert status == 200 and snapshot_direct["oid"] == blob_oid, (status, snapshot_direct)
        status, first_page = self._root_tree(repo, snapshot_root, limit=1)
        assert status == 200 and first_page["next_after"], (status, first_page)
        status, second_page = self._root_tree(repo, snapshot_root, after=first_page["next_after"], limit=1)
        assert status == 200 and second_page["items"], (status, second_page)
        status, invalid_path = self._root_tree(repo, snapshot_root, path="../escape")
        assert status == 400, (status, invalid_path)
        self._assert_no_content(status, invalid_path)

        # Snapshot bytes remain readable after the source pin is gone.
        status, snapshot_tree_after = self._root_tree(repo, snapshot_root)
        assert status == 200 and snapshot_tree_after["oid"] == head, (status, snapshot_tree_after)
        status, snapshot_blob_after = self._root_blob(repo, snapshot_root, blob_oid)
        assert status == 200 and snapshot_blob_after["content"] == "alpha\n", (status, snapshot_blob_after)
        status, expired_tree = self._root_tree(repo, expired_root)
        assert status == 200 and expired_tree["oid"] == head, (status, expired_tree)
        status, expired_blob = self._root_blob(repo, expired_root, blob_oid)
        assert status == 200 and expired_blob["content"] == "alpha\n", (status, expired_blob)

        # Explicit selected tree: whole selected closure, no original HEAD/refs.
        status, default_tree = self._root_tree(repo, tree_root)
        assert status == 404, ("oid-root HEAD was not unborn", status)
        self._assert_no_content(status, default_tree)
        status, selected_tree = self._root_tree(repo, tree_root, oid=tree_oid)
        assert status == 200 and selected_tree["tree_oid"] == tree_oid, (status, selected_tree)
        assert self._tree_item(selected_tree, "dir")["kind"] == "tree"
        status, descendant_blob = self._root_blob(repo, tree_root, tree_oid, path="dir/b.txt")
        assert status == 200 and descendant_blob["content"] == "beta\n", (status, descendant_blob)
        status, synthetic = self._root_tree(repo, tree_root, oid="refs/roots/oid/" + tree_oid)
        assert status == 200 and synthetic["tree_oid"] == tree_oid, (status, synthetic)
        status, unselected_head = self._root_tree(repo, tree_root, oid=head)
        assert status == 404, ("unselected captured HEAD was reachable", status)
        self._assert_no_content(status, unselected_head)
        status, unselected_ref = self._root_tree(repo, tree_root, oid="main")
        assert status == 404, ("unselected captured ref was reachable", status)

        # Explicit selected commit and tag: descendants/history are in closure.
        status, commit_tree = self._root_tree(repo, commit_root, oid=head)
        assert status == 200 and commit_tree["oid"] == head, (status, commit_tree)
        status, commit_blob = self._root_blob(repo, commit_root, head, path="a.txt")
        assert status == 200 and commit_blob["content"] == "alpha\n", (status, commit_blob)
        status, tag_tree = self._root_tree(repo, tag_root, oid=tag_oid)
        assert status == 200 and tag_tree["oid"] == head, (status, tag_tree)
        status, tag_blob = self._root_blob(repo, tag_root, tag_oid, path="a.txt")
        assert status == 200 and tag_blob["content"] == "alpha\n", (status, tag_blob)

        # Explicit selected blob: only that blob, no invented HEAD/tree.
        status, blob_tree = self._root_tree(repo, blob_root)
        assert status == 404, (status, blob_tree)
        status, blob_direct = self._root_blob(repo, blob_root, blob_oid)
        assert status == 200 and blob_direct["oid"] == blob_oid, (status, blob_direct)
        status, blob_as_tree = self._root_tree(repo, blob_root, oid=blob_oid)
        assert status == 404, (status, blob_as_tree)
        status, blob_unsynced = self._root_tree(repo, blob_root, oid=head)
        assert status == 404, (status, blob_unsynced)

        # Effective retained blob ceiling (memory/144) refuses oversized bytes.
        status, oversize = self._root_blob(repo, snapshot_root, large_oid)
        assert status == 413, (status, oversize)
        self._assert_no_content(status, oversize)

        # Tokenless root browse must carry exactly the API Bearer challenge and
        # no-store/no-session, not the ordinary current-Browse behavior.
        self._assert_unauthorized("GET", self._roots_path(repo, "/" + str(snapshot_root) + "/tree"))
        self._assert_unauthorized("GET", self._roots_path(repo, "/" + str(snapshot_root) + "/blob/" + blob_oid))

        # Cross-repository, non-member, and current ContentsRead-removal denies.
        other_repo, _other_remote, _other_work, _other_oid = self.seed("roots-http-browse-other")
        status, data = self._root_tree(other_repo, snapshot_root)
        assert status == 404, ("cross-repository root was observable", status)
        self._assert_no_content(status, data)
        status, data = self._root_tree(repo, snapshot_root, token=self.bob)
        assert status == 404, ("non-member root was observable", status)
        self._assert_no_content(status, data)
        scoped = self._issue_scoped(repo, "roots-http-browse-scoped", ["contents_read", "contents_write"])
        status, _ = self._root_tree(repo, snapshot_root, token=scoped)
        assert status == 200, ("pre-narrow ContentsRead root read failed", status)
        self._patch_scope(repo, scoped, ["contents_write"])
        status, data = self._root_tree(repo, snapshot_root, token=scoped)
        assert status == 403, ("contents-read narrowing did not refuse root browse", status)
        self._assert_no_content(status, data)
        status, data = self._root_blob(repo, snapshot_root, blob_oid, token=scoped)
        assert status == 403, ("contents-read narrowing did not refuse root blob", status)
        self._assert_no_content(status, data)

        assert self._ledger(repo) == baseline_ledger, "root browse changed snapshot ledger rows"
        assert self._root_rows(repo) == baseline_roots, "root browse changed root rows"

        # Released root is refused without a body; this is the only later mutation.
        status, _ = self._delete_root(repo, snapshot_root, self._release_body("roots-http-browse-release"))
        assert status == 200, ("root release", status)
        status, released = self._root_tree(repo, snapshot_root)
        assert status == 409, (status, released)
        self._assert_no_content(status, released)
        self.no_bare(repo, "after retention root browse HTTP")
        return {"snapshot_root": snapshot_root, "tag_root": tag_root, "blob_root": blob_root}

    def roots_http_browse_sha256(self):
        repo, _remote, work, _oid = self.seed("roots-http-browse-sha256", object_format="sha256")
        head = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        tree_oid = self.git("rev-parse", "HEAD^{tree}", cwd=work).stdout.decode().strip()
        blob_oid = self.git("rev-parse", "HEAD:base.txt", cwd=work).stdout.decode().strip()
        assert len(head) == len(tree_oid) == len(blob_oid) == 64
        snapshot_id = self._create(repo, "roots-http-browse-sha256-source", 300)[1]["snapshot_id"]
        root = self._selector_root(repo, "roots-http-browse-sha256-root",
                                   snapshot_id, {"kind": "snapshot"})
        status, tree = self._root_tree(repo, root)
        assert status == 200 and tree["oid"] == head, (status, tree)
        status, blob_view = self._root_blob(repo, root, blob_oid)
        assert status == 200 and blob_view["oid"] == blob_oid, (status, blob_view)
        explicit = self._selector_root(repo, "roots-http-browse-sha256-tree", snapshot_id,
                                       {"kind": "oids", "oids": [tree_oid]})
        status, _ = self._root_tree(repo, explicit)
        assert status == 404, ("sha256 explicit root invented HEAD", status)
        status, explicit_tree = self._root_tree(repo, explicit, oid=tree_oid)
        assert status == 200 and explicit_tree["tree_oid"] == tree_oid, (status, explicit_tree)
        return {"root": root, "explicit_tree": explicit}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="absolute attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git (defaults to ROOTYARD_GIT)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ.copy()
    try:
        profile = snapshot.SnapshotHttpProfile(str(Path(args.binary).resolve()), args.git, env)
        blob_profile = blob.check_blob_profile(env)
        blob.need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        blob.need(__import__("shutil").which("psql"), "psql is required")
    except Exception as error:
        blob.write_report(args.report, {
            "kind": "rootyard/refstore-root-browse-http", "passed": False,
            "preflight_failed": True, "error": str(error), "cases": [],
            "expected_cases": [], "limitations": LIMITATIONS,
        })
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2
    args.binary = str(profile.binary)
    harness = RootBrowseHttpHarness(args, profile, blob_profile)
    cases = [ROOT_BROWSE_CASE, ROOT_BROWSE_SHA256_CASE]
    success = False
    try:
        harness.prepare()
        for name in cases:
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append({"name": "cleanup", "status": "failed", "error": harness.redact(error)})
            success = False
        report = blob.build_report(harness, profile, blob_profile, cases, success)
        report["kind"] = "rootyard/refstore-root-browse-http"
        report["limitations"] = LIMITATIONS
        blob.write_report(args.report, report)
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
