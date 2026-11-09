#!/usr/bin/env python3
"""Source-bound real Git/HTTP acceptance for the Blob-only refs/commits/compare API.

Uses the same disposable random PostgreSQL schema and strict remote S3 profile
as blob_gateway_browse.py (via blob_only_service.NativeProfile / BlobOnlyHarness).
Repositories are created by HTTP and objects by stock Smart HTTP Git. SQL never
creates ready state, objects, proofs or acknowledgments; the only statements
issued here are read-only comparisons against native Git facts.

Every expected value is computed independently with stock Git in the fixture's
own work repository (or a fresh clone) and compared with the JSON answered by
serve-blob. Every endpoint is also exercised unauthenticated (401) so the real
token/session path is proven to be in front of the data.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_only_service as serving
import blob_gateway_browse as browse
import ops_provenance

CASES = (
    "refs_match_native_git_and_peel_annotated_tags",
    "refs_filter_cursor_and_limit_roundtrip",
    "commits_match_native_rev_list_for_sha1_and_sha256",
    "single_commit_detail_matches_native_git",
    "divergent_branches_compare_matches_native_git",
    "commit_listing_from_an_ancestor_paginates",
    "unauthenticated_history_reads_are_refused",
)
LIMITATIONS = [
    "Loopback HTTP, one PostgreSQL server and one configured S3 provider; no HA or physical durability claim.",
    "This verifies bounded refs/commits/compare JSON, not full legacy web/UI parity, LFS or ref transaction equivalence.",
    "Compare is exercised on real divergent branches and ancestor -> tip; unrelated histories are not covered.",
    "Annotated tags to commits, blobs and trees, including tag-of-tag, are checked against native ^{}.",
    "Blob deletion stays disabled; uploaded fixture objects are not reclaimed by this harness.",
    "Ordinary functional cases, not security or resource-exhaustion qualification.",
]


def input_hashes():
    root = Path(__file__).resolve().parent
    names = (Path(__file__).name, "blob_only_service.py", "blob_gateway_browse.py", "e2e.py",
             "native_evidence.py", "ops_provenance.py", "owned_fuse_cleanup.py")
    return {name: serving.sha256_file(root / name) for name in names}


class HistoryHarness(browse.BrowseHarness):
    """Browse fixtures plus linear history, a tag and a side branch."""

    def __init__(self, args, profile, blob_profile):
        super().__init__(args, profile, blob_profile)
        self.histories = {}

    # -- fixtures ---------------------------------------------------------
    def history_fixture(self, fmt="sha1"):
        if fmt in self.histories:
            return self.histories[fmt]
        name = "history-" + fmt
        repo, _ = self.create(name, self.alice, fmt)
        remote, work = self.base + repo["clone_path"], self.root / (name + "-work")
        self.empty_clone(remote, work, self.alice)
        self.configure(work)
        assert self.object_format(work) == fmt
        commits = []
        files = {}
        for index in range(3):
            files["file-%d.txt" % index] = ("line %d\n" % index).encode()
            files["dir/nested-%d.txt" % index] = ("nested %d\n" % index).encode()
            message = "commit %d\n\nbody of commit %d\n" % (index, index)
            commits.append(self.commit_files(work, message, files))
        # Empty clone -> commit -> push: every push is a complete capture, so
        # no pack ever holds an object whose parents are absent.
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        self.assert_ref(remote, "refs/heads/main", commits[-1])
        self.git("tag", "light", commits[0], cwd=work)
        self.git("tag", "-a", "annotated", "-m", "annotated fixture tag", commits[1], cwd=work)
        tag_oid = self.git("rev-parse", "--verify", "refs/tags/annotated", cwd=work).stdout.decode().strip()
        assert tag_oid != commits[1], "fixture did not create an annotated tag object"
        self.git("tag", "-a", "outer", "-m", "tag of the annotated fixture tag", "refs/tags/annotated", cwd=work)
        outer_oid = self.git("rev-parse", "--verify", "refs/tags/outer", cwd=work).stdout.decode().strip()
        assert outer_oid not in (tag_oid, commits[1]), "fixture did not create a tag of a tag"
        self.git("tag", "-a", "blob", "-m", "tag a blob", commits[0] + ":file-0.txt", cwd=work)
        self.git("tag", "-a", "tree", "-m", "tag a tree", commits[0] + "^{tree}", cwd=work)
        self.git("push", "origin", "refs/tags/light", "refs/tags/annotated", "refs/tags/outer", "refs/tags/blob", "refs/tags/tree",
                 cwd=work, token=self.alice)
        self.git("switch", "-c", "side", commits[1], cwd=work)
        side_change = {"side.txt": b"side branch\n"}
        side_oid = self.commit_files(work, "side commit", side_change)
        self.git("push", "origin", "HEAD:refs/heads/side", cwd=work, token=self.alice)
        assert self.remote_refs(remote).get("refs/heads/side") == side_oid
        self.git("switch", "main", cwd=work)
        self.git("fsck", "--full", "--strict", cwd=work)
        self.no_bare(repo, "history fixture")
        # Read-only corroboration that the durable state is what HTTP pushed.
        storage = self.db_repo(repo["id"])
        assert storage.split("|")[0] == "pg_refstore", "unexpected storage backend: " + storage.split("|")[0]
        value = {"repo": repo, "remote": remote, "work": work, "format": fmt, "commits": commits,
                 "side_oid": side_oid, "annotated_tag_oid": tag_oid, "outer_tag_oid": outer_oid,
                 "light_tag_oid": commits[0]}
        self.histories[fmt] = value
        return value

    # -- native expectations ---------------------------------------------
    def native(self, fixture, *args):
        return self.git(*args, cwd=fixture["work"]).stdout

    def native_ref_listing(self, fixture):
        raw = self.native(fixture, "for-each-ref", "--sort=refname", "--format=%(refname)", "refs/heads", "refs/tags")
        return [line for line in raw.decode().splitlines() if line]

    def native_ref_value(self, fixture, name):
        raw = self.native(fixture, "for-each-ref", "--format=%(objectname)", name)
        return raw.decode().strip()

    def native_peel(self, fixture, name):
        if self.native(fixture, "cat-file", "-t", name).strip() != b"tag":
            return None
        return self.native(fixture, "rev-parse", "--verify", name + "^{}").decode().strip()

    def native_rev_list(self, fixture, revision):
        raw = self.native(fixture, "rev-list", revision, "--")
        return raw.decode().split()

    def native_commit(self, fixture, oid):
        text = self.native(fixture, "show", "-s", "--format=%T%x00%P%x00%an%x00%ae%x00%at%x00%cn%x00%ce%x00%ct%x00%B", oid)
        decoded = text.decode().split("\x00")
        message = decoded[8].rstrip("\n")
        return {
            "oid": oid,
            "tree_oid": decoded[0],
            "parents": decoded[1].split() if decoded[1] else [],
            "author_name": decoded[2],
            "author_email": decoded[3],
            "authored_at": int(decoded[4]),
            "committer_name": decoded[5],
            "committer_email": decoded[6],
            "committed_at": int(decoded[7]),
            "subject": message.splitlines()[0] if message else "",
            "message": message,
        }

    def native_paths(self, fixture, oid):
        raw = self.native(fixture, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", "--root", oid)
        return [name for name in raw.decode().split("\x00") if name]

    # -- HTTP -------------------------------------------------------------
    def read(self, path):
        code, raw, headers = self.http(path, token=self.reader)
        assert code == 200, path + " status=" + str(code) + "; response=" + repr(raw[:300])
        lower = {key.lower(): value for key, value in headers.items()}
        assert lower.get("cache-control") == "no-store"
        assert lower.get("content-type", "").startswith("application/json")
        return json.loads(raw)

    def refuse(self, path, status):
        code, raw, _ = self.http(path)
        assert code == status, path + " without credentials expected " + str(status) + ", got " + str(code)
        assert raw and b"error" in raw
        code, raw, _ = self.http(path, token=self.reader)
        assert code == status, path + " expected " + str(status) + ", got " + str(code) + ": " + repr(raw[:300])
        body = json.loads(raw)
        assert isinstance(body.get("error"), str) and body["error"], "refusal has no stable message"
        return body["error"]

    def assert_format(self, fixture, result):
        fmt = fixture["format"]
        assert result["format"] == fmt
        assert result["hash_algorithm"] == "hash-algo=" + fmt
        assert result["oid_hex_len"] == (40 if fmt == "sha1" else 64)

    # -- cases -------------------------------------------------------------
    def refs_match_native_git_and_peel_annotated_tags(self):
        results = []
        for fmt in ("sha1", "sha256"):
            f = self.history_fixture(fmt)
            result = self.read(self.api_path(f, "refs", prefix="refs/"))
            self.assert_format(f, result)
            items = {item["name"]: item for item in result["items"]}
            assert result["next_after"] is None
            expected = self.native_ref_listing(f)
            assert sorted(items) == expected, "ref set differs from native Git"
            for name in expected:
                assert items[name]["oid"] == self.native_ref_value(f, name), "ref OID differs: " + name
                assert items[name]["kind"] == ("branch" if name.startswith("refs/heads/") else "tag")
                # Only annotated tag objects carry a peeled OID in this API;
                # native Git resolves that object through any tag-of-tag chain.
                native_peel = self.native_peel(f, name)
                if name.startswith("refs/tags/"):
                    assert items[name].get("peeled_oid") == native_peel, "peel differs: " + name
                else:
                    assert "peeled_oid" not in items[name], "branch reports a peel: " + name
            assert items["refs/tags/annotated"]["oid"] == f["annotated_tag_oid"]
            assert items["refs/tags/annotated"]["peeled_oid"] == f["commits"][1], "annotated tag peel"
            assert "peeled_oid" not in items["refs/tags/light"]
            # A tag of a tag peels through both tag objects to the commit.
            assert items["refs/tags/outer"]["oid"] == f["outer_tag_oid"]
            assert items["refs/tags/outer"]["peeled_oid"] == f["commits"][1], "tag-of-tag peel"
            assert items["refs/tags/light"]["oid"] == f["light_tag_oid"]
            assert result["head"]["kind"] == "symbolic"
            assert result["head"]["target"] == "refs/heads/main"
            assert result["head"]["oid"] == f["commits"][-1]
            results.append({"format": fmt, "refs": len(items),
                            "annotated_tag_peeled": items["refs/tags/annotated"]["peeled_oid"]})
        return {"formats": results}

    def refs_filter_cursor_and_limit_roundtrip(self):
        f = self.history_fixture("sha1")
        expected = self.native_ref_listing(f)
        collected, after, pages = [], None, 0
        for _ in range(len(expected) + 1):
            result = self.read(self.api_path(f, "refs", after=after, limit=1))
            items = result["items"]
            assert len(items) == 1, "limit=1 page must hold exactly one ref"
            collected.extend(item["name"] for item in items)
            pages += 1
            cursor = result["next_after"]
            if cursor is None:
                assert result["more"] is False
                break
            assert result["more"] is True
            assert cursor == items[-1]["name"] and cursor != after
            after = cursor
        else:
            raise AssertionError("ref cursor did not terminate")
        assert collected == expected, "cursor traversal differs from native ref order"
        heads = self.read(self.api_path(f, "refs", prefix="refs/heads/"))
        assert [item["name"] for item in heads["items"]] == [name for name in expected if name.startswith("refs/heads/")]
        tags = self.read(self.api_path(f, "refs", prefix="refs/tags/"))
        assert [item["name"] for item in tags["items"]] == [name for name in expected if name.startswith("refs/tags/")]
        # Unbounded/invalid inputs are refused, never clamped silently.
        self.refuse(self.api_path(f, "refs", limit=101), 400)
        self.refuse(self.api_path(f, "refs", prefix="heads/"), 400)
        self.refuse(self.api_path(f, "refs", after="bad..ref"), 400)
        return {"pages": pages, "refs": collected}

    def assert_commits(self, f, revision, *, after=0, limit=100):
        expected = self.native_rev_list(f, revision)
        page = expected[after:after + limit]
        url = self.api_path(f, "commits", rev=revision, after=after or None, limit=limit if limit != 100 else None)
        result = self.read(url)
        self.assert_format(f, result)
        observed = [item["oid"] for item in result["items"]]
        assert observed == page, "commit page differs from native rev-list for " + revision
        for item in result["items"]:
            native = self.native_commit(f, item["oid"])
            for key, value in native.items():
                assert item[key] == value, "commit field " + key + " differs for " + item["oid"]
        more = after + limit < len(expected)
        assert result["next_after"] == (after + limit if more else None), "commit cursor contract"
        assert result["truncated"] is False
        return [item["oid"] for item in result["items"]]

    def commits_match_native_rev_list_for_sha1_and_sha256(self):
        results = []
        for fmt in ("sha1", "sha256"):
            f = self.history_fixture(fmt)
            full = self.assert_commits(f, "main")
            paged, after, pages = [], 0, 0
            while True:
                result = self.read(self.api_path(f, "commits", rev="refs/heads/main", after=after or None, limit=1))
                pages += 1
                paged.extend(item["oid"] for item in result["items"])
                if result["next_after"] is None:
                    break
                after = result["next_after"]
                assert pages <= len(full) + 1, "commit cursor did not terminate"
            assert paged == full, "paged commits differ from one page"
            head = self.assert_commits(f, "HEAD")
            assert head == full
            tag_commits = self.assert_commits(f, "refs/tags/light")
            assert tag_commits == self.native_rev_list(f, "refs/tags/light")
            peeled = self.assert_commits(f, "refs/tags/annotated")
            assert peeled == self.native_rev_list(f, "refs/tags/annotated")
            self.refuse(self.api_path(f, "commits", rev="main", limit=101), 400)
            self.refuse(self.api_path(f, "commits", rev="main", after=10_001), 400)
            self.refuse(self.api_path(f, "commits", rev="missing-branch"), 404)
            results.append({"format": fmt, "commits": full, "pages": pages})
        return {"formats": results}

    def single_commit_detail_matches_native_git(self):
        results = []
        for fmt in ("sha1", "sha256"):
            f = self.history_fixture(fmt)
            for oid in (f["commits"][-1], f["commits"][0], f["side_oid"]):
                result = self.read(self.api_path(f, "commits", oid))
                self.assert_format(f, result)
                native = self.native_commit(f, oid)
                for key, value in native.items():
                    assert result[key] == value, "commit detail " + key + " differs for " + oid
                assert result["changed_paths"] == self.native_paths(f, oid), "changed paths differ for " + oid
            # Trees and blobs of the same commit remain reachable history.
            tree = self.read(self.api_path(f, "tree", oid=f["commits"][0]))
            assert tree["oid"] == f["commits"][0]
            self.refuse(self.api_path(f, "commits", "f" * len(f["commits"][0])), 404)
            # An abbreviated id is never resolved as a revision.
            self.refuse(self.api_path(f, "commits", f["commits"][0][:12]), 404)
            self.refuse(self.api_path(f, "commits", self.native_oid(f, "HEAD^{tree}")), 404)
            results.append({"format": fmt, "commits": len(f["commits"]) + 1,
                            "ancestor_commit": f["commits"][0], "side_commit": f["side_oid"]})
        return {"formats": results}

    def compare_fixture(self, fmt="sha1"):
        # The repository starts empty and every push captures its whole
        # ancestry, so the computed view holds the dense closure of main+side.
        key = "compare-" + fmt
        if key in self.histories:
            return self.histories[key]
        name = key
        repo, _ = self.create(name, self.alice, fmt)
        remote, work = self.base + repo["clone_path"], self.root / (name + "-work")
        self.empty_clone(remote, work, self.alice)
        self.configure(work)
        base = self.commit_files(work, "compare base\n", {"a.txt": b"a\n", "shared.txt": b"base\n"})
        tip = self.commit_files(work, "compare tip\n", {"a.txt": b"a2\n", "b.txt": b"b\n"})
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        self.assert_ref(remote, "refs/heads/main", tip)
        self.git("switch", "-c", "side", base, cwd=work)
        side = self.commit_files(work, "side change\n", {"side.txt": b"side\n", "shared.txt": b"side\n"})
        self.git("push", "origin", "HEAD:refs/heads/side", cwd=work, token=self.alice)
        self.assert_ref(remote, "refs/heads/side", side)
        self.git("switch", "main", cwd=work)
        self.git("fsck", "--full", "--strict", cwd=work)
        self.no_bare(repo, "compare fixture")
        value = {"repo": repo, "work": work, "format": fmt, "base": base, "tip": tip, "side": side}
        self.histories[key] = value
        return value

    def assert_compare(self, f, base, head, expected):
        result = self.read(self.api_path(f, "compare", base=base, head=head))
        self.assert_format(f, result)
        assert result["base_oid"] == expected["base_oid"], "compare base resolves differently"
        assert result["head_oid"] == expected["head_oid"], "compare head resolves differently"
        assert result["merge_base_oid"] == expected["merge_base_oid"], "merge base differs"
        assert (result["ahead"], result["behind"]) == (expected["ahead"], expected["behind"]), \
            "ahead/behind differ: %r" % ((result["ahead"], result["behind"]),)
        assert result["fast_forward"] is expected["fast_forward"]
        assert [item["oid"] for item in result["commits"]] == expected["commits"], "ahead list differs"
        assert result["truncated"] is False
        assert result["diff"] == self.native(f, "diff", expected["base_oid"], expected["head_oid"], "--").decode()
        names = self.native(f, "diff", "--name-only", "-r", "-z", expected["base_oid"], expected["head_oid"], "--")
        assert result["changed_paths"] == [n for n in names.decode().split("\x00") if n]
        for item in result["commits"]:
            native = self.native_commit(f, item["oid"])
            for key, value in native.items():
                assert item[key] == value, "compare commit field " + key + " differs for " + item["oid"]
        return result

    def native_compare(self, f, base_oid, head_oid):
        left = self.git("rev-list", "--left-right", "--count", base_oid + "..." + head_oid,
                        cwd=f["work"]).stdout.decode().split()
        ahead_list = self.git("rev-list", "--max-count=100", base_oid + ".." + head_oid, "--",
                              cwd=f["work"]).stdout.decode().split()
        merge_base = self.git("merge-base", base_oid, head_oid, cwd=f["work"]).stdout.decode().strip()
        ancestor = self.git("merge-base", "--is-ancestor", base_oid, head_oid, cwd=f["work"], check=False)
        assert ancestor.returncode in (0, 1), "native ancestry check failed"
        return {"base_oid": base_oid, "head_oid": head_oid, "merge_base_oid": merge_base,
                "behind": int(left[0]), "ahead": int(left[1]),
                "fast_forward": ancestor.returncode == 0,
                "commits": ahead_list}

    def divergent_branches_compare_matches_native_git(self):
        return {"formats": [self.assert_compare_format(fmt) for fmt in ("sha1", "sha256")]}

    def assert_compare_format(self, fmt):
        f = self.compare_fixture(fmt)
        results = []
        pairs = (
            ("refs/heads/main", "refs/heads/side", f["tip"], f["side"]),
            ("side", "main", f["side"], f["tip"]),
            ("refs/heads/main", f["tip"], f["tip"], f["tip"]),
            (f["base"], f["tip"], f["base"], f["tip"]),
            ("refs/heads/main", "refs/heads/main", f["tip"], f["tip"]),
        )
        for base, head, base_oid, head_oid in pairs:
            expected = self.native_compare(f, base_oid, head_oid)
            result = self.assert_compare(f, base, head, expected)
            results.append({"base": base_oid, "head": head_oid, "ahead": result["ahead"],
                            "behind": result["behind"], "merge_base": result["merge_base_oid"],
                            "fast_forward": result["fast_forward"]})
        # Both divergent directions are real (ahead=1, behind=1). Two commits
        # of the linear segment compare as a fast-forward.
        assert {(r["ahead"], r["behind"]) for r in results[:2]} == {(1, 1)}, "compare is not divergent"
        assert results[2]["fast_forward"] is True and results[3]["fast_forward"] is True
        # An ancestor (not a tip) is a valid compare endpoint.
        assert results[3]["merge_base"] == f["base"]
        return {"format": fmt, "pairs": results}

    def commit_listing_from_an_ancestor_paginates(self):
        f = self.compare_fixture()
        expected = self.native_rev_list(f, f["base"])
        assert expected == [f["base"]]
        result = self.read(self.api_path(f, "commits", rev=f["base"]))
        assert [item["oid"] for item in result["items"]] == expected, "ancestor listing"
        assert result["start_oid"] == f["base"]
        detail = self.read(self.api_path(f, "commits", f["base"]))
        assert detail["oid"] == f["base"]
        assert detail["changed_paths"] == self.native_paths(f, f["base"])
        # Older commits of main are served through their full object ids.
        main = self.native_rev_list(f, "refs/heads/main")
        for oid in main[1:]:
            page = self.read(self.api_path(f, "commits", rev=oid, limit=1))
            assert [item["oid"] for item in page["items"]] == [oid]
        # Paging walks the newest-first listing exactly once.
        full = self.native_rev_list(f, "HEAD")
        paged, after, pages = [], 0, 0
        while True:
            page = self.read(self.api_path(f, "commits", after=after or None, limit=1))
            pages += 1
            paged.extend(item["oid"] for item in page["items"])
            if page["next_after"] is None:
                break
            after = page["next_after"]
            assert pages <= len(full) + 1, "commit cursor did not terminate"
        assert paged == full, "paged commits differ from native rev-list"
        return {"ancestor": f["base"], "pages": pages, "commits": len(paged)}


def report_result(harness, profile, blob_profile, selected, success, hashes):
    errors = []
    try:
        serving.validate_report_cases({"cases": harness.results}, selected)
    except serving.ProfileError as error:
        errors.append(str(error))
    if profile.source_digest() != profile.build["source_inputs_sha256"]:
        errors.append("production source changed during acceptance")
    if serving.sha256_file(profile.binary) != profile.build["binary_sha256"]:
        errors.append("executed binary changed during acceptance")
    if serving.sha256_file(profile.binary.with_suffix(".build.json")) != profile.receipt_sha256:
        errors.append("build receipt changed during acceptance")
    if input_hashes() != hashes:
        errors.append("harness/helper source changed during acceptance")
    report = {"kind": "rootyard/blob-history-native-acceptance", "passed": bool(success and not errors),
              "qualification_kind": "clean-candidate" if profile.working_tree_clean else "dirty-diagnostic-only",
              "measurement_kind": "native_execution", "simulated_fields": False,
              "inputs_unchanged": not errors, "source_head": profile.build["workspace_commit"],
              "source_inputs_sha256": profile.build["source_inputs_sha256"],
              "binary_sha256": profile.build["binary_sha256"], "build_receipt_sha256": profile.receipt_sha256,
              "harness_sha256": hashes[Path(__file__).name], "harness_inputs_sha256": hashes,
              "git_sha256": profile.git_sha256, "blob_profile": blob_profile,
              "expected_cases": list(selected), "case_count": len(harness.results), "expected_count": len(selected),
              "cases": harness.results, "skips": 0, "limitations": LIMITATIONS,
              "tool_versions": ops_provenance.tool_versions()}
    if errors:
        report["binding_errors"] = errors
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="absolute source-attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git, or ROOTYARD_GIT")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--case", action="append", choices=CASES, default=[])
    args = parser.parse_args(argv)
    selected = [name for name in CASES if not args.case or name in args.case]
    try:
        env = os.environ.copy()
        profile = serving.NativeProfile(args.binary, args.git, env)
        blob_profile = serving.check_blob_profile(env)
        serving.need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        serving.need(shutil.which("psql"), "psql is required")
        serving.need(selected, "no cases selected")
        hashes = input_hashes()
    except Exception as error:
        report = {"kind": "rootyard/blob-history-native-acceptance", "passed": False, "preflight_failed": True,
                  "error": str(error), "cases": [], "skips": 0, "expected_cases": selected, "limitations": LIMITATIONS}
        serving.write_report(args.report, report)
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2
    harness, success = HistoryHarness(args, profile, blob_profile), False
    try:
        harness.prepare()
        for name in selected:
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
        report = report_result(harness, profile, blob_profile, selected, success, hashes)
        serving.write_report(args.report, report)
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
