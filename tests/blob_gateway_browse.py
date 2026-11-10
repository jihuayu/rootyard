#!/usr/bin/env python3
"""Source-bound real Git/HTTP acceptance for Blob-only tree/blob browsing.

Uses a disposable random PostgreSQL schema and the strict remote S3 profile
from blob_only_service.py. Repositories are created by HTTP, objects by stock
Smart HTTP Git. SQL never creates ready state, objects or acknowledgments.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_only_service as serving
import ops_provenance

CASES = (
    "sha1_tree_and_blob_match_native_git",
    "sha256_tree_and_blob_match_native_git",
    "empty_nested_binary_and_utf8_paths_preserve_bytes",
    "tree_pagination_and_direct_object_endpoints",
    "annotated_tags_peel_to_the_pushed_commit",
    "ref_advance_keeps_reachable_history_readable",
    "restart_without_scratch_rebuilds_browse_and_clone",
)
LIMITATIONS = [
    "Loopback HTTP, one PostgreSQL server and one configured S3 provider; no HA or physical durability claim.",
    "The restart kills only the harness-owned service process group after an acknowledged push.",
    "This verifies tree/blob JSON, not full web UI, commits/compare, LFS or ref transaction equivalence.",
    "Blob deletion stays disabled; uploaded fixture objects are not reclaimed by this harness.",
    "Ordinary functional/recovery cases, not security or resource-exhaustion qualification.",
]


def input_hashes():
    root = Path(__file__).resolve().parent
    names = (Path(__file__).name, "blob_only_service.py", "e2e.py", "native_evidence.py",
             "ops_provenance.py", "owned_fuse_cleanup.py")
    return {name: serving.sha256_file(root / name) for name in names}


class BrowseHarness(serving.BlobOnlyHarness):
    def __init__(self, args, profile, blob_profile):
        super().__init__(args, profile, blob_profile)
        self.fixtures = {}

    def fixture(self, fmt="sha1"):
        if fmt in self.fixtures:
            return self.fixtures[fmt]
        name = "browse-" + fmt
        repo, _ = self.create(name, self.alice, fmt)
        remote, work = self.base + repo["clone_path"], self.root / (name + "-work")
        self.empty_clone(remote, work, self.alice)
        self.configure(work)
        assert self.object_format(work) == fmt
        files = {"README.md": b"Blob browse initial content\n", "empty.txt": b"",
                 "a\troot-file.txt": b"tab in a root filename\n",
                 "b\nroot-file.txt": b"newline in a root filename\n",
                 "nested/deep/value.txt": b"nested exact bytes\n",
                 "nested/space name.txt": b"file name with a space\n",
                 "nested/unicode-\u4e2d\u6587.txt": "UTF-8: \u4e2d\u6587\n".encode(),
                 "payload.bin": bytes(range(256)) * 32, "z-last.txt": b"last root entry\n"}
        oid = self.commit_files(work, "browse fixture " + fmt, files)
        assert len(oid) == (40 if fmt == "sha1" else 64)
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        self.assert_ref(remote, "refs/heads/main", oid)
        self.git("fsck", "--full", "--strict", cwd=work)
        self.no_bare(repo, "browse fixture")
        value = {"repo": repo, "remote": remote, "work": work, "format": fmt, "oid": oid, "files": files}
        self.fixtures[fmt] = value
        return value

    def api_path(self, fixture, endpoint, object_oid=None, **query):
        repo = fixture["repo"]
        path = "/api/repos/" + urllib.parse.quote(repo["owner"], safe="")
        path += "/" + urllib.parse.quote(repo["name"], safe="") + "/" + endpoint
        if object_oid is not None:
            path += "/" + urllib.parse.quote(object_oid, safe="")
        query = {key: value for key, value in query.items() if value is not None}
        return path + ("?" + urllib.parse.urlencode(query) if query else "")

    def read_json(self, path):
        code, raw, headers = self.http(path, token=self.reader)
        assert code == 200, "browse status=" + str(code) + "; response=" + repr(raw[:200])
        lower = {key.lower(): value for key, value in headers.items()}
        assert lower.get("cache-control") == "no-store"
        assert lower.get("content-type", "").startswith("application/json")
        return json.loads(raw)

    def native_oid(self, fixture, expression):
        return self.git("rev-parse", "--verify", expression, cwd=fixture["work"]).stdout.decode().strip()

    def expected_tree(self, fixture, oid, path=""):
        tree_oid = self.native_oid(fixture, oid + (":" + path if path else "^{tree}"))
        raw = self.git("ls-tree", "-z", "-l", tree_oid, cwd=fixture["work"]).stdout
        entries = []
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, raw_name = record.split(b"\t", 1)
            mode, kind, object_oid, size = metadata.decode().split()
            name = raw_name.decode("utf-8")
            entries.append({"name": name, "path": path + "/" + name if path else name,
                            "mode": mode, "kind": kind, "oid": object_oid,
                            "size": None if size == "-" else int(size)})
        return tree_oid, sorted(entries, key=lambda item: item["name"])

    def assert_tree(self, fixture, revision="HEAD", *, expected_oid=None, path="", by_oid=False):
        expected_oid = expected_oid or fixture["oid"]
        tree_oid, entries = self.expected_tree(fixture, expected_oid, path)
        route = self.api_path(fixture, "tree", revision if by_oid else None,
                              **({"path": path} if by_oid else {"oid": revision, "path": path}))
        result = self.read_json(route)
        assert result["oid"] == expected_oid, "tree resolved a different commit/tree"
        assert result["tree_oid"] == tree_oid, "tree OID differs from native Git"
        assert result["path"] == path
        assert result["items"] == entries, "tree entries differ from native Git"
        assert result["next_after"] is None
        return result

    def assert_blob(self, fixture, path, expected, revision="HEAD", *, by_oid=False, direct=False):
        expected = expected.encode() if isinstance(expected, str) else expected
        object_oid = self.native_oid(fixture, revision if direct else revision + ":" + path)
        if direct:
            route = self.api_path(fixture, "blob", object_oid)
        elif by_oid:
            route = self.api_path(fixture, "blob", revision, path=path)
        else:
            route = self.api_path(fixture, "blob", oid=revision, path=path)
        result = self.read_json(route)
        assert result["oid"] == object_oid, "blob OID differs from native Git"
        assert result["size"] == len(expected)
        observed = base64.b64decode(result["content_base64"], validate=True)
        assert observed == expected, "decoded HTTP blob bytes differ"
        binary = b"\0" in expected
        try:
            text = expected.decode("utf-8")
        except UnicodeDecodeError:
            binary, text = True, None
        assert result["is_binary"] is binary
        assert result["content"] == (None if binary else text)
        return {"oid": object_oid, "bytes": len(expected), "sha256": hashlib.sha256(observed).hexdigest()}

    def roundtrip(self, fmt):
        f = self.fixture(fmt)
        self.assert_tree(f)
        self.assert_tree(f, f["oid"], by_oid=True)
        blob = self.assert_blob(f, "README.md", f["files"]["README.md"])
        self.exact_clone(f["remote"], self.root / ("browse-" + fmt + "-clone"),
                         f["oid"], fmt, f["files"], self.reader)
        return {"format": fmt, "commit_oid": f["oid"], "blob": blob, "fresh_clone_fsck": True}

    def sha1_tree_and_blob_match_native_git(self):
        return self.roundtrip("sha1")

    def sha256_tree_and_blob_match_native_git(self):
        return self.roundtrip("sha256")

    def empty_nested_binary_and_utf8_paths_preserve_bytes(self):
        results = []
        for fmt in ("sha1", "sha256"):
            f = self.fixture(fmt)
            self.assert_tree(f, path="nested")
            self.assert_tree(f, path="nested/deep")
            files = {path: self.assert_blob(f, path, f["files"][path])
                     for path in ("empty.txt", "payload.bin", "nested/deep/value.txt",
                                  "nested/space name.txt", "nested/unicode-\u4e2d\u6587.txt")}
            results.append({"format": fmt, "files": files})
        return {"formats": results}

    def tree_pagination_and_direct_object_endpoints(self):
        f = self.fixture()
        tree_oid, expected = self.expected_tree(f, f["oid"])
        all_items, pages, after = [], 0, None
        control_cursors = set()
        for _ in range(len(expected) + 1):
            result = self.read_json(self.api_path(f, "tree", oid="HEAD", limit=1, after=after))
            assert result["oid"] == f["oid"] and result["tree_oid"] == tree_oid
            items = result["items"]
            assert len(items) == 1
            all_items.extend(items)
            pages += 1
            next_after = result["next_after"]
            if next_after is None:
                break
            assert next_after == items[-1]["name"] and next_after != after
            if "\t" in next_after or "\n" in next_after:
                control_cursors.add(next_after)
            after = next_after
        else:
            raise AssertionError("tree cursor did not terminate")
        assert all_items == expected, "paged tree duplicates, omits or changes an entry"
        assert control_cursors == {"a\troot-file.txt", "b\nroot-file.txt"}, "tab/newline cursors did not roundtrip"
        self.assert_tree(f, tree_oid, expected_oid=tree_oid, by_oid=True)
        path = "nested/deep/value.txt"
        blob_oid = self.native_oid(f, f["oid"] + ":" + path)
        blob = self.assert_blob(f, "", f["files"][path], revision=blob_oid, direct=True)
        return {"pages": pages, "entries": len(all_items), "tree_oid": tree_oid, "blob": blob,
                "tab_and_newline_cursor_roundtrip": True}

    def annotated_tags_peel_to_the_pushed_commit(self):
        results = []
        for fmt in ("sha1", "sha256"):
            f = self.fixture(fmt)
            tag = "annotated-browse"
            self.git("tag", "-a", tag, "-m", "annotated browse reference", f["oid"], cwd=f["work"])
            tag_oid = self.native_oid(f, "refs/tags/" + tag)
            assert tag_oid != f["oid"], "fixture did not create an annotated tag object"
            self.git("push", "origin", "refs/tags/" + tag, cwd=f["work"], token=self.alice)
            self.assert_ref(f["remote"], "refs/tags/" + tag, tag_oid)
            self.assert_tree(f, "refs/tags/" + tag)
            self.assert_tree(f, tag_oid, by_oid=True)
            blob = self.assert_blob(f, "README.md", f["files"]["README.md"], revision=tag_oid, by_oid=True)
            results.append({"format": fmt, "tag_oid": tag_oid, "peeled_commit_oid": f["oid"], "blob": blob})
        return {"tags": results}

    def ref_advance_keeps_reachable_history_readable(self):
        f = self.fixture()
        old_oid, old_files = f["oid"], f["files"].copy()
        changed = {"README.md": b"Blob browse advanced content\n", "new.txt": b"new head entry\n"}
        new_oid = self.commit_files(f["work"], "advance browse main", changed)
        assert new_oid != old_oid
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=f["work"], token=self.alice)
        self.assert_ref(f["remote"], "refs/heads/main", new_oid)
        f["oid"] = new_oid
        f["files"].update(changed)
        self.assert_tree(f)
        self.assert_blob(f, "README.md", changed["README.md"])
        self.assert_tree(f, old_oid, expected_oid=old_oid, by_oid=True)
        blob = self.assert_blob(f, "README.md", old_files["README.md"], revision=old_oid, by_oid=True)
        return {"old_commit_oid": old_oid, "new_commit_oid": new_oid, "historical_blob": blob}

    def restart_without_scratch_rebuilds_browse_and_clone(self):
        f = self.fixture()
        self.assert_tree(f)
        old_pid = self.proc.pid
        self.stop(hard=True)
        shutil.rmtree(self.scratch)
        assert not self.scratch.exists()
        self.start(label="browse-restarted")
        assert self.proc.pid != old_pid
        self.assert_tree(f)
        self.assert_tree(f, path="nested/deep")
        blob = self.assert_blob(f, "payload.bin", f["files"]["payload.bin"])
        self.exact_clone(f["remote"], self.root / "browse-restart-clone", f["oid"], f["format"], f["files"], self.reader)
        self.no_bare(f["repo"], "browse restart")
        assert self.scratch.is_dir()
        return {"commit_oid": f["oid"], "blob": blob, "old_pid": old_pid,
                "restarted_pid": self.proc.pid, "fresh_clone_fsck": True}


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
    report = {"kind": "rootyard/blob-browse-native-acceptance", "passed": bool(success and not errors),
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
        report = {"kind": "rootyard/blob-browse-native-acceptance", "passed": False, "preflight_failed": True,
                  "error": str(error), "cases": [], "skips": 0, "expected_cases": selected, "limitations": LIMITATIONS}
        serving.write_report(args.report, report)
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2
    harness, success = BrowseHarness(args, profile, blob_profile), False
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
