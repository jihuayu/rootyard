#!/usr/bin/env python3
"""Real-Git verification harness for the opt-in local rootyard-view-lab prototype.

Exercises company Namespace BaseVector mounts, deterministic subdirectory history
projection with unreachable-object pruning, composite multi-repository task views,
and two-phase cross-repository ChangeSet integration (including zero partial
success on 3-way merge conflicts, pre-commit crash abort, active lease fencing,
and post-commit crash roll-forward recovery).
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def is_uuid(value):
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


class Harness:
    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-git-views-test-"))
        self.binary = Path(args.binary).expanduser().resolve()
        self.binary_sha256 = (
            hashlib.sha256(self.binary.read_bytes()).hexdigest()
            if self.binary.is_file()
            else None
        )
        selected_git = os.environ.get("ROOTYARD_VIEW_GIT", "git")
        found_git = shutil.which(selected_git)
        require(found_git is not None, "Git executable is unavailable")
        self.git_binary = str(Path(found_git).resolve())
        self.env = dict(os.environ)
        for key in list(self.env):
            if key.startswith("GIT_") or key.startswith("ROOTYARD_VIEW_"):
                self.env.pop(key)
        self.env.update({
            "HOME": str(self.root / "home"),
            "XDG_CONFIG_HOME": str(self.root / "xdg"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "ROOTYARD_VIEW_GIT": self.git_binary,
        })
        (self.root / "home").mkdir()
        (self.root / "xdg").mkdir()
        self.sequence = 0
        self.checks = []
        self.git_version = self.git("--version").stdout.decode().strip()

    def run(self, argv, cwd=None, check=True, env=None, expected=None):
        result = subprocess.run(
            [os.fspath(arg) for arg in argv],
            cwd=cwd,
            env=env or self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        if expected is not None:
            require(
                result.returncode == expected,
                f"Expected exit {expected}, got {result.returncode}: "
                + result.stderr.decode(errors="replace"),
            )
        elif check:
            require(
                result.returncode == 0,
                f"Command {argv[0]} {argv[1:]} failed ({result.returncode}): "
                + result.stderr.decode(errors="replace"),
            )
        return result

    def git(self, *args, cwd=None, check=True, env=None):
        return self.run(
            [
                self.git_binary,
                "-c",
                "user.name=View Test",
                "-c",
                "user.email=view-test@example.invalid",
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
                *args,
            ],
            cwd=cwd,
            check=check,
            env=env,
        )

    def git_oid(self, *args, cwd=None):
        return self.git(*args, cwd=cwd).stdout.decode().strip()

    def lab(self, *args, check=True, env=None, expected=None):
        return self.run([self.binary, *args], check=check, env=env, expected=expected)

    def data(self, *args, env=None):
        result = self.lab(*args, env=env)
        return json.loads(result.stdout.decode())

    def new_case(self, name):
        self.sequence += 1
        case_dir = self.root / f"{self.sequence:02d}-{name}"
        case_dir.mkdir()
        store = case_dir / "store"
        return case_dir, store

    def make_source_repo(self, parent, name, files):
        repo = parent / name
        repo.mkdir()
        self.git("init", "--initial-branch=main", cwd=repo)
        for rel, content in files.items():
            target = repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content if isinstance(content, bytes) else content.encode())
        self.git("add", ".", cwd=repo)
        self.git("commit", "-m", f"initial {name}", cwd=repo)
        return repo, self.git_oid("rev-parse", "HEAD", cwd=repo)

    def record(self, name, details):
        self.checks.append({"name": name, "passed": True, "details": details})

    def test_namespace_mounts_and_base_vector(self):
        case_dir, store = self.new_case("namespace-mounts")
        r1, b1 = self.make_source_repo(case_dir, "proto-src", {"api.proto": "syntax = 'proto3';\n"})
        r2, b2 = self.make_source_repo(case_dir, "search-src", {"lib.rs": "pub fn search() {}\n"})

        reg1 = self.data("register-repo", store, "proto", r1, "--quiescent")
        reg2 = self.data("register-repo", store, "search", r2, "--quiescent")
        require(is_uuid(reg1["repo_id"]) and reg1["head_oid"] == b1, "proto registration mismatch")
        require(is_uuid(reg2["repo_id"]) and reg2["head_oid"] == b2, "search registration mismatch")

        # Reject overlapping mount paths, path traversal, and .git components.
        for bad_mounts in [
            [f"libs=proto@{b1}", f"libs/proto=search@{b2}"],
            [f"libs/proto=proto@{b1}", f"libs/proto=search@{b2}"],
            [f"../escape=proto@{b1}"],
            [f"/abs/path=proto@{b1}"],
            [f"libs/.git/sub=proto@{b1}"],
            [f"libs/proto=proto@{b1}", f"services/dup=proto@{b1}"],
        ]:
            res = self.lab("create-namespace", store, "acme", *bad_mounts, check=False)
            require(res.returncode != 0, f"Unsafe mounts unexpectedly succeeded: {bad_mounts}")

        # Sibling prefixes like libs/proto and libs/proto-ext must be allowed.
        ns1 = self.data(
            "create-namespace",
            store,
            "acme",
            f"libs/proto=proto@{b1}",
            f"libs/proto-ext=search@{b2}",
        )
        require(is_uuid(ns1["revision_id"]) and ns1["revision_number"] == 1, "ns1 revision mismatch")

        # Verify source pin refs exist in each underlying bare repository.
        pin_ref = f"refs/rootyard/namespace-pins/{ns1['revision_id']}"
        require(
            self.git_oid("rev-parse", "--verify", pin_ref, cwd=reg1["repo_path"]) == b1,
            "proto namespace pin missing",
        )
        require(
            self.git_oid("rev-parse", "--verify", pin_ref, cwd=reg2["repo_path"]) == b2,
            "search namespace pin missing",
        )

        self.record(
            "namespace_mounts_and_base_vector",
            {
                "revision_id": ns1["revision_id"],
                "manifest_sha256": ns1["manifest_sha256"],
            },
        )

    def test_deterministic_subdirectory_projection(self):
        case_dir, store = self.new_case("subdir-projection")
        mono, _ = self.make_source_repo(
            case_dir,
            "mono-src",
            {
                "services/search/engine.rs": "pub fn v1() {}\n",
                "other/secret.txt": "classified-token-payload\n",
            },
        )
        secret_blob = self.git_oid("rev-parse", "HEAD:other/secret.txt", cwd=mono)

        # Second commit touches only other/secret.txt and must be folded in projection.
        (mono / "other/secret.txt").write_text("classified-token-v2\n")
        self.git("add", "other/secret.txt", cwd=mono)
        self.git("commit", "-m", "unrelated change outside subdir", cwd=mono)
        c2 = self.git_oid("rev-parse", "HEAD", cwd=mono)

        # Third commit updates services/search/engine.rs.
        (mono / "services/search/engine.rs").write_text("pub fn v2() {}\n")
        self.git("add", "services/search/engine.rs", cwd=mono)
        self.git("commit", "-m", "search engine v2", cwd=mono)
        c3 = self.git_oid("rev-parse", "HEAD", cwd=mono)

        self.data("register-repo", store, "mono", mono, "--quiescent")

        proj1 = self.data("project-subdir", store, "search-view-a", "mono", "services/search")
        proj2 = self.data("project-subdir", store, "search-view-b", "mono", "services/search")

        require(
            proj1["projected_head_oid"] == proj2["projected_head_oid"],
            "Subdirectory projection is not deterministic across runs",
        )
        require(
            proj1["commit_map"] == proj2["commit_map"],
            "Commit mapping differed between deterministic runs",
        )
        require(
            proj1["projected_commits"] == 2,
            f"Expected 2 projected commits after folding, got {proj1['projected_commits']}",
        )
        require(
            proj1["commit_map"][c2] != proj1["commit_map"][c3],
            "Commit modifying subdirectory was unexpectedly folded",
        )

        # Verify unreachable objects outside services/search were pruned from the view repo.
        cat_secret = self.git(
            "cat-file", "-e", secret_blob, cwd=proj1["repo_path"], check=False
        )
        require(
            cat_secret.returncode != 0,
            "Unrelated secret blob leaked into projected subdirectory repository",
        )

        clone_dir = case_dir / "cloned-view"
        self.git("clone", proj1["repo_path"], clone_dir)
        require((clone_dir / "engine.rs").read_text() == "pub fn v2() {}\n", "Projected file mismatch")
        require(not (clone_dir / "other").exists(), "Outside directory present in projected clone")

        self.record(
            "deterministic_subdirectory_projection",
            {
                "projected_head_oid": proj1["projected_head_oid"],
                "projected_commits": proj1["projected_commits"],
                "secret_blob_pruned": True,
            },
        )

    def test_composite_view_and_two_phase_integration(self):
        case_dir, store = self.new_case("composite-integration")
        r_proto, b_proto = self.make_source_repo(
            case_dir, "proto-src", {"api.proto": "message Query { string q = 1; }\n"}
        )
        r_search, b_search = self.make_source_repo(
            case_dir,
            "search-src",
            {"engine.rs": "pub fn run() -> &'static str { \"v1\" }\n", "README.md": "Search\n"},
        )

        reg_proto = self.data("register-repo", store, "proto", r_proto, "--quiescent")
        reg_search = self.data("register-repo", store, "search", r_search, "--quiescent")

        ns = self.data(
            "create-namespace",
            store,
            "corp",
            f"libs/proto=proto@{b_proto}",
            f"services/search=search@{b_search}",
        )
        view = self.data("create-task-view", store, "agent-view", ns["revision_id"])

        work = case_dir / "agent-work"
        self.git("clone", view["repo_path"], work)
        require(
            (work / "libs/proto/api.proto").is_file()
            and (work / "services/search/engine.rs").is_file(),
            "Composite view missing mounted files",
        )

        # 1. Verify unmapped paths outside mount prefixes are rejected.
        self.git("checkout", "-b", "task/bad-path", cwd=work)
        (work / "unmapped.txt").write_text("not in any mount\n")
        self.git("add", "unmapped.txt", cwd=work)
        self.git("commit", "-m", "unmapped file", cwd=work)
        self.git("push", "origin", "HEAD:refs/heads/task/bad-path", cwd=work)
        bad_res = self.lab(
            "integrate-changeset", store, view["view_id"], "refs/heads/task/bad-path", check=False
        )
        require(bad_res.returncode != 0, "Unmapped path commit should be rejected")

        # 2. Create a valid cross-repository commit touching both proto and search.
        self.git("checkout", "-B", "task/feature-1", "origin/main", cwd=work)
        (work / "libs/proto/api.proto").write_text(
            "message Query { string q = 1; int32 limit = 2; }\n"
        )
        (work / "services/search/engine.rs").write_text(
            "pub fn run() -> &'static str { \"v2-with-limit\" }\n"
        )
        self.git("add", "libs/proto/api.proto", "services/search/engine.rs", cwd=work)
        self.git("commit", "-m", "add limit field across proto and search", cwd=work)
        task_oid = self.git_oid("rev-parse", "HEAD", cwd=work)
        self.git("push", "origin", "HEAD:refs/heads/task/feature-1", cwd=work)

        # Direct integration from refs/heads/main must be rejected.
        bad_ref = self.lab(
            "integrate-changeset", store, view["view_id"], "refs/heads/main", check=False
        )
        require(bad_ref.returncode != 0, "refs/heads/main must not be accepted as a task ref")

        cs = self.data(
            "integrate-changeset", store, view["view_id"], "refs/heads/task/feature-1"
        )
        require(cs["state"] == "integrated", f"Unexpected state: {cs['state']}")
        require(cs["task_commit_oid"] == task_oid, "Task commit OID mismatch")
        require(cs["projected_view_oid"] is not None, "Missing projected_view_oid")

        proto_main = self.git_oid("rev-parse", "refs/heads/main", cwd=reg_proto["repo_path"])
        search_main = self.git_oid("rev-parse", "refs/heads/main", cwd=reg_search["repo_path"])
        require(proto_main != b_proto and search_main != b_search, "Source repos did not advance")
        require(
            self.git("cat-file", "-p", f"{proto_main}:api.proto", cwd=reg_proto["repo_path"])
            .stdout.decode()
            .endswith("int32 limit = 2; }\n"),
            "proto content not updated",
        )
        require(
            "v2-with-limit"
            in self.git("cat-file", "-p", f"{search_main}:engine.rs", cwd=reg_search["repo_path"])
            .stdout.decode(),
            "search content not updated",
        )

        self.record(
            "composite_view_and_two_phase_integration",
            {
                "changeset_id": cs["changeset_id"],
                "proto_main": proto_main,
                "search_main": search_main,
                "projected_view_oid": cs["projected_view_oid"],
            },
        )

    def test_three_way_merge_and_zero_partial_success_on_conflict(self):
        case_dir, store = self.new_case("conflict-zero-partial")
        r_proto, b_proto = self.make_source_repo(
            case_dir, "proto-src", {"api.proto": "v1\n"}
        )
        r_search, b_search = self.make_source_repo(
            case_dir, "search-src", {"engine.rs": "v1\n", "README.md": "init\n"}
        )

        reg_proto = self.data("register-repo", store, "proto", r_proto, "--quiescent")
        reg_search = self.data("register-repo", store, "search", r_search, "--quiescent")

        ns = self.data(
            "create-namespace",
            store,
            "corp",
            f"libs/proto=proto@{b_proto}",
            f"services/search=search@{b_search}",
        )
        view = self.data("create-task-view", store, "conflict-view", ns["revision_id"])

        # Advance search upstream on a NON-conflicting file (README.md) first, and also
        # on a conflicting file (engine.rs) to test Phase 1 conflict abort.
        (r_search / "engine.rs").write_text("upstream-conflicting-change\n")
        self.git("add", "engine.rs", cwd=r_search)
        self.git("commit", "-m", "upstream search change", cwd=r_search)
        adv = self.data("advance-repo", store, "search", r_search, "--quiescent")
        search_before = adv["head_oid"]
        proto_before = self.git_oid("rev-parse", "refs/heads/main", cwd=reg_proto["repo_path"])

        # In the view, edit BOTH proto (clean!) and search/engine.rs (conflicts with upstream!).
        work = case_dir / "work"
        self.git("clone", view["repo_path"], work)
        self.git("checkout", "-b", "task/conflicting", cwd=work)
        (work / "libs/proto/api.proto").write_text("v2-clean\n")
        (work / "services/search/engine.rs").write_text("agent-conflicting-change\n")
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "cross-repo edit with conflict in one repo", cwd=work)
        self.git("push", "origin", "HEAD:refs/heads/task/conflicting", cwd=work)

        res = self.lab(
            "integrate-changeset", store, view["view_id"], "refs/heads/task/conflicting", check=False
        )
        require(res.returncode != 0, "Conflicting 3-way merge should fail closed")

        # CRITICAL INVARIANT: Neither proto nor search may have moved their refs/heads/main!
        proto_after = self.git_oid("rev-parse", "refs/heads/main", cwd=reg_proto["repo_path"])
        search_after = self.git_oid("rev-parse", "refs/heads/main", cwd=reg_search["repo_path"])
        require(
            proto_after == proto_before and search_after == search_before,
            f"Partial update leaked! proto: {proto_before}->{proto_after}, search: {search_before}->{search_after}",
        )

        self.record(
            "three_way_merge_conflict_zero_partial_success",
            {
                "proto_unchanged": proto_after == proto_before,
                "search_unchanged": search_after == search_before,
            },
        )

    def test_crash_failpoints_lease_fencing_and_roll_forward_recovery(self):
        case_dir, store = self.new_case("failpoints-recovery")
        r_proto, b_proto = self.make_source_repo(
            case_dir, "proto-src", {"api.proto": "v1\n"}
        )
        r_search, b_search = self.make_source_repo(
            case_dir, "search-src", {"engine.rs": "v1\n"}
        )

        reg_proto = self.data("register-repo", store, "proto", r_proto, "--quiescent")
        reg_search = self.data("register-repo", store, "search", r_search, "--quiescent")

        ns = self.data(
            "create-namespace",
            store,
            "corp",
            f"libs/proto=proto@{b_proto}",
            f"services/search=search@{b_search}",
        )
        view = self.data("create-task-view", store, "ha-view", ns["revision_id"])

        work = case_dir / "work"
        self.git("clone", view["repo_path"], work)
        self.git("checkout", "-b", "task/atomic", cwd=work)
        (work / "libs/proto/api.proto").write_text("v2-atomic\n")
        (work / "services/search/engine.rs").write_text("v2-atomic\n")
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "atomic cross-repo change", cwd=work)
        self.git("push", "origin", "HEAD:refs/heads/task/atomic", cwd=work)

        # 1. Crash BEFORE the Commit Point (exit 86).
        env_pre = dict(self.env, ROOTYARD_VIEW_TEST_FAILPOINT="before_commit_point")
        self.lab(
            "integrate-changeset",
            store,
            view["view_id"],
            "refs/heads/task/atomic",
            env=env_pre,
            expected=86,
        )
        require(
            self.git_oid("rev-parse", "refs/heads/main", cwd=reg_proto["repo_path"]) == b_proto
            and self.git_oid("rev-parse", "refs/heads/main", cwd=reg_search["repo_path"]) == b_search,
            "Refs mutated before commit point",
        )
        cs_dirs = [p.name for p in (store / "changesets").iterdir()]
        require(len(cs_dirs) == 1, "Expected 1 staged changeset directory")
        aborted = self.data("recover-changeset", store, cs_dirs[0])
        require(aborted["state"] == "aborted_pre_commit", "Pre-commit crash did not abort cleanly")

        # 2. Crash AFTER Commit Point and after first repo updated (exit 87).
        env_mid = dict(self.env, ROOTYARD_VIEW_TEST_FAILPOINT="mid_commit_after_first_repo")
        self.lab(
            "integrate-changeset",
            store,
            view["view_id"],
            "refs/heads/task/atomic",
            env=env_mid,
            expected=87,
        )
        cs_dirs_after = sorted(
            [p.name for p in (store / "changesets").iterdir() if p.name != cs_dirs[0]]
        )
        require(len(cs_dirs_after) == 1, "Expected second changeset record")
        mid_cs_id = cs_dirs_after[0]

        # Exactly one repository has advanced its refs/heads/main; the second has not yet.
        p_mid = self.git_oid("rev-parse", "refs/heads/main", cwd=reg_proto["repo_path"])
        s_mid = self.git_oid("rev-parse", "refs/heads/main", cwd=reg_search["repo_path"])
        require(
            (p_mid != b_proto) ^ (s_mid != b_search),
            "Expected exactly one repository updated at mid-commit failpoint",
        )

        # While in committing state, external advance-repo on leased repositories MUST be blocked!
        (r_proto / "api.proto").write_text("rogue-concurrent-push\n")
        self.git("add", "api.proto", cwd=r_proto)
        self.git("commit", "-m", "rogue push", cwd=r_proto)
        fenced = self.lab("advance-repo", store, "proto", r_proto, "--quiescent", check=False)
        require(fenced.returncode != 0, "Active lease failed to fence concurrent advance-repo")

        # Recover-changeset must ROLL FORWARD the remaining repository and release leases!
        recovered = self.data("recover-changeset", store, mid_cs_id)
        require(recovered["state"] == "integrated", "Mid-commit recovery failed to roll forward")

        p_final = self.git_oid("rev-parse", "refs/heads/main", cwd=reg_proto["repo_path"])
        s_final = self.git_oid("rev-parse", "refs/heads/main", cwd=reg_search["repo_path"])
        require(
            p_final != b_proto and s_final != b_search,
            "Both repositories must be rolled forward after recover-changeset",
        )
        require(
            list((store / "leases").iterdir()) == [],
            "Leases were not released after roll-forward recovery",
        )

        self.record(
            "crash_failpoints_lease_fencing_and_roll_forward_recovery",
            {
                "aborted_pre_commit_id": cs_dirs[0],
                "rolled_forward_id": mid_cs_id,
                "proto_final": p_final,
                "search_final": s_final,
            },
        )

    def sign_head_commit(self, repo, sig_kind="ssh"):
        raw = self.git("cat-file", "commit", "HEAD", cwd=repo).stdout.decode()
        header, body = raw.split("\n\n", 1)
        banner = "SSH SIGNATURE" if sig_kind == "ssh" else "PGP SIGNATURE"
        gpgsig = (
            f"gpgsig -----BEGIN {banner}-----\n"
            " U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg\n"
            f" -----END {banner}-----"
        )
        signed_raw = f"{header}\n{gpgsig}\n\n{body}".encode()
        proc = subprocess.run(
            [self.git_binary, "hash-object", "-t", "commit", "-w", "--stdin"],
            cwd=repo,
            env=self.env,
            input=signed_raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        oid = proc.stdout.decode().strip()
        self.git("reset", "--hard", oid, cwd=repo)
        return oid

    def test_long_term_history_projection_and_cryptographic_provenance(self):
        case_dir, store = self.new_case("history-provenance")
        mono, c1 = self.make_source_repo(
            case_dir,
            "mono-src",
            {
                "services/search/engine.rs": "pub fn v1() {}\n",
                "other/outside.txt": "outside-v1\n",
            },
        )
        # Commit 2: outside-only change (folded).
        (mono / "other/outside.txt").write_text("outside-v2\n")
        self.git("add", "other/outside.txt", cwd=mono)
        self.git("commit", "-m", "outside only", cwd=mono)

        # Branch with signed commit inside services/search.
        self.git("checkout", "-b", "feature", cwd=mono)
        (mono / "services/search/feature.rs").write_text("pub fn feat() {}\n")
        self.git("add", "services/search/feature.rs", cwd=mono)
        self.git("commit", "-m", "signed feature commit", cwd=mono)
        c_feat = self.sign_head_commit(mono, "ssh")

        # Main branch commit + merge commit to test merge topology preservation.
        self.git("checkout", "main", cwd=mono)
        (mono / "services/search/engine.rs").write_text("pub fn v2() {}\n")
        self.git("add", "services/search/engine.rs", cwd=mono)
        self.git("commit", "-m", "main v2", cwd=mono)
        self.git("merge", "--no-ff", "feature", "-m", "merge feature", cwd=mono)
        c_merge = self.sign_head_commit(mono, "gpg")

        self.data("register-repo", store, "mono", mono, "--quiescent")

        # 1. Project deterministic_history at Epoch 1.
        hist_e1 = self.data(
            "project-history",
            store,
            "search-hist",
            "mono",
            "--strategy",
            "deterministic_history",
            "--subdir",
            "services/search",
        )
        require(hist_e1["view_epoch"] == 1, "Expected epoch 1")
        require(hist_e1["projected_commits"] == 4, f"Expected 4 commits, got {hist_e1['projected_commits']}")
        require(hist_e1["rewritten_history_commits"] == 4, "Expected 4 rewritten commits")
        require(hist_e1["source_signed_commits"] == 2, "Expected 2 source-signed commits")

        # Verify merge parent topology preserved in projected history.
        proj_merge = hist_e1["commit_map"][c_merge]
        merge_parents = (
            self.git_oid("rev-list", "--parents", "-n", "1", proj_merge, cwd=hist_e1["repo_path"])
            .split()[1:]
        )
        require(len(merge_parents) == 2, f"Expected 2 merge parents, got {merge_parents}")

        ver1 = self.data("verify-view", store, hist_e1["view_id"])
        require(ver1["signature_verified"] is True, "Epoch 1 provenance verification failed")
        require(ver1["verified_projected_commits"] == 4, "Expected 4 verified commits")

        # 2. Advance source repo and incrementally project Epoch 2 without rewriting Epoch 1.
        (mono / "services/search/engine.rs").write_text("pub fn v3() {}\n")
        self.git("add", "services/search/engine.rs", cwd=mono)
        self.git("commit", "-m", "engine v3", cwd=mono)
        self.data("advance-repo", store, "mono", mono, "--quiescent")

        hist_e2 = self.data(
            "project-history",
            store,
            "search-hist",
            "mono",
            "--strategy",
            "deterministic_history",
            "--subdir",
            "services/search",
        )
        require(hist_e2["view_epoch"] == 2, "Expected epoch 2")
        require(hist_e2["newly_projected_commits"] == 1, "Expected 1 newly projected commit")
        require(hist_e2["reused_epoch_commits"] >= 4, "Expected prior epoch commits reused")
        require(
            hist_e2["commit_map"][c1] == hist_e1["commit_map"][c1]
            and hist_e2["commit_map"][c_feat] == hist_e1["commit_map"][c_feat]
            and hist_e2["commit_map"][c_merge] == hist_e1["commit_map"][c_merge],
            "Prior epoch projected OIDs must remain immutable across epoch advancement",
        )
        ver2 = self.data("verify-view", store, hist_e2["view_id"])
        require(ver2["signature_verified"] is True and ver2["view_epoch"] == 2, "Epoch 2 verify failed")

        # 3. Project task_snapshot strategy (0 rewritten history commits) and test tamper detection.
        snap = self.data(
            "project-history",
            store,
            "search-snap",
            "mono",
            "--strategy",
            "task_snapshot",
            "--subdir",
            "services/search",
        )
        require(
            snap["projected_commits"] == 1 and snap["rewritten_history_commits"] == 0,
            "task_snapshot must produce 1 root commit with 0 rewritten history commits",
        )
        ver_snap = self.data("verify-view", store, snap["view_id"])
        require(ver_snap["signature_verified"] is True, "Snapshot provenance verification failed")

        # Tamper with refs/heads/main in the snapshot view and assert verify-view fails closed.
        tree_oid = self.git_oid("rev-parse", "refs/heads/main^{tree}", cwd=snap["repo_path"])
        forged_oid = self.git_oid(
            "commit-tree", tree_oid, "-m", "forged commit without provenance", cwd=snap["repo_path"]
        )
        self.git("update-ref", "refs/heads/main", forged_oid, cwd=snap["repo_path"])
        tamper_res = self.lab("verify-view", store, snap["view_id"], check=False)
        require(tamper_res.returncode != 0, "Tampered view must fail verify-view")
        tamper_report = json.loads(tamper_res.stdout.decode())
        require(
            tamper_report["signature_verified"] is False
            and forged_oid in tamper_report["tampered_commits"],
            "Tampered commit OID not reported by verify-view",
        )

        self.record(
            "long_term_history_projection_and_cryptographic_provenance",
            {
                "history_view_id": hist_e2["view_id"],
                "snapshot_view_id": snap["view_id"],
                "epoch_2_head": hist_e2["projected_head_oid"],
                "tamper_detected_oid": forged_oid,
            },
        )

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard-view-lab")
    parser.add_argument("--report", default="test-results/git-views.json")
    args = parser.parse_args()

    started = time.time()
    harness = Harness(args)
    try:
        harness.test_namespace_mounts_and_base_vector()
        harness.test_deterministic_subdirectory_projection()
        harness.test_composite_view_and_two_phase_integration()
        harness.test_three_way_merge_and_zero_partial_success_on_conflict()
        harness.test_crash_failpoints_lease_fencing_and_roll_forward_recovery()
        harness.test_long_term_history_projection_and_cryptographic_provenance()
        report = {
            "suite": "git-views",
            "passed": True,
            "git_version": harness.git_version,
            "binary_sha256": harness.binary_sha256,
            "duration_seconds": round(time.time() - started, 3),
            "checks": harness.checks,
        }
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        harness.cleanup()


if __name__ == "__main__":
    sys.exit(main())
