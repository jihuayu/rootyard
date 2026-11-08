#!/usr/bin/env python3
"""Real-Git tests for the opt-in local rootyard-workspace-lab prototype.

Every test owns disposable repositories and a private store. No database, remote,
existing user repository, network service, or shared object store is touched.
The caller explicitly supplies the lab's quiescence promise. These tests are not
evidence of a write barrier, hostile-tenant isolation, or power-loss durability.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import uuid


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def is_uuid(value):
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def tree(path):
    """Byte names/content, execute bits and link bytes, without inode/mtime noise."""
    result = {}
    root = os.fsencode(path)

    def walk(directory, prefix=b""):
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            relative = prefix + entry.name
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                result[relative] = ("link", os.readlink(entry.path))
            elif stat.S_ISDIR(info.st_mode):
                walk(entry.path, relative + b"/")
            elif stat.S_ISREG(info.st_mode):
                with open(entry.path, "rb") as stream:
                    digest = hashlib.sha256(stream.read()).hexdigest()
                result[relative] = ("file", info.st_mode & 0o111, digest)
            else:
                result[relative] = ("special", stat.S_IFMT(info.st_mode))

    walk(root)
    return result


class Harness:
    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-workspaces-test-"))
        self.binary = Path(args.binary).expanduser().resolve()
        self.binary_sha256 = hashlib.sha256(self.binary.read_bytes()).hexdigest() if self.binary.is_file() else None
        selected_git = os.environ.get("ROOTYARD_WORKSPACE_GIT", "git")
        found_git = shutil.which(selected_git)
        require(found_git is not None, "Git executable is unavailable")
        self.git_binary = str(Path(found_git).resolve())
        self.env = dict(os.environ)
        for key in list(self.env):
            if key.startswith("GIT_") or key.startswith("ROOTYARD_WORKSPACE_"):
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
            "ROOTYARD_WORKSPACE_GIT": self.git_binary,
        })
        (self.root / "home").mkdir()
        (self.root / "xdg").mkdir()
        self.sequence = 0
        self.checks = []
        self.git_version = self.git("--version").stdout.decode().strip()

    def run(self, argv, cwd=None, check=True, env=None, expected=None):
        result = subprocess.run(
            [os.fspath(arg) for arg in argv], cwd=cwd, env=env or self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        if expected is not None:
            require(result.returncode == expected,
                    f"Expected exit {expected}, got {result.returncode}: "
                    + result.stderr.decode(errors="replace"))
        elif check:
            require(result.returncode == 0,
                    f"Command {argv[0]} {argv[1:]} failed ({result.returncode}): "
                    + result.stderr.decode(errors="replace"))
        return result

    def git(self, *args, cwd=None, check=True, env=None):
        return self.run([
            self.git_binary, "-c", "user.name=Workspace Test",
            "-c", "user.email=workspace-test@example.invalid",
            "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args,
        ], cwd=cwd, check=check, env=env)

    def lab(self, *args, check=True, env=None, expected=None):
        return self.run([self.binary, *args], check=check, env=env, expected=expected)

    def data(self, *args, env=None):
        result = self.lab(*args, env=env)
        try:
            return json.loads(result.stdout)
        except (ValueError, UnicodeError) as error:
            raise AssertionError("Successful command must emit a JSON object: "
                                 + result.stdout.decode(errors="replace")) from error

    def fixture(self, label="case", files=None):
        self.sequence += 1
        root = self.root / f"{self.sequence:03d}-{label}"
        root.mkdir()
        source = root / "source"
        self.git("init", "-b", "main", source)
        for name, content in (files or {"plain.txt": b"base\n"}).items():
            self.write(source, name, content)
        self.git("add", "--all", cwd=source)
        self.git("commit", "-m", "base", cwd=source)
        base = self.oid(source)
        return root, source, root / "store", base

    def write(self, repo, name, content):
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def oid(self, repo, ref="HEAD"):
        return self.git("rev-parse", ref, cwd=repo).stdout.decode().strip()

    def workspace(self, result, store, base, agent, parent=None):
        require(isinstance(result, dict), "Workspace response must be an object")
        require(is_uuid(result.get("workspace_id")), "Workspace ID must be a UUID")
        require(result.get("agent_id") == agent, "Agent identity was not retained")
        require(result.get("base_oid") == base, "Fixed base OID changed")
        require(result.get("namespace_revision") == 1, "Unexpected namespace revision")
        require(result.get("parent_checkpoint_id") == parent,
                "Incorrect parent checkpoint identity")
        expected = store / "workspaces" / result["workspace_id"] / "repo"
        require(Path(result["repo_path"]).resolve() == expected.resolve(),
                "Workspace repo_path does not match its private namespace")
        require(expected.is_dir(), "Successful workspace response has no repository")
        require((expected.parent / "workspace.json").is_file(), "Missing workspace metadata")
        return expected

    def init(self, store, source, base, agent="agent-initial", env=None):
        info = self.data("init", store, source, agent, base, "--quiescent", env=env)
        return info, self.workspace(info, store, base, agent)

    def checkpoint(self, store, info):
        result = self.data("checkpoint", store, info["workspace_id"], "--quiescent")
        require(is_uuid(result.get("checkpoint_id")), "Checkpoint ID must be a UUID")
        require(result.get("state") == "local_complete", "Checkpoint is not local_complete")
        require(result.get("base_oid") == info["base_oid"], "Checkpoint changed the fixed base")
        path = store / "checkpoints" / result["checkpoint_id"]
        for name in ("manifest.json", "manifest.sha256"):
            require((path / name).is_file(), "Missing checkpoint " + name)
        require((path / "repo").is_dir(), "Missing checkpoint repository")
        return result

    def restore(self, store, checkpoint, base, agent="agent-restored"):
        checkpoint_id = (checkpoint["checkpoint_id"]
                         if isinstance(checkpoint, dict) else checkpoint)
        info = self.data("restore", store, checkpoint_id, agent)
        return info, self.workspace(info, store, base, agent, checkpoint_id)

    def published(self, store, kind):
        folder = store / kind
        return {p.name for p in folder.iterdir() if p.is_dir() and is_uuid(p.name)} if folder.exists() else set()

    def rejected(self, *args, store=None, kind="workspaces", env=None):
        before = self.published(store, kind) if store else None
        result = self.lab(*args, check=False, env=env)
        require(result.returncode != 0, "Unsafe or damaged input was accepted")
        if store:
            require(self.published(store, kind) == before,
                    "Rejected operation published a destination")
        return result

    def reject_init_before_store(self, label, source, base, agent="agent-preflight"):
        """A rejected init must fail before the store exists and must not touch the source."""
        store = source.parent / (label + "-store")
        require(not store.exists(), label + ": preflight fixture reused an existing store path")
        before = tree(source)
        refs = self.git("for-each-ref", "--format=%(refname) %(objectname)", cwd=source).stdout
        index = source / ".git/index"
        index_before = index.read_bytes() if index.is_file() else None
        result = self.lab("init", store, source, agent, base, "--quiescent", check=False)
        require(result.returncode != 0, label + ": unsupported source was accepted by init")
        require(not store.exists(), label + ": rejected init created the store directory")
        require(not (store / "staging").exists(), label + ": rejected init created a staging directory")
        require(not (store / "workspaces").exists(), label + ": rejected init created a workspace directory")
        require(self.published(store, "workspaces") == set(), label + ": rejected init published a workspace")
        self.equal(tree(source), before, label + ": rejected init modified the source bytes")
        require(self.git("for-each-ref", "--format=%(refname) %(objectname)", cwd=source).stdout == refs,
                label + ": rejected init changed source refs")
        if index_before is not None:
            require(index.read_bytes() == index_before, label + ": rejected init rewrote the source index")
        return True

    def preflight_rejections_before_store(self):
        """Real Git shapes that init must refuse before creating or locking any store."""
        checked = []

        # Real linked worktree: a .git pointer file plus shared administration in the
        # main repository. Both shapes are unsupported; neither may create a store.
        root, source, _, base = self.fixture("preflight-worktree")
        linked = root / "linked-worktree"
        self.git("worktree", "add", str(linked), "-b", "linked-branch", cwd=source)
        require((linked / ".git").is_file(), "worktree fixture did not create a .git pointer file")
        require((source / ".git/worktrees").is_dir(), "worktree fixture did not create shared admin")
        self.reject_init_before_store("linked-worktree", linked, base)
        self.reject_init_before_store("worktree-shared-admin", source, base)
        checked.extend(["linked-worktree-git-file", "worktree-shared-admin"])

        # Real submodule with a local owned URL. File transport is allowed for this
        # fixture clone only, never for lab Git invocations.
        root, source, _, _ = self.fixture("preflight-submodule")
        library = root / "library"
        self.git("init", "-b", "main", library)
        self.write(library, "lib.txt", b"library\n")
        self.git("add", "--all", cwd=library)
        self.git("commit", "-m", "library base", cwd=library)
        self.git("-c", "protocol.file.allow=always", "submodule", "add",
                 str(library), "vendor/library", cwd=source)
        self.git("commit", "-m", "add local submodule", cwd=source)
        base = self.oid(source)
        require((source / ".git/modules/vendor/library").is_dir(), "submodule fixture has no .git/modules")
        require((source / ".gitmodules").is_file(), "submodule fixture has no .gitmodules")
        self.reject_init_before_store("submodule", source, base)
        checked.append("submodule-git-modules")

        # Uninitialized gitlink fixtures: a submodule entry created directly with
        # update-index --cacheinfo, so there is no .gitmodules file, no
        # .git/modules checkout and no submodule transport or network access.
        # HEAD and index are examined independently because a name-only listing
        # hides the 160000 mode.
        root, source, _, base = self.fixture("preflight-index-gitlink")
        self.git("update-index", "--add", "--cacheinfo",
                 f"160000,{base},vendor/library", cwd=source)
        require(any(line.startswith(b"160000 ") and line.endswith(b"\tvendor/library")
                    for line in self.git("ls-files", "--stage", cwd=source).stdout.splitlines()),
                "index gitlink fixture has no 160000 index entry")
        require(not (source / ".gitmodules").exists(),
                "index gitlink fixture unexpectedly has .gitmodules")
        require(not (source / ".git/modules").exists(),
                "index gitlink fixture unexpectedly has .git/modules")
        require(not (source / "vendor").exists(),
                "index gitlink fixture unexpectedly has a checkout")
        self.reject_init_before_store("index-gitlink", source, base)

        root, source, _, _ = self.fixture("preflight-head-gitlink")
        gitlink_oid = self.oid(source)
        self.git("update-index", "--add", "--cacheinfo",
                 f"160000,{gitlink_oid},vendor/library", cwd=source)
        self.git("commit", "-m", "gitlink without submodule metadata", cwd=source)
        base = self.oid(source)
        self.git("update-index", "--force-remove", "vendor/library", cwd=source)
        require(b"160000 commit" in self.git("ls-tree", "-r", "--full-tree", "HEAD", cwd=source).stdout,
                "HEAD gitlink fixture has no 160000 tree entry")
        require(b"160000 " not in self.git("ls-files", "--stage", cwd=source).stdout,
                "HEAD gitlink fixture still has a 160000 index entry")
        require(not (source / ".gitmodules").exists(),
                "HEAD gitlink fixture unexpectedly has .gitmodules")
        require(not (source / ".git/modules").exists(),
                "HEAD gitlink fixture unexpectedly has .git/modules")
        require(not (source / "vendor").exists(),
                "HEAD gitlink fixture unexpectedly has a checkout")
        self.reject_init_before_store("head-gitlink", source, base)
        checked.extend(["index-gitlink-without-gitmodules", "head-gitlink-without-gitmodules"])

        # Tracked .gitattributes requesting an LFS filter. The fixture configures a
        # trivial filter only to create the commit, then removes it so the tracked
        # attribute file itself is the sole reason for rejection.
        root, source, _, _ = self.fixture("preflight-lfs-attributes", {"blob.bin": b"ordinary bytes\n"})
        self.git("config", "filter.lfs.clean", "cat", cwd=source)
        self.git("config", "filter.lfs.smudge", "cat", cwd=source)
        self.write(source, ".gitattributes", b"*.bin filter=lfs diff=lfs merge=lfs -text\n")
        self.git("add", ".gitattributes", "blob.bin", cwd=source)
        self.git("commit", "-m", "tracked LFS attributes", cwd=source)
        self.git("config", "--remove-section", "filter.lfs", cwd=source)
        base = self.oid(source)
        require(b"filter=lfs" in (source / ".gitattributes").read_bytes(),
                "LFS fixture did not track a filter attribute")
        require(b"filter" not in (source / ".git/config").read_bytes(),
                "LFS fixture left filter configuration behind")
        self.reject_init_before_store("lfs-attributes", source, base)
        checked.append("tracked-gitattributes-filter-lfs")

        # Real ordinary sparse checkout (cone mode, no sparse index). Git writes its
        # own sparse configuration (extensions.worktreeConfig plus config.worktree),
        # which the local Git config allowlist refuses conservatively.
        root, source, _, _ = self.fixture("preflight-sparse", {
            "visible/file.txt": b"visible\n", "excluded/file.txt": b"excluded\n",
        })
        self.git("sparse-checkout", "init", "--cone", cwd=source)
        self.git("sparse-checkout", "set", "visible", cwd=source)
        require(b"sdir" not in (source / ".git/index").read_bytes(),
                "ordinary sparse fixture unexpectedly produced a sparse index")
        require(b"040000 " not in self.git("ls-files", "--sparse", "--stage", cwd=source).stdout,
                "ordinary sparse fixture unexpectedly produced sparse directory entries")
        base = self.oid(source)
        self.reject_init_before_store("sparse-checkout", source, base)
        checked.append("sparse-checkout-ordinary-mode")

        # Real split index generated by Git itself.
        _, source, _, base = self.fixture("preflight-split-index")
        self.git("update-index", "--split-index", cwd=source)
        require(any(name.startswith("sharedindex.") for name in os.listdir(source / ".git")),
                "split-index fixture produced no shared index")
        self.reject_init_before_store("split-index", source, base)
        checked.append("split-index")

        # Real external object alternates created by a local shared clone.
        root, source, _, _ = self.fixture("preflight-alternates")
        shared = root / "shared-clone"
        self.git("clone", "--shared", str(source), str(shared), cwd=root)
        require((shared / ".git/objects/info/alternates").is_file(),
                "shared clone produced no alternates file")
        self.reject_init_before_store("alternates", shared, self.oid(shared))
        checked.append("external-alternates")

        # Real SHA-256 repository (rejected; SHA-256 support is not implemented).
        root, _, _, _ = self.fixture("preflight-sha256")
        sha = root / "sha256-repository"
        self.git("init", "--object-format=sha256", "-b", "main", sha)
        self.write(sha, "plain.txt", b"sha256\n")
        self.git("add", "--all", cwd=sha)
        self.git("commit", "-m", "sha256 base", cwd=sha)
        self.reject_init_before_store("sha256", sha, self.oid(sha))
        checked.append("sha256-repository")

        # Managed worktree symlinks that capture used to reject only after the store
        # already existed. Each variant is its own fresh repository.
        root, source, _, base = self.fixture("preflight-absolute-symlink")
        (source / "absolute-link").symlink_to(source / "plain.txt")
        self.reject_init_before_store("absolute-symlink", source, base)
        root, source, _, base = self.fixture("preflight-escaping-symlink")
        (root / "outside.txt").write_bytes(b"outside\n")
        (source / "escaping-link").symlink_to("../outside.txt")
        self.reject_init_before_store("escaping-symlink", source, base)
        root, source, _, base = self.fixture("preflight-git-target-symlink")
        (source / "git-target-link").symlink_to(".git/config")
        self.reject_init_before_store("git-target-symlink", source, base)
        checked.extend(["absolute-symlink", "escaping-symlink", "git-target-symlink"])

        # Argument validation also precedes store creation.
        _, source, _, base = self.fixture("preflight-arguments")
        self.reject_init_before_store("invalid-agent", source, base, agent="invalid agent!")
        self.reject_init_before_store("invalid-oid", source, "0" * 39)
        checked.extend(["invalid-agent-before-store", "invalid-oid-before-store"])

        # No false rejection: a .rootyardignore-excluded untracked attribute file is
        # unmanaged for capture, so init must still succeed and must not copy it.
        _, source, store, base = self.fixture("preflight-ignored-attributes")
        self.write(source, ".rootyardignore", b"generated/\n")
        self.write(source, "generated/.gitattributes", b"*.bin filter=lfs\n")
        info, work = self.init(store, source, base)
        require(not (work / "generated").exists(),
                "rootyardignore-excluded attribute file was captured despite preflight")
        self.checkpoint(store, info)

        # Ordinary non-filter attributes stay supported.
        _, source, store, base = self.fixture("preflight-ordinary-attributes")
        self.write(source, ".gitattributes", b"*.txt text eol=lf\n")
        self.git("add", ".gitattributes", cwd=source)
        self.git("commit", "-m", "ordinary attributes", cwd=source)
        base = self.oid(source)
        info, work = self.init(store, source, base)
        require((work / ".gitattributes").read_bytes() == b"*.txt text eol=lf\n",
                "ordinary .gitattributes was not copied byte-for-byte")
        checked.extend(["rootyardignore-ignored-attributes-accepted", "ordinary-attributes-accepted"])

        # No false rejection: a Git-ignored link that escapes the repository is
        # unmanaged, so init must still succeed.
        root, source, store, base = self.fixture("preflight-ignored-symlink")
        (root / "outside.txt").write_bytes(b"outside\n")
        self.write(source, ".gitignore", b"ignored-link\n")
        (source / "ignored-link").symlink_to("../outside.txt")
        self.init(store, source, base)
        checked.append("git-ignored-escaping-symlink-accepted")

        return {"preflight_rejections": checked, "fresh_store_paths_absent": True,
                "source_bytes_refs_index_preserved": True,
                "unmanaged_attributes_and_symlinks_not_rejected": True}

    def equal(self, left, right, label):
        require(left == right,
                label + "; differing byte paths: "
                + repr(sorted(key for key in left.keys() | right.keys()
                              if left.get(key) != right.get(key))[:20]))

    def disjoint(self, paths):
        seen = {}
        total = 0
        git_total = 0
        for root in paths:
            for relative in tree(root):
                full = os.path.join(os.fsencode(root), relative)
                info = os.lstat(full)
                if not stat.S_ISREG(info.st_mode):
                    continue
                inode = (info.st_dev, info.st_ino)
                require(inode not in seen,
                        f"Hardlinked files cross repositories: {seen.get(inode)!r}, {full!r}")
                seen[inode] = full
                total += 1
                git_total += relative.startswith(b".git/")
        require(git_total > 0 and total > git_total, "Inode check missed Git or worktree files")
        return total

    def isolation_and_fixed_base(self):
        _, source, store, base = self.fixture("isolation")
        original = tree(source)
        info, work = self.init(store, source, base)
        self.equal(tree(work), original, "Init was not a byte-preserving copy")
        inspected = self.data("inspect", store, info["workspace_id"])
        self.workspace(inspected, store, base, "agent-initial")
        checkpoint = self.checkpoint(store, info)
        _, first = self.restore(store, checkpoint, base, "agent-first")
        _, second = self.restore(store, checkpoint, base, "agent-second")
        saved = store / "checkpoints" / checkpoint["checkpoint_id"] / "repo"
        count = self.disjoint([source, work, saved, first, second])
        stable = {path: tree(path) for path in (source, work, saved, second)}
        self.write(first, "plain.txt", b"first fork only\n")
        self.git("add", "plain.txt", cwd=first)
        self.git("commit", "-m", "independent fork", cwd=first)
        self.git("branch", "fork-private-ref", cwd=first)
        require(self.oid(first) != base, "Mutation fixture did not move HEAD")
        for path, before in stable.items():
            self.equal(tree(path), before, "One fork changed another repository")
        self.write(work, "plain.txt", b"moved head\n")
        self.git("add", "plain.txt", cwd=work)
        self.git("commit", "-m", "advance source workspace", cwd=work)
        advanced = self.oid(work)
        changed = self.checkpoint(store, info)
        _, restored = self.restore(store, changed, base, "agent-moved-head")
        require(self.oid(restored) == advanced and advanced != base,
                "Restored HEAD does not preserve movement away from fixed base")
        inspected = self.data("inspect", store, info["workspace_id"])
        require(inspected["base_oid"] == base, "Inspect recomputed fixed base from HEAD")
        self.equal(tree(source), original, "Source changed during workspace operations")
        require(stat.S_IMODE(store.stat().st_mode) & 0o077 == 0, "Store is not private")
        return {"independent_regular_files": count, "forks": 2, "fixed_base_after_commit": True}

    def partial_staging_and_intent(self):
        _, source, store, base = self.fixture("index", {"partial.txt": b"HEAD version\n"})
        original = tree(source)
        info, work = self.init(store, source, base)
        self.write(work, "partial.txt", b"INDEX version\n")
        self.git("add", "partial.txt", cwd=work)
        self.write(work, "partial.txt", b"WORKTREE version\n")
        self.write(work, "intent.txt", b"intent bytes\n")
        self.git("add", "--intent-to-add", "intent.txt", cwd=work)
        self.write(work, "new-staged.txt", b"staged bytes\n")
        self.git("add", "new-staged.txt", cwd=work)
        self.write(work, "untracked.txt", b"untracked bytes\x00\xff\n")
        before = tree(work)
        raw_index = (work / ".git/index").read_bytes()
        checkpoint = self.checkpoint(store, info)
        _, restored = self.restore(store, checkpoint, base)
        self.equal(tree(restored), before, "Partial staging/intent snapshot changed bytes")
        require((restored / ".git/index").read_bytes() == raw_index, "Raw index was reconstructed")
        require(self.git("show", "HEAD:partial.txt", cwd=restored).stdout == b"HEAD version\n", "HEAD layer lost")
        require(self.git("show", ":partial.txt", cwd=restored).stdout == b"INDEX version\n", "Index layer lost")
        require((restored / "partial.txt").read_bytes() == b"WORKTREE version\n", "Worktree layer lost")
        cached = self.git("diff", "--cached", "--name-only", "-z", cwd=restored).stdout.split(b"\x00")
        unstaged = self.git("diff", "--name-only", "-z", cwd=restored).stdout.split(b"\x00")
        require(b"intent.txt" not in cached and b"intent.txt" in unstaged, "Intent-to-add semantic flag lost")
        self.equal(tree(source), original, "Source changed during partial-staging test")
        return {"head_index_worktree_distinct": True, "raw_index_equal": True, "intent_to_add": True}

    def hardlinks_and_detached_head(self):
        _, source, store, _ = self.fixture("hardlinks-detached")
        os.link(source / "plain.txt", source / "source-hardlink.txt")
        self.git("add", "source-hardlink.txt", cwd=source)
        self.git("commit", "-m", "source hardlink fixture", cwd=source)
        base = self.oid(source)
        self.git("checkout", "--detach", base, cwd=source)
        original = tree(source)
        require((source / "plain.txt").stat().st_ino == (source / "source-hardlink.txt").stat().st_ino,
                "Fixture did not create source hardlinks")
        info, work = self.init(store, source, base)
        checkpoint = self.checkpoint(store, info)
        _, restored = self.restore(store, checkpoint, base)
        saved = store / "checkpoints" / checkpoint["checkpoint_id"] / "repo"
        self.disjoint([work, saved, restored])
        source_inodes = {(p.stat().st_dev, p.stat().st_ino)
                         for p in (source / "plain.txt", source / "source-hardlink.txt")}
        for repo in (work, saved, restored):
            self.equal(tree(repo), original, "Hardlinked source or detached HEAD bytes changed")
            for name in ("plain.txt", "source-hardlink.txt"):
                item = (repo / name).stat()
                require((item.st_dev, item.st_ino) not in source_inodes, "Destination shares a source hardlink inode")
            require((repo / ".git/HEAD").read_bytes() == (base + "\n").encode(), "Detached HEAD was made symbolic")
            require(self.git("symbolic-ref", "-q", "HEAD", cwd=repo, check=False).returncode == 1,
                    "Restored HEAD is not detached")
        self.write(restored, "plain.txt", b"only one independent destination file\n")
        require((restored / "source-hardlink.txt").read_bytes() == b"base\n", "Source hardlink relationship survived copying")
        self.equal(tree(source), original, "Hardlink restore modified original source")
        return {"source_hardlinks_broken_into_independent_files": True, "detached_head_preserved": True}

    def merge_conflict(self):
        _, source, store, _ = self.fixture("merge", {"conflict.txt": b"base\n"})
        self.git("checkout", "-b", "side", cwd=source)
        self.write(source, "conflict.txt", b"side\n")
        self.git("add", "conflict.txt", cwd=source)
        self.git("commit", "-m", "side", cwd=source)
        side = self.oid(source)
        self.git("checkout", "main", cwd=source)
        self.write(source, "conflict.txt", b"main\n")
        self.git("add", "conflict.txt", cwd=source)
        self.git("commit", "-m", "main", cwd=source)
        base = self.oid(source)
        original = tree(source)
        info, work = self.init(store, source, base)
        merge = self.git("merge", "side", cwd=work, check=False)
        require(merge.returncode == 1, "Fixture did not produce a true Git conflict")
        stages = self.git("ls-files", "--unmerged", "-z", cwd=work).stdout
        require(all(f" {stage}\t".encode() in stages for stage in (1, 2, 3)), "Missing fixture conflict stages")
        before = tree(work)
        checkpoint = self.checkpoint(store, info)
        _, restored = self.restore(store, checkpoint, base)
        self.equal(tree(restored), before, "Merge metadata or conflict bytes changed")
        require(self.git("ls-files", "--unmerged", "-z", cwd=restored).stdout == stages, "Conflict index stages lost")
        require((restored / ".git/MERGE_HEAD").read_text().strip() == side, "MERGE_HEAD lost")
        self.write(restored, "conflict.txt", b"resolved\n")
        self.git("add", "conflict.txt", cwd=restored)
        self.git("commit", "-m", "finish restored merge", cwd=restored)
        parents = self.git("rev-list", "--parents", "-n", "1", "HEAD", cwd=restored).stdout.decode().split()[1:]
        require(parents == [base, side], "Restored merge cannot produce the expected two-parent commit")
        self.equal(tree(work), before, "Resolving restored merge changed its source workspace")
        self.equal(tree(source), original, "Merge test changed source")
        return {"stages": [1, 2, 3], "merge_head": True, "restored_merge_committed": True}

    def ignore_and_head_union(self):
        _, source, store, _ = self.fixture("ignore", {
            ".gitignore": b"ignored/\nforced/\ncache/*\n!cache/.gitignore\n!cache/keep/\n",
            "cache/.gitignore": b"*\n!.gitignore\n!keep/\n",
            "cache/keep/.gitignore": b"*\n!.gitignore\n!visible.txt\n",
            "plain.txt": b"base\n",
        })
        for name in ("ignored/tracked.txt", "forced/committed.txt"):
            self.write(source, name, b"tracked under ignore\n")
            self.git("add", "--force", name, cwd=source)
        self.git("commit", "-m", "track ignored paths", cwd=source)
        base = self.oid(source)
        self.write(source, "ignored/source-only.txt", b"ignored before init\n")
        original = tree(source)
        info, work = self.init(store, source, base)
        require(not (work / "ignored/source-only.txt").exists(), "Init copied ignored untracked source data")
        self.write(work, "ignored/tracked.txt", b"tracked changed\n")
        self.write(work, "forced/added.txt", b"force-added\n")
        self.git("add", "--force", "forced/added.txt", cwd=work)
        self.git("rm", "--cached", "forced/committed.txt", cwd=work)
        visible = ["cache/keep/visible.txt", "ordinary-untracked.txt"]
        excluded = ["ignored/discard.txt", "forced/discard.txt", "cache/discard.txt", "cache/keep/discard.txt"]
        for name in visible + excluded:
            self.write(work, name, (name + "\n").encode())
        for name in visible:
            require(self.git("check-ignore", "-q", name, cwd=work, check=False).returncode == 1,
                    "Nested ignore fixture unexpectedly excludes " + name)
        for name in excluded:
            require(self.git("check-ignore", "-q", name, cwd=work, check=False).returncode == 0,
                    "Ignore fixture unexpectedly includes " + name)
        expected = tree(work)
        for name in excluded:
            expected.pop(os.fsencode(name))
        checkpoint = self.checkpoint(store, info)
        saved = store / "checkpoints" / checkpoint["checkpoint_id"] / "repo"
        self.equal(tree(saved), expected, "Checkpoint included ignored untracked files or lost managed files")
        _, restored = self.restore(store, checkpoint, base)
        self.equal(tree(restored), expected, "Ignore/HEAD union restore differs")
        require((restored / "forced/committed.txt").is_file(), "HEAD-union path removed from index was lost")
        require(self.git("ls-files", "--error-unmatch", "forced/committed.txt", cwd=restored, check=False).returncode != 0,
                "rm --cached index deletion was undone")
        self.equal(tree(source), original, "Ignore test changed source")
        return {"ignored_untracked_excluded": len(excluded), "nested_negation": True,
                "tracked_ignored_and_force_added": True, "head_union_rm_cached": True,
                "init_excludes_ignored_source_data_without_deleting_it": True}

    def deletion_and_rename(self):
        _, source, store, base = self.fixture("rename", {
            "staged-delete.txt": b"staged deletion\n", "unstaged-delete.txt": b"unstaged deletion\n",
            "staged-rename.txt": b"staged rename\n", "unstaged-rename.txt": b"unstaged rename\n",
        })
        info, work = self.init(store, source, base)
        self.git("rm", "staged-delete.txt", cwd=work)
        (work / "unstaged-delete.txt").unlink()
        self.git("mv", "staged-rename.txt", "renamed-staged.txt", cwd=work)
        (work / "unstaged-rename.txt").rename(work / "renamed-untracked.txt")
        before = tree(work)
        status = self.git("status", "--porcelain=v1", "-z", "--untracked-files=all", cwd=work).stdout
        checkpoint = self.checkpoint(store, info)
        _, restored = self.restore(store, checkpoint, base)
        self.equal(tree(restored), before, "Deletion/rename bytes or index changed")
        require(self.git("status", "--porcelain=v1", "-z", "--untracked-files=all", cwd=restored).stdout == status,
                "Deletion/rename Git semantics changed")
        return {"staged_and_unstaged_deletions": True, "staged_and_unstaged_renames": True}

    def modes_links_and_byte_names(self):
        _, source, store, base = self.fixture("paths")
        info, work = self.init(store, source, base)
        odd = ["space name.txt", "tab\tname", "line\nname", "quote\"name", "back\\slash", "-leading", os.fsdecode(b"non-utf8-\xff")]
        for i, name in enumerate(odd):
            self.write(work, name, bytes([i, 0, 255]) + b"\r\nraw\n")
        self.write(work, "run.sh", b"#!/bin/sh\nprintf hello\\n\n").chmod(0o755)
        (work / "nested").mkdir()
        (work / "plain-link").symlink_to("plain.txt")
        (work / "nested/relative-link").symlink_to("../plain.txt")
        self.git("add", "--all", cwd=work)
        self.write(work, os.fsdecode(b"untracked-\xfe"), b"raw untracked name\n")
        before = tree(work)
        checkpoint = self.checkpoint(store, info)
        _, restored = self.restore(store, checkpoint, base)
        self.equal(tree(restored), before, "Non-UTF8 names, symlinks, modes, or raw bytes changed")
        require(os.readlink(restored / "nested/relative-link") == "../plain.txt", "Relative symlink rewritten")
        require((restored / "run.sh").stat().st_mode & 0o111 == 0o111, "Executable bits lost")
        self.disjoint([work, restored])
        return {"strange_tracked_names": len(odd), "non_utf8_tracked_and_untracked": True,
                "internal_relative_symlinks": True, "executable_bits": True}

    def fail_closed_corruption(self):
        _, source, store, base = self.fixture("corruption")
        info, _ = self.init(store, source, base)
        variants = ["content", "missing-index", "manifest", "manifest-digest", "extra-file", "execute-bit",
                    "manifest-traversal-rehashed", "manifest-absolute-rehashed", "manifest-duplicate-rehashed"]
        for variant in variants:
            checkpoint = self.checkpoint(store, info)
            directory = store / "checkpoints" / checkpoint["checkpoint_id"]
            if variant == "content":
                (directory / "repo/plain.txt").write_bytes(b"tampered\n")
            elif variant == "missing-index":
                (directory / "repo/.git/index").unlink()
            elif variant == "manifest":
                with (directory / "manifest.json").open("ab") as stream:
                    stream.write(b"corrupted")
            elif variant == "manifest-digest":
                (directory / "manifest.sha256").write_text("0" * 64 + "\n")
            elif variant == "extra-file":
                (directory / "repo/unlisted.txt").write_bytes(b"not in inventory\n")
            elif variant.startswith("manifest-") and variant.endswith("-rehashed"):
                manifest = json.loads((directory / "manifest.json").read_bytes())
                if variant == "manifest-duplicate-rehashed":
                    manifest["entries"].append(dict(manifest["entries"][0]))
                else:
                    path = b"../escape" if variant == "manifest-traversal-rehashed" else b"/tmp/escape"
                    manifest["entries"][0]["path_base64"] = base64.b64encode(path).decode()
                encoded = json.dumps(manifest).encode()
                (directory / "manifest.json").write_bytes(encoded)
                (directory / "manifest.sha256").write_text(hashlib.sha256(encoded).hexdigest())
            else:
                (directory / "repo/plain.txt").chmod(0o755)
            self.rejected("restore", store, checkpoint["checkpoint_id"], "agent-no-publish", store=store)
        return {"corruption_variants": variants, "no_destination_published": True}

    def unsupported_sources(self):
        checked = []
        variants = ["git-file", "git-symlink", "alternates", "index-lock", "ref-lock",
                    "unsupported-config", "filter-config", "info-filter-attributes", "replacement-refs",
                    "split-index", "sparse-config", "fsmonitor-config",
                    "absolute-symlink", "escaping-symlink", "git-target-symlink",
                    "indirect-escape-symlink", "indirect-git-symlink", "wrong-base"]
        for variant in variants:
            root, source, store, base = self.fixture("reject-" + variant)
            if variant in ("git-file", "git-symlink"):
                moved = root / "relocated-git"
                (source / ".git").rename(moved)
                if variant == "git-file":
                    (source / ".git").write_text("gitdir: " + str(moved) + "\n")
                else:
                    (source / ".git").symlink_to(moved, target_is_directory=True)
            elif variant == "alternates":
                (root / "other-objects").mkdir()
                (source / ".git/objects/info/alternates").write_text(str(root / "other-objects") + "\n")
            elif variant in ("index-lock", "ref-lock"):
                target = ".git/index.lock" if variant == "index-lock" else ".git/refs/heads/main.lock"
                (source / target).write_bytes(b"active writer\n")
            elif variant == "unsupported-config":
                self.git("config", "core.hooksPath", str(root / "hooks"), cwd=source)
            elif variant == "filter-config":
                self.git("config", "filter.test.clean", "cat", cwd=source)
            elif variant == "info-filter-attributes":
                (source / ".git/info/attributes").write_bytes(b"*.txt filter=test\n")
            elif variant == "replacement-refs":
                self.git("update-ref", "refs/replace/" + base, base, cwd=source)
            elif variant == "split-index":
                self.git("update-index", "--split-index", cwd=source)
            elif variant == "sparse-config":
                self.git("config", "core.sparseCheckout", "true", cwd=source)
            elif variant == "fsmonitor-config":
                self.git("config", "core.fsmonitor", "true", cwd=source)
            elif variant == "absolute-symlink":
                (source / "bad-link").symlink_to(source / "plain.txt")
            elif variant == "escaping-symlink":
                (root / "outside.txt").write_bytes(b"outside\n")
                (source / "bad-link").symlink_to("../outside.txt")
            elif variant == "git-target-symlink":
                (source / "bad-link").symlink_to(".git/config")
            elif variant == "indirect-escape-symlink":
                (root / "outside.txt").write_bytes(b"outside\n")
                (source / "alias").symlink_to(".")
                (source / "bad-link").symlink_to("alias/../outside.txt")
            elif variant == "indirect-git-symlink":
                (source / "alias").symlink_to(".")
                (source / "bad-link").symlink_to("alias/.git/config")
            else:
                self.write(source, "plain.txt", b"HEAD moved\n")
                self.git("add", "plain.txt", cwd=source)
                self.git("commit", "-m", "not requested base", cwd=source)
            original = tree(source)
            self.rejected("init", store, source, "agent-rejected", base, "--quiescent", store=store)
            self.equal(tree(source), original, "Rejection modified source for " + variant)
            checked.append(variant)
        root = self.root / "bare-and-sha256"
        root.mkdir()
        bare = root / "bare.git"
        self.git("init", "--bare", bare)
        self.rejected("init", root / "bare-store", bare, "agent-rejected", "0" * 40, "--quiescent", store=root / "bare-store")
        sha = root / "sha256"
        self.git("init", "--object-format=sha256", "-b", "main", sha)
        self.write(sha, "plain.txt", b"sha256\n")
        self.git("add", "plain.txt", cwd=sha)
        self.git("commit", "-m", "sha256 fixture", cwd=sha)
        self.rejected("init", root / "sha-store", sha, "agent-rejected", self.oid(sha), "--quiescent", store=root / "sha-store")
        checked.extend(["bare-repository", "sha256-repository"])
        return {"rejected_sources": checked}

    def checkpoint_rejections_and_quiescence(self):
        _, source, store, base = self.fixture("checkpoint-reject")
        self.rejected("init", store, source, "agent-no-promise", base, store=store)
        info, work = self.init(store, source, base)
        self.rejected("checkpoint", store, info["workspace_id"], store=store, kind="checkpoints")
        (work / ".git/index.lock").write_bytes(b"active writer\n")
        self.rejected("checkpoint", store, info["workspace_id"], "--quiescent", store=store, kind="checkpoints")
        (work / ".git/index.lock").unlink()
        self.git("config", "filter.test.clean", "cat", cwd=work)
        self.rejected("checkpoint", store, info["workspace_id"], "--quiescent", store=store, kind="checkpoints")
        self.git("config", "--remove-section", "filter.test", cwd=work)
        (work / "bad-link").symlink_to("../outside")
        self.rejected("checkpoint", store, info["workspace_id"], "--quiescent", store=store, kind="checkpoints")
        (work / "bad-link").unlink()
        checkpoint = self.checkpoint(store, info)
        self.restore(store, checkpoint, base)
        return {"explicit_quiescence_required": True, "active_lock_rejected": True,
                "unsupported_mutated_config_rejected": True, "unsafe_mutated_symlink_rejected": True}

    def overlapping_store_leaves_source_untouched(self):
        _, source, _, base = self.fixture("overlap")
        original = tree(source)
        nested = source / "private-store"
        self.rejected("init", nested, source, "agent-overlap", base, "--quiescent", store=nested)
        self.equal(tree(source), original, "Rejected overlapping store modified source")
        require(not nested.exists(), "Rejected overlap created empty directories inside source")
        return {"nested_store_rejected_before_any_source_mutation": True}

    def unsupported_native_indexes(self):
        checked = []
        for variant in ("sparse-index", "fsmonitor-index"):
            _, source, store, base = self.fixture(variant, {
                "visible/file.txt": b"visible\n", "excluded/file.txt": b"excluded\n",
            })
            config = (source / ".git/config").read_bytes()
            if variant == "sparse-index":
                self.git("sparse-checkout", "init", "--cone", "--sparse-index", cwd=source)
                self.git("sparse-checkout", "set", "visible", cwd=source)
                listing = self.git("ls-files", "--sparse", "--stage", cwd=source).stdout
                require(b"040000 " in listing, "Fixture did not create a real sparse directory index entry")
                require(b"sdir" in (source / ".git/index").read_bytes(), "Sparse index extension missing")
                # Remove setup configuration, leaving the native index as the
                # reason for rejection rather than merely an unknown config key.
                (source / ".git/config").write_bytes(config)
                (source / ".git/config.worktree").unlink(missing_ok=True)
            else:
                self.git("-c", "core.fsmonitor=true", "update-index", "--fsmonitor", cwd=source)
                require(b"FSMN" in (source / ".git/index").read_bytes(), "Native fsmonitor index extension missing")
                require((source / ".git/config").read_bytes() == config,
                        "Fsmonitor fixture unexpectedly persisted unsupported config")
            original = tree(source)
            self.rejected("init", store, source, "agent-index-rejected", base, "--quiescent", store=store)
            self.equal(tree(source), original, "Index rejection changed source")
            checked.append(variant)
        return {"native_git_generated_indexes_rejected": checked,
                "unsupported_config_removed_before_validation": True}

    def recorded_git_version_mismatch(self):
        root, source, store, base = self.fixture("version-mismatch")
        info, _ = self.init(store, source, base)
        checkpoint = self.checkpoint(store, info)
        manifest = json.loads((store / "checkpoints" / checkpoint["checkpoint_id"] / "manifest.json").read_bytes())
        require(manifest["workspace"]["git_version"] == self.git_version,
                "Checkpoint did not record the exact native Git version")
        wrapper = root / "git-version-test-wrapper"
        wrapper.write_text(
            "#!/bin/sh\n"
            "for argument in \"$@\"; do\n"
            "  if [ \"$argument\" = \"--version\" ]; then\n"
            "    printf '%s\\n' 'git version 2.99.123.workspace-test'\n"
            "    exit 0\n"
            "  fi\n"
            "done\n"
            "exec " + shlex.quote(self.git_binary) + " \"$@\"\n"
        )
        wrapper.chmod(0o700)
        env = dict(self.env, ROOTYARD_WORKSPACE_GIT=str(wrapper))
        self.rejected("restore", store, checkpoint["checkpoint_id"], "agent-wrong-version", store=store, env=env)
        self.restore(store, checkpoint, base, "agent-matching-version")
        return {"exact_version_recorded": self.git_version,
                "synthetic_version_mismatch_rejected_without_publication": True,
                "matching_version_still_restores": True}

    def publication_failpoints(self):
        _, source, store, base = self.fixture("publication")
        info, work = self.init(store, source, base)
        good = self.checkpoint(store, info)
        original = tree(work)
        self.write(work, "plain.txt", b"new checkpoint content\n")
        updated = tree(work)
        before = self.published(store, "checkpoints")
        env = dict(self.env, ROOTYARD_WORKSPACE_TEST_FAILPOINT="before_publish")
        self.lab("checkpoint", store, info["workspace_id"], "--quiescent", env=env, expected=86)
        require(self.published(store, "checkpoints") == before, "Pre-publication interruption exposed a checkpoint")
        _, restored = self.restore(store, good, base, "agent-after-before-fault")
        self.equal(tree(restored), original, "Earlier checkpoint lost after pre-publication interruption")
        env = dict(self.env, ROOTYARD_WORKSPACE_TEST_FAILPOINT="after_publish")
        self.lab("checkpoint", store, info["workspace_id"], "--quiescent", env=env, expected=87)
        added = self.published(store, "checkpoints") - before
        require(len(added) == 1, "Post-publication interruption did not leave exactly one complete checkpoint")
        _, restored = self.restore(store, added.pop(), base, "agent-after-publish-fault")
        self.equal(tree(restored), updated, "Published checkpoint failed verification after process exit")
        _, earlier = self.restore(store, good, base, "agent-earlier-still-valid")
        self.equal(tree(earlier), original, "Earlier checkpoint lost after post-publication interruption")
        self.checkpoint(store, info)
        return {"before_publish_exit": 86, "after_publish_exit": 87,
                "earlier_checkpoint_restorable": True, "later_checkpoint_operation_succeeds": True}

    def external_git_config_isolation(self):
        root, source, store, base = self.fixture("external-config")
        external = root / "invalid-external-config"
        external.write_text("[not valid Git config\n")
        env = dict(self.env, GIT_CONFIG_GLOBAL=str(external), GIT_CONFIG_SYSTEM=str(external),
                   GIT_CONFIG_NOSYSTEM="0", GIT_CONFIG_COUNT="1",
                   GIT_CONFIG_KEY_0="core.worktree", GIT_CONFIG_VALUE_0=str(root / "wrong-worktree"),
                   GIT_DIR=str(root / "wrong-git"), GIT_WORK_TREE=str(root / "wrong-tree"),
                   GIT_INDEX_FILE=str(root / "wrong-index"))
        original = tree(source)
        info, work = self.init(store, source, base, env=env)
        self.equal(tree(work), original, "External Git environment changed imported data")
        checkpoint = self.checkpoint(store, info)
        restored = self.data("restore", store, checkpoint["checkpoint_id"], "agent-clean-env", env=env)
        path = self.workspace(restored, store, base, "agent-clean-env", checkpoint["checkpoint_id"])
        self.equal(tree(path), original, "External Git environment changed restored data")
        return {"system_global_and_command_config_ignored": True, "external_git_paths_ignored": True}

    def safe_config_and_raw_eol(self):
        _, source, store, _ = self.fixture("safe-config")
        for key, value in [("core.autocrlf", "true"), ("core.eol", "crlf"),
                           ("core.ignorecase", "false"), ("core.precomposeunicode", "false"),
                           ("user.name", "Safe Fixture User"), ("user.email", "safe@example.invalid")]:
            self.git("config", key, value, cwd=source)
        self.write(source, ".gitattributes", b"*.txt text\n")
        self.write(source, "crlf.txt", b"one\r\ntwo\r\n")
        self.git("add", ".gitattributes", "crlf.txt", cwd=source)
        self.git("commit", "-m", "CRLF fixture", cwd=source)
        base = self.oid(source)
        info, work = self.init(store, source, base)
        self.write(work, "crlf.txt", b"raw\r\nraw\nunterminated")
        before = tree(work)
        checkpoint = self.checkpoint(store, info)
        _, restored = self.restore(store, checkpoint, base)
        self.equal(tree(restored), before, "EOL config caused checkout/filter normalization")
        return {"safe_local_config_accepted": True, "raw_worktree_eol_preserved": True}

    def status_and_rootyardignore(self):
        _, source, store, _ = self.fixture("status-rootyardignore", {
            ".gitignore": b"*.log\n",
            ".rootyardignore": b"# comment\n*.tmp\n!keep.tmp\nbuild/\n",
            "plain.txt": b"base\n",
        })
        self.git("add", "--all", cwd=source)
        self.git("commit", "--amend", "-m", "base with ignore files", cwd=source)
        base = self.oid(source)
        info, work = self.init(store, source, base)
        clean = self.data("status", store, info["workspace_id"])
        require(clean["clean"] is True and clean["is_dirty"] is False, "Expected clean workspace")
        self.write(work, "plain.txt", b"changed\n")
        self.write(work, "keep.tmp", b"negated\n")
        self.write(work, "drop.tmp", b"ignored by rootyardignore\n")
        self.write(work, "build/out.o", b"ignored dir\n")
        self.write(work, "app.log", b"ignored by gitignore\n")
        dirty = self.data("status", store, info["workspace_id"])
        require(dirty["is_dirty"] is True and dirty["clean"] is False, "Expected dirty workspace")
        require("keep.tmp" in dirty["untracked_paths"], "Negated .rootyardignore file missing")
        for ign in ("drop.tmp", "build/out.o", "app.log"):
            require(ign in dirty["ignored_paths"], f"Expected {ign} in ignored_paths")
        return {"dirty_entries": dirty["dirty_entries_count"], "ignored_entries": dirty["ignored_entries_count"]}

    def changeset_and_three_way_apply(self):
        _, source, store, base = self.fixture("changeset-three-way", {
            "plain.txt": b"base\n",
            "delete-me.txt": b"delete\n",
        })
        ws_a, repo_a = self.init(store, source, base, "agent-a")
        cp1 = self.checkpoint(store, ws_a)
        ws_b, repo_b = self.restore(store, cp1, base, "agent-b")
        self.write(repo_a, "plain.txt", b"modified\n")
        (repo_a / "delete-me.txt").unlink()
        self.write(repo_a, "added.txt", b"added\n")
        cp2 = self.checkpoint(store, ws_a)
        cs = self.data("changeset", store, cp1["checkpoint_id"], cp2["checkpoint_id"])
        require(cs["added"] == 1 and cs["modified"] == 1 and cs["deleted"] == 1, "Unexpected changeset counts")
        applied = self.data("apply", store, ws_b["workspace_id"], cs["changeset_id"], "--quiescent")
        require(applied["state"] == "applied" and applied["applied_entries"] == 3, "Changeset apply failed")
        self.equal(tree(repo_b), tree(repo_a), "Applied workspace differs from source")
        self.write(repo_b, "plain.txt", b"diverged\n")
        before_b = tree(repo_b)
        self.rejected("apply", store, ws_b["workspace_id"], cs["changeset_id"], "--quiescent")
        self.equal(tree(repo_b), before_b, "Conflicting apply mutated target")
        return {"changeset_applied": True, "conflict_rejected": True}

    def sync_dirty_incremental(self):
        _, source, store, base = self.fixture("sync-dirty-inc", {
            ".rootyardignore": b"*.scratch\n",
            "plain.txt": b"base\n",
        })
        self.git("add", "--all", cwd=source)
        self.git("commit", "--amend", "-m", "base", cwd=source)
        base = self.oid(source)
        ws_a, repo_a = self.init(store, source, base, "agent-a")
        cp1 = self.checkpoint(store, ws_a)
        ws_b, repo_b = self.restore(store, cp1, base, "agent-b")
        self.write(repo_a, "plain.txt", b"dirty change\n")
        self.write(repo_a, "new.txt", b"new managed\n")
        self.write(repo_a, "ignored.scratch", b"ignored scratch\n")
        res = self.data("sync-dirty", store, ws_a["workspace_id"], ws_b["workspace_id"], "--quiescent")
        require(res["state"] == "synced" and res["synced_entries"] == 2, "sync-dirty unexpected counts")
        require((repo_b / "plain.txt").read_bytes() == b"dirty change\n", "Dirty modification not synced")
        require((repo_b / "new.txt").read_bytes() == b"new managed\n", "Dirty addition not synced")
        require(not (repo_b / "ignored.scratch").exists(), "Ignored file leaked into target workspace")
        return {"synced_entries": res["synced_entries"], "excluded_ignored": res["excluded_ignored_entries"]}

    def verify_readonly_view(self):
        root, source, store, base = self.fixture("verify-ro-view", {"plain.txt": b"readonly\n"})
        ws, _ = self.init(store, source, base)
        cp = self.checkpoint(store, ws)
        view_path = root / "ro-view"
        rep = self.data("verify-readonly-view", store, cp["checkpoint_id"], view_path)
        require(rep["verified"] is True and rep["readonly"] is True, "Readonly view verification failed")
        require(((view_path / "plain.txt").stat().st_mode & 0o222) == 0, "Projected file is writable")
        (view_path / "plain.txt").chmod(0o644)
        self.rejected("verify-readonly-view", store, cp["checkpoint_id"], view_path)
        (view_path / "plain.txt").chmod(0o444)
        return {"readonly_verified": True, "writable_tamper_rejected": True}

    def run_all(self):
        require(self.binary.is_file() and os.access(self.binary, os.X_OK),
                "Build the opt-in rootyard-workspace-lab binary before running this harness")
        for method in [
            self.isolation_and_fixed_base, self.partial_staging_and_intent,
            self.hardlinks_and_detached_head, self.merge_conflict,
            self.ignore_and_head_union, self.deletion_and_rename, self.modes_links_and_byte_names,
            self.fail_closed_corruption, self.unsupported_sources,
            self.checkpoint_rejections_and_quiescence, self.overlapping_store_leaves_source_untouched,
            self.unsupported_native_indexes,
            self.preflight_rejections_before_store,
            self.recorded_git_version_mismatch, self.publication_failpoints,
            self.external_git_config_isolation, self.safe_config_and_raw_eol,
            self.status_and_rootyardignore, self.changeset_and_three_way_apply,
            self.sync_dirty_incremental, self.verify_readonly_view,
        ]:
            started = time.monotonic()
            entry = {"name": method.__name__, "ok": False}
            try:
                entry["detail"] = method()
                entry["ok"] = True
            except Exception as error:
                entry["error"] = str(error)
                entry["traceback"] = traceback.format_exc()
            entry["seconds"] = round(time.monotonic() - started, 3)
            self.checks.append(entry)
            print(("PASS " if entry["ok"] else "FAIL ") + entry["name"], flush=True)
            if not entry["ok"]:
                print(entry["error"], file=sys.stderr, flush=True)
        require(hashlib.sha256(self.binary.read_bytes()).hexdigest() == self.binary_sha256,
                "Binary changed while tests ran; rerun to bind results to one executable")

    def report(self):
        return {
            "suite": "local-workspace-prototype", "binary": str(self.binary),
            "binary_sha256": self.binary_sha256,
            "git_version": self.git_version, "checks": self.checks,
            "ok": bool(self.checks) and all(item["ok"] for item in self.checks),
            "limits": [
                "Disposable local SHA-1 Git repositories on this operating system only.",
                "Quiescence is a caller promise; no enforced write barrier is tested or claimed.",
                "Process-exit publication failpoints do not emulate kernel or power loss.",
                "No hostile multitenant isolation, remote persistence, cross-Git-version compatibility, or throughput claim.",
            ],
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard-workspace-lab")
    parser.add_argument("--report", default="test-results/workspaces.json")
    parser.add_argument("--keep", action="store_true", help="Retain disposable fixtures for debugging")
    args = parser.parse_args()
    harness = None
    try:
        harness = Harness(args)
        harness.run_all()
        report = harness.report()
    except Exception as error:
        report = harness.report() if harness else {"suite": "local-workspace-prototype", "checks": []}
        report.update({"ok": False, "setup_error": str(error)})
        print(str(error), file=sys.stderr)
    finally:
        if harness:
            if args.keep:
                print("Retained disposable fixtures: " + str(harness.root), file=sys.stderr)
            else:
                shutil.rmtree(harness.root)
    destination = Path(args.report)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    print(f"Report: {destination}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
