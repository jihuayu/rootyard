#!/usr/bin/env python3
"""Issue #4 matrix constants and the pre-execution checks of the direct-collaborator harness.

The matrix below is the product contract read from this checkout
(``git_http.rs``, ``browse/transactions.rs``, ``pulls/merge.rs``,
``pulls/rules.rs``, ``members/rbac.rs``, ``auth.rs``) for direct
``repository_collaborators`` roles only. Teams and organizations are covered
by ``tests/organizations.py`` and ``tests/members.py``.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
ZERO = "0" * 40
# CI installs Git 2.43; the plain clone/fetch/push matrix needs no newer Git.
MIN_GIT = (2, 39)
# Git is executed by: the harness client (``self.git``), the service client
# (``Config::from_env``: ROOTYARD_GIT or the first ``git`` on PATH, then
# canonicalized) and the managed hook (the running binary re-executed with
# ROOTYARD_GIT_PATH set to that same Config.git), so only exact binary/version
# equality is meaningful. The commands below are this module tree's own argv;
# anything the job runs elsewhere is reported by ``git_command_coverage``.
EXECUTED_GIT_COMMANDS = frozenset({
    "add", "checkout", "clone", "commit", "config", "fetch", "ls-remote", "merge-base",
    "push", "reset", "rev-parse", "status",
})
RECEIVE = "application/x-git-receive-pack-request"
RECEIVE_ENDPOINT = "/git-receive-pack"
# Fixture users. Their only route to alice/demo is a grant made through the
# owner API inside this run; the six in STAFF_USERS first act as owner of an
# API-created repository of their own, so a grant to alice/demo is not their
# only live permission.
FIXTURE_USERS = ("bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan",
                 "judy", "karl", "linda", "mona", "nina", "olga", "peggy", "quinn")
STAFF_USERS = ("erin", "frank", "grace", "heidi", "karl", "linda")
UPLOAD_REFS = "/info/refs?service=git-upload-pack"
RECEIVE_REFS = "/info/refs?service=git-receive-pack"
MANAGED_HOOKS = ("pre-receive", "reference-transaction", "post-receive")


def git_version(text):
    """Parse ``git version X.Y.Z``; unparsable output is a failure, never a skip."""
    words = str(text).split()
    assert len(words) >= 3 and words[0] == "git" and words[1] == "version", text
    try:
        numbers = tuple(int(part) for part in words[2].split(".")[:3])
    except ValueError as error:
        raise AssertionError("unparsable Git version " + repr(text)) from error
    assert len(numbers) == 3 and all(part >= 0 for part in numbers), text
    return numbers


def invoked_git_commands(path):
    """Subcommands ``path`` executes via ``self.git(...)`` or ``run(["git", ...])``.

    ``test_browse_git_read_steps.py`` declares its Git matrix statically because
    it controls every argument; this harness routes calls through a helper, so
    the declaration is derived from the helper and case modules (see
    ``git_command_coverage``).
    """
    found = set()
    for node in ast.walk(ast.parse(Path(path).read_text())):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr == "git":
            if node.args and isinstance(node.args[0], ast.Constant):
                found.add(node.args[0].value)
        elif (node.func.attr == "run" and node.args
              and isinstance(node.args[0], ast.List)):
            argv = [item.value for item in node.args[0].elts if isinstance(item, ast.Constant)]
            if "git" in argv:
                tail = argv[argv.index("git") + 1:]
                while tail and tail[0].startswith("-"):
                    tail = tail[2:] if tail[0] == "-c" else tail[1:]
                if tail:
                    found.add(tail[0])
    return found


def sha256_file(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


class prerequisite:
    """Resolve the executed Git and binary inputs before any owned process starts."""

    def server_git(self):
        """Resolve the server client exactly like Config::from_env (ROOTYARD_GIT, else PATH)."""
        configured = self.env.get("ROOTYARD_GIT")
        if configured:
            return str(Path(configured).resolve())
        found = os.environ.get("PATH", os.defpath).split(os.pathsep)
        for entry in found:
            if entry and (Path(entry) / "git").is_file():
                return str((Path(entry) / "git").resolve())
        raise AssertionError("required dependency missing: no git executable on server PATH")

    def hook_git(self):
        """The managed hook receives Config.git as ROOTYARD_GIT_PATH (see git_http.rs)."""
        return self.server_git()

    def git_matrix_version(self):
        # Resolve one Git for the harness, the server and the managed hook
        # before any owned process exists, so every process below runs exactly
        # the binary this case measured. The hook is a copy of this binary
        # (reliability::install_hooks) re-executed with ROOTYARD_GIT_PATH.
        executable = self.server_git()
        assert self.hook_git() == executable, (executable, self.hook_git())
        raw = {label: self.run([executable, "--version"]).stdout.decode().strip()
               for label in ("harness", "server", "hook")}
        assert len(set(raw.values())) == 1, raw
        version = git_version(raw["harness"])
        assert version >= MIN_GIT, (
            f"required Git >= {'.'.join(map(str, MIN_GIT))}; resolved {raw['harness']!r}")
        git_sha = sha256_file(executable)
        assert self.hook_binary_sha() == git_sha
        return {"versions": {k: ".".join(map(str, version)) for k in raw},
                "resolved": {"harness": executable, "server": executable, "hook": executable},
                "git_sha256": git_sha, "harness_sha256": sha256_file(__file__)}

    def hook_binary_sha(self):
        """SHA-256 of the executable Git HTTP re-executes for the managed hook."""
        return sha256_file(self.server_git())

    def git_command_coverage(self):
        """The commands this harness runs, and whether the CI job runs them elsewhere."""
        import e2e
        import members
        import reliability
        modules = [Path(item) for item in getattr(self, "case_module_files", ())]
        assert modules, "required dependency missing: case modules are not registered"
        own = set(EXECUTED_GIT_COMMANDS) & set().union(*(invoked_git_commands(p) for p in modules))
        found = set().union(*(invoked_git_commands(p) for p in modules))
        assert found == set(EXECUTED_GIT_COMMANDS), sorted(found ^ set(EXECUTED_GIT_COMMANDS))
        elsewhere = set()
        for module in (e2e, reliability, members):
            elsewhere |= invoked_git_commands(Path(module.__file__))
        return {"executed_git_commands": sorted(own), "unique_commands": len(own),
                "modules": [p.name for p in modules],
                "upstream_commands": sorted(own & elsewhere),
                "not_run_by_upstream_suites": sorted(own - elsewhere)}

    def native_executed_by_implementer(self):
        """Truthful attribution: a self-run service in implement-forbidden environments is not native evidence."""
        if os.environ.get("ROOTYARD_NATIVE_EXECUTED_BY_IMPLEMENTER", "").strip().lower() == "true":
            return True
        return {"sys.platform": sys.platform, "machine": os.uname().machine}

    def checkout_head(self, root, env, shared):
        """HEAD of the mounted checkout, discovered the way Git itself would.

        Plain discovery honours the checkout's ``.git`` file (a run sandbox may
        point it at a headless git dir). If that fails, the shared git dir the
        rules mount is tried as ``GIT_DIR``. A success that Git itself marks
        dubious (``warning:`` on stderr) is refused rather than reported as
        this worktree's HEAD.
        """
        strategies = {"discovery": {}}
        try:
            pointer = (Path(root) / ".git").read_text().strip()
        except OSError:
            pointer = ""
        linked = pointer.startswith("gitdir:")
        if linked:
            strategies["linked worktree " + pointer.split(":", 1)[1].strip()] = {}
            if Path(shared).is_dir():
                strategies["shared " + shared] = {"GIT_DIR": shared, "GIT_WORK_TREE": str(root)}
        tried = []
        for label, extra in strategies.items():
            proc = self.git("rev-parse", "HEAD", cwd=root, check=False, env={**env, **extra})
            if proc.returncode:
                tried.append(label + ": " + proc.stderr.decode(errors="replace").strip()[-160:])
                continue
            assert not proc.stderr.strip(), (
                f"{label} resolved HEAD {proc.stdout.decode().strip()} with a warning: " +
                proc.stderr.decode(errors="replace").strip()[-300:])
            # When GIT_DIR is set Git stops searching for the work tree and
            # rev-parse runs in a bare-style repository; pin it to this source.
            if extra:
                extra = {**extra, "GIT_WORK_TREE": str(root)}
            return proc.stdout.decode().strip(), {**env, **extra}, label
        raise AssertionError("required dependency missing: checkout HEAD unreachable (" +
                             "; ".join(tried) + ")")

    def source_binding(self):
        """Bind the executed binary to the current production inputs via its build receipt."""
        root = Path(__file__).resolve().parents[1]
        receipt_path = Path(self.args.binary).with_suffix(".build.json")
        assert receipt_path.is_file(), (
            "required dependency missing: no scripts/build_native.py receipt beside "
            + str(self.args.binary))
        receipt = json.loads(receipt_path.read_text())
        binary_sha = sha256_file(self.args.binary)
        assert receipt.get("binary_sha256") == binary_sha, "executed binary differs from its receipt"
        if str(PACKAGE_ROOT / "scripts") not in sys.path:
            sys.path.insert(0, str(PACKAGE_ROOT / "scripts"))
        import build_native  # scripts/ is not a package; same digest function as the build
        current = build_native.source_digest()
        assert current == receipt["source_inputs_sha256"], (
            "current src/Cargo/migrations/schema/vendor inputs differ from the binary's build")
        checkout_env = dict(self.env, GIT_OPTIONAL_LOCKS="0")
        # First: is the mounted .git really this checkout's? rev-parse can walk
        # into a repository through cwd even when GIT_DIR names nothing, so a
        # lookup must not count as evidence until --git-common-dir agrees.
        probe = self.git("rev-parse", "--git-common-dir", cwd=root, check=False, env=checkout_env)
        shared = probe.stdout.decode().strip() if probe.returncode == 0 else ""
        if shared and not shared.startswith("/"):
            shared = str((root / shared).resolve())
        if not shared or not Path(shared).is_dir():
            raise AssertionError("required dependency missing: mount the shared .git dir (" +
                                 (probe.stderr.decode(errors="replace").strip()[-200:] or
                                  shared or "no git metadata"))
        assert probe.stderr.decode().strip() == "", (
            "checkout metadata reported: " + probe.stderr.decode(errors="replace").strip()[-300:])
        head, checkout_env, discovered_via = self.checkout_head(root, checkout_env, shared)
        tracked = self.git("status", "--porcelain", "--untracked-files=no", cwd=root,
                           env=checkout_env).stdout
        assert not tracked.strip(), "tracked inputs are dirty: console builds embed differing debug paths"
        parent = receipt["workspace_commit"]
        assert self.git("merge-base", "--is-ancestor", parent, head, cwd=root,
                        check=False, env=checkout_env).returncode == 0, (
            f"binary source commit {parent} is not an ancestor of HEAD {head}")
        return {"source_commit": head, "checkout_discovered_via": discovered_via,
                "binary_source_commit": parent,
                "binary_commit_is_ancestor": True,
                "source_inputs_sha256": current, "binary_sha256": binary_sha,
                "rustc": receipt.get("rustc"), "build_command": receipt.get("command"),
                "harness": {"file": str(Path(__file__).relative_to(root)),
                            "sha256": sha256_file(Path(__file__)),
                            "modules": [str(p.relative_to(root)) for p in
                                        getattr(self, "case_module_files", ())]},
                "identity": "owned schema " + self.schema}
