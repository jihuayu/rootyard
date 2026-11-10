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
# equality is meaningful. The commands below are the case modules' own argv,
# discovered with ``invoked_git_commands``; binary/version checks run elsewhere
# are reported by ``git_command_coverage``.
EXECUTED_GIT_COMMANDS = frozenset({
    "add", "checkout", "clone", "commit", "config", "fetch", "ls-remote",
    "push", "reset", "rev-list", "rev-parse",
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

    def source_binding(self):
        """Bind the executed binary to the current production inputs via its build receipt.

        ``tests/source_bound_binary.py`` compares the receipt's production input
        digest with ``scripts/build_native.source_digest()`` and the receipt with
        the binary, and records the receipt's source commit next to the current
        HEAD. An ancestor relation between them is deliberately not required: the
        baseline is built just before the checkout's own tests-only commits, and
        identical production bytes are the binding that matters.
        """
        from source_bound_binary import SourceBindingError, bind
        env = getattr(self, "env", {})
        environ = {name: env[name] for name in ("ROOTYARD_EXPECTED_SOURCE_COMMIT",) if name in env}
        try:
            evidence = bind(self.args.binary, environ=environ)
        except SourceBindingError as error:
            raise AssertionError("required dependency missing: source binding failed: " + str(error))
        assert evidence["source_inputs_sha256"] == evidence["current_source_inputs_sha256"]
        assert not evidence["current_head_production_dirty"], (
            "production inputs differ from HEAD: " + ", ".join(evidence["current_head_production_dirty"]))
        return {"source_commit": evidence["current_head"],
                "binary_source_commit": evidence["workspace_commit"],
                "source_inputs_sha256": evidence["source_inputs_sha256"],
                "binary_sha256": evidence["binary_sha256"],
                "rustc": evidence["receipt_toolchain"]["rustc"],
                "build_command": evidence["receipt_toolchain"]["command"],
                "harness": {"file": str(Path(__file__).relative_to(PACKAGE_ROOT)),
                            "sha256": sha256_file(Path(__file__)),
                            "modules": [str(Path(p).relative_to(PACKAGE_ROOT)) for p in
                                        getattr(self, "case_module_files", ())]},
                "identity": "owned e2e schema"}
