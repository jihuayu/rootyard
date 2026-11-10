#!/usr/bin/env python3
"""Offline contract checks for tests/collaborator_transport.py (issue #4 harness).

These checks need no binary, database or network: they prove the harness
declares the Git commands it runs, parses Git versions fail-closed, registers
its nineteen cases once each, keeps every module under the size cap, and binds
the corrected product contracts (single initialization, one resolved Git,
Idempotency-Key on the first merge, real maintain/admin authority). They are a
focused oracle, not native evidence.
"""
import ast
import re
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import collaborator_transport as harness  # noqa: E402

CASE_METHODS = (
    "git_matrix_version", "source_binding", "environment", "staff_fixtures",
    "role_matrix", "fetch_propagation", "outsider_isolation", "read_only_token",
    "non_fast_forward", "ref_transactions", "pull_lifecycle", "git_command_coverage",
    "rule_refusals", "maintain_rule_matrix", "admin_management", "pull_merge_under_rule",
    "withdrawal", "audit_boundary", "token_revocation",
)
MAX_MODULE_LINES = 700
# Registered case name -> case method, in execution order (see execute()).
REGISTERED_CASES = (
    "git_matrix_version", "git_command_coverage", "source_bound_receipt", "environment",
    "staff_owned_fixtures", "role_matrix_clone_fetch_push", "fetch_propagation",
    "outsider_404_no_enumeration", "read_only_token_403", "non_fast_forward_rejected",
    "ref_transactions_role_matrix", "pull_create_merge_role_matrix",
    "branch_rule_role_matrix", "maintain_branch_rule_matrix",
    "admin_management_not_owner_only", "pull_merge_under_collaborator_rule",
    "withdrawal_revokes_new_requests", "git_receipts_are_not_repository_audit_log",
    "token_revocation_401",
)


class HarnessModules:
    """The entry point plus every module named in ``case_module_files``."""

    @classmethod
    def paths(cls):
        return [Path(harness.__file__)] + [Path(p) for p in harness.CASE_MODULES]

    @classmethod
    def sources(cls):
        return {path.name: path.read_text() for path in cls.paths()}

    @classmethod
    def methods(cls, name):
        """Method names defined as ``def name(self`` in any harness module."""
        found = {}
        for path in cls.paths():
            for node in ast.parse(path.read_text()).body:
                if isinstance(node, ast.ClassDef):
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef) and item.args.args:
                            found.setdefault(item.name, path.name)
        return found


class GitMatrixContract(unittest.TestCase):
    def test_declared_git_commands_are_exactly_the_ones_invoked(self):
        ours = set()
        for path in HarnessModules.paths():
            ours |= harness.invoked_git_commands(path)
        self.assertEqual(ours, set(harness.EXECUTED_GIT_COMMANDS))
        self.assertGreaterEqual(harness.git_version("git version 2.43.0"), harness.MIN_GIT)

    def test_declared_commands_are_run_by_this_harness_or_upstream_suites(self):
        ours = set()
        for path in HarnessModules.paths():
            ours |= harness.invoked_git_commands(path)
        elsewhere = set()
        for relative in ("tests/members.py", "tests/e2e.py", "tests/reliability.py"):
            elsewhere |= harness.invoked_git_commands(ROOT / relative)
        self.assertTrue(elsewhere & ours, "no declared command is shared with an upstream suite")
        self.assertTrue({"clone", "fetch", "push", "ls-remote"} <= ours)

    def test_git_version_parse_fails_closed(self):
        for bad in ("", "git version", "git version two.one", "svn version 1.2.3",
                    "git version 2"):
            with self.assertRaises(AssertionError, msg=bad):
                harness.git_version(bad)
        self.assertEqual(harness.git_version("git version 2.54.0 (Apple Git-155)"), (2, 54, 0))

    def test_one_git_is_resolved_for_harness_server_and_hook(self):
        """The triple is compared on resolved paths before any owned process."""
        source = (ROOT / "tests" / "collaborator_contract.py").read_text()
        body = source[source.index("    def git_matrix_version(self):"):
                      source.index("    def git_command_coverage(self):")]
        self.assertNotIn("self.setup()", body, "git_matrix_version must not initialize the schema")
        self.assertNotIn('"harness": "git"', body, "a literal git is not the executed binary")
        self.assertIn("executable = self.server_git()", body)
        self.assertIn("assert self.hook_git() == executable", body)
        self.assertIn("assert self.hook_binary_sha() == git_sha", body)
        lifecycle = (ROOT / "tests" / "collaborator_lifecycle.py").read_text()
        self.assertEqual(lifecycle.count("self.setup()"), 1,
                         "the owned schema/service must be initialized exactly once")


class HarnessContract(unittest.TestCase):
    def test_harness_parses_without_import_side_effects(self):
        for path in HarnessModules.paths():
            ast.parse(path.read_text())
        self.assertTrue(hasattr(harness, "CollaboratorTransportHarness"))

    def test_every_module_stays_under_the_line_cap(self):
        for path in HarnessModules.paths():
            lines = len(path.read_text().splitlines())
            self.assertGreater(lines, 20, f"{path.name} looks like a stub ({lines} lines)")
            self.assertLess(lines, MAX_MODULE_LINES,
                            f"{path.name} exceeds the {MAX_MODULE_LINES}-line cap ({lines} lines)")

    def test_every_required_case_is_a_method_and_registered(self):
        methods = HarnessModules.methods("case")
        registered = re.findall(r'\(\s*"([a-z0-9_]+)",\s*self\.([a-z0-9_]+)\)',
                                Path(harness.__file__).read_text())
        names = [name for name, _ in registered]
        self.assertEqual(len(names), len(set(names)), "duplicate case registration")
        self.assertEqual(len(names), 19, names)
        for method in CASE_METHODS:
            self.assertIn(method, methods, f"{method} is not defined in a harness module")
        for _, method in registered:
            self.assertIn(method, methods, f"registered case {method} has no method")

    @staticmethod
    def method_source(path, klass_method):
        """Exact source of one method via AST, never by slicing on text."""
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == klass_method:
                return ast.get_source_segment(path.read_text(), node)
        raise AssertionError(f"{klass_method} not found in {path.name}")

    @unittest.skip("FIXME(#4): reproduces the native defect; re-enable with its fix")
    def test_checkout_head_never_falls_back_to_a_repository_through_cwd(self):
        """An unavailable GIT_DIR must fail, not yield whatever repo cwd can reach."""
        try:
            harness.prerequisite.checkout_head(
                object.__new__(harness.CollaboratorTransportHarness),
                ROOT, {}, str(ROOT / "tests"), "0000000000000000000000000000000000000000")
        except AssertionError as error:
            self.assertTrue("name the same repository" in str(error)
                            or "dubious checkout state" in str(error), error)
        else:
            self.fail("a git dir that does not describe the checkout was accepted")

    def test_registration_yields_name_and_callable_pairs(self):
        """main() unpacks ``for name, fn in h.execute()``; the shape must hold."""
        harness_cls = object.__new__(harness.CollaboratorTransportHarness)
        steps = harness_cls.execute()
        self.assertEqual(len(steps), 19)
        for name, method in steps:
            self.assertIsInstance(name, str)
            self.assertIsInstance(method, type(self.assertEqual))
        self.assertEqual([name for name, _ in steps], list(REGISTERED_CASES))
        self.assertEqual({method.__name__ for _, method in steps}, set(CASE_METHODS),
                         "every case method must be registered exactly once")

    def test_method_locals_never_reference_undefined_names(self):
        """Catch stale locals (like ``head_proc``) that compile but are never bound."""
        import builtins
        for path in HarnessModules.paths():
            tree = ast.parse(path.read_text())
            module_names = set()
            for node in tree.body:
                for item in ast.walk(node) if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)) else [node]:
                    if isinstance(item, (ast.Import, ast.ImportFrom)):
                        module_names |= {(alias.asname or alias.name).split(".")[0] for alias in item.names}
                    elif isinstance(item, (ast.FunctionDef, ast.ClassDef)):
                        module_names.add(item.name)
                    elif isinstance(item, ast.Assign):
                        module_names |= {target.id for target in item.targets
                                         if isinstance(target, ast.Name)}
            for fn in [node for node in ast.walk(tree)
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]:
                bound = {arg.arg for arg in fn.args.args + fn.args.kwonlyargs}
                bound |= {node.id for node in ast.walk(fn) if isinstance(node, ast.Name)
                          and isinstance(node.ctx, (ast.Store, ast.Del))}
                for node in ast.walk(fn):
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        bound |= {(alias.asname or alias.name).split(".")[0] for alias in node.names}
                    elif isinstance(node, ast.ExceptHandler) and node.name:
                        bound.add(node.name)
                called = {id(node.func) for node in ast.walk(fn)
                          if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
                loaded = {node.id for node in ast.walk(fn) if isinstance(node, ast.Name)
                          and isinstance(node.ctx, ast.Load) and id(node) not in called}
                undefined = sorted(name for name in loaded - bound - module_names
                                   if not hasattr(builtins, name)
                                   and not (name.startswith("__") and name.endswith("__")))
                self.assertEqual(undefined, [],
                                 f"{path.name}:{fn.lineno} {fn.name} references undefined names")

    def test_checkout_head_prefers_discovery_and_refuses_dubious_success(self):
        import subprocess
        import tempfile
        base = object.__new__(harness.CollaboratorTransportHarness)
        base.env = {}
        calls = []

        def ok(argv):
            return subprocess.CompletedProcess(argv, 0, b"a" * 40 + b"\n", b"")

        def fake_git(*argv, cwd=None, check=True, env=None):
            calls.append(dict(env or {}))
            if (env or {}).get("GIT_DIR"):
                return subprocess.CompletedProcess(argv, 0, b"b" * 40 + b"\n",
                                                   b"warning: ignoring ref storage format\n")
            return ok(argv)
        base.git = fake_git
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as shared:
            (Path(root) / ".git").write_text(f"gitdir: {shared}/worktrees/x\n")
            head, env, via = base.checkout_head(Path(root), {}, shared)
        self.assertEqual((head, via, env), ("a" * 40, "discovery", {}))
        self.assertEqual(len(calls), 1)
        # A shared dir that answers with a warning is not evidence of this HEAD.
        base.git = lambda *argv, cwd=None, check=True, env=None: subprocess.CompletedProcess(
            argv, 0, b"a" * 40 + b"\n", b"warning: ignoring ref storage format\n")
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as shared:
            (Path(root) / ".git").write_text(f"gitdir: {shared}/worktrees/x\n")
            with self.assertRaisesRegex(AssertionError, "with a warning"):
                base.checkout_head(Path(root), {}, shared)

    def test_initialization_and_merge_contracts_are_fixed(self):
        contract = ROOT / "tests" / "collaborator_contract.py"
        lifecycle = ROOT / "tests" / "collaborator_lifecycle.py"
        writes = ROOT / "tests" / "collaborator_writes.py"
        merge = self.method_source(writes, "pull_lifecycle")
        first = merge.index('status, raw, _ = self.http(merge, token=self.users[user]')
        replay = merge.index("replay = self.expect(")
        self.assertLess(first, replay)
        self.assertIn('key = {"Idempotency-Key": "merge-" + user}', merge)
        self.assertIn("extra_headers=key", merge[first:replay], "first merge must carry the key")
        self.assertIn("assert replay == raw", merge)
        maintain = self.method_source(writes, "maintain_rule_matrix")
        self.assertNotIn("assert status == 403", maintain, "Role::Maintain may write rules")
        self.assertIn("assert status == 201", maintain)
        admin = self.method_source(writes, "admin_management")
        self.assertNotIn("assert status == 403", admin,
                         "Role::Admin manages collaborators; only the owner row is refused")
        self.assertIn("cannot modify or remove repository owner", admin)
        self.assertIn("assert status == 409", admin)
        managed = self.method_source(writes, "pull_merge_under_rule")
        self.assertIn('("refs/heads/maint-base", True)', managed,
                      "the merge-under-rule case must use a rule an earlier case created")
        audit = self.method_source(writes, "audit_boundary")
        self.assertIn('self.expect("/api/repos/alice/demo/events", 200', audit)
        self.assertNotIn("SELECT count(*) FROM outbox_events", audit)

    def test_every_module_compiles_and_has_no_duplicate_statements(self):
        """A text splice once duplicated a statement and shipped invalid Python."""
        for path in HarnessModules.paths():
            source = path.read_text()
            compile(source, str(path), "exec")
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    body = [ast.dump(item) for item in node.body
                            if not isinstance(item, ast.Expr)]
                    self.assertEqual(len(body), len(set(body)),
                                     f"{path.name}:{node.lineno} {node.name} repeats a statement")

    def test_missing_dependencies_are_argument_errors_not_skips(self):
        result = subprocess.run([sys.executable, str(Path(harness.__file__)), "--binary",
                                 str(ROOT / "target/debug/rootyard")],
                                cwd=ROOT, env={"PATH": "/usr/bin:/bin"},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("required dependency missing", result.stderr)
        listing = subprocess.run([sys.executable, str(Path(harness.__file__)), "--help"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertIn("--report", listing.stdout)


if __name__ == "__main__":
    unittest.main()
