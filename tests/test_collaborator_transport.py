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
        self.assertIn('"harness": self.server_git()', body)
        self.assertIn("len(set(triple.values())) == 1", body)
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

    def test_initialization_and_merge_contracts_are_fixed(self):
        merge_source = (ROOT / "tests" / "collaborator_writes.py").read_text()
        merge = merge_source[merge_source.index("    def pull_lifecycle(self):"):
                             merge_source.index("    def rule_refusals(self):")]
        first = merge.index('status, raw, _ = self.http(merge, token=self.users[user]')
        replay = merge.index("replay = self.expect(")
        self.assertLess(first, replay)
        self.assertIn('key = {"Idempotency-Key": "merge-" + user}', merge)
        self.assertIn("extra_headers=key", merge[first:replay], "first merge must carry the key")
        self.assertIn("assert replay == raw", merge)
        writes = (ROOT / "tests" / "collaborator_writes.py").read_text()
        maintain = writes[writes.index("    def maintain_rule_matrix(self):"):
                          writes.index("    def admin_management(self):")]
        self.assertNotIn("assert status == 403", maintain, "Role::Maintain may write rules")
        admin = writes[writes.index("    def admin_management(self):"):
                       writes.index("    def pull_merge_under_rule(self):")]
        self.assertNotIn("assert status == 403", admin,
                         "Role::Admin manages collaborators; only the owner row is refused")
        self.assertIn(b"cannot modify or remove repository owner".decode(), admin)
        managed = writes[writes.index("    def pull_merge_under_rule(self):"):
                         writes.index("    def audit_boundary(self):")]
        self.assertIn('("refs/heads/maint-base", True)', managed,
                      "the merge-under-rule case must use a rule an earlier case created")
        audit = writes[writes.index("    def audit_boundary(self):"):]
        # Demo-scoped receipts only (owner API for demo), never a schema-wide
        # count compared with repository-scoped events.
        self.assertIn('self.expect("/api/repos/alice/demo/events", 200', audit)
        self.assertNotIn("SELECT count(*) FROM outbox_events", audit)

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
