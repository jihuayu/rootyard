#!/usr/bin/env python3
"""Offline contract checks for tests/collaborator_transport.py (issue #4 harness).

These checks need no binary, database or network: they prove the harness
declares the Git commands it runs, parses Git versions fail-closed, and that its
required cases are registered. They are a focused oracle, not native evidence.
"""
import ast
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
    "rule_refusals", "owner_only_management", "pull_merge_under_rule", "withdrawal",
    "audit_boundary", "token_revocation",
)


class GitMatrixContract(unittest.TestCase):
    def test_declared_git_commands_are_exactly_the_ones_invoked(self):
        ours = harness.invoked_git_commands(Path(harness.__file__))
        self.assertEqual(ours, set(harness.EXECUTED_GIT_COMMANDS))
        self.assertGreaterEqual(harness.git_version("git version 2.43.0"), harness.MIN_GIT)

    def test_declared_commands_are_run_by_this_harness_or_upstream_suites(self):
        ours = harness.invoked_git_commands(Path(harness.__file__))
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


class HarnessContract(unittest.TestCase):
    def test_harness_parses_without_import_side_effects(self):
        tree = ast.parse(Path(harness.__file__).read_text())
        self.assertTrue(any(isinstance(node, ast.ClassDef)
                            and node.name == "CollaboratorTransportHarness" for node in tree.body))

    def test_every_required_case_is_a_method_and_registered(self):
        source = Path(harness.__file__).read_text()
        for name in CASE_METHODS:
            self.assertIn(f"def {name}(self)", source, name)
            self.assertIn(f'h.case("', source)
        registered = [line.split('"')[1] for line in source.splitlines()
                      if line.strip().startswith("h.case(")]
        self.assertEqual(len(registered), len(set(registered)), "duplicate case registration")
        self.assertEqual(len(registered), 18, registered)

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
