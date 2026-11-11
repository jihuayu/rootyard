#!/usr/bin/env python3
"""Focused #18 oracle for the mixed protected/unprotected atomic push cases.

Offline only: no binary, PostgreSQL, Git or Cargo is executed here. These pin
the exact native case IDs, the pure ``--porcelain`` refusal parser, the wiring
that keeps the native cases isolated in policy state, keeps the native-CAS and
policy proofs separately attributable, makes the ref-transaction case prove a
real stale CAS, uses one declared Git client as both client and server, and
binds the refusal SQL to the real schema and evidence contract. They cannot
replace the native run and never claim it passed.

The queue runner (``tests/browse.py``) is deliberately not changed in this
phase: every contract the #18 cases need from it is asserted here where the
Phase 2 integration must satisfy it.
"""
import argparse
import ast
import base64
import contextlib
import json
import io
import inspect
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import browse  # noqa: E402
import mixed_ref_cases  # noqa: E402
import refusal_audit_sql  # noqa: E402

BROWSE = Path(__file__).with_name("browse.py")
CASES = Path(__file__).with_name("mixed_ref_cases.py")
SQL = Path(__file__).with_name("refusal_audit_sql.py")
KLASS = "MixedRefPolicyCases"
# Command words that move the checked-out fixture.  ``git`` is named explicitly
# so a case cannot bypass the declared client; ``commit-tree`` is the one
# allowed exception: it writes an object and moves no branch.
MUTATING = {"git", "push", "rebase", "merge", "reset", "commit", "add", "checkout", "switch"}
ALLOWED = {"commit-tree"}


def git_commands(name):
    """The command word of every ``git``/``git_as`` call in one case method.

    ``git_as`` takes a token first, so its command is the constant directly
    after it; ``git`` takes the command as its first positional argument.
    """
    for call in ast.walk(method(name)):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr in ("git", "git_as")):
            continue
        args = list(call.args[1:] if call.func.attr == "git_as" else call.args)
        if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            yield args[0].value


def assert_not_mutating_git(test, name):
    """No Git command word of a case moves the checked-out fixture."""
    # The ref-transaction case is API-only and deliberately runs no Git at all.
    commands = list(git_commands(name))
    for word in commands:
        if word in MUTATING:
            test.fail(name + " runs a mutating Git command: " + word)
    test.assertLessEqual([word for word in commands if word in ALLOWED], ["commit-tree"], name)


def assert_no_forked_state(test, body):
    """The API case never forces or prunes: no second history proves a stale CAS."""
    test.assertNotIn("--force", body)
    test.assertNotIn("prune", body)


def method(name, path=CASES):
    tree = ast.parse(path.read_text())
    klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == KLASS)
    return next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == name)


def source(name):
    return ast.get_source_segment(CASES.read_text(), method(name))


# The queue harness used by every instance-level test; the runner now builds
# exactly this class, built here without ``Harness.__init__`` (no socket/temp DB).
FixtureHarness = browse.BrowseHarness


def completed(stdout, returncode=1, stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout.encode(), stderr=stderr.encode())


def source_of(path, name):
    text = Path(path).read_text()
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(text, node)


class PushRefusalParserTest(unittest.TestCase):
    def rejects(self, out, *refs):
        return mixed_ref_cases.MixedRefPolicyCases.assert_push_refusals(completed(out), *refs)

    def test_both_refs_rejected_by_server_is_evidence(self):
        out = ("To http://127.0.0.1:1/git/alice/demo.git\n"
               "!\trefs/heads/main:refs/heads/main\t[remote rejected] (non-fast-forward)\n"
               "!\trefs/heads/mixed-topic:refs/heads/mixed-topic\t[remote rejected] (atomic push failure)\n"
               "Done\n")
        detail = self.rejects(out, "refs/heads/main", "refs/heads/mixed-topic")
        self.assertEqual(set(detail["refs"]), {"refs/heads/main", "refs/heads/mixed-topic"})
        self.assertTrue(detail["refs"]["refs/heads/mixed-topic"]["summary"].startswith("[remote rejected]"))

    def test_local_rejection_is_not_server_evidence(self):
        # A ``+`` force refspec would bypass the client's own check; a bare one
        # is refused locally before the server ever sees it.
        out = ("!\trefs/heads/main:refs/heads/main\t[rejected] (non-fast-forward)\n"
               "!\trefs/heads/mixed-topic:refs/heads/mixed-topic\t[rejected] (atomic push failed)\n")
        with self.assertRaisesRegex(AssertionError, "not server-refused"):
            self.rejects(out, "refs/heads/main", "refs/heads/mixed-topic")

    def test_one_local_rejection_spoils_the_pair(self):
        out = ("!\trefs/heads/main:refs/heads/main\t[remote rejected] (non-fast-forward)\n"
               "!\trefs/heads/mixed-topic:refs/heads/mixed-topic\t[rejected] (atomic push failed)\n")
        with self.assertRaisesRegex(AssertionError, "refs/heads/mixed-topic was not server-refused"):
            self.rejects(out, "refs/heads/main", "refs/heads/mixed-topic")

    def test_bang_without_remote_summary_is_not_evidence(self):
        with self.assertRaisesRegex(AssertionError, "not server-refused"):
            self.rejects("!\trefs/heads/main:refs/heads/main\t[nothing to push]\n", "refs/heads/main")

    def test_local_up_to_date_noop_is_not_evidence(self):
        out = ("=\trefs/heads/main:refs/heads/main\t[up to date]\n"
               "!\trefs/heads/mixed-topic:refs/heads/mixed-topic\t[remote rejected]\n")
        with self.assertRaisesRegex(AssertionError, "local no-op"):
            self.rejects(out, "refs/heads/main", "refs/heads/mixed-topic")

    def test_other_output_is_kept_in_the_evidence(self):
        out = ("To http://127.0.0.1:1/git/alice/demo.git\n"
               "error: failed to push some refs\n"
               "!\trefs/heads/release:refs/heads/release\t[remote rejected] (deletion of the current branch prohibited)\n")
        detail = self.rejects(out, "refs/heads/release")
        self.assertEqual(detail["other_output"], ["To http://127.0.0.1:1/git/alice/demo.git",
                                                  "error: failed to push some refs"])

    def test_missing_status_line_is_not_evidence(self):
        out = "!\trefs/heads/main:refs/heads/main\t[remote rejected]\n"
        with self.assertRaisesRegex(AssertionError, "was not server-refused"):
            self.rejects(out, "refs/heads/main", "refs/heads/mixed-topic")

    def test_flags_do_not_leak_into_the_status(self):
        blank = "\trefs/heads/mixed-topic:refs/heads/mixed-topic\t[remote rejected] (denied)\n"
        with self.assertRaisesRegex(AssertionError, "local no-op|not refused per ref"):
            self.rejects(blank, "refs/heads/mixed-topic")
        star = "*\trefs/heads/main:refs/main\t[new tag]\n"
        with self.assertRaisesRegex(AssertionError, "local no-op|not refused per ref"):
            self.rejects(star, "refs/main")

    def test_successful_push_fails_the_helper(self):
        out = ("*\trefs/heads/main:refs/heads/main\t[new branch]\n"
               " \trefs/heads/mixed-topic:refs/heads/mixed-topic\tdone\n")
        with self.assertRaisesRegex(AssertionError, "not refused|not server-refused"):
            self.rejects(out, "refs/heads/main")


class CaseContractTest(unittest.TestCase):
    """The exact native IDs, kept an explicit opt-in beyond the fixed inventory."""

    def test_exact_case_ids(self):
        self.assertIsInstance(mixed_ref_cases.MIXED_REF_CASES, tuple)
        self.assertEqual(mixed_ref_cases.MIXED_REF_CASES, (
            "mixed_protected_unprotected_atomic_push",
            "mixed_protected_unprotected_ref_transaction"))
        for name in mixed_ref_cases.MIXED_REF_CASES:
            self.assertTrue(callable(getattr(mixed_ref_cases.MixedRefPolicyCases, name, None)), name)
        # No renamed, near-miss or additional case method exists.
        klass = next(n for n in ast.parse(CASES.read_text()).body if isinstance(n, ast.ClassDef) and n.name == KLASS)
        defined = {n.name for n in klass.body if isinstance(n, ast.FunctionDef)}
        for name in defined:
            if name.startswith("mixed_") and name != "mixed_protected_unprotected_atomic_push":
                self.assertEqual(name, "mixed_protected_unprotected_ref_transaction", name)

    def test_fixed_inventory_is_untouched(self):
        self.assertEqual(len(browse.CASE_NAMES), 15)
        self.assertEqual(browse.CASE_NAMES[12], "ref_scale_complete_traversal")
        self.assertEqual(browse.CASE_NAMES[-1], "protected_writes_and_ref_ack_failure")
        self.assertEqual(browse.CASE_NAMES.count("ref_scale_complete_traversal"), 1)
        for deadline in ("list_commits_deadline", "compare_commits_deadline"):
            self.assertIn(deadline, browse.CASE_NAMES)
        for name in mixed_ref_cases.MIXED_REF_CASES:
            self.assertNotIn(name, browse.CASE_NAMES)

    def test_mixin_is_the_harness_base_and_runner_imports_the_exact_ids(self):
        self.assertTrue(issubclass(browse.BrowseHarness, mixed_ref_cases.MixedRefPolicyCases))
        self.assertIsInstance(object.__new__(browse.BrowseHarness), mixed_ref_cases.MixedRefPolicyCases)
        text = BROWSE.read_text()
        # The runner imports the exact IDs from the case module, never a copy.
        self.assertIn("from mixed_ref_cases import MIXED_REF_CASES, MixedRefPolicyCases, "
                      "release_git_option", text)
        self.assertEqual(tuple(re.search(r"MIXED_REF_CASES == \((.*?)\)", text, re.S).group(0)
                               .replace("\n", " ").split('"')[1::2]), mixed_ref_cases.MIXED_REF_CASES)
        # The fixed inventory is byte-for-byte the pre-integration tuple.
        head = subprocess.run(["git", "show", "89f4bb17535bba8c9df5f0514bc3cfb050579aba:tests/browse.py"],
                              cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if head.returncode:
            self.skipTest("pre-integration queue commit unavailable")
        before = re.search(r"CASE_NAMES = \(.*?\n\)", head.stdout.decode(), re.S).group(0)
        now = re.search(r"CASE_NAMES = \(.*?\n\)", text, re.S).group(0)
        self.assertEqual(now, before)

    def test_queue_harness_still_supplies_every_primitive(self):
        needed = ("args", "env", "secrets", "bare", "work", "repo", "alice", "sql", "cli", "run",
                  "http", "document", "http_failure_detail", "redact", "_sql_literal", "git", "repo_api",
                  "first", "second", "third", "feature_oid")
        text = BROWSE.read_text() + (ROOT / "tests/e2e.py").read_text()
        for name in needed:
            self.assertIn(name, text, name)
        bare = [line.strip() for line in text.splitlines() if line.strip().startswith("self.bare =")]
        self.assertEqual(bare, ['self.bare = self.root / "data" / "repos" / (repo["id"] + ".git")'])
        # The API refs share the shape the case reads (``name``/``oid``).
        self.assertIn('assert names == ["refs/heads/feature", "refs/heads/main", "refs/tags/v1.0"], names',
                      text)

    def test_selection_is_the_fixed_inventory_then_the_two_mixed_cases(self):
        fixed, mixed = list(browse.CASE_NAMES), list(mixed_ref_cases.MIXED_REF_CASES)
        deadlines = ("list_commits_deadline", "compare_commits_deadline")
        self.assertEqual(len(fixed), 15)
        # 14 main cases (the deadline cases are part of them) + the one scale case.
        self.assertEqual((len(fixed) - 1, fixed.count("ref_scale_complete_traversal")), (14, 1))
        for deadline in deadlines:
            self.assertEqual(fixed.count(deadline), 1)
        self.assertEqual(sum(name.endswith("_deadline") for name in fixed), 2)
        self.assertEqual(browse.selected_cases(False), fixed)
        selected = browse.selected_cases(True)
        self.assertEqual(len(selected), 17)
        self.assertEqual(selected[-2:], [
            "mixed_protected_unprotected_atomic_push",
            "mixed_protected_unprotected_ref_transaction"])
        self.assertEqual(selected[:-2], fixed)
        self.assertEqual(set(selected) - set(fixed), set(mixed))
        self.assertNotIn(True, [name in fixed for name in mixed])

    def test_runner_keeps_the_fixed_assertion_before_the_opt_in(self):
        runner = source_of(BROWSE, "execute")
        # The original fixed-inventory assertion is kept, byte for byte, first.
        self.assertIn("for name in CASE_NAMES:\n            harness.case(name, getattr(harness, name))", runner)
        self.assertIn("if executed != list(CASE_NAMES):", runner)
        self.assertLess(runner.index("if executed != list(CASE_NAMES):"),
                        runner.index("for name in MIXED_REF_CASES:"))
        handoff = runner.index("harness.git_handoff = harness.restore_declared_git()")
        self.assertIn("if args.mixed_refs:\n            # Remove the fixed-suite instrumentation",
                      runner)
        self.assertLess(handoff, runner.index("for name in MIXED_REF_CASES:"))
        self.assertLess(runner.index("if executed != list(CASE_NAMES):"), handoff)
        self.assertIn("git_handoff=getattr(harness, \"git_handoff\", None)", source_of(BROWSE, "execute"))
        self.assertIn("if completed != selected:", runner)
        # A bare --mixed-refs is rejected before any harness is built.
        self.assertIn('if args.mixed_refs and not (args.git or os.environ.get("ROOTYARD_GIT")):', runner)
        self.assertLess(runner.index("if args.mixed_refs and not (args.git"),
                        runner.index("harness = harness_type(args)"))
        self.assertIn('raise RunnerError("--mixed-refs requires a declared --git', runner)
        # --mixed-refs and the trusted Git option, in that order, after base args.
        parser_source = source_of(BROWSE, "build_parser")
        self.assertLess(parser_source.index('"--keep"'), parser_source.index('"--mixed-refs"'))
        self.assertLess(parser_source.index('"--mixed-refs"'), parser_source.index("release_git_option(parser)"))
        self.assertIn("release_git_option(parser)", parser_source)
        self.assertEqual(parser_source.count("return parser"), 1)
        self.assertIn("parse_args()", source_of(BROWSE, "main"))
        self.assertIn("execute(args, BrowseHarness)", source_of(BROWSE, "main"))
        parser = argparse.ArgumentParser()
        parser.add_argument("--keep", action="store_true")
        parser.add_argument("--mixed-refs", action="store_true")
        mixed_ref_cases.release_git_option(parser)
        opts = parser.parse_args(["--mixed-refs", "--git", "/usr/bin/git"])
        self.assertTrue(opts.mixed_refs)
        self.assertEqual(opts.git, "/usr/bin/git")
        self.assertFalse(parser.parse_args([]).mixed_refs)
        self.assertIsNone(parser.parse_args([]).git)

    def test_report_carries_the_fixed_record_and_the_two_results(self):
        runner = source_of(BROWSE, "execute")
        for field in ("case_count=len(selected)", "fixed_case_count=len(CASE_NAMES)",
                      "fixed_cases=list(CASE_NAMES)", "selected_cases=selected",
                      "mixed_ref_cases=list(MIXED_REF_CASES) if args.mixed_refs else []",
                      'mixed_ref_results={item["name"]: item["status"] for item in harness.results',
                      "git=harness.git_binding", 'git_evidence=getattr(harness, "git_evidence", None)'):
            self.assertIn(field, runner, field)
        self.assertIn("cases=harness.results", runner)

    def test_ci_browse_step_runs_the_seventeen_case_mode(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        command = ('run: python3 tests/browse.py --binary target/debug/rootyard '
                   '--report test-results/browse.json --mixed-refs --git "$(command -v git)"')
        self.assertEqual(workflow.count(command), 1)
        self.assertEqual(workflow.count("tests/browse.py"), 1, "only the Browse step may change")
        # Other suites keep their exact commands.
        for untouched in ("python3 tests/pulls.py --binary target/debug/rootyard --report test-results/pulls.json",
                          "python3 tests/lfs.py --binary target/debug/rootyard --report test-results/lfs.json"):
            self.assertIn("run: " + untouched, workflow)
        if shutil.which("git"):
            # The shell substitution yields an absolute path accepted by --git.
            parsed = argparse.ArgumentParser()
            mixed_ref_cases.release_git_option(parsed)
            self.assertTrue(Path(parsed.parse_args(["--git", shutil.which("git")]).git).is_absolute())

    def test_module_stays_modular(self):
        # Refusal audit SQL/verdict live in refusal_audit_sql.py; the cap stays.
        self.assertLessEqual(len(CASES.read_text().splitlines()), 645)
        self.assertNotIn("def audit_where", CASES.read_text())
        self.assertNotIn("def operations_after_query", CASES.read_text())

    def test_reference_events_shape(self):
        real = [{"ordinal": 1, "phase": "Aborted", "changes": []},
                {"ordinal": 2, "phase": "Aborted", "changes": []}]
        self.assertEqual(mixed_ref_cases.reference_events(real), real)
        self.assertEqual(mixed_ref_cases.reference_events({"changes": []}), [{"changes": []}])
        self.assertEqual(mixed_ref_cases.reference_events(None), [])

    def test_judge_audit_never_passes_a_missing_operation(self):
        missing = mixed_ref_cases.judge_audit({"status": "missing", "reference_events": []}, [])
        self.assertEqual(missing["status"], "missing")
        self.assertEqual(missing["problems"], ["no operation"])
        settled = mixed_ref_cases.judge_audit({
            "status": "settled", "settled": True, "outcome": "no_ref_changes",
            "actor_and_token_match": True, "human_principal": True, "service_principal": False,
            "admission_present": True, "admission_state": "ABORTED", "admission_settled": True,
            "admission_identity_matches": True, "admission_ref_names": ["refs/heads/main"],
            "outbox_count": 0, "outbox_ref_names": [], "evidence_no_receipt": True,
            "finished": True, "storage_generation_matches": True, "interrupted": "false",
            "ungranted_without_hooks": "false", "reference_events": [], "ref_names": ["refs/heads/main"]},
            [])
        self.assertEqual(settled["problems"], [])
        # A row that stored the boolean as text is not the projected contract.
        text = dict(settled["audit"], finished="true")
        self.assertIn("finished", mixed_ref_cases.judge_audit(text, [])["problems"])


class MixedRefWiringTest(unittest.TestCase):
    def test_isolated_rules_is_a_context_manager(self):
        # A bare generator here fails every native case at the first `with`.
        self.assertTrue(hasattr(mixed_ref_cases.MixedRefPolicyCases.isolated_rules, "__wrapped__"))
        harness = object.__new__(FixtureHarness)
        self.assertIsInstance(harness.isolated_rules(), contextlib.AbstractContextManager)

    def test_rules_are_isolated_and_restored(self):
        both = source("mixed_protected_unprotected_atomic_push") + source(
            "mixed_protected_unprotected_ref_transaction")
        self.assertEqual(both.count("with self.isolated_rules():"), 2)
        body = ast.unparse(method("isolated_rules"))
        self.assertIn("original = policy()", body)
        self.assertIn("method='DELETE'", body)
        self.assertIn("self._restore_rules(repo, original, policy)", body)
        restore = ast.unparse(method("_restore_rules"))
        self.assertIn("for ref in self.rules(repo)", restore)
        self.assertIn("assert remaining == {}", restore)
        self.assertIn("for ref, item in original.items()", restore)
        self.assertIn("assert policy() == original", restore)
        # No case may assume the global rule inventory of an earlier case.
        self.assertNotIn('refs == {"refs/heads/main"}', CASES.read_text())
        # No docstring may claim the API refuses every update of a rule.
        for text in (CASES.read_text(), BROWSE.read_text()):
            self.assertNotIn("refuses every update", text)
        # A restore delete treats an already-deleted rule (404) as deleted, and
        # nothing else as success.
        self.assertIn("if status not in (200, 404):", restore)

    def fake_rules(self):
        """A fake rule API with ``src/pulls/rules.rs`` upsert/delete semantics.

        GET lists stored rows; a PUT for an absent branch with
        ``expected_version`` is a 409; an existing branch only updates when the
        body names its current version (then bumps it). DELETE hard-deletes and
        returns 200 (``{"deleted": true}``), exactly as the handler does.
        """
        rules, log = {}, []

        def document(self, path, code=200, token=None, **kwargs):
            method, body = kwargs.get("method", "GET"), kwargs.get("body")
            ref = path.split("/branch-rules/", 1)[1] if "/branch-rules/" in path else None
            log.append((method, ref, dict(body) if body else None))
            current = rules.get(ref)
            if method == "GET":
                return {"items": list(rules.values())}
            if method == "DELETE":
                del rules[ref]
                return {"deleted": True}
            if current is None:
                assert "expected_version" not in body, 409
                rules[ref] = {"branch_ref": ref, "version": 1}
            else:
                assert body.get("expected_version") == current["version"], 409
                current["version"] += 1
            rules[ref].update({k: body[k] for k in self.RULE_FIELDS if k in body})
            return dict(rules[ref])

        def http(self, path, token=None, method="GET"):
            ref = path.split("/branch-rules/", 1)[1]
            status = 200 if method == "DELETE" and ref in rules else 404
            if status == 200:
                del rules[ref]
            return status, json.dumps({"deleted": status == 200}).encode(), {}

        harness = object.__new__(FixtureHarness)
        harness.document, harness.http = document.__get__(harness), http.__get__(harness)
        harness.http_failure_detail = lambda path, expected, status, body, headers, token, note=None: (
            "Delete failed: " + path + " -> " + str(status))
        harness.local_repo, harness.pulled = "demo", False
        harness.alice = {"username": "alice", "token": "secret"}
        rules["refs/heads/main"] = {"branch_ref": "refs/heads/main", "required_approvals": 2,
                                    "required_checks": ["ci/required"], "require_fast_forward": True,
                                    "prevent_deletion": True, "prevent_force_push": True,
                                    "prevent_self_approval": False, "version": 3}
        return harness, rules, log

    def test_update_carries_the_real_version_insert_omits_it(self):
        harness, rules, log = self.fake_rules()
        # Insert: no rule row, so no expected_version.
        self.assertEqual(harness.put_rule("refs/heads/topic")["version"], 1)
        self.assertIsNone(log[-1][2].get("expected_version"))
        # Update of an existing rule: the real row version, not a guess.
        self.assertEqual(harness.policy_rule("refs/heads/main")["required_approvals"], 1)
        self.assertEqual(log[-1][2]["expected_version"], 3)
        self.assertEqual(harness.put_rule("refs/heads/topic", required_approvals=2)["version"], 2)
        self.assertEqual(log[-1][2]["expected_version"], 1)
        # Isolation deletes every rule (a real API DELETE) and restores policy.
        policy = lambda: {ref: harness.rule_view(item) for ref, item in rules.items()}
        original = policy()
        self.assertEqual(sorted(original), ["refs/heads/main", "refs/heads/topic"])
        log.clear()
        with harness.isolated_rules():
            self.assertEqual(policy(), {})
            harness.put_rule("refs/heads/case")
        self.assertEqual(policy(), original)
        # Every original is recreated as a new row: no old version is sent.
        restores = [body for method, ref, body in log if method == "PUT" and ref in original]
        self.assertEqual(sorted({body["branch_ref"] for body in restores}),
                         ["refs/heads/main", "refs/heads/topic"])
        for body in restores:
            self.assertEqual(set(body) & {"expected_version", "version"}, set(), body)

    def test_restore_failure_keeps_the_case_exception_as_context(self):
        """A failing restore step must not hide what the case actually failed on."""
        harness, rules, log = self.fake_rules()
        saved_get = harness.document

        def document(self, path, code=200, token=None, **kwargs):
            if kwargs.get("method", "GET") == "GET" and any(
                    entry[0] == "PUT" for entry in log):  # a restore PUT follows
                raise AssertionError("expected (200, 201), got 409: branch rule version conflict")
            return saved_get(path, code, token, **kwargs)

        harness.document = document.__get__(harness)
        with self.assertRaises(AssertionError) as caught:
            with harness.isolated_rules():
                raise ArithmeticError("the real case failure")
        self.assertIn("version conflict", str(caught.exception))
        self.assertIsInstance(caught.exception.__context__, ArithmeticError, "cause was masked")
        self.assertEqual(caught.exception.__context__.args, ("the real case failure",))

    def test_native_group_has_no_policy_and_policy_group_only_policy(self):
        body = source("mixed_protected_unprotected_atomic_push")
        # One rule-free context for both groups; each group then owns its rules.
        self.assertLess(body.index("self.native_group(main, topic)"),
                        body.index("self.policy_group(main, topic, native[\"audit\"])"))
        native = source("native_group")
        # Group 1 creates no rule and relaxes no flag: the refusal is stock Git.
        self.assertIn("self.assert_rule_state({})", native)
        for forbidden in ("put_rule", "policy_rule", "rule_body", "require_fast_forward"):
            self.assertNotIn(forbidden, native, forbidden)
        self.assertNotIn("--unset", native)
        self.assertIn("self.push_as_owner(\"--atomic\"", native)
        # Policy group: approvals only; the fast-forward commit sits on the tip.
        policy = source("policy_group")
        self.assertIn("require_fast_forward=False, prevent_force_push=False", policy)
        self.assertIn("self.policy_rule(main, require_fast_forward=False, prevent_force_push=False", policy)
        self.assertIn("policy_oid = self.commit_over(base, ", policy)
        self.assertIn("base = self.advertised_oid(main)", policy)
        self.assertIn("assert base == self.third, base", policy)
        # No ancestry check may run against an unpushed local commit.
        joined = CASES.read_text()
        self.assertNotIn("rev-list", joined)
        self.assertNotIn("merge-base", joined)
        self.assertIn('"ls-remote", self.remote, ref', source("advertised_oid"))
        self.assertIn("self.open_pull_for_main(policy_oid)", policy)
        self.assertIn("policy_oid + \":\" + main", policy)
        self.assertIn('"native_group"', body)
        self.assertIn('"policy_group"', body)
        # Every refusal re-reads the real state: two atomic pairs and the half.
        self.assertEqual(native.count("assert_one_aborted_refusal("), 1)
        self.assertEqual(policy.count("assert_one_aborted_refusal("), 2)

    def test_pull_is_recorded_but_the_direct_push_is_still_denied(self):
        self.assertIn("head_oid", [n.id for n in ast.walk(method("open_pull_for_main")) if isinstance(n, ast.Name)])
        bodies = dict_literals(method("open_pull_for_main"))
        self.assertTrue(any(item.get("head_ref") == "features" and item.get("base_ref") == "main"
                            for item in bodies), bodies)
        # The pull is listed as evidence of what does NOT authorize a direct
        # write; only the PR-merge binding could satisfy an approval rule.
        policy = source("policy_group")
        self.assertIn('"pull_alone_authorizes": False', policy)
        self.assertIn('"git_refusal": native_refusal', policy)
        # The production decision really says a pull identity does not authorize.
        self.assertIn("A direct push has\n        // no pull-request identity",
                      (ROOT / "src/browse/policy.rs").read_text())

    def test_ref_transaction_refuses_mixed_first_then_protected_alone(self):
        body = source("mixed_protected_unprotected_ref_transaction")
        markers = ["Seed with no rule", "policy_mixed = refused", "Control:",
                   "base = self.ref_state()", "alone = refused", "409 stale"]
        pos = -1
        for marker in markers:
            nxt = body.index(marker, pos + 1)
            self.assertGreater(nxt, pos, marker)
            pos = nxt
        for text in [
            'refused("403 mixed", 403, "protected branch policy denied"',
            '"ref_name": main, "old_oid": self.third, "new_oid": self.feature_oid',
            '"ref_name": topic, "old_oid": self.second, "new_oid": self.feature_oid',
            'refused("403 protected alone", 403',
            'refused("409 stale", 409, "reference old_oid mismatch"',
            'self.assert_api_refusal(before, self.ref_state(), label, [update["ref_name"] for update in updates])',
            "api_operations_delta",
            '"api_operations_delta": 0',
        ]:
            self.assertIn(text, body)
        self.assertNotIn("merge-base", body)
        api = source("assert_api_refusal")
        self.assertNotIn("git_refusal_audit", api)
        native = source("assert_one_aborted_refusal")
        self.assertIn("audit_git_refusal_interval", native)
        self.assertNotIn("git_refusal_audit", native)
        transactions = (ROOT / "src/browse/transactions.rs").read_text()
        self.assertLess(transactions.index('"reference old_oid mismatch"'),
                        transactions.index("crate::browse::policy::validate("))
        policy = (ROOT / "src/browse/policy.rs").read_text()
        self.assertIn('Error(StatusCode::FORBIDDEN, "protected branch policy denied"', policy)

    def test_topic_seed_uses_a_context_without_the_topic_rule(self):
        body = source("mixed_protected_unprotected_ref_transaction")
        seed = body[body.index("Seed with no rule"):body.index("One rule set")]
        self.assertIn("self.assert_rule_state({})", seed)
        self.assertNotIn("self.put_rule(", seed)
        self.assertLess(body.index("One rule set"), body.index("Control:"))
        self.assertLess(body.index("self.put_rule(topic, required_approvals=0)"), body.index("Control:"))
        assert_not_mutating_git(self, "mixed_protected_unprotected_ref_transaction")
        self.assertIn("refs/heads/mixed-tx-topic", body)
        assert_no_forked_state(self, body)

    def test_git_client_is_declared_and_shared_with_the_server(self):
        env_keys = {n.args[0].value for n in ast.walk(method("native_git"))
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "get" and n.args and isinstance(n.args[0], ast.Constant)}
        self.assertIn("ROOTYARD_GIT", env_keys)
        args = {n.attr for n in ast.walk(method("native_git")) if isinstance(n, ast.Attribute)}
        self.assertIn("args", args)
        messages = {n.value for n in ast.walk(method("native_git")) if isinstance(n, ast.Constant)
                    and isinstance(n.value, str) and "disagree" in n.value}
        self.assertTrue(messages, "a disagreeing --git/ROOTYARD_GIT must fail loudly")
        # Every push (and any Git I/O of these cases) runs the declared
        # executable with its own alice Authorization header, never a PATH git
        # and never a clone-time-only credential.
        for name in ("git_as", "push_with", "push_as_owner"):
            self.assertNotIn("self.git(", source(name), name)
        self.assertNotIn("self.run(", source("push_with"))
        self.assertIn('"http.extraHeader=Authorization: Basic "', source("git_as"))
        self.assertIn("probe[\"executable\"]", source("git_as"))
        self.assertIn("self.git_as(self.alice", source("push_with"))
        git_argv = ast.unparse(method("git_as"))
        self.assertIn("cwd=cwd or self.work", git_argv)

    def test_push_really_carries_the_token(self):
        # Real subprocess behaviour: the per-push header reaches Git (a wrapper
        # records argv), and the raw credential never reaches a diagnostic.
        harness = object.__new__(FixtureHarness)
        harness.args = SimpleNamespace(git="/usr/bin/git", mixed_refs=True)
        harness.git_binding = {"declared": "/usr/bin/git", "env": None, "mixed_refs": True}
        harness.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_TERMINAL_PROMPT="0")
        harness.secrets = []
        harness.work = str(Path(__file__).resolve().parent)
        harness.base_db, harness.db = "postgres://probe/admin", "postgres://probe/run"
        harness.register_token({"username": "alice", "token": "s3cr3t-token"})
        original_env = dict(harness.env)
        saved = dict(mixed_ref_cases.os.environ)
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "argv"
            wrapper = Path(root) / "git"
            wrapper.write_text("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'git version 2.47.3'; exit 0; fi\n"
                               "printf '%s\\n' \"$@\" > " + str(marker) + "\nexit 3\n")
            wrapper.chmod(0o755)
            harness.native_git = lambda: {"executable": str(wrapper), "declared": True, "notes": []}
            harness.native_git_probe = lambda: {
                "executable": str(wrapper), "declared": True, "notes": [],
                "version": "2.47.3", "minor": (2, 47), "sha256": "0" * 64}
            try:
                mixed_ref_cases.os.environ.clear()
                mixed_ref_cases.os.environ.update(harness.env)
                done = harness.git_as({"username": "alice", "token": "s3cr3t-token"},
                                      "push", "origin", "a:b")
            finally:
                mixed_ref_cases.os.environ.clear()
                mixed_ref_cases.os.environ.update(saved)
            argv = marker.read_text().splitlines()
        self.assertEqual(done.returncode, 3)
        expected = "http.extraHeader=Authorization: Basic " + base64.b64encode(b"alice:s3cr3t-token").decode()
        self.assertEqual(argv[:2], ["-c", expected])
        self.assertEqual(argv[-3:], ["push", "origin", "a:b"])
        self.assertNotIn("s3cr3t-token", harness.redact(" ".join(argv)))
        # The credential copy is per command: the server env is never rewritten
        # (a mutation here used to make the live server look bound to the client).
        self.assertEqual(harness.env, original_env, "git_as must not mutate the server env")


class _FakeProcess:
    """Minimal live ``Popen`` stand-in for ``Harness.start`` readiness checks."""

    pid = 4242
    terminated = False

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0


class BrowseIntegrationTest(unittest.TestCase):
    """The wired runner: one harness, 17 selected IDs, one bound Git."""

    GIT = str(Path(shutil.which("git")).resolve()) if shutil.which("git") else None

    def setUp(self):
        if self.GIT is None:
            self.skipTest("no stock git on PATH")
        saved = {key: os.environ.get(key) for key in ("ROOTYARD_GIT", "ROOTYARD_TEST_DATABASE_URL")}
        self.addCleanup(self._restore_env, saved)
        os.environ.pop("ROOTYARD_GIT", None)
        self.real_launch = browse.harness_start

    @staticmethod
    def _restore_env(saved):
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def harness(self, **options):
        """A real ``BrowseHarness.__init__``; it starts no server.

        ``Harness.__init__`` only reads the database URL, picks a loopback port
        and creates a temporary root, which the cleanup removes.
        """
        os.environ["ROOTYARD_TEST_DATABASE_URL"] = "postgres://probe/run"
        parsed = dict(binary="/opt/rootyard", git=None, mixed_refs=False)
        parsed.update(options)
        harness = browse.BrowseHarness(SimpleNamespace(**parsed))
        # What the server child actually receives at start time.
        harness.runtime_env = dict(harness.env)
        harness.run = self.run_for(harness)
        # Real ``Harness.start`` spawns a server; intercept only that process
        # launch. ``BrowseHarness.start`` itself still runs and captures.
        # ``Harness.start`` is the process launcher: record the env instead of
        # spawning.  ``BrowseHarness.start``'s capture still computes the fact
        # from ``self.env`` exactly as production does.
        harness.starts = []
        real_launch = browse.harness_start
        self.addCleanup(setattr, browse, "harness_start", real_launch)
        self.real_launch = real_launch

        def launch(target):
            harness.starts.append(dict(target.env))
            target.proc = _FakeProcess()
        browse.harness_start = launch
        saved_stop = harness.stop

        def stop(hard=False):
            if isinstance(harness.proc, _FakeProcess):
                harness.proc.terminated = True   # the real stop() only signals
                harness.proc = None
            return saved_stop(hard=hard)
        harness.stop = stop
        self.addCleanup(shutil.rmtree, harness.root, True)
        return harness

    @staticmethod
    def run_for(harness):
        """``Harness.run`` with the timeout widened; it executes, never starts."""
        def run(argv, cwd=None, check=True, data=None, env=None):
            done = subprocess.run(argv, cwd=cwd, env=harness.env if env is None else env, input=data,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            if check and done.returncode:
                raise AssertionError("command failed: " + done.stderr.decode(errors="replace")[-600:])
            return done
        return run

    @staticmethod
    def browse_class():
        return next(n for n in ast.parse(BROWSE.read_text()).body
                    if isinstance(n, ast.ClassDef) and n.name == "BrowseHarness")

    def test_native_git_is_the_callable_resolver_not_the_wrapper_string(self):
        harness = self.harness()
        self.assertTrue(callable(harness.native_git))
        self.assertEqual(harness.native_git()["executable"], self.GIT)
        self.assertIsInstance(harness.wrapper_git, str)
        # No class-level string shadows the resolver either: it comes only
        # from the mixin, and __init__ never assigns an instance string.
        self.assertNotIn("native_git", browse.BrowseHarness.__dict__)
        self.assertNotIn("native_git", browse.BrowseHarness.__init__.__code__.co_names)
        self.assertIn("native_git", mixed_ref_cases.MixedRefPolicyCases.__dict__)
        initializer = next(n for n in self.browse_class().body
                           if isinstance(n, ast.FunctionDef) and n.name == "__init__")
        assigned = {t.attr for n in ast.walk(initializer) if isinstance(n, ast.Assign)
                    for t in n.targets if isinstance(t, ast.Attribute)}
        self.assertIn("wrapper_git", assigned)
        self.assertNotIn("native_git", assigned, "an instance string would shadow the method")
        # The rename touches exactly the wrapper field and its four use sites.
        text = BROWSE.read_text()
        self.assertEqual(text.count("self.wrapper_git"), 4)
        self.assertIsNone(re.search(r"self\.native_git\b", text))
        probe = ast.unparse(next(n for n in self.browse_class().body
                                 if isinstance(n, ast.FunctionDef) and n.name == "native_git_probe"))
        self.assertIn("self._native_git_probe", probe)
        self.assertIn("super().native_git_probe()", probe)

    def test_wrapper_git_is_the_bound_declaration_not_path_git(self):
        """An explicit ``--git`` elsewhere on disk is what the wrappers exec."""
        self.assertNotEqual(Path(shutil.which("git")).resolve(), Path(shutil.which("sh")).resolve())
        other = str(Path(shutil.which("sh")).resolve())
        # Fixed inventory only: no --mixed-refs, so no Git probe is needed.
        harness = self.harness(git=other)
        self.assertEqual(harness.git_binding["declared"], other)
        self.assertEqual(harness.runtime_env["ROOTYARD_GIT"], other)
        self.assertEqual(harness.wrapper_git, other)
        self.assertNotEqual(harness.wrapper_git, shutil.which("git"))
        # Bind the executable of a declared PATH Git: it is the same file.
        via_path = self.harness(git=shutil.which("git"))
        self.assertEqual(Path(via_path.wrapper_git), Path(self.GIT))
        self.assertEqual(Path(via_path.native_git()["executable"]), Path(via_path.wrapper_git))
        # An inherited-only declaration binds the wrapper the same way.
        os.environ["ROOTYARD_GIT"] = other
        inherited = self.harness()
        self.assertEqual(inherited.runtime_env["ROOTYARD_GIT"], other)
        self.assertEqual(inherited.wrapper_git, other)
        os.environ.pop("ROOTYARD_GIT")
        fixed_only = self.harness()
        self.assertIsNone(fixed_only.git_binding["declared"])
        self.assertNotIn("ROOTYARD_GIT", fixed_only.runtime_env)
        self.assertEqual(fixed_only.wrapper_git, shutil.which("git"))

    def test_both_transparent_wrappers_execute_the_bound_declaration(self):
        """The wrappers really run the bound executable, not the PATH Git."""
        sh = Path(shutil.which("sh")).resolve()
        # ``/bin/sh`` does not speak Git, so any fallback to PATH Git would
        # either fail (``--version``) or run Git; the evidence must be sh.
        harness = self.harness(git=str(sh))
        self.assertEqual(harness.wrapper_git, str(sh))
        script = harness._deadline_wrapper_script(harness.wrapper_git, harness.root / "arm",
                                                  harness.root / "log")
        self.assertIn("exec " + shlex.quote(str(sh)) + ' "$@"', script)
        for case, size in (("deadline", None), ("cat-file", 1)):
            with self.subTest(wrapper=case):
                path = harness.root / ("wrapper-" + case)
                path.write_text(script if size is None else
                                "#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = cat-file ]; then :; fi\n"
                                "done\nexec " + shlex.quote(harness.wrapper_git) + " \"$@\"\n")
                path.chmod(0o700)
                # Never ``git --version``: an unarmed/wrapper-transparent call.
                done = harness.run([str(path)], check=False)
                self.assertEqual(done.returncode, 0, done.stderr[:300])
        # The native client resolves the same executable as the wrappers.
        self.assertEqual(Path(harness.native_git()["executable"]), sh)

    def test_server_start_git_is_captured_and_immutable(self):
        git = str(Path(self.GIT).resolve())
        harness = self.harness(git=git, mixed_refs=True)
        self.assertIsNone(harness.server_git, "no server has started yet")
        harness.start()
        self.assertEqual(harness.server_git, {"configured": git, "path": git})
        captured = dict(harness.server_git)
        harness.native_git_probe = lambda: {"executable": git, "declared": True, "notes": [],
                                            "version": "9.9", "minor": (9, 9), "sha256": "0" * 64}
        wrapper = harness.root / "some-wrapper"
        harness.env["ROOTYARD_GIT"] = str(wrapper)
        seen = []
        saved_environ = dict(mixed_ref_cases.os.environ)

        def run(argv, cwd=None, check=True, data=None, env=None):
            seen.append(dict(env or {}))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"", args=argv)
        harness.run = run
        try:
            mixed_ref_cases.os.environ.clear()
            mixed_ref_cases.os.environ.update(harness.env)
            # A real ``git_as`` call runs the probed Git; it must not touch the
            # server env.
            import tempfile as _tempfile
            with _tempfile.TemporaryDirectory() as scratch:
                harness.work = scratch
                done = harness.git_as({"username": "alice", "token": "x"}, "ls-remote", "origin")
        finally:
            mixed_ref_cases.os.environ.clear()
            mixed_ref_cases.os.environ.update(saved_environ)
        self.assertEqual(done.returncode, 0)
        # git_as handed its own copy the client, and the live server env and the
        # process-start fact are both unchanged by it.
        self.assertEqual(seen[0]["ROOTYARD_GIT"], git)
        self.assertEqual(harness.server_git, captured)
        self.assertEqual(harness.env["ROOTYARD_GIT"], str(wrapper))

    def test_push_evidence_reports_the_started_server_git(self):
        git = str(Path(self.GIT).resolve())
        harness = self.harness(git=git, mixed_refs=True)
        harness.start()
        harness.alice = {"username": "alice", "token": "test-only"}
        harness.native_git_probe = lambda: {
            "executable": git, "declared": True, "notes": [], "version": "2.47.3",
            "minor": (2, 47), "sha256": "0" * 64}

        def simulated_client(*args, **kwargs):
            # Simulate a post-start helper changing its mutable env view. The
            # captured process-start identity must remain the proof source.
            harness.env["ROOTYARD_GIT"] = str(harness.root / "mutated-after-start")
            return SimpleNamespace(args=[git, "push"])

        harness.git_as = simulated_client
        with tempfile.TemporaryDirectory() as root:
            harness.env["ROOTYARD_DATA_DIR"] = root
            harness.push_with("main")
        bound = harness.started_server_git()
        self.assertEqual(bound, git)
        self.assertEqual(harness.git_evidence["server_git"], git)
        self.assertEqual(harness.git_evidence["server_configured"], git)
        self.assertNotEqual(harness.env["ROOTYARD_GIT"], git)

    def test_mixed_proof_rejects_a_server_not_started_on_the_declared_git(self):
        git = str(Path(self.GIT).resolve())
        harness = self.harness(git=git, mixed_refs=True)
        harness.env["ROOTYARD_GIT"] = str(harness.root / "git-fault-wrapper")
        harness.start()
        called = []
        harness.git_as = lambda *args, **kwargs: called.append(args)
        with self.assertRaises(AssertionError) as caught:
            harness.push_with("main")
        self.assertIn("did not start on the declared Git", str(caught.exception))
        self.assertEqual(called, [], "a mismatched live server must be rejected before the push")
        # An unknown start state fails closed too.
        fresh = self.harness(git=git, mixed_refs=True)
        with self.assertRaisesRegex(AssertionError, "start-time Git is unknown"):
            fresh.started_server_git()

    def test_handoff_restarts_only_when_the_server_is_not_bound(self):
        git = str(Path(self.GIT).resolve())
        harness = self.harness(git=git)
        harness.start()
        # Already bound: no restart, no env change.
        starts = len(harness.starts)
        result = harness.restore_declared_git()
        self.assertEqual(result["restarted"], False)
        self.assertEqual(len(harness.starts), starts)
        self.assertEqual(harness.env["ROOTYARD_GIT"], git)
        # The fault wrapper a fixed case leaves behind: restarted on the binding.
        harness.stop()
        wrapper = harness.root / "git-fault-wrapper"
        harness.env["ROOTYARD_GIT"] = str(wrapper)
        harness.start()
        self.assertEqual(harness.server_git["path"], str(wrapper.resolve()))
        starts = len(harness.starts)
        result = harness.restore_declared_git()
        self.assertEqual(result["restarted"], True)
        self.assertEqual(result["previous"]["path"], str(wrapper.resolve()))
        self.assertEqual(len(harness.starts), starts + 1)
        self.assertEqual(harness.starts[-1]["ROOTYARD_GIT"], git)
        self.assertEqual(harness.server_git, {"configured": git, "path": git})
        self.assertEqual(harness.started_server_git(), git)

    def test_explicit_git_is_bound_before_any_start(self):
        harness = self.harness(git=self.GIT, mixed_refs=True)
        self.assertEqual(harness.runtime_env["ROOTYARD_GIT"], self.GIT)
        self.assertEqual(harness.git_binding, {"declared": self.GIT, "env": self.GIT, "mixed_refs": True})
        self.assertIsNone(harness.proc, "construction must not start the server")
        init = inspect.getsource(browse.BrowseHarness.__init__)
        self.assertLess(init.index("_bind_declared_git"), init.index("_native_git_probe"))
        # wrapper_git comes from the validated binding; PATH is only the
        # fallback when no Git was declared.
        self.assertLess(init.index("_bind_declared_git"), init.index("self.wrapper_git ="))
        self.assertIn('self.wrapper_git = self.git_binding["declared"] or shutil.which("git") or "git"',
                      init)
        self.assertIn("self.server_git = None", init)
        self.assertIn("super().__init__(args)", init)
        self.assertIn("start", browse.BrowseHarness.__dict__)
        launch = inspect.getsource(browse.BrowseHarness.start)
        self.assertLess(launch.index("harness_start(self)"), launch.index("self.server_git ="))
        self.assertIn('self.env.get("ROOTYARD_GIT")', launch)
        # Every server start (Harness.start) therefore sees the bound value.
        self.assertIn("env=self.env", inspect.getsource(self.real_launch))

    def test_conflicting_git_declarations_are_rejected(self):
        # Two real, distinct executables: validation passes and the
        # resolve-and-compare check is what refuses the pair.
        other = shutil.which("sh") or shutil.which("sh", path="/bin")
        self.assertTrue(other)
        self.assertNotEqual(Path(other).resolve(), Path(self.GIT).resolve())
        os.environ["ROOTYARD_GIT"] = other
        with self.assertRaises(SystemExit) as caught:
            self.harness(git=self.GIT)
        self.assertIn("disagree", str(caught.exception))
        self.assertIn(str(Path(other).resolve()), str(caught.exception))
        self.assertIn(self.GIT, str(caught.exception))
        # A distinct absolute spelling of the same file is accepted once both
        # sides resolve.  ``Path(a) / "." / b`` and ``a + "/.//" + b`` normalize
        # to ``a/b``, so the fixture concatenates without building a Path.
        resolved = Path(self.GIT).resolve()
        spelling = str(resolved.parent) + "/.//" + resolved.name
        self.assertNotEqual(spelling, self.GIT)
        self.assertIn("/.//", spelling)
        self.assertEqual(Path(spelling).resolve(), resolved)
        os.environ["ROOTYARD_GIT"] = spelling
        agreeing = self.harness(git=self.GIT)
        self.assertEqual(agreeing.runtime_env["ROOTYARD_GIT"], self.GIT)
        self.assertEqual(agreeing.git_binding["declared"], self.GIT)

    def test_mixed_refs_requires_a_declared_git(self):
        with self.assertRaises(SystemExit) as caught:
            self.harness(mixed_refs=True)
        self.assertIn("--mixed-refs requires a declared --git", str(caught.exception))
        with self.assertRaises(SystemExit) as caught:
            self.harness(git="git", mixed_refs=True)
        self.assertIn("absolute", str(caught.exception))
        # An inherited ROOTYARD_GIT alone satisfies the requirement without
        # --git, is validated, and is bound to that binary before any start.
        os.environ["ROOTYARD_GIT"] = self.GIT
        inherited_only = self.harness(mixed_refs=True)
        self.assertEqual(inherited_only.git_binding, {"declared": self.GIT, "env": self.GIT,
                                                      "mixed_refs": True})
        self.assertEqual(inherited_only.runtime_env["ROOTYARD_GIT"], self.GIT)
        self.assertIsNone(inherited_only.proc, "binding must precede any server start")
        # An inherited declaration gets the same absolute/executable validation.
        os.environ["ROOTYARD_GIT"] = "git"
        with self.assertRaises(SystemExit) as caught:
            self.harness(mixed_refs=True)
        self.assertIn("ROOTYARD_GIT must be an absolute path", str(caught.exception))
        os.environ["ROOTYARD_GIT"] = str(Path(self.GIT).parent / "git-not-declared-here")
        with self.assertRaises(SystemExit) as caught:
            self.harness(mixed_refs=True)
        self.assertIn("ROOTYARD_GIT is not an executable file", str(caught.exception))
        # The fixed inventory alone needs no declaration and adds none.
        os.environ.pop("ROOTYARD_GIT")
        fixed_only = self.harness()
        self.assertIsNone(fixed_only.git_binding["declared"])
        self.assertNotIn("ROOTYARD_GIT", fixed_only.runtime_env)

    def test_wrapper_behavior_unchanged_and_restores_the_bound_git(self):
        harness = self.harness(git=self.GIT, mixed_refs=True)
        script = harness._deadline_wrapper_script(harness.wrapper_git, harness.root / "arm", harness.root / "log")
        self.assertIn("exec " + shlex.quote(harness.wrapper_git) + ' "$@"', script)
        service = ast.unparse(self.browse_class())
        body = service[service.index("def _deadline_git_service"):service.index("def _deadline_git_events")]
        self.assertIn("bound_git = self.env.get('ROOTYARD_GIT', self.git_binding['env'])", body)
        self.assertIn("self.env['ROOTYARD_GIT'] = bound_git", body)
        # ROOTYARD_GIT is no longer snapped from the inherited env and restored.
        self.assertNotIn("'ROOTYARD_GIT', 'ROOTYARD_GIT_TIMEOUT_SECONDS'", body)
        self.assertIn("if bound_git is None:\n                self.env.pop('ROOTYARD_GIT', None)",
                      body + "\n")

    class FakeHarness:
        """Records the cases ``execute`` runs, exactly as ``Harness.case`` does."""

        def __getattr__(self, name):
            if name in browse.CASE_NAMES or name in browse.MIXED_REF_CASES:
                calls = self.calls  # bound to the instance at access time

                def case():
                    calls.append(name)
                return case
            raise AttributeError(name)

        def __init__(self, args):
            self.args, self.results, self.calls, self.events = args, [], [], []
            self.git_binding = {"declared": args.git, "mixed_refs": args.mixed_refs}
            self.git_evidence = None
            self.git_handoff = None

        def restore_declared_git(self):
            self.events.append("handoff")
            return {"restarted": True, "server_git": {"path": self.args.git}}

        def case(self, name, fn):
            self.calls.append(name)
            self.events.append(name)
            self.results.append({"name": name, "status": "passed", "seconds": 0.0, "detail": {}})

        def redact(self, value):
            return str(value)

        def cleanup(self):
            pass

    def run_execute(self, argv, harness_type=None):
        """Parse real argv and run ``execute`` against a fake harness."""
        report = Path(tempfile.mkdtemp()) / "browse.json"
        self.addCleanup(shutil.rmtree, report.parent, True)
        # Real builtin defaults: FakeHarness must not leak into the namespace.
        argv = ["--report", str(report), "--binary", sys.executable, *argv]
        args = browse.build_parser().parse_args(argv)
        args.binary = str(Path(args.binary).resolve())
        built = []

        def build(value):
            harness = (harness_type or self.FakeHarness)(value)
            built.append(harness)
            return harness

        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = browse.execute(args, build)
        return code, (json.loads(report.read_text()) if report.is_file() else None), built, err.getvalue()

    def test_runner_selects_executes_and_reports_seventeen(self):
        code, report, created, err = self.run_execute(["--mixed-refs", "--git", self.GIT])
        self.assertEqual(code, 0, err)
        expected = list(browse.CASE_NAMES) + list(mixed_ref_cases.MIXED_REF_CASES)
        self.assertEqual(report["selected_cases"], expected)
        self.assertEqual(report["case_count"], 17)
        self.assertEqual(report["fixed_case_count"], 15)
        self.assertEqual(report["fixed_cases"], list(browse.CASE_NAMES))
        self.assertEqual(report["mixed_ref_cases"], list(mixed_ref_cases.MIXED_REF_CASES))
        self.assertEqual(list(report["mixed_ref_results"]), list(mixed_ref_cases.MIXED_REF_CASES))
        self.assertEqual(set(report["mixed_ref_results"].values()), {"passed"})
        self.assertEqual([item["name"] for item in report["cases"]], expected)
        self.assertEqual(created[0].calls, expected)
        self.assertEqual(created[0].events,
                         list(browse.CASE_NAMES) + ["handoff"] + list(mixed_ref_cases.MIXED_REF_CASES))
        self.assertEqual(report["git"]["declared"], self.GIT)
        self.assertEqual(report["git_handoff"], {"restarted": True, "server_git": {"path": self.GIT}})

    def test_runner_without_opt_in_is_the_fixed_inventory_only(self):
        code, report, created, err = self.run_execute([])
        self.assertEqual(code, 0, err)
        self.assertEqual(report["selected_cases"], list(browse.CASE_NAMES))
        self.assertEqual(report["case_count"], 15)
        self.assertEqual(report["mixed_ref_cases"], [])
        self.assertEqual(report["mixed_ref_results"], {})
        self.assertEqual(report["fixed_cases"], list(browse.CASE_NAMES))
        self.assertEqual(created[0].calls, list(browse.CASE_NAMES))
        self.assertEqual(created[0].events, list(browse.CASE_NAMES))

    def test_runner_rejects_mixed_refs_without_a_declared_git(self):
        os.environ.pop("ROOTYARD_GIT", None)
        with self.assertRaises(SystemExit) as caught:
            self.run_execute(["--mixed-refs"])
        self.assertIn("--mixed-refs requires a declared --git", str(caught.exception))

    def test_runner_fails_when_a_selected_case_is_not_executed(self):
        """A skipped case fails the assertion that owns it, in both modes."""
        fixed_last, mixed_last = browse.CASE_NAMES[-1], mixed_ref_cases.MIXED_REF_CASES[-1]
        base_case = self.FakeHarness.case  # captured from the base, not the subclass

        def skipping(skip):
            def case(harness, name, fn):
                if name != skip:
                    base_case(harness, name, fn)
            return type("SkippingHarness", (self.FakeHarness,), {"case": case})

        # Fixed mode: the fixed-inventory assertion owns the skip.
        code, report, built, err = self.run_execute([], skipping(fixed_last))
        self.assertEqual(code, 1, err)
        self.assertIn("native case inventory mismatch", err)
        self.assertEqual([item["name"] for item in report["cases"]], list(browse.CASE_NAMES[:-1]))
        self.assertFalse(report["passed"])
        # Opt-in mode: the fixed suite is intact, so the skip falls through the
        # fixed assertion and is caught by the selected-case completion check.
        code, report, built, err = self.run_execute(["--mixed-refs", "--git", self.GIT],
                                                    skipping(mixed_last))
        self.assertEqual(code, 1, err)
        self.assertIn("selected cases were not all executed", err)
        self.assertEqual([item["name"] for item in report["cases"]],
                         list(browse.CASE_NAMES) + [mixed_ref_cases.MIXED_REF_CASES[0]])
        self.assertEqual(report["selected_cases"], list(browse.CASE_NAMES) + list(
            mixed_ref_cases.MIXED_REF_CASES))
        self.assertFalse(report["passed"])
        # The harness ran every selected case except the skipped one.
        self.assertEqual(built[0].calls,
                         [name for name in browse.selected_cases(True) if name != mixed_last])
        self.assertEqual(built[0].events,
                         list(browse.CASE_NAMES) + ["handoff", mixed_ref_cases.MIXED_REF_CASES[0]])


class RefusalAuditSqlTest(unittest.TestCase):
    """The audit SQL names only real tables/columns; one JSON object, no split."""

    def setUp(self):
        self.pairs = dict(refusal_audit_sql.audit_pairs("'r'", ["'refs/heads/a'", "'refs/heads/b'"], "SAME"))
        self.query = refusal_audit_sql.audit_query(list(self.pairs.items()), "'r'", str)

    def test_operation_highwater_query_validates_uuid_and_quotes_once(self):
        uuid_value = "0f8fad5b-d9cb-469f-a165-70867728950e"
        expected = (
            "SELECT COALESCE(MAX(sequence), 0)::text FROM git_operations "
            "WHERE repository_id = '%s'::uuid" % uuid_value
        )

        calls = []

        def counting_escape(value):
            calls.append(value)
            return value

        sql = refusal_audit_sql.operation_highwater_query(uuid_value, counting_escape)

        self.assertEqual(sql, expected)
        self.assertEqual(sql.count(uuid_value), 1)
        self.assertEqual(calls, [uuid_value])

        for bad in (
            "",
            "not-a-uuid",
            uuid_value.upper(),
            uuid_value + "'",
            "%s' OR '1'='1" % uuid_value,
            "'; DROP TABLE git_operations; --",
        ):
            with self.subTest(value=bad):
                calls.clear()
                with self.assertRaises(ValueError) as ctx:
                    refusal_audit_sql.operation_highwater_query(bad, counting_escape)
                if bad:
                    self.assertNotIn(bad, str(ctx.exception))
                self.assertEqual(calls, [])

    def test_operations_after_query_sql_shape(self):
        repo = "11111111-1111-4111-8111-111111111111"
        actor = "22222222-2222-4222-8222-222222222222"
        token = "33333333-3333-4333-8333-333333333333"
        seen = []

        def escape(value):
            seen.append(value)
            return "ESC[" + value + "]"

        sql = refusal_audit_sql.operations_after_query(repo, 7, actor, token, escape)
        self.assertIsInstance(sql, str)
        self.assertIn("WHERE o.repository_id = 'ESC[%s]'::uuid AND o.sequence > 7" % repo, sql)
        self.assertEqual(sql.count("jsonb_agg(jsonb_build_object("), 1)
        self.assertIn("ORDER BY o.sequence, o.id", sql)
        join = "LEFT JOIN git_ref_admissions a ON a.writer_id = o.id AND a.repository_id = o.repository_id"
        self.assertIn(join, sql)
        keys = ["operation_id", "sequence", "outcome", "settled", "actor_and_token_match",
                "human_principal", "service_principal", "admission_present", "admission_state",
                "admission_settled", "admission_identity_matches", "admission_ref_names",
                "outbox_count", "outbox_ref_names", "finished", "evidence_no_receipt", "interrupted",
                "storage_generation_matches", "ungranted_without_hooks", "reference_events"]
        for key in keys:
            self.assertIn("'%s'" % key, sql)
        # Booleans stay booleans: ``->`` keeps the JSONB value in the object.
        self.assertIn("(COALESCE(o.evidence->'finished', '\"missing\"'::jsonb))", sql)
        self.assertIn("(COALESCE(o.evidence->'storage_generation_matches', '\"missing\"'::jsonb))", sql)
        self.assertNotIn("o.evidence->>'finished'", sql)
        self.assertNotIn("o.evidence->>'storage_generation_matches'", sql)
        # The two packet-line flags stay the schema-backed text.
        self.assertIn("o.evidence->>'interrupted'", sql)
        self.assertIn("o.evidence->>'ungranted_without_hooks'", sql)
        self.assertNotIn("o.evidence->'interrupted'", sql)
        self.assertIn("o.evidence->'reference_events'", sql)
        self.assertIn("o.evidence->'post_receive' IS NULL", sql)
        self.assertIn("o.evidence->'post_receive' = 'null'::jsonb", sql)
        self.assertIn("o.actor_id = 'ESC[%s]'::uuid" % actor, sql)
        self.assertIn("o.token_id = 'ESC[%s]'::uuid" % token, sql)
        self.assertNotIn("LIMIT", sql)
        self.assertNotIn("MAX(", sql)
        self.assertEqual(seen, [repo, actor, token])
        for bad_sequence in (True, "7", -1):
            with self.assertRaises(ValueError):
                refusal_audit_sql.operations_after_query(repo, bad_sequence, actor, token, escape)
        seen.clear()
        with self.assertRaises(ValueError):
            refusal_audit_sql.operations_after_query(
                "11111111-1111-4111-8111-11111111111' OR 1=1 --", 7, actor, token, escape)
        self.assertEqual(seen, [])

    def test_schema_pins_the_evidence_json_types(self):
        """``finished``/``storage_generation_matches`` are JSON booleans."""
        evidence = (ROOT / "src/reliability.rs").read_text()
        self.assertIn('"finished":finished', evidence)
        self.assertIn('"storage_generation_matches":operation.storage_generation==generation', evidence)
        self.assertEqual(refusal_audit_sql.EVIDENCE_BOOL_KEYS, ("finished", "storage_generation_matches"))
        self.assertEqual(refusal_audit_sql.EVIDENCE_TEXT_KEYS, ("interrupted", "ungranted_without_hooks"))

    def test_release_valid_query_binds_source_evidence_and_outbox(self):
        operation_id = "44444444-4444-4444-8444-444444444444"
        repo_id = "11111111-1111-4111-8111-111111111111"
        seen = []

        def escape(value):
            seen.append(value)
            return f"ESC[{value}]"

        sql = refusal_audit_sql.service_release_valid_query(operation_id, repo_id, escape)
        self.assertIsInstance(sql, str)
        self.assertEqual(seen, [operation_id, repo_id])
        self.assertIn(f"o.id = 'ESC[{operation_id}]'::uuid", sql)
        self.assertIn(f"o.repository_id = 'ESC[{repo_id}]'::uuid", sql)
        self.assertTrue(sql.lstrip().startswith("SELECT COALESCE(EXISTS ("))
        self.assertTrue(sql.endswith("), false)::text"))
        for clause in (
            "o.outcome = 'recorded'",
            "o.settled_at IS NOT NULL",
            "o.actor_id IS NULL",
            "o.token_id IS NULL",
            "o.service_principal_id IS NOT NULL",
            "o.actor_name = 'ci-scheduler'",
            "r.state = 'ready'",
            "r.storage_generation = o.storage_generation",
            "jsonb_typeof(o.evidence) = 'object'",
            "(SELECT count(*) FROM jsonb_object_keys(o.evidence)) = 7",
            "NOT (o.evidence ? 'action')",
            "o.evidence -> 'version' = '1'::jsonb",
            "o.evidence ->> 'kind' = 'observed_immutable_ci_root'",
            "jsonb_typeof(o.evidence -> 'finished') = 'boolean'",
            "o.evidence -> 'finished' = 'true'::jsonb",
            "jsonb_typeof(o.evidence -> 'interrupted') = 'boolean'",
            "o.evidence -> 'interrupted' = 'false'::jsonb",
            "jsonb_typeof(o.evidence -> 'reference_events') = 'array'",
            "o.evidence -> 'reference_events' = '[]'::jsonb",
            "jsonb_typeof(o.evidence -> 'retained') = 'boolean'",
            "o.evidence -> 'retained' = 'true'::jsonb",
            "jsonb_typeof(o.evidence -> 'intent') = 'object'",
            "(SELECT count(*) FROM jsonb_object_keys(o.evidence -> 'intent')) = 8",
            "o.evidence -> 'intent' -> 'version' = '1'::jsonb",
            "jsonb_typeof(o.evidence -> 'intent' -> 'job_id') = 'string'",
            "~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'",
            "jsonb_typeof(o.evidence -> 'intent' -> 'owner_id') = 'string'",
            "o.evidence -> 'intent' ->> 'owner_id' = r.owner_id::text",
            "jsonb_typeof(o.evidence -> 'intent' -> 'repository_id') = 'string'",
            "o.evidence -> 'intent' ->> 'repository_id' = o.repository_id::text",
            "jsonb_typeof(o.evidence -> 'intent' -> 'storage_generation') = 'number'",
            "o.evidence -> 'intent' -> 'storage_generation' = to_jsonb(o.storage_generation)",
            "jsonb_typeof(o.evidence -> 'intent' -> 'object_format') = 'string'",
            "o.evidence -> 'intent' ->> 'object_format' IN ('sha1', 'sha256')",
            "jsonb_typeof(o.evidence -> 'intent' -> 'target_oid') = 'string'",
            "~ '^[0-9a-f]{40}$'",
            "~ '^[0-9a-f]{64}$'",
            "AND (o.evidence -> 'intent' ->> 'target_oid') ~ '[1-9a-f]'",
            "jsonb_typeof(o.evidence -> 'intent' -> 'retention_ref') = 'string'",
            "o.evidence -> 'intent' ->> 'retention_ref' = 'refs/rootyard-ci/jobs/' || (o.evidence -> 'intent' ->> 'job_id')",
            "p.id = o.service_principal_id",
            "p.repository_id = o.repository_id",
            "p.kind = 'ci-pin'",
            "p.active",
            "NOT EXISTS (SELECT 1 FROM git_ref_admissions a WHERE a.writer_id = o.id)",
            "(SELECT count(*) FROM outbox_events e WHERE e.operation_id = o.id) = 1",
        ):
            self.assertIn(clause, sql, clause)
        outbox_where = (
            "SELECT 1 FROM outbox_events e\n"
            "          WHERE e.operation_id = o.id\n"
            "            AND e.repository_id = o.repository_id\n"
            "            AND e.storage_generation = o.storage_generation\n"
            "            AND e.operation_sequence = o.sequence\n"
            "            AND e.ref_name = o.evidence -> 'intent' ->> 'retention_ref'\n"
            "            AND e.new_oid = o.evidence -> 'intent' ->> 'target_oid'\n"
            "            AND e.old_oid IS DISTINCT FROM o.evidence -> 'intent' ->> 'target_oid'\n"
            "            AND (\n"
            "                (o.evidence -> 'intent' ->> 'object_format' = 'sha1'\n"
            "                 AND e.old_oid ~ '^[0-9a-f]{40}$')\n"
            "                OR\n"
            "                (o.evidence -> 'intent' ->> 'object_format' = 'sha256'\n"
            "                 AND e.old_oid ~ '^[0-9a-f]{64}$')\n"
            "            )"
        )
        self.assertIn(outbox_where, sql)
        for forbidden in ("{{", "}}", "hex_to_int", "jsonb_object_keys(o.evidence) AS k",
                          "jsonb_object_keys(o.evidence -> 'intent') AS k", "array_agg", "AS k",
                          "'action' = 'released'", "o.evidence ->> 'action'", "repeat('0'",
                          "e.old_oid = o.evidence -> 'intent' ->> 'target_oid'", "WHERE e.old_oid",
                          "e.new_oid = repeat('0'", "e.operation_id <> o.id",
                          "e.operation_id IS DISTINCT FROM o.id",
                          "(SELECT count(*) FROM outbox_events e) = 1",
                          "FROM outbox_events e\n          WHERE e.repository_id = o.repository_id",
                          "') LIKE 'refs/rootyard-ci/jobs/'", "LIMIT", "COPY", "--"):
            self.assertNotIn(forbidden, sql, forbidden)
        self.assertEqual(seen, [operation_id, repo_id])
        calls = []

        def spy(value):
            calls.append(value)
            return "ESC"

        self.assertEqual(calls, [])
        for bad_op, bad_repo in ((("not-a-uuid"), repo_id), (operation_id, "not-a-uuid"),
                                 (None, repo_id), (operation_id, None)):
            with self.assertRaises(ValueError):
                refusal_audit_sql.service_release_valid_query(bad_op, bad_repo, spy)
        self.assertEqual(calls, [])

    def test_interval_reader_binds_actual_actor_and_token_not_account_role(self):
        source_text = source("operation_rows_since")
        self.assertIn('self.alice["user_id"]', source_text)
        self.assertIn('self.alice["token_id"]', source_text)
        self.assertNotIn('self.alice["id"]', source_text)
        self.assertNotIn('self.alice["username"]', source_text)
        self.assertNotIn('self.alice["token"]', source_text)
        self.assertNotIn("users", source_text.lower())
        self.assertNotIn("string_agg", source_text.lower())
        self.assertNotIn("role", source_text.lower())
        self.assertIn('self.repo["id"]', source_text)
        self.assertIn("self._sql_literal", source_text)
        self.assertIn("decode_operation_interval(self.sql(query), highwater)", source_text)

    def test_one_json_object_from_the_newest_operation(self):
        self.assertTrue(self.query.startswith("SELECT jsonb_build_object("))
        self.assertIn(")::text FROM git_operations o LEFT JOIN git_ref_admissions a ON a.writer_id=o.id", self.query)
        self.assertIn("ORDER BY o.sequence DESC LIMIT 1", self.query)
        self.assertNotIn("chr(", self.query)
        self.assertEqual(list(self.pairs), ["status", "created_at", "outcome", "settled", "aborted",
                                            "repository_matches", "ref_names", "refs_exactly", "no_receipt",
                                            "finished", "storage_generation_matches", "interrupted",
                                            "ungranted_without_hooks", "events", "admitted_now", "newer",
                                            "reference_events"])
        # The pushed refs are the exact sorted ARRAY[...]::text[] set.
        self.assertEqual(self.pairs["refs_exactly"],
                         "coalesce(a.ref_names=ARRAY['refs/heads/a','refs/heads/b']::text[], false)")

    def columns(self, table):
        schema = "\n".join(path.read_text() for path in sorted((ROOT / "migrations").glob("*.sql")))
        block = re.search(r"CREATE TABLE (?:IF NOT EXISTS )?" + table + r" \((.*?)\n\);", schema, re.S)
        self.assertIsNotNone(block, "table " + table + " is not in the migrations")
        return set(re.findall(r"^\s+(\w+) ", block.group(1), re.M))

    def test_only_schema_tables_and_columns(self):
        schema = "\n".join(path.read_text() for path in sorted((ROOT / "migrations").glob("*.sql")))
        created = set(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)", schema))
        tables = set(re.findall(r"\b(?:FROM|JOIN)\s+(\w+)", self.query))
        self.assertEqual(tables, {"git_operations", "git_ref_admissions", "outbox_events"})
        self.assertNotIn("journal_item", schema, "no such table exists")
        self.assertLessEqual(tables, created)
        # Every ``alias.column`` belongs to the table that alias names.
        aliases = {"o": "git_operations", "a": "git_ref_admissions", "x": "outbox_events",
                   "w": "git_ref_admissions", "y": "git_operations"}
        seen = 0
        for alias, table in aliases.items():
            used = set(re.findall(r"(?<!\w)" + alias + r"\.(\w+)", self.query))
            seen += len(used)
            self.assertTrue(used, alias)
            self.assertLessEqual(used, self.columns(table), alias)
        for alias in set(re.findall(r"(?<!\w)([a-z]+)\.(\w+)", self.query.split("FROM", 1)[1])) - set(aliases):
            self.assertIn(alias[0], aliases)
        # The admission really stores a sorted ``ref_names TEXT[]``.
        self.assertIn("ref_names TEXT[] NOT NULL", (ROOT / "migrations/126_ref_admissions.sql").read_text())

    def test_operation_tables_used_by_the_interval_reader_exist(self):
        schema = "\n".join(path.read_text() for path in sorted((ROOT / "migrations").glob("*.sql")))
        for table in ("git_operations", "git_ref_admissions", "outbox_events", "repository_ref_projection"):
            self.assertIn("CREATE TABLE IF NOT EXISTS " + table + " (", schema, table)
        # ``service_principal_id`` that the release query binds is real.
        self.assertIn("ALTER TABLE git_operations ADD COLUMN service_principal_id UUID",
                      (ROOT / "migrations/109_ci_integration_jobs.sql").read_text())

    def test_evidence_flags_are_strings_not_jsonb_each(self):
        self.assertEqual(self.pairs["interrupted"], "coalesce(o.evidence->>'interrupted', 'missing')")
        self.assertNotIn("jsonb_each", self.query)
        self.assertIn("o.evidence->'post_receive'='null'::jsonb", self.pairs["no_receipt"])

    def test_interval_decoder_enforces_complete_json_contract(self):
        decode = refusal_audit_sql.decode_operation_interval

        def row(operation_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", sequence=8):
            return {"operation_id": operation_id, "sequence": sequence,
                    "outcome": "no_ref_changes", "settled": True, "finished": True,
                    "actor_and_token_match": True, "human_principal": True, "service_principal": False,
                    "evidence_no_receipt": True, "interrupted": "false", "storage_generation_matches": True,
                    "ungranted_without_hooks": "false", "reference_events": [], "admission_present": True,
                    "admission_state": "ABORTED", "admission_settled": True, "admission_identity_matches": True,
                    "admission_ref_names": ["refs/heads/main"], "outbox_count": 0, "outbox_ref_names": []}

        def reject(rows):
            with self.assertRaises(ValueError):
                decode(json.dumps(rows), 7)

        base = row()
        self.assertEqual(decode(json.dumps([]), 7), [])
        self.assertEqual(decode(json.dumps([base]), 7), [base])
        with self.assertRaises(ValueError):
            decode("{", 7)
        with self.assertRaises(ValueError):
            decode(json.dumps({}), 7)
        missing = row()
        del missing["outcome"]
        reject([missing])
        extra = row()
        extra["actor_id"] = "actor"
        reject([extra])
        invalid_uuid = row()
        invalid_uuid["operation_id"] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
        reject([invalid_uuid])
        at_highwater = row()
        at_highwater["sequence"] = 7
        reject([at_highwater])
        boolean_sequence = row()
        boolean_sequence["sequence"] = True
        reject([boolean_sequence])
        integer_settled = row()
        integer_settled["settled"] = 1
        reject([integer_settled])
        # ``finished``/``storage_generation_matches`` are JSON booleans: text fails.
        for key in refusal_audit_sql.EVIDENCE_BOOL_KEYS:
            for bad in ("true", "false", 1, None):
                wrong = row()
                wrong[key] = bad
                reject([wrong])
            missing_bool = row()
            del missing_bool[key]
            reject([missing_bool])
        # The two packet-line flags stay text: a JSON boolean fails.
        for key in refusal_audit_sql.EVIDENCE_TEXT_KEYS:
            wrong = row()
            wrong[key] = False
            reject([wrong])
        boolean_outbox_count = row()
        boolean_outbox_count["outbox_count"] = True
        reject([boolean_outbox_count])
        integer_ref = row()
        integer_ref["admission_ref_names"] = ["refs/heads/main", 1]
        reject([integer_ref])
        earlier = row(operation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", sequence=9)
        later = row(operation_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc", sequence=8)
        reject([earlier, later])
        reject([base, dict(base, sequence=9)])

    def test_operation_rows_since_decodes_interval_and_escapes_ids(self):
        repo_uuid = "11111111-1111-4111-8111-111111111111"
        actor_uuid = "22222222-2222-4222-8222-222222222222"
        token_uuid = "33333333-3333-4333-8333-333333333333"
        escaped = []
        queries = []

        def escape(value):
            escaped.append(value)
            return "E[" + value + "]"

        def sql(query):
            queries.append(query)
            return "[]"

        fake = SimpleNamespace(
            repo={"id": repo_uuid},
            alice={"user_id": actor_uuid, "token_id": token_uuid},
            _sql_literal=escape,
            sql=sql,
        )
        result = mixed_ref_cases.MixedRefPolicyCases.operation_rows_since(fake, 7)
        self.assertEqual(result, [])
        self.assertEqual(escaped, [repo_uuid, actor_uuid, token_uuid])
        self.assertEqual(len(queries), 1)
        query = queries[0]
        self.assertIn("E[" + repo_uuid + "]", query)
        self.assertIn("E[" + actor_uuid + "]", query)
        self.assertIn("E[" + token_uuid + "]", query)
        self.assertIn("o.sequence > 7", query)
        self.assertEqual(query.count("jsonb_agg(jsonb_build_object("), 1)
        self.assertNotIn("COPY", query.upper())

    def test_service_release_valid_escapes_ids_and_requires_literal_true(self):
        repo_uuid = "11111111-1111-4111-8111-111111111111"
        operation_uuid = "44444444-4444-4444-8444-444444444444"
        for raw_result, expected in (
            ("true" + chr(10), True),
            ("false" + chr(10), False),
            ("TRUE" + chr(10), False),
        ):
            escaped = []
            queries = []

            def escape(value, escaped=escaped):
                escaped.append(value)
                return "E[" + value + "]"

            def sql(query, responses=[], raw=raw_result):
                responses.append(raw)
                queries.append(query)
                return raw

            fake = SimpleNamespace(repo={"id": repo_uuid}, _sql_literal=escape, sql=sql)
            result = mixed_ref_cases.MixedRefPolicyCases.service_release_valid(
                fake, {"operation_id": operation_uuid})
            self.assertIs(result, expected)
            self.assertEqual(escaped, [operation_uuid, repo_uuid])
            self.assertEqual(len(queries), 1)
            self.assertIn("E[" + operation_uuid + "]", queries[0])
            self.assertIn("E[" + repo_uuid + "]", queries[0])


class RefusalOracleTest(unittest.TestCase):
    """Directed truth table for ``refusal_audit_sql.refusal_audit_verdict``."""

    def row(self, **changes):
        row = {"settled": True, "outcome": "no_ref_changes",
               "actor_and_token_match": True, "human_principal": True, "service_principal": False,
               "evidence_no_receipt": True, "finished": True, "interrupted": "false",
               "storage_generation_matches": True, "ungranted_without_hooks": "false",
               "reference_events": [],
               "admission_present": True, "admission_state": "ABORTED", "admission_settled": True,
               "admission_identity_matches": True,
               "admission_ref_names": ["refs/heads/main", "refs/heads/mixed-topic"],
               "outbox_count": 0, "outbox_ref_names": []}
        row.update(changes)
        return row

    def verdict(self, row, journal=None):
        journal = [] if journal is None else journal
        return refusal_audit_sql.refusal_audit_verdict(
            self.row(**row), journal, self.row()["admission_ref_names"])

    def test_exact_settled_no_ref_changes_passes(self):
        self.assertEqual(self.verdict({}), {"status": "settled", "problems": []})
        self.assertEqual(self.verdict({"reference_events": {
            "ordinal": 1, "phase": "Aborted", "changes": []}}, [])["problems"], [])
        self.assertEqual(self.verdict({"reference_events": [{
            "ordinal": 1, "phase": "Aborted", "requested": ["refs/heads/main"], "changes": []}]}, [])["problems"], [])

    def test_unknown_recorded_or_unsettled_is_never_a_pass(self):
        unsettled = self.verdict({"settled": False, "outcome": "unknown"})
        self.assertEqual(unsettled["status"], "pending", unsettled)
        self.assertEqual(unsettled["problems"], [], unsettled)
        for outcome in ("unknown", "recorded"):
            settled = self.verdict({"settled": True, "outcome": outcome})
            self.assertEqual(settled["status"], "settled", settled)
            self.assertIn("outcome", settled["problems"], settled)
        wrong_type = self.verdict({"settled": "true"})
        self.assertEqual(wrong_type["status"], "settled", wrong_type)
        self.assertIn("settled", wrong_type["problems"], wrong_type)

    def test_every_single_defect_fails(self):
        base = self.row()
        defects = (
            {"actor_and_token_match": False},
            {"human_principal": False},
            {"service_principal": True},
            {"admission_present": False},
            {"admission_state": "COMMITTED"},
            {"admission_settled": False},
            {"admission_identity_matches": False},
            {"admission_ref_names": list(reversed(base["admission_ref_names"]))},
            {"outbox_count": True},
            {"outbox_count": 1},
            {"outbox_ref_names": ["refs/heads/main"]},
            {"evidence_no_receipt": False},
            {"finished": False},
            {"finished": "true"},
            {"finished": 1},
            {"storage_generation_matches": False},
            {"storage_generation_matches": "true"},
            {"interrupted": "maybe"},
            {"ungranted_without_hooks": "maybe"},
            {"interrupted": "true", "ungranted_without_hooks": "false"},
            {"reference_events": None},
        )
        for changes in defects:
            verdict = self.verdict(changes)
            self.assertEqual(verdict["status"], "settled", (changes, verdict))
            self.assertTrue(verdict["problems"], (changes, verdict))
        verdict = self.verdict({}, journal=["op-id"])
        self.assertEqual(verdict["status"], "settled", verdict)
        self.assertTrue(verdict["problems"], verdict)
        audit = refusal_audit_sql.refusal_audit_verdict(None, [], ["refs/heads/main"])
        self.assertTrue(audit["problems"], audit)
        for key in ("actor_and_token_match", "admission_state", "outbox_count", "reference_events",
                    "finished", "storage_generation_matches"):
            row = self.row()
            del row[key]
            result = refusal_audit_sql.refusal_audit_verdict(row, [], base["admission_ref_names"])
            self.assertTrue(result["problems"], (key, result))

    def test_recorded_ref_change_is_a_defect(self):
        for evidence in (
            [{"changes": [{"ref_name": "refs/heads/main"}]}],
            {"changes": [{"ref_name": "x"}]},
            [{"changes": []}, {"changes": [{"ref_name": "refs/heads/main"}]}],
            ["not a dict"],
        ):
            problems = self.verdict({"reference_events": evidence})["problems"]
            self.assertIn("reference_event_changes", problems, evidence)
        requested_only = self.verdict({"reference_events": [{"requested": ["refs/heads/main"], "changes": []}]})
        self.assertNotIn("reference_event_changes", requested_only["problems"])

    def test_requested_is_validation_not_a_grant(self):
        for ref in ("refs/heads/main", "refs/heads/other"):
            row = {"reference_events": [{"changes": [], "requested": [ref]}]}
            self.assertEqual(self.verdict(row)["problems"], [], ref)
        source_text = CASES.read_text()
        self.assertNotIn("no_requested_window", source_text)
        self.assertNotIn("jsonb_each", source_text)

    def test_filesystem_pending_journal_is_checked_separately_from_reference_events(self):
        row_changes = {"reference_events": {"changes": []}}
        self.assertEqual(self.verdict(row_changes)["problems"], [])
        result = self.verdict(row_changes, journal=["operation-directory"])
        self.assertEqual(result["status"], "settled")
        self.assertIn("journal", result["problems"])


class EvidenceContractTest(unittest.TestCase):
    """``assert_evidence_contract`` and ``fold_operation_evidence`` pin the storage."""

    def evidence(self, **changes):
        evidence = {"finished": True, "storage_generation_matches": True,
                    "interrupted": "false", "ungranted_without_hooks": "false"}
        evidence.update(changes)
        return evidence

    def test_accepts_the_real_packet_line_evidence(self):
        self.assertEqual(refusal_audit_sql.assert_evidence_contract("t", self.evidence()),
                         self.evidence())
        self.assertEqual(refusal_audit_sql.assert_evidence_contract(
            "t", self.evidence(interrupted="true", ungranted_without_hooks="true"))["interrupted"], "true")

    def test_rejects_each_defect(self):
        for changes in ({"finished": "true"}, {"finished": 1}, {"finished": None},
                        {"storage_generation_matches": None}, {"interrupted": True},
                        {"interrupted": "missing"}, {"ungranted_without_hooks": "missing"},
                        {"interrupted": None}):
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                refusal_audit_sql.assert_evidence_contract("t", self.evidence(**changes))
        for key in refusal_audit_sql.EVIDENCE_KEYS:
            evidence = self.evidence()
            del evidence[key]
            with self.subTest(missing=key), self.assertRaises(AssertionError):
                refusal_audit_sql.assert_evidence_contract("t", evidence)
        for value in (None, [], "true"):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                refusal_audit_sql.assert_evidence_contract("t", value)

    def test_folds_only_the_named_operation(self):
        rows = [{"operation_id": "a", **self.evidence()}, {"operation_id": "b", **self.evidence()}]
        folded = refusal_audit_sql.fold_operation_evidence({"label": "t", "operation_id": "b"}, rows)
        self.assertEqual(folded, self.evidence())
        for audit, rows in (({"label": "t", "operation_id": "c"}, rows),
                            ({"label": "t", "operation_id": "a"}, rows[:1] * 2),
                            ({"label": "t", "operation_id": "a"}, [])):
            with self.subTest(audit=audit, rows=rows), self.assertRaises(AssertionError):
                refusal_audit_sql.fold_operation_evidence(audit, rows)

    def test_both_interval_audits_require_the_contract(self):
        git_interval = source_of(SQL, "audit_git_refusal_interval")
        self.assertIn("assert_evidence_contract(label, fold_operation_evidence(", git_interval)
        self.assertIn('"evidence": evidence', git_interval)
        self.assertIn('if before.get("api_refs") != after.get("api_refs")', git_interval)
        api_interval = source_of(SQL, "audit_api_refusal_interval")
        self.assertIn('"user_operation_count": len(', api_interval)
        self.assertNotIn('"user_operation_count": 0', api_interval)


class OperationsIntervalTypeRegressionTest(unittest.TestCase):
    """End to end: projected SQL -> decoder -> fold -> contract, typed as stored."""

    REPO = "11111111-1111-4111-8111-111111111111"
    ACTOR = "22222222-2222-4222-8222-222222222222"
    TOKEN = "33333333-3333-4333-8333-333333333333"
    OPERATION = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

    @staticmethod
    def projection_values():
        sql = refusal_audit_sql.operations_after_query(
            OperationsIntervalTypeRegressionTest.REPO, 7,
            OperationsIntervalTypeRegressionTest.ACTOR,
            OperationsIntervalTypeRegressionTest.TOKEN, str)
        # Every jsonb_build_object value, in projection order: "<key>", <expr>.
        pairs = re.findall(r"'([a-z_]+)', (.*?)(?=, '[a-z_]+', |\)::text)", sql)
        return dict(pairs)

    def projected(self):
        """A representative row with the runtime types the SQL projection emits.

        ``->`` yields the stored JSON value (booleans here); ``->>`` yields the
        stored text (the two packet-line flags).  A missing boolean key becomes
        the JSON string ``EVIDENCE_MISSING_BOOL``, which the decoder rejects;
        it is never mapped to ``False``.
        """
        values = self.projection_values()
        emitted = {}
        for key, expression in values.items():
            if "o.evidence->'finished'" in expression or "o.evidence->'storage_generation_matches'" in expression:
                emitted[key] = True                      # stored JSON boolean, returned by ``->``
            elif "o.evidence->>'interrupted'" in expression or "o.evidence->>'ungranted_without_hooks'" in expression:
                emitted[key] = "false"                   # stored text, returned by ``->>``
        return emitted

    def test_sql_projects_booleans_with_the_json_operator(self):
        values = self.projection_values()
        for key in refusal_audit_sql.EVIDENCE_BOOL_KEYS:
            self.assertIn("o.evidence->'" + key + "'", values[key], key)
            self.assertNotIn("o.evidence->>'" + key + "'", values[key], key)
            self.assertIn(refusal_audit_sql.EVIDENCE_MISSING_BOOL, values[key], key)
        for key in refusal_audit_sql.EVIDENCE_TEXT_KEYS:
            self.assertIn("o.evidence->>'" + key + "'", values[key], key)
            self.assertNotIn("o.evidence->'" + key + "'", values[key], key)
        self.assertEqual(sorted(self.projected()), sorted(refusal_audit_sql.EVIDENCE_KEYS))
        self.assertEqual({type(v) for v in self.projected().values()}, {bool, str})

    def row(self, **changes):
        row = {"operation_id": self.OPERATION, "sequence": 8, "outcome": "no_ref_changes",
               "settled": True, "actor_and_token_match": True, "human_principal": True,
               "service_principal": False, "evidence_no_receipt": True,
               "reference_events": [{"ordinal": 1, "phase": "Aborted", "changes": []}],
               "admission_present": True, "admission_state": "ABORTED", "admission_settled": True,
               "admission_identity_matches": True,
               "admission_ref_names": ["refs/heads/main", "refs/heads/mixed-topic"],
               "outbox_count": 0, "outbox_ref_names": []}
        row.update(self.projected())
        row.update(changes)
        return row

    def run_pipeline(self, **changes):
        """The real chain: -At JSON text -> decode -> fold -> contract."""
        raw = json.dumps([self.row(**changes)])
        self.assertIsInstance(raw, str)
        rows = refusal_audit_sql.decode_operation_interval(raw, 7)
        folded = refusal_audit_sql.fold_operation_evidence(
            {"label": "interval", "operation_id": self.OPERATION}, rows)
        return rows, folded, refusal_audit_sql.assert_evidence_contract("interval", folded)

    def test_representative_row_passes_the_whole_chain(self):
        rows, folded, contract = self.run_pipeline()
        self.assertEqual(len(rows), 1)
        self.assertEqual(folded, self.projected())
        self.assertEqual(contract, folded)
        self.assertIs(folded["finished"], True)
        self.assertIs(folded["storage_generation_matches"], True)
        self.assertEqual(folded["interrupted"], "false")
        self.assertEqual(folded["ungranted_without_hooks"], "false")
        # The verdict consumes the same decoded row without a type problem.
        self.assertEqual(refusal_audit_sql.refusal_audit_verdict(rows[0], [], rows[0]["admission_ref_names"]),
                         {"status": "settled", "problems": []})

    def test_either_boolean_as_text_breaks_the_chain(self):
        for key in refusal_audit_sql.EVIDENCE_BOOL_KEYS:
            with self.subTest(key=key):
                # The SQL projection really emits a JSON value, not text.
                self.assertIn(refusal_audit_sql.EVIDENCE_MISSING_BOOL, self.projection_values()[key])
                with self.assertRaises(ValueError):
                    refusal_audit_sql.decode_operation_interval(
                        json.dumps([self.row(**{key: "true"})]), 7)

    def test_text_at_the_contract_and_verdict_stages_is_rejected(self):
        for key in refusal_audit_sql.EVIDENCE_BOOL_KEYS:
            with self.subTest(key=key):
                folded = dict(self.projected(), **{key: "true"})
                with self.assertRaises(AssertionError):
                    refusal_audit_sql.assert_evidence_contract("interval", folded)
                verdict = refusal_audit_sql.refusal_audit_verdict(
                    self.row(**{key: "true"}), [], self.row()["admission_ref_names"])
                self.assertIn(key, verdict["problems"], verdict)

    def test_folded_bool_is_the_only_bool_family(self):
        _, folded, _ = self.run_pipeline()
        self.assertEqual({key for key in folded if isinstance(folded[key], bool)},
                         set(refusal_audit_sql.EVIDENCE_BOOL_KEYS))
        self.assertEqual({key for key in folded if isinstance(folded[key], str)},
                         set(refusal_audit_sql.EVIDENCE_TEXT_KEYS))


class FinalApiReadRegressionTest(unittest.TestCase):
    """The rows read once the refs are final are part of the proof call."""

    JOB_REF = "refs/rootyard-ci/jobs/11111111-1111-4111-8111-111111111111"
    OPERATION = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

    @staticmethod
    def snapshot(**changes):
        snapshot = {"operation_highwater": 7, "refs": [("refs/heads/main", "a")], "journal": [],
                    "state": "ready/-", "outcomes": {}, "admissions": {}, "outbox": 0,
                    "api_refs": [("refs/heads/main", "a")]}
        snapshot.update(changes)
        return snapshot

    @classmethod
    def human(cls):
        return {"operation_id": cls.OPERATION, "sequence": 8, "human_principal": True,
                "service_principal": False, "actor_and_token_match": True, "settled": False,
                "outbox_ref_names": []}

    @classmethod
    def service(cls, settled=True):
        return {"operation_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "sequence": 9,
                "human_principal": False, "service_principal": True, "actor_and_token_match": False,
                "settled": settled, "outbox_ref_names": [cls.JOB_REF]}

    def rows(self, human_on_final, service_rows=()):
        """Empty earlier reads; only the post-refs(final) read returns rows.

        ``ref_state()`` is called exactly once, by the final proof block, so a
        ``refs`` read marks the last read in this regression's trace.
        """
        reads, refs = [], []

        def operation_rows_since(highwater):
            reads.append(highwater)
            if not refs:
                return []
            return [*service_rows, self.human()] if human_on_final else list(service_rows)

        def ref_state():
            refs.append(True)
            return self.snapshot()
        return reads, operation_rows_since, ref_state

    def test_human_row_only_on_the_final_read_fails_the_audit(self):
        reads, rows_since, ref_state = self.rows(human_on_final=True)
        validated = []
        with self.assertRaisesRegex(AssertionError, "human operation row"):
            refusal_audit_sql.audit_api_refusal_interval(
                self.snapshot(), self.snapshot(), "api 403", ["refs/heads/main"], rows_since,
                lambda row: validated.append(row) or True, ref_state)
        # The pre-final read(s) were empty and the human row was never validated.
        self.assertEqual(reads, [7, 7])
        self.assertEqual(validated, [])

    def test_user_count_comes_from_the_classified_final_rows(self):
        reads, rows_since, ref_state = self.rows(human_on_final=False, service_rows=[self.service()])
        result = refusal_audit_sql.audit_api_refusal_interval(
            self.snapshot(), self.snapshot(), "api 403", ["refs/heads/main"], rows_since,
            lambda row: True, ref_state)
        self.assertEqual(result["user_operation_count"], 0)
        self.assertEqual([op["operation_id"] for op in result["service_operations"]],
                         [self.service()["operation_id"]])
        self.assertGreaterEqual(len(reads), 2)

    def test_pending_service_row_still_settles_before_the_final_proof(self):
        reads = []
        snapshots = iter([self.snapshot(refs=[("refs/heads/main", "a")]),
                          self.snapshot(refs=[("refs/heads/main", "a"), (self.JOB_REF, "b")])])

        def rows_since(highwater):
            reads.append(highwater)
            if len(reads) == 1:
                return [self.service(settled=False)]
            return [self.service(settled=True)]

        result = refusal_audit_sql.audit_api_refusal_interval(
            self.snapshot(), self.snapshot(), "api 403", ["refs/heads/main"], rows_since,
            lambda row: True, lambda: next(snapshots))
        self.assertEqual(result["user_operation_count"], 0)
        # The pending row made the audit wait (one more read) and a fresh final
        # snapshot was taken; it was never accepted as proof while unsettled.
        self.assertEqual(reads, [7, 7, 7])
        self.assertEqual(len(result["service_operations"]), 1)

    def test_unvalidated_service_row_on_the_final_read_still_fails(self):
        _, rows_since, ref_state = self.rows(human_on_final=False, service_rows=[self.service()])
        with self.assertRaisesRegex(AssertionError, "not source-validated"):
            refusal_audit_sql.audit_api_refusal_interval(
                self.snapshot(), self.snapshot(), "api 403", ["refs/heads/main"], rows_since,
                lambda row: False, ref_state)


class NativeRefusalAccountingTest(unittest.TestCase):
    def test_native_refusal_uses_highwater_interval_and_validated_service_exception(self):
        native = source("assert_one_aborted_refusal")
        compile(native, "assert_one_aborted_refusal", "exec")
        self.assertIn("audit_git_refusal_interval", native)
        helper = source_of(SQL, "audit_git_refusal_interval")
        compile(helper, "<audit_git_refusal_interval>", "exec")
        for needle in (
            'before["operation_highwater"]',
            "operation_rows_since(highwater)",
            "service_release_valid(row)",
            'refusal_audit_verdict(human, after["journal"], requested_refs)',
            '"ready/-"',
            "refs/rootyard-ci/jobs/",
            "service_ref_names",
        ):
            self.assertIn(needle, helper)
        counter_pattern = re.compile(
            r'(?:before|after)\[\s*"(?:outcomes|admissions|outbox)"\s*\]'
            r'\s*(?:==|!=|<=|>=|<|>)'
            r'|(?:==|!=|<=|>=|<|>)\s*'
            r'(?:before|after)\[\s*"(?:outcomes|admissions|outbox)"\s*\]'
        )
        self.assertIsNone(counter_pattern.search(helper),
                          "refusal interval audit must not gate on global counters")
        api = source("assert_api_refusal")
        self.assertNotIn("git_refusal_audit", api)

    def test_api_interval_allows_valid_ci_release_and_ignores_global_count_deltas(self):
        job_ref = "refs/rootyard-ci/jobs/11111111-1111-4111-8111-111111111111"
        operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        service_row = {"operation_id": operation_id, "sequence": 8, "human_principal": False,
                       "service_principal": True, "actor_and_token_match": False, "settled": True,
                       "outbox_ref_names": [job_ref]}
        before = {"operation_highwater": 7, "refs": [("refs/heads/main", "a"), (job_ref, "b")],
                  "journal": [], "state": "ready/-", "outcomes": {"recorded": 1}, "admissions": {},
                  "outbox": 1, "api_refs": [("refs/heads/main", "a")]}
        final = {"operation_highwater": 8, "refs": [("refs/heads/main", "a")],
                 "journal": [], "state": "ready/-", "outcomes": {"recorded": 2},
                 "admissions": {"ABORTED": 1}, "outbox": 2, "api_refs": [("refs/heads/main", "a")]}
        highwaters = []
        validated = []
        state_calls = []

        def rows_since(highwater):
            highwaters.append(highwater)
            return [service_row]

        def service_valid(row):
            validated.append(row["operation_id"])
            return True

        def get_state():
            state_calls.append("state")
            return final

        result = refusal_audit_sql.audit_api_refusal_interval(
            before, before, "api 403", ["refs/heads/main"], rows_since, service_valid, get_state)
        self.assertEqual(result["user_operation_count"], 0)
        self.assertEqual(result["changed_refs"], [job_ref])
        self.assertEqual(len(result["service_operations"]), 1)
        self.assertDictEqual(result["service_operations"][0],
                             {"operation_id": operation_id, "sequence": 8, "outbox_ref": job_ref})
        self.assertTrue(highwaters)
        for highwater in highwaters:
            self.assertEqual(highwater, 7)
        self.assertIn(operation_id, validated)
        self.assertTrue(state_calls)

    def test_api_interval_rejects_unsettled_human_and_unknown_rows_immediately(self):
        rows = [
            {"operation_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "sequence": 8,
             "human_principal": True, "service_principal": False, "actor_and_token_match": True,
             "settled": False, "outbox_ref_names": []},
            {"operation_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "sequence": 8,
             "human_principal": False, "service_principal": False, "actor_and_token_match": False,
             "settled": False, "outbox_ref_names": []},
        ]
        for row in rows:
            with self.subTest(row=row):
                before = {"operation_highwater": 7, "refs": [("refs/heads/main", "a")], "journal": [],
                          "state": "ready/-", "outcomes": {}, "admissions": {}, "outbox": 0}
                after = dict(before)
                calls, valid_calls, ref_state_calls = [], [], []

                def operation_rows_since(highwater):
                    calls.append(highwater)
                    return [dict(row)]

                def service_release_valid(candidate):
                    valid_calls.append(candidate)
                    return True

                def ref_state():
                    ref_state_calls.append(True)
                    return after

                with self.assertRaises(AssertionError):
                    refusal_audit_sql.audit_api_refusal_interval(
                        before, after, "api 403", ["refs/heads/main"], operation_rows_since,
                        service_release_valid, ref_state)
                self.assertEqual(len(calls), 1)
                self.assertEqual(valid_calls, [])
                self.assertEqual(ref_state_calls, [])

    def test_api_interval_rejects_unaccounted_repository_ref_change(self):
        before = {"operation_highwater": 7, "refs": [("refs/heads/main", "a"), ("refs/heads/other", "x")],
                  "journal": [], "state": "ready/-", "outcomes": {}, "admissions": {}, "outbox": 0,
                  "api_refs": [("refs/heads/main", "a")]}
        final = {**before, "refs": [("refs/heads/main", "a"), ("refs/heads/other", "y")]}

        def rows_since(highwater):
            return []

        def service_valid(row):
            raise AssertionError("service validation must not run for an empty interval")

        def get_state():
            return final

        with self.assertRaises(AssertionError):
            refusal_audit_sql.audit_api_refusal_interval(
                before, before, "api 403", ["refs/heads/main"], rows_since, service_valid, get_state)

    def test_api_interval_rejects_a_public_view_change(self):
        before = {"operation_highwater": 7, "refs": [("refs/heads/main", "a")], "journal": [],
                  "state": "ready/-", "outcomes": {}, "admissions": {}, "outbox": 0,
                  "api_refs": [("refs/heads/main", "a")]}
        final = {**before, "api_refs": [("refs/heads/main", "z")]}
        with self.assertRaisesRegex(AssertionError, "api_refs differ"):
            refusal_audit_sql.audit_api_refusal_interval(
                before, final, "api 403", ["refs/heads/main"], lambda highwater: [],
                lambda row: True, lambda: final)

    def test_native_group_uses_the_real_server_denial(self):
        native = source("native_group")
        self.assertIn('"config", "--get", "receive.denyNonFastForwards"', native)
        self.assertIn('.strip() == "true"', native)
        self.assertIn('"+" + self.first + ":" + main', native)
        self.assertIn('"--atomic"', native)
        for forbidden in ("put_rule", "policy_rule", "rule_body", "require_fast_forward"):
            self.assertNotIn(forbidden, native, forbidden)
        self.assertIn('listed.get(main) == self.third', native)


class SourceBindingTest(unittest.TestCase):
    """Physical refs only from the run-owned bare repo via stock for-each-ref."""

    def test_ref_state_reads_the_bare_repository_with_stock_for_each_ref(self):
        body = ast.unparse(method("ref_state"))
        self.assertIn("'--git-dir=' + str(self.bare)", body)
        self.assertIn("for-each-ref", body)
        self.assertIn("%(refname)%00%(objectname)", body)
        self.assertIn("self.native_git()[\'executable\']", body)
        # Never through the PATH wrapper and never through a Git config.
        self.assertNotIn("self.git(", body)
        self.assertNotIn("self.git_as(", body)
        # The public view is a separate API read, checked before/after.
        self.assertIn('self.document(self.repo_api(\'/refs\'))', body)
        self.assertLess(body.index("api_refs"), body.index("subprocess.run("))
        # The snapshot carries the physical refs, the API refs, and the bounds.
        returns = [n for n in ast.walk(method("ref_state")) if isinstance(n, ast.Return)]
        keys = {k.value for k in returns[-1].value.keys if isinstance(k, ast.Constant)}
        self.assertLessEqual({"refs", "api_refs", "journal", "state", "operation_highwater"}, keys)
        # The interval audits compare the actual (physical) refs, not the API view.
        helper = source_of(SQL, "audit_git_refusal_interval")
        self.assertIn('before_refs = {name: oid for name, oid in before["refs"]}', helper)
        api_helper = source_of(SQL, "audit_api_refusal_interval")
        self.assertIn('before_refs = dict(before["refs"])', api_helper)

    def test_ref_oids_uses_rev_parse_on_the_bare_repository(self):
        body = ast.unparse(method("ref_oids"))
        self.assertIn("\'--git-dir=\' + str(self.bare)", body)
        self.assertIn("\'rev-parse\', \'--verify\', \'-q\'", body)


class GitResolutionTest(unittest.TestCase):
    def run_resolve(self, args_git, env, path_git):
        harness = object.__new__(FixtureHarness)
        harness.args = SimpleNamespace(git=args_git)
        harness.env = dict(env)
        saved = dict(mixed_ref_cases.os.environ)
        try:
            mixed_ref_cases.os.environ.clear()
            mixed_ref_cases.os.environ.update(env)
            mixed_ref_cases.shutil.which = lambda name: path_git
            return harness.native_git()
        finally:
            mixed_ref_cases.os.environ.clear()
            mixed_ref_cases.os.environ.update(saved)

    def test_declared_git_wins_over_path(self):
        real = str(Path(sys.executable).resolve())
        resolved = self.run_resolve(real, {"ROOTYARD_GIT": real}, "/usr/bin/false-git")
        self.assertEqual(resolved["executable"], real)
        self.assertTrue(resolved["declared"])

    def test_disagreeing_declarations_fail(self):
        harness = object.__new__(FixtureHarness)
        harness.args = SimpleNamespace(git="/opt/a/git")
        harness.env = {}
        saved = dict(mixed_ref_cases.os.environ)
        try:
            mixed_ref_cases.os.environ.clear()
            mixed_ref_cases.os.environ.update({"ROOTYARD_GIT": "/opt/b/git"})
            with self.assertRaisesRegex(AssertionError, "disagree"):
                harness.native_git()
        finally:
            mixed_ref_cases.os.environ.clear()
            mixed_ref_cases.os.environ.update(saved)

    def test_implicit_path_is_recorded_as_implicit(self):
        real = str(Path(sys.executable).resolve())
        resolved = self.run_resolve(None, {}, real)
        self.assertEqual(resolved["executable"], real)
        self.assertFalse(resolved["declared"])


def dict_literals(node):
    """Every dict literal in ``node`` with constant keys/values, as plain dicts."""
    found = []
    for literal in ast.walk(node):
        if isinstance(literal, ast.Dict):
            item = {}
            for key, value in zip(literal.keys, literal.values):
                if isinstance(key, ast.Constant) and isinstance(value, ast.Constant):
                    item[key.value] = value.value
            if item:
                found.append(item)
    return found


if __name__ == "__main__":
    unittest.main()
