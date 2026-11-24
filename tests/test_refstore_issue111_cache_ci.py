"""Source-only guard for the manual issue #111 cache native CI checkpoint."""
from pathlib import Path
import ast
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "refstore-protocol-acceptance.yml"
SCRIPT = ROOT / "scripts" / "refstore_issue111_cache_proof.py"

CACHE_STEP = 'Exercise issue #111 exact commit-cache HTTP proof on the manual owned ref'
EXACT_REF = 'refs/heads/codex/goal-issue111-original-ac-source-audit-20261117'
CASES = (
    'blob_git_gateway::session_http_acceptance::cache_tests::exact_commit_http_warm_miss_then_actual_hit_is_byte_equal',
    'blob_git_gateway::session_http_acceptance::cache_tests::exact_commit_http_hit_still_enforces_final_live_authorization',
    'blob_git_gateway::session_http_acceptance::cache_tests::exact_commit_http_hit_still_enforces_restore_incarnation_fence',
    'blob_git_gateway::session_http_acceptance::cache_tests::exact_commit_http_cached_oid_is_not_served_after_it_becomes_unreachable',
)


def step_bounds(text, name):
    marker = '- name: "' + name + '"'
    start = text.index(marker)
    next_step = text.find('\n      - name: "', start + len(marker))
    end = len(text) if next_step == -1 else next_step + 1
    return start, end


def step(text, name):
    start, end = step_bounds(text, name)
    return text[start:end]


class Issue111CacheCiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding='utf-8')
        cls.script = SCRIPT.read_text(encoding='utf-8')
        cls.cache_step = step(cls.workflow, CACHE_STEP)

    def test_step_is_manual_exact_ref_after_original_18_and_before_cleanup(self):
        session = step(self.workflow, 'Exercise the #174 HTTP foundation cases against the owned database and Blob fixture')
        cleanup = step(self.workflow, 'Drop only the run-owned #174 foundation database')
        start, _ = step_bounds(self.workflow, CACHE_STEP)
        self.assertLess(self.workflow.index(session), start)
        self.assertLess(start, self.workflow.index(cleanup))
        self.assertIn("github.event_name == 'workflow_dispatch'", self.cache_step)
        self.assertIn("github.ref == '" + EXACT_REF + "'", self.cache_step)
        self.assertIn('success()', self.cache_step)
        self.assertNotIn('pull_request', self.cache_step)

    def test_existing_174_selector_list_is_untouched(self):
        session = step(self.workflow, 'Exercise the #174 HTTP foundation cases against the owned database and Blob fixture')
        self.assertNotIn('cache_tests', session)
        public_case = (
            'blob_git_gateway::session_http_acceptance::public_operation_tests::'
            'public_operation_get_is_owned_pending_and_private_safe'
        )
        self.assertEqual(session.count(public_case), 2)
        self.assertEqual(session.replace(public_case, '').count('blob_git_gateway::session_http_acceptance'), 26)
        self.assertIn(
            'blob_git_gateway::admission_race_acceptance::pre_admission_revision_mismatch_rebases_to_old_oid_mismatch',
            session,
        )

    def test_owned_database_and_blob_prefix_are_exact_run_attempt_inputs(self):
        for marker in (
            'ROOTYARD_TEST_OWNED_DISPOSABLE_POSTGRES=1',
            'ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB=1',
            'ROOTYARD_CACHE_ENVIRONMENT="session174-cache"',
            'ROOTYARD_ISSUE111_CACHE_SCOPE="session174-cache-4-cases"',
            'ROOTYARD_BLOB_ROOT="session174-cache-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
            'expected_db="${SESSION174_DATABASE_PREFIX}_r${GITHUB_RUN_ID}_a${GITHUB_RUN_ATTEMPT}"',
            'if [ "${SESSION174_DATABASE:-}" != "$expected_db" ]',
            'postgres|rootyard_protocol|template*',
            'ROOTYARD_174_LIB_ALIAS',
            'ROOTYARD_174_LIB_RECEIPT',
        ):
            self.assertIn(marker, self.cache_step)

    def test_runner_and_four_exact_selectors_are_wired_to_the_immutable_lib(self):
        self.assertIn('python3 scripts/refstore_issue111_cache_proof.py', self.cache_step)
        self.assertIn('--preflight "$preflight"', self.cache_step)
        self.assertIn('--expected-commit "$GITHUB_SHA"', self.cache_step)
        self.assertIn('--database "$SESSION174_DATABASE"', self.cache_step)
        self.assertIn('--scope "$ROOTYARD_ISSUE111_CACHE_SCOPE"', self.cache_step)
        self.assertIn('--report "$evidence/cache-report.json"', self.cache_step)
        self.assertIn('--summary-log "$evidence/cache-summary.log"', self.cache_step)
        for case in CASES:
            self.assertIn(case, self.cache_step)
        module = ast.parse(self.script)
        cases_node = next(
            node
            for node in module.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == 'CASES'
        )
        self.assertEqual(ast.literal_eval(cases_node.value), CASES)
        self.assertGreaterEqual(self.script.count('"status": "failed"'), 4)

    def test_receipts_manifest_and_existing_artifact_are_bounded_and_always_collected(self):
        for marker in (
            'scripts/collect_evidence_receipts.py',
            'scripts/native_report_manifest.py --mode job',
            '--build-receipt "$evidence/session174-lib-tests.build.json"',
            '--binary "$lib"',
            '--manifest-out "$evidence/cache-native-job.json"',
            '--fixture-rust-from-receipt',
            '--fixture postgres=postgres:17',
            '--log-marker "cache-summary=session174 cache proof: 4/4 passed; 0 failed; 0 skipped"',
            'test-results/refstore/session174-cache',
        ):
            self.assertIn(marker, self.cache_step)
        self.assertEqual(self.cache_step.count('--require-case "cache='), 4)
        self.assertIn('name: refstore-protocol-native-${{ github.run_id }}-${{ github.run_attempt }}', self.workflow)
        upload = self.workflow[self.workflow.index('      - uses: actions/upload-artifact@v4'):]
        self.assertIn('if: always()', upload)
        self.assertIn('test-results/refstore/', upload)

    def test_runner_uses_existing_bounded_group_runner_and_writes_no_raw_output(self):
        self.assertLess(len(SCRIPT.read_text(encoding='utf-8').splitlines()), 500)
        self.assertEqual(self.script.count('.write_text('), 2)
        self.assertIn('import issue107_native11_runner as bounded_runner', self.script)
        self.assertIn('bounded_runner.run_bounded(', self.script)
        self.assertIn('timeout=CASE_TIMEOUT_SECONDS', self.script)
        self.assertIn('env=os.environ.copy()', self.script)
        self.assertIn('[lib, "--ignored", "--exact", name, "--test-threads=1"]', self.script)
        self.assertNotIn('subprocess.run(', self.script)
        self.assertNotIn('subprocess.Popen(', self.script)
        self.assertNotIn('capture_output', self.script)
        for code in ('native_timeout', 'native_process_failed', 'native_output_too_large', 'cleanup_unresolved'):
            self.assertIn(code, self.script)
        for code in (
            '"runner_failed"',
            '"internal_error"',
            '"proof_refused"',
            '"receipt_refused"',
            '"source_git_failed"',
            '"io_error"',
            '"validation_failed"',
        ):
            self.assertIn(code, self.script)
        self.assertIn('FAILURE_CODES.get', self.script)
        self.assertIn('"summary_count"', self.script)
        self.assertIn('"summary_not_exact_one"', self.script)
        self.assertIn('"case_outcome_missing"', self.script)
        for forbidden in ('process.stdout)', 'process.stderr)', 'print(combined)', 'ACCESS_KEY', 'SECRET_KEY'):
            self.assertNotIn(forbidden, self.script)
        self.assertIn('report_path.write_text(json.dumps(report', self.script)
        self.assertIn('summary_path.write_text(summary', self.script)

    def test_report_carries_checked_tree_and_source_build_anchors(self):
        for marker in (
            'receipts.git_state(ROOT)',
            'source.get("commit") != args.expected_commit',
            'source.get("tree")',
            '"source_commit": source["commit"]',
            '"source_tree": source_tree',
            '"build_receipt_sha256": validated.receipt_sha256',
            '"preflight_sha256": sha256(preflight_path)',
            'SCOPE = "session174-cache-4-cases"',
        ):
            self.assertIn(marker, self.script)
        self.assertIn('"scope": args.scope', self.script)

    def test_manual_step_has_no_remote_or_push_action(self):
        for forbidden in ('git push', 'git remote', 'gh pr'):
            self.assertNotIn(forbidden, self.cache_step)


if __name__ == '__main__':
    unittest.main()
