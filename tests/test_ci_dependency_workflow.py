"""Contract tests for the native dependency-checkout CI and manifest binding.

The native harness itself needs Linux, stock Git/Git LFS, PostgreSQL, and the
Rust binary. These tests are intentionally offline: they fail closed when the
workflow stops executing the harness, stops uploading/binding its indexed
report, drops a transitive harness digest, or stops requiring the exact
negative cases that prove dependency identity and credential boundaries.
"""
from pathlib import Path
import ast
import unittest

ROOT = Path(__file__).resolve().parents[1]
CI_YML = ROOT / ".github/workflows/ci.yml"
HARNESS = ROOT / "tests/ci_dependencies.py"
MANIFEST_COMMAND = "python3 scripts/native_report_manifest.py --mode job"
REPORT_NAME = "ci_dependencies"
REPORT_PATH = "test-results/ci-dependencies.json"

REPORTS = (
    ("ci_mirror", "tests/ci_mirror.py", "test-results/ci-mirror.json"),
    ("ci_source_pins", "tests/ci_source_pins.py", "test-results/ci-source-pins.json"),
    ("ci_job_checkouts", "tests/ci_job_checkouts.py", "test-results/ci-job-checkouts.json"),
    (REPORT_NAME, "tests/ci_dependencies.py", REPORT_PATH),
)
TRANSITIVE_HARNESSES = (
    "tests/ci_dependencies.py",
    "tests/ci_job_checkouts.py",
    "tests/ci_source_pins.py",
    "tests/ci_mirror.py",
    "tests/e2e.py",
)
REQUIRED_CASES = (
    "missing_or_corrupt_dependency_blocks_ready",
    "prepared_mirror_nested_lfs_checkout",
    "unauthorized_dependency_source_is_rejected",
    "dependency_credentials_are_scope_bound",
    "moved_submodule_branch_keeps_pinned_gitlink",
    "cancellation_revokes_all_dependency_credentials",
    "integration_claim_prepares_exact_dependencies",
    "origin_fallback_dependency_credential_boundaries",
    "unsafe_gitmodules_url_receives_no_credentials",
)
PRESERVED_BINDINGS = (
    "--report webhooks=test-results/webhooks.json",
    "--report browse=test-results/browse.json",
    "--harness tests/webhooks.py",
    "--harness tests/e2e.py",
)


def manifest_step(text):
    start = text.index(MANIFEST_COMMAND)
    end = text.find("\n      - name:", start)
    return text[start:] if end == -1 else text[start:end]


class TestCiDependencyWorkflow(unittest.TestCase):
    def setUp(self):
        self.ci_text = CI_YML.read_text(encoding="utf-8")
        self.manifest = manifest_step(self.ci_text)

    def test_ci_executes_dependency_harness_before_the_manifest(self):
        command = ("python3 tests/ci_dependencies.py --binary target/debug/rootyard "
                   "--report " + REPORT_PATH)
        self.assertEqual(self.ci_text.count(command), 1)
        self.assertLess(
            self.ci_text.index(command),
            self.ci_text.index(MANIFEST_COMMAND),
            "the dependency report must be produced before the manifest is written",
        )

    def test_each_transitive_report_is_executed_and_bound(self):
        for name, script, report in REPORTS:
            command = f"python3 {script} --binary target/debug/rootyard --report {report}"
            self.assertEqual(
                self.ci_text.count(command), 1,
                f"CI must execute {script} with its report exactly once",
            )
            self.assertLess(
                self.ci_text.index(command),
                self.ci_text.index(MANIFEST_COMMAND),
                f"{script} report must exist before the native manifest runs",
            )
            binding = f"--report {name}={report}"
            self.assertEqual(
                self.manifest.count(binding), 1,
                f"native manifest must bind {binding!r} exactly once",
            )

    def test_manifest_binds_every_transitive_harness_source(self):
        for harness in TRANSITIVE_HARNESSES:
            binding = f"--harness {harness}"
            self.assertEqual(
                self.manifest.count(binding), 1,
                f"native manifest must bind {binding!r} exactly once",
            )

    def test_manifest_requires_the_native_negative_cases(self):
        for case in REQUIRED_CASES:
            binding = f"--require-case {REPORT_NAME}={case}"
            self.assertEqual(
                self.manifest.count(binding), 1,
                f"native manifest must require {binding!r} exactly once",
            )

    def test_harness_declares_each_required_case_and_machine_report(self):
        source = HARNESS.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(HARNESS))
        methods = set()
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "DependencyCheckoutHarness":
                methods = {
                    item.name for item in node.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                break
        self.assertTrue(methods, "DependencyCheckoutHarness is missing")
        for case in REQUIRED_CASES:
            self.assertIn(case, methods, f"harness does not define required case {case!r}")
            self.assertIn(f'"{case}"', source)
        self.assertIn('parser.add_argument("--report", type=Path)', source)
        self.assertIn("binary_sha256=hashlib.sha256", source)
        self.assertIn("Path(args.binary).read_bytes()", source)

    def test_existing_native_report_gates_are_preserved(self):
        for binding in PRESERVED_BINDINGS:
            self.assertIn(binding, self.manifest)


if __name__ == "__main__":
    unittest.main()
