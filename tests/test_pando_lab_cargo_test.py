"""Exercise the CI wrapper with a fake Cargo executable and local Git only."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "run_pando_lab_cargo_test.py"
KNOWN_TESTS = (
    "config_rejects_zero_and_unsafe_values",
    "source_limit_has_fixed_retry_after_and_no_identity_leak",
    "unrelated_source_is_isolated_from_a_limited_source",
    "window_expiry_resets_only_the_elapsed_source",
    "dropping_permit_releases_capacity_without_waiting",
    "source_table_is_bounded_by_count_and_ttl",
    "forwarded_and_authorization_headers_never_change_the_peer",
    "missing_peer_is_refused_on_the_new_auth_route",
    "aborting_a_spawned_request_releases_the_permit",
)


class PandoLabCargoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        ).strip()

    def run_gate(self, code, status, phase=None, *, names=(), truncated=False, with_git=True):
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            if with_git:
                (bin_dir / "git").symlink_to(shutil.which("git"))
            if code is not None:
                fake = bin_dir / "cargo"
                fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent(code))
                fake.chmod(0o700)
            result = subprocess.run(
                [sys.executable, str(WRAPPER)], cwd=ROOT, capture_output=True, text=True,
                env={**os.environ, "PATH": directory, "PANDO_FAKE_SENTINEL": "private-value"},
                timeout=10,
            )
        self.assertEqual(result.returncode, status)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        expected = {
            "source_commit": self.commit if with_git else None,
            "stage": "cargo_test",
            "outcome": "failed" if status else "passed",
            "exit_code": status,
        }
        if phase is not None:
            expected["failure_phase"] = phase
        if phase == "test":
            expected["failed_tests"] = sorted(names)
            expected["failed_tests_truncated"] = truncated
        self.assertEqual(json.loads(result.stdout), expected)

    def test_success_preserves_argv_environment_and_working_directory(self):
        self.run_gate(f"""
            import os, sys
            assert sys.argv[1:] == ["test", "--locked", "--all-targets", "--features", "pando-lab"]
            assert os.getcwd() == {str(ROOT)!r}
            print(os.environ["PANDO_FAKE_SENTINEL"])
            print("/private/path", file=sys.stderr)
            print("error: test failed")
        """, 0)

    def test_failed_cases_emit_only_committed_test_leaf_names(self):
        self.run_gate(f"""
            import sys
            print("running 5 tests")
            print("test private_module::{KNOWN_TESTS[0]} ... FAILED")
            print("test valid_but_unknown_name ... FAILED")
            print("test /private/path::{KNOWN_TESTS[1]} ... FAILED")
            print("test new ... FAILED")
            print("failures:")
            print("test {KNOWN_TESTS[2]} ... FAILED")
            print("test result: FAILED. 0 passed; 5 failed; 0 ignored; "
                  "0 measured; 0 filtered out; finished in 0.01s")
            sys.exit(37)
        """, 37, "test", names=KNOWN_TESTS[:1])

    def test_failed_case_cap_deduplicates_and_skips_oversized_lines(self):
        rows = [f"test auth_admission::tests::{name} ... FAILED" for name in KNOWN_TESTS]
        self.run_gate(f"""
            import sys
            print("running 10 tests")
            print("x" * 4097 + {rows[-1]!r})
            for row in {[rows[0], *rows]!r}:
                print(row)
            print("error: test failed, to rerun pass `--lib`", file=sys.stderr)
            sys.exit(101)
        """, 101, "test", names=KNOWN_TESTS[:8], truncated=True)

    def test_compile_marker_is_projected_without_diagnostic_text(self):
        self.run_gate("""
            import sys
            print("\\x1b[31merror\\x1b[0m: could not compile `private-crate` (lib test)", file=sys.stderr)
            print("credential=private diagnostic", file=sys.stderr)
            sys.exit(101)
        """, 101, "compile")

    def test_unknown_text_and_oversized_marker_suffix_stay_unrecognized(self):
        self.run_gate("""
            import os, sys
            print(os.environ["PANDO_FAKE_SENTINEL"])
            print("x" * 4097 + "error: could not compile `private-crate`")
            print("error: arbitrary diagnostic /private/path", file=sys.stderr)
            sys.exit(101)
        """, 101, "unrecognized")

    def test_conflicting_markers_stay_unrecognized(self):
        self.run_gate("""
            import sys
            print("error: could not compile `private-crate`")
            print("error: test failed")
            sys.exit(101)
        """, 101, "unrecognized")

    def test_missing_cargo_uses_shell_exit_status(self):
        self.run_gate(None, 127, "infrastructure")

    def test_cargo_process_launch_marker_omits_executable_path(self):
        self.run_gate("""
            import sys
            print("error: could not execute process `/private/path` (never executed)", file=sys.stderr)
            sys.exit(101)
        """, 101, "infrastructure")

    def test_signaled_cargo_uses_shell_exit_status(self):
        self.run_gate("""
            import os, signal
            os.kill(os.getpid(), signal.SIGTERM)
        """, 143, "infrastructure")

    def test_names_are_omitted_when_the_git_source_is_unavailable(self):
        self.run_gate(f"""
            import sys
            print("running 1 test")
            print("test {KNOWN_TESTS[0]} ... FAILED")
            print("error: test failed")
            sys.exit(101)
        """, 101, "test", with_git=False)


if __name__ == "__main__":
    unittest.main()
