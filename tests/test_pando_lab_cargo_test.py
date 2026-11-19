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
    "sha256_watcher_converge_incremental_sync_and_cross_node_restore",
)
MERKLE_TEST = KNOWN_TESTS[-1]


class PandoLabCargoTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve() / "workspace"
        self.root.mkdir()
        self.receipt = self.root / "test-results/pando-lab-cargo-test.json"
        self.git = shutil.which("git")
        self.assertIsNotNone(self.git)
        git_env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

        def git(*args):
            return subprocess.check_output(
                [self.git, *args], cwd=self.root, env=git_env, text=True,
            ).strip()

        git("init", "--quiet", "--template=")
        source = self.root / "src"
        source.mkdir()
        (source / "lib.rs").write_text("".join(f"#[test]\nfn {name}() {{}}\n" for name in KNOWN_TESTS))
        git("add", "src/lib.rs")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "--quiet", "-m", "Fixture tests")
        self.commit = git("rev-parse", "HEAD")
        self.tree = git("rev-parse", "HEAD^{tree}")

    def invoke_gate(self, code, *, args=None, with_git=True, git_code=None):
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            if git_code is not None:
                fake_git = bin_dir / "git"
                fake_git.write_text(f"#!{sys.executable}\n" + textwrap.dedent(git_code))
                fake_git.chmod(0o700)
            elif with_git:
                (bin_dir / "git").symlink_to(self.git)
            invoked = bin_dir / "cargo-invoked"
            if code is not None:
                fake = bin_dir / "cargo"
                fake.write_text(
                    f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(invoked)!r}).touch()\n"
                    + textwrap.dedent(code)
                )
                fake.chmod(0o700)
            if args is None:
                args = (f"--expect-commit={self.commit}",)
            result = subprocess.run(
                [sys.executable, str(WRAPPER), *args], cwd=self.root, capture_output=True, text=True,
                env={
                    **os.environ, "PATH": directory, "PANDO_FAKE_SENTINEL": "private-value",
                    "GITHUB_SHA": self.commit,
                },
                timeout=15,
            )
            return result, invoked.exists()

    def run_gate(
        self, code, status, phase=None, *, names=(), truncated=False,
        checkpoint=None, bound=True, **invocation,
    ):
        self.receipt.unlink(missing_ok=True)
        result, invoked = self.invoke_gate(code, **invocation)
        self.assertEqual(invoked, bound and code is not None)
        self.assertEqual(result.returncode, status)
        self.assertEqual(result.stderr, "")
        outcome = "failed" if status else "passed"
        self.assertEqual(result.stdout, f"Pando lab Cargo test {outcome}\n")
        expected = {
            "source_commit": self.commit if bound else None,
            "source_tree": self.tree if bound else None,
            "stage": "cargo_test",
            "outcome": outcome,
            "exit_code": status,
        }
        if phase is not None:
            expected["failure_phase"] = phase
        if phase == "test":
            expected["failed_tests"] = sorted(names)
            expected["failed_tests_truncated"] = truncated
            if checkpoint is not None:
                expected["failure_checkpoint"] = {"stage": checkpoint[0], "class": checkpoint[1]}
        self.assertEqual(json.loads(self.receipt.read_text()), expected)

    def run_output(self, output, status, phase, **kwargs):
        code = f"import sys\nsys.stdout.write({output!r})\nsys.exit({status})"
        return self.run_gate(code, status, phase, **kwargs)

    def test_success_preserves_argv_environment_and_working_directory(self):
        self.run_gate(f"""
            import os, sys
            assert sys.argv[1:] == ["test", "--locked", "--all-targets", "--features", "pando-lab"]
            assert os.getcwd() == {str(self.root)!r}
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

    def test_named_merkle_case_projects_exact_captured_block(self):
        # Actual pinned-fork shapes: legacy deps (absolute shared cache) and the
        # default new build layout (relative target dir). Each case has a prior
        # successful non-target harness using the other layout and the same leaf.
        cases = (
            (
                "legacy-target-new-non-target",
                "/home/runner/.cargo/targets/rootyard-ec2a3e00/debug/deps/workspace_merkle_sync-0123456789abcdef",
                "/home/runner/.cargo/targets/rootyard-ec2a3e00/debug/build/rootyard/0e80d81c87db4057/out/rootyard-c512e8eeea7428b7",
                "error: test failed, to rerun pass `--test workspace_merkle_sync`",
                "0 filtered out",
            ),
            (
                "new-target-legacy-non-target",
                "target/debug/build/rootyard/0e80d81c87db4057/out/workspace_merkle_sync",
                "target/debug/deps/rootyard-c512e8eeea7428b7",
                "error: test failed, to rerun pass `-p rootyard --test workspace_merkle_sync`",
                "1 filtered out",
            ),
        )
        for name, target_exe, prior_exe, footer, filtered in cases:
            with self.subTest(case=name):
                output = f"""     Running unittests src/lib.rs ({prior_exe})

running 1 test
test {MERKLE_TEST} ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/workspace_merkle_sync.rs ({target_exe})

running 2 tests
test {MERKLE_TEST} ... FAILED
test {KNOWN_TESTS[1]} ... ok

failures:

---- {MERKLE_TEST} stdout ----
rootyard-merkle-checkpoint stage=base_capture class=not_quiescent
Error: private diagnostic /private/path

failures:
    {MERKLE_TEST}

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; {filtered}; finished in 0.01s

{footer}
"""
                self.run_output(
                    output, 101, "test", names=(MERKLE_TEST,),
                    checkpoint=("base_capture", "not_quiescent"),
                )

    def test_named_merkle_case_accepts_rootyard_package_footer(self):
        marker = "rootyard-merkle-checkpoint stage=base_capture class=not_quiescent"
        output = self.merkle_harness_output(
            marker,
            footer=(
                "error: test failed, to rerun pass "
                "`-p rootyard --test workspace_merkle_sync`"
            ),
        )
        self.run_output(
            output, 101, "test", names=(MERKLE_TEST,),
            checkpoint=("base_capture", "not_quiescent"),
        )

    def test_named_merkle_case_rejects_filtered_second_failure(self):
        output = f"""     Running tests/workspace_merkle_sync.rs (/workspace/rootyard/target/debug/deps/workspace_merkle_sync-0123456789abcdef)

running 2 tests
test {MERKLE_TEST} ... FAILED
test valid_but_unknown_name ... FAILED

failures:

---- {MERKLE_TEST} stdout ----
rootyard-merkle-checkpoint stage=base_capture class=not_quiescent

---- valid_but_unknown_name stdout ----
Error: private diagnostic

failures:
    {MERKLE_TEST}
    valid_but_unknown_name

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

error: test failed, to rerun pass `--test workspace_merkle_sync`
"""
        self.run_output(output, 101, "test", names=(MERKLE_TEST,))

    def test_named_merkle_case_rejects_second_failed_harness(self):
        output = f"""     Running tests/other_harness.rs (/workspace/rootyard/target/debug/deps/other_harness-0123456789abcdef)

running 1 test
test {KNOWN_TESTS[0]} ... FAILED

failures:

---- {KNOWN_TESTS[0]} stdout ----
Error: private diagnostic

failures:
    {KNOWN_TESTS[0]}

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

error: test failed, to rerun pass `--test other_harness`

     Running tests/workspace_merkle_sync.rs (/workspace/rootyard/target/debug/deps/workspace_merkle_sync-0123456789abcdef)

running 1 test
test {MERKLE_TEST} ... FAILED

failures:

---- {MERKLE_TEST} stdout ----
rootyard-merkle-checkpoint stage=base_capture class=not_quiescent

failures:
    {MERKLE_TEST}

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

error: test failed, to rerun pass `--test workspace_merkle_sync`
"""
        self.run_output(output, 101, "test", names=(KNOWN_TESTS[0], MERKLE_TEST))

    def test_named_merkle_case_separates_earlier_harness_with_same_leaf(self):
        output = f"""     Running tests/other_harness.rs (/workspace/rootyard/target/debug/deps/other_harness-0123456789abcdef)

running 1 test
test {MERKLE_TEST} ... FAILED

failures:

---- {MERKLE_TEST} stdout ----
rootyard-merkle-checkpoint stage=setup class=io

failures:
    {MERKLE_TEST}

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

error: test failed, to rerun pass `--test other_harness`

     Running tests/workspace_merkle_sync.rs (/workspace/rootyard/target/debug/deps/workspace_merkle_sync-0123456789abcdef)

running 1 test
test {MERKLE_TEST} ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
        self.run_output(output, 101, "test", names=(MERKLE_TEST,))

    def merkle_harness_output(
        self, body, *, summary_failed=1, summary_passed=1, running_count=2,
        include_summary=True, extra="", filtered_out=0,
        footer="error: test failed, to rerun pass `--test workspace_merkle_sync`",
        failed_row=None, source="tests/workspace_merkle_sync.rs",
        executable="target/debug/build/rootyard/0e80d81c87db4057/out/workspace_merkle_sync-0123456789abcdef",
    ):
        failed_row = failed_row or f"test {MERKLE_TEST} ... FAILED"
        summary = (
            f"test result: FAILED. {summary_passed} passed; {summary_failed} failed; "
            f"0 ignored; 0 measured; {filtered_out} filtered out; finished in 0.01s\n\n"
            if include_summary else ""
        )
        footer_line = f"{footer}\n" if footer else ""
        return (
            f"     Running {source} ({executable})\n\n"
            f"running {running_count} tests\n"
            f"{failed_row}\n"
            f"test {KNOWN_TESTS[0]} ... ok\n\n"
            f"failures:\n\n"
            f"---- {MERKLE_TEST} stdout ----\n"
            f"{body}\n\n"
            f"failures:\n"
            f"    {MERKLE_TEST}\n\n"
            f"{extra}{summary}{footer_line}"
        )

    def test_named_merkle_case_rejects_unbound_or_malformed_checkpoints(self):
        marker = "rootyard-merkle-checkpoint stage=base_capture class=not_quiescent"
        cases = {
            "unknown stage": self.merkle_harness_output(
                "rootyard-merkle-checkpoint stage=private_stage class=unknown"),
            "unknown class": self.merkle_harness_output(
                "rootyard-merkle-checkpoint stage=base_capture class=private_class"),
            "trailing text": self.merkle_harness_output(marker + " /private/path"),
            "duplicate markers": self.merkle_harness_output(marker + "\n" + marker),
            "oversized marker line": self.merkle_harness_output("x" * 4097 + marker),
            "missing summary": self.merkle_harness_output(marker, include_summary=False),
            "contradictory count": self.merkle_harness_output(marker, summary_failed=2),
            "unbound marker": self.merkle_harness_output(marker, extra=marker + "\n"),
        }
        for context, output in cases.items():
            with self.subTest(context=context):
                self.run_output(output, 101, "test", names=(MERKLE_TEST,))

    def test_named_merkle_case_rejects_foreign_or_generic_footer(self):
        marker = "rootyard-merkle-checkpoint stage=base_capture class=not_quiescent"
        cases = {
            "foreign test footer": "error: test failed, to rerun pass `--test other_harness`",
            "generic test footer": "error: test failed",
            "foreign package footer": (
                "error: test failed, to rerun pass `-p other --test workspace_merkle_sync`"
            ),
        }
        for context, footer in cases.items():
            with self.subTest(context=context):
                output = self.merkle_harness_output(marker, footer=footer)
                self.run_output(output, 101, "test", names=(MERKLE_TEST,))

    def test_named_merkle_case_rejects_module_qualified_failed_row(self):
        marker = "rootyard-merkle-checkpoint stage=base_capture class=not_quiescent"
        output = self.merkle_harness_output(
            marker,
            failed_row=f"test foreign_module::{MERKLE_TEST} ... FAILED",
        )
        self.run_output(output, 101, "test", names=(MERKLE_TEST,))

    def test_named_merkle_case_rejects_contradictory_libtest_totals(self):
        marker = "rootyard-merkle-checkpoint stage=base_capture class=not_quiescent"
        cases = {
            "running count exceeds summary total": self.merkle_harness_output(
                marker, running_count=3),
            "summary total exceeds running count": self.merkle_harness_output(
                marker, summary_passed=2),
        }
        for context, output in cases.items():
            with self.subTest(context=context):
                self.run_output(output, 101, "test", names=(MERKLE_TEST,))

    def test_named_merkle_case_rejects_foreign_layout_identity(self):
        marker = "rootyard-merkle-checkpoint stage=base_capture class=not_quiescent"
        cases = {
            "foreign package new layout": self.merkle_harness_output(
                marker,
                executable=(
                    "target/debug/build/foreign/0e80d81c87db4057/out/"
                    "workspace_merkle_sync-0123456789abcdef"
                ),
            ),
            "foreign binary new layout": self.merkle_harness_output(
                marker,
                executable=(
                    "target/debug/build/rootyard/0e80d81c87db4057/out/"
                    "other_harness-0123456789abcdef"
                ),
            ),
            "foreign harness new layout": self.merkle_harness_output(
                marker,
                source="tests/other_harness.rs",
                executable=(
                    "target/debug/build/rootyard/0e80d81c87db4057/out/"
                    "workspace_merkle_sync-0123456789abcdef"
                ),
            ),
            "foreign harness legacy layout": self.merkle_harness_output(
                marker,
                source="tests/other_harness.rs",
                executable="target/debug/deps/workspace_merkle_sync-0123456789abcdef",
            ),
        }
        for context, output in cases.items():
            with self.subTest(context=context):
                self.run_output(output, 101, "test", names=(MERKLE_TEST,))

    def test_named_merkle_case_rejects_marker_outside_target_block(self):
        output = f"""     Running tests/workspace_merkle_sync.rs (/workspace/rootyard/target/debug/deps/workspace_merkle_sync-0123456789abcdef)

running 2 tests
test {MERKLE_TEST} ... FAILED
test {KNOWN_TESTS[0]} ... FAILED

failures:

---- {MERKLE_TEST} stdout ----
Error: private diagnostic

---- {KNOWN_TESTS[0]} stdout ----
rootyard-merkle-checkpoint stage=base_capture class=not_quiescent

failures:
    {MERKLE_TEST}
    {KNOWN_TESTS[0]}

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

error: test failed, to rerun pass `--test workspace_merkle_sync`
"""
        self.run_output(output, 101, "test", names=(MERKLE_TEST, KNOWN_TESTS[0]))

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

    def test_invalid_source_binding_never_invokes_successful_cargo(self):
        contexts = {
            "omitted expected commit": {"args": ()},
            "missing expected commit value": {"args": ("--expect-commit",)},
            "empty expected commit": {"args": ("--expect-commit=",)},
            "symbolic expected commit": {"args": ("--expect-commit", "HEAD")},
            "mismatched expected commit": {"args": ("--expect-commit", "0" * 40)},
            "missing Git": {"with_git": False},
            "invalid Git HEAD": {"git_code": "print('private invalid HEAD')"},
            "invalid Git tree": {"git_code": f"""
                import sys
                print({self.commit!r} if sys.argv[-1] == "HEAD^{{commit}}" else "private invalid tree")
            """},
        }
        for context, invocation in contexts.items():
            with self.subTest(context=context):
                self.run_gate("raise SystemExit(0)", 1, "source_binding", bound=False, **invocation)

    def test_receipt_destination_failure_preserves_cargo_failure_and_rejects_success(self):
        self.receipt.mkdir(parents=True)
        for cargo_status, expected_status in ((0, 1), (37, 37)):
            with self.subTest(cargo_status=cargo_status):
                result, invoked = self.invoke_gate(f"raise SystemExit({cargo_status})")
                self.assertTrue(invoked)
                self.assertEqual(result.returncode, expected_status)
                self.assertEqual(result.stderr, "")
                self.assertEqual(result.stdout, "Pando lab Cargo test receipt could not be written\n")
                self.assertEqual(list(self.receipt.parent.iterdir()), [self.receipt])


if __name__ == "__main__":
    unittest.main()
