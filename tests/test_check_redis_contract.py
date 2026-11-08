"""Unit guards for scripts/check_redis_contract.py without Docker or Cargo.

These tests use fake command results to prove libtest/failure parsing, report
redaction, Docker port parsing, cleanup ownership, and stale-build rejection.
The real Redis container is exercised only by the optional CI job.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import check_redis_contract as gate  # noqa: E402

SECRET = "ab" * 32
URL = f"rediss://rootyard:{SECRET}@127.0.0.1:6380/0"


def completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def libtest(cases, *, passed=None, failed=None, ignored=None):
    passed = sum(1 for _name, state in cases if state == "ok") if passed is None else passed
    failed = sum(1 for _name, state in cases if state == "FAILED") if failed is None else failed
    ignored = sum(1 for _name, state in cases if state == "ignored") if ignored is None else ignored
    lines = [f"test {name} ... {state}" for name, state in cases]
    status = "ok" if failed == 0 else "FAILED"
    lines.append(
        f"test result: {status}. {passed} passed; {failed} failed; {ignored} ignored; "
        f"0 measured; 200 filtered out; finished in 0.01s")
    return "\n".join(lines) + "\n"


class RedactionTest(unittest.TestCase):
    def test_secret_url_and_private_key_are_removed(self):
        text = f"connect {URL}\npassword={SECRET}\n-----BEGIN PRIVATE KEY-----\nxx\n-----END PRIVATE KEY-----\n"
        safe = gate.redact(text, (SECRET,))
        self.assertNotIn(SECRET, safe)
        self.assertNotIn("rediss://", safe)
        self.assertNotIn("PRIVATE KEY", safe)

    def test_unsafe_documents_are_refused(self):
        with self.assertRaises(gate.RunnerError):
            gate.assert_safe({"x": URL}, ())
        with self.assertRaises(gate.RunnerError):
            gate.assert_safe({"x": SECRET}, (SECRET,))
        with self.assertRaises(gate.RunnerError):
            gate.assert_safe({"x": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"}, ())


class LibtestParseTest(unittest.TestCase):
    def cases(self):
        return [(name, "ok") for name in sorted(gate.EXPECTED_CASES)]

    def parse(self, text, **overrides):
        arguments = dict(expected_cases=gate.EXPECTED_CASES,
                         expected_passed=gate.TEST_CASE_COUNT)
        arguments.update(overrides)
        return gate.parse_libtest(text, **arguments)

    def test_six_passed_zero_failed_zero_ignored_is_accepted(self):
        parsed = self.parse(libtest(self.cases()))
        self.assertEqual([6, 0, 0], [parsed["passed"], parsed["failed"], parsed["ignored"]])
        self.assertEqual(set(gate.EXPECTED_CASES), set(parsed["cases"]))

    def test_zero_passed_or_skip_cannot_be_a_pass(self):
        with self.assertRaisesRegex(gate.RunnerError, "zero passing"):
            self.parse(libtest([(name, "ignored") for name in gate.EXPECTED_CASES],
                               passed=0, ignored=6))
        skipped_one = libtest([(sorted(gate.EXPECTED_CASES)[0], "ignored")] + self.cases()[1:])
        with self.assertRaisesRegex(gate.RunnerError, "ignored"):
            self.parse(skipped_one, expected_passed=5)

    def test_duplicate_missing_and_non_json_summary_are_rejected(self):
        name = sorted(gate.EXPECTED_CASES)[0]
        duplicate = libtest(self.cases()) + f"test {name} ... ok\n"
        with self.assertRaisesRegex(gate.RunnerError, "duplicate"):
            self.parse(duplicate)
        with self.assertRaisesRegex(gate.RunnerError, "case set mismatch"):
            self.parse(libtest(self.cases()[:-1]))
        with self.assertRaisesRegex(gate.RunnerError, "summary"):
            self.parse("test only text\n")

    def test_expected_failure_case_is_exact(self):
        text = libtest([(gate.NEGATIVE_CASE, "FAILED")], passed=0, failed=1, ignored=0)
        parsed = self.parse(text, expected_cases=frozenset({gate.NEGATIVE_CASE}),
                            expected_passed=0, expected_failed=1, require_nonzero=False)
        self.assertEqual([gate.NEGATIVE_CASE], parsed["failed_cases"])
        with self.assertRaises(gate.RunnerError):
            gate.parse_libtest(text, expected_cases=frozenset({gate.NEGATIVE_CASE + "_x"}),
                               expected_passed=0, expected_failed=1, require_nonzero=False)
class DockerPortTest(unittest.TestCase):
    def test_only_one_ipv4_loopback_ephemeral_mapping_is_accepted(self):
        self.assertEqual(49165, gate.parse_docker_port("127.0.0.1:49165\n", 6379))
        for value in ("0.0.0.0:49165", "127.0.0.1:0", "127.0.0.1:99999",
                      "127.0.0.1:1\n127.0.0.1:2", "localhost:49165"):
            with self.assertRaises(gate.RunnerError):
                gate.parse_docker_port(value, 6379)


class BuildReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.executable = Path(self.temporary.name) / "rootyard-lib-test"
        self.executable.write_bytes(b"test-binary")

    def events(self, *, fresh=False, include_artifact=True):
        events = [{"reason": "build-finished", "success": True}]
        if include_artifact:
            events.insert(0, {
                "reason": "compiler-artifact",
                "target": {"name": "rootyard", "kind": ["lib"]},
                "profile": {"test": True, "debuginfo": 0},
                "fresh": fresh,
                "executable": str(self.executable),
            })
        return "\n".join(json.dumps(event) for event in events) + "\n"

    def fake_run(self, command, **_kwargs):
        if command == gate.BUILD_COMMAND:
            return completed(stdout=self.events())
        if command == gate.CLEAN_COMMAND:
            return completed()
        if command == ["git", "rev-parse", "HEAD"]:
            return completed(stdout="deadbeef\n")
        if command == ["rustc", "--version"]:
            return completed(stdout="rustc 1.99.1 (fake)\n")
        raise AssertionError(command)

    def build(self, *, source_after="before", runner=None):
        runner = runner or self.fake_run
        with mock.patch.object(gate.build_native, "source_digest",
                               side_effect=["before", source_after]), \
             mock.patch.object(gate, "run_command", side_effect=runner):
            return gate.build_libtest()

    def test_fresh_false_profile_test_executable_binds_source(self):
        receipt = self.build()
        self.assertIs(False, receipt["fresh"])
        self.assertIs(True, receipt["profile_test"])
        self.assertEqual("before", receipt["source_inputs_sha256"])
        self.assertEqual(str(self.executable.resolve()), receipt["executable"])
        self.assertEqual(gate.BUILD_COMMAND, receipt["command"])
        self.assertIn("profile.test.package.rootyard.debug=0", receipt["command"])
        self.assertIn('profile.dev.package.rootyard.strip="debuginfo"', receipt["command"])

    def test_stale_source_or_fresh_artifact_is_rejected(self):
        with self.assertRaisesRegex(gate.RunnerError, "source inputs changed"):
            self.build(source_after="different")

        def fresh(command, **_kwargs):
            if command == gate.BUILD_COMMAND:
                return completed(stdout=self.events(fresh=True))
            return self.fake_run(command)
        with self.assertRaisesRegex(gate.RunnerError, "Fresh"):
            self.build(runner=fresh)

    def test_missing_artifact_and_non_json_are_rejected(self):
        with self.assertRaisesRegex(gate.RunnerError, "exactly one"):
            self.build(runner=lambda command, **kwargs: completed(
                stdout=self.events(include_artifact=False))
                if command == gate.BUILD_COMMAND else self.fake_run(command))
        with self.assertRaisesRegex(gate.RunnerError, "non-JSON"):
            self.build(runner=lambda command, **kwargs: completed(stdout="not-json\n")
                if command == gate.BUILD_COMMAND else self.fake_run(command))


class CleanupOwnershipTest(unittest.TestCase):
    def setUp(self):
        self.cid = "c" * 64
        self.rm_calls = []
        self.fixture = gate.OwnedRedisFixture(
            docker_runner=lambda *_args, **_kwargs: "", command_runner=self.raw)
        self.original_nonce = self.fixture.nonce

    def raw(self, command, **_kwargs):
        if command[1] == "inspect":
            fmt = command[5]
            if fmt == "{{.Id}}":
                return completed(stdout=self.cid + "\n")
            for label in ("kind", "nonce", "directory", "uid", "name"):
                if f"rootyard.fixture.{label}" in fmt:
                    value = {
                        "kind": "owned-redis", "nonce": self.original_nonce,
                        "directory": str(self.fixture.directory),
                        "uid": str(os.getuid()), "name": self.fixture.name,
                    }[label]
                    return completed(stdout=value + "\n")
            return completed(returncode=1, stderr="unexpected format\n")
        if command[1] == "rm":
            self.rm_calls.append(command)
            return completed()
        return completed(returncode=1, stderr="unexpected command\n")

    def test_cleanup_removes_only_the_created_id(self):
        self.fixture.cid = self.cid
        self.assertEqual([], self.fixture.stop())
        self.assertEqual([["docker", "rm", "-f", "--", self.cid]], self.rm_calls)
        self.assertFalse(self.fixture.directory.exists())

    def test_label_mismatch_refuses_removal_and_keeps_fixture(self):
        self.fixture.cid = self.cid
        self.fixture.nonce = "x" * 32
        errors = self.fixture.stop()
        self.assertTrue(errors)
        self.assertEqual([], self.rm_calls)
        self.assertTrue(self.fixture.directory.exists())

    def test_timeout_after_daemon_create_resolves_exact_name_and_removes(self):
        self.fixture.create_attempted = True
        self.assertEqual([], self.fixture.stop())
        self.assertEqual([["docker", "rm", "-f", "--", self.cid]], self.rm_calls)
        self.assertFalse(self.fixture.directory.exists())

    def test_invalid_cid_output_uses_the_same_name_resolution_path(self):
        self.fixture.docker_runner = lambda *_args, **_kwargs: "not-a-full-cid"
        with self.assertRaisesRegex(gate.RunnerError, "full container id"):
            self.fixture._create_container()
        self.assertIsNone(self.fixture.cid)
        self.assertTrue(self.fixture.create_attempted)
        self.assertEqual([], self.fixture.stop())
        self.assertEqual([["docker", "rm", "-f", "--", self.cid]], self.rm_calls)

    def test_ambiguous_name_lookup_keeps_fixture_and_reports_unresolved(self):
        self.fixture.create_attempted = True
        self.fixture.command_runner = lambda command, **kwargs: completed(
            returncode=1, stderr="Cannot connect to the Docker daemon\n")
        errors = self.fixture.stop()
        self.assertTrue(errors)
        self.assertEqual([], self.rm_calls)
        self.assertTrue(self.fixture.directory.exists())

    def test_absent_container_is_not_removed_and_directory_is_cleaned(self):
        self.fixture.cid = self.cid
        self.fixture.command_runner = lambda command, **kwargs: completed(
            returncode=1, stderr="Error: No such container: " + self.cid + "\n")
        self.assertEqual([], self.fixture.stop())
        self.assertFalse(self.fixture.directory.exists())
class CaseRunnerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.logs = Path(self.temporary.name) / "logs"
        self.executable = Path(self.temporary.name) / "rootyard-lib-test"

    def run_gate(self, stdout, returncode=0, **overrides):
        arguments = dict(expected_cases=gate.EXPECTED_CASES,
                         expected_passed=gate.TEST_CASE_COUNT,
                         expected_failed=0, expected_ignored=0,
                         log_dir=self.logs, secrets=(SECRET,))
        arguments.update(overrides)
        with mock.patch.object(gate, "run_command",
                               return_value=completed(stdout=stdout, returncode=returncode)):
            return gate.run_case_set(
                self.executable, arguments.pop("label", "plain"),
                ["real_redis_", "--ignored"], {}, **arguments)

    def test_redacted_log_never_contains_the_secret_or_url(self):
        output = libtest([(name, "ok") for name in gate.EXPECTED_CASES])
        output += f"\ndiagnostic {URL} password {SECRET}\n"
        parsed = self.run_gate(output)
        self.assertEqual([6, 0, 0], parsed["observed_counts"])
        log = (self.logs / "plain.log").read_text()
        self.assertNotIn(SECRET, log)
        self.assertNotIn("rediss://", log)
        self.assertIn("<redacted-url>", log)

    def test_zero_case_or_unexpected_skip_fails_even_with_zero_returncode(self):
        skipped = [(name, "ignored") for name in gate.EXPECTED_CASES]
        with self.assertRaisesRegex(gate.RunnerError, "zero passing"):
            self.run_gate(libtest(skipped, passed=0, ignored=6))
        self.assertTrue((self.logs / "plain.log").is_file())
        partial = libtest(list((name, "ok") for name in sorted(gate.EXPECTED_CASES))[:-1])
        with self.assertRaisesRegex(gate.RunnerError, "case set mismatch"):
            self.run_gate(partial)

    def test_positive_returncode_and_negative_returncode_are_checked(self):
        good = libtest([(name, "ok") for name in gate.EXPECTED_CASES])
        with self.assertRaisesRegex(gate.RunnerError, "failed with status"):
            self.run_gate(good, returncode=101)
        negative = libtest([(gate.NEGATIVE_CASE, "FAILED")], passed=0, failed=1)
        with self.assertRaisesRegex(gate.RunnerError, "unexpectedly returned success"):
            self.run_gate(negative, label="negative", expected_cases=frozenset({gate.NEGATIVE_CASE}),
                          expected_passed=0, expected_failed=1, returncode=0)

    def test_expected_failure_is_recorded_only_for_the_named_case(self):
        negative = libtest([(gate.NEGATIVE_CASE, "FAILED")], passed=0, failed=1)
        parsed = self.run_gate(negative, label="negative", expected_cases=frozenset({gate.NEGATIVE_CASE}),
                               expected_passed=0, expected_failed=1, returncode=101)
        self.assertEqual([gate.NEGATIVE_CASE], parsed["failed_cases"])
        self.assertEqual([0, 1, 0], parsed["observed_counts"])


if __name__ == "__main__":
    unittest.main()
