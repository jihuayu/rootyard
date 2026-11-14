"""Unit guards for scripts/check_redis_contract.py without Docker or Cargo.

These tests use synthetic v1/v2 receipts, fake command results and fake Docker
metadata to prove prebuilt-only evidence validation, libtest/failure parsing,
report redaction, Docker port parsing, cleanup ownership and post-run
immutability.  The real Redis container is exercised only by the optional CI
job; no test here builds, cleans or probes a compiler.
"""
import hashlib
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
import native_build_receipt as receipt  # noqa: E402

SECRET = "ab" * 32
URL = f"rediss://rootyard:{SECRET}@127.0.0.1:6380/0"
FAKE_COMMIT = "a" * 40
TRIPLE = "x86_64-unknown-linux-gnu"
BINARY_BYTES = b"prebuilt-rootyard-libtest\x00\x01"


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


def _support_digest(entries):
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item.get("path", "")):
        if entry.get("present") is True and entry.get("role") == "test_support":
            digest.update(entry["path"].encode() + b"\0")
            digest.update(bytes.fromhex(entry["sha256"]))
    return digest.hexdigest()


class FakeFixture:
    secret = SECRET
    cid = "c" * 64
    image_id = "sha256:" + "a" * 64
    image_digest = "redis@sha256:" + "b" * 64
    version_line = "Redis server v=7.2.6 sha=fake"
    plain_port = 49165
    tls_port = 49166

    def __init__(self):
        self.ca_certificate = Path("/private/tmp/rootyard-owned-ca.crt")
        self.untrusted_ca_certificate = Path("/private/tmp/rootyard-untrusted-ca.crt")
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def url(self, *, tls):
        return URL

    def stop(self):
        self.stopped = True
        return []


class PrebuiltReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "tests" / "serving_support").mkdir(parents=True)
        (self.root / "tests" / "fixtures").mkdir()
        (self.root / "toolchain").mkdir()
        (self.root / "target" / "debug" / "deps").mkdir(parents=True)
        (self.root / "relocated").mkdir()
        (self.root / "Cargo.toml").write_text('[package]\nname = "rootyard"\n')
        (self.root / "Cargo.lock").write_text("version = 3\n")
        (self.root / "src" / "lib.rs").write_text("pub fn hello() {}\n")
        (self.root / "src" / "main.rs").write_text("fn main() {}\n")
        (self.root / "tests" / "example.rs").write_text("#[test]\nfn one() {}\n")
        (self.root / "tests" / "serving_support" / "support.rs").write_text("pub fn s() {}\n")
        (self.root / "tests" / "fixtures" / "data.txt").write_text("fixture\n")
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.99.1"\n')
        for name in ("cargo", "rustc", "rustup"):
            (self.root / "toolchain" / name).write_bytes(("fake-" + name).encode())
        self.original = self.root / "target" / "debug" / "deps" / "rootyard-lib-test"
        self.relocated = self.root / "relocated" / "rootyard-lib-test"
        self.receipt_path = self.relocated.with_suffix(".build.json")
        self.reset_binary()
        self.patches = [
            mock.patch.object(gate, "ROOT", self.root),
            mock.patch.object(gate, "current_commit", return_value=FAKE_COMMIT),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def reset_binary(self):
        self.original.write_bytes(BINARY_BYTES)
        self.relocated.write_bytes(BINARY_BYTES)

    def toolchain(self):
        def identity(name, release, commit_hash, *, proxy=None):
            path = self.root / "toolchain" / name
            value = {
                "executable": str(path),
                "executable_sha256": receipt.sha256_file(path),
                "version": f"{name} {release} (fake)",
                "release": release,
                "commit_hash": commit_hash,
                "commit_date": "2026-01-01",
                "host": TRIPLE,
            }
            if proxy is not None:
                value["path_entry"] = str(path)
                value["proxy"] = proxy
            return value
        return {
            "cargo": identity("cargo", "1.101.0", "c" * 40),
            "rustc": identity("rustc", "1.99.1", "d" * 40, proxy=False),
            "rustup": {
                "executable": str(self.root / "toolchain" / "rustup"),
                "executable_sha256": receipt.sha256_file(self.root / "toolchain" / "rustup"),
                "resolved_rustc": str(self.root / "toolchain" / "rustc"),
                "resolved_rustc_sha256": receipt.sha256_file(self.root / "toolchain" / "rustc"),
            },
            "target_triple": TRIPLE,
            "pinned_channel": "1.99.1",
            "pin_source": "rust-toolchain.toml",
        }

    def artifact(self, fresh):
        event = {
            "reason": "compiler-artifact",
            "package_id": "rootyard 0.1.0",
            "target": {
                "name": "rootyard", "kind": ["lib"], "test": True,
                "src_path": str(self.root / "src" / "lib.rs"),
            },
            "profile": {
                "opt_level": "0", "debuginfo": 0,
                "debug_assertions": True, "overflow_checks": True, "test": True,
            },
            "fresh": fresh,
            "executable": str(self.original),
        }
        return receipt.cargo_artifact_record(
            event, source_root=self.root, kind="lib-test")

    def v2_payload(
        self, *, fresh=True, command=None, features="state-redis",
        no_default_features=False, profile="test", mutate=None, artifacts=None,
    ):
        self.reset_binary()
        bound = receipt.capture_bound_inputs(self.root, environ={})
        artifact = self.artifact(fresh)
        payload = receipt.make_receipt_v2(
            binary_path=self.relocated,
            command=command or gate.EXPECTED_V2_COMMAND,
            profile=profile,
            artifacts=artifacts if artifacts is not None else [artifact],
            toolchain=self.toolchain(),
            bound_inputs=bound,
            workspace_commit=FAKE_COMMIT,
            target_dir=self.root / "target",
            features=features,
            no_default_features=no_default_features,
            extra={
                "kind": "rust-library-test",
                "relocated_artifact": True,
                "original_artifact_sha256": receipt.sha256_file(self.original),
                "lib_test_support_inputs_sha256": _support_digest(
                    bound["bound_input_inventory"]),
                "build_options": {"jobs": None},
            },
        )
        if mutate is not None:
            mutate(payload)
        receipt.atomic_write_json(self.receipt_path, payload)
        return payload

    def v1_payload(self, *, include_fresh=True, fresh=False, mutate=None):
        source = receipt.source_digest(self.root)
        payload = {
            "kind": "rust-library-test",
            "command": list(gate.EXPECTED_V1_COMMAND),
            "clean_command": ["cargo", "clean", "--package", "rootyard"],
            "workspace_commit": FAKE_COMMIT,
            "rustc": "rustc 1.99.1 (fake)",
            "cargo_lock_sha256": receipt.sha256_file(self.root / "Cargo.lock"),
            "source_inputs_sha256": source,
            "source_after_build_sha256": source,
            "executable": str(self.original),
            "binary_sha256": receipt.sha256_file(self.relocated),
            "fresh": fresh,
            "profile_test": True,
            "artifact": {
                "target": "rootyard", "kind": "lib", "fresh": False,
                "profile": {"test": True},
            },
        }
        if not include_fresh:
            payload.pop("fresh")
            payload["artifact"].pop("fresh", None)
        if mutate is not None:
            mutate(payload)
        receipt.atomic_write_json(self.receipt_path, payload)
        return payload

    def verify(self, **kwargs):
        return gate.verify_prebuilt(self.relocated, self.receipt_path, **kwargs)

    def assert_rejected(self, pattern=None, **kwargs):
        with self.assertRaises(gate.RunnerError) as caught:
            self.verify(**kwargs)
        if pattern is not None:
            self.assertRegex(str(caught.exception), pattern)
        return caught.exception

    def test_v2_cache_hit_true_and_cache_miss_false_are_both_valid(self):
        for fresh in (True, False):
            with self.subTest(fresh=fresh):
                self.v2_payload(fresh=fresh)
                evidence = self.verify()
                self.assertEqual("v2", evidence["receipt_schema"])
                self.assertIs(fresh, evidence["fresh"])
                self.assertEqual("cargo_artifacts[0].fresh", evidence["freshness_source"])
                self.assertEqual("rootyard", evidence["target"])
                self.assertEqual("lib-test", evidence["artifact_kind"])
                self.assertIs(True, evidence["profile_test"])
                self.assertEqual({"enabled": ["state-redis"], "no_default_features": False},
                                 evidence["features"])
                self.assertEqual(gate.EXPECTED_V2_COMMAND, evidence["command"])
                self.assertEqual(receipt.sha256_file(self.receipt_path),
                                 evidence["receipt_sha256"])
                self.assertEqual(receipt.sha256_file(self.relocated),
                                 evidence["binary"]["sha256"])
                self.assertEqual(BINARY_BYTES, self.relocated.read_bytes())
                self.assertNotIn("build", evidence)
                self.assertNotIn("package_rebuilt", evidence)

    def test_v2_explicit_trailing_job_budget_is_valid(self):
        self.v2_payload(command=[*gate.EXPECTED_V2_COMMAND, "--jobs", "2"])
        self.assertEqual("v2", self.verify()["receipt_schema"])
        for bad in (["--jobs", "0"], ["--jobs"], ["--jobs", "two"]):
            with self.subTest(bad=bad):
                self.v2_payload(command=[*gate.EXPECTED_V2_COMMAND, *bad])
                self.assert_rejected("command")

    def test_verify_never_calls_cargo_rustc_or_a_producer(self):
        self.v2_payload()
        self.assertFalse(hasattr(gate, "build_libtest"))
        self.assertFalse(hasattr(gate, "BUILD_COMMAND"))
        self.assertFalse(hasattr(gate, "CLEAN_COMMAND"))
        self.assertFalse(hasattr(gate, "build_native"))
        with mock.patch.object(
                gate, "run_command",
                side_effect=AssertionError("no cargo/rustc/clean may run")), \
             mock.patch.object(
                gate.receipt, "probe_toolchain",
                side_effect=AssertionError("no toolchain probe may run")):
            evidence = self.verify()
        self.assertEqual("v2", evidence["receipt_schema"])

    def test_v2_feature_profile_and_command_tampering_is_rejected(self):
        tampered = {
            "extra-feature": lambda payload: payload["features"].update(
                enabled=["state-redis", "extra"]),
            "missing-feature": lambda payload: payload["features"].update(enabled=[]),
            "default-features-dropped": lambda payload: payload["features"].update(
                no_default_features=True),
            "profile": lambda payload: payload.update(profile="dev"),
            "command": lambda payload: payload.update(command=["cargo", "test", "--lib"]),
            "clean-command": lambda payload: payload.update(
                command=["cargo", "clean", "--package", "rootyard"]),
        }
        for name, mutate in tampered.items():
            with self.subTest(name=name):
                self.v2_payload(mutate=mutate)
                self.assert_rejected()

    def test_v2_artifact_identity_and_support_tampering_is_rejected(self):
        def wrong_kind(payload):
            payload["cargo_artifacts"][0]["kind"] = "test"

        def wrong_target(payload):
            payload["cargo_artifacts"][0]["target"] = "otherlib"

        def wrong_source(payload):
            row = payload["cargo_artifacts"][0]
            row["source"] = "tests/serving_support/support.rs"
            row["source_sha256"] = receipt.sha256_file(
                self.root / "tests" / "serving_support" / "support.rs")

        def wrong_support(payload):
            payload["lib_test_support_inputs_sha256"] = "0" * 64

        def wrong_original(payload):
            payload["original_artifact_sha256"] = "0" * 64

        def implicit_build(payload):
            payload["implicit_build"] = True

        def duplicate(payload):
            payload["cargo_artifacts"].append(dict(payload["cargo_artifacts"][0]))

        def missing(payload):
            payload["cargo_artifacts"] = []

        for name, mutate in {
            "kind": wrong_kind, "target": wrong_target, "source": wrong_source,
            "support": wrong_support, "original": wrong_original,
            "implicit_build": implicit_build, "duplicate": duplicate,
            "missing": missing,
        }.items():
            with self.subTest(name=name):
                self.v2_payload(mutate=mutate)
                self.assert_rejected()

    def test_v2_missing_prebuilt_tampered_receipt_and_stale_source_are_rejected(self):
        self.v2_payload()
        self.relocated.unlink()
        self.assert_rejected("executable is missing")
        self.reset_binary()
        self.receipt_path.unlink()
        self.assert_rejected("receipt is missing")
        self.v2_payload()
        self.receipt_path.write_text("{not-json\n")
        self.assert_rejected()
        self.v2_payload()
        payload = json.loads(self.receipt_path.read_text())
        payload["binary_sha256"] = "0" * 64
        receipt.atomic_write_json(self.receipt_path, payload)
        self.assert_rejected()
        self.v2_payload()
        (self.root / "src" / "lib.rs").write_text("pub fn changed() {}\n")
        self.assert_rejected("source")

    def test_v2_expected_commit_anchor_must_match_current_head(self):
        self.v2_payload()
        self.assert_rejected("expected commit does not match", expected_commit="b" * 40)
        self.assert_rejected("full 40- or 64-hex", expected_commit="not-a-commit")
        self.v2_payload(mutate=lambda payload: payload.update(workspace_commit="b" * 40))
        self.assert_rejected("expected_commit")

    def test_v1_historical_receipt_is_read_without_rewriting_or_inventing_freshness(self):
        self.v1_payload(include_fresh=True, fresh=False)
        before = self.receipt_path.read_bytes()
        evidence = self.verify()
        self.assertEqual("v1", evidence["receipt_schema"])
        self.assertIs(False, evidence["fresh"])
        self.assertEqual("artifact.fresh", evidence["freshness_source"])
        self.assertEqual(gate.EXPECTED_V1_COMMAND, evidence["command"])
        self.assertNotIn("clean_command", evidence)
        self.assertEqual(before, self.receipt_path.read_bytes())
        self.v1_payload(include_fresh=False)
        before = self.receipt_path.read_bytes()
        evidence = self.verify()
        self.assertEqual("v1", evidence["receipt_schema"])
        self.assertIsNone(evidence["fresh"])
        self.assertEqual(before, self.receipt_path.read_bytes())
        self.assertNotIn("fresh", json.loads(before))

    def test_v1_feature_profile_kind_and_freshness_tampering_is_rejected(self):
        self.v1_payload(mutate=lambda payload: payload.update(fresh=True))
        self.assert_rejected()
        self.v1_payload(mutate=lambda payload: payload["artifact"].update(kind="bin"))
        self.assert_rejected("lib/lib-test")
        self.v1_payload(mutate=lambda payload: payload["artifact"].update(
            profile={"test": False}))
        self.assert_rejected("test profile")
        self.v1_payload(mutate=lambda payload: payload.update(
            command=["cargo", "test", "--lib"]))
        self.assert_rejected("command")

    def test_invalid_evidence_fails_before_fixture_allocation(self):
        self.v2_payload()
        self.relocated.unlink()
        with mock.patch.object(
                gate, "OwnedRedisFixture",
                side_effect=AssertionError("fixture must not be allocated")):
            status, report = gate.execute(
                self.root / "report.json", self.root / "logs",
                self.relocated, self.receipt_path)
        self.assertEqual(1, status)
        self.assertEqual("failed", report["status"])
        self.assertIsNone(report["prebuilt"])
        self.assertIsNone(report["fixture"])
        self.assertEqual([], report["runs"])
        self.assertTrue((self.root / "report.json").is_file())

    def test_execute_records_exact_receipt_schema_hash_and_binary_identity(self):
        self.v2_payload(fresh=True)
        expected_receipt_sha = receipt.sha256_file(self.receipt_path)
        expected_binary_sha = receipt.sha256_file(self.relocated)
        fixture = FakeFixture()
        commands = []

        def fake_run_case(executable, label, arguments, environment, **kwargs):
            commands.append((str(executable), label, list(arguments)))
            counts = (6, 0, 0) if label in ("plain", "tls") else (
                (0, 1, 0) if label == "untrusted-ca-refused" else (1, 0, 0))
            return {
                "name": label, "passed": counts[0], "failed": counts[1],
                "ignored": counts[2], "cases": {}, "failed_cases": [],
            }

        with mock.patch.object(gate, "OwnedRedisFixture", return_value=fixture), \
             mock.patch.object(gate, "run_case_set", side_effect=fake_run_case), \
             mock.patch.object(
                gate, "run_command",
                side_effect=AssertionError("no cargo/rustc/clean may run")):
            status, report = gate.execute(
                self.root / "report.json", self.root / "logs",
                self.relocated, self.receipt_path)
        self.assertEqual(0, status)
        self.assertEqual("passed", report["status"])
        self.assertTrue(fixture.started)
        self.assertTrue(fixture.stopped)
        self.assertEqual(
            ["plain", "tls", "untrusted-ca-refused", "trusted-ca-restored"],
            [run["name"] for run in report["runs"]])
        prebuilt = report["prebuilt"]
        self.assertEqual("v2", prebuilt["receipt_schema"])
        self.assertEqual(expected_receipt_sha, prebuilt["receipt_sha256"])
        self.assertEqual(str(self.receipt_path.resolve()), prebuilt["receipt_path"])
        self.assertEqual(expected_binary_sha, prebuilt["binary"]["sha256"])
        self.assertEqual(len(BINARY_BYTES), prebuilt["binary"]["size"])
        self.assertIs(True, prebuilt["fresh"])
        self.assertTrue(report["source_still_matches"])
        self.assertTrue(report["config_still_matches"])
        self.assertTrue(report["inventory_still_matches"])
        self.assertTrue(report["receipt_still_matches"])
        self.assertTrue(report["binary_still_matches"])
        self.assertEqual(
            [str(self.relocated.resolve())] * 4,
            [command[0] for command in commands])

    def test_execute_detects_post_run_source_receipt_and_binary_mutation(self):
        for target in ("source", "receipt", "binary"):
            with self.subTest(target=target):
                self.v2_payload(fresh=True)
                fixture = FakeFixture()
                runs = []

                def fake_run_case(executable, label, arguments, environment, **kwargs):
                    runs.append(label)
                    if label == "trusted-ca-restored":
                        if target == "source":
                            (self.root / "src" / "lib.rs").write_text("pub fn changed() {}\n")
                        elif target == "receipt":
                            self.receipt_path.write_bytes(
                                self.receipt_path.read_bytes() + b" ")
                        else:
                            self.relocated.write_bytes(self.relocated.read_bytes() + b"x")
                    counts = (6, 0, 0) if label in ("plain", "tls") else (
                        (0, 1, 0) if label == "untrusted-ca-refused" else (1, 0, 0))
                    return {
                        "name": label, "passed": counts[0], "failed": counts[1],
                        "ignored": counts[2], "cases": {}, "failed_cases": [],
                    }

                with mock.patch.object(gate, "OwnedRedisFixture", return_value=fixture), \
                     mock.patch.object(gate, "run_case_set", side_effect=fake_run_case), \
                     mock.patch.object(gate, "run_command", side_effect=AssertionError("no cargo")):
                    status, report = gate.execute(
                        self.root / "report.json", self.root / "logs",
                        self.relocated, self.receipt_path)
                self.assertEqual(1, status)
                self.assertEqual("failed", report["status"])
                self.assertEqual(4, len(runs))
                expected = {
                    "source": "source_still_matches",
                    "receipt": "receipt_still_matches",
                    "binary": "binary_still_matches",
                }[target]
                self.assertFalse(report[expected])


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
        def timed_out(*_args, **_kwargs):
            raise gate.RunnerError("docker create timed out after daemon creation")
        self.fixture.docker_runner = timed_out
        with self.assertRaisesRegex(gate.RunnerError, "timed out"):
            self.fixture._create_container()
        self.assertTrue(self.fixture.create_attempted)
        self.assertIsNone(self.fixture.cid)
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
