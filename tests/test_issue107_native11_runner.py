#!/usr/bin/env python3
"""Pure mocked tests for the prebuilt native11 acceptance runner."""
from __future__ import annotations

import copy
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import issue107_native11_inventory as inventory  # noqa: E402
import issue107_native11_runner as runner  # noqa: E402

HEAD = "1" * 40


def target_report():
    targets = []
    for target in inventory.TARGET_ORDER:
        cases = [{"name": name, "status": "passed"}
                 for name in inventory.TARGETS[target]["cases"]]
        targets.append({
            "target": target,
            "passed": True,
            "cases": cases,
            "case_count": len(cases),
            "binary_sha256": "b" * 64,
            "receipt_sha256": "e" * 64,
            "source_inputs_sha256": "c" * 64,
        })
    total = sum(len(inventory.TARGETS[name]["cases"]) for name in inventory.TARGET_ORDER)
    return {
        "kind": runner.REPORT_KIND,
        "passed": True,
        "measurement_kind": "native_execution",
        "simulated_fields": False,
        "source_head": HEAD,
        "targets": targets,
        "case_count": total,
        "expected_count": total,
        "skips": 0,
        "pending_cases": [],
        "cleanup_unresolved": False,
        "error_codes": [],
        "input_closure_sha256": {"a": "f" * 64},
        "input_closure_after_sha256": {"a": "f" * 64},
    }


class StaticInventoryTests(unittest.TestCase):
    def test_exact_eleven_targets_and_167_unique_cases(self):
        self.assertEqual(len(inventory.TARGET_ORDER), 11)
        self.assertEqual(set(inventory.TARGET_ORDER), set(inventory.TARGETS))
        names = []
        for target in inventory.TARGET_ORDER:
            cases = inventory.TARGETS[target]["cases"]
            self.assertEqual(len(cases), len(set(cases)), target)
            names.extend((target, name) for name in cases)
        self.assertEqual(len(names), 167)
        self.assertEqual(len(set(names)), 167)
        self.assertIn("cancellation::cancel_versus_commit_keeps_one_exact_terminal",
                      inventory.TARGETS["ref_store_core"]["cases"])
        self.assertIn(
            "decision_subset_support::cases_a::mixed_batch_bad_cas_and_valid_new_ref_commits_only_the_good_ref_and_replays_exactly",
            inventory.TARGETS["ref_store_decision_subset"]["cases"])

    def test_target_and_pairs_mutations(self):
        targets = {name: "/x" for name in inventory.TARGET_ORDER}
        receipts = {name: "/y" for name in inventory.TARGET_ORDER}
        runner.validate_target_set(targets, receipts)
        missing = dict(targets); missing.pop(inventory.TARGET_ORDER[0])
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_target_set(missing, receipts)
        self.assertEqual(raised.exception.code, "target_set_mismatch")
        extra = dict(targets); extra["extra_target"] = "/z"
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_target_set(extra, receipts)
        self.assertEqual(raised.exception.code, "target_set_mismatch")
        with self.assertRaises(runner.RunnerError) as raised:
            runner._pairs(["a=1", "a=2"], "target")
        self.assertEqual(raised.exception.code, "duplicate_target")


class EnvironmentTests(unittest.TestCase):
    def test_missing_required_env_is_safe_failure(self):
        with mock.patch.dict(runner.os.environ, {}, clear=True):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._required_environment("ref_store_operations")
        self.assertEqual(raised.exception.code, "missing_required_environment")


class OutputTests(unittest.TestCase):
    def test_listing_and_case_summary_are_exact(self):
        self.assertEqual(runner.parse_listing(b"a: test\nb::c: test\nbench: bench\n"),
                         ["a", "b::c"])
        runner.parse_case_result(
            b"test a::b ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n",
            "a::b")
        with self.assertRaises(runner.RunnerError) as raised:
            runner.parse_case_result(
                b"test a::b ... ok\n\ntest result: ok. 0 passed; 0 failed; 1 ignored;\n",
                "a::b")
        self.assertEqual(raised.exception.code, "test_partial_or_skipped")
        with self.assertRaises(runner.RunnerError) as raised:
            runner.parse_case_result(
                b"test a::b ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored;\n",
                "a::b")
        self.assertEqual(raised.exception.code, "test_partial_or_skipped")
        with self.assertRaises(runner.RunnerError) as raised:
            runner.parse_case_result(
                b"test other ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n",
                "a::b")
        self.assertEqual(raised.exception.code, "test_not_executed")


    def test_listing_missing_extra_duplicate_is_rejected(self):
        cfg = inventory.TARGETS["ref_store_operations"]
        good = b"\n".join(name.encode() + b": test" for name in cfg["cases"])
        with mock.patch.object(runner, "run_bounded", return_value=good):
            self.assertEqual(len(runner._list_target("fake", cfg, 5.0)), 7)
        missing = good.splitlines()[:-1]
        with mock.patch.object(runner, "run_bounded", return_value=b"\n".join(missing)):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._list_target("fake", cfg, 5.0)
            self.assertEqual(raised.exception.code, "static_inventory_mismatch")
        extra = good.splitlines() + [b"extra: test"]
        with mock.patch.object(runner, "run_bounded", return_value=b"\n".join(extra)):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._list_target("fake", cfg, 5.0)
            self.assertEqual(raised.exception.code, "static_inventory_mismatch")
        duplicate = good.splitlines() + [good.splitlines()[0]]
        with mock.patch.object(runner, "run_bounded", return_value=b"\n".join(duplicate)):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._list_target("fake", cfg, 5.0)
            self.assertEqual(raised.exception.code, "static_inventory_mismatch")


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.binary = root / "ref_store_operations"
        self.binary.write_bytes(b"fake native binary")
        self.receipt = root / "ref_store_operations.build.json"
        self.receipt.write_text("{}")
        self.root = root / "source"
        self.root.mkdir()
        self.payload = {
            "kind": "rust-integration-test",
            "integration_test_source": "tests/ref_store_operations.rs",
            "profile": "test",
            "features": {"enabled": ["pando-lab"], "no_default_features": False},
            "command": ["cargo", "rustc", "--locked", "--profile", "test",
                        "--test", "ref_store_operations", "--features", "pando-lab",
                        "--message-format=json-render-diagnostics"],
        }

    def tearDown(self):
        self.temp.cleanup()

    def fake_receipt(self, **changes):
        payload = dict(self.payload)
        payload.update(changes)
        return SimpleNamespace(
            schema="v2",
            workspace_commit=HEAD,
            binary_sha256=runner._file_sha(self.binary),
            source_inputs_sha256="c" * 64,
            receipt_sha256="e" * 64,
            config_digest="d" * 64,
            payload=payload,
            artifacts=[{"target": "ref_store_operations", "kind": "test"}],
        )

    def test_valid_receipt_binds_kind_source_profile_features_and_target(self):
        with mock.patch.object(runner.receipts, "load_receipt", return_value=self.fake_receipt()):
            result = runner._receipt_identity(
                "ref_store_operations", self.binary, self.receipt, self.root, HEAD)
        self.assertEqual(result["target"], "ref_store_operations")
        self.assertEqual(result["source_inputs_sha256"], "c" * 64)

    def test_receipt_identity_mutations_and_invalid_receipt(self):
        wrong = self.fake_receipt()
        wrong.workspace_commit = "0" * 40
        with mock.patch.object(runner.receipts, "load_receipt", return_value=wrong):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._receipt_identity("ref_store_operations", self.binary, self.receipt,
                                         self.root, HEAD)
        self.assertEqual(raised.exception.code, "wrong_target_source")
        wrong = self.fake_receipt()
        wrong.binary_sha256 = "0" * 64
        with mock.patch.object(runner.receipts, "load_receipt", return_value=wrong):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._receipt_identity("ref_store_operations", self.binary, self.receipt,
                                         self.root, HEAD)
        self.assertEqual(raised.exception.code, "wrong_target_binary")
        wrong = self.fake_receipt()
        wrong.source_inputs_sha256 = "not-a-digest"
        with mock.patch.object(runner.receipts, "load_receipt", return_value=wrong):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._receipt_identity("ref_store_operations", self.binary, self.receipt,
                                         self.root, HEAD)
        self.assertEqual(raised.exception.code, "invalid_target_source_digest")
        wrong = self.fake_receipt()
        wrong.schema = "v1"
        with mock.patch.object(runner.receipts, "load_receipt", return_value=wrong):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._receipt_identity("ref_store_operations", self.binary, self.receipt,
                                         self.root, HEAD)
        self.assertEqual(raised.exception.code, "target_receipt_not_v2")
        with mock.patch.object(runner.receipts, "load_receipt", side_effect=ValueError("bad")):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._receipt_identity("ref_store_operations", self.binary, self.receipt,
                                         self.root, HEAD)
        self.assertEqual(raised.exception.code, "target_receipt_invalid")

    def test_receipt_mutations_are_rejected(self):
        mutations = {
            "kind": "wrong_target_kind",
            "integration_test_source": "wrong_target_source_file",
            "profile": "wrong_target_profile",
        }
        for field, code in mutations.items():
            with self.subTest(field=field):
                with mock.patch.object(runner.receipts, "load_receipt",
                                       return_value=self.fake_receipt(**{field: "wrong"})):
                    with self.assertRaises(runner.RunnerError) as raised:
                        runner._receipt_identity(
                            "ref_store_operations", self.binary, self.receipt, self.root, HEAD)
                self.assertEqual(raised.exception.code, code)
        bad_features = {"enabled": ["other"], "no_default_features": False}
        with mock.patch.object(runner.receipts, "load_receipt",
                               return_value=self.fake_receipt(features=bad_features)):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._receipt_identity("ref_store_operations", self.binary, self.receipt,
                                         self.root, HEAD)
        self.assertEqual(raised.exception.code, "wrong_target_features")
        bad_command = list(self.payload["command"])
        test_index = bad_command.index("--test")
        del bad_command[test_index:test_index + 2]
        with mock.patch.object(runner.receipts, "load_receipt",
                               return_value=self.fake_receipt(command=bad_command)):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._receipt_identity("ref_store_operations", self.binary, self.receipt,
                                         self.root, HEAD)
        self.assertEqual(raised.exception.code, "command_test_target_set_mismatch")
        wrong_artifact = self.fake_receipt()
        wrong_artifact.artifacts = [{"target": "other", "kind": "test"}]
        with mock.patch.object(runner.receipts, "load_receipt", return_value=wrong_artifact):
            with self.assertRaises(runner.RunnerError) as raised:
                runner._receipt_identity("ref_store_operations", self.binary, self.receipt,
                                         self.root, HEAD)
        self.assertEqual(raised.exception.code, "target_artifact_mismatch")


def batch_command(targets, *, reverse=False, extra=None):
    selected = list(reversed(targets)) if reverse else list(targets)
    command = [
        "cargo", "build", "--locked", "--profile", "test",
        "--config", "profile.dev.package.rootyard.debug=0",
        "--config", "profile.test.package.rootyard.debug=0",
        "--config", "profile.dev.package.rootyard.strip=\"debuginfo\"",
        "--config", "profile.test.package.rootyard.strip=\"debuginfo\"",
        "--config", "build.target-dir = \"/tmp/rootyard-target\"",
        "--bin", "rootyard",
    ]
    for target in selected:
        command += ["--test", target]
    if extra:
        command += ["--test", extra]
    command += ["--features", "pando-lab", "--message-format=json-render-diagnostics"]
    return command


class BatchCommandTests(unittest.TestCase):
    def test_complete_fixed11_batch_is_accepted_for_every_target(self):
        command = batch_command(inventory.TARGET_ORDER)
        for target in inventory.TARGET_ORDER:
            result = runner.validate_target_build_command(
                command, target, inventory.TARGETS[target])
            self.assertEqual(tuple(result["test_targets"]), tuple(inventory.TARGET_ORDER))

    def test_batch_selector_order_is_not_semantically_required(self):
        command = batch_command(inventory.TARGET_ORDER, reverse=True)
        for target in inventory.TARGET_ORDER:
            runner.validate_target_build_command(
                command, target, inventory.TARGETS[target])

    def test_partial_extra_duplicate_and_wrong_target_sets_are_rejected(self):
        partial = batch_command(inventory.TARGET_ORDER[:5])
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_target_build_command(partial, inventory.TARGET_ORDER[0],
                                                  inventory.TARGETS[inventory.TARGET_ORDER[0]])
        self.assertEqual(raised.exception.code, "command_test_target_set_mismatch")
        extra = batch_command(inventory.TARGET_ORDER, extra="not_a_fixed_target")
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_target_build_command(extra, inventory.TARGET_ORDER[0],
                                                  inventory.TARGETS[inventory.TARGET_ORDER[0]])
        self.assertEqual(raised.exception.code, "command_test_target_set_mismatch")
        duplicate = batch_command(inventory.TARGET_ORDER, extra=inventory.TARGET_ORDER[0])
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_target_build_command(duplicate, inventory.TARGET_ORDER[0],
                                                  inventory.TARGETS[inventory.TARGET_ORDER[0]])
        self.assertEqual(raised.exception.code, "command_ambiguous_flag")

    def test_cross_receipt_batch_command_consistency(self):
        targets = list(inventory.TARGET_ORDER)
        command = batch_command(targets)
        rows = {
            target: {"target": target, "command_test_targets": list(targets)}
            for target in targets
        }
        runner.validate_batch_command_consistency(rows)
        changed = copy.deepcopy(rows)
        changed[targets[0]]["command_test_targets"] = list(reversed(targets))
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_batch_command_consistency(changed)
        self.assertEqual(raised.exception.code, "batch_command_inconsistent")
        mixed = copy.deepcopy(rows)
        mixed[targets[0]]["command_test_targets"] = [targets[0]]
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_batch_command_consistency(mixed)
        self.assertEqual(raised.exception.code, "batch_command_inconsistent")
        partial = copy.deepcopy(rows)
        for row in partial.values():
            row["command_test_targets"] = list(targets[:5])
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_batch_command_consistency(partial)
        self.assertEqual(raised.exception.code, "batch_command_target_set_mismatch")


class ConfigOverrideTests(unittest.TestCase):
    def command(self, configs, *, target_dir=False, extra=None):
        command = ["cargo"]
        for value in configs:
            command += ["--config", value]
        command += ["rustc", "--locked", "--profile", "test", "--test", "ref_store_operations",
                    "--features", "pando-lab"]
        if target_dir:
            command += ["--config", 'build.target-dir = "/tmp/rootyard-target"']
        if extra:
            command += ["--config", extra]
        return command

    def test_actual_preparer_configs_are_accepted(self):
        configs = [
            "profile.dev.package.rootyard.debug=0",
            "profile.test.package.rootyard.debug=0",
            'profile.dev.package.rootyard.strip="debuginfo"',
            'profile.test.package.rootyard.strip="debuginfo"',
        ]
        runner.validate_target_build_command(
            self.command(configs), "ref_store_operations",
            inventory.TARGETS["ref_store_operations"])
        runner.validate_target_build_command(
            self.command(configs[:2], target_dir=True), "ref_store_operations",
            inventory.TARGETS["ref_store_operations"])

    def test_unsupported_or_malformed_configs_are_rejected(self):
        cases = [
            ("profile.test.package.rootyard.opt-level=3", "command_config_unsupported"),
            ('build.rustflags = ["-Ctarget-cpu=native"]', "command_config_unsupported"),
            ("/tmp/custom-cargo.toml", "command_config_unsupported"),
            ("profile.test.package.rootyard.debug=9", "command_config_unsupported"),
            ("profile.test.package.rootyard.strip=debuginfo", "command_config_unsupported"),
            ('build.target-dir = "relative/target"', "command_config_path"),
        ]
        for value, code in cases:
            with self.subTest(value=value):
                with self.assertRaises(runner.RunnerError) as raised:
                    runner.validate_target_build_command(
                        self.command([], extra=value), "ref_store_operations",
                        inventory.TARGETS["ref_store_operations"])
                self.assertEqual(raised.exception.code, code)

    def test_duplicate_conflicting_known_configs_are_rejected(self):
        configs = ["profile.dev.package.rootyard.debug=0",
                   "profile.dev.package.rootyard.debug=1"]
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_target_build_command(
                self.command(configs), "ref_store_operations",
                inventory.TARGETS["ref_store_operations"])
        self.assertEqual(raised.exception.code, "command_config_duplicate")
        configs = ['build.target-dir = "/tmp/one"',
                   'build.target-dir = "/tmp/two"']
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_target_build_command(
                self.command(configs), "ref_store_operations",
                inventory.TARGETS["ref_store_operations"])
        self.assertEqual(raised.exception.code, "command_config_duplicate")


class CommandSemanticsTests(unittest.TestCase):
    def assert_command(self, command, code=None):
        cfg = inventory.TARGETS["ref_store_operations"]
        if code is None:
            runner.validate_target_build_command(command, "ref_store_operations", cfg)
        else:
            with self.assertRaises(runner.RunnerError) as raised:
                runner.validate_target_build_command(command, "ref_store_operations", cfg)
            self.assertEqual(raised.exception.code, code)

    def test_real_producer_and_canonical_test_argv_are_positive(self):
        positives = [
            ["cargo", "rustc", "--locked", "--profile", "test",
             "--test", "ref_store_operations", "--features", "pando-lab",
             "--message-format=json-render-diagnostics"],
            ["cargo", "--config", "profile.dev.package.rootyard.debug=0",
             "--config", "profile.test.package.rootyard.debug=0",
             "rustc", "--locked", "--profile", "test", "--test", "ref_store_operations",
             "--features", "pando-lab", "--message-format=json-render-diagnostics"],
            ["/trusted/bin/cargo", "build", "--locked", "--profile", "test",
             "--config", "build.target-dir = \"/tmp/target\"", "--test", "ref_store_operations",
             "--features", "pando-lab", "--jobs", "2", "--bin", "rootyard"],
            ["cargo", "test", "--no-run", "--test", "ref_store_operations",
             "--features", "pando-lab"],
            ["cargo", "test", "--no-run", "--test=ref_store_operations",
             "--features=pando-lab", "--locked", "--offline"],
        ]
        for command in positives:
            with self.subTest(command=command):
                self.assert_command(command)

    def test_review_mutants_and_ambiguous_argv_are_rejected(self):
        base = ["cargo", "rustc", "--locked", "--profile", "test",
                "--test", "ref_store_operations", "--features", "pando-lab",
                "--message-format=json-render-diagnostics"]
        cases = [
            (base + ["--release"], "command_release_forbidden"),
            (base + ["--profile", "dev"], "command_ambiguous_flag"),
            (["cargo", "rustc", "--locked", "--profile", "dev", "--test",
              "ref_store_operations", "--features", "pando-lab"], "command_profile_mismatch"),
            (base + ["--all-features"], "command_all_features_forbidden"),
            (base + ["--features", "pando-lab,extra"], "command_ambiguous_flag"),
            (["cargo", "rustc", "--locked", "--profile", "test", "--test",
              "ref_store_operations", "--features", "other"], "command_features_mismatch"),
            (base + ["--no-default-features"], "command_no_default_forbidden"),
            (["cargo", "check", "--locked", "--profile", "test", "--test",
              "ref_store_operations", "--features", "pando-lab"], "command_not_test_build"),
            (["cargo", "test", "--test", "ref_store_operations",
              "--features", "pando-lab"], "command_no_run_required"),
            (["cargo", "build", "--locked", "--test", "ref_store_operations",
              "--features", "pando-lab"], "command_profile_mismatch"),
            (base + ["--no-run"], "command_no_run_unsupported"),
            (["cargo", "rustc", "--locked", "--profile", "test", "--test", "other",
              "--features", "pando-lab"], "command_test_target_mismatch"),
            (["cargo", "rustc", "--locked", "--profile", "test", "--test",
              "ref_store_operations", "--test", "ref_store_operations",
              "--features", "pando-lab"], "command_ambiguous_flag"),
            (base + ["--unsupported"], "command_unsupported_flag"),
            (["cargo", "rustc", "--locked", "--profile", "test", "--test",
              "ref_store_operations", "--features", "pando-lab,"], "command_features_invalid"),
            (base + ["--message-format", "json"], "command_ambiguous_flag"),
        ]
        for command, code in cases:
            with self.subTest(code=code, command=command):
                self.assert_command(command, code)

    def test_receipt_command_mutation_is_rejected(self):
        command = ["cargo", "rustc", "--locked", "--profile", "dev", "--test",
                   "ref_store_operations", "--features", "pando-lab"]
        cfg = inventory.TARGETS["ref_store_operations"]
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_target_build_command(command, "ref_store_operations", cfg)
        self.assertEqual(raised.exception.code, "command_profile_mismatch")


class InputClosureTests(unittest.TestCase):
    def test_changed_closure_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "tests").mkdir()
            for name in inventory.INPUT_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x")
            for pattern in inventory.INPUT_GLOBS:
                relative = pattern.replace("**/*.rs", "mod.rs") if "**/*.rs" in pattern else pattern.replace("*.rs", "seed.rs")
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("one")
            (root / "tests/ref_store_operations.rs").write_text("one")
            before = runner.input_hashes(root)
            (root / "tests/ref_store_operations.rs").write_text("two")
            after = runner.input_hashes(root)
            self.assertNotEqual(before, after)
            self.assertIn("tests/ref_store_operations.rs", before)


class BoundedProcessTests(unittest.TestCase):
    def test_timeout_with_unresolved_process_is_failure(self):
        process = mock.Mock()
        process.pid = 123
        process.stdout = io.BytesIO(b"")
        process.wait.side_effect = subprocess.TimeoutExpired("fake", 1)
        process.poll.return_value = None
        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner.os, "getpgid", return_value=123), \
             mock.patch.object(runner.os, "killpg"):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=0.01)
        self.assertEqual(raised.exception.code, "cleanup_unresolved")


class ReportValidatorTests(unittest.TestCase):
    def test_valid_synthetic_report(self):
        self.assertEqual(runner.validate_report(target_report(), HEAD),
                         {"targets": 11, "cases": 167})
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_report(target_report(), "0" * 40)
        self.assertEqual(raised.exception.code, "wrong_source_head")

    def test_mutations_are_rejected(self):
        wrong = target_report(); wrong["targets"].pop()
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_report(wrong, HEAD)
        self.assertEqual(raised.exception.code, "target_order_mismatch")
        wrong = target_report(); wrong["targets"][0]["cases"].pop()
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_report(wrong, HEAD)
        self.assertEqual(raised.exception.code, "target_case_inventory_mismatch")
        wrong = target_report(); wrong["skips"] = 1
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_report(wrong, HEAD)
        self.assertEqual(raised.exception.code, "skipped_cases")
        wrong = target_report(); wrong["cleanup_unresolved"] = True
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_report(wrong, HEAD)
        self.assertEqual(raised.exception.code, "cleanup_unresolved")
        wrong = target_report(); wrong["error_codes"] = ["native_timeout"]
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_report(wrong, HEAD)
        self.assertEqual(raised.exception.code, "runner_errors")
        wrong = target_report(); wrong["input_closure_after_sha256"] = {"a": "0" * 64}
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_report(wrong, HEAD)
        self.assertEqual(raised.exception.code, "input_closure_drift")
        wrong = target_report(); wrong["targets"][0]["cases"][0], wrong["targets"][0]["cases"][1] = (
            wrong["targets"][0]["cases"][1], wrong["targets"][0]["cases"][0])
        with self.assertRaises(runner.RunnerError) as raised:
            runner.validate_report(wrong, HEAD)
        self.assertEqual(raised.exception.code, "target_case_inventory_mismatch")


if __name__ == "__main__":
    unittest.main()
