#!/usr/bin/env python3
"""Static contract for the issue #169 format22 fixture CI wiring.

The fixture ``tests/ref_store_format22_backup_fixture.rs`` is a real
``harness = false`` program whose no-argument invocation must fail, so it may
never run inside the all-targets test/clippy gates. This module pins, without
building or running anything:

* Cargo: the target keeps ``harness = false`` and its existing ``pando-lab``
  profile, and gains an opt-in ``format22-fixture`` gate through
  ``required-features = ["pando-lab", "format22-fixture"]``, where the opt-in
  feature is declared and not enabled by the all-targets commands;
* the workflow: the fixture is built first with one
  ``scripts/build_native_test.py --test ref_store_format22_backup_fixture``
  command (which clears the rootyard package), the standalone product for the
  paired drill afterwards with ``scripts/build_native.py``; unrelated builder
  targets in the same workflow are ignored. Outputs stay under
  ``test-results/refstore/`` so the executable and its adjacent ``.build.json``
  receipt are uploaded, and the receipt reaches the drill through
  ``--format22-fixture`` next to ``--binary``/``--git``/``--report``;
* the trigger path list covers ``tests/format22_support/**``.

Only the standard library is used; full YAML/TOML validity is proven by the
consuming tools.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "refstore-protocol-acceptance.yml"
CARGO = ROOT / "Cargo.toml"
FIXTURE = "ref_store_format22_backup_fixture"
FIXTURE_FEATURE = "format22-fixture"
EXISTING_FEATURE = "pando-lab"
FIXTURE_FEATURES = f"{EXISTING_FEATURE},{FIXTURE_FEATURE}"
RESULT_DIR = "test-results/refstore"
# The absolute directory the workflow builder writes into, inside the checkout.
FIXTURE_DIR = f"$GITHUB_WORKSPACE/{RESULT_DIR}"
FIXTURE_OUTPUT = f"$fixture_dir/{FIXTURE}"


def _feature_names() -> dict[str, str]:
    """``[features]`` names mapped to their raw (joined) values."""
    features: dict[str, str] = {}
    section = None
    current = None
    for line in CARGO.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if line.startswith("["):
            section, current = stripped, None
            continue
        if section != "[features]" or not stripped or stripped.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z_][\w-]*)\s*=\s*(.*)", stripped)
        if match:
            current = match.group(1)
            features[current] = match.group(2)
        elif current is not None:
            features[current] += " " + stripped
    return features


def _test_target(name: str) -> dict[str, str]:
    """Keys of ``[[test]]`` blocks whose ``name`` matches, with raw values."""
    blocks: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    section = None
    for line in CARGO.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if line.startswith("["):
            section = stripped
            current = None
            if section == "[[test]]":
                current = {}
                blocks.append(current)
            continue
        if section != "[[test]]" or not stripped or stripped.startswith("#") or current is None:
            continue
        match = re.fullmatch(r"([A-Za-z_][\w.-]*)\s*=\s*(.*)", stripped)
        if match:
            current[match.group(1)] = match.group(2)
    matches = [block for block in blocks if block.get("name", "").strip('"') == name]
    if len(matches) != 1:
        raise AssertionError(f"Cargo.toml declares {len(matches)} [[test]] blocks named {name}")
    return matches[0]


def _value(raw: str) -> object:
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        return [item.strip().strip("'\"") for item in raw[1:-1].split(",") if item.strip()]
    return raw.strip("'\"")


class CargoOptInTest(unittest.TestCase):
    def test_fixture_remains_a_real_harness_false_program(self) -> None:
        target = _test_target(FIXTURE)
        self.assertEqual(_value(target["harness"]), "false")
        self.assertEqual(_value(target["path"]), f"tests/{FIXTURE}.rs")

    def test_fixture_keeps_pando_lab_and_adds_an_opt_in_gate(self) -> None:
        target = _test_target(FIXTURE)
        self.assertIn("required-features", target, "fixture would run in every all-targets gate")
        required = _value(target["required-features"])
        self.assertIsInstance(required, list)
        # The existing pando-lab profile is preserved, not replaced by the gate.
        self.assertEqual(required, [EXISTING_FEATURE, FIXTURE_FEATURE])
        features = _feature_names()
        for required_feature in required:
            self.assertIn(required_feature, features, f"required feature {required_feature} is not declared")
        # Declared gate must be dependency-free: it selects the target only.
        self.assertNotIn("dep:", features[FIXTURE_FEATURE])
        self.assertNotIn(FIXTURE_FEATURE, _value(features[EXISTING_FEATURE]),
                         "pando-lab must not imply the fixture gate")
        self.assertNotIn(FIXTURE_FEATURE, self._enabled(set(), features),
                         "the fixture feature must stay default-OFF")

    def test_all_targets_gates_still_omit_the_fixture(self) -> None:
        # The gates in ci.yml/pando-lab.yml/redis-contract.yml exactly as written.
        gates = (("pando-lab", False), ("pando-lab", True), ("state-redis", False), ("state-redis", True))
        required = _value(_test_target(FIXTURE)["required-features"])
        features = _feature_names()
        for named, no_default_features in gates:
            with self.subTest(features=named, no_default_features=no_default_features):
                enabled = self._enabled({named}, features, default_off=no_default_features)
                self.assertNotIn(FIXTURE_FEATURE, enabled)
                self.assertFalse(set(required) <= enabled,
                                 "an all-targets command would now select the fixture target")

    @staticmethod
    def _enabled(named: set[str], features: dict[str, str], default_off: bool = False) -> set[str]:
        """Features Cargo would enable (fully qualified `pkg/feat` edges skipped).

        Local feature names repeat items such as ``dep:rdkafka``; dependency
        activation is not modelled, only the local features the target needs.
        """
        resolved = {name: _value(raw) for name, raw in features.items()}
        enabled = set() if default_off else set(resolved.get("default", []))
        pending = list(named) + list(enabled)
        while pending:
            name = pending.pop()
            if name in enabled:
                continue
            enabled.add(name)
            for item in resolved.get(name, []):
                if not item.startswith("dep:") and "/" not in item and item not in enabled:
                    pending.append(item)
        return enabled

    def test_fixture_no_argument_invocation_still_fails(self) -> None:
        # The usage path is a program failure, not a passing fake test.
        support = (ROOT / "tests" / "format22_support" / "mod.rs").read_text(encoding="utf-8")
        self.assertIn('ok_or_else(||', support)
        self.assertIn("ref_store_format22_backup_fixture (--digest-vector", support)
        fixture = (ROOT / "tests" / f"{FIXTURE}.rs").read_text(encoding="utf-8")
        self.assertIn("Err(error) =>", fixture)
        self.assertIn("std::process::exit(1)", fixture)


class WorkflowWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.lines = self.text.splitlines()

    def _index(self, needle: str, start: int = 0, command: bool = False) -> int:
        """Line index of ``needle``; with ``command`` only run lines whose first
        command token (after ``python3``) is ``needle`` match."""
        for index in range(start, len(self.lines)):
            line = self.lines[index].strip()
            if not line:
                continue
            if not command:
                if needle in line:
                    return index
                continue
            tokens = line.split()
            if line.startswith("#"):
                if needle in tokens:
                    return index
                continue
            if tokens[0] in ("python3", "python") and len(tokens) > 1:
                tokens = tokens[1:]
            if tokens and tokens[0] == needle :
                return index
        return -1

    def _continued(self, index: int) -> str:
        """A logical run line including `\\` continuations."""
        parts = [self.lines[index].strip()]
        while parts[-1].endswith("\\") and index + 1 < len(self.lines):
            index += 1
            parts.append(self.lines[index].strip())
        return " ".join(parts)

    def _anchor(self, text: str) -> int:
        """Line index of the first run line containing ``text``."""
        index = self._index(text)
        self.assertGreaterEqual(index, 0, f"workflow has no line containing `{text}`")
        return index

    def _find_command(self, needle: str) -> tuple[int, str]:
        index = self._index(needle, command=True)
        self.assertGreaterEqual(index, 0, f"workflow has no `{needle}`")
        return index, self._continued(index)

    def _builder_commands(self, script: str) -> list[tuple[int, str]]:
        """Every run line invoking ``script`` (after ``python3``), as
        ``(line index, logical line)``."""
        commands = []
        for index, line in enumerate(self.lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            tokens = stripped.split()
            if tokens[0] in ("python3", "python") and len(tokens) > 1:
                tokens = tokens[1:]
            if tokens and tokens[0] == script:
                commands.append((index, self._continued(index)))
        return commands

    def _fixture_builders(self) -> list[tuple[int, str]]:
        """Commands building exactly the issue #169 fixture under its stages."""
        return [(index, line) for index, line in self._builder_commands("scripts/build_native_test.py")
                if re.search(r"(^|\s)--test(\s+|=)" + re.escape(FIXTURE) + r"(\s|$)", line)]

    def _product_builders(self, start: int) -> list[tuple[int, str]]:
        """Standalone product builds exiting between ``start`` and the drill."""
        drill_index, _ = self._find_command("tests/backup_blob_serving147.py")
        return [(index, line) for index, line in self._builder_commands("scripts/build_native.py")
                if start < index < drill_index]

    def _pr_paths(self) -> list[str]:
        """Entries of the ``pull_request.paths`` list, in order."""
        try:
            start = self.lines.index("  pull_request:")
        except ValueError:
            self.fail("workflow has no `pull_request:` trigger")
        end = next((index for index in range(start + 1, len(self.lines))
                    if self.lines[index].strip() and not self.lines[index].startswith("    ")),
                   len(self.lines))
        block = self.lines[start + 1:end]
        self.assertEqual(block[0].strip(), "paths:", f"pull_request is not a bare block: {block[:2]}")
        paths = []
        for line in block[1:]:
            if not line.strip():
                continue
            self.assertRegex(line, r"^      - '.+'$", "unexpected entry under pull_request.paths")
            paths.append(line.strip()[2:].strip("'"))
        return paths

    def test_pr_paths_cover_every_issue169_input(self) -> None:
        paths = self._pr_paths()
        for required in ("tests/ref_store_*.rs", "tests/format22_support/**",
                         "tests/backup_blob_serving169_support.py",
                         "tests/test_backup_blob_serving169_support.py"):
            with self.subTest(path=required):
                self.assertIn(required, paths)
        # The drill imports the support module and its focused test imports it too.
        drill = (ROOT / "tests" / "backup_blob_serving147.py").read_text(encoding="utf-8")
        self.assertIn("backup_blob_serving169_support", drill)
        self.assertTrue((ROOT / "tests" / "test_backup_blob_serving169_support.py").is_file())
        self.assertEqual(paths.count("tests/backup_blob_serving169_support.py"), 1)
        self.assertEqual(paths.count("tests/test_backup_blob_serving169_support.py"), 1)
        self.assertNotIn("paths-ignore", self.text)

    def test_fixture_builder_precedes_product_builder(self) -> None:
        # Main also builds other native targets (e.g. blob_git_gateway), so the
        # contract is scoped to the fixture command and the product build that
        # feeds the paired drill, not to every builder invocation in the file.
        fixture_builders = self._fixture_builders()
        self.assertEqual(len(fixture_builders), 1,
                         f"expected one builder command with `--test {FIXTURE}`: {fixture_builders}")
        fixture_index, fixture_line = fixture_builders[0]
        product_builders = self._product_builders(fixture_index)
        self.assertEqual(len(product_builders), 1,
                         f"expected one standalone product build between the fixture build and the "
                         f"paired drill: {product_builders}")
        self.assertLess(fixture_index, product_builders[0][0],
                        "build_native_test.py clears the rootyard package before the product build")
        self.assertIn(f"--test {FIXTURE}", fixture_line)
        self.assertIn(f"--features {FIXTURE_FEATURES}", fixture_line)
        for replaced_profile in (f"--features {FIXTURE_FEATURE} ", f"--features {EXISTING_FEATURE} "):
            self.assertNotIn(replaced_profile, fixture_line,
                             "the builder must pass pando-lab and format22-fixture together")
        self.assertRegex(fixture_line, r"(^|\s)--no-default-features(\s|$)")
        self.assertIn("--package-debug 0", fixture_line)
        self.assertIn("--strip-debuginfo", fixture_line)
        self.assertIn(f'--output "{FIXTURE_OUTPUT}"', fixture_line)
        step_start = self._anchor("Build and exercise the minimal Blob")
        run_index = self._index("run: |", step_start)
        self.assertGreater(fixture_index, run_index)
        self.assertLess(self._anchor("mkdir -p test-results/refstore"), run_index)

    def test_drill_receives_fixture_receipt_adjacent_to_executable(self) -> None:
        # Later native steps also build their own product binary; only the
        # assignment in the paired-drill step (before the drill command) belongs
        # to this contract.
        drill_index, drill = self._find_command("tests/backup_blob_serving147.py")
        binary_lines = [index for index, line in enumerate(self.lines)
                        if line.strip() == 'binary="$GITHUB_WORKSPACE/target/debug/rootyard"']
        self.assertEqual(len([index for index in binary_lines if index < drill_index]), 1,
                         "the paired drill needs exactly one product binary assignment before it")
        self.assertEqual(len(re.findall(
            r'^\s+fixture="\$fixture_dir/' + FIXTURE + r'"$', self.text, re.MULTILINE)), 1)
        self.assertIn('--format22-fixture "$fixture"', drill)
        self.assertIn('--binary "$binary"', drill)
        self.assertIn('--git "$ROOTYARD_GIT"', drill)
        self.assertIn(f"--report {RESULT_DIR}/standalone-paired-backup.json", drill)
        self.assertLess(drill.index('--binary'), drill.index('--format22-fixture'))
        self.assertLess(drill.index('--format22-fixture'), drill.index('--report'))

    def test_artifact_retains_executable_and_adjacent_receipt(self) -> None:
        # The workflow binds fixture_dir to the absolute directory it writes into.
        binding_index = self._anchor(f'fixture_dir="{FIXTURE_DIR}"')
        binding = re.fullmatch(r'\s*fixture_dir="(.+)"', self.lines[binding_index])
        self.assertIsNotNone(binding, "fixture_dir must be one plain assignment")
        directory = binding.group(1)
        self.assertEqual(directory, "$GITHUB_WORKSPACE/test-results/refstore")
        # The fixture builder writes the executable through that variable.
        fixture_index, fixture_line = self._find_command("scripts/build_native_test.py")
        self.assertGreater(fixture_index, binding_index)
        outputs = re.findall(r'--output "(\$fixture_dir/[^"]+)"', fixture_line)
        self.assertEqual(outputs, [f"$fixture_dir/{FIXTURE}"])
        # The artifact upload keeps that same directory (relative to the
        # checkout), so it retains the executable and the builder's adjacent
        # <output>.build.json receipt (tests/backup_blob_serving147.py reads it).
        name_index = self._anchor("name: refstore-protocol-native-${{ github.run_id }}-${{ github.run_attempt }}")
        step_start = max(index for index in range(name_index) if self.lines[index].strip() == "- uses: actions/upload-artifact@v4")
        step_end = next((index for index in range(step_start + 1, len(self.lines))
                         if self.lines[index].startswith("      - ")), len(self.lines))
        step = [line.strip() for line in self.lines[step_start:step_end]]
        self.assertIn("path: test-results/refstore/", step)
        self.assertIn("if-no-files-found: error", step)
        self.assertLess(fixture_index, step_start)
        # The upload path (relative to the checkout) names exactly that directory.
        self.assertEqual(directory.replace("$GITHUB_WORKSPACE/", ""), "test-results/refstore")
        uploaded = next(line.split(":", 1)[1].strip() for line in step if line.startswith("path:"))
        self.assertEqual(Path(uploaded.rstrip("/")) / FIXTURE,
                         Path("test-results/refstore/ref_store_format22_backup_fixture"))
        self.assertEqual((Path(uploaded.rstrip("/")) / FIXTURE).with_suffix(".build.json").as_posix(),
                         "test-results/refstore/ref_store_format22_backup_fixture.build.json")
        drill = (ROOT / "tests" / "backup_blob_serving147.py").read_text(encoding="utf-8")
        self.assertIn('Path(args.format22_fixture).with_suffix(".build.json")', drill)

    def test_drill_callback_and_zero_skip_contract_is_intact(self) -> None:
        harness = (ROOT / "tests" / "backup_blob_serving147.py").read_text(encoding="utf-8")
        cases = re.search(r'^CASES = \((.*?)^\)', harness, re.MULTILINE | re.DOTALL).group(1)
        names = tuple(re.findall(r'"([a-z0-9_]+)"', cases))
        # Pin the complete issue-#169 set, not only its count: a removed
        # negative would otherwise still satisfy a length assertion.
        expected = (
            "real_http_sha1_sha256_source_without_persistent_bare",
            "offline_volume_and_postgres_snapshot_barriers",
            "incomplete_and_damaged_archives_rejected_before_sql",
            "existing_database_and_directory_targets_refused",
            "missing_pack",
            "missing_idx",
            "missing_all_artifacts",
            "wrong_artifact_set_digest",
            "missing_hold",
            "mismatched_hold_locator",
            "post_backup_acknowledged_write_excluded",
            "fresh_database_restore_clone_refs_content_fsck",
            "restored_exact_receive_replay_without_second_effect",
            "format22_active_released_roots_distinct_producer_roundtrip",
        )
        self.assertEqual(names, expected)
        # Every corruption callback the harness advertises is one of the cases,
        # and the six issue-#169 negatives are exactly the advertised set.
        callbacks = re.search(r'^CORRUPTION_CALLBACKS = \{(.*?)^\}', harness, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(callbacks)
        advertised = tuple(re.findall(r'^\s+"([a-z0-9_]+)":\s*"([a-z0-9_]+)",?$', callbacks.group(1),
                                      re.MULTILINE))
        self.assertEqual(tuple(name for name, _ in advertised),
                         ("missing_pack", "missing_idx", "missing_all_artifacts", "wrong_artifact_set_digest",
                          "missing_hold", "mismatched_hold_locator"))
        self.assertEqual(tuple(callback for _, callback in advertised),
                         ("corrupt_source_missing_pack_refused_before_publication",
                          "corrupt_source_missing_idx_refused_before_publication",
                          "corrupt_source_missing_all_artifacts_refused_before_publication",
                          "corrupt_source_wrong_artifact_set_digest_refused_before_publication",
                          "corrupt_source_missing_hold_refused_before_publication",
                          "corrupt_source_mismatched_hold_locator_refused_before_publication"))
        self.assertIn('"skips": 0', harness)
        # The drill's own help keeps naming the same two-feature profile.
        self.assertIn(f"--features {FIXTURE_FEATURES} --no-default-features", harness)

    def test_workflow_runs_the_seeded_ledger_validation_pg_tests(self) -> None:
        runs = [self._continued(index) for index, line in enumerate(self.lines)
                if "backup::ledger_validation::pg_tests" in line]
        self.assertEqual(len(runs), 1, "the workflow must run the seeded pg_tests suite exactly once")
        self.assertIn("cargo test --locked --lib --features pando-lab "
                      "backup::ledger_validation::pg_tests", runs[0])
        self.assertIn("-- --ignored --test-threads=1", runs[0])

    def test_ci_discovers_the_issue169_tests_and_runs_the_native_drill(self) -> None:
        # ci.yml's full unittest discovery is what executes the static #169
        # contracts (this module and the digest/corruption plan tests).
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python3 -m unittest discover -s tests -p 'test_*.py'", ci)
        self.assertTrue((ROOT / "tests" / "test_backup_blob_serving169_support.py").is_file())
        # The native drill (all four PG corruption negatives plus the format22
        # positive) is a command in the RefStore acceptance workflow, fed the
        # source-bound fixture receipt.
        drill_index, drill = self._find_command("tests/backup_blob_serving147.py")
        self.assertIn('--binary "$binary"', drill)
        self.assertIn('--format22-fixture "$fixture"', drill)
        self.assertLess(drill_index, len(self.lines))
        self.assertFalse(self._index("tests/backup_blob_serving147.py", drill_index + 1, command=True) >= 0,
                         "the paired drill must run exactly once per workflow")


if __name__ == "__main__":
    unittest.main()
