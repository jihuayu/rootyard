#!/usr/bin/env python3
"""Pure hermetic regression for the native11 mutable source-input closure."""
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import issue107_native11_inventory as inventory  # noqa: E402
import issue107_native11_runner as runner  # noqa: E402

HELPER = "tests/ref_store_pack_snapshots_support/metadata_replay_trace.rs"
HELPER_GLOB = "tests/ref_store_pack_snapshots_support/**/*.rs"


def _seed_fixture(root: Path) -> Path:
    """Create one temporary file for every declared input so closure is complete."""
    for name in inventory.INPUT_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"// fixture {name}\n")
    for pattern in inventory.INPUT_GLOBS:
        if pattern == HELPER_GLOB:
            relative = HELPER
        elif "**/*.rs" in pattern:
            relative = pattern.replace("**/*.rs", "fixture.rs")
        elif "*.rs" in pattern:
            relative = pattern.replace("*.rs", "fixture.rs")
        else:
            raise AssertionError(f"unexpected input glob: {pattern}")
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"// fixture {relative}\n")
    return root


class ActualClosureTests(unittest.TestCase):
    def test_repository_closure_collects_metadata_replay_helper(self):
        closure = inventory.closure(ROOT)
        self.assertEqual(closure, sorted(set(closure)))
        self.assertIn(HELPER, closure)
        self.assertEqual(inventory.INPUT_GLOBS.count(HELPER_GLOB), 1)
        hashes = runner.input_hashes(ROOT)
        self.assertIn(HELPER, hashes)
        self.assertEqual(
            hashes[HELPER],
            hashlib.sha256((ROOT / HELPER).read_bytes()).hexdigest(),
        )

    def test_pack_snapshot_target_imports_the_collected_helper(self):
        target = inventory.TARGETS["ref_store_pack_snapshots"]
        source = (ROOT / target["source"]).read_text()
        self.assertEqual(target["source"], "tests/ref_store_pack_snapshots.rs")
        self.assertIn(
            '#[path = "ref_store_pack_snapshots_support/metadata_replay_trace.rs"]',
            source,
        )

    def test_exact_inventory_and_helper_is_not_a_rust_integration_target(self):
        self.assertEqual(len(inventory.TARGET_ORDER), 11)
        self.assertEqual(set(inventory.TARGET_ORDER), set(inventory.TARGETS))
        pairs = []
        for target in inventory.TARGET_ORDER:
            cases = inventory.TARGETS[target]["cases"]
            self.assertEqual(len(cases), len(set(cases)), target)
            pairs.extend((target, name) for name in cases)
        self.assertEqual(len(pairs), 167)
        self.assertEqual(len(set(pairs)), 167)
        self.assertEqual(
            len(inventory.TARGETS["ref_store_pack_snapshots"]["cases"]), 25)
        self.assertNotIn(HELPER, inventory.TARGET_ORDER)
        self.assertNotIn(HELPER, {cfg["source"] for cfg in inventory.TARGETS.values()})


class FixtureClosureTests(unittest.TestCase):
    def test_helper_bytes_are_hashed_and_drift_changes_input_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _seed_fixture(Path(temporary))
            helper = root / HELPER
            before = runner.input_hashes(root)
            self.assertIn(HELPER, before)
            self.assertEqual(
                before[HELPER], hashlib.sha256(helper.read_bytes()).hexdigest())
            helper.write_text("// changed helper bytes\n")
            after = runner.input_hashes(root)
            self.assertNotEqual(before, after)
            self.assertEqual(set(before), set(after))
            self.assertEqual(
                [name for name in before if before[name] != after[name]],
                [HELPER],
            )

    def test_removing_helper_glob_silently_drops_drift_detection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _seed_fixture(Path(temporary))
            old_globs = tuple(
                pattern for pattern in inventory.INPUT_GLOBS
                if pattern != HELPER_GLOB)
            with mock.patch.object(inventory, "INPUT_GLOBS", old_globs):
                before = runner.input_hashes(root)
                self.assertNotIn(HELPER, before)
                (root / HELPER).write_text("// changed helper bytes\n")
                after = runner.input_hashes(root)
                self.assertEqual(before, after)

    def test_required_helper_glob_rejects_a_missing_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = _seed_fixture(Path(temporary))
            (root / HELPER).unlink()
            with self.assertRaises(ValueError) as raised:
                inventory.closure(root)
            self.assertEqual(
                str(raised.exception),
                "required native11 input closure is unavailable",
            )


if __name__ == "__main__":
    unittest.main()
