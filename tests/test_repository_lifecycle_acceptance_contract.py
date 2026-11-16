"""Offline contract tests for the Issue #85 literal acceptance runner.

These tests are pure: they execute no service, database, Git clone/push, LFS
network, Docker, compiler or Cargo operation.  They use temporary files and an
injectable validator only where a real native build receipt cannot be produced
without a compiler; the canonical receipt reader itself is the real existing
``scripts/native_build_receipt.py`` implementation.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import repository_lifecycle_acceptance_support as support



def _source(clean=True, commit="a" * 40, tree="b" * 40, untracked=0):
    return {
        "commit": commit,
        "tree": tree,
        "parents": [],
        "working_tree_dirty": not clean,
        "tracked_dirty": not clean and untracked == 0,
        "untracked_count": untracked,
        "clean": clean,
    }


def _receipt(commit="a" * 40, binary="c" * 64, tree="b" * 40, clean=True):
    return {
        "present": True,
        "bound": True,
        "workspace_commit": commit,
        "binary_sha256": binary,
        "recorded_tree": tree,
        "recorded_tree_clean": clean,
        "receipt_anchor_matches": True,
    }


def _helpers(bound=True):
    return {"bound": bound, "count": len(support.ACCEPTANCE_INPUT_PATHS)}


class AcceptanceContractTest(unittest.TestCase):
    def test_checkpoint_inventory_is_exact(self):
        self.assertEqual(
            support.PLAN_CASE_NAMES,
            (
                "backup_root_blocks_purge",
                "serving_read_header_blocks_purge",
                "ci_pin_blocks_purge",
                "rename_alias_accepts_real_git_and_lfs_writes",
            ),
        )

    def test_safe_detail_drops_unknown_nested_and_unsafe_values(self):
        detail = support.safe_detail(
            {
                "fixture": "migration148_retention_metadata",
                "fixture_scope": "metadata_only",
                "hold_count": 1,
                "not_in_allowlist": True,
                "nested": {"sql": "SELECT 1"},
                "too_long": "x" * 200,
                "path_like": "/tmp/secret",
                "negative": -1,
            }
        )
        self.assertEqual(
            detail,
            {
                "fixture": "migration148_retention_metadata",
                "fixture_scope": "metadata_only",
                "hold_count": 1,
            },
        )

    def test_alias_detail_constants_are_accepted(self):
        detail = support.safe_detail(
            {
                "fixture": "rename_alias_real_git_lfs",
                "alias_git_write": "passed",
                "alias_lfs_write": "passed",
                "canonical_head": "new_oid_verified",
                "canonical_bytes": "hash_verified",
                "restricted_read": "redirected",
                "restricted_write": "denied",
                "denied_mutation": "unchanged",
            }
        )
        self.assertEqual(len(detail), 8)

    def test_failure_is_a_failure_not_a_skip(self):
        results = [
            {
                "name": "backup_root_blocks_purge",
                "status": "failed",
                "phase": "blocked_purge",
                "error_class": "assertion",
                "seconds": 0.1,
                "detail": {},
            },
            {
                "name": "serving_read_header_blocks_purge",
                "status": "passed",
                "phase": "control_purge",
                "error_class": None,
                "seconds": 0.2,
                "detail": {},
            },
            {
                "name": "ci_pin_blocks_purge",
                "status": "passed",
                "phase": "control_purge",
                "error_class": None,
                "seconds": 0.3,
                "detail": {},
            },
            {
                "name": "rename_alias_accepts_real_git_and_lfs_writes",
                "status": "passed",
                "phase": "assert_denial_unchanged",
                "error_class": None,
                "seconds": 0.4,
                "detail": {},
            },
        ]
        summary = support.summarize(
            results,
            support.PLAN_CASE_NAMES,
            cleanup_ok=True,
            binding_ok=True,
        )
        self.assertFalse(summary["passed"])
        self.assertTrue(summary["exact"])
        self.assertEqual(summary["missing"], [])
        self.assertEqual(summary["unexpected"], [])

    def test_missing_and_unexpected_cases_fail_exact_inventory(self):
        results = [
            {
                "name": "backup_root_blocks_purge",
                "status": "passed",
                "phase": "control_purge",
                "error_class": None,
                "seconds": 0.1,
                "detail": {},
            },
            {
                "name": "unexpected_case",
                "status": "passed",
                "phase": "control_purge",
                "error_class": None,
                "seconds": 0.1,
                "detail": {},
            },
        ]
        summary = support.summarize(
            results,
            support.PLAN_CASE_NAMES,
            cleanup_ok=True,
            binding_ok=True,
        )
        self.assertFalse(summary["passed"])
        self.assertFalse(summary["exact"])
        self.assertEqual(len(summary["missing"]), 3)
        self.assertEqual(summary["unexpected"], ["unexpected_case"])

    def test_error_classes_are_fixed_and_message_free(self):
        self.assertEqual(support.classify_error(AssertionError("secret")), "assertion")
        self.assertEqual(
            support.classify_error(subprocess.TimeoutExpired(["git"], 1)), "timeout"
        )
        self.assertEqual(
            support.classify_error(subprocess.CalledProcessError(1, ["git"])), "command"
        )
        self.assertEqual(
            support.classify_error(json.JSONDecodeError("x", "", 0)), "decode"
        )
        self.assertEqual(support.classify_error(TimeoutError()), "timeout")
        self.assertEqual(support.classify_error(OSError()), "io")
        self.assertEqual(support.classify_error(RuntimeError("secret")), "other")

    def test_receipt_selection_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "rootyard"
            binary.write_bytes(b"binary")
            explicit = root / "explicit.json"
            explicit.write_text("{}")
            adjacent = root / "rootyard.build.json"
            adjacent.write_text("{}")

            chosen, origin = support.select_receipt(binary, explicit, {})
            self.assertEqual((chosen, origin), (explicit, "cli"))

            chosen, origin = support.select_receipt(
                binary, None, {"ROOTYARD_BUILD_RECEIPT": str(adjacent)}
            )
            self.assertEqual((chosen, origin), (adjacent, "environment"))

            chosen, origin = support.select_receipt(binary, None, {})
            self.assertEqual(
                (chosen, origin),
                (Path(binary).resolve().with_suffix(".build.json"), "adjacent"),
            )

    def test_expected_source_commit_requires_trusted_anchor(self):
        self.assertEqual(
            support.expected_source_commit(None, {}),
            (None, "expected_source_commit_missing"),
        )
        self.assertEqual(
            support.expected_source_commit("A" * 40, {}),
            ("a" * 40, None),
        )
        self.assertEqual(
            support.expected_source_commit(None, {"GITHUB_SHA": "b" * 40}),
            ("b" * 40, None),
        )
        self.assertEqual(
            support.expected_source_commit(
                None,
                {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "short", "GITHUB_SHA": "b" * 40},
            ),
            ("short", "expected_source_commit_invalid"),
        )

    def test_expected_receipt_digest_anchor(self):
        self.assertEqual(
            support.expected_receipt_sha256(None, {}),
            (None, "receipt_anchor_missing"),
        )
        self.assertEqual(
            support.expected_receipt_sha256("A" * 64, {}),
            ("a" * 64, None),
        )
        self.assertEqual(
            support.expected_receipt_sha256("bad", {}),
            ("bad", "receipt_anchor_invalid"),
        )

    def test_clean_exact_source_binding_passes(self):
        result = support.evaluate_binding(
            _source(),
            "a" * 40,
            _receipt(),
            "c" * 64,
            _helpers(),
        )
        self.assertTrue(result["bound"])
        self.assertTrue(all(result["checks"].values()))
        self.assertIsNone(result["error_class"])

    def test_dirty_tracked_or_untracked_source_fails_binding(self):
        for source in (
            _source(clean=False, untracked=0),
            _source(clean=False, untracked=1),
        ):
            result = support.evaluate_binding(
                source,
                "a" * 40,
                _receipt(),
                "c" * 64,
                _helpers(),
            )
            self.assertFalse(result["bound"])
            self.assertFalse(result["checks"]["source_clean"])

    def test_wrong_or_missing_expected_source_fails_binding(self):
        missing = support.evaluate_binding(
            _source(), None, _receipt(), "c" * 64, _helpers()
        )
        self.assertFalse(missing["bound"])
        self.assertFalse(missing["checks"]["expected_commit_present"])
        wrong = support.evaluate_binding(
            _source(), "d" * 40, _receipt(), "c" * 64, _helpers()
        )
        self.assertFalse(wrong["bound"])
        self.assertFalse(wrong["checks"]["expected_matches_head"])

    def test_receipt_or_helper_mismatch_fails_binding(self):
        receipt = _receipt(commit="d" * 40)
        result = support.evaluate_binding(
            _source(), "a" * 40, receipt, "c" * 64, _helpers()
        )
        self.assertFalse(result["bound"])
        self.assertFalse(result["checks"]["receipt_commit_matches_head"])

        dirty_receipt = _receipt(clean=False)
        result = support.evaluate_binding(
            _source(), "a" * 40, dirty_receipt, "c" * 64, _helpers()
        )
        self.assertFalse(result["bound"])
        self.assertFalse(result["checks"]["receipt_working_tree_clean"])

        result = support.evaluate_binding(
            _source(), "a" * 40, _receipt(), "c" * 64, _helpers(bound=False)
        )
        self.assertFalse(result["bound"])
        self.assertFalse(result["checks"]["helper_inputs_bound"])

    def test_helper_input_manifest_detects_missing_or_changed_committed_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            committed = {}
            for relative in support.ACCEPTANCE_INPUT_PATHS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                data = ("content:" + relative).encode()
                path.write_bytes(data)
                committed[relative] = data
            clean = support.helper_input_manifest(
                root, committed_reader=lambda relative: committed[relative]
            )
            self.assertTrue(clean["bound"])
            self.assertEqual(clean["count"], len(support.ACCEPTANCE_INPUT_PATHS))
            self.assertEqual(clean["error_class"], None)

            changed = support.helper_input_manifest(
                root,
                committed_reader=lambda relative: (
                    b"different" if relative == support.ACCEPTANCE_INPUT_PATHS[0] else committed[relative]
                ),
            )
            self.assertFalse(changed["bound"])
            self.assertEqual(changed["error_class"], "helper_inputs_invalid")

            untracked = support.helper_input_manifest(
                root,
                committed_reader=lambda relative: (
                    None if relative == support.ACCEPTANCE_INPUT_PATHS[-1] else committed[relative]
                ),
            )
            self.assertFalse(untracked["bound"])

            (root / support.ACCEPTANCE_INPUT_PATHS[-1]).unlink()
            missing = support.helper_input_manifest(
                root, committed_reader=lambda relative: committed[relative]
            )
            self.assertFalse(missing["bound"])
            self.assertLess(missing["count"], len(support.ACCEPTANCE_INPUT_PATHS))

    def test_receipt_covers_helper_inputs(self):
        files = [{"path": "tests/a.py", "sha256": "a" * 64}]
        payload = {
            "bound_input_inventory": [{"path": "tests/a.py", "sha256": "a" * 64}]
        }
        self.assertTrue(support.receipt_covers_helper_inputs(payload, files))
        self.assertFalse(support.receipt_covers_helper_inputs({}, files))
        self.assertFalse(
            support.receipt_covers_helper_inputs(
                {"bound_input_inventory": [{"path": "tests/a.py", "sha256": "b" * 64}]},
                files,
            )
        )


if __name__ == "__main__":
    unittest.main()
