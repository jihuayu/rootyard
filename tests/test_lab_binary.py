"""Focused mock/static contracts for the pure lab-binary selector.

Nothing in this module invokes Cargo, rustc, a builder, an installer or a native
executable.  A fake executable file and an injected binder exercise selection,
fail-closed errors and provenance forwarding.
"""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_binary  # noqa: E402


class LabBinarySelectorTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rootyard-lab-binary-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def binary(self, name="rootyard-view-lab"):
        path = self.root / name
        path.write_bytes(b"prebuilt lab fixture")
        path.chmod(0o755)
        return path

    def test_explicit_path_wins_over_environment_and_is_bound(self):
        explicit = self.binary("explicit-lab")
        ignored = self.binary("environment-lab")
        binder = mock.Mock(return_value={"production_inputs_bound": True})
        selected = lab_binary.resolve_lab_binary(
            "ROOTYARD_VIEW_LAB_BIN",
            explicit=explicit,
            legacy=self.root / "legacy-lab",
            environ={"ROOTYARD_VIEW_LAB_BIN": str(ignored)},
            binder=binder,
        )
        self.assertEqual(selected.path, explicit)
        self.assertFalse(selected.from_environment)
        self.assertEqual(selected.binding, {"production_inputs_bound": True})
        binder.assert_called_once_with(
            explicit,
            expected_commit=None,
            environ={"ROOTYARD_VIEW_LAB_BIN": str(ignored)},
        )

    def test_absolute_environment_path_wins_over_legacy(self):
        environment = self.binary("environment-lab")
        legacy = self.binary("legacy-lab")
        binder = mock.Mock(return_value={"schema": "v2"})
        selected = lab_binary.resolve_lab_binary(
            "ROOTYARD_WORKSPACE_LAB_BIN",
            legacy=legacy,
            environ={"ROOTYARD_WORKSPACE_LAB_BIN": str(environment)},
            expected_commit="a" * 40,
            binder=binder,
        )
        self.assertEqual(selected.path, environment)
        self.assertTrue(selected.from_environment)
        binder.assert_called_once_with(
            environment,
            expected_commit="a" * 40,
            environ={"ROOTYARD_WORKSPACE_LAB_BIN": str(environment)},
        )

    def test_legacy_prebuilt_is_used_only_when_environment_is_absent(self):
        legacy = self.binary("legacy-lab")
        binder = mock.Mock(return_value={"attested": True})
        selected = lab_binary.resolve_lab_binary(
            "ROOTYARD_PANDO_LAB_BIN",
            legacy=legacy,
            environ={},
            binder=binder,
        )
        self.assertEqual(selected.path, legacy)
        self.assertFalse(selected.from_environment)
        binder.assert_called_once()

    def test_relative_environment_value_is_rejected_without_path_guessing(self):
        binder = mock.Mock(side_effect=AssertionError("binder must not run"))
        with mock.patch("subprocess.run") as run, mock.patch("subprocess.Popen") as popen:
            with self.assertRaisesRegex(lab_binary.LabBinaryError, "absolute canonical"):
                lab_binary.resolve_lab_binary(
                    "ROOTYARD_VIEW_LAB_BIN",
                    legacy=self.root / "legacy-lab",
                    environ={"ROOTYARD_VIEW_LAB_BIN": "rootyard-view-lab"},
                    binder=binder,
                )
        binder.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()

    def test_parent_traversal_environment_value_is_rejected(self):
        with self.assertRaisesRegex(lab_binary.LabBinaryError, "parent directories"):
            lab_binary.resolve_lab_binary(
                "ROOTYARD_VIEW_LAB_BIN",
                environ={"ROOTYARD_VIEW_LAB_BIN": str(self.root / ".." / "lab")},
                bind=False,
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlinked_environment_alias_is_rejected(self):
        target = self.binary("canonical-lab")
        alias = self.root / "mutable-alias"
        alias.symlink_to(target)
        binder = mock.Mock(side_effect=AssertionError("binder must not run"))
        with self.assertRaisesRegex(lab_binary.LabBinaryError, "symlink"):
            lab_binary.resolve_lab_binary(
                "ROOTYARD_VIEW_LAB_BIN",
                environ={"ROOTYARD_VIEW_LAB_BIN": str(alias)},
                binder=binder,
            )
        binder.assert_not_called()

    def test_missing_environment_artifact_hardfails_with_preparation_instruction(self):
        missing = self.root / "missing-lab"
        binder = mock.Mock(side_effect=AssertionError("binder must not run"))
        with mock.patch("subprocess.run") as run, mock.patch("subprocess.Popen") as popen:
            with self.assertRaisesRegex(
                lab_binary.LabBinaryError,
                "explicit native build preparation",
            ) as caught:
                lab_binary.resolve_lab_binary(
                    "ROOTYARD_VIEW_LAB_BIN",
                    environ={"ROOTYARD_VIEW_LAB_BIN": str(missing)},
                    binder=binder,
                )
        self.assertIn("ROOTYARD_VIEW_LAB_BIN", str(caught.exception))
        self.assertIn("never invokes Cargo", str(caught.exception))
        binder.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()

    def test_missing_environment_does_not_fall_back_to_legacy(self):
        legacy = self.binary("legacy-lab")
        binder = mock.Mock(side_effect=AssertionError("binder must not run"))
        with self.assertRaisesRegex(lab_binary.LabBinaryError, "missing or not executable"):
            lab_binary.resolve_lab_binary(
                "ROOTYARD_PANDO_LAB_BIN",
                legacy=legacy,
                environ={"ROOTYARD_PANDO_LAB_BIN": str(self.root / "absent-lab")},
                binder=binder,
            )
        binder.assert_not_called()

    def test_stale_binding_hardfails_and_never_retries_legacy(self):
        environment = self.binary("environment-lab")
        legacy = self.binary("legacy-lab")
        binder = mock.Mock(side_effect=RuntimeError("stale build receipt"))
        with self.assertRaisesRegex(lab_binary.LabBinaryError, "stale build receipt") as caught:
            lab_binary.resolve_lab_binary(
                "ROOTYARD_VFS_MOUNT_BIN",
                legacy=legacy,
                environ={"ROOTYARD_VFS_MOUNT_BIN": str(environment)},
                binder=binder,
            )
        self.assertIn("explicit native build preparation", str(caught.exception))
        self.assertEqual(binder.call_count, 1)

    def test_real_receipt_reader_rejects_an_unreceipted_prebuilt(self):
        binary = self.binary("no-receipt-lab")
        with self.assertRaisesRegex(
            lab_binary.LabBinaryError,
            "no matching adjacent receipt",
        ) as caught:
            lab_binary.resolve_lab_binary(
                "ROOTYARD_VIEW_LAB_BIN",
                environ={"ROOTYARD_VIEW_LAB_BIN": str(binary)},
            )
        self.assertIn("explicit native build preparation", str(caught.exception))

    def test_optional_selector_returns_none_when_nothing_is_configured(self):
        selected = lab_binary.resolve_optional_lab_binary(
            "ROOTYARD_PANDO_LAB_BIN",
            legacy=self.root / "absent-legacy-lab",
            environ={},
            binder=mock.Mock(side_effect=AssertionError("binder must not run")),
        )
        self.assertIsNone(selected)

    def test_optional_selector_still_hardfails_for_configured_missing_env(self):
        with self.assertRaisesRegex(lab_binary.LabBinaryError, "missing or not executable"):
            lab_binary.resolve_optional_lab_binary(
                "ROOTYARD_PANDO_LAB_BIN",
                legacy=self.binary("legacy-lab"),
                environ={"ROOTYARD_PANDO_LAB_BIN": str(self.root / "absent-lab")},
                binder=mock.Mock(side_effect=AssertionError("binder must not run")),
            )

    def test_optional_selector_binds_present_legacy_prebuilt(self):
        legacy = self.binary("legacy-lab")
        binder = mock.Mock(return_value={"schema": "v2"})
        selected = lab_binary.resolve_optional_lab_binary(
            "ROOTYARD_PANDO_LAB_BIN",
            legacy=legacy,
            environ={},
            binder=binder,
        )
        self.assertIsNotNone(selected)
        self.assertEqual(selected.path, legacy)
        binder.assert_called_once()


class LabSelectorSourceContractTest(unittest.TestCase):
    """Static checks: runtime test modules select env artifacts and never build."""

    def test_view_lab_setup_has_no_implicit_build(self):
        text = (Path(__file__).resolve().parent / "test_view_lab.py").read_text(encoding="utf-8")
        self.assertNotIn("cargo build", text)
        self.assertNotIn(".cargo/bin", text)
        self.assertIn("ROOTYARD_VIEW_LAB_BIN", text)
        self.assertIn("resolve_lab_binary", text)


if __name__ == "__main__":
    unittest.main()
