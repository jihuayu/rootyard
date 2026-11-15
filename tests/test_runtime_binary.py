#!/usr/bin/env python3
"""Offline contract tests for the shared server runtime binary selector."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tests.runtime_binary import (
    RuntimeBinarySelectionError,
    legacy_target_binary,
    select_runtime_binary,
)


class RuntimeBinarySelectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rootyard-runtime-binary-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.local = self._executable(self.root / "debug" / "rootyard", b"stale local target")

    @staticmethod
    def _executable(path: Path, payload: bytes = b"prebuilt fixture") -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o755)
        return path

    def test_canonical_explicit_overrides_stale_local_target(self) -> None:
        canonical = self._executable(self.root / "canonical" / "rootyard")
        environment = {
            "ROOTYARD_BIN": str(canonical),
            "CARGO_TARGET_DIR": str(self.root),
        }
        binder = mock.Mock(return_value={"production_inputs_bound": True})
        with mock.patch("subprocess.run") as run, mock.patch("subprocess.Popen") as popen:
            path, binding = select_runtime_binary(
                environment, root=self.root, binder=binder)
        self.assertEqual(path, canonical.resolve())
        self.assertNotEqual(path, self.local.resolve())
        self.assertTrue(binding["production_inputs_bound"])
        binder.assert_called_once_with(canonical.resolve(), environ=environment)
        run.assert_not_called()
        popen.assert_not_called()

    def test_missing_explicit_fails_without_local_or_compiler_fallback(self) -> None:
        missing = self.root / "missing" / "rootyard"
        environment = {
            "ROOTYARD_BIN": str(missing),
            "CARGO_TARGET_DIR": str(self.root),
        }
        binder = mock.Mock(side_effect=AssertionError("binding must not run"))
        with mock.patch("subprocess.run") as run, mock.patch("subprocess.Popen") as popen:
            with self.assertRaisesRegex(RuntimeBinarySelectionError, "ROOTYARD_BIN"):
                select_runtime_binary(environment, root=self.root, binder=binder)
        binder.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()

    def test_stale_explicit_fails_without_local_fallback(self) -> None:
        explicit = self._executable(self.root / "canonical" / "rootyard")
        environment = {
            "ROOTYARD_TEST_BINARY": str(explicit),
            "CARGO_TARGET_DIR": str(self.root),
        }
        binder = mock.Mock(side_effect=RuntimeError("stale build receipt"))
        with mock.patch("subprocess.run") as run, mock.patch("subprocess.Popen") as popen:
            with self.assertRaisesRegex(RuntimeBinarySelectionError, "build receipt rejected"):
                select_runtime_binary(environment, root=self.root, binder=binder)
        binder.assert_called_once_with(explicit.resolve(), environ=environment)
        run.assert_not_called()
        popen.assert_not_called()

    def test_explicit_empty_value_fails_closed(self) -> None:
        binder = mock.Mock(side_effect=AssertionError("binding must not run"))
        with self.assertRaisesRegex(RuntimeBinarySelectionError, "set but empty"):
            select_runtime_binary(
                {"ROOTYARD_BIN": "   ", "CARGO_TARGET_DIR": str(self.root)},
                root=self.root, binder=binder)
        binder.assert_not_called()

    def test_conflicting_explicit_variables_fail_closed(self) -> None:
        canonical = self._executable(self.root / "canonical" / "rootyard")
        legacy = self._executable(self.root / "legacy" / "rootyard")
        binder = mock.Mock(side_effect=AssertionError("binding must not run"))
        with self.assertRaisesRegex(RuntimeBinarySelectionError, "conflicting explicit"):
            select_runtime_binary(
                {"ROOTYARD_BIN": str(canonical), "ROOTYARD_TEST_BINARY": str(legacy)},
                root=self.root, binder=binder)
        binder.assert_not_called()

    def test_agreeing_legacy_variables_are_accepted(self) -> None:
        legacy = self._executable(self.root / "legacy" / "rootyard")
        environment = {
            "ROOTYARD_TEST_BINARY": str(legacy),
            "ROOTYARD_BINARY": str(legacy),
        }
        binder = mock.Mock(return_value={"production_inputs_bound": True})
        path, _ = select_runtime_binary(environment, root=self.root, binder=binder)
        self.assertEqual(path, legacy.resolve())
        binder.assert_called_once_with(legacy.resolve(), environ=environment)

    def test_no_explicit_uses_only_a_validated_local_target(self) -> None:
        environment = {"CARGO_TARGET_DIR": str(self.root)}
        binder = mock.Mock(return_value={"production_inputs_bound": True})
        path, _ = select_runtime_binary(environment, root=self.root, binder=binder)
        self.assertEqual(path, self.local.resolve())
        self.assertEqual(path, legacy_target_binary(environment, self.root))
        binder.assert_called_once_with(self.local.resolve(), environ=environment)

    def test_no_explicit_missing_local_target_fails_closed(self) -> None:
        empty = self.root / "empty-target"
        binder = mock.Mock(side_effect=AssertionError("binding must not run"))
        with self.assertRaisesRegex(RuntimeBinarySelectionError, "explicit native build preparation"):
            select_runtime_binary(
                {"CARGO_TARGET_DIR": str(empty)}, root=self.root, binder=binder)
        binder.assert_not_called()

    def test_real_compiler_absent_from_path_and_never_invoked(self) -> None:
        explicit = self._executable(self.root / "canonical" / "rootyard")
        empty_path = self.root / "empty-path"
        empty_path.mkdir()
        binder = mock.Mock(return_value={"production_inputs_bound": True})
        with mock.patch.dict(
                os.environ,
                {"PATH": str(empty_path), "ROOTYARD_BIN": str(explicit)},
                clear=True):
            self.assertIsNone(shutil.which("cargo"))
            self.assertIsNone(shutil.which("rustc"))
            with mock.patch("subprocess.run") as run, mock.patch("subprocess.Popen") as popen:
                path, _ = select_runtime_binary(binder=binder)
        self.assertEqual(path, explicit.resolve())
        binder.assert_called_once()
        run.assert_not_called()
        popen.assert_not_called()

    def test_relative_explicit_path_resolves_against_repo_root(self) -> None:
        explicit = self._executable(self.root / "canonical" / "rootyard")
        binder = mock.Mock(return_value={"production_inputs_bound": True})
        path, _ = select_runtime_binary(
            {"ROOTYARD_BIN": "canonical/rootyard"}, root=self.root, binder=binder)
        self.assertEqual(path, explicit.resolve())


if __name__ == "__main__":
    unittest.main()
