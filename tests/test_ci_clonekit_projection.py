#!/usr/bin/env python3
"""Offline contract tests for the bounded CloneKit integration-failure projection.

These tests feed synthetic command output to the projection helper only.  They never
invoke Cargo, Git, a process tree, PostgreSQL/Garage, a service, or the network.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_HELPER = ROOT / "scripts" / "ci_clonekit_integration_receipt.sh"


class IntegrationProjectionTest(unittest.TestCase):
    """Guard the closed case/phase/class projection and its atomic bounded write."""

    SHA = "c" * 40
    UNAVAILABLE = "integration CloneKit projection unavailable\n"

    def run_projection(
        self, text: str, output: Path, *, sha: str | None = SHA
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("GITHUB_SHA", None)
        if sha is not None:
            environment["GITHUB_SHA"] = sha
        return subprocess.run(
            [str(INTEGRATION_HELPER), str(output)],
            cwd=str(ROOT),
            env=environment,
            input=text,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def projected(self, output: Path) -> dict[str, object]:
        raw = output.read_bytes()
        self.assertLessEqual(len(raw), 384)
        self.assertEqual(1, raw.count(b"\n"))
        self.assertTrue(raw.endswith(b"\n"))
        return json.loads(raw)

    def test_projection_binds_first_failed_case_and_typed_phase_without_raw_output(self) -> None:
        text = "\n".join(
            (
                "running 3 tests",
                "test clonekit_sha1_and_sha256_incremental_smart_http_and_anti_stale_tip ... ok",
                "test clonekit_failed_build_empty_repo_and_history_rotation_preserve_last_valid ... FAILED",
                "ISSUE182_EMPTY_HISTORY phase=HISTORY_STRATEGY class=ASSERT "
                "source=tests/ci_clonekit_diag_support/mod.rs:1",
                "test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.01s",
                "",
            )
        )
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "nested" / "integration-failure.json"
            proc = self.run_projection(text, output)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(text, proc.stdout)
            self.assertEqual("", proc.stderr)
            self.assertEqual(
                {
                    "version": 1,
                    "source_commit": self.SHA,
                    "case": "EMPTY_HISTORY",
                    "phase": "HISTORY_STRATEGY",
                    "class": "ASSERT",
                    "counts": {"passed": 2, "failed": 1, "ignored": 0},
                },
                self.projected(output),
            )
            data = output.read_bytes()
            for raw in (
                b"cargo",
                b"clonekit_",
                b"tests/",
                b"source=",
                b"ISSUE182",
                b"finished",
                b"running",
                b"0.01s",
            ):
                self.assertNotIn(raw, data)

    def test_projection_keeps_case_identity_and_counts_without_a_typed_frame(self) -> None:
        text = "\n".join(
            (
                "test clonekit_sha1_and_sha256_incremental_smart_http_and_anti_stale_tip ... FAILED",
                "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out",
                "",
            )
        )
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "integration-failure.json"
            proc = self.run_projection(text, output)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(text, proc.stdout)
            self.assertEqual(
                {
                    "version": 1,
                    "source_commit": self.SHA,
                    "case": "SMART_HTTP",
                    "phase": None,
                    "class": None,
                    "counts": {"passed": 1, "failed": 1, "ignored": 0},
                },
                self.projected(output),
            )

    def test_projection_maps_unknown_case_and_tokens_to_closed_other(self) -> None:
        cases = (
            (
                "\n".join(
                    (
                        "test clonekit_unknown_future_case ... FAILED",
                        "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured",
                        "",
                    )
                ),
                "OTHER",
                None,
                None,
            ),
            (
                "\n".join(
                    (
                        "ISSUE182_EMPTY_HISTORY phase=SECRET_PHASE class=SECRET_CLASS "
                        "source=/private/secret.rs:9",
                        "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured",
                        "",
                    )
                ),
                "EMPTY_HISTORY",
                "OTHER",
                "OTHER",
            ),
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for index, (text, case, phase, typed) in enumerate(cases):
                with self.subTest(case=case, phase=phase):
                    output = root / f"unknown-{index}.json"
                    proc = self.run_projection(text, output)
                    self.assertEqual(0, proc.returncode, proc.stderr)
                    self.assertEqual(text, proc.stdout)
                    self.assertEqual(
                        {
                            "version": 1,
                            "source_commit": self.SHA,
                            "case": case,
                            "phase": phase,
                            "class": typed,
                            "counts": {"passed": 0, "failed": 1, "ignored": 0},
                        },
                        self.projected(output),
                    )
                    data = output.read_bytes()
                    for raw in (b"SECRET", b"/private", b"future_case"):
                        self.assertNotIn(raw, data)

    def test_projection_is_silent_and_creates_nothing_on_success(self) -> None:
        text = "\n".join(
            (
                "running 3 tests",
                "test clonekit_failed_build_empty_repo_and_history_rotation_preserve_last_valid ... ok",
                "test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out",
                "",
            )
        )
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "integration-failure.json"
            proc = self.run_projection(text, output)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(text, proc.stdout)
            self.assertEqual("", proc.stderr)
            self.assertFalse(output.exists())

    def test_projection_rejects_invalid_binding_and_directory_target(self) -> None:
        text = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured\n"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for index, sha in enumerate((None, "A" * 40, "c" * 39, "c" * 41)):
                with self.subTest(sha=sha):
                    output = root / f"invalid-{index}" / "integration-failure.json"
                    proc = self.run_projection(text, output, sha=sha)
                    self.assertEqual(0, proc.returncode, proc.stderr)
                    self.assertEqual(text, proc.stdout)
                    self.assertEqual(self.UNAVAILABLE, proc.stderr)
                    self.assertFalse(output.exists())

            blocked = root / "directory.json"
            blocked.mkdir()
            proc = self.run_projection(text, blocked)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(text, proc.stdout)
            self.assertEqual(self.UNAVAILABLE, proc.stderr)
            self.assertTrue(blocked.is_dir())

    def test_projection_atomically_replaces_and_cleans_temporary_files(self) -> None:
        text = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured\n"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = root / "integration-failure.json"
            output.write_text("old" * 500, encoding="utf-8")
            proc = self.run_projection(text, output)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual([output], list(root.iterdir()))
            self.assertFalse(any(path.name.startswith(".integration-receipt.") for path in root.iterdir()))
            self.assertEqual(
                {
                    "version": 1,
                    "source_commit": self.SHA,
                    "case": "OTHER",
                    "phase": None,
                    "class": None,
                    "counts": {"passed": 0, "failed": 1, "ignored": 0},
                },
                self.projected(output),
            )

    def test_projection_drops_out_of_bound_counts_and_keeps_closed_nulls(self) -> None:
        text = "test result: FAILED. 1000 passed; x failed; 0 ignored; 0 measured\n"
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "integration-failure.json"
            proc = self.run_projection(text, output)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(
                {
                    "version": 1,
                    "source_commit": self.SHA,
                    "case": "OTHER",
                    "phase": None,
                    "class": None,
                    "counts": {"passed": None, "failed": None, "ignored": 0},
                },
                self.projected(output),
            )


if __name__ == "__main__":
    unittest.main()
