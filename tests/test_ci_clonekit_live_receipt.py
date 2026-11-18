#!/usr/bin/env python3
"""Offline contract tests for bounded live CloneKit stage and Rust-phase evidence.

The helpers are exercised with synthetic stage/status arguments and marker lines only.
This suite never invokes Cargo, PostgreSQL/Garage, a service, or the network. It reads the
local checkout HEAD/tree with `git rev-parse` solely to verify the exact evidence binding.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIVE_HELPER = ROOT / "scripts" / "ci_clonekit_live_receipt.sh"
LIVE_MODULE = ROOT / "tests" / "ci_clonekit_live_support" / "mod.rs"
CHECKOUT_COMMIT = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ROOT), text=True).strip()
CHECKOUT_TREE = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=str(ROOT), text=True).strip()


class LiveReceiptTest(unittest.TestCase):
    """Guard the two bounded live-stage records and the unchanged live command."""

    SHA = CHECKOUT_COMMIT
    COMPLETION = "ISSUE182_LIVE_PG_GARAGE_COMPLETE"
    UNAVAILABLE = "live CloneKit evidence unavailable\n"
    RUST_UNAVAILABLE = "live CloneKit rust phase unavailable\n"
    COMPLETION_UNAVAILABLE = "live CloneKit completion marker unavailable\n"
    OK_TEXT = "\n".join(
        (
            "running 1 test",
            "test pg_and_garage_s3_clonekit_durable_hold_protected_upload_and_revocation ... ok",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
            "",
        )
    )

    def run_stage(
        self, stage: str, status: str, output: Path, *, sha: str | None = SHA
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("GITHUB_SHA", None)
        if sha is not None:
            environment["GITHUB_SHA"] = sha
        return subprocess.run(
            [str(LIVE_HELPER), "stage", stage, status, str(output)],
            cwd=str(ROOT),
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def run_project(
        self, text: str, output: Path, *, sha: str | None = SHA, completion: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("GITHUB_SHA", None)
        if sha is not None:
            environment["GITHUB_SHA"] = sha
        completion = output.with_name("live-case-complete") if completion is None else completion
        environment["ROOTYARD_LIVE_COMPLETION_FILE"] = str(completion)
        return subprocess.run(
            [str(LIVE_HELPER), "project", str(output)],
            cwd=str(ROOT),
            env=environment,
            input=text,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def mismatch_sha(self) -> str:
        return ("1" if self.SHA[0] != "1" else "0") + self.SHA[1:]

    def trap_line(self) -> str:
        workflow = (ROOT / ".github" / "workflows" / "ci-clonekit.yml").read_text(encoding="utf-8")
        marker = "      - name: Run live PostgreSQL 17 and Garage S3 CloneKit acceptance test\n"
        body = workflow.split(marker, 1)[1].split("\n      - name: ", 1)[0]
        traps = [line.strip() for line in body.splitlines() if line.strip().startswith("trap '")]
        self.assertEqual(1, len(traps))
        return traps[0]

    def run_trap(self, body: str, receipt: Path) -> subprocess.CompletedProcess[str]:
        script = "\n".join(
            (
                "set -euo pipefail",
                "live_receipt=" + shlex.quote(str(receipt)),
                "live_stage=env_setup",
                self.trap_line(),
                textwrap.dedent(body),
            )
        )
        environment = os.environ.copy()
        environment["GITHUB_SHA"] = self.SHA
        return subprocess.run(
            ["bash", "-c", script],
            cwd=str(ROOT),
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def projected(self, output: Path) -> dict[str, object]:
        raw = output.read_bytes()
        self.assertLessEqual(len(raw), 512)
        self.assertEqual(1, raw.count(b"\n"))
        self.assertTrue(raw.endswith(b"\n"))
        return json.loads(raw)

    def test_stage_receipt_binds_shell_position_and_exact_checkout(self) -> None:
        cases = (
            ("env_setup", "1", "env_setup", 1, ["cargo_test"]),
            ("cargo_test", "101", "cargo_test", 101, []),
            ("complete", "0", "complete", 0, []),
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for index, (stage, status, expected_stage, exit_code, not_run) in enumerate(cases):
                with self.subTest(stage=stage, status=status):
                    output = root / f"stage-{index}.json"
                    proc = self.run_stage(stage, status, output)
                    self.assertEqual(0, proc.returncode, proc.stderr)
                    self.assertEqual("", proc.stdout)
                    self.assertEqual("", proc.stderr)
                    self.assertEqual(
                        {
                            "version": 1,
                            "case": "PG_GARAGE_DURABLE_HOLD",
                            "source_commit": self.SHA,
                            "checkout_commit": CHECKOUT_COMMIT,
                            "checkout_tree": CHECKOUT_TREE,
                            "stage": expected_stage,
                            "exit_code": exit_code,
                            "not_run": not_run,
                        },
                        self.projected(output),
                    )
                    data = output.read_bytes()
                    for raw in (b"--locked", b"ci_clonekit", b"source=", str(output).encode()):
                        self.assertNotIn(raw, data)

    def test_stage_rejects_invalid_or_inconsistent_positions(self) -> None:
        cases = (
            ("env_setup", "0", self.SHA),
            ("cargo_test", "0", self.SHA),
            ("complete", "1", self.SHA),
            ("setup", "1", self.SHA),
            ("rust", "1", self.SHA),
            ("complete", "256", self.SHA),
            ("complete", "-1", self.SHA),
            ("complete", "1x", self.SHA),
            ("env_setup", "1", None),
            ("env_setup", "1", "A" * 40),
            ("env_setup", "1", "a" * 39),
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for index, (stage, status, sha) in enumerate(cases):
                with self.subTest(stage=stage, status=status, sha=sha):
                    output = root / f"invalid-{index}" / "live.json"
                    proc = self.run_stage(stage, status, output, sha=sha)
                    self.assertEqual(2, proc.returncode, proc.stderr)
                    self.assertEqual("", proc.stdout)
                    self.assertEqual(self.UNAVAILABLE, proc.stderr)
                    self.assertFalse(output.exists())
                    self.assertFalse(output.parent.exists())

    def test_stage_atomically_replaces_and_cleans_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = root / "nested" / "live.json"
            output.parent.mkdir()
            output.write_text("old" * 500, encoding="utf-8")
            proc = self.run_stage("complete", "0", output)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual([output], list(output.parent.iterdir()))
            self.assertFalse(any(path.name.startswith(".live-receipt.") for path in output.parent.iterdir()))

            blocked = root / "blocked.json"
            blocked.mkdir()
            proc = self.run_stage("cargo_test", "7", blocked)
            self.assertEqual(1, proc.returncode)
            self.assertEqual(self.UNAVAILABLE, proc.stderr)
            self.assertTrue(blocked.is_dir())
            self.assertEqual({output.parent, blocked}, set(root.iterdir()))

    def test_project_emits_closed_phase_and_class_without_raw_values(self) -> None:
        text = "\n".join(
            (
                "running 1 test",
                "test pg_and_garage_s3_clonekit_durable_hold_protected_upload_and_revocation ... FAILED",
                "ISSUE182_LIVE_PG_GARAGE phase=CHECKOUT class=GIT_FAILED "
                "source=tests/ci_clonekit_live_support/mod.rs:123",
                "RAW SECRET SHOULD NOT LEAK",
                "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out",
                "",
            )
        )
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "nested" / "live-rust.json"
            proc = self.run_project(text, output)
            self.assertEqual(1, proc.returncode)
            self.assertEqual(text, proc.stdout)
            self.assertEqual("", proc.stderr)
            self.assertEqual(
                {
                    "version": 1,
                    "case": "PG_GARAGE_DURABLE_HOLD",
                    "source_commit": self.SHA,
                    "checkout_commit": CHECKOUT_COMMIT,
                    "checkout_tree": CHECKOUT_TREE,
                    "phase": "CHECKOUT",
                    "class": "GIT_FAILED",
                },
                self.projected(output),
            )
            self.assertFalse(output.with_name("live-case-complete").exists())
            data = output.read_bytes()
            for raw in (b"pg_and_garage", b"source=", b"tests/", b"SECRET", b"test result", b"running"):
                self.assertNotIn(raw, data)

    def test_project_maps_unknown_and_malformed_tokens_to_other_and_first_wins(self) -> None:
        cases = (
            (
                "\n".join(
                    (
                        "ISSUE182_LIVE_PG_GARAGE phase=SECRET_PHASE class=SECRET_CLASS source=/private/secret.rs:9",
                        "ISSUE182_LIVE_PG_GARAGE phase=CHECKOUT class=GIT_FAILED source=x:1",
                        "",
                    )
                ),
                "OTHER",
                "OTHER",
            ),
            ("ISSUE182_LIVE_PG_GARAGE phase=CHECKOUT\n", "CHECKOUT", "OTHER"),
            ("ISSUE182_LIVE_PG_GARAGE phase=FUTURE class=GIT_FAILED source=x:1\n", "OTHER", "GIT_FAILED"),
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for index, (text, phase, typed) in enumerate(cases):
                with self.subTest(index=index):
                    output = root / f"unknown-{index}.json"
                    proc = self.run_project(text, output)
                    self.assertEqual(1, proc.returncode)
                    self.assertEqual(text, proc.stdout)
                    self.assertEqual("", proc.stderr)
                    self.assertEqual(phase, self.projected(output)["phase"])
                    self.assertEqual(typed, self.projected(output)["class"])
                    data = output.read_bytes()
                    for raw in (b"SECRET", b"/private", b"FUTURE", b"source="):
                        self.assertNotIn(raw, data)

    def test_project_without_marker_is_silent_and_creates_nothing(self) -> None:
        text = self.OK_TEXT
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "live-rust.json"
            output.write_text("stale evidence", encoding="utf-8")
            proc = self.run_project(text, output)
            self.assertEqual(1, proc.returncode)
            self.assertEqual(text, proc.stdout)
            self.assertEqual(self.COMPLETION_UNAVAILABLE, proc.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name("live-case-complete").exists())

    def test_project_accepts_exactly_one_completion_marker(self) -> None:
        text = self.OK_TEXT
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = root / "nested" / "live-rust.json"
            completion = root / "live-case-complete"
            completion.write_text(self.COMPLETION + "\n", encoding="utf-8")
            proc = self.run_project(text, output, completion=completion)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(text, proc.stdout)
            self.assertEqual("", proc.stderr)
            self.assertEqual(
                {
                    "version": 1,
                    "case": "PG_GARAGE_DURABLE_HOLD",
                    "source_commit": self.SHA,
                    "checkout_commit": CHECKOUT_COMMIT,
                    "checkout_tree": CHECKOUT_TREE,
                    "outcome": "COMPLETE",
                },
                self.projected(output),
            )
            self.assertFalse(completion.exists())
            data = output.read_bytes()
            for raw in (b"pg_and_garage", b"source=", b"tests/", b"test result", b"running"):
                self.assertNotIn(raw, data)

    def test_project_rejects_zero_duplicate_or_mixed_completion_markers(self) -> None:
        text = self.OK_TEXT
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            zero = root / "zero-complete"
            output = root / "zero.json"
            proc = self.run_project(text, output, completion=zero)
            self.assertEqual(1, proc.returncode)
            self.assertEqual(text, proc.stdout)
            self.assertEqual(self.COMPLETION_UNAVAILABLE, proc.stderr)
            self.assertFalse(output.exists())

            duplicate = root / "duplicate-complete"
            duplicate.write_text(self.COMPLETION + "\n" + self.COMPLETION + "\n", encoding="utf-8")
            output = root / "duplicate.json"
            proc = self.run_project(text, output, completion=duplicate)
            self.assertEqual(1, proc.returncode)
            self.assertEqual(text, proc.stdout)
            self.assertEqual(self.COMPLETION_UNAVAILABLE, proc.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(duplicate.exists())

            mixed = root / "mixed-complete"
            mixed.write_text(self.COMPLETION + "\n", encoding="utf-8")
            failure = "ISSUE182_LIVE_PG_GARAGE phase=CHECKOUT class=GIT_FAILED source=x:1\n"
            output = root / "mixed.json"
            proc = self.run_project(failure, output, completion=mixed)
            self.assertEqual(1, proc.returncode)
            self.assertEqual(failure, proc.stdout)
            self.assertEqual("", proc.stderr)
            self.assertEqual("CHECKOUT", self.projected(output)["phase"])
            self.assertEqual("GIT_FAILED", self.projected(output)["class"])
            self.assertFalse(mixed.exists())

    def test_stage_rejects_source_checkout_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "mismatch.json"
            proc = self.run_stage("complete", "0", output, sha=self.mismatch_sha())
            self.assertEqual(1, proc.returncode)
            self.assertEqual("", proc.stdout)
            self.assertEqual(self.UNAVAILABLE, proc.stderr)
            self.assertFalse(output.exists())

    def test_project_rejects_source_checkout_mismatch(self) -> None:
        text = self.OK_TEXT
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = root / "mismatch.json"
            completion = root / "live-case-complete"
            completion.write_text(self.COMPLETION + "\n", encoding="utf-8")
            proc = self.run_project(text, output, sha=self.mismatch_sha(), completion=completion)
            self.assertEqual(1, proc.returncode)
            self.assertEqual(text, proc.stdout)
            self.assertEqual(self.RUST_UNAVAILABLE, proc.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(completion.exists())

    def test_live_primary_body_error_precedes_teardown_and_cleanup(self) -> None:
        source = "".join(LIVE_MODULE.read_text(encoding="utf-8").split())
        body_error = "ifletErr(err)=&body{"
        body_record = "diag.observe_final(err);}"
        teardown = "diag.mark(LivePhase::Teardown,file!(),line!());"
        cleanup = "letcleanup:Result<()>=async{"
        self.assertIn(body_error, source)
        self.assertIn(body_record, source)
        self.assertIn(teardown, source)
        self.assertIn(cleanup, source)
        self.assertLess(source.index(body_error), source.index(body_record))
        self.assertLess(source.index(body_record), source.index(teardown))
        self.assertLess(source.index(teardown), source.index(cleanup))
        self.assertIn("matchcleanup{Ok(())=>body,Err(err)=>Err(err),}", source)
        self.assertIn("Ok(())=>diag.complete()", source)

    def test_live_checkout_plan_keeps_canonical_dependency_object(self) -> None:
        source = "".join(LIVE_MODULE.read_text(encoding="utf-8").split())
        dependencies = '"dependencies":{"version":1,"history":"full","tags":[],"lfs":[],"submodules":[]}'
        self.assertIn(dependencies, source)
        self.assertLess(source.index(dependencies), source.index("INSERTINTOci_checkout_jobs"))

    def test_workflow_trap_preserves_status_and_fails_closed_on_green_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            later = root / "later"
            receipt = root / "failed.json"
            proc = self.run_trap(
                f"""
                live_stage=env_setup
                (exit 7)
                touch {shlex.quote(str(later))}
                """,
                receipt,
            )
            self.assertEqual(7, proc.returncode)
            self.assertFalse(later.exists())
            data = json.loads(receipt.read_bytes())
            self.assertEqual("env_setup", data["stage"])
            self.assertEqual(7, data["exit_code"])
            self.assertEqual(["cargo_test"], data["not_run"])

            success = root / "success.json"
            proc = self.run_trap(
                """
                live_stage=cargo_test
                true
                live_stage=complete
                """,
                success,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            data = json.loads(success.read_bytes())
            self.assertEqual("complete", data["stage"])
            self.assertEqual(0, data["exit_code"])
            self.assertEqual([], data["not_run"])

    def test_workflow_wires_live_trap_and_preserves_original_command(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci-clonekit.yml").read_text(encoding="utf-8")
        self.assertIn("      - 'scripts/ci_clonekit_live_receipt.sh'", workflow)
        self.assertIn("      - 'tests/ci_clonekit_live_support/mod.rs'", workflow)
        self.assertIn("      - 'tests/test_ci_clonekit_live_receipt.py'", workflow)
        self.assertIn("tests.test_ci_clonekit_live_receipt", workflow)
        marker = "      - name: Run live PostgreSQL 17 and Garage S3 CloneKit acceptance test\n"
        body = workflow.split(marker, 1)[1].split("\n      - name: ", 1)[0]
        lines = [line.strip() for line in body.splitlines()]
        command = (
            "cargo test --locked --test ci_clonekit -- --ignored --test-threads=1 2>&1 | "
            'scripts/ci_clonekit_live_receipt.sh project "$live_rust_receipt"'
        )
        self.assertIn("live_receipt=test-results/ci-clonekit/live-command.json", lines)
        self.assertIn("live_rust_receipt=test-results/ci-clonekit/live-rust.json", lines)
        self.assertIn("live_completion_file=test-results/ci-clonekit/live-case-complete", lines)
        self.assertIn('rm -f -- "$live_completion_file"', lines)
        self.assertIn('export ROOTYARD_LIVE_COMPLETION_FILE="$live_completion_file"', lines)
        self.assertIn("live_stage=env_setup", lines)
        self.assertIn("live_stage=cargo_test", lines)
        self.assertIn("live_stage=complete", lines)
        self.assertIn(command, lines)
        self.assertIn('pipeline_status=("${PIPESTATUS[@]}")', lines)
        self.assertNotIn("|| true", body)
        self.assertNotIn("continue-on-error", body)
        self.assertNotIn("--skip", body)
        self.assertIn("--ignored --test-threads=1", command)
        wrapper = (ROOT / "tests" / "ci_clonekit.rs").read_text(encoding="utf-8")
        self.assertIn(
            '#[ignore = "requires PostgreSQL (ROOTYARD_TEST_DATABASE_URL) and controlled S3 (ROOTYARD_BLOB_*)"]',
            wrapper,
        )
        self.assertIn(
            "async fn pg_and_garage_s3_clonekit_durable_hold_protected_upload_and_revocation() -> Result<()> {\n"
            "    ck_live::run().await\n"
            "}",
            wrapper,
        )
        source_index = lines.index('source "$OBJECT_STORE_ENV_FILE"')
        cargo_index = lines.index(command)
        completion_index = lines.index('export ROOTYARD_LIVE_COMPLETION_FILE="$live_completion_file"')
        self.assertLess(lines.index("live_stage=env_setup"), source_index)
        self.assertLess(source_index, lines.index('rm -f -- "$live_completion_file"'))
        self.assertLess(lines.index('rm -f -- "$live_completion_file"'), completion_index)
        self.assertLess(completion_index, cargo_index)
        self.assertLess(lines.index("live_stage=cargo_test"), cargo_index)
        self.assertLess(cargo_index, lines.index("live_stage=complete"))
        producer_index = lines.index('if [ "$producer_status" -ne 0 ]; then')
        collector_index = lines.index('if [ "$collector_status" -ne 0 ]; then')
        self.assertLess(producer_index, collector_index)
        self.assertLess(collector_index, lines.index("live_stage=complete"))

        traps = [line for line in lines if line.startswith("trap '")]
        self.assertEqual(1, len(traps))
        self.assertIn(
            'scripts/ci_clonekit_live_receipt.sh stage "$live_stage" "$status" "$live_receipt"',
            traps[0],
        )
        self.assertIn('if [ "$status" -ne 0 ]; then exit "$status"; fi', traps[0])
        self.assertTrue(os.access(LIVE_HELPER, os.X_OK))
        module = LIVE_MODULE.read_bytes()
        self.assertNotIn(b"\r", module)
        self.assertLess(len(module.decode("utf-8").splitlines()), 500)
        self.assertNotIn("#[allow(", module.decode("utf-8"))
        script = LIVE_HELPER.read_bytes()
        self.assertNotIn(b"\r", script)
        self.assertLess(len(script.decode("utf-8").splitlines()), 500)


if __name__ == "__main__":
    unittest.main()
