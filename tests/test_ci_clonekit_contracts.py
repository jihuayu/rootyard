#!/usr/bin/env python3
"""Static and offline contract tests for Issue #182 CloneKit.

Checks file boundaries, <500L module size limits, zero `mod.rs`, zero `#[allow(`,
`#[serde(deny_unknown_fields)]` on all new Deserialize structs, pure LF line endings,
opt-in default (`use_clonekit: false`), CargoFork workflow contract compliance, and a
real quick smoke run of `scripts/eval_ci_clonekit.py`. Zero compiler/Cargo calls.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOCUSED_HELPER = ROOT / "scripts" / "ci_clonekit_focused_receipt.sh"
FOCUSED_STEP = "Clippy and CloneKit unit plus Smart-HTTP integration tests"
FOCUSED_RECEIPT = "test-results/ci-clonekit/focused-command.json"
FOCUSED_GROUPS = ("clippy", "lib", "integration")
FOCUSED_COMMANDS = (
    "cargo clippy --locked --lib --test ci_clonekit -- -D warnings",
    "cargo test --locked --lib ci_checkouts::clonekit",
    "cargo test --locked --test ci_clonekit",
)
CLONEKIT_RUST_FILES = (
    ROOT / "src" / "ci_checkouts.rs",
    ROOT / "src" / "ci_checkouts" / "clonekit.rs",
    ROOT / "src" / "ci_checkouts" / "clonekit" / "manifest.rs",
    ROOT / "src" / "ci_checkouts" / "clonekit" / "grants.rs",
    ROOT / "src" / "ci_checkouts" / "clonekit" / "builder.rs",
    ROOT / "src" / "ci_checkouts" / "clonekit" / "checkout.rs",
    ROOT / "tests" / "ci_clonekit.rs",
)
ALL_OWNED_TEXT_FILES = (
    *CLONEKIT_RUST_FILES,
    ROOT / "scripts" / "eval_ci_clonekit.py",
    FOCUSED_HELPER,
    ROOT / "tests" / "test_ci_clonekit_contracts.py",
    ROOT / "docs" / "ci-clonekit.md",
    ROOT / ".github" / "workflows" / "ci-clonekit.yml",
)


class CloneKitContractsTest(unittest.TestCase):
    def test_owned_files_line_caps_lf_and_no_mod_rs(self) -> None:
        self.assertFalse((ROOT / "src" / "ci_checkouts" / "mod.rs").exists())
        self.assertFalse((ROOT / "src" / "ci_checkouts" / "clonekit" / "mod.rs").exists())
        for path in ALL_OWNED_TEXT_FILES:
            with self.subTest(path=str(path.relative_to(ROOT))):
                raw = path.read_bytes()
                self.assertNotIn(b"\r", raw, f"{path.name} must use pure LF")
                lines = raw.decode("utf-8").splitlines()
                limit = 100 if path.name in ("ci_checkouts.rs", "clonekit.rs") else 500
                self.assertLess(len(lines), limit, f"{path.name} exceeds {limit} lines: {len(lines)}")

    def test_no_allow_attributes_in_clonekit_rust(self) -> None:
        self.assertEqual(1, (ROOT / "src" / "ci_checkouts.rs").read_text(encoding="utf-8").count("#[allow("))
        for path in CLONEKIT_RUST_FILES[1:]:
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=path.name):
                self.assertNotIn("#[allow(", text)

    def test_every_new_deserialize_struct_denies_unknown_fields(self) -> None:
        pat = re.compile(r"#\[derive\([^\]]*Deserialize[^\]]*\)\]\s*(?:#\[serde\([^\)]*\)\]\s*)*(?:pub\s+)?struct\s+\w+")
        for path in CLONEKIT_RUST_FILES[1:-1]:
            text = path.read_text(encoding="utf-8")
            for m in pat.finditer(text):
                self.assertIn(
                    "deny_unknown_fields",
                    m.group(0),
                    f"{path.name} missing #[serde(deny_unknown_fields)] before {m.group(0)}",
                )

    def test_checkout_policy_defaults_opt_in_false(self) -> None:
        text = (ROOT / "src" / "ci_checkouts" / "clonekit" / "checkout.rs").read_text(encoding="utf-8")
        self.assertIn("use_clonekit: false", text)
        self.assertIn("fallback_to_git_on_unusable_kit: true", text)
        self.assertIn("require_full_fsck: true", text)

    def test_pg_authority_oracle_scopes_delegations_to_job_and_expiry(self) -> None:
        text = (ROOT / "src" / "ci_checkouts" / "clonekit" / "grants.rs").read_text(encoding="utf-8")
        self.assertIn("d.job_id = $1", text)
        self.assertIn("pj.revoked", text)
        self.assertIn("j.revoked", text)
        self.assertIn("d.expires_unix >", text)
        self.assertIn('== "ready"', text)

    def test_workflow_targets_clonekit_and_disables_push_trigger(self) -> None:
        wf = (ROOT / ".github" / "workflows" / "ci-clonekit.yml").read_text(encoding="utf-8")
        self.assertTrue(wf.startswith("name: "))
        self.assertNotIn("\t", wf)
        self.assertIn("pull_request:", wf)
        self.assertIn("workflow_dispatch:", wf)
        self.assertNotIn("\npush:", wf)
        self.assertIn("      - 'scripts/ci_clonekit_focused_receipt.sh'", wf)
        for cmd in (
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "postgres:17",
            "scripts/owned_garage_fixture.sh start",
            "cargo clippy --locked --lib --test ci_clonekit -- -D warnings",
            "cargo test --locked --lib ci_checkouts::clonekit",
            "cargo test --locked --test ci_clonekit",
            "--ignored --test-threads=1",
            "scripts/eval_ci_clonekit.py --scale full",
        ):
            self.assertIn(cmd, wf)

    def test_eval_script_quick_smoke_real_git_and_fallbacks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out_json = Path(td) / "eval.json"
            out_md = Path(td) / "eval.md"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "eval_ci_clonekit.py"),
                    "--scale",
                    "quick",
                    "--output",
                    str(out_json),
                    "--markdown-out",
                    str(out_md),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            report = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertFalse(report["default_clonekit_enabled"])
            for fmt in ("sha1", "sha256"):
                f = report["formats"][fmt]
                self.assertGreater(f["origin_wire_reduction_factor"], 10.0)
                self.assertTrue(f["faults"]["kit_miss_fallback"])
                self.assertTrue(f["faults"]["kit_corrupt_fallback"])
            self.assertIn("Stock Git Direct", out_md.read_text(encoding="utf-8"))


class FocusedCommandReceiptTest(unittest.TestCase):
    """Offline guard for the three-command focused step and its bounded receipt."""

    def workflow(self) -> str:
        return (ROOT / ".github" / "workflows" / "ci-clonekit.yml").read_text(encoding="utf-8")

    def focused_script(self) -> str:
        text = self.workflow()
        marker = "      - name: " + FOCUSED_STEP + "\n"
        body = text.split(marker, 1)[1].split("\n      - name: ", 1)[0]
        match = re.search(r"^        run: \|\n((?:          .*\n)+)", body)
        if match is None:
            self.fail("focused step has no literal run block")
        return textwrap.dedent(match.group(1))

    def trap_line(self) -> str:
        lines = [line.strip() for line in self.focused_script().splitlines()]
        traps = [line for line in lines if line.startswith("trap '")]
        self.assertEqual(1, len(traps))
        return traps[0]

    def run_helper(
        self, group: str, status: str, output: Path, *, sha: str | None = "a" * 40
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("GITHUB_SHA", None)
        if sha is not None:
            environment["GITHUB_SHA"] = sha
        return subprocess.run(
            [str(FOCUSED_HELPER), group, status, str(output)],
            cwd=str(ROOT),
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def run_trap(self, body: str, receipt: Path) -> subprocess.CompletedProcess[str]:
        script = "\n".join(
            (
                "set -euo pipefail",
                "focused_receipt=" + shlex.quote(str(receipt)),
                "focused_group=",
                self.trap_line(),
                textwrap.dedent(body),
            )
        )
        environment = os.environ.copy()
        environment["GITHUB_SHA"] = "a" * 40
        return subprocess.run(
            ["bash", "-c", script],
            cwd=str(ROOT),
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_focused_step_keeps_three_commands_and_installs_one_receipt_trap(self) -> None:
        script = self.focused_script()
        self.assertTrue(script.startswith("set -euo pipefail"))
        self.assertIn("focused_receipt=" + FOCUSED_RECEIPT, script)
        self.assertEqual(1, script.count("trap '"))
        self.assertNotIn("|| true", script)
        self.assertNotIn("continue-on-error", script)

        lines = script.splitlines()
        self.assertEqual(
            ["cargo " + line.split("cargo ", 1)[1] for line in lines if line.startswith("cargo ")],
            list(FOCUSED_COMMANDS),
        )
        for group, command in zip(FOCUSED_GROUPS, FOCUSED_COMMANDS):
            self.assertEqual(f"focused_group={group}", lines[lines.index(command) - 1])

        trap = self.trap_line()
        self.assertLess(script.index(trap), script.index("focused_group=clippy"))
        for token in (
            'status=$?',
            'trap - EXIT',
            'set +e',
            'scripts/ci_clonekit_focused_receipt.sh "${focused_group:-invalid}" "$status" "$focused_receipt"',
            'if [ "$status" -ne 0 ]; then exit "$status"; fi',
            '[ "$receipt_status" -eq 0 ] || exit 1',
        ):
            with self.subTest(token=token):
                self.assertIn(token, trap)
        self.assertTrue(os.access(FOCUSED_HELPER, os.X_OK))

    def test_helper_projects_each_failure_and_success_without_raw_values(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sha = "b" * 40
            for group, status, failure, not_run in (
                ("clippy", 101, "clippy", ["lib", "integration"]),
                ("lib", 1, "lib", ["integration"]),
                ("integration", 101, "integration", []),
            ):
                with self.subTest(group=group):
                    output = root / f"{group}-{status}.json"
                    proc = self.run_helper(group, str(status), output, sha=sha)
                    self.assertEqual(0, proc.returncode, proc.stderr)
                    self.assertEqual("", proc.stdout)
                    self.assertEqual("", proc.stderr)
                    data = output.read_bytes()
                    self.assertLessEqual(len(data), 192)
                    self.assertEqual(1, data.count(b"\n"))
                    self.assertEqual(
                        {
                            "version": 1,
                            "source_commit": sha,
                            "first_failure": failure,
                            "exit_code": status,
                            "not_run": not_run,
                        },
                        json.loads(data),
                    )
                    for raw in (b"cargo", b"--locked", b"ci_checkouts", b"token", str(output).encode()):
                        self.assertNotIn(raw, data)

            output = root / "success.json"
            proc = self.run_helper("integration", "0", output, sha=sha)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual("", proc.stdout)
            self.assertEqual("", proc.stderr)
            self.assertEqual(
                {
                    "version": 1,
                    "source_commit": sha,
                    "first_failure": None,
                    "exit_code": 0,
                    "not_run": [],
                },
                json.loads(output.read_bytes()),
            )

    def test_helper_rejects_invalid_binding_and_group_status_combinations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cases = (
                ("clippy", "1", "A" * 40),
                ("clippy", "1", "a" * 39),
                ("clippy", "1", "g" * 40),
                ("clippy", "1", None),
                ("setup", "1", "a" * 40),
                ("complete", "0", "a" * 40),
                ("clippy", "256", "a" * 40),
                ("clippy", "-1", "a" * 40),
                ("clippy", "1x", "a" * 40),
                ("clippy", "0", "a" * 40),
            )
            for index, (group, status, sha) in enumerate(cases):
                with self.subTest(group=group, status=status, sha=sha):
                    output = root / f"invalid-{index}" / "report.json"
                    proc = self.run_helper(group, status, output, sha=sha)
                    self.assertEqual(2, proc.returncode, proc.stderr)
                    self.assertEqual("", proc.stdout)
                    self.assertEqual("focused CloneKit receipt unavailable\n", proc.stderr)
                    self.assertFalse(output.exists())
                    self.assertFalse(output.parent.exists())
                    for raw in (group, status, sha or ""):
                        if raw:
                            self.assertNotIn(raw, proc.stderr)

    def test_helper_atomically_replaces_and_cleans_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = root / "nested" / "focused.json"
            output.parent.mkdir()
            output.write_text("old" * 500, encoding="utf-8")
            proc = self.run_helper("lib", "7", output)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual([output], list(output.parent.iterdir()))
            self.assertEqual(
                {
                    "version": 1,
                    "source_commit": "a" * 40,
                    "first_failure": "lib",
                    "exit_code": 7,
                    "not_run": ["integration"],
                },
                json.loads(output.read_bytes()),
            )

            blocked = root / "directory.json"
            blocked.mkdir()
            proc = self.run_helper("integration", "0", blocked)
            self.assertEqual(1, proc.returncode)
            self.assertEqual("focused CloneKit receipt unavailable\n", proc.stderr)
            self.assertTrue(blocked.is_dir())
            self.assertEqual({output.parent, blocked}, set(root.iterdir()))
            self.assertFalse(any(path.name.startswith(".focused-receipt.") for path in root.iterdir()))

    def test_workflow_trap_preserves_status_and_fails_closed_on_report_io(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            later = root / "later"
            receipt = root / "failed.json"
            proc = self.run_trap(
                f"""
                focused_group=clippy
                (exit 7)
                touch {shlex.quote(str(later))}
                """,
                receipt,
            )
            self.assertEqual(7, proc.returncode)
            self.assertFalse(later.exists())
            self.assertEqual(
                {
                    "version": 1,
                    "source_commit": "a" * 40,
                    "first_failure": "clippy",
                    "exit_code": 7,
                    "not_run": ["lib", "integration"],
                },
                json.loads(receipt.read_bytes()),
            )

            success = root / "success.json"
            proc = self.run_trap(
                """
                focused_group=clippy
                true
                focused_group=lib
                true
                focused_group=integration
                true
                """,
                success,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(
                {
                    "version": 1,
                    "source_commit": "a" * 40,
                    "first_failure": None,
                    "exit_code": 0,
                    "not_run": [],
                },
                json.loads(success.read_bytes()),
            )

            blocked = root / "blocked.json"
            blocked.mkdir()
            proc = self.run_trap(
                """
                focused_group=clippy
                true
                focused_group=lib
                true
                focused_group=integration
                true
                """,
                blocked,
            )
            self.assertEqual(1, proc.returncode)
            self.assertTrue(blocked.is_dir())

            proc = self.run_trap(
                """
                focused_group=clippy
                true
                focused_group=lib
                (exit 7)
                """,
                blocked,
            )
            self.assertEqual(7, proc.returncode)


if __name__ == "__main__":
    unittest.main()
