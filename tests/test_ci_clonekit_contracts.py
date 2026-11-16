#!/usr/bin/env python3
"""Static and offline contract tests for Issue #182 CloneKit.

Checks file boundaries, <500L module size limits, zero `mod.rs`, zero `#[allow(`,
`#[serde(deny_unknown_fields)]` on all new Deserialize structs, pure LF line endings,
opt-in default (`use_clonekit: false`), CargoFork workflow contract compliance, and a
real quick smoke run of `scripts/eval_ci_clonekit.py`. Zero compiler/Cargo calls.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
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


if __name__ == "__main__":
    unittest.main()
