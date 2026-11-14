#!/usr/bin/env python3
"""Documentation guard for the Rust 1.99.1 / CargoFork 1.101.0 split.

The test only reads Markdown and TOML text. It does not run Cargo or claim that
a hosted CI run happened; the added prose explicitly says it records wiring, not
execution.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = ROOT / "docs/development.md"
CI_ACCEPTANCE = ROOT / "docs/ci-acceptance.md"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
REVISION = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"


class CargoForkDocumentationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.development = DEVELOPMENT.read_text(encoding="utf-8")
        self.ci = CI_ACCEPTANCE.read_text(encoding="utf-8")
        self.toolchain = TOOLCHAIN.read_text(encoding="utf-8")

    def test_toolchain_channel_stays_at_1991(self) -> None:
        self.assertRegex(self.toolchain, r'(?m)^channel = "1\.99\.1"$')
        self.assertNotRegex(self.toolchain, r'(?m)^channel = "1\.101\.0"$')
        self.assertIn("CargoFork", self.toolchain)
        self.assertIn(REVISION, self.toolchain)
        self.assertIn("not a rustup", self.toolchain)
        self.assertIn("`rustc -V` stays 1.99.1", self.toolchain)

    def test_development_docs_keep_compiler_and_cargo_driver_distinct(self) -> None:
        for token in (
            "Accepted gate compiler: 1.99.1",
            "Accepted gate Cargo driver: CargoFork 1.101.0",
            REVISION,
            "`release: 1.101.0`",
            "`rustc -V`",
            "`rustc 1.99.1`",
            "not the formal gate driver",
            "~/.cargo/targets",
            "CARGO_TARGET_DIR",
            "do not clone a whole `target` directory",
            "frozen schema007 legacy build",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.development)
        self.assertNotIn("Accepted gate toolchain: 1.99.1 (rustc 1.99.1, cargo 1.99.1", self.development)

    def test_ci_acceptance_lists_every_formal_rust_workflow_and_the_boundary(self) -> None:
        for token in (
            "Pinned CargoFork in formal Rust jobs",
            "This section documents the tool-selection contract",
            "does not record a hosted workflow run",
            "`ci.yml` (`verify`)",
            "`refstore-protocol-acceptance.yml` (`native`)",
            "`redis-contract.yml` (`redis-contract`)",
            "`pando-lab.yml` (`isolated-lab`)",
            "`refcas-log.yml` (`log-storage`)",
            "`native-kernel-acceptance.yml` (`native-kernel-cgroup`)",
            "`candidate-release-acceptance.yml`",
            "`browser-native` and",
            "`object-store-native`",
            REVISION,
            "rustup 1.99.1",
            "`rustc -V` to remain `rustc 1.99.1`",
            "`actions/cache@v4` restores and saves only the fork executable",
            "~/.cargo/targets",
            "do not set a per-commit `CARGO_TARGET_DIR`",
            "no Python\nharness invokes the install helper",
            "`rust:1.99.1` build stage",
            "`debian:trixie-slim`",
            "no rustup, compiler or Cargo cache",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.ci)
        self.assertNotIn("CI executed", self.ci)
        self.assertNotIn("CI passed", self.ci)
        self.assertNotIn("hosted run passed", self.ci)

    def test_no_workflow_claims_a_passing_hosted_run(self) -> None:
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertNotIn("CargoFork CI passed", text)
                self.assertNotIn("CargoFork run passed", text)
        self.assertRegex(
            self.ci,
            re.compile(r"it does not record a hosted workflow run", re.IGNORECASE),
        )


if __name__ == "__main__":
    unittest.main()
