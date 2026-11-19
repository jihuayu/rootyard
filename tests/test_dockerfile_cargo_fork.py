#!/usr/bin/env python3
"""Static contract for the formal Docker build-stage CargoFork pin."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
REVISION = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"


class DockerfileCargoForkTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOCKERFILE.read_text(encoding="utf-8")
        self.build_stage, runtime_tail = self.text.split(
            "FROM debian:trixie-slim", 1
        )
        self.runtime_stage = "FROM debian:trixie-slim" + runtime_tail

    def test_build_stage_pins_rust_1991_and_uses_the_shared_helper(self) -> None:
        self.assertIn("FROM rust:1.99.1 AS build", self.build_stage)
        self.assertNotIn("rust:1-trixie", self.text)
        self.assertIn("python3", self.build_stage.split("install_ci_cargo_fork.sh", 1)[0])
        self.assertIn(
            "COPY scripts/install_ci_cargo_fork.sh /usr/local/bin/install_ci_cargo_fork.sh",
            self.build_stage,
        )
        self.assertIn(
            "install_ci_cargo_fork.sh install \\\n"
            "         --cache-dir /opt/rootyard-cargo-fork \\\n"
            "         --require-os linux",
            self.build_stage,
        )
        self.assertIn(
            "install_ci_cargo_fork.sh verify \\\n"
            "      --cache-dir /opt/rootyard-cargo-fork \\\n"
            "      --require-os linux \\\n"
            "      --require-path",
            self.build_stage,
        )
        self.assertIn('ENV PATH="/opt/rootyard-cargo-fork/bin:${PATH}"', self.build_stage)
        self.assertIn("CARGO_FORK_AUTO_UPDATE=0", self.build_stage)

    def test_verify_precedes_the_release_build(self) -> None:
        verify = self.build_stage.index("install_ci_cargo_fork.sh verify")
        build = self.build_stage.index("cargo build --release --locked")
        self.assertLess(verify, build)
        self.assertIn("RUN cargo -vV", self.build_stage)
        self.assertIn("COPY Cargo.toml Cargo.lock rust-toolchain.toml ./", self.build_stage)

    def test_runtime_image_contains_no_compiler_or_cache(self) -> None:
        self.assertTrue(self.runtime_stage.lstrip().startswith("FROM debian:trixie-slim"))
        for forbidden in (
            "cargo",
            "rustc",
            "rustup",
            "RUSTUP_HOME",
            "CARGO_HOME",
            ".cargo",
            "rootyard-cargo-fork",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.runtime_stage)
        copy_lines = [
            line.strip()
            for line in self.runtime_stage.splitlines()
            if line.strip().startswith("COPY --from=build")
        ]
        self.assertEqual(
            copy_lines,
            [
                "COPY --from=build /build/target/release/rootyard /usr/local/bin/rootyard",
                "COPY --from=build /build/target/release/rootyard-safe-gc-voter /usr/local/bin/rootyard-safe-gc-voter",
            ],
        )
        self.assertIn(
            "RUN test -x /usr/local/bin/rootyard-safe-gc-voter && /usr/local/bin/rootyard-safe-gc-voter --version",
            self.runtime_stage,
        )

    def test_helper_is_in_the_build_context(self) -> None:
        ignored = DOCKERIGNORE.read_text(encoding="utf-8")
        self.assertNotIn("scripts", ignored)
        self.assertNotIn("install_ci_cargo_fork", ignored)
        self.assertIn(REVISION, (ROOT / "scripts/install_ci_cargo_fork.sh").read_text(encoding="utf-8"))
        self.assertTrue(re.search(r"^FROM rust:1\.99\.1 AS build$", self.text, re.M))


if __name__ == "__main__":
    unittest.main()
