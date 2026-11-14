#!/usr/bin/env python3
"""Offline contracts for the pinned formal-CI CargoFork setup helper.

These tests never build Cargo and never touch the network.  They put fake
`rustup`, `rustc` and fork executables on a private PATH so the helper's
adopt/cache/verify paths can be exercised, including a cache hit that must not
run `cargo install`.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/install_ci_cargo_fork.sh"
REVISION = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
RELEASE = "1.101.0"
BOOTSTRAP_COMMIT = "b" * 40

FAKE_RUSTUP = """#!__PYTHON__
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as stream:
    stream.write(json.dumps({"tool": "rustup", "args": args}) + "\\n")
if args[:4] == ["run", "1.99.1", "cargo", "-vV"]:
    print("cargo 1.99.1 (5f94df478 2026-08-27)")
    print("release: 1.99.1")
    print("commit-hash: __BOOTSTRAP__")
    print("commit-date: 2026-08-27")
    print("host: __HOST__")
    raise SystemExit(0)
if "install" in args:
    raise SystemExit(91)
raise SystemExit(90)
"""

FAKE_RUSTC = """#!__PYTHON__
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as stream:
    stream.write(json.dumps({"tool": "rustc", "args": args}) + "\\n")
release = os.environ.get("FAKE_RUSTC_RELEASE", "1.99.1")
if args == ["-V"]:
    print("rustc %s (58cf8f9c3 2026-10-13)" % release)
    raise SystemExit(0)
if args == ["-vV"]:
    print("rustc %s (58cf8f9c3 2026-10-13)" % release)
    print("release: " + release)
    print("commit-hash: " + "c" * 40)
    print("commit-date: 2026-10-13")
    print("host: " + os.environ.get("FAKE_RUSTC_HOST", "__HOST__"))
    raise SystemExit(0)
raise SystemExit(90)
"""

FAKE_CARGO = """#!__PYTHON__
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as stream:
    stream.write(json.dumps({"tool": "candidate", "args": args}) + "\\n")
if args == ["-vV"]:
    release = os.environ.get("FAKE_CARGO_RELEASE", "__RELEASE__")
    commit = os.environ.get("FAKE_CARGO_COMMIT", "__REVISION__")
    host = os.environ.get("FAKE_CARGO_HOST", "__HOST__")
    print("cargo %s (64a6ee6a4 2026-11-10) (huacnlee/cargo, https://huacnlee.github.io/cargo/)" % release)
    print("release: " + release)
    print("commit-hash: " + commit)
    print("commit-date: 2026-11-10")
    print("host: " + host)
    raise SystemExit(0)
raise SystemExit(0)
"""

HOST_COMMANDS = (
    "awk",
    "bash",
    "basename",
    "cat",
    "chmod",
    "cp",
    "dirname",
    "ln",
    "mkdir",
    "mv",
    "perl",
    "python3",
    "rm",
    "sed",
    "sha256sum",
    "shasum",
    "tr",
    "uname",
)


def host_triple() -> str:
    machine = platform.machine().lower()
    arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(machine, machine)
    if sys.platform == "darwin":
        return f"{arch}-apple-darwin"
    if sys.platform.startswith("linux"):
        return f"{arch}-unknown-linux-gnu"
    raise unittest.SkipTest("the helper contract is exercised on Linux and macOS only")


class CargoForkHelperTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="ci-cargo-fork-helper-")).resolve()
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)
        self.host = host_triple()
        self.system_bin = self.temp / "system-bin"
        self.fake_bin = self.temp / "fake-bin"
        self.system_bin.mkdir()
        self.fake_bin.mkdir()
        for name in HOST_COMMANDS:
            if name == "python3":
                continue
            target = shutil.which(name)
            if target:
                os.symlink(target, self.system_bin / name)
        # Ignore a mise/version-manager shim that is not a real interpreter:
        # the helper and the fake executables use the running interpreter.
        os.symlink(sys.executable, self.system_bin / "python3")
        self._script(self.fake_bin / "rustup", FAKE_RUSTUP)
        self._script(self.fake_bin / "rustc", FAKE_RUSTC)
        self.candidate = self.temp / "candidate" / "cargo"
        self.candidate.parent.mkdir()
        self._script(self.candidate, FAKE_CARGO)
        self.cache = self.temp / "cache"
        self.log = self.temp / "calls.jsonl"
        self.record = self.temp / "record.json"
        self.github_env = self.temp / "github-env"
        self.github_path = self.temp / "github-path"
        self.build_dir = self.temp / "build"
        self.home = self.temp / "home"
        self.tmpdir = self.temp / "tmp"
        self.home.mkdir()
        self.tmpdir.mkdir()
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("CARGO_FORK_")
        }
        self.env.update(
            {
                "PATH": f"{self.system_bin}:{self.fake_bin}",
                "HOME": str(self.home),
                "TMPDIR": str(self.tmpdir),
                "XDG_CACHE_HOME": str(self.temp / "xdg"),
                "FAKE_LOG": str(self.log),
                "CARGO_FORK_BUILD_DIR": str(self.build_dir),
                "GITHUB_ENV": str(self.github_env),
                "GITHUB_PATH": str(self.github_path),
            }
        )

    def _script(self, path: Path, template: str) -> None:
        path.write_text(
            template.replace("__PYTHON__", sys.executable)
            .replace("__HOST__", self.host)
            .replace("__BOOTSTRAP__", BOOTSTRAP_COMMIT)
            .replace("__REVISION__", REVISION)
            .replace("__RELEASE__", RELEASE),
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _run(self, *args: str, env: dict[str, str] | None = None,
             path: str | None = None) -> subprocess.CompletedProcess:
        environment = dict(self.env)
        if env:
            environment.update(env)
        if path is not None:
            environment["PATH"] = path
        return subprocess.run(
            [str(HELPER), *args],
            env=environment,
            cwd=self.temp,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _install(self, *extra: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        return self._run(
            "install",
            "--cache-dir", str(self.cache),
            "--reuse", str(self.candidate),
            "--record", str(self.record),
            "--no-github",
            *extra,
            env=env,
        )

    def _calls(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def _record(self, path: Path | None = None) -> dict:
        return json.loads((path or self.record).read_text(encoding="utf-8"))

    def _clear_log(self) -> None:
        self.log.unlink(missing_ok=True)

    def test_helper_pins_full_revision_and_bootstraps_with_rustup_cargo(self) -> None:
        text = HELPER.read_text(encoding="utf-8")
        self.assertIn(REVISION, text)
        self.assertIn("readonly RELEASE=1.101.0", text)
        self.assertIn("readonly BOOTSTRAP_TOOLCHAIN=1.99.1", text)
        self.assertIn('rustup run "$BOOTSTRAP_TOOLCHAIN" cargo install', text)
        self.assertIn('--git "$CARGO_GIT" --rev "$REVISION" --locked', text)
        self.assertNotRegex(text, r"(?m)^\s*rustup\s+which\s+cargo")
        self.assertIn("CARGO_FORK_AUTO_UPDATE=0", text)
        self.assertIn("binary_sha256", text)
        syntax = subprocess.run(
            ["bash", "-n", str(HELPER)], capture_output=True, text=True, check=False
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertTrue(HELPER.stat().st_mode & 0o111)

    def test_adopts_valid_installed_fork_and_records_identity(self) -> None:
        result = self._install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("source=reuse", result.stdout)
        self.assertIn(f"revision={REVISION}", result.stdout)

        record = self._record()
        self.assertEqual(record["schema"], "rootyard/ci-cargo-fork/v1")
        self.assertEqual(record["revision"], REVISION)
        self.assertEqual(record["release"], RELEASE)
        self.assertEqual(record["commit_hash"], REVISION)
        self.assertEqual(record["host"], self.host)
        self.assertEqual(record["os"], "darwin" if sys.platform == "darwin" else "linux")
        self.assertEqual(record["bootstrap"]["toolchain"], "1.99.1")
        self.assertEqual(record["bootstrap"]["commit_hash"], BOOTSTRAP_COMMIT)
        self.assertEqual(record["rustc"]["release"], "1.99.1")
        self.assertTrue(record["full_version"].startswith("cargo 1.101.0"))
        self.assertTrue(Path(record["installed_path"]).is_file())
        self.assertTrue(Path(record["resolved_path"]).is_symlink())

        cached = Path(record["installed_path"]).read_bytes()
        self.assertEqual(record["binary_sha256"], hashlib.sha256(cached).hexdigest())
        self.assertEqual(record["binary_sha256"], hashlib.sha256(self.candidate.read_bytes()).hexdigest())

    def test_cache_hit_does_not_rebuild_or_reobserve_the_candidate(self) -> None:
        first = self._install()
        self.assertEqual(first.returncode, 0, first.stderr)
        self._clear_log()

        second = self._run(
            "install",
            "--cache-dir", str(self.cache),
            "--record", str(self.record),
            "--no-github",
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("source=cache", second.stdout)
        calls = self._calls()
        self.assertFalse([call for call in calls if call.get("path") == str(self.candidate)])
        rustup_args = [call["args"] for call in calls if call["tool"] == "rustup"]
        self.assertEqual(rustup_args, [["run", "1.99.1", "cargo", "-vV"]])

    def test_verify_requires_the_pinned_path_and_checks_metadata_sha(self) -> None:
        first = self._install()
        self.assertEqual(first.returncode, 0, first.stderr)
        cache_bin = self.cache / "bin"
        good_path = f"{cache_bin}:{self.system_bin}:{self.fake_bin}"

        verified = self._run(
            "verify",
            "--cache-dir", str(self.cache),
            "--require-path",
            "--no-github",
            path=good_path,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("source=verified", verified.stdout)

        wrong_bin = self.temp / "wrong-bin"
        wrong_bin.mkdir()
        os.symlink(self.candidate, wrong_bin / "cargo")
        wrong_path = self._run(
            "verify",
            "--cache-dir", str(self.cache),
            "--require-path",
            "--no-github",
            path=f"{wrong_bin}:{self.system_bin}:{self.fake_bin}",
        )
        self.assertNotEqual(wrong_path.returncode, 0)
        self.assertIn("not the pinned fork", wrong_path.stderr)

        metadata = next(self.cache.glob("installs/*/metadata.json"))
        document = json.loads(metadata.read_text(encoding="utf-8"))
        document["binary_sha256"] = "0" * 64
        metadata.write_text(json.dumps(document), encoding="utf-8")
        rejected = self._run(
            "verify",
            "--cache-dir", str(self.cache),
            "--no-github",
            path=good_path,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("SHA-256 does not match", rejected.stderr)

    def test_invalid_metadata_or_binary_is_readopted_not_trusted(self) -> None:
        first = self._install()
        self.assertEqual(first.returncode, 0, first.stderr)
        metadata = next(self.cache.glob("installs/*/metadata.json"))
        document = json.loads(metadata.read_text(encoding="utf-8"))
        document["binary_sha256"] = "0" * 64
        metadata.write_text(json.dumps(document), encoding="utf-8")
        self._clear_log()

        readopted = self._install()
        self.assertEqual(readopted.returncode, 0, readopted.stderr)
        self.assertIn("source=reuse", readopted.stdout)
        self.assertFalse([call for call in self._calls() if "install" in call["args"]])

        installed = Path(self._record()["installed_path"])
        installed.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = -vV ]; then\n"
            "cat <<'EOF'\n"
            "cargo 1.101.0 (deadbee 2026-11-10)\n"
            "release: 1.101.0\n"
            f"commit-hash: {'d' * 40}\n"
            f"host: {self.host}\n"
            "EOF\n"
            "  exit 0\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        installed.chmod(0o755)
        self._clear_log()
        recovered = self._install()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertIn("source=reuse", recovered.stdout)
        self.assertEqual(
            self._record()["binary_sha256"],
            hashlib.sha256(self.candidate.read_bytes()).hexdigest(),
        )

    def test_rejects_wrong_release_commit_or_architecture(self) -> None:
        for name, environment in (
            ("release", {"FAKE_CARGO_RELEASE": "1.102.0"}),
            ("commit", {"FAKE_CARGO_COMMIT": "d" * 40}),
            ("architecture", {"FAKE_CARGO_HOST": "riscv64gc-unknown-linux-gnu"}),
        ):
            with self.subTest(name=name):
                self._clear_log()
                cache = self.temp / f"cache-{name}"
                record = self.temp / f"record-{name}.json"
                result = self._run(
                    "install",
                    "--cache-dir", str(cache),
                    "--reuse", str(self.candidate),
                    "--record", str(record),
                    "--no-github",
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(record.exists())
                self.assertFalse((cache / "bin" / "cargo").exists())

    def test_rejects_the_filesystem_root_as_a_cache_dir(self) -> None:
        result = self._run("install", "--cache-dir", "/", "--no-github")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("filesystem root", result.stderr)

    def test_requires_rustc_to_remain_1991(self) -> None:
        result = self._install(env={"FAKE_RUSTC_RELEASE": "1.98.0"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rustc release", result.stderr)
        self.assertIn("1.99.1", result.stderr)

    def test_github_environment_propagation(self) -> None:
        result = self._run(
            "install",
            "--cache-dir", str(self.cache),
            "--reuse", str(self.candidate),
            "--record", str(self.record),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        environment = self.github_env.read_text(encoding="utf-8")
        self.assertIn(f"CARGO_FORK_BIN={self.cache}/bin/cargo", environment)
        self.assertIn(f"CARGO_FORK_REVISION={REVISION}", environment)
        self.assertIn("CARGO_FORK_RELEASE=1.101.0", environment)
        self.assertIn("CARGO_FORK_AUTO_UPDATE=0", environment)
        self.assertIn("CARGO_FORK_CACHE_KEY=", environment)
        self.assertIn(str(self.cache / "bin"), self.github_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
