#!/usr/bin/env python3
"""Cheap contracts for the ordinary-CI native host profile.

The verify job moved from a `rust:1-trixie` container on ubuntu-24.04 to a
plain Ubuntu 22.04 host. These tests only read workflow/helper text and run
`bash -n`; they do not install packages, download sources, mount anything or
touch the current host's privileges.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
INSTALLER = ROOT / "scripts/install_ci_native_tools.sh"
HELPERS = sorted((ROOT / "scripts/ci_native_tools").glob("*.sh"))
SCRIPTS = [INSTALLER, *HELPERS]
ALL_SCRIPT_TEXT = "\n".join(script.read_text(encoding="utf-8") for script in SCRIPTS)


class NativeCiProfileTest(unittest.TestCase):
    def test_verify_job_is_plain_ubuntu_2204_without_container_init(self) -> None:
        text = CI.read_text(encoding="utf-8")
        verify = text.split("\n  container:\n", 1)[0]
        self.assertIn("runs-on: ubuntu-22.04", verify)
        self.assertNotIn("container:", verify)
        self.assertNotIn("rust:1-trixie", verify)
        self.assertNotIn("--init", verify)
        # Host init (PID 1) reaps orphaned Git grandchildren; no global
        # subreaper/LSM workaround is allowed.
        self.assertIn("PID 1", verify)
        self.assertIn("Do not introduce a global child", verify)
        self.assertNotRegex(verify, r"subreaper\s*[=:]")
        self.assertNotRegex(text, r"(?i)apparmor.*(disable|complain)")
        self.assertNotIn("--privileged", text)

    def test_database_url_is_host_loopback_and_service_port_is_fixed(self) -> None:
        text = CI.read_text(encoding="utf-8")
        self.assertIn("- 127.0.0.1:55432:5432", text)
        self.assertIn(
            "ROOTYARD_TEST_DATABASE_URL: postgresql://rootyard:rootyard-ci-only@127.0.0.1:55432/rootyard_test",
            text,
        )
        self.assertNotIn("@postgres:5432", text)
        # The ephemeral service password is retained, not turned into trust.
        self.assertIn("POSTGRES_PASSWORD: rootyard-ci-only", text)

    def test_required_native_tools_and_preflight_are_wired(self) -> None:
        text = CI.read_text(encoding="utf-8")
        self.assertIn("scripts/install_ci_native_tools.sh install", text)
        self.assertIn("scripts/install_ci_native_tools.sh preflight", text)
        self.assertIn('python-version: "3.12"', text)
        for token in (
            "git-lfs",
            "fuse3",
            "util-linux",
            "redis-server",
            "openjdk-21-jdk-headless",
            "postgresql-17 postgresql-client-17",
        ):
            self.assertTrue(
                token in text or token in ALL_SCRIPT_TEXT,
                f"missing native tool token: {token}",
            )
        # No native case may be skipped or removed to make the job pass.
        self.assertNotIn("continue-on-error", text)
        self.assertIn("python3 -m unittest discover -s tests -p 'test_*.py'", text)
        self.assertIn("python3 tests/e2e.py", text)
        self.assertIn("python3 tests/lfs.py", text)

    def test_git_and_bubblewrap_pins_and_signed_sources_are_preserved(self) -> None:
        git_helper = (ROOT / "scripts/ci_native_tools/build_git_source.sh").read_text(encoding="utf-8")
        bwrap_helper = (ROOT / "scripts/ci_native_tools/build_bubblewrap_source.sh").read_text(encoding="utf-8")
        library = (ROOT / "scripts/ci_native_tools/lib.sh").read_text(encoding="utf-8")
        self.assertIn("0.9.0-1build1", bwrap_helper)
        self.assertIn("--size 1048576", bwrap_helper)
        self.assertIn("^(1:)?2\\.43\\.[0-9]+-", git_helper)
        self.assertIn("NO_TCLTK=1", git_helper)
        self.assertIn("NO_GETTEXT=1", git_helper)
        self.assertIn("NO_INSTALL_HARDLINKS=1", git_helper)
        for package in (
            "libssl-dev",
            "libcurl4-openssl-dev",
            "libexpat1-dev",
            "zlib1g-dev",
            "gettext",
        ):
            self.assertIn(package, ALL_SCRIPT_TEXT)
        self.assertIn("B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8", library)
        self.assertIn("noble-updates", library)
        self.assertIn("noble-security", library)
        # deb-src only: the Noble entries must not enable binary packages.
        noble_lines = [line for line in library.splitlines() if "ubuntu.com/ubuntu noble" in line]
        self.assertTrue(noble_lines)
        for line in noble_lines:
            self.assertRegex(line, r"deb-src\s+\[signed-by=")
            self.assertNotRegex(line, r"(^|\s)deb\s+\[")
        self.assertNotIn("ppa:", library.lower())

    def test_preflight_really_checks_fuse_and_user_namespaces(self) -> None:
        preflight = (ROOT / "scripts/ci_native_tools/preflight.sh").read_text(encoding="utf-8")
        self.assertIn("/dev/fuse", preflight)
        self.assertIn("unshare -Urnm", preflight)
        self.assertIn("mount -t tmpfs", preflight)
        self.assertIn("--size 1048576", preflight)
        self.assertIn("require_git_243", preflight)
        self.assertNotIn("|| true", preflight)
        self.assertNotIn("continue-on-error", preflight)

    def test_scripts_parse_and_stay_bounded(self) -> None:
        for script in SCRIPTS:
            self.assertTrue(script.is_file(), f"missing helper: {script}")
            source = script.read_text(encoding="utf-8")
            self.assertLess(len(source.splitlines()), 700, f"{script} exceeds the 700-line helper bound")
            result = subprocess.run(
                ["bash", "-n", str(script)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"{script}: {result.stderr}")
        self.assertTrue(INSTALLER.stat().st_mode & 0o111, "installer must be executable")

    def test_provenance_has_no_database_url_or_credentials(self) -> None:
        self.assertNotIn("postgresql://", ALL_SCRIPT_TEXT)
        self.assertNotIn("ROOTYARD_TEST_DATABASE_URL", ALL_SCRIPT_TEXT)
        self.assertNotIn("SECRET", ALL_SCRIPT_TEXT)
        self.assertNotIn("PASSWORD", ALL_SCRIPT_TEXT)
        self.assertNotIn("Bearer ", ALL_SCRIPT_TEXT)


if __name__ == "__main__":
    unittest.main()
