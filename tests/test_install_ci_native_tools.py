#!/usr/bin/env python3
"""Cheap contracts for the ordinary-CI native host profile.

The verify job moved from a `rust:1-trixie` container on ubuntu-24.04 to a
plain Ubuntu 22.04 host. These tests only read workflow/helper text and run
`bash -n`; they do not install packages, download sources, mount anything or
touch the current host's privileges.

The phase-diagnostics tests below run a copy of the wrapper against four
stub children in a temporary directory. They never invoke apt, a native
build, Cargo, PostgreSQL, Redis, Garage or FUSE, and they never use the
network or read real step logs. Each stub only appends its phase to a local
log, prints sentinels and, if asked, writes a minimal state file. The same
harness can prepend a path-scoped `mkdir` shim (to prove exact status
propagation without touching the host) and failing digest stubs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
INSTALLER = ROOT / "scripts/install_ci_native_tools.sh"
HELPERS = sorted((ROOT / "scripts/ci_native_tools").glob("*.sh"))
SCRIPTS = [INSTALLER, *HELPERS]
ALL_SCRIPT_TEXT = "\n".join(script.read_text(encoding="utf-8") for script in SCRIPTS)

PHASE_RECORD_REL = Path("test-results/ci-native-tools/phase.json")
PHASES = (
    "setup",
    "apt",
    "git_build",
    "bubblewrap_build",
    "profile_export",
    "preflight",
    "provenance",
)
STATES = ("entered", "failed", "complete")
MODES = ("install", "preflight")
STUB_NAMES = {
    "apt": "install_apt_packages.sh",
    "git": "build_git_source.sh",
    "bubblewrap": "build_bubblewrap_source.sh",
    "preflight": "preflight.sh",
}
SENTINEL_ENV = "SENTINEL-ENV-VALUE-7f3a"
STUB_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail
phase=__PHASE__
state_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --state-dir) state_dir=${2:-}; shift 2 ;;
    *) shift ;;
  esac
done
if [ -n "${ROOTYARD_TEST_STUB_LOG:-}" ]; then
  printf '%s\\n' "$phase" >>"$ROOTYARD_TEST_STUB_LOG"
fi
printf 'STUB-OUTPUT phase=%s args=%s env=%s\\n' "$phase" "$*" "${ROOTYARD_TEST_SENTINEL_ENV:-}"
printf 'STUB-ERROR phase=%s package=postgresql-17\\n' "$phase" >&2
if [ "${ROOTYARD_TEST_STUB_FAIL_PHASE:-}" = "$phase" ]; then
  exit "${ROOTYARD_TEST_STUB_STATUS:-1}"
fi
if [ "${ROOTYARD_TEST_INTERRUPT_PHASE:-}" = "$phase" ]; then
  sleep 60
fi
if [ "${ROOTYARD_TEST_SKIP_STATE:-}" != "$phase" ]; then
  mkdir -p -- "$state_dir"
  printf '{"component":"%s"}\\n' "$phase" >"$state_dir/$phase.json"
fi
"""
MKDIR_SHIM_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail
target=""
for argument in "$@"; do
  target=$argument
done
if [ "$target" = "${ROOTYARD_TEST_MKDIR_FAIL_TARGET:-}" ]; then
  count_file=${ROOTYARD_TEST_MKDIR_COUNT_FILE:?}
  count=0
  if [ -f "$count_file" ]; then
    count=$(cat "$count_file")
  fi
  count=$((count + 1))
  printf '%s\\n' "$count" >"$count_file"
  if [ "$count" -eq "${ROOTYARD_TEST_MKDIR_FAIL_ON_CALL:-0}" ]; then
    exit "${ROOTYARD_TEST_MKDIR_FAIL_STATUS:-57}"
  fi
fi
exec __REAL_MKDIR__ "$@"
"""


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
        self.assertIn("python3 scripts/run_python_ci_tests.py", text)
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


class NativeCiPhaseRecordTest(unittest.TestCase):
    """Offline behavior of the opt-in, fixed-field phase sidecar."""

    maxDiff = None

    def setUp(self) -> None:
        self.tempdir = Path(tempfile.mkdtemp(prefix="rootyard-ci-phase-"))
        self.addCleanup(shutil.rmtree, self.tempdir, ignore_errors=True)

    # -- harness ---------------------------------------------------------
    def _prepare(self, *, jdk: bool = False) -> dict[str, Path]:
        # Resolve symlinks (macOS /var -> /private/var) so the mkdir shim sees
        # the same canonical paths the wrapper derives from `pwd -P`.
        root = Path(tempfile.mkdtemp(prefix="case-", dir=self.tempdir)).resolve()
        scripts = root / "scripts"
        helpers = scripts / "ci_native_tools"
        helpers.mkdir(parents=True)
        (helpers / "lib.sh").write_text(
            (ROOT / "scripts/ci_native_tools/lib.sh").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        wrapper_text = INSTALLER.read_text(encoding="utf-8")
        original = "java_home=/usr/lib/jvm/java-21-openjdk-amd64"
        self.assertIn(original, wrapper_text)
        # The guard itself is production text; only the JDK location is
        # redirected so the test never depends on the host's JDK.
        java_home = self._fake_jdk(root) if jdk else root / "missing-jdk"
        wrapper = scripts / "install_ci_native_tools.sh"
        wrapper.write_text(wrapper_text.replace(original, f"java_home={java_home}"), encoding="utf-8")
        for phase, name in STUB_NAMES.items():
            stub = helpers / name
            stub.write_text(STUB_TEMPLATE.replace("__PHASE__", phase), encoding="utf-8")
            stub.chmod(0o755)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        fake_id = bin_dir / "id"
        fake_id.write_text("#!/usr/bin/env bash\nprintf '1000\\n'\n", encoding="utf-8")
        fake_id.chmod(0o755)
        prefix = root / "prefix"
        return {
            "root": root,
            "wrapper": wrapper,
            "prefix": prefix,
            "provenance": root / "provenance.json",
            "record": root / PHASE_RECORD_REL,
            "log": root / "stub.log",
            "bin_dir": bin_dir,
        }

    def _fake_jdk(self, root: Path) -> Path:
        jdk = root / "fake-jdk"
        (jdk / "bin").mkdir(parents=True)
        for name in ("java", "javac"):
            binary = jdk / "bin" / name
            binary.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
        return jdk

    def _environment(self, paths: dict[str, Path], extra: dict[str, str] | None = None) -> dict[str, str]:
        env = dict(os.environ)
        env.pop("RUNNER_TEMP", None)
        env.pop("GITHUB_PATH", None)
        env.pop("GITHUB_ENV", None)
        env["PATH"] = f"{paths['bin_dir']}:{env.get('PATH', '')}"
        env["ROOTYARD_TEST_STUB_LOG"] = str(paths["log"])
        env["ROOTYARD_TEST_SENTINEL_ENV"] = SENTINEL_ENV
        if extra:
            env.update(extra)
        return env

    def _run(
        self,
        paths: dict[str, Path],
        mode: str,
        *,
        prefix: bool = True,
        record: bool = True,
        record_path: Path | None = None,
        extra_args: tuple[str, ...] = (),
        env_extra: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> dict[str, object]:
        command = ["bash", str(paths["wrapper"]), mode]
        if prefix:
            command += ["--prefix", str(paths["prefix"])]
        command += ["--provenance", str(paths["provenance"])]
        if record:
            command += ["--phase-record", str(record_path or paths["record"])]
        command += list(extra_args)
        result = subprocess.run(
            command,
            cwd=paths["root"],
            env=self._environment(paths, env_extra),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "record": record_path or paths["record"],
            "provenance": paths["provenance"],
        }

    def _log(self, paths: dict[str, Path]) -> list[str]:
        if not paths["log"].is_file():
            return []
        return [line for line in paths["log"].read_text(encoding="utf-8").splitlines() if line]

    def _reset_log(self, paths: dict[str, Path]) -> None:
        if paths["log"].exists():
            paths["log"].unlink()

    def _install_mkdir_shim(self, paths: dict[str, Path]) -> None:
        real_mkdir = shutil.which("mkdir")
        self.assertIsNotNone(real_mkdir)
        shim = paths["bin_dir"] / "mkdir"
        shim.write_text(
            MKDIR_SHIM_TEMPLATE.replace("__REAL_MKDIR__", str(real_mkdir)),
            encoding="utf-8",
        )
        shim.chmod(0o755)

    def _disable_wrapper_digest(self, paths: dict[str, Path]) -> None:
        for name in ("sha256sum", "shasum"):
            stub = paths["bin_dir"] / name
            stub.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
            stub.chmod(0o755)

    def _seed_install_state(self, paths: dict[str, Path]) -> None:
        state = paths["prefix"] / "state"
        state.mkdir(parents=True)
        for name in ("apt", "git", "bubblewrap"):
            (state / f"{name}.json").write_text('{"component": "%s"}\n' % name, encoding="utf-8")

    def _assert_record(
        self,
        raw: bytes,
        *,
        mode: str,
        phase: str,
        state: str,
        wrapper: Path,
    ) -> None:
        digest = hashlib.sha256(wrapper.read_bytes()).hexdigest()
        expected = (
            '{"mode":"%s","phase":"%s","state":"%s","wrapper_sha256":"%s"}\n' % (mode, phase, state, digest)
        ).encode()
        self.assertEqual(raw, expected)
        document = json.loads(raw)
        self.assertEqual(set(document), {"mode", "phase", "state", "wrapper_sha256"})
        self.assertIn(document["mode"], MODES)
        self.assertIn(document["phase"], PHASES)
        self.assertIn(document["state"], STATES)

    def _assert_no_detail_leak(self, raw: bytes) -> None:
        text = raw.decode("utf-8")
        # Fixed-size record; contains enumerations and a hex digest only.
        self.assertLessEqual(len(raw), 200)
        for token in (
            "/",
            "STUB",
            "ROOTYARD",
            "apt-get",
            "postgresql",
            "sudo",
            "PASSWORD",
            "SECRET",
            SENTINEL_ENV,
        ):
            self.assertNotIn(token, text)
        self.assertNotIn("java", text.lower())
        self.assertNotIn(str(self.tempdir), text)

    # -- install mode ----------------------------------------------------
    def test_install_success_records_provenance_complete(self) -> None:
        paths = self._prepare(jdk=True)
        result = self._run(paths, "install")
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(self._log(paths), ["apt", "git", "bubblewrap", "preflight"])
        raw = result["record"].read_bytes()
        self._assert_record(raw, mode="install", phase="provenance", state="complete", wrapper=paths["wrapper"])
        self._assert_no_detail_leak(raw)
        self.assertTrue(result["provenance"].is_file())

    def test_install_child_failure_records_exact_phase_and_original_exit(self) -> None:
        cases = (
            ("apt", "apt", 7, ["apt"]),
            ("git", "git_build", 9, ["apt", "git"]),
            ("bubblewrap", "bubblewrap_build", 11, ["apt", "git", "bubblewrap"]),
            ("preflight", "preflight", 13, ["apt", "git", "bubblewrap", "preflight"]),
        )
        for stub_phase, record_phase, status, reached in cases:
            with self.subTest(phase=record_phase):
                paths = self._prepare(jdk=True)
                result = self._run(
                    paths,
                    "install",
                    env_extra={
                        "ROOTYARD_TEST_STUB_FAIL_PHASE": stub_phase,
                        "ROOTYARD_TEST_STUB_STATUS": str(status),
                    },
                )
                self.assertEqual(result["returncode"], status)
                self.assertEqual(self._log(paths), reached)
                raw = result["record"].read_bytes()
                self._assert_record(
                    raw, mode="install", phase=record_phase, state="failed", wrapper=paths["wrapper"]
                )
                self._assert_no_detail_leak(raw)
                self.assertFalse(result["provenance"].exists())

    def test_profile_guard_failure_records_profile_export(self) -> None:
        paths = self._prepare()  # java_home points at a path that cannot exist
        result = self._run(paths, "install")
        self.assertEqual(result["returncode"], 1)
        # preflight is a later phase and must not have run.
        self.assertEqual(self._log(paths), ["apt", "git", "bubblewrap"])
        raw = result["record"].read_bytes()
        self._assert_record(raw, mode="install", phase="profile_export", state="failed", wrapper=paths["wrapper"])
        self._assert_no_detail_leak(raw)
        self.assertNotIn(str(paths["root"] / "missing-jdk"), raw.decode("utf-8"))
        self.assertFalse(result["provenance"].exists())

    def test_profile_export_write_failure_preserves_the_original_gate(self) -> None:
        paths = self._prepare(jdk=True)
        # GITHUB_PATH points at a directory, so the append fails exactly where
        # the unwrapped installer would have aborted.
        broken_path_file = paths["root"] / "github-path-is-a-directory"
        broken_path_file.mkdir()
        result = self._run(paths, "install", env_extra={"GITHUB_PATH": str(broken_path_file)})
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(self._log(paths), ["apt", "git", "bubblewrap"])
        raw = result["record"].read_bytes()
        self._assert_record(raw, mode="install", phase="profile_export", state="failed", wrapper=paths["wrapper"])
        self._assert_no_detail_leak(raw)
        self.assertFalse(result["provenance"].exists())

    def test_early_directory_failure_keeps_exact_status_and_stops(self) -> None:
        cases = (
            ("prefix", lambda paths: paths["prefix"]),
            ("state", lambda paths: paths["prefix"] / "state"),
            ("work", lambda paths: paths["prefix"] / "work"),
            # The default provenance is <root>/provenance.json, so its parent
            # resolution is the setup step that must not be swallowed.
            ("provenance_parent", lambda paths: paths["root"]),
        )
        for label, target_of in cases:
            with self.subTest(directory=label):
                paths = self._prepare(jdk=True)
                self._install_mkdir_shim(paths)
                result = self._run(
                    paths,
                    "install",
                    env_extra={
                        "ROOTYARD_TEST_MKDIR_FAIL_TARGET": str(target_of(paths)),
                        "ROOTYARD_TEST_MKDIR_COUNT_FILE": str(paths["root"] / "mkdir-count"),
                        "ROOTYARD_TEST_MKDIR_FAIL_ON_CALL": "1",
                        "ROOTYARD_TEST_MKDIR_FAIL_STATUS": "57",
                    },
                )
                self.assertEqual(result["returncode"], 57)
                self.assertEqual(self._log(paths), [])
                raw = result["record"].read_bytes()
                self._assert_record(raw, mode="install", phase="setup", state="failed", wrapper=paths["wrapper"])
                self._assert_no_detail_leak(raw)
                self.assertFalse(result["provenance"].exists())

    def test_provenance_failure_never_claims_complete(self) -> None:
        paths = self._prepare(jdk=True)
        result = self._run(
            paths,
            "install",
            env_extra={"ROOTYARD_TEST_SKIP_STATE": "preflight"},
        )
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(self._log(paths), ["apt", "git", "bubblewrap", "preflight"])
        raw = result["record"].read_bytes()
        self._assert_record(raw, mode="install", phase="provenance", state="failed", wrapper=paths["wrapper"])
        self._assert_no_detail_leak(raw)
        self.assertNotEqual(json.loads(raw)["state"], "complete")
        self.assertFalse(result["provenance"].exists())

    def test_provenance_directory_failure_keeps_exact_status_and_stops(self) -> None:
        # Regression for the coordinator's counterexample: a failing mkdir for
        # the provenance directory used to be swallowed once the call was made
        # with `|| status=$?`, letting python write provenance and `complete`.
        paths = self._prepare(jdk=True)
        self._install_mkdir_shim(paths)
        provenance_dir = paths["root"] / "provenance-dir"
        paths["provenance"] = provenance_dir / "provenance.json"
        result = self._run(
            paths,
            "install",
            env_extra={
                "ROOTYARD_TEST_MKDIR_FAIL_TARGET": str(provenance_dir),
                "ROOTYARD_TEST_MKDIR_COUNT_FILE": str(paths["root"] / "mkdir-count"),
                # setup resolves this directory once; write_provenance creates
                # it again and is the call under test.
                "ROOTYARD_TEST_MKDIR_FAIL_ON_CALL": "2",
                "ROOTYARD_TEST_MKDIR_FAIL_STATUS": "57",
            },
        )
        self.assertEqual(result["returncode"], 57)
        self.assertEqual(self._log(paths), ["apt", "git", "bubblewrap", "preflight"])
        raw = result["record"].read_bytes()
        self._assert_record(raw, mode="install", phase="provenance", state="failed", wrapper=paths["wrapper"])
        self._assert_no_detail_leak(raw)
        self.assertNotEqual(json.loads(raw)["state"], "complete")
        # write_provenance (python) never ran, so no provenance was produced.
        self.assertFalse(result["provenance"].exists())

    # -- preflight mode --------------------------------------------------
    def test_preflight_mode_success_and_failure(self) -> None:
        paths = self._prepare(jdk=True)
        self._seed_install_state(paths)
        result = self._run(paths, "preflight")
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(self._log(paths), ["preflight"])
        raw = result["record"].read_bytes()
        self._assert_record(raw, mode="preflight", phase="provenance", state="complete", wrapper=paths["wrapper"])
        self._assert_no_detail_leak(raw)
        self.assertTrue(result["provenance"].is_file())

        failing = self._prepare(jdk=True)
        self._seed_install_state(failing)
        failed = self._run(
            failing,
            "preflight",
            env_extra={"ROOTYARD_TEST_STUB_FAIL_PHASE": "preflight", "ROOTYARD_TEST_STUB_STATUS": "5"},
        )
        self.assertEqual(failed["returncode"], 5)
        self.assertEqual(self._log(failing), ["preflight"])
        raw = failed["record"].read_bytes()
        self._assert_record(raw, mode="preflight", phase="preflight", state="failed", wrapper=failing["wrapper"])
        self._assert_no_detail_leak(raw)
        self.assertFalse(failed["provenance"].exists())

    # -- interruption and opt-in boundaries ------------------------------
    def test_external_kill_leaves_entered_not_a_failure_claim(self) -> None:
        paths = self._prepare(jdk=True)
        command = [
            "bash",
            str(paths["wrapper"]),
            "install",
            "--prefix",
            str(paths["prefix"]),
            "--provenance",
            str(paths["provenance"]),
            "--phase-record",
            str(paths["record"]),
        ]
        process = subprocess.Popen(
            command,
            cwd=paths["root"],
            env=self._environment(paths, {"ROOTYARD_TEST_INTERRUPT_PHASE": "apt"}),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if paths["record"].is_file() and self._log(paths) == ["apt"]:
                    document = json.loads(paths["record"].read_text(encoding="utf-8"))
                    if document["phase"] == "apt" and document["state"] == "entered":
                        break
                time.sleep(0.05)
            else:
                self.fail("wrapper never reached the entered record for apt")
            process.kill()  # SIGKILL: no trap or cleanup can rewrite the record
            process.wait(timeout=10)
            self.assertLess(process.returncode, 0)
            raw = paths["record"].read_bytes()
            self._assert_record(raw, mode="install", phase="apt", state="entered", wrapper=paths["wrapper"])
            self._assert_no_detail_leak(raw)
            self.assertEqual(self._log(paths), ["apt"])
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    def test_high_exit_status_is_a_conservative_unknown_boundary(self) -> None:
        # A status above 128 cannot be told apart from a signal, so it is kept
        # as `entered` and never recorded as a phase failure cause.
        paths = self._prepare(jdk=True)
        result = self._run(
            paths,
            "install",
            env_extra={"ROOTYARD_TEST_STUB_FAIL_PHASE": "apt", "ROOTYARD_TEST_STUB_STATUS": "200"},
        )
        self.assertEqual(result["returncode"], 200)
        self.assertEqual(self._log(paths), ["apt"])
        raw = result["record"].read_bytes()
        self._assert_record(raw, mode="install", phase="apt", state="entered", wrapper=paths["wrapper"])
        self._assert_no_detail_leak(raw)
        self.assertFalse(result["provenance"].exists())

    def test_opt_in_and_unavailable_records_never_change_the_gate(self) -> None:
        # No --phase-record: no sidecar at all, same success path.
        paths = self._prepare(jdk=True)
        result = self._run(paths, "install", record=False)
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(list(paths["root"].rglob("phase.json")), [])

        # Unwritable record location (parent is a regular file): no record, no
        # new output, and success is still success.
        paths = self._prepare(jdk=True)
        blocker = paths["root"] / "blocked-record-parent"
        blocker.write_text("not a directory\n", encoding="utf-8")
        blocked_record = blocker / "phase.json"
        result = self._run(paths, "install", record_path=blocked_record)
        self.assertEqual(result["returncode"], 0)
        self.assertFalse(blocked_record.exists())
        self.assertNotIn(str(blocker), result["stdout"] + result["stderr"])

        # Same unwritable location with a real child failure: the original
        # exit status still wins and the gate is not continued.
        self._reset_log(paths)
        result = self._run(
            paths,
            "install",
            record_path=blocked_record,
            env_extra={"ROOTYARD_TEST_STUB_FAIL_PHASE": "apt", "ROOTYARD_TEST_STUB_STATUS": "7"},
        )
        self.assertEqual(result["returncode"], 7)
        self.assertEqual(self._log(paths), ["apt"])

    def test_unavailable_wrapper_digest_leaves_no_unbound_receipt(self) -> None:
        paths = self._prepare(jdk=True)
        self._disable_wrapper_digest(paths)
        result = self._run(paths, "install")
        self.assertEqual(result["returncode"], 0)
        self.assertFalse(result["record"].exists())
        self.assertEqual(list(paths["root"].rglob("phase.json")), [])
        self.assertTrue(result["provenance"].is_file())

        # The same unavailable digest must not turn a real failure into a
        # receipt either, and must not change the gate's exit status.
        self._reset_log(paths)
        result = self._run(
            paths,
            "install",
            env_extra={"ROOTYARD_TEST_STUB_FAIL_PHASE": "apt", "ROOTYARD_TEST_STUB_STATUS": "7"},
        )
        self.assertEqual(result["returncode"], 7)
        self.assertEqual(self._log(paths), ["apt"])
        self.assertFalse(result["record"].exists())

    def test_early_setup_or_argument_problems_do_not_invent_a_positive(self) -> None:
        # Missing prefix/RUNNER_TEMP is recorded honestly as a setup failure
        # with no child executed, never as a success.
        paths = self._prepare()
        result = self._run(paths, "install", prefix=False)
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(self._log(paths), [])
        raw = result["record"].read_bytes()
        self._assert_record(raw, mode="install", phase="setup", state="failed", wrapper=paths["wrapper"])
        self._assert_no_detail_leak(raw)
        self.assertFalse(result["provenance"].exists())

        # An argument error before diagnostics are enabled may have no receipt;
        # it must never fabricate one.
        paths = self._prepare()
        result = self._run(paths, "install", extra_args=("--bogus",))
        self.assertEqual(result["returncode"], 1)
        self.assertFalse(paths["record"].exists())
        self.assertEqual(self._log(paths), [])

    # -- static contracts ------------------------------------------------
    def test_installer_sidecar_is_fixed_enumeration_plus_wrapper_digest(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            '{"mode":"%s","phase":"%s","state":"%s","wrapper_sha256":"%s"}',
            text,
        )
        self.assertIn('wrapper_source_digest "${BASH_SOURCE[0]}"', text)
        self.assertIn('mktemp -- "$directory/.ci-native-tools-phase.XXXXXXXX"', text)
        self.assertIn('mv -f -- "$tmp" "$phase_record"', text)
        for phase in PHASES:
            self.assertIn(f"phase_enter {phase}", text, f"phase is not entered: {phase}")
        self.assertIn("write_phase_record \"$failed_phase\" failed", text)
        self.assertIn("write_phase_record provenance complete", text)
        self.assertNotIn('write_phase_record provenance entered', text)
        # complete is only written after write_provenance succeeds.
        self.assertLess(
            text.index('write_provenance "$state_dir" "$provenance" "$prefix"'),
            text.index("write_phase_record provenance complete"),
        )
        # The provenance directory creation is checked explicitly because the
        # call site captures its status (which suppresses errexit inside).
        self.assertIn('output_dir=$(dirname -- "$output") || return $?', text)
        self.assertIn('mkdir -p -- "$output_dir" || return $?', text)
        self.assertIn('provenance_dir=$(resolve_absolute "$provenance_dir") || return $?', text)
        # Diagnostics are enabled only after the full argument list parsed, and
        # only when the wrapper can be bound to a digest.
        self.assertLess(
            text.index("while [ $# -gt 0 ]; do"),
            text.index('wrapper_source_digest "${BASH_SOURCE[0]}"'),
        )
        self.assertLess(
            text.index('wrapper_source_digest "${BASH_SOURCE[0]}"'),
            text.index("phase_record=$phase_record_arg"),
        )
        self.assertIn('if [ -n "$wrapper_sha256" ]; then', text)
        library = (ROOT / "scripts/ci_native_tools/lib.sh").read_text(encoding="utf-8")
        self.assertIn('mkdir -p -- "$1" || return $?', library)
        self.assertIn('printf \'%s\\n\' "$directory" >>"$GITHUB_PATH" || return $?', library)

        body = text.split("write_phase_record() {", 1)[1].split("\n}\n", 1)[0]
        for token in (
            '$*',
            "$@",
            "$prefix",
            "$state_dir",
            "$work",
            "$provenance",
            "$helper_dir",
            "GITHUB",
            "ROOTYARD",
            "curl",
            "apt-get",
            "sudo",
            "bwrap",
            "python3",
        ):
            self.assertNotIn(token, body, f"sidecar writer references {token}")

    def test_workflow_enables_and_uploads_the_exact_phase_record(self) -> None:
        text = CI.read_text(encoding="utf-8")
        self.assertEqual(
            text.count("--phase-record test-results/ci-native-tools/phase.json"),
            2,
        )
        install_step = self._step_block(text, "Install native CI toolchain")
        preflight_step = self._step_block(text, "Verify native CI tool profile")
        for block in (install_step, preflight_step):
            self.assertIn("--phase-record test-results/ci-native-tools/phase.json", block)
            self.assertNotIn("continue-on-error", block)
            self.assertNotIn("retry", block.lower())
        self.assertIn("timeout-minutes: 20", install_step)
        self.assertIn("timeout-minutes: 5", preflight_step)

        upload = self._step_block(text, "Upload end-to-end report")
        self.assertIn("if: always()", upload)
        paths = upload.split("path: |", 1)[1]
        self.assertEqual(paths.count("test-results/ci-native-tools/phase.json"), 1)
        self.assertNotIn("test-results/ci-native-tools/*", paths)

    @staticmethod
    def _step_block(text: str, name: str) -> str:
        marker = f"      - name: {name}"
        start = text.index(marker) + len(marker)
        rest = text[start:]
        end = rest.find("\n      - name: ")
        return rest if end == -1 else rest[:end]


if __name__ == "__main__":
    unittest.main()
