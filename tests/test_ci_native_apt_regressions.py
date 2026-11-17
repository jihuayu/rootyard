#!/usr/bin/env python3
"""Offline behaviour regressions for the native-tool apt helpers in lib.sh.

Each case sources lib.sh in bash with a fixture PATH that holds only links to
routine host commands plus Python stand-ins for `apt-get`/`sudo`, which append
one JSON record per call to $FAKE_LOG. No real apt, sudo, /etc or network is
ever reachable. The PGDG key cases separately use Python stand-ins for
curl/gpg and a fake sleep, so no real download or keyring write is possible.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts/ci_native_tools/lib.sh"
HOST = ("bash", "cat", "env", "mkdir", "find", "sort", "id", "pwd", "dirname",
        "awk", "mktemp", "mv", "rm")
PGDG_URL = "https://www.postgresql.org/media/keys/ACCC4CF8.asc"
PGDG_FINGERPRINT = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"

SUDO = """#!{python}
import json, os, sys
log, args = sys.argv[1], sys.argv[2:]
with open(os.environ["FAKE_LOG"], "a") as stream:
    stream.write(json.dumps({{"kind": "sudo", "args": args}}) + "\\n")
# Only the one shape the helpers use is allowed; never fall back to real sudo.
apt = os.environ["FAKE_APT"]
exec_args = args[1:] if args[0] == "env" else args
assert exec_args[0] == "DEBIAN_FRONTEND=noninteractive", args
assert exec_args[1] == "apt-get", args
os.execv(apt, [apt, *exec_args[2:]])  # NEVER reach a real apt-get or sudo
"""

SUDO_REJECT = '#!{python}\nprint("fixture sudo invoked: " + " ".join(__import__("sys").argv[1:]), file=__import__("sys").stderr)\nraise SystemExit(93)\n'

APT_GET = """#!{python}
import json, os, re, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as stream:
    stream.write(json.dumps({{"kind": "apt-get", "args": args}}) + "\\n")
rest, command = list(args), None
while rest and command is None:
    if rest[0] in ("-o", "-c", "-t"):
        rest = rest[2:]
    elif rest[0].startswith("--"):
        rest = rest[1:]
    else:
        command = rest.pop(0)
if command not in ("update", "install", "source"):
    raise SystemExit(98)  # unsupported command: a real failure, not a package error
if command == "update":
    if rest != ["--error-on=any"]:
        raise SystemExit(97)  # a plain update may keep stale indexes with exit 0
elif command == "install":
    for arg in rest:
        if arg not in ("-y", "--no-install-recommends") and not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", arg):
            raise SystemExit(98)
elif not (len(rest) == 1 and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*=.*", rest[0])):
    raise SystemExit(98)
code = {{"update": "FAKE_UPDATE_RC", "install": "FAKE_INSTALL_RC", "source": "FAKE_SOURCE_RC"}}[command]
status = int(os.environ.get(code, "0"))
if status:
    raise SystemExit(status)
if command == "source":
    tree = rest[0].split("=", 1)[0]
    os.makedirs(os.path.join(tree, "debian"))
    with open(os.path.join(tree, "README"), "w") as stream:
        stream.write("fixture-acquired\\n")
"""

CURL = """#!{python}
import json, os, sys

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as stream:
    stream.write(json.dumps({{"kind": "curl", "args": args}}) + "\\n")


def value(flag):
    try:
        return args[args.index(flag) + 1]
    except (ValueError, IndexError):
        raise SystemExit(64)


# The helper must keep the exact reviewed flags and HTTPS endpoint. A missing
# bound is a hard fixture failure, never a reason to fall through to real curl.
if "-fsSL" not in args:
    raise SystemExit(64)
for forbidden in ("-k", "--insecure"):
    if forbidden in args:
        raise SystemExit(65)
if value("--url") != "https://www.postgresql.org/media/keys/ACCC4CF8.asc":
    raise SystemExit(64)
if value("--connect-timeout") != "10":
    raise SystemExit(64)
try:
    max_time = int(value("--max-time"))
except ValueError:
    raise SystemExit(64)
if not 1 <= max_time <= 30:
    raise SystemExit(64)
out = value("-o")
count_path = os.environ["FAKE_CURL_COUNT"]
try:
    count = int(open(count_path, encoding="utf-8").read())
except FileNotFoundError:
    count = 0
count += 1
with open(count_path, "w", encoding="utf-8") as stream:
    stream.write(str(count))
mode = os.environ.get("FAKE_CURL_MODE", "success")
if mode == "permanent" or (mode == "transient" and count == 1):
    with open(out, "w", encoding="utf-8") as stream:
        stream.write("partial")
    raise SystemExit(56)  # receive failure, like the hosted curl 56
with open(out, "w", encoding="utf-8") as stream:
    stream.write("fixture PGDG key\\n")
"""

GPG = """#!{python}
import json, os, sys

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as stream:
    stream.write(json.dumps({{"kind": "gpg", "args": args}}) + "\\n")
if args[:2] == ["--show-keys", "--with-colons"]:
    print("pub:-:4096:1:0123456789ABCDEF:1:1:::::::scESC:::::::")
    fingerprint = os.environ.get("FAKE_GPG_FPR", "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8")
    print("fpr:::::::::" + fingerprint + ":")
    raise SystemExit(0)
raise SystemExit(92)  # dearmor/install must not happen in these cases
"""

SLEEP = """#!{python}
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as stream:
    stream.write(json.dumps({{"kind": "sleep", "args": sys.argv[1:]}}) + "\\n")
"""

SUDO_LOG_REJECT = """#!{python}
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as stream:
    stream.write(json.dumps({{"kind": "sudo", "args": sys.argv[1:]}}) + "\\n")
raise SystemExit(93)
"""


class NativeAptRegressionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ci-native-apt-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.log = self.tmp / "argv.jsonl"
        for name in HOST:
            target = shutil.which(name)
            self.assertIsNotNone(target, f"host command missing: {name}")
            os.symlink(target, self.bin / name)
        self.apt = self.bin / "apt-get"
        self._script(self.apt, APT_GET)

    def _script(self, path: Path, template: str) -> None:
        path.write_text(template.format(python=sys.executable), encoding="utf-8")
        path.chmod(0o755)

    def _sudo(self, template: str = SUDO) -> None:
        self._script(self.bin / "sudo", template)

    def _pgdg_fixtures(self, *, curl_mode: str = "success",
                       fpr: str = PGDG_FINGERPRINT) -> dict[str, str]:
        self._script(self.bin / "curl", CURL)
        self._script(self.bin / "gpg", GPG)
        self._script(self.bin / "sudo", SUDO_LOG_REJECT)
        self._script(self.bin / "sleep", SLEEP)
        return {
            "FAKE_CURL_MODE": curl_mode,
            "FAKE_CURL_COUNT": str(self.tmp / "curl-count"),
            "FAKE_GPG_FPR": fpr,
        }

    def _run(self, body: str, **env_extra: str) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [shutil.which("bash"), "-p", "-c", f'. "{LIB}"\n' + textwrap.dedent(body)],
            cwd=self.tmp,
            env={"PATH": str(self.bin), "FAKE_LOG": str(self.log), "FAKE_APT": str(self.apt),
                 "HOME": str(self.tmp), **env_extra},
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result

    def _calls(self, kind: str) -> list[list[str]]:
        if not self.log.exists():
            return []
        lines = self.log.read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines]
        return [record["args"] for record in records if record["kind"] == kind]

    def _apt(self, args: list[str]) -> tuple[list[str], dict[str, str]]:
        """Split one fixture apt-get argv into its command and `-o k=v` map."""
        rest, options = list(args), {}
        while rest[0] != "update" and rest[0] != "install" and rest[0] != "source":
            self.assertEqual(rest[0], "-o", rest)
            key, _, value = rest[1].partition("=")
            options[key] = value
            rest = rest[2:]
        return rest[0], options

    def test_fetch_source_runs_unprivileged_with_bounded_acquire(self) -> None:
        self._sudo(SUDO_REJECT)
        result = self._run('fetch_source git "1:2.43.0-1ubuntu7" work')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._calls("sudo"), [])
        (argv,) = self._calls("apt-get")
        self.assertEqual(argv[0], "-o")  # no sudo/env wrapper in front
        command, options = self._apt(argv)
        self.assertEqual(command, "source")
        self.assertEqual(argv[argv.index("source") + 1:], ["git=1:2.43.0-1ubuntu7"])
        self.assertEqual(set(options), {"Acquire::http::Timeout", "Acquire::https::Timeout",
                                        "Acquire::Retries", "Acquire::http::Pipeline-Depth"})
        self.assertEqual(options["Acquire::http::Timeout"],
                         options["Acquire::https::Timeout"])
        self.assertEqual(options["Acquire::http::Timeout"], "30")
        self.assertEqual(options["Acquire::Retries"], "3")
        self.assertEqual(options["Acquire::http::Pipeline-Depth"], "0")
        tree = self.tmp / "work" / "git"
        self.assertTrue((tree / "README").is_file())
        self.assertEqual((tree / "README").stat().st_uid, os.getuid())
        self.assertEqual((tree / "debian").stat().st_uid, os.getuid())

    def test_update_and_install_go_through_sudo_with_same_options(self) -> None:
        self._sudo(SUDO_REJECT)
        rejected = self._run("apt_update && apt_install fuse3")
        self.assertEqual(rejected.returncode, 93, rejected.stderr)
        self.log.unlink(missing_ok=True)
        self._sudo()
        result = self._run("apt_update\napt_install ca-certificates fuse3")
        self.assertEqual(result.returncode, 0, result.stderr)
        sudo_calls = self._calls("sudo")
        self.assertEqual([argv[-2:] for argv in sudo_calls],
                         [["update", "--error-on=any"], ["ca-certificates", "fuse3"]])
        # GNU env drops the leading "env": DEBIAN_FRONTEND=... apt-get -o ...
        self.assertTrue(all(c[0] == "DEBIAN_FRONTEND=noninteractive" for c in sudo_calls))
        update_args, install_args = self._calls("apt-get")
        update_command, update_options = self._apt(update_args)
        install_command, install_options = self._apt(install_args)
        self.assertEqual(update_command, "update")
        self.assertEqual(update_args[-2:], ["update", "--error-on=any"])
        self.assertEqual(install_command, "install")
        self.assertEqual(install_args[install_args.index("install") + 1:],
                         ["-y", "--no-install-recommends", "ca-certificates", "fuse3"])
        self.assertEqual(update_options, install_options)
        self.assertEqual(len(update_options), 4)

    def test_failures_propagate_and_plain_update_is_not_accepted(self) -> None:
        self._sudo()
        for body, env in (("apt_update", {"FAKE_UPDATE_RC": "100"}),
                          ("apt_install fuse3", {"FAKE_INSTALL_RC": "100"}),
                          ("fetch_source git 2.43.0-1 work", {"FAKE_SOURCE_RC": "100"})):
            result = self._run(body, **env)
            self.assertEqual(result.returncode, 100, f"{body}: {result.stderr}")
            self.assertEqual(result.stderr, "", body)
        self.assertFalse((self.tmp / "work" / "git").exists())
        # Dropping --error-on=any (the stale-index bug) must be caught by the
        # fixture as a real failure of the plain command, not as a package error.
        stripped = self._run(
            """
            apt_run() { sudo env DEBIAN_FRONTEND=noninteractive apt-get "$@"; }
            apt_update() { apt_run update; }
            apt_update
            """
        )
        self.assertEqual(stripped.returncode, 97, stripped.stderr)

    def test_wrong_acquire_namespace_is_rejected(self) -> None:
        self._sudo()
        result = self._run("apt_update\nfetch_source git 2.43.0-1 work")
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = self._calls("apt-get") + [argv[4:] for argv in self._calls("sudo")]
        for argv in actual:
            _, options = self._apt(argv)
            self.assertTrue(options)
            for key in options:
                self.assertFalse(key == "APT::Acquire" or key.startswith("APT::Acquire::"), key)
                self.assertTrue(key.startswith(("Acquire::http::", "Acquire::https::",
                                                "Acquire::Retries")), key)


    def test_pgdg_key_fetch_retries_transient_receive_error(self) -> None:
        env = self._pgdg_fixtures(curl_mode="transient")
        result = self._run(
            """
            download_pgdg_signing_key work work/pgdg.asc
            : > reached
            """,
            **env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls("curl")
        self.assertEqual(len(calls), 2, calls)
        outputs = [argv[argv.index("-o") + 1] for argv in calls]
        self.assertEqual(len(set(outputs)), 2, outputs)  # fresh file per attempt
        for argv in calls:
            self.assertIn("-fsSL", argv)
            self.assertEqual(argv[argv.index("--url") + 1], PGDG_URL)
            self.assertEqual(argv[argv.index("--connect-timeout") + 1], "10")
            self.assertTrue(1 <= int(argv[argv.index("--max-time") + 1]) <= 30)
        self.assertEqual(self._calls("sleep"), [["2"]])
        gpg_calls = self._calls("gpg")
        self.assertEqual(len(gpg_calls), 1, gpg_calls)
        self.assertEqual(gpg_calls[0][:2], ["--show-keys", "--with-colons"])
        self.assertEqual(self._calls("sudo"), [])
        self.assertEqual((self.tmp / "work" / "pgdg.asc").read_text(encoding="utf-8"),
                         "fixture PGDG key\n")
        self.assertTrue((self.tmp / "reached").is_file())
        self.assertEqual(list((self.tmp / "work").glob(".pgdg-key.*")), [])

    def test_pgdg_key_fetch_terminal_failure_skips_gpg_and_sudo(self) -> None:
        env = self._pgdg_fixtures(curl_mode="permanent")
        result = self._run(
            """
            download_pgdg_signing_key work work/pgdg.asc
            : > reached
            """,
            **env,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("after 3 attempts", result.stderr)
        self.assertIn("curl exit 56", result.stderr)
        calls = self._calls("curl")
        self.assertEqual(len(calls), 3, calls)
        outputs = [argv[argv.index("-o") + 1] for argv in calls]
        self.assertEqual(len(set(outputs)), 3, outputs)
        self.assertEqual(self._calls("sleep"), [["2"], ["2"]])
        self.assertEqual(self._calls("gpg"), [])
        self.assertEqual(self._calls("sudo"), [])
        self.assertFalse((self.tmp / "work" / "pgdg.asc").exists())
        self.assertFalse((self.tmp / "reached").exists())
        self.assertEqual(list((self.tmp / "work").glob(".pgdg-key.*")), [])

    def test_pgdg_key_fetch_does_not_retry_bad_fingerprint(self) -> None:
        env = self._pgdg_fixtures(fpr="0" * 40)
        result = self._run(
            """
            download_pgdg_signing_key work work/pgdg.asc
            : > reached
            """,
            **env,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("fingerprint mismatch", result.stderr)
        self.assertEqual(len(self._calls("curl")), 1)
        self.assertEqual(self._calls("sleep"), [])
        gpg_calls = self._calls("gpg")
        self.assertEqual(len(gpg_calls), 1, gpg_calls)
        self.assertEqual(gpg_calls[0][:2], ["--show-keys", "--with-colons"])
        self.assertEqual(self._calls("sudo"), [])
        self.assertFalse((self.tmp / "work" / "pgdg.asc").exists())
        self.assertFalse((self.tmp / "reached").exists())
        self.assertEqual(list((self.tmp / "work").glob(".pgdg-key.*")), [])


if __name__ == "__main__":
    unittest.main()
