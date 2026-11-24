"""Focused tests for the test-only S4 reverse fsck Git wrapper.

No PostgreSQL, S3, network, cargo or remote Git is used. Synthetic Git child
processes supply stderr/statuses; one benign stock Git repository proves the
real pass-through path. Artifacts are checked for closed categories and status
only, never for sentinel/path/oid text.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "tests" / "s4_ci_pins_git_view_support" / "git_fsck_diagnostic.py"
OID40 = "a" * 40
OID64 = "b" * 64


def load_wrapper():
    spec = importlib.util.spec_from_file_location("s4_fsck_git_diagnostic", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


wrapper = load_wrapper()


def target(repo="/tmp/projected", oid=OID40):
    return ["-c", "core.hooksPath=/dev/null", "--no-replace-objects",
            "-C", repo, "fsck", "--strict", "--no-reflogs", oid]


class InvocationTests(unittest.TestCase):
    def test_wrapper_is_executable(self):
        self.assertTrue(os.access(WRAPPER, os.X_OK))

    def test_accepts_only_the_exact_reverse_fsck_shape(self):
        self.assertTrue(wrapper.is_target(target()))
        self.assertTrue(wrapper.is_target(target(oid=OID64)))
        invalid = [
            target() + ["extra"],
            target()[:-1],
            target(repo=""),
            target(repo="/tmp/bad\nrepo"),
            target(oid=OID40.upper()),
            target(oid=OID40[:-1]),
            target(oid=OID40 + "a"),
            target(oid="g" * 40),
            target()[:1] + ["core.hooksPath=/tmp"] + target()[2:],
            target()[:5] + ["fsck", "--strict", "--no-reflogs", "--"] + target()[8:],
            target()[:5] + ["fsck", "--strict", OID40],
        ]
        for args in invalid:
            with self.subTest(args=args):
                self.assertFalse(wrapper.is_target(args))

    def assert_exec(self, argv, env_value):
        with mock.patch.object(wrapper.os, "execv", side_effect=SystemExit(0)) as execv:
            with mock.patch.dict(os.environ, {wrapper.ENV: env_value}):
                with self.assertRaises(SystemExit):
                    wrapper.main(argv)
        execv.assert_called_once_with(wrapper.GIT, [wrapper.GIT, *argv])

    def test_non_targets_and_opt_out_exec_exact_stock_git(self):
        for argv in (["--version"], ["status"], target(), target(oid=OID64)):
            with self.subTest(argv=argv):
                self.assert_exec(argv, "")
        self.assert_exec(target(), "relative/path")
        self.assert_exec(target(), "/tmp/bad\npath")


class ClassificationTests(unittest.TestCase):
    def test_known_phrases_map_to_closed_categories(self):
        cases = (
            (b"missing blob " + OID40.encode(), "missing_object"),
            (b"missing tree " + OID64.encode() + b"\n", "missing_object"),
            (b"broken link from  tree " + OID40.encode() + b" to commit " + OID64.encode(), "broken_link"),
            (b"dangling commit " + OID40.encode(), "dangling"),
            (b"error in commit " + OID40.encode() + b": invalid author line", "invalid_object"),
            (b"error in commit " + OID40.encode() + b": missingAuthor: author missing", "missingAuthor"),
            (b"error in tree " + OID64.encode() + b": treeNotSorted: paths out of order", "treeNotSorted"),
            (b"error in commit " + OID40.encode() + b": privateName: secret sentinel", "invalid_object"),
            (b"error: hash mismatch for object " + OID64.encode(), "object_hash_mismatch"),
            (b"error: pack checksum mismatch", "pack_checksum_mismatch"),
            (b"fatal: object corrupt or missing", "object_corrupt_or_missing"),
            (b"fatal: transport failure", "fatal"),
            (b"error: object is corrupt", "error"),
            (b"warning: bad date", "warning"),
            (b"notice: retained", "notice"),
        )
        for line, category in cases:
            with self.subTest(line=line):
                self.assertEqual(wrapper.classify(line), category)

    def test_malformed_and_sentinel_phrases_become_unknown(self):
        for line in (
            b"missing blob not-a-hex-oid",
            b"missing blob " + OID40.upper().encode(),
            b"missing blob",
            b"broken link from tree",
            b"dangling",
            b"error in commit " + OID40.encode(),
            b"UNRECOGNIZED opaque-sentinel-7f4a",
        ):
            with self.subTest(line=line):
                self.assertEqual(wrapper.classify(line), "unknown")

    def test_oversized_line_is_capped_while_later_lines_drain(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b"x" * (53 * 1024) + b"\nmissing blob " + OID40.encode() + b"\n")
            stream.flush()
            stream.seek(0)
            counts, truncated = wrapper.classify_stream(stream.fileno())
        self.assertTrue(truncated)
        self.assertEqual(counts["unknown"], 1)
        self.assertEqual(counts["missing_object"], 1)

    def test_line_count_is_bounded(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b"notice: line\n" * (wrapper.MAX_LINES + 8))
            stream.flush()
            stream.seek(0)
            counts, truncated = wrapper.classify_stream(stream.fileno())
        self.assertTrue(truncated)
        self.assertEqual(counts["notice"], wrapper.MAX_LINES)


FAKE_GIT = """#!/usr/bin/env python3
import os, sys
sentinel = os.environ["S4_TEST_SENTINEL"].encode()
os.write(2, b"missing blob " + b"a" * 40 + b"\\n")
os.write(2, b"broken link from  tree " + b"b" * 40 + b" to commit " + b"c" * 40 + b"\\n")
os.write(2, b"dangling commit " + b"d" * 40 + b"\\n")
os.write(2, b"error in commit " + b"e" * 40 + b": invalid author line\\n")
os.write(2, b"fatal: " + sentinel + b"\\n")
os.write(2, b"malformed " + sentinel + b" " + b"f" * 40 + b"\\n")
sys.exit(17)
"""


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.fake = self.base / "fake-git"
        self.fake.write_text(FAKE_GIT, encoding="utf-8")
        self.fake.chmod(0o700)
        self.path = self.base / "diagnostic.jsonl"
        self.sentinel = "opaque-sentinel-7f4a"
        self.repo = str(self.base / ("repo-" + self.sentinel))

    def tearDown(self):
        self.temp.cleanup()

    def test_only_bounded_categories_and_status_are_written(self):
        stderr = io.StringIO()
        with mock.patch.object(wrapper, "GIT", str(self.fake)):
            with mock.patch.dict(os.environ, {"S4_TEST_SENTINEL": self.sentinel}):
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(wrapper.run_target(target(repo=self.repo), str(self.path)), 17)
        self.assertEqual(stderr.getvalue(), "")
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["schema"], wrapper.SCHEMA)
        self.assertEqual(record["exit_code"], 17)
        self.assertIsNone(record["signal"])
        self.assertFalse(record["truncated"])
        self.assertEqual(record["categories"], {
            "missing_object": 1, "broken_link": 1, "dangling": 1,
            "invalid_object": 1, "fatal": 1, "unknown": 1,
        })
        for forbidden in (self.sentinel, self.repo, OID40, "missing blob", "invalid author", "fatal: "):
            self.assertNotIn(forbidden, lines[0])
        self.assertLessEqual(len(lines[0]), 1024)

    def test_symlink_final_component_is_not_followed(self):
        victim = self.base / "victim"
        victim.write_text("unchanged", encoding="utf-8")
        link = self.base / "link"
        link.symlink_to(victim)
        wrapper.append_record(str(link), {"schema": wrapper.SCHEMA})
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")

    def test_file_cap_rejects_another_record(self):
        self.path.write_text("x" * 60, encoding="utf-8")
        with mock.patch.object(wrapper, "MAX_FILE_BYTES", 61):
            wrapper.append_record(str(self.path), {"schema": wrapper.SCHEMA})
        self.assertEqual(self.path.read_text(encoding="utf-8"), "x" * 60)

    def test_concurrent_appends_stay_within_the_file_cap(self):
        self.path.write_text("", encoding="utf-8")
        record = {"schema": wrapper.SCHEMA, "categories": dict.fromkeys(wrapper.CATEGORIES, 65535)}
        record_size = len(json.dumps(record, sort_keys=True, separators=(",", ":"))) + 1
        with mock.patch.object(wrapper, "MAX_FILE_BYTES", record_size):
            with ThreadPoolExecutor(max_workers=8) as workers:
                list(workers.map(lambda _: wrapper.append_record(str(self.path), record), range(24)))
        data = self.path.read_text(encoding="utf-8")
        self.assertEqual(len(data), record_size)
        for line in data.splitlines():
            self.assertEqual(json.loads(line)["schema"], wrapper.SCHEMA)

    def test_signal_and_exit_propagation_are_finite(self):
        with mock.patch.object(wrapper.signal, "signal") as install, \
                mock.patch.object(wrapper.os, "kill") as kill, \
                mock.patch.object(wrapper.os, "getpid", return_value=4242):
            self.assertEqual(wrapper.finish(-9), 137)
            install.assert_called_once_with(9, wrapper.signal.SIG_DFL)
            kill.assert_called_once_with(4242, 9)
        self.assertEqual(wrapper.finish(17), 17)
        self.assertEqual(wrapper.finish(0), 0)
        self.assertEqual(wrapper.finish(None), 1)
        self.assertEqual(wrapper.finish(300), 1)

    def test_sigkill_reset_failure_still_attempts_resignal(self):
        with mock.patch.object(wrapper.signal, "signal", side_effect=ValueError("uncatchable")), \
                mock.patch.object(wrapper.os, "kill") as kill, \
                mock.patch.object(wrapper.os, "getpid", return_value=4242):
            self.assertEqual(wrapper.finish(-signal.SIGKILL), 128 + signal.SIGKILL)
            kill.assert_called_once_with(4242, signal.SIGKILL)


SIGNAL_GIT = """#!/usr/bin/env python3
import os, signal
with open(os.environ["S4_MARKER"], "a", encoding="ascii") as out:
    out.write("x")
os.kill(os.getpid(), getattr(signal, os.environ.get("S4_SIGNAL", "SIGTERM")))
"""


class StockGitTests(unittest.TestCase):
    def run_driver(self, fake_git, args, env, timeout=20):
        code = (
            "import importlib.util,sys;"
            "s=importlib.util.spec_from_file_location('w',sys.argv[1]);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "m.GIT=sys.argv[2];sys.exit(m.main(sys.argv[3:]))"
        )
        return subprocess.run(
            [sys.executable, "-c", code, str(WRAPPER), str(fake_git), *args],
            env=env, capture_output=True, timeout=timeout,
        )

    def assert_signal_preserved(self, name):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake = base / "signal-git"
            fake.write_text(SIGNAL_GIT, encoding="utf-8")
            fake.chmod(0o700)
            marker = base / "marker"
            artifact = base / "artifact.jsonl"
            expected = getattr(signal, name)
            env = dict(os.environ, S4_MARKER=str(marker), S4_SIGNAL=name,
                       **{wrapper.ENV: str(artifact)})
            result = self.run_driver(fake, target(repo=str(base)), env)
            self.assertEqual(result.returncode, -expected)
            self.assertEqual(marker.read_text(encoding="ascii"), "x")
            record = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertIsNone(record["exit_code"])
            self.assertEqual(record["signal"], expected)

    def test_signal_status_and_single_invocation_are_preserved(self):
        self.assert_signal_preserved("SIGTERM")

    def test_sigkill_status_and_single_invocation_are_preserved(self):
        self.assert_signal_preserved("SIGKILL")

    def test_fifo_evidence_path_does_not_block(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake = base / "failed-git"
            fake.write_text("#!/usr/bin/env python3\nimport os,sys\n"
                            "open(os.environ['S4_MARKER'],'a').write('x')\nsys.exit(7)\n",
                            encoding="utf-8")
            fake.chmod(0o700)
            marker = base / "marker"
            fifo = base / "diagnostic.fifo"
            os.mkfifo(fifo, 0o600)
            self.assertTrue(stat.S_ISFIFO(os.stat(fifo).st_mode))
            env = dict(os.environ, S4_MARKER=str(marker), **{wrapper.ENV: str(fifo)})
            result = self.run_driver(fake, target(repo=str(base)), env, timeout=8)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(marker.read_text(encoding="ascii"), "x")

    def test_diagnostic_write_failure_still_forwards_exit_once(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake = base / "failed-git"
            fake.write_text(
                "#!/usr/bin/env python3\nimport os,sys\n"
                "open(os.environ['S4_MARKER'],'a').write('x')\nsys.exit(7)\n",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            marker = base / "marker"
            victim = base / "victim"
            victim.write_text("unchanged", encoding="utf-8")
            link = base / "artifact-link"
            link.symlink_to(victim)
            env = dict(os.environ, S4_MARKER=str(marker), **{wrapper.ENV: str(link)})
            result = self.run_driver(fake, target(repo=str(base)), env)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(marker.read_text(encoding="ascii"), "x")
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")

    @unittest.skipUnless(os.access(wrapper.GIT, os.X_OK), "stock Git is unavailable")
    def test_stock_git_passthrough_and_benign_target(self):
        version = subprocess.run([sys.executable, str(WRAPPER), "--version"], capture_output=True, timeout=20)
        self.assertEqual(version.returncode, 0)
        self.assertTrue(version.stdout.startswith(b"git version "))
        self.assertEqual(version.stderr, b"")

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "repo"
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                       GIT_AUTHOR_NAME="S4 Fixture", GIT_AUTHOR_EMAIL="s4@rootyard.invalid",
                       GIT_COMMITTER_NAME="S4 Fixture", GIT_COMMITTER_EMAIL="s4@rootyard.invalid")
            subprocess.run([wrapper.GIT, "init", "--quiet", str(repo)], check=True, env=env, timeout=20)
            (repo / "a.txt").write_text("fixture\n", encoding="utf-8")
            subprocess.run([wrapper.GIT, "-C", str(repo), "add", "a.txt"], check=True, env=env, timeout=20)
            subprocess.run([wrapper.GIT, "-C", str(repo), "commit", "--quiet", "-m", "fixture"],
                           check=True, env=env, timeout=20)
            oid = subprocess.run([wrapper.GIT, "-C", str(repo), "rev-parse", "HEAD"], check=True,
                                 capture_output=True, env=env, timeout=20).stdout.decode().strip()
            artifact = base / "artifact.jsonl"
            run_env = dict(env, **{wrapper.ENV: str(artifact)})
            result = subprocess.run([sys.executable, str(WRAPPER), *target(repo=str(repo), oid=oid)],
                                    cwd=base, env=run_env, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"")
            record = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(record["exit_code"], 0)
            self.assertIsNone(record["signal"])
            self.assertFalse(record["truncated"])

            wrapper_status = subprocess.run([sys.executable, str(WRAPPER), "not-a-command"],
                                            capture_output=True, timeout=20)
            stock_status = subprocess.run([wrapper.GIT, "not-a-command"], capture_output=True, timeout=20)
            self.assertEqual(wrapper_status.returncode, stock_status.returncode)


if __name__ == "__main__":
    unittest.main()
