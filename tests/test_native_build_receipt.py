"""Contract tests for scripts/build_native.py.

These tests never invoke Cargo. They exercise the build transaction against a
temporary workspace/target directory and fake Cargo JSON event streams, then
prove the receipt is bound to the rebuilt artifact, invalidated on every
failure path, and installed atomically under the target-directory flock.
"""
import fcntl
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import build_native  # noqa: E402


class FakeProcess:
    """Minimal Popen stand-in: iterable stdout, wait(), kill()."""

    def __init__(self, lines, returncode=0):
        self.stdout = io.StringIO(''.join(lines))
        self.returncode = returncode
        self.killed = False

    def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def _artifact(kind, fresh=False, executable=None, package_id='rootyard 0.1.0'):
    event = {
        'reason': 'compiler-artifact',
        'package_id': package_id,
        'target': {'name': 'rootyard', 'kind': [kind]},
        'fresh': fresh,
    }
    if executable is not None:
        event['executable'] = executable
    return event


def _hold_lock(target, held, release, queue):
    with build_native.build_lock(target):
        queue.put(('held', time.monotonic()))
        held.set()
        release.wait(20)


def _acquire_lock(target, acquired, queue):
    with build_native.build_lock(target):
        queue.put(('acquired', time.monotonic()))
        acquired.set()


class BuildReceiptTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp(prefix='rootyard-build-receipt-'))
        self.addCleanup(self._rmtree, self.tempdir)
        self.root = self.tempdir.resolve()
        (self.root / 'src').mkdir()
        (self.root / 'Cargo.toml').write_text('[package]\nname = "rootyard"\n')
        (self.root / 'Cargo.lock').write_text('version = 3\n')
        (self.root / 'src' / 'main.rs').write_text('fn main() {}\n')
        # Relative CARGO_TARGET_DIR exercises canonical_target() resolution.
        self.environment = mock.patch.dict(
            os.environ, {'CARGO_TARGET_DIR': 'target'}, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        patchers = [
            mock.patch.object(build_native, 'ROOT', self.root),
            mock.patch.object(build_native.subprocess, 'run', self.fake_run),
            mock.patch.object(build_native.subprocess, 'check_output',
                              self.fake_check_output),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.target = (self.root / 'target').resolve()
        self.binary = self.target / 'debug' / 'rootyard'
        self.receipt = self.binary.with_suffix('.build.json')
        self.temporary = self.receipt.with_suffix('.tmp')
        self.clean_calls = []
        self.popen_calls = []
        self.lock_violations = []
        self.popen = None

    @staticmethod
    def _rmtree(path):
        import shutil
        shutil.rmtree(path, ignore_errors=True)

    # -- fake subprocess surface -------------------------------------------
    def fake_run(self, command, **kwargs):
        self.clean_calls.append((list(command), kwargs))
        return mock.Mock(returncode=0, args=command)

    def fake_check_output(self, command, **kwargs):
        if command[0] == 'git' and command[1:3] == ['rev-parse', 'HEAD']:
            return 'deadbeefcafe\n'
        if command[0] == 'rustc' and command[1:] == ['--version']:
            return 'rustc 1.80.0 (fake)\n'
        raise AssertionError(f'unexpected check_output: {command}')

    def make_popen(self, events, returncode=0, binary_content=b'native-binary',
                   write_binary=True, mutate_source=False):
        def popen(command, **kwargs):
            self.popen_calls.append((list(command), kwargs))
            lock_path = self.target / build_native.LOCK_NAME
            if lock_path.exists():
                fd = os.open(lock_path, os.O_RDWR)
                try:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pass
                    else:
                        self.lock_violations.append('build ran without the target flock')
                        fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
            else:
                self.lock_violations.append('lock file absent during cargo build')
            self.binary.parent.mkdir(parents=True, exist_ok=True)
            if write_binary:
                self.binary.write_bytes(binary_content)
            if mutate_source:
                (self.root / 'src' / 'main.rs').write_text('fn main() { /* changed */ }\n')
            lines = [json.dumps(event) + '\n' for event in events]
            return FakeProcess(lines, returncode=returncode)
        return popen

    @staticmethod
    def args(features=None, bins=False):
        return mock.Mock(features=features, bins=bins)

    def events(self, fresh=False, executable=None, kinds=('lib', 'bin')):
        executable = str(self.binary) if executable is None else executable
        result = []
        for kind in kinds:
            if kind == 'lib':
                result.append(_artifact('lib', fresh=fresh))
            else:
                result.append(_artifact('bin', fresh=fresh, executable=executable))
        return result

    def build(self, events, **popen_kwargs):
        self.popen = self.make_popen(events, **popen_kwargs)
        with mock.patch.object(build_native.subprocess, 'Popen', self.popen):
            return build_native.run_build(self.args())

    def assert_no_receipt(self):
        self.assertFalse(self.receipt.exists(), 'a receipt survived a failed build')
        self.assertFalse(self.temporary.exists(), 'a temporary receipt was left behind')

    def seed_stale_receipt(self):
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        self.receipt.write_text('{"stale": true}\n')

    # -- happy path ---------------------------------------------------------
    def test_clean_build_fresh_false_lib_and_exact_bin_installs_receipt(self):
        report = self.build(self.events())

        self.assertEqual([call[0] for call in self.clean_calls],
                         [['cargo', 'clean', '--package', 'rootyard']])
        self.assertEqual(self.lock_violations, [])
        self.assertEqual(len(self.popen_calls), 1)
        command, kwargs = self.popen_calls[0]
        self.assertEqual(command[:2], ['cargo', 'build'])
        self.assertIn('--locked', command)
        self.assertIn('--bin', command)
        self.assertIn('rootyard', command)
        self.assertIn('--message-format=json-render-diagnostics', command)
        self.assertEqual(kwargs['cwd'], self.root)

        self.assertTrue(self.receipt.is_file())
        self.assertFalse(self.temporary.exists(), 'temporary receipt was not replaced atomically')
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual(receipt, report)
        self.assertEqual(receipt['version'], 1)
        self.assertEqual(receipt['target_dir'], str(self.target))
        self.assertEqual(receipt['lock_file'], str(self.target / build_native.LOCK_NAME))
        self.assertEqual(receipt['clean_command'],
                         ['cargo', 'clean', '--package', 'rootyard'])
        self.assertEqual(receipt['command'], command)
        self.assertIs(receipt['package_rebuilt'], True)
        self.assertIs(receipt['fresh_false_artifacts'][0]['fresh'], False)
        self.assertEqual([item['kind'] for item in receipt['fresh_false_artifacts']],
                         ['lib', 'bin'])
        self.assertEqual(receipt['fresh_false_artifacts'][1]['executable'],
                         str(self.binary.resolve()))
        self.assertEqual(receipt['workspace_commit'], 'deadbeefcafe')
        self.assertEqual(receipt['rustc'], 'rustc 1.80.0 (fake)')
        self.assertEqual(receipt['binary_sha256'],
                         hashlib.sha256(b'native-binary').hexdigest())

    def test_source_digest_is_unchanged_and_bound_to_the_receipt(self):
        before = build_native.source_digest()
        report = self.build(self.events())
        # Nothing touched the sources: pre-build, recorded and post-build digests agree.
        self.assertEqual(report['source_inputs_sha256'], before)
        self.assertEqual(build_native.source_digest(), before)
        self.assertEqual(build_native.source_digest(), report['source_inputs_sha256'])

    def test_receipt_installed_atomically_over_previous_receipt(self):
        self.seed_stale_receipt()
        self.build(self.events())
        self.assertFalse(self.temporary.exists())
        receipt = json.loads(self.receipt.read_text())
        self.assertNotEqual(receipt, {'stale': True})
        self.assertEqual(receipt['binary_sha256'],
                         hashlib.sha256(b'native-binary').hexdigest())

    # -- failure paths: no new receipt, previous receipt invalidated --------
    def test_fresh_true_artifacts_are_rejected(self):
        self.assert_failure(self.events(fresh=True),
                            'Cargo reported a Fresh rootyard artifact')

    def test_missing_lib_artifact_is_rejected(self):
        self.assert_failure(self.events(kinds=('bin',)),
                            'did not report a rootyard lib')

    def test_missing_bin_artifact_is_rejected(self):
        self.assert_failure(self.events(kinds=('lib',)),
                            'did not report the rootyard binary')

    def test_binary_without_executable_path_is_rejected(self):
        events = [_artifact('lib'), _artifact('bin')]
        self.assert_failure(events, 'has no executable path')

    def test_wrong_binary_executable_is_rejected(self):
        events = self.events(executable=str(self.root / 'elsewhere' / 'rootyard'))
        self.assert_failure(events, 'does not match')

    def test_source_change_during_build_is_rejected(self):
        self.assert_failure(self.events(), 'Source inputs changed during build',
                            mutate_source=True)

    def test_cargo_error_is_rejected(self):
        self.assert_failure(self.events(), 'cargo build failed with status 7',
                            returncode=7)

    def test_non_json_stdout_is_rejected(self):
        def popen(command, **kwargs):
            self.binary.parent.mkdir(parents=True, exist_ok=True)
            self.binary.write_bytes(b'native-binary')
            return FakeProcess(['not json\n'], returncode=0)
        self.seed_stale_receipt()
        with mock.patch.object(build_native.subprocess, 'Popen', popen):
            with self.assertRaises(build_native.BuildError) as caught:
                build_native.run_build(self.args())
        self.assertIn('non-JSON', str(caught.exception))
        self.assert_no_receipt()

    def assert_failure(self, events, message, **popen_kwargs):
        self.seed_stale_receipt()
        with self.assertRaises(build_native.BuildError) as caught:
            self.build(events, **popen_kwargs)
        self.assertIn(message, str(caught.exception))
        self.assert_no_receipt()

    # -- real two-process flock contention on the canonical target ---------
    def test_two_processes_contend_on_canonical_target_lock(self):
        context = multiprocessing.get_context('fork')
        self.target.mkdir(parents=True, exist_ok=True)
        alias = self.tempdir / 'target-alias'
        if not alias.exists():
            alias.symlink_to(self.target, target_is_directory=True)
        held = context.Event()
        release = context.Event()
        acquired = context.Event()
        queue = context.Queue()
        holder = context.Process(target=_hold_lock,
                                 args=(str(alias), held, release, queue))
        contender = context.Process(target=_acquire_lock,
                                    args=(str(self.target), acquired, queue))
        self.addCleanup(self._terminate, holder, contender, release)
        holder.start()
        try:
            self.assertTrue(held.wait(15), 'holder never acquired the build lock')
            contender.start()
            # Blocking flock in the second process must not enter while held.
            self.assertFalse(acquired.wait(0.75),
                             'contender entered the lock while the holder had it')
        finally:
            release.set()
        self.assertTrue(acquired.wait(15), 'contender did not enter after release')
        holder.join(15)
        contender.join(15)
        self.assertEqual(holder.exitcode, 0)
        self.assertEqual(contender.exitcode, 0)

        # Both children put exactly one timestamp before exiting.
        entries = [queue.get(timeout=5), queue.get(timeout=5)]
        stamps = dict(entries)
        self.assertIn('held', stamps)
        self.assertIn('acquired', stamps)
        self.assertGreater(stamps['acquired'], stamps['held'])

        # The released lock is available again to this process.
        lock_path = self.target / build_native.LOCK_NAME
        fd = os.open(lock_path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @staticmethod
    def _terminate(*processes):
        release = processes[-1]
        for process in processes[:-1]:
            if process.is_alive():
                process.terminate()
            process.join(5)
        release.set()


if __name__ == '__main__':
    unittest.main()
