"""Contract tests for scripts/build_native_batch.py.

These tests never invoke Cargo. They run the real batch transaction against a
temporary workspace and a fake Cargo JSON event stream, then prove:

* one canonical-target flock, exactly one ``cargo clean --package rootyard`` and
  exactly one ``cargo build --locked --profile test`` select every bin and test
  with one shared feature/profile/target selection;
* every recorded artifact is Fresh=false, the selected test is reported as a
  ``test`` profile artifact copied (not moved, not mirrored) outside the target
  directory, and binary receipts keep the rootyard lib + exact bin binding;
* receipts and the batch manifest are published only after all requirements
  hold, are withdrawn on every failure path, and use the standalone field sets;
* source changes, stale (Fresh=true) artifacts, duplicate, missing, extra or
  wrong-profile artifacts, bad selection, collisions and passthrough profile
  environment fail closed.

The assertions check properties of the produced receipts; they do not restate
the implementation. The fake event stream uses the same
``compiler-artifact`` / ``build-finished`` records Cargo writes.
"""
import argparse
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import build_native  # noqa: E402
import build_native_batch as batch  # noqa: E402

CARGO_TOML = """\
[package]
name = "rootyard"
version = "0.1.0"
edition = "2024"
rust-version = "1.88"

[features]
default = ["kafka-wake"]
kafka-wake = ["dep:rdkafka"]
pando-lab = []
state-redis = ["dep:redis"]

[[bin]]
name = "rootyard-pando-lab"
path = "src/bin/rootyard-pando-lab.rs"
required-features = ["pando-lab"]

[[bin]]
name = "rootyard-vfs-mount"
path = "src/bin/rootyard-vfs-mount.rs"

[dependencies]
anyhow = "1"
rdkafka = { version = "0.39", optional = true }
redis = { version = "=0.32.7", optional = true }

[dev-dependencies]
tempfile = "3"
"""

PACKAGE_ID = 'path+file:///ws#rootyard@0.1.0'
BINS = ('rootyard', 'rootyard-vfs-mount', 'rootyard-pando-lab')
TESTS = ('ref_store_snapshot_backup_fixture', 'ref_store_holds_backup_fixture')
COMMON_STRIP = ['--config', 'profile.dev.package.rootyard.strip="debuginfo"',
                '--config', 'profile.test.package.rootyard.strip="debuginfo"']


class FakeProcess:
    def __init__(self, lines, returncode=0, after=None):
        self.stdout = _Lines(lines, after)
        self.returncode = returncode

    def wait(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


class _Lines:
    """The fake Cargo's stdout.

    Real Cargo has finished writing artifacts when its output is closed, so
    ``after`` (a source mutation or a dropped binary) runs on ``close()``,
    after the last complete line was consumed. Incomplete streams (":ok:")
    stop early and leave the event logic to fail on its own.
    """

    def __init__(self, lines, after):
        self.lines = list(lines)
        self.after = after
        self.closed = False

    def __iter__(self):
        for line in self.lines:
            if line == ':ok:':
                return
            yield line

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.after is not None:
            after, self.after = self.after, None
            after()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


def artifact(kind, name, package=PACKAGE_ID, fresh=False, executable=None, test_profile=None):
    return {'reason': 'compiler-artifact', 'package_id': package,
            'target': {'name': name, 'kind': [kind]},
            'profile': {'opt_level': '0', 'debuginfo': 2, 'debug_assertions': True,
                        'overflow_checks': True,
                        'test': kind == 'test' if test_profile is None else test_profile},
            'fresh': fresh,
            **({'executable': executable} if executable is not None else {})}


def finished(success=True):
    return {'reason': 'build-finished', 'success': success}


class BatchTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp(prefix='rootyard-build-batch-'))
        self.addCleanup(shutil.rmtree, self.tempdir, True)
        self.root = Path(os.path.join(self.tempdir, 'ws')).resolve()
        (self.root / 'src' / 'bin').mkdir(parents=True)
        (self.root / 'tests').mkdir()
        (self.root / 'Cargo.toml').write_text(CARGO_TOML)
        (self.root / 'Cargo.lock').write_text('version = 3\n')
        (self.root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.99.1"\n')
        (self.root / 'src' / 'lib.rs').write_text('pub fn hello() {}\n')
        (self.root / 'src' / 'main.rs').write_text('fn main() {}\n')
        for name in ('rootyard-pando-lab', 'rootyard-vfs-mount'):
            (self.root / 'src' / 'bin' / (name + '.rs')).write_text('fn main() {}\n')
        for name in TESTS:
            (self.root / 'tests' / (name + '.rs')).write_text('#[test]\nfn one() {}\n')
        self.outdir = Path(os.path.join(self.tempdir, 'test-results'))
        self.target = Path(os.path.join(self.root, 'target')).resolve()
        self.lock_path = self.target / build_native.LOCK_NAME
        self.popen_calls = []
        self.probe_calls = []
        self.metadata_calls = []
        self.metadata_directory = None
        self.clean_commands = []

        self.addCleanup(mock.patch.stopall)
        mock.patch.dict(os.environ, {'CARGO_TARGET_DIR': 'target'}).start()
        for name in batch.PASSTHROUGH_VARIABLES:
            os.environ.pop(name, None)
        mock.patch.object(build_native, 'ROOT', self.root).start()
        mock.patch.object(batch, 'rustc_version', lambda: 'rustc 1.99.1 (fake)').start()
        mock.patch.object(batch, 'target_triple', lambda: 'x86_64-unknown-linux-gnu').start()
        mock.patch.object(batch, 'git_state', lambda: {'head': 'deadbeef', 'commit': 'c0ffee',
                                                       'tree': 'tree0', 'status': ''}).start()
        mock.patch.object(batch, 'source_digest', self.digest).start()
        mock.patch.object(batch, 'run_tool', self.fake_probe).start()
        # cargo_metadata itself stays real; only the cargo process it starts is
        # replaced, by a document a real ``cargo metadata`` would print.
        self.addCleanup(setattr, batch.subprocess, 'check_output', batch.subprocess.check_output)
        batch.subprocess.check_output = self.fake_cargo_metadata
        mock.patch.object(batch.subprocess, 'run', self.fake_clean).start()

    # -- fake build environment --------------------------------------------
    def digest(self):
        import hashlib
        hasher = hashlib.sha256()
        for path in sorted((self.root / 'src').rglob('*')):
            if path.is_file():
                hasher.update(path.read_bytes())
        return hasher.hexdigest()

    def fake_clean(self, command, **kwargs):
        self.clean_commands.append((list(command), kwargs))
        return mock.Mock(returncode=0)

    def metadata_json(self, target_directory=None):
        """What a real ``cargo metadata --no-deps --format-version 1`` prints in this workspace.

        It always carries ``target_directory``: Cargo derives it from
        ``CARGO_TARGET_DIR``/``[build].target-dir`` and never from the batch's
        ``--config``, so omitting it would be a document Cargo cannot print.
        """
        return json.dumps({
            'packages': [{'name': 'rootyard', 'version': '0.1.0', 'id': PACKAGE_ID,
                          'manifest_path': str(self.root / 'Cargo.toml')}],
            'workspace_members': [PACKAGE_ID],
            'workspace_default_members': [PACKAGE_ID],
            'resolve': None,
            'target_directory': str(target_directory or self.target),
            'workspace_root': str(self.root),
            'version': 1,
            'metadata': None,
        })

    def fake_cargo_metadata(self, command, *args, **kwargs):
        """The cargo process: it only ever answers the ``cargo metadata`` probe.

        Returns the raw text a process's ``check_output`` would, so the test
        does not also fake the decoding of what the real cargo_metadata reads.
        """
        self.metadata_calls.append(list(command))
        if command != ['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1', '--offline']:
            raise AssertionError('unexpected check_output tool: ' + repr(command))
        return self.metadata_json(self.metadata_directory)

    def fake_probe(self, command, **kwargs):
        self.probe_calls.append(list(command))
        if command[:2] == ['rustup', 'show']:
            return mock.Mock(returncode=0, stdout='1.99.1-x86_64-unknown-linux-gnu (overridden by rust-toolchain.toml)\n')
        if command == ['cargo', '--version']:
            return mock.Mock(returncode=0, stdout='cargo 1.99.1 (fake)\n')
        raise AssertionError('unexpected tool probe: ' + repr(command))

    def clean_calls(self):
        return [command for command, _ in self.clean_commands]

    def compiled_test(self, name):
        return str(os.path.join(self.target, 'debug', 'deps', name + '-0123456789abcdef'))

    def binary(self, name):
        return str(os.path.join(self.target, 'debug', name))

    def default_events(self, bins=None, tests=None, fresh=False, lib=True):
        bins = BINS if bins is None else bins
        tests = TESTS if tests is None else tests
        events = [artifact('lib', 'rootyard', fresh=fresh)] if lib else []
        events += [artifact('bin', name, fresh=fresh, executable=self.binary(name)) for name in bins]
        events += [artifact('test', name, fresh=fresh, executable=self.compiled_test(name)) for name in tests]
        return events + [finished()]

    def write_executables(self, events):
        for event in events:
            if event.get('executable'):
                Path(event['executable']).parent.mkdir(parents=True, exist_ok=True)
                Path(event['executable']).write_bytes(b'#!bin\n' + event['target']['name'].encode())

    def fake_popen(self, events, returncode=0, mutate=None):
        self.write_executables(events)
        return lambda command, **kwargs: self.launch(list(command), kwargs, events, returncode, mutate)

    def launch(self, command, kwargs, events, returncode, mutate):
        self.popen_calls.append((list(command), kwargs))
        if not self.clean_commands:
            raise AssertionError('cargo build ran before the single cargo clean')
        self.assert_cargo_holds_lock()
        return FakeProcess([json.dumps(event) + '\n' for event in events], returncode=returncode,
                           after=mutate)

    def assert_cargo_holds_lock(self):
        fd = os.open(self.lock_path, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError, msg='cargo ran outside the canonical flock'):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def args(self, bins=BINS, tests=TESTS, features='pando-lab', no_default_features=False,
             package_debug=None, strip_debuginfo=True, outputs=None, all_bins=False, manifest_out=None):
        outputs = outputs if outputs is not None else [
            str(os.path.join(self.outdir, name.replace('_', '-'))) for name in tests]
        return argparse.Namespace(features=features, no_default_features=no_default_features,
                                  package_debug=package_debug, strip_debuginfo=strip_debuginfo,
                                  all_bins=all_bins, bin=list(bins), bin_destination=[], test=list(tests),
                                  output=outputs, manifest_out=str(manifest_out or
                                                                   self.outdir / 'native-build-batch.json'))

    def expected_command(self, args):
        command = ['cargo', 'build', '--locked', '--profile', 'test']
        if args.package_debug is not None:
            command += ['--config', 'profile.dev.package.rootyard.debug=' + args.package_debug,
                        '--config', 'profile.test.package.rootyard.debug=' + args.package_debug]
        if args.strip_debuginfo:
            command += COMMON_STRIP
        command += ['--config', 'build.target-dir = "' + str(self.target) + '"']
        for name in args.bin:
            command += ['--bin', name]
        for name in args.test:
            command += ['--test', name]
        if args.features:
            command += ['--features', args.features]
        if args.no_default_features:
            command += ['--no-default-features']
        return command + ['--message-format=json-render-diagnostics']

    def build(self, events=None, args=None, **kwargs):
        args = args or self.args()
        events = self.default_events(bins=args.bin, tests=args.test) if events is None else events
        with mock.patch.object(batch.subprocess, 'Popen', self.fake_popen(events, **kwargs)):
            return batch.run_batch(args)

    # -- shared assertions --------------------------------------------------
    def seed_previous_batch(self, args=None):
        args = args or self.args()
        paths = [self.target / 'debug' / (name + '.build.json') for name in args.bin]
        paths += [Path(output + '.build.json') for output in args.output]
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"stale": true}\n')
        for output in args.output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_bytes(b'stale')
        Path(args.manifest_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.manifest_out).write_text('{"stale": true}\n')

    def assert_nothing_published(self, args=None):
        args = args or self.args()
        receipts = [self.target / 'debug' / (name + '.build.json') for name in args.bin]
        receipts += [Path(output + '.build.json') for output in args.output]
        leftovers = receipts + [Path(args.manifest_out)] + [Path(output) for output in args.output]
        leftovers += [path.with_name('.' + path.name + '.batch-new') for path in leftovers]
        self.assertEqual([str(path) for path in leftovers if path.exists()],
                         [], 'a failed batch must not leave receipts, outputs or staging files')

    # -- happy path ---------------------------------------------------------
    def test_one_clean_one_build_selects_all_bins_and_tests_under_one_lock(self):
        args = self.args()
        # The manifest and the in-memory copy must be the identical document.
        report = json.loads(json.dumps(self.build(args=args)))
        command = report['build']['command']

        self.assertEqual(self.clean_calls(), [['cargo', 'clean', '--package', 'rootyard']])
        self.assertEqual(len(self.popen_calls), 1)
        self.assertEqual(self.popen_calls[0][0], self.expected_command(args))
        self.assertEqual(self.popen_calls[0][1]['cwd'], self.root)
        self.assertEqual(report['clean']['command'], ['cargo', 'clean', '--package', 'rootyard'])
        self.assertEqual(report['clean']['commands'], 1)
        self.assertEqual(report['build'], {'command': command, 'commands': 1,
                                           'duration_seconds': report['build']['duration_seconds'],
                                           'fresh_false_artifacts': [
                                               {'target': 'rootyard', 'kind': 'lib', 'fresh': False,
                                                'package_id': PACKAGE_ID}] + [
                                               {'target': name, 'kind': 'bin', 'fresh': False,
                                                'executable': self.binary(name), 'package_id': PACKAGE_ID,
                                                'profile': {'opt_level': '0', 'debuginfo': 2,
                                                            'debug_assertions': True,
                                                            'overflow_checks': True, 'test': False}}
                                               for name in BINS]})
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['kind'], 'rootyard/native-build-batch')
        self.assertEqual(report['source_commit'], 'c0ffee')
        self.assertEqual(report['toolchain']['pinned_channel'], '1.99.1')
        self.assertEqual(report['features'], {'features': 'pando-lab', 'no_default_features': False,
                                              'profile': 'test', 'package_debug': None,
                                              'strip_debuginfo': True})
        self.assertEqual(report['architecture']['target_triple'], 'x86_64-unknown-linux-gnu')
        self.assertEqual(report['lock_file'], str(self.lock_path))
        self.assertEqual(json.loads(Path(args.manifest_out).read_text()), report)

    def test_receipts_use_the_standalone_field_sets_and_the_exact_shared_command(self):
        args = self.args()
        report = self.build(args=args)
        receipt = json.loads((self.target / 'debug' / 'rootyard.build.json').read_text())
        # native_report_manifest.REQUIRED_RECEIPT_FIELDS
        for field in ('binary_sha256', 'source_inputs_sha256', 'workspace_commit', 'rustc', 'command'):
            self.assertTrue(receipt[field], field)
        self.assertEqual(receipt['version'], 1)
        self.assertEqual(receipt['command'], report['build']['command'])
        self.assertEqual(receipt['clean_command'], ['cargo', 'clean', '--package', 'rootyard'])
        self.assertIs(receipt['package_rebuilt'], True)
        self.assertEqual([(item['kind'], item['target']) for item in receipt['fresh_false_artifacts']],
                         [('lib', 'rootyard')] + [('bin', name) for name in BINS])
        self.assertEqual(receipt['fresh_false_artifacts'][1]['executable'], self.binary('rootyard'))
        self.assertTrue(all(item['fresh'] is False for item in receipt['fresh_false_artifacts']))
        self.assertEqual(receipt['binary_sha256'], batch.sha256_file(self.binary('rootyard')))
        self.assertEqual(len(receipt['source_inputs_sha256']), 64)
        self.assertEqual(receipt['target_dir'], str(self.target))
        self.assertEqual(receipt['lock_file'], str(self.lock_path))
        self.assertEqual(receipt['toolchain']['pinned_channel'], '1.99.1')
        self.assertEqual(receipt['toolchain']['cargo'], 'cargo 1.99.1 (fake)')
        self.assertEqual(receipt['architecture']['target_triple'], 'x86_64-unknown-linux-gnu')
        self.assertEqual(receipt['duration_seconds'],
                         {'clean_seconds': report['clean']['duration_seconds'],
                          'build_seconds': report['build']['duration_seconds']})
        self.assertEqual(receipt['clean_commands'], 1)
        self.assertEqual(receipt['build_commands'], 1)

        for output, name in zip(args.output, args.test):
            test = json.loads(Path(output + '.build.json').read_text())
            self.assertEqual(test['kind'], 'rust-integration-test')
            self.assertIs(test['relocated_artifact'], True)
            self.assertIs(test['package_rebuilt'], True)
            self.assertIs(test['fresh'], False)
            self.assertEqual(test['command'], report['build']['command'])
            self.assertEqual(len(test['fresh_false_artifacts']), 1)
            entry = test['fresh_false_artifacts'][0]
            self.assertEqual((entry['target'], entry['kind'], entry['fresh']), (name, 'test', False))
            self.assertIs(entry['profile']['test'], True)
            self.assertTrue(Path(entry['executable']).name.startswith(name))
            self.assertEqual(test['integration_test_source_sha256'],
                             batch.sha256_file(self.root / 'tests' / (name + '.rs')))
            self.assertEqual(test['cargo_lock_sha256'], batch.sha256_file(self.root / 'Cargo.lock'))
            self.assertEqual(test['source_inputs_sha256'], receipt['source_inputs_sha256'])
            self.assertEqual(test['binary_sha256'], batch.sha256_file(output))
            self.assertEqual(test['original_artifact_sha256'], batch.sha256_file(entry['executable']))

    def test_test_executables_are_copied_outside_target_and_survive_a_clean(self):
        args = self.args()
        self.build(args=args)
        for output, name in zip(args.output, args.test):
            self.assertTrue(Path(output).is_file())
            self.assertEqual(Path(output).stat().st_mode & 0o777, 0o700)
            self.assertNotIn(self.target, Path(output).resolve().parents)
            compiled = Path(self.compiled_test(name))
            self.assertTrue(compiled.is_file(), 'the compiled test artifact must not be moved out of target')
            compiled.unlink()
            self.assertTrue(Path(output).is_file(), 'a later clean must not delete the relocated copy')

    def test_multiple_bins_share_one_command_and_one_receipt_each(self):
        two = ('rootyard', 'rootyard-vfs-mount')
        args = self.args(bins=two, package_debug='1')
        report = self.build(events=self.default_events(bins=two), args=args)
        command = self.popen_calls[0][0]
        self.assertEqual(command, self.expected_command(args))
        self.assertEqual(command.count('--features'), 1)
        self.assertEqual(command.count('--config'), 5)
        for name in args.bin:
            receipt = json.loads((self.target / 'debug' / (name + '.build.json')).read_text())
            self.assertEqual(receipt['command'], report['build']['command'])
            self.assertTrue(receipt['binary_sha256'])
            self.assertEqual([item['target'] for item in receipt['fresh_false_artifacts']],
                             ['rootyard', 'rootyard', 'rootyard-vfs-mount'])
            self.assertTrue(all(item['fresh'] is False for item in receipt['fresh_false_artifacts']))
            entries = receipt['fresh_false_artifacts']
            executables = [item.get('executable') for item in entries]
            self.assertIn(self.binary(name), executables)
        self.assertEqual([entry['kind'] for entry in report['artifacts']], ['bin', 'bin', 'test', 'test'])

    def test_previous_batch_receipts_are_replaced_atomically(self):
        args = self.args()
        self.seed_previous_batch(args)
        self.build(args=args)
        receipt = json.loads((self.target / 'debug' / 'rootyard.build.json').read_text())
        self.assertNotEqual(receipt, {'stale': True})
        self.assertEqual(receipt['binary_sha256'], batch.sha256_file(self.binary('rootyard')))
        for output, name in zip(args.output, args.test):
            self.assertEqual(Path(output).read_bytes(), Path(self.compiled_test(name)).read_bytes())

    # -- fail-closed paths --------------------------------------------------
    def assert_failure(self, events, message, args=None, **kwargs):
        args = args or self.args()
        self.seed_previous_batch(args)
        with mock.patch.object(batch.subprocess, 'Popen',
                               self.fake_popen(self.default_events(bins=args.bin, tests=args.test)
                                               if events is None else events, **kwargs)):
            with self.assertRaises(batch.BuildError) as caught:
                batch.run_batch(args)
        self.assertIn(message, str(caught.exception))
        self.assert_nothing_published(args)

    def test_fresh_true_artifacts_are_rejected(self):
        self.assert_failure(self.default_events(fresh=True), 'Fresh rootyard artifact')

    def test_fresh_true_lib_alone_is_rejected(self):
        events = [artifact('lib', 'rootyard', fresh=True)] + self.default_events()[1:]
        self.assert_failure(events, 'Fresh')

    def test_missing_lib_artifact_is_rejected(self):
        self.assert_failure(self.default_events(lib=False), 'did not report a rootyard lib')

    def test_missing_test_artifact_is_rejected(self):
        self.assert_failure(self.default_events(tests=TESTS[:1]), 'did not report the requested test artifacts')

    def test_missing_binary_artifact_is_rejected(self):
        events = [artifact('lib', 'rootyard')] + self.default_events(bins=())[1:]
        self.assert_failure(events, 'did not report the requested binaries')

    def test_duplicate_and_extra_artifacts_are_rejected(self):
        duplicate = self.default_events() + [artifact('test', TESTS[0],
                                                      executable=self.compiled_test(TESTS[0]))]
        self.assert_failure(duplicate, 'duplicate')
        extra = self.default_events() + self.default_events(tests=('some_other_test',))[-2:-1]
        self.assert_failure(extra, 'tests that were not selected')
        two_libs = self.default_events() + [artifact('lib', 'rootyard')]
        self.assert_failure(two_libs, 'two rootyard lib artifacts')

    def test_bin_without_executable_or_wrong_path_is_rejected(self):
        events = self.default_events()
        events[1] = artifact('bin', 'rootyard')
        self.assert_failure(events, 'has no executable path')
        events = self.default_events()
        events[1] = artifact('bin', 'rootyard', executable=str(self.root / 'elsewhere' / 'rootyard'))
        self.assert_failure(events, 'does not match')

    def test_artifact_of_another_package_is_rejected(self):
        events = self.default_events()[:-1] + [artifact('bin', 'sneaky', package='path+file:///x#other@0.1.0',
                                                        executable=self.binary('sneaky')), finished()]
        self.assert_failure(events, 'unexpected package')

    def test_test_with_a_dev_profile_is_rejected(self):
        events = self.default_events()[:-1]
        events[1 + len(BINS)] = artifact('test', TESTS[0], test_profile=False,
                                         executable=self.compiled_test(TESTS[0]))
        self.assert_failure(events + [finished()], 'test profile')

    def test_missing_test_executable_on_disk_is_rejected(self):
        vanished = self.compiled_test(TESTS[0])
        self.assert_failure(None, 'built test executable is missing',
                            mutate=lambda: Path(vanished).unlink())

    def test_build_finished_failure_or_absence_is_rejected(self):
        self.assert_failure(self.default_events()[:-1] + [finished(success=False)], 'build-finished')
        self.assert_failure(self.default_events()[:-1], 'build-finished')

    def test_cargo_failure_and_non_json_stdout_are_rejected(self):
        self.assert_failure(None, 'cargo build failed with status 7', returncode=7)
        with mock.patch.object(batch.subprocess, 'Popen', lambda *a, **k: FakeProcess(['not json\n'])):
            with self.assertRaises(batch.BuildError) as caught:
                batch.run_batch(self.args())
        self.assertIn('non-JSON', str(caught.exception))
        self.assert_nothing_published()

    def test_source_change_during_build_is_rejected(self):
        def mutate():
            (self.root / 'src' / 'lib.rs').write_text('pub fn hello() { /* changed */ }\n')
        self.assert_failure(None, 'Source inputs changed during build', mutate=mutate)

    def test_test_source_cargo_lock_and_git_changes_are_rejected(self):
        # Mutate the selected test source itself (TESTS names are file stems):
        # a new sibling tests/<stem>.rs would be a different, empty target and
        # change nothing this batch compiled.
        self.assert_failure(None, 'integration-test source', mutate=lambda: (
            self.root / 'tests' / (TESTS[1] + '.rs')).write_text('#[test]\nfn x() {}\n'))
        self.assert_failure(None, 'Cargo.lock changed',
                            mutate=lambda: (self.root / 'Cargo.lock').write_text('version = 4\n'))
        calls = []

        def dirty_after_first():
            calls.append(1)
            status = '' if len(calls) == 1 else ' M src/lib.rs\n'
            return {'head': 'deadbeef', 'commit': 'c0ffee', 'tree': 'tree0', 'status': status}
        with mock.patch.object(batch, 'git_state', dirty_after_first):
            self.assert_failure(None, 'HEAD or working-tree state changed')

    def test_cargo_metadata_target_directory_must_be_the_locked_one(self):
        events = self.default_events()
        self.write_executables(events)
        # A cargo binary that resolved its target directory outside the
        # canonical CARGO_TARGET_DIR: the real cargo_metadata must reject that
        # document before any clean or build is started.
        redirected = Path(os.path.join(self.root, 'other'))
        self.metadata_directory = redirected

        with mock.patch.object(batch.subprocess, 'Popen',
                               lambda command, **kwargs: self.launch(list(command), kwargs, events, 0, None)):
            with self.assertRaises(batch.BuildError) as caught:
                batch.run_batch(self.args())
        self.assertIn('would not be serialized by this lock', str(caught.exception))
        self.assertIn(str(redirected), str(caught.exception))
        self.assertEqual(self.metadata_calls,
                         [['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1', '--offline']])
        self.assertEqual(self.clean_calls(), [])
        self.assertEqual(self.popen_calls, [])

    def test_passthrough_profile_environment_is_rejected_before_any_cargo(self):
        with mock.patch.dict(os.environ, {'RUSTFLAGS': '-C target-cpu=native'}):
            with self.assertRaises(batch.BuildError) as caught:
                batch.run_batch(self.args())
        self.assertIn('RUSTFLAGS', str(caught.exception))
        self.assertEqual(self.clean_calls(), [])
        self.assertEqual(self.popen_calls, [])

    def test_toolchain_mismatch_is_rejected_before_clean_or_build(self):
        with mock.patch.object(batch, 'toolchain_channel', lambda: ('1.99.1', 'rust-toolchain.toml')), \
                mock.patch.object(batch, 'run_tool', lambda command: mock.Mock(
                    returncode=0, stdout='stable-x86_64-unknown-linux-gnu (default)\n')):
            with self.assertRaises(batch.BuildError) as caught:
                batch.run_batch(self.args())
        self.assertIn('not the pinned', str(caught.exception))
        self.assertEqual(self.clean_calls(), [])
        self.assertEqual(self.popen_calls, [])

    # -- selection validation (no Cargo at all) ----------------------------
    def planning_failure(self, args, message):
        with self.assertRaises(batch.BuildError) as caught:
            batch.run_batch(args)
        self.assertIn(message, str(caught.exception))
        self.assertEqual(self.clean_calls(), [])
        self.assertEqual(self.popen_calls, [])

    def test_conflicting_or_duplicate_selections_are_rejected(self):
        self.planning_failure(self.args(bins=('rootyard', 'rootyard')), 'repeats')
        self.planning_failure(self.args(tests=(TESTS[0], TESTS[0]),
                                        outputs=[str(self.outdir / 'a'), str(self.outdir / 'b')]), 'repeats')
        self.planning_failure(self.args(features='pando-lab,nope'), 'unknown features')
        self.planning_failure(self.args(features=None), 'requires features pando-lab')
        self.planning_failure(self.args(features='pando-lab --release'), 'comma-separated')
        empty = self.args(tests=(), outputs=[], bins=(), all_bins=False)
        self.planning_failure(empty, 'sel')
        cargo = CARGO_TOML.replace('[dependencies]', '''[[bin]]
name = "rootyard-view-lab"
path = "src/bin/rootyard-view-lab.rs"

[dependencies]''')
        manifest = batch.parse_cargo_toml(cargo)
        with self.assertRaises(batch.BuildError) as caught:
            batch.plan_batch(self.args(bins=('rootyard-view-lab',)), manifest)
        self.assertIn('not built here', str(caught.exception))
        self.planning_failure(self.args(bins=('no-such-bin',)), 'not a bin target')

    def test_outputs_must_be_outside_target_unique_and_one_per_test(self):
        inside = str(self.target / 'debug' / 'fixture')
        self.planning_failure(self.args(outputs=[inside, str(self.outdir / 'b')]), 'outside CARGO_TARGET_DIR')
        self.planning_failure(self.args(outputs=[str(self.outdir / 'a'), str(self.outdir / 'a')]), 'repeats')
        self.planning_failure(self.args(outputs=[str(self.outdir / 'a')]), 'once per --test')
        self.planning_failure(self.args(tests=(), outputs=[], bins=(), all_bins=False), 'select at least one')

    def test_missing_test_source_is_rejected(self):
        self.planning_failure(self.args(tests=('no_such_integration_test',),
                                        outputs=[str(self.outdir / 'x')]), 'integration-test source is missing')

    def test_all_bins_selects_every_bin_with_enabled_features(self):
        args = self.args(all_bins=True, bins=())
        report = self.build(args=args, events=self.default_events(bins=BINS))
        self.assertEqual([entry['target'] for entry in report['artifacts'] if entry['kind'] == 'bin'],
                         ['rootyard', 'rootyard-pando-lab', 'rootyard-vfs-mount'])
        self.assertEqual([self.popen_calls[0][0][index + 1] for index, token in
                          enumerate(self.popen_calls[0][0]) if token == '--bin'],
                         ['rootyard', 'rootyard-pando-lab', 'rootyard-vfs-mount'])

    # -- helpers ------------------------------------------------------------
    def test_manifest_parser_reads_features_bins_optional_dependencies(self):
        manifest = batch.parse_cargo_toml(CARGO_TOML + '\n[[test]]\nname = "declared"\npath = "tests/declared.rs"\n'
                                          'required-features = ["pando-lab"]\n')
        self.assertEqual(manifest['default_features'], ['kafka-wake'])
        self.assertEqual(manifest['features']['kafka-wake'], [])
        self.assertEqual(manifest['optional_features'], {})
        self.assertEqual([entry['name'] for entry in manifest['bins']],
                         ['rootyard', 'rootyard-pando-lab', 'rootyard-vfs-mount'])
        self.assertTrue(manifest['bins'][0]['implicit'])
        self.assertEqual(manifest['bins'][1]['required_features'], ['pando-lab'])
        self.assertEqual(manifest['tests'], [{'name': 'declared', 'path': 'tests/declared.rs',
                                              'required_features': ['pando-lab']}])

    def test_optional_dependency_without_explicit_feature_fails_closed(self):
        manifest = batch.parse_cargo_toml(CARGO_TOML.replace('kafka-wake = ["dep:rdkafka"]', 'kafka-wake = []'))
        self.assertEqual(manifest['optional_features'], {'rdkafka': 'rdkafka'})
        with self.assertRaises(batch.BuildError) as caught:
            batch.plan_batch(self.args(), manifest)
        self.assertIn('rdkafka', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
