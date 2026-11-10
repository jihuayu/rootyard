"""Contract tests for scripts/build_native_batch.py.

These tests never invoke Cargo. They run the real batch transaction against a
temporary workspace and a fake Cargo JSON event stream, then prove:

* one canonical-target flock, exactly one ``cargo clean --package rootyard`` and
  exactly one ``cargo build --locked --profile test`` select every bin and test
  with one shared feature/profile/target selection;
* every recorded artifact is Fresh=false, the selected test is reported as a
  ``test`` profile artifact copied (not moved, not mirrored) outside the target
  directory, and binary receipts keep the rootyard lib + exact bin binding;
* a relocated test whose destination is on another filesystem is staged and
  renamed inside that destination's directory and keeps the compiled
  artifact's bytes and hashes; a copy mismatch or a failing copy on that side
  publishes nothing and withdraws the bin receipts already staged in target/.
  The device boundary is emulated (its ``st_dev`` view and ``EXDEV`` for
  cross-device rename/hardlink, as a Docker named volume or foreign bind mount
  behaves); no test writes to a physical second device;
* receipts and the batch manifest are published only after all requirements
  hold, are withdrawn on every failure path, use the standalone field sets, and
  the manifest is renamed last as the commit marker after every receipt;
* source changes, stale (Fresh=true) artifacts, duplicate, missing, extra or
  wrong-profile artifacts, bad selection, collisions and passthrough profile
  environment fail closed;
* the bound build inputs (every ``tests/**/*.rs`` helper, the toolchain pin, the
  in-repo Cargo config and ``build.rs``) are frozen by path and bytes before and
  after the build and recorded in every receipt and the manifest: an edited,
  added or removed helper or config, a toolchain edit, a new config or an
  untracked helper *during* the build is refused with no receipt; and the same
  inputs give the same digest. A later, fresh run (new clean+build, empty
  target) is not a mutation: it compiles the new sources and records the new
  inventory and digest in every receipt and the manifest, while the selected
  entries and the production source digest are unchanged.

The assertions check properties of the produced receipts; they do not restate
the implementation. The fake event stream uses the same
``compiler-artifact`` / ``build-finished`` records Cargo writes.
"""
import argparse
import contextlib
import copy
import fcntl
import hashlib
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
#: ``[[bin]]`` targets of the fixture manifest: the --bin names most tests select.
BINS = ('rootyard', 'rootyard-pando-lab', 'rootyard-vfs-mount')
#: Bins Cargo auto-discovers from src/bin/*.rs: no [[bin]] table names them.
AUTO_BINS = ('rootyard-view-lab', 'rootyard-workspace-lab')
#: Every bin Cargo metadata lists for the package, in metadata order: the
#: auto-discovered src/bin labs sit between the [[bin]] tables' bins.
ALL_BINS = ('rootyard', 'rootyard-pando-lab') + AUTO_BINS + ('rootyard-vfs-mount',)
TESTS = ('ref_store_snapshot_backup_fixture', 'ref_store_holds_backup_fixture')
HELPER = 'tests/helper/mod.rs'
UNTRACKED_HELPER = 'tests/helper/untracked.rs'
CARGO_CONFIG = '.cargo/config.toml'
# A real in-repo config the batch hashes but never interprets or executes.
CARGO_CONFIG_TEXT = '[build]\njobs = 4\n[net]\nretry = 2\n'
COMMON_STRIP = ['--config', 'profile.dev.package.rootyard.strip="debuginfo"',
                '--config', 'profile.test.package.rootyard.strip="debuginfo"']


class _LaunchSteps:
    """One ``after`` callback per launch of a multi-run scenario."""

    def __init__(self, steps):
        self.steps, self.index = list(steps), 0

    def next(self):
        step = self.steps[self.index] if self.index < len(self.steps) else None
        self.index += 1
        return step, step


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
        for name in ('rootyard-pando-lab', 'rootyard-vfs-mount') + AUTO_BINS:
            (self.root / 'src' / 'bin' / (name + '.rs')).write_text('fn main() {}\n')
        for name in TESTS:
            (self.root / 'tests' / (name + '.rs')).write_text('#[test]\nfn one() {}\n')
        # A transitive helper no selected entry lists, an in-repo Cargo config
        # and a build script: none of them is in the production source digest.
        (self.root / 'tests' / 'helper').mkdir()
        (self.root / HELPER).write_text('pub fn helper() {}\n')
        (self.root / '.cargo').mkdir()
        (self.root / CARGO_CONFIG).write_text(CARGO_CONFIG_TEXT)
        (self.root / 'build.rs').write_text('fn main() {}\n')
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
        # The production digest is not stubbed (the fixture is a few files):
        # it runs for real, so the source checks fire on their own path.
        mock.patch.object(batch, 'rustc_version', lambda: 'rustc 1.99.1 (fake)').start()
        mock.patch.object(batch, 'target_triple', lambda: 'x86_64-unknown-linux-gnu').start()
        mock.patch.object(batch, 'git_state', lambda: {'head': 'deadbeef', 'commit': 'c0ffee',
                                                       'tree': 'tree0', 'status': ''}).start()
        mock.patch.object(batch, 'run_tool', self.fake_probe).start()
        # cargo_metadata itself stays real; only the cargo process it starts is
        # replaced, by a document a real ``cargo metadata`` would print.
        self.addCleanup(setattr, batch.subprocess, 'check_output', batch.subprocess.check_output)
        batch.subprocess.check_output = self.fake_cargo_metadata
        mock.patch.object(batch.subprocess, 'run', self.fake_clean).start()

    # -- fake build environment --------------------------------------------
    def fake_clean(self, command, **kwargs):
        self.clean_commands.append((list(command), kwargs))
        return mock.Mock(returncode=0)

    def metadata_json(self, target_directory=None):
        """What a real ``cargo metadata --no-deps --format-version 1`` prints in this workspace.

        It always carries ``target_directory``: Cargo derives it from
        ``CARGO_TARGET_DIR``/``[build].target-dir`` and never from the batch's
        ``--config``, so omitting it would be a document Cargo cannot print.
        """
        targets = [self.metadata_target('lib', 'rootyard', 'src/lib.rs')]
        targets += [self.metadata_target('bin', name, self.bin_source(name),
                                         ['pando-lab'] if name == 'rootyard-pando-lab' else None)
                    for name in ALL_BINS]
        targets += [self.metadata_target('test', name, 'tests/' + name + '.rs') for name in TESTS]
        document = getattr(self, 'metadata_document', None)
        if document is not None:
            return json.dumps(document)
        return json.dumps({
            'packages': [{'name': 'rootyard', 'version': '0.1.0', 'id': PACKAGE_ID,
                          'manifest_path': str(self.root / 'Cargo.toml'), 'targets': targets}],
            'workspace_members': [PACKAGE_ID],
            'workspace_default_members': [PACKAGE_ID],
            'resolve': None,
            'target_directory': str(target_directory or self.target),
            'workspace_root': str(self.root),
            'version': 1,
            'metadata': None,
        })

    def bin_source(self, name):
        return 'src/bin/' + name + '.rs' if name != 'rootyard' else 'src/main.rs'

    def metadata_target(self, kind, name, source, required_features=None):
        """One entry of the ``targets`` array a real cargo metadata prints."""
        return {'kind': [kind], 'crate_types': [kind], 'name': name,
                'src_path': str(self.root / source), 'edition': '2024', 'doc': True, 'doctest': False,
                'test': True, 'required-features': list(required_features or [])}

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

    def compiled_harness_false(self, name):
        """Where Cargo puts a harness = false test executable (real cargo 1.99.1)."""
        return str(os.path.join(self.target, 'debug', 'build', 'rootyard', '0123456789abcdef', 'out',
                                name + '-0123456789abcdef'))

    def binary(self, name):
        return str(os.path.join(self.target, 'debug', name))

    def implicit_bins(self, bins, tests, features='pando-lab', no_default_features=False):
        """What real Cargo also builds for these ``--bin``/``--test`` selections.

        Cargo names no bin when a ``--test`` is selected, so it builds every
        other *enabled* metadata bin of the package as an implicit build; a
        bin whose required-features the selection does not enable (the
        pando-lab one without pando-lab) is never built.
        """
        if not tests:
            return ()
        enabled = set(features.split(',')) if features else set()
        if enabled:
            enabled.add('kafka-wake')
        if not no_default_features:
            enabled.add('kafka-wake')
        enabled.discard('')
        return tuple(name for name in ALL_BINS if name not in bins
                     and (name != 'rootyard-pando-lab' or 'pando-lab' in enabled))

    def default_events(self, bins=None, tests=None, fresh=False, lib=True, implicit=True,
                       features='pando-lab', no_default_features=False):
        bins = BINS if bins is None else bins
        tests = TESTS if tests is None else tests
        if implicit:
            bins = tuple(bins) + self.implicit_bins(tuple(bins), tuple(tests), features,
                                                    no_default_features)
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

    def fake_popen_each(self, events_for, mutate=None):
        """A fake Cargo for several batches: executables are written per launch.

        A later batch starts with an empty target/, so a stream captured once
        before the first batch would name executables the second batch never wrote.
        """
        def popen(command, **kwargs):
            events = events_for()
            self.write_executables(events)
            return self.launch(list(command), kwargs, events, 0, mutate)
        return popen

    def launch(self, command, kwargs, events, returncode, mutate):
        self.popen_calls.append((list(command), kwargs))
        if not self.clean_commands:
            raise AssertionError('cargo build ran before the single cargo clean')
        self.assert_cargo_holds_lock()
        if isinstance(mutate, _LaunchSteps):
            # A sequence of launches: each entry runs when that launch's
            # stdout is closed, so a later batch sees the previous mutation.
            index, mutate = mutate.next()
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
        # The batch's staged copies are named on disk before publication; no
        # other test may silently hardlink or rename across devices for it.
        with self.cross_device_is_explicit(), \
                mock.patch.object(batch.subprocess, 'Popen', self.fake_popen(events, **kwargs)):
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

    def implicit_receipts(self, bins=None, tests=None, manifest_out=None):
        """Where the receipts of the implicitly built bins live (beside the manifest)."""
        bins = BINS if bins is None else bins
        tests = TESTS if tests is None else tests
        manifest_out = Path(manifest_out or self.outdir / 'native-build-batch.json')
        directory = manifest_out.parent / (manifest_out.stem + '.receipts')
        return [directory / (name + '.build.json') for name in self.implicit_bins(tuple(bins), tuple(tests))]

    def assert_nothing_published(self, args=None):
        args = args or self.args()
        receipts = [self.target / 'debug' / (name + '.build.json') for name in args.bin]
        receipts += [Path(output + '.build.json') for output in args.output]
        receipts += self.implicit_receipts(args.bin, args.test, args.manifest_out)
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
                                                            'overflow_checks': True, 'test': False},
                                                'source': str((self.root / self.bin_source(name)).resolve())}
                                               for name in BINS + self.implicit_bins(BINS, TESTS)]})
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
                         [('lib', 'rootyard')] + [('bin', name) for name in BINS + AUTO_BINS])
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

    def real_device(self, path):
        """``(major, minor)`` of the real device holding ``path``."""
        st = os.lstat(path)
        return (os.major(st.st_dev), os.minor(st.st_dev))

    def test_test_executables_are_copied_outside_target_and_survive_a_clean(self):
        args = self.args()
        self.build(args=args)
        for output, name in zip(args.output, args.test):
            self.assertTrue(Path(output).is_file())
            self.assertEqual(Path(output).stat().st_mode & 0o777, 0o700)
            self.assertNotIn(self.target, Path(output).resolve().parents)
            # Same-device relocation is one real copy, not a hardlink to the artifact.
            self.assertEqual(self.real_device(output), self.real_device(self.outdir))
            self.assertEqual(self.real_device(output), self.real_device(self.root))
            self.assertNotEqual(os.stat(output).st_ino, os.stat(self.compiled_test(name)).st_ino)
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
            # Cargo also built every other enabled metadata bin for the tests.
            self.assertEqual([item['target'] for item in receipt['fresh_false_artifacts']],
                             ['rootyard', 'rootyard', 'rootyard-vfs-mount', 'rootyard-pando-lab',
                              *AUTO_BINS])
            self.assertTrue(all(item['fresh'] is False for item in receipt['fresh_false_artifacts']))
            entries = receipt['fresh_false_artifacts']
            executables = [item.get('executable') for item in entries]
            self.assertIn(self.binary(name), executables)
        # Requested bins first, then one record per implicitly built bin, then the tests.
        self.assertEqual([entry['kind'] for entry in report['artifacts']],
                         ['bin', 'bin', 'bin', 'bin', 'bin', 'test', 'test'])
        self.assertEqual([entry['target'] for entry in report['artifacts'] if entry['kind'] == 'bin'],
                         ['rootyard', 'rootyard-vfs-mount', 'rootyard-pando-lab', *AUTO_BINS])

    def test_previous_batch_receipts_are_replaced_atomically(self):
        args = self.args()
        self.seed_previous_batch(args)
        self.build(args=args)
        receipt = json.loads((self.target / 'debug' / 'rootyard.build.json').read_text())
        self.assertNotEqual(receipt, {'stale': True})
        self.assertEqual(receipt['binary_sha256'], batch.sha256_file(self.binary('rootyard')))
        for output, name in zip(args.output, args.test):
            self.assertEqual(Path(output).read_bytes(), Path(self.compiled_test(name)).read_bytes())

    # -- relocation across filesystem boundaries ---------------------------
    def cross_device_is_explicit(self):
        """Patch cross-device hardlink/rename to fail unless a test emulates a device.

        ``emulated_device`` is the only place that says so (by setting
        ``self.device_boundary``); every other fixture then really depends on a
        same-device operation and fails closed here rather than elsewhere.
        """
        enabled = bool(getattr(self, 'device_boundary', False))

        def checked(operation):
            def run(source, destination):
                if not enabled and os.stat(source).st_dev != os.stat(destination).st_dev:
                    raise OSError(18, 'Invalid cross-device link', str(source))
                return operation(source, destination)
            return run

        def patch(tool, name):
            return mock.patch.object(tool, name, checked(getattr(tool, name)))

        guarded = contextlib.ExitStack()
        guarded.enter_context(patch(batch.os, 'link'))
        guarded.enter_context(patch(batch.os, 'rename'))
        guarded.enter_context(patch(batch.shutil.os, 'link'))
        guarded.enter_context(patch(batch.shutil.os, 'rename'))
        guarded.enter_context(patch(shutil.os, 'link'))
        guarded.enter_context(patch(shutil.os, 'rename'))
        return guarded

    @contextlib.contextmanager
    def emulated_device(self, path):
        """Let the batch see ``path`` on another device; real syscalls still run locally.

        Patch this around ``batch.run_batch`` only: the assertion helpers copy,
        compare and remove files with their own real views. It mirrors a Docker
        named volume mounted at the output directory, or a bind mount on another
        device, next to an in-container ``CARGO_TARGET_DIR``; it is not a
        physical second device.
        """
        real_stat = os.stat
        marker = Path(path)

        def fake_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            try:
                inside = marker == Path(path) or marker in Path(path).parents
            except TypeError:
                inside = False
            if not inside:
                return result
            fields = list(result)
            fields[2] = os.makedev(os.major(result.st_dev) + 1000, os.minor(result.st_dev))
            return type(result)(fields)

        def no_cross(source, destination):
            if fake_stat(source).st_dev != fake_stat(destination).st_dev:
                raise OSError(18, 'Invalid cross-device link', str(source))

        patches = [mock.patch.object(batch.os, 'stat', fake_stat),
                   mock.patch.object(batch.os, 'link', no_cross),
                   mock.patch.object(batch.os, 'rename', no_cross),
                   mock.patch.object(batch.shutil.os, 'stat', fake_stat),
                   mock.patch.object(batch.shutil.os, 'link', no_cross),
                   mock.patch.object(batch.shutil.os, 'rename', no_cross)]
        for patcher in patches:
            patcher.start()
        self.device_boundary = True
        try:
            yield
        finally:
            self.device_boundary = False
            for patcher in reversed(patches):
                patcher.stop()

    def test_cross_filesystem_outputs_are_staged_and_renamed_in_their_own_directory(self):
        args = self.args()
        volume = self.outdir / 'volume'
        outputs = [str(volume / name.replace('_', '-')) for name in args.test]
        args = self.args(outputs=outputs)
        volume.mkdir(parents=True)
        seen = []
        real_replace = os.replace

        def record(source, destination, *arguments, **keywords):
            staged, target = Path(source), Path(destination)
            device = self.real_device(staged)
            self.assertEqual(device, self.real_device(target.parent),
                             'a payload must be renamed only inside its destination directory')
            seen.append((target, device))
            return real_replace(source, destination, *arguments, **keywords)

        with self.cross_device_is_explicit(), self.emulated_device(volume), \
                mock.patch.object(batch.os, 'replace', record):
            report = self.build(args=args)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(self.real_device(outputs[0]), self.real_device(volume))
        self.assertEqual({device for _, device in seen},
                         {self.real_device(self.target), self.real_device(volume)})
        for output, name in zip(outputs, args.test):
            artifact = Path(self.compiled_test(name))
            self.assertEqual(Path(output).read_bytes(), artifact.read_bytes())
            self.assertEqual(batch.sha256_file(output), batch.sha256_file(artifact))
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o700)
            entry = next(item for item in report['artifacts'] if item['target'] == name)
            self.assertIs(entry['fresh'], False)
            self.assertEqual(entry['artifact'], str(Path(output).resolve()))
            self.assertEqual(entry['sha256'], batch.sha256_file(artifact))
            self.assertEqual(entry['original_artifact_sha256'], batch.sha256_file(artifact))
            self.assertEqual(entry['size'], artifact.stat().st_size)
            receipt = json.loads(Path(output + '.build.json').read_text())
            self.assertIs(receipt['fresh'], False)
            self.assertEqual(receipt['binary_sha256'], batch.sha256_file(artifact))
            self.assertEqual(receipt['original_artifact_sha256'], batch.sha256_file(artifact))
            self.assertEqual(receipt['batch']['targets'][-1], name)
        # The manifest is the last rename: the commit marker follows every
        # receipt and relocated executable this transaction renamed.
        self.assertEqual(seen[-1][0], Path(args.manifest_out).resolve())
        earlier = {target for target, _ in seen[:-1]}
        self.assertLessEqual({Path(output + '.build.json').resolve() for output in outputs} |
                             {Path(output).resolve() for output in outputs} |
                             {(self.target / 'debug' / (name + '.build.json')).resolve()
                              for name in args.bin},
                             earlier)
        self.assertFalse([path for path in volume.iterdir()
                          if path.name.startswith('.') or path.name.endswith('.batch-new')],
                         'cross-filesystem staging must not leave hidden siblings behind')

    def copy_staging_failure(self, copyfile):
        """The error of a batch whose copy to the other device goes through ``copyfile``."""
        volume = self.outdir / 'volume'
        args = self.args(outputs=[str(volume / name.replace('_', '-')) for name in TESTS])
        # Directories are created on this side too (prepare_destinations), so
        # create them before the boundary exists. Each test gets its own.
        volume.mkdir(parents=True, exist_ok=True)
        self.seed_previous_batch(args)
        fake_cargo = self.fake_popen(self.default_events())
        with self.cross_device_is_explicit(), self.emulated_device(volume), \
                mock.patch.object(batch.shutil, 'copyfile', copyfile), \
                mock.patch.object(self, 'write_executables'), \
                mock.patch.object(batch.subprocess, 'Popen', fake_cargo):
            with self.assertRaises((batch.BuildError, OSError)) as caught:
                batch.run_batch(args)
        self.assert_nothing_published(args)
        return caught.exception

    def test_cross_filesystem_copy_mismatch_publishes_nothing(self):
        # A copy onto the other device whose bytes do not match the artifact is
        # caught by the SHA-256 check and never renamed over the destination.
        real_copyfile = batch.shutil.copyfile

        def wrong_copy(source, destination, *arguments, **keywords):
            real_copyfile(source, destination, *arguments, **keywords)
            with open(destination, 'ab') as handle:
                handle.write(b'tampered')

        error = self.copy_staging_failure(wrong_copy)
        self.assertIn('does not match the artifact', str(error))

    def test_cross_filesystem_copy_error_withdraws_staged_bin_receipts(self):
        # A full volume on the other device fails the copy of the first test
        # after the bin receipts were already staged in target/: run_batch's
        # error path must withdraw those staged receipts too.
        def no_space(source, destination, *arguments, **keywords):
            raise OSError(28, 'No space left on device', str(destination))

        error = self.copy_staging_failure(no_space)
        self.assertIn('No space left on device', str(error))

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
        events = [artifact('lib', 'rootyard')] + self.default_events(bins=(), implicit=False)[1:]
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
        self.assert_failure(events, 'not at its canonical location')

    def test_foreign_package_artifacts_are_skipped_not_receipted(self):
        # Real Cargo reports the dependency it rebuilt before the selected
        # package's units; only the selected package's events may reach a receipt.
        foreign = 'path+file:///ws#depcrate@0.1.0'
        events = self.default_events()
        events.insert(0, artifact('lib', 'depcrate', package=foreign))
        # A foreign bin is skipped too, even though its kind/name are not selected.
        events.insert(-1, artifact('bin', 'sneaky', package=foreign, executable=self.binary('sneaky')))
        report = self.build(events=events)
        recorded = report['build']['fresh_false_artifacts']
        self.assertEqual([(item['kind'], item['target']) for item in recorded],
                         [('lib', 'rootyard')] + [('bin', name) for name in BINS + AUTO_BINS])
        self.assertTrue(all(item['package_id'] == PACKAGE_ID for item in recorded))
        receipt = json.loads((self.target / 'debug' / 'rootyard.build.json').read_text())
        self.assertEqual(receipt['fresh_false_artifacts'], recorded)
        # One receipt per selected bin and test; nothing for the dependency.
        self.assertEqual(
            sorted(Path(entry['receipt']).resolve() for entry in report['artifacts']),
            sorted([(self.target / 'debug' / (name + '.build.json')).resolve() for name in BINS] +
                   [path.resolve() for path in self.implicit_receipts(BINS, TESTS)] +
                   [(self.outdir / (name.replace('_', '-') + '.build.json')).resolve() for name in TESTS]))
        self.assertFalse(list(self.outdir.rglob('*depcrate*.build.json')))

    def test_foreign_package_artifacts_are_named_in_index_and_never_in_receipts(self):
        foreign = 'path+file:///ws#depcrate@0.1.0'
        events = [artifact('lib', 'depcrate', package=foreign),
                  artifact('bin', 'depcrate-tool', package=foreign,
                           executable=self.binary('dependency-only-tool')),
                  # A fresh (dirty-reused) dependency is Cargo's business; it is
                  # not one of the selected artifacts a receipt vouches for.
                  artifact('lib', 'depcrate', package=foreign, fresh=True)] + self.default_events()
        lib, bins, tests, skipped = batch.artifact_index(events, PACKAGE_ID)
        self.assertEqual(lib, {'target': 'rootyard', 'kind': 'lib', 'fresh': False,
                               'package_id': PACKAGE_ID})
        self.assertEqual(sorted(bins), sorted(BINS + AUTO_BINS))
        self.assertEqual(sorted(tests), sorted(TESTS))
        self.assertEqual(skipped, {foreign: 3})
        self.assertTrue(all(item['package_id'] == PACKAGE_ID
                            for item in [lib, *bins.values(), *tests.values()]))
        self.assertNotIn('depcrate-tool', bins)
        self.assertNotIn('depcrate', [item['target'] for item in [lib, *bins.values(), *tests.values()]])

    def test_foreign_artifacts_do_not_relax_selected_package_checks(self):
        foreign = 'path+file:///ws#depcrate@0.1.0'
        # A foreign package's lib must not stand in for a missing rootyard lib.
        missing = [artifact('lib', 'rootyard', package=foreign)] + self.default_events(lib=False)
        self.assert_failure(missing, 'did not report a rootyard lib')
        # A fresh foreign lib neither fails the batch nor is receipted.
        fresh_foreign = [artifact('lib', 'depcrate', package=foreign, fresh=True)] + self.default_events()
        report = self.build(events=fresh_foreign)
        self.assertEqual([(item['kind'], item['target'], item['fresh'])
                          for item in report['build']['fresh_false_artifacts']],
                         [('lib', 'rootyard', False)] + [('bin', name, False) for name in BINS + AUTO_BINS])
        # Duplicate, unexpected-kind, renamed-lib and Fresh=true artifacts of
        # the selected package stay fatal even when a foreign event is present.
        foreign_lib = artifact('lib', 'depcrate', package=foreign)
        duplicate = self.default_events() + [artifact('lib', 'rootyard'), foreign_lib]
        self.assert_failure(duplicate, 'two rootyard lib artifacts')
        example = self.default_events() + [artifact('example', 'demo', executable=self.binary('demo')),
                                           foreign_lib]
        self.assert_failure(example, 'unexpected rootyard artifact')
        renamed = self.default_events()
        renamed[0] = artifact('lib', 'rootyard_core')
        self.assert_failure([foreign_lib] + renamed, 'unexpected lib target')
        stale_bin = self.default_events()
        stale_bin[1] = artifact('bin', 'rootyard', fresh=True, executable=self.binary('rootyard'))
        stale_bin.insert(-1, foreign_lib)
        self.assert_failure(stale_bin, 'Fresh rootyard artifact of rootyard')
        # A selected bin is still required when only a foreign lib was reported.
        missing_bin = [foreign_lib] + self.default_events(bins=BINS[1:], implicit=False)
        self.assert_failure(missing_bin, 'did not report the requested binaries')
        # An implicit build (the tests are selected) cannot fill a requested
        # bin's slot: only the requested bins plus enabled metadata bins pass.
        implicit_missing = [artifact('lib', 'rootyard')] + \
            [artifact('bin', name, executable=self.binary(name)) for name in BINS[1:]] + \
            [artifact('test', name, executable=self.compiled_test(name)) for name in TESTS] + [finished()]
        self.assert_failure(implicit_missing, 'did not report the requested binaries: rootyard')

    def test_harness_false_test_is_classified_by_kind_not_profile_test(self):
        # Real Cargo 1.99.1 for a [[test]] harness = false fixture: target
        # kind ["test"], an executable under
        # target/debug/build/<pkg>/<hash>/out, profile.test = true (recorded
        # as reported, not re-derived from harness or kind).
        events = self.default_events(tests=())
        events.insert(-1, artifact('test', TESTS[0], executable=self.compiled_harness_false(TESTS[0])))
        report = self.build(events=events, args=self.args(tests=TESTS[:1],
                                                          outputs=[str(self.outdir / 'fixture')]))
        entry = report['artifacts'][-1]
        self.assertEqual((entry['kind'], entry['target'], entry['fresh']), ('test', TESTS[0], False))
        self.assertEqual(entry['original_artifact'], self.compiled_harness_false(TESTS[0]))
        self.assertEqual(entry['artifact'], str((self.outdir / 'fixture').resolve()))
        self.assertEqual(entry['source'], str(self.root / 'tests' / (TESTS[0] + '.rs')))
        self.assertEqual(entry['source_sha256'], batch.sha256_file(self.root / 'tests' / (TESTS[0] + '.rs')))
        self.assertTrue(Path(entry['artifact']).is_file())
        self.assertNotIn(self.target, Path(entry['artifact']).resolve().parents)
        # The compiled harness = false binary stays in place; the copy is ours.
        self.assertTrue(Path(self.compiled_harness_false(TESTS[0])).is_file())
        receipt = json.loads(Path(entry['receipt']).read_text())
        self.assertEqual(receipt['kind'], 'rust-integration-test')
        self.assertEqual(len(receipt['fresh_false_artifacts']), 1)
        harness = receipt['fresh_false_artifacts'][0]
        self.assertEqual((harness['kind'], harness['target'], harness['fresh']), ('test', TESTS[0], False))
        self.assertEqual(harness['executable'], self.compiled_harness_false(TESTS[0]))
        self.assertIs(harness['profile']['test'], True)
        self.assertIs(harness['profile']['debug_assertions'], True)
        self.assertEqual(receipt['binary_sha256'], batch.sha256_file(entry['artifact']))
        self.assertEqual(receipt['original_artifact_sha256'],
                         batch.sha256_file(self.compiled_harness_false(TESTS[0])))

    def test_harness_false_test_stays_a_selected_test_for_fresh_and_kind(self):
        # A harness = false fixture is a selected test: Fresh=true is a stale
        # receipt, even though its executable lives under target/debug/build.
        stale = self.default_events(tests=())
        stale.insert(-1, artifact('test', TESTS[0], fresh=True,
                                  executable=self.compiled_harness_false(TESTS[0])))
        self.assert_failure(stale, 'Fresh ' + TESTS[0] + ' artifact',
                            args=self.args(tests=TESTS[:1], outputs=[str(self.outdir / 'stale')]))
        # profile.test = false on that same kind ["test"] artifact is rejected.
        dev = self.default_events(tests=())
        dev.insert(-1, artifact('test', TESTS[0], test_profile=False,
                                executable=self.compiled_harness_false(TESTS[0])))
        self.assert_failure(dev, 'test profile', args=self.args(tests=TESTS[:1],
                                                                outputs=[str(self.outdir / 'dev')]))
        # The same artifact reported under another name is an extra test.
        extra = self.default_events() + [artifact('test', 'other_fixture',
                                                  executable=self.compiled_harness_false('other_fixture'))]
        self.assert_failure(extra, 'tests that were not selected')

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
        # Cargo.lock is part of the production digest too, so one change is
        # caught by two independent measurements; the production one speaks
        # first and its message names only what it measured.
        self.assert_failure(None, 'Source inputs changed during build',
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
        # Metadata was read before planning (no other probe beyond it is
        # needed to refuse); no clean or build ran.
        self.assertGreaterEqual(len(self.metadata_calls), 1)
        self.assertEqual(self.clean_calls(), [])
        self.assertEqual(self.popen_calls, [])

    def test_conflicting_or_duplicate_selections_are_rejected(self):
        self.planning_failure(self.args(bins=('rootyard', 'rootyard')), 'repeats')
        self.planning_failure(self.args(tests=(TESTS[0], TESTS[0]),
                                        outputs=[str(self.outdir / 'a'), str(self.outdir / 'b')]), 'repeats')
        self.planning_failure(self.args(features='pando-lab,nope'), 'unknown features')
        # pando-lab is an empty feature, so the [[bin]] gate is exercised as a plan.
        without_lab = batch.parse_cargo_toml(CARGO_TOML.replace('required-features = ["pando-lab"]',
                                                                'required-features = ["state-redis"]'))
        no_pando_lab = without_lab['features'].pop('pando-lab')
        self.assertEqual(no_pando_lab, [])
        with self.assertRaises(batch.BuildError) as caught:
            batch.plan_batch(self.args(bins=BINS, features='kafka-wake'), without_lab)
        self.assertIn('bin rootyard-pando-lab requires features state-redis', str(caught.exception))
        self.planning_failure(self.args(features='pando-lab --release'), 'comma-separated')
        empty = self.args(tests=(), outputs=[], bins=(), all_bins=False)
        self.planning_failure(empty, 'sel')
        cargo = CARGO_TOML.replace('[dependencies]', '''[[bin]]
name = "rootyard-view-lab"
path = "src/bin/rootyard-view-lab.rs"

[dependencies]''')
        # For the TOML parser a lab is just a `[[bin]]`; whether it exists as a
        # target is metadata's answer (the metadata tests below cover it).
        manifest = batch.parse_cargo_toml(cargo)
        self.assertIn('rootyard-view-lab', {entry['name'] for entry in manifest['bins']})
        self.planning_failure(self.args(bins=('no-such-bin',)), 'not a bin target')

    def test_outputs_must_be_outside_target_unique_and_one_per_test(self):
        inside = str(self.target / 'debug' / 'fixture')
        self.planning_failure(self.args(outputs=[inside, str(self.outdir / 'b')]), 'outside CARGO_TARGET_DIR')
        self.planning_failure(self.args(outputs=[str(self.outdir / 'a'), str(self.outdir / 'a')]), 'repeats')
        self.planning_failure(self.args(outputs=[str(self.outdir / 'a')]), 'once per --test')
        self.planning_failure(self.args(tests=(), outputs=[], bins=(), all_bins=False), 'select at least one')

    def test_missing_test_source_is_rejected(self):
        # metadata lists it (the fixture file exists) but the source is gone.
        (self.root / 'tests' / (TESTS[1] + '.rs')).unlink()
        self.planning_failure(self.args(tests=(TESTS[1],), outputs=[str(self.outdir / 'x')]),
                              'integration-test source is missing')

    def test_all_bins_selects_every_metadata_bin_with_enabled_features(self):
        args = self.args(all_bins=True, bins=())
        report = self.build(args=args)
        # Every bin metadata lists, auto-discovered labs included, each named
        # explicitly: nothing is left to Cargo's implicit build.
        self.assertEqual([entry['target'] for entry in report['artifacts'] if entry['kind'] == 'bin'],
                         list(ALL_BINS))
        self.assertEqual([self.popen_calls[0][0][index + 1] for index, token in
                          enumerate(self.popen_calls[0][0]) if token == '--bin'],
                         list(ALL_BINS))
        self.assertEqual({entry['implicit'] for entry in report['artifacts'] if entry['kind'] == 'bin'},
                         {False})

    # -- the Cargo metadata target set --------------------------------------
    def test_an_auto_discovered_bin_is_named_from_metadata_not_the_toml(self):
        # No [[bin]] table names the labs; only cargo metadata does. A --bin for
        # one is selected like any metadata bin, by its metadata path.
        args = self.args(bins=('rootyard', 'rootyard-view-lab'), tests=())
        report = self.build(args=args)
        self.assertEqual(self.popen_calls[0][0], self.expected_command(args))
        self.assertIn(['--bin', 'rootyard-view-lab'], [self.popen_calls[0][0][index:index + 2]
                                                      for index in range(len(self.popen_calls[0][0]))])
        bin_entries = [entry for entry in report['artifacts'] if entry['kind'] == 'bin']
        self.assertEqual([entry['target'] for entry in bin_entries], ['rootyard', 'rootyard-view-lab'])
        self.assertEqual({entry['implicit'] for entry in bin_entries}, {False})
        self.assertEqual(bin_entries[1]['target_source'], str((self.root / 'src/bin/rootyard-view-lab.rs').resolve()))
        receipt = json.loads((self.target / 'debug' / 'rootyard-view-lab.build.json').read_text())
        # A requested lab receipt is a full bin receipt and does not claim to be
        # the server binary; nothing implicit is folded into it.
        self.assertNotIn('implicit_build', receipt)
        self.assertEqual(receipt['binary_sha256'], batch.sha256_file(self.binary('rootyard-view-lab')))
        self.assertEqual(receipt['batch']['binary'], 'rootyard-view-lab')
        # Without a --test the command names every bin: nothing extra was built.
        self.assertEqual(self.clean_calls(), [['cargo', 'clean', '--package', 'rootyard']])

    def test_a_test_selection_accepts_and_receipts_cargo_implicit_bins(self):
        args = self.args(bins=('rootyard',), tests=TESTS[:1], outputs=[str(self.outdir / 'fixture')])
        report = self.build(args=args, events=self.default_events(bins=('rootyard',), tests=TESTS[:1]))
        # The command still names the requested test and no other bin...
        command = self.popen_calls[0][0]
        self.assertEqual(command, self.expected_command(args))
        # ...and Cargo's implicit build of every other enabled metadata bin is
        # recorded, flagged implicit, at its real executable with Fresh=false.
        bins = [entry for entry in report['artifacts'] if entry['kind'] == 'bin']
        self.assertEqual([(entry['target'], entry['implicit']) for entry in bins],
                         [('rootyard', False)] + [(name, True) for name in ALL_BINS[1:]])
        implicit = [entry for entry in bins if entry['implicit']]
        self.assertEqual([entry['target'] for entry in implicit],
                         ['rootyard-pando-lab', 'rootyard-view-lab', 'rootyard-workspace-lab',
                          'rootyard-vfs-mount'])
        for entry in implicit:
            self.assertIs(entry['fresh'], False)
            self.assertEqual(entry['artifact'], self.binary(entry['target']))
            self.assertEqual(entry['target_source'], str((self.root / self.bin_source(entry['target'])).resolve()))
            receipt = json.loads(Path(entry['receipt']).read_text())
            # A full, standalone-shaped receipt, stored beside the manifest.
            for field in ('binary_sha256', 'source_inputs_sha256', 'workspace_commit', 'rustc', 'command'):
                self.assertTrue(receipt[field], field)
            self.assertEqual(receipt['rustc'], report['toolchain']['rustc'])
            self.assertEqual(receipt['command'], report['build']['command'])
            self.assertEqual(receipt['binary_sha256'], batch.sha256_file(self.binary(entry['target'])))
            self.assertEqual(receipt['clean_command'], ['cargo', 'clean', '--package', 'rootyard'])
            self.assertIs(receipt['package_rebuilt'], True)
            self.assertEqual(receipt['batch']['binary'], entry['target'])
            self.assertEqual(receipt['fresh_false_artifacts'], report['build']['fresh_false_artifacts'])
            marker = receipt['implicit_build']
            self.assertEqual(marker['acceptance'], 'not-server-acceptance')
            self.assertEqual(marker['requested_by'], '--test')
            self.assertEqual(marker['target_source'], entry['target_source'])
            # The lab is recorded as a lab: no receipt calls it the server.
            self.assertNotEqual(receipt['batch']['binary'], 'rootyard')
        # One receipt per recorded bin; none of them is the server's name.
        self.assertEqual(len({str(Path(entry['receipt']).resolve()) for entry in bins}), len(bins))
        self.assertEqual(bins[0]['receipt'], str(self.target / 'debug' / 'rootyard.build.json'))
        self.assertEqual([entry['target'] for entry in report['build']['fresh_false_artifacts']],
                         ['rootyard', 'rootyard'] + list(ALL_BINS[1:]))
        # A requested bin receipt stays free of the implicit marker.
        requested = json.loads((self.target / 'debug' / 'rootyard.build.json').read_text())
        self.assertNotIn('implicit_build', requested)

    def test_implicit_bins_without_a_test_are_rejected(self):
        # Without a --test every bin is named, so Cargo has no reason to build
        # another one; accepting it would widen the selection silently.
        events = self.default_events(bins=BINS, tests=(), implicit=False)
        events += [artifact('bin', 'rootyard-view-lab', executable=self.binary('rootyard-view-lab'))]
        self.assert_failure(events, 'binaries that were not selected: rootyard-view-lab',
                            args=self.args(tests=(), outputs=[]))

    def test_unknown_and_metadata_only_targets_are_rejected(self):
        self.planning_failure(self.args(bins=('rootyard-ghost-lab',)), 'not a bin target of the rootyard package')
        # A tests/*.rs file Cargo metadata does not list (autotests = false)
        # is not a target Cargo can build by that name.
        self.write('tests/metadata_hidden.rs', '#[test]\nfn hidden() {}\n')
        self.planning_failure(self.args(tests=('metadata_hidden',), outputs=[str(self.outdir / 'x')]),
                              'metadata does not list the test target metadata_hidden')
        # A build-script or tool target is a kind outside this batch.
        document = json.loads(self.metadata_json())
        document['packages'][0]['targets'].append(self.metadata_target('custom-build', 'build-script-build',
                                                                       'build.rs'))
        self.metadata_document = document
        with self.assertRaises(batch.BuildError) as caught:
            batch.run_batch(self.args())
        self.assertIn('only lib, bin and test targets', str(caught.exception))
        self.assertEqual(self.clean_calls(), [])
        self.assertEqual(self.popen_calls, [])

    def test_an_unlisted_bin_artifact_is_an_unknown_extra(self):
        args = self.args(tests=TESTS[:1], outputs=[str(self.outdir / 'fixture')])
        # A bin metadata does not list, reported with an implicit bin present.
        events = self.default_events(bins=('rootyard',), tests=TESTS[:1], implicit=False)
        events += [artifact('bin', name, executable=self.binary(name)) for name in ALL_BINS[1:]]
        events.insert(-1, artifact('bin', 'rootyard-sneaky-lab', executable=self.binary('rootyard-sneaky-lab')))
        self.assert_failure(events, 'that cargo metadata does not list for the rootyard package', args=args)
        # Without pando-lab the lab is not an enabled metadata bin, so it is
        # neither selected nor accepted implicitly (the other enabled bins are).
        report = self.build(events=self.default_events(bins=('rootyard',), tests=TESTS[:1],
                                                       features='kafka-wake'),
                            args=self.args(bins=(), tests=TESTS[:1], outputs=[str(self.outdir / 'fixture')],
                                           features='kafka-wake'))
        self.assertEqual([entry['target'] for entry in report['artifacts'] if entry['kind'] == 'bin'],
                         ['rootyard', 'rootyard-view-lab', 'rootyard-workspace-lab', 'rootyard-vfs-mount'])

    def test_a_not_enabled_metadata_bin_is_not_accepted_implicitly(self):
        # Asking for a bin whose required features this selection lacks is
        # refused at planning, before any clean or build...
        self.planning_failure(self.args(bins=('rootyard', 'rootyard-pando-lab'), tests=TESTS[:1],
                                        outputs=[str(self.outdir / 'fixture')], features='kafka-wake'),
                              'bin rootyard-pando-lab requires features pando-lab')
        # Implicitly, it must never slip in: a test-only selection without
        # pando-lab accepts the other enabled bins and refuses this report.
        events = self.default_events(bins=('rootyard',), tests=TESTS[:1], implicit=False)
        events += [artifact('bin', name, executable=self.binary(name))
                   for name in ALL_BINS[1:] if name != 'rootyard-pando-lab']
        events.insert(-1, artifact('bin', 'rootyard-pando-lab', executable=self.binary('rootyard-pando-lab')))
        # A pando-lab artifact in a selection without pando-lab is an unknown
        # extra, not an implicit bin.
        self.assert_failure(events, 'binaries that were not selected: rootyard-pando-lab',
                            args=self.args(bins=(), tests=TESTS[:1], outputs=[str(self.outdir / 'fixture')],
                                           features='kafka-wake'))

    def test_a_metadata_bin_must_arrive_with_its_metadata_source(self):
        args = self.args(tests=TESTS[:1], outputs=[str(self.outdir / 'fixture')])
        events = self.default_events(bins=('rootyard',), tests=TESTS[:1], implicit=False)
        events += [artifact('bin', name, executable=self.binary(name)) for name in ALL_BINS[1:]]
        # The name is metadata's, but Cargo reports an artifact built from
        # another source (e.g. a build script output): not this bin.
        sneaky = next(index for index, event in enumerate(events)
                      if event.get('target', {}).get('name') == 'rootyard-view-lab')
        events[sneaky]['executable'] = str(self.target / 'debug' / 'build' / 'rootyard' / 'out' /
                                           'rootyard-view-lab')
        self.assert_failure(events, 'not at its canonical location', args=args)

    def test_missing_fresh_and_duplicate_implicit_bins_are_rejected(self):
        args = self.args(tests=TESTS[:1], outputs=[str(self.outdir / 'fixture')])
        fresh = self.default_events(bins=('rootyard',), tests=TESTS[:1])
        fresh[2] = artifact('bin', 'rootyard-pando-lab', fresh=True, executable=self.binary('rootyard-pando-lab'))
        self.assert_failure(fresh, 'Fresh rootyard-pando-lab artifact', args=args)
        duplicate = self.default_events(bins=('rootyard',), tests=TESTS[:1]) + [
            artifact('bin', 'rootyard-view-lab', executable=self.binary('rootyard-view-lab'))]
        self.assert_failure(duplicate, 'duplicate', args=args)
        no_executable = self.default_events(bins=('rootyard',), tests=TESTS[:1])
        index = next(index for index, event in enumerate(no_executable)
                     if event['target']['name'] == 'rootyard-workspace-lab')
        no_executable[index] = artifact('bin', 'rootyard-workspace-lab')
        self.assert_failure(no_executable, 'has no executable path', args=args)
        as_unit_test = self.default_events(bins=('rootyard',), tests=TESTS[:1])
        index = next(index for index, event in enumerate(as_unit_test)
                     if event['target']['name'] == 'rootyard-workspace-lab')
        as_unit_test[index] = artifact('bin', 'rootyard-workspace-lab', test_profile=True,
                                       executable=self.binary('rootyard-workspace-lab'))
        self.assert_failure(as_unit_test, 'built as a test unit', args=args)
        # An always-enabled implicit bin simply missing from the stream is not
        # refused by itself: Cargo may omit a bin unit, and nothing receipted
        # it. The requested bins and tests stay required.
        absent = [event for event in self.default_events(bins=('rootyard',), tests=TESTS[:1])
                  if event.get('target', {}).get('name') != 'rootyard-workspace-lab']
        report = self.build(args=args, events=absent)
        self.assertEqual([entry['target'] for entry in report['artifacts'] if entry['kind'] == 'bin'],
                         ['rootyard', 'rootyard-pando-lab', 'rootyard-vfs-mount', 'rootyard-view-lab'])

    def test_implicit_bin_receipts_are_withdrawn_on_a_late_failure(self):
        # Receipts of an earlier batch (implicit ones beside the manifest
        # included) never survive a run that is refused after Cargo built.
        args = self.args(tests=TESTS[:1], outputs=[str(self.outdir / 'fixture')])
        self.seed_previous_batch(args)
        for path in self.implicit_receipts(args.bin, args.test, args.manifest_out):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"stale": true}\n')
        events = self.default_events(bins=('rootyard',), tests=TESTS[:1])
        self.assert_failure(events, 'integration-test source',
                            args=args,
                            mutate=lambda: (self.root / 'tests' / (TESTS[0] + '.rs')).write_text(
                                '#[test]\nfn changed() {}\n'))

    def test_metadata_features_gate_autodiscovered_bins_with_the_existing_selection(self):
        # metadata lists required-features; the batch's own --features /
        # --no-default-features selection decides whether a bin is enabled.
        document = json.loads(self.metadata_json())
        lab = next(target for target in document['packages'][0]['targets']
                   if target['name'] == 'rootyard-view-lab')
        lab['required-features'] = ['state-redis']
        self.metadata_document = document
        with self.assertRaises(batch.BuildError) as caught:
            batch.run_batch(self.args(all_bins=True, bins=()))
        self.assertIn('bin rootyard-view-lab requires features state-redis', str(caught.exception))
        self.assertEqual(self.popen_calls, [])
        self.assertEqual(self.clean_calls(), [])
        # Enabling it makes --all-bins select it, named explicitly.
        report = self.build(args=self.args(all_bins=True, bins=(), features='pando-lab,state-redis'))
        self.assertIn('rootyard-view-lab',
                      [entry['target'] for entry in report['artifacts'] if entry['kind'] == 'bin'])

    # -- bound build inputs -------------------------------------------------
    def bound_record(self, with_blobs=False):
        """What every receipt and the manifest carry for the bound inputs."""
        args = self.args()
        report = self.build(args=args)
        receipts = [json.loads((self.target / 'debug' / (name + '.build.json')).read_text())
                    for name in args.bin]
        receipts += [json.loads(Path(output + '.build.json').read_text()) for output in args.output]
        self.assertEqual(receipts[-1]['kind'], 'rust-integration-test')
        bound, inventory = report['bound_inputs'], report['bound_input_inventory']
        for receipt in receipts:
            self.assertEqual(receipt['bound_inputs'], bound)
            self.assertEqual(receipt['bound_input_inventory'], inventory)
            self.assertEqual(receipt['batch']['bound_inputs_sha256'], bound['digest'])
        self.assertEqual(json.loads(Path(args.manifest_out).read_text()), report)
        if with_blobs:
            # The raw bytes the recorded inventory was measured from.
            return report, receipts, batch.bound_input_inventory()[1]
        return report, receipts

    def entries_of(self, report):
        return {entry['path']: entry for entry in report['bound_input_inventory']}

    def selected_entries(self):
        return ['tests/' + name + '.rs' for name in TESTS]

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def manifest(self, text=None):
        """The batch's plan manifest exactly as run_batch derives it (Cargo.toml view + metadata targets)."""
        if text is not None:
            (self.root / 'Cargo.toml').write_text(text)
        return batch.batch_manifest(batch.metadata_record(json.loads(self.metadata_json())))

    def assert_run_rejected(self, steps, message, args=None):
        """Run one batch whose launch ``i`` performs ``steps[i]``; it must be refused.

        The batch mutates inputs while it runs, so no receipt or manifest from
        the previous run may survive it.
        """
        args = args or self.args()
        self.seed_previous_batch(args)
        with mock.patch.object(batch.subprocess, 'Popen',
                               self.fake_popen(self.default_events(bins=args.bin, tests=args.test),
                                               mutate=_LaunchSteps(steps))):
            with self.assertRaises(batch.BuildError) as caught:
                batch.run_batch(args)
        self.assertIn(message, str(caught.exception))
        self.assert_nothing_published(args)
        return caught.exception

    def fresh_run_records(self, mutate, args=None):
        """A passing batch, ``mutate`` of the worktree, then a second batch that passes too.

        A later run compiles the new sources: only an input that moves *during*
        one build is refused. The second run starts from a clean target
        directory (nothing the first run built, receipted or relocated
        survives) and must run its own single clean+build, then publish every
        receipt and the manifest with the inventory and digest measured from
        the changed inputs.
        """
        args = args or self.args()
        first = self.build(args=args)
        old_manifest = Path(args.manifest_out).read_bytes()
        mutate()
        # The changed inputs as one pre-run snapshot measures them: the next
        # run's recorded identity must be that of what it compiled.
        changed_snapshot = batch.source_snapshot(batch.plan_batch(args, self.manifest()))
        shutil.rmtree(self.target, ignore_errors=True)
        self.assertFalse(self.target.exists())
        clean_before, popen_before = len(self.clean_commands), len(self.popen_calls)
        second = self.build(args=args)
        self.assertEqual(len(self.clean_commands) - clean_before, 1, 'the new run must clean once')
        self.assertEqual(len(self.popen_calls) - popen_before, 1, 'the new run must build once')
        self.assertEqual(self.popen_calls[-1][0], self.expected_command(args))
        self.assertEqual(second['status'], 'passed')
        self.assertEqual(second['clean']['commands'], 1)
        self.assertEqual(second['build']['commands'], 1)
        self.assertEqual([entry['target'] for entry in second['artifacts']],
                         [entry['target'] for entry in first['artifacts']])
        self.assertEqual({entry['fresh'] for entry in second['artifacts']}, {False})
        # Every receipt of the new transaction and the manifest carry one new inventory.
        self.assert_published(args)
        bound, inventory = second['bound_inputs'], second['bound_input_inventory']
        receipts = [json.loads((self.target / 'debug' / (name + '.build.json')).read_text())
                    for name in args.bin]
        receipts += [json.loads(Path(output + '.build.json').read_text()) for output in args.output]
        self.assertEqual(len(receipts), len(args.bin) + len(args.test))
        for receipt in receipts:
            self.assertEqual(receipt['bound_inputs'], bound)
            self.assertEqual(receipt['bound_input_inventory'], inventory)
            self.assertEqual(receipt['batch']['bound_inputs_sha256'], bound['digest'])
        self.assertNotEqual(Path(args.manifest_out).read_bytes(), old_manifest)
        self.assertEqual(json.loads(Path(args.manifest_out).read_text()), second)
        # The new inventory is exactly the disk now, re-measured from raw bytes.
        self.assertEqual(inventory, batch.bound_input_inventory()[0])
        self.assertEqual(bound, batch.bound_inputs_summary(*batch.bound_input_inventory()))
        self.assertEqual(bound['total_bytes'], sum((self.root / entry['path']).stat().st_size
                                                   for entry in inventory if entry['present']))
        # What the change did not touch is still selected and keeps its bytes;
        # no helper, config or toolchain gate fired at either point of the run.
        entries = self.entries_of(second)
        for path in self.selected_entries():
            self.assertEqual((entries[path]['present'], entries[path]['sha256']),
                             (True, batch.sha256_file(self.root / path)), path)
        # A helper, config or toolchain pin is not a production source: its
        # digest is the same in both reports, only the bound identity moves.
        self.assertEqual(second['source_inputs_sha256'], first['source_inputs_sha256'])
        self.assertEqual(second['source_inputs_sha256'], changed_snapshot['source_inputs'])
        self.assertEqual(bound['digest'], changed_snapshot['bound_inputs_digest'])
        self.assertEqual(inventory, changed_snapshot['bound_inputs'])
        self.assertNotEqual(bound['digest'], first['bound_inputs']['digest'])
        return first, second, entries, self.entries_of(first)

    def assert_published(self, args):
        paths = [self.target / 'debug' / (name + '.build.json') for name in args.bin]
        paths += [Path(output + '.build.json') for output in args.output]
        paths += [Path(output) for output in args.output] + [Path(args.manifest_out)]
        self.assertEqual([str(path) for path in paths if not path.exists()], [])

    def changed_entry(self, entries, old_entries, path, text=None, present=True, role=None,
                      old_entry_role=None):
        """The new entry for ``path`` differs from the old one exactly as the mutation made it."""
        entry = entries.get(path)
        old = old_entries.get(path)
        self.assertNotEqual(entry, old, path)
        # A removed helper leaves the inventory's present entries (only a
        # fixed path is listed absent), an added one enters it.
        old_role = old['role'] if old and old['present'] else old_entry_role
        if entry is None:
            self.assertFalse(present, path)
            return
        self.assertEqual((entry['present'], entry['role']), (present, role or old_role), path)
        self.assertEqual(entry['sha256'], hashlib.sha256(text.encode()).hexdigest() if present else None)

    def test_a_new_helper_is_recorded_by_the_next_fresh_run(self):
        text = 'pub fn helper() { /* changed */ }\n'
        first, second, entries, old_entries = self.fresh_run_records(lambda: self.write(HELPER, text))
        self.changed_entry(entries, old_entries, HELPER, text)
        self.assertEqual(second['bound_inputs']['by_role'], first['bound_inputs']['by_role'])
        self.assertEqual(second['bound_inputs']['total_bytes'],
                         first['bound_inputs']['total_bytes'] + len(text) - len('pub fn helper() {}\n'))

    def test_an_added_helper_is_recorded_by_the_next_fresh_run(self):
        text = 'pub fn untracked() {}\n'
        first, second, entries, old_entries = self.fresh_run_records(
            lambda: self.write(UNTRACKED_HELPER, text))
        self.assertNotIn(UNTRACKED_HELPER, old_entries)
        self.changed_entry(entries, old_entries, UNTRACKED_HELPER, text,
                           old_entry_role='integration_test_source')
        self.assertEqual(second['bound_inputs']['present_count'], first['bound_inputs']['present_count'] + 1)
        self.assertEqual(second['bound_inputs']['by_role']['integration_test_source'],
                         first['bound_inputs']['by_role']['integration_test_source'] + 1)
        # git status (untracked files off) is blind to it; the inventory is not.
        self.assertEqual(batch.git_state()['status'], '')

    def test_a_removed_helper_is_recorded_by_the_next_fresh_run(self):
        first, second, entries, old_entries = self.fresh_run_records(
            lambda: (self.root / HELPER).unlink())
        self.changed_entry(entries, old_entries, HELPER, present=False,
                           old_entry_role='integration_test_source')
        self.assertNotIn(HELPER, second['bound_inputs']['absent'])
        self.assertNotIn(HELPER, {entry['path'] for entry in second['bound_input_inventory']})
        self.assertEqual(second['bound_inputs']['present_count'], first['bound_inputs']['present_count'] - 1)
        self.assertEqual(second['bound_inputs']['by_role']['integration_test_source'],
                         first['bound_inputs']['by_role']['integration_test_source'] - 1)
        self.assertEqual(second['bound_inputs']['total_bytes'],
                         first['bound_inputs']['total_bytes'] - len('pub fn helper() {}\n'))

    def test_a_config_change_is_recorded_by_the_next_fresh_run(self):
        text = '[build]\njobs = 8\n'
        first, second, entries, old_entries = self.fresh_run_records(
            lambda: self.write(CARGO_CONFIG, text))
        self.changed_entry(entries, old_entries, CARGO_CONFIG, text, old_entry_role='cargo_config')
        self.assertEqual(second['bound_inputs']['total_bytes'],
                         first['bound_inputs']['total_bytes'] - len(CARGO_CONFIG_TEXT) + len(text))
        # Config values are still never recorded, only their path and byte hash.
        recorded = json.dumps({'manifest': second, 'entries': entries})
        self.assertNotIn('jobs = 8', recorded)
        self.assertNotIn('jobs = 4', recorded)

    def test_a_removed_config_is_recorded_by_the_next_fresh_run(self):
        first, second, entries, old_entries = self.fresh_run_records(
            lambda: (self.root / CARGO_CONFIG).unlink())
        self.changed_entry(entries, old_entries, CARGO_CONFIG, present=False, old_entry_role='cargo_config')
        self.assertIn(CARGO_CONFIG, second['bound_inputs']['absent'])
        self.assertEqual(second['bound_inputs']['absent_count'], first['bound_inputs']['absent_count'] + 1)
        self.assertEqual(second['bound_inputs']['by_role']['cargo_config'], 0)

    def test_a_new_config_is_recorded_by_the_next_fresh_run(self):
        (self.root / CARGO_CONFIG).unlink()
        text = '[build]\njobs = 2\n'
        first, second, entries, old_entries = self.fresh_run_records(
            lambda: self.write(CARGO_CONFIG, text))
        self.assertEqual(old_entries[CARGO_CONFIG]['present'], False)
        self.changed_entry(entries, old_entries, CARGO_CONFIG, text, old_entry_role='cargo_config')
        self.assertNotIn(CARGO_CONFIG, second['bound_inputs']['absent'])
        self.assertEqual(second['bound_inputs']['by_role']['cargo_config'], 1)
        self.assertEqual(second['bound_inputs']['total_bytes'],
                         first['bound_inputs']['total_bytes'] + len(text))
        # A config added *while* a build runs is still an input that moved.
        (self.root / CARGO_CONFIG).unlink()
        self.assert_run_rejected([lambda: self.write(CARGO_CONFIG, text)], '.cargo/config.toml (changed)')

    def pinned_probe(self, channel):
        def probe(command, **kwargs):
            self.probe_calls.append(list(command))
            if command[:2] == ['rustup', 'show']:
                return mock.Mock(returncode=0, stdout=channel + '-x86_64-unknown-linux-gnu '
                                 '(overridden by rust-toolchain.toml)\n')
            if command == ['cargo', '--version']:
                return mock.Mock(returncode=0, stdout='cargo ' + channel + ' (fake)\n')
            raise AssertionError('unexpected tool probe: ' + repr(command))
        return probe

    def test_a_new_toolchain_pin_is_recorded_by_a_run_under_it(self):
        # The worktree pin is bound like any other input: a run that passes
        # under 1.98.0 records the pin's bytes and the digest measured from them.
        new_pin = '[toolchain]\nchannel = "1.98.0"\n'
        self.build(args=self.args())
        self.write('rust-toolchain.toml', new_pin)
        shutil.rmtree(self.target, ignore_errors=True)
        with mock.patch.object(batch, 'run_tool', self.pinned_probe('1.98.0')):
            second = self.build(args=self.args())
        self.assertEqual(second['toolchain']['pinned_channel'], '1.98.0')
        self.assertEqual(second['toolchain']['active_toolchain'],
                         '1.98.0-x86_64-unknown-linux-gnu (overridden by rust-toolchain.toml)')
        self.assertEqual(self.entries_of(second)['rust-toolchain.toml']['sha256'],
                         hashlib.sha256(new_pin.encode()).hexdigest())
        self.assertEqual(second['bound_inputs'], batch.bound_inputs_summary(*batch.bound_input_inventory()))

    def test_untracked_helper_is_bound_and_not_reported_by_git(self):
        # git status (untracked files off) is blind to a new helper, an empty
        # target/ has no earlier receipt to compare against: only the bound
        # inventory records it, and a later fresh run records its new bytes.
        text = 'pub fn untracked() {}\n'
        self.write(UNTRACKED_HELPER, text)
        report = self.build(args=self.args())
        entry = self.entries_of(report)[UNTRACKED_HELPER]
        self.assertEqual((entry['present'], entry['role']), (True, 'integration_test_source'))
        self.assertEqual(entry['sha256'], batch.sha256_file(self.root / UNTRACKED_HELPER))
        self.assertEqual(batch.git_state()['status'], '')
        edited = 'pub fn untracked() { /* edited */ }\n'
        first, second, entries, old_entries = self.fresh_run_records(
            lambda: self.write(UNTRACKED_HELPER, edited))
        self.assertEqual(old_entries[UNTRACKED_HELPER]['sha256'], entry['sha256'])
        self.changed_entry(entries, old_entries, UNTRACKED_HELPER, edited)
    # -- helpers ------------------------------------------------------------
    def test_manifest_parser_reads_features_bins_optional_dependencies(self):
        manifest = self.manifest()
        self.assertEqual(manifest['default_features'], ['kafka-wake'])
        self.assertEqual(manifest['features']['kafka-wake'], [])
        self.assertEqual(manifest['optional_features'], {})
        self.assertEqual([entry['name'] for entry in manifest['bins']], list(ALL_BINS))
        # A bin is declared by [[bin]] (required-features, the manifest naming
        # it) or by a source outside Cargo's auto-discovery roots; [[bin]]
        # metadata gives none of these for a bin with no required-features.
        self.assertFalse(manifest['bins'][0]['declared'])
        self.assertEqual({entry['name']: entry['required_features'] for entry in manifest['bins']},
                         {'rootyard': [], 'rootyard-pando-lab': ['pando-lab'],
                          'rootyard-view-lab': [], 'rootyard-workspace-lab': [], 'rootyard-vfs-mount': []})
        self.assertFalse(manifest['bins'][2]['declared'])
        self.assertEqual({entry['name']: entry['declared'] for entry in manifest['bins']},
                         {'rootyard': False, 'rootyard-pando-lab': True, 'rootyard-view-lab': False,
                          'rootyard-workspace-lab': False, 'rootyard-vfs-mount': True})
        # ...and a [[bin]] table that names a bin (or a source outside Cargo's
        # auto-discovery roots) makes it declared; metadata stays the source.
        self.write('Cargo.toml', CARGO_TOML.replace('[[bin]]\nname = "rootyard-vfs-mount"',
                                                    '[[bin]]\nname = "rootyard-view-lab"'))
        named = self.manifest()
        self.assertEqual({entry['name']: entry['declared'] for entry in named['bins']},
                         {'rootyard': False, 'rootyard-pando-lab': True, 'rootyard-view-lab': True,
                          'rootyard-workspace-lab': False, 'rootyard-vfs-mount': False})
        self.write('Cargo.toml', CARGO_TOML)
        # A [[test]] table Cargo metadata reports with its required-features.
        self.write('Cargo.toml', CARGO_TOML + '\n[[test]]\nname = "declared"\npath = "tests/declared.rs"\n'
                   'required-features = ["pando-lab"]\n')
        document = json.loads(self.metadata_json())
        document['packages'][0]['targets'].append(
            self.metadata_target('test', 'declared', 'tests/declared.rs', ['pando-lab']))
        with_test = batch.batch_manifest(batch.metadata_record(document))
        declared = next(entry for entry in with_test['tests'] if entry['name'] == 'declared')
        self.assertEqual((declared['source'], declared['required_features']),
                         (str(self.root / 'tests/declared.rs'), ['pando-lab']))

    def test_optional_dependency_without_explicit_feature_fails_closed(self):
        manifest = self.manifest(CARGO_TOML.replace('kafka-wake = ["dep:rdkafka"]', 'kafka-wake = []'))
        self.assertEqual(manifest['optional_features'], {'rdkafka': 'rdkafka'})
        with self.assertRaises(batch.BuildError) as caught:
            batch.plan_batch(self.args(), manifest)
        self.assertIn('rdkafka', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
