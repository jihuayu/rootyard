"""Offline contract tests for the v2 explicit batch producer.

These tests never invoke Cargo, rustc, rustup or a clean.  They run the real
batch transaction against a temporary workspace and fake Cargo JSON streams,
proving: one explicit invocation under the canonical flock; literal freshness
captured without forcing a rebuild; exact metadata target/source binding; shared
v2 receipts for bins and relocated tests; one frozen bound inventory in every
receipt and the manifest; atomic publication with the manifest last; and
fail-closed behaviour on every malformed stream, source change and unsafe path.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import build_native  # noqa: E402
import build_native_batch as batch  # noqa: E402
import native_build_receipt as receipt  # noqa: E402

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
"""
PACKAGE_ID = 'path+file:///ws#rootyard@0.1.0'
BINS = ('rootyard', 'rootyard-vfs-mount')
ALL_BINS = ('rootyard', 'rootyard-pando-lab', 'rootyard-view-lab', 'rootyard-vfs-mount')
AUTO_BINS = ('rootyard-view-lab',)
TESTS = ('example',)
HELPER = 'tests/helper/mod.rs'
CARGO_CONFIG = '.cargo/config.toml'
CARGO_CONFIG_TEXT = '[build]\njobs = 4\n[net]\nretry = 2\n'
COMMON_STRIP = ['--config', 'profile.dev.package.rootyard.strip="debuginfo"',
                '--config', 'profile.test.package.rootyard.strip="debuginfo"']
TRIPLE = 'x86_64-unknown-linux-gnu'
CARGO_COMMIT = '64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b'
ROOT = None


def fixture_root():
    return Path(os.path.join(os.environ.get('ROOTYARD_BATCH_FIXTURE_ROOT', '/nonexistent'), 'ws')).resolve()


class _Lines:
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


class FakeProcess:
    def __init__(self, lines, returncode=0, after=None):
        self.stdout = _Lines(lines, after)
        self.returncode = returncode

    def wait(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


def artifact(kind, name, package=PACKAGE_ID, fresh=False, executable=None,
             src_path=None, test_profile=None, target=None, **extra):
    if src_path is None:
        src_path = str(ROOT / ('src/lib.rs' if kind == 'lib' else
                               ('src/main.rs' if name == 'rootyard' and kind == 'bin'
                                else ('tests/' + name + '.rs' if kind == 'test'
                                      else 'src/bin/' + name + '.rs'))))
    target = target if target is not None else {'name': name, 'kind': [kind], 'src_path': src_path}
    return {'reason': 'compiler-artifact', 'package_id': package,
            'target': target,
            'profile': {'opt_level': '0', 'debuginfo': 2, 'debug_assertions': True,
                        'overflow_checks': True,
                        'test': kind == 'test' if test_profile is None else test_profile},
            'fresh': fresh,
            **({'executable': executable} if executable is not None else {}), **extra}


def finished(success=True):
    return {'reason': 'build-finished', 'success': success}


class BatchTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp(prefix='rootyard-build-batch-v2-'))
        self.addCleanup(shutil.rmtree, self.tempdir, True)
        self.root = Path(os.path.join(self.tempdir, 'ws')).resolve()
        global ROOT
        ROOT = self.root
        (self.root / 'src' / 'bin').mkdir(parents=True)
        (self.root / 'tests' / 'helper').mkdir(parents=True)
        (self.root / '.cargo').mkdir()
        (self.root / 'toolchain').mkdir()
        (self.root / 'Cargo.toml').write_text(CARGO_TOML)
        (self.root / 'Cargo.lock').write_text('version = 3\n')
        (self.root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.99.1"\n')
        (self.root / 'src' / 'lib.rs').write_text('pub fn hello() {}\n')
        (self.root / 'src' / 'main.rs').write_text('fn main() {}\n')
        for name in ALL_BINS[1:]:
            (self.root / 'src' / 'bin' / (name + '.rs')).write_text('fn main() {}\n')
        for name in TESTS:
            (self.root / 'tests' / (name + '.rs')).write_text('#[test]\nfn one() {}\n')
        (self.root / HELPER).write_text('pub fn helper() {}\n')
        (self.root / 'tests' / 'other.rs').write_text('#[test]\nfn other() {}\n')
        (self.root / CARGO_CONFIG).write_text(CARGO_CONFIG_TEXT)
        (self.root / 'build.rs').write_text('fn main() {}\n')
        asset = self.root / 'experimental' / 'pando' / 'schema.sql'
        asset.parent.mkdir(parents=True)
        shutil.copyfile(REPO_ROOT / 'experimental' / 'pando' / 'schema.sql', asset)
        for name in ('cargo', 'rustc', 'rustup'):
            (self.root / 'toolchain' / name).write_bytes(('fake-' + name).encode())
        self.outdir = Path(os.path.join(self.tempdir, 'test-results'))
        self.target = Path(os.path.join(self.root, 'target')).resolve()
        self.lock_path = self.target / build_native.LOCK_NAME
        self.popen_calls = []
        self.metadata_calls = []
        self.metadata_environments = []
        self.probe_environments = []
        self.metadata_directory = None
        self.metadata_document = None
        self.toolchain_sequence = None
        self.git_sequence = None
        self.addCleanup(mock.patch.stopall)
        self.cargo_home = self.tempdir / 'cargo-home'
        self.home = self.tempdir / 'home'
        self.cargo_home.mkdir()
        self.home.mkdir()
        mock.patch.dict(os.environ, {
            'CARGO_TARGET_DIR': 'target',
            'CARGO_HOME': str(self.cargo_home),
            'HOME': str(self.home),
        }, clear=True).start()
        mock.patch.object(build_native, 'ROOT', self.root).start()
        mock.patch.object(batch, 'probe_toolchain', self.fake_toolchain).start()
        mock.patch.object(batch, 'git_state', self.fake_git).start()
        mock.patch.object(batch.subprocess, 'check_output', self.fake_check_output).start()
        mock.patch.object(batch.subprocess, 'run', self.fail_run).start()

    # -- fake environment ---------------------------------------------------
    def fail_run(self, command, **kwargs):
        raise AssertionError(f'unexpected subprocess.run: {command}')

    def metadata_json(self, target_directory=None):
        targets = [self.metadata_target('lib', 'rootyard', 'src/lib.rs')]
        targets += [self.metadata_target('bin', name, self.bin_source(name),
                                         ['pando-lab'] if name == 'rootyard-pando-lab' else None)
                    for name in ALL_BINS]
        targets += [self.metadata_target('test', name, 'tests/' + name + '.rs') for name in TESTS]
        if self.metadata_document is not None:
            return json.dumps(self.metadata_document)
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
        return 'src/main.rs' if name == 'rootyard' else 'src/bin/' + name + '.rs'

    def metadata_target(self, kind, name, source, required_features=None):
        return {'kind': [kind], 'crate_types': [kind], 'name': name,
                'src_path': str(self.root / source), 'edition': '2024', 'doc': True,
                'doctest': False, 'test': True,
                'required-features': list(required_features or [])}

    def fake_check_output(self, command, *args, **kwargs):
        self.metadata_calls.append(list(command))
        self.metadata_environments.append(kwargs.get('env'))
        expected = ['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1', '--offline']
        if command != expected:
            raise AssertionError('unexpected check_output tool: ' + repr(command))
        return self.metadata_json(self.metadata_directory)

    def fake_toolchain(self, environment=None):
        self.probe_environments.append(environment)
        if self.toolchain_sequence is not None:
            value = self.toolchain_sequence.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value
        def identity(name, release, commit_hash, proxy=None):
            path = self.root / 'toolchain' / name
            result = {
                'executable': str(path),
                'executable_sha256': receipt.sha256_file(path),
                'version': f'{name} {release} (fake 2026-01-01)',
                'release': release,
                'commit_hash': commit_hash,
                'commit_date': '2026-01-01',
                'host': TRIPLE,
            }
            if proxy is not None:
                result['path_entry'] = str(path)
                result['proxy'] = proxy
            return result
        return {
            'cargo': identity('cargo', '1.101.0', CARGO_COMMIT),
            'rustc': identity('rustc', '1.99.1', 'd' * 40, proxy=False),
            'rustup': {
                'executable': str(self.root / 'toolchain/rustup'),
                'executable_sha256': receipt.sha256_file(self.root / 'toolchain/rustup'),
                'resolved_rustc': str(self.root / 'toolchain/rustc'),
                'resolved_rustc_sha256': receipt.sha256_file(self.root / 'toolchain/rustc'),
            },
            'target_triple': TRIPLE,
            'pinned_channel': '1.99.1',
            'pin_source': 'rust-toolchain.toml',
        }

    def fake_git(self):
        if self.git_sequence is not None:
            return self.git_sequence.pop(0)
        return {'head': 'a' * 40, 'commit': 'a' * 40,
                'tree': 'b' * 40, 'status': ' M src/lib.rs\n'}

    # -- fixture helpers ----------------------------------------------------
    def compiled_test(self, name):
        return str(self.target / 'debug' / 'deps' / (name + '-0123456789abcdef'))

    def binary(self, name):
        return str(self.target / 'debug' / name)

    def implicit_bins(self, bins, tests, features='pando-lab', no_default_features=False):
        if not tests:
            return ()
        enabled = set((features or '').split(','))
        if not no_default_features:
            enabled.add('kafka-wake')
        return tuple(name for name in ALL_BINS if name not in bins
                     and (name != 'rootyard-pando-lab' or 'pando-lab' in enabled))

    def default_events(self, bins=None, tests=None, fresh=False, lib=True, implicit=True,
                       features='pando-lab', no_default_features=False):
        bins = BINS if bins is None else tuple(bins)
        tests = TESTS if tests is None else tuple(tests)
        if implicit:
            bins = tuple(bins) + self.implicit_bins(bins, tests, features, no_default_features)
        events = [artifact('lib', 'rootyard', fresh=fresh)] if lib else []
        events += [artifact('bin', name, fresh=fresh, executable=self.binary(name)) for name in bins]
        events += [artifact('test', name, fresh=fresh, executable=self.compiled_test(name)) for name in tests]
        return events + [finished()]

    def write_executables(self, events):
        for event in events:
            executable = event.get('executable')
            if executable:
                path = Path(executable)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'#!bin\n' + event['target']['name'].encode())

    def fake_popen(self, events, returncode=0, after=None):
        def popen(command, **kwargs):
            self.popen_calls.append((list(command), kwargs))
            self.assert_cargo_holds_lock()
            self.write_executables(events)
            return FakeProcess([json.dumps(event) + '\n' for event in events],
                               returncode=returncode, after=after)
        return popen

    def assert_cargo_holds_lock(self):
        fd = os.open(self.lock_path, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError, msg='cargo ran outside the canonical flock'):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def args(self, bins=None, tests=TESTS, features='pando-lab', no_default_features=False,
             package_debug=None, strip_debuginfo=True, outputs=None, all_bins=False,
             manifest_out=None):
        bins = [] if all_bins else (BINS if bins is None else bins)
        outputs = outputs if outputs is not None else [
            str(os.path.join(self.outdir, name.replace('_', '-'))) for name in tests]
        return argparse.Namespace(features=features, no_default_features=no_default_features,
                                  package_debug=package_debug, strip_debuginfo=strip_debuginfo,
                                  all_bins=all_bins, bin=list(bins), bin_destination=[],
                                  test=list(tests), output=outputs,
                                  manifest_out=str(manifest_out or
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
        command += ['--message-format=json-render-diagnostics']
        if os.environ.get('CARGO_BUILD_JOBS'):
            command += ['--jobs', os.environ['CARGO_BUILD_JOBS']]
        return command

    def build(self, events=None, args=None, after=None, returncode=0):
        args = args or self.args()
        events = self.default_events(bins=args.bin, tests=args.test) if events is None else events
        with mock.patch.object(batch.subprocess, 'Popen',
                               self.fake_popen(events, returncode=returncode, after=after)):
            return batch.run_batch(args)

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
        self.assertEqual([str(path) for path in leftovers if path.exists()], [],
                         'a failed batch must not leave receipts, outputs or staging files')

    def assert_failure(self, events, message, args=None, **build_kwargs):
        args = args or self.args()
        self.seed_previous_batch(args)
        with self.assertRaises(batch.BuildError) as caught:
            self.build(events=events, args=args, **build_kwargs)
        self.assertIn(message, str(caught.exception))
        self.assert_nothing_published(args)
        return caught.exception

    # -- happy paths --------------------------------------------------------
    def test_one_explicit_build_no_clean_and_exact_command(self):
        args = self.args()
        report = self.build(args=args)
        self.assertEqual(len(self.popen_calls), 1)
        self.assertEqual(self.popen_calls[0][0], self.expected_command(args))
        self.assertEqual(self.popen_calls[0][1]['cwd'], self.root)
        self.assertEqual(report['build']['command'], self.popen_calls[0][0])
        self.assertEqual(report['build']['commands'], 1)
        self.assertNotIn('clean', report)
        self.assertNotIn('fresh_false_artifacts', report['build'])
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['kind'], 'rootyard/native-build-batch')
        self.assertEqual(report['manifest_version'], 2)
        self.assertEqual(json.loads(Path(args.manifest_out).read_text()), report)

    def test_manifest_v2_exact_fields_and_no_legacy_aliases(self):
        args = self.args()
        report = self.build(args=args)
        required = {
            'kind', 'manifest_version', 'status', 'source_commit', 'git_head',
            'working_tree', 'source_inputs_sha256', 'cargo_lock_sha256', 'config_digest',
            'bound_inputs', 'bound_input_inventory', 'toolchain', 'features', 'profile',
            'target_triple', 'selection', 'architecture', 'target_directory', 'lock_file',
            'cargo_metadata_target_directory', 'cargo_package_id', 'build_options',
            'build', 'artifacts', 'duration_seconds',
        }
        self.assertEqual(set(report), required)
        for banned in receipt.V2_BANNED_FIELDS + ('clean',):
            self.assertNotIn(banned, report)
        self.assertEqual(report['features'],
                         {'enabled': ['pando-lab'], 'no_default_features': False})
        self.assertEqual(report['profile'], 'test')
        self.assertEqual(report['target_triple'], TRIPLE)
        self.assertEqual(report['source_commit'], 'a' * 40)
        self.assertEqual(report['git_head'], 'a' * 40)
        self.assertEqual(report['working_tree'], {'tree': 'b' * 40, 'status': ' M src/lib.rs\n'})
        self.assertEqual(report['source_inputs_sha256'],
                         receipt.source_digest(self.root))
        self.assertEqual(report['cargo_lock_sha256'],
                         receipt.sha256_file(self.root / 'Cargo.lock'))
        self.assertEqual(report['config_digest'],
                         receipt.config_digest_from_entries(report['bound_input_inventory']))
        self.assertEqual(report['toolchain']['cargo']['commit_hash'], CARGO_COMMIT)
        self.assertEqual(report['build_options'], {'jobs': None})
        self.assertEqual([row['kind'] for row in report['build']['cargo_artifacts']],
                         ['lib'] + ['bin'] * len(BINS + self.implicit_bins(BINS, TESTS)) + ['test'])
        self.assertEqual(report['artifacts'][-1]['kind'], 'test')
        self.assertEqual(report['artifacts'][-1]['source'], 'tests/example.rs')
        self.assertEqual(report['artifacts'][-1]['sha256'],
                         receipt.sha256_file(self.compiled_test(TESTS[0])))

    def test_cache_hit_true_and_false_freshness_are_captured_truthfully(self):
        for fresh in (True, False):
            with self.subTest(fresh=fresh):
                self.popen_calls = []
                report = self.build(events=self.default_events(fresh=fresh))
                self.assertEqual({entry['fresh'] for entry in report['artifacts']}, {fresh})
                self.assertEqual({row['fresh'] for row in report['build']['cargo_artifacts']},
                                 {fresh})
                bin_receipt = json.loads((self.target / 'debug' / 'rootyard.build.json').read_text())
                self.assertEqual({row['fresh'] for row in bin_receipt['cargo_artifacts']}, {fresh})
                test_receipt = json.loads(Path(self.args().output[0] + '.build.json').read_text())
                self.assertIs(test_receipt['cargo_artifacts'][0]['fresh'], fresh)

    def test_bin_receipt_is_shared_v2_with_batch_link(self):
        args = self.args()
        report = self.build(args=args)
        path = self.target / 'debug' / 'rootyard.build.json'
        stored = json.loads(path.read_text())
        self.assertEqual(stored['receipt_schema'], receipt.RECEIPT_SCHEMA_V2)
        for banned in receipt.V2_BANNED_FIELDS:
            self.assertNotIn(banned, stored)
        self.assertEqual(stored['kind'], 'native-build-batch-bin')
        self.assertEqual(stored['binary_sha256'], receipt.sha256_file(self.binary('rootyard')))
        self.assertEqual(stored['workspace_commit'], 'a' * 40)
        self.assertEqual(stored['git_head'], 'a' * 40)
        self.assertEqual(stored['command'], report['build']['command'])
        self.assertEqual(stored['profile'], 'test')
        self.assertEqual(stored['target_dir'], str(self.target))
        self.assertEqual(stored['batch']['kind'], receipt.BATCH_KIND)
        self.assertEqual(stored['batch']['receipt_version'], 2)
        self.assertEqual(stored['batch']['binary'], 'rootyard')
        self.assertEqual(stored['batch']['manifest'], str(Path(args.manifest_out).resolve()))
        self.assertEqual(stored['batch']['targets'],
                         ['rootyard'] + [name for name in BINS + self.implicit_bins(BINS, TESTS)])
        self.assertEqual(stored['bound_inputs'], report['bound_inputs'])
        self.assertEqual(stored['bound_input_inventory'], report['bound_input_inventory'])
        self.assertEqual(stored['batch']['bound_inputs_sha256'], stored['bound_inputs']['digest'])
        self.assertEqual([row['kind'] for row in stored['cargo_artifacts']],
                         ['lib'] + ['bin'] * len(BINS + self.implicit_bins(BINS, TESTS)))
        self.assertTrue(all(row['source_sha256'] for row in stored['cargo_artifacts']))
        self.assertTrue(all(row['executable_sha256'] for row in stored['cargo_artifacts']
                            if row['kind'] == 'bin'))
        self.assertNotIn('implicit_build', stored)

    def test_test_receipt_binds_exact_source_and_original_and_relocated_digests(self):
        args = self.args()
        report = self.build(args=args)
        output = Path(args.output[0])
        stored = json.loads(output.with_suffix('.build.json').read_text())
        self.assertEqual(stored['kind'], 'rust-integration-test')
        self.assertIs(stored['relocated_artifact'], True)
        self.assertEqual(stored['cargo_artifacts'][0]['kind'], 'test')
        self.assertEqual(stored['cargo_artifacts'][0]['source'], 'tests/example.rs')
        self.assertEqual(stored['cargo_artifacts'][0]['executable'],
                         self.compiled_test(TESTS[0]))
        self.assertEqual(stored['cargo_artifacts'][0]['profile']['test'], True)
        self.assertEqual(stored['original_artifact_sha256'],
                         receipt.sha256_file(self.compiled_test(TESTS[0])))
        self.assertEqual(stored['binary_sha256'], receipt.sha256_file(output))
        self.assertEqual(stored['binary_sha256'], stored['original_artifact_sha256'])
        self.assertEqual(stored['integration_test_source'], 'tests/example.rs')
        self.assertEqual(stored['integration_test_source_sha256'],
                         receipt.sha256_file(self.root / 'tests' / 'example.rs'))
        self.assertEqual(stored['batch']['binary'], output.name)
        self.assertEqual(stored['batch']['targets'][-1], TESTS[0])
        self.assertEqual(stored['batch']['bound_inputs_sha256'], stored['bound_inputs']['digest'])
        self.assertEqual(output.read_bytes(), Path(self.compiled_test(TESTS[0])).read_bytes())
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertNotEqual(os.stat(output).st_ino,
                            os.stat(self.compiled_test(TESTS[0])).st_ino)
        self.assertTrue(Path(self.compiled_test(TESTS[0])).is_file())
        self.assertEqual(report['artifacts'][-1]['sha256'], receipt.sha256_file(output))

    def test_jobs_are_explicit_and_normalized_environment_is_used(self):
        os.environ['CARGO_BUILD_JOBS'] = '2'
        try:
            args = self.args()
            expected = self.expected_command(args)
            report = self.build(args=args)
        finally:
            os.environ.pop('CARGO_BUILD_JOBS', None)
        command, kwargs = self.popen_calls[0]
        self.assertEqual(command[-2:], ['--jobs', '2'])
        self.assertEqual(command, expected)
        self.assertNotIn('CARGO_BUILD_JOBS', kwargs['env'])
        self.assertEqual(kwargs['env']['CARGO_TARGET_DIR'], 'target')
        self.assertTrue(self.metadata_environments)
        self.assertTrue(all(env is not None and 'CARGO_BUILD_JOBS' not in env
                            for env in self.metadata_environments))
        self.assertTrue(all(env is not None and 'CARGO_BUILD_JOBS' not in env
                            for env in self.probe_environments))
        self.assertEqual(report['build_options'], {'jobs': 2})
        self.assertEqual(report['build']['command'][-2:], ['--jobs', '2'])

    # -- environment/config refusals ---------------------------------------
    def test_rejected_environment_fails_before_metadata_or_build(self):
        sentinel = 'sentinel-do-not-display'
        for name in ('RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_PROFILE_DEV_LTO',
                     'CARGO_BUILD_TARGET', 'CARGO_BUILD_JOBS'):
            with self.subTest(name=name):
                self.metadata_calls = []
                self.popen_calls = []
                with mock.patch.dict(os.environ, {name: sentinel if name != 'CARGO_BUILD_JOBS' else '0'}):
                    with self.assertRaises(batch.BuildError) as caught:
                        batch.run_batch(self.args())
                self.assertIn(name, str(caught.exception))
                self.assertNotIn(sentinel, str(caught.exception))
                self.assertEqual(self.metadata_calls, [])
                self.assertEqual(self.popen_calls, [])

    def test_external_and_in_repository_redirect_configs_are_refused(self):
        config = self.cargo_home / 'config.toml'
        config.write_text('[build]\nrustc = "sentinel"\n')
        with self.assertRaises(batch.BuildError) as caught:
            batch.run_batch(self.args())
        self.assertIn(os.path.abspath(str(config)), str(caught.exception))
        self.assertNotIn('sentinel', str(caught.exception))
        self.assertEqual(self.popen_calls, [])
        config.unlink()
        (self.root / CARGO_CONFIG).write_text('[build]\ntarget = "sentinel"\n')
        with self.assertRaises(batch.BuildError) as caught:
            batch.run_batch(self.args())
        self.assertIn('build.target', str(caught.exception))
        self.assertNotIn('sentinel', str(caught.exception))
        self.assertEqual(self.popen_calls, [])

    def test_metadata_target_directory_must_be_the_locked_one(self):
        self.metadata_directory = self.root / 'other'
        with self.assertRaises(batch.BuildError) as caught:
            batch.run_batch(self.args())
        self.assertIn('would not be serialized by this lock', str(caught.exception))
        self.assertEqual(self.popen_calls, [])
        self.assertEqual(len(self.metadata_calls), 1)

    # -- artifact selection refusals ---------------------------------------
    def test_missing_duplicate_and_extra_artifacts_are_refused(self):
        self.assert_failure(self.default_events(lib=False), 'did not report a rootyard lib')
        missing_tests = self.default_events(tests=(), implicit=False)
        missing_tests += [artifact('bin', name, executable=self.binary(name))
                          for name in self.implicit_bins(BINS, TESTS)]
        self.assert_failure(missing_tests,
                            'did not report the requested test artifacts')
        self.assert_failure(self.default_events(bins=('rootyard-vfs-mount',), implicit=False),
                            'did not report the requested binaries: rootyard')
        duplicate = self.default_events() + [artifact('test', TESTS[0],
                                                      executable=self.compiled_test(TESTS[0]))]
        self.assert_failure(duplicate, 'duplicate')
        unlisted = self.default_events() + [
            artifact('test', 'other', executable=self.compiled_test('other'))]
        self.assert_failure(unlisted, 'test other that cargo metadata does not list')

    def test_bin_and_test_identity_paths_are_exact(self):
        events = self.default_events()
        events[1] = artifact('bin', 'rootyard')
        self.assert_failure(events, 'has no executable path')
        events = self.default_events()
        events[1] = artifact('bin', 'rootyard', executable=str(self.root / 'elsewhere' / 'rootyard'))
        Path(events[1]['executable']).parent.mkdir(parents=True, exist_ok=True)
        Path(events[1]['executable']).write_bytes(b'wrong')
        self.assert_failure(events, 'not at its canonical location')
        events = self.default_events()
        index = next(i for i, event in enumerate(events)
                     if event['target'].get('name') == 'rootyard-view-lab')
        events[index]['target']['src_path'] = str(self.root / 'tests' / 'other.rs')
        self.assert_failure(events, 'but cargo metadata lists its source as')
        no_source = self.default_events()
        next(event for event in no_source
             if event['target'].get('name') == 'rootyard')['target'].pop('src_path')
        self.assert_failure(no_source, 'without a target src_path')

    def test_freshness_absent_or_non_boolean_is_refused(self):
        for value in (None, 0, 1, 'true', [], {}):
            with self.subTest(value=value):
                events = self.default_events()
                events[0]['fresh'] = value
                self.seed_previous_batch()
                with self.assertRaises(batch.BuildError) as caught:
                    self.build(events=events)
                self.assertIn('non-boolean freshness', str(caught.exception))
                self.assert_nothing_published()

    def test_build_finished_cargo_failure_and_non_json_are_refused(self):
        self.assert_failure(self.default_events()[:-1], 'build-finished')
        failed = self.default_events()
        failed[-1] = finished(False)
        self.assert_failure(failed, 'build-finished')
        self.assert_failure(None, 'cargo build failed with status 7', returncode=7)

        class Raw:
            def __init__(self):
                self.stdout = _Lines(['not json\n'], None)
                self.returncode = 0

            def wait(self):
                return 0

            def kill(self):
                pass

        with mock.patch.object(batch.subprocess, 'Popen', lambda *a, **k: Raw()):
            with self.assertRaisesRegex(batch.BuildError, 'non-JSON'):
                batch.run_batch(self.args())
        self.assert_nothing_published()

    # -- before/after bindings ---------------------------------------------
    def test_source_lock_test_config_and_head_changes_are_refused(self):
        cases = [
            (lambda: (self.root / 'src/lib.rs').write_text('pub fn hello() { /* changed */ }\n'),
             'Source inputs changed during build'),
            (lambda: (self.root / 'Cargo.lock').write_text('version = 4\n'),
             'Source inputs changed during build'),
            (lambda: (self.root / 'tests/example.rs').write_text('#[test]\nfn changed() {}\n'),
             'integration-test source example changed'),
            (lambda: (self.root / CARGO_CONFIG).write_text('[build]\njobs = 8\n'),
             'config, build-script or toolchain inputs changed'),
            (lambda: (self.root / HELPER).write_text('pub fn helper() { /* changed */ }\n'),
             'bound build inputs changed'),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                self.assert_failure(None, message, after=mutate)
        before = {'head': 'a' * 40, 'commit': 'a' * 40, 'tree': 'b' * 40, 'status': ''}
        self.git_sequence = [before, dict(before, status=' M src/lib.rs\n')]
        self.assert_failure(None, 'HEAD or working-tree state changed')

    def test_toolchain_identity_change_is_refused(self):
        before = self.fake_toolchain({})
        after = json.loads(json.dumps(before))
        after['cargo']['executable_sha256'] = '0' * 64
        self.toolchain_sequence = [before, after]
        self.assert_failure(None, 'Toolchain identity changed')

    # -- implicit bins ------------------------------------------------------
    def test_implicit_bins_are_recorded_and_marked(self):
        args = self.args()
        report = self.build(args=args)
        bins = [entry for entry in report['artifacts'] if entry['kind'] == 'bin']
        expected_implicit = self.implicit_bins(BINS, TESTS)
        self.assertEqual([(entry['target'], entry['implicit']) for entry in bins],
                         [(name, False) for name in BINS] +
                         [(name, True) for name in expected_implicit])
        for entry in bins:
            stored = json.loads(Path(entry['receipt']).read_text())
            self.assertEqual(stored['binary_sha256'], receipt.sha256_file(entry['artifact']))
            if entry['implicit']:
                self.assertEqual(stored['batch']['binary'], entry['target'])
                self.assertEqual(stored['implicit_build']['acceptance'], 'not-server-acceptance')
                self.assertEqual(stored['implicit_build']['target_source'], entry['target_source'])
            else:
                self.assertNotIn('implicit_build', stored)

    # -- relocation and atomic publication ---------------------------------
    def test_test_output_is_independent_copy_and_survives_cache_eviction(self):
        args = self.args()
        self.build(args=args)
        for output, name in zip(args.output, args.test):
            output = Path(output)
            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(output.read_bytes(), Path(self.compiled_test(name)).read_bytes())
            self.assertNotEqual(os.stat(output).st_ino, os.stat(self.compiled_test(name)).st_ino)
            Path(self.compiled_test(name)).unlink()
            self.assertTrue(output.is_file())

    def test_publication_replaces_previous_batch_and_manifest_is_last(self):
        args = self.args()
        self.seed_previous_batch(args)
        seen = []
        real_replace = os.replace

        def record(source, destination, *arguments, **keywords):
            seen.append((Path(source), Path(destination)))
            return real_replace(source, destination, *arguments, **keywords)

        with mock.patch.object(batch.os, 'replace', record):
            report = self.build(args=args)
        self.assertEqual(seen[-1][1], Path(args.manifest_out).resolve())
        earlier = {destination for _, destination in seen[:-1]}
        for output in args.output:
            self.assertIn(Path(output).resolve(), earlier)
            self.assertIn(Path(output + '.build.json').resolve(), earlier)
        self.assertEqual(json.loads(Path(args.manifest_out).read_text()), report)
        self.assertFalse([path for path in Path(self.tempdir).rglob('*.batch-new')],
                         'publication must not leave staging siblings behind')
        self.assertEqual(Path(args.output[0]).read_bytes(),
                         Path(self.compiled_test(TESTS[0])).read_bytes())

    def test_failed_batch_withdraws_previous_receipts_outputs_and_staging(self):
        args = self.args()
        self.seed_previous_batch(args)
        for path in self.implicit_receipts(args.bin, args.test, args.manifest_out):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"stale": true}\n')
        missing_tests = self.default_events(tests=(), implicit=False)
        missing_tests += [artifact('bin', name, executable=self.binary(name))
                          for name in self.implicit_bins(BINS, TESTS)]
        self.assert_failure(missing_tests,
                            'did not report the requested test artifacts')
        self.assert_nothing_published(args)

    def test_cross_directory_staging_happens_in_the_destination_directory(self):
        volume = self.outdir / 'volume'
        volume.mkdir(parents=True)
        outputs = [str(volume / 'example')]
        args = self.args(outputs=outputs)
        seen = []
        real_replace = os.replace

        def record(source, destination, *arguments, **keywords):
            source, destination = Path(source), Path(destination)
            if destination == Path(outputs[0]) or destination == Path(outputs[0] + '.build.json'):
                self.assertEqual(source.parent, destination.parent)
            seen.append((source, destination))
            return real_replace(source, destination, *arguments, **keywords)

        with mock.patch.object(batch.os, 'replace', record):
            report = self.build(args=args)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(Path(outputs[0]).read_bytes(),
                         Path(self.compiled_test(TESTS[0])).read_bytes())
        self.assertTrue(any(destination == Path(outputs[0]).resolve() for _, destination in seen))

    # -- planning and selection ---------------------------------------------
    def test_planning_refuses_unknown_targets_outputs_and_duplicates(self):
        def planning_failure(args, message):
            self.metadata_calls = []
            self.popen_calls = []
            with self.assertRaises(batch.BuildError) as caught:
                batch.run_batch(args)
            self.assertIn(message, str(caught.exception))
            self.assertEqual(self.popen_calls, [])

        planning_failure(self.args(bins=('rootyard-ghost',)), 'not a bin target')
        planning_failure(self.args(tests=('ghost',), outputs=[str(self.outdir / 'x')]),
                         'metadata does not list the test target ghost')
        planning_failure(self.args(outputs=[str(self.target / 'debug' / 'x')]),
                         'outside CARGO_TARGET_DIR')
        planning_failure(self.args(outputs=[str(self.outdir / 'a'), str(self.outdir / 'a')]),
                         'repeats')
        planning_failure(self.args(tests=(), outputs=[], bins=()), 'select at least one')
        (self.root / 'tests' / 'example.rs').unlink()
        planning_failure(self.args(), 'integration-test source is missing')

    def test_metadata_only_non_lib_bin_test_target_is_refused(self):
        document = json.loads(self.metadata_json())
        document['packages'][0]['targets'].append(
            self.metadata_target('custom-build', 'build-script-build', 'build.rs'))
        self.metadata_document = document
        with self.assertRaises(batch.BuildError) as caught:
            batch.run_batch(self.args())
        self.assertIn('only lib, bin and test targets', str(caught.exception))
        self.assertEqual(self.popen_calls, [])

    def test_all_bins_selects_every_enabled_metadata_bin(self):
        args = self.args(all_bins=True, bins=())
        report = self.build(args=args)
        self.assertEqual([entry['target'] for entry in report['artifacts'] if entry['kind'] == 'bin'],
                         list(ALL_BINS))
        self.assertEqual({entry['implicit'] for entry in report['artifacts']
                          if entry['kind'] == 'bin'}, {False})
        for name in ALL_BINS:
            self.assertIn(['--bin', name], [self.popen_calls[0][0][index:index + 2]
                                            for index in range(len(self.popen_calls[0][0]))])

    def test_selection_required_features_are_enforced(self):
        args = self.args(bins=('rootyard', 'rootyard-pando-lab'), features='kafka-wake')
        with mock.patch.object(batch, 'cargo_metadata', return_value=batch.metadata_record(
                json.loads(self.metadata_json()))):
            with self.assertRaises(batch.BuildError) as caught:
                batch.run_batch(args)
        self.assertIn('requires features pando-lab', str(caught.exception))
        self.assertEqual(self.popen_calls, [])

    # -- fresh rerun and inventory ------------------------------------------
    def test_fresh_rerun_records_changed_helper_and_config_without_clean(self):
        args = self.args()
        first = self.build(args=args)
        old_digest = first['bound_inputs']['digest']
        (self.root / HELPER).write_text('pub fn helper() { /* changed */ }\n')
        (self.root / CARGO_CONFIG).write_text('[build]\njobs = 8\n[net]\nretry = 3\n')
        second = self.build(args=args)
        entries = {entry['path']: entry for entry in second['bound_input_inventory']}
        self.assertEqual(entries[HELPER]['sha256'],
                         hashlib.sha256((self.root / HELPER).read_bytes()).hexdigest())
        self.assertEqual(entries[CARGO_CONFIG]['sha256'],
                         hashlib.sha256((self.root / CARGO_CONFIG).read_bytes()).hexdigest())
        self.assertNotEqual(second['bound_inputs']['digest'], old_digest)
        self.assertEqual(second['source_inputs_sha256'], first['source_inputs_sha256'])
        for name in args.bin:
            stored = json.loads((self.target / 'debug' / (name + '.build.json')).read_text())
            self.assertEqual(stored['bound_inputs'], second['bound_inputs'])
            self.assertEqual(stored['bound_input_inventory'], second['bound_input_inventory'])
        test_receipt = json.loads(Path(args.output[0] + '.build.json').read_text())
        self.assertEqual(test_receipt['bound_inputs'], second['bound_inputs'])
        self.assertEqual(test_receipt['bound_input_inventory'], second['bound_input_inventory'])
        self.assertEqual(len(self.popen_calls), 2)


if __name__ == '__main__':
    unittest.main()
