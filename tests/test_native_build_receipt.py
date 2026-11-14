"""Offline contract tests for the v2 explicit producer scripts/build_native.py.

These tests never invoke Cargo, rustc or rustup. They exercise the build
transaction against a temporary workspace/target directory and fake Cargo JSON
event streams, then prove the receipt is the shared v2 contract, freshness is
copied literally and never forced, the previous receipt is invalidated on every
failure path, and installation is atomic under the target-directory flock.
"""
import argparse
import errno
import fcntl
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import shutil
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
import native_build_receipt as receipt  # noqa: E402


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


def _artifact(kind, fresh=False, executable=None, src_path=None,
              package_id='rootyard 0.1.0', profile=None):
    event = {
        'reason': 'compiler-artifact',
        'package_id': package_id,
        'target': {'name': 'rootyard', 'kind': [kind], 'src_path': str(src_path)},
        'fresh': fresh,
        'profile': profile or {
            'opt_level': '0', 'debuginfo': 2, 'debug_assertions': True,
            'overflow_checks': True, 'test': False,
        },
    }
    if executable is not None:
        event['executable'] = str(executable)
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


TOOLCHAIN_TRIPLE = 'x86_64-unknown-linux-gnu'
CARGO_COMMIT = '64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b'


class BuildReceiptTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp(prefix='rootyard-build-receipt-v2-'))
        self.addCleanup(shutil.rmtree, self.tempdir, ignore_errors=True)
        self.external = Path(tempfile.mkdtemp(prefix='rootyard-build-receipt-cas-'))
        self.addCleanup(shutil.rmtree, self.external, ignore_errors=True)
        self.store = self.external / 'store'
        self.root = self.tempdir.resolve()
        (self.root / 'src').mkdir()
        (self.root / 'tests' / 'fixtures').mkdir(parents=True)
        (self.root / '.cargo').mkdir()
        (self.root / 'toolchain').mkdir()
        (self.root / 'Cargo.toml').write_text('[package]\nname = "rootyard"\n')
        (self.root / 'Cargo.lock').write_text('version = 3\n')
        (self.root / 'build.rs').write_text('fn main() {}\n')
        (self.root / 'src' / 'main.rs').write_text('fn main() {}\n')
        (self.root / 'src' / 'lib.rs').write_text('pub fn hello() {}\n')
        (self.root / 'tests' / 'example.rs').write_text('#[test]\nfn one() {}\n')
        (self.root / 'tests' / 'fixtures' / 'data.txt').write_text('fixture\n')
        (self.root / 'experimental' / 'pando').mkdir(parents=True)
        shutil.copyfile(SCRIPTS.parent / 'experimental' / 'pando' / 'schema.sql',
                        self.root / 'experimental' / 'pando' / 'schema.sql')
        (self.root / '.cargo' / 'config.toml').write_text('[build]\njobs = 4\n')
        (self.root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.99.1"\n')
        for name, content in (('cargo', b'fake-cargo'), ('rustc', b'fake-rustc'),
                              ('rustup', b'fake-rustup')):
            (self.root / 'toolchain' / name).write_bytes(content)
        # A relative CARGO_TARGET_DIR exercises canonical_target() resolution.
        self.environment = mock.patch.dict(
            os.environ,
            {'CARGO_TARGET_DIR': 'target',
             'HOME': str(self.tempdir / 'home'),
             'CARGO_HOME': str(self.tempdir / 'cargo-home')},
            clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        (self.tempdir / 'home').mkdir()
        (self.tempdir / 'cargo-home').mkdir()
        patchers = [
            mock.patch.object(build_native, 'ROOT', self.root),
            mock.patch.object(build_native, 'probe_toolchain', self.fake_toolchain),
            mock.patch.object(build_native, 'git_state', self.fake_git),
            mock.patch.object(build_native.subprocess, 'run', self.fail_run),
            mock.patch.object(build_native.subprocess, 'check_output', self.fail_check_output),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.target = (self.root / 'target').resolve()
        self.binary = self.target / 'debug' / 'rootyard'
        self.receipt = self.binary.with_suffix('.build.json')
        self.temporary = self.receipt.with_name('.' + self.receipt.name + '.tmp')
        self.popen_calls = []
        self.lock_violations = []
        self.probe_sequences = None
        self.git_sequences = None

    # -- fake subprocess surface -------------------------------------------
    def fail_run(self, command, **kwargs):
        raise AssertionError(f'unexpected subprocess.run: {command}')

    def fail_check_output(self, command, **kwargs):
        raise AssertionError(f'unexpected subprocess.check_output: {command}')

    def fake_toolchain(self, environment):
        values = self.probe_sequences
        if values is not None:
            value = values.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value
        def identity(name, release, commit_hash, proxy=None):
            executable = self.root / 'toolchain' / name
            result = {
                'executable': str(executable),
                'executable_sha256': receipt.sha256_file(executable),
                'version': f'{name} {release} (fake 2026-01-01)',
                'release': release,
                'commit_hash': commit_hash,
                'commit_date': '2026-01-01',
                'host': TOOLCHAIN_TRIPLE,
            }
            if proxy is not None:
                result['path_entry'] = str(executable)
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
            'target_triple': TOOLCHAIN_TRIPLE,
            'pinned_channel': '1.99.1',
            'pin_source': 'rust-toolchain.toml',
        }

    def fake_git(self):
        values = self.git_sequences
        if values is not None:
            return values.pop(0)
        return {'head': 'a' * 40, 'commit': 'a' * 40,
                'tree': 'b' * 40, 'status': ' M src/lib.rs\n'}

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
    def args(features=None, bins=False, package_debug=None, no_default_features=False,
             strip_debuginfo=False, artifact_store=None, output=None):
        return argparse.Namespace(
            features=features,
            bins=bins,
            package_debug=package_debug,
            no_default_features=no_default_features,
            strip_debuginfo=strip_debuginfo,
            artifact_store=artifact_store,
            output=output,
        )

    def events(self, fresh=False, executable=None, kinds=('lib', 'bin'), lib_fresh=None,
               bin_fresh=None):
        executable = str(self.binary) if executable is None else executable
        lib_fresh = fresh if lib_fresh is None else lib_fresh
        bin_fresh = fresh if bin_fresh is None else bin_fresh
        result = []
        for kind in kinds:
            if kind == 'lib':
                result.append(_artifact('lib', fresh=lib_fresh,
                                        src_path=self.root / 'src' / 'lib.rs'))
            else:
                result.append(_artifact('bin', fresh=bin_fresh, executable=executable,
                                        src_path=self.root / 'src' / 'main.rs'))
        result.append({'reason': 'build-finished', 'success': True})
        return result

    def build(self, events, args=None, **popen_kwargs):
        popen = self.make_popen(events, **popen_kwargs)
        with mock.patch.object(build_native.subprocess, 'Popen', popen):
            return build_native.run_build(self.args() if args is None else args)

    def assert_no_receipt(self):
        self.assertFalse(self.receipt.exists(), 'a receipt survived a failed build')
        self.assertFalse(self.temporary.exists(), 'a temporary receipt was left behind')

    def seed_stale_receipt(self):
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        self.receipt.write_text('{"stale": true}\n')

    # -- happy path ---------------------------------------------------------
    def test_cache_hit_fresh_true_and_false_are_both_accepted_without_clean(self):
        for lib_fresh, bin_fresh in ((True, True), (False, False), (True, False), (False, True)):
            with self.subTest(lib=lib_fresh, bin=bin_fresh):
                self.popen_calls = []
                report = self.build(self.events(lib_fresh=lib_fresh, bin_fresh=bin_fresh))
                self.assertEqual(self.lock_violations, [])
                self.assertEqual(len(self.popen_calls), 1)
                self.assertEqual([item['fresh'] for item in report['cargo_artifacts']],
                                 [lib_fresh, bin_fresh])
                receipt_on_disk = json.loads(self.receipt.read_text())
                self.assertEqual(receipt_on_disk, report)

    def test_exact_command_and_no_cargo_clean(self):
        report = self.build(self.events())
        command, kwargs = self.popen_calls[0]
        self.assertEqual(command, [
            'cargo', 'build', '--locked', '--bin', 'rootyard',
            '--message-format=json-render-diagnostics',
        ])
        self.assertEqual(kwargs['cwd'], self.root)
        self.assertNotIn('clean', command)
        self.assertEqual(report['command'], command)
        self.assertFalse([path for path in self.root.rglob('*') if path.name == 'clean'])

    def test_v2_receipt_binds_source_config_test_lock_toolchain_command_profile(self):
        report = self.build(self.events(lib_fresh=True, bin_fresh=False))
        self.assertEqual(report['receipt_schema'], receipt.RECEIPT_SCHEMA_V2)
        for banned in receipt.V2_BANNED_FIELDS:
            self.assertNotIn(banned, report)
        self.assertEqual(report['binary_sha256'], receipt.sha256_file(self.binary))
        self.assertEqual(report['workspace_commit'], 'a' * 40)
        self.assertEqual(report['git_head'], 'a' * 40)
        self.assertEqual(report['working_tree'], {'tree': 'b' * 40, 'status': ' M src/lib.rs\n'})
        self.assertEqual(report['source_inputs_sha256'],
                         receipt.source_digest(self.root))
        self.assertEqual(report['cargo_lock_sha256'],
                         receipt.sha256_file(self.root / 'Cargo.lock'))
        self.assertEqual(report['config_digest'],
                         receipt.config_digest_from_entries(report['bound_input_inventory']))
        self.assertEqual(report['command'], self.popen_calls[0][0])
        self.assertEqual(report['profile'], 'dev')
        self.assertEqual(report['target_triple'], TOOLCHAIN_TRIPLE)
        self.assertEqual(report['target_dir'], str(self.target))
        self.assertEqual(report['features'], {'enabled': [], 'no_default_features': False})
        self.assertEqual(report['lock_file'], str(self.target / build_native.LOCK_NAME))
        self.assertEqual(report['toolchain']['cargo']['commit_hash'], CARGO_COMMIT)
        self.assertEqual(report['toolchain']['rustc']['proxy'], False)
        self.assertEqual(report['toolchain']['rustc']['executable_sha256'],
                         receipt.sha256_file(self.root / 'toolchain' / 'rustc'))
        self.assertEqual([row['kind'] for row in report['cargo_artifacts']], ['lib', 'bin'])
        self.assertEqual(report['cargo_artifacts'][1]['source'], 'src/main.rs')
        self.assertEqual(report['cargo_artifacts'][1]['executable'], str(self.binary.resolve()))
        self.assertEqual(report['cargo_artifacts'][1]['executable_sha256'],
                         receipt.sha256_file(self.binary))
        self.assertEqual(report['cargo_artifacts'][0]['executable_sha256']
                         if 'executable_sha256' in report['cargo_artifacts'][0] else None, None)
        self.assertEqual(report['kind'], 'native-binary')
        self.assertEqual(report['build_options'], {'jobs': None})
        self.assertIn({'path': 'tests/example.rs', 'role': 'integration_test_source',
                       'present': True, 'sha256': receipt.sha256_file(self.root / 'tests' / 'example.rs')},
                      report['bound_input_inventory'])

    def test_minimal_profile_flags_are_explicit_and_recorded_in_receipt(self):
        args = self.args(no_default_features=True, package_debug='1')
        report = self.build(self.events(), args=args)
        command, _ = self.popen_calls[0]
        self.assertEqual(command, [
            'cargo', 'build', '--locked', '--no-default-features',
            '--config', 'profile.dev.package.rootyard.debug=1',
            '--bin', 'rootyard', '--message-format=json-render-diagnostics',
        ])
        self.assertEqual(report['command'], command)
        self.assertEqual(report['features'], {'enabled': [], 'no_default_features': True})

    def test_ci_profile_bins_pando_lab_and_strip_debuginfo_are_recorded_verbatim(self):
        args = self.args(bins=True, features='pando-lab', strip_debuginfo=True)
        report = self.build(self.events(), args=args)
        command, kwargs = self.popen_calls[0]
        self.assertEqual(command, [
            'cargo', 'build', '--locked', '--bins',
            '--features', 'pando-lab',
            '--config', 'profile.dev.package.rootyard.strip="debuginfo"',
            '--message-format=json-render-diagnostics',
        ])
        self.assertEqual(kwargs['cwd'], self.root)
        self.assertEqual(report['command'], command)
        self.assertEqual(report['features'], {'enabled': ['pando-lab'], 'no_default_features': False})
        self.assertEqual(report['cargo_artifacts'][0]['fresh'], False)

    # -- CAS opt-in ---------------------------------------------------------
    def test_artifact_store_optin_seals_canonical_snapshot(self):
        args = self.args(artifact_store=str(self.store))
        report = self.build(self.events(), args=args)
        stored = report['artifact_store']
        snapshot = Path(stored['binary'])
        canonical_receipt = Path(stored['receipt'])
        build_receipt = Path(stored['build_receipt'])
        cas_object = Path(stored['object'])
        self.assertEqual(report['binary_sha256'], receipt.sha256_file(snapshot))
        self.assertEqual(report['binary_sha256'],
                         report['cargo_artifacts'][1]['executable_sha256'])
        self.assertEqual(report['cargo_artifacts'][1]['executable'], str(self.binary.resolve()))
        self.assertEqual(report['relocated_artifact'], True)
        self.assertEqual(report['original_artifact_sha256'], report['binary_sha256'])
        self.assertEqual(stored['binary_sha256'], report['binary_sha256'])
        self.assertEqual(canonical_receipt.read_bytes(), build_receipt.read_bytes())
        for path, mode in ((cas_object, 0o555), (snapshot, 0o555),
                           (canonical_receipt, 0o444), (build_receipt, 0o444)):
            self.assertTrue(path.is_file(), path)
            self.assertEqual(path.stat().st_mode & 0o777, mode, path)
        self.assertNotEqual(os.stat(snapshot).st_ino, os.stat(self.binary).st_ino)
        self.assertNotEqual(os.stat(cas_object).st_ino, os.stat(self.binary).st_ino)
        self.assertFalse(self.receipt.exists(), 'CAS mode must not write the mutable-output receipt')
        self.assertIsNone(stored['output_alias'])
        validated = receipt.load_receipt(
            canonical_receipt, binary_path=snapshot, expected_commit='a' * 40,
            expected_binary_sha256=report['binary_sha256'])
        self.assertEqual(validated.binary_sha256, report['binary_sha256'])
        # A later overwrite of the mutable compiler output cannot change the snapshot.
        self.binary.write_bytes(b'overwritten-mutable-output')
        self.assertEqual(receipt.sha256_file(snapshot), report['binary_sha256'])
        self.assertEqual(receipt.sha256_file(build_receipt),
                         receipt.sha256_file(canonical_receipt))

    def test_artifact_store_reuses_one_object_and_ignores_jobs(self):
        args = self.args(artifact_store=str(self.store))
        first = self.build(self.events(bin_fresh=False), args=args)
        os.environ['CARGO_BUILD_JOBS'] = '2'
        try:
            second = self.build(self.events(bin_fresh=True), args=args)
        finally:
            os.environ.pop('CARGO_BUILD_JOBS', None)
        self.assertEqual(first['artifact_store']['object'], second['artifact_store']['object'])
        self.assertEqual(first['artifact_store']['config_key'],
                         second['artifact_store']['config_key'])
        self.assertNotEqual(first['artifact_store']['binary'], second['artifact_store']['binary'])
        self.assertNotEqual(first['artifact_store']['receipt'], second['artifact_store']['receipt'])
        self.assertEqual(second['artifact_store']['method'], 'reuse')
        self.assertTrue(second['artifact_store']['reused'])
        self.assertEqual(second['artifact_store']['copied_bytes'], 0)
        self.assertEqual(first['cargo_artifacts'][1]['fresh'], False)
        self.assertEqual(second['cargo_artifacts'][1]['fresh'], True)
        self.assertEqual(second['build_options'], {'jobs': 2})

    def test_artifact_store_config_key_binds_features(self):
        first = self.build(self.events(), args=self.args(artifact_store=str(self.store)))
        second = self.build(self.events(),
                            args=self.args(features='pando-lab', artifact_store=str(self.store)))
        self.assertNotEqual(first['artifact_store']['config_key'],
                            second['artifact_store']['config_key'])
        self.assertEqual(first['artifact_store']['object'], second['artifact_store']['object'])

    def test_artifact_store_output_alias_is_no_overwrite(self):
        alias = self.external / 'aliases' / 'rootyard'
        args = self.args(artifact_store=str(self.store), output=str(alias))
        report = self.build(self.events(), args=args)
        alias_receipt = Path(str(alias) + '.build.json')
        canonical_receipt = Path(report['artifact_store']['receipt'])
        snapshot = Path(report['artifact_store']['binary'])
        self.assertTrue(alias.is_file())
        self.assertEqual(alias.read_bytes(), snapshot.read_bytes())
        self.assertEqual(alias_receipt.read_bytes(), canonical_receipt.read_bytes())
        self.assertEqual(alias.stat().st_mode & 0o777, 0o555)
        self.assertEqual(alias_receipt.stat().st_mode & 0o777, 0o444)
        alias_info = report['artifact_store']['output_alias']
        self.assertEqual(alias_info['path'], str(alias.resolve()))
        self.assertEqual(alias_info['receipt'], str(alias_receipt.resolve()))
        self.assertIn(alias_info['method'], ('hardlink', 'copy'))
        self.assertEqual(alias_info['same_inode_as_cas_object'],
                         alias_info['method'] == 'hardlink')
        self.assertFalse(alias_info['overwrote_existing'])
        # A repeated invocation refuses the existing alias before Cargo or a new seal.
        before_alias = alias.read_bytes()
        before_receipt = alias_receipt.read_bytes()
        builds = len(self.popen_calls)
        with self.assertRaises(build_native.BuildError) as caught:
            self.build(self.events(), args=args)
        self.assertIn('already exists', str(caught.exception))
        self.assertEqual(len(self.popen_calls), builds)
        self.assertEqual(alias.read_bytes(), before_alias)
        self.assertEqual(alias_receipt.read_bytes(), before_receipt)

    def test_output_alias_requires_artifact_store(self):
        with self.assertRaises(build_native.BuildError) as caught:
            self.build(self.events(), args=self.args(output=str(self.external / 'rootyard')))
        self.assertIn('requires an explicit --artifact-store', str(caught.exception))
        self.assertEqual(self.popen_calls, [])
        self.assertFalse((self.external / 'rootyard').exists())

    def test_output_alias_symlink_and_directory_are_refused_before_build(self):
        sentinel = self.external / 'sentinel'
        sentinel.write_text('keep')
        link = self.external / 'link'
        link.symlink_to(sentinel)
        directory = self.external / 'directory'
        directory.mkdir()
        for alias, message in ((link, 'symlink'), (directory, 'existing directory')):
            with self.subTest(alias=alias):
                with self.assertRaises(build_native.BuildError) as caught:
                    self.build(self.events(), args=self.args(
                        artifact_store=str(self.store), output=str(alias)))
                self.assertIn(message, str(caught.exception))
                self.assertEqual(self.popen_calls, [])
                self.assertFalse(self.store.exists())
        self.assertEqual(sentinel.read_text(), 'keep')

    def test_alias_copy_fallback_is_verified_and_independent(self):
        source = self.external / 'source'
        source.write_bytes(b'verified-source-bytes')
        os.chmod(source, 0o555)
        destination = self.external / 'copy-alias'
        real_link = os.link

        def cross_device_link(src, dst, *arguments, **keywords):
            if Path(src) == source or Path(src).name.startswith('.copy-alias.'):
                raise OSError(errno.EXDEV, 'cross-device link')
            return real_link(src, dst, *arguments, **keywords)

        with mock.patch.object(build_native.os, 'link', cross_device_link):
            method = build_native._publish_immutable_alias(source, destination, 'alias')
        self.assertEqual(method, 'copy')
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o555)
        self.assertNotEqual(os.stat(destination).st_ino, os.stat(source).st_ino)

    def test_artifact_store_failure_leaves_no_false_valid_receipt(self):
        args = self.args(artifact_store=str(self.store))
        with mock.patch.object(build_native, '_publish_immutable_alias',
                               side_effect=build_native.BuildError('publication refused')):
            with self.assertRaises(build_native.BuildError) as caught:
                self.build(self.events(), args=args)
        self.assertIn('publication refused', str(caught.exception))
        self.assertFalse([path for path in self.store.rglob('*')
                          if path.is_file() and path.name.endswith(('.build.json', '.receipt.json'))])
        self.assertFalse([path for path in (self.store / 'snapshots').rglob('*') if path.is_file()])

    def test_source_digest_is_unchanged_and_bound_to_the_receipt(self):
        before = build_native.source_digest()
        report = self.build(self.events())
        self.assertEqual(report['source_inputs_sha256'], before)
        self.assertEqual(build_native.source_digest(), before)
        self.assertEqual(build_native.source_digest(), report['source_inputs_sha256'])

    def test_jobs_are_explicit_argv_and_removed_from_the_cargo_environment(self):
        os.environ['CARGO_BUILD_JOBS'] = '2'
        try:
            report = self.build(self.events())
        finally:
            os.environ.pop('CARGO_BUILD_JOBS', None)
        command, kwargs = self.popen_calls[0]
        self.assertEqual(command[-2:], ['--jobs', '2'])
        self.assertNotIn('CARGO_BUILD_JOBS', kwargs['env'])
        self.assertEqual(kwargs['env']['CARGO_TARGET_DIR'], 'target')
        self.assertEqual(report['command'][-2:], ['--jobs', '2'])
        self.assertEqual(report['build_options'], {'jobs': 2})

    def test_rejected_environment_fails_before_cargo_or_a_receipt(self):
        os.environ['RUSTFLAGS'] = '-C target-cpu=native'
        try:
            with self.assertRaises(build_native.BuildError) as caught:
                build_native.run_build(self.args())
        finally:
            os.environ.pop('RUSTFLAGS', None)
        self.assertIn('RUSTFLAGS', str(caught.exception))
        self.assertEqual(self.popen_calls, [])
        self.assert_no_receipt()

    def test_receipt_installed_atomically_over_previous_receipt(self):
        self.seed_stale_receipt()
        self.build(self.events())
        self.assertFalse(self.temporary.exists())
        stored = json.loads(self.receipt.read_text())
        self.assertNotEqual(stored, {'stale': True})
        self.assertEqual(stored['binary_sha256'], receipt.sha256_file(self.binary))

    # -- failure paths: no new receipt, previous receipt invalidated --------
    def test_absent_or_non_boolean_freshness_is_rejected(self):
        for value in (None, 0, 1, 'false', 'true', [], {}):
            with self.subTest(value=value):
                self.seed_stale_receipt()
                events = self.events()
                events[1]['fresh'] = value
                with self.assertRaises(build_native.BuildError) as caught:
                    self.build(events)
                self.assertIn('non-boolean freshness', str(caught.exception))
                self.assert_no_receipt()
        self.seed_stale_receipt()
        missing = self.events()
        del missing[1]['fresh']
        with self.assertRaises(build_native.BuildError):
            self.build(missing)
        self.assert_no_receipt()

    def test_missing_lib_artifact_is_rejected(self):
        self.assert_failure(self.events(kinds=('bin',)), 'did not report a rootyard lib')

    def test_missing_bin_artifact_is_rejected(self):
        self.assert_failure(self.events(kinds=('lib',)), 'did not report the rootyard binary')

    def test_binary_without_executable_path_is_rejected(self):
        events = [_artifact('lib', src_path=self.root / 'src' / 'lib.rs'),
                  _artifact('bin', src_path=self.root / 'src' / 'main.rs'),
                  {'reason': 'build-finished', 'success': True}]
        self.assert_failure(events, 'has no executable path')

    def test_wrong_binary_executable_is_rejected(self):
        events = self.events(executable=str(self.root / 'elsewhere' / 'rootyard'))
        self.assert_failure(events, 'does not match')

    def test_missing_binary_output_is_rejected(self):
        self.assert_failure(self.events(), 'built binary is missing', write_binary=False)

    def test_source_change_during_build_is_rejected(self):
        self.assert_failure(self.events(), 'Source inputs changed during build',
                            mutate_source=True)

    def test_toolchain_change_during_build_is_rejected(self):
        before = self.fake_toolchain({})
        after = json.loads(json.dumps(before))
        after['cargo']['executable_sha256'] = '0' * 64
        self.probe_sequences = [before, after]
        self.assert_failure(self.events(), 'Toolchain identity changed')

    def test_head_or_working_tree_change_during_build_is_rejected(self):
        before = {'head': 'a' * 40, 'commit': 'a' * 40, 'tree': 'b' * 40, 'status': ''}
        after = dict(before, status=' M src/lib.rs\n')
        self.git_sequences = [before, after]
        self.assert_failure(self.events(), 'HEAD or working-tree state changed')

    def test_cargo_error_is_rejected(self):
        self.assert_failure(self.events(), 'cargo build failed with status 7', returncode=7)

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
            self.assertFalse(acquired.wait(0.75),
                             'contender entered the lock while the holder had it')
        finally:
            release.set()
        self.assertTrue(acquired.wait(15), 'contender did not enter after release')
        holder.join(15)
        contender.join(15)
        self.assertEqual(holder.exitcode, 0)
        self.assertEqual(contender.exitcode, 0)
        entries = [queue.get(timeout=5), queue.get(timeout=5)]
        stamps = dict(entries)
        self.assertIn('held', stamps)
        self.assertIn('acquired', stamps)
        self.assertGreater(stamps['acquired'], stamps['held'])
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
