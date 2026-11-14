#!/usr/bin/env python3
"""Build one selected integration-test executable (or the lib unit-test harness).

This is the v2 explicit test producer.  It never runs ``cargo clean`` and
accepts either literal Cargo freshness value, so a shared correctly-keyed Cargo
cache can satisfy the build.  The selected artifact is copied outside the
canonical ``CARGO_TARGET_DIR`` to a fixed immutable output; the adjacent v2
receipt binds the original and relocated executable digests, the exact
kind/profile/source closure, the shared bound input inventory (including the
library harness test-support closure), the toolchain executable digests and
full commits, the exact command and the real Git HEAD/working-tree state.

With the explicit ``--lib`` mode the lib unit-test harness is compiled instead
with ``cargo test --lib --no-run``.  Its receipt kind is
``rust-library-test`` and it binds the external test-support sources that Rust
pulls into the library through ``#[path]`` or ``include_str!``; the shared
inventory records them as ``test_support`` and the receipt also carries
``lib_test_support_inputs_sha256``.  ``LIB_TEST_SUPPORT_DIRS`` remains the
explicit, closed list of those directories.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import native_build_receipt as receipt
from build_native import BuildError, build_lock, canonical_target

ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]{0,127}$')
FEATURES = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]*(,[A-Za-z_][A-Za-z0-9_-]*)*$')
PROFILE_KEYS = receipt.PROFILE_FIELDS
LIB_TEST_SUPPORT_DIRS = receipt.TEST_SUPPORT_DIRS


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _as_build_error(error):
    if isinstance(error, BuildError):
        return error
    return BuildError(str(error))


def normalize_environment(environ=None):
    try:
        return receipt.normalize_build_environment(os.environ if environ is None else environ)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def capture_bound_inputs(environment):
    try:
        return receipt.capture_bound_inputs(ROOT, environ=environment)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def probe_toolchain(environment):
    """Probe the actual toolchain with the same guard-safe environment as Cargo."""
    def run(command):
        return subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                              check=False, env=environment)
    try:
        return receipt.probe_toolchain(ROOT, environ=environment, run=run)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def git_state():
    try:
        return receipt.git_state(ROOT)
    except (OSError, subprocess.CalledProcessError) as error:
        raise BuildError('cannot read Git state: ' + str(error)) from error


def _support_entries(bound):
    return sorted(
        (entry for entry in bound['bound_input_inventory']
         if entry['role'] == 'test_support' and entry['present']),
        key=lambda entry: entry['path'])


def support_digest_from_bound(bound):
    """The exact support-closure digest over the shared bound inventory."""
    digest = hashlib.sha256()
    for entry in _support_entries(bound):
        digest.update(entry['path'].encode() + b'\0')
        digest.update(bytes.fromhex(entry['sha256']))
    return digest.hexdigest()


def lib_test_support_digest():
    """Digest the closed support directories directly (kept for callers/tests)."""
    entries, _blobs = receipt.bound_input_inventory(ROOT)
    return support_digest_from_bound({'bound_input_inventory': entries})


def _literal_fresh(event, label):
    fresh = event.get('fresh')
    if fresh is not True and fresh is not False:
        raise BuildError(
            label + " has absent or non-boolean freshness; Cargo's reported freshness "
            'must be the literal JSON boolean true or false')
    return fresh


def _record(event, kind, label):
    _literal_fresh(event, label)
    try:
        return receipt.cargo_artifact_record(event, source_root=ROOT, kind=kind)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def selected_artifact(events, name):
    """Return the sole exact test artifact for this integration target."""
    found = []
    for event in events:
        if event.get('reason') != 'compiler-artifact':
            continue
        target = event.get('target') or {}
        if target.get('name') != name or list(target.get('kind') or []) != ['test']:
            continue
        record = _record(event, 'test', 'integration-test artifact ' + name)
        expected_source = 'tests/' + name + '.rs'
        if record['source'] != expected_source:
            raise BuildError('integration-test artifact ' + name + ' was built from ' +
                             record['source'] + ', not ' + expected_source)
        if record['profile'].get('test') is not True:
            raise BuildError('integration-test artifact ' + name + ' was not built with a test profile')
        found.append(record)
    if len(found) != 1:
        raise BuildError('Cargo reported ' + str(len(found)) + ' ' + name +
                         ' test artifacts; expected exactly one')
    return found[0]


def selected_library_artifact(events):
    """Return the sole exact lib-test harness artifact for target ``rootyard``."""
    found = []
    for event in events:
        if event.get('reason') != 'compiler-artifact':
            continue
        target = event.get('target') or {}
        if target.get('name') != 'rootyard' or list(target.get('kind') or []) != ['lib']:
            continue
        profile = event.get('profile') or {}
        if profile.get('test') is not True:
            continue
        if 'test' in target and target['test'] is not True:
            continue
        record = _record(event, 'lib-test', 'rootyard lib test artifact')
        if not record['source'].startswith('src/'):
            raise BuildError('rootyard lib test artifact source is outside src/: ' + record['source'])
        found.append(record)
    if len(found) != 1:
        raise BuildError('Cargo reported ' + str(len(found)) +
                         ' rootyard lib test artifacts; expected exactly one')
    return found[0]


def require_build_finished(events):
    try:
        receipt.require_build_finished(events)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def _require_bound_unchanged(before, after, library):
    if before == after:
        return
    if before['source_inputs_sha256'] != after['source_inputs_sha256']:
        raise BuildError('Source inputs changed during build; rebuild before recording acceptance.')
    if before['cargo_lock_sha256'] != after['cargo_lock_sha256']:
        raise BuildError('Cargo.lock changed during build; refusing the receipt')
    if before['config_digest'] != after['config_digest']:
        raise BuildError('config, build-script or toolchain inputs changed during build; refusing the receipt')
    old = {entry['path']: entry for entry in before['bound_input_inventory']}
    new = {entry['path']: entry for entry in after['bound_input_inventory']}
    if old != new:
        changed = sorted(path for path in set(old) | set(new) if old.get(path) != new.get(path))
        if library:
            raise BuildError('lib test-support inputs changed during build: ' + ', '.join(changed) +
                             '; rebuild before recording acceptance.')
        raise BuildError('Source inputs changed during build: ' + ', '.join(changed))
    raise BuildError('bound build inputs changed during build; refusing the receipt')


def run_build(args, popen=None, environ=None):
    popen = popen or subprocess.Popen
    library = bool(getattr(args, 'lib', False))
    if library and args.test is not None:
        raise BuildError('--lib and --test are mutually exclusive')
    if library:
        test_source = None
    else:
        if args.test is None:
            raise BuildError('one of --test or --lib is required')
        if not NAME.match(args.test):
            raise BuildError('--test must be a plain Rust target identifier: ' + repr(args.test))
        test_source = ROOT / 'tests' / (args.test + '.rs')
        if not test_source.is_file():
            raise BuildError('integration-test source is missing: ' + str(test_source))
    if args.features and not FEATURES.match(args.features):
        raise BuildError('--features must be comma-separated Rust feature identifiers')
    normalized = normalize_environment(environ)
    environment = normalized['environment']
    target = canonical_target()
    raw_output = Path(args.output).expanduser()
    if not raw_output.is_absolute():
        raw_output = ROOT / raw_output
    if raw_output.is_symlink():
        raise BuildError('--output must not be a symlink: ' + str(raw_output))
    output = raw_output.resolve()
    if output == target or target in output.parents:
        raise BuildError('--output must be outside CARGO_TARGET_DIR so it stays independent of cache eviction')
    if output.is_dir():
        raise BuildError('--output is a directory: ' + str(output))
    receipt_path = output.with_suffix('.build.json')
    with build_lock(target) as lock_path:
        if receipt_path.exists():
            receipt_path.unlink()
        if output.exists():
            output.unlink()
        temporary = output.with_name('.' + output.name + '.tmp')
        try:
            bound_before = capture_bound_inputs(environment)
            toolchain_before = probe_toolchain(environment)
            git_before = git_state()
            support_before = support_digest_from_bound(bound_before) if library else None
            command = ['cargo']
            if args.package_debug is not None:
                command += ['--config', 'profile.dev.package.rootyard.debug=' + args.package_debug,
                            '--config', 'profile.test.package.rootyard.debug=' + args.package_debug]
            if args.strip_debuginfo:
                command += ['--config', 'profile.dev.package.rootyard.strip="debuginfo"',
                            '--config', 'profile.test.package.rootyard.strip="debuginfo"']
            if library:
                command += ['test', '--locked']
            else:
                command += ['rustc', '--locked', '--profile', 'test', '--test', args.test]
            if library:
                # Only an explicit user --no-default-features drops defaults; --features keeps them.
                if args.no_default_features:
                    command += ['--no-default-features']
                if args.features:
                    command += ['--features', args.features]
                command += ['--lib', '--no-run']
            else:
                if args.features:
                    command += ['--features', args.features]
                if getattr(args, 'no_default_features', False):
                    command += ['--no-default-features']
            command += ['--message-format=json-render-diagnostics']
            command += list(normalized['cargo_args'])
            events = []
            process = popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=None,
                            text=True, bufsize=1, env=environment)
            try:
                for line in process.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise BuildError('Cargo wrote non-JSON to stdout: ' + str(error)) from error
                    if not isinstance(event, dict):
                        raise BuildError('Cargo JSON event was not an object')
                    events.append(event)
                returncode = process.wait()
            except BaseException:
                process.kill()
                process.wait()
                raise
            if returncode != 0:
                runner = 'cargo test' if library else 'cargo rustc'
                raise BuildError(runner + ' failed with status ' + str(returncode))
            require_build_finished(events)
            bound_after = capture_bound_inputs(environment)
            _require_bound_unchanged(bound_before, bound_after, library)
            toolchain_after = probe_toolchain(environment)
            if toolchain_before != toolchain_after:
                raise BuildError('Toolchain identity changed during build; refusing the receipt')
            git_after = git_state()
            if git_before != git_after:
                raise BuildError('HEAD or working-tree state changed during build; refusing the receipt')
            artifact = selected_library_artifact(events) if library else selected_artifact(events, args.test)
            original = Path(artifact['executable'])
            if not original.is_file():
                raise BuildError('built test executable is missing: ' + str(original))
            original_sha = sha256_file(original)
            if original_sha != artifact['executable_sha256']:
                raise BuildError('built test executable changed while its receipt was being recorded')
            output.parent.mkdir(parents=True, exist_ok=True)
            temporary = output.with_name('.' + output.name + '.tmp')
            shutil.copyfile(original, temporary)
            os.chmod(temporary, 0o700)
            if sha256_file(temporary) != original_sha:
                raise BuildError('relocated executable does not match the selected artifact')
            os.replace(temporary, output)
            if sha256_file(output) != original_sha:
                raise BuildError('relocated executable changed during publication')
            support_after = support_digest_from_bound(bound_after) if library else None
            extra = {
                'kind': 'rust-library-test' if library else 'rust-integration-test',
                'relocated_artifact': True,
                'original_artifact_sha256': original_sha,
                'build_options': normalized['build_options'],
            }
            if library:
                extra['lib_test_support_inputs_sha256'] = support_after
                if support_before != support_after:
                    raise BuildError('lib test-support inputs changed during build; refusing the receipt')
            else:
                extra['integration_test_source'] = artifact['source']
                extra['integration_test_source_sha256'] = artifact['source_sha256']
            try:
                report = receipt.make_receipt_v2(
                    binary_path=output,
                    command=command,
                    profile='test',
                    artifacts=[artifact],
                    toolchain=toolchain_after,
                    bound_inputs=bound_after,
                    workspace_commit=git_after['commit'],
                    target_dir=target,
                    features=args.features,
                    no_default_features=getattr(args, 'no_default_features', False),
                    lock_file=lock_path,
                    git_head=git_after['head'],
                    working_tree={'tree': git_after['tree'], 'status': git_after['status']},
                    extra=extra,
                )
            except receipt.ReceiptError as error:
                raise _as_build_error(error) from error
            receipt.atomic_write_json(receipt_path, report)
            return report
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                receipt_path.unlink()
            with contextlib.suppress(FileNotFoundError):
                output.unlink()
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Build one selected Rust test executable and record its source binding.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--test', help='Rust integration-test target name')
    mode.add_argument('--lib', action='store_true',
                      help='build the rootyard library unit-test harness (cargo test --lib --no-run)')
    parser.add_argument('--features')
    parser.add_argument('--no-default-features', action='store_true')
    parser.add_argument('--package-debug', choices=('0', '1', '2'), help='rootyard dev/test debug level')
    parser.add_argument('--strip-debuginfo', action='store_true',
                        help='strip rootyard dev/test debug information')
    parser.add_argument('--output', required=True,
                        help='fixed path outside CARGO_TARGET_DIR for the executable')
    args = parser.parse_args(argv)
    try:
        report = run_build(args)
    except (BuildError, receipt.ReceiptError, subprocess.CalledProcessError, OSError) as error:
        print('build_native_test: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
