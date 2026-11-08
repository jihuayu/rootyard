#!/usr/bin/env python3
"""Build one selected integration-test executable and bind it to source inputs.

The test is compiled with `cargo rustc --profile test` after clearing only the
rootyard package under the canonical shared build lock, so a rootyard artifact
reported by Cargo cannot be a stale or pre-built server binary.  The selected
test artifact must be Fresh=false and is relocated outside CARGO_TARGET_DIR,
where a later `build_native.py` `cargo clean --package rootyard` cannot delete
it.  The receipt next to the relocated executable records the source, test,
Cargo.lock and binary digests plus the unchanged HEAD/working-tree state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from build_native import BuildError, build_lock, canonical_target, source_digest

ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]{0,127}$')
FEATURES = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]*(,[A-Za-z_][A-Za-z0-9_-]*)*$')
PROFILE_KEYS = ('opt_level', 'debuginfo', 'debug_assertions', 'overflow_checks', 'test')


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def git_state():
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    status = subprocess.check_output(
        ['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT, text=True)
    return head, status


def selected_artifact(events, name):
    """Return the sole Fresh=false test artifact for this exact target."""
    found = []
    for event in events:
        if event.get('reason') != 'compiler-artifact':
            continue
        target = event.get('target') or {}
        if target.get('name') != name or 'test' not in (target.get('kind') or []):
            continue
        if event.get('fresh') is not False:
            raise BuildError('Cargo reported a Fresh ' + name + ' test artifact; refusing a stale receipt')
        executable = event.get('executable')
        if not executable:
            raise BuildError('integration-test artifact ' + name + ' has no executable path')
        profile = event.get('profile') or {}
        found.append({'target': name, 'kind': 'test', 'fresh': False,
                      'profile': {key: profile.get(key) for key in PROFILE_KEYS},
                      'executable': str(Path(executable).resolve())})
    if len(found) != 1:
        raise BuildError('Cargo reported ' + str(len(found)) + ' ' + name +
                         ' test artifacts; expected exactly one')
    return found[0]


def require_build_finished(events):
    finished = [event for event in events if event.get('reason') == 'build-finished']
    if len(finished) != 1 or finished[0].get('success') is not True:
        raise BuildError('Cargo did not report exactly one successful build-finished event')


def run_build(args):
    if not NAME.match(args.test):
        raise BuildError('--test must be a plain Rust target identifier: ' + repr(args.test))
    if args.features and not FEATURES.match(args.features):
        raise BuildError('--features must be comma-separated Rust feature identifiers')
    test_source = ROOT / 'tests' / (args.test + '.rs')
    if not test_source.is_file():
        raise BuildError('integration-test source is missing: ' + str(test_source))
    target = canonical_target()
    output = Path(args.output).expanduser()
    output = (ROOT / output if not output.is_absolute() else output).resolve()
    if output == target or target in output.parents:
        raise BuildError('--output must be outside CARGO_TARGET_DIR so a later clean cannot delete it')
    if output.is_dir():
        raise BuildError('--output is a directory: ' + str(output))
    receipt = output.with_suffix('.build.json')
    with build_lock(target):
        if receipt.exists():
            receipt.unlink()
        if output.exists():
            output.unlink()
        before = source_digest()
        test_before = sha256_file(test_source)
        lock_before = sha256_file(ROOT / 'Cargo.lock')
        head_before, status_before = git_state()
        # Clear only the rootyard package so its test artifact is honestly Fresh=false.
        clean_command = ['cargo', 'clean', '--package', 'rootyard']
        subprocess.run(clean_command, cwd=ROOT, check=True)
        command = ['cargo']
        if args.package_debug is not None:
            command += ['--config', 'profile.dev.package.rootyard.debug=' + args.package_debug,
                        '--config', 'profile.test.package.rootyard.debug=' + args.package_debug]
        if args.strip_debuginfo:
            command += ['--config', 'profile.dev.package.rootyard.strip="debuginfo"',
                        '--config', 'profile.test.package.rootyard.strip="debuginfo"']
        command += ['rustc', '--locked', '--profile', 'test', '--test', args.test]
        if args.features:
            command += ['--features', args.features]
        command += ['--message-format=json-render-diagnostics']
        events = []
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=None,
                                   text=True, bufsize=1)
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
            raise BuildError('cargo rustc failed with status ' + str(returncode))
        after = source_digest()
        test_after = sha256_file(test_source)
        lock_after = sha256_file(ROOT / 'Cargo.lock')
        head_after, status_after = git_state()
        if (before, test_before, lock_before) != (after, test_after, lock_after):
            raise BuildError('Source inputs changed during build; rebuild before recording acceptance.')
        if (head_before, status_before) != (head_after, status_after):
            raise BuildError('HEAD or working-tree state changed during build; refusing the receipt')
        artifact = selected_artifact(events, args.test)
        require_build_finished(events)
        original = Path(artifact['executable'])
        if not original.is_file():
            raise BuildError('built test executable is missing: ' + str(original))
        original_sha = sha256_file(original)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + '.tmp')
        shutil.copyfile(original, temporary)
        os.chmod(temporary, 0o700)
        os.replace(temporary, output)
        report = {'kind': 'rust-integration-test', 'relocated_artifact': True,
                  'original_artifact_sha256': original_sha,
                  'workspace_commit': head_after, 'fresh': False,
                  'source_inputs_sha256': before,
                  'binary_sha256': sha256_file(output),
                  'integration_test_source_sha256': test_after,
                  'cargo_lock_sha256': lock_after,
                  'command': command,
                  'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                  'package_rebuilt': True,
                  'fresh_false_artifacts': [artifact]}
        receipt_tmp = receipt.with_suffix('.tmp')
        receipt_tmp.write_text(json.dumps(report, indent=2) + '\n')
        os.replace(receipt_tmp, receipt)
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Build one selected Rust integration test and record its source binding.')
    parser.add_argument('--test', required=True, help='Rust integration-test target name')
    parser.add_argument('--features')
    parser.add_argument('--package-debug', choices=('0', '1', '2'), help='rootyard dev/test debug level')
    parser.add_argument('--strip-debuginfo', action='store_true', help='strip rootyard dev/test debug information')
    parser.add_argument('--output', required=True, help='path outside CARGO_TARGET_DIR for the executable')
    args = parser.parse_args(argv)
    try:
        report = run_build(args)
    except (BuildError, subprocess.CalledProcessError, OSError) as error:
        print('build_native_test: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
