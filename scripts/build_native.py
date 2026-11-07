#!/usr/bin/env python3
"""Build a native binary and bind its digest to the exact compiled source inputs.

The build transaction holds an exclusive flock in the canonical shared
CARGO_TARGET_DIR while it digests sources, clears only the rootyard package,
streams Cargo JSON, checks Fresh=false proof, hashes the artifact and installs
the receipt atomically. Any raw cargo invocation that targets the same directory
must take the same lock or be serialized externally: otherwise it can overwrite
the artifact after this transaction releases the lock. The former wrapper used
subprocess.run(command, cwd=ROOT, check=True); it could not prove a rebuild.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LOCK_NAME = '.rootyard-native-build.lock'
DEFAULT_BIN = 'rootyard'


class BuildError(RuntimeError):
    pass


def source_digest():
    files = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    if (ROOT / 'build.rs').exists():
        files.append(ROOT / 'build.rs')
    for directory in ('src', 'migrations', 'schema', 'vendor'):
        path = ROOT / directory
        if path.exists():
            files.extend(item for item in path.rglob('*') if item.is_file())
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(str(path.relative_to(ROOT)).encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def canonical_target():
    raw = os.environ.get('CARGO_TARGET_DIR') or ROOT / 'target'
    target = Path(raw).expanduser()
    if not target.is_absolute():
        target = ROOT / target
    return target.resolve()


@contextlib.contextmanager
def build_lock(target):
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    lock_path = target / LOCK_NAME
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield lock_path
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def fresh_artifacts(events, binary):
    """Require Fresh=false rootyard lib and bin artifacts for the exact binary."""
    lib = None
    executable_artifact = None
    expected = Path(binary).resolve()
    for event in events:
        if event.get('reason') != 'compiler-artifact':
            continue
        target = event.get('target') or {}
        if target.get('name') != DEFAULT_BIN:
            continue
        kind = target.get('kind') or []
        if event.get('fresh') is not False:
            raise BuildError('Cargo reported a Fresh rootyard artifact; refusing a stale binary receipt')
        if 'lib' in kind and lib is None:
            lib = {'target': DEFAULT_BIN, 'kind': 'lib', 'fresh': False,
                   'package_id': event.get('package_id')}
        if 'bin' in kind and executable_artifact is None:
            executable = event.get('executable')
            if not executable:
                raise BuildError('rootyard binary artifact has no executable path')
            if Path(executable).resolve() != expected:
                raise BuildError(f'rootyard executable {executable} does not match {expected}')
            executable_artifact = {'target': DEFAULT_BIN, 'kind': 'bin', 'fresh': False,
                                   'executable': str(expected), 'package_id': event.get('package_id')}
    if lib is None:
        raise BuildError('Cargo did not report a rootyard lib compiler-artifact')
    if executable_artifact is None:
        raise BuildError('Cargo did not report the rootyard binary compiler-artifact')
    return [lib, executable_artifact]


def run_build(args, popen=None):
    popen = popen or subprocess.Popen
    target = canonical_target()
    destination = target / 'debug' / DEFAULT_BIN
    receipt = destination.with_suffix('.build.json')
    with build_lock(target) as lock_path:
        if receipt.exists():
            receipt.unlink()
        before = source_digest()
        # Clear only the rootyard package; dependency artifacts stay shared.
        clean_command = ['cargo', 'clean', '--package', DEFAULT_BIN]
        subprocess.run(clean_command, cwd=ROOT, check=True)
        command = ['cargo', 'build', '--locked']
        command += ['--bins'] if args.bins else ['--bin', DEFAULT_BIN]
        if args.features:
            command += ['--features', args.features]
        command += ['--message-format=json-render-diagnostics']
        events = []
        process = popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=None,
                        text=True, bufsize=1)
        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    raise BuildError(f'Cargo wrote non-JSON to stdout: {error}') from error
                if not isinstance(event, dict):
                    raise BuildError('Cargo JSON event was not an object')
                events.append(event)
            returncode = process.wait()
        except BaseException:
            process.kill()
            process.wait()
            raise
        if returncode != 0:
            raise BuildError(f'cargo build failed with status {returncode}')
        after = source_digest()
        if before != after:
            raise BuildError('Source inputs changed during build; rebuild before recording acceptance.')
        binary = target / 'debug' / DEFAULT_BIN
        if not binary.is_file():
            raise BuildError(f'built binary is missing: {binary}')
        artifacts = fresh_artifacts(events, binary)
        report = {'version': 1, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                  'source_inputs_sha256': before,
                  'workspace_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                  'command': command,
                  'package_rebuilt': True,
                  'clean_command': clean_command,
                  'target_dir': str(target),
                  'lock_file': str(lock_path),
                  'fresh_false_artifacts': artifacts}
        temporary = receipt.with_suffix('.tmp')
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(receipt)
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Build a native binary and record its source binding.')
    parser.add_argument('--features')
    parser.add_argument('--bins', action='store_true')
    args = parser.parse_args(argv)
    try:
        report = run_build(args)
    except (BuildError, subprocess.CalledProcessError) as error:
        print(f'build_native: {error}', file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
