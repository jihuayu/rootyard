#!/usr/bin/env python3
"""Build a native binary and bind its digest to the exact compiled source inputs.

This is the explicit v2 producer for one ``rootyard`` binary.  It never runs
``cargo clean`` and never requires Cargo to report a rebuilt (``fresh=false``)
artifact: a shared, correctly keyed Cargo cache may return the existing binary
with either literal freshness value.  The receipt records that value exactly
and the shared v2 contract refuses a missing, null or non-boolean freshness.

The build transaction holds an exclusive flock in the canonical shared
``CARGO_TARGET_DIR`` while it measures the bound inputs, streams Cargo JSON,
checks the selected lib/bin artifacts, hashes the output and installs the
receipt atomically.  ``CARGO_BUILD_JOBS`` is normalized to an explicit
``--jobs`` argument and the guard-safe environment is used for every metadata
helper and for Cargo itself; no compiler/profile selector is silently dropped.

``--strip-debuginfo`` is optional, off by default and mirrors
``scripts/build_native_test.py``: it injects only
``profile.dev.package.rootyard.strip="debuginfo"`` as an explicit ``--config``
argument of the executed cargo command, so the recorded receipt ``command`` is
exactly the profile that was built.  It never sets RUSTFLAGS and never touches
dependency or workspace-wide profiles.
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

import native_build_receipt as receipt

ROOT = Path(__file__).resolve().parents[1]
LOCK_NAME = '.rootyard-native-build.lock'
DEFAULT_BIN = 'rootyard'


class BuildError(RuntimeError):
    pass


def source_digest():
    """The exact historical production source digest, rooted at ``ROOT``.

    Kept as a module-level function because the shared contract and the
    existing qualification tests compare this algorithm byte for byte.
    """
    files = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    if (ROOT / 'build.rs').exists():
        files.append(ROOT / 'build.rs')
    for directory in ('src', 'migrations', 'schema', 'vendor'):
        path = ROOT / directory
        if path.exists():
            files.extend(item for item in path.rglob('*') if item.is_file())
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b'\0')
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


def _as_build_error(error):
    if isinstance(error, BuildError):
        return error
    return BuildError(str(error))


def normalize_environment(environ=None):
    """Normalize scheduling and validate the compiler/config environment names."""
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


def _literal_fresh(event, label):
    fresh = event.get('fresh')
    if fresh is not True and fresh is not False:
        raise BuildError(
            label + ' has absent or non-boolean freshness; Cargo\'s reported freshness must be '
            'the literal JSON boolean true or false')
    return fresh


def selected_artifacts(events, binary):
    """Return the exact rootyard lib and bin v2 artifact rows from one Cargo stream.

    Freshness is accepted as either literal boolean and copied from the event;
    a missing or non-boolean value fails closed.  The selected bin's executable
    must be the canonical built binary and its hash must match the bytes this
    transaction is about to receipt.
    """
    lib = None
    executable_artifact = None
    expected = Path(binary).resolve()
    for event in events:
        if event.get('reason') != 'compiler-artifact':
            continue
        target = event.get('target') or {}
        if target.get('name') != DEFAULT_BIN:
            continue
        kinds = list(target.get('kind') or [])
        if kinds == ['lib']:
            if lib is not None:
                raise BuildError('Cargo reported two rootyard lib compiler-artifacts')
            _literal_fresh(event, 'rootyard lib artifact')
            try:
                lib = receipt.cargo_artifact_record(event, source_root=ROOT, kind='lib')
            except receipt.ReceiptError as error:
                raise _as_build_error(error) from error
        elif kinds == ['bin']:
            if executable_artifact is not None:
                raise BuildError('Cargo reported two rootyard binary compiler-artifacts')
            _literal_fresh(event, 'rootyard binary artifact')
            executable = event.get('executable')
            if not executable:
                raise BuildError('rootyard binary artifact has no executable path')
            resolved = Path(executable).resolve()
            if resolved != expected:
                raise BuildError(f'rootyard executable {executable} does not match {expected}')
            try:
                executable_artifact = receipt.cargo_artifact_record(
                    event, source_root=ROOT, kind='bin')
            except receipt.ReceiptError as error:
                raise _as_build_error(error) from error
            if Path(executable_artifact['executable']).resolve() != expected:
                raise BuildError(f'rootyard executable {executable_artifact["executable"]} does not match {expected}')
            if executable_artifact['executable_sha256'] != receipt.sha256_file(expected):
                raise BuildError('rootyard executable changed while its receipt was being recorded')
    if lib is None:
        raise BuildError('Cargo did not report a rootyard lib compiler-artifact')
    if executable_artifact is None:
        raise BuildError('Cargo did not report the rootyard binary compiler-artifact')
    if lib['package_id'] != executable_artifact['package_id']:
        raise BuildError('rootyard lib and binary artifacts report different package ids')
    return [lib, executable_artifact]


def _command(args, cargo_args):
    command = ['cargo', 'build', '--locked']
    if getattr(args, 'no_default_features', False):
        command += ['--no-default-features']
    if getattr(args, 'package_debug', None) is not None:
        command += ['--config', 'profile.dev.package.rootyard.debug=' + args.package_debug]
    command += ['--bins'] if args.bins else ['--bin', DEFAULT_BIN]
    if args.features:
        command += ['--features', args.features]
    # Optional debuginfo stripping for this package only; the flag is part of
    # the recorded command so the receipt cannot describe a different profile.
    if getattr(args, 'strip_debuginfo', False):
        command += ['--config', 'profile.dev.package.rootyard.strip="debuginfo"']
    command += ['--message-format=json-render-diagnostics']
    command += list(cargo_args)
    return command


def run_build(args, popen=None, environ=None):
    popen = popen or subprocess.Popen
    normalized = normalize_environment(environ)
    environment = normalized['environment']
    target = canonical_target()
    destination = target / 'debug' / DEFAULT_BIN
    receipt_path = destination.with_suffix('.build.json')
    with build_lock(target) as lock_path:
        # Withdraw the previous receipt for this fixed output before measuring.
        # A failed transaction must never leave a stale receipt beside a binary
        # it does not describe.
        if receipt_path.exists():
            receipt_path.unlink()
        try:
            bound_before = capture_bound_inputs(environment)
            toolchain_before = probe_toolchain(environment)
            git_before = git_state()
            command = _command(args, normalized['cargo_args'])
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
            try:
                receipt.require_build_finished(events)
            except receipt.ReceiptError as error:
                raise _as_build_error(error) from error
            bound_after = capture_bound_inputs(environment)
            if bound_before != bound_after:
                raise BuildError('Source inputs changed during build; rebuild before recording acceptance.')
            toolchain_after = probe_toolchain(environment)
            if toolchain_before != toolchain_after:
                raise BuildError('Toolchain identity changed during build; refusing the receipt')
            git_after = git_state()
            if git_before != git_after:
                raise BuildError('HEAD or working-tree state changed during build; refusing the receipt')
            binary = target / 'debug' / DEFAULT_BIN
            if not binary.is_file():
                raise BuildError(f'built binary is missing: {binary}')
            artifacts = selected_artifacts(events, binary)
            try:
                report = receipt.make_receipt_v2(
                    binary_path=binary,
                    command=command,
                    profile='dev',
                    artifacts=artifacts,
                    toolchain=toolchain_after,
                    bound_inputs=bound_after,
                    workspace_commit=git_after['commit'],
                    target_dir=target,
                    features=args.features,
                    no_default_features=getattr(args, 'no_default_features', False),
                    lock_file=lock_path,
                    git_head=git_after['head'],
                    working_tree={'tree': git_after['tree'], 'status': git_after['status']},
                    extra={
                        'kind': 'native-binary',
                        'build_options': normalized['build_options'],
                    },
                )
            except receipt.ReceiptError as error:
                raise _as_build_error(error) from error
            receipt.atomic_write_json(receipt_path, report)
            return report
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                receipt_path.unlink()
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description='Build a native binary and record its source binding.')
    parser.add_argument('--features')
    parser.add_argument('--package-debug', choices=('0', '1', '2'))
    parser.add_argument('--no-default-features', action='store_true',
                        help='build the minimal profile without optional default transports')
    parser.add_argument('--bins', action='store_true')
    parser.add_argument('--strip-debuginfo', action='store_true',
                        help='strip rootyard dev debug information')
    args = parser.parse_args(argv)
    try:
        report = run_build(args)
    except (BuildError, receipt.ReceiptError, subprocess.CalledProcessError, OSError) as error:
        print(f'build_native: {error}', file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
