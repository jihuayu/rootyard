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
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

import native_artifact_store as artifact_store
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


_ALIAS_LINK_FALLBACK = frozenset({
    errno.EACCES,
    errno.EMLINK,
    errno.ENOSYS,
    errno.ENOTSUP,
    errno.EOPNOTSUPP,
    errno.EPERM,
    errno.EXDEV,
})


def _user_path(raw):
    value = Path(raw).expanduser()
    return ROOT / value if not value.is_absolute() else value


def _explicit_file_destination(raw, label):
    """Resolve an explicit file without silently following a final symlink."""
    raw_path = _user_path(raw)
    if raw_path.is_symlink():
        raise BuildError(label + ' must not be a symlink: ' + str(raw_path))
    if raw_path.exists() and raw_path.is_dir():
        raise BuildError(label + ' must not be an existing directory: ' + str(raw_path))
    resolved = raw_path.parent.resolve() / raw_path.name
    if resolved.is_symlink():
        raise BuildError(label + ' must not be a symlink: ' + str(resolved))
    if resolved.exists() and resolved.is_dir():
        raise BuildError(label + ' must not be an existing directory: ' + str(resolved))
    return resolved


def _artifact_store_root(raw):
    """Absolute store root without following a final symlink (the helper checks it)."""
    return Path(os.path.abspath(_user_path(raw)))


def _require_absent(path, label):
    if os.path.lexists(path):
        raise BuildError(label + ' already exists; refusing to overwrite: ' + str(path))


def cas_destinations(args, target):
    """Preflight the optional artifact store and output alias before any build.

    ``--output`` is a compatibility alias of the immutable CAS snapshot, never
    of the mutable compiler output, so it requires an explicit store.  The
    alias and its adjacent ``.build.json`` receipt are checked for symlinks,
    directories and pre-existing files before Cargo runs; they must also stay
    outside both ``CARGO_TARGET_DIR`` and the managed store.
    """
    store_raw = getattr(args, 'artifact_store', None)
    output_raw = getattr(args, 'output', None)
    if output_raw is not None and not store_raw:
        raise BuildError('--output requires an explicit --artifact-store; the alias is only '
                         'published from an immutable CAS snapshot')
    if not store_raw:
        return None, None, None
    store_root = _artifact_store_root(store_raw)
    if store_root == target or target in store_root.parents:
        raise BuildError('--artifact-store must be outside CARGO_TARGET_DIR')
    if store_root == ROOT or ROOT in store_root.parents:
        raise BuildError('--artifact-store must be outside the source repository')
    if store_root.is_symlink():
        raise BuildError('--artifact-store must not be a symlink: ' + str(store_root))
    if store_root.exists() and not store_root.is_dir():
        raise BuildError('--artifact-store must be a directory: ' + str(store_root))
    if output_raw is None:
        return store_root, None, None
    alias = _explicit_file_destination(output_raw, '--output')
    if alias == target or target in alias.parents:
        raise BuildError('--output must be outside CARGO_TARGET_DIR')
    if alias == store_root or store_root in alias.parents:
        raise BuildError('--output must be outside the artifact store')
    alias_receipt = Path(str(alias) + '.build.json')
    _explicit_file_destination(alias_receipt, '--output receipt')
    _require_absent(alias, '--output')
    _require_absent(alias_receipt, '--output receipt')
    return store_root, alias, alias_receipt


def _publish_immutable_alias(source, destination, label):
    """Publish one same-byte readonly alias, hard-linking first and copying only if needed.

    No pre-existing path is replaced.  A hard link is preferred so the alias
    and the immutable CAS object share one inode; the verified copy fallback is
    used only when the filesystem cannot hard-link across the source/destination
    pair.  The copy is staged in the destination directory and published with a
    no-replace hard link, so a destination created concurrently is preserved.
    If the filesystem cannot provide that atomic no-replace publication the
    helper fails closed rather than renaming over it.  Either way the
    destination bytes and mode are re-verified.
    """
    source, destination = Path(source), Path(destination)
    _require_absent(destination, label)
    source_sha = receipt.sha256_file(source)
    try:
        source_mode = stat.S_IMODE(source.stat().st_mode)
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise BuildError(label + ': cannot prepare destination: ' + str(error)) from error
    created = False
    method = 'hardlink'
    try:
        try:
            os.link(source, destination)
            created = True
        except FileExistsError as error:
            raise BuildError(label + ' already exists; refusing to overwrite: ' +
                             str(destination)) from error
        except OSError as error:
            if error.errno not in _ALIAS_LINK_FALLBACK:
                raise BuildError(label + ': cannot hard-link: ' + str(error)) from error
            method = 'copy'
            try:
                fd, temporary_name = tempfile.mkstemp(
                    prefix='.' + destination.name + '.', suffix='.alias-tmp',
                    dir=destination.parent)
                os.close(fd)
            except OSError as temp_error:
                raise BuildError(label + ': cannot create temporary alias: ' +
                                 str(temp_error)) from temp_error
            temporary = Path(temporary_name)
            try:
                shutil.copyfile(source, temporary)
                os.chmod(temporary, source_mode)
                if receipt.sha256_file(temporary) != source_sha:
                    raise BuildError(label + ' copy does not match its immutable source')
                try:
                    os.link(temporary, destination)
                    created = True
                except FileExistsError as link_error:
                    raise BuildError(label + ' already exists; refusing to overwrite: ' +
                                     str(destination)) from link_error
                except OSError as link_error:
                    # The template lives in the destination directory, so a
                    # no-replace hard link is the only publication primitive
                    # needed.  Never add a check-then-replace fallback: that
                    # would clobber an alias created after the absence check.
                    raise BuildError(
                        label + ': cannot atomically publish the verified copy without '
                        'replacing the destination; refusing to overwrite: ' +
                        str(destination) + ' (' +
                        (link_error.strerror or str(link_error)) + ')') from link_error
            finally:
                with contextlib.suppress(FileNotFoundError):
                    temporary.unlink()
        if destination.is_symlink() or not destination.is_file():
            raise BuildError(label + ' is not a regular file: ' + str(destination))
        if receipt.sha256_file(destination) != source_sha:
            raise BuildError(label + ' does not match its immutable source: ' + str(destination))
        if stat.S_IMODE(destination.stat().st_mode) != source_mode:
            raise BuildError(label + ' mode does not match its immutable source: ' +
                             str(destination))
        return method
    except BaseException:
        if created:
            with contextlib.suppress(OSError):
                destination.unlink()
        raise


def _schedule_free_command(command):
    """The immutable command configuration, excluding the scheduling job budget."""
    result = []
    skip = False
    for token in command:
        if skip:
            skip = False
            continue
        if token == '--jobs':
            skip = True
            continue
        result.append(token)
    return result


def _toolchain_identity(toolchain):
    def identity(name):
        value = toolchain[name]
        return {key: value[key] for key in ('commit_hash', 'executable_sha256', 'release', 'host')
                if key in value}
    result = {
        'cargo': identity('cargo'),
        'rustc': identity('rustc'),
        'target_triple': toolchain['target_triple'],
    }
    if toolchain.get('pinned_channel') is not None:
        result['pinned_channel'] = toolchain['pinned_channel']
    if toolchain.get('rustup') and toolchain['rustup'].get('resolved_rustc_sha256'):
        result['rustup_resolved_rustc_sha256'] = toolchain['rustup']['resolved_rustc_sha256']
    return result


def cas_configuration(args, command, toolchain, bound, profile='dev'):
    """Stable build identity for the CAS snapshot path.

    Scheduling (``--jobs``) is recorded in the receipt but deliberately omitted
    here so it cannot multiply identical binary objects.  The absolute target
    directory and toolchain executable paths are omitted for the same reason;
    target triple, full toolchain commits/hashes, the exact command
    configuration and source/config/lock content identity remain.
    """
    enabled = sorted(name for name in (args.features or '').split(',') if name)
    return {
        'kind': 'native-binary',
        'binary': DEFAULT_BIN,
        'profile': profile,
        'features': {
            'enabled': enabled,
            'no_default_features': bool(getattr(args, 'no_default_features', False)),
        },
        'target_triple': toolchain['target_triple'],
        'command': _schedule_free_command(command),
        'toolchain': _toolchain_identity(toolchain),
        'content': {
            'source_inputs_sha256': bound['source_inputs_sha256'],
            'cargo_lock_sha256': bound['cargo_lock_sha256'],
            'config_digest': bound['config_digest'],
            'bound_inputs_digest': bound['bound_inputs']['digest'],
        },
    }


def run_build(args, popen=None, environ=None):
    popen = popen or subprocess.Popen
    normalized = normalize_environment(environ)
    environment = normalized['environment']
    target = canonical_target()
    store_root, alias_path, alias_receipt = cas_destinations(args, target)
    cas = store_root is not None
    destination = target / 'debug' / DEFAULT_BIN
    receipt_path = destination.with_suffix('.build.json')
    with build_lock(target) as lock_path:
        if cas:
            # The legacy mutable-output receipt is not ours in CAS mode; leave
            # any prior evidence in place.  Re-check alias absence under the
            # lock: both aliases are no-overwrite publications.
            if alias_path is not None:
                _require_absent(alias_path, '--output')
                _require_absent(alias_receipt, '--output receipt')
        else:
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
            if not cas:
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

            # CAS opt-in: seal the completed mutable compiler output only after
            # the full pre/post input, toolchain and Git bindings succeeded.
            executable_sha = next(
                row['executable_sha256'] for row in artifacts if row['kind'] == 'bin')
            sealed = None
            canonical_build_alias = None
            canonical_build_alias_written = False
            alias_written = False
            alias_receipt_written = False
            alias_method = None
            alias_same_inode = None

            def cleanup_publication():
                # Aliases are removed only if this invocation created them; a
                # concurrent callers' file is never mistaken for ours.  The
                # canonical receipt/snapshot live in a fresh per-invocation
                # build directory, so any partial publication there is ours.
                if alias_receipt_written and alias_path is not None:
                    with contextlib.suppress(OSError):
                        alias_receipt.unlink()
                if canonical_build_alias_written and canonical_build_alias is not None:
                    with contextlib.suppress(OSError):
                        canonical_build_alias.unlink()
                if sealed is not None:
                    with contextlib.suppress(OSError):
                        sealed.receipt_path.unlink()
                    with contextlib.suppress(OSError):
                        sealed.binary_path.unlink()
                    directory = sealed.binary_path.parent
                    for _ in range(3):
                        with contextlib.suppress(OSError):
                            directory.rmdir()
                        directory = directory.parent
                if alias_written and alias_path is not None:
                    with contextlib.suppress(OSError):
                        alias_path.unlink()

            try:
                config_key = artifact_store.configuration_key(
                    cas_configuration(args, command, toolchain_after, bound_after))
                sealed = artifact_store.seal_binary(
                    binary,
                    store_root=store_root,
                    commit=git_after['commit'],
                    config_key=config_key,
                    expected_sha256=executable_sha,
                )
                if sealed.sha256 != executable_sha:
                    raise BuildError('sealed CAS snapshot does not match the selected Cargo artifact')
                if alias_path is not None:
                    alias_method = _publish_immutable_alias(
                        sealed.binary_path, alias_path, '--output')
                    alias_written = True
                    alias_stat = os.stat(alias_path)
                    object_stat = os.stat(sealed.object_path)
                    alias_same_inode = (
                        (alias_stat.st_dev, alias_stat.st_ino) ==
                        (object_stat.st_dev, object_stat.st_ino))
                canonical_build_alias = sealed.binary_path.with_name(
                    sealed.binary_path.name + '.build.json')
                _require_absent(canonical_build_alias, 'canonical compatibility receipt')
                if alias_path is not None:
                    _require_absent(alias_receipt, '--output receipt')
                store_record = {
                    'schema': artifact_store.STORE_SCHEMA,
                    'root': str(store_root),
                    'object': str(sealed.object_path),
                    'binary': str(sealed.binary_path),
                    'receipt': str(sealed.receipt_path),
                    'build_receipt': str(canonical_build_alias),
                    'binary_sha256': sealed.sha256,
                    'config_key': sealed.config_key,
                    'build_id': sealed.build_id,
                    'method': sealed.method,
                    'reused': sealed.reused,
                    'copied_bytes': sealed.copied_bytes,
                    'output_alias': None if alias_path is None else {
                        'path': str(alias_path),
                        'receipt': str(alias_receipt),
                        'method': alias_method,
                        'same_inode_as_cas_object': alias_same_inode,
                        'overwrote_existing': False,
                    },
                }
                try:
                    report = receipt.make_receipt_v2(
                        binary_path=sealed.binary_path,
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
                            'relocated_artifact': True,
                            'original_artifact_sha256': sealed.sha256,
                            'build_options': normalized['build_options'],
                            'artifact_store': store_record,
                        },
                    )
                except receipt.ReceiptError as error:
                    raise _as_build_error(error) from error
                try:
                    artifact_store.write_receipt(sealed, report)
                except artifact_store.ArtifactStoreError as error:
                    raise _as_build_error(error) from error
                _publish_immutable_alias(
                    sealed.receipt_path, canonical_build_alias,
                    'canonical compatibility receipt')
                canonical_build_alias_written = True
                if alias_path is not None:
                    _publish_immutable_alias(
                        sealed.receipt_path, alias_receipt, '--output receipt')
                    alias_receipt_written = True
                return report
            except artifact_store.ArtifactStoreError as error:
                cleanup_publication()
                raise _as_build_error(error) from error
            except BaseException:
                cleanup_publication()
                raise
        except BaseException:
            if not cas:
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
    parser.add_argument('--artifact-store',
                        help='explicit managed artifact-store root; opt in to sealing the completed '
                             'binary as an immutable content-addressed snapshot')
    parser.add_argument('--output',
                        help='optional compatibility alias path for the immutable CAS snapshot; '
                             'requires --artifact-store')
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
