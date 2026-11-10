#!/usr/bin/env python3
"""Build one batch of native binaries and integration tests from one clean.

``scripts/build_native.py`` and ``scripts/build_native_test.py`` each clear the
rootyard package and then compile; running them for N selected artifacts costs
N clean+compile cycles of the rootyard library. This driver keeps every safety
property of those two transactions but pays for the clean once:

* it holds the same canonical ``build_lock`` in ``canonical_target()`` for the
  whole transaction, so no ``build_native.py``, ``build_native_test.py`` or
  other batch can interleave a ``cargo clean`` or overwrite an artifact;
* it runs exactly one ``cargo clean --package rootyard`` and then exactly one
  ``cargo build --locked --profile test`` that selects every requested
  ``--bin`` and ``--test`` target with the same features, no-default-features,
  ``[build] target``, package debug/``strip=debuginfo`` override and
  toolchain. ``cargo build --locked --profile test`` accepts ``--bin`` *and*
  ``--test`` in one invocation, so the application binaries and the selected
  integration tests come from one compiler run (``cargo rustc --profile
  test`` takes a single target and cannot);
* Cargo events are filtered by package: artifacts of the selected rootyard
  package are indexed by their real ``target.kind`` (``lib``/``bin``/``test``),
  name, executable and profile; artifacts of dependencies Cargo happens to
  rebuild in the same invocation are skipped and never receipted, because a
  legal dependency must not make a build fail;
* it fails closed unless every selected artifact is reported ``Fresh=false``,
  the rootyard lib is ``Fresh=false`` and is bound to every binary receipt,
  the exact-rootyard-package binary artifacts carry their executable path and
  resolve to ``<canonical target>/debug/<name>``, exactly one selected test
  artifact is reported per ``--test`` with a ``test`` profile, a ``Fresh=false``
  event and an on-disk executable, exactly one successful ``build-finished``
  event exists, and the source-input digest, ``Cargo.lock``, every selected
  test source, HEAD and the working-tree state are identical before and after
  the build;
* it copies test executables outside ``CARGO_TARGET_DIR`` (mode 0700) so a
  later ``cargo clean --package rootyard`` cannot delete them, and it never
  moves or rewrites a binary in ``CARGO_TARGET_DIR``;
* receipts use the field sets of the two standalone builders, so
  ``native_report_manifest.py``, ``NativeProfile`` (``blob_only_service.py``)
  and the RefStore backup drills accept them unchanged. ``command`` is the
  exact one cargo invocation and ``clean_command`` the single clean, so no
  receipt pretends each artifact was cleaned and built on its own;
* receipts and the batch manifest are published only after *all* requirements
  hold and the sources are still unchanged, by renamed directory swaps; a
  failure removes every receipt/manifest and relocated executable this
  transaction could have installed. There is no option that skips Cargo.

Cargo's own target-dir resolution is recorded rather than reimplemented: the
build appends ``--config build.target-dir=<canonical target>`` (the real
project has no relative ``[build].target-dir`` and ignores it), and
``cargo metadata`` is recorded so a toolchain that redirected executables
elsewhere is visible in the batch manifest.

Python here orchestrates; the only executable artifacts are those Rust targets.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

import build_native
from build_native import BuildError, build_lock, source_digest
from build_native_test import FEATURES


def _root():
    """The workspace: bound to build_native.ROOT so both share one target and lock."""
    return build_native.ROOT


NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]{0,127}$')
IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]*$')
PACKAGE = 'rootyard'
DEFAULT_BIN = 'rootyard'
#: Program names ``src/main.rs`` dispatches on that are deliberately not built here.
KNOWN_FORBIDDEN_BINS = ('rootyard-view-lab', 'rootyard-workspace-lab')
KIND = 'rootyard/native-build-batch'
RECEIPT_VERSION = 1
MANIFEST_NAME = 'rootyard-native-build-batch.json'
CLEAN_COMMAND = ['cargo', 'clean', '--package', PACKAGE]
#: Environment that would silently change the workspace, profile or target.
PASSTHROUGH_VARIABLES = (
    'RUSTFLAGS',
    'CARGO_ENCODED_RUSTFLAGS',
    'CARGO_BUILD_TARGET',
    'CARGO_BUILD_RUSTFLAGS',
    'CARGO_BUILD_TARGET_DIR',
    'CARGO_BUILD_BUILD_DIR',
    'CARGO_PROFILE_DEV_DEBUG',
    'CARGO_PROFILE_TEST_DEBUG',
    'CARGO_PROFILE_DEV_STRIP',
    'CARGO_PROFILE_TEST_STRIP',
)


def canonical_target():
    """The shared build lock lives in this directory; the canonical function is build_native's."""
    return build_native.canonical_target()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def git_output(*arguments):
    return subprocess.check_output(['git', *arguments], cwd=_root(), text=True)


def git_state():
    """HEAD commit/tree plus the tracked working-tree state (staged and unstaged).

    ``--untracked-files=no`` keeps the comparison about source Cargo reads: a
    build writes only ignored ``test-results/`` and ``target/`` files.
    """
    head = git_output('rev-parse', 'HEAD').strip()
    commit = git_output('rev-parse', '--verify', 'HEAD^{commit}').strip()
    tree = git_output('rev-parse', 'HEAD^{tree}').strip()
    status = git_output('status', '--porcelain', '--untracked-files=no')
    return {'head': head, 'commit': commit, 'tree': tree, 'status': status}


def run_tool(command):
    """Run a probe (``rustup``, ``cargo --version``); Cargo itself is only started by run_json_build."""
    return subprocess.run(command, cwd=_root(), capture_output=True, text=True, check=False)


def toolchain_channel():
    path = _root() / 'rust-toolchain.toml'
    if path.is_file():
        match = re.search(r'^\s*channel\s*=\s*"([^"]+)"', path.read_text(), re.MULTILINE)
        if match:
            return match.group(1), 'rust-toolchain.toml'
    override = run_tool(['rustup', 'show', 'active-toolchain'])
    if override.returncode == 0 and override.stdout.split():
        return override.stdout.split()[0], 'rustup override'
    raise BuildError('no pinned Rust toolchain: rust-toolchain.toml is missing and rustup reports no override')


def reject_passthrough_environment():
    found = sorted(name for name in PASSTHROUGH_VARIABLES if os.environ.get(name))
    if found:
        raise BuildError('refusing inherited profile/target environment: ' + ', '.join(found) +
                         '; pass the batch options instead so the recorded command is the build')


def host_architecture():
    machine = platform.machine()
    return {'target_triple': target_triple(), 'os': platform.system().lower(), 'machine': machine,
            'cpu_count': os.cpu_count()}


def target_triple():
    """The triple this compile will use, from a scratch rustc invocation (no RUSTFLAGS)."""
    output = subprocess.check_output(['rustc', '-vV'], text=True)
    for line in output.splitlines():
        if line.startswith('host: '):
            return line.split(': ', 1)[1].strip()
    raise BuildError('rustc -vV did not report a host triple')


def rustc_version():
    return subprocess.check_output(['rustc', '--version'], text=True).strip()


# -- Cargo.toml metadata (batch-local, deliberately small) ---------------------
QUOTED = re.compile(r'"([^"]*)"')


def parse_cargo_toml(text):
    """Read the static package fields the batch needs from this repository's Cargo.toml.

    The workspace is one ``[package]`` with ``[features]``, ``[dependencies]``,
    ``[[bin]]`` and (optional) ``[[test]]`` tables and no ``workspace = true``
    inheritance for these keys; arrays of other tables (``[[bench]]`` ...) are
    skipped. Anything unexpected raises instead of guessing, and
    ``cargo metadata`` remains the authority for the package id itself.
    """
    package = {}
    features, optional = {}, {}
    targets = {'bin': [], 'test': []}
    section, current = None, None
    for raw in text.splitlines():
        if raw.lstrip().startswith('#'):
            continue
        line = raw.strip()
        if not line:
            continue
        if line.startswith('[') and line.endswith(']'):
            current = None
            if line.startswith('[[') and line.endswith(']]'):
                kind = line[2:-2].strip()
                if kind in targets:
                    current = {}
                    targets[kind].append(current)
                    section = kind
                else:
                    section = None
                continue
            section = line[1:-1].strip()
            if section not in ('package', 'features', 'dependencies'):
                section = None
            continue
        key, separator, value = line.partition('=')
        if not separator:
            continue
        key, value = key.strip().strip('"'), value.strip()
        if current is not None:
            if key == 'name':
                current['name'] = value.strip('"')
            elif key == 'path':
                current['path'] = value.strip('"')
            elif key == 'required-features':
                current['required_features'] = QUOTED.findall(value)
        elif section == 'package' and key in ('name', 'version', 'default-run'):
            package[key] = value.strip('"')
        elif section == 'features':
            names = [name for name in QUOTED.findall(value) if not name.startswith('dep:')]
            features[key] = names
        elif section == 'dependencies' and 'optional = true' in value and 'dep:' + key not in text:
            optional[key] = key.replace('-', '_')
    if not any(single.get('name') == PACKAGE for single in targets['bin']) and \
            (_root() / 'src' / 'main.rs').is_file():
        targets['bin'].insert(0, {'name': PACKAGE, 'path': 'src/main.rs', 'required_features': [],
                                  'implicit': True})
    for single in targets['bin']:
        if 'path' not in single:
            raise BuildError('Cargo.toml [[bin]] without a path is not understood')
        single.setdefault('required_features', [])
    for single in targets['test']:
        if 'name' not in single or 'path' not in single:
            raise BuildError('Cargo.toml [[test]] without name or path is not understood')
        single.setdefault('required_features', [])
    if 'name' not in package:
        raise BuildError('Cargo.toml has no [package] name')
    return {'package': package, 'features': features,
            'default_features': features.get('default', []),
            'optional_features': optional, 'bins': targets['bin'], 'tests': targets['test']}


# -- argument validation -----------------------------------------------------
def unique_identifiers(values, flag):
    seen = []
    for value in values or []:
        if not NAME.match(value):
            raise BuildError(flag + ' must be plain Rust target identifiers: ' + repr(value))
        if value in seen:
            raise BuildError(flag + ' repeats ' + repr(value) + '; select each artifact once')
        seen.append(value)
    return seen


def enabled_features(manifest, args):
    """Effective feature set of this build from the manifest's default and CLI features."""
    enabled = set(filter(None, (args.features or '').split(',')))
    if not args.no_default_features:
        enabled |= set(manifest['default_features'])
    return enabled


def bin_specs_for(manifest, args):
    enabled = enabled_features(manifest, args)
    bins = unique_identifiers(args.bin, '--bin')
    if args.all_bins and bins:
        raise BuildError('--all-bins and --bin are mutually exclusive')
    listed = {entry['name']: entry for entry in manifest['bins']}
    selected = []
    if args.all_bins:
        selected = list(manifest['bins'])
    else:
        for name in bins:
            if name not in listed:
                raise BuildError(name + ' is not a bin target of the rootyard package')
            selected.append(listed[name])
    for entry in selected:
        if not set(entry['required_features']) <= enabled:
            raise BuildError('bin ' + entry['name'] + ' requires features ' +
                             ', '.join(entry['required_features']))
        if entry['name'] in KNOWN_FORBIDDEN_BINS:
            raise BuildError(entry['name'] + ' is not built here; it needs its own toolchain/profile and '
                             'cannot share this batch')
    return selected


def test_specs_for(manifest, args):
    enabled = enabled_features(manifest, args)
    listed = {entry['name']: entry for entry in manifest['tests']}
    specs = []
    for name in unique_identifiers(args.test, '--test'):
        if name in listed:
            if not set(listed[name]['required_features']) <= enabled:
                raise BuildError('test ' + name + ' requires features ' +
                                 ', '.join(listed[name]['required_features']))
            specs.append({'name': name, 'source': _root() / listed[name]['path'], 'declared': True})
            continue
        if not IDENT.match(name):
            raise BuildError(name + ' is neither a declared test target nor a tests/*.rs file')
        specs.append({'name': name, 'source': _root() / 'tests' / (name + '.rs'), 'declared': False})
    for spec in specs:
        if not spec['source'].is_file():
            raise BuildError('integration-test source is missing: ' + str(spec['source']))
    return specs


@dataclass(frozen=True)
class Selection:
    features: str | None
    no_default_features: bool
    package_debug: str | None
    strip_debuginfo: bool

    def profile_overrides(self):
        """The ``--config`` pairs build_native_test.py records for dev and test."""
        values = []
        if self.package_debug is not None:
            values += ['profile.dev.package.rootyard.debug=' + self.package_debug,
                       'profile.test.package.rootyard.debug=' + self.package_debug]
        if self.strip_debuginfo:
            values += ['profile.dev.package.rootyard.strip="debuginfo"',
                       'profile.test.package.rootyard.strip="debuginfo"']
        return values

    def as_record(self):
        return {'features': self.features, 'no_default_features': self.no_default_features,
                'profile': 'test', 'package_debug': self.package_debug,
                'strip_debuginfo': self.strip_debuginfo}


@dataclass(frozen=True)
class Plan:
    selection: Selection
    bins: list
    tests: list
    outputs: list
    manifest_out: Path


def resolve_output(raw):
    value = Path(raw).expanduser()
    return (_root() / value if not value.is_absolute() else value).resolve()


def plan_batch(args, manifest):
    """Validate one batch request completely before any Cargo command runs."""
    if args.features and not FEATURES.match(args.features):
        raise BuildError('--features must be comma-separated Rust feature identifiers')
    bin_specs = bin_specs_for(manifest, args)
    test_specs = test_specs_for(manifest, args)
    if not bin_specs and not test_specs:
        raise BuildError('select at least one --bin, --test or --all-bins')
    enabled = enabled_features(manifest, args)
    unknown = enabled - (set(manifest['features']) | set(manifest['default_features']))
    if unknown:
        raise BuildError('unknown features: ' + ', '.join(sorted(unknown)))
    required = [feature for dependency, feature in manifest['optional_features'].items()
                if not any('dep:' + dependency in names for names in manifest['features'].values())]
    for feature in required:
        if feature not in enabled:
            raise BuildError('feature ' + feature + ' (optional dependency without a dep: feature) must be '
                             'enabled explicitly; --no-default-features would silently change the profile')

    target = canonical_target()
    outputs = [resolve_output(raw) for raw in args.output or []]
    if len(set(outputs)) != len(outputs):
        raise BuildError('--output repeats a destination')
    for output in outputs:
        if output == target or target in output.parents:
            raise BuildError('--output must be outside CARGO_TARGET_DIR so a later clean cannot delete '
                             'it: ' + str(output))
    if len(outputs) != len(test_specs):
        raise BuildError('--output must be given exactly once per --test (got ' + str(len(outputs)) +
                         ' outputs for ' + str(len(test_specs)) + ' tests)')

    destinations = args.bin_destination or [str(target / 'debug' / spec['name']) for spec in bin_specs]
    if len(destinations) != len(bin_specs):
        raise BuildError('--bin-destination must be given exactly once per --bin')
    for spec, raw in zip(bin_specs, destinations):
        if resolve_output(raw) != target / 'debug' / spec['name']:
            raise BuildError('binary ' + spec['name'] + ' may only be recorded at its canonical '
                             '"<target>/debug/' + spec['name'] + '" location')
    for spec in test_specs:
        if spec['name'] in {item['name'] for item in bin_specs}:
            raise BuildError('test ' + spec['name'] + ' collides with a binary of the same name')
        if not spec['source'].is_file():
            raise BuildError('integration-test source is missing: ' + str(spec['source']))

    manifest_out = resolve_output(args.manifest_out)
    manifest_out = manifest_out if manifest_out.suffix == '.json' else manifest_out / MANIFEST_NAME
    if manifest_out == target or target in manifest_out.parents:
        raise BuildError('--manifest-out must be outside CARGO_TARGET_DIR')
    return Plan(Selection(args.features, args.no_default_features, args.package_debug, args.strip_debuginfo),
                bin_specs, test_specs, outputs, manifest_out)


# -- Cargo events -------------------------------------------------------------
def emit_command(selection):
    """The single cargo invocation: profile/test, exact bins and tests, one common config."""
    command = ['cargo', 'build', '--locked', '--profile', 'test']
    for value in selection.profile_overrides():
        command += ['--config', value]
    # A TOML string, so Cargo never parses a path as a dotted key expression.
    command += ['--config', 'build.target-dir = "' + str(canonical_target()) + '"']
    return command


def prepare_destinations(plan):
    """Create every destination's parent directory before anything is measured."""
    for output in plan.outputs:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.is_dir() and not output.is_symlink():
            raise BuildError('--output is a directory: ' + str(output))
    plan.manifest_out.parent.mkdir(parents=True, exist_ok=True)


def run_json_build(argv):
    """Stream Cargo JSON events; non-JSON stdout, a crash or a non-zero status fails."""
    events = []
    process = subprocess.Popen(argv, cwd=_root(), stdout=subprocess.PIPE, stderr=None, text=True, bufsize=1)
    try:
        # Explicit close (not an abandoned loop-local reference) releases the
        # pipe the moment the last event was read.
        with process.stdout:
            lines = list(process.stdout)
        for line in lines:
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
    return events


def _profile(event):
    profile = event.get('profile') or {}
    return {key: profile.get(key) for key in ('opt_level', 'debuginfo', 'debug_assertions',
                                               'overflow_checks', 'test')}


def artifact_index(events, package):
    """Index the fresh=False lib/bin/test compiler artifacts of exactly one selected package.

    Cargo reports every unit it built or found fresh in this invocation, so a
    selected package with a dependency that is rebuilt reports that
    dependency's artifacts in the same stream (a ``depcrate`` lib next to
    ``rootyard``). Only events whose
    ``package_id`` is the selected package are indexed: a foreign artifact
    says nothing about what this batch compiled (a fresh or dirty foreign
    dependency is Cargo's own concern, not a receipt for a selected target),
    so it is skipped rather than failed on. Inside the selected package the
    checks stay closed: any Fresh=true selected artifact, a lib other than
    the package-named one, a duplicate, a kind other than lib/bin/test, or a
    bin/test without an executable is rejected.

    ``target.kind`` (``["test"]``) is the classification of a target, not
    ``profile.test``: a ``harness = false`` integration test has kind
    ``["test"]`` and Cargo still reports ``profile.test`` for it.
    """
    if not package:
        raise BuildError('no rootyard package id to bind artifacts to')
    lib = None
    bins, tests = {}, {}
    skipped = {}
    for event in events:
        if event.get('reason') != 'compiler-artifact':
            continue
        if event.get('package_id') != package:
            skipped[event.get('package_id')] = skipped.get(event.get('package_id'), 0) + 1
            continue
        target = event.get('target') or {}
        name = target.get('name')
        kinds = list(target.get('kind') or [])
        if event.get('fresh') is not False:
            raise BuildError(f'Cargo reported a Fresh {name} artifact of {PACKAGE}; refusing a stale receipt')
        if kinds == ['lib']:
            if name != PACKAGE:
                raise BuildError(f'{PACKAGE} reported an unexpected lib target {name!r}; the batch binds '
                                 f'the {PACKAGE} lib to every receipt')
            if lib is not None:
                raise BuildError(f'Cargo reported two {PACKAGE} lib artifacts for one build')
            lib = {'target': name, 'kind': 'lib', 'fresh': False, 'package_id': event.get('package_id')}
        elif kinds == ['bin']:
            executable = event.get('executable')
            if not executable:
                raise BuildError(f'{PACKAGE} binary artifact {name} has no executable path')
            if not name or name in bins:
                raise BuildError(f'Cargo reported a duplicate or unnamed {PACKAGE} bin artifact: {name!r}')
            bins[name] = {'target': name, 'kind': 'bin', 'fresh': False,
                          'executable': str(Path(executable).resolve()),
                          'package_id': event.get('package_id'), 'profile': _profile(event)}
        elif kinds == ['test']:
            executable = event.get('executable')
            if not executable:
                raise BuildError(f'{PACKAGE} integration-test artifact {name} has no executable path')
            if not name or name in tests:
                raise BuildError(f'Cargo reported duplicate {name!r} {PACKAGE} test artifacts; '
                                 'expected exactly one')
            tests[name] = {'target': name, 'kind': 'test', 'fresh': False,
                           'profile': _profile(event), 'executable': str(Path(executable).resolve()),
                           'package_id': event.get('package_id')}
        else:
            raise BuildError(f'unexpected {PACKAGE} artifact {name!r} {kinds}; only lib, bin and test '
                             'artifacts belong in this batch')
    if lib is None:
        raise BuildError(f'Cargo did not report a {PACKAGE} lib compiler-artifact')
    return lib, bins, tests, skipped


def require_build_finished(events):
    finished = [event for event in events if event.get('reason') == 'build-finished']
    if len(finished) != 1 or finished[0].get('success') is not True:
        raise BuildError('Cargo did not report exactly one successful build-finished event')


def select_artifacts(events, package, bin_specs, test_specs):
    """Return ``(lib, [bin artifacts], [test artifacts])`` for exactly the selected targets.

    Foreign-package artifacts (dependencies Cargo rebuilt alongside the
    selected package) are skipped by artifact_index and never receipted.
    """
    lib, bins, tests, _ = artifact_index(events, package)
    require_build_finished(events)
    wanted_bins = [spec['name'] for spec in bin_specs]
    missing = [name for name in wanted_bins if name not in bins]
    if missing:
        raise BuildError('Cargo did not report the requested binaries: ' + ', '.join(missing))
    extra = sorted(set(bins) - set(wanted_bins))
    if extra:
        raise BuildError('Cargo reported binaries that were not selected: ' + ', '.join(extra))
    selected_bins = [bins[name] for name in wanted_bins]
    for artifact in selected_bins:
        expected = str(canonical_target() / 'debug' / artifact['target'])
        if artifact['executable'] != expected:
            raise BuildError(f'rootyard executable {artifact["executable"]} does not match {expected}')
    names = [spec['name'] for spec in test_specs]
    missing = [name for name in names if name not in tests]
    if missing:
        raise BuildError('Cargo did not report the requested test artifacts: ' + ', '.join(missing))
    extra = sorted(set(tests) - set(names))
    if extra:
        raise BuildError('Cargo reported tests that were not selected: ' + ', '.join(extra))
    selected_tests = []
    for spec in test_specs:
        artifact = tests[spec['name']]
        # The test profile is the recorded build selection (--profile test),
        # not a re-derivation: a harness = false integration test is still a
        # kind ["test"] target and Cargo reports profile.test for it.
        if artifact['profile'].get('test') is not True:
            raise BuildError('selected test artifact ' + spec['name'] + ' was not built with a test profile')
        if not Path(artifact['executable']).is_file():
            raise BuildError('built test executable is missing: ' + artifact['executable'])
        selected_tests.append(artifact)
    return lib, selected_bins, selected_tests


def same_filesystem(paths):
    """A copy keeps file identity (mode, xattrs) only inside one filesystem.

    Missing paths are skipped here; the copy itself fails closed on them.
    """
    families = set()
    for path in paths:
        path = Path(path).resolve()
        if not path.exists():
            continue
        st = path.stat()
        families.add((os.major(st.st_dev), os.minor(st.st_dev)))
    if len(families) > 1:
        raise BuildError('selected artifacts and their destinations are on different filesystems; '
                         'a copy there could not preserve file identity')


class Publisher:
    """Stage every payload beside its destination and publish by ``os.replace``.

    A receipt is written to a hidden sibling; a relocated test executable is
    copied to a hidden sibling with the same copy+chmod+hash procedure
    ``build_native_test.py`` uses, and the compiled artifact stays in place.
    Nothing is published until Cargo, the event checks, the digests and every
    staging check succeeded; each payload is then renamed over its destination,
    so a reader sees the previous file or the complete new one, and a failure
    removes every staging file and any already renamed receipt.
    """

    def __init__(self):
        self.entries = []

    def _sibling(self, destination):
        return Path(destination).with_name('.' + Path(destination).name + '.batch-new')

    def text(self, destination, payload):
        self.entries.append((Path(destination), None, json.dumps(payload, indent=2) + '\n'))

    def copy(self, source, destination):
        self.entries.append((Path(destination), Path(source), None))

    def staging(self):
        return [self._sibling(destination) for destination, _, _ in self.entries]

    def stage(self):
        for destination, source, text in self.entries:
            temporary = self._sibling(destination)
            temporary.parent.mkdir(parents=True, exist_ok=True)
            if source is not None:
                verified_copy(source, temporary)
            else:
                temporary.write_text(text)

    def publish(self):
        self.abort()
        published = []
        try:
            self.stage()
            for destination, source, _ in self.entries:
                temporary = self._sibling(destination)
                if source is not None and sha256_file(temporary) != sha256_file(source):
                    raise BuildError('staged copy ' + str(temporary) + ' differs from ' + str(source))
                if destination.is_dir() and not destination.is_symlink():
                    raise BuildError('planned file destination is a directory: ' + str(destination))
                temporary.replace(destination)
                published.append(destination)
        except BaseException:
            remove_paths(published)
            self.abort()
            raise
        self.abort()

    def abort(self):
        remove_paths(self.staging())


def remove_paths(paths):
    if isinstance(paths, (str, Path)):
        paths = [paths]
    for path in paths:
        path = Path(path)
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()


def verified_copy(source, destination):
    """Fresh 0700 copy of one artifact, byte-identical, renamed into place."""
    source, destination = Path(source), Path(destination)
    temporary = destination.with_name('.' + destination.name + '.copy-tmp')
    try:
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o700)
        if sha256_file(temporary) != sha256_file(source):
            raise BuildError('copy of ' + str(source) + ' does not match the artifact')
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    if sha256_file(destination) != sha256_file(source):
        raise BuildError('published copy ' + str(destination) + ' does not match the artifact')


def cargo_metadata():
    output = subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1', '--offline'],
        cwd=_root(), text=True)
    metadata = json.loads(output)
    packages = [package for package in metadata.get('packages') or [] if package.get('name') == PACKAGE]
    if len(packages) != 1 or not packages[0].get('id'):
        raise BuildError('cargo metadata does not list exactly one rootyard package')
    resolved = Path(metadata.get('target_directory') or '')
    if resolved.resolve() != canonical_target():
        raise BuildError('cargo resolved target directory ' + str(resolved) + ' but the build lock is in ' +
                         str(canonical_target()) + '; the build would not be serialized by this lock')
    return {'target_directory': metadata.get('target_directory'), 'package_id': packages[0]['id']}


def source_snapshot(plan):
    """Every input whose change after the build invalidates the whole batch."""
    return {
        'source_inputs': source_digest(),
        'cargo_lock': sha256_file(_root() / 'Cargo.lock'),
        'tests': {spec['name']: sha256_file(spec['source']) for spec in plan.tests},
        'git': git_state(),
    }


def require_unchanged(before, after, metadata_before=None, metadata_after=None):
    """Fail closed unless the complete source snapshot is identical after the build."""
    if before['source_inputs'] != after['source_inputs']:
        raise BuildError('Source inputs changed during build; rebuild before recording acceptance.')
    if before['cargo_lock'] != after['cargo_lock']:
        raise BuildError('Cargo.lock changed during build; refusing the receipt')
    for name in before['tests']:
        if before['tests'][name] != after['tests'][name]:
            raise BuildError('integration-test source ' + name + ' changed during build; refusing the receipt')
    if before['git'] != after['git']:
        raise BuildError('HEAD or working-tree state changed during build; refusing the receipt')
    if metadata_after is not None and metadata_before != metadata_after:
        raise BuildError('cargo metadata (package id or target directory) changed during build')


def tool_version(command):
    process = run_tool(command)
    return process.stdout.strip() if process.returncode == 0 else None


def toolchain_record(selection):
    """Pin, active toolchain, compiler, Cargo, features, profile and architecture of the build."""
    channel, source = toolchain_channel()
    active = run_tool(['rustup', 'show', 'active-toolchain'])
    reported = active.stdout.strip() if active.returncode == 0 else ''
    if not reported.startswith(channel):
        raise BuildError(f'active toolchain {reported!r} is not the pinned {channel!r} ({source}); '
                         'install and select it before building')
    return {'pinned_channel': channel, 'pin_source': source, 'active_toolchain': reported,
            'rustc': rustc_version(), 'cargo': tool_version(['cargo', '--version']),
            **selection.as_record(), 'architecture': host_architecture()}


def binary_receipt(*, path, digests, toolchain, command, targets, lock_path, timings):
    """The ``build_native.py`` receipt fields, bound to this batch's single build."""
    path = Path(path)
    return {
        'version': RECEIPT_VERSION,
        'binary_sha256': sha256_file(path),
        'source_inputs_sha256': digests['source_inputs'],
        'workspace_commit': digests['commit'],
        'git_head': digests['git_head'],
        'working_tree': digests['working_tree'],
        'cargo_lock_sha256': digests['cargo_lock'],
        'integration_test_sources_sha256': digests['test_sources'],
        'toolchain': toolchain,
        'rustc': toolchain['rustc'],
        'features': {'enabled': toolchain['features'],
                     'no_default_features': toolchain['no_default_features'], 'profile': 'test',
                     'package_debug': toolchain['package_debug'],
                     'strip_debuginfo': toolchain['strip_debuginfo']},
        'architecture': toolchain['architecture'],
        'command': command,
        'package_rebuilt': True,
        'clean_command': CLEAN_COMMAND,
        'clean_commands': 1,
        'build_commands': 1,
        'target_dir': str(canonical_target()),
        'lock_file': str(lock_path),
        'fresh_false_artifacts': targets,
        'duration_seconds': timings,
        'batch': {'kind': KIND, 'receipt_version': RECEIPT_VERSION, 'binary': path.name,
                  'targets': [item['target'] for item in targets]},
    }


def test_receipt(*, path, artifact, digests, toolchain, command, targets, lock_path, timings):
    """The ``build_native_test.py`` receipt fields for one relocated test executable."""
    path = Path(path)
    return {
        'kind': 'rust-integration-test',
        'relocated_artifact': True,
        'original_artifact_sha256': artifact['original_artifact_sha256'],
        'workspace_commit': digests['commit'],
        'fresh': False,
        'source_inputs_sha256': digests['source_inputs'],
        'binary_sha256': sha256_file(path),
        'integration_test_source_sha256': artifact['source_sha256'],
        'cargo_lock_sha256': digests['cargo_lock'],
        'command': command,
        'rustc': toolchain['rustc'],
        'package_rebuilt': True,
        'fresh_false_artifacts': [artifact],
        'integration_test_source': str(Path(artifact['source'])),
        'toolchain': toolchain,
        'architecture': toolchain['architecture'],
        'target_dir': str(canonical_target()),
        'lock_file': str(lock_path),
        'duration_seconds': timings,
        'batch': {'kind': KIND, 'receipt_version': RECEIPT_VERSION, 'binary': path.name,
                  'targets': [item['target'] for item in targets] + [artifact['target']]},
    }


def run_batch(args):
    """Run the whole transaction and return the published batch manifest."""
    reject_passthrough_environment()
    manifest = parse_cargo_toml((_root() / 'Cargo.toml').read_text())
    plan = plan_batch(args, manifest)
    selection = plan.selection
    target = canonical_target()
    started = time.monotonic()

    prepare_destinations(plan)
    metadata_before = cargo_metadata()
    toolchain = toolchain_record(selection)
    command = emit_command(selection)
    for spec in plan.bins:
        command += ['--bin', spec['name']]
    for spec in plan.tests:
        command += ['--test', spec['name']]
    if selection.features:
        command += ['--features', selection.features]
    if selection.no_default_features:
        command += ['--no-default-features']
    command += ['--message-format=json-render-diagnostics']

    bin_receipts = [(spec, target / 'debug' / (spec['name'] + '.build.json')) for spec in plan.bins]
    test_receipts = list(zip(plan.tests, plan.outputs, [Path(str(output) + '.build.json')
                                                        for output in plan.outputs]))
    owned = [path for _, path in bin_receipts] + [path for _, _, path in test_receipts] + \
        [plan.manifest_out] + list(plan.outputs)
    with build_lock(target) as lock_path:
        # A failed or interrupted batch never leaves a receipt, manifest or
        # relocated executable from an earlier or partial transaction behind.
        remove_paths(owned + [path.with_name('.' + path.name + '.batch-new') for path in owned])
        before = source_snapshot(plan)
        clean_started = time.monotonic()
        subprocess.run(CLEAN_COMMAND, cwd=_root(), check=True)
        clean_seconds = round(time.monotonic() - clean_started, 3)
        build_started = time.monotonic()
        events = run_json_build(command)
        build_seconds = round(time.monotonic() - build_started, 3)
        after = source_snapshot(plan)
        require_unchanged(before, after)
        lib, bins, tests = select_artifacts(events, metadata_before['package_id'], plan.bins, plan.tests)
        metadata_after = cargo_metadata()
        if metadata_after['target_directory'] != metadata_before['target_directory'] or \
                metadata_after['package_id'] != metadata_before['package_id']:
            raise BuildError('cargo metadata (package id or target directory) changed during build')
        require_unchanged(before, after)
        if tests:
            same_filesystem([artifact['executable'] for artifact in tests] + plan.outputs)
            for artifact, output in zip(tests, plan.outputs):
                if Path(artifact['executable']).resolve() == output:
                    raise BuildError('relocated output would overwrite the compiled artifact ' + str(output))

        digests = {'source_inputs': before['source_inputs'], 'cargo_lock': before['cargo_lock'],
                   'commit': before['git']['commit'], 'git_head': before['git']['head'],
                   'working_tree': {key: before['git'][key] for key in ('tree', 'status')},
                   'test_sources': before['tests']}
        timings = {'clean_seconds': clean_seconds, 'build_seconds': build_seconds}
        targets = [lib] + bins
        publisher = Publisher()
        artifacts = []
        # Receipts describe the sources and artifacts after everything that can
        # change them was measured; their digests are taken when they are staged.
        for (spec, path), artifact in zip(bin_receipts, bins):
            publisher.text(path, binary_receipt(path=artifact['executable'], digests=digests,
                                                toolchain=toolchain, command=command, targets=targets,
                                                lock_path=lock_path, timings=timings))
            stat = os.stat(artifact['executable'])
            artifacts.append({'kind': 'bin', 'target': spec['name'], 'artifact': artifact['executable'],
                              'receipt': str(path), 'fresh': False,
                              'sha256': sha256_file(artifact['executable']), 'size': stat.st_size,
                              'mtime_ns': stat.st_mtime_ns, 'duration_seconds': build_seconds})
        copy_receipts = []
        for (spec, output, path), artifact in zip(test_receipts, tests):
            original = artifact['executable']
            copy_artifact = dict(artifact, source=str(spec['source']), output=str(output),
                                 source_sha256=before['tests'][spec['name']],
                                 original_artifact_sha256=sha256_file(original))
            publisher.copy(original, output)
            copy_receipts.append((path, copy_artifact))
            artifacts.append({'kind': 'test', 'target': spec['name'], 'artifact': str(output),
                              'original_artifact': original,
                              'original_artifact_sha256': copy_artifact['original_artifact_sha256'],
                              'receipt': str(path), 'fresh': False,
                              'sha256': copy_artifact['original_artifact_sha256'],
                              'source': str(spec['source']), 'source_sha256': copy_artifact['source_sha256'],
                              'duration_seconds': build_seconds})
        # A test receipt hashes the relocated executable, which only exists when
        # the batch stages it; build the payload after staging the copies.
        publisher.stage()
        for path, artifact in copy_receipts:
            staged = Path(artifact['output']).with_name('.' + Path(artifact['output']).name + '.batch-new')
            publisher.text(path, test_receipt(path=staged, artifact=artifact, digests=digests,
                                              toolchain=toolchain, command=command, targets=targets,
                                              lock_path=lock_path, timings=timings))
        manifest = {
            'kind': KIND,
            'manifest_version': RECEIPT_VERSION,
            'status': 'passed',
            'source_commit': digests['commit'],
            'source_inputs_sha256': digests['source_inputs'],
            'working_tree': digests['working_tree'],
            'cargo_lock_sha256': digests['cargo_lock'],
            'toolchain': toolchain,
            'features': selection.as_record(),
            'architecture': toolchain['architecture'],
            'target_directory': str(target),
            'lock_file': str(lock_path),
            'cargo_metadata_target_directory': metadata_after['target_directory'],
            'cargo_package_id': metadata_after['package_id'],
            'clean': {'command': CLEAN_COMMAND, 'commands': 1, 'duration_seconds': clean_seconds},
            'build': {'command': command, 'commands': 1, 'duration_seconds': build_seconds,
                      'fresh_false_artifacts': targets},
            'artifacts': artifacts,
            'duration_seconds': round(time.monotonic() - started, 3),
        }
        # Stage every remaining payload, then re-check the sources at the moment
        # the receipts are about to become visible; publish renames them in place.
        publisher.stage()
        for entry in artifacts:
            if entry['kind'] != 'test':
                continue
            staged = Path(entry['artifact']).with_name('.' + Path(entry['artifact']).name + '.batch-new')
            entry['sha256'] = sha256_file(staged)
            entry['size'] = os.path.getsize(staged)
            staged_receipt = (Path(entry['receipt']).parent /
                              ('.' + Path(entry['receipt']).name + '.batch-new'))
            receipt = json.loads(staged_receipt.read_text())
            if receipt['binary_sha256'] != entry['sha256']:
                raise BuildError('staged ' + entry['target'] + ' copy does not match its receipt')
        require_unchanged(before, source_snapshot(plan))
        # The batch manifest is the last renamed payload: its presence is the
        # commit marker that every receipt of this transaction is in place.
        publisher.text(plan.manifest_out, manifest)
        publisher.publish()
    return manifest


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description='Build several native binaries and integration tests from one clean.')
    selection = parser.add_argument_group('common build selection (one value for the whole batch)')
    selection.add_argument('--features')
    selection.add_argument('--no-default-features', action='store_true')
    selection.add_argument('--package-debug', choices=('0', '1', '2'))
    selection.add_argument('--strip-debuginfo', action='store_true',
                           help='strip rootyard dev/test debug information')
    selection.add_argument('--all-bins', action='store_true',
                           help='select every [[bin]] whose required features are enabled')
    parser.add_argument('--bin', action='append', default=[], help='bin target name (repeatable)')
    parser.add_argument('--bin-destination', action='append', default=[],
                        help='only for explicit records; must be <target>/debug/<bin>')
    parser.add_argument('--test', action='append', default=[], help='integration-test target (repeatable)')
    parser.add_argument('--output', action='append', default=[],
                        help='relocated executable path outside CARGO_TARGET_DIR, once per --test, in --test order')
    parser.add_argument('--manifest-out', required=True,
                        help='batch manifest path (a directory receives ' + MANIFEST_NAME + ')')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        batch = run_batch(args)
    except (BuildError, subprocess.CalledProcessError, OSError) as error:
        print('build_native_batch: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({key: batch[key] for key in ('status', 'source_commit', 'source_inputs_sha256',
                                                  'toolchain', 'features', 'architecture', 'clean', 'build')}
                     | {'artifacts': [{'kind': entry['kind'], 'target': entry['target'],
                                       'artifact': entry['artifact'], 'receipt': entry['receipt'],
                                       'fresh': entry['fresh']} for entry in batch['artifacts']]},
                     indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
