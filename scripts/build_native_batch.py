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
* the bin and test target set is Cargo's own: one
  ``cargo metadata --no-deps`` is the authority for the ``rootyard`` package's
  targets, their paths and their ``required-features``, so a bin Cargo
  auto-discovers from ``src/bin/*.rs`` is selected exactly like a ``[[bin]]``.
  ``--all-bins`` builds every metadata bin whose required features are enabled
  by this batch's ``--features``/``--no-default-features``; a ``--bin`` or
  ``--test`` name Cargo does not list for the package is refused;
* with any ``--test`` selected, Cargo also builds the other enabled bins of the
  package *without* a ``--bin`` flag of its own (an implicit build: a bin
  integration test runs through its package's bins). Each such bin is accepted
  only when metadata confirms it exists in this package, requires nothing this
  selection lacks, is reported Fresh=false with its own executable at
  ``<canonical target>/debug/<name>``, and is typed ``bin`` by Cargo. It gets
  the same full bin receipt as a requested bin and is marked ``implicit`` in
  that receipt and in the manifest instead of a receipt path; any other
  unselected bin artifact is still refused. Without a ``--test`` the command
  names every bin, so Cargo builds no extra bin and only requested bins are
  accepted. ``rootyard-view-lab`` and ``rootyard-workspace-lab`` are such
  bins: compiling them is part of this package's build, but installing them is
  not acceptance of the ``rootyard`` server, and their receipts say so;
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
  event exists, and the source-input digest, ``Cargo.lock``, every bound input,
  HEAD and the working-tree state are identical before and after the build;
* the bound inputs are what an integration test or the toolchain can compile
  or read beyond the production sources: every ``*.rs`` file under ``tests/``
  (selected entries, transitive ``mod`` helpers and untracked new helpers
  alike), ``rust-toolchain``/``rust-toolchain.toml``, the fixed build-affecting
  ``.cargo/*.toml`` files and the workspace ``build.rs``. Each is recorded by
  repository-relative path, presence and raw-byte SHA-256, every absent
  candidate is listed too, and one ``bound_inputs_sha256`` hashes the sorted
  inventory when it was the same before and after the build. Receipts and the
  manifest carry that summary and the full inventory, so a missing, added or
  edited input cannot disappear from a receipt; ``source_inputs_sha256`` keeps
  its production meaning for the existing receipts. The batch does not parse
  the Rust module graph: ``tests/**/*.rs`` is taken as a whole. Only in-repo
  configuration is hashed, by raw bytes and path: its keys are inspected and no
  value is recorded, and a config whose keys redirect inputs (flags, linker,
  source replacement or a directory) is refused rather than half-recorded;
* it copies test executables outside ``CARGO_TARGET_DIR`` (mode 0700) so a
  later ``cargo clean --package rootyard`` cannot delete them, and it never
  moves or rewrites a binary in ``CARGO_TARGET_DIR``. The compiled artifact and
  each destination may live on different filesystems (a target directory on one
  device and a mounted output volume on another): the copy is staged as a
  hidden ``.<name>.batch-new`` sibling *in the destination's own directory*,
  its SHA-256 is verified against the artifact, and only then is it renamed over
  the destination inside that filesystem. No step requires a rename across
  directories or devices;
* receipts use the field sets of the two standalone builders, so
  ``native_report_manifest.py``, ``NativeProfile`` (``blob_only_service.py``)
  and the RefStore backup drills accept them unchanged. ``command`` is the
  exact one cargo invocation and ``clean_command`` the single clean, so no
  receipt pretends each artifact was cleaned and built on its own. A bin Cargo
  built implicitly alongside a selected test also carries ``implicit_build``:
  it is a real artifact of this package's build, but not one this batch
  requested, and the batch records it rather than dropping it;
* receipts and the batch manifest are published only after *all* requirements
  hold and the sources are still unchanged, each by one ``os.replace`` of its
  own staged sibling onto its own destination; a failure removes every
  receipt/manifest and relocated executable this transaction could have
  installed. There is no option that skips Cargo.

The set of payloads is *not* published atomically. Each file (a bin receipt in
``CARGO_TARGET_DIR``, a relocated executable and its receipt, the batch
manifest) appears complete or not at all, but they may live in different
directories or filesystems and become visible one after another. The commit
marker is the last-renamed batch manifest: a per-file receipt on its own is not
an accepted batch, and a consumer must treat receipts as bound only once the
manifest for that transaction exists.

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
PACKAGE = 'rootyard'
DEFAULT_BIN = 'rootyard'
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
#: Compiler or toolchain selectors that would replace the pinned build.
REJECTED_COMPILER_VARIABLES = (
    'RUSTC',
    'RUSTC_WRAPPER',
    'RUSTC_WORKSPACE_WRAPPER',
    'RUSTDOC',
    'RUSTDOCFLAGS',
    'RUSTUP_TOOLCHAIN',
    'RUSTC_BOOTSTRAP',
)
#: Namespace prefixes whose every variable changes the profile or build.
REJECTED_VARIABLE_PREFIXES = (
    'CARGO_PROFILE_',
    'CARGO_BUILD_',
)
#: Exact name: it defines the batch's canonical target directory.
ALLOWED_TARGET_DIR = 'CARGO_TARGET_DIR'


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


def is_rejected_environment_name(name):
    """Whether this variable name would change the compiler, profile, workspace or target."""
    if name in PASSTHROUGH_VARIABLES or name in REJECTED_COMPILER_VARIABLES:
        return True
    if name == ALLOWED_TARGET_DIR:
        return False
    if name.startswith(REJECTED_VARIABLE_PREFIXES):
        return True
    return (name.startswith('CARGO_TARGET_') and
            (name.endswith('_LINKER') or name.endswith('_RUSTFLAGS')))


def reject_passthrough_environment():
    found = sorted(name for name in os.environ if os.environ.get(name) and
                   is_rejected_environment_name(name))
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


#: Cargo's auto-discovery roots for bins that no ``[[bin]]`` names
#: (``src/main.rs`` and ``src/bin/*.rs``/``src/bin/*/main.rs``). They are
#: defaults, not the target set: ``cargo metadata`` decides what exists, here
#: including ``rootyard-view-lab`` and ``rootyard-workspace-lab`` (opt-in local
#: experiments, not network services). Those labs are real bin artifacts of
#: this package's build and are recorded as such, but a receipt for a lab is
#: not acceptance of ``rootyard``: only ``rootyard`` (``src/main.rs``) is the
#: server binary.
AUTODISCOVERED_BIN_SOURCES = ('src/main.rs', 'src/bin')


def metadata_targets(document):
    """The rootyard package's targets as ``cargo metadata`` lists them, in Cargo's order.

    ``document`` is what :func:`cargo_metadata` returns; each target keeps the
    kind, name, canonical source path and ``required-features`` Cargo reports,
    so an auto-discovered ``src/bin/*.rs`` bin is a target exactly like a
    ``[[bin]]`` one. A bin is marked ``declared`` when a ``[[bin]]`` table or a
    build script must have produced it (it has required-features, the manifest
    names it, or its source is outside Cargo's auto-discovery roots); every
    other bin was auto-discovered. Non-lib/bin/test kinds are refused here.
    """
    root = _root().resolve()
    targets = []
    for raw in document.get('targets') or []:
        kinds = list(raw.get('kind') or [])
        name, source = raw.get('name'), raw.get('src_path')
        if len(kinds) != 1 or not name or not source:
            raise BuildError('cargo metadata listed a target this batch cannot bind: ' + repr(name))
        if kinds[0] not in ('lib', 'bin', 'test'):
            raise BuildError('cargo metadata listed a ' + kinds[0] + ' target ' + name +
                             '; this batch builds only lib, bin and test targets')
        source = Path(source).resolve()
        autodiscovered = source == root / AUTODISCOVERED_BIN_SOURCES[0] or \
            (root / AUTODISCOVERED_BIN_SOURCES[1]) in source.parents
        targets.append({'kind': kinds[0], 'name': name, 'source': str(source),
                        'required_features': [str(feature) for feature in raw.get('required-features') or []],
                        'declared': kinds[0] != 'bin' or bool(raw.get('required-features')) or
                        not autodiscovered or _named_by_manifest(name)})
    return targets


def _named_by_manifest(name):
    """Whether a ``[[bin]]`` table in Cargo.toml names ``name``.

    Cargo reports a ``[[bin]]`` bin and a build-script bin with the same
    fields; only the manifest text tells them apart. This looks for the name
    inside ``[[bin]]`` tables and never interprets them (``required-features``
    and the source path stay ``cargo metadata``'s). Without a Cargo.toml to
    read the bin counts as declared, the conservative side: it is never
    accepted implicitly.
    """
    path = _root() / 'Cargo.toml'
    if not path.is_file():
        return True
    section = None
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped[1:-1].strip()
            continue
        key, separator, value = stripped.partition('=')
        if section == '[bin]' and separator and key.strip() == 'name' and \
                value.strip().strip('"') == name:
            return True
    return False


def bin_specs_for(manifest, args):
    """The requested bins, from the metadata target list and this batch's features."""
    enabled = enabled_features(manifest, args)
    bins = unique_identifiers(args.bin, '--bin')
    if args.all_bins and bins:
        raise BuildError('--all-bins and --bin are mutually exclusive')
    listed = {entry['name']: entry for entry in manifest['bins']}
    selected = []
    if args.all_bins:
        selected = enabled_bins(manifest, args)
    else:
        for name in bins:
            if name not in listed:
                raise BuildError(name + ' is not a bin target of the rootyard package (cargo metadata lists: ' +
                                 ', '.join(sorted(listed)) + ')')
            selected.append(listed[name])
    for entry in selected:
        if not set(entry['required_features']) <= enabled:
            raise BuildError('bin ' + entry['name'] + ' requires features ' +
                             ', '.join(entry['required_features']))
    return selected


def test_specs_for(manifest, args):
    """The requested integration tests, from the metadata test targets only.

    Cargo builds an integration test by target name from ``cargo metadata``
    (an implicit ``tests/<name>.rs`` is such a target unless ``autotests`` or
    a ``[[test]]`` table removes it), so a ``tests/*.rs`` file metadata does
    not list is refused rather than guessed at.
    """
    enabled = enabled_features(manifest, args)
    listed = {entry['name']: entry for entry in manifest['tests']}
    specs = []
    for name in unique_identifiers(args.test, '--test'):
        if name not in listed:
            raise BuildError('cargo metadata does not list the test target ' + name + ' for the ' + PACKAGE +
                             ' package (it lists: ' + ', '.join(sorted(listed)) + ')')
        if not set(listed[name]['required_features']) <= enabled:
            raise BuildError('test ' + name + ' requires features ' +
                             ', '.join(listed[name]['required_features']))
        specs.append({'name': name, 'source': Path(listed[name]['source']), 'declared': True,
                      'implicit': False})
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
    #: Enabled metadata bins no ``--bin``/``--all-bins`` requested.
    implicit_bins: list
    #: Metadata bin names that ``--bin``/``--all-bins`` may have received.
    requested_bin_names: tuple


def enabled_bins(manifest, args):
    """Every metadata bin whose required-features the batch's own selection enables."""
    enabled = enabled_features(manifest, args)
    return [entry for entry in manifest['bins'] if set(entry['required_features']) <= enabled]


def implicit_bins_for(manifest, args):
    """Enabled metadata bins Cargo also builds when ``--test`` selects tests.

    With any ``--test`` the invocation names no bin, and Cargo builds the other
    enabled bins of the selected package as a side effect (an integration test
    runs its package's binaries). That set is exactly the metadata bins whose
    required-features this selection enables (:func:`enabled_bins`) and which
    were not requested; everything else Cargo may report as a bin is unknown
    and refused later. For this package that includes the auto-discovered
    ``rootyard-view-lab`` and ``rootyard-workspace-lab``: they are compiled
    into ``target/debug`` like any bin artifact, but a receipt for them
    (marked ``implicit_build``) does not accept them as the ``rootyard``
    server.
    """
    if not args.test:
        return []
    requested = {entry['name'] for entry in enabled_bins(manifest, args)} \
        if args.all_bins else set(unique_identifiers(args.bin, '--bin'))
    return [entry for entry in enabled_bins(manifest, args) if entry['name'] not in requested]


def resolve_output(raw):
    value = Path(raw).expanduser()
    return (_root() / value if not value.is_absolute() else value).resolve()


def plan_batch(args, manifest):
    """Validate one batch request completely before any Cargo command runs."""
    if args.features and not FEATURES.match(args.features):
        raise BuildError('--features must be comma-separated Rust feature identifiers')
    # Explicit requests are validated whether or not --test is given: a bin
    # this selection cannot enable is refused here, not mistaken for implicit.
    bin_specs = bin_specs_for(manifest, args) if args.bin or args.all_bins else []
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
    implicit = implicit_bins_for(manifest, args)
    requested_names = tuple(entry['name'] for entry in bin_specs) if args.all_bins else \
        tuple(spec['name'] for spec in bin_specs)
    return Plan(Selection(args.features, args.no_default_features, args.package_debug, args.strip_debuginfo),
                bin_specs, test_specs, outputs, manifest_out, implicit, requested_names)


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


def _unbound_source(record, target):
    """The source of an indexed artifact when no metadata target set was supplied.

    ``target.src_path`` is still required (an event without one is refused),
    but it is not compared with metadata: only the standalone index, which
    has no metadata document, is allowed to index this way. The batch itself
    always passes its metadata targets, so receipts never carry an unchecked
    source.
    """
    source = target.get('src_path')
    if not source:
        raise BuildError('Cargo reported ' + record['kind'] + ' ' + record['target'] +
                         ' without a target src_path')
    try:
        return str(Path(source).resolve())
    except OSError as error:
        raise BuildError('Cargo reported ' + record['kind'] + ' ' + record['target'] +
                         ' with an unusable src_path ' + repr(source) + ': ' + str(error)) from error


def _bind_source(record, target, targets):
    """Require the event's ``target.src_path`` to be the metadata target's canonical source."""
    name, kind = record['target'], record['kind']
    spec = targets.get((kind, name))
    if spec is None:
        raise BuildError('Cargo reported ' + kind + ' ' + name + ' that cargo metadata does not list for the ' +
                         PACKAGE + ' package')
    source = target.get('src_path')
    if not source:
        raise BuildError('Cargo reported ' + kind + ' ' + name + ' without a target src_path')
    try:
        reported = Path(source).resolve()
    except OSError as error:
        raise BuildError('Cargo reported ' + kind + ' ' + name + ' with an unusable src_path ' + repr(source) +
                         ': ' + str(error)) from error
    if reported != Path(spec['source']):
        raise BuildError('Cargo reported ' + kind + ' ' + name + ' from ' + str(reported) +
                         ', but cargo metadata lists its source as ' + spec['source'])
    record['source'] = spec['source']


def artifact_index(events, package, targets=()):
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
    the package-named one, a duplicate, a kind other than lib/bin/test, a
    bin/test without an executable, or a bin the event lists as ``test``
    (which Cargo would run as a unit test) is rejected. When ``targets``
    (the metadata targets) is given, every lib, bin and test artifact must be
    the metadata target of its kind and name, and its ``target.src_path`` must
    be that target's canonical source path: Cargo cannot mean another library,
    program or test source by a known name. A missing or foreign source path is
    rejected. ``targets`` is optional only for a standalone index that has no
    metadata document (as in :mod:`tests`); then every artifact's source is
    still required from its own event, but it is not compared with metadata.
    The batch path always passes its metadata targets (and
    :func:`select_artifacts` refuses to run without them).

    ``target.kind`` (``["test"]``) is the classification of a target, not
    ``profile.test``: a ``harness = false`` integration test has kind
    ``["test"]`` and Cargo still reports ``profile.test`` for it.
    """
    if not package:
        raise BuildError('no rootyard package id to bind artifacts to')
    lib = None
    bins, tests = {}, {}
    skipped = {}
    targets = {(entry['kind'], entry['name']): entry for entry in targets}
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
            record = {'target': name, 'kind': 'lib', 'fresh': False, 'package_id': event.get('package_id')}
            if targets:
                _bind_source(record, target, targets)
            else:
                record['source'] = _unbound_source(record, target)
            lib = record
        elif kinds == ['bin']:
            executable = event.get('executable')
            if not executable:
                raise BuildError(f'{PACKAGE} binary artifact {name} has no executable path')
            if not name or name in bins:
                raise BuildError(f'Cargo reported a duplicate or unnamed {PACKAGE} bin artifact: {name!r}')
            if event.get('profile', {}).get('test') is not False:
                raise BuildError(f'{PACKAGE} bin artifact {name} was built as a test unit, not the binary')
            record = {'target': name, 'kind': 'bin', 'fresh': False,
                      'executable': str(Path(executable).resolve()),
                      'package_id': event.get('package_id'), 'profile': _profile(event)}
            if targets:
                _bind_source(record, target, targets)
                if str(Path(executable).resolve().with_suffix('')) != str(canonical_target() / 'debug' / name):
                    raise BuildError('binary ' + name + ' was built at ' + str(executable) +
                                     ', not at its canonical location')
            else:
                record['source'] = _unbound_source(record, target)
            bins[name] = record
        elif kinds == ['test']:
            executable = event.get('executable')
            if not executable:
                raise BuildError(f'{PACKAGE} integration-test artifact {name} has no executable path')
            if not name or name in tests:
                raise BuildError(f'Cargo reported duplicate {name!r} {PACKAGE} test artifacts; '
                                 'expected exactly one')
            record = {'target': name, 'kind': 'test', 'fresh': False,
                      'profile': _profile(event), 'executable': str(Path(executable).resolve()),
                      'package_id': event.get('package_id')}
            if targets:
                _bind_source(record, target, targets)
            else:
                record['source'] = _unbound_source(record, target)
            tests[name] = record
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


def select_artifacts(events, package, plan, targets=()):
    """Return ``(lib, [(bin artifact, implicit)], [test artifacts])`` for the real targets.

    Foreign-package artifacts (dependencies Cargo rebuilt alongside the
    selected package) are skipped by artifact_index and never receipted.
    Requested, enabled metadata bins come first (in selection order), then the
    implicit ones Cargo also built for a ``--test`` in metadata order; a bin
    that is in neither set is an unknown extra and fails the batch. Every
    selected bin is bound to its canonical ``<target>/debug/<name>`` path.

    ``targets`` is mandatory here: the batch path refuses to select an
    artifact whose metadata target (lib, bin or test) and source it cannot
    check, so no receipt is ever built from an unverified event.
    """
    if not targets:
        raise BuildError('the batch must verify artifacts against cargo metadata targets')
    bin_specs, test_specs = plan.bins, plan.tests
    lib, bins, tests, _ = artifact_index(events, package, targets)
    require_build_finished(events)
    wanted_bins = [spec['name'] for spec in bin_specs]
    missing = [name for name in wanted_bins if name not in bins]
    if missing:
        raise BuildError('Cargo did not report the requested binaries: ' + ', '.join(missing))
    unknown = sorted(set(bins) - set(wanted_bins) - {spec['name'] for spec in plan.implicit_bins})
    if unknown:
        raise BuildError('Cargo reported binaries that were not selected: ' + ', '.join(unknown))
    selected = [(bins[name], False) for name in wanted_bins]
    # An implicit bin is not optional: Cargo builds every enabled bin when a
    # --test is selected, and the integration test links and runs through
    # them, so a missing one means the event stream does not describe this
    # build.
    missing = [spec['name'] for spec in plan.implicit_bins if spec['name'] not in bins]
    if missing:
        raise BuildError('Cargo did not report every enabled implicit binary: ' + ', '.join(missing))
    selected += [(bins[spec['name']], True) for spec in plan.implicit_bins]
    selected_bins = [artifact for artifact, _ in selected]
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
    return lib, selected, selected_tests


class Publisher:
    """Stage every payload beside its destination and publish by ``os.replace``.

    A receipt is written to a hidden sibling; a relocated test executable is
    copied to a hidden sibling with the same copy+chmod+hash procedure
    ``build_native_test.py`` uses (a byte copy, so the source may be on another
    filesystem than the destination), and the compiled artifact stays in place.
    Nothing is published until Cargo, the event checks, the digests and every
    staging check succeeded; each payload is then renamed over its destination
    within its own directory, so a reader sees the previous file or the complete
    new one for that path, and a failure removes every staging file and any
    already renamed payload. The payloads are not one cross-directory atomic
    rename: callers publish the batch manifest last as the commit marker.
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
    """The Cargo metadata document this batch plans and verifies from.

    It is the authority for the package id, the target directory the lock
    covers, and the ``rootyard`` targets (bins included: auto-discovery is
    Cargo's, not this script's). Cargo's own resolution is used (no extra
    ``--config``), exactly as before; the document is read once when the
    batch is planned and once after the build, under the lock.
    """
    output = subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1', '--offline'],
        cwd=_root(), text=True)
    return metadata_record(json.loads(output))


def metadata_record(metadata):
    """``(target_directory, package_id, targets)`` of the one rootyard package, from one document."""
    packages = [package for package in metadata.get('packages') or [] if package.get('name') == PACKAGE]
    if len(packages) != 1 or not packages[0].get('id'):
        raise BuildError('cargo metadata does not list exactly one rootyard package')
    resolved = Path(metadata.get('target_directory') or '')
    if resolved.resolve() != canonical_target():
        raise BuildError('cargo resolved target directory ' + str(resolved) + ' but the build lock is in ' +
                         str(canonical_target()) + '; the build would not be serialized by this lock')
    return {'target_directory': metadata.get('target_directory'), 'package_id': packages[0]['id'],
            'targets': packages[0].get('targets')}


def batch_manifest(document):
    """The Cargo.toml feature/optional-dependency view, with Cargo's target list.

    Target names, paths and required-features come from metadata; the
    features and optional dependencies the batch gates on still come from
    ``parse_cargo_toml`` (metadata lists neither).
    """
    manifest = parse_cargo_toml((_root() / 'Cargo.toml').read_text())
    targets = metadata_targets(document)
    if len({entry['name'] for entry in targets if entry['kind'] == 'bin'}) != \
            sum(1 for entry in targets if entry['kind'] == 'bin'):
        raise BuildError('cargo metadata lists two bins of the ' + PACKAGE + ' package with one name')
    for entry in targets:
        if entry['kind'] in ('bin', 'test') and not Path(entry['source']).is_relative_to(_root().resolve()):
            raise BuildError(entry['kind'] + ' target ' + entry['name'] + ' has a source outside the workspace: ' +
                             entry['source'])
    manifest['bins'] = [entry for entry in targets if entry['kind'] == 'bin']
    manifest['tests'] = [entry for entry in targets if entry['kind'] == 'test']
    return manifest


# -- bound build inputs -------------------------------------------------------
#: The inputs beyond the production ``source_digest()`` that a test build reads
#: or is configured by: the whole ``tests/**/*.rs`` tree, the toolchain pins, the
#: fixed in-repo Cargo config files and the workspace ``build.rs``. Each is
#: bound by repository-relative path and raw bytes, listed (absent ones too) and
#: frozen before and after the build, so no helper, config or toolchain edit can
#: hide behind a selected entry that did not itself change.
#: Roles of the bound inputs, in the order the summary lists them.
BOUND_ROLES = ('integration_test_source', 'toolchain', 'cargo_config', 'build_script')
#: Toolchain pin files; both are listed, and whichever exists is bound.
TOOLCHAIN_PINS = ('rust-toolchain.toml', 'rust-toolchain')
#: Build-affecting configuration Cargo reads from ``.cargo/`` without a
#: command-line ``--config``. ``credentials.toml`` is authentication, not part of
#: what is compiled, and other files in ``.cargo/`` are neither hashed nor refused.
CARGO_CONFIG_FILES = ('.cargo/config.toml', '.cargo/config')
#: Cargo config keys that change what is compiled or where inputs come from
#: (flags, linker, source replacement, the target directory Cargo writes to),
#: matched case-insensitively as ``<key>``, ``name.<key>`` or
#: ``<triple>.<key>``. ``runner`` is not one: it only runs a built binary.
PATH_KEYS = ('rustflags', 'linker', 'target-dir', 'directory', 'local-registry',
             'registry', 'CARGO_TARGET_DIR')
PATH_TABLES = ('build', 'target', 'source', 'env')
TOML_KEY = re.compile(r'\s*(?:"([^"]*)"|([A-Za-z0-9_.\-]+))\s*=(.*)$')
#: ``[target.<triple>]`` table names come from rustc's ``-vV`` output, which is
#: JSON-encoded as a config value, so the body of a ``[target.'...'.linker]``
#: without a separate ``[target.'...']`` segment is unambiguous only in practice;
#: treating an unknown dotted name as a triple can therefore over- rather than
#: under-refuse.
def _relative(path):
    return Path(path).relative_to(_root()).as_posix()


def config_path_keys(raw):
    """The keys of one Cargo config that redirect inputs (``[table]`` headers, then ``key =``)."""
    table, keys = None, []
    for line in raw.decode('utf-8', 'replace').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('[') and stripped.endswith(']'):
            table = stripped.strip('[]<').strip().strip('"')
            continue
        match = TOML_KEY.match(stripped)
        if not match:
            continue
        key = match.group(1) if match.group(1) is not None else match.group(2).strip('"')
        names = [key] if table is None else table.split('.') + [key]
        candidates = {key, '.'.join(names[-2:]), '.'.join(names[-3:])}
        table_names = names[:-1]
        if len(table_names) >= 2 and table_names[0] in PATH_TABLES:
            candidates.add(table_names[0] + '.' + table_names[1] + '.' + key)
        folded = {candidate.lower() for candidate in candidates}
        for pattern in PATH_KEYS:
            if pattern.lower() in folded:
                keys.append(table + '.' + key if table is not None and key != 'CARGO_TARGET_DIR'
                            else pattern)
                break
    return keys


def require_in_repository_config(name, raw):
    """Refuse a bound config that redirects Cargo to inputs or outputs this batch cannot bind."""
    keys = config_path_keys(raw)
    if keys:
        raise BuildError(name + ' sets ' + ', '.join(repr(key) for key in keys) +
                         ', a value that redirects build inputs; this batch binds in-repository '
                         'configuration only and refuses rather than record a partial input set')


def bound_input_files():
    """Every in-repository file the batch binds, sorted by path, plus the absent fixed candidates."""
    present, absent = {}, []
    for name in TOOLCHAIN_PINS:
        if (_root() / name).is_file():
            present[name] = 'toolchain'
        else:
            absent.append(name)
    for name in CARGO_CONFIG_FILES:
        if (_root() / name).is_file():
            present[name] = 'cargo_config'
        else:
            absent.append(name)
    if (_root() / 'build.rs').is_file():
        present['build.rs'] = 'build_script'
    else:
        absent.append('build.rs')
    # Every Rust file under tests/, not only the selected entries: a helper a
    # selected entry reaches (or a new, still untracked one) is an input too.
    # The module graph is not parsed; the whole test source tree is bound.
    tests = _root() / 'tests'
    if tests.is_dir():
        for path in tests.rglob('*'):
            if path.is_file() and path.suffix == '.rs':
                present[_relative(path)] = 'integration_test_source'
    return present, sorted(absent)


def _read_bound(relative):
    """Raw bytes of one present bound input, or None when it vanished after being listed."""
    try:
        return (_root() / relative).read_bytes()
    except FileNotFoundError:
        return None


def bound_input_inventory():
    """Path, role, presence and raw-byte SHA-256 of every bound input, in one canonical order.

    The raw bytes are read here once: the inventory of one measurement and the
    digest taken from it describe the same bytes, not two later reads.
    """
    present, absent = bound_input_files()
    entries, blobs = [], {}
    for relative in sorted(present):
        raw = _read_bound(relative)
        if raw is None:
            absent.append(relative)
            continue
        if present[relative] == 'cargo_config':
            require_in_repository_config(relative, raw)
        blobs[relative] = raw
        entries.append({'path': relative, 'role': present[relative], 'present': True,
                        'sha256': hashlib.sha256(raw).hexdigest()})
    for relative in absent:
        entries.append({'path': relative, 'role': _fixed_role(relative), 'present': False,
                        'sha256': None})
    entries.sort(key=lambda entry: entry['path'])
    return entries, blobs


def _fixed_role(relative):
    if relative in TOOLCHAIN_PINS:
        return 'toolchain'
    if relative in CARGO_CONFIG_FILES:
        return 'cargo_config'
    return 'build_script'


def bound_inputs_digest(entries, blobs):
    """One digest over the path and raw bytes of every present bound input, in the given order.

    Only "present" entries are folded in, and ``blobs`` must be the bytes the
    entries' SHA-256 values were taken from; a present entry without them is an
    error rather than a silently dropped input. Absent candidates are listed in
    the inventory and the summary, so adding or removing one still changes the
    inventory; the digest is the bytes identity of what was read.
    """
    digest = hashlib.sha256()
    for path in sorted(entry['path'] for entry in entries if entry['present']):
        raw = blobs.get(path)
        if raw is None:
            raise BuildError('bound input ' + path + ' is present but its bytes were not measured')
        digest.update(bound_entry_line(path, raw))
    return digest.hexdigest()


def bound_entry_line(path, raw):
    digest = hashlib.sha256()
    digest.update(path.encode() + b'\0')
    digest.update(hashlib.sha256(raw).digest())
    return digest.digest()


def bound_inputs_summary(entries, blobs):
    present = [entry for entry in entries if entry['present']]
    by_role = {role: sum(1 for entry in present if entry['role'] == role) for role in BOUND_ROLES}
    return {'digest_algorithm': 'sha256(concat sha256(path\\0sha256(bytes)) over present inputs, path-sorted)',
            'digest': bound_inputs_digest(entries, blobs),
            'present_count': len(present), 'absent_count': len(entries) - len(present),
            'total_bytes': sum(len(blobs[entry['path']]) for entry in present), 'by_role': by_role,
            'absent': [entry['path'] for entry in entries if not entry['present']]}


def source_snapshot(plan):
    """Every input whose change after the build invalidates the whole batch."""
    bound_inputs, bound_blobs = bound_input_inventory()
    production_inputs = source_digest()
    return {
        'source_inputs': production_inputs,
        'cargo_lock': sha256_file(_root() / 'Cargo.lock'),
        'tests': {spec['name']: sha256_file(spec['source']) for spec in plan.tests},
        'bound_inputs': bound_inputs,
        # The very bytes inventoried above, not a second read: the digest and
        # any summary derived later must be taken from these, not from disk again.
        'bound_input_blobs': bound_blobs,
        'bound_inputs_digest': bound_inputs_digest(bound_inputs, bound_blobs),
        'git': git_state(),
    }


def bound_inputs_for_receipts(before, after):
    """Re-measure the inputs at freeze time and refuse unless they are the pre-build ones.

    The production digest of ``after`` was taken after the build by
    ``require_unchanged``; the bound inputs are read from disk again here, so an
    input changed and restored between the build and publication is still hashed
    anew. Returns the frozen inventory the receipts and manifest record.
    """
    measured = after['bound_inputs']
    old = {entry['path']: entry for entry in before['bound_inputs']}
    new = {entry['path']: entry for entry in measured}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(path for path in set(old) & set(new) if old[path] != new[path])
    if added or removed or changed:
        details = ', '.join([path + ' (added)' for path in added] +
                            [path + ' (removed)' for path in removed] +
                            [path + ' (changed)' for path in changed])
        raise BuildError('bound build inputs changed during build: ' + details +
                         '; refusing the receipt')
    if after['bound_inputs_digest'] != before['bound_inputs_digest']:
        raise BuildError('bound build inputs digest changed during build; refusing the receipt')
    return measured


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


def bind_inputs(plan, before):
    """Freeze the bound inputs at publish time and return the receipt fields for them.

    ``after`` is measured now, after the build and before publication; it must
    equal the pre-build inventory and digest, and the recorded summary is derived
    from that same frozen inventory. Every receipt and the manifest record this
    one frozen value, so neither can omit an input.
    """
    after = source_snapshot(plan)
    entries = bound_inputs_for_receipts(before, after)
    summary = bound_inputs_summary(entries, after['bound_input_blobs'])
    return {'bound_inputs': summary, 'bound_input_inventory': entries}


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


def binary_receipt(*, path, digests, toolchain, command, targets, lock_path, timings, bound,
                   implicit=None):
    """The ``build_native.py`` receipt fields, bound to this batch's single build.

    ``implicit`` (``None`` for a requested bin) is the ``implicit_build``
    record of a bin Cargo also built for a selected test: a real artifact of
    this build that was neither requested nor part of the server acceptance.
    """
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
        # Additive to the standalone fields: the existing consumers of these
        # receipts do not verify them, so they are not claimed to be verified
        # until a consumer gate binds them.
        'bound_inputs': bound['bound_inputs'],
        'bound_input_inventory': bound['bound_input_inventory'],
        'batch': {'kind': KIND, 'receipt_version': RECEIPT_VERSION, 'binary': path.name,
                  'targets': [item['target'] for item in targets],
                  'bound_inputs_sha256': bound['bound_inputs']['digest']},
        **({'implicit_build': implicit} if implicit is not None else {}),
    }


def test_receipt(*, path, artifact, digests, toolchain, command, targets, lock_path, timings, bound):
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
        'bound_inputs': bound['bound_inputs'],
        'bound_input_inventory': bound['bound_input_inventory'],
        'batch': {'kind': KIND, 'receipt_version': RECEIPT_VERSION, 'binary': path.name,
                  'targets': [item['target'] for item in targets] + [artifact['target']],
                  'bound_inputs_sha256': bound['bound_inputs']['digest']},
    }


def run_batch(args):
    """Run the whole transaction and return the published batch manifest."""
    reject_passthrough_environment()
    # The target set is Cargo's: the metadata document is read before the
    # request is planned, so --all-bins, a --bin name, a --test that is a
    # metadata test and the implicit bins all come from one target list.
    metadata_before = cargo_metadata()
    manifest = batch_manifest(metadata_before)
    plan = plan_batch(args, manifest)
    selection = plan.selection
    target = canonical_target()
    started = time.monotonic()

    prepare_destinations(plan)
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

    # Requested bins keep their receipts at <target>/debug/<bin>.build.json;
    # an implicitly built bin's receipt (it has no slot in that fixed
    # scheme) is filed with the batch manifest instead of being dropped.
    bin_receipts = bin_receipt_locations(plan, target)
    test_receipts = list(zip(plan.tests, plan.outputs, [Path(str(output) + '.build.json')
                                                        for output in plan.outputs]))
    owned = [path for _, path, _ in bin_receipts] + [path for _, _, path in test_receipts] + \
        [plan.manifest_out] + list(plan.outputs)
    with build_lock(target) as lock_path:
        # A failed or interrupted batch never leaves a receipt, manifest or
        # relocated executable from an earlier or partial transaction behind.
        remove_paths(owned + [path.with_name('.' + path.name + '.batch-new') for path in owned])
        try:
            return publish_transaction(plan, owned, lock_path, metadata_before, toolchain, command,
                                       started)
        except BaseException:
            # Staging siblings of this transaction may sit in the target
            # directory and in every output directory (each on its own
            # filesystem); withdraw them wherever the failure happened.
            remove_paths(owned + [path.with_name('.' + path.name + '.batch-new') for path in owned])
            raise


def bin_receipt_locations(plan, target):
    """``(spec, receipt path, implicit)`` for every bin receipt of one batch, in plan order."""
    requested = [(spec, target / 'debug' / (spec['name'] + '.build.json'), False) for spec in plan.bins]
    directory = plan.manifest_out.parent / (plan.manifest_out.stem + '.receipts')
    implicit = [(spec, directory / (spec['name'] + '.build.json'), True) for spec in plan.implicit_bins]
    return requested + implicit


def publish_transaction(plan, owned, lock_path, metadata_before, toolchain, command, started):
    """Clean, build, verify and publish one batch; it runs under the canonical lock."""
    selection = plan.selection
    target = canonical_target()
    # Bin receipts stay in CARGO_TARGET_DIR (the single clean was the only
    # destructive step on it), implicitly built bins' beside the manifest, and
    # test receipts beside their relocated output.
    locations = bin_receipt_locations(plan, target)
    bin_receipts = [(spec, path) for spec, path, _ in locations]
    test_receipts = list(zip(plan.tests, plan.outputs, [Path(str(output) + '.build.json')
                                                        for output in plan.outputs]))
    # ``owned`` is every final path of this transaction, in the order run_batch
    # names them: bin receipts (requested, then implicit), test receipts, the
    # manifest, then the outputs.
    assert bin_receipts == list(zip(plan.bins + plan.implicit_bins, owned[:len(locations)]))
    bins_count = len(locations)
    assert test_receipts == list(zip(plan.tests, plan.outputs,
                                     owned[bins_count:bins_count + len(plan.tests)]))
    assert owned[bins_count + len(plan.tests)] == plan.manifest_out
    assert owned[bins_count + len(plan.tests) + 1:] == list(plan.outputs)
    before = source_snapshot(plan)
    clean_started = time.monotonic()
    subprocess.run(CLEAN_COMMAND, cwd=_root(), check=True)
    clean_seconds = round(time.monotonic() - clean_started, 3)
    build_started = time.monotonic()
    events = run_json_build(command)
    build_seconds = round(time.monotonic() - build_started, 3)
    after = source_snapshot(plan)
    require_unchanged(before, after)
    lib, bins, tests = select_artifacts(events, metadata_before['package_id'], plan,
                                        metadata_targets(metadata_before))
    metadata_after = cargo_metadata()
    # The target set is planned from the first document, so a target added or
    # removed while building is a mismatch like a redirected target directory.
    if {key: metadata_after[key] for key in ('target_directory', 'package_id', 'targets')} != \
            {key: metadata_before[key] for key in ('target_directory', 'package_id', 'targets')}:
        raise BuildError('cargo metadata (package id or target directory) changed during build')
    require_unchanged(before, after)
    if tests:
        for artifact, output in zip(tests, plan.outputs):
            if Path(artifact['executable']).resolve() == output:
                raise BuildError('relocated output would overwrite the compiled artifact ' + str(output))

    digests = {'source_inputs': before['source_inputs'], 'cargo_lock': before['cargo_lock'],
               'commit': before['git']['commit'], 'git_head': before['git']['head'],
               'working_tree': {key: before['git'][key] for key in ('tree', 'status')},
               'test_sources': before['tests']}
    timings = {'clean_seconds': clean_seconds, 'build_seconds': build_seconds}
    # The one frozen bound-input record of this batch, re-measured now.
    bound = bind_inputs(plan, before)
    selected_bins = [artifact for artifact, _ in bins]
    targets = [lib] + selected_bins
    publisher = Publisher()
    artifacts = []
    # Receipts describe the sources and artifacts after everything that can
    # change them was measured; their digests are taken when they are staged.
    for (spec, path), (artifact, implicit) in zip(bin_receipts, bins):
        marker = {'requested_by': '--test', 'reason': 'Cargo also builds the selected package\'s enabled bins '
                  'when an integration test is selected (an integration test runs through its package\'s '
                  'bins); this bin was reported by that same build, not selected by this batch',
                  'acceptance': 'not-server-acceptance', 'target_source': artifact['source']} \
            if implicit else None
        publisher.text(path, binary_receipt(path=artifact['executable'], digests=digests,
                                            toolchain=toolchain, command=command, targets=targets,
                                            lock_path=lock_path, timings=timings, bound=bound,
                                            implicit=marker))
        stat = os.stat(artifact['executable'])
        artifacts.append({'kind': 'bin', 'target': spec['name'], 'artifact': artifact['executable'],
                          'receipt': str(path), 'fresh': False,
                          'sha256': sha256_file(artifact['executable']), 'size': stat.st_size,
                          'mtime_ns': stat.st_mtime_ns, 'duration_seconds': build_seconds}
                         | ({'implicit': True, 'target_source': artifact['source']} if implicit else
                            {'implicit': False, 'target_source': artifact['source']}))
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
                                          lock_path=lock_path, timings=timings, bound=bound))
    manifest = {
        'kind': KIND,
        'manifest_version': RECEIPT_VERSION,
        'status': 'passed',
        'source_commit': digests['commit'],
        'source_inputs_sha256': digests['source_inputs'],
        'working_tree': digests['working_tree'],
        'cargo_lock_sha256': digests['cargo_lock'],
        'bound_inputs': bound['bound_inputs'],
        'bound_input_inventory': bound['bound_input_inventory'],
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
    # the receipts are about to become visible; publish renames each staged
    # sibling onto its own destination in that destination's directory.
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
    if bound_inputs_for_receipts(before, source_snapshot(plan)) != \
            bound['bound_input_inventory']:
        raise BuildError('bound build inputs changed after their inventory was frozen')
    # The payloads are not renamed as one atomic set across directories or
    # filesystems. The batch manifest is the last renamed payload: its
    # presence is the commit marker that every receipt of this transaction
    # has already been renamed into place.
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
                           help='select every bin cargo metadata lists for the package whose required '
                                'features are enabled ([[bin]] tables and auto-discovered src/bin/*.rs)')
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
