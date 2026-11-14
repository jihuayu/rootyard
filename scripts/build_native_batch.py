#!/usr/bin/env python3
"""Build several native binaries and integration tests from one explicit Cargo build.

This driver migrates the batch producer to the shared v2 contract.  It never
runs ``cargo clean`` and accepts either literal Cargo freshness value, so a
correctly-keyed shared Cargo cache can satisfy a repeated or cross-worktree
build without forcing a rebuild.  It still keeps every safety property of the
standalone producers:

* one canonical ``build_lock`` in ``canonical_target()`` for the whole
  transaction, so no other producer or batch can interleave a build or replace
  an artifact while this transaction measures and publishes;
* exactly one explicit ``cargo build --locked --profile test`` invocation that
  selects every requested ``--bin`` and ``--test`` with the same features,
  no-default-features, ``[build] target-dir``, package debug/``strip`` override
  and toolchain.  ``CARGO_BUILD_JOBS`` is normalized to an explicit ``--jobs``
  argument and the guard-safe environment is passed to every helper and to
  Cargo; a rejected compiler/profile selector fails closed instead of being
  dropped;
* the target set is Cargo metadata's own.  ``--all-bins`` selects every enabled
  metadata bin, a bin auto-discovered from ``src/bin/*.rs`` is selected exactly
  like a ``[[bin]]``, and an unknown ``--bin``/``--test`` is refused.  With a
  selected test Cargo also builds the other enabled package bins; each is
  accepted only after metadata confirms its name/source and is marked
  ``implicit_build`` in its receipt and manifest entry;
* artifacts are filtered by the selected package and bound by exact
  ``target.kind``, name, profile, source path, executable path and executable
  SHA-256.  Freshness is copied from the selected event, never forced.  The
  selected test executable is copied (never hardlinked or moved) outside
  ``CARGO_TARGET_DIR`` to a fixed 0700 output; its original and relocated
  digests are both recorded;
* every receipt is a shared v2 receipt built by
  ``native_build_receipt.make_receipt_v2``: production source, test/config,
  lock and toolchain inventory, actual compiler executable digests and full
  commits, command/profile/target/features, executable digest, real Git HEAD
  and the batch link.  No v2 receipt carries ``package_rebuilt``,
  ``clean_command``, ``clean_commands``, ``fresh_false_artifacts`` or a
  top-level ``fresh`` alias;
* receipts and the batch manifest are staged beside their destinations and
  renamed into place only after all checks pass.  The batch manifest is the
  last rename and is the commit marker; a failed transaction withdraws every
  receipt, output and staging sibling it could have installed.  Payloads are
  not one cross-directory atomic set, but each file appears complete or not at
  all;
* a test output on another filesystem is staged in that destination's own
  directory, its hash is compared with the compiled artifact, and only then is
  it renamed.  The compiled artifact remains in ``CARGO_TARGET_DIR``.

Python orchestration only: the executable artifacts are the Rust targets Cargo
builds, and the batch never invokes a second Cargo build or a clean.
"""
import argparse
import contextlib
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import build_native
import native_build_receipt as receipt
from build_native import BuildError, build_lock, source_digest
from build_native_test import FEATURES


def _root():
    """The workspace: bound to build_native.ROOT so both share one target and lock."""
    return build_native.ROOT


NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]{0,127}$')
PACKAGE = 'rootyard'
DEFAULT_BIN = 'rootyard'
KIND = receipt.BATCH_KIND
RECEIPT_VERSION = 2
MANIFEST_VERSION = 2
MANIFEST_NAME = 'rootyard-native-build-batch.json'
PASSTHROUGH_VARIABLES = receipt.PASSTHROUGH_VARIABLES
REJECTED_COMPILER_VARIABLES = receipt.REJECTED_COMPILER_VARIABLES
REJECTED_VARIABLE_PREFIXES = receipt.REJECTED_VARIABLE_PREFIXES
ALLOWED_TARGET_DIR = receipt.ALLOWED_TARGET_DIR


def canonical_target():
    """The shared build lock lives in this directory; the canonical function is build_native's."""
    return build_native.canonical_target()


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


def capture_bound_inputs(environment=None):
    environment = os.environ if environment is None else environment
    try:
        return receipt.capture_bound_inputs(_root(), environ=environment)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def probe_toolchain(environment=None):
    environment = os.environ if environment is None else environment
    def run(command):
        return subprocess.run(command, cwd=_root(), capture_output=True, text=True,
                              check=False, env=environment)
    try:
        return receipt.probe_toolchain(_root(), environ=environment, run=run)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def git_state():
    """HEAD commit/tree plus the tracked working-tree state."""
    try:
        return receipt.git_state(_root())
    except (OSError, subprocess.CalledProcessError) as error:
        raise BuildError('cannot read Git state: ' + str(error)) from error


def is_rejected_environment_name(name):
    return receipt.is_rejected_environment_name(name)


def reject_passthrough_environment(environ=None):
    environment = os.environ if environ is None else environ
    try:
        receipt.reject_passthrough_environment(environment)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


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


def _require_file_destination(path, label):
    """A final file destination must not be a symlink or an existing directory."""
    path = Path(path)
    if path.is_symlink():
        raise BuildError(label + ' must not be a symlink: ' + str(path))
    if path.exists() and path.is_dir():
        raise BuildError(label + ' must not be an existing directory: ' + str(path))


def final_destinations(plan, target):
    """Every final file this batch transaction owns, in its documented order."""
    destinations = [(('bin receipt ' + spec['name']), Path(path))
                    for spec, path, _implicit in bin_receipt_locations(plan, target)]
    for spec, output in zip(plan.tests, plan.outputs):
        destinations.append(('test output ' + spec['name'], Path(output)))
        destinations.append(('test receipt ' + spec['name'], Path(str(output) + '.build.json')))
    destinations.append(('batch manifest', Path(plan.manifest_out)))
    return destinations


def _validate_disjoint_destinations(destinations):
    """Check file destinations are non-symlink, unique and pairwise disjoint."""
    seen = {}
    for label, path in destinations:
        _require_file_destination(path, label)
        if path in seen:
            raise BuildError(label + ' ' + str(path) + ' collides with ' + seen[path])
        seen[path] = label
    items = list(seen.items())
    for index, (path, label) in enumerate(items):
        for other, other_label in items[index + 1:]:
            if path in other.parents or other in path.parents:
                raise BuildError(label + ' ' + str(path) + ' conflicts with ancestor/descendant ' +
                                 other_label + ' ' + str(other))


def preflight_request_paths(args, target):
    """Validate the explicit file requests before even reading Cargo metadata.

    The full final set also depends on metadata-selected bin names, so
    :func:`validate_final_destinations` checks it after planning.  This early
    pass is what guarantees a raw symlink, an existing directory at a ``.json``
    manifest path or an explicit output/manifest collision never reaches a
    Cargo process, a lock acquisition or any cleanup.
    """
    outputs = [resolve_output(raw, '--output') for raw in args.output or []]
    if len(set(outputs)) != len(outputs):
        raise BuildError('--output repeats a destination')
    for output in outputs:
        if output == target or target in output.parents:
            raise BuildError('--output must be outside CARGO_TARGET_DIR so cache eviction cannot '
                             'delete it: ' + str(output))
    for raw in args.bin_destination or []:
        resolve_output(raw, '--bin-destination')
    manifest_out = resolve_manifest_output(args.manifest_out)
    if manifest_out == target or target in manifest_out.parents:
        raise BuildError('--manifest-out must be outside CARGO_TARGET_DIR')
    explicit = [('--output destination', output) for output in outputs]
    explicit += [('test receipt destination', Path(str(output) + '.build.json'))
                 for output in outputs]
    explicit.append(('batch manifest destination', manifest_out))
    _validate_disjoint_destinations(explicit)
    return outputs, manifest_out


def validate_final_destinations(plan, target):
    """Fail closed before any cleanup, lock, mkdir or Cargo build mutation.

    Every final path -- requested and implicit bin receipts, relocated test
    outputs and their receipts, and the manifest -- must be a non-symlink file
    destination, unique, and pairwise disjoint with no ancestor/descendant
    relationship.  Otherwise a cleanup or publication could touch a path that
    belongs to another destination or to the caller's data.
    """
    destinations = final_destinations(plan, target)
    _validate_disjoint_destinations(destinations)


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


def _raw_output(raw):
    """The requested path before any symlink resolution (relative to the workspace)."""
    value = Path(raw).expanduser()
    return _root() / value if not value.is_absolute() else value


def resolve_output(raw, label='path'):
    """Resolve one explicit file destination without silently following a symlink.

    ``Path.resolve()`` follows a file symlink to its referent, which would make
    cleanup and publication operate on a path the caller never named.  Reject
    the raw final component first, then canonicalize only its parent so the
    returned path is stable for collision checks.
    """
    raw_path = _raw_output(raw)
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


def resolve_manifest_output(raw):
    """Resolve --manifest-out, preserving the directory-form convenience.

    A path whose final component ends in ``.json`` is an explicit manifest
    file; anything else is a directory that receives ``MANIFEST_NAME``.  The
    raw directory must not be a symlink or an existing non-directory, so the
    directory form cannot silently follow a referent either.
    """
    raw_path = _raw_output(raw)
    if raw_path.is_symlink():
        raise BuildError('--manifest-out must not be a symlink: ' + str(raw_path))
    if raw_path.suffix == '.json':
        return resolve_output(raw, '--manifest-out')
    if raw_path.exists() and not raw_path.is_dir():
        raise BuildError('--manifest-out must be a directory or a .json file: ' + str(raw_path))
    directory = raw_path.resolve()
    if not directory.is_dir() and directory.exists():
        raise BuildError('--manifest-out must be a directory or a .json file: ' + str(directory))
    manifest_path = directory / MANIFEST_NAME
    if manifest_path.is_symlink():
        raise BuildError('--manifest-out manifest must not be a symlink: ' + str(manifest_path))
    if manifest_path.exists() and manifest_path.is_dir():
        raise BuildError('--manifest-out manifest must not be an existing directory: ' + str(manifest_path))
    return manifest_path


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
    outputs = [resolve_output(raw, '--output') for raw in args.output or []]
    if len(set(outputs)) != len(outputs):
        raise BuildError('--output repeats a destination')
    for output in outputs:
        if output == target or target in output.parents:
            raise BuildError('--output must be outside CARGO_TARGET_DIR so cache eviction cannot delete '
                             'it: ' + str(output))
    if len(outputs) != len(test_specs):
        raise BuildError('--output must be given exactly once per --test (got ' + str(len(outputs)) +
                         ' outputs for ' + str(len(test_specs)) + ' tests)')

    destinations = args.bin_destination or [str(target / 'debug' / spec['name']) for spec in bin_specs]
    if len(destinations) != len(bin_specs):
        raise BuildError('--bin-destination must be given exactly once per --bin')
    for spec, raw in zip(bin_specs, destinations):
        if resolve_output(raw, '--bin-destination') != target / 'debug' / spec['name']:
            raise BuildError('binary ' + spec['name'] + ' may only be recorded at its canonical '
                             '"<target>/debug/' + spec['name'] + '" location')
    for spec in test_specs:
        if spec['name'] in {item['name'] for item in bin_specs}:
            raise BuildError('test ' + spec['name'] + ' collides with a binary of the same name')
        if not spec['source'].is_file():
            raise BuildError('integration-test source is missing: ' + str(spec['source']))

    manifest_out = resolve_manifest_output(args.manifest_out)
    if manifest_out == target or target in manifest_out.parents:
        raise BuildError('--manifest-out must be outside CARGO_TARGET_DIR')
    implicit = implicit_bins_for(manifest, args)
    requested_names = tuple(entry['name'] for entry in bin_specs) if args.all_bins else \
        tuple(spec['name'] for spec in bin_specs)
    plan = Plan(Selection(args.features, args.no_default_features, args.package_debug,
                          args.strip_debuginfo), bin_specs, test_specs, outputs, manifest_out,
                implicit, requested_names)
    validate_final_destinations(plan, target)
    return plan


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
        _require_file_destination(output, '--output')
        output.parent.mkdir(parents=True, exist_ok=True)
    _require_file_destination(plan.manifest_out, '--manifest-out')
    plan.manifest_out.parent.mkdir(parents=True, exist_ok=True)


def run_json_build(argv, environment=None):
    """Stream Cargo JSON events; non-JSON stdout, a crash or a non-zero status fails."""
    environment = os.environ if environment is None else environment
    events = []
    process = subprocess.Popen(argv, cwd=_root(), stdout=subprocess.PIPE, stderr=None,
                               text=True, bufsize=1, env=environment)
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


def _require_src_path(target, kind, name):
    if not target.get('src_path'):
        raise BuildError('Cargo reported ' + kind + ' ' + str(name) +
                         ' without a target src_path')


def _source_required(record, target):
    """Require the selected event's own source path; used by the standalone index."""
    _require_src_path(target, record['kind'], record['target'])
    source = target.get('src_path')
    try:
        return Path(source).resolve()
    except OSError as error:
        raise BuildError('Cargo reported ' + record['kind'] + ' ' + record['target'] +
                         ' with an unusable src_path ' + repr(source) + ': ' + str(error)) from error


def _record(event, kind):
    """Capture one selected event through the shared v2 artifact helper."""
    name = (event.get('target') or {}).get('name')
    fresh = event.get('fresh')
    if fresh is not True and fresh is not False:
        raise BuildError('Cargo reported ' + kind + ' ' + str(name) +
                         " with absent or non-boolean freshness; Cargo's reported freshness "
                         'must be the literal JSON boolean true or false')
    try:
        return receipt.cargo_artifact_record(event, source_root=_root(), kind=kind)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def _bind_source(record, target, targets):
    """Require the selected artifact's source to be the metadata target's source."""
    name, kind = record['target'], record['kind']
    spec = targets.get((kind, name))
    if spec is None:
        raise BuildError('Cargo reported ' + kind + ' ' + name + ' that cargo metadata does not list for the ' +
                         PACKAGE + ' package')
    _source_required(record, target)
    reported = (_root().resolve() / record['source']).resolve()
    if reported != Path(spec['source']).resolve():
        raise BuildError('Cargo reported ' + kind + ' ' + name + ' from ' + str(reported) +
                         ', but cargo metadata lists its source as ' + spec['source'])


def artifact_index(events, package, targets=()):
    """Index the selected lib/bin/test compiler artifacts of exactly one package.

    Cargo reports every unit it built or found fresh in this invocation.  Only
    events whose ``package_id`` is the selected package are indexed; foreign
    dependency artifacts are skipped and never receipted.  Inside the selected
    package the checks stay closed: a lib other than the package-named one, a
    duplicate, an unexpected kind, a bin/test without an executable, or a bin
    built as a test unit is rejected.  Freshness is copied literally from the
    event, so both cache-miss and cache-hit builds are captured.

    When ``targets`` (the metadata targets) is given, every lib, bin and test
    artifact must be the metadata target of its kind and name, and its
    ``target.src_path`` must be that target's canonical source.  ``targets`` is
    optional only for a standalone index with no metadata document; the batch
    path always supplies them.
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
        if kinds == ['lib']:
            if name != PACKAGE:
                raise BuildError(f'{PACKAGE} reported an unexpected lib target {name!r}; the batch binds '
                                 f'the {PACKAGE} lib to every receipt')
            if lib is not None:
                raise BuildError(f'Cargo reported two {PACKAGE} lib artifacts for one build')
            _require_src_path(target, 'lib', name)
            record = _record(event, 'lib')
            if targets:
                _bind_source(record, target, targets)
            else:
                _source_required(record, target)
            lib = record
        elif kinds == ['bin']:
            executable = event.get('executable')
            if not executable:
                raise BuildError(f'{PACKAGE} binary artifact {name} has no executable path')
            if not name or name in bins:
                raise BuildError(f'Cargo reported a duplicate or unnamed {PACKAGE} bin artifact: {name!r}')
            if (event.get('profile') or {}).get('test') is not False:
                raise BuildError(f'{PACKAGE} bin artifact {name} was built as a test unit, not the binary')
            _require_src_path(target, 'bin', name)
            record = _record(event, 'bin')
            if targets:
                _bind_source(record, target, targets)
                if Path(record['executable']).resolve() != canonical_target() / 'debug' / name:
                    raise BuildError('binary ' + name + ' was built at ' + record['executable'] +
                                     ', not at its canonical location')
            else:
                _source_required(record, target)
            bins[name] = record
        elif kinds == ['test']:
            executable = event.get('executable')
            if not executable:
                raise BuildError(f'{PACKAGE} integration-test artifact {name} has no executable path')
            if not name or name in tests:
                raise BuildError(f'Cargo reported duplicate {name!r} {PACKAGE} test artifacts; '
                                 'expected exactly one')
            _require_src_path(target, 'test', name)
            record = _record(event, 'test')
            if targets:
                _bind_source(record, target, targets)
            else:
                _source_required(record, target)
            tests[name] = record
        else:
            raise BuildError(f'unexpected {PACKAGE} artifact {name!r} {kinds}; only lib, bin and test '
                             'artifacts belong in this batch')
    if lib is None:
        raise BuildError(f'Cargo did not report a {PACKAGE} lib compiler-artifact')
    return lib, bins, tests, skipped


def require_build_finished(events):
    try:
        receipt.require_build_finished(events)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


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
    """Remove only files, symlinks and empty invocation-private directories.

    Final destinations are preflight-checked files, so a directory here is
    either an invocation-owned temporary directory (``rmdir`` after its files)
    or an unknown pre-existing directory that this transaction must never
    recursively delete.  Non-empty directories are conservatively preserved.
    """
    if isinstance(paths, (str, Path)):
        paths = [paths]
    for path in paths:
        path = Path(path)
        if path.is_symlink():
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        elif path.is_dir():
            with contextlib.suppress(OSError):
                path.rmdir()
        elif path.exists():
            with contextlib.suppress(FileNotFoundError):
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


def cargo_metadata(environment=None):
    """The Cargo metadata document this batch plans and verifies from.

    It is the authority for the package id, the target directory the lock
    covers, and the ``rootyard`` targets (bins included: auto-discovery is
    Cargo's, not this script's). Cargo's own resolution is used (no extra
    ``--config``); the document is read once when the batch is planned and
    once after the build, under the lock, with the guard-safe environment.
    """
    environment = os.environ if environment is None else environment
    output = subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1', '--offline'],
        cwd=_root(), text=True, env=environment)
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
#: The shared inventory roles, including production sources, manifests, tests,
#: test support and the configuration candidates the receipts bind.
BOUND_ROLES = receipt.BOUND_ROLES
TOOLCHAIN_PINS = receipt.TOOLCHAIN_PINS
CARGO_CONFIG_FILES = receipt.CARGO_CONFIG_FILES


def config_path_keys(raw):
    return receipt.config_path_keys(raw)


def require_in_repository_config(name, raw):
    try:
        receipt.require_in_repository_config(name, raw)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def reject_external_cargo_config(environ=None):
    environment = os.environ if environ is None else environ
    try:
        receipt.reject_external_cargo_config(_root(), environment)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def bound_input_inventory():
    """The shared path/role/presence/raw-byte inventory for this workspace."""
    try:
        return receipt.bound_input_inventory(_root())
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def bound_inputs_digest(entries, blobs):
    try:
        return receipt.bound_inputs_digest(entries, blobs)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def bound_entry_line(path, raw):
    return receipt.bound_entry_line(path, raw)


def bound_inputs_summary(entries, blobs):
    try:
        return receipt.bound_inputs_summary(entries, blobs)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def source_snapshot(plan, environment=None):
    """Every input whose change after the build invalidates the whole batch."""
    bound = capture_bound_inputs(environment)
    return {
        'bound': bound,
        'source_inputs': bound['source_inputs_sha256'],
        'cargo_lock': bound['cargo_lock_sha256'],
        'config_digest': bound['config_digest'],
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
    if before['config_digest'] != after['config_digest']:
        raise BuildError('config, build-script or toolchain inputs changed during build; refusing the receipt')
    if before['bound'] != after['bound']:
        old = {entry['path']: entry for entry in before['bound']['bound_input_inventory']}
        new = {entry['path']: entry for entry in after['bound']['bound_input_inventory']}
        changed = sorted(path for path in set(old) | set(new) if old.get(path) != new.get(path))
        raise BuildError('bound build inputs changed during build: ' + ', '.join(changed) +
                         '; refusing the receipt')
    if before['git'] != after['git']:
        raise BuildError('HEAD or working-tree state changed during build; refusing the receipt')
    if metadata_after is not None and metadata_before != metadata_after:
        raise BuildError('cargo metadata (package id or target directory) changed during build')


def bind_inputs(plan, before, environment=None):
    """Freeze the shared bound inventory after the build and return it for receipts."""
    after = source_snapshot(plan, environment)
    require_unchanged(before, after)
    return after['bound']


def toolchain_record(environment=None):
    """The shared metadata-only toolchain identity of this build."""
    return probe_toolchain(environment)


def _batch_link(manifest_path, binary_name, targets, bound):
    return {
        'kind': KIND,
        'receipt_version': RECEIPT_VERSION,
        'binary': Path(binary_name).name,
        'targets': [item['target'] for item in targets],
        'bound_inputs_sha256': bound['bound_inputs']['digest'],
        'manifest': str(Path(manifest_path).resolve()),
    }


def _make_receipt(**arguments):
    try:
        return receipt.make_receipt_v2(**arguments)
    except receipt.ReceiptError as error:
        raise _as_build_error(error) from error


def binary_receipt(*, path, bound, toolchain, command, targets, lock_path, timings,
                   manifest_path, selection, environment, git, implicit=None):
    """A shared v2 bin receipt for this batch's single build."""
    path = Path(path)
    extra = {
        'kind': 'native-build-batch-bin',
        'batch': _batch_link(manifest_path, path.name, targets, bound),
        'timings': timing_record(timings),
        'build_options': environment['build_options'],
        'selection': selection.as_record(),
    }
    if implicit is not None:
        extra['implicit_build'] = implicit
    return _make_receipt(
        binary_path=path,
        command=command,
        profile='test',
        artifacts=targets,
        toolchain=toolchain,
        bound_inputs=bound,
        workspace_commit=git['commit'],
        target_dir=canonical_target(),
        features=selection.features,
        no_default_features=selection.no_default_features,
        lock_file=lock_path,
        git_head=git['head'],
        working_tree={'tree': git['tree'], 'status': git['status']},
        duration_seconds=timings['build_seconds'],
        extra=extra,
    )


def test_receipt(*, path, binary_name, artifact, bound, toolchain, command, link_targets,
                 lock_path, timings, manifest_path, selection, environment, git):
    """A shared v2 receipt for one relocated integration-test executable."""
    path = Path(path)
    extra = {
        'kind': 'rust-integration-test',
        'relocated_artifact': True,
        'original_artifact_sha256': artifact['executable_sha256'],
        'integration_test_source': artifact['source'],
        'integration_test_source_sha256': artifact['source_sha256'],
        'batch': _batch_link(manifest_path, binary_name, link_targets, bound),
        'timings': timing_record(timings),
        'build_options': environment['build_options'],
        'selection': selection.as_record(),
    }
    return _make_receipt(
        binary_path=path,
        command=command,
        profile='test',
        artifacts=[artifact],
        toolchain=toolchain,
        bound_inputs=bound,
        workspace_commit=git['commit'],
        target_dir=canonical_target(),
        features=selection.features,
        no_default_features=selection.no_default_features,
        lock_file=lock_path,
        git_head=git['head'],
        working_tree={'tree': git['tree'], 'status': git['status']},
        duration_seconds=timings['build_seconds'],
        extra=extra,
    )


def timing_record(timings):
    return {key: timings[key] for key in ('build_seconds',) if key in timings}


def run_batch(args):
    """Run the whole transaction and return the published batch manifest."""
    normalized = normalize_environment()
    environment = normalized['environment']
    reject_external_cargo_config(environment)
    # The target set is Cargo's: the metadata document is read before the
    # request is planned, so --all-bins, a --bin name, a --test that is a
    # metadata test and the implicit bins all come from one target list.
    target = canonical_target()
    preflight_request_paths(args, target)
    metadata_before = cargo_metadata(environment)
    manifest = batch_manifest(metadata_before)
    plan = plan_batch(args, manifest)
    selection = plan.selection
    started = time.monotonic()

    # Re-check the complete destination set immediately before the first
    # mutation; a pre-existing directory or symlink at a final file path is
    # refused rather than cleaned, and every final path stays disjoint.
    validate_final_destinations(plan, target)
    prepare_destinations(plan)
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
    command += list(normalized['cargo_args'])

    # Requested bins keep their receipts at <target>/debug/<bin>.build.json;
    # an implicitly built bin's receipt (it has no slot in that fixed
    # scheme) is filed with the batch manifest instead of being dropped.
    bin_receipts = bin_receipt_locations(plan, target)
    test_receipts = list(zip(plan.tests, plan.outputs, [Path(str(output) + '.build.json')
                                                        for output in plan.outputs]))
    owned = ([path for _, path, _ in bin_receipts]
             + [path for _, _, path in test_receipts]
             + [plan.manifest_out]
             + list(plan.outputs))
    with build_lock(target) as lock_path:
        # Re-check under the lock, before any cleanup: a path that changed
        # between planning and lock acquisition must still be refused, never
        # followed or recursively deleted.
        validate_final_destinations(plan, target)
        # A failed or interrupted batch never leaves a receipt, manifest or
        # relocated executable from an earlier or partial transaction behind.
        remove_paths(owned + [path.with_name('.' + path.name + '.batch-new') for path in owned])
        try:
            return publish_transaction(plan, owned, lock_path, metadata_before, command,
                                       started, environment, normalized)
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


def _features_record(selection):
    enabled = [name for name in (selection.features or '').split(',') if name]
    return {'enabled': enabled, 'no_default_features': selection.no_default_features}


def publish_transaction(plan, owned, lock_path, metadata_before, command, started,
                        environment, normalized):
    """Build, verify and publish one batch under the canonical flock (no clean)."""
    selection = plan.selection
    target = canonical_target()
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
    before = source_snapshot(plan, environment)
    toolchain_before = probe_toolchain(environment)
    build_started = time.monotonic()
    events = run_json_build(command, environment)
    build_seconds = round(time.monotonic() - build_started, 3)
    after = source_snapshot(plan, environment)
    require_unchanged(before, after)
    toolchain_after = probe_toolchain(environment)
    if toolchain_before != toolchain_after:
        raise BuildError('Toolchain identity changed during build; refusing the receipt')
    lib, bins, tests = select_artifacts(events, metadata_before['package_id'], plan,
                                        metadata_targets(metadata_before))
    metadata_after = cargo_metadata(environment)
    # The target set is planned from the first document, so a target added or
    # removed while building is a mismatch like a redirected target directory.
    metadata_keys = ('target_directory', 'package_id', 'targets')
    if ({key: metadata_after[key] for key in metadata_keys}
            != {key: metadata_before[key] for key in metadata_keys}):
        raise BuildError('cargo metadata (package id or target directory) changed during build')
    require_unchanged(before, after, metadata_before, metadata_after)
    if tests:
        for artifact, output in zip(tests, plan.outputs):
            if Path(artifact['executable']).resolve() == output:
                raise BuildError('relocated output would overwrite the compiled artifact ' + str(output))

    bound = bind_inputs(plan, before, environment)
    git = before['git']
    timings = {'build_seconds': build_seconds}
    selected_bins = [artifact for artifact, _ in bins]
    targets = [lib] + selected_bins
    test_targets = targets + list(tests)
    publisher = Publisher()
    artifacts = []
    # Bin receipts bind the lib and every selected bin from this one build.
    for (spec, path), (artifact, implicit) in zip(bin_receipts, bins):
        marker = {'requested_by': '--test', 'reason': 'Cargo also builds the selected package\'s enabled bins '
                  'when an integration test is selected (an integration test runs through its package\'s '
                  'bins); this bin was reported by that same build, not selected by this batch',
                  'acceptance': 'not-server-acceptance', 'target_source': artifact['source']} \
            if implicit else None
        publisher.text(path, binary_receipt(path=artifact['executable'], bound=bound,
                                            toolchain=toolchain_after, command=command,
                                            targets=targets, lock_path=lock_path,
                                            timings=timings, manifest_path=plan.manifest_out,
                                            selection=selection, environment=normalized,
                                            git=git, implicit=marker))
        stat = os.stat(artifact['executable'])
        artifacts.append({'kind': 'bin', 'target': spec['name'], 'artifact': artifact['executable'],
                          'receipt': str(path), 'fresh': artifact['fresh'],
                          'sha256': artifact['executable_sha256'], 'size': stat.st_size,
                          'mtime_ns': stat.st_mtime_ns, 'duration_seconds': build_seconds,
                          'package_id': artifact['package_id'], 'profile': artifact['profile'],
                          'source': artifact['source']}
                         | ({'implicit': True, 'target_source': artifact['source']} if implicit else
                            {'implicit': False}))
    copy_receipts = []
    for (spec, output, path), artifact in zip(test_receipts, tests):
        original = artifact['executable']
        publisher.copy(original, output)
        copy_receipts.append((path, output, artifact, spec))
        artifacts.append({'kind': 'test', 'target': spec['name'], 'artifact': str(output),
                          'original_artifact': original,
                          'original_artifact_sha256': artifact['executable_sha256'],
                          'receipt': str(path), 'fresh': artifact['fresh'],
                          'sha256': artifact['executable_sha256'],
                          'source': artifact['source'], 'source_sha256': artifact['source_sha256'],
                          'package_id': artifact['package_id'], 'profile': artifact['profile'],
                          'duration_seconds': build_seconds})
    # A test receipt hashes the relocated executable, which only exists when
    # the batch stages it; build the payload after staging the copies.
    publisher.stage()
    for path, output, artifact, spec in copy_receipts:
        staged = Path(output).with_name('.' + Path(output).name + '.batch-new')
        # The shared v2 reader requires the receipt's binary basename to match
        # the batch link.  The final output is still unpublished, so measure a
        # private staged copy that carries the final basename; it is removed as
        # soon as the receipt payload has been built.
        receipt_input_dir = Path(output).parent / ('.' + Path(output).name + '.receipt-input')
        receipt_input = receipt_input_dir / Path(output).name
        receipt_input_dir.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copyfile(staged, receipt_input)
            os.chmod(receipt_input, 0o700)
            payload = test_receipt(path=receipt_input, binary_name=Path(output).name,
                                   artifact=artifact, bound=bound,
                                   toolchain=toolchain_after, command=command,
                                   link_targets=test_targets, lock_path=lock_path,
                                   timings=timings, manifest_path=plan.manifest_out,
                                   selection=selection, environment=normalized,
                                   git=git)
        finally:
            remove_paths([receipt_input, receipt_input_dir])
        publisher.text(path, payload)
    manifest = {
        'kind': KIND,
        'manifest_version': MANIFEST_VERSION,
        'status': 'passed',
        'source_commit': git['commit'],
        'git_head': git['head'],
        'working_tree': {'tree': git['tree'], 'status': git['status']},
        'source_inputs_sha256': bound['source_inputs_sha256'],
        'cargo_lock_sha256': bound['cargo_lock_sha256'],
        'config_digest': bound['config_digest'],
        'bound_inputs': bound['bound_inputs'],
        'bound_input_inventory': bound['bound_input_inventory'],
        'toolchain': toolchain_after,
        'features': _features_record(selection),
        'profile': 'test',
        'target_triple': toolchain_after['target_triple'],
        'selection': selection.as_record(),
        'architecture': {'target_triple': toolchain_after['target_triple'],
                         'host': toolchain_after['rustc']['host']},
        'target_directory': str(target),
        'lock_file': str(lock_path),
        'cargo_metadata_target_directory': metadata_after['target_directory'],
        'cargo_package_id': metadata_after['package_id'],
        'build_options': normalized['build_options'],
        'build': {'command': command, 'commands': 1, 'duration_seconds': build_seconds,
                  'cargo_artifacts': test_targets},
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
        stored = json.loads(staged_receipt.read_text())
        if stored['binary_sha256'] != entry['sha256']:
            raise BuildError('staged ' + entry['target'] + ' copy does not match its receipt')
    require_unchanged(before, source_snapshot(plan, environment))
    if bind_inputs(plan, before, environment) != bound:
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
        description='Build several native binaries and integration tests from one explicit Cargo invocation.')
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
                                                  'toolchain', 'features', 'profile', 'target_triple',
                                                  'architecture', 'build')}
                     | {'artifacts': [{'kind': entry['kind'], 'target': entry['target'],
                                       'artifact': entry['artifact'], 'receipt': entry['receipt'],
                                       'fresh': entry['fresh']} for entry in batch['artifacts']]},
                     indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
