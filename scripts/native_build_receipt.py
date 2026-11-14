#!/usr/bin/env python3
"""Shared contract for legacy (v1) and explicit v2 native-build receipts.

The v2 discriminator is ``receipt_schema = "rootyard/native-build-receipt/v2"``.
A receipt without that key is historical v1 and is only ever read: this module
never rewrites it, upgrades it or invents a freshness value.  V2 records the
literal ``fresh`` boolean Cargo reported for each selected compiler artifact and
never writes ``package_rebuilt``, ``clean_command``, ``clean_commands``, a
``fresh_false_artifacts`` alias, or a top-level ``fresh`` claim.

The module owns:

* the exact production ``source_digest()`` algorithm, but with an explicit
  ``root`` argument instead of a module-global repository path;
* the batch-style bound-input inventory (path, role, presence and raw-byte
  SHA-256, including absent fixed candidates) extended with the production
  source closure, Cargo manifests, test support, literal compile-time
  ``include_*!`` assets and a common config digest;
* conservative in-repository Cargo-config checks and an environment-name guard
  that never records environment values; scheduling is split out explicitly:
  :func:`normalize_build_environment` turns ``CARGO_BUILD_JOBS`` into an
  explicit ``--jobs`` argument and a guard-safe environment copy;
* metadata-only toolchain probes (``cargo -vV``, ``rustc -vV`` and
  ``rustup which rustc``).  Cargo identity is always resolved from PATH, never
  from ``rustup which cargo``, so a CargoFork on PATH is not replaced by the
  official rustup Cargo.  A rustup ``rustc`` proxy is resolved to the actual
  compiler with ``rustup which rustc`` and probed/hashed there; the PATH entry
  is recorded separately.  The full commit hash is copied from ``-vV``, never
  inferred from a short version string;
* receipt construction and version-dispatched validation.

The reader performs no compilation, no ``cargo clean`` and no toolchain probe;
it reads files only below an explicit ``source_root`` and an explicit
``binary_path``/expected path.  An unsigned JSON receipt is evidence, not a
cryptographic proof.  Callers must anchor the receipt hash, commit, toolchain
identity and executable digest in a trusted channel; the ``expected_*``
arguments are that anchoring hook.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

RECEIPT_SCHEMA_V2 = "rootyard/native-build-receipt/v2"
BATCH_KIND = "rootyard/native-build-batch"

ARTIFACT_KINDS = ("lib", "bin", "test", "lib-test")
EXECUTABLE_KINDS = ("bin", "test", "lib-test")
PROFILE_FIELDS = (
    "opt_level",
    "debuginfo",
    "debug_assertions",
    "overflow_checks",
    "test",
)
SOURCE_DIRS = ("src", "migrations", "schema", "vendor")
TOOLCHAIN_PINS = ("rust-toolchain.toml", "rust-toolchain")
CARGO_CONFIG_FILES = (".cargo/config.toml", ".cargo/config")
#: Test-support files reached by the library harness through ``#[path]`` or
#: ``include_str!`` in addition to ``tests/**/*.rs``.  They are bound but are
#: not individual Cargo targets.
TEST_SUPPORT_DIRS = (
    "tests/blob_gateway_support",
    "tests/serving_proof_support",
    "tests/serving_reads_support",
    "tests/serving_support",
    "tests/fixtures",
)
#: Literal in-repository files embedded at compile time by ``include_str!``,
#: ``include_bytes!`` or ``include!`` from a bound Rust source file.  This is
#: the explicit closed set of assets used by the current production closure;
#: additional literal includes are discovered from the bound sources and bound
#: with the same role.  It is not a copy of the repository.
COMPILED_ASSETS = ("experimental/pando/schema.sql",)

BOUND_ROLES = (
    "production_source",
    "manifest",
    "lockfile",
    "build_script",
    "integration_test_source",
    "test_support",
    "toolchain",
    "cargo_config",
    "compiled_asset",
)
CONFIG_ROLES = ("build_script", "toolchain", "cargo_config")
BOUND_INPUTS_DIGEST_ALGORITHM = (
    "sha256(concat sha256(path\\0sha256(bytes)) over present inputs, path-sorted)"
)
FIXED_CANDIDATES = {
    "build.rs": "build_script",
    "rust-toolchain.toml": "toolchain",
    "rust-toolchain": "toolchain",
    ".cargo/config.toml": "cargo_config",
    ".cargo/config": "cargo_config",
}
MANIFEST_INPUTS = {"Cargo.toml": "manifest", "Cargo.lock": "lockfile"}

#: Fields a v2 receipt may not carry: v1 freshness/rebuild claims and aliases.
V2_BANNED_FIELDS = (
    "package_rebuilt",
    "clean_command",
    "clean_commands",
    "clean",
    "fresh_false_artifacts",
    "fresh",
)
V1_REQUIRED_FIELDS = (
    "binary_sha256",
    "source_inputs_sha256",
    "workspace_commit",
    "rustc",
    "command",
)

_FULL_HASH = re.compile(r"^[0-9a-fA-F]{40,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# Conservative environment guard shared with build_native_batch.py.  Only
# variable names are inspected and reported; values are never recorded.
PASSTHROUGH_VARIABLES = (
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
    "CARGO_PROFILE_DEV_DEBUG",
    "CARGO_PROFILE_TEST_DEBUG",
    "CARGO_PROFILE_DEV_STRIP",
    "CARGO_PROFILE_TEST_STRIP",
)
REJECTED_COMPILER_VARIABLES = (
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTUP_TOOLCHAIN",
    "RUSTC_BOOTSTRAP",
)
REJECTED_VARIABLE_PREFIXES = ("CARGO_PROFILE_", "CARGO_BUILD_")
ALLOWED_TARGET_DIR = "CARGO_TARGET_DIR"
BUILD_JOBS_VARIABLE = "CARGO_BUILD_JOBS"

TOML_KEY = re.compile(r'\s*(?:"([^"]*)"|([A-Za-z0-9_.\-]+))\s*=(.*)$')
_INCLUDE_LITERAL = re.compile(
    r'\binclude(?:_str|_bytes)?!\s*\(\s*'
    r'(?:r(?P<hashes>#+)"(?P<raw>.*?)"(?P=hashes)|"(?P<plain>(?:\\.|[^"\\])*)")'
    r'\s*\)',
    re.DOTALL,
)
PATH_KEYS = (
    "rustflags",
    "linker",
    "target-dir",
    "directory",
    "local-registry",
    "registry",
    "CARGO_TARGET_DIR",
)
BUILD_REDIRECT_KEYS = ("target", "rustc", "rustc-wrapper", "rustc-workspace-wrapper")
PATH_TABLES = ("build", "target", "source", "env")


class ReceiptError(ValueError):
    """A receipt, input inventory or probe violated the shared contract."""


@dataclass(frozen=True)
class ValidatedReceipt:
    """The fields a caller may rely on after :func:`validate_receipt`."""

    schema: str
    payload: dict
    binary_sha256: str
    workspace_commit: str
    source_inputs_sha256: str
    artifacts: tuple
    batch: dict | None = None
    toolchain: dict | None = None
    config_digest: str | None = None
    receipt_path: Path | None = None
    binary_path: Path | None = None
    receipt_sha256: str | None = None


# -- primitives ---------------------------------------------------------------
def sha256_file(path):
    """SHA-256 of a file's bytes."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _require(condition, label, message):
    if not condition:
        raise ReceiptError(f"{label}: {message}")


def _is_bool(value):
    return type(value) is bool


def _require_mapping(value, label, what="object"):
    _require(isinstance(value, Mapping), label, f"{what} must be an object")
    return value


def _require_list(value, label, what="list", nonempty=True):
    _require(isinstance(value, list), label, f"{what} must be a list")
    if nonempty:
        _require(bool(value), label, f"{what} must not be empty")
    return value


def _require_nonempty_str(value, label, what):
    _require(isinstance(value, str) and bool(value), label, f"{what} must be a nonempty string")
    return value


def _require_bool(value, label, what):
    _require(_is_bool(value), label, f"{what} must be a JSON boolean")
    return value


def _require_int(value, label, what, minimum=None):
    _require(
        isinstance(value, int) and not isinstance(value, bool),
        label,
        f"{what} must be an integer",
    )
    if minimum is not None:
        _require(value >= minimum, label, f"{what} must be >= {minimum}")
    return value


def _require_sha256(value, label, what):
    _require(
        isinstance(value, str) and bool(_SHA256.fullmatch(value)),
        label,
        f"{what} must be a lowercase 64-hex SHA-256",
    )
    return value


def _require_commit(value, label, what="workspace_commit"):
    _require(
        isinstance(value, str) and bool(_FULL_HASH.fullmatch(value)),
        label,
        f"{what} must be a full 40- or 64-hex commit hash",
    )
    return value.lower()


def _require_absolute_path(value, label, what):
    _require(isinstance(value, str) and bool(value), label, f"{what} must be a nonempty string")
    _require(Path(value).is_absolute(), label, f"{what} must be an absolute path")
    return value


def _require_relative_path(value, label, what):
    _require(isinstance(value, str) and bool(value), label, f"{what} must be a nonempty string")
    _require("\\" not in value, label, f"{what} must use POSIX separators")
    _require(not Path(value).is_absolute(), label, f"{what} must be repository-relative")
    parts = value.split("/")
    _require(
        all(part not in ("", ".", "..") for part in parts),
        label,
        f"{what} must not be empty, '.', '..' or traverse",
    )
    return value


def _is_within(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
    except (OSError, ValueError):
        return False
    return True


def _relative_to_root(path, root):
    path = Path(path).resolve()
    root = Path(root).resolve()
    _require(_is_within(path, root), "bound input", f"{path} resolves outside {root}")
    return path.relative_to(root).as_posix()


# -- production source digest (exact existing definition) ---------------------
def _production_files(root):
    root = Path(root)
    files = [root / "Cargo.toml", root / "Cargo.lock"]
    if (root / "build.rs").exists():
        files.append(root / "build.rs")
    for directory in SOURCE_DIRS:
        path = root / directory
        if path.exists():
            files.extend(item for item in path.rglob("*") if item.is_file())
    return files


def source_digest(root):
    """The exact existing production source digest, with an explicit root.

    This is the algorithm from ``scripts/build_native.py``: sorted
    repository-relative path, NUL, and the raw-byte SHA-256 are folded into one
    SHA-256 over Cargo.toml, Cargo.lock, build.rs when present, and every file
    below src, migrations, schema and vendor.
    """
    root = Path(root).resolve()
    digest = hashlib.sha256()
    for path in sorted(_production_files(root)):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _source_digest_from_blobs(root, blobs):
    root = Path(root).resolve()
    digest = hashlib.sha256()
    for path in sorted(_production_files(root)):
        relative = path.relative_to(root).as_posix()
        raw = blobs.get(relative)
        _require(raw is not None, "bound input", f"production input {relative} was not measured")
        digest.update(relative.encode() + b"\0")
        digest.update(hashlib.sha256(raw).digest())
    return digest.hexdigest()


def _is_production_path(path):
    return path in ("Cargo.toml", "Cargo.lock", "build.rs") or any(
        path == directory or path.startswith(directory + "/") for directory in SOURCE_DIRS
    )


def source_digest_from_entries(entries):
    """Recompute the production source digest from recorded content hashes.

    No file needs to be present.  This is the same path/NUL/content-digest
    folding as :func:`source_digest`, restricted to the production closure that
    the v2 inventory records.
    """
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item["path"]):
        if not entry["present"] or not _is_production_path(entry["path"]):
            continue
        digest.update(entry["path"].encode() + b"\0")
        digest.update(bytes.fromhex(entry["sha256"]))
    return digest.hexdigest()


# -- git / atomic evidence ----------------------------------------------------
def git_state(root):
    """HEAD/commit/tree plus tracked and non-ignored untracked working state.

    ``status`` is retained as the historical tracked-only porcelain status.
    ``status_with_untracked`` uses ``--untracked-files=normal``, so real
    untracked source files are reported while ignored build outputs (for
    example an ignored target directory) remain ignored: ``--ignored`` is
    never passed and file contents are never read.  ``untracked`` lists the
    repository-relative paths Git reported.  This helper is producer-only; the
    reader never invokes Git.
    """
    root = Path(root)

    def git_output(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root, text=True)

    head = git_output("rev-parse", "HEAD").strip()
    commit = git_output("rev-parse", "--verify", "HEAD^{commit}").strip()
    tree = git_output("rev-parse", "HEAD^{tree}").strip()
    tracked_status = git_output("status", "--porcelain", "--untracked-files=no")
    status_with_untracked = git_output("status", "--porcelain", "--untracked-files=normal")
    untracked = [
        line[3:]
        for line in status_with_untracked.splitlines()
        if line.startswith("?? ")
    ]
    return {
        "head": head,
        "commit": commit,
        "tree": tree,
        "status": tracked_status,
        "tracked_status": tracked_status,
        "status_with_untracked": status_with_untracked,
        "untracked": untracked,
        "untracked_count": len(untracked),
        "tracked_dirty": bool(tracked_status.strip()),
        "dirty": bool(status_with_untracked.strip()),
        "clean": not status_with_untracked.strip(),
    }


def require_clean_git_state(root):
    """Fail closed unless tracked and non-ignored untracked state are clean.

    Ignored build outputs stay ignored because Git is queried with
    ``--untracked-files=normal`` and never with ``--ignored``.  The error names
    only the kind/count of dirty state, not file contents or environment.
    """
    state = git_state(root)
    problems = []
    if state["tracked_dirty"]:
        problems.append("tracked changes")
    if state["untracked_count"]:
        problems.append(f"{state['untracked_count']} untracked file(s)")
    if problems:
        raise ReceiptError(
            "source tree is not clean: "
            + ", ".join(problems)
            + "; commit the inputs or add generated outputs to .gitignore before building"
        )
    return state


def atomic_write_json(path, payload):
    """Write one deterministic JSON evidence file by a same-directory rename."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name("." + destination.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, destination)
    return destination


# -- in-repository Cargo config and environment guard -------------------------
def config_path_keys(raw):
    """The keys of one Cargo config that redirect inputs or override the build."""
    table, keys, seen = None, [], set()
    for line in raw.decode("utf-8", "replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            table = stripped.strip("[]<>").strip().strip('"')
            continue
        match = TOML_KEY.match(stripped)
        if not match:
            continue
        key = match.group(1) if match.group(1) is not None else match.group(2)
        names = [key] if table is None else table.split(".") + [key]
        candidates = {key, ".".join(names[-2:]), ".".join(names[-3:])}
        table_names = names[:-1]
        if len(table_names) >= 2 and table_names[0] in PATH_TABLES:
            candidates.add(table_names[0] + "." + table_names[1] + "." + key)
        folded = {candidate.lower() for candidate in candidates}
        hit = None
        for pattern in PATH_KEYS:
            if pattern.lower() in folded:
                hit = table + "." + key if table is not None and key != "CARGO_TARGET_DIR" else pattern
                break
        if hit is None and table is not None:
            parts = table.split(".")
            if table == "build" and key in BUILD_REDIRECT_KEYS:
                hit = "build." + key
            elif parts[0] == "profile":
                hit = table + "." + key
        if hit is not None and hit not in seen:
            seen.add(hit)
            keys.append(hit)
    return keys


def require_in_repository_config(name, raw):
    """Refuse a bound config that redirects inputs this inventory cannot bind."""
    keys = config_path_keys(raw)
    if keys:
        raise ReceiptError(
            name
            + " sets "
            + ", ".join(repr(key) for key in keys)
            + ", a value that redirects build inputs or overrides the compiler or build profile; "
            "only in-repository configuration is bound"
        )


def reject_external_cargo_config(root, environ=None):
    """Refuse external Cargo config candidates without reading their contents.

    Only existence is checked, so a private HOME/CARGO_HOME config is rejected
    rather than hashed, copied or inspected.  Credential files are never read.
    """
    root = Path(root).resolve()
    env = os.environ if environ is None else environ
    cargo_home = env.get("CARGO_HOME")
    if cargo_home:
        home = Path(cargo_home)
        if not home.is_absolute():
            home = root / home
        candidates = [home / "config.toml", home / "config"]
    else:
        user_home = env.get("HOME")
        if user_home:
            candidates = [Path(user_home) / ".cargo" / "config.toml", Path(user_home) / ".cargo" / "config"]
        else:
            candidates = []
    for ancestor in root.parents:
        candidates.append(ancestor / ".cargo" / "config.toml")
        candidates.append(ancestor / ".cargo" / "config")
    for path in candidates:
        if path.is_file():
            raise ReceiptError(
                "Cargo configuration outside the workspace at "
                + os.path.abspath(str(path))
                + " could change this build; only in-repository configuration is bound"
            )


def is_rejected_environment_name(name):
    """Whether this variable name would change the compiler, profile, workspace or target."""
    if name in PASSTHROUGH_VARIABLES or name in REJECTED_COMPILER_VARIABLES:
        return True
    if name == ALLOWED_TARGET_DIR:
        return False
    if name.startswith(REJECTED_VARIABLE_PREFIXES):
        return True
    return name.startswith("CARGO_TARGET_") and (name.endswith("_LINKER") or name.endswith("_RUSTFLAGS"))


def reject_passthrough_environment(environ=None):
    """Reject build-affecting inherited variable names, never their values."""
    env = os.environ if environ is None else environ
    found = sorted(name for name in env if env.get(name) and is_rejected_environment_name(name))
    if found:
        raise ReceiptError(
            "refusing inherited profile/target environment: "
            + ", ".join(found)
            + "; pass explicit build options so the recorded command is the build"
        )


def _parse_build_jobs(value):
    """Parse one CARGO_BUILD_JOBS value without retaining it in an error."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if re.fullmatch(r"[0-9]+", text) is None:
        return None
    jobs = int(text, 10)
    return jobs if jobs > 0 else None


def normalize_build_environment(environ=None):
    """Extract a validated Cargo job budget from an inherited environment.

    ``CARGO_BUILD_JOBS`` is the only scheduling variable this API normalizes.
    When present it must be a positive decimal integer.  The value is removed
    from a copy of ``environ`` and represented twice in the returned mapping:
    as the explicit Cargo argv fragment ``["--jobs", "<n>"]`` and as
    ``{"jobs": n}`` in ``build_options``.  A caller therefore appends
    ``cargo_args`` to the exact Cargo command (so the job budget is recorded)
    and passes ``environment`` to :func:`capture_bound_inputs` or
    :func:`probe_toolchain`.

    The remaining variable names still pass the conservative compiler/config
    guard.  ``RUSTFLAGS``, ``CARGO_PROFILE_*``, ``CARGO_BUILD_TARGET`` and the
    other rejected selectors fail closed; they are never dropped or ignored.
    ``CARGO_TARGET_DIR`` remains allowed.  Error messages name the offending
    variable and never include its value.
    """
    env = dict(os.environ if environ is None else environ)
    jobs = None
    if BUILD_JOBS_VARIABLE in env:
        jobs = _parse_build_jobs(env.pop(BUILD_JOBS_VARIABLE))
        if jobs is None:
            raise ReceiptError(
                BUILD_JOBS_VARIABLE
                + " must be a positive decimal integer; remove it from the inherited "
                "environment and pass an explicit --jobs value instead"
            )
    reject_passthrough_environment(env)
    return {
        "environment": env,
        "jobs": jobs,
        "cargo_args": ["--jobs", str(jobs)] if jobs is not None else [],
        "build_options": {"jobs": jobs},
    }


# -- bound input inventory ----------------------------------------------------
def _files_under(root, base):
    root = Path(root).resolve()
    for path in sorted(Path(base).rglob("*")):
        if path.is_file():
            _require(_is_within(path, root), "bound input", f"{path} resolves outside {root}")
            yield path


def _discover_compiled_assets(root, source_paths):
    """Literal in-repository ``include_*!`` targets from bound Rust sources.

    Only string/raw-string literal arguments are considered.  A literal must be
    repository-relative and resolve inside ``root``; a missing target fails
    closed rather than being silently omitted.  Non-literal forms such as
    ``include!(concat!(env!("OUT_DIR"), ...))`` are generated build outputs,
    not repository inputs, and are left to Cargo.
    """
    root = Path(root).resolve()
    discovered = {}
    for relative in sorted(source_paths):
        if not relative.endswith(".rs"):
            continue
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in _INCLUDE_LITERAL.finditer(text):
            literal = match.group("raw")
            if literal is None:
                literal = match.group("plain")
            if literal is None:
                continue
            target = Path(literal)
            if target.is_absolute():
                raise ReceiptError(
                    f"bound input: compile-time include {literal!r} in {relative} "
                    "must be repository-relative"
                )
            resolved = (path.parent / target).resolve()
            _require(
                _is_within(resolved, root),
                "bound input",
                f"compile-time include {literal!r} in {relative} resolves outside {root}",
            )
            discovered[resolved.relative_to(root).as_posix()] = relative
    return discovered


def bound_input_inventory(root):
    """Return ``(entries, blobs)`` for the full v2 input inventory.

    Entries are sorted by repository-relative path and carry role, presence and
    raw-byte SHA-256 only; contents are returned separately in ``blobs`` for
    digest computation and are never serialized.  Fixed absent candidates are
    listed.  Production files reproduce the exact ``source_digest`` closure;
    the test closure binds ``tests/**/*.rs`` plus the known support directories.
    Files embedded by literal ``include_*!`` macros are bound as
    ``compiled_asset`` even when they live outside those directories; the
    explicit :data:`COMPILED_ASSETS` set is required to be present.
    """
    root = Path(root).resolve()
    _require(root.is_dir(), "bound input", f"source root {root} is not a directory")
    roles = {}
    absent = set()

    def add_fixed(relative, role):
        if (root / relative).is_file():
            roles[relative] = role
        else:
            absent.add(relative)

    for name in TOOLCHAIN_PINS:
        add_fixed(name, "toolchain")
    for name in CARGO_CONFIG_FILES:
        add_fixed(name, "cargo_config")
    add_fixed("build.rs", "build_script")
    for name, role in MANIFEST_INPUTS.items():
        _require((root / name).is_file(), "bound input", f"{name} is missing from {root}")
        roles[name] = role
    for directory in SOURCE_DIRS:
        base = root / directory
        if base.is_dir():
            for path in _files_under(root, base):
                roles[path.relative_to(root).as_posix()] = "production_source"
    tests = root / "tests"
    if tests.is_dir():
        for path in _files_under(root, tests):
            if path.suffix == ".rs":
                roles[path.relative_to(root).as_posix()] = "integration_test_source"
    for directory in TEST_SUPPORT_DIRS:
        base = root / directory
        if base.is_dir():
            for path in _files_under(root, base):
                roles[path.relative_to(root).as_posix()] = "test_support"

    for relative in COMPILED_ASSETS:
        _require(
            (root / relative).is_file(),
            "bound input",
            f"required compiled asset {relative} is missing from {root}",
        )
        roles[relative] = "compiled_asset"
    for relative in _discover_compiled_assets(root, list(roles)):
        if relative not in roles:
            _require(
                (root / relative).is_file(),
                "bound input",
                f"compile-time include target {relative} is missing from {root}",
            )
            roles[relative] = "compiled_asset"

    entries, blobs = [], {}
    for relative in sorted(set(roles) | absent):
        path = root / relative
        if path.is_file():
            _require(_is_within(path, root), "bound input", f"{path} resolves outside {root}")
            raw = path.read_bytes()
            if roles.get(relative) == "cargo_config":
                require_in_repository_config(relative, raw)
            blobs[relative] = raw
            entries.append(
                {
                    "path": relative,
                    "role": roles[relative],
                    "present": True,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        elif relative in absent:
            entries.append(
                {
                    "path": relative,
                    "role": roles.get(relative, FIXED_CANDIDATES.get(relative)),
                    "present": False,
                    "sha256": None,
                }
            )
        else:
            raise ReceiptError(f"bound input {relative} disappeared before measurement")
    return entries, blobs


def bound_entry_line(path, raw):
    digest = hashlib.sha256()
    digest.update(path.encode() + b"\0")
    digest.update(hashlib.sha256(raw).digest())
    return digest.digest()


def _entry_line_from_digest(path, content_sha256):
    digest = hashlib.sha256()
    digest.update(path.encode() + b"\0")
    digest.update(bytes.fromhex(content_sha256))
    return digest.digest()


def bound_inputs_digest_from_entries(entries):
    """Digest over path and recorded content hashes; no files need be present."""
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item["path"]):
        if not entry["present"]:
            continue
        digest.update(_entry_line_from_digest(entry["path"], entry["sha256"]))
    return digest.hexdigest()


def bound_inputs_digest(entries, blobs):
    """Digest over path and raw bytes of every present entry."""
    digest = hashlib.sha256()
    for path in sorted(entry["path"] for entry in entries if entry["present"]):
        raw = blobs.get(path)
        if raw is None:
            raise ReceiptError(f"bound input {path} is present but its bytes were not measured")
        digest.update(bound_entry_line(path, raw))
    return digest.hexdigest()


def config_digest_from_entries(entries):
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item["path"]):
        if entry["present"] and entry["role"] in CONFIG_ROLES:
            digest.update(_entry_line_from_digest(entry["path"], entry["sha256"]))
    return digest.hexdigest()


def config_digest(entries, blobs):
    digest = hashlib.sha256()
    for path in sorted(
        entry["path"]
        for entry in entries
        if entry["present"] and entry["role"] in CONFIG_ROLES
    ):
        raw = blobs.get(path)
        if raw is None:
            raise ReceiptError(f"config input {path} is present but its bytes were not measured")
        digest.update(bound_entry_line(path, raw))
    return digest.hexdigest()


def bound_inputs_summary(entries, blobs):
    """The documented summary for one inventory (digest, counts and roles)."""
    present = [entry for entry in entries if entry["present"]]
    by_role = {role: 0 for role in BOUND_ROLES}
    for entry in present:
        by_role[entry["role"]] = by_role.get(entry["role"], 0) + 1
    total_bytes = 0
    for entry in present:
        raw = blobs.get(entry["path"])
        if raw is None:
            raise ReceiptError(f"bound input {entry['path']} is present but its bytes were not measured")
        total_bytes += len(raw)
    return {
        "digest_algorithm": BOUND_INPUTS_DIGEST_ALGORITHM,
        "digest": bound_inputs_digest(entries, blobs),
        "present_count": len(present),
        "absent_count": len(entries) - len(present),
        "total_bytes": total_bytes,
        "by_role": by_role,
        "absent": [entry["path"] for entry in entries if not entry["present"]],
    }


def capture_bound_inputs(root, environ=None):
    """Producer helper: bind source, test, manifest, config and toolchain inputs.

    The environment is checked by name before anything is measured.  External
    Cargo configuration is rejected by existence only; no HOME/CARGO_HOME
    config or credential file is read.  Returned ``bound_input_inventory``
    contains no file contents and no environment values.
    """
    root = Path(root).resolve()
    reject_passthrough_environment(environ)
    reject_external_cargo_config(root, environ)
    entries, blobs = bound_input_inventory(root)
    return {
        "source_inputs_sha256": _source_digest_from_blobs(root, blobs),
        "cargo_lock_sha256": hashlib.sha256(blobs["Cargo.lock"]).hexdigest(),
        "config_digest": config_digest(entries, blobs),
        "bound_inputs": bound_inputs_summary(entries, blobs),
        "bound_input_inventory": entries,
    }


# -- metadata-only toolchain probes -------------------------------------------
def _parse_verbose_version(text, label):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    _require(bool(lines), label, "verbose version output is empty")
    fields = {}
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if not separator:
            continue
        fields[key.strip().lower().replace(" ", "_").replace("-", "_")] = value.strip()
    return lines[0], fields


def _tool_identity(executable, label, run, *, probe):
    executable = Path(executable).resolve()
    _require(executable.is_file(), label, f"executable {executable} is missing")
    process = run([str(executable), "-vV"])
    _require(
        getattr(process, "returncode", 1) == 0,
        label,
        f"{probe} -vV failed with status {getattr(process, 'returncode', 'unknown')}",
    )
    version, fields = _parse_verbose_version(getattr(process, "stdout", ""), label)
    release = fields.get("release")
    commit_hash = fields.get("commit_hash")
    host = fields.get("host")
    _require_nonempty_str(release, label, f"{probe} release")
    _require_commit(commit_hash, label, f"{probe} commit-hash")
    _require_nonempty_str(host, label, f"{probe} host")
    return {
        "executable": str(executable),
        "executable_sha256": sha256_file(executable),
        "version": version,
        "release": release,
        "commit_hash": commit_hash.lower(),
        "commit_date": fields.get("commit_date"),
        "host": host,
    }


def _pinned_channel(root):
    toml = Path(root) / "rust-toolchain.toml"
    if toml.is_file():
        match = re.search(r'^\s*channel\s*=\s*"([^"]+)"', toml.read_text(encoding="utf-8"), re.MULTILINE)
        if match:
            return match.group(1), "rust-toolchain.toml"
    legacy = Path(root) / "rust-toolchain"
    if legacy.is_file():
        channel = legacy.read_text(encoding="utf-8").strip()
        if channel:
            return channel, "rust-toolchain"
    return None, None


def _is_rustup_proxy(executable):
    """Whether a PATH rustc entry resolves to the rustup multi-call binary."""
    return Path(executable).resolve().name.lower() in ("rustup", "rustup.exe")


def probe_toolchain(root, environ=None, which=None, run=None):
    """Producer metadata probe: Cargo/rustc/rustup identity, never a compile.

    Cargo is resolved from PATH only; ``rustup which cargo`` is deliberately not
    used.  A PATH ``rustc`` that is a rustup proxy (a symlink resolving to the
    rustup binary) is resolved with ``rustup which rustc`` before any identity
    probe, so ``rustc -vV`` is executed by the actual compiler and never by
    rustup under the wrong argv0.  A direct, non-proxy ``rustc`` is probed
    in place.  Cargo's and rustc's full ``commit-hash`` values are copied from
    ``-vV``; the resolved rustc release must match an exact version pin when
    ``rust-toolchain.toml``/``rust-toolchain`` names one.

    The only subprocesses issued are ``cargo -vV``, ``rustc -vV`` and
    ``rustup which rustc`` (the latter when rustup is available or needed).
    The default runner passes the caller-supplied ``environ`` mapping verbatim
    as the subprocess environment, after the same name-only compiler/config
    guard used by :func:`capture_bound_inputs`; it never merges or inherits the
    process environment.  An exact version pin is checked against the rustc
    that is actually selected, whether direct or rustup-proxied.
    """
    root = Path(root).resolve()
    env = os.environ if environ is None else environ
    reject_passthrough_environment(env)
    which = which or shutil.which
    run = run or (
        lambda command: subprocess.run(
            command,
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    )
    search_path = env.get("PATH", "")

    cargo_path = which("cargo", path=search_path)
    _require(bool(cargo_path), "toolchain", "cargo is not on PATH")
    cargo = _tool_identity(cargo_path, "toolchain", run, probe="cargo")

    rustc_entry = which("rustc", path=search_path)
    _require(bool(rustc_entry), "toolchain", "rustc is not on PATH")
    rustc_proxy = _is_rustup_proxy(rustc_entry)

    rustup_entry = which("rustup", path=search_path)
    if rustc_proxy:
        # The proxy itself resolves to the rustup binary that owns it.  Prefer
        # that binary over an unrelated rustup that happens to be on PATH.
        rustup_path = Path(rustc_entry).resolve()
    elif rustup_entry:
        rustup_path = Path(rustup_entry).resolve()
    else:
        rustup_path = None

    rustup = None
    resolved_rustc = None
    rustc = None
    if not rustc_proxy:
        rustc = _tool_identity(rustc_entry, "toolchain", run, probe="rustc")
        rustc["path_entry"] = os.path.abspath(str(rustc_entry))
        rustc["proxy"] = False

    if rustup_path is not None:
        _require(rustup_path.is_file(), "toolchain", f"rustup executable {rustup_path} is missing")
        rustup = {
            "executable": str(rustup_path),
            "executable_sha256": sha256_file(rustup_path),
        }
        process = run([str(rustup_path), "which", "rustc"])
        succeeded = getattr(process, "returncode", 1) == 0
        output = getattr(process, "stdout", "").strip()
        if rustc_proxy:
            _require(
                succeeded and bool(output),
                "toolchain",
                "rustc is a rustup proxy but rustup which rustc did not resolve "
                f"an executable (status {getattr(process, 'returncode', 'unknown')})",
            )
        if succeeded and output:
            resolved = Path(output).resolve()
            _require(resolved.is_file(), "toolchain", f"rustup resolved rustc {resolved} is missing")
            rustup["resolved_rustc"] = str(resolved)
            rustup["resolved_rustc_sha256"] = sha256_file(resolved)
            resolved_rustc = resolved

    if rustc_proxy:
        _require(
            resolved_rustc is not None,
            "toolchain",
            "rustc is a rustup proxy but no actual rustc executable was resolved",
        )
        rustc = _tool_identity(resolved_rustc, "toolchain", run, probe="rustc")
        rustc["path_entry"] = os.path.abspath(str(rustc_entry))
        rustc["proxy"] = True
        _require(
            rustc["version"].startswith("rustc "),
            "toolchain",
            "rustup which rustc did not resolve a rustc identity",
        )

    channel, pin_source = _pinned_channel(root)
    if channel:
        pinned_release = re.match(r"^([0-9]+\.[0-9]+\.[0-9]+)(?:[-+].*)?$", channel)
        if pinned_release:
            _require(
                rustc["release"] == pinned_release.group(1),
                "toolchain",
                f"selected rustc release {rustc['release']!r} does not match "
                f"pinned channel {channel!r}",
            )

    return {
        "cargo": cargo,
        "rustc": rustc,
        "rustup": rustup,
        "target_triple": rustc["host"],
        "pinned_channel": channel,
        "pin_source": pin_source,
    }


# -- Cargo event capture ------------------------------------------------------
def _normalize_profile(profile, label):
    profile = _require_mapping(profile, label, "profile")
    result = {key: profile.get(key) for key in PROFILE_FIELDS}
    opt_level = result["opt_level"]
    _require(
        (isinstance(opt_level, str) and bool(opt_level)) or (isinstance(opt_level, int) and not _is_bool(opt_level)),
        label,
        "profile.opt_level must be a nonempty string or integer",
    )
    debuginfo = result["debuginfo"]
    _require(
        debuginfo is None or isinstance(debuginfo, (str, int, bool)),
        label,
        "profile.debuginfo must be a string, integer, boolean or null",
    )
    for key in ("debug_assertions", "overflow_checks", "test"):
        _require_bool(result[key], label, f"profile.{key}")
    return result


def _require_kind_profile(kind, profile, label):
    """One centralized kind/profile consistency check for capture and reading."""
    expects_test = kind in ("test", "lib-test")
    _require(
        profile["test"] is expects_test,
        label,
        f"{kind} artifact profile.test must be exactly {str(expects_test).lower()}",
    )


def cargo_artifact_record(event, source_root, kind=None):
    """Capture one selected Cargo compiler-artifact as a v2 row.

    ``fresh`` is copied strictly; a missing, null, integer or string freshness
    is refused instead of being coerced.  Sources are stored relative to
    ``source_root`` with their content hash.  Executable rows record the
    absolute executable path and its SHA-256.
    """
    source_root = Path(source_root).resolve()
    _require_mapping(event, "cargo artifact", "compiler-artifact event")
    _require(event.get("reason") == "compiler-artifact", "cargo artifact", "event is not compiler-artifact")
    package_id = _require_nonempty_str(event.get("package_id"), "cargo artifact", "package_id")
    target = _require_mapping(event.get("target"), "cargo artifact", "target")
    name = _require_nonempty_str(target.get("name"), "cargo artifact", "target.name")
    kinds = list(target.get("kind") or [])
    profile = _normalize_profile(event.get("profile") or {}, "cargo artifact")
    if kind is None:
        if "test" in kinds:
            kind = "test"
        elif "bin" in kinds:
            kind = "bin"
        elif "lib" in kinds:
            kind = "lib-test" if profile["test"] else "lib"
        else:
            raise ReceiptError(f"cargo artifact: unsupported target kind {kinds!r}")
    _require(kind in ARTIFACT_KINDS, "cargo artifact", f"unsupported kind {kind!r}")
    if kind == "test":
        _require("test" in kinds, "cargo artifact", "test kind does not match the Cargo target")
    elif kind == "bin":
        _require("bin" in kinds, "cargo artifact", "bin kind does not match the Cargo target")
    else:
        _require("lib" in kinds, "cargo artifact", "lib kind does not match the Cargo target")
    _require_kind_profile(kind, profile, "cargo artifact")
    fresh = event.get("fresh")
    _require(_is_bool(fresh), "cargo artifact", "fresh must be a JSON boolean")
    src_path = target.get("src_path")
    _require(isinstance(src_path, str) and bool(src_path), "cargo artifact", "target.src_path is missing")
    source_path = Path(src_path)
    if not source_path.is_absolute():
        source_path = source_root / source_path
    _require(source_path.is_file(), "cargo artifact", f"source {source_path} is missing")
    source = _relative_to_root(source_path, source_root)

    record = {
        "target": name,
        "kind": kind,
        "package_id": package_id,
        "profile": profile,
        "source": source,
        "source_sha256": sha256_file(source_root / source),
        "fresh": fresh,
    }
    executable = event.get("executable")
    if kind in EXECUTABLE_KINDS:
        _require(isinstance(executable, str) and bool(executable), "cargo artifact", f"{kind} artifact has no executable")
        executable_path = Path(executable)
        if not executable_path.is_absolute():
            executable_path = source_root / executable_path
        executable_path = executable_path.resolve()
        _require(executable_path.is_file(), "cargo artifact", f"executable {executable_path} is missing")
        record["executable"] = str(executable_path)
        record["executable_sha256"] = sha256_file(executable_path)
    else:
        _require(not executable, "cargo artifact", f"lib artifact unexpectedly has executable {executable!r}")
    return record


def require_build_finished(events):
    """Require exactly one successful Cargo ``build-finished`` event."""
    finished = [event for event in events if isinstance(event, Mapping) and event.get("reason") == "build-finished"]
    _require(
        len(finished) == 1 and finished[0].get("success") is True,
        "cargo events",
        "expected exactly one successful build-finished event",
    )


def _feature_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    else:
        _require(isinstance(value, Iterable), "features", "features must be a string or iterable")
        items = list(value)
    result = []
    for item in items:
        _require(
            isinstance(item, str) and bool(item) and item == item.strip() and "," not in item,
            "features",
            f"invalid feature identifier {item!r}",
        )
        result.append(item)
    _require(len(result) == len(set(result)), "features", "duplicate feature identifier")
    return result


def _validate_command(command, label, reject_clean=True):
    _require(isinstance(command, (list, tuple)), label, "command must be a list of strings")
    _require(bool(command), label, "command must not be empty")
    result = []
    for argument in command:
        _require(isinstance(argument, str) and bool(argument), label, "command entries must be nonempty strings")
        result.append(argument)
    if reject_clean and len(result) >= 2 and result[1] == "clean":
        raise ReceiptError(f"{label}: command starts a cargo clean; v2 receipts describe builds only")
    return result


def _validate_features(features, label):
    features = _require_mapping(features, label, "features")
    enabled = features.get("enabled")
    _require(isinstance(enabled, list), label, "features.enabled must be a list")
    for item in enabled:
        _require(
            isinstance(item, str) and bool(item) and item == item.strip() and "," not in item,
            label,
            "features.enabled entries must be nonempty feature names",
        )
    _require(len(enabled) == len(set(enabled)), label, "features.enabled has duplicate names")
    _require_bool(features.get("no_default_features"), label, "features.no_default_features")
    return {"enabled": list(enabled), "no_default_features": features["no_default_features"]}


# -- receipt construction -----------------------------------------------------
def make_receipt_v2(
    *,
    binary_path,
    command,
    profile,
    artifacts,
    toolchain,
    bound_inputs,
    workspace_commit,
    target_dir,
    target_triple=None,
    features=None,
    no_default_features=False,
    lock_file=None,
    git_head=None,
    working_tree=None,
    duration_seconds=None,
    extra=None,
):
    """Build a v2 receipt from producer measurements.

    ``bound_inputs`` is the mapping returned by :func:`capture_bound_inputs`.
    ``features`` accepts a comma-separated string, an iterable of names or the
    documented ``{"enabled": [...], "no_default_features": bool}`` mapping.
    ``extra`` may add provenance fields such as ``kind``, ``batch``,
    ``relocated_artifact`` or ``implicit_build`` but may not override required
    fields or reintroduce v1 freshness/clean aliases.
    """
    binary = Path(binary_path).resolve()
    _require(binary.is_file(), "build receipt", f"binary {binary} is missing")
    command = _validate_command(command, "build receipt")
    _require_nonempty_str(profile, "build receipt", "profile")
    _require_commit(workspace_commit, "build receipt")
    bound = _require_mapping(bound_inputs, "build receipt", "bound_inputs")
    for key in ("source_inputs_sha256", "cargo_lock_sha256", "config_digest"):
        _require_sha256(bound.get(key), "build receipt", key)
    summary = _require_mapping(bound.get("bound_inputs"), "build receipt", "bound_inputs.bound_inputs")
    inventory = _require_list(
        bound.get("bound_input_inventory"), "build receipt", "bound_inputs.bound_input_inventory"
    )
    _require_mapping(toolchain, "build receipt", "toolchain")
    resolved_triple = target_triple or toolchain.get("target_triple")
    _require_nonempty_str(resolved_triple, "build receipt", "target_triple")
    if isinstance(features, Mapping):
        enabled = _feature_list(features.get("enabled"))
        no_default = _require_bool(
            features.get("no_default_features"), "build receipt", "features.no_default_features"
        )
    else:
        enabled = _feature_list(features)
        no_default = _require_bool(no_default_features, "build receipt", "no_default_features")
    target_dir = os.fspath(target_dir)
    _require_absolute_path(target_dir, "build receipt", "target_dir")
    if lock_file is not None:
        lock_file = os.fspath(lock_file)
        _require_absolute_path(lock_file, "build receipt", "lock_file")
    if working_tree is not None:
        _require_mapping(working_tree, "build receipt", "working_tree")

    payload = {
        "receipt_schema": RECEIPT_SCHEMA_V2,
        "binary_sha256": sha256_file(binary),
        "workspace_commit": _require_commit(workspace_commit, "build receipt"),
        "source_inputs_sha256": bound["source_inputs_sha256"],
        "cargo_lock_sha256": bound["cargo_lock_sha256"],
        "config_digest": bound["config_digest"],
        "command": command,
        "features": {"enabled": enabled, "no_default_features": no_default},
        "profile": profile,
        "target_triple": resolved_triple,
        "target_dir": str(Path(target_dir).resolve()),
        "toolchain": toolchain,
        "bound_inputs": summary,
        "bound_input_inventory": inventory,
        "cargo_artifacts": list(artifacts),
    }
    if lock_file is not None:
        payload["lock_file"] = lock_file
    if git_head is not None:
        payload["git_head"] = git_head
    if working_tree is not None:
        payload["working_tree"] = working_tree
    if duration_seconds is not None:
        payload["duration_seconds"] = duration_seconds
    if extra is not None:
        extra = _require_mapping(extra, "build receipt", "extra")
        for key in extra:
            _require(key not in V2_BANNED_FIELDS, "build receipt", f"extra may not set {key}")
            _require(key not in payload, "build receipt", f"extra may not override {key}")
        payload.update(extra)
    _validate_v2_payload(payload, "build receipt", binary_path=binary)
    return payload


# -- shape validation ---------------------------------------------------------
def _validate_v1_artifacts(rows, label):
    rows = _require_list(rows, label, "fresh_false_artifacts")
    seen = set()
    result = []
    for index, row in enumerate(rows):
        row = _require_mapping(row, label, f"fresh_false_artifacts[{index}]")
        target = _require_nonempty_str(row.get("target"), label, f"fresh_false_artifacts[{index}].target")
        kind = row.get("kind")
        _require(kind in ARTIFACT_KINDS, label, f"fresh_false_artifacts[{index}].kind is invalid")
        _require(
            row.get("fresh") is False,
            label,
            f"fresh_false_artifacts[{index}].fresh must be exactly false for a v1 receipt",
        )
        if "package_id" in row:
            _require_nonempty_str(row.get("package_id"), label, f"fresh_false_artifacts[{index}].package_id")
        if "executable" in row:
            _require_nonempty_str(row.get("executable"), label, f"fresh_false_artifacts[{index}].executable")
        key = (kind, target)
        _require(key not in seen, label, f"duplicate ({kind}, {target}) in fresh_false_artifacts")
        seen.add(key)
        result.append(dict(row))
    return result


def _validate_inventory(
    entries,
    summary,
    label,
    *,
    require_fixed,
    require_manifests,
    require_compiled_assets=False,
    full_roles,
    algorithm_exact,
):
    entries = _require_list(entries, label, "bound_input_inventory")
    seen = set()
    for index, entry in enumerate(entries):
        entry = _require_mapping(entry, label, f"bound_input_inventory[{index}]")
        path = _require_relative_path(entry.get("path"), label, f"bound_input_inventory[{index}].path")
        _require(path not in seen, label, f"duplicate bound input {path}")
        seen.add(path)
        _require(
            entry.get("role") in BOUND_ROLES,
            label,
            f"bound input {path} has an unknown role {entry.get('role')!r}",
        )
        present = _require_bool(entry.get("present"), label, f"bound input {path}.present")
        if present:
            _require_sha256(entry.get("sha256"), label, f"bound input {path}.sha256")
        else:
            _require(entry.get("sha256") is None, label, f"absent bound input {path} must have null sha256")
            _require(
                entry["role"] != "compiled_asset",
                label,
                f"compiled asset {path} must be present",
            )
    paths = [entry["path"] for entry in entries]
    _require(paths == sorted(paths), label, "bound_input_inventory must be path-sorted")
    by_path = {entry["path"]: entry for entry in entries}
    if require_fixed:
        for path in FIXED_CANDIDATES:
            _require(path in by_path, label, f"bound_input_inventory is missing fixed candidate {path}")
    if require_manifests:
        for path in MANIFEST_INPUTS:
            _require(path in by_path, label, f"bound_input_inventory is missing {path}")
            _require(by_path[path]["present"] is True, label, f"{path} must be present")
    if require_compiled_assets:
        for path in COMPILED_ASSETS:
            _require(
                path in by_path and by_path[path]["present"] is True,
                label,
                f"bound_input_inventory is missing required compiled asset {path}",
            )

    summary = _require_mapping(summary, label, "bound_inputs")
    computed = bound_inputs_digest_from_entries(entries)
    digest = _require_sha256(summary.get("digest"), label, "bound_inputs.digest")
    _require(digest == computed, label, "bound_inputs.digest does not match bound_input_inventory")
    algorithm = _require_nonempty_str(summary.get("digest_algorithm"), label, "bound_inputs.digest_algorithm")
    if algorithm_exact:
        _require(
            algorithm == BOUND_INPUTS_DIGEST_ALGORITHM,
            label,
            "bound_inputs.digest_algorithm is not the documented v2 algorithm",
        )
    present = [entry for entry in entries if entry["present"]]
    present_count = _require_int(summary.get("present_count"), label, "bound_inputs.present_count", minimum=0)
    absent_count = _require_int(summary.get("absent_count"), label, "bound_inputs.absent_count", minimum=0)
    _require_int(summary.get("total_bytes"), label, "bound_inputs.total_bytes", minimum=0)
    _require(present_count == len(present), label, "bound_inputs.present_count does not match inventory")
    _require(
        present_count + absent_count == len(entries),
        label,
        "bound_inputs present_count + absent_count does not match inventory",
    )
    absent_paths = [entry["path"] for entry in entries if not entry["present"]]
    _require(summary.get("absent") == absent_paths, label, "bound_inputs.absent does not match inventory")
    by_role = _require_mapping(summary.get("by_role"), label, "bound_inputs.by_role")
    actual_by_role = {role: 0 for role in BOUND_ROLES}
    for role, count in by_role.items():
        _require(role in BOUND_ROLES, label, f"bound_inputs.by_role has unknown role {role!r}")
        actual_by_role[role] = _require_int(count, label, f"bound_inputs.by_role.{role}", minimum=0)
    if full_roles:
        _require(
            set(by_role) == set(BOUND_ROLES),
            label,
            "bound_inputs.by_role must document every v2 role",
        )
    for role in BOUND_ROLES:
        expected = sum(1 for entry in present if entry["role"] == role)
        _require(
            actual_by_role.get(role, 0) == expected,
            label,
            f"bound_inputs.by_role.{role} does not match inventory",
        )
    _require(
        sum(actual_by_role.values()) == present_count,
        label,
        "bound_inputs.by_role counts do not sum to present_count",
    )
    return entries, summary


def _validate_v2_toolchain(toolchain, label):
    toolchain = _require_mapping(toolchain, label, "toolchain")
    target_triple = _require_nonempty_str(toolchain.get("target_triple"), label, "toolchain.target_triple")
    for name in ("cargo", "rustc"):
        identity = _require_mapping(toolchain.get(name), label, f"toolchain.{name}")
        _require_absolute_path(identity.get("executable"), label, f"toolchain.{name}.executable")
        _require_sha256(identity.get("executable_sha256"), label, f"toolchain.{name}.executable_sha256")
        _require_nonempty_str(identity.get("version"), label, f"toolchain.{name}.version")
        _require_nonempty_str(identity.get("release"), label, f"toolchain.{name}.release")
        _require_commit(identity.get("commit_hash"), label, f"toolchain.{name}.commit_hash")
        _require_nonempty_str(identity.get("host"), label, f"toolchain.{name}.host")
        if name == "rustc" and ("proxy" in identity or "path_entry" in identity):
            _require_bool(identity.get("proxy"), label, "toolchain.rustc.proxy")
            _require_absolute_path(identity.get("path_entry"), label, "toolchain.rustc.path_entry")
    rustup = toolchain.get("rustup")
    if rustup is not None:
        rustup = _require_mapping(rustup, label, "toolchain.rustup")
        _require_absolute_path(rustup.get("executable"), label, "toolchain.rustup.executable")
        _require_sha256(rustup.get("executable_sha256"), label, "toolchain.rustup.executable_sha256")
        if "resolved_rustc" in rustup:
            _require_absolute_path(rustup.get("resolved_rustc"), label, "toolchain.rustup.resolved_rustc")
            _require_sha256(
                rustup.get("resolved_rustc_sha256"), label, "toolchain.rustup.resolved_rustc_sha256"
            )
    channel = toolchain.get("pinned_channel")
    if channel is not None:
        _require_nonempty_str(channel, label, "toolchain.pinned_channel")
    return dict(toolchain)


def _validate_v2_artifacts(rows, label):
    rows = _require_list(rows, label, "cargo_artifacts")
    seen = set()
    result = []
    for index, row in enumerate(rows):
        row_label = f"{label}: cargo_artifacts[{index}]"
        row = _require_mapping(row, row_label, "artifact")
        target = _require_nonempty_str(row.get("target"), label, f"cargo_artifacts[{index}].target")
        kind = row.get("kind")
        _require(kind in ARTIFACT_KINDS, label, f"cargo_artifacts[{index}].kind is invalid")
        _require_nonempty_str(row.get("package_id"), label, f"cargo_artifacts[{index}].package_id")
        _require(
            _is_bool(row.get("fresh")),
            label,
            f"cargo_artifacts[{index}].fresh must be a JSON boolean (true or false)",
        )
        profile = _normalize_profile(row.get("profile"), row_label)
        _require_kind_profile(kind, profile, row_label)
        source = _require_relative_path(row.get("source"), label, f"cargo_artifacts[{index}].source")
        _require_sha256(row.get("source_sha256"), label, f"cargo_artifacts[{index}].source_sha256")
        if kind in EXECUTABLE_KINDS:
            _require_absolute_path(row.get("executable"), label, f"cargo_artifacts[{index}].executable")
            _require_sha256(
                row.get("executable_sha256"), label, f"cargo_artifacts[{index}].executable_sha256"
            )
        else:
            _require(
                "executable" not in row and "executable_sha256" not in row,
                label,
                f"cargo_artifacts[{index}] is a lib and must not claim an executable",
            )
        key = (kind, target)
        _require(key not in seen, label, f"duplicate ({kind}, {target}) in cargo_artifacts")
        seen.add(key)
        result.append(dict(row, source=source))
    return result


def _validate_primary_artifact(payload, artifacts, binary_digest, label, binary_path):
    executable_rows = [row for row in artifacts if row["kind"] in EXECUTABLE_KINDS]
    _require(bool(executable_rows), label, "cargo_artifacts has no executable artifact")
    relocated = payload.get("relocated_artifact", False)
    _require(_is_bool(relocated), label, "relocated_artifact must be a JSON boolean")
    if relocated:
        original = _require_sha256(
            payload.get("original_artifact_sha256"), label, "original_artifact_sha256"
        )
        _require(
            binary_digest == original,
            label,
            "relocated binary_sha256 does not match original_artifact_sha256",
        )
        _require(
            any(row["executable_sha256"] == original for row in executable_rows),
            label,
            "no selected executable artifact matches original_artifact_sha256",
        )
        return
    _require(
        any(row["executable_sha256"] == binary_digest for row in executable_rows),
        label,
        "no selected executable artifact matches binary_sha256",
    )


def _validate_batch_link(payload, label, binary_path):
    batch = payload.get("batch")
    if batch is None:
        return None
    batch = _require_mapping(batch, label, "batch")
    _require(batch.get("kind") == BATCH_KIND, label, "batch.kind is invalid")
    _require_int(batch.get("receipt_version"), label, "batch.receipt_version", minimum=1)
    binary = _require_nonempty_str(batch.get("binary"), label, "batch.binary")
    _require(Path(binary).name == binary, label, "batch.binary must be a file name, not a path")
    targets = _require_list(batch.get("targets"), label, "batch.targets")
    for target in targets:
        _require_nonempty_str(target, label, "batch.targets entry")
    bound_digest = _require_sha256(batch.get("bound_inputs_sha256"), label, "batch.bound_inputs_sha256")
    _require_absolute_path(batch.get("manifest"), label, "batch.manifest")
    bound = payload.get("bound_inputs")
    if isinstance(bound, Mapping) and bound.get("digest") is not None:
        _require(
            bound.get("digest") == bound_digest,
            label,
            "batch.bound_inputs_sha256 does not match the receipt bound_inputs digest",
        )
    if binary_path is not None:
        _require(
            Path(binary_path).name == binary,
            label,
            f"batch.binary {binary!r} does not match {Path(binary_path).name!r}",
        )
    return dict(batch)


def _validate_v1_payload(payload, label):
    _require_mapping(payload, label, "receipt")
    if "version" in payload:
        _require_int(payload.get("version"), label, "version", minimum=1)
        _require(payload.get("version") == 1, label, "legacy version must be 1")
    for field in V1_REQUIRED_FIELDS:
        _require(field in payload, label, f"legacy receipt is missing {field}")
    binary_digest = _require_sha256(payload.get("binary_sha256"), label, "binary_sha256")
    source_digest_value = _require_sha256(payload.get("source_inputs_sha256"), label, "source_inputs_sha256")
    commit = _require_commit(payload.get("workspace_commit"), label)
    _require_nonempty_str(payload.get("rustc"), label, "rustc")
    _validate_command(payload.get("command"), label, reject_clean=False)
    if "target_dir" in payload:
        _require_absolute_path(payload.get("target_dir"), label, "target_dir")
    if "lock_file" in payload:
        _require_absolute_path(payload.get("lock_file"), label, "lock_file")
    if "fresh" in payload:
        _require(payload.get("fresh") is False, label, "legacy top-level fresh must be exactly false")
    if "package_rebuilt" in payload:
        _require(payload.get("package_rebuilt") is True, label, "legacy package_rebuilt must be exactly true")
    if "clean_command" in payload:
        clean = payload.get("clean_command")
        _require(isinstance(clean, (list, tuple)) and bool(clean), label, "clean_command must be a nonempty list")
        for argument in clean:
            _require(isinstance(argument, str) and bool(argument), label, "clean_command entries must be strings")
    if "clean_commands" in payload:
        _require_int(payload.get("clean_commands"), label, "clean_commands", minimum=0)
    if "cargo_lock_sha256" in payload:
        _require_sha256(payload.get("cargo_lock_sha256"), label, "cargo_lock_sha256")
    config_digest_value = None
    if "config_digest" in payload:
        config_digest_value = _require_sha256(payload.get("config_digest"), label, "config_digest")
    artifacts = []
    if "fresh_false_artifacts" in payload:
        artifacts = _validate_v1_artifacts(payload.get("fresh_false_artifacts"), label)
    toolchain = None
    if "toolchain" in payload:
        toolchain = _require_mapping(payload.get("toolchain"), label, "toolchain")
        if "target_triple" in toolchain:
            _require_nonempty_str(toolchain.get("target_triple"), label, "toolchain.target_triple")
    if "bound_inputs" in payload or "bound_input_inventory" in payload:
        _require(
            "bound_inputs" in payload and "bound_input_inventory" in payload,
            label,
            "legacy bound_inputs and bound_input_inventory must be present together",
        )
        entries, _ = _validate_inventory(
            payload.get("bound_input_inventory"),
            payload.get("bound_inputs"),
            label,
            require_fixed=False,
            require_manifests=False,
            full_roles=False,
            algorithm_exact=False,
        )
        if config_digest_value is not None:
            _require(
                config_digest_from_entries(entries) == config_digest_value,
                label,
                "config_digest does not match the legacy bound inventory",
            )
    batch = _validate_batch_link(payload, label, None)
    return ValidatedReceipt(
        schema="v1",
        payload=payload,
        binary_sha256=binary_digest,
        workspace_commit=commit,
        source_inputs_sha256=source_digest_value,
        artifacts=tuple(artifacts),
        batch=batch,
        toolchain=toolchain,
        config_digest=config_digest_value,
    )


def _validate_v2_payload(payload, label, binary_path=None):
    _require_mapping(payload, label, "receipt")
    _require(payload.get("receipt_schema") == RECEIPT_SCHEMA_V2, label, "not a v2 receipt")
    for field in V2_BANNED_FIELDS:
        _require(field not in payload, label, f"v2 receipt may not carry legacy field {field}")
    if "version" in payload:
        _require_int(payload.get("version"), label, "version", minimum=1)
        _require(payload.get("version") == 2, label, "version must be 2 in a v2 receipt")
    binary_digest = _require_sha256(payload.get("binary_sha256"), label, "binary_sha256")
    commit = _require_commit(payload.get("workspace_commit"), label)
    source_digest_value = _require_sha256(payload.get("source_inputs_sha256"), label, "source_inputs_sha256")
    lock_digest = _require_sha256(payload.get("cargo_lock_sha256"), label, "cargo_lock_sha256")
    config_digest_value = _require_sha256(payload.get("config_digest"), label, "config_digest")
    _validate_command(payload.get("command"), label)
    _validate_features(payload.get("features"), label)
    _require_nonempty_str(payload.get("profile"), label, "profile")
    target_triple = _require_nonempty_str(payload.get("target_triple"), label, "target_triple")
    _require_absolute_path(payload.get("target_dir"), label, "target_dir")
    if "lock_file" in payload:
        _require_absolute_path(payload.get("lock_file"), label, "lock_file")
    if "git_head" in payload:
        _require_commit(payload.get("git_head"), label, "git_head")
    if "working_tree" in payload:
        _require_mapping(payload.get("working_tree"), label, "working_tree")
    toolchain = _validate_v2_toolchain(payload.get("toolchain"), label)
    _require(
        toolchain["target_triple"] == target_triple,
        label,
        "target_triple does not match toolchain.target_triple",
    )
    entries, _ = _validate_inventory(
        payload.get("bound_input_inventory"),
        payload.get("bound_inputs"),
        label,
        require_fixed=True,
        require_manifests=True,
        require_compiled_assets=True,
        full_roles=True,
        algorithm_exact=True,
    )
    _require(
        source_digest_from_entries(entries) == source_digest_value,
        label,
        "source_inputs_sha256 does not match the production entries in bound_input_inventory",
    )
    lock_entry = next(entry for entry in entries if entry["path"] == "Cargo.lock")
    _require(
        lock_entry["sha256"] == lock_digest,
        label,
        "cargo_lock_sha256 does not match the Cargo.lock inventory entry",
    )
    _require(
        config_digest_from_entries(entries) == config_digest_value,
        label,
        "config_digest does not match the config/toolchain/build-script inventory entries",
    )
    artifacts = _validate_v2_artifacts(payload.get("cargo_artifacts"), label)
    entries_by_path = {entry["path"]: entry for entry in entries}
    for row in artifacts:
        bound_entry = entries_by_path.get(row["source"])
        _require(
            bound_entry is not None and bound_entry["present"] is True,
            label,
            f"artifact source {row['source']} is not present in bound_input_inventory",
        )
        _require(
            bound_entry["sha256"] == row["source_sha256"],
            label,
            f"artifact source {row['source']} hash does not match bound_input_inventory",
        )
    _validate_primary_artifact(payload, artifacts, binary_digest, label, binary_path)
    batch = _validate_batch_link(payload, label, binary_path)
    return ValidatedReceipt(
        schema="v2",
        payload=payload,
        binary_sha256=binary_digest,
        workspace_commit=commit,
        source_inputs_sha256=source_digest_value,
        artifacts=tuple(artifacts),
        batch=batch,
        toolchain=toolchain,
        config_digest=config_digest_value,
    )


# -- expected-value matching --------------------------------------------------
def _matches_subset(actual, expected, label, path="value"):
    if isinstance(expected, Mapping):
        _require(isinstance(actual, Mapping), label, f"{path} must be an object")
        for key, value in expected.items():
            _require(key in actual, label, f"{path} is missing {key}")
            _matches_subset(actual[key], value, label, f"{path}.{key}")
        return
    if isinstance(expected, (list, tuple)):
        _require(
            isinstance(actual, (list, tuple)) and list(actual) == list(expected),
            label,
            f"{path} does not match",
        )
        return
    if _is_bool(expected):
        _require(_is_bool(actual) and actual is expected, label, f"{path} does not match")
        return
    _require(type(actual) is type(expected) and actual == expected, label, f"{path} does not match")


def _match_expected_artifacts(actual, expected, label):
    expected = _require_list(list(expected), label, "expected_artifacts")
    actual_by_key = {(row["target"], row["kind"]): row for row in actual}
    _require(
        len(expected) == len(actual_by_key),
        label,
        f"expected {len(expected)} selected artifacts but receipt has {len(actual_by_key)}",
    )
    seen = set()
    for index, item in enumerate(expected):
        item = _require_mapping(item, label, f"expected_artifacts[{index}]")
        target = _require_nonempty_str(item.get("target"), label, f"expected_artifacts[{index}].target")
        kind = _require_nonempty_str(item.get("kind"), label, f"expected_artifacts[{index}].kind")
        key = (target, kind)
        _require(key in actual_by_key, label, f"expected artifact ({kind}, {target}) was not selected")
        _require(key not in seen, label, f"duplicate expected artifact ({kind}, {target})")
        seen.add(key)
        row = actual_by_key[key]
        for field, value in item.items():
            _require(field in row, label, f"selected artifact ({kind}, {target}) has no {field}")
            _matches_subset(row[field], value, label, f"cargo_artifacts[{kind}/{target}].{field}")
    _require(len(seen) == len(actual_by_key), label, "expected_artifacts does not cover every selected artifact")


def _receipt_profile(payload):
    profile = payload.get("profile")
    if isinstance(profile, str) and profile:
        return profile
    features = payload.get("features")
    if isinstance(features, Mapping) and isinstance(features.get("profile"), str):
        return features["profile"]
    return None


def _apply_expectations(
    result,
    *,
    binary_path,
    receipt_path,
    receipt_sha256,
    expected_commit,
    expected_source_digest,
    expected_config_digest,
    expected_binary_sha256,
    expected_command,
    expected_profile,
    expected_toolchain,
    expected_artifacts,
    expected_batch_manifest,
    forbid_implicit_build,
):
    label = "build receipt"
    payload = result.payload
    if expected_commit is not None:
        _require(
            result.workspace_commit == _require_commit(expected_commit, label, "expected_commit"),
            label,
            "workspace_commit does not match expected_commit",
        )
    if expected_source_digest is not None:
        _require(
            result.source_inputs_sha256
            == _require_sha256(expected_source_digest, label, "expected_source_digest"),
            label,
            "source_inputs_sha256 does not match expected_source_digest",
        )
    if expected_config_digest is not None:
        expected_config_digest = _require_sha256(
            expected_config_digest, label, "expected_config_digest"
        )
        _require(result.config_digest is not None, label, "receipt has no config_digest")
        _require(
            result.config_digest == expected_config_digest,
            label,
            "config_digest does not match expected_config_digest",
        )
    if expected_binary_sha256 is not None:
        _require(
            result.binary_sha256
            == _require_sha256(expected_binary_sha256, label, "expected_binary_sha256"),
            label,
            "binary_sha256 does not match expected_binary_sha256",
        )
    if binary_path is not None:
        binary = Path(binary_path).resolve()
        _require(binary.is_file(), label, f"binary {binary} is missing")
        actual = sha256_file(binary)
        _require(
            actual == result.binary_sha256,
            label,
            f"binary digest {actual} does not match receipt {result.binary_sha256}",
        )
        result = ValidatedReceipt(
            schema=result.schema,
            payload=result.payload,
            binary_sha256=result.binary_sha256,
            workspace_commit=result.workspace_commit,
            source_inputs_sha256=result.source_inputs_sha256,
            artifacts=result.artifacts,
            batch=result.batch,
            toolchain=result.toolchain,
            config_digest=result.config_digest,
            receipt_path=result.receipt_path,
            binary_path=binary,
            receipt_sha256=result.receipt_sha256,
        )
    if result.batch is not None and result.binary_path is not None:
        _require(
            result.batch["binary"] == result.binary_path.name,
            label,
            "batch.binary does not match the supplied binary name",
        )
    if expected_command is not None:
        expected_command = _validate_command(
            expected_command, label, reject_clean=(result.schema == "v2")
        )
        _require(payload.get("command") == expected_command, label, "command does not match expected_command")
    if expected_profile is not None:
        actual_profile = _receipt_profile(payload)
        _require(
            actual_profile == _require_nonempty_str(expected_profile, label, "expected_profile"),
            label,
            "profile does not match expected_profile",
        )
    if expected_toolchain is not None:
        _require(result.toolchain is not None, label, "receipt has no toolchain metadata")
        _matches_subset(result.toolchain, expected_toolchain, label, "toolchain")
    if expected_artifacts is not None:
        _match_expected_artifacts(result.artifacts, expected_artifacts, label)
    if expected_batch_manifest is not None:
        _require(result.batch is not None, label, "receipt has no batch link")
        expected_manifest = Path(expected_batch_manifest).resolve()
        actual_manifest = Path(result.batch["manifest"]).resolve()
        _require(
            actual_manifest == expected_manifest,
            label,
            "batch.manifest does not match expected_batch_manifest",
        )
    if forbid_implicit_build and payload.get("implicit_build"):
        raise ReceiptError(f"{label}: implicit-build receipts are not acceptable here")
    if receipt_path is not None:
        receipt = Path(receipt_path).resolve()
        recorded_sha256 = (
            _require_sha256(receipt_sha256, label, "receipt_sha256")
            if receipt_sha256 is not None
            else sha256_file(receipt)
        )
        result = ValidatedReceipt(
            schema=result.schema,
            payload=result.payload,
            binary_sha256=result.binary_sha256,
            workspace_commit=result.workspace_commit,
            source_inputs_sha256=result.source_inputs_sha256,
            artifacts=result.artifacts,
            batch=result.batch,
            toolchain=result.toolchain,
            config_digest=result.config_digest,
            receipt_path=receipt,
            binary_path=result.binary_path,
            receipt_sha256=recorded_sha256,
        )
    return result


# -- file-backed source verification ------------------------------------------
def _verify_v2_source_files(result, source_root):
    label = "build receipt"
    entries, blobs = bound_input_inventory(source_root)
    recorded = result.payload.get("bound_input_inventory")
    _require(
        entries == recorded,
        label,
        "bound input inventory differs from the current source root",
    )
    current_summary = bound_inputs_summary(entries, blobs)
    _require(
        current_summary == result.payload.get("bound_inputs"),
        label,
        "bound_inputs summary differs from the current source root",
    )
    _require(
        _source_digest_from_blobs(source_root, blobs) == result.source_inputs_sha256,
        label,
        "source_inputs_sha256 differs from the current source root",
    )
    _require(
        hashlib.sha256(blobs["Cargo.lock"]).hexdigest() == result.payload.get("cargo_lock_sha256"),
        label,
        "cargo_lock_sha256 differs from the current Cargo.lock",
    )
    _require(
        config_digest(entries, blobs) == result.config_digest,
        label,
        "config_digest differs from the current config/toolchain/build-script inputs",
    )
    by_path = {entry["path"]: entry for entry in entries}
    for row in result.artifacts:
        entry = by_path.get(row["source"])
        _require(entry is not None and entry["present"], label, f"artifact source {row['source']} is not bound")
        _require(
            entry["sha256"] == row["source_sha256"],
            label,
            f"artifact source {row['source']} content changed",
        )


def _verify_v1_source_files(result, source_root):
    label = "build receipt"
    _require(
        source_digest(source_root) == result.source_inputs_sha256,
        label,
        "source_inputs_sha256 differs from the current source root",
    )
    payload = result.payload
    if "cargo_lock_sha256" in payload:
        _require(
            sha256_file(Path(source_root) / "Cargo.lock") == payload["cargo_lock_sha256"],
            label,
            "cargo_lock_sha256 differs from the current Cargo.lock",
        )
    if "bound_input_inventory" in payload:
        for entry in payload["bound_input_inventory"]:
            path = Path(source_root) / entry["path"]
            _require(_is_within(path, source_root), label, f"bound input {entry['path']} escapes source root")
            exists = path.is_file()
            _require(
                exists is entry["present"],
                label,
                f"bound input {entry['path']} presence changed",
            )
            if exists:
                _require(
                    sha256_file(path) == entry["sha256"],
                    label,
                    f"bound input {entry['path']} content changed",
                )
        if "config_digest" in payload:
            _require(
                config_digest_from_entries(payload["bound_input_inventory"]) == payload["config_digest"],
                label,
                "config_digest does not match the current bound inventory entries",
            )


# -- public reader ------------------------------------------------------------
def validate_receipt(
    receipt,
    *,
    source_root=None,
    receipt_path=None,
    receipt_sha256=None,
    binary_path=None,
    expected_commit=None,
    expected_source_digest=None,
    expected_config_digest=None,
    expected_binary_sha256=None,
    expected_command=None,
    expected_profile=None,
    expected_toolchain=None,
    expected_artifacts=None,
    expected_batch_manifest=None,
    forbid_implicit_build=False,
    verify_source_files=True,
):
    """Validate a v1 or v2 receipt without invoking Cargo, rustc or any builder.

    Required receipt fields are checked by schema.  Caller-provided
    ``expected_*`` values are trust anchors: when supplied they must match
    exactly (nested mappings for ``expected_toolchain`` and
    ``expected_artifacts`` match as subsets of the recorded row).  When
    ``source_root`` is supplied and ``verify_source_files`` is true, the
    inventory, source digest, lockfile, config digest and artifact source
    hashes are recomputed from that tree.  When ``binary_path`` is supplied its
    bytes are hashed and compared with ``binary_sha256``.  When
    ``receipt_sha256`` is supplied it is the hash of the bytes the caller
    already read, so the reported evidence hash does not depend on a later
    re-read.  Without those anchors an unsigned receipt is shape-validated
    only; it is not proof.
    """
    if not isinstance(receipt, Mapping):
        raise ReceiptError("build receipt: receipt must be an object")
    label = "build receipt"
    if "receipt_schema" in receipt:
        if receipt.get("receipt_schema") != RECEIPT_SCHEMA_V2:
            raise ReceiptError(
                f"{label}: unknown receipt_schema {receipt.get('receipt_schema')!r}"
            )
        schema = "v2"
    else:
        schema = "v1"
    src_root = Path(source_root).resolve() if source_root is not None else None
    bin_path = Path(binary_path).resolve() if binary_path is not None else None
    if schema == "v2":
        result = _validate_v2_payload(receipt, label, binary_path=bin_path)
    else:
        result = _validate_v1_payload(receipt, label)
    result = _apply_expectations(
        result,
        binary_path=bin_path,
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha256,
        expected_commit=expected_commit,
        expected_source_digest=expected_source_digest,
        expected_config_digest=expected_config_digest,
        expected_binary_sha256=expected_binary_sha256,
        expected_command=expected_command,
        expected_profile=expected_profile,
        expected_toolchain=expected_toolchain,
        expected_artifacts=expected_artifacts,
        expected_batch_manifest=expected_batch_manifest,
        forbid_implicit_build=forbid_implicit_build,
    )
    if src_root is not None and verify_source_files:
        if schema == "v2":
            _verify_v2_source_files(result, src_root)
        else:
            _verify_v1_source_files(result, src_root)
    return result


def load_receipt(path, *, source_root=None, binary_path=None, infer_binary=True, **kwargs):
    """Read and validate one receipt JSON file.

    When ``binary_path`` is omitted, a sibling ``<name>`` next to a
    ``<name>.build.json`` receipt is used only if it already exists.  Missing
    binaries are not built or inferred from a compiler.  The reported receipt
    hash is taken from the exact bytes that were parsed.
    """
    receipt_file = Path(path)
    _require(receipt_file.is_file(), "build receipt", f"missing file {receipt_file}")
    raw = receipt_file.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f"build receipt: not JSON: {error}") from error
    if not isinstance(payload, Mapping):
        raise ReceiptError("build receipt: receipt must be an object")
    if binary_path is None and infer_binary and receipt_file.name.endswith(".build.json"):
        candidate = Path(str(receipt_file)[: -len(".build.json")])
        if candidate.is_file():
            binary_path = candidate
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    kwargs.setdefault("receipt_sha256", raw_sha256)
    return validate_receipt(
        payload,
        source_root=source_root,
        receipt_path=receipt_file,
        binary_path=binary_path,
        **kwargs,
    )


__all__ = [
    "ARTIFACT_KINDS",
    "BATCH_KIND",
    "BOUND_INPUTS_DIGEST_ALGORITHM",
    "BOUND_ROLES",
    "BUILD_JOBS_VARIABLE",
    "CARGO_CONFIG_FILES",
    "COMPILED_ASSETS",
    "CONFIG_ROLES",
    "EXECUTABLE_KINDS",
    "FIXED_CANDIDATES",
    "MANIFEST_INPUTS",
    "PROFILE_FIELDS",
    "RECEIPT_SCHEMA_V2",
    "ReceiptError",
    "SOURCE_DIRS",
    "TEST_SUPPORT_DIRS",
    "TOOLCHAIN_PINS",
    "V2_BANNED_FIELDS",
    "ValidatedReceipt",
    "atomic_write_json",
    "bound_input_inventory",
    "bound_inputs_digest",
    "bound_inputs_digest_from_entries",
    "bound_inputs_summary",
    "capture_bound_inputs",
    "cargo_artifact_record",
    "config_digest",
    "config_digest_from_entries",
    "config_path_keys",
    "git_state",
    "is_rejected_environment_name",
    "load_receipt",
    "make_receipt_v2",
    "normalize_build_environment",
    "probe_toolchain",
    "reject_external_cargo_config",
    "reject_passthrough_environment",
    "require_build_finished",
    "require_clean_git_state",
    "require_in_repository_config",
    "sha256_bytes",
    "sha256_file",
    "source_digest",
    "source_digest_from_entries",
    "validate_receipt",
]
