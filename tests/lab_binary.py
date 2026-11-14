"""Select explicitly prepared, source-bound lab binaries for Python tests.

The lab harnesses must never build Rust artifacts.  A native execution therefore
uses exactly one of these inputs:

* the caller's explicit path (``WorkspaceHarness(binary_path=...)``);
* an absolute ``ROOTYARD_*_LAB_BIN``/``ROOTYARD_VFS_MOUNT_BIN`` environment
  value exported from the validated v2 batch manifest; or
* a historical local prebuilt path, considered only when the environment value
  is absent, so existing local runs keep their fallback without ever compiling.

Selection is literal: this module never searches ``PATH`` by binary basename,
never derives an artifact from Cargo metadata or ``target/debug`` layout, and
never follows a symlink to guess the canonical file.  The chosen file must be a
regular executable and, unless ``bind=False`` is used for a pure selector test,
must pass the existing :mod:`source_bound_binary` receipt/hash/source binding.

No Cargo, rustc, rustup, builder, installer, clean, database or network probe is
invoked here.  Missing or stale artifacts fail closed with an explicit operator
preparation instruction instead of falling back to a build.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import sys

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import source_bound_binary  # noqa: E402  (shared pure v1/v2 receipt reader)


class LabBinaryError(RuntimeError):
    """A lab executable was absent, non-canonical, or not source-bound."""


@dataclass(frozen=True)
class LabBinary:
    """One selected lab executable and, when requested, its binding evidence."""

    path: Path
    env_name: str
    from_environment: bool
    binding: dict | None = None


def preparation_instruction(env_name: str) -> str:
    """Operator-facing instruction used verbatim by every fail-closed path."""
    return (
        "run the explicit native build preparation step as the ROOT operator "
        "(scripts/build_native_batch.py with an immutable artifact store, then "
        "scripts/export_native_artifacts.py), keep the adjacent .build.json "
        f"receipt, and export {env_name}=/absolute/path/to/the/canonical/binary. "
        "This acceptance test never invokes Cargo, rustc, build_native.py, an "
        "installer, a build or a clean."
    )


def _fail(env_name: str, purpose: str, detail: str) -> LabBinaryError:
    return LabBinaryError(
        f"{purpose}: {detail}. No local build fallback exists. Please "
        + preparation_instruction(env_name)
    )


def _require_no_symlink_components(path: Path, env_name: str, purpose: str) -> None:
    """Reject an environment path that reaches the artifact through an alias.

    ``resolve()`` equality is intentionally not the only check: walking each
    existing component with ``lstat`` also catches a parent-directory symlink
    on filesystems whose canonical spelling differs (notably macOS /var).
    """
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            # A missing suffix is handled by the regular-executable check; it
            # cannot hide an existing symlink component below this point.
            return
        except OSError as error:
            raise _fail(
                env_name,
                purpose,
                f"{env_name} path component {current} cannot be inspected: {error}",
            ) from error
        if stat.S_ISLNK(info.st_mode):
            raise _fail(
                env_name,
                purpose,
                f"{env_name} must name a canonical path with no symlink "
                f"components or parent aliases; {current} is a symlink",
            )


def _environment_path(raw, env_name: str, purpose: str) -> Path:
    """Parse a present environment value; never treat blank text as absent."""
    if raw is None or not str(raw).strip():
        raise _fail(
            env_name,
            purpose,
            f"{env_name} is present but empty or whitespace-only; refusing to "
            "silently select the legacy fallback. Unset the variable to use the "
            "legacy prebuilt or set it to an absolute canonical artifact",
        )
    path = _absolute_environment_path(str(raw).strip(), env_name, purpose)
    _require_no_symlink_components(path, env_name, purpose)
    return path


def _legacy_path(legacy) -> Path | None:
    if legacy is None:
        return None
    path = Path(os.fspath(legacy)).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    return path


def _absolute_environment_path(raw: str, env_name: str, purpose: str) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise _fail(
            env_name,
            purpose,
            f"{env_name} must name an absolute canonical artifact, got {raw!r}; "
            "PATH/basename/symlink-target guessing is not accepted",
        )
    if ".." in path.parts:
        raise _fail(
            env_name,
            purpose,
            f"{env_name} must not traverse parent directories, got {raw!r}",
        )
    return path


def _explicit_path(raw, env_name: str, purpose: str) -> Path:
    path = Path(os.fspath(raw)).expanduser()
    if not path.is_absolute():
        # Preserve the historical --binary/binary_path behaviour: a relative
        # caller-supplied path is relative to the invoking process, not to PATH.
        path = (Path.cwd() / path).resolve()
    return path


def _canonical_selected_path(path: Path, env_name: str, purpose: str) -> Path:
    """Return the bound canonical file for explicit/legacy caller selections.

    Explicit caller paths and the documented legacy fallback keep their
    existing meaning, but execution and receipt lookup use the resolved target
    rather than a mutable alias spelling.
    """
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise _fail(
            env_name,
            purpose,
            f"selected lab binary path {path} cannot be canonicalized: {error}",
        ) from error


def _legacy_candidate_present(legacy_path: Path, env_name: str, purpose: str) -> bool:
    """True when a legacy candidate exists; dangling aliases are malformed."""
    try:
        legacy_path.lstat()
    except FileNotFoundError:
        # The final path is absent.  Walk existing parents only to distinguish
        # a genuinely absent candidate from a dangling symlink component.
        current = legacy_path.parent
        while current != current.parent:
            try:
                current.lstat()
            except FileNotFoundError:
                current = current.parent
                continue
            except OSError as error:
                raise _fail(
                    env_name,
                    purpose,
                    f"legacy prebuilt path component {current} cannot be inspected: {error}",
                ) from error
            if current.is_symlink() and not current.exists():
                raise _fail(
                    env_name,
                    purpose,
                    f"legacy prebuilt path contains a dangling symlink component: {current}",
                )
            break
        return False
    except OSError as error:
        raise _fail(
            env_name,
            purpose,
            f"legacy prebuilt path {legacy_path} cannot be inspected: {error}",
        ) from error
    if legacy_path.is_symlink() and not legacy_path.exists():
        raise _fail(
            env_name,
            purpose,
            f"legacy prebuilt path is a dangling symlink: {legacy_path}",
        )
    return True


def _selected_path(
    env_name: str,
    *,
    legacy,
    explicit,
    environ: dict,
    purpose: str,
) -> tuple[Path, bool]:
    if explicit is not None:
        return _explicit_path(explicit, env_name, purpose), False
    if env_name in environ:
        return _environment_path(environ[env_name], env_name, purpose), True
    legacy_path = _legacy_path(legacy)
    if legacy_path is not None:
        return legacy_path, False
    raise _fail(
        env_name,
        purpose,
        f"no prebuilt lab binary is selected; set {env_name} to the immutable "
        "canonical artifact (the legacy local prebuilt fallback is absent)",
    )


def _require_regular_executable(path: Path, env_name: str, purpose: str) -> None:
    if path.is_symlink():
        raise _fail(
            env_name,
            purpose,
            f"prebuilt lab binary {path} is a symlink; point the variable at the "
            "immutable canonical regular file instead of a mutable alias",
        )
    if not path.is_file() or not os.access(path, os.X_OK):
        raise _fail(
            env_name,
            purpose,
            f"prebuilt lab binary is missing or not executable at {path}",
        )


def resolve_lab_binary(
    env_name: str,
    *,
    legacy=None,
    explicit=None,
    purpose: str = "lab runtime",
    environ=None,
    expected_commit=None,
    binder=None,
    bind: bool = True,
) -> LabBinary:
    """Return the one selected lab binary, source-bound by default.

    ``explicit`` (a caller-supplied ``binary_path``/``--binary``) always wins.
    Otherwise a present environment key must contain a nonempty absolute path;
    only an absent key permits ``legacy``.  A present-but-empty or whitespace
    value is a hard failure before any legacy path or binder work, as are
    missing, relative, symlinked or stale artifacts; there is no artifact
    fallback after a configured environment failure.
    """
    environ = dict(os.environ if environ is None else environ)
    path, from_environment = _selected_path(
        env_name,
        legacy=legacy,
        explicit=explicit,
        environ=environ,
        purpose=purpose,
    )
    if not from_environment:
        path = _canonical_selected_path(path, env_name, purpose)
    _require_regular_executable(path, env_name, purpose)
    binding = None
    if bind:
        selected_binder = source_bound_binary.bind if binder is None else binder
        try:
            binding = selected_binder(
                path,
                expected_commit=expected_commit,
                environ=environ,
            )
        except LabBinaryError:
            raise
        except Exception as error:  # receipt/hash/stale/source rejection is fatal
            raise _fail(
                env_name,
                purpose,
                f"prebuilt lab binary {path} is not source-bound "
                f"(missing, stale, hash-mismatched or rejected receipt: {error})",
            ) from error
    return LabBinary(
        path=path,
        env_name=env_name,
        from_environment=from_environment,
        binding=binding,
    )


def resolve_optional_lab_binary(
    env_name: str,
    *,
    legacy=None,
    explicit=None,
    purpose: str = "lab runtime",
    environ=None,
    expected_commit=None,
    binder=None,
    bind: bool = True,
) -> LabBinary | None:
    """Like :func:`resolve_lab_binary`, but return ``None`` when nothing exists.

    This is only for tests that also contain static assertions.  An explicitly
    configured environment value, or a present legacy prebuilt, is still
    validated and source-bound; it is never silently ignored.
    """
    environ = dict(os.environ if environ is None else environ)
    if explicit is not None or env_name in environ:
        return resolve_lab_binary(
            env_name,
            legacy=legacy,
            explicit=explicit,
            purpose=purpose,
            environ=environ,
            expected_commit=expected_commit,
            binder=binder,
            bind=bind,
        )
    legacy_path = _legacy_path(legacy)
    if legacy_path is None or not _legacy_candidate_present(legacy_path, env_name, purpose):
        return None
    return resolve_lab_binary(
        env_name,
        legacy=legacy,
        purpose=purpose,
        environ=environ,
        expected_commit=expected_commit,
        binder=binder,
        bind=bind,
    )
