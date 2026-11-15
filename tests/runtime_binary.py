#!/usr/bin/env python3
"""Select and bind the prebuilt main ``rootyard`` binary for runtime tests.

Selection is explicit-first and deterministic:

1. ``ROOTYARD_BIN`` -- the canonical CI export for the qualified executable;
2. ``ROOTYARD_TEST_BINARY`` -- legacy explicit choice;
3. ``ROOTYARD_BINARY`` -- older legacy explicit choice;
4. only when none of the three is present, the legacy local prebuilt artifact
   at ``$CARGO_TARGET_DIR/debug/rootyard`` or ``target/debug/rootyard``.

Every explicit variable that is present is part of the selection.  Present
variables must resolve to the same executable; two different explicit paths are
a hard conflict rather than an implicit winner.  A variable that is present but
empty, or points at a missing/non-executable/stale artifact, is a hard failure.
In particular an explicit choice never falls back to the local target and never
falls back to Cargo, rustc, rustup, a builder or any compiler.

A selected artifact is bound through the existing pure
:mod:`source_bound_binary` reader.  That preserves its adjacent receipt hash,
binary SHA-256, source/config/toolchain and expected-source checks.  This module
never rewrites a receipt, never probes a toolchain and never starts a build.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
_TEST_DIR = Path(__file__).resolve().parent
if str(_TEST_DIR) not in sys.path:
    sys.path.insert(0, str(_TEST_DIR))
import source_bound_binary  # noqa: E402

CANONICAL_VARIABLE = "ROOTYARD_BIN"
LEGACY_VARIABLES = ("ROOTYARD_TEST_BINARY", "ROOTYARD_BINARY")
EXPLICIT_VARIABLES = (CANONICAL_VARIABLE, *LEGACY_VARIABLES)
DEFAULT_INSTRUCTION = (
    "run the explicit native build preparation step and set ROOTYARD_BIN "
    "(the legacy ROOTYARD_TEST_BINARY/ROOTYARD_BINARY names are also accepted) "
    "to a source-bound prebuilt rootyard executable; this test never invokes "
    "Cargo, rustc, a builder or scripts/build_native.py"
)


class RuntimeBinarySelectionError(RuntimeError):
    """A runtime artifact was not explicitly selected or failed binding."""


def _resolved(raw, root):
    path = Path(str(raw).strip()).expanduser()
    return (path if path.is_absolute() else Path(root) / path).resolve()


def _explicit_choice(environ, root):
    """Return ``(variable, path)`` or ``None``; conflicts fail closed."""
    chosen = []
    for name in EXPLICIT_VARIABLES:
        if name not in environ:
            continue
        raw = environ.get(name)
        if raw is None or not str(raw).strip():
            raise RuntimeBinarySelectionError(
                f"{name} is set but empty; an explicit runtime binary choice must "
                "name a prebuilt executable and is never silently replaced by a "
                "local target or a compiler")
        chosen.append((name, _resolved(raw, root)))
    if not chosen:
        return None
    name, path = chosen[0]
    if any(other != path for _, other in chosen[1:]):
        rendered = ", ".join(f"{variable}={candidate}" for variable, candidate in chosen)
        raise RuntimeBinarySelectionError(
            "conflicting explicit rootyard binary selections: " + rendered +
            "; set only one of " + ", ".join(EXPLICIT_VARIABLES) +
            " or point them at the same executable")
    return name, path


def legacy_target_binary(environ, root=ROOT):
    """Return the historical local prebuilt path when no explicit choice exists."""
    raw_target = Path(str(environ.get("CARGO_TARGET_DIR") or (Path(root) / "target"))).expanduser()
    target_dir = raw_target if raw_target.is_absolute() else Path(root) / raw_target
    return (target_dir / "debug" / "rootyard").resolve()


def select_runtime_binary_path(environ=None, *, root=ROOT, default_binary=None,
                               instruction=None):
    """Select and validate only the executable path; this does not bind it.

    ``default_binary`` overrides the historical target fallback for callers that
    already own a documented default.  It is still used only when no explicit
    variable is present.
    """
    environ = os.environ if environ is None else environ
    root = Path(root)
    instruction = DEFAULT_INSTRUCTION if instruction is None else instruction
    explicit = _explicit_choice(environ, root)
    if explicit is None:
        if default_binary is None:
            binary = legacy_target_binary(environ, root)
        else:
            candidate = Path(default_binary).expanduser()
            binary = (candidate if candidate.is_absolute() else root / candidate).resolve()
        source = "legacy local prebuilt target"
    else:
        _, binary = explicit
        source = "explicit " + explicit[0]
    if not (binary.is_file() and os.access(binary, os.X_OK)):
        raise RuntimeBinarySelectionError(
            f"prebuilt rootyard binary is required at {binary} ({source}); "
            f"no local build or compiler fallback exists. Please {instruction}")
    return binary


def bind_runtime_binary(binary, environ=None, *, binder=None, instruction=None):
    """Bind ``binary`` through the existing pure receipt reader, or fail closed."""
    environ = os.environ if environ is None else environ
    instruction = DEFAULT_INSTRUCTION if instruction is None else instruction
    binary = Path(binary).resolve()
    binder = source_bound_binary.bind if binder is None else binder
    try:
        binding = binder(binary, environ=environ)
    except Exception as error:
        raise RuntimeBinarySelectionError(
            f"prebuilt rootyard binary {binary} is not bound to this checkout "
            f"(source, contents or build receipt rejected: {error}). "
            f"Please {instruction}; provenance is never rewritten by acceptance."
        ) from error
    return binding


def select_runtime_binary(environ=None, *, root=ROOT, default_binary=None,
                          binder=None, instruction=None):
    """Return ``(path, binding)`` for the selected source-bound prebuilt binary."""
    environ = os.environ if environ is None else environ
    path = select_runtime_binary_path(
        environ, root=root, default_binary=default_binary, instruction=instruction)
    binding = bind_runtime_binary(path, environ, binder=binder, instruction=instruction)
    return path, binding
