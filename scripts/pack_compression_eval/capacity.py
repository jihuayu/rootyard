"""Bounded harness-only capacity envelope for the Issue #178 live fixture.

The live 3-way concurrent-push fixture must admit its own configured workload.
The gateway defaults are intentionally unchanged: the request ceiling stays at
128 MiB and the production inflight default stays at 256 MiB.  This helper
derives a bounded *test* envelope from the canonical fixture shape (3 branches
at 128 MiB each plus one sequential Browse worker at 32 MiB peak) and injects
the two admission environment values into a private copy of the child environment.

The helper is deliberately strict:

* the branch count is 1..=3 (the fixture's exact oracle count is 3);
* the request ceiling is 1..=128 MiB (the existing production default, never
  raised by the harness);
* the derived inflight budget is checked against the gateway's documented
  16 GiB upper bound and must cover the full configured workload;
* invalid, boolean, non-integer, or out-of-range values raise ``ValueError``;
* the base mapping (normally ``os.environ``) is never mutated.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

CONCURRENT_BRANCHES: Final[int] = 3
REQUEST_CEILING_BYTES: Final[int] = 128 * 1024 * 1024
BROWSE_PEAK_LEASE_BYTES: Final[int] = 32 * 1024 * 1024
MAX_CONCURRENT_BRANCHES: Final[int] = 3
MAX_INFLIGHT_BYTES: Final[int] = 16 * 1024 * 1024 * 1024

REQUEST_ENV: Final[str] = "ROOTYARD_MAX_REQUEST_BYTES"
INFLIGHT_ENV: Final[str] = "ROOTYARD_MAX_INFLIGHT_BYTES"

CAPACITY_FIELDS: Final[tuple[str, ...]] = (
    "concurrent_branches",
    "request_ceiling_bytes",
    "inflight_bytes",
)


def _checked_int(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} is outside its bounded range")
    return value


def derive_capacity_envelope(
    *,
    concurrent_branches: Any = CONCURRENT_BRANCHES,
    request_ceiling_bytes: Any = REQUEST_CEILING_BYTES,
) -> dict[str, int]:
    """Return the exact checked fixture envelope for the live concurrent phase."""
    branches = _checked_int(
        concurrent_branches,
        name="concurrent_branches",
        minimum=1,
        maximum=MAX_CONCURRENT_BRANCHES,
    )
    ceiling = _checked_int(
        request_ceiling_bytes,
        name="request_ceiling_bytes",
        minimum=1,
        maximum=REQUEST_CEILING_BYTES,
    )
    # Browse reserves min(MAX_MEMORY_BYTES, inflight) from the shared pool.
    # A positive push budget requires inflight to exceed that memory cap.
    inflight = branches * ceiling + BROWSE_PEAK_LEASE_BYTES
    if inflight > MAX_INFLIGHT_BYTES:
        raise ValueError("derived inflight budget exceeds the bounded maximum")
    if inflight < ceiling:
        raise ValueError("derived inflight budget is smaller than one request")
    return {
        "concurrent_branches": branches,
        "request_ceiling_bytes": ceiling,
        "inflight_bytes": inflight,
    }


def _validate_capacity(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != set(CAPACITY_FIELDS):
        raise ValueError("capacity envelope must contain exactly the fixed fields")
    envelope = derive_capacity_envelope(
        concurrent_branches=value["concurrent_branches"],
        request_ceiling_bytes=value["request_ceiling_bytes"],
    )
    inflight = _checked_int(
        value["inflight_bytes"], name="inflight_bytes", minimum=1, maximum=MAX_INFLIGHT_BYTES,
    )
    if inflight != envelope["inflight_bytes"]:
        raise ValueError("capacity envelope inflight budget does not match its checked derivation")
    return envelope


def build_server_env(
    base_env: Mapping[str, str],
    capacity: Mapping[str, int] | None = None,
) -> dict[str, str]:
    """Copy ``base_env`` and inject the checked harness admission values.

    ``base_env`` is never modified. With ``capacity=None`` the canonical 416 MiB
    envelope is used. A supplied envelope must contain exactly the fixed fields
    and its inflight value must equal the checked derivation.
    """
    if capacity is None:
        envelope = derive_capacity_envelope()
    else:
        envelope = _validate_capacity(capacity)
    env = dict(base_env)
    env[REQUEST_ENV] = str(envelope["request_ceiling_bytes"])
    env[INFLIGHT_ENV] = str(envelope["inflight_bytes"])
    return env


def sanitize_capacity(value: Any) -> dict[str, int | None]:
    """Project one capacity mapping into the fixed numeric report shape.

    Invalid values yield ``None`` for every field. The accepted envelope must
    match the exact derivation used by ``build_server_env``.
    """
    try:
        return dict(_validate_capacity(value))
    except ValueError:
        return {field: None for field in CAPACITY_FIELDS}
