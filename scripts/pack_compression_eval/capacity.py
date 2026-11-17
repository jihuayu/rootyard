"""Bounded harness-only capacity envelope for the Issue #178 live fixture.

The live 3-way concurrent-push fixture must admit its own configured workload.
The gateway defaults are intentionally unchanged: the request ceiling stays at
128 MiB and the production inflight default stays at 256 MiB.  This helper
derives a bounded *test* envelope from the canonical fixture shape (3 branches,
128 MiB request ceiling) and injects only the two admission environment values
into a private copy of the child environment.

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
MAX_CONCURRENT_BRANCHES: Final[int] = 3
MAX_INFLIGHT_BYTES: Final[int] = 16 * 1024 * 1024 * 1024

REQUEST_ENV: Final[str] = "ROOTYARD_MAX_REQUEST_BYTES"
INFLIGHT_ENV: Final[str] = "ROOTYARD_MAX_INFLIGHT_BYTES"

CAPACITY_FIELDS: Final[tuple[str, ...]] = (
    "concurrent_branches",
    "request_ceiling_bytes",
    "inflight_bytes",
)

_LIMITS: Final[dict[str, int]] = {
    "concurrent_branches": MAX_CONCURRENT_BRANCHES,
    "request_ceiling_bytes": REQUEST_CEILING_BYTES,
    "inflight_bytes": MAX_INFLIGHT_BYTES,
}


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
    inflight = branches * ceiling
    if inflight > MAX_INFLIGHT_BYTES:
        raise ValueError("derived inflight budget exceeds the bounded maximum")
    if inflight < ceiling:
        raise ValueError("derived inflight budget is smaller than one request")
    return {
        "concurrent_branches": branches,
        "request_ceiling_bytes": ceiling,
        "inflight_bytes": inflight,
    }


def build_server_env(
    base_env: Mapping[str, str],
    capacity: Mapping[str, int] | None = None,
) -> dict[str, str]:
    """Copy ``base_env`` and inject the checked harness admission values.

    ``base_env`` is never modified.  With ``capacity=None`` the canonical
    3 x 128 MiB envelope is used.  A supplied envelope must contain exactly the
    fixed fields and its inflight value must equal the checked derivation.
    """
    if capacity is None:
        envelope = derive_capacity_envelope()
    else:
        if not isinstance(capacity, Mapping) or set(capacity) != set(CAPACITY_FIELDS):
            raise ValueError("capacity envelope must contain exactly the fixed fields")
        envelope = derive_capacity_envelope(
            concurrent_branches=capacity["concurrent_branches"],
            request_ceiling_bytes=capacity["request_ceiling_bytes"],
        )
        if envelope["inflight_bytes"] != capacity["inflight_bytes"]:
            raise ValueError("capacity envelope inflight budget does not match its checked derivation")
    env = dict(base_env)
    env[REQUEST_ENV] = str(envelope["request_ceiling_bytes"])
    env[INFLIGHT_ENV] = str(envelope["inflight_bytes"])
    return env


def sanitize_capacity(value: Any) -> dict[str, int | None]:
    """Project one capacity mapping into the fixed numeric report shape.

    Invalid, injected, inconsistent, or overprovisioned values fail closed:
    every field becomes ``None`` so a failure record never advertises
    unbounded or unvalidated capacity.  The accepted envelope must satisfy
    ``inflight_bytes == concurrent_branches * request_ceiling_bytes`` exactly,
    matching ``build_server_env``.
    """
    if not isinstance(value, Mapping):
        return {field: None for field in CAPACITY_FIELDS}
    if set(value.keys()) - set(CAPACITY_FIELDS):
        return {field: None for field in CAPACITY_FIELDS}
    projected: dict[str, int | None] = {}
    for field in CAPACITY_FIELDS:
        raw = value.get(field)
        limit = _LIMITS[field]
        if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0 or raw > limit:
            projected[field] = None
        else:
            projected[field] = raw
    if any(item is None for item in projected.values()):
        return {field: None for field in CAPACITY_FIELDS}
    branches = projected["concurrent_branches"]
    ceiling = projected["request_ceiling_bytes"]
    inflight = projected["inflight_bytes"]
    if branches is None or ceiling is None or inflight is None or inflight != branches * ceiling:
        return {field: None for field in CAPACITY_FIELDS}
    return projected
