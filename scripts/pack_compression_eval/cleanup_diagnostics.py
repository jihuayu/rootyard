"""Independent owned-resource cleanup outcomes for the live benchmark (Refs #178).

Every cleanup step is attempted even when an earlier step raises.  Only fixed
status IDs, booleans and static failure classes are retained; exception text,
argv, paths and command output are never serialized.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import shutil
import subprocess
from pathlib import Path
from typing import Any

CLEANUP_STATUSES = ("ok", "failed", "not_needed", "skipped")
CLEANUP_FAILURE_CLASSES = (
    "server_stop_timeout",
    "server_stop_os_error",
    "server_stop_error",
    "proxy_stop_timeout",
    "proxy_stop_os_error",
    "proxy_stop_error",
    "sampler_stop_timeout",
    "sampler_stop_os_error",
    "sampler_stop_error",
    "psql_timeout",
    "psql_spawn_error",
    "psql_nonzero",
    "psql_error",
    "scratch_timeout",
    "scratch_os_error",
    "scratch_remaining",
    "scratch_error",
)
_STEP_SUCCESS_KEYS = {
    "server": "reaped",
    "proxy": "stopped",
    "sampler": "stopped",
    "psql": "completed",
    "scratch": "removed",
}
_FAILURE_PREFIXES = {
    "server": "server_stop",
    "proxy": "proxy_stop",
    "sampler": "sampler_stop",
    "psql": "psql",
    "scratch": "scratch",
}


def _status(value: Any, default: str = "not_needed") -> str:
    return value if isinstance(value, str) and value in CLEANUP_STATUSES else default


def _bool(value: Any) -> bool:
    return value is True


def sanitize_cleanup(cleanup: Any) -> dict[str, Any]:
    """Project a cleanup outcome onto the fixed cleanup schema."""
    source = cleanup if isinstance(cleanup, Mapping) else {}
    raw_failures = source.get("failures")
    failures = (
        sorted({item for item in raw_failures if isinstance(item, str) and item in CLEANUP_FAILURE_CLASSES})
        if isinstance(raw_failures, (list, tuple, set, frozenset))
        else []
    )
    result: dict[str, Any] = {
        "attempted": _bool(source.get("attempted")),
        "all_attempted": _bool(source.get("all_attempted")),
        "failures": failures,
    }
    for step, success_key in _STEP_SUCCESS_KEYS.items():
        raw_step = source.get(step)
        raw = raw_step if isinstance(raw_step, Mapping) else {}
        status = _status(raw.get("status"))
        result[step] = {
            "status": status,
            "attempted": _bool(raw.get("attempted")),
            success_key: _bool(raw.get(success_key)) and status == "ok",
        }
    return result


def _attempt_step(
    call: Callable[[], Any] | None,
    *,
    name: str,
    success_key: str,
) -> tuple[dict[str, Any], str | None]:
    record: dict[str, Any] = {
        "status": "not_needed",
        "attempted": False,
        success_key: False,
    }
    if call is None:
        return record, None
    record.update(status="failed", attempted=True)
    prefix = _FAILURE_PREFIXES[name]
    try:
        result = call()
    except subprocess.TimeoutExpired:
        return record, f"{prefix}_timeout"
    except OSError:
        return record, "psql_spawn_error" if name == "psql" else f"{prefix}_os_error"
    except Exception:  # noqa: BLE001 - cleanup failures are classified, never serialized
        return record, f"{prefix}_error"
    if name == "psql" and getattr(result, "returncode", 0) != 0:
        return record, "psql_nonzero"
    if name == "scratch" and result is False:
        return record, "scratch_remaining"
    record.update(status="ok", **{success_key: True})
    return record, None


def remove_tree_checked(path: str | Path) -> bool:
    """Best-effort owned tree removal with a finite removed/not-removed result."""
    target = Path(path)
    shutil.rmtree(target, ignore_errors=True)
    return not target.exists()


def run_cleanup_steps(
    *,
    stop_server: Callable[[], Any] | None = None,
    stop_proxy: Callable[[], Any] | None = None,
    stop_sampler: Callable[[], Any] | None = None,
    drop_schema: Callable[[], Any] | None = None,
    remove_scratch: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Attempt every supplied cleanup step independently and retain finite outcomes."""
    failures: list[str] = []
    server, failure = _attempt_step(stop_server, name="server", success_key="reaped")
    if failure:
        failures.append(failure)
    proxy, failure = _attempt_step(stop_proxy, name="proxy", success_key="stopped")
    if failure:
        failures.append(failure)
    sampler, failure = _attempt_step(stop_sampler, name="sampler", success_key="stopped")
    if failure:
        failures.append(failure)
    psql, failure = _attempt_step(drop_schema, name="psql", success_key="completed")
    if failure:
        failures.append(failure)
    scratch, failure = _attempt_step(remove_scratch, name="scratch", success_key="removed")
    if failure:
        failures.append(failure)
    steps = (server, proxy, sampler, psql, scratch)
    required = [step for step in steps if step["status"] != "not_needed"]
    attempted = [step for step in required if step["attempted"]]
    return sanitize_cleanup(
        {
            "attempted": bool(attempted),
            "all_attempted": len(attempted) == len(required),
            "failures": failures,
            "server": server,
            "proxy": proxy,
            "sampler": sampler,
            "psql": psql,
            "scratch": scratch,
        }
    )


__all__ = [
    "CLEANUP_FAILURE_CLASSES",
    "CLEANUP_STATUSES",
    "remove_tree_checked",
    "run_cleanup_steps",
    "sanitize_cleanup",
]
