"""Fully synchronous cleanup regressions for metered tier boundaries."""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from rubicon_workload.runner import (  # noqa: E402
    FleetCleanupError,
    WorkloadConfig,
    _run_tier,
)
from rubicon_workload.workloads import MeterQuiescenceTimeout  # noqa: E402


class _FakeClock:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FakeProc:
    def __init__(self, pid: int) -> None:
        self.pid = pid


class _FakePath:
    def __init__(self, name: str = "tier") -> None:
        self.name = name
        self.mkdir_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def __truediv__(self, other: object) -> "_FakePath":
        return _FakePath(f"{self.name}/{other}")

    def mkdir(self, *args: object, **kwargs: object) -> None:
        self.mkdir_calls.append((args, kwargs))


class _FakeFleet(list):
    def __init__(self, name: str, pid: int) -> None:
        self.name = name
        super().__init__([(_FakeProc(pid), f"http://127.0.0.1:{pid}", _FakePath(f"scratch-{name}"), None)])


class _FakeSampler:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.stop_calls = 0
        self.stop_error: BaseException | None = None
        self.sample_calls = 0
        self.set_targets_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.max_rss_kib = 0
        self.max_hwm_kib = 0
        self.max_temp_disk_bytes = 0
        self.max_server_scratch_bytes = 0
        self.max_client_worktree_bytes = 0
        self.max_pg_active = 0
        self.max_pg_lock_waiters = 0
        self.errors: list[str] = []
        self.time_series: list[dict[str, object]] = []

    def set_targets(self, *args: object, **kwargs: object) -> None:
        self.set_targets_calls.append((args, kwargs))

    def start(self) -> None:
        return None

    def sample_once(self) -> None:
        self.sample_calls += 1

    def stop(self) -> None:
        self.stop_calls += 1
        if self.stop_error is not None:
            raise self.stop_error

    def total_cpu_seconds(self) -> float:
        return 1.0


def _empty_snapshot() -> dict[str, object]:
    return {
        "observed": True,
        "get_requests": 0,
        "get_bytes": 0,
        "put_requests": 0,
        "put_bytes": 0,
        "head_requests": 0,
        "other_requests": 0,
        "total_requests": 0,
        "error_responses": 0,
        "status_counts": {},
    }


class _ScriptedProxy:
    def __init__(self, raise_at: int | None = None, error: BaseException | None = None) -> None:
        self.raise_at = raise_at
        self.error = error
        self.calls = 0
        self.deadlines: list[float] = []

    def snapshot_after_quiescence(self, deadline: float) -> dict[str, object]:
        self.calls += 1
        self.deadlines.append(deadline)
        if self.raise_at == self.calls:
            assert self.error is not None
            raise self.error
        return _empty_snapshot()


class _FakeFuture:
    def result(self) -> tuple[bool, float, None]:
        return True, 1.0, None


class _FakeExecutor:
    def __init__(self, *args: object, **kwargs: object) -> None:
        return None

    def __enter__(self) -> "_FakeExecutor":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False

    def submit(self, *args: object, **kwargs: object) -> _FakeFuture:
        return _FakeFuture()


_REPOS = {
    "text_history": {
        "info": {"owner": "o", "name": "n1", "clone_path": "/r1"},
        "seed_oid": "a" * 40,
        "browse_file": "f",
        "ds_class": "text_history",
        "ro": {},
    },
    "compressed_media": {
        "info": {"owner": "o", "name": "n2", "clone_path": "/r2"},
        "seed_oid": "b" * 40,
        "browse_file": "f",
        "ds_class": "compressed_media",
        "ro": {},
    },
}


def _fake_users(*args: object, **kwargs: object) -> dict[str, object]:
    return {}


def _fake_cli(*args: object, **kwargs: object) -> str:
    return '{"token": "tok"}'


def _fake_seed(*args: object, **kwargs: object) -> dict[str, object]:
    return _REPOS


def _fake_noop(*args: object, **kwargs: object) -> dict[str, object]:
    return {}


def _fake_fault(*args: object, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
    return {}, {}


def _fake_pg(*args: object, **kwargs: object) -> dict[str, int]:
    return {
        "pack_count": 0,
        "publication_count": 0,
        "serving_pack_bytes": 0,
        "coexisting_pack_bytes": 0,
    }


def _fake_cold(
    n_procs: int,
    pre: dict[str, object],
    base_env: dict[str, str],
    pg_url: str,
    s3_endpoint: str,
    s3_proxy: object,
    tier_scratch: _FakePath,
    tier_dir: _FakePath,
    askpass: _FakePath,
    repos: dict[str, object],
    records: list[dict[str, object]],
    fleet: _FakeFleet,
    sampler: _FakeSampler,
) -> tuple[_FakeFleet, dict[str, object], dict[str, object]]:
    return fleet, {}, {}


def _fake_clone(*args: object, **kwargs: object) -> tuple[bool, float, None]:
    return True, 1.0, None


def _fake_http(*args: object, **kwargs: object) -> tuple[int, bytes, dict[str, object], float]:
    return 200, b"{}", {}, 1.0


def _run_case(
    proxy: _ScriptedProxy,
    sampler: _FakeSampler,
    fleets: list[_FakeFleet],
    *,
    real_cold: bool,
    stop_behavior: object = None,
) -> tuple[dict[str, object] | None, list[dict[str, object]], BaseException | None]:
    clock = _FakeClock()
    stops: list[dict[str, object]] = []
    fleet_iter = iter(fleets)

    def fake_start(*args: object, **kwargs: object) -> _FakeFleet:
        return next(fleet_iter)

    def fake_stop(fleet: list[object]) -> None:
        stops.append({"fleet": fleet, "id": id(fleet), "items": list(fleet)})
        if stop_behavior is not None:
            stop_behavior(fleet)  # type: ignore[operator]

    with ExitStack() as stack:
        stack.enter_context(patch("rubicon_workload.runner._create_user_and_tokens", new=_fake_users))
        stack.enter_context(patch("rubicon_workload.runner._cli", new=_fake_cli))
        stack.enter_context(patch("rubicon_workload.runner._start_fleet", side_effect=fake_start))
        stack.enter_context(patch("rubicon_workload.runner._stop_fleet", new=fake_stop))
        stack.enter_context(patch("rubicon_workload.runner.ResourceSampler", return_value=sampler))
        stack.enter_context(patch("rubicon_workload.runner._phase_seed", new=_fake_seed))
        stack.enter_context(patch("rubicon_workload.runner._phase_concurrent_overlap", new=_fake_noop))
        stack.enter_context(patch("rubicon_workload.runner._phase_same_repo_mixed", new=lambda *a, **k: ({}, [])))
        stack.enter_context(patch("rubicon_workload.runner._phase_cas_race", new=_fake_noop))
        stack.enter_context(patch("rubicon_workload.runner._phase_atomic_subset", new=_fake_noop))
        stack.enter_context(patch("rubicon_workload.runner._phase_fault_and_audit", new=_fake_fault))
        stack.enter_context(patch("rubicon_workload.runner.query_pg_snapshot_json", new=_fake_pg))
        stack.enter_context(patch("rubicon_workload.runner.time.monotonic", new=clock.monotonic))
        if real_cold:
            stack.enter_context(patch("rubicon_workload.runner.ThreadPoolExecutor", new=_FakeExecutor))
            stack.enter_context(patch("rubicon_workload.runner.clone_and_fsck", new=_fake_clone))
            stack.enter_context(patch("rubicon_workload.runner.http_json", new=_fake_http))
        else:
            stack.enter_context(patch("rubicon_workload.runner._phase_cold_warm_and_ci", new=_fake_cold))

        config = WorkloadConfig(binary="/bin/true", report="/tmp/r.json", git="/usr/bin/git", require_build_receipt=False)
        try:
            result = _run_tier(
                1,
                config,
                {"binary": "/bin/true", "git": "/usr/bin/git"},
                {},
                {},
                "postgresql://u@127.0.0.1/db",
                "http://127.0.0.1:9000",
                proxy,
                _FakePath("tier"),
                _FakePath("askpass"),
                [],
            )
            return result, stops, None
        except BaseException as exc:
            return None, stops, exc


class MeterTierCleanupTests(unittest.TestCase):
    def test_initial_boundary_timeout_cleans_sampler_and_original_fleet(self) -> None:
        sampler = _FakeSampler()
        error = MeterQuiescenceTimeout(2, 130.0)
        proxy = _ScriptedProxy(raise_at=1, error=error)
        initial = _FakeFleet("old", 101)

        result, stops, exc = _run_case(proxy, sampler, [initial], real_cold=False)

        self.assertIsNone(result)
        self.assertIs(exc, error)
        self.assertEqual(sampler.stop_calls, 1)
        self.assertEqual(len(stops), 1)
        self.assertIs(stops[0]["fleet"], initial)
        self.assertEqual(stops[0]["items"], list(initial))
        self.assertEqual(proxy.calls, 1)

    def test_cold_boundary_timeouts_leave_replacement_fleet_for_caller(self) -> None:
        for raise_at in (4, 5):
            with self.subTest(raise_at=raise_at):
                sampler = _FakeSampler()
                error = MeterQuiescenceTimeout(1, 130.0)
                proxy = _ScriptedProxy(raise_at=raise_at, error=error)
                initial = _FakeFleet("old", 101)
                replacement = _FakeFleet("new", 202)
                old_items = list(initial)
                replacement_items = list(replacement)

                result, stops, exc = _run_case(proxy, sampler, [initial, replacement], real_cold=True)

                self.assertIsNone(result)
                self.assertIs(exc, error)
                self.assertEqual(sampler.stop_calls, 1)
                self.assertEqual(len(stops), 2)
                self.assertIs(stops[0]["fleet"], initial)
                self.assertEqual(stops[0]["items"], old_items)
                self.assertIs(stops[1]["fleet"], initial)
                self.assertEqual(stops[1]["id"], id(initial))
                self.assertEqual(stops[1]["items"], replacement_items)
                self.assertEqual(proxy.calls, raise_at)

    def test_active_timeout_survives_sampler_stop_failure_and_fleet_attempt(self) -> None:
        sampler = _FakeSampler()
        sampler.stop_error = RuntimeError("SECRET_DSN=postgresql://user:secret@db")
        error = MeterQuiescenceTimeout(3, 140.0)
        proxy = _ScriptedProxy(raise_at=1, error=error)
        initial = _FakeFleet("old", 101)

        result, stops, exc = _run_case(proxy, sampler, [initial], real_cold=False)

        self.assertIsNone(result)
        self.assertIs(exc, error)
        self.assertEqual(sampler.stop_calls, 1)
        self.assertEqual(len(stops), 1)
        self.assertIs(stops[0]["fleet"], initial)
        notes = list(getattr(error, "__notes__", []))
        self.assertIn("sampler cleanup incomplete: stop_error", notes)
        self.assertNotIn("SECRET_DSN", str(error))
        self.assertTrue(all("SECRET_DSN" not in note for note in notes))

    def test_no_active_sampler_failure_fails_closed_after_fleet_cleanup(self) -> None:
        sampler = _FakeSampler()
        sampler_error = RuntimeError("sampler boom")
        sampler.stop_error = sampler_error
        proxy = _ScriptedProxy()
        initial = _FakeFleet("old", 101)

        result, stops, exc = _run_case(proxy, sampler, [initial], real_cold=False)

        self.assertIsNone(result)
        self.assertIs(exc, sampler_error)
        self.assertEqual(sampler.stop_calls, 1)
        self.assertEqual(len(stops), 1)
        self.assertIs(stops[0]["fleet"], initial)

    def test_fleet_cleanup_failure_preserves_timeout_identity(self) -> None:
        sampler = _FakeSampler()
        error = MeterQuiescenceTimeout(1, 150.0)
        proxy = _ScriptedProxy(raise_at=1, error=error)
        initial = _FakeFleet("old", 101)

        def fail_fleet_cleanup(fleet: list[object]) -> None:
            raise FleetCleanupError(["worker[0]: wait_error"])

        result, stops, exc = _run_case(
            proxy, sampler, [initial], real_cold=False, stop_behavior=fail_fleet_cleanup
        )

        self.assertIsNone(result)
        self.assertIs(exc, error)
        self.assertEqual(sampler.stop_calls, 1)
        self.assertEqual(len(stops), 1)
        notes = list(getattr(error, "__notes__", []))
        self.assertIn("fleet cleanup incomplete: worker[0]: wait_error", notes)

    def test_successful_restart_retains_shared_fleet_list_identity(self) -> None:
        sampler = _FakeSampler()
        proxy = _ScriptedProxy()
        initial = _FakeFleet("old", 101)
        replacement = _FakeFleet("new", 202)
        old_items = list(initial)
        replacement_items = list(replacement)

        result, stops, exc = _run_case(proxy, sampler, [initial, replacement], real_cold=True)

        self.assertIsNone(exc)
        self.assertIsNotNone(result)
        self.assertEqual(sampler.stop_calls, 1)
        self.assertEqual(len(stops), 2)
        self.assertIs(stops[0]["fleet"], initial)
        self.assertEqual(stops[0]["items"], old_items)
        self.assertIs(stops[1]["fleet"], initial)
        self.assertEqual(stops[1]["id"], id(initial))
        self.assertEqual(stops[1]["items"], replacement_items)
        self.assertEqual(proxy.calls, 8)
        self.assertEqual(result["compute_processes"], 1)


if __name__ == "__main__":
    unittest.main()
