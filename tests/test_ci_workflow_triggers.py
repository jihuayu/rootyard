"""Trigger contract for the duplicated full-gate workflows (issue: CI trigger de-duplication).

`CI`, `Pando synthetic lab` and `Redis contract` used an unfiltered
``push:`` + ``pull_request:`` pair, so every PR head SHA produced two runs of the
same full gate (2026-11-10: push 42783486160 and pull_request 42783651096 for
268e8b0ff). The contract now enforced here:

* ``pull_request`` remains the single full-gate event for every PR head;
* ``push`` is limited to the real long-lived branches (``main`` today; there are
  no release/maintenance branches or tags in the repository);
* neither event carries a ``paths``/``paths-ignore`` filter, so a required check
  can never be left permanently pending;
* ``workflow_dispatch`` is available for manual specialised dispatch;
* job ids (the check-run names ``verify``, ``container``, ``isolated-lab``,
  ``redis-contract``) are unchanged, and no job-level ``name:`` renames them.

Only the trigger block and the job keys are read, by indentation, with the
standard library only: the repository declares no PyYAML dependency, and this
module therefore has none. Job steps are owned by other changes; full YAML
validity is proven by GitHub parsing the pushed workflow.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# workflow file -> job ids that must keep their check-run names
FULL_GATE = {
    "ci.yml": ("verify", "container"),
    "pando-lab.yml": ("isolated-lab",),
    "redis-contract.yml": ("redis-contract",),
}
PATH_FILTERS = ("paths", "paths-ignore")
LONG_LIVED_BRANCHES = {"main"}


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _content(lines: list[str]) -> list[str]:
    return [line for line in lines if line.strip() and not line.lstrip().startswith("#")]


def _top_block(lines: list[str], name: str) -> tuple[int, list[str]] | None:
    """Children of the top-level ``name:`` as ``(indent, lines)``; ``None`` if absent.

    The first child line is on the ``name:`` line itself and is not returned.
    """
    for index, line in enumerate(lines):
        match = re.fullmatch(rf"{re.escape(name)}:\s*(.*)", line)
        if not match:
            continue
        if match.group(1):
            raise AssertionError(f"top-level `{name}:` is not a block mapping")
        body: list[str] = []
        for child in lines[index + 1:]:
            if child.strip() and not child.lstrip().startswith("#") and _indent(child) == 0:
                break
            body.append(child)
        return 2, body
    return None


def _mapping(children: list[str]) -> dict[str, list[str]] | None:
    """Map each key of a block to its deeper lines; ``None`` for a flow value.

    ``children`` come from :func:`_top_block`, so keys sit at indent 2. A key
    whose value is an inline ``[...]`` list makes the block flow style.
    """
    mapping: dict[str, list[str]] | None = {}
    current: str | None = None
    for line in _content(children):
        key = re.fullmatch(r"  ([A-Za-z_][\w-]*):[ \t]*(.*)", line)
        if key:
            current = key.group(1)
            value = key.group(2)
            mapping[current] = [f"    {value}"] if value else []
            if value.startswith("["):
                return None
            continue
        if current is not None:
            mapping[current].append(line)  # keep indentation for nested reads
    return mapping


def _nested(children: list[str]) -> dict[str, list[str]]:
    """Keys one level deeper than ``children`` (the trigger filters of an event)."""
    nested: dict[str, list[str]] = {}
    for line in _content(children):
        key = re.fullmatch(r"    ([A-Za-z_][\w-]*):[ \t]*(.*)", line)
        if key:
            nested.setdefault(key.group(1), [key.group(2)])
    return nested


def _branches(value: list[str]) -> list[str]:
    """Branches from the value of a ``branches:`` key (``[main]`` or a block list)."""
    text = " ".join(line.strip() for line in value)
    match = re.fullmatch(r"\[([^\]]*)\]", text)
    if match:
        return [item.strip().strip("'\"") for item in match.group(1).split(",") if item.strip()]
    if value == [""] or not text:
        raise AssertionError("empty branches filter")
    return [item.lstrip("- ").strip().strip("'\"") for item in value if item.lstrip("- ").strip()]


class Workflow:
    def __init__(self, name: str) -> None:
        self.name = name
        lines = (WORKFLOWS / name).read_text(encoding="utf-8").splitlines()
        self.events = _mapping(self._block(lines, "on"))
        self.jobs = _mapping(self._block(lines, "jobs"))

    @staticmethod
    def _block(lines: list[str], name: str) -> list[str]:
        block = _top_block(lines, name)
        if block is None:
            raise AssertionError(f"no top-level `{name}:`")
        return block[1]


class TriggerDedupTest(unittest.TestCase):
    def test_full_gate_workflows_use_pr_event_and_main_only_push(self) -> None:
        for name in FULL_GATE:
            with self.subTest(workflow=name):
                events = Workflow(name).events
                self.assertIsNotNone(events, f"{name}: `on:` must be a block mapping")
                self.assertIn("pull_request", events, f"{name}: PR gate must remain")
                self.assertIn("push", events, f"{name}: post-merge main gate must remain")
                # A bare `push:` (no branch filter) re-runs the gate for every
                # feature branch head that also opened a pull request.
                push = _nested([f"  push:", *events["push"]]).get("branches")
                self.assertTrue(push, f"{name}: bare `push:` duplicates PR runs")
                self.assertEqual(set(_branches(push)), LONG_LIVED_BRANCHES, name)

    def test_full_gate_events_have_no_path_filters(self) -> None:
        for name in FULL_GATE:
            events = Workflow(name).events
            for event in ("pull_request", "push"):
                with self.subTest(workflow=name, event=event):
                    filters = _nested(events[event])
                    for filter_name in PATH_FILTERS:
                        self.assertFalse(
                            any(f == filter_name for f in filters),
                            f"{name}: {event} has `{filter_name}:` (required checks could hang)",
                        )
                    # `branches` is the only key allowed under either event.
                    self.assertLessEqual(set(filters), {"branches"}, f"{name}: {event}")

    def test_manual_dispatch_is_available_alongside_the_pr_gate(self) -> None:
        # The specialised suites never had dispatch before; it was added so an
        # affected suite can be run on a branch. ci.yml is the PR gate itself
        # and never offered dispatch, which this change does not alter.
        for name in ("pando-lab.yml", "redis-contract.yml"):
            with self.subTest(workflow=name):
                self.assertIn("workflow_dispatch", Workflow(name).events)
        self.assertNotIn("workflow_dispatch", Workflow("ci.yml").events)

    def test_required_check_run_names_are_unchanged(self) -> None:
        for name, job_ids in FULL_GATE.items():
            with self.subTest(workflow=name):
                jobs = Workflow(name).jobs
                self.assertIsNotNone(jobs, f"{name}: `jobs:` must be a block mapping")
                for job in job_ids:
                    self.assertIn(job, jobs, f"{name}: check `{job}` missing")
                    # A job-level `name:` would rename the required check.
                    self.assertFalse(
                        any(job_line.startswith("    name:") for job_line in jobs[job]),
                        f"{name}:{job} was renamed",
                    )

    def test_reporting_only_workflows_keep_their_original_triggers(self) -> None:
        # Not required checks; their triggers are out of this change's scope.
        for name in ("native-kernel-acceptance.yml", "candidate-release-acceptance.yml"):
            with self.subTest(workflow=name):
                events = Workflow(name).events
                self.assertIsNotNone(events)
                self.assertEqual(set(events), {"workflow_dispatch"}, name)
        for name in ("refstore-protocol-acceptance.yml", "refcas-log.yml"):
            with self.subTest(workflow=name):
                events = Workflow(name).events
                self.assertIn("workflow_dispatch", events)
                self.assertNotIn("push", events, f"{name}: reporting-only workflow")
                filters = _nested(events["pull_request"])
                self.assertTrue(filters.get("paths"), f"{name}: PR path list missing")
                self.assertNotIn("paths-ignore", filters, name)


if __name__ == "__main__":
    unittest.main()
