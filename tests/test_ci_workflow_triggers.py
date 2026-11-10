"""Trigger contract for the duplicated full-gate workflows (issue: CI trigger de-duplication).

`CI`, `Pando synthetic lab` and `Redis contract` used an unfiltered
``push:`` + ``pull_request:`` pair, so every PR head SHA produced two runs of the
same full gate (2026-11-10: push 42783486160 and pull_request 42783651096 for
268e8b0ff). The contract now enforced here:

* ``pull_request`` remains the single full-gate event for every PR head;
* ``push`` is limited to the real long-lived branches (``main`` today; there are
  no release/maintenance branches or tags in the repository);
* ``workflow_dispatch`` is kept where it existed (manual specialised dispatch);
* no ``paths:`` filter is introduced on ``pull_request``/``push``, so a required
  check can never be left permanently pending;
* job ids (the check-run names ``verify``, ``container``, ``isolated-lab``,
  ``redis-contract``) are unchanged.

Only the trigger block is asserted; job steps are owned by other changes.
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
# Path-filtered / dispatch-only suites keep their own triggers untouched.
UNCHANGED = (
    "refstore-protocol-acceptance.yml",
    "refcas-log.yml",
    "native-kernel-acceptance.yml",
    "candidate-release-acceptance.yml",
)

LONG_LIVED_BRANCHES = {"main"}


def _triggers(data: dict) -> dict:
    """Return the ``on:`` mapping; YAML 1.1 parsers read ``on`` as boolean ``True``."""
    triggers = data["on"] if "on" in data else data[True]
    return {event: (body or {}) for event, body in triggers.items()}


def _on_block(path: Path) -> list[str]:
    """Return the top-level ``on:`` block lines (its keys and nested content)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.fullmatch(r"on:\s*", line):
            start = index + 1
            break
        if re.fullmatch(r"on:\s*\S.*", line):  # flow style `on: [push]`
            return [line]
    if start is None:
        raise AssertionError(f"{path}: no top-level `on:` block")
    block = []
    for line in lines[start:]:
        if line.strip() and not line.startswith((" ", "#", "\t")):
            break
        block.append(line)
    return block


def _event_keys(block: list[str]) -> dict[str, list[str]]:
    """Map each event key in the ``on:`` block to its non-comment child lines."""
    events: dict[str, list[str]] = {}
    current = None
    for line in block:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key = re.fullmatch(r"  ([A-Za-z_]+):\s*(.*)", line)
        if key:
            current = key.group(1)
            events[current] = [key.group(2)] if key.group(2) else []
            continue
        if current is not None:
            events[current].append(stripped)
    return events


def _branches(children: list[str]) -> list[str]:
    text = " ".join(children)
    match = re.search(r"branches:\s*(\[[^\]]*\])", text)
    if match:
        return re.findall(r"[\w./*-]+", match.group(1))
    match = re.search(r"branches:\s*(\S+)", text)
    if match:
        return [match.group(1)]
    raise AssertionError(f"branches filter present but unparsable: {children}")


class TriggerDedupTest(unittest.TestCase):
    def test_deduped_workflows_use_pr_event_and_main_only_push(self) -> None:
        for name in FULL_GATE:
            with self.subTest(workflow=name):
                events = _event_keys(_on_block(WORKFLOWS / name))
                self.assertIn("pull_request", events, f"{name}: PR gate must remain")
                self.assertIn("push", events, f"{name}: post-merge main gate must remain")
                # Unfiltered push would re-run the full gate for every feature branch.
                self.assertTrue(events["push"], f"{name}: bare `push:` duplicates PR runs")
                self.assertEqual(set(_branches(events["push"])), LONG_LIVED_BRANCHES, name)
                for event in ("pull_request", "push"):
                    self.assertFalse(
                        any(line.startswith(("paths:", "paths_ignore:")) for line in events[event]),
                        f"{name}: no path filter on {event} (required checks must not hang)",
                    )
                self.assertNotIn("paths-ignore", "\n".join(events.get("pull_request", [])))

    def test_full_gate_workflows_keep_manual_dispatch_where_they_have_no_pr_gate(self) -> None:
        for name in ("native-kernel-acceptance.yml", "candidate-release-acceptance.yml"):
            with self.subTest(workflow=name):
                events = _event_keys(_on_block(WORKFLOWS / name))
                self.assertEqual(set(events), {"workflow_dispatch"}, name)

    def test_required_check_run_names_are_unchanged(self) -> None:
        import yaml  # noqa: PLC0415 - optional dependency in some local envs

        for name in FULL_GATE:
            jobs = FULL_GATE[name]
            with self.subTest(workflow=name):
                data = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
                triggers = _triggers(data)
                self.assertIn("pull_request", triggers)
                self.assertIn("push", triggers)
                push = triggers["push"]
                self.assertIn("branches", push, f"{name}: bare `push:` duplicates PR runs")
                self.assertEqual(set(push["branches"]), LONG_LIVED_BRANCHES)
                self.assertNotIn("paths", push)
                self.assertNotIn("paths", triggers["pull_request"])
                self.assertNotIn("paths-ignore", triggers["pull_request"])
                for job in jobs:
                    self.assertIn(job, data["jobs"], f"{name}: check `{job}` missing")
                    # A job-level `name:` would rename the required check.
                    self.assertNotIn("name", data["jobs"][job], f"{name}:{job} was renamed")
    def test_manual_dispatch_is_available_alongside_the_pr_gate(self) -> None:
        import yaml  # noqa: PLC0415

        for name in ("pando-lab.yml", "redis-contract.yml"):
            with self.subTest(workflow=name):
                triggers = _triggers(yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8")))
                # A specialised suite can still be dispatched on a development
                # branch without re-enabling an unfiltered push run.
                self.assertIn("workflow_dispatch", triggers)

    def test_path_filtered_suites_keep_pr_paths_and_dispatch(self) -> None:
        import yaml  # noqa: PLC0415

        for name in ("refstore-protocol-acceptance.yml", "refcas-log.yml"):
            with self.subTest(workflow=name):
                data = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
                triggers = _triggers(data)
                self.assertIn("workflow_dispatch", triggers)
                self.assertIn("paths", triggers["pull_request"])
                self.assertNotIn("push", triggers)


if __name__ == "__main__":
    unittest.main()
