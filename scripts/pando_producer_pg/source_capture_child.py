#!/usr/bin/env python3
"""Private bounded child for one complete canonical source capture.

The parent starts this helper with an explicit ``cwd`` equal to the source root
and owns/reaps it under the remaining work budget.  The helper runs the
unchanged in-process ``source.capture`` semantics (the same five Git commands,
the same bound-input inventory and the same source hashing) and emits only one
fixed JSON object.  It never prints exception text, argv, environment values or
absolute paths.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pando_producer_pg.errors import RunnerError  # noqa: E402


def run(argv, capture_fn=None):
    if len(argv) != 4:
        return 2
    source_root, expected_commit, expected_tree = argv[1], argv[2], argv[3]
    if expected_tree == "-":
        expected_tree = ""
    if capture_fn is None:
        from pando_producer_pg import source

        capture_fn = source.capture
    try:
        binding = capture_fn(
            source_root,
            expected_commit,
            expected_tree=expected_tree or None,
            environ=os.environ,
        )
        payload = {"ok": True, "binding": binding}
    except RunnerError as error:
        payload = {"ok": False, "stage": error.stage, "code": error.code}
    except Exception:
        payload = {
            "ok": False,
            "stage": "source",
            "code": "source_capture_failed",
        }
    try:
        sys.stdout.write(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        )
    except (OSError, ValueError):
        return 1
    return 0


def main(argv=None):
    return run(sys.argv if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(main())
