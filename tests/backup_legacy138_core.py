#!/usr/bin/env python3
"""Restore a genuine schema138/format14 archive into schema139/format15.

Reuses the shared legacy-archive harness with the coordinator-provided format14
binary.  The legacy binary creates the real Git/Pando source and writes the
offline archive; the candidate must reject it without
``--allow-legacy-schema138`` (and with a mixed/mismatched opt-in), then restore
it into a fresh database and apply migration 139 (the minimal RefStore core).
The genuine schema138 source has no core rows, so the drill asserts the new
gate/ref/event tables, current-ref key, operation foreign key and immutable
event trigger exist and stay empty; it does not claim a core-row roundtrip.
This file is an entry point only; the root runs the native two-binary drill.
"""
from backup_legacy132_sessions import LEGACY138, run_main


def main():
    return run_main(LEGACY138)


if __name__ == "__main__":
    raise SystemExit(main())
