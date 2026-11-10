#!/usr/bin/env python3
"""Restore a genuine schema139/format15 archive into schema140/format16.

Reuses the shared legacy-archive harness with the coordinator-provided format15
binary.  The legacy binary creates the real Git/Pando source and writes the
offline archive; the candidate must reject it without
``--allow-legacy-schema139`` (and with a mixed/mismatched opt-in), then restore
it into a fresh database and apply migration 140 (the reviewed
RefStore-core-snapshot migration).

A genuine format15/schema139 source carries no RefStore core rows, so the drill
asserts that the migration-139 gate/ref/event tables exist, are constrained and
stay empty.  It deliberately makes no schema140 snapshot/pin table or row
assertion: a populated current-format restore qualification follows the primary
migration-140 SQL.  This file is an entry point only; the root runs the native
two-binary drill.
"""
from backup_legacy132_sessions import LEGACY139, run_main


def main():
    return run_main(LEGACY139)


if __name__ == "__main__":
    raise SystemExit(main())
