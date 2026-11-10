#!/usr/bin/env python3
"""Restore a genuine schema140/format16 archive into schema141/format17.

Reuses the shared legacy-archive harness with the root-provided, retained old
format16 producer.  The old binary creates the real Git/Pando source and writes
the offline archive; this file never manufactures, edits or relabels an archive
or manifest.  The candidate must reject it without
``--allow-legacy-schema140`` (and with a mixed/mismatched opt-in), then restore
it into a fresh database and apply the reviewed migration 141.

A genuine format16/schema140 source carries no schema141 artifact-hold rows.
The drill derives the new table list from the generated current-vs-140 catalogs,
asserts every new global hold/request/consumption table exists, and requires
them to be empty except for the exact fixed rows (currently the 64 global shard
rows) that the settled migration141 SQL itself inserts.  It fabricates no hold,
request or consumption row, does not copy Blob bytes and makes no serving or
physical-protection claim.  This file is an entry point only; the root runs the
native two-binary drill after supplying the genuine producer.
"""
from backup_legacy132_sessions import LEGACY140, run_main


def main():
    return run_main(LEGACY140)


if __name__ == "__main__":
    raise SystemExit(main())
