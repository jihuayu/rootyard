#!/usr/bin/env python3
"""Restore a genuine schema141/format17 archive into schema142/format18.

Reuses the shared legacy-archive harness with the root-provided, retained old
format17 producer.  The old binary creates the real Git/Pando source and writes
the offline archive; this file never manufactures, edits or relabels an archive
or manifest.  The candidate must reject it without
``--allow-legacy-schema141`` (and with a mixed/mismatched opt-in), then restore
it into a fresh database and apply the reviewed migration 142.

A genuine format17/schema141 source carries the fixed 64 migration141 global
shard rows but no schema142 pack registration, artifact, membership, history or
usage rows.  The drill derives the new table list from the generated current-vs-
141 catalogs, asserts every new pack-ledger table exists and is empty, requires
the preserved shard seed to stay unchanged, and checks that the core gate's new
``pack_mode`` column defaults to exactly ``metadata_only``.  It fabricates no
pack row, starts no pack commit, copies no Blob bytes and makes no serving or
physical-protection claim.  This file is an entry point only; the root runs the
native two-binary drill after supplying the genuine producer.

Root retains the native genuine format17 producer binary outside this worktree
(RAW ``/scratch/state-artifact141-app-v1/rootyard``); this agent cannot read
outside the task root, did not run or forge that producer, and therefore does
not claim the legacy141 path is qualified yet.
"""
from backup_legacy132_sessions import LEGACY141, run_main


def main():
    return run_main(LEGACY141)


if __name__ == "__main__":
    raise SystemExit(main())
