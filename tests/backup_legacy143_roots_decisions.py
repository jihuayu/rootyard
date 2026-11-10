#!/usr/bin/env python3
"""Genuine format19/schema143 -> format20/schema144 roots/decisions upgrade.

Root supplies the retained genuine schema143 producer
(``/workspace/scratch/state-pack143-app-v1/rootyard``, sha256
``c61d3f9a5617fe03d17afd4a5277912c6e6948414c06e5d6e3a5460b4508d96b``) and the
retained old typed A5 integration-test helper
(``state-pack143-backup-helper-build-v5/ref_store_pack_snapshots_backup_fixture``
plus its ``.build.json`` receipt). This file never manufactures, edits or
relabels an archive or a manifest.

Sequence enforced by the shared ``backup_legacy132_sessions`` harness with the
frozen ``LEGACY143`` contract:

1. the retained old producer creates the real Git/Pando source on the frozen
   format19/schema143 schema;
2. the retained old typed A5 helper runs in **seed** mode only, before the
   offline backup, so the archive carries a genuine NON-EMPTY schema143 A5
   ledger (four binding/history/permanent-usage tables, active/renewed/released/
   expired scenarios) plus the complete 139/140/141/142 ledgers;
3. the old producer writes the real format19 archive (never edited);
4. the candidate rejects it without ``--allow-legacy-schema143`` (and with a
   mixed/mismatched legacy opt-in), then restores it into a fresh database,
   applies the reviewed migration 144 and rotates authority;
5. after the upgrade the complete schema143 A5 rows are compared **exactly**
   (the old helper's ``verify`` mode is never run against the schema144 target,
   and no schema143 seed is replayed there), the schema140 snapshot rows stay
   ``metadata_only``, and the seventeen generated 144-vs-143 root/decision
   tables exist and stay empty: no retention root, root receipt, protocol realm
   or publication decision is fabricated by the upgrade.

This is PostgreSQL metadata-only. It makes no serving, Blob-byte backup,
complete Git-read snapshot or production qualification claim.
"""
import sys

from backup_legacy132_sessions import LEGACY143, LegacyArchiveHarness, run_main

# The shared harness must carry the genuine schema143-source path: A5 seeding on
# the frozen source, exact A5 preservation after the upgrade, and the
# migration-144 emptiness assertion. There is no fallback to the format18 path
# and no hidden unsupported behaviour.
REQUIRED_HARNESS_METHODS = (
    "seed_legacy_a5_fixture",
    "validate_legacy_a5_fixture",
    "assert_genuine_schema143_snapshot_ledger",
    "assert_roots_decision_schema",
)


def missing_harness_support():
    return [name for name in REQUIRED_HARNESS_METHODS
            if not callable(getattr(LegacyArchiveHarness, name, None))]


def main():
    missing = missing_harness_support()
    if missing:
        print("backup_legacy143_roots_decisions: the shared legacy harness is missing "
              "its schema143-source support (" + ", ".join(missing) + "); refusing to run "
              "the format19 drill with a hidden unsupported fallback", file=sys.stderr)
        return 2
    if LEGACY143.schema != 143 or LEGACY143.format != 19:
        print("backup_legacy143_roots_decisions: frozen LEGACY143 contract is not "
              "format19/schema143", file=sys.stderr)
        return 2
    return run_main(LEGACY143)


if __name__ == "__main__":
    sys.exit(main())
