#!/usr/bin/env python3
"""Legacy format18/schema142 entry point for the A5a pack-snapshot upgrade.

Root supplies the genuine retained A4 producer binary and an archive it wrote;
this file never manufactures, edits or relabels an archive.  The format18/schema142
entrypoint also requires the retained schema142 A4 integration-test helper plus its
build receipt (``--legacy-fixture-binary``/``--legacy-fixture-receipt``); the shared
harness runs that helper in seed mode only, before the old offline backup, so the
archive carries a genuine NON-EMPTY schema142 pack/A3 ledger.  Its verify mode is
never run against the schema143 target.  The shared
``backup_legacy132_sessions.LegacyArchiveHarness`` rejects the format18 archive
without ``--allow-legacy-schema142``, rejects mixed/mismatched legacy opt-ins,
and restores it only after verifying the exact frozen format18/schema142 catalog
and version list.

The restored target must then carry the complete schema143 additions from
migration 143: the four generated 143-vs-142 pack-snapshot binding, history and
permanent-usage tables exist and are empty (no A5 pin/history is fabricated),
the A2 snapshot header gains defaulted ``pack_mode='metadata_only'`` /
``pack_count=0`` / null digest columns, and old snapshot rows stay
``unavailable``.  The complete schema142 pack/A3 ledger rows that the genuine
source carries are compared exactly before and after the upgrade, as are the
schema139/140/141 ledgers.  The gate keeps its captured pack mode.

This is PostgreSQL metadata-only.  It makes no serving, Blob-byte backup,
complete Git-read snapshot or production qualification claim.  The A4 legacy
trace/guard mismatch is handled by the shared harness's schema142 gate-fence
expectation; the Rust helper's normalized-digest marker fix is Root's merge.
"""
import sys

from backup_legacy132_sessions import LEGACY142, run_main


def main():
    return run_main(LEGACY142)


if __name__ == "__main__":
    sys.exit(main())
