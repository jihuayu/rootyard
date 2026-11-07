#!/usr/bin/env python3
"""Genuine format9/schema133 Pando archive upgraded by the current binary.

The trusted ``gc133-v2`` binary creates two real repositories, pushes Git
history through the stock server, performs the real Pando cutovers and writes
an unmodified offline archive (format 9, schema versions through 133).  The
candidate binary must reject that archive by default and with the wrong legacy
opt-in, accept it only with ``--allow-legacy-schema133``, restore into a fresh
isolated database/data directory, apply the reviewed schema134/schema135
migrations and then serve stock Git clone/fetch/fsck for both repositories.

After the upgrade the four schema134 composite identity foreign keys, the
supporting unique constraint and the schema135 partial metrics index must
exist validated, the single-column manifest link must be gone, both
repositories must share exactly one newly minted Pando
authority whose remote paths are disjoint from the source, the pre-backup
browser cookie must be rejected while the API token still works, and the
source authority/remote objects must remain readable and undeleted.

Only random task-owned databases and temporary storage are used.  Secrets,
DSNs, raw HTTP logs and Garage/Vault credentials are never printed.  This is
the format9/schema133 contract; ``backup_legacy132_sessions.py`` remains the
compatible format8/schema132 entry point and shares the same harness.
"""
import sys

from backup_legacy132_sessions import LEGACY133, run_main


if __name__ == "__main__":
    sys.exit(run_main(LEGACY133))
