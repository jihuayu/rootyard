#!/usr/bin/env python3
"""Genuine format11/schema135 archive upgraded to the current reviewed target.

Light entry point over the shared ``backup_legacy132_sessions`` harness. The
trusted ``observability135-v2`` binary writes an unmodified format11/schema135
archive; the candidate must reject it without ``--allow-legacy-schema135``,
accept it only with that exact opt-in, apply the reviewed migrations through the
current target selected from ``schema_baseline``, and retain the existing
schema133 GC indexes, schema134 identity foreign keys and schema135 metrics
index. The restored schema must add the token scope columns/tables while every
pre-migration token keeps ``is_restricted = false`` and no scope grant is
fabricated.

Only the reviewed target schema/format is replaced here; the frozen genuine
format11/schema135 source contract and its exact opt-in remain ``LEGACY135``.
Only random task-owned databases and temporary storage are used. This worker
does not build or run the legacy binary.
"""
import sys

from dataclasses import replace

from backup_legacy132_sessions import LEGACY135, run_main
from schema_baseline import CURRENT_BACKUP_FORMAT, CURRENT_SCHEMA_VERSION


LEGACY135_CURRENT_TARGET = replace(
    LEGACY135,
    target_schema=CURRENT_SCHEMA_VERSION,
    target_format=CURRENT_BACKUP_FORMAT,
)


if __name__ == "__main__":
    sys.exit(run_main(LEGACY135_CURRENT_TARGET))
