"""Canonical schema baseline derived from migrations/ and schema/ fixtures.

Centralizes version lists, table sets, and catalog paths so parallel tracks
adding new migrations do not cause cross-suite test conflicts.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = ROOT / "migrations"
SCHEMA_DIR = ROOT / "schema"

SCHEMA_VERSIONS = sorted(
    int(path.name.split("_", 1)[0]) for path in MIGRATIONS_DIR.glob("*.sql")
)
SCHEMA_VERSION_CSV = ",".join(str(v) for v in SCHEMA_VERSIONS)
LATEST_VERSION = SCHEMA_VERSIONS[-1]
LATEST_PREFIX = f"{LATEST_VERSION:03d}"

# Single explicit source for the current archive format. Tests must not infer
# the expected format from the manifest produced by the implementation under test.
# Legacy metadata archives use format21/schema147, format22/schema147 remains
# frozen at schema147, formats 23..=24 remain frozen at schema148, formats 25..=26
# remain frozen at schema149, formats 27..=28 remain frozen at schema150, and
# format20 remains frozen at schema144. Formats 29 and 30 remain frozen at
# schema151. Current archives use format31 (metadata + legacy Pando fence) and
# format32 (paired PG + OpenDAL Blob closure) at schema152.
CURRENT_BACKUP_FORMAT = 31
CURRENT_BLOB_BACKUP_FORMAT = 32
CURRENT_SCHEMA_VERSION = 152
assert LATEST_VERSION == CURRENT_SCHEMA_VERSION, (
    "a new migration requires an explicit current backup format/schema contract bump")
FROZEN_FORMAT17_SCHEMA_VERSION = 141
FROZEN_FORMAT18_SCHEMA_VERSION = 142
FROZEN_FORMAT19_SCHEMA_VERSION = 143
# Immutable archive-contract pins for formats 29 (metadata) and 30 (paired
# PG+Blob). Never derive these from CURRENT_*: a later current-format bump must
# not stop proving that the old 29/30 mappings remain schema151.
FROZEN_FORMAT29_SCHEMA_VERSION = 151
FROZEN_FORMAT30_SCHEMA_VERSION = 151

CATALOG_SQL_PATH = SCHEMA_DIR / f"{LATEST_PREFIX}_catalog.sql"
CATALOG_JSON_PATH = SCHEMA_DIR / f"{LATEST_PREFIX}_catalog.json"
RESTORED_CATALOG_JSON_PATH = SCHEMA_DIR / f"{LATEST_PREFIX}_restored_catalog.json"
UPGRADED_CATALOG_JSON_PATH = SCHEMA_DIR / f"{LATEST_PREFIX}_upgraded_catalog.json"


def catalog_tables(version):
    """Regular public tables in one generated catalog, never a guessed list.

    The catalog is produced only by the root runner from a real PostgreSQL
    migration/restore/upgrade; a missing fixture is an explicit failure, not an
    invitation to invent the expected table names.
    """
    path = SCHEMA_DIR / f"{version:03d}_catalog.json"
    try:
        catalog = json.loads(path.read_text())
    except OSError as error:
        raise AssertionError(
            "catalog " + str(path) + " is unavailable; the root runner must "
            "generate it from settled PostgreSQL: " + str(error))
    tables = catalog.get("tables")
    assert isinstance(tables, list), str(path) + " has no tables list"
    return {entry["name"] for entry in tables if entry.get("kind") == "r"}


def schema_delta(version):
    """Exact catalog delta introduced by one settled migration."""
    return tuple(sorted(catalog_tables(version) - catalog_tables(version - 1)))


EXPECTED_TABLES = catalog_tables(LATEST_VERSION)
TABLE_COUNT = len(EXPECTED_TABLES)

# A5a/migration-143 binding/history/permanent-usage tables, derived from the
# generated 143-vs-142 catalogs. A4 fixtures populate only the six migration-142
# tables; no older fixture may fabricate an A5 snapshot-pack row.
A5_PACK_SNAPSHOT_TABLES = schema_delta(143)


def backup_format_arm(format):
    """Match a complete decimal Rust pattern arm, including shared catalogs."""
    return rf"\n\s*(?:\d+\s*\|\s*)*{format}(?:\s*\|\s*\d+)*\s*=>"


def backup_schema_versions(catalog_source, format, versions=SCHEMA_VERSIONS):
    """Evaluate the catalog's full or version-capped roster against a supplied migration list."""
    arm = re.search(
        backup_format_arm(format) + r"\s*Ok\(crate::db::SCHEMA_VERSIONS"
        r"(?:\.to_vec\(\)|\.iter\(\)\.copied\(\)\.filter\(\|version\| \*version <= (\d+)\)\.collect\(\))\)",
        catalog_source,
    )
    if arm is None:
        raise AssertionError(f"missing schema version roster for backup format {format}")
    ceiling = arm.group(1)
    if ceiling is None:
        return list(versions)
    return [version for version in versions if version <= int(ceiling)]
