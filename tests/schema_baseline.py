"""Canonical schema baseline derived from migrations/ and schema/ fixtures.

Centralizes version lists, table sets, and catalog paths so parallel tracks
adding new migrations do not cause cross-suite test conflicts.
"""
import json
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
# The current archive is format21/schema147. Old format20 remains frozen at
# schema144; current fixtures are generated from actual PostgreSQL.
CURRENT_BACKUP_FORMAT = 21
CURRENT_SCHEMA_VERSION = 147
assert LATEST_VERSION == CURRENT_SCHEMA_VERSION, (
    "a new migration requires an explicit current backup format/schema contract bump")
FROZEN_FORMAT17_SCHEMA_VERSION = 141
FROZEN_FORMAT18_SCHEMA_VERSION = 142
FROZEN_FORMAT19_SCHEMA_VERSION = 143

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
