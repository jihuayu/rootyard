#!/usr/bin/env python3
"""Issue #169 fixture support for the format22 paired backup drill.

Static/offline module: it imports only the standard library, so every plan can
be unit-tested without a binary, PostgreSQL, S3 or boto3 (the harness imports
boto3 lazily only when it actually reads objects).

Three independent pieces live here:

* :func:`format22_manifest_checks` -- the positive expectations for one
  format22 paired archive built from API-created ``pg_refstore`` repositories
  with a non-empty active + released retained-root set and a producer owner
  distinct from the repository tenant. It reads only the public manifest
  surface (repositories, pack closure, files, refstore carry, blob artifacts).
* :class:`CorruptionCase`/:func:`corruption_plan` -- the dedicated raw-SQL
  source corruption negative cases. Each case is applied only inside its own
  throw-away ``pg_dump`` clone of the API-produced base source, so a corrupted
  source can never be read by a later case.
* :class:`NativeFixtureRequest` + :func:`native_fixture_argv` and
  :func:`native_marker_checks` -- the contract of the source-bound Rust helper
  (``tests/ref_store_format22_backup_fixture.rs``) that creates the real
  PostgreSQL/Blob repository, packs, snapshots and roots through production
  APIs, and the checks the Python drill applies to the helper's seed marker.

The artifact-set digest (``core-pack-artifact-set-v2``) is rebuilt here with the
same canonical field encoding as ``ArtifactSetDigest::of`` so the "wrong digest"
negative case changes exactly the stored digest column and nothing else.
"""
import hashlib
import json
from pathlib import Path
import re

ARTIFACT_SET_DOMAIN = "core-pack-artifact-set-v2"
ROOT_STATES = ("active", "released")
# Roles a registration must carry exactly once each, in the canonical slots.
PAIR_ROLES = (("pack", 0), ("idx", 1))
TABLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UUID_HEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MARKER_KIND = "rootyard/format22-backup-fixture-seed"
CORRUPTION_CASES = ("missing_pack", "missing_idx", "missing_all_artifacts", "wrong_artifact_set_digest")


def need(condition, message):
    if not condition:
        raise AssertionError(message)


def parse_columns(value):
    """Stable jsonb columns of one artifact set row."""
    if isinstance(value, str):
        value = json.loads(value)
    need(isinstance(value, dict), "artifact set columns are not a JSON object")
    return value


def _field(name, length=None):
    """Length-prefixed canonical field (``length`` is recomputed/verified, so a
    caller can never mismatch the prefix with the payload)."""
    payload = name.encode() if isinstance(name, str) else bytes(name)
    if length is not None:
        need(length == len(payload), "canonical field length mismatch")
    return len(payload).to_bytes(8, "big") + payload


def _int(value, bits=64):
    return int(value).to_bytes(bits, "big", signed=False)


def artifact_set_digest(columns):
    """Exact rebuild of ``ArtifactSetDigest::of`` over stored jsonb columns.

    ``columns`` is either one artifact row or a list of them; each row carries
    ``role``, ``slot``, ``hold_id``, ``tenant_id``, ``authority_id``,
    ``authority_generation``, ``attempt_id``, ``namespace``, ``sha256``,
    ``content_length``, ``provider``, ``backend_identity``. Artifacts are
    sorted on their canonical ``RegisteredArtifact`` derivation, which is
    equivariant under the row order, so a stable sort reproduces the Rust sort.
    """
    rows = columns if isinstance(columns, list) else [columns]
    keyed = []
    for row in rows:
        row = parse_columns(row)
        canonical = (
            str(row["role"]), int(row["slot"]), str(row["hold_id"]), str(row["tenant_id"]),
            str(row["authority_id"]), int(row["authority_generation"]), str(row["attempt_id"]),
            str(row["namespace"]), str(row["sha256"]), int(row["content_length"]), str(row["provider"]),
            str(row["backend_identity"]),
        )
        keyed.append((canonical, row))
    keyed.sort(key=lambda item: item[0])
    fields = [_int(len(keyed))]
    for _, row in keyed:
        fields.extend((
            _field(row["role"]), _int(row["slot"], 4),
            _field(bytes.fromhex(str(row["hold_id"]).replace("-", ""))),
            _field(bytes.fromhex(str(row["tenant_id"]).replace("-", ""))),
            _field(bytes.fromhex(str(row["authority_id"]).replace("-", ""))),
            _int(row["authority_generation"]),
            _field(bytes.fromhex(str(row["attempt_id"]).replace("-", ""))),
            _field(row["namespace"]),
            _field(row["sha256"]),
            _int(row["content_length"]),
            _field(row["provider"]),
            _field(row["backend_identity"]),
            _field(row["sha256"]),
            _int(row["content_length"]),
        ))
    digest = hashlib.sha256()
    digest.update(b"rootyard-ref-store-request-v1\0")
    digest.update(_field(ARTIFACT_SET_DOMAIN))
    for field in fields:
        digest.update(_field(field))
    return digest.hexdigest()


def q(value):
    """Single-quoted SQL literal (fixture values are generated identifiers)."""
    text = str(value)
    need("'" not in text and "\x00" not in text, "SQL literal refused")
    return "'" + text + "'"


def uuid_array(values):
    return "ARRAY[" + ",".join(q(value) + "::uuid" for value in values) + "]::uuid[]" if values else "'{}'::uuid[]"


def text_array(values):
    return "ARRAY[" + ",".join(q(value) for value in values) + "]::text[]" if values else "'{}'::text[]"


# ---------------------------------------------------------------------------
# Positive format22 manifest expectations
# ---------------------------------------------------------------------------
_CARRY_TABLES = (
    "ref_store_core_pack_publications", "ref_store_core_pack_artifacts", "ref_store_core_pack_memberships",
    "ref_store_core_root_heads", "ref_store_core_roots", "ref_store_core_root_packs", "ref_store_core_root_refs",
    "ref_store_core_root_receipts", "ref_store_core_snapshot_packs", "ref_store_core_pins",
)


def format22_manifest_checks(manifest, expected):
    """Return a detail dict or raise AssertionError for a non-format22 archive.

    ``expected`` carries the API-created identities: ``format`` (22),
    ``schema_versions``, ``registered_packs`` (registrations the source holds),
    ``artifacts`` (pack + idx rows), ``roots`` (``[{root_id, state, owner_id}]``
    with at least one active and one released root), ``repos``
    (``[{id, owner_id, tenant_id}]``) and ``producer`` (the owner of every root
    capture). ``manifest`` is the parsed archive manifest.
    """
    need(manifest.get("format") == 22 == expected["format"], "archive is not format22")
    need(manifest.get("schema_versions") == list(expected["schema_versions"]) == [147], "unexpected schema versions")
    repos = manifest.get("repositories") or []
    need(len(repos) == len(expected["repos"]), "manifest repository count differs from the API-created set")
    need({str(repo["id"]) for repo in repos} == {str(repo["id"]) for repo in expected["repos"]},
         "manifest repositories are not exactly the API-created repositories")
    need(all(repo.get("backend") == "pg_refstore" for repo in repos), "a manifest repository is not pg_refstore")
    closure = manifest.get("blob_closure") or {}
    artifacts = manifest.get("blob_artifacts") or []
    need(closure.get("artifacts") == expected["artifacts"] == len(artifacts),
         "closure artifact count differs from the registered pack + idx rows")
    registrations = {str(entry["registration_id"]) for entry in artifacts}
    need(registrations == {str(value) for value in expected["registered_packs"]},
         "closure does not carry exactly one pack+idx pair per registered pack")
    for registration in expected["registered_packs"]:
        roles = sorted((str(entry["role"]), int(entry["slot"])) for entry in artifacts
                       if str(entry["registration_id"]) == str(registration))
        need(roles == sorted(PAIR_ROLES), "a registration is not exactly one pack(slot 0) + idx(slot 1)")
    need(len({str(entry["hold_id"]) for entry in artifacts}) == len(artifacts), "artifact hold ids are not unique")
    need(all(HEX64.match(str(entry["sha256"])) and int(entry["content_length"]) > 0 for entry in artifacts),
         "an archived artifact has no positive byte proof")
    need(all(str(entry["provider"]) == closure.get("provider") for entry in artifacts),
         "an archived artifact names another provider")
    need(all(str(entry["backend_identity"]) == closure.get("backend_identity") for entry in artifacts),
         "an archived artifact names another backend identity")
    blob_files = [name for name, entry in manifest["files"].items()
                  if name.startswith("blob/") and entry["kind"] == "file"]
    need(len(blob_files) == len(artifacts), "archived blob members differ from the closure")
    need(sum(manifest["files"][name]["bytes"] for name in blob_files) == closure.get("bytes") > 0,
         "archived blob bytes differ from the closure")
    # RefStore carry: every registered-set and roots ledger must travel too.
    carry = manifest.get("refstore") or {}
    for table in _CARRY_TABLES:
        need(int(carry.get(table, {}).get("rows", 0)) > 0, "archive carry is missing " + table)
    # Positive roots: non-empty active AND released API-created roots.
    states = [str(root["state"]) for root in expected["roots"]]
    for state in ROOT_STATES:
        need(states.count(state) >= 1, "positive format22 archive needs a non-empty " + state + " root set")
    need(len({str(root["root_id"]) for root in expected["roots"]}) == len(expected["roots"]),
         "root ids are not unique")
    # Producer owner (root owner_id / pack hold owner_id) is never the tenant.
    tenants = {str(repo["owner_id"]) for repo in expected["repos"]}
    need(str(expected["producer"]) not in tenants, "the root producer equals a repository tenant")
    need(all(str(root.get("owner_id")) == str(expected["producer"]) for root in expected["roots"]),
         "root captures disagree on their producer owner")
    return {"format": 22, "repositories": len(repos), "closure_artifacts": len(artifacts),
            "registrations": len(registrations), "roots": {state: states.count(state) for state in ROOT_STATES},
            "producer_distinct_from_tenant": True, "carry_tables": len(carry)}


# ---------------------------------------------------------------------------
# Corruption negatives (dedicated owned database copy per case)
# ---------------------------------------------------------------------------
class CorruptionCase:
    """One privileged raw-SQL source corruption and the rows it must break.

    ``statement`` is a single DML statement that only removes rows or changes
    the stored artifact-set digest; it never touches a column the pack tables
    guard with CHECK constraints, so the corruption is the logical damage of
    issue #169 and nothing else.
    """

    def __init__(self, name, statement, broken_rows, requires=()):
        need(TABLE_NAME.match(name), "corruption case name is not a table-safe token")
        self.name = name
        self.statement = statement
        self.broken_rows = tuple(broken_rows)
        self.requires = tuple(requires)

    def fingerprint_tables(self):
        return sorted({*self.broken_rows, *self.requires})

    def __repr__(self):
        return "CorruptionCase(" + self.name + ")"


def _registration(value):
    need(isinstance(value, str) and UUID_HEX.match(value), "registration id is not a uuid")
    return q(value) + "::uuid"


def missing_pack(registration):
    registration = _registration(registration)
    return CorruptionCase(
        "missing_pack",
        "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id="
        + registration + " AND role='pack'",
        ("ref_store_core_pack_artifacts",), ("ref_store_core_pack_memberships",))


def missing_idx(registration):
    registration = _registration(registration)
    return CorruptionCase(
        "missing_idx",
        "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id="
        + registration + " AND role='idx'",
        ("ref_store_core_pack_artifacts",), ("ref_store_core_pack_memberships",))


def missing_all(registration):
    registration = _registration(registration)
    return CorruptionCase(
        "missing_all_artifacts",
        "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id=" + registration,
        ("ref_store_core_pack_artifacts",), ("ref_store_core_pack_memberships",))


def wrong_digest(registration, value):
    registration = _registration(registration)
    need(isinstance(value, str) and HEX64.match(value) and value != "0" * 64,
         "wrong-digest value must be a non-zero sha256")
    return CorruptionCase(
        "wrong_artifact_set_digest",
        "UPDATE public.ref_store_core_pack_publications SET artifact_set_digest=" + q(value)
        + " WHERE registration_id=" + registration + " AND artifact_set_digest<>" + q(value),
        ("ref_store_core_pack_publications",), ("ref_store_core_pack_artifacts", "ref_store_core_pack_memberships"))


# The four acceptance negatives of issue #169. ``registration`` and ``value``
# come from the API-produced base source (see ``corruption_plan``).
BUILDERS = {"missing_pack": missing_pack, "missing_idx": missing_idx,
            "missing_all_artifacts": missing_all, "wrong_artifact_set_digest": wrong_digest}


def corruption_plan(registered, retainable):
    """Build the four cases from API-produced rows.

    ``registered`` is every registration id (all with both artifacts);
    ``retainable`` is the subset whose registration is still declared by a
    root, snapshot or serving read, so dropping its artifacts must not silently
    shrink the archived set. All four cases use the same retained registration
    (the first one in sorted order), so the missing-pack case and the missing-idx
    case differ only in the removed role.
    """
    registered = [str(value) for value in registered]
    retainable = sorted({str(value) for value in retainable} & set(registered))
    need(len(registered) >= 2, "the base source needs at least two registered packs")
    need(retainable, "no registered pack is retained by a root/snapshot/read lease")
    target = retainable[0]
    value = hashlib.sha256(("wrong-digest:" + target).encode()).hexdigest()
    return [wrong_digest(target, value) if name == "wrong_artifact_set_digest" else BUILDERS[name](target)
            for name in CORRUPTION_CASES]


# ---------------------------------------------------------------------------
# Native fixture helper contract
# ---------------------------------------------------------------------------
class NativeFixtureRequest:
    """Invocation of ``tests/ref_store_format22_backup_fixture.rs`` in seed mode."""

    def __init__(self, binary, database_url, git, seed, data_dir, blob_root):
        self.binary = Path(binary)
        self.database_url = database_url
        self.git = Path(git)
        self.seed = Path(seed)
        self.data_dir = Path(data_dir)
        self.blob_root = blob_root

    def argv(self, env=None):
        return native_fixture_argv(self.binary, self.seed, self.data_dir, self.blob_root, self.git, env)

    def env(self, base):
        return {key: value for key, value in base.items() if key != "ROOTYARD_BLOB_ROOT"}


def native_fixture_argv(binary, seed, data_dir, blob_root, git, env=None):
    """Deterministic argv; real absolute paths only and no credential in argv."""
    seed, data_dir, git = Path(seed), Path(data_dir), Path(git)
    need(seed.is_absolute() and data_dir.is_absolute() and git.is_absolute(), "fixture paths must be absolute")
    need(blob_root and not str(blob_root).startswith("/") and ".." not in str(blob_root).split("/"),
         "ROOTYARD_BLOB_ROOT must be a relative run-owned prefix")
    return [str(binary), "--seed", str(seed), "--data-dir", str(data_dir), "--git", str(git),
            "--blob-root", str(blob_root)]


_FORBIDDEN_MARKER_TEXT = ("postgres://", "postgresql://", "ryt_", "SECRET_ACCESS_KEY", "ACCESS_KEY_ID", "password")


def native_marker_checks(marker):
    """Validate the helper's seed marker and return the expected-positive set.

    The marker must never carry a DSN, token or S3 credential: only ids,
    digests, counts and states.
    """
    need(marker.get("kind") == MARKER_KIND, "native fixture marker has another kind")
    need(marker.get("format") == 22, "native fixture is not a format22 source")
    text = json.dumps(marker, sort_keys=True)
    for forbidden in _FORBIDDEN_MARKER_TEXT:
        need(forbidden not in text, "native fixture marker leaks " + forbidden)
    repos = marker.get("repositories") or []
    need(len(repos) >= 2, "native fixture must create at least two API repositories")
    producer = str(marker.get("producer_owner_id", ""))
    tenants = {str(repo["owner_id"]) for repo in repos}
    need(producer and producer not in tenants, "the fixture producer owner must differ from every repository tenant")
    for repo in repos:
        need(repo.get("state") == "ready" and repo.get("storage_backend") == "pg_refstore",
             "an API-created repository is not ready pg_refstore")
    registrations = marker.get("registrations") or []
    need(len(registrations) >= 2, "the fixture needs at least two registered packs")
    for registration in registrations:
        need(sorted(registration.get("roles") or []) == ["idx", "pack"], "a registration is not a pack+idx pair")
        need(HEX64.match(str(registration.get("artifact_set_digest") or "x")), "a registration has no set digest")
    roots = marker.get("roots") or []
    states = [str(root.get("state")) for root in roots]
    need(states.count("active") >= 1 and states.count("released") >= 1,
         "the fixture needs non-empty active and released roots")
    need({str(root.get("tenant_id")) for root in roots} <= tenants,
         "a root capture names a tenant that does not own an API-created repository")
    need(all(str(root.get("owner_id")) == producer for root in roots), "root captures disagree on their producer owner")
    return {"repositories": len(repos), "registrations": len(registrations),
            "roots": {state: states.count(state) for state in ROOT_STATES},
            "producer_distinct_from_tenant": True}
