#!/usr/bin/env python3
"""Issue #169 fixture support for the format22 paired backup drill.

Static/offline module: it imports only the standard library, so every plan can
be unit-tested without a binary, PostgreSQL, S3 or boto3 (the harness imports
boto3 lazily only when it actually reads objects).

Three independent pieces live here:

* :func:`format22_manifest_checks` -- the positive expectations for one
  format22 paired archive built from API-created ``pg_refstore`` repositories
  with a non-empty active + released retained-root set, a producer owner
  distinct from the repository tenant, and one nonempty transient serving read
  owned by a third real requester. It reads only the public manifest
  surface (repositories, pack closure, files, refstore carry, blob artifacts).
* :class:`CorruptionCase`/:func:`corruption_plan` and :func:`corruption_sql`/
  :func:`corruption_findings`/:func:`validator_refusal` -- the dedicated raw-SQL
  source corruption negatives. Each case is applied by one clone-local,
  explicitly privileged transaction inside its own throw-away ``pg_dump`` clone
  of the API-produced base source, the clone must prove exactly the intended
  row changed, and the backup may refuse only with that case's precise
  source-ledger violation.
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
import types

ARTIFACT_SET_DOMAIN = "core-pack-artifact-set-v2"
ROOT_STATES = ("active", "released")
# Roles a registration must carry exactly once each, in the canonical slots.
PAIR_ROLES = (("pack", 0), ("idx", 1))
TABLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UUID_HEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TARGET_LITERAL = re.compile(r"^'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'::uuid$")
MARKER_KIND = "rootyard/format22-backup-fixture-seed"
CORRUPTION_CASES = ("missing_pack", "missing_idx", "missing_all_artifacts", "wrong_artifact_set_digest")
# The declared-set sources of ledger_validation::DECLARED_SETS.
DECLARED_SOURCES = ("membership", "snapshot_packs", "root_packs", "serving_read_packs")


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
    "ref_store_core_root_receipts", "ref_store_core_root_oids", "ref_store_core_root_tombstones",
    "ref_store_core_snapshot_packs", "ref_store_core_pins",
    # Migration-146 transient serving reads: the header and all three of its
    # children of the one nonempty `serving_read` marker.
    "ref_store_core_serving_reads", "ref_store_core_serving_read_refs",
    "ref_store_core_serving_read_packs", "ref_store_core_serving_read_artifacts",
)


def format22_manifest_checks(manifest, expected):
    """Return a detail dict or raise AssertionError for a non-format22 archive.

    ``expected`` carries the API-created identities: ``format`` (22),
    ``schema_versions``, ``registered_packs`` (registrations the source holds),
    ``artifacts`` (pack + idx rows), ``roots`` (``[{root_id, state, owner_id}]``
    with at least one active and one released root), ``repos``
    (``[{id, owner_id, tenant_id}]``), ``producer`` (the owner of every root
    capture) and ``serving_read`` (the validated ``markers["serving_read"]``
    entry of :func:`native_marker_checks`). ``manifest`` is the parsed archive
    manifest.
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
    serving_read = _archive_serving_read(expected.get("serving_read"), expected["repos"], tenants,
                                         expected["registered_packs"], expected["producer"])
    return {"format": 22, "repositories": len(repos), "closure_artifacts": len(artifacts),
            "registrations": len(registrations), "roots": {state: states.count(state) for state in ROOT_STATES},
            "producer_distinct_from_tenant": True, "carry_tables": len(carry),
            "serving_read": {key: serving_read[key] for key in ("pin_id", "repository_id", "tenant_id", "owner_id",
                                                                "pack_count")}}


def _archive_serving_read(serving_read, repos, tenants, registrations, producer):
    """The validated marker read, once more bound to this archive's exact set.

    ``serving_read`` is the ``native_marker_checks`` entry (already proven a
    valid nonempty read on the marker's bound repository/tenant with a
    distinct requester). Here it must additionally sit on an archived
    repository whose manifest carries the exact ``repository_id``/``tenant_id``
    binding, keep its nonempty ``pack_count`` equal to the archived
    registrations, and never be owned by a repository tenant or the producer.
    """
    need(isinstance(serving_read, dict), "format22 expectations carry no validated serving_read marker")
    for field in ("pin_id", "repository_id", "tenant_id", "owner_id"):
        need(isinstance(serving_read.get(field), str) and UUID_HEX.match(serving_read[field]),
             "serving_read " + field + " is not a valid uuid")
    pack_count = serving_read.get("pack_count")
    need(isinstance(pack_count, int) and not isinstance(pack_count, bool) and pack_count > 0,
         "serving_read has no nonempty pack count")
    bindings = {str(repo["id"]): (str(repo.get("owner_id")), str(repo.get("tenant_id"))) for repo in repos}
    repo_id = str(serving_read["repository_id"])
    need(repo_id in bindings, "serving_read names a repository the archive does not carry")
    owner, tenant = bindings[repo_id]
    need(str(serving_read["tenant_id"]) in (tenant, owner),
         "serving_read tenant is not the tenant of its archived repository")
    need(pack_count == len(registrations),
         "serving_read pack_count differs from the archived registrations")
    need(str(serving_read["owner_id"]) not in tenants, "serving_read requester is a repository tenant")
    need(str(serving_read["owner_id"]) != str(producer), "serving_read requester is the producer")
    return serving_read


def serving_read_tables(alias="public"):
    """The migration-146 tables one restored serving read must be read from."""
    need(TABLE_NAME.match(alias), "serving-read table alias is not a safe token")
    return {"header": alias + ".ref_store_core_serving_reads", "refs": alias + ".ref_store_core_serving_read_refs",
            "packs": alias + ".ref_store_core_serving_read_packs",
            "artifacts": alias + ".ref_store_core_serving_read_artifacts"}


def format22_restore_sql(serving_read):
    """One bounded, read-only row of restored serving-read facts for ``pin_id``.

    Only counts and booleans are selected: no ref/oid, locator, digest or lease
    value leaves the restored database. Every count is scoped to the exact pin
    or to that pin's own headers/packs, so a second read cannot satisfy it.
    """
    marker = _bound_marker(serving_read)
    pin = q(marker["pin_id"]) + "::uuid"
    repo, tenant, owner = (q(marker[field]) + "::uuid" for field in ("repository_id", "tenant_id", "owner_id"))
    tables = serving_read_tables()
    scope = " AND ".join(column + "=" + value for column, value in
                         (("repository_id", repo), ("tenant_id", tenant), ("owner_id", owner)))
    return (
        "SELECT jsonb_build_object("
        "'headers', (SELECT count(*) FROM " + tables["header"] + " WHERE pin_id=" + pin + "), "
        "'bound_headers', (SELECT count(*) FROM " + tables["header"] + " WHERE pin_id=" + pin + " AND " + scope
        + " AND pack_count=" + str(marker["pack_count"]) + "), "
        "'refs', (SELECT count(*) FROM " + tables["refs"] + " WHERE pin_id=" + pin + "), "
        "'declared_ref_count', (SELECT coalesce(max(ref_count), -1) FROM " + tables["header"]
        + " WHERE pin_id=" + pin + "), "
        "'packs', (SELECT count(*) FROM " + tables["packs"] + " WHERE pin_id=" + pin + "), "
        "'declared_pack_count', (SELECT coalesce(max(pack_count), -1) FROM " + tables["header"]
        + " WHERE pin_id=" + pin + "), "
        # Every one of the pin's pack rows must carry exactly its slot-0 pack
        # and slot-1 idx artifact (and nothing else).
        "'packs_with_exact_pair', (SELECT count(*) FROM " + tables["packs"] + " p WHERE p.pin_id=" + pin
        + " AND (SELECT count(*) FROM " + tables["artifacts"] + " a WHERE a.pin_id=p.pin_id "
          "AND a.pack_id=p.pack_id)=2 AND EXISTS (SELECT 1 FROM " + tables["artifacts"] + " a "
          "WHERE a.pin_id=p.pin_id AND a.pack_id=p.pack_id AND a.role='pack' AND a.slot=0) "
          "AND EXISTS (SELECT 1 FROM " + tables["artifacts"] + " a WHERE a.pin_id=p.pin_id "
          "AND a.pack_id=p.pack_id AND a.role='idx' AND a.slot=1)), "
        # Each pack must carry a verified, nonempty physical identity for both
        # its pack and its idx artifact (migration-146 CHECKs included).
        "'packs_with_verified_pair', (SELECT count(*) FROM " + tables["packs"] + " p WHERE p.pin_id=" + pin
        + " AND (SELECT count(*) FROM " + tables["artifacts"] + " a WHERE a.pin_id=p.pin_id "
          "AND a.pack_id=p.pack_id AND a.verified_sha256=a.locator_sha256 "
          "AND a.verified_length=a.locator_length AND a.verified_length>0)=2), "
        "'artifacts', (SELECT count(*) FROM " + tables["artifacts"] + " WHERE pin_id=" + pin + "))")
    # Only counts/booleans leave the restored database; sha256 values are
    # compared inside SQL and never selected.


def _bound_marker(serving_read):
    need(isinstance(serving_read, dict), "format22 checks need the validated serving_read marker")
    need(set(serving_read) >= {"pin_id", "repository_id", "tenant_id", "owner_id", "pack_count"},
         "serving_read marker is incomplete")
    for field in ("pin_id", "repository_id", "tenant_id", "owner_id"):
        need(isinstance(serving_read[field], str) and UUID_HEX.match(serving_read[field]),
             "serving_read " + field + " is not a valid uuid")
    count = serving_read["pack_count"]
    need(isinstance(count, int) and not isinstance(count, bool) and count > 0,
         "serving_read has no nonempty pack count")
    return serving_read


def format22_serving_read_checks(observed, serving_read):
    """Prove the restored database carries exactly the marker's serving read.

    ``observed`` is the JSON object :func:`format22_restore_sql` selected and
    ``serving_read`` the validated ``markers["serving_read"]`` entry. Only
    bounded counts/booleans are recorded, never a secret or a locator.
    """
    marker = _bound_marker(serving_read)
    try:
        observed = json.loads(observed) if isinstance(observed, (str, bytes)) else observed
    except ValueError as error:
        raise AssertionError("restored serving-read facts are not JSON: " + str(error)) from None
    need(isinstance(observed, dict), "restored serving-read facts are not a JSON object")
    need(set(observed) == {"headers", "bound_headers", "refs", "declared_ref_count", "packs",
                           "declared_pack_count", "packs_with_exact_pair", "packs_with_verified_pair",
                           "artifacts"}, "restored serving-read facts carry unexpected fields")
    for name, value in observed.items():
        need(isinstance(value, int) and not isinstance(value, bool), "restored serving-read " + name + " is not an int")
    count = marker["pack_count"]
    need(observed["headers"] == 1, "the restored database does not carry exactly one marker serving-read header")
    need(observed["bound_headers"] == 1,
         "the restored serving read is not bound to the marker repository/tenant/requester and pack_count")
    need(observed["declared_ref_count"] >= 0 and observed["refs"] == observed["declared_ref_count"],
         "restored serving-read ref rows differ from the header's declared ref_count")
    need(observed["declared_pack_count"] == count == observed["packs"],
         "restored serving-read pack rows differ from the marker pack_count")
    need(observed["packs_with_exact_pair"] == count,
         "a restored serving-read pack lacks exactly one slot-0 pack and slot-1 idx artifact")
    need(observed["artifacts"] == 2 * count, "restored serving-read artifacts are not exactly 2 * pack_count")
    need(observed["packs_with_verified_pair"] == count,
         "a restored serving-read pack lacks a verified nonempty pack/id x artifact pair")
    return {"pin": True, "headers": 1, "refs_equal_declared": True, "pack_count": observed["declared_pack_count"],
            "packs": count, "packs_with_exact_pair": count, "artifacts": observed["artifacts"],
            "verified_pairs": count}


# ---------------------------------------------------------------------------
# Corruption negatives (one dedicated, disposable clone per case)
# ---------------------------------------------------------------------------
def _uuid(value, what):
    need(isinstance(value, str) and UUID_HEX.match(value), what + " is not a uuid")
    return value


class Registration:
    """One complete A4 registration with its actual repository/pack identity.

    ``repository_id``/``pack_id`` are the native SQL target's own
    ``ref_store_core_pack_publications`` values; they are required and never
    derived, because the validator names all three ids in every violation.
    """

    def __init__(self, value, digest, repository_id, pack_id):
        self.id = _uuid(value, "registration id")
        need(isinstance(digest, str) and HEX64.match(digest), "registration digest is not a sha256")
        self.digest = digest
        self.repository_id = _uuid(repository_id, "repository id")
        self.pack_id = _uuid(pack_id, "pack id")

    def scope(self):
        return (self.repository_id, self.pack_id, self.id)

    def __repr__(self):
        return "Registration(" + self.id + ")"


class ValidatorRefusal:
    """The source-ledger violations an expected corrupted source must yield.

    ``ledger_sets::check_declared`` emits ``<token>:<repository_id>:<pack_id>:
    <registration_id>`` as plain violation tokens (no digest details): every
    damaged A4 set is ``canonical_pair_mismatch``, one missing role is
    ``incomplete_pair``, no artifact rows is ``missing_artifacts``, and a
    rewritten publication digest is ``declared_set_digest_mismatch:<source>:
    <repository_id>:<pack_id>:<registration_id>`` for each declaring set kind.
    The snapshot/root/serving-read rechecks of that same registration may add
    only the dependent tokens below.
    """

    def __init__(self, cause, source=None):
        need(cause in CORRUPTION_CASES, "validator refusal has an unknown cause")
        need(source is None or (cause == "wrong_artifact_set_digest" and source in DECLARED_SOURCES),
             "only a rewritten digest names a declared-set source")
        self.cause = cause
        # Representative declared-set source for one concrete expected line; the
        # oracle itself accepts any of DECLARED_SOURCES that the product emits.
        self.source = source

    @property
    def token(self):
        """The cause-specific token that distinguishes this case."""
        return self.required[1]

    @property
    def required(self):
        """The violations every refusal carries; the last one names the cause."""
        return ("canonical_pair_mismatch", {"missing_pack": "incomplete_pair", "missing_idx": "incomplete_pair",
                                            "missing_all_artifacts": "missing_artifacts",
                                            "wrong_artifact_set_digest": "declared_set_digest_mismatch"}[self.cause])

    def violation(self, registration):
        """The first required violation for ``registration``'s actual ids."""
        return ":".join((self.required[0], *registration.scope()))

    def declared_source(self, registration):
        """The exact ``declared_set_digest_mismatch`` this case expects."""
        need(self.source is not None, "refusal has no declared-set source")
        return ":".join((self.required[1], self.source, *registration.scope()))

    def cause_violation(self, registration):
        """The exact cause-specific violation for ``registration``."""
        return (self.declared_source(registration) if self.source is not None
                else ":".join((self.required[1], *registration.scope())))

    def __repr__(self):
        return "ValidatorRefusal(" + self.cause + ("," + self.source if self.source else "") + ")"


class CorruptionCase:
    """One privileged raw-SQL source corruption and the rows it must break.

    ``statement`` is a single DML statement that only removes rows or changes
    the stored artifact-set digest; it never touches a column the pack tables
    guard with CHECK constraints, so the corruption is the logical damage of
    issue #169 and nothing else. A planned case also carries the registration
    it damages, the single-row target the clone must prove changed, and the
    source-ledger violation the backup must refuse with.
    """

    def __init__(self, name, statement, broken_rows, requires=(), registration=None, wrong_value=None,
                 refusal=None):
        need(TABLE_NAME.match(name), "corruption case name is not a table-safe token")
        self.name = name
        self.statement = statement
        self.broken_rows = tuple(broken_rows)
        self.requires = tuple(requires)
        self.registration = registration
        self.wrong_value = wrong_value
        self.refusal = refusal

    @property
    def planned(self):
        """A planned positive-row case: the clone must prove one changed row."""
        return self.registration is not None and self.refusal is not None

    @property
    def targets_digest(self):
        return self.statement.startswith("UPDATE ")

    def fingerprint_tables(self):
        return sorted({*self.broken_rows, *self.requires})

    def __repr__(self):
        return "CorruptionCase(" + self.name + ")"


def _registration(value):
    need(isinstance(value, str) and UUID_HEX.match(value), "registration id is not a uuid")
    return q(value) + "::uuid"


def missing_pack(registration):
    registration = _registration(registration)
    return CorruptionCase("missing_pack",
                 "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id="
                 + registration + " AND role='pack'",
                 ("ref_store_core_pack_artifacts",), ("ref_store_core_pack_memberships",))


def missing_idx(registration):
    registration = _registration(registration)
    return CorruptionCase("missing_idx",
                 "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id="
                 + registration + " AND role='idx'",
                 ("ref_store_core_pack_artifacts",), ("ref_store_core_pack_memberships",))


def missing_all(registration):
    registration = _registration(registration)
    return CorruptionCase("missing_all_artifacts",
                 "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id=" + registration,
                 ("ref_store_core_pack_artifacts",), ("ref_store_core_pack_memberships",))


def wrong_digest(registration, value):
    registration = _registration(registration)
    need(isinstance(value, str) and HEX64.match(value) and value != "0" * 64,
         "wrong-digest value must be a non-zero sha256")
    return CorruptionCase("wrong_artifact_set_digest",
                 "UPDATE public.ref_store_core_pack_publications SET artifact_set_digest=" + q(value)
                 + " WHERE registration_id=" + registration + " AND artifact_set_digest<>" + q(value),
                 ("ref_store_core_pack_publications",), ("ref_store_core_pack_artifacts",
                                                         "ref_store_core_pack_memberships"))


# The four acceptance negatives of issue #169 and the source-ledger violations
# each produces once a complete API registration is damaged exactly that way
# (ledger_sets::check_declared).
BUILDERS = {"missing_pack": missing_pack, "missing_idx": missing_idx,
            "missing_all_artifacts": missing_all, "wrong_artifact_set_digest": wrong_digest}
# A missing artifact is still declared by the pair check (canonical_pair_mismatch)
# plus its own cause token; a rewritten stored digest keeps every declaring set
# row, so each kind that still holds the old digest reports
# declared_set_digest_mismatch with its source. ``membership`` is the
# representative source used for one concrete expected line; the oracle accepts
# any of DECLARED_SOURCES that the product actually emits.
REFUSALS = {
    "missing_pack": ValidatorRefusal("missing_pack"),
    "missing_idx": ValidatorRefusal("missing_idx"),
    "missing_all_artifacts": ValidatorRefusal("missing_all_artifacts"),
    "wrong_artifact_set_digest": ValidatorRefusal("wrong_artifact_set_digest", DECLARED_SOURCES[0]),
}


def wrong_digest_value(registration):
    return hashlib.sha256(("wrong-digest:" + str(registration)).encode()).hexdigest()


def _stored_digest(pairs, digests, target):
    """The one stored digest of an intact pair, or ``None`` when not intact.

    Both facts are required: a registration without its complete recorded pair
    or without its recorded digests cannot be the target (the harness always
    passes both from the API source).
    """
    if pairs is None or digests is None:
        return None
    if {str(role) for role in pairs.get(target, ())} != {role for role, _ in PAIR_ROLES}:
        return None
    values = {str(value) for value in digests.get(target, ())}
    # A stored and a declared digest that disagree is already a damaged source.
    return values.pop() if len(values) == 1 and all(HEX64.match(value) for value in values) else None


def _actual_scope(scopes, target):
    """The ``(repository_id, pack_id)`` the native SQL holds for ``target``."""
    need(isinstance(scopes, dict), "the actual repository/pack scopes are required")
    scope = scopes.get(target)
    need(isinstance(scope, (tuple, list)) and len(scope) == 2, "no actual repository/pack scope for " + target)
    return _uuid(scope[0], "actual repository id"), _uuid(scope[1], "actual pack id")


def corruption_plan(registered, retainable, scopes, pairs=None, digests=None):
    """Pick the one retained registration all four cases damage.

    ``registered`` is every registration id; ``retainable`` is the subset a
    root, snapshot or serving read still declares, so dropping its artifacts
    must not silently shrink the archived set. ``scopes`` maps every
    registration to the actual ``(repository_id, pack_id)`` of its
    ``ref_store_core_pack_publications`` row; it is required and is never
    derived from the registration id. ``pairs`` maps a registration to the
    roles it still carries and ``digests`` to the digests its A4 and declaring
    rows hold (when provided, an earlier case that already damaged a
    registration makes it ineligible). The first intact retained registration in
    sorted order is used, so the cases differ only in the removed role or in
    the stored digest. Without both ``pairs`` and ``digests`` no registration can
    be proven intact and the plan is refused.
    """
    registered = [str(value) for value in registered]
    retainable = sorted({str(value) for value in retainable} & set(registered))
    need(len(registered) >= 2, "the base source needs at least two registered packs")
    need(retainable, "no registered pack is retained by a root/snapshot/read lease")
    for target in retainable:
        stored = _stored_digest(pairs, digests, target)
        value = wrong_digest_value(target)
        if stored is None or value == stored:
            continue
        repository_id, pack_id = _actual_scope(scopes, target)
        registration = Registration(target, stored, repository_id, pack_id)
        return [_planned(name, registration, target, value) for name in CORRUPTION_CASES]
    raise AssertionError("no retained registered pack still carries an intact pack+idx pair and digest")


def _planned(name, registration, target, value):
    """One case statement bound to the actual ids of ``registration``."""
    plan = wrong_digest(target, value) if name == "wrong_artifact_set_digest" else BUILDERS[name](target)
    return CorruptionCase(plan.name, plan.statement, plan.broken_rows, plan.requires,
                          registration=registration,
                          wrong_value=value if plan.name == "wrong_artifact_set_digest" else None,
                          refusal=REFUSALS[plan.name])


def finding(case):
    """The one artifact field the case removes or rewrites."""
    if case.targets_digest:
        return "publication:artifact_set_digest"
    return "artifact:" + (registration_role(case.statement) or "pack+idx")


def registration_role(statement):
    """The artifact role a missing-artifact statement removes; ``None`` for all."""
    if "role='pack'" in statement:
        return "pack"
    if "role='idx'" in statement:
        return "idx"
    return None


# ``rowcount`` of the single DML statement, echoed last by ``corruption_sql``.
CHANGED = "corruption_changed"
# The only facts a corruption statement may change: the A4 artifact rows it
# deletes and the stored publication digest it rewrites.
AFTER_TABLES = ("ref_store_core_pack_artifacts", "ref_store_core_pack_publications")
# Facts the corruption statement itself must never touch (migration 142 guards).
GUARDED_TABLES = ("ref_store_core_pack_memberships", "ref_store_core_pack_history",
                  "ref_store_core_pack_repo_usage", "ref_store_core_pack_tenant_usage")
# Migration-142 immutability guards (row and statement forms). They must exist
# and stay enabled in the clone; the corruption never disables them.
IMMUTABLE_TRIGGERS = tuple(
    table + suffix
    for table in ("ref_store_core_pack_publications", "ref_store_core_pack_artifacts",
                  "ref_store_core_pack_memberships", "ref_store_core_pack_history")
    for suffix in ("_immutable", "_no_truncate")) + tuple(
    table + suffix
    for table in ("ref_store_core_pack_repo_usage", "ref_store_core_pack_tenant_usage")
    for suffix in ("_no_delete", "_no_truncate"))


def _fact_sql(tables, exclude=None):
    """One md5 per table over every row, or every row but ``exclude``.

    ``exclude`` is the quoted uuid literal of the target registration whose
    rows the case is meant to change: those rows are captured separately by
    ``_target_sql`` so the before/after facts prove nothing else moved.
    """
    need(exclude is None or (isinstance(exclude, str) and TARGET_LITERAL.fullmatch(exclude)),
         "a target exclusion must be one quoted uuid literal")
    return "jsonb_build_object(" + ", ".join(
        q(table) + ", COALESCE((SELECT md5(COALESCE(string_agg(to_jsonb(t)::text, E'\\n' "
        "ORDER BY to_jsonb(t)::text), '')) FROM public.\"" + table + "\" t"
        + (" WHERE t.registration_id <> " + exclude if exclude is not None else "") + "), '')"
        for table in tables) + ")"


def _target_sql(registration):
    return ("(SELECT to_jsonb(t) || jsonb_build_object('repository_id', (SELECT r.id FROM public.repositories r "
            "WHERE r.id = (SELECT g.repository_id FROM public.ref_store_core_pack_publications g "
            "WHERE g.registration_id=" + registration + ")), 'pack_id', (SELECT g.pack_id "
            "FROM public.ref_store_core_pack_publications g WHERE g.registration_id=" + registration + ")) "
            "FROM public.ref_store_core_pack_publications t WHERE t.registration_id=" + registration + "), "
            "(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.role), '[]'::jsonb) "
            "FROM public.ref_store_core_pack_artifacts a WHERE a.registration_id=" + registration + ")")


def corruption_sql(case):
    """One transaction on the disposable clone: evidence, the explicitly
    privileged clone-local DML, and the exact row count it changed.

    The A4 ledger is immutable by design (migration 142 guards, and the
    publication digest is the membership FK target), so the refusal is lifted
    for this transaction only with ``SET LOCAL session_replication_role``
    (needs a superuser; the run-owned admin clone is the only database it is
    ever run on). ``RESET`` runs before COMMIT; the production schema, triggers
    and DDL are never changed.
    """
    need(isinstance(case, CorruptionCase) and case.planned, "planned corruption case expected")
    registration = _registration(case.registration.id)
    return (
        "BEGIN; SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='10s'; "
        "CREATE TEMP TABLE issue169_before ON COMMIT DROP AS SELECT jsonb_build_object("
        "'target', jsonb_build_array(" + _target_sql(registration) + "), "
        "'after', " + _fact_sql(AFTER_TABLES, registration) + ", 'guarded', " + _fact_sql(GUARDED_TABLES) + ") AS snapshot; "
        "SET LOCAL session_replication_role = replica; " + case.statement + ";\n"
        "\\echo " + CHANGED + " :ROW_COUNT\n"
        "RESET session_replication_role; "
        # A plain SELECT under the runner's psql -qAt mode prints the JSON
        # object as one line. COPY ... TO STDOUT would apply COPY text
        # escaping (doubling backslashes inside nested JSON strings), so its
        # payload is not parseable JSON.
        "SELECT jsonb_build_object("
        "'registration', CAST(" + registration + " AS text), "
        "'superuser', (SELECT rolsuper FROM pg_roles WHERE rolname=current_user), "
        "'replication_role_default', current_setting('session_replication_role')='origin', "
        "'intact_triggers', (SELECT count(*) FROM pg_trigger g WHERE NOT g.tgisinternal AND g.tgenabled='O' "
        "AND g.tgname IN (" + ", ".join(q(name) for name in IMMUTABLE_TRIGGERS) + ")), "
        "'target', jsonb_build_array(" + _target_sql(registration) + "), "
        "'after', " + _fact_sql(AFTER_TABLES, registration) + ", 'guarded', " + _fact_sql(GUARDED_TABLES) + ", "
        "'before', (SELECT snapshot FROM issue169_before))::text; COMMIT")


def corruption_findings(case, changed, observed):
    """Evidence if the clone alone carries exactly the intended corruption.

    ``changed`` is the DML row count the clone reported and ``observed`` the
    JSON row ``corruption_sql`` printed. A missing or unchanged row, another
    role/digest, a touched guarded ledger, a non-superuser admin, disabled
    triggers, or a replication role still set after COMMIT fail the fixture
    before any backup is attempted.
    """
    need(isinstance(case, CorruptionCase) and case.planned, "planned corruption case expected")
    need(isinstance(changed, int) and not isinstance(changed, bool), "corruption row count is not an integer")
    try:
        observed = json.loads(observed) if isinstance(observed, (str, bytes)) else observed
    except ValueError as error:
        raise AssertionError("corruption evidence is not JSON: " + str(error)) from None
    need(isinstance(observed, dict), "corruption evidence is not a JSON object")
    need(str(observed.get("registration")) == case.registration.id, "corruption ran on another registration")
    need(observed.get("superuser") is True, "the clone-local corruption needs a superuser admin clone")
    need(observed.get("replication_role_default") is True, "session_replication_role leaked past the transaction")
    need(observed.get("intact_triggers") == len(IMMUTABLE_TRIGGERS),
         "migration-142 immutability triggers are missing or disabled in the clone")
    for state in (observed.get("before"), observed):
        need(isinstance(state, dict) and set(state.get("after") or {}) == set(AFTER_TABLES)
             and set(state.get("guarded") or {}) == set(GUARDED_TABLES), "the clone facts are incomplete")
    need(observed.get("before", {}).get("after") == observed.get("after"),
         "corruption changed another pack artifact row")
    need(observed.get("before", {}).get("guarded") == observed.get("guarded"),
         "corruption touched the memberships/history/usage ledgers")
    # The AFTER_TABLES facts exclude the target registration (the exclusion is
    # proven from the SQL below); its publication and artifacts are compared
    # exactly through the separately captured target evidence.
    need("t.registration_id <> '" + case.registration.id + "'::uuid" in corruption_sql(case),
         "the target registration is not excluded from the after facts")
    publication, before = _target(observed["before"].get("target"))
    need(publication is not None and publication.get("registration_id") == case.registration.id,
         "the target registration has no publication")
    need(publication.get("repository_id") == case.registration.repository_id
         and publication.get("pack_id") == case.registration.pack_id, "the target publication is another row")
    need(publication.get("artifact_set_digest") == case.registration.digest,
         "the target publication carries another artifact-set digest")
    need(not case.targets_digest or artifact_set_digest(_digest_rows(publication, before)) == case.registration.digest,
         "the stored digest is not the digest of the target artifact pair")
    need(sorted(before) == sorted(role for role, _ in PAIR_ROLES),
         "the target registration is not an intact pack+idx pair before corruption")
    after_publication, after = _target(observed.get("target"))
    need(after_publication is not None and after_publication.get("registration_id") == case.registration.id,
         "the target publication disappeared")
    if case.targets_digest:
        need(changed == 1, case.name + ": exactly one row must change, got " + str(changed))
        need(after_publication.get("artifact_set_digest") == case.wrong_value,
             "the stored artifact-set digest was not changed to the intended value")
        need(after_publication == dict(publication, artifact_set_digest=case.wrong_value),
             "the wrong-digest corruption changed another publication field")
        need(after == before, "the wrong-digest corruption changed an artifact row")
    else:
        removed = registration_role(case.statement)
        kept = set(before) - ({removed} if removed else set(before))
        need(changed == len(before) - len(kept), case.name + ": the deletion row count is not exact")
        need(set(after) == kept, case.name + ": the wrong artifact roles survived")
        need(all(after[role] == before[role] for role in after), case.name + ": another artifact row changed")
        need(after_publication == publication, case.name + ": the publication row changed")
    return {
        "case": case.name, "registration_id": case.registration.id, "rows_changed": changed,
        "finding": finding(case), "removed_roles": sorted(set(before) - set(after)),
        "stored_digest": after_publication.get("artifact_set_digest"),
        "clone_local_superuser": True, "session_replication_role": "replica-transaction-local",
        "guarded_ledgers_unchanged": True,
    }


def _target(value):
    need(isinstance(value, (list, tuple)) and len(value) == 2, "the target evidence is incomplete")
    publication, artifacts = value
    need(publication is None or isinstance(publication, dict), "the target publication is not a row")
    need(isinstance(artifacts, list) and all(isinstance(row, dict) for row in artifacts),
         "the target artifacts are not rows")
    return publication, {row["role"]: row for row in artifacts}


DIGEST_COLUMNS = ("role", "slot", "hold_id", "tenant_id", "authority_id", "authority_generation", "attempt_id",
                  "namespace", "sha256", "content_length", "provider", "backend_identity")


DIGEST_IDENTITY = ("hold_id", "tenant_id", "authority_id", "authority_generation", "attempt_id", "namespace",
                   "provider", "backend_identity")


def _digest_rows(publication, artifacts):
    """The pair encoded like ``Artifact::line``: hold/tenant/authority identity
    from the publication (or the artifact row), physical fields per role."""
    rows = []
    for role, artifact in artifacts.items():
        need(all(name in publication or name in artifact for name in DIGEST_IDENTITY),
             "the artifact row lacks a digest field")
        row = {name: artifact[name] if name in artifact else publication[name] for name in DIGEST_IDENTITY}
        row.update(role=role, slot=artifact.get("slot"), sha256=artifact.get("sha256"),
                   content_length=artifact.get("content_length"))
        need(slot_of(role) == row["slot"] and HEXDIGEST.match(str(row["sha256"]))
             and int(row["content_length"] or 0) > 0, "the artifact row is not a canonical pair member")
        rows.append(row)
    return rows


def slot_of(role):
    return dict(PAIR_ROLES).get(role)


HEXDIGEST = re.compile(r"[0-9a-f]{64}")
VALIDATOR_PREFIX = ("rootyard: backup failed; requires stopped writers, supported dedicated database and safe new "
                    "destination; partial files may remain: Caused by: source artifact ledger cannot be archived: "
                    "Caused by: source artifact ledger is inconsistent (")
# Any of these means the failure was not the source-ledger validator: another
# backend/root, an absent or changed Blob byte, a missing source file, or a
# broken fixture/CLI invocation. A nonzero exit alone therefore proves nothing.
UNRELATED_ERRORS = (
    "blob closure backend differs", "failed verified read-back", "exported from the source backend",
    "changed during export", "blob closure cannot be captured", "notfound", "digestmismatch",
    "lengthmismatch", "deadlineexceeded", "database_url", "postgresql 17", "transition fence",
    "schema_migrations", "search_path", "permission denied", "caused by: syntax error", "deadlock",
    "connection refused",
)


# ``ledger_sets`` violation tokens that can only be caused by damaging one A4
# set. ``canonical_pair_mismatch`` is the per-publication digest check; the
# missing-pair and rewritten-digest tokens are cause-specific.
SET_TOKENS = ("canonical_pair_mismatch", "incomplete_pair", "missing_artifacts", "declared_set_digest_mismatch")
# Snapshot/root/serving-read rechecks of that same registration. They are
# keyed by ``<repository_id>:<snapshot-or-root-id>`` before any free-text
# reason, so only the repository can be required exactly; the affected
# registration is proven by the SET_TOKENS above.
DEPENDENT_TOKENS = ("snapshot_set_mismatch", "snapshot_membership_mismatch", "root_set_mismatch",
                    "root_pack_set_mismatch", "serving_read_pack_mismatch")
# The validator stamps its own message with any decode failure before any
# violation is emitted, so these can never be a plain token violation.
DECODE_ERRORS = ("stored declared set is malformed", "stored publication digest is invalid",
                 "stored declared joined revision is invalid", "negative artifact length",
                 "negative hold length", "source artifact ledger cannot be read")
UUID_TEXT = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
VIOLATION = re.compile("(?P<token>" + "|".join(SET_TOKENS + DEPENDENT_TOKENS) + "):(?P<ids>.*)")


def split_violations(listed):
    """The violations of the canonical ``; ``-joined report (count = their len)."""
    if not listed:
        return [], 0
    entries = listed.split("; ")
    need(len(entries) == len(set(entries)), "the violation list repeats an entry: " + listed[:300])
    return entries, len(entries)


def _exact(entry, pattern):
    need(re.fullmatch(pattern, entry) is not None, "malformed violation: " + entry[:300])


def _target_violation(entry, case):
    """Classify one exact violation of this case's actual target registration."""
    registration = case.registration
    repository, pack, identity = registration.scope()
    match = VIOLATION.fullmatch(entry)
    need(match is not None, "the refusal lists an unrelated violation: " + entry[:300])
    token, ids = match.group("token"), match.group("ids")
    scope = ":".join((repository, pack, identity))
    pair = re.escape(pack) + ":" + re.escape(identity)
    if token in DEPENDENT_TOKENS:
        # The snapshot/root rechecks are keyed by the affected repository and
        # the snapshot/root id (plus a free-text reason); a serving-read recheck
        # may instead name the exact target pair.
        keyed = re.fullmatch(re.escape(repository) + ":" + UUID_TEXT + r"(:[^:]+)*", ids)
        pair_keyed = token == "serving_read_pack_mismatch" and ids == pack + ":" + identity
        need(keyed is not None or pair_keyed, "dependent violation names another repository: " + entry[:300])
        return token
    if token == "declared_set_digest_mismatch":
        noted = re.fullmatch("(?P<source>[a-z_]+):" + re.escape(scope), ids)
        need(noted is not None or ids == scope, "declared-set violation names another set: " + entry[:300])
        return token
    _exact(ids, re.escape(scope))
    return token


def validator_refusal(stderr, case):
    """Strict causal check of one precise source-ledger validator refusal.

    The backup CLI prints exactly one deterministic line: ``rootyard: <backup
    failure>: Caused by: source artifact ledger cannot be archived: Caused by:
    source artifact ledger is inconsistent (N violations): <violations>``.
    Every violation must be an exact ``<token>:<ids>`` token of this case's
    actual repository/pack/registration: the canonical-pair violation always,
    the cause-specific ``incomplete_pair``/``missing_artifacts`` or a
    ``declared_set_digest_mismatch`` for one of the four declared-set sources,
    and only the dependent tokens of that same affected registration. The list
    need not have length one, but a count mismatch, duplicate, truncation,
    unrelated token/ids, malformed entry or any other failure text is refused.
    """
    need(isinstance(case, CorruptionCase) and case.planned, "planned corruption case expected")
    text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else (stderr or "")
    lines = text.strip().splitlines()
    need(len(lines) == 1, "backup did not print exactly one deterministic refusal line")
    line = lines[0]
    need(line.startswith(VALIDATOR_PREFIX), "backup refusal is not the source-ledger validator: " + line[-600:])
    rest = line[len(VALIDATOR_PREFIX):]
    match = re.match(r"(\d+) violations\): (.+)$", rest)
    need(match is not None, "the validator line has no bounded violation list")
    listed, count = split_violations(match.group(2))
    need(int(match.group(1)) == count, "the validator violation count does not match its list")
    lowered = line.lower()
    need("... " not in match.group(2) and " more" not in lowered, "the refusal list is truncated")
    need(not [phrase for phrase in UNRELATED_ERRORS if phrase in lowered],
         "the refusal also names an unrelated failure: " + line[-300:])
    need(not [phrase for phrase in DECODE_ERRORS if phrase in lowered],
         "the refusal carries a decode error instead of token violations: " + line[-300:])
    tokens = [_target_violation(entry, case) for entry in listed]
    required = case.refusal.required
    need(tokens.count(required[0]) == 1,
         "the refusal does not carry exactly one " + required[0] + " for the target: " + "; ".join(listed)[:400])
    allowed = {required[0], required[1]}
    need(set(tokens) <= allowed | set(DEPENDENT_TOKENS),
         "the refusal carries a cause token from the wrong mutation: " + "; ".join(listed)[:400])
    if case.name == "wrong_artifact_set_digest":
        sources = {entry.split(":", 2)[1] for entry in listed
                   if entry.startswith("declared_set_digest_mismatch:")}
        need(sources and sources <= set(DECLARED_SOURCES),
             "the refusal does not name only declared-set sources of the target digest: " + "; ".join(listed)[:400])
    elif case.name in ("missing_pack", "missing_idx"):
        need(tokens.count("incomplete_pair") == 1, "the refusal does not carry the cause-specific incomplete_pair")
    elif case.name == "missing_all_artifacts":
        need(tokens.count("missing_artifacts") == 1, "the refusal does not carry missing_artifacts")
    return str(count) + "|" + "; ".join(listed)


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
    digests, counts and states. ``serving_read`` names the one nonempty
    transient serving read the helper captured through
    ``PgServingReads::capture``: its pin, its repository/tenant (exactly the
    marker's API-created bound repository) and a requester owner that is never a
    repository tenant or the producer.
    """
    need(marker.get("kind") == MARKER_KIND, "native fixture marker has another kind")
    need(marker.get("format") == 22, "native fixture is not a format22 source")
    text = json.dumps(marker, sort_keys=True)
    for forbidden in _FORBIDDEN_MARKER_TEXT:
        need(forbidden not in text, "native fixture marker leaks " + forbidden)
    repos = marker.get("repositories") or []
    need(len(repos) >= 2, "native fixture must create at least two API repositories")
    producer = str(marker.get("producer_owner_id", ""))
    bound_repository = str(marker.get("bound_repository_id", ""))
    marker_tenant = str(marker.get("tenant_id", ""))
    need(UUID_HEX.match(bound_repository), "native fixture marker has no bound_repository_id")
    need(UUID_HEX.match(marker_tenant), "native fixture marker has no tenant_id")
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
    serving_read = _serving_read_checks(marker.get("serving_read"), repos, producer, len(registrations),
                                        bound_repository, marker_tenant)
    return {"repositories": len(repos), "registrations": len(registrations),
            "roots": {state: states.count(state) for state in ROOT_STATES},
            "producer_distinct_from_tenant": True, "serving_read": serving_read}


def _serving_read_checks(marker, repos, producer, registrations, bound_repository, marker_tenant):
    """One valid, nonempty transient serving read owned by a third real user.

    Besides being a repository the API created, its repository and tenant must
    be exactly the marker's bound repository/tenant: a serving read on another
    API-created (but unbound) repository is not the source the format22 drill
    archived.
    """
    need(isinstance(marker, dict), "native fixture marker carries no serving_read")
    need(set(marker) == {"pin_id", "repository_id", "tenant_id", "owner_id", "pack_count"},
         "a serving_read entry carries unexpected fields")
    for field in ("pin_id", "repository_id", "tenant_id", "owner_id"):
        need(isinstance(marker.get(field), str) and UUID_HEX.match(marker[field]),
             "serving_read " + field + " is not a valid uuid")
    need(isinstance(marker.get("pack_count"), int) and not isinstance(marker["pack_count"], bool)
         and marker["pack_count"] > 0, "serving_read has no nonempty pack count")
    need(marker["pack_count"] == registrations, "serving_read pack_count differs from the registration count")
    repo_id, tenant, owner = (marker[field] for field in ("repository_id", "tenant_id", "owner_id"))
    owners = {str(repo["id"]): str(repo["owner_id"]) for repo in repos}
    need(repo_id in owners, "serving_read names a repository that was not API-created")
    need(tenant == owners[repo_id], "serving_read tenant is not the owning tenant of its repository")
    need(repo_id == bound_repository, "serving_read repository_id differs from marker.bound_repository_id")
    need(tenant == marker_tenant, "serving_read tenant_id differs from marker.tenant_id")
    tenants = set(owners.values())
    need(owner not in tenants, "serving_read requester is a repository tenant")
    need(owner != producer, "serving_read requester is the producer")
    return {"pin_id": marker["pin_id"], "repository_id": repo_id, "tenant_id": tenant, "owner_id": owner,
            "pack_count": marker["pack_count"], "requester_distinct": True}
