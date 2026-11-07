#!/usr/bin/env python3
"""Native regression coverage for schema134 repository/tenant identity FKs (#90).

The shared Harness starts the real `rootyard` binary against a private
PostgreSQL schema. Two repositories with two different owners are created and
pushed with real stock Git; both are cut over to Pando, so the genuine
publication path writes `pando_pack_manifests` and `pando_manifest_artifacts`
through real Garage + Vault Transit for each owner. Every positive link asserted
below is therefore produced by trusted code, never by this script.

Negative cases are plain SQL inserts into this run's own schema. The synthetic
manifest rows are copies of a real manifest with fresh ids and the same
repository/tenant triple, and they carry no artifact links, so their
`(manifest_id, artifact_role)` primary key is free. Each negative probe is
pre-validated before it runs: the manifest triple exists, the referenced
artifact tuple exists for exactly one owner, and the deliberately wrong tuple is
absent. A rejection can therefore only come from the intended composite foreign
key, and the probe asserts SQLSTATE 23503 plus the exact constraint name. A
different error is never treated as a pass.

No synthetic remote-artifact metadata is inserted at all. The probes reference
only the real remote rows that the two genuine publications registered, so a
missing-reference case is a missing (tenant, namespace, sha256) tuple rather
than a fake row. Real published objects are retained by the dedicated synthetic
bucket used by the test environment; this script never deletes remote objects.
Dirty schema133 upgrade refusal is a separate native entry point:
tests/storage_identity_upgrade.py.

Runtime fail-closed proofs (stale generation, wrong backend, not-ready
repository) are intentionally NOT re-implemented here as SQL text checks; they
stay covered by tests/storage_lifecycle.py and tests/storage_lifecycle_physical.py.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness

REQUIRED_ENV = (
    "ROOTYARD_TEST_DATABASE_URL",
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_KMS_VAULT_URL",
    "ROOTYARD_KMS_VAULT_TOKEN",
    "ROOTYARD_KMS_VAULT_KEY",
)

INDEX_BASELINE = {
    "pando_pack_manifests": {
        "pando_pack_manifests_pkey",
        "pando_pack_manifests_repository_id_id_key",
        "pando_pack_manifests_repository_idx",
        "pando_pack_manifests_id_repository_tenant_key",
    },
    "pando_manifest_artifacts": {
        "pando_manifest_artifacts_pkey",
        "pando_manifest_artifacts_artifact",
        "pando_manifest_artifacts_repository",
    },
    "storage_maintenance_jobs": {
        "storage_maintenance_jobs_pkey",
        "storage_maintenance_one_active_kind",
        "storage_maintenance_claimable",
        "storage_maintenance_history",
    },
    "storage_maintenance_repo_state": {"storage_maintenance_repo_state_pkey"},
    "storage_maintenance_tombstones": {
        "storage_maintenance_tombstones_pkey",
        "storage_maintenance_tombstones_due",
    },
}

MANIFEST_IDENTITY_FK = "pando_manifest_artifacts_manifest_identity_fkey"
ARTIFACT_AUTHORITY_FK = "pando_manifest_artifacts_authority_id_tenant_id_namespace__fkey"
PANDO_ROLES = "index-cipher,index-envelope,pack-cipher,pack-envelope"


def require_environment():
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "storage identity FK regression needs real Garage/Vault configuration; missing: "
            + ", ".join(missing)
        )


class IdentityHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.limits.append(
            "Negative link/probe rows are controlled SQL against this run's own schema; "
            "they prove the database constraints only, not that any object was uploaded."
        )
        self.limits.append(
            "The test environment must provide a dedicated synthetic Garage bucket. "
            "This script preserves every published remote object and never deletes a "
            "valid remote artifact; do not point it at production or shared live data."
        )
        self.limits.append(
            "Dirty pre-upgrade refusal (inconsistent rows on a schema133 database) is "
            "proved by tests/storage_identity_upgrade.py, not by this script."
        )
        self.limits.append(
            "Backup format 9 / legacy schema133 restore gates are out of scope for this "
            "script; the coordinator owns format10 and legacy133 restore support."
        )
        self.limits.append(
            "Runtime stale-generation, wrong-backend and not-ready fail-closed proofs are "
            "reused from tests/storage_lifecycle.py and tests/storage_lifecycle_physical.py."
        )
        self.synthetic_manifest_ids = []

    # ---- fixture helpers ---------------------------------------------------------
    def create_repo(self, token, name, object_format="sha1"):
        code, raw, _ = self.http(
            "/api/repos", token=token, method="POST",
            body={"name": name, "object_format": object_format},
        )
        assert code == 201, (code, raw[:400])
        repo = json.loads(raw)
        remote = self.base + repo["clone_path"]
        work = self.root / ("work-" + repo["id"])
        self.git("init", "--object-format=" + object_format, "--initial-branch=main", str(work))
        self.git("config", "user.name", "Identity FKs", cwd=work)
        self.git("config", "user.email", "identity-fks@example.invalid", cwd=work)
        self.git("remote", "add", "origin", remote, cwd=work)
        return repo, remote, work

    def commit_and_push(self, work, token, filename, text):
        (work / filename).write_text(text)
        self.git("add", filename, cwd=work)
        self.git("commit", "-m", text, cwd=work)
        oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=token)
        return oid

    def owner(self, repo):
        return self.sql("SELECT owner_id::text FROM repositories WHERE id='" + repo["id"] + "'")

    def generation(self, repo):
        return self.sql("SELECT storage_generation::text FROM repositories WHERE id='" + repo["id"] + "'")

    def cutover_all(self, repos):
        """Cut over every repository while the server is stopped, then restart once."""
        self.stop()
        reports = {}
        for repo in repos:
            report = json.loads(self.cli(
                "pando-transition", "cutover", "--repository", repo["id"]
            ))
            assert report["direction"] == "gitfs_to_pando", report
            assert report["new_storage_backend"] == "pando", report
            reports[repo["id"]] = report
        self.start()
        return reports

    def probe_fk(self, statement, expected_constraint):
        """Run one insert that must be refused by exactly `expected_constraint`."""
        self.sql("DELETE FROM schema134_probe")
        self.sql(
            "DO $$\n"
            "DECLARE\n"
            "    name text;\n"
            "    state text;\n"
            "BEGIN\n"
            "    BEGIN\n"
            "        " + statement + ";\n"
            "    EXCEPTION WHEN others THEN\n"
            "        GET STACKED DIAGNOSTICS name = CONSTRAINT_NAME, state = RETURNED_SQLSTATE;\n"
            "        INSERT INTO schema134_probe(constraint_name, sqlstate) VALUES(name, state);\n"
            "    END;\n"
            "END\n"
            "$$"
        )
        raw = self.sql(
            "SELECT COALESCE(constraint_name,'-') || '|' || COALESCE(sqlstate,'-') "
            "FROM schema134_probe"
        )
        assert raw, "statement was accepted but should violate " + expected_constraint
        observed, state = raw.split("|", 1)
        # A syntax error or another error class is not an FK proof.
        assert state == "23503", (observed, state, expected_constraint)
        assert observed == expected_constraint, (observed, expected_constraint)
        return {"sqlstate": state, "constraint": observed}

    def remote_tuple_exists(self, authority, tenant, namespace, sha256):
        return self.sql(
            "SELECT count(*) FROM pando_remote_artifacts WHERE authority_id='" + authority
            + "' AND tenant_id='" + tenant + "' AND namespace='" + namespace
            + "' AND sha256='" + sha256 + "'"
        ) == "1"

    def manifest_identity_exists(self, manifest_id, repository_id, tenant_id):
        return self.sql(
            "SELECT count(*) FROM pando_pack_manifests WHERE id='" + manifest_id
            + "' AND repository_id='" + repository_id + "' AND tenant_id='" + tenant_id + "'"
        ) == "1"

    def synthetic_manifest_copy(self, source):
        """Copy one real manifest with a fresh id; leave its artifact roles free."""
        manifest_id = str(uuid.uuid4())
        self.synthetic_manifest_ids.append(manifest_id)
        self.sql(
            "INSERT INTO pando_pack_manifests"
            "(id,repository_id,tenant_id,storage_generation,object_format,manifest) "
            "SELECT '" + manifest_id + "',repository_id,tenant_id,storage_generation,"
            "object_format,manifest FROM pando_pack_manifests WHERE id='" + source + "'"
        )
        assert self.sql(
            "SELECT count(*) FROM pando_pack_manifests WHERE id='" + manifest_id + "'"
        ) == "1"
        assert self.sql(
            "SELECT count(*) FROM pando_manifest_artifacts WHERE manifest_id='"
            + manifest_id + "'"
        ) == "0", "synthetic manifest copy must keep the (manifest_id, artifact_role) key free"
        return manifest_id

    def latest_manifest(self, repo):
        return self.sql(
            "SELECT id::text FROM pando_pack_manifests WHERE repository_id='"
            + repo["id"] + "' ORDER BY created_at DESC, id DESC LIMIT 1"
        )

    def artifact_tuple(self, manifest_id):
        raw = self.sql(
            "SELECT authority_id::text || '|' || tenant_id::text || '|' || namespace "
            "|| '|' || sha256 FROM pando_manifest_artifacts WHERE manifest_id='"
            + manifest_id + "' AND artifact_role='pack-cipher'"
        )
        assert raw, (manifest_id, "missing pack-cipher link")
        authority, tenant, namespace, sha256 = raw.split("|")
        return {
            "authority_id": authority,
            "tenant_id": tenant,
            "namespace": namespace,
            "sha256": sha256,
        }

    def clone_fetch_fsck(self, label, remote, token, expected_head):
        checkout = self.root / ("clone-" + label)
        self.git("clone", remote, str(checkout), token=token)
        assert self.git("rev-parse", "HEAD", cwd=checkout).stdout.decode().strip() == expected_head
        self.git("fetch", "origin", cwd=checkout, token=token)
        self.git("fsck", "--full", cwd=checkout)
        return checkout

    def published_closure(self, label, repo, owner, remote, token, expected_head):
        raw = self.sql(
            "SELECT count(*),"
            " count(*) FILTER (WHERE l.repository_id=m.repository_id AND l.tenant_id=m.tenant_id),"
            " count(*) FILTER (WHERE l.repository_id='" + repo["id"] + "' AND l.tenant_id='"
            + owner + "'),"
            " count(*) FILTER (WHERE r.sha256 IS NULL)"
            " FROM pando_manifest_artifacts l"
            " JOIN pando_pack_manifests m ON m.id=l.manifest_id"
            " LEFT JOIN pando_remote_artifacts r ON r.authority_id=l.authority_id"
            "  AND r.tenant_id=l.tenant_id AND r.namespace=l.namespace AND r.sha256=l.sha256"
            " WHERE m.repository_id='" + repo["id"] + "'"
        )
        total, matched, owned, missing_remote = (int(value) for value in raw.split("|"))
        assert total >= 4, (label, total)
        assert matched == total, (label, total, matched)
        assert owned == total, (label, total, owned)
        assert missing_remote == 0, (label, missing_remote)
        roles = self.sql(
            "SELECT string_agg(DISTINCT artifact_role, ',' ORDER BY artifact_role) "
            "FROM pando_manifest_artifacts l JOIN pando_pack_manifests m ON m.id=l.manifest_id "
            "WHERE m.repository_id='" + repo["id"] + "'"
        )
        assert roles == PANDO_ROLES, (label, roles)
        source = self.latest_manifest(repo)
        assert self.sql(
            "SELECT count(*) FROM pando_manifest_artifacts WHERE manifest_id='" + source + "'"
        ) == "4", (label, source, "published manifest must link four artifacts")
        self.clone_fetch_fsck(label, remote, token, expected_head)
        return {
            "manifest_id": source,
            "pack_cipher": self.artifact_tuple(source),
            "published_links": total,
            "artifact_roles": roles,
        }

    # ---- schema contract ---------------------------------------------------------
    def schema_contract(self):
        version = self.sql("SELECT max(version) FROM schema_migrations")
        assert version == "134", version
        self.sql(
            "CREATE TABLE schema134_probe("
            "id bigserial PRIMARY KEY,constraint_name text,sqlstate text)"
        )
        definitions = {}
        raw = self.sql(
            "SELECT k.conname || '|' || pg_get_constraintdef(k.oid) || '|' || k.convalidated "
            "FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=current_schema() AND k.conname IN ("
            "'pando_manifest_artifacts_manifest_identity_fkey',"
            "'pando_manifest_artifacts_manifest_id_fkey',"
            "'pando_manifest_artifacts_authority_id_tenant_id_namespace__fkey',"
            "'pando_pack_manifests_id_repository_tenant_key',"
            "'storage_maintenance_repo_state_repository_owner_fkey',"
            "'storage_maintenance_jobs_repository_owner_fkey',"
            "'storage_maintenance_tombstones_repository_owner_fkey')"
        )
        for line in raw.splitlines():
            name, definition, validated = line.split("|", 2)
            # pg_get_constraintdef may qualify same-schema targets; normalise so
            # the shape assertions below do not depend on search_path.
            definitions[name] = (definition.replace("public.", ""), validated)
        composite = {
            "pando_manifest_artifacts_manifest_identity_fkey": (
                "FOREIGN KEY (manifest_id, repository_id, tenant_id)",
                "REFERENCES pando_pack_manifests(id, repository_id, tenant_id)",
            ),
            "storage_maintenance_repo_state_repository_owner_fkey": (
                "FOREIGN KEY (repository_id, tenant_id)",
                "REFERENCES repositories(id, owner_id)",
            ),
            "storage_maintenance_jobs_repository_owner_fkey": (
                "FOREIGN KEY (repository_id, tenant_id)",
                "REFERENCES repositories(id, owner_id)",
            ),
            "storage_maintenance_tombstones_repository_owner_fkey": (
                "FOREIGN KEY (repository_id, tenant_id)",
                "REFERENCES repositories(id, owner_id)",
            ),
        }
        for name, (columns, target) in composite.items():
            assert name in definitions, name
            definition, validated = definitions[name]
            assert columns in definition, (name, definition)
            assert target in definition, (name, definition)
            assert "ON DELETE CASCADE" in definition, (name, definition)
            assert validated == "t", (name, validated)
        assert "pando_manifest_artifacts_manifest_id_fkey" not in definitions, definitions
        assert ARTIFACT_AUTHORITY_FK in definitions, (
            "independent artifact authority/tenant FK was removed"
        )
        unique, _ = definitions["pando_pack_manifests_id_repository_tenant_key"]
        assert "UNIQUE (id, repository_id, tenant_id)" in unique, unique

        observed = {}
        for table, expected in INDEX_BASELINE.items():
            rows = self.sql(
                "SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() "
                "AND tablename='" + table + "'"
            )
            observed[table] = set(rows.splitlines()) if rows else set()
            assert observed[table] == expected, (table, sorted(observed[table] ^ expected))
        return {
            "schema_version": int(version),
            "composite_fks": sorted(composite),
            "single_column_manifest_fk_removed": True,
            "artifact_authority_fk_retained": True,
            "indexes": {table: sorted(names) for table, names in observed.items()},
        }

    # ---- GitFS lifecycle identity pairs -----------------------------------------
    def gitfs_identity_pairs(self):
        repo_a, _, work_a = self.create_repo(self.alice, "identity-owner-a")
        repo_b, _, work_b = self.create_repo(self.bob, "identity-owner-b")
        self.commit_and_push(work_a, self.alice, "a.txt", "owner a")
        self.commit_and_push(work_b, self.bob, "b.txt", "owner b")
        owner_a, owner_b = self.owner(repo_a), self.owner(repo_b)
        assert owner_a != owner_b, "the two repositories must belong to different owners"
        for owner in (owner_a, owner_b):
            assert self.sql("SELECT count(*) FROM namespaces WHERE id='" + owner + "'") == "1"
        generation_a = self.generation(repo_a)
        generation_b = self.generation(repo_b)

        # Wrong tenant is refused for all three lifecycle tables.
        kind = self.sql(
            "SELECT k FROM (VALUES ('gitfs_stage_cleanup'),('gitfs_unreachable_mark'),"
            "('gitfs_tombstone_delete'),('gitfs_repack')) AS candidates(k) "
            "WHERE NOT EXISTS (SELECT 1 FROM storage_maintenance_jobs "
            "WHERE repository_id IN ('" + repo_a["id"] + "','" + repo_b["id"] + "') "
            "AND kind=k AND state IN ('queued','running')) LIMIT 1"
        )
        assert kind, "no free maintenance kind to probe without a unique-index clash"
        jobs = self.probe_fk(
            "INSERT INTO storage_maintenance_jobs"
            "(id,repository_id,tenant_id,kind,repository_generation) VALUES"
            "('" + str(uuid.uuid4()) + "','" + repo_a["id"] + "','" + owner_b + "','"
            + kind + "'," + generation_a + ")",
            "storage_maintenance_jobs_repository_owner_fkey",
        )

        # A repository created just for this probe cannot own a maintenance state
        # row yet, so the negative insert can only fail on the identity FK and
        # never on the (repository_id) primary key.
        state_repo = self.create_repo(self.alice, "identity-state-probe")[0]["id"]
        assert self.sql(
            "SELECT count(*) FROM storage_maintenance_repo_state WHERE repository_id='"
            + state_repo + "'"
        ) == "0"
        state_probe = self.probe_fk(
            "INSERT INTO storage_maintenance_repo_state(repository_id,tenant_id) VALUES"
            "('" + state_repo + "','" + owner_b + "')",
            "storage_maintenance_repo_state_repository_owner_fkey",
        )

        # A random 40-hex oid cannot collide with a real tombstone primary key.
        oid_wrong = os.urandom(20).hex()
        tombstones = self.probe_fk(
            "INSERT INTO storage_maintenance_tombstones"
            "(repository_id,tenant_id,oid,object_kind,repository_generation,delete_after) VALUES"
            "('" + repo_a["id"] + "','" + owner_b + "','" + oid_wrong
            + "','blob'," + generation_a + ",clock_timestamp())",
            "storage_maintenance_tombstones_repository_owner_fkey",
        )

        # The refused inserts must have rolled back completely: nothing with the
        # wrong tenant may exist, otherwise the probes proved nothing.
        assert self.sql(
            "SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id='"
            + repo_a["id"] + "' AND tenant_id='" + owner_b + "'"
        ) == "0"
        assert self.sql(
            "SELECT count(*) FROM storage_maintenance_repo_state WHERE repository_id='"
            + state_repo + "'"
        ) == "0"
        assert self.sql(
            "SELECT count(*) FROM storage_maintenance_tombstones WHERE repository_id='"
            + repo_a["id"] + "' AND oid='" + oid_wrong + "'"
        ) == "0"

        # The legal pair still inserts for every table; each row is this run's own
        # fixture and is removed again before the case returns.
        own_job = str(uuid.uuid4())
        self.sql(
            "INSERT INTO storage_maintenance_jobs"
            "(id,repository_id,tenant_id,kind,repository_generation,state,completed_at) "
            "VALUES('" + own_job + "','" + repo_b["id"] + "','" + owner_b + "','"
            + kind + "'," + generation_b + ",'failed',clock_timestamp())"
        )
        assert self.sql(
            "SELECT count(*) FROM storage_maintenance_jobs WHERE id='" + own_job + "'"
        ) == "1"
        self.sql(
            "INSERT INTO storage_maintenance_repo_state(repository_id,tenant_id) VALUES"
            "('" + state_repo + "','" + owner_a + "')"
        )
        assert self.sql(
            "SELECT tenant_id::text FROM storage_maintenance_repo_state WHERE repository_id='"
            + state_repo + "'"
        ) == owner_a
        oid_legal = os.urandom(20).hex()
        self.sql(
            "INSERT INTO storage_maintenance_tombstones"
            "(repository_id,tenant_id,oid,object_kind,repository_generation,delete_after,state) "
            "VALUES('" + repo_a["id"] + "','" + owner_a + "','" + oid_legal
            + "','blob'," + generation_a + ",clock_timestamp(),'retained')"
        )
        assert self.sql(
            "SELECT count(*) FROM storage_maintenance_tombstones WHERE repository_id='"
            + repo_a["id"] + "' AND oid='" + oid_legal + "'"
        ) == "1"

        self.sql("DELETE FROM storage_maintenance_jobs WHERE id='" + own_job + "'")
        self.sql(
            "DELETE FROM storage_maintenance_repo_state WHERE repository_id='" + state_repo + "'"
        )
        self.sql(
            "DELETE FROM storage_maintenance_tombstones WHERE repository_id='"
            + repo_a["id"] + "' AND oid='" + oid_legal + "'"
        )
        return {
            "owners": {"a": owner_a, "b": owner_b},
            "repositories": {"a": repo_a["id"], "b": repo_b["id"]},
            "rejected": {
                "storage_maintenance_jobs": jobs,
                "storage_maintenance_repo_state": state_probe,
                "storage_maintenance_tombstones": tombstones,
            },
            "legal_pairs_inserted_and_removed": True,
        }

    # ---- Pando publication links -------------------------------------------------
    def pando_identity_links(self):
        repo_a, remote_a, work_a = self.create_repo(self.alice, "identity-pando-a")
        repo_b, remote_b, work_b = self.create_repo(self.bob, "identity-pando-b")
        owner_a, owner_b = self.owner(repo_a), self.owner(repo_b)
        assert owner_a != owner_b, "the two Pando repositories must belong to different owners"

        self.commit_and_push(work_a, self.alice, "a-gitfs.txt", "owner a gitfs before cutover")
        self.commit_and_push(work_b, self.bob, "b-gitfs.txt", "owner b gitfs before cutover")
        cutovers = self.cutover_all((repo_a, repo_b))
        head_a = self.commit_and_push(work_a, self.alice, "a-pando.txt", "owner a pando publication")
        head_b = self.commit_and_push(work_b, self.bob, "b-pando.txt", "owner b pando publication")

        closure_a = self.published_closure(
            "pando-a", repo_a, owner_a, remote_a, self.alice, head_a
        )
        closure_b = self.published_closure(
            "pando-b", repo_b, owner_b, remote_b, self.bob, head_b
        )
        assert closure_a["pack_cipher"]["tenant_id"] == owner_a
        assert closure_b["pack_cipher"]["tenant_id"] == owner_b

        artifact_a = closure_a["pack_cipher"]
        artifact_b = closure_b["pack_cipher"]
        manifest_a = self.synthetic_manifest_copy(closure_a["manifest_id"])
        manifest_b = self.synthetic_manifest_copy(closure_b["manifest_id"])
        assert self.manifest_identity_exists(manifest_a, repo_a["id"], owner_a)
        assert self.manifest_identity_exists(manifest_b, repo_b["id"], owner_b)

        try:
            # The artifact tuples below are all real registrations from the two
            # genuine publications; no synthetic remote metadata is needed.
            assert self.remote_tuple_exists(
                artifact_a["authority_id"], artifact_a["tenant_id"],
                artifact_a["namespace"], artifact_a["sha256"])
            assert self.remote_tuple_exists(
                artifact_b["authority_id"], artifact_b["tenant_id"],
                artifact_b["namespace"], artifact_b["sha256"])

            # manifest_a names owner a, so only the manifest identity triple fails.
            wrong_repo = self.probe_fk(
                "INSERT INTO pando_manifest_artifacts"
                "(manifest_id,repository_id,authority_id,tenant_id,namespace,sha256,artifact_role) "
                "VALUES('" + manifest_a + "','" + repo_b["id"] + "','"
                + artifact_a["authority_id"] + "','" + artifact_a["tenant_id"] + "','"
                + artifact_a["namespace"] + "','" + artifact_a["sha256"] + "','pack-cipher')",
                MANIFEST_IDENTITY_FK,
            )

            # manifest_a still names owner a; the artifact tuple belongs to the
            # real owner b publication, so once again only the manifest triple fails.
            wrong_tenant = self.probe_fk(
                "INSERT INTO pando_manifest_artifacts"
                "(manifest_id,repository_id,authority_id,tenant_id,namespace,sha256,artifact_role) "
                "VALUES('" + manifest_a + "','" + repo_a["id"] + "','"
                + artifact_b["authority_id"] + "','" + artifact_b["tenant_id"] + "','"
                + artifact_b["namespace"] + "','" + artifact_b["sha256"] + "','pack-cipher')",
                MANIFEST_IDENTITY_FK,
            )

            # manifest_b names owner b and repository b (a legal triple). The row
            # reuses owner a's real artifact namespace and sha256 with owner b, so
            # the tuple is absent. The namespace matches the remote row contract;
            # only the target artifact foreign key can reject this insert.
            assert self.manifest_identity_exists(manifest_b, repo_b["id"], owner_b)
            assert self.remote_tuple_exists(
                artifact_a["authority_id"], owner_a,
                artifact_a["namespace"], artifact_a["sha256"])
            assert not self.remote_tuple_exists(
                artifact_a["authority_id"], owner_b,
                artifact_a["namespace"], artifact_a["sha256"]), (
                "owner b unexpectedly owns owner a's artifact tuple; cannot prove a missing reference"
            )
            artifact_tenant_probe = self.probe_fk(
                "INSERT INTO pando_manifest_artifacts"
                "(manifest_id,repository_id,authority_id,tenant_id,namespace,sha256,artifact_role) "
                "VALUES('" + manifest_b + "','" + repo_b["id"] + "','"
                + artifact_a["authority_id"] + "','" + owner_b + "','"
                + artifact_a["namespace"] + "','" + artifact_a["sha256"] + "','pack-cipher')",
                ARTIFACT_AUTHORITY_FK,
            )

            # Legal path still works after the refusals: a real publication for
            # each owner and a real clone/fetch/fsck of the new head.
            before_a = int(self.sql(
                "SELECT count(*) FROM pando_pack_manifests WHERE repository_id='"
                + repo_a["id"] + "'"))
            before_b = int(self.sql(
                "SELECT count(*) FROM pando_pack_manifests WHERE repository_id='"
                + repo_b["id"] + "'"))
            second_a = self.commit_and_push(
                work_a, self.alice, "a-after-refusals.txt", "owner a pando after refusals")
            second_b = self.commit_and_push(
                work_b, self.bob, "b-after-refusals.txt", "owner b pando after refusals")
            assert int(self.sql(
                "SELECT count(*) FROM pando_pack_manifests WHERE repository_id='"
                + repo_a["id"] + "'")) > before_a
            assert int(self.sql(
                "SELECT count(*) FROM pando_pack_manifests WHERE repository_id='"
                + repo_b["id"] + "'")) > before_b
            self.clone_fetch_fsck("pando-a-after", remote_a, self.alice, second_a)
            self.clone_fetch_fsck("pando-b-after", remote_b, self.bob, second_b)
        finally:
            self.drop_synthetic_manifests()

        return {
            "owners": {"a": owner_a, "b": owner_b},
            "repositories": {"a": repo_a["id"], "b": repo_b["id"]},
            "cutovers": {key: {"direction": value["direction"],
                               "new_storage_backend": value["new_storage_backend"]}
                         for key, value in cutovers.items()},
            "published": {
                "a": {key: value for key, value in closure_a.items() if key != "pack_cipher"},
                "b": {key: value for key, value in closure_b.items() if key != "pack_cipher"},
            },
            "rejected": {
                "wrong_manifest_repository": wrong_repo,
                "wrong_manifest_tenant": wrong_tenant,
                "artifact_tenant_mismatch": artifact_tenant_probe,
            },
            "publication_after_refusals": {"a": second_a, "b": second_b},
            "synthetic_remote_metadata": False,
            "real_artifacts_touched": False,
        }

    def drop_synthetic_manifests(self):
        for manifest_id in self.synthetic_manifest_ids:
            self.sql("DELETE FROM pando_manifest_artifacts WHERE manifest_id='" + manifest_id + "'")
            self.sql("DELETE FROM pando_pack_manifests WHERE id='" + manifest_id + "'")
            assert self.sql(
                "SELECT count(*) FROM pando_manifest_artifacts WHERE manifest_id='"
                + manifest_id + "'"
            ) == "0"
            assert self.sql(
                "SELECT count(*) FROM pando_pack_manifests WHERE id='" + manifest_id + "'"
            ) == "0"
        self.synthetic_manifest_ids = []

    def cleanup(self):
        try:
            if self.schema_created:
                self.drop_synthetic_manifests()
        finally:
            self.synthetic_manifest_ids = []
            super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, help="Write machine-readable JSON report (no credentials)")
    parser.add_argument("--keep", action="store_true", help="Keep temporary Git/data/log files; SQL schema is still removed")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    try:
        require_environment()
        if not os.access(args.binary, os.X_OK):
            raise RuntimeError("binary is not executable: " + args.binary)
    except RuntimeError as error:
        parser.error(str(error))

    h = IdentityHarness(args)
    passed = False
    try:
        h.case("setup", h.setup)
        h.case("schema134_contract", h.schema_contract)
        h.case("gitfs_lifecycle_identity_pairs", h.gitfs_identity_pairs)
        h.case("pando_manifest_identity_links", h.pando_identity_links)
        passed = True
    except Exception as error:
        args.keep = True
        log = h.root / "server.log"
        if log.exists():
            print("retained server log: " + str(log), file=sys.stderr)
            print(h.redact(log.read_text(errors="replace")[-8000:]), file=sys.stderr)
        print(h.redact(error), file=sys.stderr)
    finally:
        h.cleanup()
    report = {
        "passed": passed,
        "cases": h.results,
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "required_environment": list(REQUIRED_ENV),
        "not_tested": [
            "Dirty pre-upgrade refusal on a schema133 database containing inconsistent "
            "identity pairs is proved by tests/storage_identity_upgrade.py, a separate "
            "native entry point; this script never runs a legacy binary.",
            "Backup format/catalog gates and legacy schema133 restore are coordinator-owned "
            "follow-ups; this branch makes no backup gate claim.",
        ],
        "reused_runtime_proofs": [
            "tests/storage_lifecycle.py",
            "tests/storage_lifecycle_physical.py",
        ],
        "limitations": h.limits,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
