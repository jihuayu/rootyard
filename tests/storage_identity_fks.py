#!/usr/bin/env python3
"""Native regression coverage for schema134 repository/tenant identity FKs (#90).

The shared Harness starts the real `rootyard` binary against a private
PostgreSQL schema. Two repositories with two different owners are created and
pushed with real stock Git; one of them is cut over to Pando so the genuine
publication path writes `pando_pack_manifests` and `pando_manifest_artifacts`
through real Garage + Vault Transit. The positives are therefore produced by
trusted code, never by this script.

Negative cases are plain SQL inserts into this run's own schema. A synthetic
manifest row is copied from a legal one (fresh ids, same repository/tenant) so
its `(manifest_id, artifact_role)` primary key is still free: a rejection can
only come from the intended composite foreign key, not from a duplicate key or
a check constraint. The synthetic remote-artifact row used for the artifact
tenant case carries no remote bytes, exists only to satisfy the independent
artifact authority/tenant FK in the negative test, and is deleted afterwards.
It is not evidence that anything was uploaded.

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
            "Dirty pre-upgrade refusal (inconsistent rows on a schema133 database) is not "
            "exercised by this script; it is a documented follow-up case."
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
        self.synthetic_artifact_paths = []

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
        raw = self.sql("SELECT constraint_name || '|' || sqlstate FROM schema134_probe")
        assert raw, "statement was accepted but should violate " + expected_constraint
        observed, state = raw.split("|", 1)
        assert state == "23503", (observed, state, expected_constraint)
        assert observed == expected_constraint, (observed, expected_constraint)
        return {"sqlstate": state, "constraint": observed}

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
            "SELECT conname || '|' || pg_get_constraintdef(oid) || '|' || convalidated "
            "FROM pg_constraint WHERE conname IN ("
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
            definitions[name] = (definition, validated)
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
        assert "pando_manifest_artifacts_authority_id_tenant_id_namespace__fkey" in definitions, (
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
        oid_legal = "e" * 40
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
        repo, remote, work = self.create_repo(self.alice, "identity-pando")
        owner = self.owner(repo)
        self.commit_and_push(work, self.alice, "first.txt", "gitfs before cutover")
        self.stop()
        report = json.loads(self.cli("pando-transition", "cutover", "--repository", repo["id"]))
        assert report["direction"] == "gitfs_to_pando", report
        self.start()
        head = self.commit_and_push(work, self.alice, "second.txt", "pando publication")

        # Positive: the trusted publication produced links that agree with their
        # manifest on both identity columns, and every artifact role is present.
        raw = self.sql(
            "SELECT count(*),count(*) FILTER (WHERE l.repository_id=m.repository_id "
            "AND l.tenant_id=m.tenant_id) FROM pando_manifest_artifacts l "
            "JOIN pando_pack_manifests m ON m.id=l.manifest_id "
            "WHERE m.repository_id='" + repo["id"] + "'"
        )
        total, matched = (int(value) for value in raw.split("|"))
        assert total >= 4, (total, matched)
        assert matched == total, (total, matched)
        roles = self.sql(
            "SELECT string_agg(DISTINCT artifact_role, ',' ORDER BY artifact_role) "
            "FROM pando_manifest_artifacts l JOIN pando_pack_manifests m ON m.id=l.manifest_id "
            "WHERE m.repository_id='" + repo["id"] + "'"
        )
        assert roles == "index-cipher,index-envelope,pack-cipher,pack-envelope", roles

        clone = self.root / "clone-published"
        self.git("clone", remote, str(clone), token=self.alice)
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == head
        self.git("fsck", "--full", cwd=clone)

        source = self.sql(
            "SELECT id::text FROM pando_pack_manifests WHERE repository_id='"
            + repo["id"] + "' ORDER BY created_at DESC LIMIT 1"
        )
        pack_link = self.sql(
            "SELECT authority_id::text || '|' || tenant_id::text || '|' || namespace "
            "|| '|' || sha256 FROM pando_manifest_artifacts WHERE manifest_id='"
            + source + "' AND artifact_role='pack-cipher'"
        )
        authority, artifact_tenant, namespace, sha256 = pack_link.split("|")
        assert artifact_tenant == owner, (artifact_tenant, owner)

        # Two unlinked manifest copies: fresh ids, identical legal payload, so the
        # artifact-role primary key is free for the negative inserts below.
        manifest_a, manifest_b = str(uuid.uuid4()), str(uuid.uuid4())
        self.synthetic_manifest_ids = [manifest_a, manifest_b]
        for manifest_id in self.synthetic_manifest_ids:
            self.sql(
                "INSERT INTO pando_pack_manifests"
                "(id,repository_id,tenant_id,storage_generation,object_format,manifest) "
                "SELECT '" + manifest_id + "',repository_id,tenant_id,storage_generation,"
                "object_format,manifest FROM pando_pack_manifests WHERE id='" + source + "'"
            )
            assert self.sql(
                "SELECT count(*) FROM pando_manifest_artifacts WHERE manifest_id='"
                + manifest_id + "'"
            ) == "0"

        # A second repository with a different owner, only used as the wrong
        # repository id in the first negative case.
        other_repo = self.create_repo(self.bob, "identity-pando-other")[0]
        other_owner = self.owner(other_repo)
        assert other_owner != owner

        wrong_repo = self.probe_fk(
            "INSERT INTO pando_manifest_artifacts"
            "(manifest_id,repository_id,authority_id,tenant_id,namespace,sha256,artifact_role) "
            "VALUES('" + manifest_a + "','" + other_repo["id"] + "','" + authority + "','"
            + artifact_tenant + "','" + namespace + "','" + sha256 + "','pack-cipher')",
            "pando_manifest_artifacts_manifest_identity_fkey",
        )

        # The artifact tenant case needs an artifact row owned by the other tenant
        # so only the manifest triple can fail. It has no remote bytes, is state
        # 'deleted' (never a deletion candidate) and is removed below.
        synthetic_sha = hashlib.sha256(("schema134-" + str(uuid.uuid4())).encode()).hexdigest()
        synthetic_path = "schema134-negative/" + str(uuid.uuid4())
        self.synthetic_artifact_paths.append(synthetic_path)
        self.sql(
            "INSERT INTO pando_remote_artifacts"
            "(authority_id,tenant_id,namespace,sha256,size,object_generation,remote_path,"
            "state,deleted_at) VALUES('" + authority + "','" + other_owner
            + "','pando-cipher','" + synthetic_sha + "',0,1,'" + synthetic_path
            + "','deleted',clock_timestamp())"
        )

        wrong_tenant = self.probe_fk(
            "INSERT INTO pando_manifest_artifacts"
            "(manifest_id,repository_id,authority_id,tenant_id,namespace,sha256,artifact_role) "
            "VALUES('" + manifest_a + "','" + repo["id"] + "','" + authority + "','"
            + other_owner + "','pando-cipher','" + synthetic_sha + "','pack-cipher')",
            "pando_manifest_artifacts_manifest_identity_fkey",
        )
        artifact_tenant_probe = self.probe_fk(
            "INSERT INTO pando_manifest_artifacts"
            "(manifest_id,repository_id,authority_id,tenant_id,namespace,sha256,artifact_role) "
            "VALUES('" + manifest_b + "','" + repo["id"] + "','" + authority + "','"
            + other_owner + "','pando-envelope','" + synthetic_sha + "','pack-envelope')",
            "pando_manifest_artifacts_authority_id_tenant_id_namespace__fkey",
        )

        # Legal path still works after the refusals: another real publication and
        # a real fetch of the new head.
        second = self.commit_and_push(work, self.alice, "third.txt", "pando after refusals")
        assert int(
            self.sql(
                "SELECT count(*) FROM pando_pack_manifests WHERE repository_id='"
                + repo["id"] + "'"
            )
        ) >= 2
        clone2 = self.root / "clone-after-refusals"
        self.git("clone", remote, str(clone2), token=self.alice)
        assert self.git("rev-parse", "HEAD", cwd=clone2).stdout.decode().strip() == second
        self.git("fsck", "--full", cwd=clone2)

        # Remove exactly this run's synthetic rows.
        for manifest_id in self.synthetic_manifest_ids:
            self.sql("DELETE FROM pando_manifest_artifacts WHERE manifest_id='" + manifest_id + "'")
            self.sql("DELETE FROM pando_pack_manifests WHERE id='" + manifest_id + "'")
        for path in self.synthetic_artifact_paths:
            self.sql("DELETE FROM pando_remote_artifacts WHERE remote_path='" + path + "'")
        for manifest_id in self.synthetic_manifest_ids:
            assert self.sql(
                "SELECT count(*) FROM pando_manifest_artifacts WHERE manifest_id='"
                + manifest_id + "'"
            ) == "0"
        assert self.sql(
            "SELECT count(*) FROM pando_remote_artifacts WHERE remote_path LIKE 'schema134-negative/%'"
        ) == "0"
        self.synthetic_manifest_ids = []
        self.synthetic_artifact_paths = []

        return {
            "repository_id": repo["id"],
            "published_links": total,
            "artifact_roles": roles,
            "rejected": {
                "wrong_manifest_repository": wrong_repo,
                "wrong_manifest_tenant": wrong_tenant,
                "artifact_tenant_mismatch": artifact_tenant_probe,
            },
            "publication_after_refusals": second,
            "real_artifacts_touched": False,
        }

    def cleanup(self):
        try:
            if self.schema_created:
                for manifest_id in self.synthetic_manifest_ids:
                    self.sql(
                        "DELETE FROM pando_manifest_artifacts WHERE manifest_id='"
                        + manifest_id + "'"
                    )
                    self.sql("DELETE FROM pando_pack_manifests WHERE id='" + manifest_id + "'")
                for path in self.synthetic_artifact_paths:
                    self.sql(
                        "DELETE FROM pando_remote_artifacts WHERE remote_path='" + path + "'"
                    )
        finally:
            self.synthetic_manifest_ids = []
            self.synthetic_artifact_paths = []
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
            "identity pairs (fixed count-only abort) is not exercised here.",
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
