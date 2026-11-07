#!/usr/bin/env python3
"""Native dirty-schema133 upgrade refusal drill for schema134 identity FKs (#90).

This is a separate, compact entry point; tests/storage_identity_fks.py remains
the post-134 contract/real-Pando-publication suite. Here a trusted pre-134
binary (for example the coordinator's real ``gc133-v2`` build) creates an
isolated private PostgreSQL schema and two real GitFS repositories owned by two
different users, pushes real Git history, and leaves a genuine schema133 ledger.
The old DDL accepts a maintenance job whose tenant_id names the other owner; this
script seeds exactly one such row plus one legal control row.

The candidate ``--binary`` must then fail ``migrate`` with the fixed schema134
preflight diagnostic. The assertion is strict: SQLSTATE/error text must contain
the fixed sentence and count-only numbers, must not contain any row, repository
or owner UUID, version 134 must not be in the ledger, none of the new constraints
may exist, the old single-column manifest link must still be there, and both
seeded rows must be unchanged in the five identity/state columns checked below (the migration transaction rolled
back). This is a refusal, not a silent repair.

Only after the script explicitly deletes its own bad row does the candidate
upgrade succeed. The four validated cascading composite foreign keys and the
supporting unique constraint are then checked, version 134 is in the ledger, the
legal control row survives, and both pre-upgrade repositories still clone, fetch
and pass ``git fsck --full`` through the upgraded binary.

No real Pando cutover/publication is needed for the dirty maintenance case: the
seeded inconsistency is a storage_maintenance_jobs tenant pair, and the upgrade
preflight covers all four identity classes. Backup format/catalog gates and real
Pando publication remain separate entry points.

Every schema, data directory, port and temporary path is private to this run; the
CLI has no hardcoded scratch paths and no credential is printed in the report.
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

REQUIRED_ENV = ("ROOTYARD_TEST_DATABASE_URL",)

SCHEMA134_FKS = (
    "pando_manifest_artifacts_manifest_identity_fkey",
    "storage_maintenance_repo_state_repository_owner_fkey",
    "storage_maintenance_jobs_repository_owner_fkey",
    "storage_maintenance_tombstones_repository_owner_fkey",
)
SCHEMA134_UNIQUE = "pando_pack_manifests_id_repository_tenant_key"
REMOVED_FK = "pando_manifest_artifacts_manifest_id_fkey"
SCHEMA134_CONSTRAINTS = SCHEMA134_FKS + (SCHEMA134_UNIQUE,)

FIXED_REFUSAL = (
    "schema134 refuses to upgrade: 0 manifest link row(s), "
    "0 repository state row(s), 1 maintenance job(s) and 0 tombstone(s) "
    "disagree with their repository identity; no row was modified"
)


class UpgradeHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.candidate_binary = str(Path(args.binary).resolve())
        self.legacy_binary = str(Path(args.legacy_binary).resolve())
        self.limits.append(
            "The source schema is created by the real legacy binary, not by an "
            "edited manifest, dump or hand-written migration subset."
        )
        self.limits.append(
            "This entry point proves the dirty storage_maintenance_jobs refusal and "
            "the clean rerun only; it does not perform a real Pando cutover or "
            "publication. tests/storage_identity_fks.py proves that separately."
        )
        self.limits.append(
            "Backup format/catalog gates and legacy schema133 restore are "
            "coordinator-owned follow-ups; no backup gate claim is made here."
        )
        self.bad_job_id = str(uuid.uuid4())
        self.legal_job_id = str(uuid.uuid4())
        self.repo_a = None
        self.repo_b = None
        self.remote_a = None
        self.remote_b = None
        self.work_a = None
        self.work_b = None
        self.head_a = None
        self.head_b = None
        self.owner_a = None
        self.owner_b = None
        self.bad_row_expected = None
        self.legal_row_expected = None

    # ---- small helpers ----------------------------------------------------------
    def create_repo(self, token, name):
        code, raw, _ = self.http(
            "/api/repos", token=token, method="POST",
            body={"name": name, "object_format": "sha1"},
        )
        assert code == 201, (code, raw[:400])
        repo = json.loads(raw)
        remote = self.base + repo["clone_path"]
        work = self.root / ("work-" + repo["id"])
        self.git("init", "--object-format=sha1", "--initial-branch=main", str(work))
        self.git("config", "user.name", "Upgrade Drill", cwd=work)
        self.git("config", "user.email", "upgrade@example.invalid", cwd=work)
        self.git("remote", "add", "origin", remote, cwd=work)
        return repo, remote, work

    def commit_and_push(self, work, token, filename, text):
        (work / filename).write_text(text)
        self.git("add", filename, cwd=work)
        self.git("commit", "-m", text, cwd=work)
        oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=token)
        return oid

    def clone_fetch_fsck(self, label, remote, token, expected_head):
        checkout = self.root / ("clone-" + label)
        self.git("clone", remote, str(checkout), token=token)
        assert self.git("rev-parse", "HEAD", cwd=checkout).stdout.decode().strip() == expected_head
        self.git("fetch", "origin", cwd=checkout, token=token)
        self.git("fsck", "--full", cwd=checkout)

    def job_row(self, job_id):
        return self.sql(
            "SELECT repository_id::text || '|' || tenant_id::text || '|' || kind "
            "|| '|' || state || '|' || repository_generation::text "
            "FROM storage_maintenance_jobs WHERE id='" + job_id + "'"
        )

    def constraint_defs(self, names):
        quoted = ",".join("'" + name + "'" for name in names)
        raw = self.sql(
            "SELECT k.conname::text || '|' || k.convalidated::text || '|' || k.contype::text "
            "|| '|' || k.confdeltype::text || '|' || pg_get_constraintdef(k.oid) "
            "FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=current_schema() AND k.conname IN (" + quoted + ")"
        )
        definitions = {}
        for line in raw.splitlines():
            name, validated, contype, delete_action, definition = line.split("|", 4)
            # Normalise a same-schema qualified target so search_path cannot
            # change the shape assertions.
            definitions[name] = {
                "validated": validated,
                "type": contype,
                "delete_action": delete_action,
                "definition": definition.replace("public.", ""),
            }
        return definitions

    def constraint_count(self, names):
        quoted = ",".join("'" + name + "'" for name in names)
        return self.sql(
            "SELECT count(*) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=current_schema() AND k.conname IN (" + quoted + ")"
        )

    def assert_legacy_schema(self):
        assert self.sql("SELECT max(version) FROM schema_migrations") == "133"
        assert self.sql(
            "SELECT count(*) FROM schema_migrations WHERE version=134"
        ) == "0"
        assert self.constraint_count(SCHEMA134_CONSTRAINTS) == "0"
        assert self.constraint_count((REMOVED_FK,)) == "1"

    def assert_upgraded_schema(self):
        assert self.sql("SELECT max(version) FROM schema_migrations") == "134"
        assert self.sql(
            "SELECT count(*) FROM schema_migrations WHERE version=134"
        ) == "1"
        definitions = self.constraint_defs(SCHEMA134_CONSTRAINTS)
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
        observed = {}
        for name, (columns, target) in composite.items():
            assert name in definitions, name
            info = definitions[name]
            assert info["validated"] == "true", (name, info)
            assert info["type"] == "f", (name, info)
            assert info["delete_action"] == "c", (name, info)
            assert columns in info["definition"], (name, info)
            assert target in info["definition"], (name, info)
            assert "ON DELETE CASCADE" in info["definition"], (name, info)
            observed[name] = "validated composite cascade"
        unique = definitions[SCHEMA134_UNIQUE]
        assert unique["validated"] == "true", unique
        assert unique["type"] == "u", unique
        assert "UNIQUE (id, repository_id, tenant_id)" in unique["definition"], unique
        assert self.constraint_count((REMOVED_FK,)) == "0"
        return {
            "schema_version": 134,
            "composite_fks": sorted(composite),
            "unique_constraint": SCHEMA134_UNIQUE,
            "single_column_manifest_fk_removed": True,
            "observed": observed,
        }

    # ---- cases ------------------------------------------------------------------
    def legacy_stack(self):
        self.sql('CREATE SCHEMA "' + self.schema + '"', isolated=False)
        self.schema_created = True
        saved_binary = self.args.binary
        self.args.binary = self.legacy_binary
        try:
            # The legacy binary applies its own genuine schema133 migrations.
            self.cli("migrate")
            self.assert_legacy_schema()
            self.alice = self.account("create-user", "alice")
            self.bob = self.account("create-user", "bob")
            self.start()
            self.repo_a, self.remote_a, self.work_a = self.create_repo(
                self.alice, "upgrade-owner-a")
            self.repo_b, self.remote_b, self.work_b = self.create_repo(
                self.bob, "upgrade-owner-b")
            self.head_a = self.commit_and_push(
                self.work_a, self.alice, "a.txt", "upgrade owner a")
            self.head_b = self.commit_and_push(
                self.work_b, self.bob, "b.txt", "upgrade owner b")
            self.stop()
        finally:
            self.args.binary = saved_binary

        self.owner_a = self.sql(
            "SELECT owner_id::text FROM repositories WHERE id='" + self.repo_a["id"] + "'")
        self.owner_b = self.sql(
            "SELECT owner_id::text FROM repositories WHERE id='" + self.repo_b["id"] + "'")
        generation_a = self.sql(
            "SELECT storage_generation::text FROM repositories WHERE id='"
            + self.repo_a["id"] + "'")
        generation_b = self.sql(
            "SELECT storage_generation::text FROM repositories WHERE id='"
            + self.repo_b["id"] + "'")
        assert self.owner_a != self.owner_b, "two owners are required for a wrong-tenant pair"

        # The schema133 DDL only has single-column FKs, so this wrong tenant pair
        # is accepted. It is the one dirty class seeded by this script.
        self.sql(
            "INSERT INTO storage_maintenance_jobs"
            "(id,repository_id,tenant_id,kind,state,repository_generation,completed_at) "
            "VALUES('" + self.bad_job_id + "','" + self.repo_a["id"] + "','"
            + self.owner_b + "','gitfs_repack','failed'," + generation_a
            + ",clock_timestamp())"
        )
        # A legal control row must survive the failed attempt and the later upgrade.
        self.sql(
            "INSERT INTO storage_maintenance_jobs"
            "(id,repository_id,tenant_id,kind,state,repository_generation,completed_at) "
            "VALUES('" + self.legal_job_id + "','" + self.repo_b["id"] + "','"
            + self.owner_b + "','gitfs_stage_cleanup','failed'," + generation_b
            + ",clock_timestamp())"
        )
        self.bad_row_expected = (
            self.repo_a["id"] + "|" + self.owner_b + "|gitfs_repack|failed|" + generation_a
        )
        self.legal_row_expected = (
            self.repo_b["id"] + "|" + self.owner_b + "|gitfs_stage_cleanup|failed|" + generation_b
        )
        assert self.job_row(self.bad_job_id) == self.bad_row_expected
        assert self.job_row(self.legal_job_id) == self.legal_row_expected
        return {
            "source_schema_version": 133,
            "owners": {"a": self.owner_a, "b": self.owner_b},
            "repositories": {"a": self.repo_a["id"], "b": self.repo_b["id"]},
            "heads": {"a": self.head_a, "b": self.head_b},
            "seeded_dirty_class": "storage_maintenance_jobs.tenant_id != repositories.owner_id",
            "bad_row_id": self.bad_job_id,
            "legal_control_row_id": self.legal_job_id,
        }

    def candidate_refuses_dirty_upgrade(self):
        saved_binary = self.args.binary
        self.args.binary = self.candidate_binary
        try:
            result = self.run([self.candidate_binary, "migrate"], check=False)
        finally:
            self.args.binary = saved_binary
        stdout = self.redact(result.stdout.decode(errors="replace"))
        stderr = self.redact(result.stderr.decode(errors="replace"))
        combined = stdout + "\n" + stderr
        assert result.returncode != 0, "candidate silently upgraded a dirty schema133 database"
        assert FIXED_REFUSAL in combined, (
            "candidate did not emit the fixed count-only schema134 refusal",
            combined[-4000:],
        )
        # The abort text is fixed and count-only: no own row, repository, owner or
        # object identifier may leak into the failure output.
        for label, value in (("bad_job", self.bad_job_id),
                             ("legal_job", self.legal_job_id),
                             ("repo_a", self.repo_a["id"]),
                             ("repo_b", self.repo_b["id"]),
                             ("owner_a", self.owner_a),
                             ("owner_b", self.owner_b)):
            assert value not in stdout, (label, "candidate stdout leaked an identifier")
            assert value not in stderr, (label, "candidate stderr leaked an identifier")

        # The failed migration transaction must be fully rolled back.
        self.assert_legacy_schema()
        assert self.job_row(self.bad_job_id) == self.bad_row_expected, (
            "the bad row was modified or removed instead of being preserved"
        )
        assert self.job_row(self.legal_job_id) == self.legal_row_expected
        return {
            "candidate_exit_status": result.returncode,
            "diagnostic": FIXED_REFUSAL,
            "row_identifiers_absent": True,
            "ledger_version": 133,
            "constraints_absent": list(SCHEMA134_CONSTRAINTS),
            "old_single_column_fk_preserved": True,
            "bad_row_preserved": True,
            "legal_control_row_preserved": True,
        }

    def explicit_repair_then_upgrade(self):
        assert self.job_row(self.bad_job_id) == self.bad_row_expected
        self.sql("DELETE FROM storage_maintenance_jobs WHERE id='" + self.bad_job_id + "'")
        assert self.sql(
            "SELECT count(*) FROM storage_maintenance_jobs WHERE id='" + self.bad_job_id + "'"
        ) == "0"
        assert self.job_row(self.legal_job_id) == self.legal_row_expected

        result = self.run([self.candidate_binary, "migrate"], check=False)
        assert result.returncode == 0, (
            "candidate still refused after the owned bad row was deleted",
            self.redact(result.stderr.decode(errors="replace")[-4000:]),
        )
        assert "database migrations applied" in self.redact(
            result.stderr.decode(errors="replace")), result.stderr[-2000:]
        contract = self.assert_upgraded_schema()
        assert self.job_row(self.bad_job_id) == ""
        assert self.job_row(self.legal_job_id) == self.legal_row_expected

        saved_binary = self.args.binary
        self.args.binary = self.candidate_binary
        try:
            self.start()
            try:
                self.clone_fetch_fsck("upgrade-a", self.remote_a, self.alice, self.head_a)
                self.clone_fetch_fsck("upgrade-b", self.remote_b, self.bob, self.head_b)
            finally:
                self.stop()
        finally:
            self.args.binary = saved_binary
        return {
            **contract,
            "upgrade_after_explicit_delete": True,
            "bad_row_removed_by_test": True,
            "legal_control_row_preserved": True,
            "clones_fetched_and_fsck": {"a": self.head_a, "b": self.head_b},
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard",
                        help="candidate binary that knows schema134")
    parser.add_argument("--legacy-binary", required=True,
                        help="real pre-134 binary that applies schema133 (for example gc133-v2)")
    parser.add_argument("--report", type=Path,
                        help="Write machine-readable JSON report (no credentials)")
    parser.add_argument("--keep", action="store_true",
                        help="Keep temporary Git/data/log files; SQL schema is still removed")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    args.legacy_binary = str(Path(args.legacy_binary).resolve())
    try:
        missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
        if missing:
            raise RuntimeError(
                "storage identity upgrade drill needs a real PostgreSQL test database; missing: "
                + ", ".join(missing))
        for label, binary in (("candidate", args.binary), ("legacy", args.legacy_binary)):
            if not os.access(binary, os.X_OK):
                raise RuntimeError(label + " binary is not executable: " + binary)
    except RuntimeError as error:
        parser.error(str(error))

    h = UpgradeHarness(args)
    passed = False
    try:
        h.case("legacy_schema133_dirty_seed", h.legacy_stack)
        h.case("candidate_refuses_dirty_upgrade", h.candidate_refuses_dirty_upgrade)
        h.case("explicit_repair_then_upgrade", h.explicit_repair_then_upgrade)
        passed = True
    except Exception as error:
        args.keep = True
        log = h.root / "server.log"
        if log.exists():
            print("retained server log: " + str(log), file=sys.stderr)
            print(h.redact(log.read_text(errors="replace")[-8000:]), file=sys.stderr)
        print(h.redact(error), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(error)))
            passed = False
    report = {
        "passed": passed,
        "cases": h.results,
        "candidate_binary_sha256": hashlib.sha256(
            Path(args.binary).read_bytes()).hexdigest(),
        "legacy_binary_sha256": hashlib.sha256(
            Path(args.legacy_binary).read_bytes()).hexdigest(),
        "required_environment": list(REQUIRED_ENV),
        "not_tested": [
            "Real Pando publication is not exercised by this dirty-maintenance "
            "upgrade entry point; tests/storage_identity_fks.py owns that proof.",
            "Backup format/catalog gates and legacy schema133 restore are "
            "coordinator-owned follow-ups; no backup gate claim is made here.",
            "GC/retention worker behaviour after upgrade is outside this script.",
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
