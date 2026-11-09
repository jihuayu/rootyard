#!/usr/bin/env python3
"""Executable #120 gap test: current-format metadata restore of served Blob repos.

Requires an attested absolute --binary, trusted --git, a disposable PostgreSQL
17 administrator with CREATEDB, and the strict S3 profile used by
blob_only_service.py. Creates and drops only run-owned databases. All ready
repositories, packs and acknowledgements come from real HTTP/stock Git traffic.

This is deliberately NOT a green qualification of the present implementation:
backup::git_inventory currently requires a persistent bare repo even for a ready
pg_refstore repository, so the positive snapshot case must fail until production
backup supports that backend. Do not bypass that check or fabricate a bare repo.

Even after that gap is fixed, this drill retains the same external Blob originals
and tests restored metadata against them. It does NOT back up Blob bytes or prove
that the archive independently contains a complete Blob closure. It is not wired
into CI and does not establish #120 completion.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.parse
import uuid

from backup import bounded_line
from blob_only_service import (
    BlobOnlyHarness, NativeProfile, ProfileError, ZERO_SHA1,
    assert_receive_report_ok, check_blob_profile, need, pg_replay_counts,
    receive_pack_request, sensitive_values, sha256_file, validate_report_cases,
    write_report,
)
from schema_baseline import CURRENT_BACKUP_FORMAT, CURRENT_SCHEMA_VERSION, SCHEMA_VERSIONS, catalog_tables

CASES = (
    "real_http_sha1_sha256_source_without_persistent_bare",
    "offline_volume_and_postgres_snapshot_barriers",
    "incomplete_and_damaged_archives_rejected_before_sql",
    "existing_database_and_directory_targets_refused",
    "post_backup_acknowledged_write_excluded",
    "fresh_database_restore_clone_refs_content_fsck",
    "restored_exact_receive_replay_without_second_effect",
)
LIMITATIONS = [
    "Known production gap: nonempty pg_refstore backup currently requires a missing persistent bare repository; the positive snapshot must fail.",
    "External Blob originals remain in the same provider/root; no Blob bytes are exported or imported by this drill.",
    "The archive is not qualified as an independent PG+Blob closure backup or as #120 completion.",
    "The operator stops serve-blob before backup; serve-blob currently does not hold the legacy volume flock or check its restore guard.",
    "No interrupted restore, multi-host failure, physical power-loss, throughput, or production RPO/RTO qualification is claimed.",
    "No legacy format/schema upgrade is exercised. The current binary must restore its own format21/schema147 archive.",
    "Remote Blob deletion is disabled; objects under this run's private prefix are retained.",
]


class Drill(BlobOnlyHarness):
    def __init__(self, args, profile, blob_profile):
        super().__init__(args, profile, blob_profile)
        self.schema = "public"
        self.admin = self.base_db
        self.restore_admin = os.environ.get("ROOTYARD_RESTORE_TEST_DATABASE_URL", self.admin)
        self.created = []
        self.source_db = self.target_db = None
        self.backup = self.root / "backup"
        self.target = self.root / "restored-data"
        self.source_volume = Path(self.env["ROOTYARD_DATA_DIR"])
        self.source_scratch = self.scratch
        self.specs = []
        prefix = self.env.get("ROOTYARD_BLOB_ROOT", "").rstrip("/")
        self.env["ROOTYARD_BLOB_ROOT"] = "/".join(filter(None, (prefix, "backup147-" + uuid.uuid4().hex)))
        self.secrets.extend(sensitive_values(os.environ))
        self.secrets.extend((self.restore_admin, self.env["ROOTYARD_BLOB_ROOT"]))
        for value in (self.admin, self.restore_admin):
            password = urllib.parse.urlsplit(value).password
            if password:
                self.secrets.append(urllib.parse.unquote(password))

    def pg_env(self, database):
        """Keep URLs and passwords out of argv; preserve supported libpq options."""
        parts = urllib.parse.urlsplit(database)
        assert parts.scheme in ("postgres", "postgresql") and parts.hostname
        options = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        assert "options" not in options, "dedicated backup databases cannot use search_path options"
        env = self.env.copy()
        for name in ("PGOPTIONS", "PGDATABASE", "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD"):
            env.pop(name, None)
        env.update(PGHOST=parts.hostname, PGPORT=str(parts.port or 5432),
                   PGDATABASE=urllib.parse.unquote(parts.path.lstrip("/")),
                   PGUSER=urllib.parse.unquote(parts.username or ""),
                   PGPASSWORD=urllib.parse.unquote(parts.password or ""),
                   PGCONNECT_TIMEOUT="5", PGTZ="UTC")
        for key, name in (("sslmode", "PGSSLMODE"), ("sslrootcert", "PGSSLROOTCERT"),
                          ("sslcert", "PGSSLCERT"), ("sslkey", "PGSSLKEY")):
            if key in options:
                env[name] = options.pop(key)
        assert not options, "unsupported PostgreSQL test URL parameters"
        return env

    def query(self, database, sql):
        return self.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql],
                        env=self.pg_env(database)).stdout.decode().strip()

    def sql(self, query, isolated=True):
        return self.query(self.db if isolated else self.base_db, query)

    def no_bare(self, repo, stage):
        directory = Path(self.env["ROOTYARD_DATA_DIR"]) / "repos"
        assert not list(directory.glob("*.git")), "persistent bare exists: " + stage
        assert not directory.joinpath(repo["id"] + ".git").exists(), "persistent bare exists: " + stage

    def new_database(self, admin):
        name = "rootyard_blob_backup_" + uuid.uuid4().hex
        self.query(admin, 'CREATE DATABASE "' + name + '" TEMPLATE template0')
        self.created.append((admin, name))
        database = urllib.parse.urlunsplit(urllib.parse.urlsplit(admin)._replace(path="/" + name))
        self.secrets.append(database)
        return database

    def backup_command(self, destination=None, check=True):
        return self.run([self.args.binary, "backup", str(destination or self.backup), "--offline"], check=check)

    def restore_command(self, source=None, target=None, database=None, check=True):
        env = self.env.copy()
        env.update(DATABASE_URL=database or self.target_db, ROOTYARD_DATA_DIR=str(target or self.target))
        return self.run([self.args.binary, "restore", str(source or self.backup), "--isolated", "--trust-backup"],
                        env=env, check=check)

    def ledger_digests(self, database):
        """Read-only exact canonical row-set digests, never returned token rows."""
        tables = sorted(name for name in catalog_tables(CURRENT_SCHEMA_VERSION)
                        if name.startswith("ref_store_") or name == "repositories")
        result = {}
        for table in tables:
            assert table.replace("_", "").isalnum()
            raw = self.query(database,
                "SELECT count(*)::text || '|' || encode(sha256(convert_to("
                "coalesce(string_agg(to_jsonb(t)::text, E'\\n' ORDER BY to_jsonb(t)::text), ''),"
                "'UTF8')), 'hex') FROM public.\"" + table + "\" t")
            count, digest = raw.split("|")
            result[table] = {"count": int(count), "sha256": digest}
        return result

    def synthetic_source(self):
        self.source_db = self.new_database(self.admin)
        self.target_db = self.new_database(self.restore_admin)
        self.db = self.source_db
        self.env["DATABASE_URL"] = self.db
        self.cli("migrate")
        # This real maintenance entry initializes the archive's compatibility
        # volume before any repository exists. No hand-made volume identity,
        # fake bare repository, SQL ready row, proof, registration or ACK.
        self.cli("reconcile")
        assert self.source_volume.joinpath(".volume-id").is_file()
        self.alice = self.account("create-user", "alice")
        self.reader = self.account("create-token", "alice", "--read-only")
        self.revoked = self.account("create-token", "alice")
        self.start()
        for fmt in ("sha1", "sha256"):
            name = "backup-" + fmt
            repo, _ = self.create(name, self.alice, fmt)
            remote = self.base + repo["clone_path"]
            work = self.root / (name + "-work")
            self.empty_clone(remote, work, self.alice)
            self.configure(work)
            files = {"hello.txt": fmt + " backed by Blob\n", "nested/empty": b"",
                     "payload.bin": bytes(range(256)) * 128}
            oid = self.commit_files(work, "offline backup boundary", files)
            if fmt == "sha1":
                pack = self.run([str(self.profile.git), "pack-objects", "--stdout", "--all"],
                                cwd=work, data=b"").stdout
                assert pack.startswith(b"PACK")
                self.replay_operation = str(uuid.uuid4())
                self.replay_body = receive_pack_request(ZERO_SHA1, oid, "refs/heads/main", pack)
                self.replay_destination = repo["clone_path"] + "/git-receive-pack"
                code, self.replay_report, _ = self.http(
                    self.replay_destination, token=self.alice, method="POST", body=self.replay_body,
                    content_type="application/x-git-receive-pack-request",
                    extra_headers={"X-Rootyard-Operation": self.replay_operation})
                assert code == 200, "real initial receive-pack did not ACK: " + str(code)
                assert_receive_report_ok(self.replay_report, "refs/heads/main")
            else:
                self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
            self.git("tag", "backup-boundary", oid, cwd=work)
            self.git("push", "origin", "refs/tags/backup-boundary", cwd=work, token=self.alice)
            refs = self.remote_refs(remote, self.alice)
            assert refs["refs/heads/main"] == refs["refs/tags/backup-boundary"] == oid
            self.exact_clone(remote, self.root / (name + "-source-clone"), oid, fmt, files, self.reader)
            self.no_bare(repo, "before offline backup")
            self.specs.append({"repo": repo, "remote": remote, "work": work,
                               "oid": oid, "format": fmt, "files": files, "refs": refs})
        self.stop()
        self.source_rows = self.ledger_digests(self.source_db)
        for table in ("ref_store_serving_repositories", "ref_store_serving_operations",
                      "ref_store_core_pack_publications", "ref_store_operations"):
            assert self.source_rows[table]["count"] >= 2, table + " was not populated by real serving"
        assert self.source_rows["ref_store_core_serving_reads"]["count"] == 0
        return {"owned_databases": 2, "formats": ["sha1", "sha256"],
                "real_git_push_clone_fsck": True, "no_persistent_bare": True,
                "archive_volume_initialized_by_real_reconcile_cli": True}

    def snapshot(self):
        with self.source_volume.joinpath(".rootyard.lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert self.backup_command(check=False).returncode != 0
            assert not self.backup.exists()
        env = self.pg_env(self.source_db)
        writer = subprocess.Popen(["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        backup = None
        stdout_path = self.root / "backup.stdout.log"
        stderr_path = self.root / "backup.stderr.log"
        try:
            token_id = str(uuid.UUID(self.revoked["token_id"]))
            writer.stdin.write(("BEGIN; UPDATE public.tokens SET revoked=true WHERE id='" + token_id +
                                "';\n\\echo LOCKED\n").encode())
            writer.stdin.flush()
            assert bounded_line(writer.stdout, time.monotonic() + 10, "owned token writer") == b"LOCKED"
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                backup = subprocess.Popen([self.args.binary, "backup", str(self.backup), "--offline"],
                                          env=self.env, stdout=stdout, stderr=stderr)
            deadline = time.monotonic() + 15
            while not int(self.query(self.source_db,
                    "SELECT count(*) FROM pg_stat_activity WHERE application_name='rootyard-backup' AND wait_event_type='Lock'")):
                assert backup.poll() is None, "backup exited before its PostgreSQL barrier"
                assert time.monotonic() < deadline, "backup did not wait for the source metadata writer"
                time.sleep(0.05)
            writer.stdin.write(b"COMMIT;\n\\q\n")
            writer.stdin.flush()
            assert writer.wait(timeout=10) == 0
            status = backup.wait(timeout=90)
            assert status == 0, (
                "positive nonempty pg_refstore backup failed (exit " + str(status) + "). "
                "Current production git_inventory requires persistent bare storage; "
                "this drill will not synthesize a bare repository or skip the positive restore contract.")
            self.backup_result = json.loads(stdout_path.read_text())
        finally:
            for process in (writer, backup):
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
        manifest = json.loads(self.backup.joinpath("manifest.json").read_text())
        assert manifest["format"] == CURRENT_BACKUP_FORMAT == 21
        assert manifest["schema_versions"] == SCHEMA_VERSIONS and max(SCHEMA_VERSIONS) == 147
        assert len(manifest["repositories"]) == 2
        self.cli("backup-verify", str(self.backup))
        assert self.ledger_digests(self.source_db) == self.source_rows
        return {"format": CURRENT_BACKUP_FORMAT, "schema": CURRENT_SCHEMA_VERSION,
                "legacy_volume_lock_refused": True, "snapshot_waited_for_metadata_commit": True,
                "source_ledgers_unchanged": True, "blob_bytes_in_archive": False}

    def invalid_archives(self):
        changes = (
            ("missing-complete", lambda path: path.joinpath("COMPLETE").unlink()),
            ("truncated-dump", lambda path: path.joinpath("metadata.dump").write_bytes(b"PGDMP")),
            ("changed-volume-id", lambda path: path.joinpath("volume", ".volume-id").write_text(str(uuid.uuid4()))),
        )
        for name, change in changes:
            damaged = self.root / name
            shutil.copytree(self.backup, damaged)
            change(damaged)
            assert self.run([self.args.binary, "backup-verify", str(damaged)], check=False).returncode != 0
            assert self.restore_command(source=damaged, check=False).returncode != 0
            assert not self.target.exists()
            assert self.query(self.target_db, "SELECT count(*) FROM pg_tables WHERE schemaname='public'") == "0"
            shutil.rmtree(damaged)
        return {"damaged_archives_rejected": len(changes), "target_sql_untouched": True}

    def existing_targets(self):
        existing = self.root / "existing-target"
        existing.mkdir(mode=0o700)
        existing.joinpath("sentinel").write_text("keep")
        assert self.restore_command(target=existing, check=False).returncode != 0
        assert existing.joinpath("sentinel").read_text() == "keep"
        assert self.restore_command(database=self.source_db, check=False).returncode != 0
        assert not self.target.exists()
        assert self.ledger_digests(self.source_db) == self.source_rows
        assert self.backup_command(self.source_volume / "nested-backup", check=False).returncode != 0
        return {"existing_directory_preserved": True, "populated_database_preserved": True,
                "nested_backup_refused": True}

    def write_after_backup(self):
        self.start()
        spec = self.specs[0]
        self.post_backup_oid = self.commit_files(spec["work"], "acknowledged after backup", {"after-backup.txt": "outside cut\n"})
        self.git("push", spec["remote"], "HEAD:refs/heads/main", cwd=spec["work"], token=self.alice)
        assert self.remote_refs(spec["remote"], self.alice)["refs/heads/main"] == self.post_backup_oid
        self.stop()
        assert self.post_backup_oid != spec["oid"]
        return {"real_post_boundary_ack": True, "post_boundary_oid": self.post_backup_oid}

    def restore_and_clone(self):
        restored = json.loads(self.restore_command().stdout)
        assert restored["restored"] is True and restored["started_service"] is False
        assert self.ledger_digests(self.target_db) == self.source_rows, "restored core/serving ledger differs from the backup cut"
        token_id = str(uuid.UUID(self.revoked["token_id"]))
        assert self.query(self.target_db, "SELECT revoked FROM public.tokens WHERE id='" + token_id + "'") == "t"
        # Delete only the source's disposable compute state. The source server
        # is stopped; the restored service must materialize from retained Blob.
        shutil.rmtree(self.source_scratch)
        self.scratch = self.root / "restored-scratch"
        self.scratch.mkdir(mode=0o700)
        self.db = self.target_db
        self.env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target), ROOTYARD_SCRATCH_DIR=str(self.scratch))
        self.start()
        for spec in self.specs:
            assert self.remote_refs(spec["remote"], self.alice) == spec["refs"]
            clone = self.root / ("restored-" + spec["format"])
            self.exact_clone(spec["remote"], clone, spec["oid"], spec["format"], spec["files"], self.reader)
            assert not clone.joinpath("after-backup.txt").exists()
            if spec["format"] == "sha1":
                assert self.git("cat-file", "-e", self.post_backup_oid, cwd=clone, check=False).returncode != 0
            self.no_bare(spec["repo"], "fresh restore")
        self.expect("/api/repos", 401, token=self.revoked)
        self.expect(self.specs[0]["repo"]["clone_path"] + "/info/refs?service=git-receive-pack", 403, token=self.reader)
        return {"fresh_database": True, "formats": ["sha1", "sha256"], "exact_refs_content_fsck": True,
                "source_scratch_deleted": True, "post_boundary_commit_excluded": True,
                "read_only_and_revoked_token_state_preserved": True,
                "same_external_blob_originals_retained": True, "independent_blob_closure_restore": False}

    def restored_replay(self):
        repo = self.specs[0]["repo"]
        before = pg_replay_counts(self, repo["id"])
        code, body, _ = self.http(self.replay_destination, token=self.alice, method="POST", body=self.replay_body,
                                 content_type="application/x-git-receive-pack-request",
                                 extra_headers={"X-Rootyard-Operation": self.replay_operation})
        assert code == 200 and body == self.replay_report, "restored operation did not return its exact original report"
        assert_receive_report_ok(body, "refs/heads/main")
        assert pg_replay_counts(self, repo["id"]) == before, "restored exact replay produced another effect"
        assert self.remote_refs(self.specs[0]["remote"], self.alice) == self.specs[0]["refs"]
        self.stop()
        assert self.ledger_digests(self.target_db) == self.source_rows
        return {"exact_original_report": True, "ledger_counters_unchanged": True, "immutable_rows_unchanged": True}

    def cleanup(self):
        failures = []
        try:
            self.stop()
        except Exception as error:
            failures.append("service stop: " + self.redact(error))
        for admin, name in self.created:
            try:
                self.query(admin, 'DROP DATABASE "' + name + '" WITH (FORCE)')
            except Exception as error:
                failures.append("owned database cleanup: " + self.redact(error))
        if not self.args.keep and not failures:
            shutil.rmtree(self.root)
        if failures:
            raise RuntimeError("; ".join(failures))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="absolute attested current rootyard binary")
    parser.add_argument("--git", help="absolute trusted stock Git")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args(argv)
    harness = None
    success = False
    error_text = None
    script_digest = sha256_file(Path(__file__))
    dependency_digest = sha256_file(Path(__file__).with_name("blob_only_service.py"))
    try:
        profile = NativeProfile(args.binary, args.git, os.environ)
        blob_profile = check_blob_profile(os.environ)
        need(os.environ.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        for executable in ("psql", "pg_dump", "pg_restore"):
            need(shutil.which(executable), executable + " is required")
        harness = Drill(args, profile, blob_profile)
        methods = (harness.synthetic_source, harness.snapshot, harness.invalid_archives, harness.existing_targets,
                   harness.write_after_backup, harness.restore_and_clone, harness.restored_replay)
        for name, method in zip(CASES, methods, strict=True):
            harness.case(name, method)
        success = True
    except Exception as error:
        if harness is None:
            error_text = "preflight: " + type(error).__name__ + ": " + str(error)
        else:
            error_text = harness.redact(error)
        print(error_text, file=sys.stderr)
    finally:
        if harness is not None:
            try:
                harness.cleanup()
            except Exception as error:
                harness.results.append({"name": "cleanup", "status": "failed", "error": harness.redact(error)})
                error_text = harness.redact(error)
                success = False
    report = {"kind": "rootyard/blob-serving147-backup-gap-drill", "passed": False,
              "expected_cases": list(CASES), "cases": harness.results if harness else [],
              "skips": 0, "limitations": LIMITATIONS,
              "harness_sha256": script_digest, "blob_only_service_sha256": dependency_digest,
              "independent_blob_closure_backup_claimed": False, "ci_release_gate": False}
    try:
        validate_report_cases(report, CASES)
        need(harness.profile.source_digest() == harness.profile.build["source_inputs_sha256"], "production inputs changed during drill")
        need(sha256_file(Path(__file__)) == script_digest, "drill source changed during execution")
        need(sha256_file(Path(__file__).with_name("blob_only_service.py")) == dependency_digest, "shared harness changed during execution")
        need(sha256_file(harness.profile.binary) == harness.profile.build["binary_sha256"], "binary changed during execution")
        report["passed"] = success
    except (ProfileError, AttributeError) as error:
        report["binding_error"] = str(error)
    if harness:
        report.update(source_head=profile.build["workspace_commit"], source_inputs_sha256=profile.build["source_inputs_sha256"],
                      binary_sha256=profile.build["binary_sha256"], git_sha256=profile.git_sha256,
                      qualification_kind="clean-candidate" if profile.working_tree_clean else "dirty-diagnostic-only")
        if args.keep:
            report["retained_directory"] = str(harness.root)
    if not success:
        report["error"] = error_text
    write_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
