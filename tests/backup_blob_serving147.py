#!/usr/bin/env python3
"""Current format22/schema147 PG + Blob paired backup/restore drill.

Requires an attested binary, PostgreSQL 17 with CREATEDB, the strict S3 profile,
and boto3 (tests/requirements-blob-backup.txt). Only run-owned databases and an
independent UUID Blob prefix are used. Ready state and ACKs come from HTTP/Git.
The drill verifies and deletes the exact original pack/idx objects, then must
rebuild them from the archive at unchanged locators before clone/fsck/replay.
Product GC stays disabled. This is fresh PG/Blob functionality, not LFS,
workspace, interrupted-restore, physical durability or HA qualification.
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
from schema_baseline import CURRENT_BLOB_BACKUP_FORMAT as CURRENT_BACKUP_FORMAT, CURRENT_SCHEMA_VERSION, SCHEMA_VERSIONS, catalog_tables

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
    "Restore requires the same physical Blob backend identity (provider, endpoint, bucket, root, region, account) as the archive; a different backend is refused, not remapped.",
    "Original Blob objects are deleted only in this run-owned fixture to prove the archive closure; product GC stays disabled and is untouched.",
    "serve-blob holds the shared lifecycle advisory lock for its whole lifetime; offline backup/restore hold the exclusive one until publication. The legacy volume flock still only covers the native GitFS path.",
    "No interrupted restore, multi-host failure, physical power-loss, throughput, or production RPO/RTO qualification is claimed.",
    "No legacy format/schema upgrade is exercised. The current binary must restore its own format22/schema147 archive; format21/schema147 stays readable as a metadata-only historical archive.",
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
        self.owned_blob_suffix = "backup147-" + uuid.uuid4().hex
        self.env["ROOTYARD_BLOB_ROOT"] = "/".join(filter(None, (prefix, self.owned_blob_suffix)))
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

    def artifact_rows(self, database=None):
        """Exact original locators of the closure, from the real hold ledger."""
        raw = self.query(database or self.source_db,
            "SELECT encode(sha256(convert_to(coalesce(string_agg(x, E'\\n' ORDER BY x), ''), 'UTF8')), 'hex') FROM ("
            "SELECT a.repository_id::text || ':' || a.pack_id::text || ':' || a.role || ':' || a.hold_id::text || ':' ||"
            "h.attempt_id::text || ':' || h.storage_tenant_id::text || ':' || h.authority_id::text || ':' ||"
            "h.authority_generation::text || ':' || h.namespace || ':' || h.sha256 || ':' || h.content_length::text AS x "
            "FROM public.ref_store_core_pack_artifacts a JOIN public.artifact_holds h ON h.hold_id=a.hold_id "
            "ORDER BY x) rows")
        count = int(self.query(database or self.source_db, "SELECT count(*) FROM public.ref_store_core_pack_artifacts"))
        assert count > 0 and len(raw) == 64
        return {"count": count, "sha256": raw}

    def s3_client(self):
        import boto3
        from botocore.config import Config
        return boto3.client("s3", endpoint_url=self.env["ROOTYARD_BLOB_ENDPOINT"],
            region_name=self.env["ROOTYARD_BLOB_REGION"],
            aws_access_key_id=self.env["ROOTYARD_BLOB_ACCESS_KEY_ID"],
            aws_secret_access_key=self.env["ROOTYARD_BLOB_SECRET_ACCESS_KEY"],
            config=Config(signature_version="s3v4", connect_timeout=2, read_timeout=5,
                          retries={"max_attempts": 1, "mode": "standard"}, s3={"addressing_style": "path"}))

    def verify_original(self, client, locator):
        import hashlib
        key = self.env["ROOTYARD_BLOB_ROOT"].rstrip("/") + "/" + locator["key"]
        obj = client.get_object(Bucket=self.env["ROOTYARD_BLOB_BUCKET"], Key=key)
        assert obj["ContentLength"] == locator["length"], "original object length differs"
        total, digest = 0, hashlib.sha256()
        try:
            while chunk := obj["Body"].read(65536):
                total += len(chunk)
                assert total <= locator["length"], "original exceeded its declared length"
                digest.update(chunk)
        finally:
            obj["Body"].close()
        assert total == locator["length"] and digest.hexdigest() == locator["sha256"], "original byte digest differs"
        return key

    def delete_originals(self, locators):
        """Prove every exact run-owned object existed, delete it, require 404."""
        from botocore.exceptions import ClientError
        assert self.env["ROOTYARD_BLOB_ROOT"].endswith(self.owned_blob_suffix)
        client, bucket = self.s3_client(), self.env["ROOTYARD_BLOB_BUCKET"]
        keys = [self.verify_original(client, locator) for locator in locators]
        assert keys and len(keys) == len(set(keys)), "object identity list is not unique"
        for key in keys:
            client.delete_object(Bucket=bucket, Key=key)
        for key in keys:
            try:
                client.head_object(Bucket=bucket, Key=key)
            except ClientError as error:
                assert error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404, "absence was not confirmed"
            else:
                raise AssertionError("original object survived deletion")

    def original_locators(self, database=None):
        raw = self.query(database or self.source_db,
            "SELECT json_build_object('key', 'v1/tenants/' || h.storage_tenant_id::text || '/authorities/' ||"
            " h.authority_id::text || '/g' || h.authority_generation::text || '/attempts/' || h.attempt_id::text ||"
            " '/' || h.namespace || '/' || h.sha256, 'sha256', h.sha256, 'length', h.content_length)::text"
            " FROM public.ref_store_core_pack_artifacts a JOIN public.artifact_holds h ON h.hold_id=a.hold_id"
            " ORDER BY h.storage_tenant_id,h.authority_id,h.authority_generation,h.attempt_id,h.namespace,h.sha256")
        return [json.loads(line) for line in raw.splitlines()]

    def synthetic_source(self):
        self.source_db = self.new_database(self.admin)
        self.target_db = self.new_database(self.restore_admin)
        self.db = self.source_db
        self.env["DATABASE_URL"] = self.db
        self.cli("migrate")
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
        # Kill only the dedicated barrier session of this run-owned database.
        killed = self.query(self.source_db,
            "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE "
            "datname=current_database() AND application_name='rootyard-blob-barrier') stopped")
        assert killed == "1", "fixture did not identify one owned barrier session"
        assert self.proc.wait(timeout=15) != 0, "service survived losing its shared barrier"
        self.stop()
        self.start(label="after-barrier-loss")
        self.stop()
        self.source_rows = self.ledger_digests(self.source_db)
        for table in ("ref_store_serving_repositories", "ref_store_serving_operations",
                      "ref_store_core_pack_publications", "ref_store_operations"):
            assert self.source_rows[table]["count"] >= 2, table + " was not populated by real serving"
        assert self.source_rows["ref_store_core_serving_reads"]["count"] == 0
        self.closure_rows = self.artifact_rows()
        self.originals = self.original_locators()
        assert len(self.originals) >= 4
        return {"owned_databases": 2, "formats": ["sha1", "sha256"], "real_git_push_clone_fsck": True,
                "no_persistent_bare": True, "archive_volume_initialized_by_real_reconcile_cli": True,
                "closure_artifacts": self.closure_rows["count"], "shared_barrier_loss_stops_service": True}

    def wait_for_advisory_holder(self, database, exclusive, timeout=15):
        """Wait until a real session on `database` holds the lifecycle key."""
        mode = "ExclusiveLock" if exclusive else "ShareLock"
        deadline = time.monotonic() + timeout
        sql = ("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=738390103"
               " AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1 AND mode='" + mode + "' AND granted")
        while int(self.query(database, sql)) == 0:
            assert time.monotonic() < deadline, "lifecycle barrier was not taken"
            time.sleep(0.05)

    def advisory_holds(self, database):
        return int(self.query(database,
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=738390103"
            " AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1 AND mode='ExclusiveLock' AND granted"))

    def serving_barrier_refused(self, env=None):
        """serve-blob must refuse to start while the exclusive offline barrier is held."""
        probe = (env or self.env).copy()
        directory = self.root / "unrelated-probe-data"
        directory.mkdir(exist_ok=True)
        probe["ROOTYARD_DATA_DIR"] = str(directory)
        try:
            process = subprocess.run([self.args.binary, "serve-blob"], env=probe,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except subprocess.TimeoutExpired:
            return False
        return process.returncode != 0

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
            # The exclusive lifecycle lock proves the real cross-process barrier:
            # a serve-blob started now must refuse, and the backup must wait for
            # this metadata writer instead of taking a snapshot around it.
            self.wait_for_advisory_holder(self.source_db, exclusive=True)
            assert self.serving_barrier_refused(), "serve-blob started while the offline barrier was held"
            deadline = time.monotonic() + 15
            while not int(self.query(self.source_db,
                    "SELECT count(*) FROM pg_stat_activity WHERE application_name='rootyard-backup' AND wait_event_type='Lock'")):
                assert backup.poll() is None, "backup exited before its PostgreSQL barrier"
                assert time.monotonic() < deadline, "backup did not wait for the source metadata writer"
                time.sleep(0.05)
            writer.stdin.write(b"COMMIT;\n\\q\n")
            writer.stdin.flush()
            assert writer.wait(timeout=10) == 0
            status = backup.wait(timeout=120)
            assert status == 0, "positive nonempty pg_refstore paired backup failed (exit " + str(status) + ")"
            self.backup_result = json.loads(stdout_path.read_text())
        finally:
            for process in (writer, backup):
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
        assert self.advisory_holds(self.source_db) == 0, "backup did not release its exclusive barrier"
        manifest = json.loads(self.backup.joinpath("manifest.json").read_text())
        assert manifest["format"] == CURRENT_BACKUP_FORMAT == 22
        assert manifest["schema_versions"] == SCHEMA_VERSIONS and max(SCHEMA_VERSIONS) == 147
        assert len(manifest["repositories"]) == 2
        assert manifest["blob_closure"]["artifacts"] == self.closure_rows["count"]
        assert len(manifest["blob_artifacts"]) == manifest["blob_closure"]["artifacts"]
        blob_files = [name for name, entry in manifest["files"].items() if name.startswith("blob/") and entry["kind"]=="file"]
        assert len(blob_files) == manifest["blob_closure"]["artifacts"]
        total = sum(manifest["files"][name]["bytes"] for name in blob_files)
        assert total == manifest["blob_closure"]["bytes"] > 0
        self.cli("backup-verify", str(self.backup))
        assert self.ledger_digests(self.source_db) == self.source_rows
        return {"format": CURRENT_BACKUP_FORMAT, "schema": CURRENT_SCHEMA_VERSION,
                "legacy_volume_lock_refused": True, "snapshot_waited_for_metadata_commit": True,
                "exclusive_pg_barrier_held_during_snapshot": True, "serve_blob_refused_during_barrier": True,
                "source_ledgers_unchanged": True, "blob_bytes_in_archive": True,
                "closure_artifacts": manifest["blob_closure"]["artifacts"], "closure_bytes": total}

    def invalid_archives(self):
        blob_member = sorted(p for p in self.backup.joinpath("blob").rglob("*") if p.is_file())[0]
        changes = (
            ("missing-complete", lambda path: path.joinpath("COMPLETE").unlink()),
            ("truncated-dump", lambda path: path.joinpath("metadata.dump").write_bytes(b"PGDMP")),
            ("changed-volume-id", lambda path: path.joinpath("volume", ".volume-id").write_text(str(uuid.uuid4()))),
            ("changed-blob-byte", lambda path: blob_member.relative_to(self.backup) and
                path.joinpath(blob_member.relative_to(self.backup)).write_bytes(b"tampered")),
            ("removed-blob-member", lambda path: path.joinpath(blob_member.relative_to(self.backup)).unlink()),
            ("false-locator", lambda path: self.forge_locator(path)),
        )
        for name, change in changes:
            damaged = self.root / name
            shutil.copytree(self.backup, damaged)
            change(damaged)
            assert self.run([self.args.binary, "backup-verify", str(damaged)], check=False).returncode != 0, name
            assert self.restore_command(source=damaged, check=False).returncode != 0, name
            assert not self.target.exists()
            assert self.query(self.target_db, "SELECT count(*) FROM pg_tables WHERE schemaname='public'") == "0"
            shutil.rmtree(damaged)
        return {"damaged_archives_rejected": len(changes), "target_sql_untouched": True}

    def forge_locator(self, path):
        # Replace one locator with a different (valid-looking) digest; the
        # closure digest and member inventory must refuse it.
        manifest = json.loads(path.joinpath("manifest.json").read_text())
        manifest["blob_artifacts"][0]["sha256"] = "0" * 64
        raw = json.dumps(manifest, indent=2).encode()
        path.joinpath("manifest.json").write_bytes(raw)
        path.joinpath("COMPLETE").write_text(sha256_file(path.joinpath("manifest.json")))

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
        # Delete only this run's private Blob originals: the archive must be the
        # sole source of every pack/idx byte from here on.
        self.delete_originals(self.originals)
        env = self.env.copy()
        env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        restore = None
        stdout_path = self.root / "restore.stdout.log"
        stderr_path = self.root / "restore.stderr.log"
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                restore = subprocess.Popen([self.args.binary, "restore", str(self.backup), "--isolated", "--trust-backup"],
                                           env=env, stdout=stdout, stderr=stderr)
            self.wait_for_advisory_holder(self.target_db, exclusive=True)
            assert self.serving_barrier_refused(env), "serve-blob started while the restore barrier was held"
            status = restore.wait(timeout=180)
            assert status == 0, "paired restore from the archive failed (exit " + str(status) + ")"
        finally:
            if restore is not None and restore.poll() is None:
                restore.kill()
                restore.wait(timeout=10)
        restored = json.loads(stdout_path.read_text())
        assert restored["restored"] is True and restored["started_service"] is False
        assert restored["blob_artifacts"] == self.closure_rows["count"]
        assert self.advisory_holds(self.target_db) == 0, "restore did not release its exclusive barrier"
        assert self.ledger_digests(self.target_db) == self.source_rows, "restored core/serving ledger differs from the backup cut"
        assert self.artifact_rows(self.target_db) == self.closure_rows, "restored locators were rewritten"
        assert self.original_locators(self.target_db) == self.originals, "restored ledger changed the original locators"
        # Every rebuilt object must live at its exact original coordinate with
        # exactly the archived digest and length (the locator path ends in the
        # content digest, so the fetched bytes must hash to it).
        client = self.s3_client()
        for locator in self.originals:
            self.verify_original(client, locator)
        token_id = str(uuid.UUID(self.revoked["token_id"]))
        assert self.query(self.target_db, "SELECT revoked FROM public.tokens WHERE id='" + token_id + "'") == "t"
        shutil.rmtree(self.source_scratch)
        self.scratch = self.root / "restored-scratch"
        self.scratch.mkdir(mode=0o700)
        self.db = self.target_db
        self.env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target),
                        ROOTYARD_SCRATCH_DIR=str(self.scratch))
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
                "same_backend_identity": True, "original_blob_objects_deleted_before_restore": True,
                "independent_blob_closure_restore": True}

    def artifact_rows_for(self, database):
        raw = self.query(database,
            "SELECT encode(sha256(convert_to(coalesce(string_agg(x, E'\\n' ORDER BY x), ''), 'UTF8')), 'hex') FROM ("
            "SELECT a.repository_id::text || ':' || a.pack_id::text || ':' || a.role || ':' || a.hold_id::text || ':' ||"
            "h.attempt_id::text || ':' || h.storage_tenant_id::text || ':' || h.authority_id::text || ':' ||"
            "h.authority_generation::text || ':' || h.namespace || ':' || h.sha256 || ':' || h.content_length::text AS x "
            "FROM public.ref_store_core_pack_artifacts a JOIN public.artifact_holds h ON h.hold_id=a.hold_id "
            "ORDER BY x) rows")
        count = int(self.query(database, "SELECT count(*) FROM public.ref_store_core_pack_artifacts"))
        return {"count": count, "sha256": raw}

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
        blob_profile = check_blob_profile(harness.env)
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
    report = {"kind": "rootyard/paired-blob-backup-restore-acceptance", "passed": False,
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
    report["independent_blob_closure_backup_claimed"] = bool(report["passed"])
    write_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
