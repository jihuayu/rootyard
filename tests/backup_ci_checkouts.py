#!/usr/bin/env python3
"""Current-format grant/tombstone backup and real format4/schema007 compatibility.

Only disposable synthetic PostgreSQL. --legacy-binary must be a trusted local
schema007/format4 executable; it creates a real old archive without rewriting
its manifest or bypassing the actual restored-catalog check.
"""
import argparse
import copy
import hashlib
import json
import os
import shutil
from pathlib import Path
import sys
import time
import uuid

from backup_ci_pins import BackupCiPinsHarness
from ci_job_checkouts import JobCheckoutHarness
from schema_baseline import (
    CATALOG_JSON_PATH,
    CURRENT_BACKUP_FORMAT,
    RESTORED_CATALOG_JSON_PATH,
    SCHEMA_VERSIONS,
    SCHEMA_VERSION_CSV,
    UPGRADED_CATALOG_JSON_PATH,
)


class CheckoutBackupHarness(BackupCiPinsHarness):
    rpc = JobCheckoutHarness.rpc

    def __init__(self, args):
        super().__init__(args)
        self.audience = str(uuid.uuid4())
        self.env['ROOTYARD_CI_MIRROR_AUDIENCE'] = self.audience
        self.mirror_env['ROOTYARD_CI_MIRROR_AUDIENCE'] = self.audience

    def grants(self):
        self.setup()
        self.job, self.tombstone = str(uuid.uuid4()), str(uuid.uuid4())
        self.target_oid = self.second
        self.start()
        self.pin(self.job)
        request = dict(job_id=self.job, storage_generation=1, target_oid=self.second,
                       mirror_audience=self.audience, expires_unix=int(time.time()) + 3600)
        issued = json.loads(self.expect('/api/repos/alice/demo/ci-checkouts', (200, 201),
                                        token=self.alice, method='POST', body=request))
        self.plan, self.raw = issued['plan'], issued['token']
        self.secrets.append(self.raw)
        self.job_token = dict(username='alice', token=self.raw)
        self.start_mirror()
        self.sync()
        self.mirror_expect(self.advertise(self.second), 200, token=self.job_token)
        self.stop_mirror()
        self.stop()
        self.sql("INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,cancelled) VALUES ('%s','%s','%s',true)" %
                 (self.repo['id'], self.tombstone, self.alice['user_id']))
        for statement in ["DELETE FROM ci_checkout_jobs", "TRUNCATE ci_checkout_jobs",
                          "UPDATE ci_checkout_jobs SET cancelled=false WHERE plan IS NULL",
                          "UPDATE ci_checkout_jobs SET expires_unix=expires_unix+1 WHERE plan IS NOT NULL",
                          "UPDATE ci_checkout_jobs SET owner_id='%s'" % self.bob['user_id'],
                          "UPDATE ci_checkout_jobs SET plan='{}' WHERE plan IS NULL"]:
            self.fail_sql(statement, 'ERROR')
        self.source_rows = self.all_rows()
        self.backup_command()
        self.cli('backup-verify', str(self.backup))
        manifest = json.loads((self.backup / 'manifest.json').read_text())
        assert manifest['format'] == CURRENT_BACKUP_FORMAT and manifest['schema_versions'] == SCHEMA_VERSIONS
        assert self.raw.encode() not in (self.backup / 'metadata.dump').read_bytes()
        legacy_env = self.env.copy()
        legacy_env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        assert self.run([self.args.binary, 'restore', str(self.backup), '--isolated', '--trust-backup',
                         '--allow-legacy-schema007'], env=legacy_env, check=False).returncode != 0
        assert not self.target.exists()
        assert not (self.root / '.restored-data.rootyard-restoring').exists()
        # Cancel after the backup boundary: restoring the earlier snapshot must
        # not resurrect this credential even though cancelled was false there.
        self.sql("UPDATE ci_checkout_jobs SET cancelled=true,revoked=true WHERE job_id='%s'" % self.job)
        self.restore_command()
        restored = json.loads(self.query(self.target_db, "SELECT json_agg(t ORDER BY job_id) FROM ci_checkout_jobs t"))
        expected = copy.deepcopy(self.source_rows['ci_checkout_jobs'])
        for row in expected:
            if row['plan'] is not None:
                row['revoked'] = True
        assert sorted(restored, key=lambda r: r['job_id']) == sorted(expected, key=lambda r: r['job_id'])
        assert self.query(self.target_db, "SELECT count(*) FROM ci_checkout_jobs WHERE plan IS NOT NULL AND NOT revoked") == '0'
        assert self.query(self.target_db, "SELECT count(*) FROM ci_checkout_jobs WHERE plan IS NULL AND cancelled") == '1'
        assert not (self.target.parent / ('.' + self.target.name + '.rootyard-restoring')).exists()
        self.db = self.target_db
        self.env.update(DATABASE_URL=self.db, ROOTYARD_DATA_DIR=str(self.target))
        self.mirror_env['DATABASE_URL'] = self.db
        self.start()
        self.start_mirror()
        self.sync(token=self.alice)
        self.mirror_expect(self.advertise(self.second), 200, token=self.alice)
        owner_clone = self.root / 'restored-owner-clone'
        self.git('clone', self.mirror_base + self.path(self.second), str(owner_clone), token=self.alice)
        assert self.git('rev-parse', 'HEAD', cwd=owner_clone).stdout.decode().strip() == self.second
        self.git('fsck', '--full', '--strict', cwd=owner_clone)
        assert self.plan['expires_unix'] > int(time.time()), 'Revocation test credential expired'
        self.mirror_expect(self.advertise(self.second), 401, token=self.job_token)
        status, body = self.rpc(self.second, self.job_token, self.second)
        assert status == 401 and b'PACK' not in body
        self.stop_mirror()
        self.stop()
        return dict(current_format=CURRENT_BACKUP_FORMAT, immutable_grants=True, permanent_tombstones=True,
                    backup_then_cancel_then_restore_revokes_grant=True, raw_credential_not_persisted=True, live_old_bearer_denied_discovery_and_rpc=True,
                    ordinary_owner_restored_target_access=True, genuine_native_pin_and_issuance=True)


def legacy_restore(args):
    old_args = copy.copy(args)
    old_args.binary = str(Path(args.legacy_binary).resolve())
    h = CheckoutBackupHarness(old_args)
    try:
        h.setup()
        h.backup_command()
        manifest = json.loads((h.backup / 'manifest.json').read_text())
        assert manifest['format'] == 4 and manifest['schema_versions'] == [1, 2, 3, 6, 7]
        assert manifest['binary_sha256'] != hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
        h.args.binary = args.binary
        assert h.run([args.binary, 'backup-verify', str(h.backup)], check=False).returncode == 0, 'Real historical archive verification failed'
        # Compatibility is explicit and rejection happens before target writes.
        assert h.restore_command(check=False).returncode != 0
        assert not h.target.exists()
        env = h.env.copy()
        env.update(DATABASE_URL=h.target_db, ROOTYARD_DATA_DIR=str(h.target))
        h.run([args.binary, 'restore', str(h.backup), '--isolated', '--trust-backup', '--allow-legacy-schema007'], env=env)
        assert h.query(h.target_db, "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == '1,2,3,6,7'
        # A correctly checksummed current-format manifest around an actual007 dump is
        # still rejected by the post-restore catalog check, with guard retained.
        hybrid = h.root / 'hybrid-archive'
        shutil.copytree(h.backup, hybrid, symlinks=True)
        changed = copy.deepcopy(manifest)
        changed['format'] = CURRENT_BACKUP_FORMAT
        changed['lfs_objects'] = []
        changed['schema_versions'] = SCHEMA_VERSIONS
        changed['binary_sha256'] = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
        catalogs = [json.loads(path.read_text()) for path in
                    [CATALOG_JSON_PATH, RESTORED_CATALOG_JSON_PATH, UPGRADED_CATALOG_JSON_PATH]]
        changed['schema_contract_sha256'] = hashlib.sha256(json.dumps(catalogs, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        body = json.dumps(changed).encode()
        (hybrid / 'manifest.json').write_bytes(body)
        (hybrid / 'COMPLETE').write_text(hashlib.sha256(body).hexdigest())
        hybrid_db = h.new_database(h.restore_admin)
        hybrid_target = h.root / 'hybrid-target'
        assert h.run([args.binary, 'backup-verify', str(hybrid)], check=False).returncode == 0, 'Synthetic hybrid manifest verification failed'
        assert h.restore_command(source=hybrid, target=hybrid_target, db=hybrid_db, check=False).returncode != 0
        assert not hybrid_target.exists()
        assert (h.root / '.hybrid-target.rootyard-restoring').exists()
        h.run([args.binary, 'migrate'], env=env)
        assert h.query(h.target_db, "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == SCHEMA_VERSION_CSV
        assert h.query(h.target_db, 'SELECT count(*) FROM ci_checkout_jobs') == '0'
        return dict(real_historical_binary_archive=True, genuine_archive_manifest_unchanged=True,
                    explicit_legacy_opt_in_required=True, schema007_verified_before_upgrade=True,
                    current_schema_upgrade_empty_authority=True, mismatched_dump_rejected_guard_retained=True)
    finally:
        h.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--legacy-binary', required=True)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--keep', action='store_true')
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get('ROOTYARD_TEST_DATABASE_URL'):
        parser.error('dedicated synthetic ROOTYARD_TEST_DATABASE_URL required')
    h = CheckoutBackupHarness(args)
    success = False
    try:
        h.case('current_checkout_authority_restore', h.grants)
        h.case('format4_real_legacy_restore_then_upgrade', lambda: legacy_restore(args))
        success = True
    except Exception as error:
        print(h.redact(error), file=sys.stderr)
    finally:
        h.cleanup()
    report = dict(passed=success, cases=h.results,
                  binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                  legacy_binary_sha256=hashlib.sha256(Path(args.legacy_binary).read_bytes()).hexdigest(),
                  limitations=['Synthetic loopback backup/restore does not establish a production RPO/RTO.',
                               'Restoring permanently revokes all issued checkout credentials; native pins and plans remain.'])
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
