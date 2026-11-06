#!/usr/bin/env python3
"""Real schema003 logical restore -> migrate008 -> nonempty Git/Forge backup.

Requires dedicated synthetic PostgreSQL administrators with CREATEDB. The old
schema is built from migrations 001/002/003, never from an unavailable historical
binary and never by manually rewriting CHECK definitions. The default contract
must complete a real backup and fresh PostgreSQL/volume restore. An explicit
--expect-schema-rejection mode reproduces the pre-fix regression only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

from backup_recovery import BackupRecoveryHarness
from forge import ForgeHarness
from schema_baseline import (
    CATALOG_JSON_PATH,
    CATALOG_SQL_PATH,
    RESTORED_CATALOG_JSON_PATH,
    SCHEMA_VERSIONS,
    SCHEMA_VERSION_CSV,
    TABLE_COUNT,
    UPGRADED_CATALOG_JSON_PATH,
)


class BackupUpgradeHarness(BackupRecoveryHarness):
    document = ForgeHarness.document

    def legacy_dump_restore(self):
        self.legacy_db = self.new_database(self.admin)
        migrations = Path(__file__).resolve().parents[1] / 'migrations'
        for name in ('001_initial.sql', '002_reliability.sql', '003_recovery_operations.sql'):
            self.query(self.legacy_db, (migrations / name).read_text())
        self.legacy_user = str(uuid.uuid4())
        self.legacy_repo = str(uuid.uuid4())
        self.query(self.legacy_db,
                   f"INSERT INTO users(id,username) VALUES('{self.legacy_user}','legacy-owner'); "
                   f"INSERT INTO repositories(id,owner_id,name) VALUES('{self.legacy_repo}','{self.legacy_user}','legacy-repo')")
        assert self.query(self.legacy_db, "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == '1,2,3'
        archive = self.root / 'real-schema003.dump'
        self.run(['pg_dump', '--dbname', self.legacy_db, '--format=custom', '--schema=public',
                  '--no-owner', '--no-privileges', '--file', str(archive)])
        assert self.query(self.source_db, "SELECT count(*) FROM pg_tables WHERE schemaname='public'") == '0'
        self.run(['pg_restore', '--dbname', self.source_db, '--single-transaction', '--exit-on-error',
                  '--clean', '--if-exists', '--no-owner', '--no-privileges', str(archive)])
        assert self.sql("SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == '1,2,3'
        assert self.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'") == '11'
        assert self.sql("SELECT owner_id::text || ':' || name FROM repositories WHERE id='" + self.legacy_repo + "'") == self.legacy_user + ':legacy-repo'
        self.cli('migrate')
        self.cli('migrate')
        assert self.sql("SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == SCHEMA_VERSION_CSV
        assert self.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'") == str(TABLE_COUNT)
        assert self.sql("SELECT username FROM users WHERE id='" + self.legacy_user + "'") == 'legacy-owner'
        assert self.sql("SELECT name FROM repositories WHERE id='" + self.legacy_repo + "'") == 'legacy-repo'
        # Record the actual third catalog for review; this test never changes or
        # weakens the fixture contract on behalf of the implementation.
        catalog_sql = CATALOG_SQL_PATH.read_text()
        self.upgraded_catalog = json.loads(self.run(['psql', self.db, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                                                    '-c', 'SET search_path=pg_catalog; ' + catalog_sql]).stdout)
        assert self.upgraded_catalog == json.loads(UPGRADED_CATALOG_JSON_PATH.read_text())
        assert self.upgraded_catalog != json.loads(CATALOG_JSON_PATH.read_text())
        assert self.upgraded_catalog != json.loads(RESTORED_CATALOG_JSON_PATH.read_text())
        (self.root / 'actual-restored003-upgraded008-catalog.json').write_text(json.dumps(self.upgraded_catalog, indent=2, sort_keys=True) + '\n')
        return dict(real_schema003_dump_and_restore=True, old_tables=11, upgraded_tables=TABLE_COUNT,
                    exact_versions=SCHEMA_VERSIONS, legacy_identity_and_repository_preserved=True,
                    repeated_migrate=True, historical_binary_required=False,
                    manual_constraint_rewrite=False)

    def upgraded_source(self):
        # This exercises real provision/clone/commit/push/fetch and records an
        # unresolved synthetic operation using the existing dedicated-DB harness.
        super().setup()
        self.start()
        self.issue_base = '/api/repos/alice/demo/issues'
        self.issues = []
        self.comments = []
        for i in range(1, 4):
            issue = self.document(self.issue_base, 201, method='POST',
                                  body={'title': f'旧库升级问题 {i} 🚀', 'body': 'Unicode e\u0301 é\n**text**'})
            assert issue['number'] == i
            if i == 1:
                issue = self.document(self.issue_base + '/1', method='PATCH',
                                      body={'expected_version': 1, 'state': 'closed', 'body': '升级后修订'})
            self.issues.append(issue)
            comments = []
            for j in range(1, 3):
                comment = self.document(self.issue_base + f'/{i}/comments', 201, method='POST',
                                        body={'body': f'评论 {j} 日本語'})
                if j == 1:
                    comment = self.document(self.issue_base + f'/{i}/comments/1', method='PATCH',
                                            body={'expected_version': 1, 'body': '已编辑 ✅'})
                comments.append(comment)
            self.comments.append(comments)
        self.stop()
        assert self.sql("SELECT state FROM repositories WHERE id='" + self.legacy_repo + "'") == 'ready'
        assert (Path(self.env['ROOTYARD_DATA_DIR']) / 'repos' / (self.legacy_repo + '.git')).is_dir()
        return dict(real_git_clone_commit_push_fetch=True, legacy_repo_provisioned_with_same_identity=True,
                    forge_issues=3, forge_comments=6, edited_versions_and_unicode=True)

    def backup_upgraded_source(self):
        if self.args.expect_schema_rejection:
            result = self.backup_command(check=False)
            assert result.returncode != 0, 'Pre-fix binary unexpectedly accepted restored003->008 source'
            assert b'backup failed; requires stopped writers, supported dedicated database and safe new destination' in result.stderr, self.redact(result.stderr.decode())
            assert not self.backup.exists(), 'Rejected backup unexpectedly published a destination'
            return dict(expected_regression_reproduced=True, known_third_catalog_rejected=True, detailed_internal_error_intentionally_redacted=True,
                        backup_not_published=True)
        result = self.lock_and_snapshot()
        self.source_rows = self.all_rows()
        assert len(self.source_rows) == TABLE_COUNT
        assert len(self.source_rows['forge_issues']) == 3
        assert len(self.source_rows['forge_issue_comments']) == 6
        assert self.source_rows['forge_issue_counters'][0]['next_number'] == 4
        manifest = json.loads((self.backup / 'manifest.json').read_text())
        assert manifest['schema_versions'] == SCHEMA_VERSIONS
        return {**result, 'restored003_upgraded008_catalog_accepted': True,
                'all_current_tables_backed_up': True, 'populated_forge_backed_up': True}

    def post_boundary_writes(self):
        result = self.write_after_backup()
        self.start()
        self.unbacked_issue = self.document(self.issue_base, 201, method='POST',
                                            body={'title': 'unbacked post-upgrade snapshot issue'})
        assert self.unbacked_issue['number'] == 4
        self.document(self.issue_base + '/1', method='PATCH',
                      body={'expected_version': 2, 'state': 'open', 'body': 'unbacked edit'})
        self.stop()
        return {**result, 'acknowledged_forge_changes_outside_snapshot': 2,
                'lossless_restore_claim': False}

    def restore_upgraded_source(self):
        result = json.loads(self.restore_command().stdout)
        self.db = self.target_db
        self.env.update(DATABASE_URL=self.db, ROOTYARD_DATA_DIR=str(self.target))
        self.assert_restored_rows()
        assert self.sql("SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == SCHEMA_VERSION_CSV
        assert self.sql("SELECT username FROM users WHERE id='" + self.legacy_user + "'") == 'legacy-owner'
        assert self.sql("SELECT owner_id::text || ':' || name FROM repositories WHERE id='" + self.legacy_repo + "'") == self.legacy_user + ':legacy-repo'
        self.start()
        assert self.git('ls-remote', self.remote, token=self.alice).stdout == self.before_refs
        clone = self.root / 'upgrade-restored-clone'
        self.git('clone', self.remote, str(clone), token=self.reader)
        self.git('fsck', '--full', '--strict', cwd=clone)
        assert self.git('rev-parse', 'HEAD', cwd=clone).stdout.decode().strip() == self.second
        assert (clone / 'hello.txt').read_text() == 'second\n'
        assert not (clone / 'after-backup.txt').exists()
        assert self.git('cat-file', '-e', self.post_backup_oid, cwd=clone, check=False).returncode != 0
        for i, issue in enumerate(self.issues, 1):
            assert self.document(self.issue_base + '/' + str(i), token=self.reader) == issue
            assert self.document(self.issue_base + f'/{i}/comments', token=self.reader)['items'] == self.comments[i - 1]
        self.document(self.issue_base + '/4', 404)
        self.document(self.issue_base, 401, token=self.revoked)
        self.document(self.issue_base, 404, token=self.bob)
        self.document(self.issue_base, 403, token=self.reader, method='POST', body={'title': 'denied'})
        self.expect(self.unknown_repo['clone_path'] + '/info/refs?service=git-upload-pack', 503, token=self.alice)
        next_issue = self.document(self.issue_base, 201, method='POST', body={'title': 'new after restore'})
        assert next_issue['number'] == 4
        self.document(self.issue_base + '/1', 409, method='PATCH', body={'expected_version': 1, 'body': 'stale'})
        changed = self.document(self.issue_base + '/1', method='PATCH', body={'expected_version': 2, 'state': 'open'})
        assert changed['version'] == 3
        self.stop()
        return dict(fresh_database_and_volume=True, separate_pg_server=self.admin != self.restore_admin,
                    durable_rows_exact_with_authority_rotated=True, legacy_identity_and_repository_preserved=True,
                    genuine_authenticated_clone_fsck_content=True, populated_forge_exact=True,
                    owner_read_only_revoked_permissions=True, restored_number_and_cas=True,
                    post_boundary_git_commit_not_recovered=1, post_boundary_forge_changes_not_recovered=2,
                    restore_seconds=result['elapsed_seconds'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--keep', action='store_true')
    parser.add_argument('--expect-schema-rejection', action='store_true',
                        help='Regression reproduction only: expect the known old catalog rejection, never use in normal CI')
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get('ROOTYARD_TEST_DATABASE_URL'):
        parser.error('dedicated synthetic ROOTYARD_TEST_DATABASE_URL required')
    h = BackupUpgradeHarness(args)
    success = False
    try:
        groups = [('schema003_logical_restore_then_migrate008', h.legacy_dump_restore),
                  ('upgraded_real_git_and_forge_source', h.upgraded_source),
                  ('backup_restored003_upgraded008_source', h.backup_upgraded_source)]
        if not args.expect_schema_rejection:
            groups += [('post_backup_acknowledged_writes', h.post_boundary_writes),
                       ('fresh_database_volume_restore_and_clone', h.restore_upgraded_source)]
        for name, fn in groups:
            h.case(name, fn)
        success = True
    except Exception as error:
        print(h.redact(error), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:
            success = False
            h.results.append(dict(name='cleanup', status='failed', error=h.redact(error)))
        report = dict(passed=success, cases=h.results,
                      mode='expected_regression_reproduction' if args.expect_schema_rejection else 'required_upgrade_acceptance',
                      binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=['Real logical restore and migrations in synthetic disposable PostgreSQL only.',
                                   'Offline snapshot excludes later acknowledged Git/Forge writes; no production zero-loss promise.',
                                   'The regression mode proves known rejection only, not successful backup or restore.'])
        if args.keep:
            report['retained_directory'] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
