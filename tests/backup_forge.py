#!/usr/bin/env python3
"""Restore nonempty Forge and durable Git workers into fresh synthetic PG/volume.

Requires CREATEDB on a dedicated synthetic ROOTYARD_TEST_DATABASE_URL. Set
ROOTYARD_RESTORE_TEST_DATABASE_URL to a separate disposable PostgreSQL server.
Only randomly named databases and test-owned directories are created/removed.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from forge import ForgeHarness
from restored_workers import RestoredWorkers
from schema_baseline import EXPECTED_TABLES, SCHEMA_VERSIONS, SCHEMA_VERSION_CSV, TABLE_COUNT


FORGE_TABLES = ('forge_creation_requests', 'forge_issue_counters', 'forge_issues', 'forge_issue_comments')


class BackupForgeHarness(RestoredWorkers):
    document = ForgeHarness.document

    def forge_rows(self):
        return {table: self.rows('SELECT * FROM ' + table + ' t ORDER BY to_jsonb(t)::text')
                for table in FORGE_TABLES}

    def git_authority(self):
        """Exact Git metadata and native refs, not merely aggregate row counts."""
        repos = self.rows('SELECT id,storage_generation FROM repositories ORDER BY id')
        root = Path(self.env['ROOTYARD_DATA_DIR'])
        return dict(repositories=repos,
                    operations=self.rows('SELECT * FROM git_operations t ORDER BY to_jsonb(t)::text'),
                    outbox=self.rows('SELECT * FROM outbox_events t ORDER BY to_jsonb(t)::text'),
                    refs={r['id']: self.git('--git-dir=' + str(root / 'repos' / (r['id'] + '.git')),
                                           'for-each-ref', '--format=%(refname) %(objectname)').stdout.decode()
                          for r in repos})

    def recovery_source(self):
        super().recovery_source()
        self.start()
        self.forge_expired_token = self.account('create-token', 'alice')
        self.sql("UPDATE tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE id='" + self.forge_expired_token['token_id'] + "'")
        self.bob_reader = self.account('create-token', 'bob', '--read-only')
        self.bob_repo = self.document('/api/repos', 201, token=self.bob, method='POST', body={'name': 'demo'})
        self.basepath = '/api/repos/alice/demo/issues'
        self.resolvedpath = '/api/repos/alice/resolved/issues'
        self.bobpath = '/api/repos/bob/demo/issues'
        self.saved_http = []
        self.saved_replays = []
        self.forge_repos = [(self.repo, self.basepath, self.alice),
                            (self.resolved['repo'], self.resolvedpath, self.alice),
                            (self.bob_repo, self.bobpath, self.bob)]
        before = self.git_authority()
        for _, path, token in self.forge_repos:
            for i in range(1, 4):
                payload = {'title': f'问题 {i} 🧪 café e\u0301',
                           'body': '原始内容\n\t**Markdown** <script>untrusted()</script>\n'}
                headers = {'Idempotency-Key': 'backup-issue-' + str(i)}
                issue = self.document(path, 201, token=token, method='POST', body=payload, extra_headers=headers)
                self.saved_replays.append((path, token, payload, headers, issue))
                assert issue['number'] == i and issue['author_id'] == token['user_id']
                issue_path = path + '/' + str(i)
                if i != 3:
                    issue = self.document(issue_path, token=token, method='PATCH',
                                          body={'expected_version': 1, 'title': '修订 ' + str(i), 'state': 'closed'})
                if i == 1:
                    issue = self.document(issue_path, token=token, method='PATCH',
                                          body={'expected_version': 2, 'state': 'open', 'body': '重新打开\nUnicode ✅'})
                comments = []
                for j in range(1, 4):
                    comment_path = issue_path + '/comments'
                    payload = {'body': f'评论 {j}: 日本語 Ελληνικά 🚀\n\tline'}
                    headers = {'Idempotency-Key': f'backup-comment-{i}-{j}'}
                    comment = self.document(comment_path, 201, token=token, method='POST', body=payload, extra_headers=headers)
                    self.saved_replays.append((comment_path, token, payload, headers, comment))
                    if j == 1:
                        comment = self.document(comment_path + '/1', token=token, method='PATCH',
                                                body={'expected_version': 1, 'body': '已编辑评论 e\u0301 é <b>text</b>'})
                    comments.append(comment)
                self.saved_http.append((issue_path, token, issue, comments))
        assert self.git_authority() == before, 'Forge mutations changed Git authority or outbox'
        self.stop()

    def populated_source(self):
        result = super().pending_source()
        assert set(self.source_rows) == EXPECTED_TABLES
        assert self.sql("SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == SCHEMA_VERSION_CSV
        assert len(self.source_rows['forge_issues']) == 9
        assert len(self.source_rows['forge_issue_comments']) == 27
        assert len(self.source_rows['forge_issue_counters']) == 3
        assert len(self.source_rows['forge_creation_requests']) == 36
        self.initial_git_authority = self.git_authority()
        return {**result, 'full_public_table_count': TABLE_COUNT, 'forge_issues': 9,
                'forge_comments': 27, 'personal_owners': 2, 'unicode_revisions_and_states': True,
                'forge_did_not_mutate_git_or_outbox': True}

    def incomplete_key_rejected(self):
        tenant, repo = self.alice['user_id'], self.repo['id']
        self.sql(f"INSERT INTO forge_creation_requests(tenant_id,repository_id,idempotency_key,request) VALUES('{tenant}','{repo}','incomplete-test','{{}}'::jsonb)")
        try:
            destination = self.root / 'incomplete-key-backup'
            assert self.backup_command(destination, check=False).returncode != 0
            assert not destination.exists(), 'Incomplete key backup was published'
        finally:
            self.sql(f"DELETE FROM forge_creation_requests WHERE tenant_id='{tenant}' AND repository_id='{repo}' AND idempotency_key='incomplete-test'")
        constraint = self.sql("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='forge_creation_requests'::regclass AND conname='forge_creation_requests_idempotency_key_check'")
        self.sql("ALTER TABLE forge_creation_requests DROP CONSTRAINT forge_creation_requests_idempotency_key_check")
        try:
            destination = self.root / 'drifted-key-check-backup'
            assert self.backup_command(destination, check=False).returncode != 0
            assert not destination.exists(), 'Drifted key constraint backup was published'
        finally:
            self.sql("ALTER TABLE forge_creation_requests ADD CONSTRAINT forge_creation_requests_idempotency_key_check " + constraint)
        return dict(committed_incomplete_key_rejected=True, removed_key_constraint_rejected=True)

    def commit_barrier(self):
        self.backup = self.root / 'forge-barrier-backup'
        tenant, repo = self.alice['user_id'], self.repo['id']
        number = int(self.sql("SELECT next_number FROM forge_issue_counters WHERE repository_id='" + repo + "'"))
        self.barrier_number = number
        sql = (
            "BEGIN; "
            f"INSERT INTO forge_creation_requests(tenant_id,repository_id,idempotency_key,request) VALUES('{tenant}','{repo}','barrier-key',jsonb_build_object('operation','issue','title','barrier issue','body','committed before frozen snapshot')); "
            f"UPDATE forge_issue_counters SET next_number=next_number+1 WHERE tenant_id='{tenant}' AND repository_id='{repo}'; "
            f"INSERT INTO forge_issues(tenant_id,repository_id,number,author_id,title,body,next_comment_number) VALUES('{tenant}','{repo}',{number},'{tenant}','barrier issue','committed before frozen snapshot',2); "
            f"INSERT INTO forge_issue_comments(tenant_id,repository_id,issue_number,number,author_id,body) VALUES('{tenant}','{repo}',{number},1,'{tenant}','barrier comment');\n"
            "\\echo FORGE_WRITER_LOCKED\n")
        writer = subprocess.Popen(['psql', self.db, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1'], env=self.env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        backup = None
        try:
            writer.stdin.write(sql.encode()); writer.stdin.flush()
            assert writer.stdout.readline().strip() == b'FORGE_WRITER_LOCKED'
            backup = subprocess.Popen([self.args.binary, 'backup', str(self.backup), '--offline'], env=self.env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 10
            while not int(self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='rootyard-backup' AND wait_event_type='Lock'")):
                assert backup.poll() is None and time.monotonic() < deadline, 'Backup never waited for Forge writer'
                time.sleep(.02)
            assert self.sql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name='rootyard-backup' AND l.relation='forge_creation_requests'::regclass AND l.mode='ShareLock' AND NOT l.granted") == '1', 'Backup did not lock the creation-key table'
            complete = f"UPDATE forge_creation_requests SET response=(SELECT to_jsonb(i) FROM forge_issues i WHERE tenant_id='{tenant}' AND repository_id='{repo}' AND number={number}) WHERE tenant_id='{tenant}' AND repository_id='{repo}' AND idempotency_key='barrier-key'; COMMIT;\n\\q\n"
            writer.stdin.write(complete.encode()); writer.stdin.flush()
            stdout, stderr = writer.communicate(timeout=10)
            assert writer.returncode == 0, self.redact(stderr.decode())
            stdout, stderr = backup.communicate(timeout=60)
            assert backup.returncode == 0, self.redact(stderr.decode())
            self.backup_result = json.loads(stdout)
        finally:
            for proc in (writer, backup):
                if proc and proc.poll() is None:
                    proc.kill(); proc.wait(timeout=5)
        self.cli('backup-verify', str(self.backup))
        self.source_rows = self.all_rows()
        assert set(self.source_rows) == EXPECTED_TABLES
        assert len(self.source_rows['forge_creation_requests']) == 37
        assert all(r['response'] is not None for r in self.source_rows['forge_creation_requests'])
        assert len(self.source_rows['forge_issues']) == 10
        assert len(self.source_rows['forge_issue_comments']) == 28
        self.backed_up_forge = self.forge_rows()
        self.issue_counters = {r['repository_id']: r['next_number'] for r in self.source_rows['forge_issue_counters']}
        self.comment_counters = {(r['repository_id'], r['number']): r['next_comment_number'] for r in self.source_rows['forge_issues']}
        assert self.issue_counters[repo] == number + 1
        assert self.comment_counters[(repo, number)] == 2
        assert self.git_authority() == self.initial_git_authority
        manifest = json.loads((self.backup / 'manifest.json').read_text())
        assert manifest['schema_versions'] == SCHEMA_VERSIONS
        assert manifest['format'] == 6
        return dict(forge_tables_uncommitted_writer=True, backup_waited_on_share_barrier=True,
                    pre_boundary_commit_included=True, full_public_table_count=TABLE_COUNT,
                    issue_rows=10, comment_rows=28, issue_counter_after_commit=number + 1,
                    git_authority_unchanged=True)

    def post_boundary(self):
        self.start()
        before = self.git_authority()
        self.after_issue = self.document(self.basepath, 201, method='POST',
                                         body={'title': 'after backup issue', 'body': 'not in backup'},
                                         extra_headers={'Idempotency-Key': 'after-backup'})
        assert self.after_issue['number'] == self.issue_counters[self.repo['id']]
        self.after_comment = self.document(self.basepath + '/1/comments', 201, method='POST',
                                           body={'body': 'after backup comment'})
        self.document(self.basepath + '/1', method='PATCH',
                      body={'expected_version': 3, 'state': 'closed', 'body': 'unbacked edit'})
        self.document(self.basepath + '/1/comments/1', method='PATCH',
                      body={'expected_version': 2, 'body': 'unbacked comment edit'})
        self.after_ack = time.time()
        assert self.git_authority() == before
        self.stop()
        assert self.forge_rows() != self.backed_up_forge
        return dict(acknowledged_issue_creations_outside_backup=1,
                    acknowledged_comment_creations_outside_backup=1,
                    acknowledged_edits_outside_backup=2,
                    observed_seconds_after_backup_boundary=round(self.after_ack - self.backup_result['boundary_unix_seconds'], 3),
                    production_lossless_restore_claim=False, git_authority_unchanged=True)

    def restore_forge_exact(self):
        result = super().restore_exact()
        assert set(self.all_rows()) == EXPECTED_TABLES
        assert self.all_rows() == self.source_rows
        assert self.forge_rows() == self.backed_up_forge
        assert self.sql("SELECT count(*) FROM forge_issues WHERE title='after backup issue'") == '0'
        assert self.sql("SELECT count(*) FROM forge_issue_comments WHERE body IN ('after backup comment','unbacked comment edit')") == '0'
        return {**result, 'full_public_table_count': TABLE_COUNT, 'all_forge_rows_and_counters_exact': True,
                'post_boundary_creations_and_edits_not_recovered': 4,
                'snapshot_counters_restored_not_global_monotonic_after_data_loss': True}

    def restored_forge_access(self):
        self.start()
        before = self.all_rows()
        git_before = self.git_authority()
        for path, token, issue, comments in self.saved_http:
            reader = self.reader if token is self.alice else self.bob_reader
            stranger = self.bob if token is self.alice else self.alice
            assert self.document(path, token=reader) == issue
            assert self.document(path + '/comments', token=reader)['items'] == comments
            page = self.document(path + '/comments?limit=2', token=reader)
            assert page['items'] == comments[:2] and page['next_after'] == 2
            assert self.document(path + '/comments?limit=2&after=2', token=reader) == {'items': comments[2:], 'next_after': None}
            for endpoint in (path, path + '/comments', path + '/comments/1'):
                self.document(endpoint, 404, token=stranger)
            for endpoint, method, payload in ((path, 'PATCH', {'expected_version': issue['version'], 'title': 'denied'}),
                                               (path + '/comments', 'POST', {'body': 'denied'}),
                                               (path + '/comments/1', 'PATCH', {'expected_version': 2, 'body': 'denied'})):
                self.document(endpoint, 403, token=reader, method=method, body=payload)
                self.document(endpoint, 404, token=stranger, method=method, body=payload)
        for path, token in ((self.basepath, self.reader), (self.bobpath, self.bob_reader)):
            self.document(path, 403, token=token, method='POST', body={'title': 'denied'})
        for token in (self.revoked, self.forge_expired_token):
            for path in (self.basepath, self.basepath + '/1', self.basepath + '/1/comments', self.basepath + '/1/comments/1'):
                self.document(path, 401, token=token)
            self.document(self.basepath, 401, token=token, method='POST', body={'title': 'denied'})
            self.document(self.basepath + '/1/comments', 401, token=token, method='POST', body={'body': 'denied'})
        frozen = '/api/repos/alice/unknown/issues'
        for path in (frozen, frozen + '/1', frozen + '/1/comments', frozen + '/1/comments/1'):
            self.document(path, 409)
        for path, method, payload in ((frozen, 'POST', {'title': 'denied'}),
                                     (frozen + '/1', 'PATCH', {'expected_version': 1, 'state': 'closed'}),
                                     (frozen + '/1/comments', 'POST', {'body': 'denied'}),
                                     (frozen + '/1/comments/1', 'PATCH', {'expected_version': 1, 'body': 'denied'})):
            self.document(path, 409, method=method, body=payload)
        barrier = self.document(self.basepath + '/' + str(self.barrier_number))
        assert barrier['title'] == 'barrier issue'
        assert self.document(self.basepath + '/' + str(self.barrier_number) + '/comments')['items'][0]['body'] == 'barrier comment'
        for path, token, payload, headers, original in self.saved_replays:
            assert self.document(path, 201, token=token, method='POST', body=payload, extra_headers=headers) == original
            changed = dict(payload)
            changed['body'] = 'conflicting retry'
            self.document(path, 409, token=token, method='POST', body=changed, extra_headers=headers)
        self.document(self.basepath + '/' + str(self.after_issue['number']), 404)
        self.document(self.basepath + '/1/comments/' + str(self.after_comment['number']), 404)
        assert self.all_rows() == before, 'Read/denied calls changed restored SQL rows'
        assert self.git_authority() == git_before
        self.stop()
        return dict(unicode_bodies_states_versions_authors_timestamps_exact=True,
                    owner_isolation_and_read_only=True, revoked_and_expired_tokens_preserved=True,
                    recovering_repository_all_eight_endpoints_frozen=True,
                    pagination_preserved=True, denied_requests_no_sql_mutation=True)

    def restored_forge_mutations(self):
        self.start()
        git_before = self.git_authority()
        for repo, path, token in self.forge_repos:
            issue = self.document(path, 201, token=token, method='POST', body={'title': 'restored issue'},
                                  extra_headers={'Idempotency-Key': 'after-backup'})
            assert issue['number'] == self.issue_counters[repo['id']]
            comment = self.document(path + '/1/comments', 201, token=token, method='POST', body={'body': 'restored comment'})
            assert comment['number'] == self.comment_counters[(repo['id'], 1)]
            closed = self.document(path + '/1', token=token, method='PATCH', body={'expected_version': 3, 'state': 'closed'})
            assert closed['version'] == 4 and closed['state'] == 'closed'
            self.document(path + '/1', 409, token=token, method='PATCH', body={'expected_version': 3, 'body': 'stale'})
            reopened = self.document(path + '/1', token=token, method='PATCH', body={'expected_version': 4, 'state': 'open'})
            assert reopened['version'] == 5 and reopened['state'] == 'open'
            edited = self.document(path + '/1/comments/1', token=token, method='PATCH', body={'expected_version': 2, 'body': 'restored edit ✅'})
            assert edited['version'] == 3
            self.document(path + '/1/comments/1', 409, token=token, method='PATCH', body={'expected_version': 2, 'body': 'stale'})
        def update(i):
            return self.http(self.basepath + '/1', token=self.alice, method='PATCH',
                             body={'expected_version': 5, 'title': 'restored race ' + str(i)})[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(update, range(8)))
        assert statuses.count(200) == 1 and statuses.count(409) == 7, statuses
        assert self.git_authority() == git_before
        self.stop()
        self.after_mutation_forge = self.forge_rows()
        return dict(next_issue_and_comment_numbers_equal_restored_counters=True,
                    version_cas_close_reopen_and_edit=True, eight_concurrent_updates_one_winner=True,
                    forge_did_not_mutate_refs_generations_git_operations_or_outbox=True,
                    unbacked_pre_restore_numbers_can_be_reused=True)

    def workers_preserve_forge(self):
        result = super().restored_workers()
        assert self.forge_rows() == self.after_mutation_forge
        return {**result, 'all_forge_rows_unchanged_by_workers': True}

    def git_preserves_forge(self):
        result = super().new_push()
        assert self.forge_rows() == self.after_mutation_forge
        return {**result, 'all_forge_rows_unchanged_by_real_git_push_and_workers': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--keep', action='store_true')
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get('ROOTYARD_TEST_DATABASE_URL'):
        parser.error('dedicated synthetic ROOTYARD_TEST_DATABASE_URL required')
    h = BackupForgeHarness(args)
    success = False
    try:
        for name, fn in [('populated_forge_and_pending_workers', h.populated_source),
                         ('incomplete_creation_key_rejected', h.incomplete_key_rejected),
                         ('forge_commit_before_backup_barrier', h.commit_barrier),
                         ('acknowledged_forge_after_backup_boundary', h.post_boundary),
                         ('fresh_pg_volume_exact_16_table_restore', h.restore_forge_exact),
                         ('restored_forge_content_and_permissions', h.restored_forge_access),
                         ('restored_forge_numbering_cas_and_git_isolation', h.restored_forge_mutations),
                         ('restored_independent_workers_preserve_forge', h.workers_preserve_forge),
                         ('post_restore_real_git_and_workers_preserve_forge', h.git_preserves_forge)]:
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
                      binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=['Synthetic local PostgreSQL clusters and fresh test-owned volumes, not production failover.',
                                   'Backup is a point-in-time boundary: acknowledged later Forge creations/edits are intentionally not recovered.',
                                   'Counters resume from the snapshot; unbacked pre-restore numbers can be reused after data loss.',
                                   'Personal-owner tenancy only, not organization/collaborator ACLs.',
                                   'Exactly-once assertions cover PostgreSQL effects, not external event delivery.'])
        if args.keep:
            report['retained_directory'] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
