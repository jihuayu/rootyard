#!/usr/bin/env python3
"""Schema-003 backup/restore acceptance on fresh synthetic databases and volumes.

Requires CREATEDB on dedicated ROOTYARD_TEST_DATABASE_URL; an optional separate
ROOTYARD_RESTORE_TEST_DATABASE_URL provides a second PostgreSQL server. Never use
production. Synthetic prepared journals do not claim successful pushes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import uuid
from backup import BackupHarness

ZERO = '0' * 40


class BackupRecoveryHarness(BackupHarness):
    reason = 'Synthetic drill: native refs inspected; missing push audit evidence explicitly acknowledged.'

    def __init__(self, args):
        super().__init__(args)
        # This fixture owns exact SQL state transitions via worker-once. A
        # background worker stopped mid-lease may validly defer replay for 60s;
        # lease recovery and concurrent workers are covered in separate suites.
        self.env.update(ROOTYARD_OUTBOX_WORKER='false', ROOTYARD_WAKE_TRANSPORT='poll')

    def rows(self, select):
        return json.loads(self.sql("SELECT COALESCE(json_agg(t), '[]'::json) FROM (" + select + ") t"))

    def command(self, *args, error=None):
        p = self.run([self.args.binary, *map(str, args)], check=error is None)
        if error is not None:
            assert p.returncode != 0, 'Unexpected successful command: ' + str(args)
            assert error in p.stderr.decode(), p.stderr.decode()
        return p

    def resolve(self, fixture, error=None):
        p = self.command('resolve-unknown', fixture['repo']['id'], '--expected-generation',
                         fixture['inspection']['storage_generation'], '--fingerprint',
                         fixture['inspection']['fingerprint'], '--acknowledge-audit-gap',
                         self.reason, error=error)
        return json.loads(p.stdout) if error is None else None

    def fail_sql(self, sql, error):
        p = self.run(['psql', '--dbname', self.db, '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', sql], check=False)
        assert p.returncode != 0 and error in p.stderr.decode(), p.stderr.decode()

    def drain(self):
        deadline = time.monotonic() + 30
        while int(self.sql("SELECT count(*) FROM event_deliveries WHERE state <> 'delivered'")):
            assert time.monotonic() < deadline, 'Outbox did not drain'
            self.cli('worker-once')

    def all_rows(self):
        tables = self.rows("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
        return {r['tablename']: self.rows('SELECT * FROM public."' + r['tablename'] + '" t ORDER BY to_jsonb(t)::text') for r in tables}

    def make_resolved(self, name, missing=False):
        self.start()
        repo = json.loads(self.expect('/api/repos', 201, token=self.alice, method='POST', body={'name': name}))
        remote = self.base + repo['clone_path']
        self.git('push', remote, 'HEAD:main', cwd=self.work, token=self.alice)
        self.stop()
        journal_root = Path(self.env['ROOTYARD_DATA_DIR']) / 'journal' / repo['id']
        sequence = int((journal_root / 'sequence').read_text()) + 1
        op_id = str(uuid.uuid4())
        journal = journal_root / (f'{sequence:020}-' + op_id)
        journal.mkdir(mode=0o700)
        (journal_root / 'sequence').write_text(str(sequence))
        metadata = dict(id=op_id, repository_id=repo['id'], actor_id=self.sql("SELECT id FROM users WHERE username='alice'"), actor_name='alice', token_id=self.alice['token_id'], sequence=sequence, storage_generation=1)
        (journal / 'operation.json').write_text(json.dumps(metadata))
        (journal / '00000000000000000001.event.json').write_text(json.dumps(dict(ordinal=1, phase='Prepared', changes=[dict(ref_name='refs/heads/main', old_oid=self.first, new_oid=self.second)])))
        self.cli('reconcile')
        saved = self.root / (name + '-saved-journal')
        shutil.copytree(journal, saved)
        if missing:
            shutil.rmtree(journal)
        fixture = dict(repo=repo, remote=remote, op_id=op_id, sequence=sequence, saved=saved,
                       journal=journal.relative_to(Path(self.env['ROOTYARD_DATA_DIR'])))
        fixture['inspection'] = json.loads(self.cli('inspect-recovery', repo['id']))
        assert fixture['inspection']['fsck'] == 'passed'
        if not missing:
            self.candidate = 'e' * 64
            self.sql("INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid) VALUES('" + self.candidate + "','" + op_id + "','" + repo['id'] + "',1," + str(sequence) + ",1,'refs/heads/after-restore','" + ZERO + "','" + self.second + "'); INSERT INTO event_deliveries(event_id,consumer) VALUES('" + self.candidate + "','ref-index'),('" + self.candidate + "','audit-log')")
            self.sql("UPDATE event_deliveries SET state='leased',lease_owner='" + str(uuid.uuid4()) + "',lease_generation=4,lease_until=clock_timestamp()+interval '1 hour' WHERE event_id='" + self.candidate + "' AND consumer='ref-index'")
        original = self.rows("SELECT * FROM git_operations WHERE id='" + op_id + "'")
        result = self.resolve(fixture)
        assert result['new_generation'] == 2 and not result['already_applied']
        fixture['resolution_id'] = result['resolution_id']
        assert self.rows("SELECT * FROM git_operations WHERE id='" + op_id + "'") == original
        assert not journal.exists()
        return fixture

    def recovery_source(self):
        super().setup()
        self.resolved = self.make_resolved('resolved')
        self.missing = self.make_resolved('missing-evidence', missing=True)
        self.drain()
        self.sql("UPDATE tokens SET revoked=true WHERE id='" + self.revoked['token_id'] + "'")
        self.source_rows = self.all_rows()
        self.marker = (Path(self.env['ROOTYARD_DATA_DIR']) / '.volume-id').read_bytes()
        assert len(self.source_rows['recovery_resolutions']) == 2
        assert len(self.source_rows['operation_resolutions']) == 2
        for fixture in (self.resolved, self.missing):
            resolution = next(r for r in self.source_rows['recovery_resolutions'] if r['id'] == fixture['resolution_id'])
            assert resolution['reason'] == self.reason
            assert resolution['old_generation'] == 1 and resolution['new_generation'] == 2
            assert resolution['inspected_fingerprint'] == fixture['inspection']['fingerprint']
            assert resolution['volume_id'] == self.marker.decode().strip()
            assert resolution['snapshot']['refs'] == [dict(name='refs/heads/main', oid=self.second)]
            assert resolution['database_actor'] and resolution['created_at']
        mapping = next(r for r in self.source_rows['operation_resolutions'] if r['operation_id'] == self.resolved['op_id'])
        assert mapping['journal_digest'] and mapping['operation_digest'] and mapping['journal_evidence']
        absent = next(r for r in self.source_rows['operation_resolutions'] if r['operation_id'] == self.missing['op_id'])
        assert absent['journal_digest'] is None and absent['journal_evidence'] is None
        self.backup_result = json.loads(self.backup_command().stdout)
        self.cli('backup-verify', str(self.backup))
        (self.root / 'source-sql-rows.json').write_text(json.dumps(self.source_rows, indent=2) + '\n')
        return dict(resolved_unknowns=2, unresolved_unknowns=1, full_table_rows_captured=len(self.source_rows), synthetic_prepared_only=True)

    def schema_rejection(self):
        function = self.sql("SELECT pg_get_functiondef('public.rootyard_freeze_resolved_operation()'::regprocedure)")
        constraint = self.sql("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='repository_ref_projection'::regclass AND conname='projection_source'")
        internal = self.rows("SELECT c.relname AS table_name,t.tgname AS trigger_name FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_constraint k ON k.oid=t.tgconstraint WHERE n.nspname='public' AND t.tgisinternal AND k.contype='f' AND t.tgenabled='O' ORDER BY c.relname,t.tgname LIMIT 1")[0]
        internal_target = 'public."' + internal['table_name'].replace('"', '""') + '"'
        internal_name = '"' + internal['trigger_name'].replace('"', '""') + '"'
        changes = [
            ("CREATE OR REPLACE FUNCTION rootyard_freeze_resolved_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END $$", function),
            ('ALTER TABLE git_operations DISABLE TRIGGER freeze_resolved_operation', 'ALTER TABLE git_operations ENABLE TRIGGER freeze_resolved_operation'),
            ('ALTER TABLE ' + internal_target + ' DISABLE TRIGGER ' + internal_name, 'ALTER TABLE ' + internal_target + ' ENABLE TRIGGER ' + internal_name),
            ('ALTER TABLE repository_ref_projection DROP CONSTRAINT projection_source; ALTER TABLE repository_ref_projection ADD CONSTRAINT projection_source CHECK(true)', 'ALTER TABLE repository_ref_projection DROP CONSTRAINT projection_source; ALTER TABLE repository_ref_projection ADD CONSTRAINT projection_source ' + constraint),
        ]
        for index, (change, undo) in enumerate(changes):
            destination = self.root / ('bad-schema-' + str(index))
            self.sql(change)
            try:
                assert self.backup_command(destination, check=False).returncode != 0
                assert not destination.exists()
            finally:
                self.sql(undo)
        self.query(self.target_db, function)
        try:
            assert self.restore_command(check=False).returncode != 0
            assert not self.target.exists()
            assert self.query(self.target_db, "SELECT count(*) FROM pg_tables WHERE schemaname='public'") == '0'
        finally:
            self.query(self.target_db, 'DROP FUNCTION public.rootyard_freeze_resolved_operation()')
        return dict(altered_freeze_function_rejected=True, disabled_trigger_rejected=True, disabled_internal_fk_trigger_rejected=True, altered_constraint_rejected=True, existing_known_function_target_rejected=True)

    def restore_exact(self):
        result = json.loads(self.restore_command().stdout)
        assert (self.target / '.volume-id').read_bytes() == self.marker
        for path in (self.backup / 'volume' / 'journal').rglob('*'):
            if path.is_file():
                assert (self.target / path.relative_to(self.backup / 'volume')).read_bytes() == path.read_bytes()
        self.db = self.target_db
        self.env.update(DATABASE_URL=self.db, ROOTYARD_DATA_DIR=str(self.target))
        restored = self.all_rows()
        (self.root / 'restored-sql-rows.json').write_text(json.dumps(restored, indent=2) + '\n')
        assert restored == self.source_rows, 'Full public table contents differ after restore'
        assert self.sql('SELECT max(version) FROM schema_migrations') == '3'
        for fixture in (self.resolved, self.missing):
            assert self.sql("SELECT storage_generation FROM repositories WHERE id='" + fixture['repo']['id'] + "'") == '2'
        projection = self.rows("SELECT * FROM repository_ref_projection WHERE repository_id='" + self.resolved['repo']['id'] + "'")
        assert projection and all(r['source_kind'] == 'recovery_snapshot' and r['event_id'] is None and r['resolution_id'] == self.resolved['resolution_id'] and r['storage_generation'] == 2 for r in projection)
        effects = self.rows("SELECT state,effect,lease_owner,lease_until FROM event_deliveries WHERE event_id='" + self.candidate + "'")
        assert len(effects) == 2 and all(r == dict(state='delivered',effect='discarded_unknown',lease_owner=None,lease_until=None) for r in effects)
        assert self.sql("SELECT count(*) FROM audit_events WHERE event_id='" + self.candidate + "'") == '0'
        return dict(all_public_rows_exact=True, volume_id_byte_exact=True, journal_files_byte_exact=True, recovery_snapshot_provenance=True, delivery_effects_preserved=True, separate_pg_server=self.admin != self.restore_admin, restore_seconds=result['elapsed_seconds'])

    def restored_guards(self):
        f = self.resolved
        repo = f['repo']['id']
        for table, where in [('recovery_resolutions', "id='" + f['resolution_id'] + "'"), ('operation_resolutions', "operation_id='" + f['op_id'] + "'")]:
            self.fail_sql('UPDATE ' + table + ' SET repository_id=repository_id WHERE ' + where, 'immutable')
            self.fail_sql('DELETE FROM ' + table + ' WHERE ' + where, 'immutable')
        self.fail_sql("UPDATE git_operations SET evidence='{}' WHERE id='" + f['op_id'] + "'", 'immutable')
        self.fail_sql("DELETE FROM git_operations WHERE id='" + f['op_id'] + "'", 'immutable')
        self.fail_sql("INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid) VALUES('" + 'f' * 64 + "','" + f['op_id'] + "','" + repo + "',1," + str(f['sequence']) + ",1,'refs/heads/forged','" + ZERO + "','" + self.second + "')", 'cannot publish events')
        self.fail_sql("UPDATE repository_ref_projection SET storage_generation=1 WHERE repository_id='" + repo + "'", 'stale projection storage generation')
        self.fail_sql("INSERT INTO repository_ref_projection(repository_id,ref_name,oid,deleted,storage_generation,operation_sequence,transaction_sequence,event_id,source_kind,resolution_id) VALUES('" + repo + "','refs/heads/stale','" + self.second + "',false,1,0,0,NULL,'recovery_snapshot','" + f['resolution_id'] + "')", 'stale projection storage generation')
        self.fail_sql("UPDATE repository_ref_projection SET source_kind='push_receipt' WHERE repository_id='" + repo + "'", 'projection_source')
        self.fail_sql("UPDATE repository_ref_projection SET source_kind='invented' WHERE repository_id='" + repo + "'", 'projection_source')
        self.fail_sql("UPDATE repository_ref_projection SET resolution_id=NULL WHERE repository_id='" + repo + "'", 'projection_source')
        assert self.all_rows() == self.source_rows, 'Rejected writes mutated restored data'
        before = self.all_rows()
        assert self.resolve(f)['already_applied']
        assert self.all_rows() == before, 'Original resolution retry changed SQL rows'
        unknown = self.unknown_repo['id']
        revision = int(self.sql("SELECT incident_revision FROM repositories WHERE id='" + unknown + "'"))
        self.sql("UPDATE repositories SET incident_revision=999999 WHERE id='" + unknown + "'")
        assert self.sql("SELECT incident_revision FROM repositories WHERE id='" + unknown + "'") == str(revision)
        self.sql("UPDATE repositories SET next_retry_at=next_retry_at+interval '1 second' WHERE id='" + unknown + "'")
        assert self.sql("SELECT incident_revision FROM repositories WHERE id='" + unknown + "'") == str(revision)
        self.sql("UPDATE repositories SET recovery_reason='test_new_incident',incident_revision=999999 WHERE id='" + unknown + "'")
        assert self.sql("SELECT incident_revision FROM repositories WHERE id='" + unknown + "'") == str(revision + 1)
        return dict(resolution_update_delete_immutable=True, resolved_operation_update_delete_immutable=True, resolved_outbox_insert_rejected=True, stale_projection_insert_update_rejected=True, invalid_provenance_rejected=True, original_resolution_retry_no_changes=True, incident_revision_increment_no_override=True)

    def restored_git(self):
        self.start()
        assert self.git('ls-remote', self.remote, token=self.alice).stdout == self.before_refs
        clone = self.root / 'resolved-clone'
        self.git('clone', self.resolved['remote'], str(clone), token=self.reader)
        self.git('fsck', '--full', '--strict', cwd=clone)
        assert self.git('rev-parse', 'HEAD', cwd=clone).stdout.decode().strip() == self.second
        assert (clone / 'hello.txt').read_text() == 'second\n'
        self.expect('/api/repos', 401, token=self.revoked)
        self.expect(self.resolved['repo']['clone_path'] + '/info/refs?service=git-receive-pack', 403, token=self.reader)
        self.expect(self.unknown_repo['clone_path'] + '/info/refs?service=git-upload-pack', 503, token=self.alice)
        self.git('push', self.resolved['remote'], 'HEAD:after-restore', cwd=self.work, token=self.alice)
        repo = self.resolved['repo']['id']
        assert self.sql("SELECT storage_generation FROM git_operations WHERE repository_id='" + repo + "' AND outcome='recorded' ORDER BY sequence DESC LIMIT 1") == '2'
        self.drain()
        assert self.sql("SELECT source_kind FROM repository_ref_projection WHERE repository_id='" + repo + "' AND ref_name='refs/heads/after-restore'") == 'push_receipt'
        assert self.sql("SELECT count(*) FROM audit_events a JOIN outbox_events e USING(event_id) WHERE e.repository_id='" + repo + "' AND e.ref_name='refs/heads/after-restore'") == '1'
        assert self.sql("SELECT count(*) FROM audit_events WHERE event_id='" + self.candidate + "'") == '0'
        self.stop()
        return dict(authenticated_clone_fsck_content=True, revoked_read_only_enforced=True, unresolved_repo_blocked=True, current_generation_real_push=True, genuine_push_audit_once=True)

    def journal_replay(self):
        f = self.resolved
        journal = self.target / f['journal']
        shutil.copytree(f['saved'], journal)
        before = self.all_rows()
        assert self.resolve(f)['already_applied']
        assert not journal.exists() and self.all_rows() == before
        shutil.copytree(f['saved'], journal)
        evidence = journal / '00000000000000000001.event.json'
        evidence.write_text(evidence.read_text().replace(self.first, ZERO))
        self.resolve(f, error='resolved journal changed')
        assert journal.exists()
        self.cli('reconcile')
        assert self.sql("SELECT recovery_reason FROM repositories WHERE id='" + f['repo']['id'] + "'") == 'resolved_journal_changed'
        self.start()
        assert self.git('push', f['remote'], 'HEAD:changed-evidence-blocked', cwd=self.work, token=self.alice, check=False).returncode != 0
        self.stop()
        bare = self.target / 'repos' / (f['repo']['id'] + '.git')
        assert self.git('--git-dir=' + str(bare), 'show-ref', '--verify', 'refs/heads/changed-evidence-blocked', check=False).returncode != 0
        missing = self.target / self.missing['journal']
        shutil.copytree(self.missing['saved'], missing)
        self.resolve(self.missing, error='resolved journal changed')
        assert missing.exists()
        return dict(matching_journal_retired_idempotently=True, changed_journal_preserved_blocks_push=True, previously_missing_reappearing_journal_protected=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--keep', action='store_true')
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get('ROOTYARD_TEST_DATABASE_URL'):
        parser.error('dedicated synthetic ROOTYARD_TEST_DATABASE_URL required')
    h = BackupRecoveryHarness(args)
    success = False
    try:
        for name, fn in [('schema003_source_fixture', h.recovery_source), ('schema_tampering_rejected', h.schema_rejection), ('fresh_database_volume_exact_restore', h.restore_exact), ('restored_schema003_guards', h.restored_guards), ('real_clone_auth_generation2_push', h.restored_git), ('restored_journal_replay_protection', h.journal_replay)]:
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
        report = dict(passed=success, cases=h.results, binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(), limitations=['Synthetic disposable PostgreSQL/loopback drill, not production RPO/RTO or power-loss evidence.', 'Prepared-only journal fixtures do not establish a successful push.'])
        if args.keep:
            report['retained_directory'] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
