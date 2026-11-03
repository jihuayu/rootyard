#!/usr/bin/env python3
"""Offline audit-gap integration tests. Synthetic crash evidence is not a real push."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import uuid
from reliability import ReliabilityHarness, ZERO


class RecoveryHarness(ReliabilityHarness):
    reason = 'Operator inspected native refs and acknowledges missing push audit evidence.'

    def command(self, *args, error=None):
        p = self.run([self.args.binary, *map(str, args)], check=error is None)
        if error is not None:
            assert p.returncode != 0, ('command unexpectedly succeeded', args)
            assert error in p.stderr.decode(), p.stderr.decode()
        return p

    def inspect(self, error=None):
        p = self.command('inspect-recovery', self.repo['id'], error=error)
        return json.loads(p.stdout) if error is None else None

    def resolve(self, inspection, error=None, reason=None, generation=None, fingerprint=None):
        p = self.command('resolve-unknown', self.repo['id'], '--expected-generation',
                         inspection['storage_generation'] if generation is None else generation,
                         '--fingerprint', fingerprint or inspection['fingerprint'],
                         '--acknowledge-audit-gap', self.reason if reason is None else reason,
                         error=error)
        return json.loads(p.stdout) if error is None else None

    def fail_sql(self, query, error):
        env = self.env.copy()
        p = self.run(['psql', '--dbname', self.db, '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', query], check=False, env=env)
        assert p.returncode and error in p.stderr.decode(), p.stderr.decode()

    def fixture(self):
        self.roundtrip()
        self.push('HEAD:removed-before-baseline')
        self.command('inspect-recovery', self.repo['id'], error='data directory already in use')
        self.command('reconcile', error='data directory already in use')
        self.stop()
        journal = self.root / 'data/journal' / self.repo['id']
        seq = int((journal / 'sequence').read_text()) + 1
        self.unknown_id = str(uuid.uuid4())
        metadata = dict(id=self.unknown_id, repository_id=self.repo['id'],
                        actor_id=self.sql("SELECT id FROM users WHERE username='alice'"),
                        actor_name='alice', token_id=self.alice['token_id'], sequence=seq, storage_generation=1)
        self.journal = journal / (f'{seq:020}-' + self.unknown_id)
        self.journal.mkdir(mode=0o700)
        (journal / 'sequence').write_text(str(seq))
        (self.journal / 'operation.json').write_text(json.dumps(metadata))
        self.evidence_file = self.journal / '00000000000000000001.event.json'
        self.evidence_file.write_text(json.dumps(dict(ordinal=1, phase='Prepared', changes=[dict(ref_name='refs/heads/main', old_oid=self.first, new_oid=self.second)])))
        self.inspect(error='not imported as unknown')
        self.command('reconcile')
        assert self.last_operation('unknown')['id'] == self.unknown_id
        self.start()
        assert self.push('HEAD:blocked', check=False).returncode != 0
        self.stop()
        self.baseline = self.inspect()
        assert self.baseline['fsck'] == 'passed'
        assert len(self.baseline['unknown_operations']) == 1
        return {'synthetic_prepared_only': True, 'offline_reconcile_imported': True, 'restart_blocks_push': True}

    def stale_inspections(self):
        b = self.baseline
        self.resolve(b, error='inspection changed', generation=2)
        self.resolve(b, error='inspection changed', fingerprint='0' * 64)
        self.resolve(b, error='reason must contain', reason=' ')
        lock = self.bare / 'refs/heads/main.lock'
        lock.write_text('test lock')
        self.inspect(error='Git lock file')
        self.resolve(b, error='Git lock file')
        lock.unlink()
        link = self.bare / 'unexpected-link'
        link.symlink_to('HEAD')
        self.inspect(error='unsupported symbolic link')
        link.unlink()
        broken_ref = self.bare / 'refs/heads/broken-object'
        broken_ref.write_text('1' * 40 + '\n')
        self.inspect(error='native integrity check failed')
        broken_ref.unlink()
        counter = self.journal.parent / 'sequence'
        old_counter = counter.read_text()
        counter.write_text(str(int(old_counter) + 1))
        self.resolve(b, error='inspection changed')
        counter.write_text(old_counter)
        duplicate_seq = int(old_counter) + 1
        duplicate = self.journal.parent / (f'{duplicate_seq:020}-' + self.unknown_id)
        shutil.copytree(self.journal, duplicate)
        duplicate_metadata = json.loads((duplicate / 'operation.json').read_text())
        duplicate_metadata['sequence'] = duplicate_seq
        (duplicate / 'operation.json').write_text(json.dumps(duplicate_metadata))
        counter.write_text(str(duplicate_seq))
        self.inspect(error='')
        shutil.rmtree(duplicate)
        counter.write_text(old_counter)
        head = self.bare / 'HEAD'
        original_head = head.read_bytes()
        head.write_text(self.second + '\n')
        self.resolve(b, error='inspection changed')
        head.write_bytes(original_head)
        evidence = self.evidence_file.read_bytes()
        changed = json.loads(evidence)
        changed['changes'][0]['old_oid'] = ZERO
        self.evidence_file.write_text(json.dumps(changed))
        self.resolve(b, error='inspection changed')
        self.evidence_file.write_bytes(evidence)
        # Same final state/reason, different incident revision must invalidate review.
        self.sql("UPDATE repositories SET recovery_reason='manual_storage_check' WHERE id='" + self.repo['id'] + "'")
        unrelated = self.inspect()
        self.resolve(unrelated, error='only the unknown-push incident')
        self.sql("UPDATE repositories SET recovery_reason='push_outcome_unknown' WHERE id='" + self.repo['id'] + "'")
        self.resolve(b, error='inspection changed')
        b = self.inspect()
        self.git('--git-dir=' + str(self.bare), 'update-ref', '-d', 'refs/heads/removed-before-baseline')
        self.resolve(b, error='inspection changed')
        self.baseline = self.inspect()
        # SQL evidence is bound separately from filesystem evidence.
        self.sql("UPDATE git_operations SET evidence=evidence || '{\"test_marker\":true}'::jsonb WHERE id='" + self.unknown_id + "'")
        self.resolve(self.baseline, error='inspection changed')
        self.baseline = self.inspect()
        return {'generation_fingerprint_refs_head_journal_sql_evidence_incident_revision_bound': True,
                'unrelated_incident_and_git_lock_rejected': True}

    def acknowledge(self):
        # Legacy/candidate events attached to an unknown must be discarded, not
        # delivered as successful audit or allowed to block future same-ref work.
        self.candidate_id = 'e' * 64
        sequence = self.last_operation('unknown')['sequence']
        self.sql("INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid) VALUES('" + self.candidate_id + "','" + self.unknown_id + "','" + self.repo['id'] + "',1," + str(sequence) + ",1,'refs/heads/after-resolution','" + ZERO + "','" + self.second + "'); INSERT INTO event_deliveries(event_id,consumer) VALUES('" + self.candidate_id + "','ref-index'),('" + self.candidate_id + "','audit-log')")
        self.sql("UPDATE event_deliveries SET state='leased',lease_owner='" + str(uuid.uuid4()) + "',lease_generation=4,lease_until=clock_timestamp()+interval '1 hour' WHERE event_id='" + self.candidate_id + "' AND consumer='ref-index'")
        before = self.events()
        self.original_operation = self.last_operation('unknown')
        self.journal_backup = self.root / 'saved-journal'
        shutil.copytree(self.journal, self.journal_backup)
        result = self.resolve(self.baseline)
        assert result['new_generation'] == 2 and not result['already_applied']
        self.resolution_id = result['resolution_id']
        assert not self.journal.exists()
        assert self.last_operation('unknown') == self.original_operation
        assert self.events() == before
        candidate_deliveries = self.rows("SELECT state,effect FROM event_deliveries WHERE event_id='" + self.candidate_id + "'")
        assert len(candidate_deliveries) == 2 and all(row == {'state': 'delivered', 'effect': 'discarded_unknown'} for row in candidate_deliveries)
        assert self.sql("SELECT count(*) FROM audit_events WHERE event_id='" + self.candidate_id + "'") == '0'
        candidate_lease = self.rows("SELECT lease_owner,lease_until,lease_generation FROM event_deliveries WHERE event_id='" + self.candidate_id + "' AND consumer='ref-index'")[0]
        assert candidate_lease == {'lease_owner': None, 'lease_until': None, 'lease_generation': 5}
        rows = self.rows("SELECT * FROM repository_ref_projection WHERE repository_id='" + self.repo['id'] + "'")
        assert [(r['ref_name'], r['oid']) for r in rows] == [('refs/heads/main', self.second)], rows
        assert all(r['source_kind'] == 'recovery_snapshot' and r['event_id'] is None and r['resolution_id'] == self.resolution_id and r['storage_generation'] == 2 for r in rows)
        resolution = self.rows("SELECT * FROM operation_resolutions WHERE operation_id='" + self.unknown_id + "'")[0]
        assert resolution['journal_evidence'] is not None and resolution['journal_digest']
        original_data_dir = self.env['ROOTYARD_DATA_DIR']
        try:
            self.env['ROOTYARD_DATA_DIR'] = str(self.root / 'wrong-volume')
            self.resolve(self.baseline, error='')
        finally:
            self.env['ROOTYARD_DATA_DIR'] = original_data_dir
        assert self.resolve(self.baseline)['already_applied']
        self.resolve(self.baseline, reason='different acknowledgment', error='reason mismatch')
        assert self.sql('SELECT count(*) FROM recovery_resolutions') == '1'
        for table, where in [('recovery_resolutions', "id='" + self.resolution_id + "'"), ('operation_resolutions', "operation_id='" + self.unknown_id + "'")]:
            self.fail_sql('DELETE FROM ' + table + ' WHERE ' + where, 'immutable')
            self.fail_sql('UPDATE ' + table + ' SET repository_id=repository_id WHERE ' + where, 'immutable')
        self.fail_sql("UPDATE git_operations SET outcome='recorded' WHERE id='" + self.unknown_id + "'", 'immutable')
        self.fail_sql("INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid) VALUES('" + 'f'*64 + "','" + self.unknown_id + "','" + self.repo['id'] + "',1," + str(self.original_operation['sequence']) + ",1,'refs/heads/forged','" + ZERO + "','" + self.second + "')", 'cannot publish events')
        self.fail_sql("UPDATE repository_ref_projection SET storage_generation=1 WHERE repository_id='" + self.repo['id'] + "'", 'stale projection storage generation')
        self.drain()
        assert self.rows("SELECT * FROM repository_ref_projection WHERE repository_id='" + self.repo['id'] + "'") == rows
        assert self.sql("SELECT count(*) FROM event_deliveries WHERE consumer='ref-index' AND effect='superseded_generation'") == str(len(before) - 1)
        self.start()
        self.command('resolve-unknown', self.repo['id'], '--expected-generation', '1', '--fingerprint', self.baseline['fingerprint'], '--acknowledge-audit-gap', self.reason, error='data directory already in use')
        resolution_path = '/api/repos/alice/demo/resolutions'
        summaries = json.loads(self.expect(resolution_path, 200, token=self.alice))
        assert summaries[0]['id'] == self.resolution_id and summaries[0]['new_generation'] == 2
        self.expect(resolution_path, 401)
        self.expect(resolution_path, (403, 404), token=self.bob)
        listed_events = json.loads(self.expect('/api/repos/alice/demo/events', 200, token=self.alice))
        candidate = next(e for e in listed_events if e['event_id'] == self.candidate_id)
        assert candidate['operation_outcome'] == 'unknown' and candidate['resolution_id'] == self.resolution_id
        assert set(candidate['delivery_effects'].values()) == {'discarded_unknown'}
        self.push('HEAD:after-resolution')
        assert self.last_operation('recorded')['storage_generation'] == 2
        self.drain()
        assert self.sql("SELECT source_kind FROM repository_ref_projection WHERE ref_name='refs/heads/after-resolution'") == 'push_receipt'
        assert self.sql("SELECT count(*) FROM audit_events WHERE event_id='" + self.candidate_id + "'") == '0'
        assert self.sql("SELECT count(*) FROM event_deliveries WHERE state<>'delivered'") == '0'
        assert self.sql("SELECT count(*) FROM audit_events a JOIN outbox_events e USING(event_id) WHERE e.ref_name='refs/heads/after-resolution'") == '1'
        self.stop()
        return {'resolution_id': self.resolution_id, 'unknown_preserved_no_fake_events': True,
                'immutable_records': True, 'snapshot_provenance': True,
                'old_events_do_not_resurrect_removed_ref': True, 'unknown_candidates_discarded_without_blocking_new_event': True, 'new_real_push_generation': 2}

    def missing_and_bad_journal(self):
        self.start()
        self.repo = json.loads(self.expect('/api/repos', 201, method='POST', token=self.alice, body={'name': 'missing-evidence'}))
        self.remote = self.base + self.repo['clone_path']
        self.git('push', self.remote, 'HEAD:main', cwd=self.work, token=self.alice)
        self.bare = self.root / 'data/repos' / (self.repo['id'] + '.git')
        self.stop()
        journal = self.root / 'data/journal' / self.repo['id']
        seq = int((journal / 'sequence').read_text()) + 1
        op_id = str(uuid.uuid4())
        path = journal / (f'{seq:020}-' + op_id)
        path.mkdir()
        (journal / 'sequence').write_text(str(seq))
        metadata = dict(id=op_id, repository_id=self.repo['id'], actor_id=self.sql("SELECT id FROM users WHERE username='alice'"),
                        actor_name='alice', token_id=self.alice['token_id'], sequence=seq, storage_generation=1)
        (path / 'operation.json').write_text(json.dumps(metadata))
        event = path / '00000000000000000001.event.json'
        event.write_text('{broken json')
        self.command('reconcile')
        assert self.last_operation('unknown')['evidence']['invalid_journal']
        self.inspect(error='')
        event.write_text(json.dumps(dict(ordinal=1, phase='Prepared', changes=[dict(ref_name='refs/heads/main', old_oid=self.first, new_oid=self.second)])))
        self.command('reconcile')
        before = self.inspect()
        saved = self.root / 'missing-journal-backup'
        shutil.move(str(path), saved)
        self.resolve(before, error='inspection changed')
        counter = journal / 'sequence'
        saved_counter = counter.read_bytes()
        counter.unlink()
        self.inspect(error='')
        counter.write_text('0')
        self.inspect(error='journal sequence missing or behind PostgreSQL history')
        counter.write_bytes(saved_counter)
        missing = self.inspect()
        assert missing['unknown_operations'][0]['journal_digest'] is None
        # Missing evidence may be acknowledged explicitly, never invented.
        result = self.resolve(missing)
        assert result['audit_gap_acknowledged']
        mapping = self.rows("SELECT * FROM operation_resolutions WHERE operation_id='" + op_id + "'")[0]
        assert mapping['journal_digest'] is None and mapping['journal_evidence'] is None
        assert self.last_operation('unknown')['id'] == op_id
        shutil.copytree(saved, path)
        self.resolve(missing, error='resolved journal changed')
        assert path.exists()
        return {'malformed_evidence_inspection_refused': True,
                'journal_disappearance_invalidates_review': True,
                'missing_and_rolled_back_counter_refused': True,
                'explicit_missing_journal_gap_preserves_null_evidence': True,
                'later_journal_not_authorized_for_retirement': True}

    def reintroduced_journal(self):
        # Identical post-commit leftover is safe to retire again.
        shutil.copytree(self.journal_backup, self.journal)
        assert self.resolve(self.baseline)['already_applied']
        assert not self.journal.exists()
        shutil.copytree(self.journal_backup, self.journal)
        self.evidence_file.write_text(self.evidence_file.read_text().replace(self.first, ZERO))
        self.resolve(self.baseline, error='resolved journal changed')
        assert self.journal.exists()
        self.command('reconcile')
        assert self.sql("SELECT recovery_reason FROM repositories WHERE id='" + self.repo['id'] + "'") == 'resolved_journal_changed'
        self.start()
        assert self.push('HEAD:changed-journal-blocked', check=False).returncode != 0
        assert self.ref('refs/heads/changed-journal-blocked') is None
        self.stop()
        return {'matching_journal_idempotently_retired': True, 'changed_journal_preserved_and_blocks_push': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--keep', action='store_true')
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get('ROOTYARD_TEST_DATABASE_URL'):
        parser.error('ROOTYARD_TEST_DATABASE_URL is required')
    h = RecoveryHarness(args)
    success = False
    try:
        for name, case in [('setup', h.setup), ('api', h.api), ('synthetic_unknown_offline_import', h.fixture),
                           ('stale_inspection_and_guardrails', h.stale_inspections),
                           ('explicit_gap_acknowledgment', h.acknowledge),
                           ('reintroduced_journal_fail_closed', h.reintroduced_journal),
                           ('missing_and_malformed_evidence', h.missing_and_bad_journal)]:
            h.case(name, case)
        success = True
    except Exception as error:
        print(h.redact(error), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:
            h.results.append(dict(name='cleanup', status='failed', error=h.redact(error)))
            success = False
        report = dict(passed=success, cases=h.results, limitations=h.limits + [
            'Synthetic prepared-only journal is not evidence of a successful push.',
            'No power-loss, multi-host fencing, or PostgreSQL worker/resolve race is simulated by this suite.'
        ], binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest())
        if args.keep:
            report['retained_directory'] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
