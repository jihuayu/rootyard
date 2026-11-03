#!/usr/bin/env python3
"""Restore durable delivery state, then exercise real independent PG-only workers.

Requires synthetic CREATEDB administrators. Optional separate restore administrator
selects another PG cluster. Prepared/lease fixtures do not imply successful pushes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

from backup_recovery import BackupRecoveryHarness
from cross_process import CrossProcessHarness


class RestoredWorkers(BackupRecoveryHarness):
    worker_env = CrossProcessHarness.worker_env
    spawn_worker = CrossProcessHarness.spawn_worker
    kill_worker = CrossProcessHarness.kill_worker
    stop_workers = CrossProcessHarness.stop_workers
    stop_process = staticmethod(CrossProcessHarness.stop_process)
    until = CrossProcessHarness.until

    def __init__(self, args):
        super().__init__(args)
        self.env.update(ROOTYARD_OUTBOX_WORKER='false', ROOTYARD_WAKE_TRANSPORT='poll')
        self.workers = []
        self.serial = 0

    def history(self):
        return {table: self.rows('SELECT * FROM ' + table + ' t ORDER BY to_jsonb(t)::text')
                for table in ('recovery_resolutions', 'operation_resolutions')}

    def volume_files(self):
        root = Path(self.env['ROOTYARD_DATA_DIR'])
        return {str(p.relative_to(root)): ('link', os.readlink(p)) if p.is_symlink()
                else ('file', hashlib.sha256(p.read_bytes()).hexdigest())
                for p in root.rglob('*') if p.is_file() or p.is_symlink()}

    def pending_source(self):
        self.recovery_source()
        self.start()
        self.git('push', self.remote, 'HEAD:queued-before-backup', cwd=self.work, token=self.alice)
        self.git('push', self.resolved['remote'], 'HEAD:queued-generation2', cwd=self.work, token=self.alice)
        self.stop()
        self.pending_events = self.rows("SELECT event_id FROM outbox_events WHERE ref_name IN ('refs/heads/queued-before-backup','refs/heads/queued-generation2') ORDER BY event_id")
        assert len(self.pending_events) == 2
        self.expired = self.pending_events[0]['event_id']
        self.sql("UPDATE event_deliveries SET state='leased',lease_owner='" + str(uuid.uuid4()) + "',lease_generation=4,lease_until=clock_timestamp()-interval '1 second' WHERE event_id='" + self.expired + "' AND consumer='audit-log'")
        self.unexpired = self.pending_events[1]['event_id']
        self.sql("UPDATE event_deliveries SET state='leased',lease_owner='" + str(uuid.uuid4()) + "',lease_generation=9,lease_until=clock_timestamp()+interval '1 hour' WHERE event_id='" + self.unexpired + "' AND consumer='audit-log'")
        self.unexpired_row = self.rows("SELECT * FROM event_deliveries WHERE event_id='" + self.unexpired + "' AND consumer='audit-log'")
        # Requeue one genuine pre-resolution ref event as a stale-lease fixture.
        # It must be retired, never replayed over the observed generation-2 snapshot.
        repo = self.resolved['repo']['id']
        self.stale = self.sql("SELECT e.event_id FROM outbox_events e JOIN git_operations o ON o.id=e.operation_id WHERE e.repository_id='" + repo + "' AND e.storage_generation=1 AND o.outcome='recorded' ORDER BY e.event_id LIMIT 1")
        assert self.stale
        self.sql("UPDATE event_deliveries SET state='leased',lease_owner='" + str(uuid.uuid4()) + "',lease_generation=7,lease_until=clock_timestamp()-interval '1 second',delivered_at=NULL,effect=NULL WHERE event_id='" + self.stale + "' AND consumer='ref-index'")
        self.snapshot = self.rows("SELECT * FROM repository_ref_projection WHERE repository_id='" + repo + "' AND ref_name='refs/heads/main'")
        self.original_history = self.history()
        self.source_rows = self.all_rows()
        self.backup = self.root / 'worker-backup'
        self.backup_result = json.loads(self.backup_command().stdout)
        self.cli('backup-verify', str(self.backup))
        assert int(self.sql("SELECT count(*) FROM event_deliveries WHERE state<>'delivered'")) == 5
        return dict(pending_delivery_rows=2, expired_lease_rows=2, unexpired_lease_rows=1, old_generation_lease_fixture=True,
                    immutable_resolution_rows=2, no_embedded_workers=True)

    def restored_workers(self):
        before_volume = self.volume_files()
        self.spawn_worker()
        self.spawn_worker()
        self.until(lambda: self.sql("SELECT count(*) FROM event_deliveries WHERE state<>'delivered'") == '1', 'all eligible restored deliveries')
        time.sleep(.2)
        assert self.rows("SELECT * FROM event_deliveries WHERE event_id='" + self.unexpired + "' AND consumer='audit-log'") == self.unexpired_row
        assert self.sql("SELECT count(*) FROM audit_events WHERE event_id='" + self.unexpired + "'") == '0'
        # Advance this synthetic deadline only after proving workers honor it.
        self.sql("UPDATE event_deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE event_id='" + self.unexpired + "' AND consumer='audit-log'")
        self.until(lambda: self.sql("SELECT count(*) FROM event_deliveries WHERE state<>'delivered'") == '0', 'restored outstanding deliveries')
        assert int(self.sql("SELECT lease_generation FROM event_deliveries WHERE event_id='" + self.unexpired + "' AND consumer='audit-log'")) > 9
        self.stop_workers()
        assert self.volume_files() == before_volume, 'PG-only worker changed restored GitFS bytes'
        assert not (self.root / 'not-a-directory' / 'impossible').exists()
        assert self.history() == self.original_history
        repo = self.resolved['repo']['id']
        assert self.rows("SELECT * FROM repository_ref_projection WHERE repository_id='" + repo + "' AND ref_name='refs/heads/main'") == self.snapshot
        assert self.sql("SELECT effect FROM event_deliveries WHERE event_id='" + self.stale + "' AND consumer='ref-index'") == 'superseded_generation'
        assert int(self.sql("SELECT lease_generation FROM event_deliveries WHERE event_id='" + self.stale + "' AND consumer='ref-index'")) > 7
        assert int(self.sql("SELECT lease_generation FROM event_deliveries WHERE event_id='" + self.expired + "' AND consumer='audit-log'")) > 4
        for event in self.pending_events:
            assert self.sql("SELECT count(*) FROM audit_events WHERE event_id='" + event['event_id'] + "'") == '1'
            assert self.sql("SELECT count(*) FROM event_deliveries WHERE event_id='" + event['event_id'] + "' AND state='delivered' AND effect='applied'") == '2'
        assert self.sql("SELECT count(*) FROM audit_events WHERE event_id='" + self.candidate + "'") == '0'
        assert self.sql("SELECT count(*) FROM git_operations WHERE id IN ('" + self.resolved['op_id'] + "','" + self.missing['op_id'] + "') AND outcome='unknown'") == '2'
        self.fail_sql("UPDATE git_operations SET outcome='recorded' WHERE id='" + self.resolved['op_id'] + "'", 'immutable')
        return dict(two_pg_only_workers=True, no_volume_access=True, restored_expired_leases_reclaimed=True, unexpired_lease_respected=True,
                    pending_effects_once=True, stale_generation_retired=True, recovery_snapshot_unchanged=True,
                    resolved_unknown_frozen=True)

    def new_push(self):
        self.start()
        clone = self.root / 'worker-restored-clone'
        self.git('clone', self.resolved['remote'], str(clone), token=self.reader)
        self.git('fsck', '--full', '--strict', cwd=clone)
        assert self.git('rev-parse', 'HEAD', cwd=clone).stdout.decode().strip() == self.second
        self.expect('/api/repos', 401, token=self.revoked)
        self.expect(self.unknown_repo['clone_path'] + '/info/refs?service=git-upload-pack', 503, token=self.alice)
        self.expect(self.resolved['repo']['clone_path'] + '/info/refs?service=git-receive-pack', 403, token=self.reader)
        self.git('push', self.resolved['remote'], 'HEAD:after-worker-restore', cwd=self.work, token=self.alice)
        event = self.sql("SELECT event_id FROM outbox_events WHERE repository_id='" + self.resolved['repo']['id'] + "' AND ref_name='refs/heads/after-worker-restore'")
        assert event and self.sql("SELECT count(*) FROM event_deliveries WHERE event_id='" + event + "' AND state='pending'") == '2'
        self.spawn_worker()
        self.spawn_worker()
        self.until(lambda: self.sql("SELECT count(*) FROM event_deliveries WHERE event_id='" + event + "' AND state='delivered'") == '2', 'new generation-2 push delivery')
        self.stop_workers()
        self.stop()
        assert self.sql("SELECT count(*) FROM audit_events WHERE event_id='" + event + "'") == '1'
        assert self.sql("SELECT storage_generation::text || ':' || source_kind FROM repository_ref_projection WHERE event_id='" + event + "'") == '2:push_receipt'
        # A further worker process cannot duplicate an already committed effect.
        before = self.all_rows()
        self.run([self.args.binary, 'worker-once'], env=self.worker_env())
        assert self.all_rows() == before and self.history() == self.original_history
        return dict(authenticated_clone_fsck=True, revoked_read_only_preserved=True, unresolved_repo_blocked=True,
                    real_generation2_push=True, independent_workers_once=True, repeated_worker_no_changes=True)

    def cleanup(self):
        self.stop_workers()
        super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--keep', action='store_true')
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get('ROOTYARD_TEST_DATABASE_URL'):
        parser.error('dedicated synthetic ROOTYARD_TEST_DATABASE_URL required')
    h = RestoredWorkers(args)
    success = False
    try:
        for name, fn in [('backup_pending_and_expired_deliveries', h.pending_source),
                         ('fresh_database_volume_exact_restore', h.restore_exact),
                         ('restored_independent_pg_workers', h.restored_workers),
                         ('post_restore_git_and_worker_effects', h.new_push)]:
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
        report = dict(passed=success, cases=h.results, binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=['Synthetic local PG clusters; no production failover guarantee.',
                                   'Expired and old-generation lease rows are explicit fixtures; native push events are real.',
                                   'PostgreSQL transactional effects only; Redis remains an optional non-durable wake hint.'])
        if args.keep:
            report['retained_directory'] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
