#!/usr/bin/env python3
"""Paired source-pin backup/restore on fresh disposable databases and volumes.

Requires CREATEDB on dedicated synthetic ROOTYARD_TEST_DATABASE_URL. Set
ROOTYARD_RESTORE_TEST_DATABASE_URL to a second disposable PG server. No real
resources, credentials, remote writes, or production data may be used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import uuid

from backup_recovery import BackupRecoveryHarness
from ci_mirror import MirrorHarness


class BackupCiPinsHarness(BackupRecoveryHarness):
    mirror_http = MirrorHarness.mirror_http
    mirror_expect = MirrorHarness.mirror_expect
    start_mirror = MirrorHarness.start_mirror
    stop_mirror = MirrorHarness.stop_mirror
    path = MirrorHarness.path
    advertise = MirrorHarness.advertise
    sync = MirrorHarness.sync
    clone_at = MirrorHarness.clone_at

    def __init__(self, args):
        super().__init__(args)
        self.mirror_proc = self.mirror_log = None
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.mirror_base = f'http://127.0.0.1:{port}'
        self.mirror_env = self.env.copy()
        self.mirror_env.update(ROOTYARD_BIND=f'127.0.0.1:{port}',
                               ROOTYARD_DATA_DIR=str(self.root / 'mirror-data'),
                               ROOTYARD_PRIMARY_URL=self.base)

    def pin(self, job, generation=1, code=200, token=None, oid=None):
        value = self.expect('/api/repos/alice/demo/ci-pins', code,
                            token=token or self.alice, method='POST',
                            body=dict(job_id=job, target_oid=oid or self.target_oid,
                                      storage_generation=generation))
        return json.loads(value) if code == 200 else value

    def prepare(self, generation=1, code=200, token=None):
        value = self.mirror_expect('/api/repos/alice/demo/mirror-prepare', code,
                                   token=token or self.reader, method='POST',
                                   body=dict(target_oid=self.target_oid,
                                             storage_generation=generation))
        return json.loads(value) if code == 200 else value

    def metadata(self):
        root = Path(self.env['ROOTYARD_DATA_DIR']) / 'ci-pins'
        return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}

    def assert_catalog(self, filename):
        schema = Path(__file__).resolve().parents[1] / 'schema'
        query = (schema / '007_catalog.sql').read_text()
        catalog = json.loads(self.run(['psql', self.db, '-X', '-qAt', '-v',
                                       'ON_ERROR_STOP=1', '-c',
                                       'SET search_path=pg_catalog; ' + query]).stdout)
        assert catalog == json.loads((schema / filename).read_text()), 'Schema007 catalog changed'

    def native_ref(self, name):
        value = self.git('--no-replace-objects', '--git-dir=' + str(self.bare),
                         'rev-parse', '--verify', name, check=False)
        return value.stdout.decode().strip() if value.returncode == 0 else None

    def source_retention(self):
        super().setup()
        self.start()
        self.job, self.pending_job = str(uuid.uuid4()), str(uuid.uuid4())
        self.git('checkout', '-b', 'source-only', cwd=self.work)
        (self.work / 'ci-only.txt').write_text('retained before any mirror synchronization\n')
        self.git('add', 'ci-only.txt', cwd=self.work)
        self.git('commit', '-m', 'unique CI source target', cwd=self.work)
        self.target_oid = self.git('rev-parse', 'HEAD', cwd=self.work).stdout.decode().strip()
        self.git('push', 'origin', 'HEAD:source-only', cwd=self.work, token=self.alice)
        self.git('checkout', 'main', cwd=self.work)
        self.plan = self.pin(self.job)
        expected = dict(version=1, job_id=self.job, owner_id=self.alice['user_id'],
                        repository_id=self.repo['id'], storage_generation=1,
                        object_format='sha1', target_oid=self.target_oid,
                        retention_ref='refs/rootyard-ci/jobs/' + self.job, state='pinned')
        assert self.plan == expected
        assert self.pin(self.job) == self.plan
        self.pending_plan = self.pin(self.pending_job)
        self.git('push', 'origin', ':source-only', cwd=self.work, token=self.alice)
        self.stop()
        assert not (self.root / 'mirror-data').exists(), 'Mirror used before source retention'
        assert self.native_ref('refs/heads/source-only') is None
        ordinary = self.git('--no-replace-objects', '--git-dir=' + str(self.bare),
                            'rev-list', '--branches', '--tags').stdout.decode().splitlines()
        assert self.target_oid not in ordinary, 'Target still reachable from an ordinary source ref'
        self.git('--git-dir=' + str(self.bare), 'reflog', 'expire', '--expire=now', '--all')
        self.git('--git-dir=' + str(self.bare), 'gc', '--prune=now')
        assert self.native_ref(self.plan['retention_ref']) == self.target_oid
        self.git('--no-replace-objects', '--git-dir=' + str(self.bare), 'fsck', '--full', '--strict')
        self.git('--no-replace-objects', '--git-dir=' + str(self.bare), 'cat-file', '-e', self.target_oid + '^{commit}')
        # Explicit offline interruption fixture: actual root and observed journal
        # result exist, but final source receipt publication is absent. This is
        # not a claim that a process was killed at precisely this boundary.
        pending = Path(self.env['ROOTYARD_DATA_DIR']) / 'ci-pins' / self.repo['id'] / (self.pending_job + '.pinned.json')
        self.pending_receipt = pending.read_bytes()
        pending.unlink()
        self.drain()
        self.source_metadata = self.metadata()
        assert len(self.source_metadata) == 3
        self.assert_catalog('007_catalog.json')
        self.source_rows = self.all_rows()
        assert len(self.source_rows) == 15
        self.pin_operations = [row for row in self.source_rows['git_operations']
                               if row['evidence'].get('kind') == 'observed_immutable_ci_root']
        assert len(self.pin_operations) == 2
        assert all(row['outcome'] == 'recorded' for row in self.pin_operations)
        assert self.sql("SELECT count(*) FROM git_operations WHERE outcome='unknown'") == '1'
        self.marker = (Path(self.env['ROOTYARD_DATA_DIR']) / '.volume-id').read_bytes()
        self.backup_result = json.loads(self.backup_command().stdout)
        self.cli('backup-verify', str(self.backup))
        manifest = json.loads((self.backup / 'manifest.json').read_text())
        assert manifest['format'] == 4 and manifest['schema_versions'] == [1, 2, 3, 6, 7]
        assert all((self.backup / 'volume' / 'ci-pins' / name).read_bytes() == data
                   for name, data in self.source_metadata.items())
        return dict(root_created_before_source_delete_and_first_mirror=True,
                    unreachable_from_ordinary_refs_survives_gc=True,
                    exact_intent_and_receipt_backed_up=True, receipt_absence_fixture=True,
                    generic_unknown_preserved=True, full_public_tables=15, backup_format=4)

    def corrupt_backups_rejected(self):
        relative = Path('volume/ci-pins') / self.repo['id'] / (self.job + '.pinned.json')
        for name, remove in [('modified-pin-receipt', False), ('missing-pin-receipt', True)]:
            damaged = self.root / name
            shutil.copytree(self.backup, damaged)
            path = damaged / relative
            if remove:
                path.unlink()
            else:
                value = json.loads(path.read_text())
                value['target_oid'] = self.second
                path.write_text(json.dumps(value))
            try:
                assert self.run([self.args.binary, 'backup-verify', str(damaged)], check=False).returncode != 0
                assert self.restore_command(source=damaged, check=False).returncode != 0
                assert not self.target.exists()
                assert self.query(self.target_db, "SELECT count(*) FROM pg_tables WHERE schemaname='public'") == '0'
            finally:
                shutil.rmtree(damaged)
        return dict(changed_or_missing_inventory_receipt_rejected_before_restore=True)

    def restored_source_and_first_mirror(self):
        result = json.loads(self.restore_command().stdout)
        self.db = self.target_db
        self.env.update(DATABASE_URL=self.db, ROOTYARD_DATA_DIR=str(self.target))
        self.mirror_env['DATABASE_URL'] = self.db
        self.bare = self.target / 'repos' / (self.repo['id'] + '.git')
        assert self.all_rows() == self.source_rows
        self.assert_catalog('007_restored_catalog.json')
        assert self.metadata() == self.source_metadata
        assert (self.target / '.volume-id').read_bytes() == self.marker
        for plan in (self.plan, self.pending_plan):
            assert self.native_ref(plan['retention_ref']) == self.target_oid
        self.start()
        assert self.pin(self.job) == self.plan
        before = self.rows('SELECT * FROM git_operations ORDER BY id')
        assert self.pin(self.pending_job) == self.pending_plan
        assert self.rows('SELECT * FROM git_operations ORDER BY id') == before
        pending = self.target / 'ci-pins' / self.repo['id'] / (self.pending_job + '.pinned.json')
        assert pending.read_bytes() == self.pending_receipt
        self.complete_metadata = self.metadata()
        for token, code in [(self.reader, 403), (self.bob, 404)]:
            self.pin(self.job, token=token, code=code)
        self.pin(self.job, oid=self.second, code=409)
        assert self.metadata() == self.complete_metadata
        self.expect(self.unknown_repo['clone_path'] + '/info/refs?service=git-upload-pack', 503, token=self.alice)
        self.start_mirror()
        self.prepare(code=409)
        self.sync()
        ready = self.prepare()
        assert ready['target_oid'] == self.target_oid and ready['storage_generation'] == 1
        assert ready['repository_id'] == self.repo['id'] and ready['snapshot']
        assert ready['clone_path'] == self.path(self.target_oid)
        clone = self.clone_at(self.target_oid, 'restored-first-ever-mirror-clone')
        assert (clone / 'ci-only.txt').read_text() == 'retained before any mirror synchronization\n'
        self.prepare(token=self.bob, code=404)
        return dict(all_15_tables_exact_before_startup=True, volume_metadata_and_roots_exact=True,
                    pending_receipt_retry_without_new_operation=True,
                    private_tenant_and_read_only_enforced=True,
                    first_mirror_sync_after_restore_and_source_deletion=True,
                    authenticated_exact_target_clone_fsck=True,
                    separate_pg_server=self.admin != self.restore_admin,
                    restore_seconds=result['elapsed_seconds'])

    def tampered_live_metadata(self):
        self.stop()
        path = self.target / 'ci-pins' / self.repo['id'] / (self.job + '.pinned.json')
        original = path.read_bytes()
        changed = json.loads(original)
        changed['target_oid'] = self.second
        altered = json.dumps(changed).encode()
        try:
            path.write_bytes(altered)
            self.start()
            self.pin(self.job, code=503)
            assert path.read_bytes() == altered, 'Corrupt receipt was silently overwritten'
            assert self.native_ref(self.plan['retention_ref']) == self.target_oid
        finally:
            self.stop()
            path.write_bytes(original)
        self.start()
        assert self.pin(self.job) == self.plan
        self.stop()
        return dict(tampered_receipt_fails_closed_without_rewriting=True)

    def recovery_generation_fencing(self):
        repo = self.repo['id']
        journal_root = self.target / 'journal' / repo
        sequence = int((journal_root / 'sequence').read_text()) + 1
        op_id = str(uuid.uuid4())
        operation = journal_root / (f'{sequence:020}-' + op_id)
        operation.mkdir(mode=0o700)
        (journal_root / 'sequence').write_text(str(sequence))
        # Generic receive-pack uncertainty must remain unknown despite observed
        # CI roots. It requires the normal explicit audit-gap resolution.
        metadata = dict(id=op_id, repository_id=repo, actor_id=self.alice['user_id'],
                        actor_name='alice', token_id=self.alice['token_id'],
                        sequence=sequence, storage_generation=1)
        (operation / 'operation.json').write_text(json.dumps(metadata))
        self.cli('reconcile')
        original = self.rows("SELECT * FROM git_operations WHERE id='" + op_id + "'")
        assert len(original) == 1 and original[0]['outcome'] == 'unknown'
        fixture = dict(repo=self.repo, inspection=json.loads(self.cli('inspect-recovery', repo)))
        assert fixture['inspection']['fsck'] == 'passed'
        result = self.resolve(fixture)
        assert result['new_generation'] == 2 and not result['already_applied']
        assert self.rows("SELECT * FROM git_operations WHERE id='" + op_id + "'") == original
        assert self.sql("SELECT count(*) FROM outbox_events WHERE operation_id='" + op_id + "'") == '0'
        self.fail_sql("UPDATE git_operations SET evidence='{}' WHERE id='" + op_id + "'", 'immutable')
        self.fail_sql("DELETE FROM operation_resolutions WHERE operation_id='" + op_id + "'", 'immutable')
        assert self.metadata() == self.complete_metadata
        self.start()
        self.pin(self.job, generation=1, code=409)
        self.pin(self.job, generation=2, code=409)
        self.prepare(generation=1, code=409)
        self.prepare(generation=2, code=409)
        fresh_job = str(uuid.uuid4())
        fresh = self.pin(fresh_job, generation=2)
        assert fresh['target_oid'] == self.target_oid and fresh['storage_generation'] == 2
        assert all(self.metadata()[name] == data for name, data in self.complete_metadata.items())
        self.sync()
        self.prepare(generation=1, code=409)
        assert self.prepare(generation=2)['target_oid'] == self.target_oid
        self.clone_at(self.target_oid, 'new-generation-clone')
        self.git('push', 'origin', 'HEAD:after-ci-restore', cwd=self.work, token=self.alice)
        self.drain()
        assert self.sql("SELECT storage_generation FROM git_operations WHERE repository_id='" + repo + "' ORDER BY sequence DESC LIMIT 1") == '2'
        assert self.sql("SELECT count(*) FROM audit_events a JOIN outbox_events e USING(event_id) WHERE e.repository_id='" + repo + "' AND e.ref_name='refs/heads/after-ci-restore'") == '1'
        current_ops = self.rows("SELECT * FROM git_operations WHERE evidence->>'kind'='observed_immutable_ci_root' ORDER BY id")
        assert all(row in current_ops for row in self.pin_operations), 'Old observed evidence mutated'
        self.stop_mirror()
        self.stop()
        return dict(generic_unknown_not_inferred_from_native_refs=True,
                    explicit_audit_gap_resolution_preserves_immutable_evidence=True,
                    old_job_rejected_with_old_and_new_generation=True,
                    new_job_same_target_current_generation=True,
                    stale_plan_never_ready=True, ordinary_push_and_audit_after_restore=True)

    def cleanup(self):
        self.stop_mirror()
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
    h = BackupCiPinsHarness(args)
    success = False
    try:
        for name in ('source_retention', 'corrupt_backups_rejected',
                     'restored_source_and_first_mirror', 'tampered_live_metadata',
                     'recovery_generation_fencing'):
            h.case(name, getattr(h, name))
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
                      test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      limitations=['Synthetic loopback paired restore, not production RPO/RTO or power-loss proof.',
                                   'Missing receipt and generic unfinished journal are explicit offline crash-state fixtures.',
                                   'Mirror snapshot data is rebuilt; primary source intent and native refs remain authority.'])
        if args.keep:
            report['retained_directory'] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
