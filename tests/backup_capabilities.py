#!/usr/bin/env python3
"""Native paired restore: durable namespaces/locks/workspaces and revoked authority."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys

from backup import BackupHarness
from web_sessions import BrowserHarness


class CapabilityBackupHarness(BackupHarness):
    request = BrowserHarness.request
    sign_in = BrowserHarness.sign_in
    cookie_header = BrowserHarness.cookie_header

    def populated_restore(self):
        self.setup()
        self.start()
        self.expect('/api/orgs', 201, token=self.alice, method='POST',
                    body={'slug': 'restore-team'})
        org_repo = json.loads(self.expect('/api/repos', 201, token=self.alice, method='POST',
                             body={'owner': 'restore-team', 'name': 'shared'}))
        self.expect('/api/orgs/restore-team/members/bob', (200, 201), token=self.alice,
                    method='PUT', body={'role': 'write'})
        self.expect('/api/repos/restore-team/shared', 200, token=self.bob)
        lock_path = '/git/alice/demo.git/info/lfs/locks'
        lock = json.loads(self.expect(lock_path, 201, token=self.alice, method='POST',
                          body={'path': 'docs/preserved.bin'},
                          content_type='application/vnd.git-lfs+json'))['lock']
        lfs_bytes = b'paired restore LFS payload\n' * 4096
        lfs_oid = hashlib.sha256(lfs_bytes).hexdigest()
        lfs_path = f'/git/alice/demo.git/info/lfs/objects/{lfs_oid}/{len(lfs_bytes)}'
        self.expect(lfs_path, 200, token=self.alice, method='PUT', body=lfs_bytes,
                    content_type='application/octet-stream')
        workspace = json.loads(self.expect('/api/workspaces', 201, token=self.alice, method='POST',
                               body={'owner': 'alice', 'repository': 'demo',
                                     'agent_id': 'restore-agent', 'base_oid': self.second},
                               extra_headers={'Idempotency-Key': 'restore-workspace'}))
        wid = workspace['id']
        file_path = f'/api/workspaces/{wid}/files?path=hello.txt'
        payload = {'content_base64': base64.b64encode(b'preserved workspace\n').decode(),
                   'expected_entry_version': 0, 'expected_workspace_revision': 0,
                   'lease_epoch': workspace['lease_epoch']}
        self.expect(file_path, 200, token=self.alice, method='PUT', body=payload,
                    extra_headers={'Idempotency-Key': 'restore-edit'})
        cookies = self.sign_in()
        headers = {'Cookie': self.cookie_header(cookies)}
        assert self.request('/web/repos', headers=headers)[0] == 200
        before_authority = self.query(self.db, 'SELECT incarnation FROM cluster_authority')
        self.stop()
        remote_lfs = getattr(self.args, 'remote_lfs', False)
        if remote_lfs:
            assert self.env.get('ROOTYARD_OBJECT_STORE_ENDPOINT'), 'real remote object store required'
            cached = self.root / 'data/lfs' / self.repo['id'] / lfs_oid
            cached.unlink()
            assert not cached.exists()
        self.backup_command()
        manifest = json.loads((self.backup / 'manifest.json').read_text())
        assert any(obj['oid'] == lfs_oid and obj['size'] == len(lfs_bytes)
                   for obj in manifest['lfs_objects'])
        if remote_lfs:
            assert cached.read_bytes() == lfs_bytes
            self.env.pop('ROOTYARD_OBJECT_STORE_ENDPOINT')
        self.cli('backup-verify', str(self.backup))
        self.restore_command()
        assert self.query(self.target_db, 'SELECT incarnation FROM cluster_authority') != before_authority
        assert self.query(self.target_db, 'SELECT count(*) FROM web_sessions WHERE NOT revoked') == '0'
        assert self.query(self.target_db, "SELECT count(*) FROM tokens WHERE kind='browser' AND NOT revoked") == '0'
        assert int(self.query(self.target_db, f"SELECT lease_epoch FROM workspaces WHERE id='{wid}'")) == workspace['lease_epoch'] + 1
        self.db = self.target_db
        self.env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        self.start()
        assert self.request('/web/repos', headers=headers)[0] == 401
        self.expect('/api/repos/restore-team/shared', 200, token=self.bob)
        locks = json.loads(self.expect(lock_path, 200, token=self.alice))['locks']
        assert any(item['id'] == lock['id'] and item['path'] == 'docs/preserved.bin' for item in locks)
        assert self.expect(lfs_path, 200, token=self.alice) == lfs_bytes
        self.expect(lfs_path, 404, token=self.bob)
        restored = json.loads(self.expect(file_path, 200, token=self.alice))
        assert base64.b64decode(restored['content_base64']) == b'preserved workspace\n'
        payload.update(expected_entry_version=1, expected_workspace_revision=1)
        self.expect(file_path, 409, token=self.alice, method='PUT', body=payload,
                    extra_headers={'Idempotency-Key': 'stale-restored-lease'})
        lease = json.loads(self.expect(f'/api/workspaces/{wid}/lease', 200, token=self.alice,
                           method='POST', body={'expected_lease_epoch': workspace['lease_epoch'] + 1}))
        payload['lease_epoch'] = lease['lease_epoch']
        self.expect(file_path, 200, token=self.alice, method='PUT', body=payload,
                    extra_headers={'Idempotency-Key': 'renewed-restored-lease'})
        clone = self.root / 'capability-restored-clone'
        self.git('clone', self.remote, str(clone), token=self.alice)
        self.git('fsck', '--full', '--strict', cwd=clone)
        assert (clone / 'hello.txt').read_text() == 'second\n'
        return {'fresh_database_and_volume': True, 'organization_inherited_access': True,
                'lfs_lock_identity_preserved': True, 'lfs_bytes_preserved': True, 'workspace_bytes_preserved': True,
                'old_workspace_lease_rejected': True, 'renewed_lease_accepted': True,
                'browser_session_revoked': True, 'cluster_authority_rotated': True,
                'stock_git_clone_fsck': True, 'remote_lfs_hydrated_without_target_endpoint': remote_lfs,
                'backup_manifest_format': manifest['format'],
                'backup_manifest_schema_versions': manifest['schema_versions'],
                'backup_schema_contract_sha256': manifest['schema_contract_sha256'],
                'restored_schema_versions_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--keep', action='store_true')
    parser.add_argument('--remote-lfs', action='store_true')
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get('ROOTYARD_TEST_DATABASE_URL'):
        parser.error('dedicated synthetic ROOTYARD_TEST_DATABASE_URL required')
    harness = CapabilityBackupHarness(args)
    passed = False
    try:
        harness.case('populated_capability_restore', harness.populated_restore)
        passed = True
    except Exception as exc:
        print(harness.redact(exc), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as exc:
            print(harness.redact(exc), file=sys.stderr)
            passed = False
    report = {'passed': passed, 'cases': harness.results,
              'binary_sha256': hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
              'limitations': ['Loopback service and PostgreSQL; no hardware failure guarantee.']}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
