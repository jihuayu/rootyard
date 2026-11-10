#!/usr/bin/env python3
"""Current-format grant/tombstone backup and real format4/schema007 compatibility.

Only disposable synthetic PostgreSQL. --legacy-binary must be a trusted local
schema007/format4 executable; it creates a real old archive without rewriting
its manifest or bypassing the actual restored-catalog check.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback
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


class BackupCaseFailure(Exception):
    """A failure already formatted and redacted by the harness that owns the case."""


class CheckoutBackupHarness(BackupCiPinsHarness):
    rpc = JobCheckoutHarness.rpc

    def __init__(self, args):
        super().__init__(args)
        self.audience = str(uuid.uuid4())
        self.env['ROOTYARD_CI_MIRROR_AUDIENCE'] = self.audience
        self.mirror_env['ROOTYARD_CI_MIRROR_AUDIENCE'] = self.audience
        self.step_name = 'startup'
        # Diagnostics only: the last process's program label, outcome and
        # captured stderr. Never argv, str(exception) or cmd: Git argv and
        # TimeoutExpired/CalledProcessError strings can carry Basic credentials.
        self.last_process = None

    def mark(self, name):
        """Name the phase being exercised so a later bare assertion is locatable."""
        self.step_name = name

    def register_token(self, username, token):
        """Register raw and Git Basic forms so diagnostics stay secret-free."""
        self.secrets.extend([token, base64.b64encode((username + ':' + token).encode()).decode()])

    def run(self, argv, **kwargs):
        try:
            process = super().run(argv, **kwargs)
        except Exception as error:
            self._record_process_failure(argv, error)
            raise
        self.last_process = dict(program=Path(str(argv[0])).name, returncode=process.returncode,
                                 error_type=None, stderr=process.stderr.decode(errors='replace')[-4000:])
        return process

    def _record_process_failure(self, argv, error):
        stderr = getattr(error, 'stderr', None)
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors='replace')
        self.last_process = dict(program=Path(str(argv[0])).name, returncode=None,
                                 error_type=type(error).__name__, stderr=(stderr or '')[-4000:])

    @staticmethod
    def _safe_error_text(error):
        """Describe an exception without ever rendering argv/cmd.

        TimeoutExpired and CalledProcessError carry the full command line in
        their string form; Git's extraHeader argument is a Basic credential.
        """
        if isinstance(error, subprocess.TimeoutExpired):
            return f'TimeoutExpired: command exceeded {error.timeout}s'
        if isinstance(error, subprocess.CalledProcessError):
            return f'CalledProcessError: command exited {error.returncode}'
        return str(error).strip()

    def failure_detail(self, error):
        """Redacted failure report: message, step, exact source line, native stderr.

        Tracebacks are formatted without local variables so credentials held in
        fixture locals cannot leak into CI logs; the result still passes through
        Harness.redact for tokens and database URLs.
        """
        message = self._safe_error_text(error) or f'{type(error).__name__} raised without a message (bare assert?)'
        frames = traceback.extract_tb(error.__traceback__)
        lines = [f'{type(error).__name__}: {message}', f'step: {self.step_name}']
        for frame in frames[-4:]:
            source = Path(frame.filename)
            try:
                shown = str(source.resolve().relative_to(Path(__file__).resolve().parents[1]))
            except ValueError:
                shown = str(source)
            lines.append(f'at {shown}:{frame.lineno} in {frame.name}: {(frame.line or "<unavailable>").strip()}')
        process = self.last_process
        if process:
            outcome = (f"exit={process['returncode']}" if process.get('returncode') is not None
                       else f"error={process.get('error_type')}")
            lines.append('last process: {program} {outcome} stderr={stderr!r}'.format(
                program=process.get('program'), outcome=outcome, stderr=process.get('stderr')))
        log = self.root / 'server.log'
        if log.exists():
            lines.append('server.log tail: ' + log.read_text(errors='replace')[-4000:])
        return self.redact('\n'.join(lines))

    def grants(self):
        self.mark('source_checkout_grant_and_immutable_rows')
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
        self.register_token('alice', self.raw)
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
        self.mark('archive_manifest_and_legacy_opt_in_rejection')
        self.backup_command()
        self.cli('backup-verify', str(self.backup))
        manifest = json.loads((self.backup / 'manifest.json').read_text())
        assert manifest['format'] == CURRENT_BACKUP_FORMAT, (
            f"backup manifest format {manifest['format']} != expected current format "
            f"{CURRENT_BACKUP_FORMAT} (tests/schema_baseline.py CURRENT_BACKUP_FORMAT is stale?)")
        assert manifest['schema_versions'] == SCHEMA_VERSIONS, (
            f"backup manifest schema_versions {manifest['schema_versions']} != migrations "
            f"{SCHEMA_VERSIONS}")
        assert self.raw.encode() not in (self.backup / 'metadata.dump').read_bytes(), (
            "raw checkout credential was persisted into metadata.dump")
        legacy_env = self.env.copy()
        legacy_env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        legacy = self.run([self.args.binary, 'restore', str(self.backup), '--isolated', '--trust-backup',
                           '--allow-legacy-schema007'], env=legacy_env, check=False)
        assert legacy.returncode != 0, (
            f"current format {manifest['format']} archive restored under --allow-legacy-schema007 "
            f"(exit 0); expected explicit rejection, stderr={legacy.stderr.decode(errors='replace')[-2000:]!r}")
        assert not self.target.exists(), (
            f"rejected legacy opt-in still created target {self.target}")
        assert not (self.root / '.restored-data.rootyard-restoring').exists(), (
            "rejected legacy opt-in left a restore guard marker")
        # Cancel after the backup boundary: restoring the earlier snapshot must
        # not resurrect this credential even though cancelled was false there.
        self.mark('revocation_after_backup_boundary_and_restore')
        self.sql("UPDATE ci_checkout_jobs SET cancelled=true,revoked=true WHERE job_id='%s'" % self.job)
        self.restore_command()
        restored = json.loads(self.query(self.target_db, "SELECT json_agg(t ORDER BY job_id) FROM ci_checkout_jobs t"))
        expected = copy.deepcopy(self.source_rows['ci_checkout_jobs'])
        for row in expected:
            if row['plan'] is not None:
                row['revoked'] = True
        actual_rows = sorted(restored or [], key=lambda r: r['job_id'])
        expected_rows = sorted(expected, key=lambda r: r['job_id'])
        assert actual_rows == expected_rows, (
            f"restored ci_checkout_jobs rows differ (revocation of plan-bearing grants expected); "
            f"expected={expected_rows!r} actual={actual_rows!r}")
        unrevoked = self.query(self.target_db, "SELECT count(*) FROM ci_checkout_jobs WHERE plan IS NOT NULL AND NOT revoked")
        assert unrevoked == '0', f"restore left {unrevoked} plan-bearing grant(s) unrevoked"
        tombstones = self.query(self.target_db, "SELECT count(*) FROM ci_checkout_jobs WHERE plan IS NULL AND cancelled")
        assert tombstones == '1', f"restore lost the permanent tombstone; plan-less cancelled rows={tombstones}"
        assert not (self.target.parent / ('.' + self.target.name + '.rootyard-restoring')).exists(), (
            "successful restore left its guard marker behind")
        self.mark('restored_owner_and_revoked_credential_access')
        self.db = self.target_db
        self.env.update(DATABASE_URL=self.db, ROOTYARD_DATA_DIR=str(self.target))
        self.mirror_env['DATABASE_URL'] = self.db
        self.start()
        self.start_mirror()
        self.sync(token=self.alice)
        self.mirror_expect(self.advertise(self.second), 200, token=self.alice)
        owner_clone = self.root / 'restored-owner-clone'
        self.git('clone', self.mirror_base + self.path(self.second), str(owner_clone), token=self.alice)
        head = self.git('rev-parse', 'HEAD', cwd=owner_clone).stdout.decode().strip()
        assert head == self.second, f"restored owner clone HEAD {head} != pinned target {self.second}"
        self.git('fsck', '--full', '--strict', cwd=owner_clone)
        assert self.plan['expires_unix'] > int(time.time()), 'Revocation test credential expired'
        self.mirror_expect(self.advertise(self.second), 401, token=self.job_token)
        status, body = self.rpc(self.second, self.job_token, self.second)
        assert status == 401 and b'PACK' not in body, (
            f"revoked job credential still accepted: status={status} pack_bytes={b'PACK' in body}")
        self.stop_mirror()
        self.stop()
        return dict(current_format=CURRENT_BACKUP_FORMAT, immutable_grants=True, permanent_tombstones=True,
                    backup_then_cancel_then_restore_revokes_grant=True, raw_credential_not_persisted=True, live_old_bearer_denied_discovery_and_rpc=True,
                    ordinary_owner_restored_target_access=True, genuine_native_pin_and_issuance=True)


def legacy_restore(args):
    old_args = copy.copy(args)
    old_args.binary = str(Path(args.legacy_binary).resolve())
    h = CheckoutBackupHarness(old_args)

    def run_case():
        h.mark('legacy_schema007_source_archive')
        h.setup()
        h.backup_command()
        manifest = json.loads((h.backup / 'manifest.json').read_text())
        assert manifest['format'] == 4 and manifest['schema_versions'] == [1, 2, 3, 6, 7], (
            f"legacy schema007 archive manifest mismatch: format={manifest['format']} "
            f"schema_versions={manifest['schema_versions']}")
        assert manifest['binary_sha256'] != hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(), (
            "legacy archive claimed to be produced by the current binary")
        h.args.binary = args.binary
        h.mark('legacy_archive_verification_and_opt_in')
        verified = h.run([args.binary, 'backup-verify', str(h.backup)], check=False)
        assert verified.returncode == 0, (
            f"Real historical archive verification failed: exit={verified.returncode} "
            f"stderr={verified.stderr.decode(errors='replace')[-2000:]!r}")
        # Compatibility is explicit and rejection happens before target writes.
        rejected = h.restore_command(check=False)
        assert rejected.returncode != 0, (
            "format4/schema007 archive restored without --allow-legacy-schema007; "
            f"stderr={rejected.stderr.decode(errors='replace')[-2000:]!r}")
        assert not h.target.exists(), "implicit legacy rejection still created the restore target"
        env = h.env.copy()
        env.update(DATABASE_URL=h.target_db, ROOTYARD_DATA_DIR=str(h.target))
        h.run([args.binary, 'restore', str(h.backup), '--isolated', '--trust-backup', '--allow-legacy-schema007'], env=env)
        versions = h.query(h.target_db, "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations")
        assert versions == '1,2,3,6,7', f"explicit legacy restore installed schema versions {versions}"
        h.mark('hybrid_manifest_mismatched_dump_rejected')
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
        hybrid_verified = h.run([args.binary, 'backup-verify', str(hybrid)], check=False)
        assert hybrid_verified.returncode == 0, (
            f"Synthetic hybrid manifest verification failed: exit={hybrid_verified.returncode} "
            f"stderr={hybrid_verified.stderr.decode(errors='replace')[-2000:]!r}")
        hybrid_restore = h.restore_command(source=hybrid, target=hybrid_target, db=hybrid_db, check=False)
        assert hybrid_restore.returncode != 0, (
            "current-format manifest around a schema007 dump was accepted; the post-restore catalog "
            f"check did not reject it, stderr={hybrid_restore.stderr.decode(errors='replace')[-2000:]!r}")
        assert not hybrid_target.exists(), "rejected hybrid archive left a restored target directory"
        assert (h.root / '.hybrid-target.rootyard-restoring').exists(), (
            "rejected hybrid archive did not retain its restore guard marker")
        h.mark('current_schema_upgrade_from_legacy')
        h.run([args.binary, 'migrate'], env=env)
        upgraded = h.query(h.target_db, "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations")
        assert upgraded == SCHEMA_VERSION_CSV, (
            f"post-legacy migrate installed {upgraded} != {SCHEMA_VERSION_CSV}")
        jobs = h.query(h.target_db, 'SELECT count(*) FROM ci_checkout_jobs')
        assert jobs == '0', f"legacy upgrade populated restored checkout authority with {jobs} row(s)"
        return dict(real_historical_binary_archive=True, genuine_archive_manifest_unchanged=True,
                    explicit_legacy_opt_in_required=True, schema007_verified_before_upgrade=True,
                    current_schema_upgrade_empty_authority=True, mismatched_dump_rejected_guard_retained=True)

    detail = cleanup_detail = None
    outcome = None
    try:
        outcome = run_case()
    except BackupCaseFailure:
        raise
    except Exception as error:
        # This case owns its own harness: format and redact with it before its
        # fixture directories (and server.log) are removed.
        detail = h.failure_detail(error)
    try:
        h.cleanup()
    except Exception as error:
        cleanup_detail = 'legacy case cleanup failed: ' + h.redact(error)
    if detail is not None:
        # A cleanup failure is appended, never substituted for the real failure.
        raise BackupCaseFailure(detail if cleanup_detail is None else detail + '\n' + cleanup_detail) from None
    if cleanup_detail is not None:
        raise BackupCaseFailure(cleanup_detail)
    return outcome


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
    failure = cleanup_failure = None
    try:
        h.case('current_checkout_authority_restore', h.grants)
        h.case('format4_real_legacy_restore_then_upgrade', lambda: legacy_restore(args))
        success = True
    except BackupCaseFailure as error:
        # Already redacted against the harness that owned the case; the outer
        # harness's step/last-process state belongs to a different case.
        failure = str(error)
        if h.results and h.results[-1].get('status') == 'failed':
            h.results[-1]['error'] = failure
    except Exception as error:
        failure = h.failure_detail(error)
        if h.results and h.results[-1].get('status') == 'failed':
            h.results[-1]['error'] = failure
            h.results[-1]['step'] = h.step_name
    finally:
        try:
            h.cleanup()
        except Exception as error:
            # Cleanup is recorded independently: it must neither mask the real
            # failure nor suppress the JSON report below.
            cleanup_failure = h.redact(error)
            success = False
    if cleanup_failure is not None:
        h.results.append(dict(name='cleanup', status='failed', error='cleanup failed: ' + cleanup_failure))
        if failure is None:
            failure = 'cleanup failed: ' + cleanup_failure
    if failure is not None:
        print(failure, file=sys.stderr)
    report = dict(passed=success, cases=h.results,
                  binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                  legacy_binary_sha256=hashlib.sha256(Path(args.legacy_binary).read_bytes()).hexdigest(),
                  limitations=['Synthetic loopback backup/restore does not establish a production RPO/RTO.',
                               'Restoring permanently revokes all issued checkout credentials; native pins and plans remain.'])
    if failure is not None:
        report['failure'] = failure
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
