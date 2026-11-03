#!/usr/bin/env python3
"""Standalone synthetic Pando lab acceptance tests, with an owned ephemeral PG.

Never connects to DATABASE_URL inherited from the caller. Only the fresh cluster
created under this run's directory is used. No third-party Python dependencies.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import traceback
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Lab:
    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix='rootyard-pando-lab-'))
        self.env = os.environ.copy()
        for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'PGOPTIONS'):
            self.env.pop(key, None)
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_TERMINAL_PROMPT='0', LC_ALL='C', NO_PROXY='127.0.0.1,localhost',
                        no_proxy='127.0.0.1,localhost', GIT_AUTHOR_DATE='2026-11-03T00:00:00Z',
                        GIT_COMMITTER_DATE='2026-11-03T00:00:00Z')
        self.pgport, self.port = free_port(), free_port()
        while self.port == self.pgport:
            self.port = free_port()
        self.db = f'postgresql://pando_lab@127.0.0.1:{self.pgport}/postgres'
        self.env.update(DATABASE_URL=self.db, ROOTYARD_TEST_DATABASE_URL=self.db)
        self.proc = None
        self.pg_started = False
        self.commands = []
        self.results = {'passed': False, 'checks': {}, 'limits': [
            'Synthetic repositories and loopback-only ephemeral PostgreSQL.',
            'Local immutable packs are not an S3/R2 service or durability certification.',
            'Fault injection is process-level; no HA, failover, power-loss or committed-object GC certification.'
        ]}
        self.binary = str(Path(args.binary).resolve())

    def run(self, argv, check=True, cwd=None, data=None, env=None, timeout=90):
        p = subprocess.run([str(x) for x in argv], cwd=cwd, env=env or self.env,
                           input=data, capture_output=True, text=True, timeout=timeout)
        self.commands.append({'argv': [str(x) for x in argv], 'cwd': str(cwd or ''),
                              'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
        if check and p.returncode:
            raise AssertionError(f'{argv[0]} exited {p.returncode}: {p.stderr[-5000:]}')
        return p

    def sql(self, query):
        return self.run(['psql', self.db, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', query]).stdout.strip()

    def rows(self, query):
        return json.loads(self.sql("SELECT COALESCE(json_agg(x),'[]'::json) FROM (" + query + ') x'))

    def start_pg(self):
        data = self.root / 'postgres'
        command = ['initdb', '-D', data, '-U', 'pando_lab', '-A', 'trust', '--no-locale', '--encoding=UTF8']
        if self.args.pg_share:
            command += ['-L', self.args.pg_share]
        self.run(command)
        # A bind collision fails startup; never fall back to an existing database.
        self.run(['pg_ctl', '-D', data, '-l', self.root / 'postgres.log', '-o',
                  f"-h 127.0.0.1 -p {self.pgport} -k '' -c fsync=on -c synchronous_commit=on -c full_page_writes=on", '-w', 'start'])
        self.pg_started = True
        self.results['versions'] = {'postgres': self.sql('SELECT version()'),
                                    'git': self.run(['git', '--version']).stdout.strip(),
                                    'settings': self.rows("SELECT name,setting FROM pg_settings WHERE name IN ('fsync','synchronous_commit','full_page_writes') ORDER BY name")}

    def cleanup(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        if self.pg_started:
            self.run(['pg_ctl', '-D', self.root / 'postgres', '-m', 'fast', '-w', 'stop'], check=False)
        (self.root / 'commands.json').write_text(json.dumps(self.commands, indent=2))
        (self.root / 'results.json').write_text(json.dumps(self.results, indent=2))
        print('Evidence:', self.root, flush=True)

    def cli(self, *args):
        return self.run([self.binary, *args]).stdout.strip()

    def start_server(self):
        self.server_log = open(self.root / ('server-' + str(time.time_ns()) + '.log'), 'w+')
        self.proc = subprocess.Popen([self.binary, 'serve'], env=self.env,
                                     stdout=self.server_log, stderr=subprocess.STDOUT, text=True)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            self.server_log.flush()
            contents = Path(self.server_log.name).read_text()
            for line in contents.splitlines():
                if line.startswith('LISTEN '):
                    self.base = line.split(' ', 1)[1].strip()
                    return
            if self.proc.poll() is not None:
                raise AssertionError('Server exited: ' + contents)
            time.sleep(.05)
        raise AssertionError('Server did not announce LISTEN: ' + contents)

    def git(self, *args, principal='alice', protocol=2, check=True, cwd=None):
        env = self.env.copy()
        trace = self.root / ('git-packets-' + str(time.time_ns()) + '.log')
        env['GIT_TRACE_PACKET'] = str(trace)
        result = self.run(['git', '-c', 'protocol.version=' + str(protocol), '-c',
                           'http.extraHeader=X-Pando-Principal: ' + principal, *args], check=check, cwd=cwd, env=env)
        result.packet_trace = trace.read_text() if trace.exists() else ''
        return result

    def url(self, repo=None):
        return self.base + '/repos/' + (repo or self.repo) + '.git'

    def state(self):
        return {'refs': self.rows('SELECT * FROM pando_lab.refs ORDER BY repo,name'),
                'repos': self.rows('SELECT * FROM pando_lab.repositories ORDER BY id'),
                'changes': self.rows('SELECT * FROM pando_lab.changes ORDER BY repo,generation'),
                'manifests': self.rows('SELECT * FROM pando_lab.manifests ORDER BY repo,pack_id'),
                'objects': self.rows('SELECT * FROM pando_lab.objects ORDER BY repo,oid')}

    def check(self, name, fn):
        started = time.monotonic()
        detail = fn()
        self.results['checks'][name] = {'passed': True, 'seconds': round(time.monotonic() - started, 3), 'detail': detail}
        print('PASS', name, flush=True)

    def commit(self, path, text):
        (path / 'data.txt').write_text(text + '\n')
        self.git('add', '.', cwd=path)
        self.git('-c', 'user.name=Synthetic Pando', '-c', 'user.email=pando@example.invalid', 'commit', '-m', text, cwd=path)
        return self.git('rev-parse', 'HEAD', cwd=path).stdout.strip()

    def clone(self, name, protocol=2, repo=None, principal='reader'):
        dst = self.root / name
        reply = self.git('clone', self.url(repo), str(dst), principal=principal, protocol=protocol)
        if protocol == 2:
            assert 'version 2' in reply.packet_trace, 'Git clone silently fell back from requested v2'
        else:
            assert 'version 2' not in reply.packet_trace, 'Expected Git v0 advertisement'
        self.git('fsck', '--full', '--strict', cwd=dst)
        return dst

    def push(self, path, *refs, check=True, principal='alice', atomic=False):
        return self.git('push', *(['--atomic'] if atomic else []), self.url(), *refs,
                        check=check, principal=principal, cwd=path)

    def control(self, **values):
        (self.store / 'control.json').write_text(json.dumps(values))

    def http(self, path, principal='reader', method='GET', body=None, redirects=True):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener() if redirects else urllib.request.build_opener(NoRedirect())
        headers = {'X-Pando-Principal': principal}
        if method == 'POST':
            headers['Content-Type'] = 'application/x-' + ('git-receive-pack' if '/git-receive-pack' in path else 'git-upload-pack') + '-request'
        req = urllib.request.Request(path if path.startswith('http') else self.base + path,
                                     data=body, headers=headers, method=method)
        try:
            response = opener.open(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        return response.code, dict(response.headers), response.read()

    def setup(self):
        import uuid
        self.start_pg()
        self.store = self.root / 'store'
        self.store.mkdir()
        self.env.update(PANDO_SYNTHETIC_ONLY='1', PANDO_DATABASE_URL=self.db,
                        PANDO_ROOT=str(self.store), PANDO_GIT=shutil.which('git'), PANDO_LISTEN='127.0.0.1:0')
        self.cli('init')
        self.repo = str(uuid.uuid4())
        self.other = str(uuid.uuid4())
        self.cli('create-repo', self.repo, 'alice')
        self.cli('create-repo', self.other, 'bob')
        self.sql(f"INSERT INTO pando_lab.acl(repo,principal,write_allowed) VALUES ('{self.repo}','reader',false)")
        self.start_server()
        self.source = self.root / 'source'
        self.git('init', '--initial-branch=main', str(self.source))
        self.initial = self.commit(self.source, 'initial synthetic commit')

    def roundtrip(self):
        self.push(self.source, 'HEAD:refs/heads/main')
        for protocol in (0, 2):
            clone = self.clone('clone-v' + str(protocol), protocol)
            assert self.git('rev-parse', 'HEAD', cwd=clone).stdout.strip() == self.initial
        self.second = self.commit(self.source, 'incremental update')
        self.push(self.source, 'HEAD:refs/heads/main')
        for protocol in (0, 2):
            clone = self.root / ('clone-v' + str(protocol))
            self.git('fetch', 'origin', principal='reader', protocol=protocol, cwd=clone)
            assert self.git('rev-parse', 'origin/main', cwd=clone).stdout.strip() == self.second
            self.git('fsck', '--full', '--strict', cwd=clone)
        self.git('-c', 'user.name=Synthetic Pando', '-c', 'user.email=pando@example.invalid', 'tag', '-a', 'v1', '-m', 'synthetic tag', cwd=self.source)
        self.push(self.source, 'refs/tags/v1', 'HEAD:refs/heads/delete-me', atomic=True)
        self.push(self.source, ':refs/heads/delete-me')
        refs = self.git('ls-remote', self.url(), principal='reader').stdout
        assert 'refs/tags/v1^{}' in refs and 'refs/heads/delete-me' not in refs
        return {'clone_fetch_protocols': [0, 2], 'annotated_tag_and_delete': True}

    def acl_checks(self):
        before = self.state()
        statuses = {}
        for principal in ('reader', '', 'bob'):
            statuses[principal] = []
            for method, suffix in [('GET', '/info/refs?service=git-receive-pack'), ('POST', '/git-receive-pack')]:
                code, _, _ = self.http(self.url() + suffix, principal, method, b'' if method == 'POST' else None)
                statuses[principal].append(code)
                assert code in (401, 403, 404), statuses
        assert self.push(self.source, 'HEAD:refs/heads/forbidden', principal='reader', check=False).returncode
        assert self.git('ls-remote', self.url(), principal='', check=False).returncode
        assert self.state() == before
        return statuses

    def atomic_checks(self):
        before = self.state()
        self.sql("ALTER TABLE pando_lab.refs ADD CONSTRAINT test_reject CHECK (name <> 'refs/heads/reject')")
        try:
            p = self.push(self.source, 'HEAD:refs/heads/good', 'HEAD:refs/heads/reject', atomic=True, check=False)
            assert p.returncode and self.state() == before
        finally:
            self.sql('ALTER TABLE pando_lab.refs DROP CONSTRAINT test_reject')
        self.push(self.source, 'HEAD:refs/heads/alpha', 'HEAD:refs/heads/beta', atomic=True)
        assert self.sql(f"SELECT count(*) FROM pando_lab.refs WHERE repo='{self.repo}' AND name IN ('refs/heads/alpha','refs/heads/beta') AND oid='{self.second}'") == '2'
        before = self.state()
        p = self.push(self.source, 'HEAD:refs/heads/path', 'HEAD:refs/heads/path/child', atomic=True, check=False)
        assert p.returncode and self.state() == before
        return {'constraint_rollback': True, 'multi_ref_commit': True, 'directory_file_conflict': True}

    def raw_atomic_native_rejection(self):
        import struct
        header = b'PACK' + struct.pack('!II', 2, 0)
        empty_pack = header + hashlib.sha1(header).digest()
        oid = self.sql(f"SELECT oid FROM pando_lab.refs WHERE repo='{self.repo}' AND name='refs/heads/main'")
        cases = [('missing-oid', 'refs/heads/atomic-missing', 'f' * 40),
                 ('invalid-ref', 'refs/heads/invalid..name', oid),
                 ('outside-refs', 'UNSUPPORTED', oid)]
        evidence = {}
        for label, bad_ref, bad_oid in cases:
            before = self.state()
            valid_ref = 'refs/heads/atomic-valid-' + label
            lines = [(('0' * 40) + ' ' + oid + ' ' + valid_ref + '\0report-status atomic\n').encode(),
                     (('0' * 40) + ' ' + bad_oid + ' ' + bad_ref + '\n').encode()]
            payload = b''.join(f'{len(line)+4:04x}'.encode() + line for line in lines) + b'0000' + empty_pack
            code, _, response = self.http(self.url() + '/git-receive-pack', principal='alice', method='POST', body=payload)
            (self.root / ('raw-atomic-' + label + '-request.bin')).write_bytes(payload)
            (self.root / ('raw-atomic-' + label + '-response.bin')).write_bytes(response)
            assert self.state() == before, f'Atomic {label} rejection partially published state: {response!r}'
            assert code == 200, (label, code, response)
            assert b'ng ' + valid_ref.encode() + b' ' in response, (label, response)
            assert b'ng ' + bad_ref.encode() + b' ' in response, (label, response)
            assert b'ok ' + valid_ref.encode() not in response and b'ok ' + bad_ref.encode() not in response, (label, response)
            evidence[label] = {'all_refs_rejected': True, 'refs_objects_manifests_generations_changes_unchanged': True,
                               'response': response.decode(errors='replace')}
        return evidence

    def loopback_hostaddr(self):
        env = self.env.copy()
        env['PANDO_DATABASE_URL'] = 'host=127.0.0.1 hostaddr=192.0.2.1 user=pando_lab dbname=postgres connect_timeout=1'
        # No subcommand: even the vulnerable binary only reaches its usage error,
        # never init/serve or a database connection. The config guard must fail first.
        reply = self.run([self.binary], check=False, env=env)
        assert reply.returncode and 'loopback' in reply.stderr.lower(), reply.stderr
        assert 'usage:' not in reply.stderr.lower(), 'hostaddr bypassed configuration validation'
        return {'nonloopback_hostaddr_rejected_during_config_load': True, 'no_database_operation_requested': True}

    def faults(self):
        outcomes = {}
        for fault in ('before-objects', 'after-objects', 'before-commit'):
            before = self.state()
            oid = self.commit(self.source, 'fault ' + fault)
            self.control(fault=fault)
            try:
                p = self.push(self.source, 'HEAD:refs/heads/main', check=False)
            finally:
                self.control()
            assert p.returncode and self.state() == before, fault
            self.push(self.source, 'HEAD:refs/heads/main')
            assert self.sql(f"SELECT oid FROM pando_lab.refs WHERE repo='{self.repo}' AND name='refs/heads/main'") == oid
            outcomes[fault] = {'client_failed': True, 'authoritative_state_unchanged': True, 'retry_succeeded': True}
        oid = self.commit(self.source, 'reply loss after commit')
        self.control(fault='after-commit')
        try:
            p = self.push(self.source, 'HEAD:refs/heads/main', check=False)
        finally:
            self.control()
        assert p.returncode
        assert self.sql(f"SELECT oid FROM pando_lab.refs WHERE repo='{self.repo}' AND name='refs/heads/main'") == oid
        before = self.state()
        self.push(self.source, 'HEAD:refs/heads/main')
        assert self.state() == before
        clone = self.clone('after-commit-clone')
        assert self.git('rev-parse', 'HEAD', cwd=clone).stdout.strip() == oid
        outcomes['after-commit'] = {'client_failed': True, 'server_committed': True, 'retry_did_not_republish': True}
        return outcomes

    def cas(self):
        a, b = self.clone('race-a'), self.clone('race-b')
        aoid, boid = self.commit(a, 'racer a'), self.commit(b, 'racer b')
        barrier = self.root / 'barrier'
        barrier.mkdir()
        self.control(barrier=str(barrier))
        before = int(self.sql(f"SELECT generation FROM pando_lab.repositories WHERE id='{self.repo}'"))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                pending = [pool.submit(self.push, path, 'HEAD:refs/heads/main', 'HEAD:refs/heads/race-' + label, check=False, atomic=True) for path, label in ((a, 'a'), (b, 'b'))]
                deadline = time.monotonic() + 25
                while len(list(barrier.glob('*.ready'))) < 2:
                    if time.monotonic() > deadline or any(f.done() for f in pending):
                        (barrier / 'release').touch()
                        raise AssertionError('Both receive hooks did not enter CAS barrier')
                    time.sleep(.05)
                (barrier / 'release').touch()
                replies = [f.result(timeout=40) for f in pending]
        finally:
            (barrier / 'release').touch()
            self.control()
        assert sum(p.returncode == 0 for p in replies) == 1
        assert int(self.sql(f"SELECT generation FROM pando_lab.repositories WHERE id='{self.repo}'")) == before + 1
        assert self.sql(f"SELECT oid FROM pando_lab.refs WHERE repo='{self.repo}' AND name='refs/heads/main'") in (aoid, boid)
        winner = 'a' if replies[0].returncode == 0 else 'b'
        raced = self.rows(f"SELECT name,oid FROM pando_lab.refs WHERE repo='{self.repo}' AND name LIKE 'refs/heads/race-%'")
        assert raced == [{'name': 'refs/heads/race-' + winner, 'oid': aoid if winner == 'a' else boid}], raced
        return {'successful_writers': 1, 'rejected_writers': 1, 'generation_delta': 1, 'losing_batch_extra_ref_absent': True}

    def storage_fence(self):
        client = self.clone('storage-fence')
        self.commit(client, 'writer on stale storage generation')
        before = self.state()
        barrier = self.root / 'storage-barrier'
        barrier.mkdir()
        self.control(barrier=str(barrier))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.push, client, 'HEAD:refs/heads/main', check=False)
                deadline = time.monotonic() + 25
                while not list(barrier.glob('*.ready')):
                    if time.monotonic() > deadline or pending.done():
                        (barrier / 'release').touch()
                        raise AssertionError('Storage-fence writer did not reach barrier')
                    time.sleep(.05)
                self.sql(f"UPDATE pando_lab.repositories SET storage_generation=storage_generation+1 WHERE id='{self.repo}'")
                (barrier / 'release').touch()
                reply = pending.result(timeout=40)
        finally:
            (barrier / 'release').touch()
            self.control()
        assert reply.returncode, 'Stale storage generation writer was accepted'
        after = self.state()
        for row in before['repos']:
            if row['id'] == self.repo:
                row['storage_generation'] += 1
        assert after == before, 'Fenced writer mutated authoritative state'
        return {'stale_writer_rejected': True, 'refs_objects_changes_unchanged': True}

    def commit_acl_revocation(self):
        client = self.clone('acl-revocation-writer')
        self.commit(client, 'write grant revoked after objects ready')
        before = self.state()
        barrier = self.root / 'acl-barrier'
        barrier.mkdir()
        self.control(barrier=str(barrier))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.push, client, 'HEAD:refs/heads/main', check=False)
                deadline = time.monotonic() + 25
                while not list(barrier.glob('*.ready')):
                    if time.monotonic() > deadline or pending.done():
                        (barrier / 'release').touch()
                        raise AssertionError('ACL-revocation writer did not reach barrier')
                    time.sleep(.05)
                self.sql(f"UPDATE pando_lab.acl SET write_allowed=false WHERE repo='{self.repo}' AND principal='alice'")
                (barrier / 'release').touch()
                reply = pending.result(timeout=40)
                assert reply.returncode, 'Writer committed after write authorization was revoked'
                assert self.state() == before, 'Revoked writer mutated authoritative state'
        finally:
            (barrier / 'release').touch()
            self.control()
            self.sql(f"UPDATE pando_lab.acl SET write_allowed=true WHERE repo='{self.repo}' AND principal='alice'")
        return {'write_revoked_after_pack_ready': True, 'commit_rejected': True,
                'refs_objects_manifests_generations_changes_unchanged': True}

    def isolation(self):
        other = self.root / 'other'
        self.git('init', '--initial-branch=main', str(other))
        secret = self.commit(other, 'only bob repository contains this object')
        self.git('push', self.url(self.other), 'HEAD:refs/heads/main', principal='bob', cwd=other)
        assert self.git('ls-remote', self.url(self.other), principal='alice', check=False).returncode
        p = self.git('fetch', self.url(), secret, principal='reader', cwd=self.source, check=False)
        assert p.returncode, 'Cross-repository raw OID fetch was accepted'
        orphan = self.clone('orphan-writer')
        orphan_oid = self.commit(orphan, 'unique subsequently unreachable commit')
        self.push(orphan, 'HEAD:refs/heads/orphan-only')
        self.push(orphan, ':refs/heads/orphan-only')
        assert self.sql(f"SELECT count(*) FROM pando_lab.objects WHERE repo='{self.repo}' AND oid='{orphan_oid}'") == '1'
        empty = self.root / 'empty-orphan-reader'
        self.git('init', str(empty))
        reply = self.git('fetch', self.url(), orphan_oid, principal='reader', cwd=empty, check=False)
        assert reply.returncode, 'Same-repo unreachable raw OID fetch was accepted'
        assert self.git('cat-file', '-e', orphan_oid, cwd=empty, check=False).returncode
        return {'cross_repo_read_denied': True, 'foreign_oid_fetch_denied': True,
                'same_repo_unreachable_oid_denied_from_empty_client': True}

    def snapshot(self):
        code, headers, body = self.http(self.url() + '/info/refs?service=git-upload-pack', redirects=False)
        assert code in (302, 307, 308), (code, body)
        location = headers.get('Location') or headers.get('location')
        assert location and '/snapshots/' in location
        if location.startswith('/'):
            location = self.base + location
        old_oid = self.sql(f"SELECT oid FROM pando_lab.refs WHERE repo='{self.repo}' AND name='refs/heads/main'")
        code, _, old_advertisement = self.http(location)
        assert code == 200
        self.sql(f"INSERT INTO pando_lab.acl(repo,principal,write_allowed) VALUES('{self.repo}','alternate-reader',false)")
        try:
            assert self.http(location, principal='alternate-reader')[0] in (403, 404), 'Snapshot accepted a different authorized principal'
        finally:
            self.sql(f"DELETE FROM pando_lab.acl WHERE repo='{self.repo}' AND principal='alternate-reader'")
        self.sql(f"INSERT INTO pando_lab.acl(repo,principal,write_allowed) VALUES('{self.other}','reader',false)")
        try:
            substituted = location.replace(self.repo + '.git', self.other + '.git')
            assert substituted != location
            assert self.http(substituted)[0] in (403, 404), 'Snapshot token accepted for a different authorized repository'
        finally:
            self.sql(f"DELETE FROM pando_lab.acl WHERE repo='{self.other}' AND principal='reader'")
        self.sql(f"UPDATE pando_lab.acl SET write_allowed=true WHERE repo='{self.repo}' AND principal='reader'")
        self.git('fetch', self.url(), principal='reader', cwd=self.source)
        self.git('reset', '--hard', 'FETCH_HEAD', cwd=self.source)
        oid = self.commit(self.source, 'snapshot advances after advertisement')
        self.push(self.source, 'HEAD:refs/heads/main')
        code, _, still_old = self.http(location)
        assert code == 200 and still_old == old_advertisement
        want = ('want ' + old_oid + '\n').encode()
        request = f'{len(want)+4:04x}'.encode() + want + b'00000009done\n'
        rpc = location.split('/info/refs')[0] + '/git-upload-pack'
        code, _, pack_response = self.http(rpc, method='POST', body=request)
        assert code == 200 and b'PACK' in pack_response, (code, pack_response[:200])
        self.saved_snapshot = (location.replace(self.base, ''), old_advertisement)
        _, _, current = self.http(self.url() + '/info/refs?service=git-upload-pack')
        assert oid.encode() in current and current != old_advertisement
        self.sql(f"DELETE FROM pando_lab.acl WHERE repo='{self.repo}' AND principal='reader'")
        try:
            assert self.http(location)[0] in (401, 403, 404)
        finally:
            self.sql(f"INSERT INTO pando_lab.acl(repo,principal,write_allowed) VALUES('{self.repo}','reader',false)")
        return {'stable_advertisement': True, 'old_snapshot_pack_received': True, 'new_read_advances': True, 'principal_bound': True, 'repository_bound_even_with_acl': True, 'revoked_acl_denied': True}

    def cold_restart(self):
        # Restart alone proves process-memory independence. Per-request cache cleanup
        # is asserted separately when the implementation's cache layout is known.
        self.proc.terminate()
        self.proc.wait(timeout=15)
        sessions = self.store / 'sessions'
        if sessions.exists():
            shutil.rmtree(sessions)
        self.start_server()
        path, advertised = self.saved_snapshot
        code, _, recovered = self.http(path)
        assert code == 200 and recovered == advertised
        dst = self.clone('cold-restart')
        expected = self.sql(f"SELECT oid FROM pando_lab.refs WHERE repo='{self.repo}' AND name='refs/heads/main'")
        assert self.git('rev-parse', 'HEAD', cwd=dst).stdout.strip() == expected
        if sessions.exists():
            assert not list(sessions.iterdir()), 'Disposable sessions were not cleaned up'
        snapshot_id = path.split('/snapshots/')[1].split('/')[0]
        self.sql(f"UPDATE pando_lab.snapshots SET expires_at=clock_timestamp()-interval '1 second' WHERE id='{snapshot_id}'")
        assert self.http(path)[0] in (403, 404, 410)
        return {'fresh_process_clone_fsck': True, 'deleted_caches': True, 'snapshot_survives_restart': True, 'expired_snapshot_denied': True}

    def thin_pack(self):
        import uuid
        target, empty_target = str(uuid.uuid4()), str(uuid.uuid4())
        for repo in (target, empty_target):
            self.cli('create-repo', repo, 'alice')
        source = self.root / 'thin-source'
        self.git('init', '--initial-branch=main', str(source))
        # Large deterministic, non-repeating blob: a small edit selects a delta
        # against the explicitly excluded old history, not an accidental full blob.
        content = ''.join(hashlib.sha256(str(i).encode()).hexdigest() + '\n' for i in range(8000))
        (source / 'large.txt').write_text(content)
        self.git('add', '.', cwd=source)
        self.git('-c', 'user.name=Synthetic Pando', '-c', 'user.email=pando@example.invalid', 'commit', '-m', 'thin base', cwd=source)
        old = self.git('rev-parse', 'HEAD', cwd=source).stdout.strip()
        self.git('push', self.url(target), 'HEAD:refs/heads/main', cwd=source)
        (source / 'large.txt').write_text(content[:200000] + 'small synthetic edit\n' + content[200000:])
        self.git('add', '.', cwd=source)
        self.git('-c', 'user.name=Synthetic Pando', '-c', 'user.email=pando@example.invalid', 'commit', '-m', 'thin delta', cwd=source)
        new = self.git('rev-parse', 'HEAD', cwd=source).stdout.strip()
        argv = ['git', 'pack-objects', '--thin', '--stdout', '--revs']
        made = subprocess.run(argv, cwd=source, env=self.env, input=(new + '\n^' + old + '\n').encode(), capture_output=True, timeout=60)
        assert made.returncode == 0, made.stderr
        pack = made.stdout
        assert pack.startswith(b'PACK')
        (self.root / 'actual-thin.pack').write_bytes(pack)
        self.commands.append({'argv': argv, 'cwd': str(source), 'rc': made.returncode,
                              'stdout_bytes': len(pack), 'stdout_sha256': hashlib.sha256(pack).hexdigest(), 'stderr': made.stderr.decode()})
        isolated = self.root / 'thin-no-bases.git'
        self.git('init', '--bare', str(isolated))
        argv = ['git', '--git-dir=' + str(isolated), 'index-pack', '--fix-thin', '--stdin']
        missing = subprocess.run(argv, env=self.env, input=pack, capture_output=True, timeout=60)
        self.commands.append({'argv': argv, 'rc': missing.returncode, 'stdout': missing.stdout.decode(), 'stderr': missing.stderr.decode()})
        assert missing.returncode != 0 and b'unresolved delta' in missing.stderr, missing.stderr

        def request(old_oid):
            command = (old_oid + ' ' + new + ' refs/heads/main\0report-status\n').encode()
            return f'{len(command)+4:04x}'.encode() + command + b'0000' + pack

        code, headers, accepted = self.http(self.url(target) + '/git-receive-pack', principal='alice', method='POST', body=request(old))
        assert code == 200 and b'unpack ok' in accepted and b'ok refs/heads/main' in accepted, (code, accepted)
        assert self.sql(f"SELECT oid FROM pando_lab.refs WHERE repo='{target}' AND name='refs/heads/main'") == new
        restored = self.clone('thin-roundtrip', repo=target, principal='alice')
        assert self.git('rev-parse', 'HEAD', cwd=restored).stdout.strip() == new
        before = self.state()
        code, headers, rejected = self.http(self.url(empty_target) + '/git-receive-pack', principal='alice', method='POST', body=request('0' * 40))
        assert code >= 400 or b'unpack ok' not in rejected or b'ng refs/heads/main' in rejected, (code, rejected)
        assert self.state() == before, 'Missing-base thin pack published authoritative state'
        (self.root / 'thin-response-positive.bin').write_bytes(accepted)
        (self.root / 'thin-response-negative.bin').write_bytes(rejected)
        return {'actual_thin_bytes': len(pack), 'isolated_index_pack_unresolved_delta': True,
                'existing_base_push_and_clone_fsck': True, 'missing_base_push_no_publication': True}

    def pack_integrity(self):
        manifests = self.rows('SELECT * FROM pando_lab.manifests ORDER BY repo,pack_id')
        for row in manifests:
            for extension in ('pack', 'idx'):
                file = self.store / 'objects' / row['repo'] / (row['pack_id'] + '.' + extension)
                assert hashlib.sha256(file.read_bytes()).hexdigest() == row[extension + '_sha256']
        before = self.state()
        self.control(fault='corrupt-read')
        try:
            failed = self.git('clone', self.url(), str(self.root / 'corrupt-read'), principal='reader', check=False)
            assert failed.returncode, 'Corrupted pack read did not fail closed'
        finally:
            self.control()
        assert self.state() == before
        row = next(row for row in manifests if row['repo'] == self.repo)
        pack = self.store / 'objects' / row['repo'] / (row['pack_id'] + '.pack')
        backup = pack.with_suffix('.temporarily-missing')
        pack.rename(backup)
        try:
            failed = self.git('clone', self.url(), str(self.root / 'missing-pack'), principal='reader', check=False)
            assert failed.returncode, 'Missing published pack did not fail closed'
        finally:
            backup.rename(pack)
        self.clone('restored-packs')
        return {'pack_and_idx_checksums_verified': len(manifests), 'corrupt_read_denied': True,
                'missing_published_pack_denied': True, 'restored_clone_fsck': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard-pando-lab')
    parser.add_argument('--pg-share', default=os.environ.get('PG_SHARE'))
    args = parser.parse_args()
    lab = Lab(args)
    try:
        lab.setup()
        for name in ('roundtrip', 'acl_checks', 'atomic_checks', 'raw_atomic_native_rejection', 'loopback_hostaddr', 'faults', 'cas', 'storage_fence', 'commit_acl_revocation', 'isolation', 'snapshot', 'cold_restart', 'thin_pack', 'pack_integrity'):
            lab.check(name, getattr(lab, name))
        lab.results['passed'] = True
    except Exception:
        lab.results['failure'] = traceback.format_exc()
        raise
    finally:
        lab.cleanup()


if __name__ == '__main__':
    main()
