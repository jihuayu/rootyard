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

    def incremental_pack_deduplication(self):
        before_packs = {r['pack_id'] for r in self.rows(f"SELECT pack_id FROM pando_lab.manifests WHERE repo='{self.repo}'")}
        inc_oid = self.commit(self.source, 'incremental delta-self-contained commit')
        self.push(self.source, 'HEAD:refs/heads/main')
        after_packs = {r['pack_id'] for r in self.rows(f"SELECT pack_id FROM pando_lab.manifests WHERE repo='{self.repo}'")}
        new_packs = after_packs - before_packs
        assert len(new_packs) == 1, new_packs
        new_pack_id = next(iter(new_packs))
        pack_file = self.store / 'objects' / self.repo / (new_pack_id + '.pack')
        report = json.loads(self.cli('verify-delta', str(pack_file)))
        pack_oids = {obj['oid'] for obj in report['objects']}
        assert inc_oid in pack_oids
        assert self.initial not in pack_oids, 'Incremental pack redundantly re-packed initial commit'
        return {'incremental_pack_id': new_pack_id, 'object_count': report['object_count'], 'initial_commit_excluded': True}

    def delta_and_graph_cli(self):
        manifests = self.rows(f"SELECT pack_id FROM pando_lab.manifests WHERE repo='{self.repo}' ORDER BY pack_id")
        verified = 0
        for row in manifests:
            pack_path = self.store / 'objects' / self.repo / (row['pack_id'] + '.pack')
            rep = json.loads(self.cli('verify-delta', str(pack_path)))
            assert rep['version'] == 2 and rep['object_count'] == len(rep['objects'])
            verified += 1
        thin = self.root / 'actual-thin.pack'
        if thin.exists():
            bad = self.run([self.binary, 'verify-delta', str(thin)], check=False)
            assert bad.returncode != 0, 'Non-self-contained thin pack must be rejected by verify-delta'
        head_oid = self.sql(f"SELECT oid FROM pando_lab.refs WHERE repo='{self.repo}' AND name='refs/heads/main'")
        walk_full = json.loads(self.cli('walk-graph', self.repo))
        assert walk_full['reachable_count'] == len(walk_full['reachable_oids']) and walk_full['commits'] >= 2
        walk_inc = json.loads(self.cli('walk-graph', self.repo, head_oid, '^' + self.initial))
        assert walk_inc['excluded_count'] > 0 and walk_inc['reachable_count'] < walk_full['reachable_count']
        return {'packs_verified': verified, 'full_reachable': walk_full['reachable_count'], 'incremental_reachable': walk_inc['reachable_count']}

    def dual_operator_diff_export(self):
        rep = json.loads(self.cli('diff-export', self.repo))
        assert rep['matched'] is True and rep['bit_for_bit_match'] is True, rep
        assert rep['reachable_objects'] > 0 and rep['commits'] >= 2
        rep_inc = json.loads(self.cli('diff-export', self.repo, '^' + self.initial))
        assert rep_inc['matched'] is True and rep_inc['bit_for_bit_match'] is True, rep_inc
        assert rep_inc['excluded_objects'] > 0
        return {'full_diff_export_matched': True, 'incremental_diff_export_matched': True}

    def refs_and_operations_api(self):
        code, _, raw = self.http(f'/repos/{self.repo}.git/refs', principal='reader')
        assert code == 200, (code, raw)
        refs_payload = json.loads(raw.decode())
        assert refs_payload['repo'] == self.repo and 'refs/heads/main' in refs_payload['refs']
        code_unauth, _, _ = self.http(f'/repos/{self.repo}.git/refs', principal='bob')
        assert code_unauth == 403, code_unauth
        ops = self.rows(f"SELECT id,state FROM pando_lab.operations WHERE repo='{self.repo}' AND state='COMMITTED' LIMIT 1")
        assert ops, 'Expected at least one committed operation'
        op_id = ops[0]['id']
        code_op, _, raw_op = self.http(f'/repos/{self.repo}.git/operations/{op_id}', principal='reader')
        assert code_op == 200, (code_op, raw_op)
        op_payload = json.loads(raw_op.decode())
        assert op_payload['id'] == op_id and op_payload['state'] == 'COMMITTED'
        return {'refs_endpoint_verified': True, 'operations_endpoint_verified': True}

    def orphan_and_snapshot_gc(self):
        gc_rep = json.loads(self.cli('gc', self.repo))
        assert gc_rep['orphan_files_deleted'] >= 1, gc_rep
        assert gc_rep['committed_packs_retained'] >= 1, gc_rep
        self.clone('post-gc-clone')
        return gc_rep

    def online_migration_state_machine(self):
        import uuid
        self.mig_repo = str(uuid.uuid4())
        self.cli('create-repo', self.mig_repo, 'alice')
        self.sql(f"INSERT INTO pando_lab.acl(repo,principal,write_allowed) VALUES ('{self.mig_repo}','reader',false)")

        gitfs_bare = self.root / 'gitfs-origin.git'
        gitfs_work = self.root / 'gitfs-work'
        self.git('init', '--bare', '--initial-branch=main', str(gitfs_bare))
        self.git('init', '--initial-branch=main', str(gitfs_work))
        c1 = self.commit(gitfs_work, 'gitfs commit 1')
        self.git('push', str(gitfs_bare), 'HEAD:refs/heads/main', 'HEAD:refs/heads/feature', cwd=gitfs_work)
        c2 = self.commit(gitfs_work, 'gitfs commit 2')
        self.git('-c', 'user.name=Synthetic Pando', '-c', 'user.email=pando@example.invalid',
                 'tag', '-a', 'v1.0', '-m', 'release v1.0', cwd=gitfs_work)
        self.git('push', str(gitfs_bare), 'HEAD:refs/heads/main', 'refs/tags/v1.0', cwd=gitfs_work)
        self.mig_gitfs = gitfs_bare

        # Step 1: copy
        copy_rep = json.loads(self.cli('migrate-step', self.mig_repo, str(gitfs_bare), 'copy'))
        assert copy_rep['step'] == 'copy' and copy_rep['state'] == 'COPYING', copy_rep
        assert copy_rep['storage_backend'] == 'gitfs' and copy_rep['migration_state'] == 'copying', copy_rep
        assert copy_rep['write_paused'] is False and copy_rep['ref_count'] == 3, copy_rep
        code_pre_switch, _, _ = self.http(self.url(self.mig_repo) + '/info/refs?service=git-receive-pack', principal='alice')
        assert code_pre_switch == 409, code_pre_switch

        # Step 2: verify
        verify_rep = json.loads(self.cli('migrate-step', self.mig_repo, str(gitfs_bare), 'verify'))
        assert verify_rep['step'] == 'verify' and verify_rep['state'] == 'VERIFIED', verify_rep
        assert verify_rep['migration_state'] == 'verified', verify_rep
        assert verify_rep['diff_report']['matched'] is True and verify_rep['diff_report']['bit_for_bit_match'] is True

        # Incremental GitFS write arriving between verify and drain
        c3 = self.commit(gitfs_work, 'gitfs pre-drain incremental commit 3')
        self.git('push', str(gitfs_bare), 'HEAD:refs/heads/main', cwd=gitfs_work)
        self.mig_c3 = c3

        # Step 3: drain (pauses writes, fences GitFS, syncs incremental delta)
        drain_rep = json.loads(self.cli('migrate-step', self.mig_repo, str(gitfs_bare), 'drain'))
        assert drain_rep['step'] == 'drain' and drain_rep['state'] == 'DRAINED', drain_rep
        assert drain_rep['migration_state'] == 'draining' and drain_rep['write_paused'] is True, drain_rep
        assert drain_rep['incremental_objects_synced'] >= 1 and drain_rep['gitfs_fenced_readonly'] is True, drain_rep
        assert drain_rep['diff_report']['bit_for_bit_match'] is True
        c_blocked = self.commit(gitfs_work, 'blocked gitfs commit during drain')
        assert self.git('push', str(gitfs_bare), 'HEAD:refs/heads/blocked', cwd=gitfs_work, check=False).returncode != 0
        self.git('reset', '--hard', c3, cwd=gitfs_work)

        # Step 4: fence (bumps storage_generation)
        fence_rep = json.loads(self.cli('migrate-step', self.mig_repo, str(gitfs_bare), 'fence'))
        assert fence_rep['step'] == 'fence' and fence_rep['state'] == 'FENCED', fence_rep
        assert fence_rep['migration_state'] == 'fenced' and fence_rep['write_paused'] is True, fence_rep
        assert fence_rep['new_storage_generation'] == fence_rep['old_storage_generation'] + 1, fence_rep

        # Step 5: switchover (cuts authority to pando, keeps gitfs fenced read-only)
        switch_rep = json.loads(self.cli('migrate-step', self.mig_repo, str(gitfs_bare), 'switchover'))
        assert switch_rep['step'] == 'switchover' and switch_rep['state'] == 'SWITCHED_OVER', switch_rep
        assert switch_rep['storage_backend'] == 'pando' and switch_rep['migration_state'] == 'switched_over', switch_rep
        assert switch_rep['write_paused'] is False and switch_rep['gitfs_fenced_readonly'] is True, switch_rep

        # Verify migration-status CLI and GET /repos/{id}.git/migration HTTP endpoint
        status_cli = json.loads(self.cli('migration-status', self.mig_repo))
        assert status_cli['storage_backend'] == 'pando' and status_cli['migration_state'] == 'switched_over', status_cli
        code_mig, _, raw_mig = self.http(f'/repos/{self.mig_repo}.git/migration', principal='reader')
        assert code_mig == 200, (code_mig, raw_mig)
        status_http = json.loads(raw_mig.decode())
        assert status_http['storage_backend'] == 'pando' and status_http['latest_migration']['state'] == 'SWITCHED_OVER'
        code_mig_denied, _, _ = self.http(f'/repos/{self.mig_repo}.git/migration', principal='bob')
        assert code_mig_denied == 403, code_mig_denied

        # Clone migrated repository from Pando Smart HTTP and verify c3, feature, v1.0
        mig_clone = self.clone('migrated-clone', repo=self.mig_repo, principal='alice')
        assert self.git('rev-parse', 'HEAD', cwd=mig_clone).stdout.strip() == c3

        # Also verify one-shot migrate command
        one_shot_repo = str(uuid.uuid4())
        self.cli('create-repo', one_shot_repo, 'alice')
        gitfs_bare2 = self.root / 'gitfs-oneshot.git'
        self.git('clone', '--bare', str(gitfs_bare), str(gitfs_bare2))
        full_rep = json.loads(self.cli('migrate', one_shot_repo, str(gitfs_bare2)))
        assert full_rep['step'] == 'full' and full_rep['state'] == 'SWITCHED_OVER', full_rep
        assert full_rep['storage_backend'] == 'pando' and full_rep['diff_report']['bit_for_bit_match'] is True

        return {
            'migration_id': switch_rep['migration_id'],
            'old_storage_generation': switch_rep['old_storage_generation'],
            'new_storage_generation': switch_rep['new_storage_generation'],
            'incremental_objects_synced': drain_rep['incremental_objects_synced'],
            'one_shot_migrated': True,
        }

    def post_switchover_rollback_with_new_commits(self):
        mig_clone = self.root / 'migrated-clone'
        c4 = self.commit(mig_clone, 'post-switchover pando commit 4')
        c5 = self.commit(mig_clone, 'post-switchover pando commit 5')
        self.git('push', '--atomic', self.url(self.mig_repo),
                 'HEAD:refs/heads/main', 'HEAD:refs/heads/post-switchover', ':refs/heads/feature',
                 principal='alice', cwd=mig_clone)

        # Before rollback, GitFS bare repo still has pre-switchover main (c3) and feature branch
        gitfs_main_before = self.git('--git-dir=' + str(self.mig_gitfs), 'rev-parse', 'refs/heads/main').stdout.strip()
        assert gitfs_main_before == self.mig_c3

        # Execute rollback from Pando back to GitFS
        rb_rep = json.loads(self.cli('rollback', self.mig_repo, str(self.mig_gitfs)))
        assert rb_rep['direction'] == 'pando_to_gitfs' and rb_rep['state'] == 'ROLLED_BACK', rb_rep
        assert rb_rep['storage_backend'] == 'gitfs' and rb_rep['migration_state'] == 'rolled_back', rb_rep
        assert rb_rep['write_paused'] is True and rb_rep['gitfs_write_paused'] is False, rb_rep
        assert rb_rep['post_switchover_commits'] >= 2 and rb_rep['deleted_refs_reconciled'] >= 1, rb_rep
        assert rb_rep['gitfs_fsck_ok'] is True and rb_rep['diff_report']['bit_for_bit_match'] is True, rb_rep
        assert rb_rep['new_storage_generation'] == rb_rep['old_storage_generation'] + 1, rb_rep

        # Pando Smart HTTP receive-pack must now reject pushes (authority is back on GitFS)
        c_pando_rejected = self.commit(mig_clone, 'rejected push to pando after rollback')
        assert self.git('push', self.url(self.mig_repo), 'HEAD:refs/heads/main',
                        principal='alice', cwd=mig_clone, check=False).returncode != 0
        self.git('reset', '--hard', c5, cwd=mig_clone)

        # Restored GitFS bare repository has c5, post-switchover branch, deleted feature branch, and passes fsck
        self.git('--git-dir=' + str(self.mig_gitfs), 'fsck', '--full', '--strict')
        assert self.git('--git-dir=' + str(self.mig_gitfs), 'rev-parse', 'refs/heads/main').stdout.strip() == c5
        assert self.git('--git-dir=' + str(self.mig_gitfs), 'rev-parse', 'refs/heads/post-switchover').stdout.strip() == c5
        assert self.git('--git-dir=' + str(self.mig_gitfs), 'rev-parse', '--verify', 'refs/heads/feature', check=False).returncode != 0

        # Stale storage_generation push to GitFS is rejected by hooks/pre-receive, while current generation push succeeds
        c6 = self.commit(mig_clone, 'post-rollback commit on restored gitfs')
        stale_env = self.env.copy()
        stale_env['ROOTYARD_EXPECTED_STORAGE_GENERATION'] = '1'
        assert self.run(['git', 'push', str(self.mig_gitfs), 'HEAD:refs/heads/main'],
                        cwd=mig_clone, env=stale_env, check=False).returncode != 0
        self.git('push', str(self.mig_gitfs), 'HEAD:refs/heads/main', cwd=mig_clone)
        assert self.git('--git-dir=' + str(self.mig_gitfs), 'rev-parse', 'refs/heads/main').stdout.strip() == c6

        return {
            'rollback_migration_id': rb_rep['migration_id'],
            'post_switchover_commits': rb_rep['post_switchover_commits'],
            'deleted_refs_reconciled': rb_rep['deleted_refs_reconciled'],
            'new_storage_generation': rb_rep['new_storage_generation'],
            'gitfs_restored_and_writable': True,
        }

    def object_store_cas_and_cache_recovery(self):
        manifests = self.rows(
            f"SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo='{self.repo}' ORDER BY pack_id"
        )
        assert manifests, 'Expected at least one committed manifest for object store test'
        pack_id = manifests[0]['pack_id']

        put_rep = json.loads(self.cli('object-store-put', self.repo, pack_id, '--chunk-size', '4096'))
        assert put_rep['status'] == 'published' and put_rep['chunk_count'] >= 1, put_rep
        assert put_rep['immutable_mode'] == '0444', put_rep

        fail_res = self.run(
            [self.binary, 'object-store-put', self.repo, pack_id, '--chunk-size', '64', '--fail-after-chunks', '1'],
            check=False,
        )
        assert fail_res.returncode != 0, 'Fault injection --fail-after-chunks 1 must fail closed'
        corrupt_res = self.run(
            [self.binary, 'object-store-put', self.repo, pack_id, '--chunk-size', '64', '--corrupt-chunk', '1'],
            check=False,
        )
        assert corrupt_res.returncode != 0, 'Corrupt chunk part must fail closed'
        multipart_dir = self.store / 'multipart'
        assert not multipart_dir.exists() or len(list(multipart_dir.iterdir())) == 0

        local_pack = self.store / 'objects' / self.repo / f'{pack_id}.pack'
        if local_pack.exists():
            local_pack.unlink()
        get_rep = json.loads(self.cli('object-store-get', self.repo, pack_id))
        assert get_rep['rehydrated_from_object_store'] is True and get_rep['verified'] is True, get_rep
        assert local_pack.is_file()

        ver_rep = json.loads(self.cli('object-store-verify', self.repo))
        assert ver_rep['verified'] is True and ver_rep['packs_verified'] >= 1, ver_rep

        code_os, _, raw_os = self.http(f'/repos/{self.repo}.git/object-store', principal='reader')
        assert code_os == 200, (code_os, raw_os)
        os_status = json.loads(raw_os.decode())
        assert os_status['repo'] == self.repo and os_status['object_store_manifests'] >= 1, os_status
        code_os_denied, _, _ = self.http(f'/repos/{self.repo}.git/object-store', principal='bob')
        assert code_os_denied == 403, code_os_denied

        self.clone('post-object-store-rehydrated')
        return {
            'pack_id': pack_id,
            'chunk_count': put_rep['chunk_count'],
            'rehydrated': True,
            'verified': True,
        }

    def multi_pack_repack_and_pinned_gc(self):
        import uuid
        repack_repo = str(uuid.uuid4())
        self.cli('create-repo', repack_repo, 'alice')
        self.sql(f"INSERT INTO pando_lab.acl(repo,principal,write_allowed) VALUES ('{repack_repo}','reader',false)")

        repack_work = self.root / 'repack-work'
        self.git('init', '--initial-branch=main', str(repack_work))
        c1 = self.commit(repack_work, 'repack base commit 1')
        self.git('push', '--atomic', self.url(repack_repo), 'HEAD:refs/heads/main', principal='alice', cwd=repack_work)

        c2_pinned = self.commit(repack_work, 'repack pinned commit 2')
        self.git('push', '--atomic', self.url(repack_repo), 'HEAD:refs/heads/pinned-temp', principal='alice', cwd=repack_work)
        pin_rep = json.loads(self.cli('pin-root', repack_repo, 'ci-release-pin', c2_pinned))
        assert pin_rep['pinned'] is True and pin_rep['oid'] == c2_pinned, pin_rep
        self.git('push', '--atomic', self.url(repack_repo), ':refs/heads/pinned-temp', principal='alice', cwd=repack_work)

        self.git('reset', '--hard', c1, cwd=repack_work)
        c3_orphan = self.commit(repack_work, 'repack orphan commit 3')
        self.git('push', '--atomic', self.url(repack_repo), 'HEAD:refs/heads/orphan-temp', principal='alice', cwd=repack_work)
        self.git('push', '--atomic', self.url(repack_repo), ':refs/heads/orphan-temp', principal='alice', cwd=repack_work)

        self.git('reset', '--hard', c1, cwd=repack_work)
        c4_main = self.commit(repack_work, 'repack main commit 4')
        self.git('push', '--atomic', self.url(repack_repo), 'HEAD:refs/heads/main', principal='alice', cwd=repack_work)

        code_snap, snap_headers, _ = self.http(
            f'/repos/{repack_repo}.git/info/refs?service=git-upload-pack',
            principal='reader',
            redirects=False,
        )
        assert code_snap == 302, code_snap
        snap_loc = snap_headers['location']

        code_packs_pre, _, raw_packs_pre = self.http(f'/repos/{repack_repo}.git/packs', principal='reader')
        assert code_packs_pre == 200, (code_packs_pre, raw_packs_pre)
        packs_pre = json.loads(raw_packs_pre.decode())
        assert packs_pre['active_pack_count'] >= 3, packs_pre

        code_repack_denied, _, _ = self.http(
            f'/repos/{repack_repo}.git/repack', principal='bob', method='POST', body=b'{}'
        )
        assert code_repack_denied == 403, code_repack_denied

        repack_body = json.dumps(
            {'prune_superseded': True, 'pin_oids': [c2_pinned], 'sync_object_store': True}
        ).encode()
        code_repack, _, raw_repack = self.http(
            f'/repos/{repack_repo}.git/repack', principal='alice', method='POST', body=repack_body
        )
        assert code_repack == 200, (code_repack, raw_repack)
        rep = json.loads(raw_repack.decode())
        assert rep['packs_before'] >= 3 and rep['packs_after'] == 1, rep
        assert rep['compacted_pack_id'] is not None, rep
        assert rep['unreachable_objects_pruned'] >= 1, rep
        assert rep['pinned_roots_count'] >= 1 and rep['active_snapshots_count'] >= 1, rep
        assert len(rep['snapshot_retained_packs']) >= 1, rep
        assert rep['dual_operator_verified'] is True, rep

        code_snap_read, _, _ = self.http(snap_loc, principal='reader', redirects=False)
        assert code_snap_read == 200, code_snap_read

        code_packs_post, _, raw_packs_post = self.http(f'/repos/{repack_repo}.git/packs', principal='reader')
        assert code_packs_post == 200, (code_packs_post, raw_packs_post)
        packs_post = json.loads(raw_packs_post.decode())
        assert packs_post['active_pack_count'] == 1 and packs_post['latest_repack'] is not None, packs_post

        repacked_clone = self.clone('repacked-clone', repo=repack_repo, principal='alice')
        assert self.git('rev-parse', 'HEAD', cwd=repacked_clone).stdout.strip() == c4_main
        unpin_rep = json.loads(self.cli('unpin-root', repack_repo, 'ci-release-pin'))
        assert unpin_rep['unpinned'] is True, unpin_rep

        return {
            'repack_id': rep['repack_id'],
            'packs_before': rep['packs_before'],
            'packs_after': rep['packs_after'],
            'unreachable_objects_pruned': rep['unreachable_objects_pruned'],
            'snapshot_retained_packs': len(rep['snapshot_retained_packs']),
        }

    def object_format_and_compat_matrix(self):
        det = json.loads(self.cli('object-format-detect', self.repo))
        assert det['object_format'] == 'sha1' and det['oid_hex_len'] == 40 and det['raw_oid_bytes'] == 20, det
        ver = json.loads(self.cli('verify-object-format', self.repo, '--format', 'sha1'))
        assert ver['verified'] is True and ver['packs_verified'] >= 1 and ver['dual_hashes_computed'] >= 2, ver
        mat = json.loads(self.cli('compat-matrix', self.repo, '--client-format', 'sha1', '--protocol-v2'))
        assert mat['passed'] is True and mat['negotiation_admitted'] is True, mat
        assert mat['sha1_pack_objects_verified'] >= 4 and mat['sha256_pack_objects_verified'] >= 4, mat

        code_get, _, raw_get = self.http(f'/repos/{self.repo}.git/object-format', principal='reader')
        assert code_get == 200, (code_get, raw_get)
        get_doc = json.loads(raw_get.decode())
        assert get_doc['object_format'] == 'sha1' and get_doc['protocol_v2_capability'] == 'object-format=sha1'

        code_conflict, _, raw_conflict = self.http(
            f'/repos/{self.repo}.git/object-format',
            principal='reader',
            method='POST',
            body=json.dumps({'client_object_format': 'sha256', 'protocol_version': 2}).encode(),
        )
        assert code_conflict == 409, (code_conflict, raw_conflict)
        conflict_doc = json.loads(raw_conflict.decode())
        assert conflict_doc['negotiation_admitted'] is False
        return {
            'detected_format': det['object_format'],
            'verified_objects': ver['objects_verified'],
            'sha256_pack_objects_verified': mat['sha256_pack_objects_verified'],
            'cross_format_rejected': True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard-pando-lab')
    parser.add_argument('--pg-share', default=os.environ.get('PG_SHARE'))
    args = parser.parse_args()
    lab = Lab(args)
    try:
        lab.setup()
        for name in (
            'roundtrip', 'acl_checks', 'atomic_checks', 'raw_atomic_native_rejection',
            'loopback_hostaddr', 'faults', 'cas', 'storage_fence', 'commit_acl_revocation',
            'isolation', 'snapshot', 'cold_restart', 'thin_pack', 'pack_integrity',
            'incremental_pack_deduplication', 'delta_and_graph_cli',
            'dual_operator_diff_export', 'refs_and_operations_api', 'orphan_and_snapshot_gc',
            'online_migration_state_machine', 'post_switchover_rollback_with_new_commits',
            'object_store_cas_and_cache_recovery', 'multi_pack_repack_and_pinned_gc',
            'object_format_and_compat_matrix',
        ):
            lab.check(name, getattr(lab, name))
        lab.results['passed'] = True
    except Exception:
        lab.results['failure'] = traceback.format_exc()
        raise
    finally:
        lab.cleanup()


if __name__ == '__main__':
    main()




