"""Native protocol/state extensions shared by the versioned client matrix."""
import hashlib
import json
import random
from pathlib import Path


class ClientFeatures:
    def filter_and_symbolic_refs(self):
        discovery = self.git('ls-remote', '--symref', self.remote, 'HEAD', token=self.alice).stdout.decode()
        assert 'ref: refs/heads/main\tHEAD' in discovery, discovery
        status, advertisement, _ = self.http(
            self.repo['clone_path'] + '/info/refs?service=git-upload-pack', token=self.alice)
        assert status == 200
        assert b'filter' not in advertisement, 'filter contract changed; add partial-clone acceptance'
        directory = self.root / 'filter-unsupported'
        attempt = self.git('clone', '--filter=blob:none', '--no-checkout',
                           self.remote, str(directory), token=self.alice)
        assert b'filtering not recognized by server' in attempt.stderr
        # Git falls back to a full clone. Record that as unsupported, never a
        # successful partial clone; prove objects are actually present locally.
        env = self.env.copy()
        env['GIT_NO_LAZY_FETCH'] = '1'
        blob = self.git('show', self.second + ':payload.bin', cwd=directory, env=env).stdout
        assert blob == (self.root / 'stock-v2' / 'payload.bin').read_bytes()
        return {'symbolic_head': discovery, 'partial_clone': 'unsupported',
                'filter_advertised': False, 'client_fallback': attempt.stderr.decode(),
                'full_blob_sha256': hashlib.sha256(blob).hexdigest(),
                'ssh': 'unsupported: no SSH endpoint is provided'}

    def sha256_clients(self):
        repository = json.loads(self.expect('/api/repos', 201, token=self.alice,
                                method='POST', body={'name': 'sha256-client', 'object_format': 'sha256'}))
        original_remote = self.remote
        self.remote = self.base + repository['clone_path']
        try:
            source = self.root / 'sha256-source'
            self.git('init', '--object-format=sha256', '-b', 'main', str(source))
            self.git('config', 'user.name', 'SHA256 compatibility', cwd=source)
            self.git('config', 'user.email', 'compat@example.invalid', cwd=source)
            payload = b'native SHA-256 hosting\n'
            (source / 'sha256.txt').write_bytes(payload)
            self.git('add', '.', cwd=source)
            self.git('commit', '-m', 'sha256 client', cwd=source)
            oid = self.git('rev-parse', 'HEAD', cwd=source).stdout.decode().strip()
            assert len(oid) == 64
            self.git('push', self.remote, 'HEAD:main', cwd=source, token=self.alice)
            clone = self.root / 'sha256-clone'
            self.git('clone', self.remote, str(clone), token=self.alice)
            assert self.git('rev-parse', '--show-object-format', cwd=clone).stdout.strip() == b'sha256'
            self.git('fsck', '--full', '--strict', cwd=clone)
            assert self.git('rev-parse', 'HEAD', cwd=clone).stdout.decode().strip() == oid
            assert (clone / 'sha256.txt').read_bytes() == payload
            independent = {}
            for client in ('jgit', 'libgit2'):
                result = self.independent(client, 'clone', self.root / (client + '-sha256'), check=False)
                assert result.returncode != 0, (
                    client + ' gained SHA256 support: add full interoperability tests before granting support')
                message = (result.stdout + result.stderr).decode(errors='replace')
                assert message.strip(), 'client failed without a diagnostic'
                self.expect('/health/ready', 200)
                observed = self.git('ls-remote', self.remote, 'refs/heads/main', token=self.alice).stdout.decode()
                assert observed.startswith(oid + '\t'), 'stock client no longer reads the same SHA256 repository'
                independent[client] = {'state': 'unsupported', 'exit_code': result.returncode,
                                       'reason': self.redact(message)}
            return {'stock_git': {'state': 'passed', 'head': oid, 'fsck': 0,
                                  'content_sha256': hashlib.sha256(payload).hexdigest()},
                    'independent_clients': independent}
        finally:
            self.remote = original_remote

    def thin_delta_pack(self):
        directory = self.root / 'delta-source'
        self.git('clone', self.remote, str(directory), token=self.alice)
        self.git('config', 'user.name', 'Pack compatibility', cwd=directory)
        self.git('config', 'user.email', 'compat@example.invalid', cwd=directory)
        base = random.Random(45).randbytes(64 * 1024)
        for index in range(24):
            value = bytearray(base)
            value[index * 256:index * 256 + 32] = bytes([index]) * 32
            (directory / f'delta-{index}.bin').write_bytes(value)
        self.git('add', '.', cwd=directory)
        self.git('commit', '-m', 'delta pack base', cwd=directory)
        self.git('push', self.remote, 'HEAD:refs/heads/delta-test', cwd=directory, token=self.alice)
        for index in range(24):
            with (directory / f'delta-{index}.bin').open('ab') as stream:
                stream.write(b'updated for thin pack\n')
        self.git('commit', '-am', 'thin delta update', cwd=directory)
        self.git('repack', '-adf', '--window=50', '--depth=50', cwd=directory)
        entries = []
        for index_file in (directory / '.git/objects/pack').glob('*.idx'):
            entries.extend(self.git('verify-pack', '-v', str(index_file), cwd=directory).stdout.decode().splitlines())
        deltas = [line for line in entries if len(line.split()) == 7 and line.split()[1] == 'blob']
        assert deltas, 'fixture produced no delta objects'
        trace = self.root / 'thin-push.trace'
        env = self.env.copy()
        env['GIT_TRACE_PACKET'] = str(trace)
        self.git('push', '--thin', self.remote, 'HEAD:refs/heads/delta-test',
                 cwd=directory, token=self.alice, env=env)
        target = self.git('rev-parse', 'HEAD', cwd=directory).stdout.decode().strip()
        clone = self.root / 'delta-clone'
        self.git('clone', '-b', 'delta-test', self.remote, str(clone), token=self.alice)
        self.git('fsck', '--full', '--strict', cwd=clone)
        digests = {}
        for index in range(24):
            name = f'delta-{index}.bin'
            assert (clone / name).read_bytes() == (directory / name).read_bytes()
            digests[name] = hashlib.sha256((clone / name).read_bytes()).hexdigest()
        return {'head': target, 'local_verified_delta_objects': len(deltas),
                'push_thin_requested': True, 'received_content_sha256': digests,
                'fsck': 0, 'packet_transcript': self.redact(trace.read_text())}

    def stock_lfs(self):
        directory = self.root / 'lfs-client'
        self.git('clone', self.remote, str(directory), token=self.alice)
        self.git('config', 'user.name', 'LFS compatibility', cwd=directory)
        self.git('config', 'user.email', 'compat@example.invalid', cwd=directory)
        self.git('lfs', 'install', '--local', cwd=directory)
        self.git('lfs', 'track', '*.asset', cwd=directory)
        payload = random.Random(41).randbytes(1024 * 1024)
        (directory / 'client.asset').write_bytes(payload)
        self.git('add', '.gitattributes', 'client.asset', cwd=directory)
        self.git('commit', '-m', 'LFS compatibility object', cwd=directory)
        self.git('push', self.remote, 'HEAD:refs/heads/lfs-client', cwd=directory, token=self.alice)
        clone = self.root / 'lfs-client-clone'
        self.git('clone', '-b', 'lfs-client', self.remote, str(clone), token=self.alice)
        self.git('lfs', 'install', '--local', cwd=clone)
        self.git('lfs', 'pull', cwd=clone, token=self.alice)
        assert (clone / 'client.asset').read_bytes() == payload
        self.git('fsck', '--full', '--strict', cwd=clone)
        self.git('lfs', 'fsck', cwd=clone)
        self.git('lfs', 'lock', 'client.asset', cwd=clone, token=self.alice)
        assert b'client.asset' in self.git('lfs', 'locks', cwd=clone, token=self.alice).stdout
        self.git('lfs', 'unlock', 'client.asset', cwd=clone, token=self.alice)
        return {'version': self.git('lfs', 'version').stdout.decode().strip(),
                'payload_sha256': hashlib.sha256(payload).hexdigest(),
                'stock_git_fsck': 0, 'stock_lfs_fsck': 0, 'lock_unlock': True}
