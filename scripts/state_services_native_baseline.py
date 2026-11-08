"""Bounded, real legacy Pando baseline; not new-backend qualification."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import platform
import math
from pathlib import Path
import random
import shutil
import statistics
import sys
import threading
import time
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

if not __debug__:
    raise RuntimeError('Native baseline requires Python assertions; do not use -O or PYTHONOPTIMIZE')

HARNESS_ROOT = Path(os.environ.get('ROOTYARD_BASELINE_HARNESS_ROOT', Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(HARNESS_ROOT / 'tests'))
from e2e import Harness

def validate_repository(repo, name, expected_id=None):
    value = repo.get('id')
    try:
        identity = uuid.UUID(value) if isinstance(value, str) else None
    except ValueError:
        identity = None
    if identity is None or identity.int == 0 or str(identity) != value:
        raise ValueError('repository response must contain a canonical non-nil UUID')
    if expected_id is not None and value != expected_id:
        raise ValueError('repository identity changed during provisioning')
    # Names and owner here are the fixed, harness-created fixture identities.
    if repo.get('name') != name or repo.get('clone_path') != '/git/alice/' + name + '.git':
        raise ValueError('repository response has an unexpected name or clone path')
    return value

def owned_cache_path(fixture_root, repository_id):
    identity = uuid.UUID(repository_id)
    if str(identity) != repository_id or identity.int == 0:
        raise ValueError('cache path requires a canonical repository UUID')
    owned = fixture_root.resolve()
    parent = owned / 'data' / 'pando-cache'
    cache = parent / repository_id
    if not parent.resolve().is_relative_to(owned) or cache.is_symlink() or cache.resolve().parent != parent.resolve():
        raise ValueError('disposable cache escapes its owned fixture directory')
    if not shutil.rmtree.avoids_symlink_attacks:
        raise RuntimeError('cache cleanup requires descriptor-safe rmtree')
    return cache

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def resources(pid):
    fields = {}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in ('VmRSS', 'VmHWM', 'Threads'):
            fields[key] = int(value.split()[0])
    fields['units'] = {'VmRSS': 'KiB', 'VmHWM': 'KiB', 'Threads': 'count'}
    return fields

def postgres_ports(pid, pg_port):
    inodes = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            value = os.readlink(fd)
        except FileNotFoundError:
            continue
        if value.startswith('socket:['):
            inodes.add(value[8:-1])
    ports = set()
    for table in ('tcp', 'tcp6'):
        for line in Path(f'/proc/{pid}/net/{table}').read_text().splitlines()[1:]:
            fields = line.split()
            if fields[9] in inodes and int(fields[2].rsplit(':', 1)[1], 16) == pg_port:
                ports.add(int(fields[1].rsplit(':', 1)[1], 16))
    return sorted(ports)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binary', required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--source-root', type=Path, required=True)
    args = p.parse_args()
    binary = Path(args.binary).resolve()
    receipt = json.loads(binary.with_suffix('.build.json').read_text())
    assert digest(binary) == receipt['binary_sha256']
    source_root = args.source_root.resolve()
    import importlib.util
    spec = importlib.util.spec_from_file_location('source_binding', HARNESS_ROOT / 'scripts/build_native.py')
    binding = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(binding)
    binding.ROOT = source_root
    assert binding.source_digest() == receipt['source_inputs_sha256']
    h = Harness(argparse.Namespace(binary=str(binary), keep=True))
    app_name = 'state_baseline_' + h.schema[-32:]
    parts = urlsplit(h.db)
    query = parse_qsl(parts.query) + [('application_name', app_name)]
    h.db = urlunsplit(parts._replace(query=urlencode(query)))
    h.env['DATABASE_URL'] = h.db
    report = {'version': 1, 'status': 'failed', 'profile': 'legacy-pando-s3-vault',
              'build_receipt': receipt, 'binary_bytes': binary.stat().st_size,
              'runner_sha256': digest(Path(__file__)), 'cases': [],
              'harness_sha256': digest(HARNESS_ROOT / 'tests/e2e.py'),
              'cargo_lock_sha256': digest(source_root / 'Cargo.lock'),
              'hardware': {'kernel': platform.release(), 'machine': platform.machine(),
                           'logical_cpus': os.cpu_count(), 'memory_total': next(
                               line.partition(':')[2].strip() for line in Path('/proc/meminfo').read_text().splitlines()
                               if line.startswith('MemTotal:')),
                           'scope': 'host-visible resources; not a reserved hardware allocation'},
              'provider_versions': {'garage': None, 'vault': None,
                                    'reason': 'service executable inspection unavailable to test uid'},
              'limits': ['One physical host, loopback PostgreSQL/Garage/Vault; no throughput or HA qualification.',
                         'Small fixed workload; no production latency objective inferred.',
                         'PG sampling every 250ms can miss short waits; observed peak is a lower bound.',
                         'Git materialization, internal lock wait, and Blob costs are not separately instrumented.'],
              'unmeasured': {'git_materialization_ms': None, 'blob_io_bytes': None,
                             'exact_lock_wait_ms': None, 'artifact_authority_contention_ms': None,
                             'native_git_cpu_seconds': None, 'peak_temp_disk_bytes': None}}
    samples, stop = [], threading.Event()
    sampler_errors = []
    def pg_sample():
        while not stop.is_set():
            try:
                proc = h.proc
                if proc is None or proc.poll() is not None:
                    stop.wait(.25)
                    continue
                ports = postgres_ports(proc.pid, urlsplit(h.db).port or 5432)
                if not ports:
                    stop.wait(.25)
                    continue
                raw = h.sql("SELECT count(*),count(*) FILTER (WHERE wait_event_type='Lock'),"
                            "count(*) FILTER (WHERE state='active') FROM pg_stat_activity WHERE "
                            "application_name='rootyard' AND client_port IN (" + ','.join(map(str, ports)) + ")")
                samples.append(tuple(map(int, raw.split('|'))))
            except Exception as error:
                sampler_errors.append(h.redact(error))
                return
            stop.wait(.25)
    def measure(label, function):
        begin = time.monotonic()
        value = function()
        report['cases'].append({'name': label, 'seconds': time.monotonic() - begin, 'status': 'passed'})
        return value
    try:
        measure('schema_accounts_server_ready', h.setup)
        report['idle_after_setup'] = resources(h.proc.pid)
        report['pg_version'] = h.sql('SHOW server_version')
        report['git_version'] = h.git('--version').stdout.decode().strip()
        sampler = threading.Thread(target=pg_sample, daemon=True)
        sampler.start()
        repos = []
        for idx in range(2):
            name = 'state-baseline-' + str(idx)
            code, body, _ = h.http('/api/repos', token=h.alice, method='POST', body={'name': name})
            assert code in (201, 202), code
            repo = json.loads(body)
            expected_id = validate_repository(repo, name)
            end = time.monotonic() + 30
            while repo['state'] != 'ready' and time.monotonic() < end:
                time.sleep(.1)
                code, body, _ = h.http('/api/repos/alice/' + name, token=h.alice)
                assert code == 200
                repo = json.loads(body)
                validate_repository(repo, name, expected_id)
            assert repo['state'] == 'ready'
            work = h.root / ('work-' + str(idx))
            h.git('init', '--initial-branch=main', str(work))
            h.git('config', 'user.name', 'State Baseline', cwd=work)
            h.git('config', 'user.email', 'baseline@example.invalid', cwd=work)
            (work / 'payload.bin').write_bytes(random.Random(105 + idx).randbytes(256 * 1024))
            h.git('add', '.', cwd=work)
            h.git('commit', '-m', 'fixed initial payload', cwd=work)
            remote = h.base + repo['clone_path']
            measure('gitfs_seed_push_' + str(idx), lambda: h.git('push', remote, 'HEAD:refs/heads/main', cwd=work, token=h.alice))
            repos.append((repo, work, remote))
        h.stop()
        for repo, work, remote in repos:
            measure('offline_pando_cutover_' + repo['name'], lambda: h.cli('pando-transition', 'cutover', '--repository', repo['id']))
        measure('pando_server_ready', h.start)
        report['idle_pando'] = resources(h.proc.pid)
        for idx, (repo, work, remote) in enumerate(repos):
            for n in range(3):
                (work / 'delta.txt').write_text('fixed update ' + str(n) + '\n')
                h.git('add', '.', cwd=work)
                h.git('commit', '-m', 'delta ' + str(n), cwd=work)
                measure('pando_serial_push_' + str(idx) + '_' + str(n), lambda: h.git('push', remote, 'HEAD:refs/heads/main', cwd=work, token=h.alice))
        def different_ref(item):
            idx, ref = item
            _, work, remote = repos[idx]
            return measure('pando_parallel_repo_' + str(idx) + '_ref_' + str(ref), lambda: h.git('push', remote, 'HEAD:refs/heads/parallel-' + str(ref), cwd=work, token=h.alice))
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(different_ref, [(idx, ref) for idx in range(2) for ref in range(4)]))
        # Actual new packs on different repos exercise shared artifact reservation.
        for idx, (_, work, _) in enumerate(repos):
            (work / 'cross-repo.txt').write_text('cross repo pack ' + str(idx))
            h.git('add', '.', cwd=work)
            h.git('commit', '-m', 'cross repo pack', cwd=work)
        def cross_repo(idx):
            _, work, remote = repos[idx]
            return measure('pando_cross_repo_new_pack_' + str(idx), lambda: h.git('push', remote, 'HEAD:refs/heads/main', cwd=work, token=h.alice))
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(cross_repo, range(2)))
        # Competing same-ref pushes: advertisements can observe different old OIDs.
        # This proves one winner, not a synchronized explicit-old-OID CAS race.
        _, work, remote = repos[0]
        old = h.git('rev-parse', 'HEAD', cwd=work).stdout.decode().strip()
        tree = h.git('rev-parse', 'HEAD^{tree}', cwd=work).stdout.decode().strip()
        contenders = [h.git('commit-tree', tree, '-p', old, '-m', 'contender ' + str(n), cwd=work).stdout.decode().strip() for n in range(2)]
        def contend(n):
            return measure('pando_same_ref_contender_' + str(n), lambda: h.git('push', remote, contenders[n] + ':refs/heads/main', cwd=work, token=h.alice, check=False))
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(contend, range(2)))
        winners = [n for n, result in enumerate(outcomes) if result.returncode == 0]
        assert len(winners) == 1, [result.returncode for result in outcomes]
        current = h.git('ls-remote', remote, 'refs/heads/main', token=h.alice).stdout.decode().split()[0]
        assert current == contenders[winners[0]]
        h.git('reset', '--hard', current, cwd=work)
        report['same_ref_result'] = {'contenders': 2, 'accepted': 1, 'rejected': 1, 'winner_read_back': True,
            'mode': 'ordinary competing Git pushes; advertised old OIDs are not synchronized'}
        measure('pando_atomic_two_refs', lambda: h.git('push', '--atomic', remote,
                'HEAD:refs/heads/atomic-a', 'HEAD:refs/heads/atomic-b', cwd=work, token=h.alice))
        atomic_refs = h.git('ls-remote', remote, 'refs/heads/atomic-*', token=h.alice).stdout.decode().splitlines()
        assert len(atomic_refs) == 2 and all(line.split()[0] == current for line in atomic_refs)
        h.stop()
        # Only the two exact, owned, documented disposable cache directories.
        for repo, _, _ in repos:
            cache = owned_cache_path(h.root, repo['id'])
            if cache.exists():
                shutil.rmtree(cache)
        h.start()
        for idx, (repo, work, remote) in enumerate(repos):
            expected = h.git('rev-parse', 'HEAD', cwd=work).stdout.strip()
            for temperature in ('cold', 'warm'):
                clone = h.root / ('clone-' + str(idx) + '-' + temperature)
                measure('pando_' + temperature + '_clone_' + str(idx), lambda: h.git('clone', remote, str(clone), token=h.alice))
                assert h.git('rev-parse', 'HEAD', cwd=clone).stdout.strip() == expected
                h.git('fsck', '--full', '--strict', cwd=clone)
        for n in range(12):
            def api():
                assert h.http('/api/repos', token=h.alice)[0] == 200
            measure('api_repo_list_' + str(n), api)
        report['final_resources'] = resources(h.proc.pid)
        groups = {'serial_push': 'pando_serial_push_', 'different_ref': 'pando_parallel_',
                  'cross_repo_new_pack': 'pando_cross_repo_', 'same_ref': 'pando_same_ref_',
                  'cold_clone': 'pando_cold_', 'warm_clone': 'pando_warm_', 'api_list': 'api_repo_list_'}
        report['latency_ms'] = {}
        for group, prefix in groups.items():
            values = sorted(item['seconds'] * 1000 for item in report['cases'] if item['name'].startswith(prefix))
            report['latency_ms'][group] = {'n': len(values), 'method': 'nearest rank; small-sample descriptive only',
                **{f'p{int(q*100)}': values[math.ceil(q*len(values))-1] for q in (.50, .95, .99)}}
        report['status'] = 'passed'
    except Exception as error:
        report['error'] = h.redact(error)
        raise
    finally:
        stop.set()
        if 'sampler' in locals():
            sampler.join(5)
            if sampler.is_alive():
                report['status'] = 'failed'
                report['sampler_error'] = 'sampler failed to stop'
        report['pg_samples'] = {'count': len(samples), 'peak_connections': max((s[0] for s in samples), default=None),
                                'peak_lock_waiters': max((s[1] for s in samples), default=None),
                                'peak_active': max((s[2] for s in samples), default=None), 'errors': sampler_errors}
        if not samples or not any(s[0] for s in samples):
            report['status'] = 'failed'
            report['pg_samples']['error'] = 'no owned API PostgreSQL sessions observed'
        if sampler_errors:
            report['status'] = 'failed'
        report['fixture_root'] = str(h.root)
        try:
            h.cleanup()
        except Exception as error:
            report['cleanup_error'] = h.redact(error)
            report['status'] = 'failed'
        report['binary_still_matches'] = digest(binary) == receipt['binary_sha256']
        report['source_still_matches'] = binding.source_digest() == receipt['source_inputs_sha256']
        if not report['source_still_matches']:
            report['status'] = 'failed'
        if not report['binary_still_matches']:
            report['status'] = 'failed'
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['status'] == 'passed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
