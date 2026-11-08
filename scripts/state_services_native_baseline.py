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
import socket
import statistics
import sys
import threading
import time
import urllib.request
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

# Fixed phase/outcome/bucket label sets mirrored from src/baseline_metrics.rs.
# The parser accepts nothing outside these sets, so a scrape can never inject an
# actor, repository, endpoint or error string into the report.
PHASE_LABELS = ('publication_slot', 'ref_advisory', 'pool_checkout', 'repo_publication_window',
                'state_row', 'authority_lock', 'native_git_prepare', 'native_git_fsck',
                'native_git_hydration', 'remote_put', 'remote_verified_readback', 'remote_get')
OUTCOME_LABELS = ('ok', 'error', 'cancelled')
BUCKET_LABELS = ('0.005', '0.01', '0.025', '0.05', '0.1', '0.25', '0.5', '1', '5', '30', '+Inf')
BASELINE_PREFIX = 'rootyard_baseline_'
PHASE_LIMITS = [
    'Exact SQL lock wait is still unmeasured: state_row and authority_lock are client round trips '
    'and include statement submission, PostgreSQL execution and row return.',
    'Values are per process. Counters reset across h.stop/h.start and are never differenced '
    'across processes; a case spanning a restart reports process_restarted instead of a delta.',
    'Phase spans nest (native_git_hydration contains remote GET and decrypt) and must not be summed.',
    'Bytes are logical payload of successful S3-backed transfers only; local-filesystem object '
    'storage emits no remote_* series, and retries, headers and TLS overhead are excluded.',
]


class MetricsRestart(ValueError):
    """Two samples come from different application processes."""


def _integral(number):
    if number != int(number) or number > (2 ** 64 - 1):
        raise ValueError('baseline counter must be an unsigned 64-bit integer')
    return int(number)


def _exact_labels(labels, expected):
    if set(labels) != set(expected):
        raise ValueError('unexpected label set for a baseline series')


def _baseline_sample(line):
    """Return (name, labels, value) for one baseline line, or None for a foreign line."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    name, separator, value = line.partition(' ')
    if not separator or not name:
        raise ValueError('malformed exposition line')
    if not name.startswith(BASELINE_PREFIX):
        return None
    labels = {}
    if '{' in name:
        name, _, tail = name.partition('{')
        if not tail.endswith('}'):
            raise ValueError('malformed baseline label set')
        for pair in tail[:-1].split(','):
            key, equals, raw = pair.partition('=')
            if not equals or len(raw) < 2 or not raw.startswith('"') or not raw.endswith('"'):
                raise ValueError('malformed baseline label pair')
            if key in labels or key not in ('phase', 'outcome', 'le'):
                raise ValueError('unexpected baseline label key')
            labels[key] = raw[1:-1]
    try:
        number = float(value.strip())
    except ValueError:
        raise ValueError('non-numeric baseline sample value') from None
    if not math.isfinite(number) or number < 0:
        raise ValueError('baseline sample value must be finite and non-negative')
    return name, labels, number


def parse_phase_metrics(text):
    """Parse only rootyard_baseline_* series; None means the feature is absent."""
    observations, outcomes, buckets, sums, counts, byte_counts = {}, {}, {}, {}, {}, {}
    seen = set()
    for line in text.splitlines():
        parsed = _baseline_sample(line)
        if parsed is None:
            continue
        name, labels, number = parsed
        key = (name, tuple(sorted(labels.items())))
        if key in seen:
            raise ValueError('duplicate baseline series')
        seen.add(key)
        phase = labels.get('phase')
        if phase not in PHASE_LABELS:
            raise ValueError('unexpected baseline phase label')
        if name == 'rootyard_baseline_phase_observations_total':
            _exact_labels(labels, ('phase',))
            observations[phase] = _integral(number)
        elif name == 'rootyard_baseline_phase_outcomes_total':
            _exact_labels(labels, ('outcome', 'phase'))
            if labels['outcome'] not in OUTCOME_LABELS:
                raise ValueError('unexpected baseline outcome label')
            outcomes.setdefault(phase, {})[labels['outcome']] = _integral(number)
        elif name == 'rootyard_baseline_phase_duration_seconds_bucket':
            _exact_labels(labels, ('le', 'phase'))
            if labels['le'] not in BUCKET_LABELS:
                raise ValueError('unexpected baseline histogram bucket')
            buckets.setdefault(phase, {})[labels['le']] = _integral(number)
        elif name == 'rootyard_baseline_phase_duration_seconds_sum':
            _exact_labels(labels, ('phase',))
            sums[phase] = number
        elif name == 'rootyard_baseline_phase_duration_seconds_count':
            _exact_labels(labels, ('phase',))
            counts[phase] = _integral(number)
        elif name == 'rootyard_baseline_phase_bytes_total':
            _exact_labels(labels, ('phase',))
            byte_counts[phase] = _integral(number)
        else:
            raise ValueError('unexpected baseline series name')
    if not seen:
        return None
    phases = {}
    for phase in PHASE_LABELS:
        if (phase not in observations or phase not in sums or phase not in counts
                or phase not in byte_counts or set(outcomes.get(phase, ())) != set(OUTCOME_LABELS)
                or set(buckets.get(phase, ())) != set(BUCKET_LABELS)):
            raise ValueError('baseline series incomplete for a fixed phase')
        total = observations[phase]
        if counts[phase] != total or sum(outcomes[phase].values()) != total:
            raise ValueError('baseline observation count disagrees with outcomes/count')
        previous = 0
        for label in BUCKET_LABELS:
            value = buckets[phase][label]
            if value < previous:
                raise ValueError('baseline histogram buckets are not cumulative')
            previous = value
        if previous != total:
            raise ValueError('baseline +Inf bucket disagrees with the observation count')
        phases[phase] = {'observations': total, 'outcomes': dict(outcomes[phase]),
                         'buckets': dict(buckets[phase]), 'sum_seconds': sums[phase],
                         'count': counts[phase], 'bytes': byte_counts[phase]}
    return {'phases': phases}


def sample_delta(before, after):
    """Per-phase delta between two samples of the same process; rejects regressions."""
    if before['identity'] != after['identity']:
        raise MetricsRestart('application process changed; counters are not comparable')
    delta = {}
    for phase in PHASE_LABELS:
        left, right = before['sample']['phases'][phase], after['sample']['phases'][phase]
        entry = {
            'observations': right['observations'] - left['observations'],
            'outcomes': {name: right['outcomes'][name] - left['outcomes'][name] for name in OUTCOME_LABELS},
            'bytes': right['bytes'] - left['bytes'],
            'duration_seconds': {
                'buckets': {label: right['buckets'][label] - left['buckets'][label] for label in BUCKET_LABELS},
                'sum': round(right['sum_seconds'] - left['sum_seconds'], 9),
                'count': right['count'] - left['count'],
            },
        }
        values = [entry['observations'], entry['bytes'], entry['duration_seconds']['sum']]
        values.extend(entry['outcomes'].values())
        values.extend(entry['duration_seconds']['buckets'].values())
        values.append(entry['duration_seconds']['count'])
        if min(values) < 0:
            raise ValueError('baseline counter regressed within one process')
        delta[phase] = entry
    return delta


def loopback_metrics_port():
    """Allocate one fixture-owned ephemeral loopback port; no external address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    if not 1024 < port < 65536:
        raise ValueError('fixture could not allocate an unprivileged loopback port')
    return port


def process_identity(pid):
    """(pid, kernel start time) distinguishes a restarted process from the same pid."""
    fields = Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()
    return {'pid': pid, 'starttime': int(fields[19])}


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """The exporter is a fixed loopback origin: a redirect is a failure, never a hop."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError('metrics endpoint must not redirect (status ' + str(code) + ')')


PHASE_CASE_STATUSES = ('captured', 'not_applicable', 'offline', 'service_stopped',
                       'process_restarted', 'unavailable', 'feature_disabled')
UNEXPECTED_CASE_STATUSES = ('service_stopped', 'process_restarted', 'unavailable', 'feature_disabled')


def phase_metrics_accounting(cases):
    """Group per-case phase-metrics statuses so a run cannot silently lose a case."""
    counts, unexpected = {}, []
    for case in cases:
        entry = case.get('phase_metrics')
        if entry is None:
            raise ValueError('case ' + str(case.get('name')) + ' has no phase metrics accounting')
        status = entry.get('status')
        if status not in PHASE_CASE_STATUSES:
            raise ValueError('unexpected phase metrics status: ' + str(status))
        counts[status] = counts.get(status, 0) + 1
        if status in UNEXPECTED_CASE_STATUSES:
            unexpected.append(case.get('name'))
    return {'cases': len(cases), 'by_status': counts, 'unexpected': unexpected}


def same_ref_rejection_diagnostic(result):
    """Prove the non-winning contender was rejected as a Git ref update, not by a transport fault."""
    if result.returncode == 0:
        raise AssertionError('the non-winning contender unexpectedly exited zero')
    text = (result.stderr or b'').decode('utf-8', 'replace').lower()
    for forbidden in ('authentication failed', 'could not read username', 'unable to access',
                      'connection refused', 'connection timed out', 'proxy', 'ssl'):
        if forbidden in text:
            raise AssertionError('non-winning contender failed for a non-ref reason: ' + forbidden)
    for expected in ('failed to update ref', 'fetch first',
                     'non-fast-forward', 'cannot lock ref', 'stale info'):
        if expected in text:
            return expected
    raise AssertionError('non-winning contender reports no Git ref rejection')


class PhaseMetricsCapture:
    """Opt-in before/after scrape of the private loopback exporter, per process."""

    def __init__(self, port, timeout=2.0):
        self.port = port
        self.url = 'http://127.0.0.1:' + str(port) + '/metrics'
        self.timeout = timeout
        self.status = 'ready'
        self.reason = None
        self.scrapes = 0
        self.scrape_seconds = []
        self.processes = []

    def _scrape(self, pid):
        if self.status != 'ready':
            return None
        begin = time.monotonic()
        identity = process_identity(pid)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RefuseRedirect())
        with opener.open(self.url, timeout=self.timeout) as response:
            if response.status != 200:
                raise ValueError('metrics endpoint returned status ' + str(response.status))
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError('metrics exposition exceeds fixture bound')
            text = raw.decode('utf-8')
        if process_identity(pid) != identity:
            raise MetricsRestart('application process changed during scrape')
        self.scrape_seconds.append(time.monotonic() - begin)
        self.scrapes += 1
        sample = parse_phase_metrics(text)
        if sample is None:
            self.status = 'feature_disabled'
            self.reason = ('exporter answered but exported no ' + BASELINE_PREFIX + '* series; '
                           'the binary was built without the state-baseline-metrics feature')
            return None
        return {'identity': identity, 'sample': sample}

    def fail(self, reason):
        """Mark the capture unusable for the rest of the run; the report status fails."""
        if self.status == 'ready':
            self.status = 'partial'
        self.reason = reason

    def _failed(self, error):
        self.status = 'unavailable'
        self.reason = 'metrics scrape failed: ' + type(error).__name__
        return {'status': self.status, 'reason': self.reason}

    def observe_start(self, pid):
        self.processes.append({'event': 'start', 'identity': process_identity(pid)})

    def close_process(self, pid, event):
        """Capture the process one last time before it is stopped or torn down."""
        try:
            sample = self._scrape(pid)
        except Exception as error:
            return self._failed(error)
        if sample is None:
            return {'status': self.status, 'reason': self.reason}
        record = {'event': event, 'identity': sample['identity'],
                  'observations': {phase: sample['sample']['phases'][phase]['observations'] for phase in PHASE_LABELS}}
        self.processes.append(record)
        return record

    def open_case(self, pid):
        if self.status != 'ready':
            return {'status': self.status, 'reason': self.reason}
        try:
            sample = self._scrape(pid)
        except Exception as error:
            return self._failed(error)
        if sample is None:
            return {'status': self.status, 'reason': self.reason}
        return {'status': 'sampled', 'sample': sample}

    def close_case(self, pid, marker):
        if marker.get('status') != 'sampled':
            return marker
        try:
            after = self._scrape(pid)
        except Exception as error:
            return self._failed(error)
        if after is None:
            return {'status': self.status, 'reason': self.reason}
        try:
            delta = sample_delta(marker['sample'], after)
        except MetricsRestart as error:
            self.fail('phase metrics lost process continuity during a case: ' + str(error))
            return {'status': 'process_restarted', 'reason': str(error)}
        return {'status': 'captured', 'identity': after['identity'], 'phases': delta,
                'note': 'phase spans nest and are not additive; the scrape adds one pooled SQL '
                        'snapshot outside this case'}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binary', required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--phase-metrics', action='store_true',
                   help='capture per-process phase metrics from the private loopback listener of a '
                        'state-baseline-metrics build')
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
    capture = None
    if args.phase_metrics:
        capture = PhaseMetricsCapture(loopback_metrics_port())
        # Private loopback bind only; the fixture allocates the port, nothing external is contacted.
        h.env['ROOTYARD_METRICS_BIND'] = '127.0.0.1:' + str(capture.port)
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
                         'Phase spans and successful payload bytes require --phase-metrics; exact CPU/lock-wait costs remain unmeasured.'],
              'unmeasured': {'git_materialization_ms': None, 'blob_io_bytes': None,
                             'exact_lock_wait_ms': None, 'artifact_authority_contention_ms': None,
                             'native_git_cpu_seconds': None, 'peak_temp_disk_bytes': None}}
    report['concurrent_wall_times'] = {}
    report['interpretation'] = {
        'schema_version': 1, 'measurement_revision': 2,
        'concurrent_measurement': 'Each concurrent batch (different-ref, cross-repo new pack, competing '
            'same-ref) is bracketed by exactly one measure()/scrape pair. Per-push worker wall times are '
            'reported separately and are not phase attributed, so concurrent phase deltas are never '
            'divided, summed or compared per push.',
        'historical_v1': 'Earlier v1 reports recorded one measure() per concurrent push. Those per-case '
            'phase deltas overlap in the process-global counters and are INVALID for individual or batch '
            'aggregation; they remain only as historical raw data. A v2 run replaces them.',
        'same_ref_rejection': 'The non-winning contender is reported only with a Git ref-rejection '
            'diagnostic (remote rejected / non-fast-forward / failed to update ref / stale info); an '
            'authentication or transport failure fails the run and is never counted as a ref rejection. '
            'This is ordinary competing pushes, not an explicit-old-OID CAS assertion.'}
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
    def measure(label, function, phase_skip=None):
        if capture is None:
            marker = None
        elif phase_skip is not None:
            marker = {'status': phase_skip[0], 'reason': phase_skip[1]}
        elif h.proc is None or h.proc.poll() is not None:
            marker = {'status': 'service_stopped', 'reason': 'no running application process to scrape'}
        else:
            marker = capture.open_case(h.proc.pid)
        begin = time.monotonic()
        value = function()
        entry = {'name': label, 'seconds': time.monotonic() - begin, 'status': 'passed'}
        if marker is not None:
            if marker.get('status') == 'sampled' and (h.proc is None or h.proc.poll() is not None):
                capture.fail('application process ended during the sampled case ' + label)
                entry['phase_metrics'] = {'status': 'service_stopped',
                    'reason': 'application process ended during the case; no comparable delta'}
            else:
                entry['phase_metrics'] = capture.close_case(h.proc.pid if h.proc is not None else None, marker)
        report['cases'].append(entry)
        return value

    def setup_app():
        h.setup()
        if capture is not None:
            capture.observe_start(h.proc.pid)

    def stop_app():
        # Capture the running process before it is signalled, so no delta spans a restart.
        if capture is not None and h.proc is not None and h.proc.poll() is None:
            capture.close_process(h.proc.pid, 'stop')
        h.stop()

    def start_app():
        h.start()
        if capture is not None:
            capture.observe_start(h.proc.pid)
    try:
        measure('schema_accounts_server_ready', setup_app,
                phase_skip=('not_applicable', 'setup creates the schema and starts the process'))
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
            measure('gitfs_seed_push_' + str(idx), lambda: h.git('push', remote, 'HEAD:refs/heads/main', cwd=work, token=h.alice),
                    phase_skip=('not_applicable', 'legacy GitFS backend; Pando phases are not exercised'))
            repos.append((repo, work, remote))
        stop_app()
        for repo, work, remote in repos:
            measure('offline_pando_cutover_' + repo['name'], lambda: h.cli('pando-transition', 'cutover', '--repository', repo['id']),
                    phase_skip=('offline', 'service stopped for the offline cutover CLI; no process metrics'))
        measure('pando_server_ready', start_app,
                phase_skip=('not_applicable', 'process start lifecycle; the stop/start capture brackets it'))
        report['idle_pando'] = resources(h.proc.pid)
        for idx, (repo, work, remote) in enumerate(repos):
            for n in range(3):
                (work / 'delta.txt').write_text('fixed update ' + str(n) + '\n')
                h.git('add', '.', cwd=work)
                h.git('commit', '-m', 'delta ' + str(n), cwd=work)
                measure('pando_serial_push_' + str(idx) + '_' + str(n), lambda: h.git('push', remote, 'HEAD:refs/heads/main', cwd=work, token=h.alice))
        # One bracket for the whole batch: per-operation measure() calls overlap, so their
        # process-global counter deltas are invalid for per-push or batch aggregation.
        parallel_wall = []
        def different_ref(item):
            idx, ref = item
            _, work, remote = repos[idx]
            begin = time.monotonic()
            result = h.git('push', remote, 'HEAD:refs/heads/parallel-' + str(ref), cwd=work, token=h.alice)
            parallel_wall.append({'case': 'pando_parallel_repo_' + str(idx) + '_ref_' + str(ref),
                                  'worker_seconds': time.monotonic() - begin})
            return result
        def different_ref_batch():
            with ThreadPoolExecutor(max_workers=4) as pool:
                return list(pool.map(different_ref, [(idx, ref) for idx in range(2) for ref in range(4)]))
        measure('pando_parallel_repo_batch', different_ref_batch)
        report['concurrent_wall_times']['pando_parallel_repo_batch'] = {
            'mode': 'per-push worker wall time; not phase attributed', 'pushes': parallel_wall}
        # Actual new packs on different repos exercise shared artifact reservation.
        for idx, (_, work, _) in enumerate(repos):
            (work / 'cross-repo.txt').write_text('cross repo pack ' + str(idx))
            h.git('add', '.', cwd=work)
            h.git('commit', '-m', 'cross repo pack', cwd=work)
        cross_wall = []
        def cross_repo(idx):
            _, work, remote = repos[idx]
            begin = time.monotonic()
            result = h.git('push', remote, 'HEAD:refs/heads/main', cwd=work, token=h.alice)
            cross_wall.append({'case': 'pando_cross_repo_new_pack_' + str(idx),
                               'worker_seconds': time.monotonic() - begin})
            return result
        def cross_repo_batch():
            with ThreadPoolExecutor(max_workers=2) as pool:
                return list(pool.map(cross_repo, range(2)))
        measure('pando_cross_repo_new_pack_batch', cross_repo_batch)
        report['concurrent_wall_times']['pando_cross_repo_new_pack_batch'] = {
            'mode': 'per-push worker wall time; not phase attributed', 'pushes': cross_wall}
        # Competing same-ref pushes: advertisements can observe different old OIDs.
        # This proves one winner, not a synchronized explicit-old-OID CAS race.
        _, work, remote = repos[0]
        old = h.git('rev-parse', 'HEAD', cwd=work).stdout.decode().strip()
        tree = h.git('rev-parse', 'HEAD^{tree}', cwd=work).stdout.decode().strip()
        contenders = [h.git('commit-tree', tree, '-p', old, '-m', 'contender ' + str(n), cwd=work).stdout.decode().strip() for n in range(2)]
        same_ref_wall = []
        def contend(n):
            begin = time.monotonic()
            result = h.git('push', remote, contenders[n] + ':refs/heads/main', cwd=work, token=h.alice, check=False)
            same_ref_wall.append({'case': 'pando_same_ref_contender_' + str(n),
                                  'worker_seconds': time.monotonic() - begin,
                                  'returncode': result.returncode})
            return result
        def contend_batch():
            with ThreadPoolExecutor(max_workers=2) as pool:
                return list(pool.map(contend, range(2)))
        outcomes = measure('pando_same_ref_contenders_batch', contend_batch)
        report['concurrent_wall_times']['pando_same_ref_contenders_batch'] = {
            'mode': 'per-push worker wall time; not phase attributed', 'pushes': same_ref_wall}
        winners = [n for n, result in enumerate(outcomes) if result.returncode == 0]
        losers = [n for n, result in enumerate(outcomes) if result.returncode != 0]
        assert len(winners) == 1 and len(losers) == 1, [result.returncode for result in outcomes]
        # The loser must be a Git ref rejection, never an auth or transport failure.
        loser_diagnostic = same_ref_rejection_diagnostic(outcomes[losers[0]])
        current = h.git('ls-remote', remote, 'refs/heads/main', token=h.alice).stdout.decode().split()[0]
        assert current == contenders[winners[0]]
        h.git('reset', '--hard', current, cwd=work)
        report['same_ref_result'] = {'contenders': 2, 'accepted': 1, 'rejected': 1, 'winner_read_back': True,
            'loser_returncode': outcomes[losers[0]].returncode,
            'loser_rejection': loser_diagnostic,
            'loser_rejection_is_git_ref_rejection': True,
            'mode': 'ordinary competing Git pushes; advertised old OIDs are not synchronized; the loser is '
                    'proven by a Git ref-rejection diagnostic rather than a nonzero exit code, and this is '
                    'not an explicit-old-OID CAS claim'}
        measure('pando_atomic_two_refs', lambda: h.git('push', '--atomic', remote,
                'HEAD:refs/heads/atomic-a', 'HEAD:refs/heads/atomic-b', cwd=work, token=h.alice))
        atomic_refs = h.git('ls-remote', remote, 'refs/heads/atomic-*', token=h.alice).stdout.decode().splitlines()
        assert len(atomic_refs) == 2 and all(line.split()[0] == current for line in atomic_refs)
        stop_app()
        # Only the two exact, owned, documented disposable cache directories.
        for repo, _, _ in repos:
            cache = owned_cache_path(h.root, repo['id'])
            if cache.exists():
                shutil.rmtree(cache)
        start_app()
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
        concurrent_groups = ('different_ref', 'cross_repo_new_pack', 'same_ref')
        for group, prefix in groups.items():
            values = sorted(item['seconds'] * 1000 for item in report['cases'] if item['name'].startswith(prefix))
            if not values:
                report['latency_ms'][group] = {'n': 0, 'method': 'not measured in this run'}
                continue
            report['latency_ms'][group] = {'n': len(values),
                'unit': ('batch wall time; not per push and not phase attributed' if group in concurrent_groups
                         else 'single operation wall time'),
                'method': 'nearest rank; small-sample descriptive only',
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
        if capture is not None:
            if h.proc is not None and h.proc.poll() is None:
                capture.close_process(h.proc.pid, 'final')
            overhead = capture.scrape_seconds
            report['phase_metrics'] = {
                'enabled': True, 'feature': 'state-baseline-metrics',
                'endpoint': {'bind': '127.0.0.1', 'port': capture.port, 'path': '/metrics',
                             'scope': 'private loopback listener allocated by the fixture; never external'},
                'status': capture.status, 'reason': capture.reason, 'scrapes': capture.scrapes,
                'scrape_overhead_ms': {
                    'median': round(statistics.median(overhead) * 1000, 3) if overhead else None,
                    'max': round(max(overhead) * 1000, 3) if overhead else None,
                    'note': 'each scrape takes one pooled PostgreSQL connection and runs one SQL '
                            'snapshot statement outside the instrumented spans, so before/after '
                            'scrapes perturb the case slightly'},
                'phase_limits': PHASE_LIMITS, 'processes': capture.processes}
            report['phase_metrics']['accounting'] = phase_metrics_accounting(report['cases'])
            if report['phase_metrics']['accounting']['unexpected']:
                report['status'] = 'failed'
            if capture.status != 'ready':
                report['status'] = 'failed'
                report['phase_metrics']['error'] = capture.reason
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
