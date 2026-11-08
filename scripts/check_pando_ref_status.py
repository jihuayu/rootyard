#!/usr/bin/env python3
"""Focused root-run issue126 native acceptance harness (Pando ref status).

Only a root-supplied binary/build receipt/source tree and the execution
environment are used.  The runner does not invoke Cargo, Docker, services,
FUSE, kernel controls or a push.  It creates one disposable PostgreSQL schema
through the existing tests/e2e.py Harness, seeds a GitFS repository, cuts it
over to Pando, then drives real stock Git clients through an owned, bounded
loopback HTTP proxy.

A response drop after the upstream COMMIT/200 is an UNKNOWN TRANSPORT outcome,
never a rejection or abort.  HTTP 409 is likewise recorded as an HTTP failure,
not as proof that receive-pack sent `ng`.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import socket
import socketserver
import sys
import threading
import time
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

if not __debug__:
    raise RuntimeError('native harness requires Python assertions; do not use -O or PYTHONOPTIMIZE')

CASE_INVENTORY = (
    'legacy_pando_setup',
    'same_old_oid_two_stock_clients_one_winner',
    'loser_negotiated_sideband_ng_reason',
    'atomic_multiref_rejection_no_ref_changed',
    'auth_failure_distinct_from_refusal',
    'post_commit_response_lost_unknown_transport',
    'source_binary_runner_stable',
)

MAX_REQUEST_BODY = 16 * 1024 * 1024
MAX_RESPONSE_BODY = 8 * 1024 * 1024
MAX_HEAD = 64 * 1024
MAX_HEADERS = 64
MAX_CAPTURE_PREFIX = 8192
SOCKET_TIMEOUT = 60.0
GATE_TIMEOUT = 30.0
PUSH_TIMEOUT = 120
MAX_PROXY_THREADS = 4
MAX_PROXY_RECORDS = 64
MAX_PROXY_CAPTURED_BYTES = 32 * 1024 * 1024
MAX_PROXY_ERRORS = 32
MAX_PROXY_THREAD_JOIN_SECONDS = 5.0
MAX_ATOMIC_ERROR_BODY = 4096
MAX_DIAGNOSTIC_STDERR_CHARS = 1200
MAX_DIAGNOSTIC_RECORD_COUNT = 12
MAX_DIAGNOSTIC_ERROR_COUNT = 6
MAX_DIAGNOSTIC_FIELD_CHARS = 240
SAFE_PROXY_RECORD_KEYS = frozenset({
    'label', 'method', 'path', 'is_receive_post', 'is_receive_advertisement',
    'authorization_header_present', 'gated', 'dropped', 'upstream_status', 'response_bytes',
    'body_has_unpack_ok', 'body_has_ng', 'request_protocol', 'report', 'report_error', 'recorded',
})
ATOMIC_HEAD_DELETE_REASON = 'cannot delete the advertised HEAD ref; retarget HEAD first'


class HarnessFailure(RuntimeError):
    pass


class DiagnosticFailure(HarnessFailure):
    """Failure carrying bounded, redacted, body/header-free diagnostics."""

    def __init__(self, message, diagnostics):
        super().__init__(message)
        self.diagnostics = diagnostics


def require(condition, message):
    if not condition:
        raise HarnessFailure(message)


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def safe_error(harness, error):
    text = traceback.format_exc() if not isinstance(error, HarnessFailure) else str(error)
    if harness is not None:
        try:
            text = harness.redact(text)
        except Exception:
            pass
    return text[-4000:]


def load_binding(source_root):
    path = source_root / 'scripts' / 'build_native.py'
    spec = importlib.util.spec_from_file_location('rootyard_native_binding', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = source_root
    return module


def load_harness(source_root):
    tests = source_root / 'tests'
    sys.path.insert(0, str(tests))
    from e2e import Harness
    return Harness


def verify_build(args, binding):
    binary = Path(args.binary).resolve()
    require(binary.is_file(), 'binary does not exist')
    receipt_path = binary.with_suffix('.build.json')
    require(receipt_path.is_file(), 'build receipt is missing beside the binary')
    receipt = json.loads(receipt_path.read_text())
    require(receipt.get('version') == 1, 'unsupported build receipt version')
    actual = digest(binary)
    require(actual == receipt.get('binary_sha256'), 'binary digest does not match its build receipt')
    source = binding.source_digest()
    require(source == receipt.get('source_inputs_sha256'),
            'source inputs do not match the built binary receipt')
    return binary, receipt_path, receipt, actual, source



def record_case(report, name, function, harness):
    started = time.monotonic()
    entry = {'name': name, 'status': 'failed'}
    try:
        detail = function()
        entry['status'] = 'passed'
        if detail is not None:
            entry['detail'] = detail
    except Exception as error:
        entry['error'] = safe_error(harness, error)
        diagnostics = getattr(error, 'diagnostics', None)
        if diagnostics is not None:
            entry['diagnostics'] = diagnostics
    entry['seconds'] = round(time.monotonic() - started, 4)
    report['cases'].append(entry)
    return entry['status']


def remote_main(harness, remote):
    output = harness.git('ls-remote', remote, 'refs/heads/main', token=harness.alice).stdout.decode()
    lines = [line for line in output.splitlines() if line.strip()]
    require(len(lines) == 1, 'expected exactly one advertised refs/heads/main')
    oid, name = lines[0].split('\t', 1)
    require(name == 'refs/heads/main' and re.fullmatch(r'[0-9a-f]{40,64}', oid), 'malformed ls-remote main line')
    return oid


def all_refs(harness, remote):
    output = harness.git('ls-remote', remote, token=harness.alice).stdout.decode()
    refs = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        oid, name = line.split('\t', 1)
        refs[name] = oid
    return refs


def clone(harness, remote, path, label):
    harness.git('clone', remote, str(path), token=harness.alice)
    harness.git('config', 'user.name', 'Issue126 ' + label, cwd=path)
    harness.git('config', 'user.email', label + '@example.invalid', cwd=path)
    return path


def commit_file(harness, work, filename, text, message):
    (work / filename).write_text(text)
    harness.git('add', filename, cwd=work)
    harness.git('commit', '-m', message, cwd=work)
    oid = harness.git('rev-parse', 'HEAD', cwd=work).stdout.decode().strip()
    require(re.fullmatch(r'[0-9a-f]{40,64}', oid) is not None, 'commit did not produce a canonical OID')
    return oid


def read_line(stream, limit):
    data = bytearray()
    while len(data) <= limit:
        chunk = stream.read(1)
        if not chunk:
            raise HarnessFailure('unexpected EOF while reading HTTP line')
        data += chunk
        if chunk == b'\n':
            return bytes(data)
    raise HarnessFailure('HTTP line exceeded its bound')


class BufferedSocket:
    def __init__(self, sock, initial=b''):
        self.sock = sock
        self.buffer = bytearray(initial)

    def read(self, size):
        if self.buffer:
            count = min(size, len(self.buffer))
            out = bytes(self.buffer[:count])
            del self.buffer[:count]
            return out
        return self.sock.recv(size)

    def read_exact(self, size):
        out = bytearray()
        while len(out) < size:
            chunk = self.read(size - len(out))
            if not chunk:
                raise HarnessFailure('unexpected EOF in HTTP body')
            out += chunk
        return bytes(out)

    def readline(self, limit):
        out = bytearray()
        while len(out) < limit:
            chunk = self.read(1)
            if not chunk:
                raise HarnessFailure('unexpected EOF in HTTP header')
            out += chunk
            if chunk == b'\n':
                return bytes(out)
        raise HarnessFailure('HTTP header line exceeded its bound')


def read_head(stream, request=True):
    first = stream.readline(MAX_HEAD)
    if request:
        line = first.decode('latin1').rstrip('\r\n')
        fields = line.split(' ')
        require(len(fields) == 3 and fields[2].startswith('HTTP/1.'), 'malformed HTTP request line')
    headers = []
    total = len(first)
    while True:
        line = stream.readline(MAX_HEAD)
        total += len(line)
        require(total <= MAX_HEAD, 'HTTP headers exceeded their bound')
        if line in (b'\r\n', b'\n'):
            break
        text = line.decode('latin1').rstrip('\r\n')
        name, separator, value = text.partition(':')
        require(separator == ':' and name and '\x00' not in text, 'malformed HTTP header')
        headers.append((name, value.strip()))
        require(len(headers) <= MAX_HEADERS, 'too many HTTP headers')
    return first, headers


def header_map(headers):
    mapped = {}
    for name, value in headers:
        mapped.setdefault(name.lower(), value)
    return mapped


def relay_request_body(client, upstream, headers, capture_limit):
    captured = bytearray()
    total = 0

    def forward(chunk):
        nonlocal total
        if not chunk:
            return
        if total + len(chunk) > MAX_REQUEST_BODY:
            raise HarnessFailure('request body exceeded its bound')
        upstream.sendall(chunk)
        total += len(chunk)
        if len(captured) < capture_limit:
            captured.extend(chunk[:capture_limit - len(captured)])

    transfer = headers.get('transfer-encoding', '').lower()
    if transfer == 'chunked':
        while True:
            line = client.readline(1024)
            forward(line)
            size_text = line.split(b';', 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError as error:
                raise HarnessFailure('malformed chunked request body') from error
            require(0 <= size <= MAX_REQUEST_BODY, 'chunked request chunk exceeded its bound')
            if size == 0:
                trailer_total = 0
                while True:
                    trailer = client.readline(MAX_HEAD)
                    trailer_total += len(trailer)
                    require(trailer_total <= MAX_HEAD, 'chunked request trailers exceeded their bound')
                    forward(trailer)
                    if trailer in (b'\r\n', b'\n'):
                        break
                break
            forward(client.read_exact(size))
            forward(client.read_exact(2))
    else:
        raw_length = headers.get('content-length')
        require(raw_length is not None, 'POST without Content-Length or chunked encoding')
        try:
            length = int(raw_length)
        except ValueError as error:
            raise HarnessFailure('malformed Content-Length') from error
        require(0 <= length <= MAX_REQUEST_BODY, 'request body exceeded its bound')
        remaining = length
        while remaining:
            chunk = client.read(min(65536, remaining))
            if not chunk:
                raise HarnessFailure('unexpected EOF in request body')
            forward(chunk)
            remaining -= len(chunk)
    return bytes(captured)


def read_chunked(stream, limit):
    out = bytearray()
    while True:
        line = stream.readline(1024)
        size_text = line.split(b';', 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as error:
            raise HarnessFailure('malformed chunked response body') from error
        require(0 <= size <= limit and len(out) + size <= limit, 'chunked response exceeded its bound')
        if size == 0:
            trailer_total = 0
            while True:
                trailer = stream.readline(MAX_HEAD)
                trailer_total += len(trailer)
                require(trailer_total <= MAX_HEAD, 'response trailers exceeded their bound')
                if trailer in (b'\r\n', b'\n'):
                    return bytes(out)
        out += stream.read_exact(size)
        require(stream.read_exact(2) in (b'\r\n', b'\n'), 'malformed chunk terminator')


def read_response(upstream):
    while True:
        first_line, headers = read_head(upstream, request=False)
        require(len(first_line) <= 4096, 'HTTP status line exceeded its bound')
        status_line = first_line.decode('latin1').rstrip('\r\n')
        fields = status_line.split(' ', 2)
        require(len(fields) >= 2 and fields[0].startswith('HTTP/1.'), 'malformed HTTP status line')
        try:
            status = int(fields[1])
        except ValueError as error:
            raise HarnessFailure('malformed HTTP status code') from error
        if 100 <= status < 200:
            continue
        break
    mapped = header_map(headers)
    if status in (204, 304) or 100 <= status < 200:
        body = b''
    elif mapped.get('transfer-encoding', '').lower() == 'chunked':
        body = read_chunked(upstream, MAX_RESPONSE_BODY)
    elif 'content-length' in mapped:
        try:
            length = int(mapped['content-length'])
        except ValueError as error:
            raise HarnessFailure('malformed response Content-Length') from error
        require(0 <= length <= MAX_RESPONSE_BODY, 'response body exceeded its bound')
        body = upstream.read_exact(length) if length else b''
    else:
        out = bytearray()
        while True:
            chunk = upstream.read(65536)
            if not chunk:
                break
            require(len(out) + len(chunk) <= MAX_RESPONSE_BODY, 'response body exceeded its bound')
            out += chunk
        body = bytes(out)
    return status_line, status, headers, body


def pktline_payloads(stream, require_end=True):
    payloads = []
    offset = 0
    terminated = False
    while offset + 4 <= len(stream):
        header = stream[offset:offset + 4]
        if header == b'0000':
            offset += 4
            terminated = True
            break
        if header in (b'0001', b'0002'):
            raise HarnessFailure('unexpected special pkt-line packet')
        try:
            length = int(header, 16)
        except ValueError as error:
            raise HarnessFailure('non-hex pkt-line header') from error
        require(4 <= length <= 65520, 'pkt-line length outside protocol bound')
        require(offset + length <= len(stream), 'truncated pkt-line')
        payloads.append(stream[offset + 4:offset + length])
        offset += length
        require(len(payloads) <= 8192, 'too many pkt-lines')
    require(terminated, 'pkt-line stream missing flush')
    if require_end:
        require(offset == len(stream), 'pkt-line stream has trailing bytes')
    return payloads


def parse_receive_request(prefix):
    payloads = pktline_payloads(prefix, require_end=False)
    require(payloads, 'receive request contained no command pkt-line')
    refs = []
    capabilities = {'report_status': False, 'report_status_v2': False,
                    'sideband_64k': False, 'atomic': False}
    for index, payload in enumerate(payloads):
        body = payload[:-1] if payload.endswith(b'\n') else payload
        capability_bytes = b''
        if b'\x00' in body:
            body, capability_bytes = body.split(b'\x00', 1)
        fields = body.split(b' ')
        require(len(fields) == 3, 'malformed receive command')
        old, new, name = fields
        require(re.fullmatch(rb'[0-9a-fA-F]{40,64}', old) and re.fullmatch(rb'[0-9a-fA-F]{40,64}', new),
                'receive command has a non-canonical OID')
        require(name.startswith(b'refs/') and b'\x00' not in name and all(byte > 32 for byte in name),
                'receive command has an invalid ref name')
        refs.append(name.decode('ascii'))
        if index == 0:
            for token in capability_bytes.split(b' '):
                if token == b'report-status':
                    capabilities['report_status'] = True
                elif token == b'report-status-v2':
                    capabilities['report_status_v2'] = True
                elif token == b'side-band-64k':
                    capabilities['sideband_64k'] = True
                elif token == b'atomic':
                    capabilities['atomic'] = True
    require(refs, 'receive request advertised no refs')
    return {'refs': refs, 'capabilities': capabilities}


def parse_advertisement(body, content_encoding):
    encoding = (content_encoding or '').lower()
    if encoding not in ('', 'identity'):
        return {'parsed': False, 'reason': 'advertisement used a non-identity content encoding'}
    payloads = []
    offset = 0
    sections = 0
    try:
        while offset + 4 <= len(body):
            header = body[offset:offset + 4]
            if header == b'0000':
                offset += 4
                sections += 1
                continue
            if header in (b'0001', b'0002'):
                raise HarnessFailure('unexpected special packet')
            length = int(header, 16)
            if not 4 <= length <= 65520 or offset + length > len(body):
                raise HarnessFailure('malformed advertisement pkt-line')
            payloads.append(body[offset + 4:offset + length])
            offset += length
            if len(payloads) > 8192:
                raise HarnessFailure('too many advertisement packets')
        if offset != len(body) or sections == 0:
            raise HarnessFailure('advertisement was incomplete')
    except (ValueError, HarnessFailure):
        return {'parsed': False, 'reason': 'advertisement was not a complete pkt-line stream'}
    refs = {}
    capability_count = 0
    for payload in payloads:
        text = payload.decode('latin1').rstrip('\n')
        if text.startswith('# service=') or text.startswith('version '):
            continue
        body_text, separator, caps = text.partition('\x00')
        fields = body_text.split(' ')
        if len(fields) != 2:
            continue
        oid, name = fields
        if not re.fullmatch(r'[0-9a-fA-F]{40,64}', oid) or not name.startswith('refs/'):
            continue
        refs[name] = oid.lower()
        if separator:
            capability_count = len(caps.split(' '))
    return {'parsed': True, 'refs': refs, 'ref_count': len(refs),
            'main_oid': refs.get('refs/heads/main'), 'capability_count': capability_count}


def parse_status_report(body, capabilities):
    report = {'sideband_negotiated': bool(capabilities.get('sideband_64k'))}
    if report['sideband_negotiated']:
        outer = pktline_payloads(body)
        inner = bytearray()
        bands = set()
        progress_packets = 0
        for payload in outer:
            require(payload, 'empty sideband packet')
            band = payload[0]
            bands.add(band)
            if band == 1:
                inner += payload[1:]
            elif band == 2:
                progress_packets += 1
            else:
                raise HarnessFailure('unexpected sideband channel in status report')
        report['bands'] = sorted(bands)
        report['progress_packets'] = progress_packets
        require(1 in bands, 'negotiated sideband report carried no band-1 status')
        status_packets = pktline_payloads(bytes(inner))
    else:
        status_packets = pktline_payloads(body)
    lines = []
    for packet in status_packets:
        text = packet.decode('latin1')
        require(text.endswith('\n'), 'status pkt-line is unterminated')
        line = text[:-1]
        if line.startswith('option ') and (capabilities.get('report_status_v2')):
            continue
        lines.append(line)
    require(lines and lines[0] == 'unpack ok', 'status report does not begin with unpack ok')
    statuses = {'ok': [], 'ng': []}
    for line in lines[1:]:
        if line.startswith('ok '):
            statuses['ok'].append(line[3:])
        elif line.startswith('ng '):
            rest = line[3:]
            ref, separator, reason = rest.partition(' ')
            require(separator == ' ' and ref and reason, 'ng line has no ref or reason')
            require(all(32 <= ord(char) < 127 for char in reason), 'ng reason has a control byte')
            require(len(reason) <= 256, 'ng reason exceeded its bound')
            statuses['ng'].append((ref, reason))
        else:
            raise HarnessFailure('unrecognized receive status line')
    report['ok'] = statuses['ok']
    report['ng'] = statuses['ng']
    report['reason'] = statuses['ng'][0][1] if statuses['ng'] else None
    report['accepted'] = bool(statuses['ok'])
    report['refused'] = bool(statuses['ng'])
    return report


class TwoWayGate:
    def __init__(self, expected=2, timeout=GATE_TIMEOUT):
        self.expected = expected
        self.timeout = timeout
        self.lock = threading.Lock()
        self.event = threading.Event()
        self.arrived = 0
        self.overflow = 0
        self.timed_out = False
        self.labels = []

    def arrive(self, label):
        with self.lock:
            if self.arrived < self.expected:
                self.arrived += 1
                claimed = True
                self.labels.append(label)
                if self.arrived == self.expected:
                    self.event.set()
            else:
                self.overflow += 1
                claimed = False
        if claimed and not self.event.wait(self.timeout):
            with self.lock:
                self.timed_out = True
            raise HarnessFailure('two-way advertisement barrier timed out')

    def snapshot(self):
        with self.lock:
            return {'expected': self.expected, 'arrived': self.arrived,
                    'overflow': self.overflow, 'released': self.event.is_set(),
                    'timed_out': self.timed_out, 'labels': list(self.labels),
                    'scope': 'only successful authenticated receive-pack advertisement GETs are gated'}


def _safe_proxy_message(error):
    text = str(error).replace('\\', '/')[:300]
    return type(error).__name__ + ': ' + text

def safe_proxy_snapshot(proxy):
    try:
        snapshot = proxy.snapshot()
    except Exception as error:
        return {'label': getattr(proxy, 'label', 'unknown'), 'records': [],
                'errors': ['snapshot: ' + _safe_proxy_message(error)]}
    # Diagnostics retain status/counts only: no response bodies or header values.
    snapshot['records'] = [
        {key: value for key, value in item.items() if key in SAFE_PROXY_RECORD_KEYS}
        for item in (snapshot.get('records') or [])]
    return snapshot


def _diagnostic_text(harness, value, limit=MAX_DIAGNOSTIC_FIELD_CHARS):
    text = '' if value is None else str(value)
    if harness is not None:
        try:
            text = harness.redact(text)
        except Exception as error:
            text = 'redaction_failed: ' + _safe_proxy_message(error)
    return text[:limit]


def _diagnostic_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _diagnostic_record(record):
    protocol = record.get('request_protocol')
    request_summary = None
    if isinstance(protocol, dict):
        refs = protocol.get('refs')
        capabilities = protocol.get('capabilities')
        request_summary = {
            'parsed': bool(refs),
            'ref_count': len(refs) if isinstance(refs, list) else 0,
            'refs': [str(item)[:MAX_DIAGNOSTIC_FIELD_CHARS] for item in (refs or [])[:16]],
            'capabilities': ({key: bool(value) for key, value in capabilities.items()}
                             if isinstance(capabilities, dict) else None),
        }
    report = record.get('report')
    report_summary = None
    if isinstance(report, dict):
        report_summary = {
            'accepted': bool(report.get('accepted')),
            'refused': bool(report.get('refused')),
            'ok': [str(item)[:MAX_DIAGNOSTIC_FIELD_CHARS] for item in (report.get('ok') or [])[:16]],
            'ng_refs': [str(item[0])[:MAX_DIAGNOSTIC_FIELD_CHARS]
                        for item in (report.get('ng') or [])[:16]
                        if isinstance(item, (list, tuple)) and item],
        }
    return {'post': bool(record.get('is_receive_post')),
            'advertisement': bool(record.get('is_receive_advertisement')),
            'gated': bool(record.get('gated')),
            'dropped': bool(record.get('dropped')),
            'upstream_status': _diagnostic_int(record.get('upstream_status')),
            'authorization_header_present': bool(record.get('authorization_header_present')),
            'response_bytes': _diagnostic_int(record.get('response_bytes')),
            'body_has_unpack_ok': bool(record.get('body_has_unpack_ok')),
            'body_has_ng': bool(record.get('body_has_ng')),
            'request': request_summary,
            'report': report_summary,
            'report_error': (str(record.get('report_error'))[:MAX_DIAGNOSTIC_FIELD_CHARS]
                             if record.get('report_error') else None)}


def proxy_diagnostics(harness, snapshot):
    records = snapshot.get('records') or []
    errors = snapshot.get('errors') or []
    return {'label': _diagnostic_text(harness, snapshot.get('label'), 64),
            'record_count': len(records),
            'post_count': sum(1 for item in records if item.get('is_receive_post')),
            'advertisement_count': sum(1 for item in records if item.get('is_receive_advertisement')),
            'records': [_diagnostic_record(item) for item in records[-MAX_DIAGNOSTIC_RECORD_COUNT:]],
            'errors': [_diagnostic_text(harness, item, 400)
                       for item in errors[:MAX_DIAGNOSTIC_ERROR_COUNT]],
            'errors_dropped': _diagnostic_int(snapshot.get('errors_dropped')),
            'records_dropped': _diagnostic_int(snapshot.get('records_dropped')),
            'sensitive_values_recorded': False}


def case_diagnostics(harness, label, push, snapshot, extra=None):
    raw_stderr = getattr(push, 'stderr', b'') or b''
    try:
        stderr_text = raw_stderr.decode(errors='replace')
    except Exception as error:
        stderr_text = 'decode_failed: ' + _safe_proxy_message(error)
    diagnostics = {
        'case': label,
        'client_returncode': _diagnostic_int(getattr(push, 'returncode', None)),
        'stock_git_stderr_tail_bounded_redacted': _diagnostic_text(
            harness, stderr_text[-MAX_DIAGNOSTIC_STDERR_CHARS:], MAX_DIAGNOSTIC_STDERR_CHARS),
        'proxy': proxy_diagnostics(harness, snapshot),
    }
    if extra:
        diagnostics.update(extra)
    return diagnostics


def close_proxy(proxy):
    try:
        proxy.close()
    except Exception as error:
        proxy.note_error('close: ' + _safe_proxy_message(error))


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self._handle()
        except Exception as error:
            self.server.note_error(_safe_proxy_message(error))

    def _handle(self):
        server = self.server
        client = self.request
        client.settimeout(SOCKET_TIMEOUT)
        client_stream = BufferedSocket(client)
        first_line, header_list = read_head(client_stream, request=True)
        request_line = first_line.decode('latin1').rstrip('\r\n')
        method, target, _version = request_line.split(' ')
        headers = header_map(header_list)
        parsed_target = urllib.parse.urlsplit(target)
        path = parsed_target.path
        query = dict(urllib.parse.parse_qsl(parsed_target.query, keep_blank_values=True))
        receive_post = method.upper() == 'POST' and path.endswith('/git-receive-pack')
        receive_ad = (method.upper() == 'GET' and path.endswith('/info/refs')
                      and query.get('service') == 'git-receive-pack')
        record = {'label': server.label, 'method': method.upper(), 'path': path,
                  'is_receive_post': receive_post, 'is_receive_advertisement': receive_ad,
                  'authorization_header_present': 'authorization' in headers,
                  'gated': False, 'dropped': False}
        upstream = socket.create_connection(server.upstream, timeout=SOCKET_TIMEOUT)
        upstream.settimeout(SOCKET_TIMEOUT)
        try:
            forwarded = []
            for name, value in header_list:
                lower = name.lower()
                if lower in ('connection', 'proxy-connection', 'keep-alive', 'expect',
                             'accept-encoding', 'transfer-encoding', 'content-length', 'host'):
                    continue
                forwarded.append((name, value))
            forwarded.append(('Host', '127.0.0.1:' + str(server.upstream[1])))
            transfer = headers.get('transfer-encoding', '').lower()
            if transfer == 'chunked':
                forwarded.append(('Transfer-Encoding', 'chunked'))
            elif 'content-length' in headers:
                forwarded.append(('Content-Length', headers['content-length']))
            forwarded.append(('Connection', 'close'))
            head = (method + ' ' + target + ' HTTP/1.1\r\n' +
                    ''.join(name + ': ' + value + '\r\n' for name, value in forwarded) + '\r\n').encode('latin1')
            upstream.sendall(head)
            body_prefix = b''
            if method.upper() in ('POST', 'PUT', 'PATCH'):
                if '100-continue' in headers.get('expect', '').lower():
                    client.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
                body_prefix = relay_request_body(client_stream, upstream, headers, MAX_CAPTURE_PREFIX)
            response_stream = BufferedSocket(upstream)
            status_line, status, response_headers, body = read_response(response_stream)
            mapped = header_map(response_headers)
            record['upstream_status'] = status
            record['content_type'] = mapped.get('content-type')
            record['response_bytes'] = len(body)
            record['_body'] = body
            record['body_has_unpack_ok'] = b'unpack ok' in body
            record['body_has_ng'] = b'ng refs/' in body
            if receive_post:
                try:
                    record['request_protocol'] = parse_receive_request(body_prefix)
                except Exception as error:
                    record['request_protocol'] = {'parsed': False, 'reason': _safe_proxy_message(error)}
                protocol = record.get('request_protocol') or {}
                if status == 200 and protocol.get('capabilities'):
                    try:
                        record['report'] = parse_status_report(body, protocol['capabilities'])
                    except Exception as error:
                        record['report_error'] = _safe_proxy_message(error)
            if receive_ad:
                record['advertisement'] = parse_advertisement(body, mapped.get('content-encoding'))
            if receive_ad and status == 200 and record['authorization_header_present'] and server.gate is not None:
                record['gated'] = True
                try:
                    server.gate.arrive(server.label)
                except Exception as error:
                    server.note_error(_safe_proxy_message(error))
            if server.drop_receive_response and receive_post:
                record['dropped'] = True
                record['recorded'] = True
                server.add_record(record)
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return
            out_headers = []
            for name, value in response_headers:
                if name.lower() in ('connection', 'keep-alive', 'transfer-encoding', 'content-length'):
                    continue
                out_headers.append((name, value))
            out_headers.append(('Content-Length', str(len(body))))
            out_headers.append(('Connection', 'close'))
            wire = (status_line + '\r\n' +
                    ''.join(name + ': ' + value + '\r\n' for name, value in out_headers) + '\r\n').encode('latin1') + body
            client.sendall(wire)
        finally:
            if not record.get('recorded'):
                server.add_record(record)
            try:
                upstream.close()
            except OSError:
                pass


def require_proxy_clean(snapshot, label):
    errors = snapshot.get('errors') or []
    require(not errors, label + ' proxy error(s): ' + '; '.join(str(item)[:160] for item in errors[:4]))
    require(snapshot.get('records_dropped', 0) == 0, label + ' proxy dropped records at its bound')
    require(snapshot.get('errors_dropped', 0) == 0, label + ' proxy dropped error messages at its bound')
    require(snapshot.get('live_threads', 0) == 0, label + ' proxy retained live handler threads')


class LoopbackProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, upstream, label, gate=None, drop_receive_response=False):
        self.upstream = upstream
        self.label = label
        self.gate = gate
        self.drop_receive_response = drop_receive_response
        self.records = []
        self.errors = []
        self.captured_bytes = 0
        self.records_dropped = 0
        self.errors_dropped = 0
        self.threads_started = 0
        self.live_threads = set()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(MAX_PROXY_THREADS)
        self._closed = False
        super().__init__(('127.0.0.1', 0), _ProxyHandler)
        self.serve_thread = threading.Thread(target=self.serve_forever, kwargs={'poll_interval': 0.2}, daemon=True)
        self.serve_thread.start()

    @property
    def url(self):
        return 'http://127.0.0.1:' + str(self.server_address[1])

    def _note_error_locked(self, message):
        if len(self.errors) < MAX_PROXY_ERRORS:
            self.errors.append(message[:400])
        else:
            self.errors_dropped = min(self.errors_dropped + 1, 1_000_000)

    def note_error(self, message):
        with self.lock:
            self._note_error_locked(message)

    def add_record(self, record):
        stored = dict(record)
        with self.lock:
            if len(self.records) >= MAX_PROXY_RECORDS:
                self.records_dropped = min(self.records_dropped + 1, 1_000_000)
                self._note_error_locked('proxy record cap exceeded; record not retained')
                return False
            body = stored.get('_body')
            if isinstance(body, (bytes, bytearray)):
                if self.captured_bytes + len(body) > MAX_PROXY_CAPTURED_BYTES:
                    stored.pop('_body', None)
                    stored['response_body_retained'] = False
                    self._note_error_locked('proxy captured-body cap exceeded; response body not retained')
                else:
                    stored['_body'] = bytes(body)
                    stored['response_body_retained'] = True
                    self.captured_bytes += len(body)
            else:
                stored['response_body_retained'] = True
            self.records.append(stored)
            return True

    def snapshot(self):
        with self.lock:
            return {'label': self.label, 'url_port': self.server_address[1],
                    'records': [{key: value for key, value in item.items() if not key.startswith('_')}
                                for item in self.records],
                    'errors': list(self.errors), 'errors_dropped': self.errors_dropped,
                    'records_dropped': self.records_dropped,
                    'captured_body_bytes': self.captured_bytes,
                    'live_threads': len(self.live_threads),
                    'threads_started': self.threads_started,
                    'limits': {'max_records': MAX_PROXY_RECORDS,
                               'max_captured_body_bytes': MAX_PROXY_CAPTURED_BYTES,
                               'max_threads': MAX_PROXY_THREADS,
                               'max_errors': MAX_PROXY_ERRORS}}

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.note_error('proxy thread admission bound exceeded; accepted socket closed')
            try:
                request.close()
            except OSError:
                pass
            return
        with self.lock:
            if len(self.live_threads) >= MAX_PROXY_THREADS:
                self._note_error_locked('proxy live-thread bound exceeded; accepted socket closed')
                self.slots.release()
                try:
                    request.close()
                except OSError:
                    pass
                return
            thread = threading.Thread(target=self._run_handler, args=(request, client_address), daemon=True)
            self.live_threads.add(thread)
            self.threads_started = min(self.threads_started + 1, 1_000_000)
        try:
            thread.start()
        except Exception as error:
            with self.lock:
                self.live_threads.discard(thread)
            self.slots.release()
            self.note_error('proxy thread start failed: ' + _safe_proxy_message(error))
            try:
                request.close()
            except OSError:
                pass

    def _run_handler(self, request, client_address):
        try:
            self.process_request_thread(request, client_address)
        except Exception as error:
            self.note_error('proxy handler dispatch failed: ' + _safe_proxy_message(error))
        finally:
            with self.lock:
                self.live_threads.discard(threading.current_thread())
            self.slots.release()

    def handle_error(self, request, client_address):
        self.note_error('proxy unhandled request error')

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.shutdown()
        self.server_close()
        deadline = time.monotonic() + MAX_PROXY_THREAD_JOIN_SECONDS
        while True:
            with self.lock:
                live = list(self.live_threads)
            if not live:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                with self.lock:
                    self._note_error_locked('proxy shutdown deadline exceeded with ' +
                                            str(len(live)) + ' live handler thread(s)')
                break
            for thread in live:
                thread.join(timeout=min(0.2, max(0.0, deadline - time.monotonic())))
        self.serve_thread.join(timeout=2)
        if self.serve_thread.is_alive():
            self.note_error('proxy serve thread did not stop before deadline')


def setup_legacy_pando(harness, state):
    harness.setup()
    repo = harness.create_repository({'name': 'retstatus-cas'}, token=harness.alice)
    require(repo.get('state') == 'ready', 'repository was not ready after provisioning')
    require(repo.get('clone_path') == '/git/alice/retstatus-cas.git', 'unexpected clone path')
    direct = harness.base + repo['clone_path']
    seed = harness.root / 'seed'
    harness.git('init', '--initial-branch=main', str(seed))
    harness.git('config', 'user.name', 'Issue126 Seed', cwd=seed)
    harness.git('config', 'user.email', 'seed@example.invalid', cwd=seed)
    (seed / 'seed.txt').write_text('issue126 ref status seed\n')
    harness.git('add', 'seed.txt', cwd=seed)
    harness.git('commit', '-m', 'seed GitFS commit', cwd=seed)
    seed_oid = harness.git('rev-parse', 'HEAD', cwd=seed).stdout.decode().strip()
    require(re.fullmatch(r'[0-9a-f]{40,64}', seed_oid) is not None, 'seed commit OID is not canonical')
    harness.git('push', direct, 'HEAD:refs/heads/main', cwd=seed, token=harness.alice)
    require(remote_main(harness, direct) == seed_oid, 'GitFS seed push did not publish main')

    state.update({'harness': harness, 'repo': repo, 'direct': direct, 'seed_oid': seed_oid})
    harness.stop()
    try:
        harness.cli('pando-transition', 'cutover', '--repository', repo['id'])
    finally:
        harness.start()
    require(remote_main(harness, direct) == seed_oid, 'Pando cutover changed the authoritative main OID')

    clients = {}
    for label in ('a', 'b'):
        work = clone(harness, direct, harness.root / ('client-' + label), 'client-' + label)
        require(harness.git('rev-parse', 'HEAD', cwd=work).stdout.decode().strip() == seed_oid,
                'client clone did not start at the advertised old OID')
        clients[label] = work
    oid_a = commit_file(harness, clients['a'], 'client-a.txt', 'differing client A\n', 'client A contender')
    oid_b = commit_file(harness, clients['b'], 'client-b.txt', 'differing client B\n', 'client B contender')
    require(oid_a != oid_b, 'the two contenders did not produce differing commits')
    for label, oid in (('a', oid_a), ('b', oid_b)):
        parent = harness.git('rev-parse', 'HEAD~1', cwd=clients[label]).stdout.decode().strip()
        require(parent == seed_oid, 'a contender is not based on the advertised old OID')
    state.update({'clients': clients, 'oid_a': oid_a, 'oid_b': oid_b, 'setup_ok': True})
    return {'repository_id': repo['id'], 'clone_path': repo['clone_path'], 'seed_oid': seed_oid,
            'contender_oids': [oid_a, oid_b], 'mode': 'GitFS seed, offline Pando cutover, stock Git clones'}


def run_same_old_race(harness, state):
    direct = state['direct']
    seed_oid = state['seed_oid']
    require(remote_main(harness, direct) == seed_oid, 'main moved before the synchronized race')
    for label, oid in (('a', state['oid_a']), ('b', state['oid_b'])):
        require(harness.git('rev-parse', 'HEAD~1', cwd=state['clients'][label]).stdout.decode().strip() == seed_oid,
                'client ' + label.upper() + ' basis is not the current advertised old OID')
        require(harness.git('rev-parse', 'HEAD', cwd=state['clients'][label]).stdout.decode().strip() == oid,
                'client ' + label.upper() + ' HEAD is not its expected contender commit')
    gate = TwoWayGate(2, GATE_TIMEOUT)
    upstream = ('127.0.0.1', harness.port)
    proxies = [LoopbackProxy(upstream, 'client-a', gate=gate),
               LoopbackProxy(upstream, 'client-b', gate=gate)]
    outcomes = []
    try:
        urls = [proxy.url + state['repo']['clone_path'] for proxy in proxies]

        def push_one(index):
            return harness.git('push', urls[index], 'HEAD:refs/heads/main',
                               cwd=state['clients'][('a', 'b')[index]],
                               token=harness.alice, check=False)

        with ThreadPoolExecutor(max_workers=2, thread_name_prefix='issue126-push') as pool:
            futures = [pool.submit(push_one, index) for index in range(2)]
            for index, future in enumerate(futures):
                result = future.result(timeout=PUSH_TIMEOUT)
                outcomes.append({'index': index, 'client': ('a', 'b')[index],
                                 'commit': (state['oid_a'], state['oid_b'])[index],
                                 'returncode': result.returncode,
                                 'stderr_tail': harness.redact(result.stderr.decode(errors='replace'))[-3000:]})
    finally:
        for proxy in proxies:
            close_proxy(proxy)
        snapshots = [safe_proxy_snapshot(proxy) for proxy in proxies]

    advertisements = {}
    posts = {}
    for index, (proxy, snapshot) in enumerate(zip(proxies, snapshots)):
        client = ('a', 'b')[index]
        raw = list(proxy.records)
        ads = [item for item in raw if item.get('is_receive_advertisement')]
        advertisement = [item.get('advertisement') for item in ads]
        advertisements[client] = {
            'count': len(ads),
            'statuses': [item.get('upstream_status') for item in ads],
            'authorized': [bool(item.get('authorization_header_present')) for item in ads],
            'parsed': advertisement,
            'gated': [bool(item.get('gated')) for item in ads],
        }
        receive_posts = [item for item in raw if item.get('is_receive_post')]
        post_details = []
        for item in receive_posts:
            protocol = item.get('request_protocol')
            report = None
            report_error = None
            if item.get('upstream_status') == 200 and isinstance(item.get('_body'), (bytes, bytearray)):
                try:
                    report = parse_status_report(bytes(item['_body']), protocol.get('capabilities', {}))
                except Exception as error:
                    report_error = _safe_proxy_message(error)
            post_details.append({'upstream_status': item.get('upstream_status'),
                                 'content_type': item.get('content_type'),
                                 'response_bytes': item.get('response_bytes'),
                                 'request_protocol': protocol, 'report': report,
                                 'report_error': report_error})
        posts[client] = post_details
    result = {
        'pre_old_oid': seed_oid,
        'outcomes': outcomes,
        'advertisements': advertisements,
        'posts': posts,
        'gate': gate.snapshot(),
        'readback_after_race': remote_main(harness, direct),
        'proxy_snapshots': snapshots,
        'mode': ('two real stock Git push processes; each authenticated 200 advertisement response '
                 'was held by an owned loopback proxy until both arrived, so both commands carried '
                 'the same advertised old OID; not an unsynchronized parallel push'),
    }
    state['race'] = result
    return result


def _one(items, message):
    require(len(items) == 1, message + '; observed ' + str(len(items)))
    return items[0]


def validate_cas_result(harness, state):
    result = state.get('race')
    require(result is not None, 'blocked: synchronized race capture is unavailable: ' + str(state.get('race_error')))
    for snapshot in result['proxy_snapshots']:
        require_proxy_clean(snapshot, snapshot.get('label', 'unknown'))
    outcomes = result['outcomes']
    require(len(outcomes) == 2, 'race did not return exactly two stock Git outcomes')
    winners = [item for item in outcomes if item['returncode'] == 0]
    require(len(winners) == 1, 'expected exactly one accepted stock Git push; returncodes=' +
            str([item['returncode'] for item in outcomes]))
    loser = [item for item in outcomes if item['returncode'] != 0]
    require(len(loser) == 1, 'expected exactly one losing stock Git push')
    winner = winners[0]
    loser = loser[0]

    advertised = []
    for client in ('a', 'b'):
        entry = result['advertisements'][client]
        require(entry['count'] >= 1, client + ' issued no receive-pack advertisement GET')
        require(all(status == 200 for status in entry['statuses']),
                client + ' advertisement was not HTTP 200')
        require(all(entry['authorized']), client + ' advertisement was not authenticated')
        require(all(isinstance(item, dict) and item.get('parsed') for item in entry['parsed']),
                client + ' advertisement body was not parseable pkt-line output')
        oids = {item.get('main_oid') for item in entry['parsed']}
        require(len(oids) == 1 and None not in oids, client + ' advertisement had no single main OID')
        advertised.append(oids.pop())
        require(all(entry['gated']), client + ' successful advertisement did not pass the barrier')
    require(advertised[0] == advertised[1] == result['pre_old_oid'],
            'the two clients did not advertise the same old OID')
    gate = result['gate']
    require(gate['arrived'] == 2 and gate['released'] and not gate['timed_out'] and gate['overflow'] == 0,
            'advertisement barrier did not prove two synchronized authenticated GETs')

    winner_post = _one(result['posts'][winner['client']], 'winner receive POST count')
    require(winner_post['upstream_status'] == 200, 'winner receive POST was not HTTP 200')
    winner_report = winner_post['report']
    require(winner_report is not None, 'winner report could not be parsed: ' + str(winner_post['report_error']))
    require('refs/heads/main' in winner_report['ok'], 'winner report did not accept refs/heads/main')
    require(not winner_report['ng'], 'winner report contained ng')

    readback = result['readback_after_race']
    require(readback == winner['commit'], 'readback does not equal the winning new commit')

    loser_post = _one(result['posts'][loser['client']], 'loser receive POST count')
    status = loser_post['upstream_status']
    if status != 200:
        raise HarnessFailure(
            'loser receive POST returned HTTP ' + str(status) +
            '; an HTTP error (including 409) is not negotiated receive-pack refusal proof')
    loser_report = loser_post['report']
    require(loser_report is not None, 'loser report could not be parsed: ' + str(loser_post['report_error']))
    require(loser_report['refused'], 'loser report contained no ng')
    require(_one(loser_report['ng'], 'loser ng line count')[0] == 'refs/heads/main',
            'loser ng did not name refs/heads/main')
    reason = loser_report['reason']
    require(reason and len(reason) <= 256, 'loser ng reason was empty or oversized')
    require(not loser_report['accepted'], 'loser report also contained an ok line')
    stderr = loser['stderr_tail']
    require('[remote rejected]' in stderr, 'stock Git did not report a remote rejection')
    require(reason in stderr, 'stock Git did not surface the server ng reason')

    return {'winner_client': winner['client'], 'winner_commit': winner['commit'],
            'loser_client': loser['client'], 'loser_commit': loser['commit'],
            'advertised_old_oid_both': advertised[0], 'both_advertisements_authenticated_200': True,
            'readback_equals_winner': True, 'winner_http_status': 200,
            'winner_report_accepted_main': True, 'loser_http_status': 200,
            'loser_ng_ref': 'refs/heads/main', 'loser_ng_reason': reason,
            'loser_stock_git_remote_rejected': True,
            'http_409_is_not_refusal_proof': True, 'mode': result['mode'], 'gate': gate}


def validate_sideband_result(harness, state):
    result = state.get('race')
    require(result is not None, 'blocked: synchronized race capture is unavailable: ' + str(state.get('race_error')))
    for snapshot in result['proxy_snapshots']:
        require_proxy_clean(snapshot, snapshot.get('label', 'unknown'))
    outcomes = result['outcomes']
    losers = [item for item in outcomes if item['returncode'] != 0]
    require(len(losers) == 1, 'sideband case needs exactly one losing stock Git push')
    loser = losers[0]
    post = _one(result['posts'][loser['client']], 'loser receive POST count')
    if post['upstream_status'] != 200:
        raise HarnessFailure('loser receive POST returned HTTP ' + str(post['upstream_status']) +
                             '; no negotiated sideband report exists')
    protocol = post.get('request_protocol')
    require(isinstance(protocol, dict) and protocol.get('capabilities'), 'loser request capabilities were not captured')
    capabilities = protocol['capabilities']
    require(capabilities.get('sideband_64k'), 'stock client did not negotiate side-band-64k')
    require(capabilities.get('report_status') or capabilities.get('report_status_v2'),
            'stock client did not negotiate report-status or report-status-v2')
    report = post.get('report')
    require(report is not None, 'sideband report could not be parsed: ' + str(post.get('report_error')))
    require(report['sideband_negotiated'], 'response was not framed on negotiated sideband')
    require(1 in report.get('bands', []) and 3 not in report.get('bands', []),
            'sideband report did not carry status on band 1 or used an error band')
    require(report['refused'], 'sideband report contained no ng')
    ref, reason = _one(report['ng'], 'sideband ng line count')
    require(ref == 'refs/heads/main' and reason, 'sideband ng lacked a ref or reason')
    require('[remote rejected]' in loser['stderr_tail'] and reason in loser['stderr_tail'],
            'stock Git did not parse the negotiated sideband rejection reason')
    return {'capabilities': capabilities, 'sideband_negotiated': True,
            'bands': report.get('bands'), 'progress_packets': report.get('progress_packets'),
            'http_status': 200, 'ng_ref': ref, 'ng_reason': reason,
            'stock_git_parsed_ng': True}


def run_atomic_case(harness, state):
    direct = state['direct']
    before = all_refs(harness, direct)
    pre_main = before.get('refs/heads/main')
    require(pre_main is not None, 'atomic case has no current refs/heads/main')
    work = clone(harness, direct, harness.root / 'atomic-client', 'atomic')
    require(harness.git('rev-parse', 'HEAD', cwd=work).stdout.decode().strip() == pre_main,
            'atomic client clone did not start at current main')
    proxy = LoopbackProxy(('127.0.0.1', harness.port), 'atomic')
    try:
        url = proxy.url + state['repo']['clone_path']
        push = harness.git('push', '--atomic', url, ':refs/heads/main',
                           'HEAD:refs/heads/atomic-created',
                           'HEAD:refs/heads/atomic-created-2', cwd=work,
                           token=harness.alice, check=False)
    finally:
        close_proxy(proxy)
        snapshot = safe_proxy_snapshot(proxy)
    after = all_refs(harness, direct)
    require_proxy_clean(snapshot, 'atomic')
    diagnostics = case_diagnostics(harness, 'atomic', push, snapshot,
                                   {'refs_unchanged': after == before,
                                    'main_oid_unchanged': after.get('refs/heads/main') == pre_main})
    posts = [item for item in proxy.records if item.get('is_receive_post')]
    if len(posts) != 1:
        message = ('atomic push produced no receive POST; connection, auth or transport failure is not acceptance'
                   if not posts else 'atomic receive POST count; observed ' + str(len(posts)))
        raise DiagnosticFailure(message, diagnostics)
    post = posts[0]
    require(post.get('authorization_header_present'), 'atomic receive POST was not authenticated')
    require(post.get('response_body_retained', True) is not False,
            'atomic response body was not retained within the proxy capture cap')
    protocol = post.get('request_protocol')
    require(isinstance(protocol, dict) and protocol.get('capabilities'), 'atomic request capabilities were not captured')
    attempted = protocol.get('refs') or []
    expected = {'refs/heads/main', 'refs/heads/atomic-created', 'refs/heads/atomic-created-2'}
    require(protocol['capabilities'].get('atomic'), 'stock Git did not negotiate atomic receive')
    require(set(attempted) == expected, 'atomic request did not carry every attempted ref: ' + repr(attempted))
    require(push.returncode != 0, 'atomic multi-ref rejection unexpectedly succeeded')
    require(after == before, 'atomic rejection changed at least one attempted ref')
    require('refs/heads/atomic-created' not in after and 'refs/heads/atomic-created-2' not in after,
            'atomic rejection created a new ref')
    require(after.get('refs/heads/main') == pre_main, 'atomic rejection changed refs/heads/main')

    status = post.get('upstream_status')
    require(isinstance(status, int), 'atomic receive POST had no upstream HTTP status')
    ng_all = False
    guard_reason_exact = False
    not_cas_or_ng_proof = False
    if status == 200:
        report = post.get('report')
        require(report is not None, 'atomic HTTP 200 report could not be parsed: ' + str(post.get('report_error')))
        ng_refs = {item[0] for item in report['ng']}
        ng_all = (not report['accepted']) and ng_refs == expected
        require(ng_all, 'atomic HTTP 200 response was not a valid ng report for every requested ref')
        refusal_form = 'http_200_all_requested_ng'
    elif status == 409:
        content_type = (post.get('content_type') or '').split(';', 1)[0].strip().lower()
        require(content_type == 'application/json', 'atomic HTTP 409 did not carry the expected JSON error')
        body = post.get('_body')
        require(isinstance(body, (bytes, bytearray)), 'atomic HTTP 409 error body was unavailable')
        require(len(body) <= MAX_ATOMIC_ERROR_BODY, 'atomic HTTP 409 error body exceeded the bounded decode size')
        try:
            payload = json.loads(bytes(body).decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise HarnessFailure('atomic HTTP 409 error body was not bounded UTF-8 JSON') from error
        require(isinstance(payload, dict) and payload.get('error') == ATOMIC_HEAD_DELETE_REASON,
                'atomic HTTP 409 did not carry the exact advertised-HEAD-delete guard reason')
        guard_reason_exact = True
        not_cas_or_ng_proof = True
        refusal_form = 'http_409_advertised_head_delete_guard'
    else:
        raise HarnessFailure('atomic push failed for a non-semantic reason: HTTP ' + str(status) +
                             '; only HTTP 200 all-requested ng or the exact advertised-HEAD-delete guard 409 is accepted')
    scope = ('HTTP 409 advertised-HEAD-delete guard proves only atomic unchanged refs; '
             'it is not CAS or negotiated-ng proof' if not_cas_or_ng_proof else
             'HTTP 200 negotiated ng report covers every requested ref')
    return {'attempted_refs': sorted(expected), 'atomic_negotiated': True,
            'client_returncode': push.returncode, 'refs_unchanged': True,
            'refs_before': before, 'refs_after': after,
            'refusal_http_status': status, 'refusal_form': refusal_form,
            'ng_all_requested_refs': ng_all, 'guard_reason_exact': guard_reason_exact,
            'not_cas_or_ng_proof': not_cas_or_ng_proof, 'scope': scope,
            'stock_git_stderr_tail': harness.redact(push.stderr.decode(errors='replace'))[-1500:]}


def run_auth_case(harness, state):
    direct = state['direct']
    before = all_refs(harness, direct)
    work = clone(harness, direct, harness.root / 'auth-client', 'auth')
    proxy = LoopbackProxy(('127.0.0.1', harness.port), 'auth')
    try:
        url = proxy.url + state['repo']['clone_path']
        no_token = harness.git('push', url, 'HEAD:refs/heads/auth-denied', cwd=work,
                               check=False)
        readonly = harness.git('push', url, 'HEAD:refs/heads/auth-denied-readonly', cwd=work,
                               token=harness.reader, check=False)
    finally:
        close_proxy(proxy)
        snapshot = safe_proxy_snapshot(proxy)
    after = all_refs(harness, direct)
    require_proxy_clean(snapshot, 'auth')
    require(no_token.returncode != 0, 'unauthenticated stock Git push unexpectedly succeeded')
    require(readonly.returncode != 0, 'read-only stock Git push unexpectedly succeeded')
    require(after == before, 'auth failure changed repository refs')
    advertisements = [item for item in snapshot['records'] if item.get('is_receive_advertisement')]
    require(advertisements, 'auth attempts produced no receive-pack advertisement')
    statuses = sorted({item.get('upstream_status') for item in advertisements})
    require(401 in statuses and 403 in statuses,
            'auth failures were not distinct HTTP 401/403 responses: ' + repr(statuses))
    posts = [item for item in snapshot['records'] if item.get('is_receive_post')]
    require(not posts, 'auth failure reached a receive-pack POST')
    for item in advertisements:
        require(not item.get('body_has_unpack_ok') and not item.get('body_has_ng'),
                'auth failure produced a receive-pack status report')
    require(any(item.get('authorization_header_present') for item in advertisements),
            'read-only token was not forwarded to the advertisement')
    require(any(not item.get('authorization_header_present') for item in advertisements),
            'unauthenticated request unexpectedly carried credentials')
    return {'http_statuses': statuses, 'unauthenticated_returncode': no_token.returncode,
            'read_only_returncode': readonly.returncode, 'posts': 0,
            'ng_seen': False, 'refs_unchanged': True,
            'classification': 'authentication_or_authorization_failure_before_receive',
            'not_a_ref_refusal': True}


def run_lost_response_case(harness, state):
    direct = state['direct']
    before = remote_main(harness, direct)
    work = clone(harness, direct, harness.root / 'lost-client', 'lost')
    require(harness.git('rev-parse', 'HEAD', cwd=work).stdout.decode().strip() == before,
            'lost-response clone did not start at current main')
    lost_oid = commit_file(harness, work, 'lost.txt', 'committed before response drop\n',
                           'post-COMMIT response loss commit')
    require(lost_oid != before, 'lost-response commit equals the old OID')
    proxy = LoopbackProxy(('127.0.0.1', harness.port), 'lost', drop_receive_response=True)
    try:
        url = proxy.url + state['repo']['clone_path']
        push = harness.git('push', url, 'HEAD:refs/heads/main', cwd=work,
                           token=harness.alice, check=False)
    finally:
        close_proxy(proxy)
        snapshot = safe_proxy_snapshot(proxy)
    require_proxy_clean(snapshot, 'lost')
    diagnostics = case_diagnostics(harness, 'lost-response', push, snapshot)
    posts = [item for item in snapshot['records'] if item.get('is_receive_post')]
    if len(posts) != 1:
        raise DiagnosticFailure('response-drop receive POST count; observed ' + str(len(posts)),
                                diagnostics)
    post = posts[0]
    require(post.get('upstream_status') == 200,
            'response drop could not be proven after COMMIT; upstream status=' +
            str(post.get('upstream_status')))
    require(post.get('dropped') is True, 'owned proxy did not record the response drop')
    protocol = post.get('request_protocol')
    report = post.get('report')
    require(isinstance(protocol, dict) and protocol.get('capabilities'), 'response-drop request capabilities were not captured')
    require(report is not None, 'upstream success report could not be parsed: ' + str(post.get('report_error')))
    require('refs/heads/main' in report['ok'] and not report['ng'],
            'upstream did not produce a successful main report before the drop')
    require(push.returncode != 0, 'stock Git unexpectedly returned success despite the response drop')
    stderr = harness.redact(push.stderr.decode(errors='replace'))[-3000:]
    require('[remote rejected]' not in stderr,
            'client observed a receive-pack rejection; this case requires a response drop, not rejection')
    lowered = stderr.lower()
    transport_markers = ('rpc failed', 'empty reply', 'curl 52', 'connection reset',
                         'unexpected disconnect', 'recv failure', 'transfer closed')
    require(any(marker in lowered for marker in transport_markers),
            'stock Git did not report a transport failure after the response drop')
    readback = remote_main(harness, direct)
    require(readback == lost_oid, 'committed winner was not readable after the response drop')
    verify = clone(harness, direct, harness.root / 'lost-readback', 'lost-readback')
    require(harness.git('rev-parse', 'HEAD', cwd=verify).stdout.decode().strip() == lost_oid,
            'fresh clone did not read back the committed winner')
    harness.git('fsck', '--full', cwd=verify)
    return {'classification': 'unknown_transport_after_commit',
            'never_rejected_or_aborted': True,
            'client_returncode': push.returncode, 'client_stderr_tail': stderr,
            'upstream_http_status_before_drop': 200, 'proxy_dropped_response': True,
            'upstream_success_report_before_drop': True,
            'committed_winner_readback': True, 'winner_commit': lost_oid,
            'fresh_clone_readback': True, 'fresh_clone_fsck': True}


def run_source_stable_case(args, state, binary, receipt, binding, runner_before):
    binary_after = digest(binary)
    source_after = binding.source_digest()
    runner_after = digest(Path(__file__).resolve())
    require(binary_after == receipt['binary_sha256'], 'binary changed during the harness run')
    require(source_after == receipt['source_inputs_sha256'], 'source inputs changed during the harness run')
    require(runner_after == runner_before, 'harness runner changed during its own run')
    return {'binary_sha256_before_and_after': binary_after,
            'source_inputs_sha256_before_and_after': source_after,
            'runner_sha256_before_and_after': runner_after,
            'build_receipt_bound': True}


def new_report(args, runner_sha):
    memory = None
    try:
        memory = next(line.partition(':')[2].strip() for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemTotal:'))
    except Exception:
        pass
    return {
        'version': 1,
        'issue': '126',
        'supporting': ['prioritized105'],
        'profile': 'legacy-pando-ref-status-native',
        'status': 'failed',
        'started_at': utc_now(),
        'runner_path': str(Path(__file__).resolve()),
        'runner_sha256_before': runner_sha,
        'binary_path': str(Path(args.binary).resolve()),
        'source_root': str(Path(args.source_root).resolve()),
        'case_inventory': list(CASE_INVENTORY),
        'cases': [],
        'environment': {
            'ROOTYARD_TEST_DATABASE_URL_present': bool(os.environ.get('ROOTYARD_TEST_DATABASE_URL')),
            'ROOTYARD_OBJECT_STORE_ENDPOINT_present': bool(os.environ.get('ROOTYARD_OBJECT_STORE_ENDPOINT')),
            'credentials_or_headers_recorded': False,
            'note': 'Only presence booleans are recorded; values, argv and HTTP header values are never written.',
        },
        'hardware': {'kernel': platform.release(), 'machine': platform.machine(),
                     'logical_cpus': os.cpu_count(), 'memory_total': memory,
                     'scope': 'host-visible resources; not a reserved allocation'},
        'provider_versions': {'garage': None, 'vault': None,
                              'reason': 'service executables are not inspected by this harness'},
        'limits': [
            'One physical host and loopback services; no HA, durability, power-loss or throughput qualification.',
            'The two stock clients are synchronized only at authenticated advertisement GETs; server CAS ordering after the barrier is not forced.',
            'The response-drop case is an owned proxy closing after the complete upstream response; it is not a general network partition.',
            'Full client operation query/retry idempotency (#112/#117) is not exercised; no issue126-complete claim follows from this report.',
            'No FUSE, mount, kernel control or old FUSE directory is used or traversed.',
        ],
        'unmeasured': {'server_cas_order': None, 'network_partition': None,
                       'client_retry_idempotency': None, 'throughput': None},
    }


def write_report(path, report):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp-' + str(os.getpid()))
    try:
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description='Focused issue126 Pando ref-status acceptance harness')
    parser.add_argument('--binary', required=True, help='root-built rootyard binary; its .build.json receipt must sit beside it')
    parser.add_argument('--report', type=Path, required=True, help='JSON report destination (secret-free)')
    parser.add_argument('--source-root', type=Path, required=True, help='source tree the binary was built from')
    parser.add_argument('--keep', action='store_true', help='retain the owned temporary fixture after cleanup')
    args = parser.parse_args()
    runner_before = digest(Path(__file__).resolve())
    report = new_report(args, runner_before)
    harness = None
    binary = None
    binding = None
    receipt = None
    state = {}
    try:
        binding = load_binding(args.source_root.resolve())
        binary, receipt_path, receipt, binary_sha, source_before = verify_build(args, binding)
        report.update({'build_receipt': receipt, 'receipt_path': str(receipt_path),
                       'binary_bytes': binary.stat().st_size,
                       'binary_sha256_before': binary_sha,
                       'source_inputs_sha256_before': source_before,
                       'cargo_lock_sha256': digest(args.source_root.resolve() / 'Cargo.lock')})
        Harness = load_harness(args.source_root.resolve())
        harness = Harness(argparse.Namespace(binary=str(binary), keep=args.keep))
        parts = urllib.parse.urlsplit(harness.db)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        query.append(('application_name', 'issue126_ref_status'))
        harness.db = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
        harness.env['DATABASE_URL'] = harness.db
        state = {'harness': harness}
        report['git_client_version'] = harness.git('--version').stdout.decode().strip()

        def setup_entry():
            try:
                return setup_legacy_pando(harness, state)
            except Exception as error:
                state['setup_error'] = safe_error(harness, error)
                raise

        def race_entry():
            try:
                run_same_old_race(harness, state)
                return validate_cas_result(harness, state)
            except Exception as error:
                state['race_error'] = safe_error(harness, error)
                raise

        actions = {
            'same_old_oid_two_stock_clients_one_winner': lambda: validate_cas_result(harness, state),
            'loser_negotiated_sideband_ng_reason': lambda: validate_sideband_result(harness, state),
            'atomic_multiref_rejection_no_ref_changed': lambda: run_atomic_case(harness, state),
            'auth_failure_distinct_from_refusal': lambda: run_auth_case(harness, state),
            'post_commit_response_lost_unknown_transport': lambda: run_lost_response_case(harness, state),
        }
        for name in CASE_INVENTORY:
            if name == 'legacy_pando_setup':
                status = record_case(report, name, setup_entry, harness)
            elif name == 'source_binary_runner_stable':
                status = record_case(report, name,
                                     lambda: run_source_stable_case(args, state, binary, receipt, binding, runner_before),
                                     harness)
            elif not state.get('setup_ok'):
                report['cases'].append({'name': name, 'status': 'failed',
                                        'error': 'blocked_by_setup: ' + state.get('setup_error', 'legacy setup did not complete')})
            elif name == 'same_old_oid_two_stock_clients_one_winner':
                status = record_case(report, name, race_entry, harness)
                if status != 'passed':
                    pass
            elif name in actions:
                status = record_case(report, name, actions[name], harness)
            else:
                report['cases'].append({'name': name, 'status': 'failed', 'error': 'unknown case action'})
            print(name + ': ' + report['cases'][-1]['status'], flush=True)
    except Exception as error:
        report['error'] = safe_error(harness, error)
    finally:
        present = {entry['name'] for entry in report['cases']}
        for name in CASE_INVENTORY:
            if name not in present:
                report['cases'].append({'name': name, 'status': 'failed',
                                        'error': 'not executed because the harness ended early: ' +
                                                 report.get('error', 'unknown preflight failure')})
        order = [entry['name'] for entry in report['cases']]
        if order != list(CASE_INVENTORY):
            report['case_inventory_error'] = {'expected': list(CASE_INVENTORY), 'actual': order}
        if harness is not None:
            try:
                harness.cleanup()
            except Exception as error:
                report['cleanup_error'] = safe_error(harness, error)
        finished_at = utc_now()
        report.update({'finished_at': finished_at, 'seconds': round(
            (datetime.fromisoformat(finished_at) - datetime.fromisoformat(report['started_at'])).total_seconds(), 4)})
        runner_after = digest(Path(__file__).resolve())
        report['runner_sha256_after'] = runner_after
        try:
            report['binary_sha256_after'] = digest(binary) if binary else None
            report['source_inputs_sha256_after'] = binding.source_digest() if binding else None
        except Exception as error:
            report['after_digest_error'] = safe_error(harness, error)
            report['binary_sha256_after'] = None
            report['source_inputs_sha256_after'] = None
        report['binary_still_matches'] = bool(receipt and report.get('binary_sha256_after') == receipt.get('binary_sha256'))
        report['source_still_matches'] = bool(receipt and report.get('source_inputs_sha256_after') == receipt.get('source_inputs_sha256'))
        report['runner_still_matches'] = runner_after == runner_before
        if harness is not None:
            report['fixture_root'] = str(harness.root)
            report['fixture_retained'] = bool(args.keep)
        all_cases_passed = (len(report['cases']) == len(CASE_INVENTORY) and
                            all(entry.get('status') == 'passed' for entry in report['cases']))
        if (all_cases_passed and not report.get('error') and not report.get('cleanup_error')
                and not report.get('case_inventory_error') and report['binary_still_matches']
                and report['source_still_matches'] and report['runner_still_matches']):
            report['status'] = 'passed'
        else:
            report['status'] = 'failed'
        try:
            write_report(args.report, report)
        except Exception as error:
            print('REPORT WRITE FAILED: ' + safe_error(harness, error), file=sys.stderr)
            return 1
    return 0 if report.get('status') == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
