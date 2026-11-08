#!/usr/bin/env python3
import importlib.util
import socket
import threading
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/check_pando_ref_status.py'
spec = importlib.util.spec_from_file_location('native_harness', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def parse_response(raw):
    left, right = socket.socketpair()

    def serve():
        try:
            right.sendall(raw)
        finally:
            right.shutdown(socket.SHUT_WR)
            right.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = module.read_response(module.BufferedSocket(left))
    finally:
        left.close()
        thread.join(timeout=5)
    assert not thread.is_alive(), 'fake HTTP writer did not finish'
    return result


# Content-Type is the first header and must survive header parsing.
status_line, status, headers, body = parse_response(
    b'HTTP/1.1 200 OK\r\n'
    b'Content-Type: application/x-git-receive-pack-result\r\n'
    b'Content-Length: 5\r\n'
    b'\r\n'
    b'hello')
assert status_line == 'HTTP/1.1 200 OK', status_line
assert status == 200, status
assert headers[0] == ('Content-Type', 'application/x-git-receive-pack-result'), headers
assert dict(headers)['Content-Length'] == '5', headers
assert body == b'hello', body

# A 100 Continue response must be skipped while the final 200 keeps its first header.
status_line, status, headers, body = parse_response(
    b'HTTP/1.1 100 Continue\r\n'
    b'X-Interim: ignored\r\n'
    b'\r\n'
    b'HTTP/1.1 200 OK\r\n'
    b'Content-Type: application/x-git-receive-pack-result\r\n'
    b'Content-Length: 2\r\n'
    b'\r\n'
    b'ok')
assert status_line == 'HTTP/1.1 200 OK', status_line
assert status == 200, status
assert headers[0] == ('Content-Type', 'application/x-git-receive-pack-result'), headers
assert ('X-Interim', 'ignored') not in headers, headers
assert dict(headers)['Content-Length'] == '2', headers
assert body == b'ok', body

# Content-Length as the first header must also survive.
status_line, status, headers, body = parse_response(
    b'HTTP/1.1 200 OK\r\n'
    b'Content-Length: 4\r\n'
    b'Content-Type: application/x-git-receive-pack-result\r\n'
    b'\r\n'
    b'body')
assert status == 200, status
assert headers[0] == ('Content-Length', '4'), headers
assert headers[1] == ('Content-Type', 'application/x-git-receive-pack-result'), headers
assert body == b'body', body

print('3/3 portable socketpair HTTP response parser checks passed')
