#!/usr/bin/env python3
"""Optional source-bound real-Redis contract gate for the state-redis feature.

The runner owns one disposable Docker Redis fixture (official redis:7.2.6-alpine
image), builds the library test binary from the current sources, runs the six
ignored real-Redis cases over plaintext loopback and verified private-CA TLS,
then proves an untrusted CA fails and the owned CA restores trust. It never
uses an inherited Redis endpoint, never changes host trust, and redacts URLs,
ACL passwords and private key material before writing logs or reports.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import build_native  # noqa: E402

REDIS_IMAGE = "redis:7.2.6-alpine"
REDIS_VERSION = "7.2.6"
REDIS_VERSION_MARKER = "v=7.2.6"
MAXMEMORY_BYTES = 33554432
TEST_FILTER = "real_redis_"
TEST_CASE_COUNT = 6
NEGATIVE_CASE = "cache_wake::redis::tests::real_redis_cache_contract_round_trip_and_bounded_read"
EXPECTED_CASES = frozenset({
    "cache_wake::redis::cancel_tests::real_redis_cancelled_inflight_connections_are_closed",
    "cache_wake::redis::tests::real_redis_bad_acl_credentials_are_rejected_bounded_and_redacted",
    "cache_wake::redis::tests::real_redis_cache_contract_round_trip_and_bounded_read",
    "cache_wake::redis::tests::real_redis_flushall_is_authoritative_cache_miss",
    "cache_wake::redis::tests::real_redis_noeviction_policy_fails_connect_closed_and_restores",
    "cache_wake::redis::tests::real_redis_wake_publishes_only_a_hint",
})
CONTAINER_PORT = 6379
TLS_CONTAINER_PORT = 6380
CLEAN_COMMAND = ["cargo", "clean", "--package", "rootyard"]
BUILD_COMMAND = [
    "cargo",
    "--config", "profile.dev.package.rootyard.debug=0",
    "--config", "profile.test.package.rootyard.debug=0",
    "--config", 'profile.dev.package.rootyard.strip="debuginfo"',
    "--config", 'profile.test.package.rootyard.strip="debuginfo"',
    "test", "--locked", "--lib", "--features", "state-redis",
    "--no-run", "--message-format=json-render-diagnostics",
]
SENSITIVE_ENV = (
    "ROOTYARD_TEST_REDIS_URL",
    "ROOTYARD_TEST_REDIS_DESTRUCTIVE",
    "ROOTYARD_CACHE_REDIS_URL",
    "ROOTYARD_REDIS_URL",
    "ROOTYARD_REDIS_ADDRESS",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSLKEYLOGFILE",
)
URL_RE = re.compile(r"(?i)\b(?:rediss?|https?)://[^\s\"'<>]+")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


class RunnerError(RuntimeError):
    """A fixture, build, test or cleanup contract was not satisfied."""
def redact(text: object, secrets: tuple[str, ...] = ()) -> str:
    """Remove passwords, Redis URLs and private keys from untrusted text."""
    value = str(text)
    value = PRIVATE_KEY_RE.sub("<redacted-private-key>", value)
    candidates = set(secrets)
    for secret in tuple(candidates):
        if secret:
            candidates.add(quote(secret, safe=""))
    for secret in sorted(candidates, key=len, reverse=True):
        if secret:
            value = value.replace(secret, "<redacted>")
    return URL_RE.sub("<redacted-url>", value)


def redact_tree(value: object, secrets: tuple[str, ...]) -> object:
    """Recursively redact every string in a JSON-compatible value."""
    if isinstance(value, str):
        return redact(value, secrets)
    if isinstance(value, list):
        return [redact_tree(item, secrets) for item in value]
    if isinstance(value, dict):
        return {str(key): redact_tree(item, secrets) for key, item in value.items()}
    return value


def assert_safe(value: object, secrets: tuple[str, ...]) -> str:
    """Serialize a value only when it contains no known secret or URL."""
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    for secret in secrets:
        if secret and (secret in text or quote(secret, safe="") in text):
            raise RunnerError("refusing to write a report containing a fixture secret")
    if URL_RE.search(text):
        raise RunnerError("refusing to write a report containing a Redis/HTTP URL")
    if PRIVATE_KEY_RE.search(text):
        raise RunnerError("refusing to write a report containing private key material")
    return text


def write_private_file(path: Path, content: str, mode: int = 0o600) -> None:
    """Create a new private regular file without following symlinks."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_json_atomic(path: Path, value: object, secrets: tuple[str, ...]) -> None:
    """Write one already-safe JSON document with an atomic replace."""
    path = Path(path)
    text = assert_safe(redact_tree(value, secrets), secrets)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    write_private_file(temporary, text, 0o600)
    os.replace(temporary, path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_command(
    command: list[str], *, env: dict[str, str] | None = None, timeout: int = 300,
    cwd: Path | None = ROOT,
) -> subprocess.CompletedProcess[str]:
    """Run one argv command without a shell; callers never pass secrets in argv."""
    try:
        return subprocess.run(
            command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except FileNotFoundError as error:
        raise RunnerError(f"required executable is missing: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise RunnerError(f"command timed out after {timeout}s: {command[0]}") from error


def docker(*args: str, timeout: int = 300) -> str:
    """Run docker with no inherited Redis/trust environment."""
    env = {key: value for key, value in os.environ.items() if key not in SENSITIVE_ENV}
    result = run_command(["docker", *args], env=env, timeout=timeout)
    if result.returncode != 0:
        detail = redact(result.stderr.strip() or result.stdout.strip())
        raise RunnerError(f"docker {args[0]} failed with status {result.returncode}: {detail}")
    return result.stdout.strip()
def parse_docker_port(output: str, container_port: int) -> int:
    """Parse one IPv4-loopback ephemeral Docker port mapping."""
    lines = [line.strip() for line in str(output).splitlines() if line.strip()]
    if len(lines) != 1:
        raise RunnerError(f"expected one loopback mapping for {container_port}/tcp")
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", lines[0])
    if not match:
        raise RunnerError(f"mapping for {container_port}/tcp is not IPv4 loopback")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise RunnerError(f"mapping for {container_port}/tcp has an invalid port")
    return port


def parse_libtest(
    output: str, *, expected_cases: frozenset[str], expected_passed: int,
    expected_failed: int = 0, expected_ignored: int = 0, require_nonzero: bool = True,
) -> dict:
    """Parse libtest case lines and summary; reject zero-skip false passes."""
    case_pattern = re.compile(r"^test ([\w:]+) \.\.\. (ok|FAILED|ignored)$")
    cases: dict[str, str] = {}
    for line in str(output).splitlines():
        match = case_pattern.match(line.strip())
        if match:
            name, status = match.groups()
            if name in cases:
                raise RunnerError(f"libtest reported duplicate case {name}")
            cases[name] = status
    summaries = re.findall(
        r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$",
        str(output), re.MULTILINE,
    )
    if len(summaries) != 1:
        raise RunnerError("libtest did not emit exactly one result summary")
    status, passed, failed, ignored, measured, filtered, seconds = summaries[0]
    counts = {name: int(value) for name, value in (
        ("passed", passed), ("failed", failed), ("ignored", ignored),
        ("measured", measured), ("filtered_out", filtered),
    )}
    observed = sum(counts[key] for key in ("passed", "failed", "ignored"))
    if observed != len(cases):
        raise RunnerError("libtest summary does not match its case lines")
    if require_nonzero and counts["passed"] == 0:
        raise RunnerError("libtest reported zero passing cases")
    if set(cases) != set(expected_cases):
        missing = sorted(set(expected_cases) - set(cases))
        extra = sorted(set(cases) - set(expected_cases))
        raise RunnerError(f"libtest case set mismatch; missing={missing} extra={extra}")
    if counts["passed"] != expected_passed:
        raise RunnerError(f"expected {expected_passed} passed, observed {counts['passed']}")
    if counts["failed"] != expected_failed:
        raise RunnerError(f"expected {expected_failed} failed, observed {counts['failed']}")
    if counts["ignored"] != expected_ignored:
        raise RunnerError(f"expected {expected_ignored} ignored, observed {counts['ignored']}")
    if expected_failed == 0 and status != "ok":
        raise RunnerError("libtest summary was not ok despite zero expected failures")
    if expected_failed > 0 and status != "FAILED":
        raise RunnerError("libtest did not report the expected failure")
    failures = sorted(name for name, state in cases.items() if state == "FAILED")
    if expected_failed and set(failures) != set(expected_cases):
        raise RunnerError("unexpected failing case names")
    return {
        "status": status,
        "passed": counts["passed"],
        "failed": counts["failed"],
        "ignored": counts["ignored"],
        "measured": counts["measured"],
        "filtered_out": counts["filtered_out"],
        "seconds": float(seconds),
        "cases": dict(sorted(cases.items())),
        "failed_cases": failures,
    }


def child_environment(url: str, ca_file: Path) -> dict[str, str]:
    """Build a child environment with no inherited external Redis endpoint."""
    environment = {key: value for key, value in os.environ.items() if key not in SENSITIVE_ENV}
    environment.update({
        "ROOTYARD_TEST_REDIS_URL": url,
        "ROOTYARD_TEST_REDIS_DESTRUCTIVE": "owned-fixture",
        "SSL_CERT_FILE": str(ca_file),
        "RUST_BACKTRACE": "0",
    })
    return environment
def run_openssl(arguments: list[str], cwd: Path) -> None:
    """Run openssl silently; private key output is never inherited or logged."""
    try:
        result = subprocess.run(
            ["openssl", *arguments], cwd=cwd, text=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=120, check=False,
        )
    except FileNotFoundError as error:
        raise RunnerError("openssl is required for the owned TLS fixture") from error
    except subprocess.TimeoutExpired as error:
        raise RunnerError("openssl timed out while creating fixture material") from error
    if result.returncode != 0:
        raise RunnerError("openssl could not create the owned TLS fixture material")


def create_ca(directory: Path, name: str, common_name: str) -> tuple[Path, Path]:
    """Create an ephemeral CA certificate and private key."""
    certificate = directory / f"{name}.crt"
    key = directory / f"{name}.key"
    run_openssl([
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
        "-keyout", str(key), "-out", str(certificate),
        "-subj", f"/CN={common_name}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ], directory)
    os.chmod(key, 0o600)
    os.chmod(certificate, 0o644)
    return certificate, key


def create_server_certificate(directory: Path, ca_certificate: Path, ca_key: Path) -> tuple[Path, Path]:
    """Create a 127.0.0.1 SAN certificate signed by the ephemeral CA."""
    server_key = directory / "server.key"
    request = directory / "server.csr"
    certificate = directory / "server.crt"
    extensions = directory / "server.ext"
    write_private_file(extensions, (
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:127.0.0.1\n"
    ), 0o600)
    run_openssl([
        "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-keyout", str(server_key), "-out", str(request),
        "-subj", "/CN=127.0.0.1",
    ], directory)
    run_openssl([
        "x509", "-req", "-in", str(request), "-CA", str(ca_certificate),
        "-CAkey", str(ca_key), "-CAcreateserial", "-sha256", "-days", "1",
        "-extfile", str(extensions), "-out", str(certificate),
    ], directory)
    os.chmod(server_key, 0o600)
    os.chmod(certificate, 0o644)
    return certificate, server_key


def redis_configuration(secret: str) -> str:
    """Return an explicit TLS + bounded-cache configuration with no persistence."""
    return (
        "bind 0.0.0.0\n"
        "protected-mode no\n"
        f"port {CONTAINER_PORT}\n"
        f"tls-port {TLS_CONTAINER_PORT}\n"
        "tls-cert-file /run/rootyard-fixture/server.crt\n"
        "tls-key-file /run/rootyard-fixture/server.key\n"
        "tls-ca-cert-file /run/rootyard-fixture/ca.crt\n"
        "tls-auth-clients no\n"
        'tls-protocols "TLSv1.2 TLSv1.3"\n'
        "daemonize no\n"
        "databases 1\n"
        f"maxmemory {MAXMEMORY_BYTES}\n"
        "maxmemory-policy allkeys-lru\n"
        'save ""\n'
        "appendonly no\n"
        "dir /tmp\n"
        "user default off\n"
        f"user rootyard on >{secret} ~* &* +@all\n"
    )
class OwnedRedisFixture:
    """One private, loopback-only Redis 7.2.6 container created by this process."""

    def __init__(self, docker_runner=docker, command_runner=run_command):
        self.docker_runner = docker_runner
        self.command_runner = command_runner
        self.directory = Path(tempfile.mkdtemp(prefix="rootyard-redis-contract-"))
        os.chmod(self.directory, 0o700)
        self.nonce = secrets.token_hex(16)
        self.secret = secrets.token_hex(32)
        self.cid: str | None = None
        self.create_attempted = False
        self.name = f"rootyard-owned-redis-{self.nonce[:12]}"
        self.plain_port: int | None = None
        self.tls_port: int | None = None
        self.version_line = ""
        self.image_id = ""
        self.image_digest = ""
        self.ca_certificate = self.directory / "ca.crt"
        self.untrusted_ca_certificate = self.directory / "untrusted-ca.crt"

    def _docker(self, *arguments: str, timeout: int = 300) -> str:
        return self.docker_runner(*arguments, timeout=timeout)

    def _raw_docker(self, *arguments: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
        environment = {key: value for key, value in os.environ.items() if key not in SENSITIVE_ENV}
        return self.command_runner(["docker", *arguments], env=environment, timeout=timeout)

    def _create_materials(self) -> None:
        ca_certificate, ca_key = create_ca(self.directory, "ca", f"Rootyard owned Redis CA {self.nonce}")
        create_ca(self.directory, "untrusted-ca", f"Rootyard untrusted CA {self.nonce}")
        server_certificate, server_key = create_server_certificate(
            self.directory, ca_certificate, ca_key)
        config = self.directory / "redis.conf"
        write_private_file(config, redis_configuration(self.secret), 0o600)
        for path in (ca_certificate, server_certificate):
            os.chmod(path, 0o644)
        for path in (server_key, ca_key):
            os.chmod(path, 0o600)

    def _image_metadata(self) -> None:
        try:
            self.image_id = self._docker("image", "inspect", "--format", "{{.Id}}", REDIS_IMAGE)
            digests = self._docker(
                "image", "inspect", "--format", '{{join .RepoDigests "\\n"}}', REDIS_IMAGE)
        except RunnerError as error:
            raise RunnerError(
                f"{REDIS_IMAGE} is not present locally; pull the official image first") from error
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id):
            raise RunnerError("docker image id is not a full sha256 digest")
        for digest in digests.splitlines():
            if re.fullmatch(r"redis@sha256:[0-9a-f]{64}", digest.strip()):
                self.image_digest = digest.strip()
                break
        if not self.image_digest:
            raise RunnerError("official redis:7.2.6-alpine image has no redis repo digest")

    def _mount(self, source: Path, target: str) -> str:
        return f"type=bind,source={source},target={target},readonly"

    def _create_container(self) -> str:
        self.create_attempted = True
        uid, gid = os.getuid(), os.getgid()
        arguments = [
            "create", "--name", self.name,
            "--label", "rootyard.fixture.kind=owned-redis",
            "--label", f"rootyard.fixture.nonce={self.nonce}",
            "--label", f"rootyard.fixture.directory={self.directory}",
            "--label", f"rootyard.fixture.uid={uid}",
            "--label", f"rootyard.fixture.name={self.name}",
            "--user", f"{uid}:{gid}",
            "--publish", f"127.0.0.1::{CONTAINER_PORT}",
            "--publish", f"127.0.0.1::{TLS_CONTAINER_PORT}",
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--mount", self._mount(self.directory / "redis.conf", "/run/rootyard-fixture/redis.conf"),
            "--mount", self._mount(self.directory / "server.crt", "/run/rootyard-fixture/server.crt"),
            "--mount", self._mount(self.directory / "server.key", "/run/rootyard-fixture/server.key"),
            "--mount", self._mount(self.directory / "ca.crt", "/run/rootyard-fixture/ca.crt"),
            "--entrypoint", "redis-server", REDIS_IMAGE, "/run/rootyard-fixture/redis.conf",
        ]
        cid = self._docker(*arguments, timeout=120)
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise RunnerError("docker create did not return one full container id")
        return cid

    def start(self) -> None:
        """Create and validate the owned fixture; the caller must always stop it."""
        self._create_materials()
        self._image_metadata()
        self.cid = self._create_container()
        self._docker("start", self.cid, timeout=120)
        plain = self._docker("port", self.cid, f"{CONTAINER_PORT}/tcp")
        secure = self._docker("port", self.cid, f"{TLS_CONTAINER_PORT}/tcp")
        self.plain_port = parse_docker_port(plain, CONTAINER_PORT)
        self.tls_port = parse_docker_port(secure, TLS_CONTAINER_PORT)
        self._wait_ready()
        self.version_line = self._docker("exec", self.cid, "redis-server", "--version")
        if REDIS_VERSION_MARKER not in self.version_line:
            raise RunnerError(f"owned Redis image version is not {REDIS_VERSION}: {self.version_line}")
        self._probe(self.plain_port, tls=False)
        self._probe(self.tls_port, tls=True)
    def url(self, *, tls: bool) -> str:
        scheme = "rediss" if tls else "redis"
        port = self.tls_port if tls else self.plain_port
        if port is None:
            raise RunnerError("owned Redis port was not assigned")
        return f"{scheme}://rootyard:{self.secret}@127.0.0.1:{port}/0"

    def _container_state(self) -> str:
        if not self.cid:
            return "missing"
        result = self._raw_docker("inspect", "--format", "{{.State.Status}}", self.cid, timeout=30)
        return result.stdout.strip() if result.returncode == 0 else "missing"

    def _container_logs(self) -> str:
        if not self.cid:
            return ""
        result = self._raw_docker("logs", "--tail", "40", self.cid, timeout=30)
        return redact(result.stdout + result.stderr, (self.secret,))

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 40
        assert self.plain_port is not None and self.tls_port is not None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.plain_port), timeout=1):
                    pass
                with socket.create_connection(("127.0.0.1", self.tls_port), timeout=1):
                    pass
                return
            except OSError:
                state = self._container_state()
                if state not in ("running", "created"):
                    logs = self._container_logs()
                    raise RunnerError(
                        f"owned Redis container stopped before readiness ({state}): {logs}")
                time.sleep(0.1)
        raise RunnerError("owned Redis loopback ports did not become ready in 40s")

    def _probe(self, port: int, *, tls: bool) -> None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                if tls:
                    context = ssl.create_default_context(cafile=str(self.ca_certificate))
                    context.check_hostname = True
                    with context.wrap_socket(raw, server_hostname="127.0.0.1") as secure:
                        secure.settimeout(5)
                        secure.sendall(b"*1\r\n$4\r\nPING\r\n")
                        response = secure.recv(128)
                else:
                    raw.settimeout(5)
                    raw.sendall(b"*1\r\n$4\r\nPING\r\n")
                    response = raw.recv(128)
        except (OSError, ssl.SSLError) as error:
            raise RunnerError(
                f"owned Redis {'TLS' if tls else 'plaintext'} probe failed: {redact(error)}") from error
        if not response or response[:1] not in (b"+", b"-"):
            raise RunnerError(
                f"owned Redis {'TLS' if tls else 'plaintext'} probe returned no RESP reply")

    def _labels(self, cid: str) -> dict[str, str]:
        labels = {}
        for label in ("kind", "nonce", "directory", "uid", "name"):
            inspected = self._raw_docker(
                "inspect", "--type", "container", "--format",
                f'{{{{index .Config.Labels "rootyard.fixture.{label}"}}}}',
                cid, timeout=30)
            labels[label] = inspected.stdout.strip() if inspected.returncode == 0 else ""
        return labels

    def _owned(self, actual: str, labels: dict[str, str]) -> bool:
        return (
            re.fullmatch(r"[0-9a-f]{64}", actual) is not None
            and (self.cid is None or actual == self.cid)
            and labels["kind"] == "owned-redis"
            and labels["nonce"] == self.nonce
            and labels["directory"] == str(self.directory)
            and labels["uid"] == str(os.getuid())
            and labels["name"] == self.name
        )

    def _remove(self, actual: str, labels: dict[str, str], errors: list[str]) -> bool:
        if not self._owned(actual, labels):
            errors.append("owned Redis container could not be proven by id/labels; keeping fixture")
            return False
        result = self._raw_docker("rm", "-f", "--", actual, timeout=60)
        if result.returncode != 0:
            errors.append("docker could not remove the owned Redis container; keeping fixture")
            return False
        self.cid = None
        return True

    def stop(self) -> list[str]:
        """Remove only this run's container, even after an ambiguous create result."""
        errors: list[str] = []
        removed = False
        absent = False
        try:
            if self.cid:
                result = self._raw_docker(
                    "inspect", "--type", "container", "--format", "{{.Id}}", self.cid, timeout=30)
                if result.returncode != 0:
                    if "no such container" in result.stderr.lower():
                        absent = True
                    else:
                        errors.append("owned Redis container could not be inspected for cleanup")
                else:
                    actual = result.stdout.strip()
                    removed = self._remove(actual, self._labels(self.cid), errors)
            elif self.create_attempted:
                # docker create may have created the daemon object before a CLI
                # timeout or invalid stdout prevented recording its id. Resolve
                # only this run's random name, then prove the full id and every
                # ownership label before removing it.
                result = self._raw_docker(
                    "inspect", "--type", "container", "--format", "{{.Id}}", self.name, timeout=30)
                if result.returncode != 0:
                    if "no such container" in result.stderr.lower():
                        absent = True
                    else:
                        errors.append("owned Redis create result is ambiguous; keeping fixture")
                else:
                    actual = result.stdout.strip()
                    removed = self._remove(actual, self._labels(actual), errors)
        except RunnerError as error:
            errors.append(f"owned Redis cleanup unresolved: {redact(error)}")
        if not self.cid or removed or absent:
            if not errors:
                if self.directory.exists():
                    shutil.rmtree(self.directory, ignore_errors=True)
                if self.directory.exists():
                    errors.append("private fixture directory could not be removed")
        return errors

def build_libtest() -> dict:
    """Build one fresh source-bound rootyard lib test executable via Cargo JSON."""
    source_before = build_native.source_digest()
    lock_sha = sha256_file(ROOT / "Cargo.lock")
    rustc_version = run_command(["rustc", "--version"], cwd=ROOT, timeout=60)
    if rustc_version.returncode != 0:
        raise RunnerError("rustc --version failed")
    clean = run_command(CLEAN_COMMAND, cwd=ROOT, timeout=300)
    if clean.returncode != 0:
        raise RunnerError(f"cargo clean failed with status {clean.returncode}")
    result = run_command(BUILD_COMMAND, cwd=ROOT, timeout=1800)
    if result.returncode != 0:
        detail = redact(result.stderr.strip()[-4000:])
        raise RunnerError(f"cargo test --no-run failed with status {result.returncode}: {detail}")
    events = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise RunnerError("cargo wrote non-JSON to stdout") from error
        if not isinstance(event, dict):
            raise RunnerError("cargo JSON event was not an object")
        events.append(event)
    artifacts = []
    finished = []
    for event in events:
        if event.get("reason") == "build-finished":
            finished.append(event)
        if event.get("reason") != "compiler-artifact":
            continue
        target = event.get("target") or {}
        profile = event.get("profile") or {}
        if target.get("name") != "rootyard" or "lib" not in (target.get("kind") or []):
            continue
        if profile.get("test") is not True:
            continue
        if event.get("fresh") is not False:
            raise RunnerError("cargo reported a Fresh rootyard test lib; refusing a stale run")
        executable = event.get("executable")
        if not executable:
            raise RunnerError("rootyard test lib artifact has no executable path")
        artifacts.append(event)
    if len(artifacts) != 1:
        raise RunnerError("cargo did not report exactly one rootyard profile.test lib executable")
    if any(event.get("success") is False for event in finished):
        raise RunnerError("cargo reported an unsuccessful build-finished event")
    executable = Path(artifacts[0]["executable"]).resolve()
    if not executable.is_file():
        raise RunnerError("source-bound test executable is missing")
    binary_sha = sha256_file(executable)
    source_after = build_native.source_digest()
    if source_before != source_after:
        raise RunnerError("source inputs changed during the test build")
    return {
        "kind": "rust-library-test",
        "command": list(BUILD_COMMAND),
        "clean_command": list(CLEAN_COMMAND),
        "workspace_commit": run_command(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=30).stdout.strip(),
        "rustc": rustc_version.stdout.strip(),
        "cargo_lock_sha256": lock_sha,
        "source_inputs_sha256": source_before,
        "source_after_build_sha256": source_after,
        "executable": str(executable),
        "binary_sha256": binary_sha,
        "fresh": False,
        "profile_test": True,
        "cargo_returncode": result.returncode,
        "build_finished": finished,
        "artifact": {
            "target": "rootyard", "kind": "lib",
            "fresh": artifacts[0]["fresh"], "profile": artifacts[0].get("profile"),
        },
    }


def run_case_set(
    executable: Path, label: str, arguments: list[str], environment: dict[str, str],
    *, expected_cases: frozenset[str], expected_passed: int, expected_failed: int,
    expected_ignored: int, log_dir: Path, secrets: tuple[str, ...],
) -> dict:
    """Run one exact libtest selection and reject missing, skipped or extra cases."""
    command = [str(executable), *arguments, "--test-threads=1"]
    result = run_command(command, env=environment, timeout=300, cwd=ROOT)
    safe_output = redact(result.stdout + result.stderr, secrets)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{label}.log"
    log_path.unlink(missing_ok=True)
    write_private_file(log_path, safe_output, 0o644)
    parsed = parse_libtest(
        safe_output, expected_cases=expected_cases, expected_passed=expected_passed,
        expected_failed=expected_failed, expected_ignored=expected_ignored,
        require_nonzero=expected_passed > 0,
    )
    if expected_failed == 0 and result.returncode != 0:
        raise RunnerError(f"{label} failed with status {result.returncode}; see {log_path.name}")
    if expected_failed > 0 and result.returncode == 0:
        raise RunnerError(f"{label} unexpectedly returned success")
    parsed.update({
        "name": label,
        "command": command,
        "returncode": result.returncode,
        "log_sha256": sha256_file(log_path),
        "required_counts": [expected_passed, expected_failed, expected_ignored],
        "observed_counts": [parsed["passed"], parsed["failed"], parsed["ignored"]],
    })
    return parsed
def execute(report_path: Path, log_dir: Path) -> tuple[int, dict]:
    source_before = build_native.source_digest()
    fixture = OwnedRedisFixture()
    build = None
    runs: list[dict] = []
    failures: list[str] = []
    container_id = None
    try:
        build = build_libtest()
        fixture.start()
        executable = Path(build["executable"])
        plain_environment = child_environment(fixture.url(tls=False), fixture.ca_certificate)
        runs.append(run_case_set(
            executable, "plain", [TEST_FILTER, "--ignored"], plain_environment,
            expected_cases=EXPECTED_CASES, expected_passed=TEST_CASE_COUNT,
            expected_failed=0, expected_ignored=0, log_dir=log_dir,
            secrets=(fixture.secret,),
        ))
        tls_url = fixture.url(tls=True)
        tls_environment = child_environment(tls_url, fixture.ca_certificate)
        runs.append(run_case_set(
            executable, "tls", [TEST_FILTER, "--ignored"], tls_environment,
            expected_cases=EXPECTED_CASES, expected_passed=TEST_CASE_COUNT,
            expected_failed=0, expected_ignored=0, log_dir=log_dir,
            secrets=(fixture.secret,),
        ))
        untrusted_environment = child_environment(tls_url, fixture.untrusted_ca_certificate)
        runs.append(run_case_set(
            executable, "untrusted-ca-refused", ["--ignored", "--exact", NEGATIVE_CASE],
            untrusted_environment, expected_cases=frozenset({NEGATIVE_CASE}),
            expected_passed=0, expected_failed=1, expected_ignored=0,
            log_dir=log_dir, secrets=(fixture.secret,),
        ))
        runs.append(run_case_set(
            executable, "trusted-ca-restored", ["--ignored", "--exact", NEGATIVE_CASE],
            tls_environment, expected_cases=frozenset({NEGATIVE_CASE}),
            expected_passed=1, expected_failed=0, expected_ignored=0,
            log_dir=log_dir, secrets=(fixture.secret,),
        ))
    except Exception as error:  # noqa: BLE001 - report every failure, then clean up
        failures.append(redact(error, (fixture.secret,)))
    finally:
        container_id = fixture.cid or container_id
        failures.extend(fixture.stop())
    source_after = build_native.source_digest()
    if source_before != source_after:
        failures.append("source inputs changed during the contract gate")
    binary_still_matches = False
    if build and Path(build["executable"]).is_file():
        binary_still_matches = sha256_file(Path(build["executable"])) == build["binary_sha256"]
    if build and not binary_still_matches:
        failures.append("test executable changed after the recorded build")
    expected_labels = ["plain", "tls", "untrusted-ca-refused", "trusted-ca-restored"]
    if [run["name"] for run in runs] != expected_labels:
        failures.append("contract gate did not execute all four required runs")
    status = "passed" if not failures else "failed"
    report = {
        "status": status,
        "gate": "optional-state-redis-real-contract",
        "build": build,
        "receipt": build,
        "fixture": {
            "provider": "Redis", "image": REDIS_IMAGE, "image_id": fixture.image_id,
            "image_digest": fixture.image_digest, "version": fixture.version_line,
            "owned_container_id": container_id, "uid_gid": f"{os.getuid()}:{os.getgid()}",
            "plain_port": fixture.plain_port, "tls_port": fixture.tls_port,
            "maxmemory_bytes": MAXMEMORY_BYTES, "eviction": "allkeys-lru",
            "persistence": False, "default_user_disabled": True,
            "tls_ephemeral_ca": True, "loopback_only": True,
            "scope": "disposable single-host fixture; task ACL user has full commands",
        },
        "runs": runs,
        "case_counts": {run["name"]: {
            "passed": run["passed"], "failed": run["failed"], "ignored": run["ignored"],
        } for run in runs},
        "zero_skipped": all(run["ignored"] == 0 for run in runs),
        "source_inputs_sha256": source_before,
        "source_after_all_sha256": source_after,
        "source_still_matches": source_before == source_after,
        "binary_still_matches": binary_still_matches,
        "failures": failures,
        "limits": [
            "one disposable loopback container; no HA, Sentinel, Cluster or physical fault-domain claim",
            "task ACL user permits CONFIG and destructive test commands; not a production ACL model",
            "no serving-cache consumer integration; issue 111 remains incomplete",
        ],
    }
    write_json_atomic(report_path, report, (fixture.secret,))
    summary = {
        "status": status, "report": str(report_path), "image": REDIS_IMAGE,
        "image_digest": fixture.image_digest, "owned_container_id": container_id,
        "runs": report["case_counts"], "failures": failures,
    }
    print(json.dumps(redact_tree(summary, (fixture.secret,)), sort_keys=True))
    return (0 if status == "passed" else 1), report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the owned real-Redis state-redis contract gate.")
    parser.add_argument(
        "--report", type=Path, default=ROOT / "test-results/state-redis-contract.json")
    parser.add_argument(
        "--log-dir", type=Path, default=ROOT / "test-results/state-redis")
    arguments = parser.parse_args(argv)
    try:
        status, _report = execute(arguments.report, arguments.log_dir)
        return status
    except RunnerError as error:
        print(f"check_redis_contract: {redact(error)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
