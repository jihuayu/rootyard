#!/usr/bin/env python3
"""Fast unit tests for scripts/state_services_blob_baseline.py.

Only pure helpers and in-memory fakes run here: no PostgreSQL, S3 profile,
credentials, network, native service or cargo build is required. ``/proc`` is
synthesized in a temporary directory and Git operations are counted on a fake
harness instead of being executed.
"""
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import state_services_blob_baseline as baseline  # noqa: E402

OID = "1" * 40
# A batch window starts at the first barrier release, up to a few microseconds
# before the earliest clone timer starts (worker hand-off into measured_clone).
WINDOW_START_SLACK = 0.005
PG_PORT = 54329
PG_ADDRESS = "127.0.0.1"
PG_ENDPOINT = ([PG_ADDRESS], PG_PORT)
PG_HEX = "0100007F:%04X" % PG_PORT     # 127.0.0.1:54329 as Linux prints it (host-order u32)
LOOPBACK_HEX = "0100007F"              # 127.0.0.1
LOOPBACK_V6_HEX = "00000000000000000000000001000000"  # ::1 exactly as /proc/net/tcp6 prints it
TCP_HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  "
              "timeout inode")


def kernel_inet6(text):
    """Encode an IPv6 address exactly as Linux prints it in /proc/net/tcp6 (host-order u32 words)."""
    import ipaddress
    packed = ipaddress.IPv6Address(text).packed
    return "".join(packed[index:index + 4][::-1].hex() for index in range(0, 16, 4)).upper()


def tcp_row(index, local, peer, state="01", inode=1000):
    return ("%4d: %s %s %s 00000000:00000000 00:00000000 00000000   501        0 %d 1 "
            "0000000000000000 20 4 30 10 -1" % (index, local, peer, state, inode))


def table(*rows):
    return "\n".join((TCP_HEADER,) + rows) + "\n"


def resolver_raising(error):
    def resolve(*args):
        raise error
    return resolve


def resolver_for(addresses, port=PG_PORT, family=socket.AF_INET):
    """A getaddrinfo stand-in that records calls and never touches the network."""
    calls = []

    def resolve(host, service, *flags):
        calls.append((host, service) + flags)
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port)) for address in addresses]

    resolve.calls = calls
    return resolve


class FakeHelper:
    """Stands in for BlobOnlyHarness: isolated psql helper plus fixture redaction."""

    def __init__(self, rows=("1|0|1|0",)):
        self.rows = list(rows)
        self.queries = []
        self.secrets = ["s3cr3t-endpoint-value"]

    def redact(self, value):
        text = str(value)
        for secret in self.secrets:
            text = text.replace(secret, "[REDACTED]")
        return text

    def sql(self, query):
        self.queries.append(query)
        value = self.rows.pop(0) if len(self.rows) > 1 else self.rows[0]
        if isinstance(value, Exception):
            raise value
        return value


class FakeProc:
    """A temporary /proc subtree with one process's fd links and network tables."""

    def __init__(self, pid=4242):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.pid = pid
        (self.root / str(pid) / "fd").mkdir(parents=True)
        (self.root / str(pid) / "net").mkdir(parents=True)
        for name in ("tcp", "tcp6"):
            (self.root / str(pid) / "net" / name).write_text(table())
        self.set_links(["socket:[1000]"])

    def write_net(self, name, rows):
        (self.root / str(self.pid) / "net" / name).write_text(table(*rows))

    def set_links(self, links):
        fd = self.root / str(self.pid) / "fd"
        for entry in fd.iterdir():
            entry.unlink()
        for index, link in enumerate(links):
            (fd / str(10 + index)).symlink_to(link)

    def owned_connection(self, **row):
        settings = {"local": LOOPBACK_HEX + ":CE2B", "peer": PG_HEX, "inode": 1000}
        settings.update(row)
        self.write_net("tcp", (tcp_row(0, settings["local"], settings["peer"],
                                       state=settings.get("state", "01"), inode=settings["inode"]),))

    def close(self):
        self.directory.cleanup()


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid

    def poll(self):
        return None


class FakeGitHarness(FakeHelper):
    """A fake BlobOnlyHarness: in-memory files, counted clones, injectable clock."""

    def __init__(self, files, pid=500, object_format="sha1"):
        super().__init__()
        self.files = files
        self.proc = FakeProcess(pid)
        self.ready = False
        self.clones = []            # (remote, destination name, token) per git clone
        self.fsck = []              # destinations whose local fsck ran
        self.root = Path(tempfile.mkdtemp(prefix="blob-baseline-fake-"))
        self.base = "http://fixture.invalid"
        self.reader = {"username": "alice", "token": "reader-token-value"}
        self.alice = {"username": "alice", "token": "writer-token-value"}
        self.object_format_name = object_format
        self.delay = 0.02               # wall-clock mode: clone duration
        self.verification_delay = 0.0   # wall-clock mode: optional verification delay
        self.clone_failures = {}        # per instance: destination name -> exception
        self.clock = None               # set by patch_clock: the batch's deterministic clock

    def _write_tree(self, destination):
        destination = Path(destination)
        for name, data in self.files.items():
            (destination / name).parent.mkdir(parents=True, exist_ok=True)
            (destination / name).write_bytes(data)
        (destination / ".git").mkdir(exist_ok=True)
        return destination

    def clone(self, remote, destination, token=None):
        import time
        self.clones.append((remote, Path(destination).name, token))
        try:
            time.sleep(self.delay)
            failure = self.clone_failures.get(Path(destination).name)
            if failure is not None:
                raise failure
        finally:
            pass
        return self._write_tree(destination)

    def verify_tick(self):
        """Wall-clock mode only: optional local-check delay."""
        import time
        if self.verification_delay:
            time.sleep(self.verification_delay)

    def object_format(self, work):
        self.verify_tick()
        return self.object_format_name

    def git(self, *args, cwd=None, token=None, check=True, **kwargs):
        self.verify_tick()
        if "fsck" in args:
            self.fsck.append(Path(cwd).name)
        return mock.Mock(stdout=OID.encode() + b"\n", stderr=b"", returncode=0)

    def patch_clock(self, test):
        """A deterministic clock shared by the clone timers and the aggregate window.

        It advances only while a clone runs (exactly ``delay`` per clone), so
        each worker's clone timer and the aggregate are exact, independent of
        host sleep jitter or scheduling. Verification never advances it; that a
        window excludes verification is proven on real wall time instead.
        """
        clock = {"t": 0.0}

        def now():
            return clock["t"]

        def virtual_clone(remote, destination, token=None):
            self.clones.append((remote, Path(destination).name, token))
            clock["t"] += self.delay
            failure = self.clone_failures.get(Path(destination).name)
            if failure is not None:
                raise failure
            return self._write_tree(destination)

        patcher = mock.patch.object(self, "clone", side_effect=virtual_clone)
        patcher.start()
        test.addCleanup(patcher.stop)
        self.clone_clock = now  # every worker's clone timer uses this clock
        test.addCleanup(lambda: setattr(self, "clone_clock", None))
        return now

    def cleanup(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)


def summary(**overrides):
    value = baseline.summarize_samples([baseline.sample_row(2, 1, 1, 0)], scans_without_connection=0)
    value.update(overrides)
    return value


def push(**overrides):
    value = {"returncode": 0, "stdout": "*\trefs/heads/main:refs/heads/main\t[new branch]\n",
             "oid": OID, "expected_oid": OID, "remote_oid": OID, "push_wall_seconds": 0.42,
             "ls_remote_seconds": 0.01, "payload_bytes": 262144}
    value.update(overrides)
    return value


def worker(index, **overrides):
    value = {"label": "worker-" + str(index + 1), "kind": "read_clone", "repository": baseline.REPOSITORY_NAME,
             "destination": "concurrent-worker-" + str(index + 1), "seconds": 0.4,
             "verification_seconds": 0.05, "head_oid": OID, "expected_oid": OID,
             "files_verified": True, "fsck": True}
    value.update(overrides)
    return value


def restart(epoch=1, **overrides):
    value = {"name": "restart", "status": "passed", "seconds": 1.5, "service_epoch": epoch, "sampled": False,
             "pg_samples": None, "skip_reason": "infrastructure case: the process is replaced",
             "from_epoch": epoch - 1, "old_pid": 500, "new_pid": 501, "samples_stopped_before_stop": True,
             "detail": {}}
    value.update(overrides)
    return value


def case_fixture(epochs=(0, 0, 0, 1, 1)):
    values = []
    for name, epoch in zip(baseline.CASE_ORDER, epochs):
        if name == "restart":
            values.append({key: value for key, value in restart(epoch).items() if key in (
                "name", "status", "seconds", "service_epoch", "sampled", "pg_samples", "skip_reason",
                "from_epoch", "old_pid", "new_pid", "samples_stopped_before_stop")})
            continue
        detail = {"push": push()} if name == "seed_push" else {}
        values.append({"name": name, "status": "passed", "seconds": 0.25, "service_epoch": epoch,
                       "sampled": True, "pg_samples": summary(), "detail": detail})
    return values


def cold_fixture(**overrides):
    value = {"seconds": 0.3, "service_restarted": True, "scratch_empty_before": True,
             "scratch_empty_after": True, "head_oid": OID, "expected_oid": OID, "files_verified": True,
             "fsck": True, "verification_seconds": None, "samples_across_restart": False}
    value.update(overrides)
    return value


def workload():
    files = baseline.select_workload()
    return {**baseline.describe_workload(files), "version": baseline.WORKLOAD_VERSION, "mode": baseline.READ_MODE,
            "concurrency": baseline.CONCURRENCY, "repositories_provisioned_via": "POST /api/repos",
            "fingerprint_sha256": baseline.workload_fingerprint(files)}


BINDING = {"attested": True, "inputs_unchanged": True, "binary_sha256": "a" * 64,
           "source_inputs_sha256": "b" * 64, "build_receipt_sha256": "c" * 64, "runner_sha256": "d" * 64,
           "harness_sha256": "e" * 64, "trusted_git_sha256": "f" * 64, "workspace_commit": "0" * 40,
           "rustc": "rustc 1", "inputs": {"runner": "d" * 64, "tests/blob_only_service.py": "e" * 64}}
CGROUP_UNAVAILABLE = {"version": "v2",
                      **{key: {"status": "unavailable", "raw": "unavailable", "format": "cgroup-v2",
                               "source": "unavailable"}
                         for key in ("cpu_max", "cpuset_cpus_effective", "memory_max")}}
RUNTIME = {"git_version": "git version 2", "psql_version": "psql (17)", "postgres_server_version": "17.1",
           "python": "3.12.0", "kernel": "6.1.0", "machine": "x86_64", "architecture": "x86_64",
           "cpu_model": "Fixture CPU Model 1", "hostname": "fixture", "logical_cpus": 4,
           "host_memory_total_kb": 1024, "procfs": True,
           "cgroup": {**CGROUP_UNAVAILABLE}}


class SocketAddressTest(unittest.TestCase):
    """Decoding follows Linux's host-order printing, using addresses a kernel actually produced."""

    def test_decodes_inet_and_kernel_tcp6_rows(self):
        self.assertEqual(baseline.decode_socket_address("0100007F:CE2B"), ("inet", "127.0.0.1", 52779))
        # Observed on the Linux runner image: ::1 is printed host-order per u32 word.
        self.assertEqual(baseline.decode_socket_address(LOOPBACK_V6_HEX + ":CE2B"), ("inet6", "::1", 52779))
        self.assertEqual(baseline.decode_socket_address("00000000000000000000000000000000:0016"),
                         ("inet6", "::", 22))
        self.assertEqual(baseline.decode_socket_address("B80D0120000000000000000000000000:1F90"),
                         ("inet6", "2001:db8::", 8080))
        self.assertEqual(baseline.decode_socket_address("00000000000000000000000000000001:0016"),
                         ("inet6", "::100:0", 22))

    def test_rejects_malformed_endpoints(self):
        for value in ("", "0100007F", "0100007F:CE2", "zz00007F:0016", "0100007F:CE2B:00", None, 7):
            with self.subTest(value=value), self.assertRaises(ValueError):
                baseline.decode_socket_address(value)

    def test_rejects_table_without_header_or_bad_rows(self):
        with self.assertRaises(ValueError):
            baseline.parse_proc_net_tcp("")
        with self.assertRaises(ValueError):
            baseline.parse_proc_net_tcp("  sl local_address\n 0: bad row\n")
        with self.assertRaises(ValueError):  # queue without "tx:rx"
            baseline.parse_proc_net_tcp(table(tcp_row(0, LOOPBACK_HEX + ":CE2B", PG_HEX)
                                              .replace(" 00000000:00000000 ", " 00000000 ")))
        with self.assertRaises(ValueError):  # non-hex socket state
            baseline.parse_proc_net_tcp(table(tcp_row(0, LOOPBACK_HEX + ":CE2B", PG_HEX, state="qq")))

    def test_tcp6_fixture_decodes_the_observed_loopback_peer(self):
        proc = FakeProc()
        try:
            proc.write_net("tcp6", (tcp_row(0, LOOPBACK_V6_HEX + ":CE2B", LOOPBACK_V6_HEX + ":%04X" % PG_PORT,
                                            inode=1000),))
            index = baseline.PgPortIndex(proc.pid, (["::1"], PG_PORT), proc=proc.root)
            # The ::1 peer matches the configured ::1 endpoint: one owned endpoint socket.
            self.assertEqual(index.count, 1)
            self.assertEqual(index.sockets, [("inet6", "::1", PG_PORT)])
        finally:
            proc.close()


class EndpointResolutionTest(unittest.TestCase):
    def test_resolves_once_and_maps_ipv6(self):
        resolver = resolver_for(["::ffff:127.0.0.1", "127.0.0.1"], family=socket.AF_INET6)
        endpoint = baseline.resolve_pg_endpoint("postgresql://u:pw@db.internal:54329/svc", resolver=resolver)
        self.assertEqual(endpoint, (["127.0.0.1"], 54329))
        self.assertEqual(len(resolver.calls), 1)  # resolved once, never again inside psql
        self.assertEqual(len(baseline.resolve_pg_endpoint(
            "postgres://u:pw@localhost/db", resolver=resolver_for(["::1"], port=5432))[0]), 1)
        self.assertEqual(baseline.resolve_pg_endpoint("postgres://u@h/db", resolver=resolver_for(["127.0.0.1"],
                                                                                                 port=5432)),
                         (["127.0.0.1"], 5432))

    def test_unsupported_endpoints_fail_without_echoing_them(self):
        cases = [("postgresql://u:pw@/var/run/postgresql", resolver_for(["127.0.0.1"])),
                 ("postgresql://u:pw@socket-host/db", resolver_for(["127.0.0.1"], family=socket.AF_UNIX)),
                 ("postgresql://u:pw@udp-host/db", resolver_for(["127.0.0.1"], family=socket.AF_INET)),
                 ("postgresql://u:pw@broken-host.internal/db", resolver_raising(RuntimeError("cannot resolve"))),
                 ("postgresql://u:pw@empty-host.internal/db", resolver_for([])),
                 ("postgresql://u:pw@text-host.internal/db", resolver_for(["not-an-address"]))]
        for url, resolve in cases:
            with self.subTest(url=url), self.assertRaises(baseline.ScanFailure) as raised:
                baseline.resolve_pg_endpoint(url, resolver=resolve)
            self.assertNotIn("internal", str(raised.exception))
            self.assertNotIn("pw", str(raised.exception))

    def test_unix_socket_dsn_is_rejected_with_a_clear_reason(self):
        with self.assertRaises(baseline.ScanFailure) as raised:
            baseline.resolve_pg_endpoint("postgresql:///svc", resolver=resolver_for(["127.0.0.1"]))
        self.assertIn("TCP host", str(raised.exception))


class PgEndpointTest(unittest.TestCase):
    """pg_endpoint accepts a Docker published port: DSN 55433 -> server listen 5432."""

    def test_published_host_port_is_accepted_and_server_listen_port_is_not_queried(self):
        resolver = resolver_for(["127.0.0.1"], port=55433)
        harness = mock.Mock()
        harness.db = "postgresql://u:pw@db-published.invalid:55433/svc"
        with mock.patch.object(baseline.socket, "getaddrinfo", side_effect=resolver) as getaddrinfo:
            endpoint = baseline.pg_endpoint(harness)
        # The resolver ran exactly once for the configured host, TCP port and stream type.
        getaddrinfo.assert_called_once_with("db-published.invalid", 55433, socket.AF_UNSPEC, socket.SOCK_STREAM)
        self.assertEqual(resolver.calls, [("db-published.invalid", 55433, socket.AF_UNSPEC, socket.SOCK_STREAM)])
        # The parsed client endpoint is returned verbatim; no server-side port comparison exists.
        self.assertEqual(endpoint, (["127.0.0.1"], 55433))
        harness.sql.assert_not_called()
        # Even a server reporting the container-internal listen port changes nothing.
        with mock.patch.object(baseline, "resolve_pg_endpoint", return_value=(["127.0.0.1"], 55433)):
            harness.sql.return_value = "5432"
            self.assertEqual(baseline.pg_endpoint(harness), (["127.0.0.1"], 55433))
        harness.sql.assert_not_called()
        self.assertNotIn("db-published.invalid", repr(endpoint))


class OwnershipTest(unittest.TestCase):
    """Only the service process's own ESTABLISHED sockets to the configured database endpoint count."""

    def owned(self, fd_links, rows, endpoint=PG_ENDPOINT):
        return baseline.pg_endpoint_sockets(fd_links, {"tcp": baseline.parse_proc_net_tcp(table(*rows))}, endpoint)

    def test_only_established_owned_sockets_to_the_configured_endpoint_count(self):
        rows = (tcp_row(0, LOOPBACK_HEX + ":CE2B", PG_HEX, inode=1000),
                tcp_row(1, LOOPBACK_HEX + ":CE2C", LOOPBACK_HEX + ":0050", inode=1001),
                tcp_row(2, LOOPBACK_HEX + ":CE2D", PG_HEX, inode=1002, state="06"),
                tcp_row(3, LOOPBACK_HEX + ":CE2E", PG_HEX, inode=1003))
        self.assertEqual(self.owned(["socket:[1000]", "socket:[1001]", "socket:[1002]"], rows),
                         [("inet", PG_ADDRESS, PG_PORT)])

    def test_sessions_the_process_does_not_own_are_ignored(self):
        rows = (tcp_row(0, LOOPBACK_HEX + ":CE2B", PG_HEX, inode=1000),)
        self.assertEqual(self.owned(["socket:[2000]", "pipe:[3]", "anon_inode:[eventfd]"], rows), [])
        self.assertEqual(self.owned([], rows), [])

    def test_another_server_on_the_same_port_is_not_the_configured_database(self):
        rows = (tcp_row(0, LOOPBACK_HEX + ":CE2B", "0100000A:%04X" % PG_PORT, inode=1000),
                tcp_row(1, LOOPBACK_HEX + ":CE2C", "0100007F:%04X" % (PG_PORT + 1), inode=1001))
        self.assertEqual(self.owned(["socket:[1000]", "socket:[1001]"], rows), [])

    def test_repeated_endpoint_sockets_are_counted_with_multiplicity(self):
        # Four pool/barrier sockets to one endpoint each: counted, never de-duplicated.
        rows = tuple(tcp_row(index, LOOPBACK_HEX + ":%04X" % (41000 + index), PG_HEX, inode=1000 + index)
                     for index in range(4))
        owned = self.owned(["socket:[%d]" % (1000 + index) for index in range(4)], rows)
        self.assertEqual(len(owned), 4)
        self.assertEqual(set(owned), {("inet", PG_ADDRESS, PG_PORT)})

    def test_endpoint_is_required_and_validated(self):
        rows = (tcp_row(0, LOOPBACK_HEX + ":CE2B", PG_HEX, inode=1000),)
        for endpoint in ((), ([], PG_PORT), (["127.0.0.1"], 0), (["127.0.0.1"], "54329"), ("127.0.0.1", PG_PORT)):
            with self.subTest(endpoint=endpoint), self.assertRaises(baseline.BaselineError):
                self.owned(["socket:[1000]"], rows, endpoint)

    def test_invalid_socket_links_raise(self):
        for link in ("socket:[abc]", "socket:12]", "socket:[12"):
            with self.subTest(link=link), self.assertRaises(ValueError):
                baseline.parse_fd_links([link])

    def test_index_reads_only_this_process_proc_subtree(self):
        proc = FakeProc()
        try:
            proc.write_net("tcp", (tcp_row(0, LOOPBACK_HEX + ":CE2B", PG_HEX, inode=1000),
                                   tcp_row(1, LOOPBACK_HEX + ":CE2C", PG_HEX, inode=1002)))
            index = baseline.PgPortIndex(proc.pid, PG_ENDPOINT, proc=proc.root)
            self.assertEqual(index.count, 1)
            proc.set_links(["socket:[1002]"])
            self.assertEqual(index.rescan(), 1)
            proc.set_links([])
            self.assertEqual(index.rescan(), 0)
        finally:
            proc.close()

    def test_scan_never_reports_the_endpoint(self):
        proc = FakeProc()
        try:
            proc.write_net("tcp", (tcp_row(0, LOOPBACK_HEX + ":CE2B", PG_HEX, inode=1000),))
            index = baseline.PgPortIndex(proc.pid, PG_ENDPOINT, proc=proc.root)
            self.assertEqual(index.count, 1)
            (proc.root / str(proc.pid) / "net" / "tcp").write_text("")
            with self.assertRaises(baseline.ScanFailure) as raised:
                index.rescan()
            self.assertNotIn(str(PG_PORT), str(raised.exception))
            self.assertNotIn(PG_ADDRESS, str(raised.exception))
        finally:
            proc.close()


class CountConsistencyTest(unittest.TestCase):
    def test_equal_nonzero_counts_pass(self):
        self.assertEqual(baseline.count_consistency(4, 4), 4)
        self.assertEqual(baseline.count_consistency(1, 1), 1)

    def test_zero_or_unequal_counts_fail_closed(self):
        for owned, named in ((0, 0), (4, 0), (4, 3), (3, 4), (-1, 1), (4, True), (4, "4"), (None, 1)):
            with self.subTest(owned=owned, named=named), self.assertRaises(baseline.BaselineError):
                baseline.count_consistency(owned, named)


class NoServiceSessionsTest(unittest.TestCase):
    """Pre-start gate: fixed literal SQL, four non-negative integers, zero sessions."""

    def test_empty_session_check_passes_with_the_fixed_literal_sql(self):
        helper = FakeHelper(rows=("0|0|0|0",))
        self.assertEqual(baseline.require_no_service_sessions(helper), 0)
        self.assertEqual(helper.queries, [baseline.PG_STAT_QUERY])
        self.assertEqual(baseline.require_no_service_sessions(FakeHelper(rows=("0|0|0|0",))), 0)

    def test_existing_sessions_are_rejected_fail_closed(self):
        for row in ("1|0|1|0", "4|3|1|0"):
            helper = FakeHelper(rows=(row,))
            with self.subTest(row=row), self.assertRaises(baseline.BaselineError) as raised:
                baseline.require_no_service_sessions(helper)
            self.assertIn("service sessions already exist before a service start", str(raised.exception))
            self.assertEqual(helper.queries, [baseline.PG_STAT_QUERY])

    def test_malformed_or_failed_checks_raise_fixed_safe_errors(self):
        for row in ("", "0|0|0", "0|0|0|0|0", "0|-1|0|0", "0|x|0|0", "0.0|0|0|0", None, 0,
                    # count(*)/FILTER never return NULL; a NULL row is malformed and never read as zero.
                    "|0|0|0",
                    RuntimeError("connect failed to s3cr3t-endpoint-value")):
            helper = FakeHelper(rows=(row,))
            if row is None or isinstance(row, Exception):  # no row / helper failure is never zero
                with self.subTest(row=row), self.assertRaises(RuntimeError):
                    baseline.require_no_service_sessions(helper)
                continue
            with self.subTest(row=row), self.assertRaises(baseline.BaselineError) as raised:
                baseline.require_no_service_sessions(helper)
            self.assertNotIn("s3cr3t", str(raised.exception))
            self.assertIn("four non-negative integers", str(raised.exception))


class SamplerTest(unittest.TestCase):
    def sampler(self, proc, helper, interval=0.25, endpoint=PG_ENDPOINT):
        sampler = baseline.PgSampler(helper, proc.pid, endpoint, proc=proc.root, interval=interval)
        return sampler

    def ready(self, proc):
        proc.owned_connection()

    def four_endpoint_sockets(self, proc):
        """Four PID-owned ESTABLISHED sockets to the configured endpoint with local client ports."""
        proc.write_net("tcp", tuple(tcp_row(index, LOOPBACK_HEX + ":%04X" % (41000 + index), PG_HEX,
                                            inode=1000 + index) for index in range(4)))
        proc.set_links(["socket:[%d]" % (1000 + index) for index in range(4)])

    def test_query_selects_current_database_rows_by_source_application_names(self):
        proc = FakeProc()
        helper = FakeHelper(rows=("1|0|1|0",))
        try:
            self.ready(proc)
            sampler = self.sampler(proc, helper)
            sample = sampler.scan_once()
            self.assertEqual(sample, {"sessions": 1, "active": 0, "idle": 1, "lock": 0})
            query = helper.queries[0]
            self.assertEqual(query, baseline.PG_STAT_QUERY)  # fixed literal, nothing interpolated
            self.assertIn("FROM pg_stat_activity WHERE datname=current_database() "
                          "AND application_name IN ('rootyard', 'rootyard-blob-barrier')", query)
            # The NAT-sensitive client pair never enters SQL or the ownership decision.
            for fragment in ("client_addr", "client_port", "52779", PG_ADDRESS, str(PG_PORT)):
                self.assertNotIn(fragment, query)
        finally:
            proc.close()

    def test_nat_rewritten_client_addresses_are_accepted_when_counts_agree(self):
        """Docker host network -> published PG port: server client_addr/ports differ from local ones."""
        proc = FakeProc()
        try:
            self.four_endpoint_sockets(proc)
            sampler = self.sampler(proc, FakeHelper(rows=("4|2|2|1",)))
            self.assertEqual(sampler.scan_once(), {"sessions": 4, "active": 2, "idle": 2, "lock": 1})
            # The PID's local ports are 41000..41003; the server saw other addresses/ports entirely.
            server_rows = (("172.18.0.1", 55110, "rootyard"), ("172.18.0.1", 55111, "rootyard"),
                           ("172.18.0.1", 55112, "rootyard"), ("172.18.0.1", 55113, "rootyard-blob-barrier"))
            self.assertFalse({port for _, port, _ in server_rows} & set(range(41000, 41004)))
            self.assertTrue(all(application in baseline.SERVICE_APPLICATION_NAMES
                                for _, _, application in server_rows))
            self.assertNotIn("client_port", sampler.helper.queries[0])
        finally:
            proc.close()

    def test_admin_and_psql_rows_are_not_named_and_never_counted(self):
        proc = FakeProc()
        try:
            self.four_endpoint_sockets(proc)
            # The server-side tally excludes the runner's psql helper and admin sessions by name: only
            # the four named sessions are counted even though other rows exist on the database.
            sampler = self.sampler(proc, FakeHelper(rows=("4|3|1|0",)))
            self.assertEqual(sampler.scan_once()["sessions"], 4)
            for other in ("psql", "runner", "postgres"):
                self.assertNotIn(other, baseline.SERVICE_APPLICATION_NAMES)
        finally:
            proc.close()

    def test_zero_named_rows_fail_even_with_owned_sockets(self):
        proc = FakeProc()
        try:
            self.four_endpoint_sockets(proc)
            sampler = self.sampler(proc, FakeHelper(rows=("0|0|0|0",)))
            with self.assertRaises(baseline.BaselineError) as raised:
                sampler.scan_once()
            self.assertIn("no named PostgreSQL session", str(raised.exception))
            self.assertTrue(sampler.errors)
            with self.assertRaises(baseline.BaselineError):
                sampler.scan_once()  # sticky: never silently skipped
        finally:
            proc.close()

    def test_unequal_named_and_owned_counts_fail_closed(self):
        proc = FakeProc()
        try:
            self.four_endpoint_sockets(proc)
            # Named and owned counts that disagree (fewer named, no named, more named) fail closed.
            for row, expected in (("3|1|2|0", "differ from the service PID"), ("0|0|0|0", "no named PostgreSQL session"),
                                  ("2|0|2|0", "differ from the service PID")):
                sampler = self.sampler(proc, FakeHelper(rows=(row,)))
                with self.subTest(row=row), self.assertRaises(baseline.BaselineError) as raised:
                    sampler.scan_once()
                self.assertIn(expected, str(raised.exception))
                self.assertEqual(sampler.samples, [])
        finally:
            proc.close()

    def test_interval_below_bound_is_rejected(self):
        proc = FakeProc()
        try:
            with self.assertRaises(baseline.BaselineError):
                self.sampler(proc, FakeHelper(), interval=0.1)
        finally:
            proc.close()

    def test_scan_without_owned_connection_is_counted_not_sampled(self):
        proc = FakeProc()
        try:
            proc.write_net("tcp", (tcp_row(0, LOOPBACK_HEX + ":CE2B", PG_HEX, inode=9999),))
            sampler = self.sampler(proc, FakeHelper())
            self.assertIsNone(sampler.scan_once())
            self.assertEqual(sampler.scans_without_connection, 1)
            self.assertEqual(sampler.samples, [])
        finally:
            proc.close()

    def test_begin_and_end_require_an_owned_service_session(self):
        proc = FakeProc()
        try:
            self.ready(proc)
            sampler = self.sampler(proc, FakeHelper())

            class IdleThread:
                def __init__(self, **_):
                    pass

                def start(self):
                    return None

                def join(self, timeout=None):
                    return None

                def is_alive(self):
                    return False

            with mock.patch.object(baseline.threading, "Thread", IdleThread):
                sampler.start(timeout=0.05)
            self.assertEqual(sampler.finish()["samples"], 2)
        finally:
            proc.close()

    def test_missing_connection_at_boundary_fails_the_run(self):
        proc = FakeProc()
        try:
            self.ready(proc)
            sampler = self.sampler(proc, FakeHelper())
            sampler.scan_once()
            proc.set_links(["socket:[9999]"])
            with self.assertRaises(baseline.BaselineError):
                sampler.finish()
        finally:
            proc.close()

    def test_sql_error_is_visible_redacted_and_fails(self):
        proc = FakeProc()
        helper = FakeHelper(rows=(RuntimeError("could not connect to s3cr3t-endpoint-value"),))
        try:
            self.ready(proc)
            sampler = self.sampler(proc, helper)
            with self.assertRaises(baseline.BaselineError) as raised:
                sampler.scan_once()
            self.assertNotIn("s3cr3t-endpoint-value", str(raised.exception))
            self.assertIn("[REDACTED]", str(raised.exception))
            self.assertTrue(sampler.errors)
            with self.assertRaises(baseline.BaselineError):
                sampler.scan_once()  # sticky failure: later samples are never silently skipped
        finally:
            proc.close()

    def test_malformed_query_row_fails(self):
        proc = FakeProc()
        try:
            self.ready(proc)
            for row in ("3|1|2", "3|x|2|0", "1|2|2|0", "2|1|1|3"):
                sampler = self.sampler(proc, FakeHelper(rows=(row,)))
                with self.subTest(row=row), self.assertRaises(baseline.BaselineError):
                    sampler.scan_once()
        finally:
            proc.close()

    def test_missing_kernel_procfs_fails_closed(self):
        with self.assertRaises(baseline.ScanFailure):
            baseline.PgPortIndex(4242, PG_ENDPOINT, proc=Path(tempfile.gettempdir()) / "absent-proc-for-test")


class SamplerSummaryTest(unittest.TestCase):
    def samples(self, values):
        return [baseline.sample_row(*value) for value in values]

    def test_lower_bound_summary(self):
        value = baseline.summarize_samples(self.samples([(0, 0, 0, 0), (3, 1, 2, 1), (4, 0, 3, 2)]),
                                           scans_without_connection=1)
        self.assertEqual(value["peak_sessions"], 4)
        self.assertEqual(value["peak_lock_waiters"], 2)
        self.assertEqual(value["samples_with_connection"], 2)
        self.assertTrue(value["observed_lower_bound"])
        self.assertIsNone(value["exact_lock_wait_ms"])
        self.assertIn("application_name IN ('rootyard', 'rootyard-blob-barrier')", value["matched_by"])
        self.assertIn("never compared with client_addr/client_port", value["matched_by"])
        baseline.validate_summary(value)

    def test_independent_peaks_need_not_come_from_one_sample(self):
        value = baseline.summarize_samples(self.samples([(4, 4, 0, 0), (4, 0, 4, 0)]),
                                           scans_without_connection=0)
        self.assertEqual(value["peak_sessions"], 4)
        self.assertEqual(value["peak_active"], 4)
        self.assertEqual(value["peak_idle"], 4)
        baseline.validate_summary(value)

    def test_single_peak_above_peak_sessions_is_rejected(self):
        value = summary()
        for key in ("peak_active", "peak_idle"):
            with self.subTest(key=key), self.assertRaises(baseline.BaselineError):
                baseline.validate_summary({**value, key: 3})

    def test_zero_owned_sessions_fail(self):
        with self.assertRaises(baseline.BaselineError):
            baseline.summarize_samples(self.samples([(0, 0, 0, 0)]), scans_without_connection=0)

    def test_summary_marks_are_required(self):
        value = summary()
        for key, replacement in (("observed_lower_bound", False), ("exact_lock_wait_ms", 12.5),
                                 ("interval_seconds", 0.01), ("errors", ["boom"]), ("peak_lock_waiters", 99)):
            with self.subTest(key=key), self.assertRaises(baseline.BaselineError):
                baseline.validate_summary({**value, key: replacement})

    def test_unbounded_interval_is_rejected(self):
        with self.assertRaises(baseline.BaselineError):
            baseline.summarize_samples(self.samples([(1, 0, 1, 0)]), scans_without_connection=0, interval=0.05)

    def test_sample_row_rejects_inconsistent_counts(self):
        for value in ((-1, 0, 0, 0), (1, 2, 0, 0), (1, 0, 0, 2), ("3", 0, 0, 0), (True, 0, 0, 0)):
            with self.subTest(value=value), self.assertRaises(baseline.BaselineError):
                baseline.sample_row(*value)


class WorkloadTest(unittest.TestCase):
    def test_deterministic_bounded_workload(self):
        first, second = baseline.select_workload(), baseline.select_workload()
        self.assertEqual(first, second)
        self.assertEqual(sum(len(data) for data in first.values()), baseline.MAX_PAYLOAD_BYTES)
        self.assertEqual(baseline.workload_fingerprint(first), baseline.workload_fingerprint(second))

    def test_workload_declaration(self):
        declared = workload()
        self.assertEqual(baseline.validate_workload(declared)["total_bytes"], baseline.MAX_PAYLOAD_BYTES)
        self.assertEqual(baseline.READ_MODE, "single_repository_independent_read_clones")
        for field, value in (("total_bytes", baseline.MAX_PAYLOAD_BYTES + 1), ("concurrency", 8),
                             ("mode", "independent_repository_read_clones"),
                             ("mode", "independent_ref_pushes"),
                             ("repositories_provisioned_via", "SQL"), ("version", 2),
                             ("fingerprint_sha256", "short")):
            with self.subTest(field=field, value=value), self.assertRaises(baseline.BaselineError):
                baseline.validate_workload({**declared, field: value})
        for files in ([{"path": "/etc/passwd", "bytes": 1}], [{"path": "../escape", "bytes": 1}],
                      [{"path": "a//b", "bytes": 1}], [{"path": "a", "bytes": -1}],
                      [{"path": "a", "bytes": 1}, {"path": "a", "bytes": 1}],
                      [{"path": "big", "bytes": baseline.MAX_PAYLOAD_BYTES + 1}], []):
            with self.subTest(files=files), self.assertRaises(baseline.BaselineError):
                baseline.validate_workload({**declared, "files": files})


class ServiceAdmissionTest(unittest.TestCase):
    """Configured admission facts: defaults, overrides and fail-closed capacity."""

    DEFAULT = "src/standalone/config.rs default"
    OVERRIDE = "environment_override"

    def test_defaults_come_from_the_config_rs_values(self):
        env = {}
        facts = baseline.service_admission_facts(env)
        self.assertEqual(env, {})  # read only, never written or overridden
        settings = facts["settings"]
        self.assertEqual(settings["max_concurrent_git"]["value"], 8)
        self.assertEqual(settings["max_request_bytes"]["value"], 128 << 20)
        self.assertEqual(settings["max_inflight_bytes"]["value"], 256 << 20)
        for name in ("max_concurrent_git", "max_request_bytes", "max_inflight_bytes"):
            self.assertEqual(settings[name]["source"], self.DEFAULT)
        self.assertEqual(facts["upload_pack_reservation_bytes"], 128 << 20)
        self.assertEqual(facts["byte_budget_capacity"], 2)
        self.assertEqual(facts["effective_upload_pack_capacity"], 2)
        self.assertEqual(facts["measured_clone_concurrency"], 2)
        self.assertIs(facts["capacity_covers_measured_concurrency"], True)
        self.assertIn("before spooling", facts["explanation"])
        self.assertIn("neither", facts["scope"])

    def test_config_rs_defaults_match_the_runner(self):
        source = (ROOT / "src/standalone/config.rs").read_text()
        for name, default in (("ROOTYARD_MAX_CONCURRENT_GIT", "8"),
                              ("ROOTYARD_MAX_REQUEST_BYTES", "128 << 20"),
                              ("ROOTYARD_MAX_INFLIGHT_BYTES", "256 << 20")):
            self.assertIn('number("%s", %s,' % (name, default), source)

    def test_overrides_keep_their_source_and_derive_capacity(self):
        facts = baseline.service_admission_facts({"ROOTYARD_MAX_CONCURRENT_GIT": "3",
                                                  "ROOTYARD_MAX_REQUEST_BYTES": str(64 << 20),
                                                  "ROOTYARD_MAX_INFLIGHT_BYTES": str(300 << 20)})
        settings = facts["settings"]
        self.assertEqual([settings[name]["value"] for name in
                          ("max_concurrent_git", "max_request_bytes", "max_inflight_bytes")],
                         [3, 64 << 20, 300 << 20])
        for name in ("max_concurrent_git", "max_request_bytes", "max_inflight_bytes"):
            self.assertEqual(settings[name]["source"], self.OVERRIDE)
        self.assertEqual(facts["upload_pack_reservation_bytes"], 64 << 20)
        self.assertEqual(facts["byte_budget_capacity"], 4)
        self.assertEqual(facts["effective_upload_pack_capacity"], 3)  # bounded by max concurrent Git
        # A Git limit alone is the binding one when the byte budget is wider.
        git_bound = baseline.service_admission_facts({"ROOTYARD_MAX_CONCURRENT_GIT": "2"})
        self.assertEqual(git_bound["byte_budget_capacity"], 2)
        self.assertEqual(git_bound["effective_upload_pack_capacity"], 2)

    def test_byte_budget_of_one_fails_closed(self):
        for env in ({"ROOTYARD_MAX_INFLIGHT_BYTES": str(128 << 20)},
                    {"ROOTYARD_MAX_REQUEST_BYTES": str(200 << 20)},
                    {"ROOTYARD_MAX_CONCURRENT_GIT": "1"}):
            with self.subTest(env=env), self.assertRaises(baseline.BaselineError) as raised:
                baseline.service_admission_facts(env)
            for value in env.values():
                self.assertNotIn(value, str(raised.exception))

    def test_invalid_values_fail_closed_without_echoing_them(self):
        for env in ({"ROOTYARD_MAX_CONCURRENT_GIT": "four"}, {"ROOTYARD_MAX_REQUEST_BYTES": "-1"},
                    {"ROOTYARD_MAX_INFLIGHT_BYTES": "1_000"},
                    {"ROOTYARD_MAX_INFLIGHT_BYTES": " 1024"}, {"ROOTYARD_MAX_CONCURRENT_GIT": ""},
                    {"ROOTYARD_MAX_REQUEST_BYTES": "\u0661"}, {"ROOTYARD_MAX_CONCURRENT_GIT": "257"},
                    {"ROOTYARD_MAX_REQUEST_BYTES": str(64 << 10 - 1)},
                    {"ROOTYARD_MAX_INFLIGHT_BYTES": str(16 << 30 + 1)},
                    {"ROOTYARD_MAX_CONCURRENT_GIT": None}):
            with self.subTest(env=env), self.assertRaises(baseline.BaselineError) as raised:
                baseline.service_admission_facts(env)
            for value in env.values():
                if isinstance(value, str) and len(value) > 1:
                    self.assertNotIn(value.strip(), str(raised.exception))

    def test_report_refuses_tampered_admission_facts(self):
        facts = baseline.service_admission_facts({})
        tampered = [
            {"byte_budget_capacity": 4},
            {"effective_upload_pack_capacity": 8},
            {"measured_clone_concurrency": 4},
            {"capacity_covers_measured_concurrency": False},
            {"upload_pack_reservation_bytes": 1},
            {"scope": "measured throughput"},
        ]
        for override in tampered:
            with self.subTest(override=override), self.assertRaises(baseline.BaselineError):
                report_payload(admission={**facts, **override})
        settings = json.loads(json.dumps(facts["settings"]))
        settings["max_request_bytes"]["value"] = 64 << 20
        with self.assertRaises(baseline.BaselineError):
            report_payload(admission={**facts, "settings": settings})


class PushTest(unittest.TestCase):
    def test_validated_summaries_are_not_measurements(self):
        # A report must be assembled from the measured push, never from its summary.
        measured = baseline.validate_push_summary(push())
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_push_result(measured)  # summary without its raw push evidence
        raw_measurement = {**push(), **measured}    # exactly what run_push returns
        self.assertIsNone(baseline.validate_push_result(raw_measurement))

    def test_push_wall_time_is_preserved_and_kept_apart_from_ls_remote(self):
        result = baseline.validate_push_summary(push(push_wall_seconds=0.375, ls_remote_seconds=0.02))
        self.assertEqual(result["push_wall_seconds"], 0.375)
        self.assertEqual(result["ls_remote_seconds"], 0.02)
        self.assertEqual(result["payload_bytes"], 262144)
        self.assertNotIn("seconds", result)  # never folded into the setup or case duration

    def test_push_requires_a_measured_duration(self):
        for override in ({"push_wall_seconds": None}, {"push_wall_seconds": -1}, {"push_wall_seconds": "1"},
                         {"push_wall_seconds": float("nan")}):
            with self.subTest(override=override), self.assertRaises(baseline.BaselineError):
                baseline.validate_push_summary(push(**override))

    def test_push_content_rules(self):
        for override in ({"returncode": 1}, {"stdout": "!\trefs/heads/main:refs/heads/main\t[rejected]\n"},
                         {"stdout": ""}, {"remote_oid": "2" * 40}, {"oid": "short"}, {"expected_oid": "2" * 40},
                         {"ls_remote_seconds": -1}, {"payload_bytes": -1}):
            with self.subTest(override=override), self.assertRaises(baseline.BaselineError):
                baseline.validate_push_summary(push(**override))

    def test_report_carries_the_measured_push_duration(self):
        payload = report_payload()
        self.assertEqual(payload["seed_push"]["push_wall_seconds"], 0.42)
        self.assertEqual(payload["seed_push"]["ls_remote_seconds"], 0.01)


class SingleCloneTest(unittest.TestCase):
    """Each read issues exactly one git clone; verification never clones again."""

    def setUp(self):
        self.files = baseline.select_workload()
        self.harness = FakeGitHarness(self.files)
        self.seed = {"remote": "http://fixture.invalid/git/alice/blob-baseline.git", "oid": OID,
                     "files": self.files}

    def tearDown(self):
        self.harness.cleanup()

    def test_worker_clones_once_per_destination(self):
        self.harness.patch_clock(self)
        records = [baseline.measured_clone(self.harness, self.seed["remote"],
                                           self.harness.root / ("concurrent-worker-" + str(index + 1)),
                                           self.seed["oid"], self.seed["files"], self.harness.reader,
                                           "read_clone", "worker-" + str(index + 1),
                                           repository=baseline.REPOSITORY_NAME)
                   for index in range(4)]
        self.assertEqual(len(self.harness.clones), 4)
        self.assertEqual(sorted(name for _, name, _ in self.harness.clones),
                         ["concurrent-worker-1", "concurrent-worker-2", "concurrent-worker-3",
                          "concurrent-worker-4"])
        self.assertTrue(all(remote == self.seed["remote"] for remote, _, _ in self.harness.clones))
        self.assertTrue(all(token is self.harness.reader for _, _, token in self.harness.clones))
        for index, record in enumerate(records):
            self.assertEqual(record["label"], "worker-" + str(index + 1))
            self.assertEqual(record["destination"], "concurrent-worker-" + str(index + 1))
            self.assertEqual(record["head_oid"], OID)
            self.assertEqual(len(self.harness.clones), len(self.harness.fsck))  # one clone, one fsck
            self.assertIn("OID/file/fsck checks", record["timed_scope"])

    def test_concurrent_batch_clones_once_per_worker(self):
        # Real wall time, the normal FakeGitHarness.clone: each clone really sleeps.
        self.harness.delay = 0.15
        started = time.monotonic()
        workers, aggregate_seconds, record = baseline.run_concurrent_reads(self.harness, self.seed)
        elapsed = time.monotonic() - started
        self.assertEqual(len(self.harness.clones), baseline.CONCURRENCY)
        self.assertEqual(len(workers), baseline.CONCURRENCY)
        self.assertGreater(aggregate_seconds, 0)
        self.assertEqual(len(record["workers"]), baseline.CONCURRENCY)
        self.assertEqual(len({worker["destination"] for worker in record["workers"]}), baseline.CONCURRENCY)
        self.assertFalse(record["includes_local_verification"])
        self.assertIn("never compared or summed", record["verification_scope"])
        self.assertFalse(record["concurrent_write_pushes"])
        # Every clone took at least `delay`, and the two really overlapped: the
        # aggregate is far below their sum (serial clones would take the sum).
        for worker_record in workers:
            self.assertGreaterEqual(worker_record["seconds"], self.harness.delay)
        self.assertLess(aggregate_seconds, sum(record["worker_seconds"]) * 0.75)
        self.assertGreaterEqual(aggregate_seconds, self.harness.delay)  # real sleeping happened
        self.assertGreaterEqual(elapsed, aggregate_seconds)

    def test_delayed_verification_cannot_extend_aggregate_seconds(self):
        """Real wall time: slow local checks run only after the aggregate window closes."""
        self.harness.delay = 0.02
        self.harness.verification_delay = 0.1   # two workers => ~0.2 s of local checks
        started = time.monotonic()
        workers, aggregate_seconds, record = baseline.run_concurrent_reads(self.harness, self.seed)
        elapsed = time.monotonic() - started
        self.assertEqual(len(self.harness.clones), baseline.CONCURRENCY)
        # Verification did happen, for every worker, but never inside the window.
        self.assertEqual(len(self.harness.fsck), baseline.CONCURRENCY)
        self.assertGreater(elapsed - aggregate_seconds, baseline.CONCURRENCY * self.harness.verification_delay * 0.5)
        self.assertLess(aggregate_seconds, self.harness.verification_delay)
        self.assertFalse(record["includes_local_verification"])
        self.assertIn("first git clone call start", record["aggregate_definition"])
        for worker_record in workers:
            self.assertGreaterEqual(worker_record["verification_seconds"], self.harness.verification_delay)

    def test_aggregate_is_exact_against_a_deterministic_clone_clock(self):
        self.harness.delay = 0.05
        self.harness.verification_delay = 0.25
        self.harness.patch_clock(self)
        workers, aggregate_seconds, record = baseline.run_concurrent_reads(self.harness, self.seed)
        # Clone timers and the aggregate come from the same timed clone calls only:
        # every recorded duration is nonzero clone time, well below one verification
        # tick (0.25 s), which never enters the clock or the window.
        for worker_record in workers:
            self.assertGreater(worker_record["seconds"], 0)
            self.assertLess(worker_record["seconds"], self.harness.verification_delay)
        self.assertGreater(aggregate_seconds, 0)
        self.assertLess(aggregate_seconds, self.harness.verification_delay)
        self.assertFalse(record["includes_local_verification"])
        self.assertIn("verification runs only after the window closes", record["aggregate_definition"])

    def test_failed_clone_settles_and_raises_promptly(self):
        self.harness.delay = 0.02
        # One worker's clone fails; peers must not hang and nothing may verify.
        self.harness.clone_failures = {"concurrent-worker-2": RuntimeError("clone transport failed")}
        outcome = {}

        def batch():
            try:
                outcome["result"] = baseline.run_concurrent_reads(self.harness, self.seed)
            except BaseException as error:
                outcome["error"] = error

        thread = threading.Thread(target=batch, daemon=True)
        started = time.monotonic()
        thread.start()
        thread.join(10)
        self.assertFalse(thread.is_alive(), "a failed clone left the batch blocked")
        self.assertLess(time.monotonic() - started, 5)
        self.assertNotIn("result", outcome)  # no partial batch is ever measured
        error = outcome["error"]
        self.assertIsInstance(error, baseline.BaselineError)
        self.assertIn("concurrent read batch failed (worker 2)", str(error))
        self.assertIn("clone transport failed", str(error))
        self.assertEqual(len(self.harness.clones), baseline.CONCURRENCY)  # every clone call settled
        self.assertEqual(self.harness.fsck, [])                         # nothing verified

    def test_cold_clone_is_single_and_follows_a_restart(self):
        self.harness.patch_clock(self)
        self.harness.scratch = self.harness.root / "scratch"
        self.harness.scratch.mkdir(mode=0o700)
        record = baseline.run_cold_clone(self.harness, self.seed, restarted=True)
        self.assertEqual(len(self.harness.clones), 1)
        self.assertEqual(self.harness.clones[0][1], "cold-clone")
        self.assertTrue(record["scratch_empty_before"] and record["scratch_empty_after"])
        self.assertEqual(record["head_oid"], OID)
        self.assertEqual(list(self.harness.scratch.iterdir()), [])
        with self.assertRaises(baseline.BaselineError):
            baseline.run_cold_clone(self.harness, self.seed, restarted=False)
        self.assertEqual(len(self.harness.clones), 1)

    def test_wrong_bytes_fail_verification_without_a_second_clone(self):
        self.harness.patch_clock(self)
        # The clone's bytes differ from the content the seed push is supposed to contain.
        self.seed["files"] = dict(self.files, **{"README.txt": b"tampered\n"})
        with self.assertRaises(baseline.BaselineError):
            baseline.measured_clone(self.harness, self.seed["remote"], self.harness.root / "wrong-bytes",
                                    self.seed["oid"], self.seed["files"], self.harness.reader, "read_clone",
                                    "worker-1", repository=baseline.REPOSITORY_NAME)
        self.assertEqual(len(self.harness.clones), 1)

    def test_wrong_object_format_fails_verification(self):
        self.harness.patch_clock(self)
        self.harness.object_format_name = "sha256"  # the clone produced a different object format
        with self.assertRaises(baseline.BaselineError):
            baseline.measured_clone(self.harness, self.seed["remote"], self.harness.root / "wrong-format",
                                    self.seed["oid"], self.seed["files"], self.harness.reader, "read_clone",
                                    "worker-1", repository=baseline.REPOSITORY_NAME)
        self.assertEqual(len(self.harness.clones), 1)

    def test_worker_validates_single_seed_repository_and_destination(self):
        value = baseline.validate_worker("worker-1", worker(0), OID)
        self.assertEqual(value["seconds"], 0.4)
        self.assertEqual(value["verification_seconds"], 0.05)
        for override in ({"label": "worker-2"}, {"kind": "cold_clone"},
                         {"repository": "blob-reader-2"}, {"expected_oid": "2" * 40},
                         {"head_oid": "2" * 40}, {"files_verified": False}, {"fsck": False}):
            with self.subTest(override=override), self.assertRaises(baseline.BaselineError):
                baseline.validate_worker("worker-1", worker(0, **override), OID)

    def test_aggregate_rejects_shared_destinations_and_reports_clone_only_scope(self):
        workers = [worker(index) for index in range(baseline.CONCURRENCY)]
        record = baseline.aggregate_wall(workers, 0.9, OID)
        self.assertEqual(record["mode"], baseline.READ_MODE)
        self.assertFalse(record["includes_local_verification"])
        self.assertEqual(record["concurrency_window_ratio"],
                         round(record["aggregate_seconds"] / max(record["worker_seconds"]), 6))
        shared = [workers[0], worker(1, destination="concurrent-worker-1")] + workers[2:]
        with self.assertRaises(baseline.BaselineError):
            baseline.aggregate_wall(shared, 0.9, OID)
        with self.assertRaises(baseline.BaselineError):
            baseline.aggregate_wall(workers, 0.1, OID)  # shorter than a worker
        with self.assertRaises(baseline.BaselineError):
            baseline.aggregate_wall(workers[:baseline.CONCURRENCY - 1], 1.0, OID)


class SetupAndRestartTest(unittest.TestCase):
    def test_cases_require_setup_then_sampled_provisioning(self):
        payload = report_payload()
        self.assertEqual(payload["setup"]["ordered_before"], "provision")
        self.assertTrue(payload["setup"]["service_running_before_provision"])
        self.assertEqual(payload["cases"][0]["name"], "provision")
        self.assertTrue(payload["cases"][0]["sampled"])
        self.assertIsNotNone(payload["cases"][0]["pg_samples"])
        with self.assertRaises(baseline.BaselineError):
            report_payload(setup={"seconds": 1.0, "ordered_before": "after"})

    def test_restart_is_unsampled_and_advances_exactly_one_epoch(self):
        validated = baseline.validate_cases(case_fixture(), [0, 0, 0, 1, 1])
        self.assertFalse(validated[baseline.CASE_ORDER.index("restart")]["sampled"])
        self.assertIsNone(validated[baseline.CASE_ORDER.index("restart")]["pg_samples"])
        broken = case_fixture()
        broken[3]["pg_samples"] = summary()  # samples across the stop would merge two PIDs
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_cases(broken, [0, 0, 0, 1, 1])

    def test_epoch_and_pid_rules(self):
        for epochs in ([2, 2, 2, 1, 1],       # epochs not monotone
                       [0, 0, 0, 2, 2],       # restart skipped an epoch
                       [0, 2, 2, 1, 1],       # restart merged two processes
                       [0, 1, 1, 2, 2],       # epochs advanced before the restart
                       [0, 0, 0, 1, 2]):      # cold clone outside the restarted epoch
            with self.subTest(epochs=epochs), self.assertRaises(baseline.BaselineError):
                baseline.validate_cases(case_fixture(), epochs)
        same_pid = case_fixture()
        same_pid[3]["new_pid"] = same_pid[3]["old_pid"]
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_cases(same_pid, [0, 0, 0, 1, 1])
        not_finished = case_fixture()
        not_finished[3]["samples_stopped_before_stop"] = False
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_cases(not_finished, [0, 0, 0, 1, 1])
        unsampled_case = case_fixture()
        unsampled_case[1]["sampled"] = False
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_cases(unsampled_case, [0, 0, 0, 1, 1])

    def test_cold_clone_never_spans_the_restart(self):
        record = baseline.validate_cold(cold_fixture())
        self.assertEqual(record["samples_across_restart"], False)
        self.assertFalse(record["includes_local_verification"])
        self.assertIsNone(record["verification_seconds"])
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_cold(cold_fixture(samples_across_restart=True))


class HardwareProvenanceTest(unittest.TestCase):
    """CPU model and cgroup evidence: explicit, bounded, and never guessed."""

    def test_cpu_model_from_common_cpuinfo_fields(self):
        x86 = "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz\nModel\t: 173\n"
        self.assertEqual(baseline.cpu_model(x86, "x86_64"), "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz")
        # ARM lists the SoC under Hardware; a bare board name is still a model, never the arch.
        arm = "processor\t: 0\nBogoMIPS\t: 50.00\n\nHardware\t: BCM2711\nRevision\t: c03114\n"
        self.assertEqual(baseline.cpu_model(arm, "aarch64"), "BCM2711")
        self.assertEqual(baseline.cpu_model("Model\t: Raspberry Pi 4 Model B Rev 1.4\n", "aarch64"),
                         "Raspberry Pi 4 Model B Rev 1.4")
        power = "processor\t: 0\ncpu\t\t: POWER9 (architected), altivec supported\n"
        self.assertEqual(baseline.cpu_model(power, "ppc64le"), "POWER9 (architected), altivec supported")

    def test_cpu_model_is_unavailable_rather_than_the_architecture(self):
        self.assertEqual(baseline.cpu_model("", "x86_64"), "unavailable")
        self.assertEqual(baseline.cpu_model("processor\t: 0\ncpu\t\t: x86_64\n", "x86_64"), "unavailable")
        self.assertEqual(baseline.cpu_model("model name\t: \n", "x86_64"), "unavailable")
        self.assertEqual(baseline.cpu_model(None, "x86_64"), "unavailable")
        # Bounded and single-line, even for hostile content.
        hostile = "model name\t: A\x00B  " + "x" * 500 + "\n"
        model = baseline.cpu_model(hostile, "x86_64")
        self.assertLessEqual(len(model), 200)
        self.assertNotIn("\0", model)
        self.assertNotIn("\n", model)

    def test_cgroup_view_distinguishes_missing_from_max(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            view = baseline.read_cgroup_view(root)
            for key in ("cpu_max", "cpuset_cpus_effective", "memory_max"):
                self.assertEqual(view[key], {"status": "unavailable", "raw": "unavailable",
                                             "format": "cgroup-v2", "source": "unavailable"})
                self.assertNotIn("limited", view[key])   # a missing limit is never "unlimited"
                self.assertNotIn("cpu_count", view[key])
            (root / "cpu.max").write_text("max 100000\n")
            (root / "cpuset.cpus.effective").write_text("0-3,8\n")
            (root / "memory.max").write_text("max\n")
            view = baseline.read_cgroup_view(root)
            self.assertEqual(view["cpu_max"], {"status": "unlimited", "raw": "max 100000", "format": "cgroup-v2",
                                               "source": "cgroup-v2", "limited": False})
            self.assertEqual(view["memory_max"], {"status": "unlimited", "raw": "max", "format": "cgroup-v2",
                                                  "source": "cgroup-v2", "limited": False})
            self.assertEqual(view["cpuset_cpus_effective"], {"status": "observed", "raw": "0-3,8",
                                                             "format": "cgroup-v2", "source": "cgroup-v2",
                                                             "cpu_count": 5})
            (root / "cpu.max").write_text("2 100000\n")
            (root / "memory.max").write_text("536870912\n")
            view = baseline.read_cgroup_view(root)
            self.assertEqual((view["cpu_max"]["status"], view["cpu_max"]["limited"]), ("limited", True))
            self.assertEqual((view["memory_max"]["status"], view["memory_max"]["limited"]), ("limited", True))
            baseline.validate_cgroup_view(view)

    def test_cgroup_view_reports_no_path(self):
        root = self._fixture({"cpu.max": "2 100000", "cpuset.cpus.effective": "0", "memory.max": "max"})
        view = baseline.read_cgroup_view(root)
        self.assertEqual(set(view), {"version", "cpu_max", "cpuset_cpus_effective", "memory_max"})
        self.assertNotIn("root", view)
        self.assertNotIn("path", json.dumps(view))
        self.assertNotIn(root, json.dumps(view))
        self.assertNotIn("/sys/fs/cgroup", json.dumps(view))   # not even a fixed path label
        baseline.validate_cgroup_view(view)

    def test_cpu_max_format(self):
        cases = {"2 100000": ("limited", True), "max 100000": ("unlimited", False),
                 "1 1": ("limited", True), "0 100000": ("limited", True)}
        for raw, (status, limited) in cases.items():
            with self.subTest(raw=raw):
                parsed = baseline.parse_cpu_max(raw)
                self.assertEqual(parsed[0], status)
                self.assertIs(parsed[2], limited)
        for raw in ("", "2", "2 100000 7", "max", "max 0", "2 0", "-1 100000", "2.5 100000", "2 x",
                    "２ 100000", "2\t100000x"):
            with self.subTest(raw=raw):
                self.assertIsNone(baseline.parse_cpu_max(raw))

    def test_memory_max_format(self):
        self.assertEqual(baseline.parse_memory_max("max"), ("unlimited", "max", False))
        self.assertEqual(baseline.parse_memory_max("0"), ("limited", "0", True))
        self.assertEqual(baseline.parse_memory_max(str(2 ** 64 - 1))[0], "limited")
        for raw in ("", "1 2", "max ", "12x", "-1", "+5", "2.5", "1e9", "２", str(2 ** 64)):
            with self.subTest(raw=raw):
                self.assertIsNone(baseline.parse_memory_max(raw))

    def test_cpuset_format_is_an_observation_not_a_limit(self):
        for raw, count in (("0", 1), ("0-3", 4), ("0-3,8", 5), ("0,2,4", 3), ("8-9", 2)):
            with self.subTest(raw=raw):
                self.assertEqual(baseline.parse_cpuset(raw), count)
        for raw in ("", "0,", ",0", "0,,1", "3-1", "0-3,2", "0,0", "a", "0 - 3", " 0", "0-", "-1", "0, 1"):
            with self.subTest(raw=raw):
                self.assertIsNone(baseline.parse_cpuset(raw))
        view = baseline.read_cgroup_view(self._fixture({"cpuset.cpus.effective": "0-1"}))
        self.assertEqual(view["cpuset_cpus_effective"]["status"], "observed")
        self.assertNotIn("limited", view["cpuset_cpus_effective"])  # a CPU set is never limited/unlimited

    def test_malformed_content_is_unavailable_not_a_limit(self):
        root = self._fixture({"cpu.max": "max 0\n", "cpuset.cpus.effective": "3-1\n", "memory.max": "lots\n"})
        view = baseline.read_cgroup_view(root)
        for key in ("cpu_max", "cpuset_cpus_effective", "memory_max"):
            self.assertEqual(view[key]["status"], "unavailable")
            self.assertEqual(view[key]["source"], "malformed")
            self.assertNotIn("limited", view[key])  # never claimed bounded or unlimited
            self.assertNotIn("cpu_count", view[key])
        baseline.validate_cgroup_view(view)
        empty = self._fixture({"cpu.max": ""})
        self.assertEqual(baseline.read_cgroup_view(empty)["cpu_max"]["source"], "empty")

    def test_cgroup_view_rejects_contradictory_evidence(self):
        bounded = baseline.read_cgroup_view(self._fixture({"cpu.max": "max 100000", "cpuset.cpus.effective": "0-3",
                                                           "memory.max": "max"}))
        self.assertIs(bounded["memory_max"]["limited"], False)
        baseline.validate_cgroup_view(bounded)
        for key, override in (("cpu_max", {"limited": True}),                     # max claimed bounded
                              ("cpu_max", {"status": "limited"}),                  # status vs raw
                              ("memory_max", {"status": "limited"}),               # max vs status
                              ("memory_max", {"limited": True}),                   # max vs flag
                              ("cpu_max", {"raw": "x\ny"}),                        # multi-line raw value
                              ("cpu_max", {"raw": "2"}),                           # raw that no longer parses
                              ("cpuset_cpus_effective", {"status": "limited"}),    # a cpuset is not a limit
                              ("cpuset_cpus_effective", {"limited": False}),       # ... and has no flag
                              ("cpuset_cpus_effective", {"cpu_count": 9}),         # count vs raw
                              ("cpu_max", {"source": "unavailable"}),              # observed, unknown source
                              ("memory_max", {"format": "v1"})):                   # wrong label
            with self.subTest(key=key, override=override), self.assertRaises(baseline.BaselineError):
                broken = json.loads(json.dumps(bounded))
                broken[key].update(override)
                baseline.validate_cgroup_view(broken)
        for mutate in (lambda view: view.update({"root": "/sys/fs/cgroup"}),          # path field
                       lambda view: view.update({"cpu_max": {**view["cpu_max"], "path": "present"}}),
                       lambda view: view.update({"cpu_max": {**view["cpu_max"], "limited": None}}),
                       lambda view: view.update({"memory_max": {"status": "unavailable", "raw": "unavailable",
                                                                "format": "cgroup-v2", "source": "unavailable",
                                                                "limited": False}})):
            broken = json.loads(json.dumps(bounded))
            mutate(broken)
            with self.subTest(mutation=mutate), self.assertRaises(baseline.BaselineError):
                baseline.validate_cgroup_view(broken)

    def _fixture(self, files):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        for name, content in files.items():
            (Path(directory.name) / name).write_text(content)
        return directory.name

    def test_runtime_facts_reads_injected_cpuinfo_and_cgroup_root(self):
        harness = mock.Mock()
        harness.run.side_effect = lambda argv: mock.Mock(stdout=(argv[-1] + " 1").encode())
        harness.sql.return_value = "17.1"
        root = self._fixture({"cpu.max": "max 100000", "cpuset.cpus.effective": "0-1"})
        facts = baseline.runtime_facts(harness, mock.Mock(git="/trusted/git"),
                                       cpuinfo="Hardware\t: Fixture SoC\n",
                                       meminfo="MemTotal:       2048 kB\n", cgroup_root=root, procfs=True)
        self.assertEqual(facts["cpu_model"], "Fixture SoC")
        self.assertEqual(facts["architecture"], facts["machine"])          # architecture is kept
        self.assertIsInstance(facts["logical_cpus"], int)
        self.assertEqual(facts["host_memory_total_kb"], 2048)
        cgroup = facts["cgroup"]
        self.assertEqual((cgroup["cpu_max"]["status"], cgroup["cpu_max"]["limited"]), ("unlimited", False))
        self.assertEqual((cgroup["cpuset_cpus_effective"]["status"], cgroup["cpuset_cpus_effective"]["cpu_count"]),
                         ("observed", 2))
        self.assertEqual(cgroup["memory_max"]["status"], "unavailable")    # missing != unlimited
        self.assertNotIn("root", cgroup)
        for leaked in (root, "/trusted/git", "/sys/fs/cgroup"):
            self.assertNotIn(leaked, json.dumps(facts))


class ReportValidationTest(unittest.TestCase):
    def test_cold_rules(self):
        self.assertEqual(baseline.validate_cold(cold_fixture())["head_oid"], OID)
        for override in ({"service_restarted": False}, {"scratch_empty_before": False},
                         {"scratch_empty_after": False}, {"files_verified": False}, {"fsck": False},
                         {"head_oid": "2" * 40}, {"expected_oid": ""}, {"seconds": -1}):
            with self.subTest(override=override), self.assertRaises(baseline.BaselineError):
                baseline.validate_cold(cold_fixture(**override))

    def test_runtime_facts_must_be_complete(self):
        self.assertEqual(baseline.validate_runtime(RUNTIME)["hostname"], "fixture")
        for key, value in (("hostname", ""), ("logical_cpus", None), ("host_memory_total_kb", 0),
                           ("procfs", False), ("kernel", "a\nb"), ("cpu_model", "x86_64")):
            with self.subTest(key=key), self.assertRaises(baseline.BaselineError):
                baseline.validate_runtime({**RUNTIME, key: value})

    def test_binding_requires_attested_receipt_and_inputs(self):
        self.assertIs(baseline.validate_binding(BINDING), BINDING)
        for key, value in (("attested", False), ("inputs_unchanged", False), ("harness_sha256", "0"),
                           ("workspace_commit", ""), ("rustc", None)):
            with self.subTest(key=key), self.assertRaises(baseline.BaselineError):
                baseline.validate_binding({**BINDING, key: value})
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_binding({**BINDING, "inputs": {"runner": "d" * 64}})

    def test_secret_scan_refuses_credentials(self):
        sensitive = ["s3cr3t-endpoint-value", "long-access-key-id-0001", "postgres://user:pw@h/db"]
        payload = {"blob_profile": {"driver": "opendal", "service": "s3"}, "cases": []}
        self.assertTrue(baseline.validate_no_secrets(payload, sensitive))
        for leaked in sensitive:
            with self.subTest(leaked=leaked), self.assertRaises(baseline.BaselineError):
                baseline.validate_no_secrets({**payload, "note": leaked}, sensitive)
        for marker in ("https://user:pw@example.invalid", "password=hunter2", "Secret_Access_Key: x",
                       "Authorization: Bearer x"):
            with self.subTest(marker=marker), self.assertRaises(baseline.BaselineError):
                baseline.validate_no_secrets({**payload, "note": marker}, [])

    def test_short_secret_is_matched_only_as_a_complete_value(self):
        payload = {"postgres_server_version": "17.1", "kind": "rootyard/state-services-blob-baseline"}
        self.assertTrue(baseline.validate_no_secrets(payload, ["postgres", "rootyard"]))
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_no_secrets({**payload, "hostname": "postgres"}, ["postgres"])
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_no_secrets({"note": "prefix long-access-key-id-0001 suffix"},
                                         ["long-access-key-id-0001"])

    def test_common_database_password_does_not_block_its_own_report(self):
        env = {"ROOTYARD_TEST_DATABASE_URL": "postgresql://postgres:postgres@db.invalid:5432/rootyard"}
        sensitive = baseline.sensitive_values(env)
        self.assertIn("postgres", sensitive)
        self.assertIn("postgresql://postgres:postgres@db.invalid:5432/rootyard", sensitive)
        self.assertTrue(baseline.validate_no_secrets(report_payload(), sensitive))

    def test_public_blob_profile_enums_are_not_treated_as_secrets(self):
        env = {"ROOTYARD_BLOB_DRIVER": "opendal", "ROOTYARD_BLOB_SERVICE": "s3",
               "ROOTYARD_BLOB_DELETE": "disabled",
               "ROOTYARD_BLOB_ENDPOINT": "http://127.0.0.1:9000",
               "ROOTYARD_BLOB_BUCKET": "private-bucket",
               "ROOTYARD_BLOB_SECRET_ACCESS_KEY": "private-secret",
               "ROOTYARD_TEST_DATABASE_URL": "postgresql://user:db-password@db.invalid:5432/rootyard"}
        sensitive = baseline.sensitive_values(env)
        for public in ("opendal", "s3", "disabled"):
            self.assertNotIn(public, sensitive)
        for private in ("http://127.0.0.1:9000", "private-bucket", "private-secret", "db-password"):
            self.assertIn(private, sensitive)
        payload = report_payload()
        payload["blob_profile"]["delete_policy"] = "disabled"
        self.assertTrue(baseline.validate_no_secrets(payload, sensitive))
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_no_secrets({**payload, "note": "private-secret"}, sensitive)

    def test_report_labels_and_bounds(self):
        payload = report_payload()
        self.assertEqual(payload["status"], "passed")
        admission = payload["service_admission"]
        self.assertEqual(admission["settings"]["max_concurrent_git"],
                         {"value": 8, "source": "src/standalone/config.rs default", "range": [1, 256]})
        self.assertEqual(admission["settings"]["max_request_bytes"]["value"], 128 << 20)
        self.assertEqual(admission["settings"]["max_inflight_bytes"]["value"], 256 << 20)
        self.assertEqual(admission["upload_pack_reservation_bytes"], 128 << 20)
        self.assertEqual(admission["byte_budget_capacity"], 2)
        self.assertEqual(admission["effective_upload_pack_capacity"], 2)
        self.assertEqual(admission["measured_clone_concurrency"], baseline.CONCURRENCY)
        self.assertIs(admission["capacity_covers_measured_concurrency"], True)
        self.assertIn("max_request_bytes per upload-pack body before spooling", admission["explanation"])
        self.assertEqual(payload["workload"]["concurrency"], 2)
        self.assertEqual(payload["workload"]["read_repositories"], ["blob-baseline"] * 2)
        self.assertFalse(payload["issue"]["issue_complete"])
        self.assertFalse(payload["issue"]["budgets_frozen"])
        self.assertFalse(payload["legacy_pando_profile_used"])
        self.assertEqual(payload["concurrent"]["worker_seconds"], [0.4] * baseline.CONCURRENCY)
        self.assertTrue(payload["concurrent"]["identical_commit_oid_by_construction"])
        self.assertEqual(payload["cold_clone"]["provider_cache_state"], "unknown")
        self.assertTrue(payload["pg_ownership_samples"]["observed_lower_bound"])
        self.assertFalse(payload["pg_ownership_samples"]["restart_case_sampled"])
        layers = payload["pg_ownership_samples"]["ownership_layers"]
        self.assertIn("filter and count", layers["process_sockets"])
        self.assertIn("'rootyard-blob-barrier'", layers["server_sessions"])
        self.assertIn("never compared", layers["cross_check"])
        for key in ("opendal_get_bytes", "opendal_get_phase_ms", "exact_lock_wait_ms"):
            self.assertIsNone(payload["unmeasured"][key])
        text = json.dumps(payload)
        for forbidden in ("ROOTYARD_BLOB_ENDPOINT", "bucket", "s3://", "postgres://", PG_ADDRESS + ":"):
            self.assertNotIn(forbidden, text)
        limits = json.dumps(payload["limits"])
        self.assertIn("two independent read-only destinations", limits)
        self.assertNotIn("three identical read-only", limits)
        self.assertIn("HTTP request/response byte counts are not measured", limits)
        self.assertIn("payload_bytes is the deterministic file payload size, not wire bytes", limits)

    def test_report_version_scope_and_no_four_tuple_claim(self):
        payload = report_payload()
        self.assertEqual(baseline.REPORT_VERSION, 3)
        self.assertEqual(payload["report_version"], 3)
        ownership = payload["pg_ownership_samples"]
        for field in ("limits", "limitations"):
            self.assertEqual(payload[field], baseline.LIMITS)
        scope = "dedicated baseline PostgreSQL database + harness isolated random schema"
        scoped = [limit for limit in baseline.LIMITS if scope in limit]
        self.assertEqual(len(scoped), 2)  # the ownership count and the no-four-tuple scope
        self.assertIn(scope, ownership["scope"])
        self.assertIn(scope, baseline.LIMITS[0])  # the single-server host limit names its database scope
        for text in scoped + [ownership["scope"]]:
            # Only the disclaiming "never a per-socket four-tuple" wording may mention it.
            for match in re.finditer(r"four-tuple", text):
                self.assertTrue(text[max(0, match.start() - 20):match.start()].endswith("never a per-socket "),
                                text)
        self.assertIn("no concurrent same-name Rootyard CLI/service", ownership["scope"])
        self.assertIn("no PostgreSQL pooler or shared database", ownership["scope"])
        self.assertIn("A pre-start check requires zero named sessions", ownership["scope"])
        self.assertTrue(ownership["prestart_requires_zero_sessions"])
        self.assertIs(ownership["per_socket_four_tuple_attribution"], False)
        self.assertIs(ownership["pid_to_backend_mapping"], False)
        self.assertIn("dedicated baseline database + isolated random schema", ownership["sql_helper"])
        self.assertIn("dedicated baseline database + harness isolated random schema",
                      ownership["ownership_layers"]["server_sessions"])
        self.assertTrue(any("NAT-rewritten client address/port pairs are never compared or attributed" in limit
                            for limit in baseline.LIMITS))

    def test_report_rejects_inconsistent_measurements(self):
        for index, override in ((1, {"detail": {"push": push(remote_oid="2" * 40)}}),
                                (1, {"detail": {"push": push(push_wall_seconds=None)}}),
                                (1, {"detail": {"push": push(push_wall_seconds=0.9)}}),
                                (4, {"detail": {}})):
            broken = case_fixture()
            broken[index].update(override)
            if index == 4:
                # A completed run whose cold case lost its scratch/restart evidence.
                expected_report_error({"cold_record": cold_fixture(scratch_empty_before=False)},
                                      "a validation rule")
                continue
            with self.subTest(index=index, override=override):
                expected_report_error({"case_list": broken}, "a validation rule")
        # The cold clone read another repository state than the measured seed push.
        expected_report_error({"cold_record": cold_fixture(expected_oid="2" * 40, head_oid="2" * 40)},
                              "a validation rule")
        mismatched = [worker(index, expected_oid="2" * 40) for index in range(baseline.CONCURRENCY)]
        expected_report_error({"concurrent": mismatched_concurrent(mismatched)}, "a validation rule")

    def test_report_writer_is_atomic_and_never_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "report.json"
            self.assertEqual(baseline.safe_write_report(destination, {"b": 1, "a": [1, 2]}), "")
            self.assertEqual(json.loads(destination.read_text()), {"a": [1, 2], "b": 1})
            self.assertFalse(destination.with_suffix(".json.tmp").exists())
            self.assertEqual(baseline.safe_write_report("", {"x": 1}), "")


def mismatched_concurrent(workers):
    return {"workers": workers, "aggregate_seconds": 1.0, "worker_oid": OID}


def expected_report_error(case, categories):
    """The report must be refused by a *validation* rule, not by a stray exception."""
    try:
        report_payload(**case)
    except baseline.BaselineError:
        return
    except (KeyError, TypeError) as error:
        raise AssertionError("report refused by " + type(error).__name__ + ", expected " + categories) from None
    raise AssertionError("report accepted " + repr(case))


def report_payload(*, case_list=None, cold_record=None, concurrent=None, setup=None, admission=None):
    return baseline.report_payload(
        binding=BINDING, blob_profile={"driver": "opendal", "service": "s3", "root_configured": True},
        runtime=RUNTIME, workload=workload(), cases=case_list if case_list is not None else case_fixture(),
        setup=setup or {"seconds": 2.0, "ordered_before": "provision", "service_running_before_provision": True},
        seeding={"push": push(), "object_format": "sha1"},
        concurrent=concurrent or {"workers": [worker(index) for index in range(baseline.CONCURRENCY)],
                                  "aggregate_seconds": 1.0, "worker_oid": OID},
        cold=cold_record or baseline.validate_cold(cold_fixture()),
        # Default admission facts from an empty environment, never the ambient host env.
        service_admission=admission or baseline.service_admission_facts({}))


class FakeRunHarness(FakeGitHarness):
    """End-to-end fake of the orchestration: every step recorded in wall-clock order."""

    URL = "postgresql://www-data:super-secret@database.fixture.invalid:54329/service"

    def __init__(self, files, restart_changes_pid=True):
        super().__init__(files)
        self.events = []
        self.db = self.URL
        self.schema = "rootyard_e2e_fixture0123456789abcdef"
        self.scratch = self.root / "scratch"
        self.restart_changes_pid = restart_changes_pid
        self.captured = None
        # Only names/values the runner may inspect; no real profile is ever read.
        self.env = {"ROOTYARD_BLOB_ENDPOINT": "http://127.0.0.1:1", "ROOTYARD_BLOB_SECRET_ACCESS_KEY": "fake-secret"}
        self.sql_answers = {"SELECT current_setting('port')": str(PG_PORT),
                            "SHOW server_version": "17.1"}
        # Every pre-start session check sees an empty database unless a test injects sessions.
        self.session_rows = ["0|0|0|0"]
        self.start_method = self.start  # the original, un-wrapped method

    def note(self, event):
        self.events.append(event)

    def prepare(self):
        self.note("prepare")
        # Mirrors the real setup: schema migration and account CLI steps, then the first start.
        self.note("schema migration")
        self.start()

    def create(self, name, token, object_format="sha1"):
        self.note("POST /api/repos")
        return {"id": "fixture", "owner": "alice", "name": name,
                "clone_path": "/git/alice/" + name + ".git"}, 201  # (repo, POST status)

    def db_repo(self, repo_id):
        self.note("db binding")
        return "pg_refstore|1|sha1"

    def clone(self, remote, destination, token=None):
        self.note("clone " + Path(destination).name)
        return super().clone(remote, destination, token)

    def configure(self, work):
        pass

    def commit_files(self, work, message, files):
        self.note("commit")
        for name, data in files.items():
            (Path(work) / name).parent.mkdir(parents=True, exist_ok=True)
            (Path(work) / name).write_bytes(data)
        return OID

    def git(self, *args, cwd=None, token=None, check=True, **kwargs):
        if "push" in args:
            self.note("git push")
            return mock.Mock(stdout=b"*\trefs/heads/main:refs/heads/main\t[new branch]\n",
                             stderr=b"", returncode=0)
        return super().git(*args, cwd=cwd, token=token, check=check, **kwargs)

    def remote_refs(self, remote, token=None):
        self.note("ls-remote")
        return {"refs/heads/main": OID}

    def run_push(self, remote, work, files):
        """Run the real push measurement against this fake git, then keep its summary."""
        self.note("measure push")
        return baseline.run_push(self, remote, work, files)

    def sql(self, query):
        if query == baseline.PG_STAT_QUERY:
            self.note("prestart check")
            return self.session_rows.pop(0) if len(self.session_rows) > 1 else self.session_rows[0]
        self.note("sql")
        for prefix, answer in self.sql_answers.items():
            if query.startswith(prefix):
                return answer
        return super().sql(query)

    def stop(self):
        self.note("stop " + str(self.proc.pid))

    def start(self):
        self.note("start from " + str(self.proc.pid))
        next_pid = (self.proc.pid + 1) if (self.restart_changes_pid or self.proc.pid != 500) else self.proc.pid
        self.proc = FakeProcess(next_pid)
        self.scratch.mkdir(mode=0o700, exist_ok=True)

    def run(self, argv, **kwargs):
        return mock.Mock(stdout=(argv[-1] if isinstance(argv[-1], str) else "tool").encode(), returncode=0)


class FakeSampler:
    """Stands in for PgSampler and mirrors the real sweep's end-of-case validation."""

    instances = []

    def __init__(self, helper, pid, endpoint, **kwargs):
        self.helper, self.pid, self.endpoint = helper, pid, endpoint
        self.finished = False
        self.calls = []
        FakeSampler.instances.append(self)

    def start(self, timeout=None):
        self.calls.append(baseline.sample_row(1, 0, 1, 0))
        return self.calls[-1]

    def finish(self):
        self.finished = True
        self.calls.append(baseline.sample_row(1, 0, 1, 0))
        return baseline.summarize_samples(self.calls, scans_without_connection=0)


class RunOrchestrationTest(unittest.TestCase):
    """The run itself: setup before sampling, restart without cross-PID samples."""

    def setUp(self):
        self.args = mock.Mock(binary="/fixture/rootyard", keep=False)
        self.args.report = Path(tempfile.mkdtemp(prefix="blob-baseline-report-")) / "report.json"
        FakeSampler.instances = []

    def run_once(self, restart_changes_pid=True, session_rows=None, service_env=None):
        files = baseline.select_workload()
        harness = FakeRunHarness(files, restart_changes_pid=restart_changes_pid)
        if service_env:
            harness.env.update(service_env)
        if session_rows is not None:
            harness.session_rows = list(session_rows)
        profile = mock.Mock(working_tree_clean=True, build={"binary_sha256": "a" * 64,
                                                            "source_inputs_sha256": "b" * 64,
                                                            "workspace_commit": "c" * 40, "rustc": "rustc 1"},
                            receipt_sha256="d" * 64, harness_sha256="e" * 64, git_sha256="f" * 64)
        def capture(*args, **kwargs):
            # Record the run's own case records, then build the report normally.
            harness.captured = {"cases": kwargs["cases"], "setup": kwargs["setup"], "seeding": kwargs["seeding"],
                                "service_admission": kwargs["service_admission"]}
            return real_report_payload(*args, **kwargs)

        real_report_payload = baseline.report_payload
        patches = (mock.patch.object(baseline, "report_payload", side_effect=capture),
                   mock.patch.object(baseline, "binding_record", return_value=BINDING),
                   mock.patch.object(baseline.serving, "BlobOnlyHarness", return_value=harness),
                   mock.patch.object(baseline, "resolve_pg_endpoint",
                                     return_value=([PG_ADDRESS], PG_PORT)),
                   mock.patch.object(baseline, "PgSampler", FakeSampler),
                   mock.patch.object(baseline, "runtime_facts", return_value=RUNTIME),
                   mock.patch.object(baseline, "sensitive_values", return_value=[]))
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(harness.cleanup)
        code = baseline.run(self.args, profile, {"driver": "opendal", "service": "s3"})
        return code, harness, json.loads(self.args.report.read_text()), harness.captured or {}

    def test_setup_precedes_every_sampled_case(self):
        code, harness, report, captured = self.run_once()
        self.assertEqual(code, 0, report.get("error"))
        self.assertEqual(report["status"], "passed")
        events = harness.events
        self.assertLess(events.index("prepare"), events.index("POST /api/repos"))
        self.assertLess(events.index("prepare"), events.index("clone blob-baseline-work"))
        names = [case["name"] for case in report["cases"]]
        self.assertEqual(names, list(baseline.CASE_ORDER))
        self.assertGreater(report["setup"]["seconds"], 0)
        self.assertTrue(report["cases"][0]["sampled"])
        self.assertIsNotNone(report["cases"][0]["pg_samples"])
        self.assertEqual(report["seed_push"]["push_wall_seconds"] > 0, True)
        self.assertNotIn("super-secret", json.dumps(report))
        self.assertNotIn("database.fixture.internal", json.dumps(report))

    def test_report_carries_the_effective_service_admission(self):
        code, harness, report, captured = self.run_once(
            service_env={"ROOTYARD_MAX_REQUEST_BYTES": str(64 << 20), "ROOTYARD_MAX_INFLIGHT_BYTES": str(128 << 20)})
        self.assertEqual(code, 0, report.get("error"))
        admission = report["service_admission"]
        self.assertEqual(report["report_version"], 3)
        self.assertEqual(admission["settings"]["max_concurrent_git"]["source"], "src/standalone/config.rs default")
        self.assertEqual(admission["settings"]["max_request_bytes"],
                         {"value": 64 << 20, "source": "environment_override", "range": [64 << 10, 4 << 30]})
        self.assertEqual(admission["settings"]["max_inflight_bytes"]["source"], "environment_override")
        self.assertEqual(admission["byte_budget_capacity"], 2)
        self.assertEqual(admission["effective_upload_pack_capacity"], 2)
        self.assertEqual(admission, captured["service_admission"])
        self.assertEqual(len(captured["cases"][2]["detail"]["workers"]), 2)
        # The reported values are the profile's effective settings, never a runner override.
        self.assertEqual({name: harness.env[name] for name in ("ROOTYARD_MAX_REQUEST_BYTES",
                                                               "ROOTYARD_MAX_INFLIGHT_BYTES")},
                         {"ROOTYARD_MAX_REQUEST_BYTES": str(64 << 20),
                          "ROOTYARD_MAX_INFLIGHT_BYTES": str(128 << 20)})

    def test_restart_is_never_sampled_and_samples_follow_the_pid(self):
        code, harness, report, captured = self.run_once()
        self.assertEqual(code, 0, report.get("error"))
        restart = captured["cases"][baseline.CASE_ORDER.index("restart")]
        self.assertFalse(restart["sampled"])
        self.assertIsNone(restart["pg_samples"])
        sampled_pids = [sampler.pid for sampler in FakeSampler.instances if sampler.calls]
        self.assertEqual(len(sampled_pids), 4)            # every case except the restart
        # prepare now runs the first start (501); the restart creates 502.
        self.assertEqual(sampled_pids, [501, 501, 501, 502])
        self.assertTrue(all(sampler.finished for sampler in FakeSampler.instances))
        # Old-process sampling is finished strictly before the stop.
        self.assertIn("stop 501", harness.events)
        self.assertEqual([case["service_epoch"] for case in captured["cases"]], [0, 0, 0, 1, 1])

    def test_prestart_session_checks_bracket_every_start(self):
        code, harness, report, _ = self.run_once()
        self.assertEqual(code, 0, report.get("error"))
        events = harness.events
        starts = [index for index, event in enumerate(events)
                  if event in ("start from 500", "start from 501")]
        checks = [index for index, event in enumerate(events) if event == "prestart check"]
        # Before setup, right after setup's migration and immediately before the first start
        # (500), then after the SIGTERM stop (501) and immediately before the restart's start.
        self.assertEqual(starts, [events.index("start from 500"), events.index("start from 501")])
        self.assertEqual(len(checks), 3)
        self.assertLess(checks[0], events.index("prepare"))
        self.assertLess(events.index("schema migration"), checks[1])
        self.assertEqual(checks[1] + 1, starts[0])
        self.assertLess(events.index("stop 501"), checks[2])
        self.assertEqual(checks[2] + 1, starts[1])
        self.assertEqual(harness.start, harness.start_method)  # the wrapper is always restored

    def test_existing_sessions_fail_before_the_first_start(self):
        # The initial check is zero; the injected row is the next check, i.e. the one
        # immediately before the first start, which blocks the start before it runs.
        code, harness, report, _ = self.run_once(session_rows=["0|0|0|0", "2|1|1|0"])
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "failed")
        self.assertIn("service sessions already exist before a service start: 2", report["error"])
        self.assertEqual(harness.events, ["prestart check", "prepare", "schema migration", "prestart check"])
        self.assertEqual(harness.start, harness.start_method)  # restored by prepare's finally
        self.assertFalse(any(event.startswith("start from ") for event in harness.events))

    def test_stale_session_after_setup_start_is_checked_before_start(self):
        # A named session already present after setup's migration is caught right before start() runs.
        code, harness, report, _ = self.run_once(session_rows=["0|0|0|0", "1|0|1|0", "0|0|0|0", "0|0|0|0"])
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "failed")
        self.assertIn("service sessions already exist before a service start: 1", report["error"])
        self.assertEqual(harness.start, harness.start_method)  # restored through prepare's finally

    def test_session_left_after_stop_blocks_the_restart(self):
        # The initial check and the check before the first start see zero;
        # the check right after the stop sees two and blocks the restart's start.
        code, harness, report, _ = self.run_once(session_rows=["0|0|0|0", "0|0|0|0", "2|1|1|0"])
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "failed")
        self.assertIn("service sessions already exist before a service start: 2", report["error"])
        events = harness.events
        self.assertEqual([event for event in events if event.startswith("start from ")], ["start from 500"])
        self.assertIn("stop 501", events)
        # The gate sits between the SIGTERM stop and the restart's start.
        self.assertEqual(events[events.index("stop 501") + 1], "prestart check")
        self.assertNotIn("clone cold-clone", events)

    def test_same_pid_after_restart_fails_the_run(self):
        code, _, report, _ = self.run_once(restart_changes_pid=False)
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "failed")
        self.assertIn("new service process", report["error"])


class FixtureReuseTest(unittest.TestCase):
    def test_runner_reuses_the_real_blob_only_fixture(self):
        self.assertIs(baseline.serving.BlobOnlyHarness.__mro__[1], baseline.serving.Harness)
        for name in ("NativeProfile", "check_blob_profile", "BlobOnlyHarness", "ProfileError"):
            self.assertTrue(hasattr(baseline.serving, name), name)
        run_source = Path(baseline.__file__).read_text()
        for reused in ("serving.BlobOnlyHarness(", "serving.NativeProfile(", "serving.check_blob_profile("):
            self.assertIn(reused, run_source)
        for forbidden in ("delete_objects", "ROOTYARD_BLOB_DELETE=", "s3://", "exact_clone("):
            self.assertNotIn(forbidden, run_source)
        self.assertEqual(run_source.count('need(binding_record(profile)["inputs"] == binding["inputs"]'), 1)
        run_body = run_source[run_source.index("def run(args, profile, blob_profile):"):]
        self.assertEqual(run_body.count("binding = binding_record(profile)"), 1)  # attested once, re-checked once

    def test_cli_contract(self):
        parser_source = Path(baseline.__file__).read_text()
        for flag in ('"--binary", required=True', '"--git"', '"--report", required=True', '"--keep"'):
            self.assertIn(flag, parser_source)

    def test_main_fails_closed_before_any_run(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with mock.patch.object(baseline.serving, "NativeProfile",
                                   side_effect=baseline.serving.ProfileError("no receipt")):
                self.assertEqual(baseline.main(["--binary", "/bin/sh", "--report", str(report)]), 2)
            written = json.loads(report.read_text())
            self.assertTrue(written["preflight_failed"])
            self.assertEqual(written["status"], "failed")
            self.assertEqual(written["error"], "no receipt")
            self.assertEqual(written["cases"], [])

    def test_main_fails_closed_without_procfs(self):
        real_is_dir = Path.is_dir

        def is_dir(path):
            return False if str(path) == "/proc/self/fd" else real_is_dir(path)

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with mock.patch.object(baseline.serving, "NativeProfile", return_value=mock.Mock()), \
                    mock.patch.object(baseline.serving, "check_blob_profile", return_value={}), \
                    mock.patch.dict(os.environ, {"ROOTYARD_TEST_DATABASE_URL": "postgres://unused"}), \
                    mock.patch.object(Path, "is_dir", is_dir):
                self.assertEqual(baseline.main(["--binary", "/bin/sh", "--report", str(report)]), 2)
            self.assertIn("procfs", json.loads(report.read_text())["error"])


if __name__ == "__main__":
    unittest.main()
