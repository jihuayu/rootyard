import socket
import threading
import unittest
from unittest import mock

from scripts.pack_compression_eval.s3_meter import S3MeterProxy


class MeterSettleTest(unittest.TestCase):
    def handler_fixture(self):
        proxy = S3MeterProxy("127.0.0.1", 9)
        self.addCleanup(proxy.stop)
        client, downstream = socket.socketpair()
        upstream, server = socket.socketpair()
        for connection in (client, downstream, upstream, server):
            connection.settimeout(2.0)
            self.addCleanup(connection.close)
        client.sendall(b"GET /fixture HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\n\r\n")
        return proxy, client, downstream, upstream, server

    def test_response_forwarded_before_accounting_stays_in_its_phase(self):
        proxy, client, downstream, upstream, server = self.handler_fixture()
        entered, release = threading.Event(), threading.Event()
        payload = b"packed objects"
        headers = b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n"
        server.sendall(headers + payload)
        record = proxy._record

        def record_after_release(*args):
            entered.set()
            if release.wait(2.0):
                record(*args)

        with mock.patch.object(socket, "create_connection", return_value=upstream), mock.patch.object(
            proxy, "_record", side_effect=record_after_release,
        ):
            handler = threading.Thread(target=proxy._handle_conn, args=(downstream,))
            handler.start()
            try:
                with client.makefile("rb") as response:
                    self.assertEqual(response.read(len(headers) + len(payload)), headers + payload)
                self.assertTrue(entered.wait(2.0))
                self.assertEqual(proxy.snapshot()["get_requests"], 0)
                with self.assertRaisesRegex(TimeoutError, "accounting did not settle"):
                    proxy.snapshot(settle_timeout=0.0)
                with self.assertRaisesRegex(TimeoutError, "accounting did not settle"):
                    proxy.reset_counters(settle_timeout=0.0)
                release.set()
                settled = proxy.snapshot(settle_timeout=2.0)
                self.assertEqual((settled["get_requests"], settled["get_bytes"]), (1, len(payload)))
                proxy.reset_counters(settle_timeout=0.0)
                self.assertEqual(proxy.snapshot(settle_timeout=0.0)["get_requests"], 0)
            finally:
                release.set()
                handler.join(3.0)
            self.assertFalse(handler.is_alive())

    def test_upstream_disconnect_releases_pending_accounting(self):
        proxy, _, downstream, upstream, server = self.handler_fixture()
        server.close()
        with mock.patch.object(socket, "create_connection", return_value=upstream):
            proxy._handle_conn(downstream)
        self.assertEqual(proxy.snapshot(settle_timeout=0.0)["get_requests"], 0)
