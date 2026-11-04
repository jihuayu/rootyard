"""Regression tests for bounded slow-client process observation; no database."""
import unittest
from unittest.mock import Mock, patch

from e2e import Harness


class GitChildObservationTests(unittest.TestCase):
    def observe(self, children, response=b"HTTP/1.1 200 OK\r\n", ready=True):
        harness = object.__new__(Harness)
        harness.descendants = Mock(side_effect=children)
        sock = Mock()
        if isinstance(response, list):
            sock.recv.side_effect = response
        else:
            sock.recv.return_value = response
        elapsed = [0.0]

        def sleep(seconds):
            elapsed[0] += seconds

        with patch("e2e.time.monotonic", side_effect=lambda: elapsed[0]), \
                patch("e2e.time.sleep", side_effect=sleep), \
                patch("e2e.select.select", return_value=([sock] if ready else [], [], [])):
            result = harness.wait_for_git_children(sock, 0, "test upload")
        return result, elapsed[0]

    def test_observes_startup_later_than_one_hundred_milliseconds(self):
        children = iter([{}] * 30 + [{123: "starttime"}])
        result, elapsed = self.observe(lambda: next(children))
        self.assertEqual(result, {123: "starttime"})
        self.assertGreater(elapsed, .1)
        self.assertLess(elapsed, 2)

    def test_missing_child_still_fails_within_bound(self):
        with self.assertRaisesRegex(AssertionError, "within 2 seconds"):
            self.observe(lambda: {})

    def test_child_without_http_response_is_not_success(self):
        with self.assertRaisesRegex(AssertionError, "within 2 seconds"):
            self.observe(lambda: {123: "starttime"}, ready=False)

    def test_fragmented_status_line_waits_for_complete_response(self):
        result, elapsed = self.observe(lambda: {123: "starttime"},
                                       response=[b"HTTP/1.1 20", b"HTTP/1.1 200 OK\r\n"])
        self.assertEqual(result, {123: "starttime"})
        self.assertGreater(elapsed, 0)

    def test_error_response_is_not_treated_as_slow_startup(self):
        with self.assertRaisesRegex(AssertionError, "did not start streaming"):
            self.observe(lambda: {}, response=b"HTTP/1.1 503 Service Unavailable\r\n")

    def test_early_eof_is_not_treated_as_slow_startup(self):
        with self.assertRaisesRegex(AssertionError, "connection ended"):
            self.observe(lambda: {}, response=b"")

    def test_disappearing_proc_entry_is_reaped(self):
        harness = object.__new__(Harness)
        with patch("e2e.Path.read_text", side_effect=ProcessLookupError):
            harness.assert_reaped({123: "100"}, "test upload")

    def test_reused_pid_is_not_reported_as_surviving(self):
        harness = object.__new__(Harness)
        stat = "123 (git) " + " ".join(["S", "1", "123"] + ["0"] * 16 + ["101"])
        with patch("e2e.Path.read_text", return_value=stat):
            harness.assert_reaped({123: "100"}, "test upload")

    def test_zombie_is_not_reported_as_reaped(self):
        harness = object.__new__(Harness)
        stat = "123 (git) " + " ".join(["Z", "1", "123"] + ["0"] * 16 + ["100"])
        with patch("e2e.Path.read_text", return_value=stat), \
                patch("e2e.time.monotonic", side_effect=[0, 3]):
            with self.assertRaisesRegex(AssertionError, "'state': 'Z'"):
                harness.assert_reaped({123: "100"}, "test upload")


if __name__ == "__main__":
    unittest.main()
