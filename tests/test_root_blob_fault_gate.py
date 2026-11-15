#!/usr/bin/env python3
"""Pure boundary tests for the bounded root blob S3 forward gate."""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "blob_gateway_support"))
from root_blob_fault_gate import MAX_REQUEST_BYTES, RootBlobFaultGate


class EndpointTests(unittest.TestCase):
    def test_loopback_http_origin_is_accepted(self):
        self.assertEqual(RootBlobFaultGate.validate_endpoint("http://127.0.0.1:9000"), ("127.0.0.1", 9000))
        self.assertEqual(RootBlobFaultGate.validate_endpoint("http://localhost"), ("localhost", 80))

    def test_https_nonloopback_credentials_path_and_query_are_rejected(self):
        for endpoint in (
            "https://127.0.0.1:9000",
            "http://10.0.0.1:9000",
            "http://user:pass@127.0.0.1:9000",
            "http://127.0.0.1:9000/root",
            "http://127.0.0.1:9000?x=1",
            "http://127.0.0.1:9000#frag",
        ):
            with self.assertRaises(ValueError, msg=endpoint):
                RootBlobFaultGate.validate_endpoint(endpoint)


class SelectorTests(unittest.TestCase):
    SUFFIX = "v1/tenants/11111111-1111-4111-8111-111111111111/authorities/22222222-2222-4222-8222-222222222222/g1/attempts/33333333-3333-4333-8333-333333333333/registered-pack/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def test_full_locator_get_matches_but_leaf_does_not(self):
        self.assertTrue(RootBlobFaultGate.full_path_matches("GET", "/bucket/" + self.SUFFIX, True, self.SUFFIX))
        self.assertTrue(RootBlobFaultGate.full_path_matches("GET", "/bucket/" + self.SUFFIX + "?x=1", True, self.SUFFIX))
        self.assertFalse(RootBlobFaultGate.full_path_matches("GET", "/" + self.SUFFIX.rsplit("/", 1)[-1], True, self.SUFFIX))
        other = self.SUFFIX.rsplit("/", 1)[0] + "/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        self.assertFalse(RootBlobFaultGate.full_path_matches("GET", "/bucket/" + other, True, self.SUFFIX))

    def test_only_armed_get_is_targeted(self):
        self.assertFalse(RootBlobFaultGate.full_path_matches("HEAD", "/bucket/" + self.SUFFIX, True, self.SUFFIX))
        self.assertFalse(RootBlobFaultGate.full_path_matches("GET", "/bucket/" + self.SUFFIX, False, self.SUFFIX))


class BoundTests(unittest.TestCase):
    def test_body_limit_boundaries(self):
        self.assertEqual(RootBlobFaultGate.bounded_body_length(None), 0)
        self.assertEqual(RootBlobFaultGate.bounded_body_length("0"), 0)
        self.assertEqual(RootBlobFaultGate.bounded_body_length(str(MAX_REQUEST_BYTES)), MAX_REQUEST_BYTES)
        with self.assertRaises(ValueError):
            RootBlobFaultGate.bounded_body_length(str(MAX_REQUEST_BYTES + 1))
        with self.assertRaises(ValueError):
            RootBlobFaultGate.bounded_body_length("-1")
        with self.assertRaises(ValueError):
            RootBlobFaultGate.bounded_body_length("not-a-number")

    def test_remaining_deadline_is_nonnegative_and_decreases(self):
        future = time.monotonic() + 1.0
        self.assertGreater(RootBlobFaultGate.remaining(future), 0)
        self.assertEqual(RootBlobFaultGate.remaining(time.monotonic() - 1.0), 0.0)


if __name__ == "__main__":
    unittest.main()
