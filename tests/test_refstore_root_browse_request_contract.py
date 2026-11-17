#!/usr/bin/env python3
"""Pure return-contract regressions for the root browse HTTP request wrappers.

These tests construct ``RootBrowseHttpHarness`` with ``object.__new__`` and do
not start the service. They need no PostgreSQL, Git, Blob/profile environment,
network or native binary. The wrapper tests replace only the inherited
``_request`` parent with a recorded three-tuple, proving that the two real root
helpers consume the parent contract and publish a two-tuple. The policy tests
replace only the low-level ``http`` transport, so the real inherited
``SnapshotHttpHarness._request`` cache-control/no-session boundary still runs.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from refstore_root_browse_http import RootBrowseHttpHarness  # noqa: E402
from refstore_snapshot_http import SnapshotHttpHarness  # noqa: E402

REPO = {"owner": "owner with space", "name": "repo/name"}
ROOT = "11111111-1111-4111-8111-111111111111"
TREE_OID = "a" * 40
BLOB_OID = "b" * 40
ALICE = "alice-token"
PARENT_HEADERS = {"cache-control": "no-store", "x-parent-only": "must-not-escape"}


def bare_harness():
    harness = object.__new__(RootBrowseHttpHarness)
    harness.alice = ALICE
    return harness


class RecordingParentRequest:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, method, path, token, body=None, assert_no_session=True):
        self.calls.append(SimpleNamespace(method=method, path=path, token=token, body=body,
                                          assert_no_session=assert_no_session))
        return self.response


class RecordingHttp:
    def __init__(self, status=200, raw="{}", headers=None):
        self.status = status
        self.raw = raw
        self.headers = dict(headers or {})
        self.calls = []

    def __call__(self, path, token=None, method=None, body=None):
        self.calls.append(SimpleNamespace(path=path, token=token, method=method, body=body))
        return self.status, self.raw, self.headers


class WrapperContractTests(unittest.TestCase):
    def test_parent_request_contract_remains_the_inherited_three_tuple(self):
        self.assertIs(RootBrowseHttpHarness._request, SnapshotHttpHarness._request)
        harness = bare_harness()
        http = RecordingHttp(200, '{"ok": true}', PARENT_HEADERS)
        harness.http = http
        result = harness._request("GET", "/probe", "token-1")
        self.assertEqual(result, (200, {"ok": True}, PARENT_HEADERS))
        self.assertEqual(len(result), 3)
        self.assertEqual(http.calls[0].path, "/probe")
        self.assertEqual(http.calls[0].token, "token-1")
        self.assertEqual(http.calls[0].method, "GET")
        self.assertIsNone(http.calls[0].body)

    def test_root_tree_consumes_parent_triple_and_returns_pair(self):
        harness = bare_harness()
        parent = RecordingParentRequest((207, {"tree_oid": TREE_OID}, dict(PARENT_HEADERS)))
        harness._request = parent
        result = harness._root_tree(REPO, ROOT, oid=TREE_OID, path="dir/a b.txt",
                                    after="next", limit=3)
        self.assertEqual(result, (207, {"tree_oid": TREE_OID}))
        self.assertEqual(len(result), 2)
        self.assertEqual(len(parent.calls), 1)
        call = parent.calls[0]
        self.assertEqual(call.method, "GET")
        self.assertEqual(call.token, ALICE)
        self.assertIsNone(call.body)
        self.assertIs(call.assert_no_session, True)
        self.assertEqual(
            call.path,
            "/api/repos/owner%20with%20space/repo%2Fname/roots/" + ROOT
            + "/tree?oid=" + TREE_OID + "&path=dir%2Fa+b.txt&after=next&limit=3")

    def test_root_blob_consumes_parent_triple_and_returns_pair(self):
        harness = bare_harness()
        parent = RecordingParentRequest((201, {"oid": BLOB_OID}, dict(PARENT_HEADERS)))
        harness._request = parent
        result = harness._root_blob(REPO, ROOT, "refs/heads/main", path="a b.txt",
                                    token="bob-token")
        self.assertEqual(result, (201, {"oid": BLOB_OID}))
        self.assertEqual(len(result), 2)
        call = parent.calls[0]
        self.assertEqual(call.method, "GET")
        self.assertEqual(call.token, "bob-token")
        self.assertIsNone(call.body)
        self.assertIs(call.assert_no_session, True)
        self.assertEqual(
            call.path,
            "/api/repos/owner%20with%20space/repo%2Fname/roots/" + ROOT
            + "/blob/refs%2Fheads%2Fmain?path=a+b.txt")

    def test_denial_triple_also_returns_pair(self):
        harness = bare_harness()
        harness._request = RecordingParentRequest((403, {"error": {"code": "forbidden"}},
                                                   dict(PARENT_HEADERS)))
        result = harness._root_tree(REPO, ROOT)
        self.assertEqual(result, (403, {"error": {"code": "forbidden"}}))
        self.assertEqual(len(result), 2)

    def test_parent_headers_are_unused_and_parent_arity_is_exact(self):
        harness = bare_harness()
        harness._request = RecordingParentRequest((200, {"ok": True}, dict(PARENT_HEADERS)))
        result = harness._root_tree(REPO, ROOT)
        self.assertEqual(result, (200, {"ok": True}))
        self.assertNotIn(PARENT_HEADERS["x-parent-only"], repr(result))
        for response in ((200, {"ok": True}), (200, {"ok": True}, {}, "extra")):
            with self.subTest(arity=len(response)):
                harness._request = RecordingParentRequest(response)
                with self.assertRaisesRegex(ValueError, "values to unpack"):
                    harness._root_tree(REPO, ROOT)


class ParentPolicyTests(unittest.TestCase):
    def test_real_parent_policy_success_keeps_three_and_wrapper_pair(self):
        harness = bare_harness()
        raw = json.dumps({"tree_oid": TREE_OID})
        harness.http = RecordingHttp(200, raw, PARENT_HEADERS)
        parent = harness._request("GET", "/probe", ALICE)
        self.assertEqual(parent, (200, {"tree_oid": TREE_OID}, PARENT_HEADERS))
        self.assertEqual(harness._root_tree(REPO, ROOT, oid=TREE_OID),
                         (200, {"tree_oid": TREE_OID}))

    def test_missing_no_store_still_raises_for_both_helpers(self):
        for label, invoke in (
            ("tree", lambda harness: harness._root_tree(REPO, ROOT)),
            ("blob", lambda harness: harness._root_blob(REPO, ROOT, BLOB_OID)),
        ):
            with self.subTest(helper=label):
                harness = bare_harness()
                harness.http = RecordingHttp(200, "{}", {"x-parent-only": "no-store-missing"})
                with self.assertRaises(AssertionError):
                    invoke(harness)

    def test_session_header_still_raises_for_both_helpers(self):
        headers = {"cache-control": "no-store", "x-rootyard-session": "session-key"}
        for label, invoke in (
            ("tree", lambda harness: harness._root_tree(REPO, ROOT)),
            ("blob", lambda harness: harness._root_blob(REPO, ROOT, BLOB_OID)),
        ):
            with self.subTest(helper=label):
                harness = bare_harness()
                harness.http = RecordingHttp(200, "{}", headers)
                with self.assertRaisesRegex(AssertionError, "x-rootyard-session"):
                    invoke(harness)


if __name__ == "__main__":
    unittest.main()
