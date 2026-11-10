import json
import threading
import unittest

import webhooks


class FakeReceiver:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []

    def clear(self):
        with self.lock:
            self.requests.clear()

    def add(self, record):
        with self.lock:
            self.requests.append(record)


HOOK_ID = "hook-1"
REPO_ID = "repo-1"
TARGET_ID = "00000000-0000-4000-8000-0000000000aa"
SECRET = "s3cr3t"
PUSH_BEFORE_ID = "00000000-0000-4000-8000-0000000000b1"
PUSH_AFTER_ID = "00000000-0000-4000-8000-0000000000b2"
PAYLOAD = dict(event="ping", zen="Rootyard HMAC verification test", hook_id=HOOK_ID, repository_id=REPO_ID)


def _record(secret, delivery_id, event, payload):
    raw_body = json.dumps(payload, separators=(",", ":")).encode()
    signature = webhooks.compute_hmac_sha256_header(secret, raw_body)
    headers = {
        "x-rootyard-event": event,
        "x-rootyard-delivery": delivery_id,
        "x-rootyard-hook-id": HOOK_ID,
        "x-rootyard-signature-256": signature,
    }
    return {
        "path": "/webhook",
        "headers": headers,
        "raw_body": raw_body,
        "json": payload,
        "signature": signature,
        "signature_valid": signature == webhooks.compute_hmac_sha256_header(SECRET, raw_body),
    }


def _push_record(delivery_id):
    payload = {"event": "push", "ref": "refs/heads/main", "delivery": delivery_id}
    return _record("push-secret", delivery_id, "push", payload)


def _ping_record(signing_secret=SECRET, delivery_id=TARGET_ID):
    return _record(signing_secret, delivery_id, "ping", PAYLOAD)


def _ping_response():
    raw_body = json.dumps(PAYLOAD, separators=(",", ":")).encode()
    return {
        "id": TARGET_ID,
        "event_id": "ping-fixed-1",
        "event_type": "ping",
        "webhook_id": HOOK_ID,
        "repository_id": REPO_ID,
        "payload": PAYLOAD,
        "signature_256": webhooks.compute_hmac_sha256_header(SECRET, raw_body),
        "state": "delivered",
        "response_status": 200,
    }


class WebhooksPingTest(unittest.TestCase):
    def _make_hook(self, ping_records):
        hook = webhooks.WebhooksHarness.__new__(webhooks.WebhooksHarness)
        hook.receiver = FakeReceiver()
        hook.hook_path = f"/api/repos/alice/forge/webhooks/{HOOK_ID}"
        hook.hook = {"id": HOOK_ID}
        hook.webhook_secret = SECRET
        hook.calls = []
        hook.target_requests = ping_records

        def document(path, status, method=None, body=None):
            self.assertEqual(list(hook.receiver.requests), [])
            hook.calls.append({"path": path, "status": status, "method": method, "body": body})
            hook.receiver.add(_push_record(PUSH_BEFORE_ID))
            for record in hook.target_requests:
                hook.receiver.add(record)
            hook.receiver.add(_push_record(PUSH_AFTER_ID))
            return _ping_response()

        hook.document = document
        return hook

    def test_ping_and_hmac_sha256_signature_verification_passes(self):
        hook = self._make_hook([_ping_record()])
        hook.ping_and_hmac_sha256_signature_verification()
        self.assertEqual(len(hook.calls), 1)
        call = hook.calls[0]
        self.assertEqual(call["path"], f"{hook.hook_path}/ping")
        self.assertEqual(call["status"], 200)
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["body"]["event_id"], "ping-fixed-1")
        ids = [r["headers"].get("x-rootyard-delivery") for r in hook.receiver.requests]
        self.assertIn(PUSH_BEFORE_ID, ids)
        self.assertIn(PUSH_AFTER_ID, ids)

    def test_ping_verification_fails_on_duplicate_or_bad_signature(self):
        cases = {
            "duplicate_target": [_ping_record(), _ping_record()],
            "wrong_hmac": [_ping_record(signing_secret="wrong-secret")],
        }
        for name, records in cases.items():
            with self.subTest(case=name):
                hook = self._make_hook(records)
                with self.assertRaises(AssertionError):
                    hook.ping_and_hmac_sha256_signature_verification()
