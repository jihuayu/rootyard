import copy
import json
import unittest

import webhooks


class DispatchPullDeliveryTest(unittest.TestCase):
    def setUp(self):
        self.secret = "dispatch-race-secret"
        self.webhook_id = "hook-1"
        self.repository_id = "repo-1"
        self.event_id = "pull:7:1:head:opened"
        self.payload = {
            "event": "pull_request",
            "action": "opened",
            "repository_id": self.repository_id,
            "pull_number": 7,
            "head_oid": "head",
        }
        self.raw_body = json.dumps(self.payload, separators=(",", ":")).encode("utf-8")
        self.signature = webhooks.compute_hmac_sha256_header(self.secret, self.raw_body)
        self.delivery = {
            "id": "delivery-1",
            "webhook_id": self.webhook_id,
            "repository_id": self.repository_id,
            "sequence": 1,
            "event_id": self.event_id,
            "event_type": "pull_request",
            "payload": copy.deepcopy(self.payload),
            "request_headers": {
                "X-Rootyard-Event": "pull_request",
                "X-Rootyard-Delivery": "delivery-1",
                "X-Rootyard-Hook-Id": self.webhook_id,
                "X-Rootyard-Signature-256": self.signature,
                "X-Rootyard-Attempt": "1",
            },
            "signature_256": self.signature,
            "state": "delivered",
            "attempts": 1,
            "response_status": 200,
            "delivered_at": "2026-11-11T00:00:00Z",
        }

    def wire(self, delivery_id="delivery-1", **changes):
        header_changes = changes.pop("headers", None)
        request = {
            "headers": {
                "x-rootyard-event": "pull_request",
                "x-rootyard-delivery": delivery_id,
                "x-rootyard-hook-id": self.webhook_id,
                "x-rootyard-signature-256": self.signature,
                "x-rootyard-attempt": "1",
            },
            "raw_body": self.raw_body,
            "json": copy.deepcopy(self.payload),
            "signature": self.signature,
            "signature_valid": True,
            "response_status": 200,
        }
        if header_changes:
            request["headers"].update(header_changes)
        request.update(changes)
        return request

    def assert_contract(self, summary, delivery, requests):
        webhooks.assert_dispatch_pull_delivery(
            summary,
            delivery,
            requests,
            webhook_id=self.webhook_id,
            repository_id=self.repository_id,
            event_id=self.event_id,
            expected_payload=self.payload,
            secret=self.secret,
        )

    def test_zero_count_requires_exact_durable_hmac_delivery(self):
        unrelated = self.wire("another-delivery", json={"event": "push"})
        self.assert_contract(
            {"delivered_count": 0},
            self.delivery,
            [unrelated, self.wire()],
        )

    def test_positive_count_does_not_replace_exact_target_proof(self):
        self.assert_contract(
            {"delivered_count": 1},
            self.delivery,
            [self.wire()],
        )

    def test_missing_duplicate_or_mismatched_target_evidence_fails(self):
        cases = {
            "missing target": [self.wire("another-delivery")],
            "duplicate target": [self.wire(), self.wire()],
            "wrong hook": [
                self.wire(headers={"x-rootyard-hook-id": "another-hook"})
            ],
            "wrong signature header": [
                self.wire(headers={"x-rootyard-signature-256": "sha256=" + "0" * 64})
            ],
            "bad hmac bytes": [self.wire(raw_body=b'{"tampered":true}')],
            "invalid hmac flag": [self.wire(signature_valid=False)],
            "wrong receiver status": [self.wire(response_status=500)],
        }
        for name, requests in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(AssertionError):
                    self.assert_contract({"delivered_count": 0}, self.delivery, requests)

    def test_wrong_durable_identity_or_payload_fails(self):
        cases = {
            "hook": {"webhook_id": "another-hook"},
            "repository": {"repository_id": "another-repo"},
            "event": {"event_id": "another-event"},
            "payload": {"payload": {"event": "push"}},
        }
        for name, changes in cases.items():
            with self.subTest(case=name):
                delivery = copy.deepcopy(self.delivery)
                delivery.update(changes)
                with self.assertRaises(AssertionError):
                    self.assert_contract({"delivered_count": 0}, delivery, [self.wire()])

    def test_invalid_summary_count_fails(self):
        for count in (-1, True, "0"):
            with self.subTest(count=count):
                with self.assertRaises(AssertionError):
                    self.assert_contract(
                        {"delivered_count": count},
                        self.delivery,
                        [self.wire()],
                    )


if __name__ == "__main__":
    unittest.main()
