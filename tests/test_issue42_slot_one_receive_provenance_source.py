"""Pure source checks for the private slot-one receive-provenance seam.

No Cargo, database, service, network or native command is used. The checks pin
the producer-owned construction point, private completion, and the absence of
the old independent request/pairs/digest/mode handoff arguments.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RECEIVE = ROOT / "src/blob_git_gateway/receive.rs"
SLOT_ONE = ROOT / "src/blob_git_gateway/publish/slot_one.rs"


def production(source: str) -> str:
    return source.split("#[cfg(test)]", 1)[0]


def slice_between(source: str, start: str, end: str) -> str:
    assert start in source, start
    assert end in source, end
    return source.split(start, 1)[1].split(end, 1)[0]


class SlotOneReceiveProvenanceSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receive = RECEIVE.read_text()
        cls.receive_prod = production(cls.receive)
        cls.slot_one = SLOT_ONE.read_text()

    def test_receive_value_is_created_only_at_the_parsed_wire_digest_point(self):
        source = self.receive_prod
        self.assertIn("struct ReceiveInput<'a> {", source)
        self.assertNotIn("pub(super) struct ReceiveInput<'a>", source)
        self.assertIn("fn complete(self, pairs: Vec<Pair>) -> VerifiedReceive<'a>", source)
        self.assertNotIn("pub(super) fn complete(", source)
        self.assertEqual(source.count("ReceiveInput {"), 1)
        self.assertEqual(source.count(".complete(pairs)"), 1)
        self.assertLess(source.index("operation::request_digest("), source.index("let receive = ReceiveInput {"))
        self.assertLess(source.index("native::run_capture("), source.index("let receive = receive.complete(pairs)"))
        self.assertLess(source.index("Pair::stage("), source.index("let receive = receive.complete(pairs)"))

    def test_completed_receive_fields_are_private_to_the_producer(self):
        source = self.receive_prod
        fields = slice_between(
            source,
            "pub(super) struct VerifiedReceive<'a> {",
            "}",
        )
        for field in (
            "actor:",
            "operation:",
            "repository_id:",
            "object_format:",
            "request:",
            "mode:",
            "digest:",
            "pairs:",
        ):
            self.assertIn(field, fields)
            self.assertNotIn(f"pub {field}", fields)

    def test_handoff_accepts_only_completed_receive_and_exact_retirement(self):
        handoff = slice_between(
            self.slot_one,
            "fn from_verified_slot_zero(",
            ") -> Result<Self, GatewayError>",
        )
        self.assertIn("verified: &'verified VerifiedReceive<'actor>", handoff)
        for independent in ("actor:", "request:", "pairs:", "wire_digest:", "mode:", "public_id:"):
            self.assertNotIn(independent, handoff)

    def test_rotation_takes_only_the_completed_receive_value(self):
        rotation = slice_between(
            self.slot_one,
            "async fn rotate_slot_one(",
            ") -> Result<SlotOneAdmission, GatewayError>",
        )
        self.assertIn("receive: &SlotOneReceive<'_, '_>", rotation)
        for independent in ("actor: &Identity", "request: &PushRequest", "pairs: &[Pair]"):
            self.assertNotIn(independent, rotation)
        self.assertIn("let actor = receive.actor();", self.slot_one)
        self.assertIn("let request = receive.request();", self.slot_one)
        self.assertIn("let pairs = receive.pairs();", self.slot_one)

    def test_normal_receive_selects_private_push_private(self):
        self.assertIn("publish::push_private(", self.receive)
        self.assertNotIn("publish::push(", self.receive)
        self.assertNotIn("rotate_slot_one(", self.receive)
        self.assertIn(
            "publish::push_private(&state, &serving, &receive, deadline).await;",
            self.receive_prod,
        )


if __name__ == "__main__":
    unittest.main()
