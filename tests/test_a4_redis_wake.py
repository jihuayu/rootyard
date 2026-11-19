"""Source-only guards for the explicit A4 advisory wake topology (Refs #111).

The production path is intentionally opt-in: serve-blob publishes the existing
fixed wake hint only when ``ROOTYARD_A4_WAKE_TRANSPORT=redis`` is selected and
the binary was built with ``state-redis``. An external ``rootyard worker`` in
``ROOTYARD_WORKER_SCOPE=a4-target-audit`` subscribes on the same A4 channel and
scans only the target-audit evidence kind; it never enrolls legacy consumers or
Ref-CAS projection jobs. PostgreSQL remains the sole delivery authority.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def source(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def body(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin + len(start))]


class A4RedisWakeShapeTests(unittest.TestCase):
    def test_a4_worker_scope_is_explicit_and_excludes_legacy_work(self):
        dispatch = source("src/dispatch.rs")
        self.assertIn('pub const WORKER_SCOPE_ENV: &str = "ROOTYARD_WORKER_SCOPE"', dispatch)
        self.assertIn('pub const A4_WORKER_SCOPE: &str = "a4-target-audit"', dispatch)
        settings = body(dispatch, "pub fn a4_target_audit() -> Self", "/// Read only the shared")
        self.assertIn("crate::events::TARGET_AUDIT_CONSUMER", settings)
        self.assertIn("target_audit_only: true", settings)
        self.assertIn("projection_jobs: false", settings)
        transport = body(dispatch, "fn a4_transport_from_setting", "/// Runs independently")
        for forbidden in ("ROOTYARD_WORKER_CONSUMERS", "ROOTYARD_WAKE_TRANSPORT", "ROOTYARD_WAKE_CHANNEL"):
            self.assertNotIn(forbidden, transport)
        self.assertIn("ROOTYARD_A4_WAKE_TRANSPORT", dispatch)
        self.assertIn("ROOTYARD_A4_WAKE_CHANNEL", dispatch)

    def test_a4_transport_requires_state_redis_and_validates_its_channel(self):
        dispatch = source("src/dispatch.rs")
        transport = body(dispatch, "fn a4_transport_from_setting", "/// Runs independently")
        self.assertIn("state-redis", transport)
        self.assertIn("#[cfg(not(feature = \"state-redis\"))]", transport)
        self.assertIn("from_env_with_channel", transport)
        channel = body(dispatch, "pub fn a4_wake_channel()", "/// Resolve")
        self.assertIn('format!("rootyard:a4:{}:v1"', channel)
        self.assertIn("crate::events::TARGET_AUDIT_KIND", channel)
        resolve = body(dispatch, "pub fn a4_wake_channel_from_env()", "pub fn worker_scope_from_env")
        self.assertIn("validate_wake_channel", resolve)

    def test_serve_blob_reads_only_the_a4_opt_in_and_owns_publisher_cancellation(self):
        standalone = source("src/standalone.rs")
        self.assertIn("crate::dispatch::Settings::standalone_from_env()", standalone)
        self.assertIn("let transport = settings.transport.clone();", standalone)
        self.assertIn("crate::dispatch::publisher", standalone)
        self.assertIn("let mut publisher", standalone)
        self.assertIn("if !publisher.is_finished()", standalone)
        self.assertIn("publisher.abort()", standalone)
        self.assertGreaterEqual(standalone.count("dispatch_stop.clone()"), 2)
        for forbidden in (
            "ROOTYARD_WAKE_TRANSPORT",
            "ROOTYARD_WAKE_CHANNEL",
            "ROOTYARD_A4_WAKE_TRANSPORT",
            "Settings::from_env",
            "RedisWake",
        ):
            self.assertNotIn(forbidden, standalone)

    def test_external_worker_mode_is_explicit_and_default_stays_embedded(self):
        dispatch = source("src/dispatch.rs")
        self.assertIn('pub const A4_WORKER_MODE_ENV: &str = "ROOTYARD_A4_WORKER_MODE"', dispatch)
        self.assertIn('"" | "embedded" => Ok(A4WorkerMode::Embedded)', dispatch)
        self.assertIn('"external" => Ok(A4WorkerMode::External)', dispatch)
        self.assertIn("pub const fn runs_embedded_worker", dispatch)
        self.assertIn("matches!(self, Self::Embedded)", dispatch)
        self.assertIn("fn a4_worker_mode_defaults_embedded_and_external_is_explicit", dispatch)
        standalone = source("src/standalone.rs")
        self.assertIn("a4_worker_mode_from_env()", standalone)
        self.assertIn("if mode.runs_embedded_worker()", standalone)
        self.assertIn("None\n    };", standalone)
        self.assertIn("std::future::pending::<()>().await", standalone)
        self.assertIn("if let Some(worker) = worker.as_mut()", standalone)
        # The publisher is unconditional; external placement only removes the
        # local consumer, never the optional advisory producer.
        self.assertIn("let mut publisher = tokio::spawn(crate::dispatch::publisher", standalone)
        self.assertIn("dispatch_stop.cancel()", standalone)
        # The old unconditional worker spawn must not return.
        self.assertNotIn("let mut worker = tokio::spawn(crate::dispatch::worker", standalone)

    def test_external_worker_selects_the_a4_scope_before_scanning(self):
        main = source("src/main.rs")
        self.assertIn("worker_scope_from_env()?", main)
        self.assertIn("WorkerScope::Generic =>", main)
        self.assertIn("WorkerScope::A4TargetAudit =>", main)
        self.assertIn("Settings::a4_target_audit_from_env()?", main)
        self.assertIn("worker_once_with_lease_scoped(", main)
        self.assertIn(".then_some(rootyard::events::TARGET_AUDIT_KIND)", main)
        # worker-once must not bypass scoping with the old unscoped helper.
        self.assertNotIn("worker_once_with_lease(\n", main)

    def test_a4_commit_trigger_remains_post_commit_and_nonblocking(self):
        publish = source("src/blob_git_gateway/publish.rs")
        push = body(publish, "Start::Fresh { plan, _token: token }", "async fn repository_owner")
        self.assertLess(push.index("decide(state"), push.index("if notify"))
        self.assertLess(push.index("if notify"), push.index("state.dispatch().committed()"))
        dispatch = source("src/dispatch.rs")
        committed = body(dispatch, "pub fn committed(&self)", "}")
        self.assertIn("self.local.notify_one()", committed)
        self.assertIn("self.remote.notify_one()", committed)
        for forbidden in ("INSERT", "UPDATE", "DELETE", "Redis", "publish(", "await"):
            self.assertNotIn(forbidden, committed)

    def test_default_no_feature_build_keeps_redis_uncompiled(self):
        cargo = source("Cargo.toml")
        default = body(cargo, "default = [", "]")
        self.assertNotIn("state-redis", default)
        self.assertIn('state-redis = ["dep:redis"]', cargo)
        self.assertIn("redis = { version = \"=0.32.7\", optional = true", cargo)

    def test_wake_payload_stays_a_fixed_non_event_hint(self):
        types = source("src/cache_wake/types.rs")
        self.assertIn('pub const WAKE_PAYLOAD: &[u8] = b"v1"', types)


if __name__ == "__main__":
    unittest.main()
