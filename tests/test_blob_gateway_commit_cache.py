"""Source-level shape checks for the target serve-blob commit-preview cache.

This test deliberately reads source only: it must not need PostgreSQL, Blob,
native Git, a service process or a built binary. Runtime cache-hit behavior is
covered by the focused in-process `read_cache` unit test; these assertions keep
the actual route wired at the only safe point and keep every live authority,
reachability and final output fence in front of a cached payload.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def source(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def body(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin + len(start))]


class BlobGatewayCommitCacheShapeTests(unittest.TestCase):
    def test_standalone_initializes_memory_cache_and_attaches_it(self):
        text = source("src/standalone.rs")
        self.assertIn("ServingCache::standalone_memory()", text)
        self.assertIn("state.with_cache(Arc::new(cache))", text)
        self.assertNotIn("ServingCache::from_env", text)
        self.assertNotIn("RedisCache", text)

    def test_commit_route_caches_only_after_reachability_and_before_finalize(self):
        text = source("src/blob_git_gateway/history.rs")
        handler = body(text, "async fn commit_authorized", "\npub(super) async fn compare")
        order = [
            "BrowseSession::open",
            "exact_oid",
            "browse::require_reachable",
            "browse::require_kind",
            "session.state.cache()",
            "CommitPreviewScope::from_session",
            "read_cache::cached_commit_detail",
            "finish(session, &response)",
        ]
        positions = [handler.index(marker) for marker in order]
        self.assertEqual(positions, sorted(positions), "cache must sit after live reachability and before finalize")
        self.assertNotIn("return Ok(Response", handler)
        self.assertNotIn("get_or_load_json", handler)

    def test_cached_payload_is_exact_native_oid_and_never_a_credential(self):
        text = source("src/blob_git_gateway/read_cache.rs")
        key_body = body(text, "fn key(&self, oid: &str)", "/// Fold storage generation")
        self.assertIn("GitOid::parse(self.object_format, oid)", key_body)
        self.assertIn("CACHE_AUTHORITY", key_body)
        self.assertIn("CACHE_AUTHORITY: &str = PG_REFSTORE_BACKEND", text)
        scope = source("src/ref_store/core/serving_scope.rs")
        self.assertIn('pub(crate) const PG_REFSTORE_BACKEND: &str = "pg_refstore"', scope)
        self.assertIn("CacheKind::GitObjectPreview", key_body)
        for domain in (
            "environment: &self.environment",
            "history_incarnation: self.history_incarnation",
            "tenant: self.tenant",
            "repo: self.repo",
        ):
            self.assertIn(domain, key_body)
        version_body = body(text, "fn version(&self) -> u64", "}\n\n/// Read one immutable")
        for domain in ("object_format", "storage_generation", "gate_revision", "restore_incarnation"):
            self.assertIn(domain, version_body)
        for forbidden in ("token", "authorization", "bearer", "credential"):
            self.assertNotIn(forbidden, key_body.lower())

    def test_miss_or_invalid_value_uses_the_real_origin_and_cache_is_advisory(self):
        text = source("src/blob_git_gateway/read_cache.rs")
        load_body = body(text, "pub(super) async fn cached_commit_detail", "#[cfg(test)]")
        self.assertIn("let Some(cache) = cache else", load_body)
        self.assertIn("let Some(key) = scope", load_body)
        self.assertIn("return load().await", load_body)
        self.assertIn("cache.get_json::<CachedCommitDetail>(&key)", load_body)
        self.assertIn("cached.oid == oid", load_body)
        self.assertIn("let detail = load().await?", load_body)
        self.assertIn("let cached = CachedCommitDetail::from(&detail)", load_body)
        self.assertIn("cache.put_json(&key, &cached, None).await", load_body)
        self.assertNotIn("get_or_load_json", load_body)
        self.assertNotIn("OriginError", load_body)
        self.assertNotIn("CircuitOpen", load_body)

    def test_native_http_hit_proof_seam_is_cfg_test_only(self):
        state = source("src/blob_git_gateway/state.rs")
        history = source("src/blob_git_gateway/history.rs")
        pauses = source("src/blob_git_gateway/state/acceptance_pauses.rs")
        native = source("src/blob_git_gateway/session_http_acceptance/cache_tests.rs")
        self.assertIn("#[cfg(test)]\nmod acceptance_pauses;", state)
        self.assertIn(
            "#[cfg(test)]\npub(crate) use acceptance_pauses::{AdmissionPause, ReadPause};",
            state,
        )
        self.assertNotIn("async fn pause_before_commit_finalize", state)
        self.assertIn("pub(crate) async fn pause_before_commit_finalize", pauses)
        self.assertIn(
            "#[cfg(test)]\n    session.state.pause_before_commit_finalize(&oid).await;",
            history,
        )
        self.assertIn("Gateway::start_with_cache", native)
        self.assertIn("cache_stats", native)
        self.assertIn("ReadPause", native)
        self.assertIn("tokio::spawn", native)
        self.assertIn("NATIVE_ACCEPTANCE_SERIAL", native)
        self.assertIn("db.finish(outcome).await", native)
        self.assertEqual(native.count("require_owned_disposable_fixture()?;"), 4)
        self.assertEqual(native.count("let db = Db::setup().await?;"), 4)
        for marker in (
            "ROOTYARD_TEST_OWNED_DISPOSABLE_POSTGRES",
            "ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB",
            "public.cluster_authority",
            "dedicated whole database",
        ):
            self.assertIn(marker, native)

    def test_paused_cache_request_is_released_reaped_and_never_panics(self):
        pauses = source("src/blob_git_gateway/state/acceptance_pauses.rs")
        native = source("src/blob_git_gateway/session_http_acceptance/cache_tests.rs")
        wait = body(
            pauses,
            "pub(crate) async fn wait_reached(&self, deadline: Instant)",
            "/// Let the paused request",
        )
        self.assertIn("anyhow::Result<()>", wait)
        self.assertIn("timeout_at", wait)
        self.assertNotIn("panic!", wait)
        self.assertIn("struct PausedRequest", native)
        self.assertIn("async fn reap", native)
        self.assertIn("task.abort()", native)
        self.assertIn("CASE_LIMIT", native)
        self.assertIn("CLEANUP_LIMIT", native)

    def test_paused_case_bounds_action_and_drains_server_before_db_finish(self):
        native = source("src/blob_git_gateway/session_http_acceptance/cache_tests.rs")
        http = source("src/blob_git_gateway/session_http_acceptance/support/http.rs")
        support = source("src/blob_git_gateway/session_http_acceptance/support.rs")
        self.assertIn("timeout_at(case_deadline, while_paused)", native)
        self.assertIn("Instant::now() + cleanup_limit", native)
        self.assertIn("timeout_at(cleanup_deadline, &mut task)", native)
        self.assertNotIn("let _ = task.await", native)
        self.assertIn("struct CaseFixture", native)
        self.assertIn("retain_on_drop", native)
        self.assertIn("std::mem::forget(gateway)", native)
        self.assertIn("start_drainable", http)
        self.assertIn("with_graceful_shutdown", http)
        self.assertIn("async fn shutdown", http)
        self.assertIn("timeout_at(deadline, &mut self.task)", http)
        self.assertNotIn("self.task.await", http)
        self.assertIn("self._server.shutdown(deadline).await", support)

    def test_final_live_authorization_and_session_fence_is_unchanged(self):
        text = source("src/blob_git_gateway/browse/session.rs")
        finalize = body(text, "pub(crate) async fn finalize", "/// The session decision")
        for marker in ("encode_response", "revalidate_serving", "verify_capture_anchor", "session_claim"):
            self.assertIn(marker, finalize)
        self.assertLess(finalize.index("encode_response"), finalize.index("revalidate_serving"))
        self.assertLess(finalize.index("verify_capture_anchor"), finalize.index("session_claim"))
        # A cache hit uses the same handler/response builder, not a cached raw
        # HTTP response or a session/login decision.
        history = source("src/blob_git_gateway/history.rs")
        self.assertIn("browse::finalize(session, &value).await", history)


if __name__ == "__main__":
    unittest.main()
