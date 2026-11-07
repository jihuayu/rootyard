-- Index-only support for bounded browser-session/token garbage collection.
-- No table, column, constraint, trigger or row data semantics change here.
-- Each index backs exactly one reference-preservation probe the GC deletion
-- statement performs before it may remove an expired `browser` child token.
CREATE INDEX IF NOT EXISTS git_operations_token_actor_idx
    ON git_operations (token_id, actor_id);
CREATE INDEX IF NOT EXISTS git_ref_admissions_token_actor_idx
    ON git_ref_admissions (token_id, actor_id);
CREATE INDEX IF NOT EXISTS ci_checkout_jobs_issuer_token_idx
    ON ci_checkout_jobs (issuer_token_id);
CREATE INDEX IF NOT EXISTS ci_checkout_delegations_issuer_token_idx
    ON ci_checkout_delegations (issuer_token_id);
-- Deliberately not partial: revoked and unrevoked expired rows are both GC input.
CREATE INDEX IF NOT EXISTS web_sessions_expiry_token_idx
    ON web_sessions (expires_at, token_id);
-- Browser child tokens are the only deletable token kind.
CREATE INDEX IF NOT EXISTS tokens_browser_expiry_idx
    ON tokens (expires_at, id) WHERE kind = 'browser';
INSERT INTO schema_migrations (version) VALUES (133) ON CONFLICT DO NOTHING;
