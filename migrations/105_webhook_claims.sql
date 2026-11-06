-- A lease generation fences late network outcomes and manual retries.
ALTER TABLE forge_webhook_deliveries
    ADD COLUMN lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0);
CREATE INDEX forge_webhook_deliveries_reclaim_idx
    ON forge_webhook_deliveries (state, next_attempt_unix, sequence);
INSERT INTO schema_migrations (version) VALUES (105) ON CONFLICT (version) DO NOTHING;
