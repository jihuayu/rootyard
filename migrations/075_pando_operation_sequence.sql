-- Pando ref publication and its outbox operation advance in one PostgreSQL
-- transaction. A new storage generation starts its own operation sequence.
ALTER TABLE pando_repository_states
    ADD COLUMN IF NOT EXISTS operation_sequence BIGINT NOT NULL DEFAULT 0
    CHECK (operation_sequence >= 0);

INSERT INTO schema_migrations (version) VALUES (75) ON CONFLICT DO NOTHING;
