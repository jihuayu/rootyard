-- The destination records the actual journal sequence measured with the
-- transferred, fsck-verified Git snapshot. An operator cannot supply this as
-- a takeover receipt.
ALTER TABLE shard_replication_operations
    ADD COLUMN IF NOT EXISTS journal_sequence BIGINT CHECK (journal_sequence >= 0);
INSERT INTO schema_migrations (version) VALUES (86) ON CONFLICT DO NOTHING;
