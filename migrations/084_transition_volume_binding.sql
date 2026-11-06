-- Upgrade installations that briefly ran the first 081 draft. Existing
-- unbound pending rows remain fail-closed for manual incident review.
ALTER TABLE shard_marker_transitions ADD COLUMN IF NOT EXISTS volume_id UUID;
CREATE INDEX IF NOT EXISTS shard_marker_transitions_volume_pending_idx
    ON shard_marker_transitions(volume_id, repository_id) WHERE state = 'pending';
INSERT INTO schema_migrations (version) VALUES (84) ON CONFLICT DO NOTHING;
