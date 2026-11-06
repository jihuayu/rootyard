-- A committed route transition records the marker it needs to publish.
-- An incomplete publication blocks writes until startup reconciliation succeeds.
CREATE TABLE IF NOT EXISTS shard_marker_transitions (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    volume_id UUID NOT NULL,
    target_marker JSONB NOT NULL CHECK (jsonb_typeof(target_marker) = 'object'),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'complete')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    CHECK ((state = 'pending' AND completed_at IS NULL) OR (state = 'complete' AND completed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS shard_marker_transitions_pending_idx
    ON shard_marker_transitions(volume_id, repository_id) WHERE state = 'pending';

INSERT INTO schema_migrations (version) VALUES (81) ON CONFLICT DO NOTHING;
