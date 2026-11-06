-- Durable two-phase storage transition fence. Every write admission reads the
-- repository's transition state; a cutover or rollback bumps the transition
-- epoch exactly once so an operation admitted before the fence cannot be
-- mistaken for one admitted after it.
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS backend_transition_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS transition_state TEXT NOT NULL DEFAULT 'stable';
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS transition_id UUID;
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS transition_started_at TIMESTAMPTZ;
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS transition_error TEXT;

ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_transition_epoch_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_transition_epoch_check
    CHECK (backend_transition_epoch >= 0);
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_transition_state_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_transition_state_check
    CHECK (transition_state IN ('stable', 'draining', 'failed'));
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_transition_fence_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_transition_fence_check
    CHECK ((transition_state = 'stable') = (transition_id IS NULL)
        AND (transition_state = 'stable') = (transition_started_at IS NULL)
        AND (transition_state <> 'failed' OR transition_error IS NOT NULL));

CREATE INDEX IF NOT EXISTS repositories_transition_inflight
    ON repositories(transition_started_at)
    WHERE transition_state <> 'stable';

INSERT INTO schema_migrations (version) VALUES (128) ON CONFLICT DO NOTHING;
