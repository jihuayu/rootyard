-- Durable PostgreSQL admission for native Git ref writers. A writer inserts an
-- ADMITTED row before staging journal/object data. Route takeover fences the
-- writer's shard_epoch first and then either drains or marks old-epoch rows as
-- FENCED_ABORTED. The writer's SQL settlement condition requires ADMITTED, so a
-- paused writer cannot publish refs or outbox events after takeover.
CREATE TABLE IF NOT EXISTS git_ref_admissions (
    writer_id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    shard_epoch BIGINT NOT NULL CHECK (shard_epoch > 0),
    node_id TEXT CHECK (
        node_id IS NULL OR (
            octet_length(node_id) >= 1 AND octet_length(node_id) <= 63
            AND node_id !~ '[[:cntrl:]]'
        )
    ),
    actor_id UUID NOT NULL REFERENCES users(id),
    token_id UUID NOT NULL,
    ref_names TEXT[] NOT NULL CHECK (
        cardinality(ref_names) >= 1 AND cardinality(ref_names) <= 128
    ),
    state TEXT NOT NULL DEFAULT 'ADMITTED' CHECK (
        state IN ('ADMITTED', 'COMMITTED', 'ABORTED', 'FENCED_ABORTED')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    settled_at TIMESTAMPTZ,
    FOREIGN KEY (token_id, actor_id) REFERENCES tokens(id, user_id),
    CHECK (
        (state = 'ADMITTED' AND settled_at IS NULL)
        OR (state <> 'ADMITTED' AND settled_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS git_ref_admissions_open_epoch_idx
    ON git_ref_admissions (repository_id, shard_epoch, state)
    WHERE state = 'ADMITTED';

CREATE INDEX IF NOT EXISTS git_ref_admissions_repository_idx
    ON git_ref_admissions (repository_id, writer_id);

INSERT INTO schema_migrations (version) VALUES (126) ON CONFLICT DO NOTHING;
