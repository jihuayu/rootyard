-- The advertised HEAD is part of the authoritative Pando ref snapshot.
-- A disposable Git session must not invent a default branch from git init.
ALTER TABLE pando_repository_states
    ADD COLUMN IF NOT EXISTS head_ref TEXT NOT NULL DEFAULT 'refs/heads/main'
    CHECK (octet_length(head_ref) >= 12 AND octet_length(head_ref) <= 1024
        AND head_ref LIKE 'refs/heads/%' AND head_ref !~ '[[:cntrl:]]');

INSERT INTO schema_migrations (version) VALUES (126) ON CONFLICT DO NOTHING;
