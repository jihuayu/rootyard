-- The advertised HEAD is part of the authoritative Pando ref snapshot.
-- A disposable Git session must not invent a default branch from git init.
ALTER TABLE pando_repository_states ADD COLUMN IF NOT EXISTS head_ref TEXT;
-- Backfill existing snapshots from a real branch in their own pando_refs rows
-- instead of hard-coding main: a Pando repository may legitimately have no
-- refs/heads/main and must still advertise and roll back one existing branch.
UPDATE pando_repository_states s
SET head_ref = COALESCE(
    (
        SELECT r.ref_name
        FROM pando_refs r
        WHERE r.repository_id = s.repository_id
          AND r.ref_name LIKE 'refs/heads/%'
          AND octet_length(r.ref_name) >= 12
          AND octet_length(r.ref_name) <= 1024
          AND r.ref_name !~ '[[:cntrl:]]'
        ORDER BY (r.ref_name = 'refs/heads/main') DESC, r.ref_name
        LIMIT 1
    ),
    'refs/heads/main'
)
WHERE s.head_ref IS NULL;
ALTER TABLE pando_repository_states ALTER COLUMN head_ref SET DEFAULT 'refs/heads/main';
ALTER TABLE pando_repository_states ALTER COLUMN head_ref SET NOT NULL;
ALTER TABLE pando_repository_states DROP CONSTRAINT IF EXISTS pando_repository_states_head_ref_check;
ALTER TABLE pando_repository_states ADD CONSTRAINT pando_repository_states_head_ref_check
    CHECK (octet_length(head_ref) >= 12 AND octet_length(head_ref) <= 1024
        AND head_ref LIKE 'refs/heads/%' AND head_ref !~ '[[:cntrl:]]');

INSERT INTO schema_migrations (version) VALUES (128) ON CONFLICT DO NOTHING;
