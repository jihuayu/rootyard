-- Rotated after metadata restore so replayed, pre-restore delegations cannot
-- become valid again when the nonce table is rolled back.
CREATE TABLE IF NOT EXISTS cluster_authority (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    incarnation UUID NOT NULL DEFAULT gen_random_uuid(),
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO cluster_authority(singleton) VALUES(true) ON CONFLICT DO NOTHING;
INSERT INTO schema_migrations (version) VALUES (85) ON CONFLICT DO NOTHING;
