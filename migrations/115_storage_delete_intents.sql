-- A committed intent survives a crash between native unlink and the final
-- tombstone update. Retry can distinguish an already removed object from a
-- newly reachable one without trusting a late worker result.
ALTER TABLE storage_maintenance_tombstones
    DROP CONSTRAINT storage_maintenance_tombstones_state_check;
ALTER TABLE storage_maintenance_tombstones
    ADD CONSTRAINT storage_maintenance_tombstones_state_check
    CHECK (state IN ('pending','deleting','retained','deleted'));
DROP INDEX storage_maintenance_tombstones_due;
CREATE INDEX storage_maintenance_tombstones_due
    ON storage_maintenance_tombstones(delete_after,repository_id)
    WHERE state IN ('pending','deleting');

INSERT INTO schema_migrations (version) VALUES (115) ON CONFLICT DO NOTHING;
