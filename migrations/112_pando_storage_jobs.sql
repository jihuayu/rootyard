-- Reserve durable lifecycle work kinds for a production Pando gateway. The
-- GitFS worker must reject these until pack manifests, retention roots, and
-- remote deletion fencing are wired to the production callback.
ALTER TABLE storage_maintenance_jobs
    DROP CONSTRAINT storage_maintenance_jobs_kind_check;
ALTER TABLE storage_maintenance_jobs
    ADD CONSTRAINT storage_maintenance_jobs_kind_check CHECK (kind IN (
        'gitfs_stage_cleanup', 'gitfs_repack', 'gitfs_cache_hydrate',
        'gitfs_cache_evict', 'gitfs_unreachable_mark', 'gitfs_tombstone_delete',
        'pando_repack', 'pando_cache_hydrate', 'pando_cache_evict',
        'pando_unreachable_mark', 'pando_tombstone_delete'
    ));

INSERT INTO schema_migrations (version) VALUES (112) ON CONFLICT DO NOTHING;
