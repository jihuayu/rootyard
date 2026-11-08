-- Metrics scrape support for durable storage maintenance backlog (#80).
--
-- The metrics endpoint aggregates exactly the seven fixed non-GC lifecycle
-- kinds by state. A partial covering index keeps the frequent COUNT(...) from
-- scanning the retained `succeeded` history and keeps the query's referenced
-- columns (kind, state, not_before, lease_until, created_at) inside the index.
-- GC admission kinds are excluded so their independent retention paths do not
-- inherit this index. Nothing is deleted or rewritten: this is index-only DDL.
CREATE INDEX storage_maintenance_metrics
    ON storage_maintenance_jobs (kind, state, not_before, lease_until, created_at)
    WHERE state IN ('queued','running','failed')
      AND kind IN (
          'gitfs_stage_cleanup', 'gitfs_repack', 'gitfs_cache_hydrate',
          'gitfs_cache_evict', 'pando_repack', 'pando_cache_hydrate',
          'pando_cache_evict'
      );

INSERT INTO schema_migrations (version) VALUES (135) ON CONFLICT DO NOTHING;
