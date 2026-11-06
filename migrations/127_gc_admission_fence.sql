-- Durable physical-GC admission fence. A repository row carries the monotonic
-- gc_epoch and the committed maintenance lease; writers must hold a durable
-- admission row tied to that epoch. Retention-root triggers reject root
-- creation or mutation for the duration of a committed fence, so the SQL root
-- snapshot cannot drift while native Git objects are quarantined.
ALTER TABLE repositories
    ADD COLUMN gc_epoch BIGINT NOT NULL DEFAULT 0 CHECK (gc_epoch >= 0),
    ADD COLUMN gc_owner UUID,
    ADD COLUMN gc_job_id UUID REFERENCES storage_maintenance_jobs(id) ON DELETE SET NULL,
    ADD COLUMN gc_lease_until TIMESTAMPTZ,
    ADD COLUMN gc_fence_started_at TIMESTAMPTZ,
    ADD COLUMN gc_quiesced_at TIMESTAMPTZ;
ALTER TABLE repositories
    ADD CONSTRAINT repositories_gc_fence_consistency CHECK (
        (gc_owner IS NULL AND gc_job_id IS NULL AND gc_lease_until IS NULL
         AND gc_fence_started_at IS NULL AND gc_quiesced_at IS NULL)
        OR
        (gc_owner IS NOT NULL AND gc_job_id IS NOT NULL
         AND gc_lease_until IS NOT NULL AND gc_fence_started_at IS NOT NULL)
    );
CREATE INDEX repositories_gc_fence_active
    ON repositories(gc_lease_until) WHERE gc_owner IS NOT NULL;

-- A durable, lease-backed write admission. It is inserted under a
-- repositories FOR SHARE lock only after the writer observes no maintenance
-- fence. GC waits for every unexpired active row before it prunes. Rows are
-- never used as proof that an effect happened; they prove that an admitted
-- writer may still be in flight.
CREATE TABLE storage_write_admissions (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    gc_epoch BIGINT NOT NULL CHECK (gc_epoch >= 0),
    owner UUID NOT NULL,
    kind TEXT NOT NULL CHECK (kind ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    state TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'finished', 'aborted', 'fenced')),
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_until TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    detail TEXT CHECK (detail IS NULL OR octet_length(detail) <= 512),
    CHECK ((state = 'active') = (finished_at IS NULL))
);
CREATE INDEX storage_write_admissions_active
    ON storage_write_admissions(repository_id, lease_until) WHERE state = 'active';
CREATE INDEX storage_write_admissions_history
    ON storage_write_admissions(repository_id, admitted_at DESC);

-- GC retention roots also include workspace and checkpoint base commits. The
-- OID is durable SQL metadata; it does not replace native refs as authority.
ALTER TABLE workspaces ADD COLUMN base_oid TEXT
    CHECK (base_oid IS NULL OR (
        base_oid COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        AND base_oid <> repeat('0', length(base_oid))));
ALTER TABLE workspace_checkpoints ADD COLUMN base_oid TEXT
    CHECK (base_oid IS NULL OR (
        base_oid COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        AND base_oid <> repeat('0', length(base_oid))));

-- A physical GC fence freezes every SQL table that can introduce a new object
-- retention root. Foreign-key INSERTs already wait on the repositories row;
-- this trigger also covers UPDATEs of an existing root row and tables whose
-- repository binding is reached through another row.
CREATE FUNCTION rootyard_reject_gc_root_change() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE repo_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'workspace_view_history' THEN
        IF TG_OP = 'DELETE' THEN
            SELECT v.repository_id INTO repo_id
            FROM workspace_views v WHERE v.id = OLD.view_id;
        ELSE
            SELECT v.repository_id INTO repo_id
            FROM workspace_views v WHERE v.id = NEW.view_id;
        END IF;
    ELSIF TG_TABLE_NAME = 'sandbox_jobs' THEN
        -- A sandbox job reaches its repository through either a workspace or a
        -- CI run; the table itself has no repository_id column.
        IF TG_OP = 'DELETE' THEN
            SELECT COALESCE(
                (SELECT repository_id FROM workspaces WHERE id = OLD.workspace_id),
                (SELECT repository_id FROM ci_runs WHERE id = OLD.ci_run_id)
            ) INTO repo_id;
        ELSE
            SELECT COALESCE(
                (SELECT repository_id FROM workspaces WHERE id = NEW.workspace_id),
                (SELECT repository_id FROM ci_runs WHERE id = NEW.ci_run_id)
            ) INTO repo_id;
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        repo_id := OLD.repository_id;
    ELSE
        repo_id := NEW.repository_id;
    END IF;
    IF repo_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM repositories r
        WHERE r.id = repo_id AND r.gc_owner IS NOT NULL
          AND r.gc_lease_until > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'repository retention roots are fenced by physical GC'
            USING ERRCODE = '55006';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER forge_pulls_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON forge_pulls
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER forge_pull_reviews_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON forge_pull_reviews
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER forge_check_runs_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON forge_check_runs
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER ci_runs_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON ci_runs
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER ci_checkout_jobs_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON ci_checkout_jobs
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER ci_integration_checkout_jobs_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON ci_integration_checkout_jobs
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER ci_pull_sync_progress_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON ci_pull_sync_progress
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER workspaces_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON workspaces
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER workspace_checkpoints_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON workspace_checkpoints
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER workspace_namespace_mounts_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON workspace_namespace_mounts
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER workspace_views_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON workspace_views
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER workspace_view_history_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON workspace_view_history
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER workspace_changeset_steps_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON workspace_changeset_steps
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();
CREATE TRIGGER sandbox_jobs_gc_root_fence
    BEFORE INSERT OR UPDATE OR DELETE ON sandbox_jobs
    FOR EACH ROW EXECUTE FUNCTION rootyard_reject_gc_root_change();

INSERT INTO schema_migrations(version) VALUES (127) ON CONFLICT DO NOTHING;
