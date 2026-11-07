-- Relational hardening for repository/tenant identity pairs (#90).
--
-- Runtime paths already re-check the owning repository before touching shared
-- state (jobs::current, the transition fence and the serving lookup all verify
-- owner, generation and backend), so this is not an exploitable runtime
-- authorization gap. What was missing is relational integrity: a row could name
-- one repository id together with a different tenant's id and PostgreSQL would
-- accept it, leaving the runtime guard as the only thing standing between two
-- tenants. These constraints make such a pair unresolvable in the first place;
-- none of the existing runtime guards are removed or weakened.
--
-- Upgrade policy: nothing here rewrites, deletes or "repairs" data. If rows on
-- disk already disagree, the migration aborts with count-only diagnostics and
-- an operator has to inspect the rows before the constraints are installed. A
-- silently corrected job, tombstone, artifact link or repository owner would
-- hide exactly the condition this migration is meant to expose.

-- 1. Read-only preflight. The abort text is a fixed format carrying counts only:
--    no row ids, repository ids, tenant ids, object names or payloads, so a
--    failed upgrade cannot leak tenant-scoped values into a log.
DO $$
DECLARE
    bad_links BIGINT;
    bad_repo_state BIGINT;
    bad_jobs BIGINT;
    bad_tombstones BIGINT;
BEGIN
    SELECT count(*) INTO bad_links
      FROM pando_manifest_artifacts l
      JOIN pando_pack_manifests m ON m.id = l.manifest_id
     WHERE l.repository_id IS DISTINCT FROM m.repository_id
        OR l.tenant_id IS DISTINCT FROM m.tenant_id;
    SELECT count(*) INTO bad_repo_state
      FROM storage_maintenance_repo_state s
      JOIN repositories r ON r.id = s.repository_id
     WHERE s.tenant_id IS DISTINCT FROM r.owner_id;
    SELECT count(*) INTO bad_jobs
      FROM storage_maintenance_jobs j
      JOIN repositories r ON r.id = j.repository_id
     WHERE j.tenant_id IS DISTINCT FROM r.owner_id;
    SELECT count(*) INTO bad_tombstones
      FROM storage_maintenance_tombstones t
      JOIN repositories r ON r.id = t.repository_id
     WHERE t.tenant_id IS DISTINCT FROM r.owner_id;

    IF bad_links + bad_repo_state + bad_jobs + bad_tombstones > 0 THEN
        RAISE EXCEPTION
            'schema134 refuses to upgrade: % manifest link row(s), % repository state row(s), % maintenance job(s) and % tombstone(s) disagree with their repository identity; no row was modified',
            bad_links, bad_repo_state, bad_jobs, bad_tombstones
            USING HINT = 'Inspect these identity pairs manually. Migration 134 never deletes, rewrites or re-owns maintenance jobs, tombstones, artifact links or repository owners.';
    END IF;
END
$$;

-- 2. The manifest row needs a unique key that contains the tenant before an
--    artifact link can reference (id, repository_id, tenant_id) as a triple.
--    The existing UNIQUE (repository_id, id) stays: it is a different lookup
--    shape and already used by the manifest readers.
ALTER TABLE pando_pack_manifests
    ADD CONSTRAINT pando_pack_manifests_id_repository_tenant_key
        UNIQUE (id, repository_id, tenant_id);

-- 3. Replace the manifest_id-only link FK with the composite one. Keeping the
--    single-column FK would install a second cascade path for the same manifest
--    rows, so it is dropped by its actual pre-134 name instead of coexisting.
--    Cascade behaviour is preserved; the independent artifact authority/tenant
--    FK below is untouched. The new FK is validated by its own index: the
--    existing primary key (manifest_id, artifact_role) already leads with
--    manifest_id, so no extra lookup index is created here.
ALTER TABLE pando_manifest_artifacts
    DROP CONSTRAINT pando_manifest_artifacts_manifest_id_fkey,
    ADD CONSTRAINT pando_manifest_artifacts_manifest_identity_fkey
        FOREIGN KEY (manifest_id, repository_id, tenant_id)
        REFERENCES pando_pack_manifests (id, repository_id, tenant_id)
        ON DELETE CASCADE;

-- 4. The three GitFS lifecycle tables keep their namespace (users/namespaces)
--    FK and their repository cascade, but the repository reference is now the
--    (repository_id, tenant_id) -> repositories(id, owner_id) pair. Every one of
--    these tables is already indexed with repository_id leading (repo state and
--    tombstones by primary key, jobs by storage_maintenance_history), and the
--    referenced side uses the existing repositories_owner_identity unique index,
--    so no duplicate index is added.
ALTER TABLE storage_maintenance_repo_state
    DROP CONSTRAINT storage_maintenance_repo_state_repository_id_fkey,
    ADD CONSTRAINT storage_maintenance_repo_state_repository_owner_fkey
        FOREIGN KEY (repository_id, tenant_id)
        REFERENCES repositories (id, owner_id)
        ON DELETE CASCADE;

ALTER TABLE storage_maintenance_jobs
    DROP CONSTRAINT storage_maintenance_jobs_repository_id_fkey,
    ADD CONSTRAINT storage_maintenance_jobs_repository_owner_fkey
        FOREIGN KEY (repository_id, tenant_id)
        REFERENCES repositories (id, owner_id)
        ON DELETE CASCADE;

ALTER TABLE storage_maintenance_tombstones
    DROP CONSTRAINT storage_maintenance_tombstones_repository_id_fkey,
    ADD CONSTRAINT storage_maintenance_tombstones_repository_owner_fkey
        FOREIGN KEY (repository_id, tenant_id)
        REFERENCES repositories (id, owner_id)
        ON DELETE CASCADE;

-- 5. Assert the intended shape: four validated cascading composite FKs and no
--    leftover single-column manifest link. Fixed text only; this fails the
--    migration transaction rather than leaving a half-hardened schema.
DO $$
DECLARE
    installed INT;
BEGIN
    SELECT count(*) INTO installed
      FROM pg_constraint
     WHERE conname IN (
               'pando_manifest_artifacts_manifest_identity_fkey',
               'storage_maintenance_repo_state_repository_owner_fkey',
               'storage_maintenance_jobs_repository_owner_fkey',
               'storage_maintenance_tombstones_repository_owner_fkey')
       AND contype = 'f'
       AND convalidated
       AND confdeltype = 'c';
    IF installed <> 4 THEN
        RAISE EXCEPTION 'schema134 installed % of 4 validated composite identity foreign keys', installed;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint
                WHERE conname = 'pando_manifest_artifacts_manifest_id_fkey') THEN
        RAISE EXCEPTION 'schema134 left the single-column manifest link in place';
    END IF;
END
$$;

INSERT INTO schema_migrations (version) VALUES (134) ON CONFLICT DO NOTHING;
