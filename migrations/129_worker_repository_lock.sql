-- Let the outbox role hold the repository row lock required by the delivery
-- ordering protocol without granting it UPDATE on repository metadata.
CREATE FUNCTION rootyard_worker_repository_generation(repo_uuid uuid, app_schema name)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE generation bigint;
BEGIN
    IF NOT has_table_privilege(session_user, format('%I.event_deliveries', app_schema), 'UPDATE') THEN
        RAISE EXCEPTION 'repository delivery lock requires event delivery role'
            USING ERRCODE = '42501';
    END IF;
    EXECUTE format('SELECT storage_generation FROM %I.repositories WHERE id=$1 FOR SHARE', app_schema)
        INTO STRICT generation USING repo_uuid;
    RETURN generation;
END;
$$;
-- Executable by any login, but the SECURITY DEFINER body rejects callers
-- without UPDATE on the application event_deliveries table. This keeps the
-- split worker role usable without granting it UPDATE on repository metadata;
-- a non-delivery login still gets SQLSTATE 42501 from the function itself.
GRANT EXECUTE ON FUNCTION rootyard_worker_repository_generation(uuid, name) TO PUBLIC;
-- The projection trigger also checks the generation under FOR SHARE. Reuse
-- the same narrowly authorized lock rather than requiring worker UPDATE on
-- repositories through that trigger's invoker privileges.
CREATE OR REPLACE FUNCTION rootyard_projection_epoch()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE current_generation bigint;
BEGIN
    EXECUTE format('SELECT storage_generation FROM %I.repositories WHERE id=$1 FOR SHARE', TG_TABLE_SCHEMA)
        INTO STRICT current_generation USING NEW.repository_id;
    IF NEW.storage_generation IS DISTINCT FROM current_generation THEN
        RAISE EXCEPTION 'stale projection storage generation';
    END IF;
    RETURN NEW;
END;
$$;
INSERT INTO schema_migrations (version) VALUES (129) ON CONFLICT DO NOTHING;
