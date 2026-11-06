-- Run as the schema owner after `rootyard migrate` and after each schema upgrade.
-- The local profile uses node0..node3 and worker login names.
REVOKE CREATE ON DATABASE rootyard FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE rootyard TO worker;
GRANT USAGE ON SCHEMA public TO worker;

DO $$
DECLARE app_table record;
DECLARE node_name text;
BEGIN
    FOR node_name IN
        SELECT rolname FROM pg_roles WHERE rolname IN ('node0', 'node1', 'node2', 'node3')
    LOOP
        EXECUTE format('GRANT CONNECT ON DATABASE rootyard TO %I', node_name);
        EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', node_name);
        FOR app_table IN
            SELECT tablename FROM pg_tables
            WHERE schemaname = 'public'
              AND tablename NOT IN ('schema_migrations', 'cluster_authority', 'cluster_operator_tokens')
        LOOP
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO %I', app_table.tablename, node_name);
        END LOOP;
        EXECUTE format('GRANT SELECT ON TABLE public.schema_migrations, public.cluster_authority, public.cluster_operator_tokens TO %I', node_name);
        EXECUTE format('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO %I', node_name);
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.rootyard_worker_repository_generation(uuid, name) TO %I', node_name);
    END LOOP;
END $$;
GRANT SELECT ON TABLE public.schema_migrations TO worker;

GRANT SELECT ON TABLE public.repositories, public.git_operations,
    public.operation_resolutions, public.outbox_events,
    public.event_deliveries, public.repository_ref_projection TO worker;
GRANT UPDATE ON TABLE public.event_deliveries TO worker;
GRANT INSERT ON TABLE public.audit_events TO worker;
GRANT INSERT, UPDATE ON TABLE public.repository_ref_projection TO worker;
-- The SECURITY DEFINER function checks the caller's event-delivery UPDATE
-- grant and only takes a FOR SHARE row lock; it never grants repository DML.
GRANT EXECUTE ON FUNCTION public.rootyard_worker_repository_generation(uuid, name) TO worker;
