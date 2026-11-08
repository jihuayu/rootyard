-- Schema 137: narrow historical projection for terminal Git admissions.
--
-- Native Git may have committed a real receive-pack transaction before SQL
-- membership changed. Rust settlement moves the admitted writer to COMMITTED
-- (or ABORTED for a ref-free push) in the *same* transaction that inserts the
-- conservative `unknown` operation, its events and the final outcome. The
-- membership trigger must therefore accept a projection of that exact,
-- already-terminal operation even when the actor is no longer a member.
--
-- The exemption is deliberately narrow:
--   * only git_operations (Forge author tables never use it);
--   * only the CI service-principal branch is unchanged and returns first;
--   * writer_id must equal the operation id and the ledger row must name the
--     same repository, actor and token;
--   * COMMITTED allows only unknown/recorded, ABORTED only unknown/
--     no_ref_changes;
--   * UPDATE must keep the immutable operation identity, generation, sequence
--     and actor name, and may not change a terminal outcome.
-- A new ADMITTED write has no terminal row and still requires current
-- membership. A terminal row for a different operation, actor, token or
-- generation cannot authorize anything.
CREATE OR REPLACE FUNCTION enforce_repository_actor_membership()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actor_user_id UUID; repo_owner_id UUID; repo_generation BIGINT; projected BOOLEAN := false;
BEGIN
    IF TG_TABLE_NAME='git_operations' THEN
      IF NEW.service_principal_id IS NOT NULL THEN
        IF NEW.actor_id IS NOT NULL OR NEW.token_id IS NOT NULL OR
           NEW.actor_name IS DISTINCT FROM 'ci-scheduler' OR
           NEW.outcome NOT IN ('unknown','recorded') OR
           (NEW.evidence->>'kind') IS DISTINCT FROM 'observed_immutable_ci_root' OR
           (NEW.evidence->'intent'->>'repository_id') IS DISTINCT FROM NEW.repository_id::text OR
           (NEW.evidence->'intent'->>'storage_generation') IS DISTINCT FROM NEW.storage_generation::text OR
           NOT COALESCE((NEW.evidence->'intent'->>'job_id') COLLATE "C" ~
             '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false) OR
           NOT COALESCE((NEW.evidence->'intent'->>'target_oid') COLLATE "C" ~
             '^([0-9a-f]{40}|[0-9a-f]{64})$',false) OR
           (NEW.evidence->'intent'->>'retention_ref') IS DISTINCT FROM
             ('refs/rootyard-ci/jobs/' || (NEW.evidence->'intent'->>'job_id')) OR
           NOT EXISTS(SELECT 1 FROM ci_service_principals s
               JOIN repositories r ON r.id=s.repository_id
               WHERE s.id=NEW.service_principal_id AND s.repository_id=NEW.repository_id
               AND s.kind='ci-pin' AND s.active AND r.state='ready'
               AND r.storage_generation=NEW.storage_generation
               AND (NEW.evidence->'intent'->>'owner_id')=r.owner_id::text
               AND (s.issuer_webhook_id IS NULL OR EXISTS(
                   SELECT 1 FROM forge_webhooks w JOIN forge_trusted_check_contexts b
                     ON b.webhook_id=w.id AND b.repository_id=w.repository_id AND b.active
                   WHERE w.id=s.issuer_webhook_id AND w.repository_id=s.repository_id AND w.active)))
        THEN RAISE EXCEPTION 'invalid CI service principal operation' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
      END IF;
      actor_user_id:=NEW.actor_id;
    ELSE
      actor_user_id:=NEW.author_id;
    END IF;
    SELECT owner_id,storage_generation INTO repo_owner_id,repo_generation FROM repositories WHERE id=NEW.repository_id;
    IF repo_owner_id IS NULL THEN
        RAISE EXCEPTION 'repository does not exist' USING ERRCODE='23503';
    END IF;
    IF TG_TABLE_NAME='git_operations' THEN
      IF TG_OP='INSERT' THEN
        projected := EXISTS (
          SELECT 1 FROM git_ref_admissions a
          WHERE a.writer_id=NEW.id AND a.repository_id=NEW.repository_id
            AND a.actor_id=NEW.actor_id AND a.token_id=NEW.token_id
            AND ((a.state='COMMITTED' AND NEW.outcome IN ('unknown','recorded'))
              OR (a.state='ABORTED' AND NEW.outcome IN ('unknown','no_ref_changes'))))
          AND (
            (EXISTS (SELECT 1 FROM git_operations o WHERE o.id=NEW.id)
             AND EXISTS (
               SELECT 1 FROM git_operations o
               WHERE o.id=NEW.id AND o.repository_id=NEW.repository_id
                 AND o.actor_id IS NOT DISTINCT FROM NEW.actor_id
                 AND o.token_id IS NOT DISTINCT FROM NEW.token_id
                 AND o.service_principal_id IS NOT DISTINCT FROM NEW.service_principal_id
                 AND o.actor_name=NEW.actor_name AND o.sequence=NEW.sequence
                 AND o.storage_generation=NEW.storage_generation))
            OR (NOT EXISTS (SELECT 1 FROM git_operations o WHERE o.id=NEW.id)
                AND NEW.storage_generation=repo_generation));
      ELSE
        projected := OLD.id=NEW.id
          AND OLD.repository_id=NEW.repository_id
          AND OLD.actor_id IS NOT DISTINCT FROM NEW.actor_id
          AND OLD.token_id IS NOT DISTINCT FROM NEW.token_id
          AND OLD.service_principal_id IS NOT DISTINCT FROM NEW.service_principal_id
          AND OLD.actor_name=NEW.actor_name
          AND OLD.sequence=NEW.sequence
          AND OLD.storage_generation=NEW.storage_generation
          AND (OLD.outcome='unknown' OR OLD.outcome=NEW.outcome)
          AND EXISTS (
            SELECT 1 FROM git_ref_admissions a
            WHERE a.writer_id=NEW.id AND a.repository_id=NEW.repository_id
              AND a.actor_id=NEW.actor_id AND a.token_id=NEW.token_id
              AND ((a.state='COMMITTED' AND NEW.outcome IN ('unknown','recorded'))
                OR (a.state='ABORTED' AND NEW.outcome IN ('unknown','no_ref_changes'))));
      END IF;
      IF projected THEN RETURN NEW; END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM namespaces WHERE id=repo_owner_id AND user_id=actor_user_id)
       OR EXISTS (SELECT 1 FROM organization_memberships
                  WHERE organization_id=repo_owner_id AND user_id=actor_user_id)
       OR EXISTS (SELECT 1 FROM repository_collaborators
                  WHERE repository_id=NEW.repository_id AND user_id=actor_user_id)
       OR EXISTS (SELECT 1 FROM repository_team_members
                  WHERE repository_id=NEW.repository_id AND user_id=actor_user_id)
    THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'actor is not a member or collaborator of repository' USING ERRCODE='23514';
END $$;

INSERT INTO schema_migrations (version) VALUES (137) ON CONFLICT DO NOTHING;
