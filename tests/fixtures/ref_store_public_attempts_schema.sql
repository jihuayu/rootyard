-- Run with psql -X -f in a disposable database. This unnumbered draft covers
-- ownership, retention and UUID admission. It has no producer or retry path.
\set ON_ERROR_STOP on
BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
CREATE SCHEMA issue42_schema_contract;
SET LOCAL search_path = issue42_schema_contract, pg_catalog, pg_temp;

CREATE TABLE repositories (id uuid PRIMARY KEY, owner_id uuid NOT NULL);
CREATE TABLE schema_migrations (version int PRIMARY KEY);
\ir ../../migrations/138_ref_store_operation_identity.sql

CREATE TABLE ref_store_public_operations (
    repository_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    public_id uuid NOT NULL,
    admission_owner_id uuid NOT NULL,
    PRIMARY KEY (repository_id, public_id)
);

CREATE TABLE ref_store_private_attempts (
    repository_id uuid NOT NULL,
    public_id uuid NOT NULL,
    slot smallint NOT NULL CONSTRAINT attempt_slot CHECK (slot IN (0, 1)),
    private_id uuid NOT NULL,
    PRIMARY KEY (repository_id, public_id, slot),
    UNIQUE (repository_id, private_id),
    FOREIGN KEY (repository_id, public_id) REFERENCES ref_store_public_operations(repository_id, public_id) ON DELETE CASCADE
);

CREATE FUNCTION operation_key(repo uuid, op uuid) RETURNS bigint LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT hashtextextended('rootyard-ref-store-operation-v1/' || repo::text || '/' || op::text, 0)
$$;

CREATE FUNCTION candidate_ids(public_op uuid, slot_zero uuid, slot_one uuid) RETURNS uuid[] LANGUAGE sql IMMUTABLE AS $$
    SELECT ARRAY(SELECT DISTINCT id FROM unnest(ARRAY[public_op, slot_zero, slot_one]) AS ids(id)
                 WHERE id IS NOT NULL ORDER BY id)
$$;

CREATE FUNCTION lock_candidates(repo uuid, public_op uuid, slot_zero uuid, slot_one uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    op uuid;
BEGIN
    FOREACH op IN ARRAY candidate_ids(public_op, slot_zero, slot_one) LOOP
        PERFORM pg_advisory_xact_lock(operation_key(repo, op));
    END LOOP;
END $$;

CREATE FUNCTION require_operation_lock(repo uuid, op uuid) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory'
        AND objsubid = 1 AND mode = 'ExclusiveLock' AND granted
        AND ((classid::bigint << 32) | objid::bigint) = operation_key(repo, op)
    ) THEN
        RAISE EXCEPTION 'candidate lock is required' USING ERRCODE = '55000', CONSTRAINT = 'candidate_lock';
    END IF;
END $$;

-- These checks cover the wrapper/attempt side of admission. Before turning on
-- producers, reserve/begin/cancel must reciprocally check both claim tables
-- under the same advisory prefix, including cancel-before-register. Legacy
-- replay must exclude private IDs. This draft leaves legacy writers intact.
CREATE FUNCTION require_unclaimed(repo uuid, op uuid) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM require_operation_lock(repo, op);
    IF EXISTS (SELECT FROM ref_store_operations WHERE (repository_id, operation_id) = (repo, op))
       OR EXISTS (SELECT FROM ref_store_cancellations WHERE (repository_id, operation_id) = (repo, op))
       OR EXISTS (SELECT FROM ref_store_public_operations WHERE (repository_id, public_id) = (repo, op))
       OR EXISTS (SELECT FROM ref_store_private_attempts WHERE (repository_id, private_id) = (repo, op)) THEN
        RAISE EXCEPTION 'candidate is already claimed' USING ERRCODE = '23505', CONSTRAINT = 'candidate_claim';
    END IF;
END $$;

CREATE FUNCTION guard_admission_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    admitted_owner uuid;
    current_owner uuid;
BEGIN
    IF TG_TABLE_NAME = 'ref_store_public_operations' THEN
        PERFORM require_unclaimed(NEW.repository_id, NEW.public_id);
        admitted_owner := NEW.admission_owner_id;
    ELSE
        PERFORM require_operation_lock(NEW.repository_id, NEW.public_id);
        PERFORM require_unclaimed(NEW.repository_id, NEW.private_id);
        SELECT admission_owner_id INTO admitted_owner FROM ref_store_public_operations
            WHERE (repository_id, public_id) = (NEW.repository_id, NEW.public_id);
    END IF;
    SELECT owner_id INTO current_owner FROM repositories WHERE id = NEW.repository_id FOR SHARE;
    IF admitted_owner IS NULL OR current_owner IS DISTINCT FROM admitted_owner THEN
        RAISE EXCEPTION 'admission owner must match the locked repository owner'
            USING ERRCODE = '23514', CONSTRAINT = 'admission_owner';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION guard_admission_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Both cascade paths reach this trigger after the repository row has gone.
        IF NOT EXISTS (SELECT FROM repositories WHERE id = OLD.repository_id) THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'admission identity is retained while its repository exists'
        USING ERRCODE = '55000', CONSTRAINT = 'admission_history';
END $$;

CREATE TRIGGER guard_admission_insert BEFORE INSERT ON ref_store_public_operations
    FOR EACH ROW EXECUTE FUNCTION guard_admission_insert();
CREATE TRIGGER guard_admission_insert BEFORE INSERT ON ref_store_private_attempts
    FOR EACH ROW EXECUTE FUNCTION guard_admission_insert();
CREATE TRIGGER guard_admission_history BEFORE UPDATE OR DELETE ON ref_store_public_operations
    FOR EACH ROW EXECUTE FUNCTION guard_admission_history();
CREATE TRIGGER guard_admission_history BEFORE UPDATE OR DELETE ON ref_store_private_attempts
    FOR EACH ROW EXECUTE FUNCTION guard_admission_history();
CREATE TRIGGER guard_admission_truncate BEFORE TRUNCATE ON ref_store_public_operations
    FOR EACH STATEMENT EXECUTE FUNCTION guard_admission_history();
CREATE TRIGGER guard_admission_truncate BEFORE TRUNCATE ON ref_store_private_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION guard_admission_history();

-- The future serving caller must acquire the normalized prefix before the
-- issuer-lane and repository locks. This fixture does not touch an issuer lane
-- during admission or authorize any lifecycle action.
CREATE FUNCTION fixture_admit(repo uuid, tenant uuid, public_op uuid, slot_zero uuid, slot_one uuid DEFAULT NULL)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM lock_candidates(repo, public_op, slot_zero, slot_one);
    INSERT INTO ref_store_public_operations VALUES (repo, public_op, tenant);
    INSERT INTO ref_store_private_attempts VALUES (repo, public_op, 0, slot_zero);
    IF slot_one IS NOT NULL THEN
        INSERT INTO ref_store_private_attempts VALUES (repo, public_op, 1, slot_one);
    END IF;
END $$;

CREATE FUNCTION fixture_id(n integer) RETURNS uuid LANGUAGE sql IMMUTABLE AS $$
    SELECT ('00000000-0000-4000-8000-' || lpad(n::text, 12, '0'))::uuid
$$;

CREATE FUNCTION fixture_refuses(command text, expected_state text, expected_constraint text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    actual_constraint text;
BEGIN
    BEGIN
        EXECUTE command;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS actual_constraint = CONSTRAINT_NAME;
        IF SQLSTATE IS DISTINCT FROM expected_state OR actual_constraint IS DISTINCT FROM expected_constraint THEN
            RAISE EXCEPTION 'unexpected ownership contract refusal';
        END IF;
        RETURN;
    END;
    RAISE EXCEPTION 'expected ownership contract refusal';
END $$;

DO $$
DECLARE
    repo constant uuid := fixture_id(1);
    other_repo constant uuid := fixture_id(2);
    prior_owner constant uuid := fixture_id(3);
    next_owner constant uuid := fixture_id(4);
    occupied uuid;
    ids uuid[];
BEGIN
    INSERT INTO repositories VALUES (repo, prior_owner), (other_repo, next_owner);
    INSERT INTO ref_store_issuer_lanes(repository_id, issuer_id, lane, last_reserved_sequence)
    VALUES (repo, fixture_id(5), 'fixture', 2);
    INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest, state)
    VALUES (repo, fixture_id(5), 'fixture', 1, fixture_id(11), repeat('a', 64), 'pending');
    INSERT INTO ref_store_cancellations(repository_id, issuer_id, lane, sequence, operation_id, request_digest)
    VALUES (repo, fixture_id(5), 'fixture', 2, fixture_id(12), repeat('b', 64));

    IF candidate_ids(fixture_id(30), fixture_id(20), fixture_id(10)) <> ARRAY[fixture_id(10), fixture_id(20), fixture_id(30)]
       OR candidate_ids(fixture_id(10), fixture_id(10), NULL) <> ARRAY[fixture_id(10)] THEN
        RAISE EXCEPTION 'candidate normalization differs';
    END IF;
    PERFORM fixture_refuses('INSERT INTO ref_store_public_operations VALUES (fixture_id(1), fixture_id(30), fixture_id(3))',
                            '55000', 'candidate_lock');
    FOREACH occupied IN ARRAY ARRAY[fixture_id(11), fixture_id(12)] LOOP
        FOR candidate_index IN 1..3 LOOP
            ids := ARRAY[fixture_id(30), fixture_id(10), fixture_id(20)];
            ids[candidate_index] := occupied;
            PERFORM fixture_refuses(format('SELECT fixture_admit(%L, %L, %L, %L, %L)', repo, prior_owner, ids[1], ids[2], ids[3]),
                                    '23505', 'candidate_claim');
        END LOOP;
    END LOOP;
    IF EXISTS (SELECT FROM ref_store_public_operations) OR EXISTS (SELECT FROM ref_store_private_attempts) THEN
        RAISE EXCEPTION 'refused admission left a partial claim';
    END IF;
    PERFORM fixture_refuses('SELECT fixture_admit(fixture_id(1), fixture_id(4), fixture_id(30), fixture_id(10), fixture_id(20))',
                            '23514', 'admission_owner');
    PERFORM fixture_admit(repo, prior_owner, fixture_id(30), fixture_id(10), fixture_id(20));
    PERFORM fixture_admit(repo, prior_owner, fixture_id(32), fixture_id(31));
    PERFORM fixture_admit(other_repo, next_owner, fixture_id(30), fixture_id(10), fixture_id(20));
    PERFORM fixture_refuses('SELECT fixture_admit(fixture_id(1), fixture_id(3), fixture_id(10), fixture_id(40))',
                            '23505', 'candidate_claim');
    PERFORM fixture_refuses('SELECT fixture_admit(fixture_id(1), fixture_id(3), fixture_id(40), fixture_id(30))',
                            '23505', 'candidate_claim');
    PERFORM fixture_refuses('SELECT fixture_admit(fixture_id(1), fixture_id(3), fixture_id(40), fixture_id(20))',
                            '23505', 'candidate_claim');
    PERFORM lock_candidates(repo, fixture_id(30), fixture_id(50), NULL);
    PERFORM fixture_refuses('INSERT INTO ref_store_private_attempts VALUES (fixture_id(1), fixture_id(30), 2, fixture_id(50))',
                            '23514', 'attempt_slot');

    UPDATE repositories SET owner_id = next_owner WHERE id = repo;
    IF (SELECT owner_id FROM repositories WHERE id = repo) IS DISTINCT FROM next_owner
       OR (SELECT count(*) FROM ref_store_public_operations WHERE repository_id = repo AND admission_owner_id = prior_owner) <> 2
       OR (SELECT count(*) FROM ref_store_private_attempts WHERE repository_id = repo) <> 3 THEN
        RAISE EXCEPTION 'owner transfer rewrote or removed admission history';
    END IF;
    PERFORM lock_candidates(repo, fixture_id(32), fixture_id(31), fixture_id(33));
    PERFORM fixture_refuses('INSERT INTO ref_store_private_attempts VALUES (fixture_id(1), fixture_id(32), 1, fixture_id(33))',
                            '23514', 'admission_owner');
    PERFORM fixture_refuses('SELECT fixture_admit(fixture_id(1), fixture_id(3), fixture_id(60), fixture_id(61))',
                            '23514', 'admission_owner');
    PERFORM fixture_admit(repo, next_owner, fixture_id(60), fixture_id(61));
    PERFORM fixture_refuses('UPDATE ref_store_public_operations SET admission_owner_id = fixture_id(4) WHERE repository_id = fixture_id(1)',
                            '55000', 'admission_history');
    PERFORM fixture_refuses('UPDATE ref_store_public_operations SET public_id = fixture_id(70) WHERE repository_id = fixture_id(1)',
                            '55000', 'admission_history');
    PERFORM fixture_refuses('UPDATE ref_store_private_attempts SET private_id = fixture_id(70) WHERE repository_id = fixture_id(1)',
                            '55000', 'admission_history');
    PERFORM fixture_refuses('DELETE FROM ref_store_public_operations WHERE repository_id = fixture_id(1)',
                            '55000', 'admission_history');
    PERFORM fixture_refuses('DELETE FROM ref_store_private_attempts WHERE repository_id = fixture_id(1)',
                            '55000', 'admission_history');
    PERFORM fixture_refuses('TRUNCATE ref_store_public_operations, ref_store_private_attempts', '55000', 'admission_history');

    -- Model only the SQL delete after lifecycle authorization has succeeded.
    -- The delete fixture has no existing 138 operation or cancellation ledger.
    DELETE FROM repositories WHERE id = other_repo;
    IF EXISTS (SELECT FROM ref_store_public_operations WHERE repository_id = other_repo)
       OR EXISTS (SELECT FROM ref_store_private_attempts WHERE repository_id = other_repo)
       OR (SELECT count(*) FROM ref_store_public_operations WHERE repository_id = repo) <> 3
       OR (SELECT count(*) FROM ref_store_private_attempts WHERE repository_id = repo) <> 4 THEN
        RAISE EXCEPTION 'repository delete did not cascade within its scope';
    END IF;
END $$;

ROLLBACK;
