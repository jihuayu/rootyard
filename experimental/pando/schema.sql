-- Separate namespace, never applied by Rootyard's production migration runner.
CREATE SCHEMA IF NOT EXISTS pando_lab;
CREATE TABLE IF NOT EXISTS pando_lab.repositories (
 id uuid PRIMARY KEY, generation bigint NOT NULL DEFAULT 0,
 storage_generation bigint NOT NULL DEFAULT 1 CHECK(storage_generation>0));
CREATE TABLE IF NOT EXISTS pando_lab.acl (
 repo uuid REFERENCES pando_lab.repositories, principal text NOT NULL,
 write_allowed boolean NOT NULL, PRIMARY KEY(repo,principal));
CREATE TABLE IF NOT EXISTS pando_lab.operations (
 id uuid PRIMARY KEY, repo uuid NOT NULL REFERENCES pando_lab.repositories,
 principal text NOT NULL, state text NOT NULL,
 commands jsonb NOT NULL DEFAULT '[]', result jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS pando_lab.manifests (
 repo uuid NOT NULL REFERENCES pando_lab.repositories, pack_id uuid NOT NULL,
 pack_sha256 text NOT NULL, idx_sha256 text NOT NULL,
 PRIMARY KEY(repo,pack_id));
CREATE TABLE IF NOT EXISTS pando_lab.objects (
 repo uuid NOT NULL, oid text NOT NULL CHECK(oid ~ '^[0-9a-f]{40}$'),
 pack_id uuid NOT NULL, PRIMARY KEY(repo,oid),
 FOREIGN KEY(repo,pack_id) REFERENCES pando_lab.manifests(repo,pack_id));
CREATE TABLE IF NOT EXISTS pando_lab.refs (
 repo uuid NOT NULL, name text NOT NULL, oid text NOT NULL,
 PRIMARY KEY(repo,name), FOREIGN KEY(repo,oid) REFERENCES pando_lab.objects(repo,oid));
CREATE TABLE IF NOT EXISTS pando_lab.changes (
 repo uuid NOT NULL REFERENCES pando_lab.repositories, generation bigint NOT NULL,
 operation_id uuid NOT NULL REFERENCES pando_lab.operations, commands jsonb NOT NULL,
 PRIMARY KEY(repo,generation), UNIQUE(operation_id));
CREATE TABLE IF NOT EXISTS pando_lab.snapshots (
 id uuid PRIMARY KEY, repo uuid NOT NULL REFERENCES pando_lab.repositories,
 principal text NOT NULL, generation bigint NOT NULL, storage_generation bigint NOT NULL,
 refs jsonb NOT NULL, packs jsonb NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '5 minutes');
CREATE OR REPLACE FUNCTION pando_lab.immutable_manifest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable object locator'; END $$;
CREATE OR REPLACE TRIGGER immutable_manifest BEFORE UPDATE OR DELETE ON pando_lab.manifests
 FOR EACH ROW EXECUTE FUNCTION pando_lab.immutable_manifest();
CREATE OR REPLACE TRIGGER immutable_object BEFORE UPDATE OR DELETE ON pando_lab.objects
 FOR EACH ROW EXECUTE FUNCTION pando_lab.immutable_manifest();
