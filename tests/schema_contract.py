#!/usr/bin/env python3
"""Check current schema catalogs, including upgrades from restored legacy schemas.

Only use disposable PostgreSQL with CREATEDB. --write generates fixtures for
review; it does not establish their correctness or accept production drift.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.parse
import uuid

from schema_baseline import CATALOG_SQL_PATH, LATEST_PREFIX, SCHEMA_VERSIONS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--sql-migrate', action='store_true', help='Generate fixtures with reviewed migrations before building the binary')
    args = parser.parse_args()
    admin = os.environ.get('ROOTYARD_TEST_DATABASE_URL')
    if not admin:
        parser.error('ROOTYARD_TEST_DATABASE_URL must select a synthetic test administrator')
    parts = urllib.parse.urlsplit(admin)
    prefix = 'rootyard_contract_' + uuid.uuid4().hex
    created = []
    binary = str(Path(args.binary).resolve())
    sql = 'SET search_path=pg_catalog;' + CATALOG_SQL_PATH.read_text()

    def run(command, db=admin):
        env = os.environ.copy()
        url = urllib.parse.urlsplit(db)
        env.update(PGHOST=url.hostname, PGPORT=str(url.port or 5432),
                   PGDATABASE=url.path.lstrip('/'), PGUSER=urllib.parse.unquote(url.username),
                   PGPASSWORD=urllib.parse.unquote(url.password or ''), DATABASE_URL=db)
        proc = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if proc.returncode:
            raise RuntimeError('Synthetic schema contract command failed; private diagnostics suppressed')
        return proc.stdout.decode()

    def database(label):
        name = prefix + '_' + label
        assert len(name) <= 63, 'Synthetic database name exceeds PostgreSQL identifier bound'
        run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', 'CREATE DATABASE ' + name + ' TEMPLATE template0'])
        created.append(name)
        return urllib.parse.urlunsplit(parts._replace(path='/' + name, query=''))

    def migrate(db):
        if args.sql_migrate:
            versions = run(['psql', '-X', '-qAt', '-c', "SELECT version FROM schema_migrations"], db) if run(['psql', '-X', '-qAt', '-c', "SELECT to_regclass('public.schema_migrations') IS NOT NULL"], db).strip() == 't' else ''
            for path in sorted(Path('migrations').glob('*.sql')):
                if str(int(path.name[:3])) not in versions.split():
                    run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-f', str(path)], db)
        else:
            run([binary, 'migrate'], db)

    def catalog(db):
        return json.loads(run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', sql], db))

    def roundtrip(source, destination, archive):
        run(['pg_dump', '--format=custom', '--schema=public', '--no-owner', '--no-privileges', '--file', str(archive)], source)
        run(['pg_restore', '--dbname', '', '--single-transaction', '--exit-on-error', '--clean', '--if-exists', '--no-owner', '--no-privileges', str(archive)], destination)

    try:
        with tempfile.TemporaryDirectory(prefix='rootyard-contract-') as temporary:
            temporary = Path(temporary)
            fresh = database('fresh')
            migrate(fresh)
            actual = catalog(fresh)
            restored_db = database('restored')
            roundtrip(fresh, restored_db, temporary / 'schema008.dump')
            restored = catalog(restored_db)

            # A real schema003 restore normalizes its ref-name CHECK before the
            # later Forge migration creates two still-native CHECK expressions.
            legacy = database('legacy')
            for migration in ['001_initial.sql', '002_reliability.sql', '003_recovery_operations.sql']:
                run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-f', str(Path('migrations') / migration)], legacy)
            upgraded_db = database('upgraded')
            roundtrip(legacy, upgraded_db, temporary / 'schema003.dump')
            migrate(upgraded_db)
            upgraded = catalog(upgraded_db)
            # A restored schema006 upgraded to008 must match the full-restored
            # shape: migration008 introduces no BETWEEN normalization variance.
            legacy6 = database('legacy6')
            for migration in ['001_initial.sql', '002_reliability.sql', '003_recovery_operations.sql', '006_forge_issues.sql']:
                run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-f', str(Path('migrations') / migration)], legacy6)
            upgraded6 = database('upgrade6')
            roundtrip(legacy6, upgraded6, temporary / 'schema006.dump')
            migrate(upgraded6)
            assert catalog(upgraded6) == restored, 'Restored006 upgrade differs from full restore contract'

            legacy7 = database('legacy7')
            for path in sorted(Path('migrations').glob('*.sql')):
                if int(path.name[:3]) < 8:
                    run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-f', str(path)], legacy7)
            upgraded7 = database('upgrade7')
            roundtrip(legacy7, upgraded7, temporary / 'schema007.dump')
            migrate(upgraded7)
            assert catalog(upgraded7) == restored, 'Restored007 upgrade differs from full restore contract'

            upgraded_restored_db = database('upgrade_rt')
            roundtrip(upgraded_db, upgraded_restored_db, temporary / 'upgraded008.dump')
            assert catalog(upgraded_restored_db) == restored, 'Upgraded schema did not converge on the full restore contract'

            # A database may already have an initialized public schema and a
            # fresh custom search_path schema. Migrate must use the effective
            # schema for its ledger check, bootstrap the custom schema, and
            # never mutate the initialized public schema.
            custom = database('custom')
            migrate(custom)
            public_tables = run(['psql', '--dbname', custom, '-X', '-qAt', '-c',
                                 "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                                 "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S')"], custom).strip()
            run(['psql', '--dbname', custom, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                 '-c', 'CREATE SCHEMA tenant'], custom)
            tenant_url = urllib.parse.urlunsplit(
                urllib.parse.urlsplit(custom)._replace(
                    query=urllib.parse.urlencode({'options': '-csearch_path=tenant'})))
            run([binary, 'migrate'], tenant_url)
            tenant_versions = run(['psql', '--dbname', custom, '-X', '-qAt', '-c',
                                   "SELECT string_agg(version::text,',' ORDER BY version) FROM tenant.schema_migrations"], custom).strip()
            assert tenant_versions == ",".join(str(v) for v in sorted(SCHEMA_VERSIONS)), tenant_versions
            public_after = run(['psql', '--dbname', custom, '-X', '-qAt', '-c',
                                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                                "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S')"], custom).strip()
            assert public_after == public_tables, (public_tables, public_after)
            run([binary, 'migrate'], tenant_url)
            assert run(['psql', '--dbname', custom, '-X', '-qAt', '-c',
                        "SELECT count(*) FROM tenant.schema_migrations"], custom).strip() == str(len(SCHEMA_VERSIONS))
            assert run(['psql', '--dbname', custom, '-X', '-qAt', '-c',
                        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S')"], custom).strip() == public_tables

        for filename, value in [(f'{LATEST_PREFIX}_catalog.json', actual),
                                (f'{LATEST_PREFIX}_restored_catalog.json', restored),
                                (f'{LATEST_PREFIX}_upgraded_catalog.json', upgraded)]:
            path = Path('schema') / filename
            if args.write:
                path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
            else:
                expected = json.loads(path.read_text())
                if value != expected:
                    for k in sorted(set(value) | set(expected)):
                        if value.get(k) != expected.get(k):
                            v_list, e_list = value.get(k), expected.get(k)
                            if isinstance(v_list, list) and isinstance(e_list, list):
                                print(f'DIFF in {filename} [{k}]: actual_len={len(v_list)} expected_len={len(e_list)}')
                                for item in v_list:
                                    if item not in e_list:
                                        print(f'  ACTUAL ONLY [{k}]: {json.dumps(item, sort_keys=True)}')
                                for item in e_list:
                                    if item not in v_list:
                                        print(f'  EXPECTED ONLY [{k}]: {json.dumps(item, sort_keys=True)}')
                            else:
                                print(f'DIFF in {filename} [{k}]: actual={v_list} expected={e_list}')
                assert value == expected, 'Canonical schema fixture differs: ' + filename
        print(json.dumps(dict(schema_version=LATEST_PREFIX, canonical=True, roundtrip=True,
                              restored003_upgrade=True, restored006_upgrade=True, restored007_upgrade=True, upgraded_roundtrip=True,
                              custom_search_path_bootstrap=True, custom_migrate_idempotent=True,
                              tables=len(actual['tables']), functions=len(actual['functions']), triggers=len(actual['triggers']))))
    finally:
        for name in reversed(created):
            run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', 'DROP DATABASE ' + name + ' WITH (FORCE)'])


if __name__ == '__main__':
    main()
