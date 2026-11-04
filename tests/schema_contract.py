#!/usr/bin/env python3
"""Check exact schema007 catalogs, including an upgrade from restored schema003.

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    admin = os.environ.get('ROOTYARD_TEST_DATABASE_URL')
    if not admin:
        parser.error('ROOTYARD_TEST_DATABASE_URL must select a synthetic test administrator')
    parts = urllib.parse.urlsplit(admin)
    prefix = 'rootyard_contract_' + uuid.uuid4().hex
    created = []
    binary = str(Path(args.binary).resolve())
    sql = 'SET search_path=pg_catalog;' + Path('schema/007_catalog.sql').read_text()

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

    def catalog(db):
        return json.loads(run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', sql], db))

    def roundtrip(source, destination, archive):
        run(['pg_dump', '--format=custom', '--schema=public', '--no-owner', '--no-privileges', '--file', str(archive)], source)
        run(['pg_restore', '--dbname', '', '--single-transaction', '--exit-on-error', '--clean', '--if-exists', '--no-owner', '--no-privileges', str(archive)], destination)

    try:
        with tempfile.TemporaryDirectory(prefix='rootyard-contract-') as temporary:
            temporary = Path(temporary)
            fresh = database('fresh')
            run([binary, 'migrate'], fresh)
            actual = catalog(fresh)
            restored_db = database('restored')
            roundtrip(fresh, restored_db, temporary / 'schema007.dump')
            restored = catalog(restored_db)

            # A real schema003 restore normalizes its ref-name CHECK before the
            # later Forge migration creates two still-native CHECK expressions.
            legacy = database('legacy')
            for migration in ['001_initial.sql', '002_reliability.sql', '003_recovery_operations.sql']:
                run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-f', str(Path('migrations') / migration)], legacy)
            upgraded_db = database('upgraded')
            roundtrip(legacy, upgraded_db, temporary / 'schema003.dump')
            run([binary, 'migrate'], upgraded_db)
            upgraded = catalog(upgraded_db)
            # A restored schema006 upgraded to007 must match the full-restored
            # shape: migration007 introduces no BETWEEN normalization variance.
            legacy6 = database('legacy6')
            for migration in ['001_initial.sql', '002_reliability.sql', '003_recovery_operations.sql', '006_forge_issues.sql']:
                run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-f', str(Path('migrations') / migration)], legacy6)
            upgraded6 = database('upgrade6')
            roundtrip(legacy6, upgraded6, temporary / 'schema006.dump')
            run([binary, 'migrate'], upgraded6)
            assert catalog(upgraded6) == restored, 'Restored006 upgrade differs from full restore contract'

            upgraded_restored_db = database('upgrade_rt')
            roundtrip(upgraded_db, upgraded_restored_db, temporary / 'upgraded007.dump')
            assert catalog(upgraded_restored_db) == restored, 'Upgraded schema did not converge on the full restore contract'

        for filename, value in [('007_catalog.json', actual), ('007_restored_catalog.json', restored),
                                ('007_upgraded_catalog.json', upgraded)]:
            path = Path('schema') / filename
            if args.write:
                path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
            else:
                assert value == json.loads(path.read_text()), 'Canonical schema fixture differs: ' + filename
        print(json.dumps(dict(canonical_schema007=True, roundtrip_schema007=True,
                              restored003_upgrade007=True, restored006_upgrade007=True, upgraded007_roundtrip=True,
                              tables=len(actual['tables']), functions=len(actual['functions']), triggers=len(actual['triggers']))))
    finally:
        for name in reversed(created):
            run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', 'DROP DATABASE ' + name + ' WITH (FORCE)'])


if __name__ == '__main__':
    main()
