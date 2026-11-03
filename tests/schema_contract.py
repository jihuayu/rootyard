#!/usr/bin/env python3
"""Check schema003 using pristine migrations and a real dump/restore round trip.

Only run on disposable PostgreSQL: the administrator must have CREATEDB.
--write updates fixtures for review; it does not establish their correctness.
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
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',default='target/debug/rootyard')
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    admin=os.environ.get('ROOTYARD_TEST_DATABASE_URL')
    if not admin:parser.error('ROOTYARD_TEST_DATABASE_URL must select a synthetic test administrator')
    name='rootyard_contract_'+uuid.uuid4().hex
    parts=urllib.parse.urlsplit(admin)
    def run(command,db=admin):
        env=os.environ.copy();u=urllib.parse.urlsplit(db)
        env.update(PGHOST=u.hostname,PGPORT=str(u.port or 5432),PGDATABASE=u.path.lstrip('/'),PGUSER=u.username,PGPASSWORD=u.password or '',DATABASE_URL=db)
        p=subprocess.run(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        if p.returncode:raise RuntimeError('Synthetic schema contract command failed; private diagnostics suppressed')
        return p.stdout.decode()
    run(['psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE '+name+' TEMPLATE template0'])
    db=urllib.parse.urlunsplit(parts._replace(path='/'+name,query=''))
    restored_name=name+'_restore'
    restored_db=urllib.parse.urlunsplit(parts._replace(path='/'+restored_name,query=''))
    restored_created=False
    try:
        run([str(Path(args.binary).resolve()),'migrate'],db)
        sql='SET search_path=pg_catalog;'+Path('schema/003_catalog.sql').read_text()
        actual=json.loads(run(['psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c',sql],db))
        run(['psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE '+restored_name+' TEMPLATE template0'])
        restored_created=True
        with tempfile.TemporaryDirectory(prefix='rootyard-contract-') as temporary:
            archive=Path(temporary)/'schema.dump'
            run(['pg_dump','--format=custom','--schema=public','--no-owner','--no-privileges','--file',str(archive)],db)
            run(['pg_restore','--dbname','','--single-transaction','--exit-on-error','--clean','--if-exists','--no-owner','--no-privileges',str(archive)],restored_db)
            restored=json.loads(run(['psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c',sql],restored_db))
        for filename,value in [('003_catalog.json',actual),('003_restored_catalog.json',restored)]:
            path=Path('schema')/filename
            if args.write:path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
            else:assert value==json.loads(path.read_text()),'Canonical schema fixture differs: '+filename
        print(json.dumps({'canonical_schema003':True,'roundtrip_schema003':True,'tables':len(actual['tables']),'functions':len(actual['functions']),'triggers':len(actual['triggers'])}))
    finally:
        if restored_created:run(['psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c','DROP DATABASE '+restored_name+' WITH (FORCE)'])
        run(['psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c','DROP DATABASE '+name+' WITH (FORCE)'])

if __name__=='__main__':main()
