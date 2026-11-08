"""Root-only source-bound schema/backup qualification; no private data output."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

p=argparse.ArgumentParser()
p.add_argument('--kind',choices=['schema','backup15','legacy14'],required=True)
p.add_argument('--folder',type=Path,required=True)
a=p.parse_args()
root=Path('/workspace/scratch/state-services-pg-core')
binary=Path('/workspace/scratch/state-pg139-app-v1/rootyard')
legacy=Path('/workspace/scratch/state-refstore138-app-v6/rootyard')
receipt=json.loads(binary.with_suffix('.build.json').read_text())
spec=importlib.util.spec_from_file_location('binding',root/'scripts/build_native.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
sha=lambda path:hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
head=lambda:subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
scripts={'schema':'schema_contract.py','backup15':'backup_refstore_core139.py','legacy14':'backup_legacy138_core.py'}
script=root/'tests'/scripts[a.kind]
harness_files=[script,root/'tests/e2e.py',root/'tests/schema_baseline.py']
if a.kind!='schema':harness_files.append(root/'tests/backup.py')
if a.kind=='legacy14':harness_files.append(root/'tests/backup_legacy132_sessions.py')
before={'source':m.source_digest(),'binary':sha(binary),'head':head(),
        'harness':{str(f.relative_to(root)):sha(f) for f in harness_files}}
assert before['source']==receipt['source_inputs_sha256'] and before['binary']==receipt['binary_sha256']
if a.kind=='legacy14':before['legacy_binary']=sha(legacy)
a.folder.mkdir(mode=0o700,parents=True,exist_ok=False)
command=['python3',str(script),'--binary',str(binary)]
if a.kind!='schema':command+=['--report',str(a.folder/'native.json')]
if a.kind=='legacy14':command+=['--legacy-binary',str(legacy)]
start=time.monotonic()
r=subprocess.run(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
output=r.stdout.decode(errors='replace')
for key,value in os.environ.items():
    if value and len(value)>=6 and ('DATABASE_URL' in key or any(t in key for t in ('TOKEN','SECRET','PASSWORD','ACCESS_KEY'))):
        output=output.replace(value,'[redacted]')
(a.folder/'native.log').write_text(output)
after={'source':m.source_digest(),'binary':sha(binary),'head':head(),
       'harness':{str(f.relative_to(root)):sha(f) for f in harness_files}}
if a.kind=='legacy14':after['legacy_binary']=sha(legacy)
native=None
if a.kind=='schema':
    try:native=json.loads(output)
    except json.JSONDecodeError:pass
elif (a.folder/'native.json').exists():native=json.loads((a.folder/'native.json').read_text())
if a.kind=='schema':
    valid=bool(native and str(native.get('schema_version'))=='139' and native.get('migration_mode')=='binary'
               and native.get('canonical') is True and native.get('tables')==93 and native.get('functions')==16
               and native.get('triggers')==36 and all(native.get(k) is True for k in ['roundtrip','restored003_upgrade',
               'restored006_upgrade','restored007_upgrade','upgraded_roundtrip','custom_search_path_bootstrap','custom_migrate_idempotent']))
else:
    cases=native.get('cases',[]) if native else []
    valid=bool(native and native.get('passed') is True and len(cases)==7 and all(v['status']=='passed' for v in cases))
passed=bool(r.returncode==0 and valid and before==after)
report={'passed':passed,'kind':a.kind,'returncode':r.returncode,'command':command,
        'seconds':round(time.monotonic()-start,3),'before':before,'after':after,
        'source_binary_harness_head_unchanged':before==after,'build_receipt':receipt,'native':native,
        'limits':['Real loopback synthetic fixtures on one physical host; no power-loss, HA or production RPO/RTO qualification.',
                  'Backup15 rows are direct SQL metadata fixtures, not adapter ACK evidence; twelve PostgreSQL core cases separately test adapter semantics.']}
(a.folder/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ['passed','kind','returncode','seconds']}))
raise SystemExit(0 if passed else 1)
