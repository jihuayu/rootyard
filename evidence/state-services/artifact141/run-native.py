"""Root-only source-bound schema141/current17/legacy16 qualification."""
import argparse, hashlib, importlib.util, json, os
from pathlib import Path
import subprocess, time
p=argparse.ArgumentParser()
p.add_argument('--kind',choices=['schema','backup17','legacy16'],required=True)
p.add_argument('--folder',type=Path,required=True)
p.add_argument('--binary',type=Path,required=True)
p.add_argument('--fixture-binary',type=Path)
a=p.parse_args()
root=Path('/workspace/scratch/state-services-artifact-holds')
binary=a.binary.resolve();legacy=Path('/workspace/scratch/state-pg140-app-v1/rootyard')
sha=lambda p:hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
receipt=json.loads(binary.with_suffix('.build.json').read_text())
spec=importlib.util.spec_from_file_location('binding',root/'scripts/build_native.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
head=lambda:subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
scripts={'schema':'schema_contract.py','backup17':'backup_refstore_holds141.py','legacy16':'backup_legacy140_holds.py'}
script=root/'tests'/scripts[a.kind]
files=[script,root/'tests/e2e.py',root/'tests/schema_baseline.py']
if a.kind!='schema':files.append(root/'tests/backup.py')
if a.kind=='backup17':files += [root/'tests/backup_refstore_core139.py',root/'tests/ref_store_holds_backup_fixture.rs']
if a.kind=='legacy16':files.append(root/'tests/backup_legacy132_sessions.py')
helper_receipt=None
if a.kind=='backup17':
 assert a.fixture_binary
 helper_receipt=json.loads(a.fixture_binary.with_suffix('.build.json').read_text())
 assert helper_receipt['kind']=='rust-integration-test' and helper_receipt['package_rebuilt'] is True
 assert sha(a.fixture_binary)==helper_receipt['binary_sha256']
 assert helper_receipt['source_inputs_sha256']==receipt['source_inputs_sha256']
 assert helper_receipt['integration_test_source_sha256']==sha(root/'tests/ref_store_holds_backup_fixture.rs')
def state():
 r={'source':m.source_digest(),'binary':sha(binary),'head':head(),'harness':{str(f.relative_to(root)):sha(f) for f in files}}
 if a.kind=='backup17':r['fixture_binary']=sha(a.fixture_binary)
 if a.kind=='legacy16':r['legacy_binary']=sha(legacy)
 return r
before=state()
assert before['source']==receipt['source_inputs_sha256'] and before['binary']==receipt['binary_sha256']
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
a.folder.mkdir(mode=0o700,parents=True,exist_ok=False)
command=['python3',str(script),'--binary',str(binary)]
if a.kind!='schema':command+=['--report',str(a.folder/'native.json')]
if a.kind=='legacy16':command+=['--legacy-binary',str(legacy)]
if a.kind=='backup17':command+=['--holds-fixture-binary',str(a.fixture_binary)]
start=time.monotonic();r=subprocess.run(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
output=r.stdout.decode(errors='replace')
for k,v in os.environ.items():
 if v and len(v)>=6 and ('DATABASE_URL' in k or any(t in k for t in ('TOKEN','SECRET','PASSWORD','ACCESS_KEY'))):output=output.replace(v,'[redacted]')
(a.folder/'native.log').write_text(output);after=state();native=None
if a.kind=='schema':
 try:native=json.loads(output)
 except json.JSONDecodeError:pass
elif (a.folder/'native.json').exists():native=json.loads((a.folder/'native.json').read_text())
if a.kind=='schema':
 valid=bool(native and str(native.get('schema_version'))=='141' and native.get('migration_mode')=='binary' and native.get('canonical') is True and native.get('tables')==105 and native.get('functions')==33 and native.get('triggers')==69 and all(native.get(k) is True for k in ['roundtrip','restored003_upgrade','restored006_upgrade','restored007_upgrade','upgraded_roundtrip','custom_search_path_bootstrap','custom_migrate_idempotent']))
else:
 cases=native.get('cases',[]) if native else []
 valid=bool(native and native.get('passed') is True and len(cases)==7 and all(c['status']=='passed' for c in cases))
passed=bool(r.returncode==0 and valid and before==after)
report=dict(passed=passed,kind=a.kind,returncode=r.returncode,command=command,seconds=round(time.monotonic()-start,3),before=before,after=after,source_binary_harness_head_unchanged=before==after,build_receipt=receipt,helper_build_receipt=helper_receipt,native=native,limits=['Real synthetic fixtures on one loopback host; no HA, power loss, production RPO/RTO, serving or physical GC qualification.','A1 core refs and parent operation are explicit SQL metadata fixtures; A3 holds/ACK/consume receipts/usage seeded through actual typed adapter APIs. No Blob bytes are included in this hold-metadata drill.'])
(a.folder/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ['passed','kind','returncode','seconds']}));raise SystemExit(0 if passed else 1)
