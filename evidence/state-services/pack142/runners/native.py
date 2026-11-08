"""Root-only source-bound schema142/current18/genuine legacy17 native qualification."""
import argparse,hashlib,importlib.util,json,os,subprocess,time,uuid
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--kind',choices=['schema','backup18','legacy17'],required=True);p.add_argument('--folder',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--fixture-binary',type=Path);p.add_argument('--trace',action='store_true');a=p.parse_args()
root=Path('/workspace/scratch/state-services-pack-commit');binary=a.binary.resolve();legacy=Path('/workspace/scratch/state-artifact141-app-v1/rootyard')
sha=lambda p:hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
receipt=json.loads(binary.with_suffix('.build.json').read_text());helper=None
spec=importlib.util.spec_from_file_location('binding',root/'scripts/build_native.py');binding=importlib.util.module_from_spec(spec);spec.loader.exec_module(binding)
script=root/'tests'/dict(schema='schema_contract.py',backup18='backup_refstore_packs142.py',legacy17='backup_legacy141_packs.py')[a.kind]
files=[script,root/'tests/e2e.py',root/'tests/schema_baseline.py']
if a.kind!='schema':files.append(root/'tests/backup.py')
if a.kind=='backup18':
    files += [root/'tests/backup_refstore_core139.py',root/'tests/ref_store_packs_backup_fixture.rs']
    assert a.fixture_binary
    helper=json.loads(a.fixture_binary.with_suffix('.build.json').read_text())
    assert helper['kind']=='rust-integration-test' and helper['package_rebuilt'] is True
    assert sha(a.fixture_binary)==helper['binary_sha256'] and helper['source_inputs_sha256']==receipt['source_inputs_sha256']
    assert helper['integration_test_source_sha256']==sha(root/'tests/ref_store_packs_backup_fixture.rs')
if a.kind=='legacy17':
    files.append(root/'tests/backup_legacy132_sessions.py')
    assert sha(legacy)=='c3003c7cfbd96702eb4b53efed491ed4d86a35066c73d9ed53d05429ee065668'
def state():
    s=dict(source=binding.source_digest(),binary=sha(binary),head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),harness={str(f.relative_to(root)):sha(f) for f in files})
    if a.kind=='backup18':s['fixture_binary']=sha(a.fixture_binary)
    if a.kind=='legacy17':s['legacy_binary']=sha(legacy)
    if a.trace:s['diagnostic_launcher']=sha(Path('/workspace/scratch/trace-state142-backup.py'))
    return s
before=state();assert before['source']==receipt['source_inputs_sha256'] and before['binary']==receipt['binary_sha256']
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
a.folder.mkdir(mode=0o700,parents=True,exist_ok=False)
command=['python3',str(script),'--binary',str(binary)]
if a.trace:command.insert(1,'/workspace/scratch/trace-state142-backup.py')
if a.kind!='schema':command+=['--report',str(a.folder/'native.json')]
if a.kind=='legacy17':command+=['--legacy-binary',str(legacy)]
if a.kind=='backup18':command+=['--pack-fixture-binary',str(a.fixture_binary)]
env=os.environ.copy()
if a.kind=='backup18':
    for dst,src in {'ENDPOINT':'ENDPOINT','BUCKET':'BUCKET','REGION':'REGION','ACCESS_KEY_ID':'ACCESS_KEY','SECRET_ACCESS_KEY':'SECRET_KEY'}.items():env['ROOTYARD_BLOB_'+dst]=env['ROOTYARD_OBJECT_STORE_'+src]
    if 'ROOTYARD_OBJECT_STORE_SESSION_TOKEN' in env:env['ROOTYARD_BLOB_SESSION_TOKEN']=env['ROOTYARD_OBJECT_STORE_SESSION_TOKEN']
    env.update(ROOTYARD_BLOB_DRIVER='opendal',ROOTYARD_BLOB_SERVICE='s3',ROOTYARD_BLOB_ROOT='packbackup/'+uuid.uuid4().hex,ROOTYARD_TEST_GIT='/usr/bin/git')
started=time.monotonic();result=subprocess.run(command,cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=1200)
output=result.stdout.decode(errors='replace')
for key,value in env.items():
    if value and len(value)>=6 and ('DATABASE_URL' in key or any(t in key for t in ('TOKEN','SECRET','PASSWORD','ACCESS_KEY'))):output=output.replace(value,'[redacted]')
(a.folder/'native.log').write_text(output);after=state();native=None
if a.kind=='schema':
    try:native=json.loads(output)
    except json.JSONDecodeError:pass
elif (a.folder/'native.json').exists():native=json.loads((a.folder/'native.json').read_text())
if a.kind=='schema':valid=bool(native and str(native.get('schema_version'))=='142' and native.get('migration_mode')=='binary' and native.get('canonical') is True and native.get('tables')==111 and native.get('functions')==36 and native.get('triggers')==84 and all(native.get(k) is True for k in ['roundtrip','restored003_upgrade','restored006_upgrade','restored007_upgrade','upgraded_roundtrip','custom_search_path_bootstrap','custom_migrate_idempotent']))
else:
    cases=native.get('cases',[]) if native else [];valid=bool(native and native.get('passed') is True and len(cases)==7 and all(c['status']=='passed' for c in cases))
passed=bool(result.returncode==0 and valid and before==after)
report=dict(passed=passed,kind=a.kind,returncode=result.returncode,command=command,seconds=round(time.monotonic()-started,3),before=before,after=after,inputs_unchanged=before==after,runner_sha256=sha(Path(__file__)),build_receipt=receipt,helper_build_receipt=helper,native=native,limits=['One loopback PostgreSQL/Garage fixture; no HA/powerloss/production RPO/RTO/serving/GC qualification.','Current18 pack ledger seeded by real protectedS3/nativeGit/typed verified commit; external original Blob bytes remain outside the metadata archive.','Genuine17 is produced by retained schema141 app C300; upgraded142 pack tables must be empty, no fabricated registration.'])
(a.folder/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({key:report[key] for key in ['passed','kind','returncode','seconds']}));raise SystemExit(0 if passed else 1)
