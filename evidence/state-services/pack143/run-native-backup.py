"""Root-only source-bound schema143/current19/genuine legacy18 native qualification."""
import argparse,hashlib,importlib.util,json,os,subprocess,time,uuid
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--kind',choices=['schema','backup19','legacy18','core139'],required=True);p.add_argument('--folder',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--fixture-binary',type=Path);p.add_argument('--trace',action='store_true');a=p.parse_args()
root=Path('/workspace/scratch/state-services-pack-snapshot');binary=a.binary.resolve();legacy=Path('/workspace/scratch/state-pack142-app-v1/rootyard')
sha=lambda p:hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
receipt=json.loads(binary.with_suffix('.build.json').read_text());helper=None
spec=importlib.util.spec_from_file_location('binding',root/'scripts/build_native.py');binding=importlib.util.module_from_spec(spec);spec.loader.exec_module(binding)
script=root/'tests'/dict(schema='schema_contract.py',backup19='backup_refstore_pack_snapshots143.py',legacy18='backup_legacy142_pack_snapshots.py',core139='backup_refstore_core139.py')[a.kind]
files=[script,root/'tests/e2e.py',root/'tests/schema_baseline.py']
if a.kind!='schema':files.append(root/'tests/backup.py')
if a.kind=='backup19':
    files += [root/'tests/backup_refstore_core139.py',root/'tests/ref_store_pack_snapshots_backup_fixture.rs']
    assert a.fixture_binary
    helper=json.loads(a.fixture_binary.with_suffix('.build.json').read_text())
    assert helper['kind']=='rust-integration-test' and helper['package_rebuilt'] is True
    assert sha(a.fixture_binary)==helper['binary_sha256'] and helper['source_inputs_sha256']==receipt['source_inputs_sha256']
    assert helper['integration_test_source_sha256']==sha(root/'tests/ref_store_pack_snapshots_backup_fixture.rs')
if a.kind=='legacy18':
    files += [root/'tests/backup_legacy142_pack_snapshots.py', root/'tests/backup_refstore_pack_snapshots143.py']
    files.append(root/'tests/backup_legacy132_sessions.py')
    assert sha(legacy)=='0be216508eec5348294bd6d1f2c28feb8513112fba6b407a52fdb4c9a2b329d1'
def state():
    s=dict(source=binding.source_digest(),binary=sha(binary),head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),harness={str(f.relative_to(root)):sha(f) for f in files})
    if a.kind=='backup19':s['fixture_binary']=sha(a.fixture_binary)
    if a.kind=='legacy18':
        s['legacy_binary']=sha(legacy)
        s['legacy_fixture_binary']=sha(Path('/workspace/scratch/state-pack142-backup-helper-build-v2/ref_store_packs_backup_fixture'))
        s['legacy_fixture_receipt']=sha(Path('/workspace/scratch/state-pack142-backup-helper-build-v2/ref_store_packs_backup_fixture.build.json'))
    if a.trace:s['diagnostic_launcher']=sha(Path('/workspace/scratch/trace-state142-backup.py'))
    return s
before=state();assert before['source']==receipt['source_inputs_sha256'] and before['binary']==receipt['binary_sha256']
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
a.folder.mkdir(mode=0o700,parents=True,exist_ok=False)
command=['python3',str(script),'--binary',str(binary)]
if a.trace:command.insert(1,'/workspace/scratch/trace-state142-backup.py')
if a.kind!='schema':command+=['--report',str(a.folder/'native.json')]
if a.kind=='legacy18':command+=['--legacy-binary',str(legacy),'--legacy-fixture-binary','/workspace/scratch/state-pack142-backup-helper-build-v2/ref_store_packs_backup_fixture','--legacy-fixture-receipt','/workspace/scratch/state-pack142-backup-helper-build-v2/ref_store_packs_backup_fixture.build.json']
if a.kind=='backup19':command+=['--pack-snapshot-fixture-binary',str(a.fixture_binary)]
env=os.environ.copy()
if a.kind in ('backup19','legacy18'):
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
if a.kind=='schema':valid=bool(native and str(native.get('schema_version'))=='143' and native.get('migration_mode')=='binary' and native.get('canonical') is True and native.get('tables')==115 and native.get('functions')==39 and native.get('triggers')==95 and all(native.get(k) is True for k in ['roundtrip','restored003_upgrade','restored006_upgrade','restored007_upgrade','upgraded_roundtrip','custom_search_path_bootstrap','custom_migrate_idempotent']))
else:
    cases=native.get('cases',[]) if native else [];valid=bool(native and native.get('passed') is True and len(cases)==7 and all(c['status']=='passed' for c in cases))
passed=bool(result.returncode==0 and valid and before==after)
report=dict(passed=passed,kind=a.kind,returncode=result.returncode,command=command,seconds=round(time.monotonic()-started,3),before=before,after=after,inputs_unchanged=before==after,runner_sha256=sha(Path(__file__)),build_receipt=receipt,helper_build_receipt=helper,native=native,limits=['Loopback PostgreSQL/Garage/nativeGit metadata backup only; external original Blob bytes are not archived.','A5a complete registered-membership metadata/pins; no materialized Git ReadSnapshot or serving qualification.','Genuine format18 uses retained schema142 producer and old typed A4 helper seed-only, never seeds against143.'])
(a.folder/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({key:report[key] for key in ['passed','kind','returncode','seconds']}));raise SystemExit(0 if passed else 1)
