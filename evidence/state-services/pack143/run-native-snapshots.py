"""Root-only source-bound real PG/S3/Git pack qualification; inherited credentials stay private."""
import argparse,hashlib,importlib.util,json,os,re,subprocess,time,uuid
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--folder',type=Path,required=True);p.add_argument('--diagnostic-dirty',action='store_true');a=p.parse_args()
root=Path('/workspace/scratch/state-services-pack-snapshot')
a.folder.mkdir(mode=0o700,parents=True,exist_ok=False)
env=os.environ.copy()
for dst,src in {'ENDPOINT':'ENDPOINT','BUCKET':'BUCKET','REGION':'REGION','ACCESS_KEY_ID':'ACCESS_KEY','SECRET_ACCESS_KEY':'SECRET_KEY'}.items():
    env['ROOTYARD_BLOB_'+dst]=env['ROOTYARD_OBJECT_STORE_'+src]
if 'ROOTYARD_OBJECT_STORE_SESSION_TOKEN' in env:env['ROOTYARD_BLOB_SESSION_TOKEN']=env['ROOTYARD_OBJECT_STORE_SESSION_TOKEN']
env.update(ROOTYARD_BLOB_DRIVER='opendal',ROOTYARD_BLOB_SERVICE='s3',ROOTYARD_BLOB_ROOT='snapqual/'+uuid.uuid4().hex,ROOTYARD_TEST_GIT='/usr/bin/git')
spec=importlib.util.spec_from_file_location('binding',root/'scripts/build_native.py');binding=importlib.util.module_from_spec(spec);spec.loader.exec_module(binding)
sha=lambda f:hashlib.file_digest(f.open('rb'),'sha256').hexdigest()
receipt=json.loads(a.binary.with_suffix('.build.json').read_text())
def state():
    return dict(source=binding.source_digest(),test=sha(root/'tests/ref_store_pack_snapshots.rs'),binary=sha(a.binary),head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),clean=not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip())
before=state()
assert (before['clean'] or a.diagnostic_dirty) and before['source']==receipt['source_inputs_sha256'] and before['test']==receipt['integration_test_source_sha256'] and before['binary']==receipt['binary_sha256']
command=[str(a.binary),'--ignored','--test-threads=1']
started=time.monotonic();result=subprocess.run(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
output=result.stdout.decode(errors='replace')
for key,value in env.items():
    if value and len(value)>=6 and ('DATABASE_URL' in key or any(part in key for part in ('TOKEN','SECRET','PASSWORD','ACCESS_KEY'))):output=output.replace(value,'[redacted]')
(a.folder/'native.log').write_text(output)
summary=re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',output)
after=state();passed=bool(before==after and result.returncode==0 and summary and summary[1]=='ok' and summary[2]=='10' and summary[3]=='0' and summary[4]=='0')
report=dict(passed=passed,returncode=result.returncode,seconds=round(time.monotonic()-started,3),summary=summary[0] if summary else None,command=command,before=before,after=after,inputs_unchanged=before==after,runner_sha256=sha(Path(__file__)),build_receipt=receipt,limits=['Loopback PG17, Garage S3, actual native Git; A5a registered-membership metadata/pins only; no materialized Git ReadSnapshot, serving, restart, HA, encryption, GC, roots or physical Blob backup qualification.'])
report['qualification_kind']='clean-candidate' if before['clean'] else 'dirty-diagnostic-only'
(a.folder/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({key:report[key] for key in ('passed','summary','seconds')}))
raise SystemExit(0 if passed else 1)
