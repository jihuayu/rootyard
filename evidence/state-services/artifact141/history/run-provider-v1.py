"""Root-only real-provider test runner; inherited credentials never printed."""
import argparse,hashlib,importlib.util,json,os,re,subprocess,time,uuid
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--folder',type=Path,required=True);p.add_argument('--library-provider',action='store_true');a=p.parse_args()
a.folder.mkdir(mode=0o700,parents=True,exist_ok=False)
e=os.environ.copy()
for dst,src in {'ENDPOINT':'ENDPOINT','BUCKET':'BUCKET','REGION':'REGION','ACCESS_KEY_ID':'ACCESS_KEY','SECRET_ACCESS_KEY':'SECRET_KEY'}.items():e['ROOTYARD_BLOB_'+dst]=e['ROOTYARD_OBJECT_STORE_'+src]
e.update(ROOTYARD_BLOB_DRIVER='opendal',ROOTYARD_BLOB_SERVICE='s3',ROOTYARD_BLOB_ROOT='hold-qualification-'+uuid.uuid4().hex)
if 'ROOTYARD_OBJECT_STORE_SESSION_TOKEN' in e:e['ROOTYARD_BLOB_SESSION_TOKEN']=e['ROOTYARD_OBJECT_STORE_SESSION_TOKEN']
command=[str(a.binary),'--ignored','--test-threads=1']
if a.library_provider:command+=['--exact','blob_store::provider_contract_tests::real_provider_publish_verify_range_delete_contract']
root=Path('/workspace/scratch/state-services-artifact-holds')
spec=importlib.util.spec_from_file_location('binding',root/'scripts/build_native.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
receipt=json.loads(a.binary.with_suffix('.build.json').read_text())
sha=lambda f:hashlib.file_digest(f.open('rb'),'sha256').hexdigest()
def state():
 v=dict(source=m.source_digest(),binary=sha(a.binary),head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip())
 if not a.library_provider:v['test']=sha(root/'tests/ref_store_holds_provider.rs')
 return v
before=state();assert before['source']==receipt['source_inputs_sha256'] and before['binary']==receipt['binary_sha256']
if not a.library_provider:assert before['test']==receipt['integration_test_source_sha256']
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
start=time.monotonic();r=subprocess.run(command,env=e,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
s=r.stdout.decode(errors='replace')
for k,v in e.items():
 if v and len(v)>=6 and ('DATABASE_URL' in k or any(t in k for t in ('TOKEN','SECRET','PASSWORD','ACCESS_KEY'))):s=s.replace(v,'[redacted]')
(a.folder/'native.log').write_text(s)
summary=re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',s)
after=state()
passed=bool(before==after and r.returncode==0 and summary and summary[1]=='ok' and summary[2]=='1' and summary[3]=='0' and summary[4]=='0')
report=dict(passed=passed,returncode=r.returncode,seconds=round(time.monotonic()-start,3),summary=summary[0] if summary else None,command=command,before=before,after=after,source_binary_harness_head_unchanged=before==after,binary_sha256=hashlib.file_digest(a.binary.open('rb'),'sha256').hexdigest(),build_receipt=json.loads(a.binary.with_suffix('.build.json').read_text()),limits=['One loopback PostgreSQL17/Garage S3 fixture; no Azure, encryption, retirement, GC, serving or physical backup closure qualification.'])
(a.folder/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['passed','summary','seconds']}));raise SystemExit(0 if passed else 1)
