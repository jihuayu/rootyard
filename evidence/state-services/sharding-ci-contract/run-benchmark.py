import hashlib,importlib.util,json,os,subprocess,time
from pathlib import Path
import argparse
p=argparse.ArgumentParser();p.add_argument('--folder',type=Path,required=True);a=p.parse_args()
compiled=Path('/workspace/scratch/state-services-pg-core');harness=Path('/workspace/scratch/state-shared-contract-gates');binary=Path('/workspace/scratch/state-pg139-app-v1/rootyard')
spec=importlib.util.spec_from_file_location('binding',compiled/'scripts/build_native.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
sha=lambda f:hashlib.file_digest(f.open('rb'),'sha256').hexdigest()
head=lambda root:subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
receipt=json.loads(binary.with_suffix('.build.json').read_text());files=[harness/'tests'/n for n in ('benchmark_tiers.py','sharding.py','pulls.py','e2e.py','schema_baseline.py')]
snapshot=lambda:{'compiled_inputs':m.source_digest(),'app':sha(binary),'compiled_checkout':head(compiled),'harness_checkout':head(harness),'harness_files':{str(f.relative_to(harness)):sha(f) for f in files},'driver':sha(Path(__file__))}
before=snapshot();assert before['compiled_inputs']==receipt['source_inputs_sha256'] and before['app']==receipt['binary_sha256'];a.folder.mkdir(parents=True,exist_ok=False)
command=['python3',str(harness/'tests/benchmark_tiers.py'),'--binary',str(binary),'--report',str(a.folder/'native.json')];start=time.monotonic();r=subprocess.run(command,cwd=harness,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=360);output=r.stdout.decode(errors='replace')
for key,value in os.environ.items():
 if value and len(value)>=6 and ('DATABASE_URL' in key or any(t in key for t in ('TOKEN','SECRET','PASSWORD','ACCESS_KEY'))):output=output.replace(value,'[redacted]')
(a.folder/'native.log').write_text(output);after=snapshot();native=json.loads((a.folder/'native.json').read_text()) if (a.folder/'native.json').exists() else {};cases=native.get('cases',[])
passed=bool(r.returncode==0 and native.get('passed') is True and len(cases)==5 and all(v['status']=='passed' for v in cases) and before==after and native.get('mode')=='live_metadata_drill' and native.get('production_validation') is False and native.get('reference_only') is False and native.get('data_plane_success_claimed') is False)
report={'passed':passed,'returncode':r.returncode,'seconds':round(time.monotonic()-start,3),'command':command,'before':before,'after':after,'identities_unchanged':before==after,'build_receipt':receipt,'native':native,'limits':['Actual HTTP/PostgreSQL control-plane guard test only; application contains additional unserved metadata-core code beyond the harness checkout.','No multi-node transfer, failover, HA, physical fencing or production benchmark success claimed; HTTP receipts must remain simulation-only.']};(a.folder/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ('passed','returncode','seconds')}));raise SystemExit(0 if passed else 1)
