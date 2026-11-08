import argparse,hashlib,importlib.util,json,re,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--folder',type=Path,required=True);a=p.parse_args()
root=Path('/workspace/scratch/state-services-read-materialize');binary=a.folder/'rootyard-lib-contract';receipt=json.loads(binary.with_suffix('.build.json').read_text())
spec=importlib.util.spec_from_file_location('binding',root/'scripts/build_native.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
sha=lambda p:hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
def state():return dict(source=m.source_digest(),binary=sha(binary),head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip())
before=state();assert before['source']==receipt['source_inputs_sha256'] and before['binary']==receipt['binary_sha256']
listing=subprocess.check_output([str(binary),'--list'],cwd=root,text=True);declared=re.search(r'(\d+) tests?, 0 benchmarks?',listing);assert declared
command=[str(binary),'--test-threads=2'];start=time.monotonic();r=subprocess.run(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300);output=r.stdout.decode(errors='replace');(a.folder/'library.log').write_text(output)
summary=re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',output);after=state()
passed=bool(r.returncode==0 and summary and summary[1]=='ok' and int(summary[2])>=281 and summary[3]=='0' and summary[4]=='9' and int(summary[2])+int(summary[4])==int(declared[1]) and before==after)
ignored_listing=subprocess.check_output([str(binary),'--ignored','--list'],cwd=root,text=True)
(a.folder/'ignored-tests.txt').write_text(ignored_listing)
report=dict(passed=passed,returncode=r.returncode,command=command,summary=summary[0] if summary else None,declared_tests=int(declared[1]),seconds=round(time.monotonic()-start,3),before=before,after=after,source_binary_head_unchanged=before==after,build_receipt=receipt,limits=['Eight existing ignored tests and the newly ignored mandatory-config real-provider test are not exercised by this library run. Dedicated PostgreSQL and real-provider runs are recorded separately.'])
(a.folder/'library.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['passed','summary','seconds']}));raise SystemExit(0 if passed else 1)
