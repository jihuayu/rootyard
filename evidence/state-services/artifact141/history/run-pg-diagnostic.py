import hashlib,importlib.util,json,os,re,shutil,subprocess,time
from pathlib import Path
root=Path('/workspace/scratch/state-services-artifact-holds');folder=Path('/workspace/scratch/state-artifact141-pg-diagnostic-v1');folder.mkdir(mode=0o700,exist_ok=False)
events=[json.loads(l) for l in Path('/workspace/scratch/state-artifact141-pg-diagnostic-build-v1.jsonl').read_text().splitlines() if l.strip()]
art=[e for e in events if e.get('reason')=='compiler-artifact' and e.get('target',{}).get('name')=='ref_store_artifact_holds' and e.get('executable')];assert len(art)==1
binary=folder/'ref_store_artifact_holds';shutil.copy2(art[0]['executable'],binary)
spec=importlib.util.spec_from_file_location('binding',root/'scripts/build_native.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
sha=lambda p:hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
def state():return dict(source=m.source_digest(),test=sha(root/'tests/ref_store_artifact_holds.rs'),binary=sha(binary))
before=state();start=time.monotonic();r=subprocess.run([str(binary),'--ignored','--test-threads=1'],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600);s=r.stdout.decode(errors='replace')
for k,v in os.environ.items():
 if v and len(v)>=6 and ('DATABASE_URL' in k or any(t in k for t in ('TOKEN','SECRET','PASSWORD','ACCESS_KEY'))):s=s.replace(v,'[redacted]')
(folder/'native.log').write_text(s);after=state();summary=re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',s)
report=dict(diagnostic_only=True,returncode=r.returncode,summary=summary[0] if summary else None,seconds=round(time.monotonic()-start,3),before=before,after=after,compiled_inputs_and_test_unchanged_during_run=before==after,limits=['Uncommitted development checkout diagnostic; not final clean-source qualification. Other independent new test files may be written during execution; compiled production inputs and this test are hashed.'])
(folder/'diagnostic.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['returncode','summary','seconds']}));raise SystemExit(r.returncode)
