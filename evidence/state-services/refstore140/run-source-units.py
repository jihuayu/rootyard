import json,sys,unittest
from pathlib import Path
root=Path('/workspace/scratch/state-services-pg-snapshot')
sys.path.insert(0,str(root))
sys.path.insert(0,str(root/'tests'))
suite=unittest.defaultTestLoader.discover(str(root/'tests'),pattern='test_*.py')
native={
 'test_changeset_service','test_ci_sandbox','test_namespace_service',
 'test_sandbox_service','test_view_lab','test_workspace_source_lease',
 'test_workspaces_service','test_track4_labs','test_workspace_crash_recovery',
 'test_workspace_fuse','test_workspace_fuse_service','test_workspace_remote_namespace',
 'test_workspace_vfs'
}
def flatten(s):
 for x in s:
  if isinstance(x,unittest.TestSuite): yield from flatten(x)
  else: yield x
selected=[]; excluded=[]
for case in flatten(suite):
 if case.__class__.__module__.split('.')[-1] in native: excluded.append(case.id())
 else:selected.append(case)
result=unittest.TextTestRunner(verbosity=1).run(unittest.TestSuite(selected))
report={'status':'passed' if result.wasSuccessful() else 'failed',
 'run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
 'skipped':len(result.skipped),'excluded':excluded,
 'exclusion_reason':'Requires dedicated native executables/services/kernel fixture; not qualified by this source/unit-only run. Full CI native suites remain required.'}
Path('/workspace/scratch/state-pg140-source-tests-v3.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='excluded'}))
raise SystemExit(0 if result.wasSuccessful() else 1)
