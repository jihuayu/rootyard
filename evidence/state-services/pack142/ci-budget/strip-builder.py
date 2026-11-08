"""Exercise the repository's actual optional strip path under a recorded low-disk override."""
import argparse,importlib.util,subprocess
from pathlib import Path
root=Path('/workspace/scratch/state-services-pack-commit')
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
spec=importlib.util.spec_from_file_location('binding',root/'scripts/build_native.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def low_disk_popen(command,**kwargs):
    assert command[:3]==['cargo','build','--locked']
    # The helper records this same list after execution, so no profile is hidden
    # from the receipt. Dependency profiles and workspace sources stay unchanged.
    command[1:1]=['--config','profile.dev.package.rootyard.debug=0']
    return subprocess.Popen(command,**kwargs)
m.run_build(argparse.Namespace(features='pando-lab',bins=False,strip_debuginfo=True),popen=low_disk_popen)
