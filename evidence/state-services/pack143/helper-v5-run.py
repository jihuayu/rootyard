import json,os,subprocess,time
from pathlib import Path
p=Path(__file__).parent
command=['python3','scripts/build_native_test.py','--test','ref_store_pack_snapshots_backup_fixture','--features','pando-lab','--package-debug','0','--strip-debuginfo','--output',str(p/'ref_store_pack_snapshots_backup_fixture')]
started=time.monotonic()
r=subprocess.run(command,cwd='/workspace/scratch/state-services-pack-snapshot')
(p/'process-result.json').write_text(json.dumps({'returncode':r.returncode,'seconds':round(time.monotonic()-started,3),'command':command},indent=2)+'\n')
