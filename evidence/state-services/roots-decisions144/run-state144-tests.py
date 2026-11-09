"""Root-only source-bound real PG/S3/native Git integration qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

p = argparse.ArgumentParser()
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--target', required=True)
p.add_argument('--expected', type=int, required=True)
p.add_argument('--folder', type=Path, required=True)
p.add_argument('--support', action='append', default=[])
p.add_argument('--diagnostic-dirty', action='store_true')
a = p.parse_args()
root = Path('/workspace/scratch/state-services-roots-decisions')
sha = lambda f: hashlib.file_digest(f.open('rb'), 'sha256').hexdigest()
spec = importlib.util.spec_from_file_location('binding', root / 'scripts/build_native.py')
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)
receipt = json.loads(a.binary.with_suffix('.build.json').read_text())
test = root / 'tests' / (a.target + '.rs')
test_inputs = [test]
for folder in a.support:
    test_inputs += sorted((root / 'tests' / folder).rglob('*.rs'))

def state():
    return dict(source=binding.source_digest(), test=sha(test),
                test_inputs={str(f.relative_to(root)): sha(f) for f in test_inputs},
                binary=sha(a.binary),
                head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                clean=not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True).strip())

before = state()
assert before['clean'] or a.diagnostic_dirty
assert before['source'] == receipt['source_inputs_sha256']
assert before['test'] == receipt['integration_test_source_sha256']
assert before['binary'] == receipt['binary_sha256']
if a.support:
    supplemental = json.loads(a.binary.with_suffix('.test-inputs.json').read_text())
    assert supplemental['test_inputs'] == before['test_inputs']
    assert supplemental['binary_sha256'] == before['binary']
    assert supplemental['inputs_unchanged'] is True
env = os.environ.copy()
for dst, src in {'ENDPOINT': 'ENDPOINT', 'BUCKET': 'BUCKET', 'REGION': 'REGION',
                 'ACCESS_KEY_ID': 'ACCESS_KEY', 'SECRET_ACCESS_KEY': 'SECRET_KEY'}.items():
    env['ROOTYARD_BLOB_' + dst] = env['ROOTYARD_OBJECT_STORE_' + src]
if 'ROOTYARD_OBJECT_STORE_SESSION_TOKEN' in env:
    env['ROOTYARD_BLOB_SESSION_TOKEN'] = env['ROOTYARD_OBJECT_STORE_SESSION_TOKEN']
env.update(ROOTYARD_BLOB_DRIVER='opendal', ROOTYARD_BLOB_SERVICE='s3',
           ROOTYARD_BLOB_ROOT='state144qual/' + uuid.uuid4().hex, ROOTYARD_TEST_GIT='/usr/bin/git')
a.folder.mkdir(mode=0o700, parents=True, exist_ok=False)
command = [str(a.binary), '--ignored', '--test-threads=1']
started = time.monotonic()
result = subprocess.run(command, cwd=root, env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=1200)
output = result.stdout.decode(errors='replace')
for key, value in env.items():
    if value and len(value) >= 6 and ('DATABASE_URL' in key or
        any(part in key for part in ('TOKEN', 'SECRET', 'PASSWORD', 'ACCESS_KEY'))):
        output = output.replace(value, '[redacted]')
(a.folder / 'native.log').write_text(output)
summary = re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;', output)
after = state()
passed = bool(before == after and result.returncode == 0 and summary and summary[1] == 'ok'
              and int(summary[2]) == a.expected and summary[3] == '0' and summary[4] == '0')
report = dict(passed=passed, target=a.target, expected=a.expected, returncode=result.returncode,
              seconds=round(time.monotonic() - started, 3), summary=summary[0] if summary else None,
              command=command, before=before, after=after, inputs_unchanged=before == after,
              runner_sha256=sha(Path(__file__)), build_receipt=receipt,
              qualification_kind='clean-candidate' if before['clean'] else 'dirty-diagnostic-only',
              limits=['Loopback PG17 and Garage S3, native Git; no serving cutover or distributed Raft barrier.',
                      'Metadata backup does not archive original external Blob bytes.'])
(a.folder / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({key: report[key] for key in ('passed', 'target', 'summary', 'seconds')}))
raise SystemExit(0 if passed else 1)
