"""Bind split test support modules across an actual native test build."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('--target', required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--support', action='append', default=[])
a = p.parse_args()
root = Path('/workspace/scratch/state-services-roots-decisions')
sha = lambda f: hashlib.file_digest(f.open('rb'), 'sha256').hexdigest()
files = [root / 'tests' / (a.target + '.rs')]
for folder in a.support:
    files += sorted((root / 'tests' / folder).rglob('*.rs'))
before = {str(f.relative_to(root)): sha(f) for f in files}
command = [sys.executable, str(root / 'scripts/build_native_test.py'), '--test', a.target,
           '--features', 'pando-lab', '--package-debug', '0', '--strip-debuginfo',
           '--output', str(a.output)]
subprocess.run(command, cwd=root, check=True)
after = {str(f.relative_to(root)): sha(f) for f in files}
assert before == after, 'Test support changed while compiling'
receipt = dict(test_inputs=before, binary_sha256=sha(a.output), inputs_unchanged=True,
               builder_sha256=sha(Path(__file__)), command=command)
a.output.with_suffix('.test-inputs.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('Split test input binding written')
