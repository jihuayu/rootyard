"""Root-only real PostgreSQL integration runner, with public provenance."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--root', type=Path, required=True)
p.add_argument('--folder', type=Path, required=True)
p.add_argument('--report-folder', type=Path)
a = p.parse_args()
report_folder = a.report_folder or a.folder
if a.report_folder:
    report_folder.mkdir(parents=True, exist_ok=False)
spec = importlib.util.spec_from_file_location('binding', a.root / 'scripts/build_native.py')
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)
binary = a.folder / 'ref_store_core_snapshot'
receipt = json.loads(binary.with_suffix('.build.json').read_text())
sha = lambda path: hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()
head = lambda: subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=a.root, text=True).strip()
test = a.root / 'tests/ref_store_core_snapshot.rs'
before = dict(source=binding.source_digest(), binary=sha(binary), test=sha(test), head=head())
assert before['source'] == receipt['source_inputs_sha256']
assert before['binary'] == receipt['binary_sha256']
assert before['test'] == receipt['integration_test_source_sha256']
# Compiled inputs plus this integration test's source are authoritative.
# A later Python-only fixture/inventory commit does not require rebuilding Rust;
# retain both exact commits rather than relabel the original build receipt.
command = [str(binary), '--ignored', '--test-threads=1']
start = time.monotonic()
result = subprocess.run(command, cwd=a.root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
output = result.stdout.decode(errors='replace')
# Do not publish environment values even if a dependency includes one in an error.
for key, value in os.environ.items():
    if value and len(value) >= 6 and ('DATABASE_URL' in key or any(part in key for part in ('SECRET', 'TOKEN', 'PASSWORD', 'ACCESS_KEY'))):
        output = output.replace(value, '[redacted]')
(report_folder / 'real-pg.log').write_text(output)
after = dict(source=binding.source_digest(), binary=sha(binary), test=sha(test), head=head())
summary = re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;', output)
expected_cases = set(re.findall(r'(?m)^async fn ([a-zA-Z_0-9]+)\(\) -> Result<\(\)> \{', test.read_text()))
# Exact names declared with ignored test attributes, not helper functions.
expected_cases = {name for name in expected_cases if re.search(r'#\[ignore[^\n]*\]\s*async fn ' + re.escape(name) + r'\(', test.read_text())}
cases = re.findall(r'^test ([\w:]+) \.\.\. (ok|FAILED)$', output, re.M)
passed = bool(result.returncode == 0 and summary and summary.groups() == ('ok', str(len(expected_cases)), '0', '0') and {name for name, _ in cases} == expected_cases and len(cases) == len(expected_cases) and len(expected_cases) >= 15 and before == after)
report = dict(passed=passed, elapsed_seconds=round(time.monotonic()-start, 3),
              command=command, returncode=result.returncode,
              summary=summary.group(0) if summary else None,
              cases=[dict(name=name, passed=status == 'ok') for name, status in cases],
              source_binary_test_head_unchanged=before == after, before=before, after=after,
              build_receipt=receipt,
              compiled_commit=receipt['workspace_commit'],
              tested_checkout_commit=before['head'],
              compiled_inputs_and_integration_test_match_receipt=True,
              limits=['Real PostgreSQL on one loopback host; metadata pins only; no serving/cutover, pack membership, physical roots/holds, multi-host or power-loss qualification.'])
(report_folder / 'real-pg.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(dict(passed=passed, returncode=result.returncode, summary=report['summary'], seconds=report['elapsed_seconds'])))
raise SystemExit(0 if passed else 1)
