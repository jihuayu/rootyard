"""Qualify both selected native Git variants against one exact app artifact."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path('/workspace/scratch/state-shared-contract-gates')
binary = Path('/workspace/scratch/state-browse130-app-v3/rootyard')
receipt = json.loads(binary.with_suffix('.build.json').read_text())
spec = importlib.util.spec_from_file_location('binding', '/workspace/scratch/state-services-baseline-metrics/scripts/build_native.py')
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)
binding.ROOT = root
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
runner = root / 'tests/browse.py'
expected = next(ast.literal_eval(node.value) for node in ast.parse(runner.read_text()).body
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'CASE_NAMES' for t in node.targets))
before = binding.source_digest()
runner_before = sha(runner)
assert len(expected) == 12 and before == receipt['source_inputs_sha256']
assert sha(binary) == receipt['binary_sha256']
assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True).strip()
report = dict(status='failed', build_receipt=receipt, runner_sha256=runner_before,
              qualification_driver_sha256=sha(Path(__file__)), cases_expected=list(expected), variants=[],
              limits=['One physical host and loopback PostgreSQL; no throughput/HA qualification.',
                      'Configured native Git is selected per variant; counting and ref-ack fault wrappers delegate to that same selected executable.',
                      'Git2.43 is an isolated upstream server-only NO_CURL build; its source/binary receipt is retained. Git2.47 exercises the same unsupported-start-after fallback; clients use stock Git2.52.'])
for label, git in [('git243', '/workspace/.rootyard-tools/git243/bin/git'), ('git247', '/usr/bin/git'), ('git252', '/usr/local/bin/git')]:
    output = Path('/workspace/scratch/state-browse130-' + label + '-native-v1.json')
    log = output.with_suffix('.log')
    env = os.environ.copy()
    env['ROOTYARD_GIT'] = git
    command = [sys.executable, str(runner), '--binary', str(binary), '--report', str(output)]
    with log.open('w') as stream:
        result = subprocess.run(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
    native = json.loads(output.read_text()) if output.exists() else {}
    complete = (result.returncode == 0 and native.get('passed') is True
                and native.get('case_count') == 12 and native.get('cases_run') == 12
                and native.get('cases_passed') == 12 and native.get('cases_failed') == 0
                and [c['name'] for c in native.get('cases', [])] == list(expected)
                and native.get('binary_sha256') == receipt['binary_sha256'])
    report['variants'].append(dict(label=label, git_version=subprocess.check_output([git, '--version'], text=True).strip(),
                                   command=command, exit_code=result.returncode, passed=complete,
                                   report=str(output), log=str(log)))
    print(label, 'PASS' if complete else 'FAIL', flush=True)
report['source_matches_after'] = binding.source_digest() == before
report['runner_matches_after'] = sha(runner) == runner_before
report['binary_matches_after'] = sha(binary) == receipt['binary_sha256']
report['status'] = 'passed' if all(v['passed'] for v in report['variants']) and all(report[k] for k in
                  ['source_matches_after', 'runner_matches_after', 'binary_matches_after']) else 'failed'
Path('/workspace/scratch/state-browse130-triple-native-v1.json').write_text(json.dumps(report, indent=2) + '\n')
sys.exit(0 if report['status'] == 'passed' else 1)
