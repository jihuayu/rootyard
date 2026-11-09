"""Root-only source-bound schema144/format20/genuine format19 qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

p = argparse.ArgumentParser()
p.add_argument('--kind', choices=['schema', 'backup20', 'legacy19'], required=True)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--fixture-binary', type=Path)
p.add_argument('--folder', type=Path, required=True)
p.add_argument('--trace', action='store_true')
a = p.parse_args()
root = Path('/workspace/scratch/state-services-roots-decisions')
sha = lambda f: hashlib.file_digest(f.open('rb'), 'sha256').hexdigest()
spec = importlib.util.spec_from_file_location('binding', root / 'scripts/build_native.py')
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)
binary = a.binary.resolve()
receipt = json.loads(binary.with_suffix('.build.json').read_text())
legacy = Path('/workspace/scratch/state-pack143-app-v1/rootyard')
legacy_helper = Path('/workspace/scratch/state-pack143-backup-helper-build-v5/ref_store_pack_snapshots_backup_fixture')
scripts = dict(schema='schema_contract.py', backup20='backup_refstore_roots_decisions144.py',
               legacy19='backup_legacy143_roots_decisions.py')
script = root / 'tests' / scripts[a.kind]
files = [script, root / 'tests/schema_baseline.py', root / 'tests/e2e.py']
helper = None
if a.kind != 'schema':
    files += [root / 'tests/backup.py', root / 'tests/backup_refstore_core139.py',
              root / 'tests/backup_refstore_pack_snapshots143.py',
              root / 'tests/backup_refstore_roots_decisions144.py']
if a.kind == 'backup20':
    assert a.fixture_binary
    helper = json.loads(a.fixture_binary.with_suffix('.build.json').read_text())
    assert helper['kind'] == 'rust-integration-test' and helper['package_rebuilt'] is True
    assert sha(a.fixture_binary) == helper['binary_sha256']
    assert helper['source_inputs_sha256'] == receipt['source_inputs_sha256']
    assert helper['integration_test_source_sha256'] == sha(root / 'tests/ref_store_roots_decisions_backup_fixture.rs')
    files += [root / 'tests/ref_store_roots_decisions_backup_fixture.rs']
    support_inputs = [root / 'tests/ref_store_roots_decisions_backup_fixture.rs']
    for directory in ('roots_decisions_backup_support', 'retention_roots_support'):
        support_inputs += sorted((root / 'tests' / directory).rglob('*.rs'))
    supplemental = json.loads(a.fixture_binary.with_suffix('.test-inputs.json').read_text())
    assert supplemental['binary_sha256'] == sha(a.fixture_binary)
    assert supplemental['inputs_unchanged'] is True
    assert supplemental['test_inputs'] == {str(f.relative_to(root)): sha(f) for f in support_inputs}
    files += support_inputs

if a.kind == 'legacy19':
    assert sha(legacy) == 'c61d3f9a5617fe03d17afd4a5277912c6e6948414c06e5d6e3a5460b4508d96b'
    files += [root / 'tests/backup_legacy132_sessions.py']

def state():
    value = dict(source=binding.source_digest(), binary=sha(binary),
                 head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                 harness={str(f.relative_to(root)): sha(f) for f in files})
    if a.kind == 'backup20':
        value['fixture_binary'] = sha(a.fixture_binary)
    if a.kind == 'legacy19':
        value.update(legacy_binary=sha(legacy), legacy_fixture_binary=sha(legacy_helper),
                     legacy_fixture_receipt=sha(legacy_helper.with_suffix('.build.json')))
    if a.trace:
        value['diagnostic_launcher'] = sha(Path('/workspace/scratch/trace-state142-backup.py'))
    return value

before = state()
assert before['source'] == receipt['source_inputs_sha256'] and before['binary'] == receipt['binary_sha256']
assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True).strip()
a.folder.mkdir(mode=0o700, parents=True, exist_ok=False)
command = ['python3', str(script), '--binary', str(binary)]
if a.trace:
    command.insert(1, '/workspace/scratch/trace-state142-backup.py')
if a.kind != 'schema':
    command += ['--report', str(a.folder / 'native.json')]
if a.kind == 'backup20':
    command += ['--roots-decisions-fixture-binary', str(a.fixture_binary)]
if a.kind == 'legacy19':
    command += ['--legacy-binary', str(legacy), '--legacy-fixture-binary', str(legacy_helper),
                '--legacy-fixture-receipt', str(legacy_helper.with_suffix('.build.json'))]
env = os.environ.copy()
if a.kind != 'schema':
    for dst, src in {'ENDPOINT': 'ENDPOINT', 'BUCKET': 'BUCKET', 'REGION': 'REGION',
                     'ACCESS_KEY_ID': 'ACCESS_KEY', 'SECRET_ACCESS_KEY': 'SECRET_KEY'}.items():
        env['ROOTYARD_BLOB_' + dst] = env['ROOTYARD_OBJECT_STORE_' + src]
    if 'ROOTYARD_OBJECT_STORE_SESSION_TOKEN' in env:
        env['ROOTYARD_BLOB_SESSION_TOKEN'] = env['ROOTYARD_OBJECT_STORE_SESSION_TOKEN']
    env.update(ROOTYARD_BLOB_DRIVER='opendal', ROOTYARD_BLOB_SERVICE='s3',
               ROOTYARD_BLOB_ROOT='rootsbackup/' + uuid.uuid4().hex, ROOTYARD_TEST_GIT='/usr/bin/git')
started = time.monotonic()
result = subprocess.run(command, cwd=root, env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=1200)
output = result.stdout.decode(errors='replace')
for key, value in env.items():
    if value and len(value) >= 6 and ('DATABASE_URL' in key or
        any(t in key for t in ('TOKEN', 'SECRET', 'PASSWORD', 'ACCESS_KEY'))):
        output = output.replace(value, '[redacted]')
(a.folder / 'native.log').write_text(output)
after = state()
native = None
if a.kind == 'schema':
    try:
        native = json.loads(output)
    except json.JSONDecodeError:
        pass
    catalog = json.loads((root / 'schema/144_catalog.json').read_text())
    counts = dict(tables=len(catalog['tables']), functions=len(catalog['functions']), triggers=len(catalog['triggers']))
    valid = bool(native and str(native.get('schema_version')) == '144'
                 and native.get('migration_mode') == 'binary' and native.get('canonical') is True
                 and all(native.get(k) == v for k, v in counts.items())
                 and all(native.get(k) is True for k in ['roundtrip', 'restored003_upgrade',
                     'restored006_upgrade', 'restored007_upgrade', 'upgraded_roundtrip',
                     'custom_search_path_bootstrap', 'custom_migrate_idempotent']))
else:
    if (a.folder / 'native.json').exists():
        native = json.loads((a.folder / 'native.json').read_text())
    cases = native.get('cases', []) if native else []
    valid = bool(native and native.get('passed') is True and len(cases) == 7
                 and all(c['status'] == 'passed' for c in cases))
passed = bool(result.returncode == 0 and valid and before == after)
report = dict(passed=passed, kind=a.kind, returncode=result.returncode, command=command,
              seconds=round(time.monotonic() - started, 3), before=before, after=after,
              inputs_unchanged=before == after, runner_sha256=sha(Path(__file__)),
              build_receipt=receipt, helper_build_receipt=helper, native=native,
              limits=['Loopback PostgreSQL17/Garage/native Git; metadata backup only, external Blob bytes not archived.',
                      'Genuine format19 uses retained schema143 producer and old typed A5 helper, never relabeled.'])
(a.folder / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({key: report[key] for key in ['passed', 'kind', 'returncode', 'seconds']}))
raise SystemExit(0 if passed else 1)
