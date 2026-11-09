"""Collect actual qualification records and scan inherited secrets without printing them."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

scratch = Path('/workspace/scratch')
root = scratch / 'state-services-roots-decisions'
stage = scratch / 'state144-evidence-staging'
stage.mkdir(mode=0o700, exist_ok=True)

def copy(source, name):
    source = Path(source)
    assert source.is_file(), str(source)
    shutil.copyfile(source, stage / name)

for target, folder in [('roots', 'state144-roots-native-v3'), ('decisions', 'state144-decisions-native-v2'),
                       ('a4-regression', 'state144-a4-regression-v1'), ('a5b-regression', 'state144-a5b-regression-v1')]:
    data = json.loads((scratch / folder / 'qualification.json').read_text())
    assert data['passed'] and data['before']['source'] == '753bfabe4d6c1f4ba793bad38e4997f0b610222e6bcb205de98f6e904cf00b30'
    copy(scratch / folder / 'qualification.json', target + '.json')
    copy(scratch / folder / 'native.log', target + '.log')

for kind, folder in [('schema', 'state144-schema-native-v1'), ('legacy19', 'state144-legacy19-native-v1'),
                     ('backup20', 'state144-backup20-native-v8')]:
    assert json.loads((scratch / folder / 'qualification.json').read_text())['passed']
    for filename in ('qualification.json', 'native.log', 'native.json'):
        if (scratch / folder / filename).is_file():
            copy(scratch / folder / filename, kind + '-' + filename)

for label, folder in [('roots-first-five-of-eight', 'state144-roots-native-v1'),
                      ('roots-first-eleven-passed', 'state144-roots-native-v2'),
                      ('decisions-first-eleven-of-twenty', 'state144-decisions-native-v1')]:
    for filename in ('qualification.json', 'native.log'):
        copy(scratch / folder / filename, label + '-' + filename)
for filename in ('qualification.json', 'native.log', 'native.json'):
    copy(scratch / 'state144-backup20-native-v6' / filename, 'backup20-previous-passed-v6-' + filename)
    copy(scratch / 'state144-backup20-native-v7' / filename, 'backup20-assertion-tightening-v7-' + filename)
for version in range(1, 6):
    for filename in ('qualification.json', 'native.log', 'native.json'):
        copy(scratch / ('state144-backup20-native-v' + str(version)) / filename,
             'backup20-failed-v' + str(version) + '-' + filename)

for filename in ('rootyard-lib-contract.build.json', 'library.json', 'library.log', 'ignored-tests.txt'):
    copy(scratch / 'state144-lib-build-v1' / filename, 'library-' + filename)
copy(scratch / 'state144-app-v2/rootyard.build.json', 'app-build.json')
for target in ('ref_store_retention_roots', 'ref_store_decision_subset', 'ref_store_packs', 'ref_store_materialized_reads'):
    for suffix in ('.build.json', '.test-inputs.json'):
        copy(scratch / 'state144-matrix-build-v2' / (target + suffix), target + suffix)
for suffix in ('.build.json', '.test-inputs.json'):
    copy(scratch / 'state144-backup-helper-build-v5' / ('ref_store_roots_decisions_backup_fixture' + suffix),
         'backup-helper' + suffix)
for pattern in ('state144-check-v*.log', 'state144-tests-check-v*.log', 'state144-clippy-v*.log',
                'state144-cargo-fix-v*.log', 'state144-tests-fix-v*.log', 'state144-sqlgen-v*.log',
                'state144-clippy-helper-final*.log'):
    for file in sorted(scratch.glob(pattern)):
        copy(file, file.name)
copy(scratch / 'state144-sqlgen-v6/receipt.json', 'sqlgen-v6-receipt.json')
copy(scratch / 'state144-reference-final.json', 'reference.json')
copy(scratch / 'state144-source-tests-v1.json', 'source-units.json')
copy(scratch / 'state144-python-units-v1.log', 'unfiltered-units-incomplete-tooling-failed.log')
for filename in ('run-state144-tests.py', 'run-state144-native.py', 'run-state144-library.py',
                 'build-state144-matrix.py', 'build-state144-tests.py', 'run-state144-source-units-v1.py'):
    copy(scratch / filename, filename)
for filename in ('roots-review-v2.md', 'integration-review-final.md'):
    copy(root / 'target/task-context' / filename, 'luna-' + filename)
copy(Path(__file__), 'seal-evidence.py')

notes = {
    'production_inputs_sha256': '753bfabe4d6c1f4ba793bad38e4997f0b610222e6bcb205de98f6e904cf00b30',
    'production_commit': '84cae1e50feba336503cfae4e1a1eb4bf9a7ba25',
    'later_changes': 'Only backup fixtures, assertions, documentation and evidence; production inputs unchanged.',
    'workflow': 'Actual DeepSeek CLI primary implementation/test agents; Luna Max source-only review; Root alone builds, real services, native Git and qualification.',
    'native_tests': {'roots': 11, 'decisions_subset': 20, 'a4': 8, 'a5b': 12, 'failed': 0, 'ignored': 0},
    'library': {'passed': 410, 'failed': 0, 'ignored': 9},
    'backup': {'format20_cases': 7, 'genuine_format19_upgrade_cases': 7, 'skipped': 0},
    'failed_attempts': [
        'Roots first 5/8: source pin generation and bare Git fixture target fixed, original assertions retained.',
        'Decision first 11/20: actual SQL parameter25 persisted facts as authz; repaired without weakening final recheck. Other failures were JSONB/text fixture types and stale code/prefix assertions.',
        'Backup v1: PG INT4 octet_length incorrectly decoded as i64; fixed to an explicit i32->i64 conversion.',
        'Backup v2/v3: ordinary release also retains a tombstone; duplicate JSON cancellation count key and stale protocol marker corrected.',
        'Backup v4: exact retained-ledger hashes matched, but fixture reconstruction lost a refused registration request ID with no receipt; preserve intent metadata independently of receipts.',
        'Backup v5: restored ledgers and full-schema read-only checks passed; a negative quota mutation was correctly refused but its expected trigger-error wording was stale. Corrected the assertion, not the trigger.',
        'Final reviewer follow-ups tighten exact root rows/released shape/Push action and broaden CI input paths; the initial added capture-revision assertion guessed all four mutations, corrected to the two registrations after reading the actual protocol. Release fences are head generations.',
        'Unfiltered Python discovery requires unrelated native executables/kernel fixtures absent from this worktree; its failures are retained. The selected source-only run explicitly excludes those modules and reports 286 tests, 6 skips.',
    ],
    'boundaries': [
        'Unserved library increment. No Merge producer, distributed Raft bridge, service cutover, GC or encryption qualification.',
        'LFS pointer refs fail closed without immutable remote byte attestation; local file availability is insufficient.',
        'Backup archives PG metadata, not external Blob bytes. Restored retained roots are verified against surviving external S3 originals.',
        'All RefStore ledgers are compared exactly across restore; all schema tables are checked unchanged around read-only replay. Unrelated cluster authority intentionally rotates during restore.',
        'Loopback PG17/Garage S3 and native Git 2.47.3; Azure is a compilation check, not provider runtime acceptance.',
        'Native admission/view/workspace bounds are process-local. No hard kernel cleanup return, physical orphan-disk bound, power-loss or restart-durable cleanup claim.',
        'Issues stay open until the relevant PR is merged and acceptance is complete.',
    ],
}
(stage / 'validation-notes.json').write_text(json.dumps(notes, indent=2) + '\n')

secrets = [value.encode() for key, value in os.environ.items() if len(value) >= 8 and
           ('DATABASE_URL' in key or any(part in key for part in ('TOKEN', 'SECRET', 'PASSWORD', 'ACCESS_KEY')))]
files = [file for file in stage.iterdir() if file.is_file() and file.name not in ('privacy.json', 'manifest.json')]
hits = [file.name for file in files if any(secret in file.read_bytes() for secret in secrets)]
privacy = {'passed': not hits, 'scanned_files': len(files), 'matching_files': hits,
           'rule': 'Exact inherited fixture DSN and secret values; values/configuration are never retained.'}
(stage / 'privacy.json').write_text(json.dumps(privacy, indent=2) + '\n')
assert not hits, 'Secret scan failed; names retained privately, no publication'
manifest = {file.name: hashlib.sha256(file.read_bytes()).hexdigest()
            for file in sorted(stage.iterdir()) if file.is_file() and file.name != 'manifest.json'}
(stage / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({'files': len(manifest), 'secret_matches': len(hits)}))
