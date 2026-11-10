"""Root-only serialized native builds, with one clean and separate exact receipts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path('/workspace/scratch/state-services-roots-decisions')
sys.path.insert(0, str(root / 'scripts'))
import build_native as binding
import build_native_test as selected

p = argparse.ArgumentParser()
p.add_argument('--folder', type=Path, required=True)
p.add_argument('--target', action='append')
p.add_argument('--reuse-matching-lib', action='store_true')
a = p.parse_args()
support = {
    'ref_store_retention_roots': ['retention_roots_support'],
    'ref_store_decision_subset': ['decision_subset_support', 'retention_roots_support'],
    'ref_store_roots_decisions_backup_fixture': ['roots_decisions_backup_support', 'retention_roots_support'],
    'ref_store_packs': [],
    'ref_store_materialized_reads': [],
}
targets = a.target or list(support)
assert all(target in support for target in targets)
sha = lambda f: hashlib.file_digest(Path(f).open('rb'), 'sha256').hexdigest()
def inputs(target):
    files = [root / 'tests' / (target + '.rs')]
    for folder in support[target]:
        files += sorted((root / 'tests' / folder).rglob('*.rs'))
    return {str(f.relative_to(root)): sha(f) for f in files}

def state():
    return {'source': binding.source_digest(), 'git': selected.git_state(),
            'tests': {target: inputs(target) for target in targets}, 'lock': sha(root / 'Cargo.lock')}

a.folder.mkdir(parents=True, exist_ok=False)
with binding.build_lock(binding.canonical_target()):
    before = state()
    if not a.reuse_matching_lib:
        subprocess.run(['cargo', 'clean', '--package', 'rootyard'], cwd=root, check=True)
    for index, target in enumerate(targets):
        command = ['cargo', '--config', 'profile.dev.package.rootyard.debug=0',
                   '--config', 'profile.test.package.rootyard.debug=0',
                   '--config', 'profile.dev.package.rootyard.strip="debuginfo"',
                   '--config', 'profile.test.package.rootyard.strip="debuginfo"',
                   'rustc', '--locked', '--profile', 'test', '--test', target,
                   '--features', 'pando-lab', '--message-format=json-render-diagnostics']
        result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE)
        events_path = a.folder / (target + '.cargo-events.jsonl')
        events_path.write_bytes(result.stdout)
        assert result.returncode == 0, 'Native compilation failed for ' + target
        events = [json.loads(line) for line in result.stdout.decode().splitlines() if line.strip()]
        selected.require_build_finished(events)
        artifact = selected.selected_artifact(events, target)
        if index == 0:
            libraries = [event for event in events if event.get('reason') == 'compiler-artifact'
                         and event.get('target', {}).get('name') == 'rootyard'
                         and 'lib' in event.get('target', {}).get('kind', [])]
            assert libraries
            library_rebuilt = all(event['fresh'] is False for event in libraries)
            assert a.reuse_matching_lib or library_rebuilt
        assert state() == before, 'Inputs changed during matrix build'
        original = Path(artifact['executable'])
        output = a.folder / target
        shutil.copyfile(original, output)
        os.chmod(output, 0o700)
        digest = sha(output)
        assert digest == sha(original)
        receipt = {'kind': 'rust-integration-test', 'relocated_artifact': True,
                   'original_artifact_sha256': digest, 'workspace_commit': before['git'][0],
                   'fresh': False, 'source_inputs_sha256': before['source'],
                   'binary_sha256': digest, 'integration_test_source_sha256': sha(root / 'tests' / (target + '.rs')),
                   'cargo_lock_sha256': before['lock'], 'command': command,
                   'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                   'package_rebuilt': True, 'fresh_false_artifacts': [artifact],
                   'matrix_clean_once': not a.reuse_matching_lib, 'matrix_first_rootyard_library_rebuilt': library_rebuilt,
                   'matching_dependency_reuse': a.reuse_matching_lib}
        output.with_suffix('.build.json').write_text(json.dumps(receipt, indent=2) + '\n')
        supplemental = {'test_inputs': before['tests'][target], 'binary_sha256': digest,
                        'inputs_unchanged': True, 'builder_sha256': sha(__file__), 'command': command}
        output.with_suffix('.test-inputs.json').write_text(json.dumps(supplemental, indent=2) + '\n')
        print(json.dumps({'target': target, 'built': True, 'fresh': False, 'sha256': digest}), flush=True)
    assert state() == before
