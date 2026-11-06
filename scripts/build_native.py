#!/usr/bin/env python3
"""Build a native binary and bind its digest to the exact compiled source inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def source_digest():
    files = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    if (ROOT / 'build.rs').exists():
        files.append(ROOT / 'build.rs')
    for directory in ('src', 'migrations', 'schema', 'vendor'):
        path = ROOT / directory
        if path.exists():
            files.extend(item for item in path.rglob('*') if item.is_file())
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(str(path.relative_to(ROOT)).encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features')
    parser.add_argument('--bins', action='store_true')
    args = parser.parse_args()
    before = source_digest()
    command = ['cargo', 'build', '--locked']
    command += ['--bins'] if args.bins else ['--bin', 'rootyard']
    if args.features:
        command += ['--features', args.features]
    subprocess.run(command, cwd=ROOT, check=True)
    after = source_digest()
    if before != after:
        raise SystemExit('Source inputs changed during build; rebuild before recording acceptance.')
    target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
    if not target.is_absolute():
        target = ROOT / target
    binary = target / 'debug/rootyard'
    report = {'version': 1, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'source_inputs_sha256': before,
              'workspace_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
              'command': command}
    destination = binary.with_suffix('.build.json')
    temporary = destination.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(destination)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
