import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import state_services_native_baseline as baseline


class NativeBaselineInputsTest(unittest.TestCase):
    def test_response_identity_and_same_origin_clone_path(self):
        identity = str(uuid.uuid4())
        valid = {'id': identity, 'name': 'fixture', 'clone_path': '/git/alice/fixture.git'}
        self.assertEqual(baseline.validate_repository(valid, 'fixture'), identity)
        for malicious in ('@outside.invalid/repo', '//outside.invalid/repo',
                          'https://outside.invalid/repo', '/git/alice/other.git'):
            with self.subTest(path=malicious), self.assertRaises(ValueError):
                baseline.validate_repository(dict(valid, clone_path=malicious), 'fixture')
        for value in ('../../outside', '/absolute', str(uuid.UUID(int=0)), 'invalid'):
            with self.subTest(identity=value), self.assertRaises(ValueError):
                baseline.validate_repository(dict(valid, id=value), 'fixture')
        with self.assertRaises(ValueError):
            baseline.validate_repository(valid, 'fixture', str(uuid.uuid4()))

    def test_cache_cleanup_rejects_escape_and_symlinks(self):
        identity = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as owned, tempfile.TemporaryDirectory() as outside:
            root = Path(owned)
            parent = root / 'data' / 'pando-cache'
            parent.mkdir(parents=True)
            self.assertEqual(baseline.owned_cache_path(root, identity), parent / identity)
            (parent / identity).symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                baseline.owned_cache_path(root, identity)
            (parent / identity).unlink()
            parent.rmdir()
            parent.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                baseline.owned_cache_path(root, identity)
            for value in ('../../outside', '/absolute', 'invalid'):
                with self.subTest(identity=value), self.assertRaises(ValueError):
                    baseline.owned_cache_path(root, value)


if __name__ == '__main__':
    unittest.main()
