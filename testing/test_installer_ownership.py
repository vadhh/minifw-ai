"""Exercise the postinst permission block without installing on the workstation."""
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILD = (ROOT / "scripts/build_deb.sh").read_text()
BLOCK = BUILD.split('# --- Protect executable inputs', 1)[1].split('# --- 1. Python', 1)[0]
BLOCK = '# --- Protect executable inputs' + BLOCK


class OwnershipTests(unittest.TestCase):
    def run_block(self, root):
        # Ownership requires Linux/root acceptance; exercise real chmod/find locally.
        return subprocess.run(['bash', '-c', 'set -e\nAPP_ROOT="$1"\nchown() { :; }\n' + BLOCK,
                               'test', str(root)], capture_output=True, text=True)

    def test_existing_writable_code_and_venv_are_locked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('app', 'models', 'scripts', 'venv', 'config'):
                folder = root / name
                folder.mkdir(mode=0o777)
                folder.chmod(0o777)
                code = folder / 'input'
                code.write_text('fixture')
                code.chmod(0o666)
            (root / 'venv/python').symlink_to('/usr/bin/python3')
            result = self.run_block(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            for path in root.rglob('*'):
                if not path.is_symlink():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o022, 0, str(path))

    def test_linked_code_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'install'
            (root / 'app').mkdir(parents=True)
            outside = Path(directory) / 'outside'
            outside.write_text('unchanged')
            outside.chmod(0o666)
            (root / 'app/code.py').symlink_to(outside)
            self.assertNotEqual(self.run_block(root).returncode, 0)
            self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o666)

    def test_guard_precedes_installed_python(self):
        self.assertLess(BUILD.index('# --- Protect executable inputs'), BUILD.index('python3 -m venv'))
        self.assertIn('chown -hR root:root', BLOCK)


if __name__ == '__main__':
    unittest.main()
