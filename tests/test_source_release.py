"""Exercise Git snapshot packaging, including rejected and uncommitted inputs."""
import contextlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import check_source_release as release


class SourceRelease(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='traceq-source-release-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git('init', '-q')
        for name in release.REQUIRED:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('frozen source\n')
        (self.root / '.gitattributes').write_text('/tests export-ignore\n/evaluation export-ignore\n')
        (self.root / '.gitignore').write_text('/build/\n*.gtsw\n')
        for name in ('tests/regression.py', 'evaluation/runner.rs'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('development only\n')
        self.commit()
        self.output = self.root / 'build/source.tar.gz'

    def git(self, *args):
        return subprocess.check_output([
            'git', '-c', 'user.name=traceq test', '-c', 'user.email=traceq@example.invalid',
            '-c', 'commit.gpgsign=false', *args,
        ], cwd=self.root, timeout=10)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'Source snapshot fixture')

    def package(self, ref='HEAD'):
        with patch.object(release, 'ROOT', self.root), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return release.main(ref, self.output)

    def test_exports_the_checked_commit_and_excludes_development_files(self):
        # Worktree edits and an untracked local trace cannot enter a commit export.
        (self.root / 'Makefile').write_text('uncommitted edit\n')
        (self.root / 'local.gtsw').write_bytes(b'private trace')
        self.assertEqual(self.package(), 0)
        with tarfile.open(self.output) as archive:
            self.assertEqual(archive.extractfile('Makefile').read(), b'frozen source\n')
            names = archive.getnames()
        self.assertNotIn('tests/regression.py', names)
        self.assertNotIn('evaluation/runner.rs', names)
        self.assertNotIn('local.gtsw', names)

    def test_missing_dependency_manifest_does_not_replace_a_previous_archive(self):
        self.output.parent.mkdir()
        self.output.write_bytes(b'previous archive')
        (self.root / 'rust/traceq-core/Cargo.toml').unlink()
        self.commit()
        self.assertEqual(self.package(), 1)
        self.assertEqual(self.output.read_bytes(), b'previous archive')

    def test_unexcluded_evaluation_files_are_rejected(self):
        (self.root / '.gitattributes').write_text('/tests export-ignore\n')
        self.commit()
        self.assertEqual(self.package(), 1)
        self.assertFalse(self.output.exists())

    def test_unexcluded_tests_are_rejected(self):
        (self.root / '.gitattributes').write_text('/evaluation export-ignore\n')
        self.commit()
        self.assertEqual(self.package(), 1)
        self.assertFalse(self.output.exists())

    def test_symlink_to_outside_the_snapshot_is_rejected(self):
        path = self.root / 'tools/build_capture.py'
        path.unlink()
        path.symlink_to('/tmp/local-build-script.py')
        self.commit()
        self.assertEqual(self.package(), 1)
        self.assertFalse(self.output.exists())

    def test_invalid_ref_does_not_replace_a_previous_archive(self):
        self.output.parent.mkdir()
        self.output.write_bytes(b'previous archive')
        self.assertEqual(self.package('missing-commit'), 1)
        self.assertEqual(self.output.read_bytes(), b'previous archive')


if __name__ == '__main__':
    unittest.main()
