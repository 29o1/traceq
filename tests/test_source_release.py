"""Exercise Git snapshot packaging, including rejected and uncommitted inputs."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'release'))

import source_archive as release


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
        (self.root / '.gitattributes').write_text(
            '/tests export-ignore\n/evaluation export-ignore\n/release export-ignore\n'
            '/rust/*/tests export-ignore\n/rust/*/examples export-ignore\n'
            '/AGENTS.md export-ignore\n/DEVELOPMENT.md export-ignore\n'
        )
        (self.root / '.gitignore').write_text('/build/\n*.gtsw\n')
        self.dev_paths = ('tests/regression.py', 'evaluation/runner.rs', 'release/source_archive.py',
                          'rust/traceq-core/tests/units.rs', 'rust/traceq-core/examples/sample.rs',
                          'AGENTS.md', 'DEVELOPMENT.md')
        for name in self.dev_paths:
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
        self.assertTrue(set(self.dev_paths).isdisjoint(names))
        self.assertNotIn('local.gtsw', names)

    def test_missing_dependency_manifest_does_not_replace_a_previous_archive(self):
        self.output.parent.mkdir()
        self.output.write_bytes(b'previous archive')
        (self.root / 'rust/traceq-core/Cargo.toml').unlink()
        self.commit()
        self.assertEqual(self.package(), 1)
        self.assertEqual(self.output.read_bytes(), b'previous archive')

    def test_unexcluded_evaluation_files_are_rejected(self):
        attributes = self.root / '.gitattributes'
        attributes.write_text(attributes.read_text().replace('/evaluation export-ignore\n', ''))
        self.commit()
        self.assertEqual(self.package(), 1)
        self.assertFalse(self.output.exists())

    def test_unexcluded_tests_are_rejected(self):
        attributes = self.root / '.gitattributes'
        attributes.write_text(attributes.read_text().replace('/tests export-ignore\n', ''))
        self.commit()
        self.assertEqual(self.package(), 1)
        self.assertFalse(self.output.exists())

    def test_misplaced_development_script_is_rejected(self):
        (self.root / 'tools/benchmark.py').write_text('development only\n')
        self.commit()
        self.assertEqual(self.package(), 1)
        self.assertFalse(self.output.exists())

    def test_forced_git_add_of_a_trace_in_tests_is_rejected(self):
        trace = 'tests/private.gtsw'
        (self.root / trace).write_bytes(b'synthetic trace')
        self.git('add', '-f', '--', trace)
        self.commit()
        self.assertEqual(self.package(), 1)
        self.assertFalse(self.output.exists())

    def test_includes_sdk_documentation_when_committed(self):
        name = 'capture/traceq/README.md'
        (self.root / name).write_text('Android SDK documentation\n')
        self.commit()
        self.assertEqual(self.package(), 0)
        with tarfile.open(self.output) as archive:
            self.assertEqual(archive.extractfile(name).read(), b'Android SDK documentation\n')

    def test_includes_traceq_skill_when_committed(self):
        skill_files = (
            'SKILL.md', 'agents/openai.yaml', 'references/analysis.md', 'references/capture.md',
        )
        skill = self.root / '.agents/skills/traceq'
        for name in skill_files:
            path = skill / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name + '\n')
        self.commit()
        self.assertEqual(self.package(), 0)
        with tarfile.open(self.output) as archive:
            for name in skill_files:
                member = f'.agents/skills/traceq/{name}'
                self.assertEqual(archive.extractfile(member).read(), (name + '\n').encode())

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

    def test_git_attributes_cannot_hide_a_tracked_product_module(self):
        name = 'rust/traceq-query/src/cli/find.rs'
        module = self.root / name
        module.parent.mkdir()
        module.write_text('mod query_support;\n')
        self.commit()
        self.assertEqual(self.package(), 0)
        original = self.output.read_bytes()
        (self.root / '.git/info/attributes').write_text(f'/{name} export-ignore\n')
        self.assertEqual(self.package(), 1)
        self.assertEqual(self.output.read_bytes(), original)

    def test_export_requires_an_explicit_ref(self):
        result = subprocess.run(
            [sys.executable, release.__file__, '--output', self.output], capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'explicit commit or tag', result.stderr)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
