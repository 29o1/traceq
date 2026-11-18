"""Check the real capture CMake graph without compiling or loading an SDK."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(all(shutil.which(tool) for tool in ('cmake', 'make', 'cc')),
                     'CMake, make and a C compiler are required')
class CaptureBuild(unittest.TestCase):
    def run_command(self, *args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def check_manifest_rebuild(self, package):
        with tempfile.TemporaryDirectory(prefix='traceq-capture-build-') as directory:
            root = Path(directory)
            capture = root / 'capture/traceq'
            (capture / 'cmake').mkdir(parents=True)
            shutil.copy2(ROOT / 'capture/traceq/CMakeLists.txt', capture / 'CMakeLists.txt')
            # Only the Cargo dependency graph is under test. No native Gum
            # archive is built, linked or represented as a qualified SDK.
            (capture / 'cmake/TraceqGum.cmake').write_text('')
            for name in ('traceq-capture', 'traceq-core', 'traceq-observer'):
                (root / 'rust' / name / 'src').mkdir(parents=True)
                (root / 'rust' / name / 'Cargo.toml').write_text('# initial manifest\n')
                (root / 'rust' / name / 'src/lib.rs').write_text('// initial source\n')
            for name in ('Cargo.toml', 'Cargo.lock'):
                (root / 'rust' / name).write_text('# workspace\n')
            (root / 'tools').mkdir()
            (root / 'tools/rust_workspace.py').write_text('''from pathlib import Path
r = Path(__file__).resolve().parents[1]
p = r / '.deps/rust/target/aarch64-linux-android/release/libtraceq_capture.a'
p.parent.mkdir(parents=True, exist_ok=True)
count = int(p.read_text()) + 1 if p.exists() else 1
p.write_text(str(count))
''')
            build = root / 'build'
            # Exercise the Android branch as a graph; the selected build target
            # only invokes the compiler stub, so it needs no Android toolchain.
            self.run_command('cmake', '-S', str(capture), '-B', str(build),
                             '-G', 'Unix Makefiles', '-DANDROID=ON',
                             '-DANDROID_ABI=arm64-v8a')
            command = ('cmake', '--build', str(build), '--target', 'traceq_rust_capture')
            artifact = root / '.deps/rust/target/aarch64-linux-android/release/libtraceq_capture.a'
            self.run_command(*command)
            self.assertEqual(artifact.read_text(), '1')
            self.run_command(*command)
            self.assertEqual(artifact.read_text(), '1', 'unchanged inputs must stay up to date')
            time.sleep(1.05)  # Also works with generators using whole-second mtimes.
            (root / 'rust' / package / 'Cargo.toml').write_text('# changed dependency manifest\n')
            self.run_command(*command)
            self.assertEqual(artifact.read_text(), '2', package + ' left a stale SDK archive')
            self.run_command(*command)
            self.assertEqual(artifact.read_text(), '2')

    def test_core_manifest_rebuilds_capture(self):
        self.check_manifest_rebuild('traceq-core')

    def test_observer_manifest_rebuilds_capture(self):
        self.check_manifest_rebuild('traceq-observer')


if __name__ == '__main__':
    unittest.main()
