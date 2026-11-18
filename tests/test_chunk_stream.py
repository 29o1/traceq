"""Focused packed transport regression; no device or capture SDK dependency."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
class ChunkStreamChecks(unittest.TestCase):
    def test_bounded_field_decoding(self):
        with tempfile.TemporaryDirectory(prefix='traceq-chunks-') as directory:
            binary=Path(directory)/'check-chunks'
            command=[*shlex.split(os.environ.get('CXX','c++')),'-std=c++17','-O2','-I'+str(ROOT/'cli/include'),str(ROOT/'tests/chunk_stream.cpp'),'-o',str(binary)]
            subprocess.run(command,check=True,capture_output=True,text=True)
            result=subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=30)
            self.assertIn('PASS',result.stdout)
if __name__=='__main__':unittest.main()
