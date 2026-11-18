"""Build a validation-only C ABI adapter to the Rust product classifier."""
import os
from pathlib import Path
import platform
import subprocess
ROOT=Path(__file__).resolve().parents[2]
def archive():
    target=ROOT/'.deps/rust/target/release'
    source=Path(__file__).with_suffix('.rs')
    out=ROOT/'build/traceq-classifier/libtraceq_classifier.a'
    inputs=[source,target/'libtraceq_capture.rlib']
    if not out.exists() or any(p.stat().st_mtime_ns>out.stat().st_mtime_ns for p in inputs):
        host={'arm64':'aarch64','x86_64':'x86_64'}[platform.machine()]+'-apple-darwin'
        local=ROOT/'.deps/rust/toolchain'
        toolchain=Path(os.environ.get('TRACEQ_RUST_TOOLCHAIN',str(local if local.exists() else Path.home()/'.rustup/toolchains'/('1.95.0-'+host))))
        rustc=toolchain/'bin/rustc'
        version=subprocess.check_output([rustc,'--version'],text=True)
        if not version.startswith('rustc 1.95.0 '):raise RuntimeError('fixed rustc 1.95.0 required')
        out.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run([rustc,source,'--edition=2024','--crate-type=staticlib','-C','opt-level=2','-C','panic=unwind',
                        '--extern','traceq_capture='+str(inputs[1]),
                        '-L','dependency='+str(target/'deps'),'-o',out],check=True,timeout=60)
    return out
