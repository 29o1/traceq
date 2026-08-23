'use strict';

// traceq real-device validation, capture B: trace one large libc memcpy.
// Fires only when n >= MIN_N so the trace contains the SIMD copy loop.

const CONFIG = {
    gumPath: '/data/local/tmp/libGumTrace.so',
    // Replace com.example.tracefixture with the package you control.
    outputPath: '/data/data/com.example.tracefixture/files/gt_memcpy.log',
    mode: 1
};
const MIN_N = 4096;

let installed = false;
let traced = false;

function loadGumTrace() {
    const dlopenAddress = Module.findExportByName(null, 'dlopen');
    const dlsymAddress = Module.findExportByName(null, 'dlsym');
    const dlopen = new NativeFunction(dlopenAddress, 'pointer', ['pointer', 'int']);
    const dlsym = new NativeFunction(dlsymAddress, 'pointer', ['pointer', 'pointer']);
    const handle = dlopen(Memory.allocUtf8String(CONFIG.gumPath), 2);
    if (handle.isNull()) throw new Error('Unable to load ' + CONFIG.gumPath);
    function resolve(name) {
        const address = dlsym(handle, Memory.allocUtf8String(name));
        if (address.isNull()) throw new Error('Missing GumTrace export: ' + name);
        return address;
    }
    return {
        init: new NativeFunction(resolve('init'), 'void', ['pointer', 'pointer', 'int', 'pointer']),
        run: new NativeFunction(resolve('run'), 'void', []),
        unrun: new NativeFunction(resolve('unrun'), 'void', [])
    };
}

const target = Module.findExportByName('libc.so', 'memcpy');
if (target === null) throw new Error('memcpy not found');
const gum = loadGumTrace();
const options = Memory.alloc(8);
options.writeU64(CONFIG.mode);
installed = true;

console.log('Hooking libc.so!memcpy at ' + target + ' (n>=' + MIN_N + ')');
Interceptor.attach(target, {
    onEnter(args) {
        if (traced) return;
        if (args[2].toUInt32() < MIN_N) return;
        traced = true;
        this.tracing = true;
        this.n = args[2].toUInt32();
        gum.init(
            Memory.allocUtf8String('libc.so'),
            Memory.allocUtf8String(CONFIG.outputPath),
            0,
            options
        );
        gum.run();
        console.log('GumTrace started on tid=' + Process.getCurrentThreadId() + ' n=' + this.n);
    },
    onLeave() {
        if (!this.tracing) return;
        gum.unrun();
        console.log('GumTrace stopped: ' + CONFIG.outputPath);
    }
});
