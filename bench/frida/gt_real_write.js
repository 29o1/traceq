'use strict';

// traceq real-device validation: trace one native write() path.
// Primary target: libjavacore.so Java_libcore_io_Linux_writeBytes (JNI wrapper,
// exercises memcpy loop + syscall path). Fallback: libc.so write.

const CONFIG = {
    gumPath: '/data/local/tmp/libGumTrace.so',
    // Replace com.example.tracefixture with the package you control.
    outputPath: '/data/data/com.example.tracefixture/files/gt_write.log',
    mode: 1
};

let installed = false;
let traced = false;

function loadGumTrace() {
    const dlopenAddress = Module.findExportByName(null, 'dlopen');
    const dlsymAddress = Module.findExportByName(null, 'dlsym');
    if (dlopenAddress === null || dlsymAddress === null) throw new Error('dlopen/dlsym unavailable');

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

function pickTarget() {
    const jni = Module.findExportByName('libjavacore.so', 'Java_libcore_io_Linux_writeBytes');
    if (jni !== null) return { module: 'libjavacore.so', address: jni, label: 'Java_libcore_io_Linux_writeBytes' };
    const w = Module.findExportByName('libc.so', 'write');
    if (w !== null) return { module: 'libc.so', address: w, label: 'write' };
    throw new Error('No usable target export found');
}

function install() {
    if (installed) return;
    const target = pickTarget();
    const gum = loadGumTrace();
    const options = Memory.alloc(8);
    options.writeU64(CONFIG.mode);
    installed = true;

    console.log('Hooking ' + target.module + '!' + target.label + ' at ' + target.address);
    Interceptor.attach(target.address, {
        onEnter() {
            if (traced) return;
            traced = true;
            this.tracing = true;
            gum.init(
                Memory.allocUtf8String(target.module),
                Memory.allocUtf8String(CONFIG.outputPath),
                0,
                options
            );
            gum.run();
            console.log('GumTrace started on tid=' + Process.getCurrentThreadId());
        },
        onLeave() {
            if (!this.tracing) return;
            gum.unrun();
            console.log('GumTrace stopped: ' + CONFIG.outputPath);
        }
    });
}

install();
