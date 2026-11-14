"""Fixture inputs and independent expected semantics. Collectors do not import this module."""
MASK = (1 << 64) - 1
CASES = [
    dict(id='arith-low', function='arithmetic_branch', seed=0, count=1, initial=0),
    dict(id='arith-equal', function='arithmetic_branch', seed=3, count=1, initial=0),
    dict(id='arith-high', function='arithmetic_branch', seed=15, count=1, initial=0),
    dict(id='arith-wrap', function='arithmetic_branch', seed=MASK, count=1, initial=0),
    dict(id='memory-zero', function='memory_overlap', seed=0, count=1, initial=0),
    dict(id='memory-input', function='memory_overlap', seed=0x123456789abcdef0, count=1, initial=0),
    dict(id='loop-first', function='state_loop', seed=9, count=1, initial=0),
    dict(id='loop-state', function='state_loop', seed=9, count=7, initial=5),
    dict(id='loop-wrap', function='state_loop', seed=MASK, count=8, initial=2),
    dict(id='loop-scale', function='state_loop', seed=123, count=256, initial=7),
]

def subtract_flags(a, b):
    r = (a - b) & MASK
    overflow = bool((a ^ b) & (a ^ r) & (1 << 63))
    return ((r >> 63) << 31) | ((r == 0) << 30) | ((a >= b) << 29) | (overflow << 28)

def expected(case):
    """Hand-specified effects for owned assembly; no disassembler or collector used."""
    regs = {'x0': case['seed'], 'x2': case['count']}
    buf = bytearray(32)
    buf[16:24] = case['initial'].to_bytes(8, 'little')
    events = []
    def step(pc, updates=None, accesses=None):
        before = regs.copy()
        for key, value in (updates or {}).items():
            regs[key] = value & MASK
        events.append({'pc': pc, 'pre': before, 'post': regs.copy(), 'memory': accesses or []})
    def store(offset, size, value):
        value &= (1 << (8 * size)) - 1
        buf[offset:offset+size] = value.to_bytes(size, 'little')
        return [dict(rw='w', offset=offset, size=size, value=value)]
    def read(offset, size):
        value = int.from_bytes(buf[offset:offset+size], 'little')
        return value, [dict(rw='r', offset=offset, size=size, value=value)]
    if case['function'] == 'arithmetic_branch':
        step(0, {'x3': regs['x0'] + 7})
        step(4, {'x4': regs['x3'] ^ regs['x0']})
        step(8, {'x5': regs['x4'] - 9, 'nzcv': subtract_flags(regs['x4'], 9)})
        step(12)
        if regs['x4'] < 9:
            step(24, {'x6': regs['x4'] + 11})
        else:
            step(16, {'x6': regs['x5'] + 3})
            step(20)
        step(28, accesses=store(0, 8, regs['x6']))
        step(32, {'nzcv': subtract_flags(regs['x6'], 16)})
        step(36, {'x7': int(regs['x6'] > 16)})
        step(40, accesses=store(8, 4, regs['x7']))
        step(44, {'x0': regs['x6']})
        step(48)
    elif case['function'] == 'memory_overlap':
        step(0, {'x3': 0x1122})
        step(4, {'x3': 0x33441122})
        step(8, {'x3': regs['x3'] ^ regs['x0']})
        step(12, accesses=store(0, 8, regs['x3']))
        step(16, {'x4': 0xaabb})
        step(20, accesses=store(2, 2, regs['x4']))
        step(24, accesses=store(2, 2, regs['x4']))
        val, accesses = read(3, 1); step(28, {'x5': val}, accesses)
        val, accesses = read(0, 4); step(32, {'x6': val}, accesses)
        step(36, {'x7': int.from_bytes(regs['x6'].to_bytes(4, 'little'), 'big')})
        step(40, accesses=store(8, 4, regs['x7']))
        step(44, {'x0': regs['x5'] + regs['x6']})
        step(48)
    elif case['function'] == 'state_loop':
        val, accesses = read(16, 8); step(0, {'x3': val}, accesses)
        step(4, {'x3': regs['x3'] + 1})
        step(8, accesses=store(16, 8, regs['x3']))
        step(12, {'x4': 0})
        for _ in range(case['count']):
            step(16, {'x0': regs['x0'] + regs['x3']})
            step(20, {'x0': regs['x0'] ^ regs['x4']})
            step(24, {'x4': regs['x4'] + 1})
            step(28, {'nzcv': subtract_flags(regs['x4'], regs['x2'])})
            step(32)
        step(36, accesses=store(0, 8, regs['x0']))
        step(40)
    else:
        raise ValueError(case['function'])
    # Post-RET state is outside the declared function scope.
    events[-1]['post'] = {}
    return {'events': events, 'result': regs['x0'], 'buffer': buf.hex()}
