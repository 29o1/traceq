#!/usr/bin/env python3
"""Recorded, bounded adapter over the actual traceq CLI; copied into task packs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
COMMANDS = frozenset({'stat', 'boundaries', 'instructions', 'context', 'reg-state', 'mem-access',
                      'mem-state', 'last-writers', 'find-pc', 'find-value'})
ROW_COMMANDS = frozenset({'boundaries', 'instructions', 'context', 'mem-access', 'find-pc', 'find-value'})
DEFAULT_ROWS = 40
MAX_ROWS = 256
MEMORY_MAX_ROWS = 4096
FORBIDDEN_OPTIONS = frozenset({'-o', '--all'})
CONTEXT_COLUMNS = ('ev', 'pc', 'off', 'opcode', 'text', 'focus', 'completion', 'gap',
                   'gap_reasons', 'register_set', 'pre', 'post', 'memory', 'scope_exit', 'scope_reentry')
MEM_ACCESS_COLUMNS = ('ev', 'pc', 'off', 'rw', 'addr', 'size', 'known', 'val')
COMPACT_MEMORY_GUIDANCE = ('Profile2 mem-access supports optional --compact --json: columns-v1 arrays with meta.columns '
                           'and rw-indexed meta.value_sources. Each page retains all access facts, unknown nulls, '
                           'pagination and full-input validation. Resolve row fields and value sources using meta.columns and meta.value_sources. Default named JSON; tiny pages may grow. Mixed write-source pages '
                           'return named rows with meta.compact_fallback=mixed_write_sources to preserve provenance.')
METADATA_GUIDANCE = ('Reuse fields already present in results.meta for the same unchanged trace (e.g. code_base/data_base/scope). '
                     'Use stat for missing metadata or detailed format/profile/gap diagnostics. '
                     'Keep addresses tied to their trace; unknown or absent fields are not zero.')
CONTEXT_GUIDANCE = ('Profile2 context includes PC/opcode/disassembly, pre/post registers, real memory accesses, boundaries, gap and completion. '
                    'Reuse instruction facts for events already returned by context. '
                    'For a small region needing state, start with a bounded window, e.g. --at-ev 0 --before 0 --after 39 --limit 40. '
                    'Use instructions for wider code-only navigation; context covers only its returned events. '
                    'Repeat --at-ev; --before 0 --after 0 selects points in one validated scan. '
                    'Default registers vary by instruction. Repeated --reg selects the same explicit views on every row and replaces defaults; '
                    'include all needed operand/changed views when merging context with extra states, or use a small point-only batch. '
                    'Reuse pre/post at the exact event; null post means unobserved completion. '
                    'Pagination counts describe query rows; capture metadata describes the full stream through END/suffix.')
MEMORY_CHECKPOINT_GUIDANCE = ('Profile2 mem-state: one --range B,L plus repeated --checkpoint E:pre or E:post shares one full validated scan. '
                             'Do not mix with --at-ev/--phase. Request order and duplicates are retained. '
                             'checkpoints-v1 data groups identify ev/phase/pc/instruction_completion/gap and contain byte rows. '
                             '--limit/--offset apply bytes per checkpoint; at most 64 checkpoints and 4096 returned byte cells in total, no clamping. '
                             'meta.total/shown count aggregate byte cells; meta.next advances all groups together. '
                             'An unobserved post is unknown; pre values and global gaps retain their normal semantics. '
                             'With --json, repeat --range to group disjoint or overlapping ranges in one scan. '
                             'ranges-checkpoints-v1 returns range_base, range_size and checkpoints in each range group; byte limits apply per range and the whole page cap is 4096 cells.')
COMPACT_STATE_GUIDANCE = ('Profile2 mem-state supports optional --compact --json for single/batch snapshots: hex-v1 frames '
                         'contain address/size/data_hex and per-byte sources. null source is unknown (00 placeholder); '
                         '[observed_ev,pc_index] is known, with PCs in page-local meta.pc_table. '
                         'Limits/counts still measure bytes; all per-byte observations, checkpoint fields, gaps and full validation remain. '
                         'Resolve each known byte through its source pair and meta.pc_table. Default named JSON; tiny pages may grow.')

BYTE_RUN_GUIDANCE = 'Profile2 find-value FILE --bytes HEX supports optional --across-events: match1..64 known bytes at adjacent increasing addresses across events. With --read/--write, known disjoint opposite accesses may be skipped; unknowns, gaps, overlaps and selected address/direction changes break runs. This searches historical recorded access sequences, not current memory or last writers. ev/access_index/byte_offset identify the first byte; last_ev/last_access_index identify the last byte. Hits are ordered by completion byte, then pattern order; pagination is per pattern. An unpositioned gap retains only intra-instruction matches without skipped accesses. --context N adds bounded endpoint windows for the first hit. Default --bytes remains within one instruction. Reordered stores can yield no hit despite complete content. Locate/disambiguate a shorter prefix, use mem-access --range B,L to choose the last required observation E, then mem-state --range B,L --checkpoint E:post before later gaps.'


def expand_context(document):
    """Expand optional context columns for local analysis without changing tool stdout.

    Rows use meta.columns; pre/post cells use that row's page-local register set.
    An entire null post means unobserved completion, distinct from unknown cells.
    """
    if not isinstance(document, dict) or not isinstance(document.get('meta'), dict):
        return document
    meta = document['meta']
    if 'context_format' not in meta:
        return document
    if meta['context_format'] != 'columns-v1':
        raise ValueError('Unsupported context_format')
    columns, sets = meta.get('columns'), meta.get('register_sets')
    if not isinstance(columns, list) or any(not isinstance(c, str) for c in columns) or \
            len(columns) != len(CONTEXT_COLUMNS) or set(columns) != set(CONTEXT_COLUMNS):
        raise ValueError('Invalid context columns')
    if not isinstance(sets, list) or not isinstance(document.get('data'), list):
        raise ValueError('Invalid context register_sets or data')
    for names in sets:
        if not isinstance(names, list) or any(not isinstance(n, str) or not n for n in names) or len(set(names)) != len(names):
            raise ValueError('Invalid context register names')
    rows = []
    for cells in document['data']:
        if not isinstance(cells, list) or len(cells) != len(columns):
            raise ValueError('Invalid context row length')
        row = dict(zip(columns, cells))
        ref = row.pop('register_set')
        if type(ref) is not int or not 0 <= ref < len(sets):
            raise ValueError('Invalid context register_set reference')
        names = sets[ref]
        for phase in ('pre', 'post'):
            values = row[phase]
            if values is None and phase == 'post':
                continue
            if not isinstance(values, list) or len(values) != len(names) or \
                    any(v is not None and not isinstance(v, str) for v in values):
                raise ValueError('Invalid context register values')
            row[phase] = dict(zip(names, values))
        rows.append(row)
    return {**document, 'data': rows,
            'meta': {k: v for k, v in meta.items() if k not in {'context_format', 'columns', 'register_sets'}}}


def expand_mem_access(document):
    """Restore named access rows, including the source label hoisted by rw."""
    if not isinstance(document, dict) or not isinstance(document.get('meta'), dict):
        return document
    meta = document['meta']
    if 'mem_access_format' not in meta:
        if meta.get('compact_fallback') == 'mixed_write_sources':
            return {**document, 'meta': {k: v for k, v in meta.items() if k != 'compact_fallback'}}
        return document
    if meta['mem_access_format'] != 'columns-v1':
        raise ValueError('Unsupported mem_access_format')
    columns, sources = meta.get('columns'), meta.get('value_sources')
    if not isinstance(columns, list) or len(columns) != len(MEM_ACCESS_COLUMNS) or \
            any(not isinstance(c, str) for c in columns) or set(columns) != set(MEM_ACCESS_COLUMNS):
        raise ValueError('Invalid memory access columns')
    if not isinstance(sources, dict) or set(sources) != {'r', 'w'} or \
            any(not isinstance(v, str) for v in sources.values()) or not isinstance(document.get('data'), list):
        raise ValueError('Invalid memory access value_sources or data')
    rows = []
    for cells in document['data']:
        if not isinstance(cells, list) or len(cells) != len(columns):
            raise ValueError('Invalid memory access row length')
        row = dict(zip(columns, cells))
        if not isinstance(row['rw'], str) or row['rw'] not in sources:
            raise ValueError('Invalid memory access rw')
        row['value_source'] = sources[row['rw']]
        rows.append(row)
    return {**document, 'data': rows,
            'meta': {k: v for k, v in meta.items() if k not in {'mem_access_format', 'columns', 'value_sources'}}}


def expand_mem_state(document):
    """Restore every byte and source from compact memory snapshots."""
    if not isinstance(document, dict) or not isinstance(document.get('meta'), dict):
        return document
    meta = document['meta']
    if 'mem_state_format' not in meta:
        return document
    with_access_source = meta['mem_state_format'] == 'hex-v2'
    columns = ['observed_ev', 'pc_index']
    if with_access_source:
        columns.extend(['observed_rw', 'observed_access_index'])
    if meta['mem_state_format'] not in ('hex-v1', 'hex-v2') or meta.get('source_columns') != columns:
        raise ValueError('Unsupported memory state format or source columns')
    table = meta.get('pc_table')
    if not isinstance(table, list) or len(table) > 4096 or not isinstance(document.get('data'), list):
        raise ValueError('Invalid memory state PC table or data')

    def address(value):
        if not isinstance(value, str) or not value.startswith('0x') or not value[2:] or \
                any(c not in '0123456789abcdef' for c in value[2:]) or int(value[2:], 16) >= 1 << 64:
            raise ValueError('Invalid memory state address')
        return int(value[2:], 16)

    for pc in table:
        if not isinstance(pc, dict) or set(pc) != {'pc', 'pc_offset'}:
            raise ValueError('Invalid memory state PC entry')
        address(pc['pc']); address(pc['pc_offset'])

    def expand(frame):
        if not isinstance(frame, dict) or set(frame) != {'address', 'size', 'data_hex', 'sources'}:
            raise ValueError('Invalid memory state frame')
        base, size = address(frame['address']), frame['size']
        text, sources = frame['data_hex'], frame['sources']
        if type(size) is not int or not 0 <= size <= 4096 or base + size >= 1 << 64 or \
                not isinstance(text, str) or len(text) != 2 * size or \
                any(c not in '0123456789abcdef' for c in text) or \
                not isinstance(sources, list) or len(sources) != size:
            raise ValueError('Invalid memory state bytes or source count')
        raw = bytes.fromhex(text)
        rows = []
        for i, source in enumerate(sources):
            row = {'address': hex(base+i), 'known': source is not None}
            if source is None:
                if raw[i] != 0:
                    raise ValueError('Unknown memory byte requires zero placeholder')
                row.update(value=None, writer_seq=None, pc=None)
            else:
                if not isinstance(source, list) or len(source) != len(columns) or \
                        type(source[0]) is not int or not 0 <= source[0] < 1 << 64 or \
                        type(source[1]) is not int or not 0 <= source[1] < len(table):
                    raise ValueError('Invalid memory state observation source')
                row.update(value=hex(raw[i]), observed_ev=source[0], **table[source[1]])
                if with_access_source:
                    direction, index = source[2:]
                    if direction not in ('r', 'w') or type(index) is not int or not 0 <= index < 4:
                        raise ValueError('Invalid memory state access source')
                    row.update(observed_rw=direction, observed_access_index=index)
            rows.append(row)
        return rows

    def expand_checkpoints(groups):
        if not isinstance(groups, list):
            raise ValueError('Invalid memory checkpoints')
        rows = []
        for group in groups:
            if not isinstance(group, dict) or 'data' not in group:
                raise ValueError('Invalid memory checkpoint group')
            rows.append({**group, 'data': expand(group['data'])})
        return rows

    if meta.get('memory_format') == 'ranges-checkpoints-v1':
        rows = []
        for group in document['data']:
            if not isinstance(group, dict) or 'data' not in group:
                raise ValueError('Invalid memory range group')
            rows.append({**group, 'data': expand_checkpoints(group['data'])})
    elif meta.get('memory_format') == 'checkpoints-v1':
        rows = expand_checkpoints(document['data'])
    else:
        if len(document['data']) != 1:
            raise ValueError('Single memory snapshot requires one frame')
        rows = expand(document['data'][0])
    return {**document, 'data': rows,
            'meta': {k: v for k, v in meta.items() if k not in {'mem_state_format', 'source_columns', 'pc_table'}}}


def capabilities():
    return {'allowed_commands': sorted(COMMANDS),
            'row_limits': {'commands': sorted(ROW_COMMANDS), 'default': DEFAULT_ROWS, 'minimum': 1, 'maximum': MAX_ROWS},
            'memory_state_limits': {'commands': ['mem-state'], 'unit': 'bytes', 'default': DEFAULT_ROWS,
                                    'minimum': 1, 'maximum': MEMORY_MAX_ROWS},
            'disallowed_options': sorted(FORBIDDEN_OPTIONS),
            'batch_context': CONTEXT_GUIDANCE,
            'memory_checkpoints': MEMORY_CHECKPOINT_GUIDANCE,
            'compact_context': 'Optional --compact --json: columns-v1, page-local register_sets; Resolve page-local fields and register sets using meta.columns and meta.register_sets. Default named JSON; tools.context_format can select columns-v1. Tiny pages may grow.',
            'compact_memory_access': COMPACT_MEMORY_GUIDANCE,
            'compact_memory_state': COMPACT_STATE_GUIDANCE,
            'memory_byte_runs': BYTE_RUN_GUIDANCE,
            'metadata_reuse': METADATA_GUIDANCE,
            'rejections': 'Rejected attempts are recorded; limits are never silently clamped.',
            'trace_formats': 'Structured GTSW/GTSC. Execution-state queries use profile2; last-writers retains structured write-evidence profile1. Historical text/GTB2 and its command families are retired; use a frozen older CLI for archived data.'}


def main():
    started_ns, started = time.time_ns(), time.monotonic()
    args = sys.argv[1:]
    trace_id = args[0] if args else None
    command = args[1] if len(args) > 1 else None
    options = args[2:]
    backend = None
    context_format = None

    def finish(stdout, stderr, status, origin, launched, argv=None, partial_stdout=b''):
        finished_ns, seconds = time.time_ns(), time.monotonic() - started
        log_dir = HERE / 'queries'
        log_dir.mkdir(exist_ok=True)
        key = str(finished_ns) + '-' + str(os.getpid())
        (log_dir / (key + '.stdout')).write_bytes(stdout)
        (log_dir / (key + '.stderr')).write_bytes(stderr)
        if partial_stdout:
            (log_dir / (key + '.partial.stdout')).write_bytes(partial_stdout)
        record = {'log_schema': 2, 'id': key, 'trace': trace_id, 'command': command,
                  'requested_options': args[2:], 'options': options, 'argv': argv,
                  'query_backend': backend, 'configured_context_format': context_format,
                  'context_format': ('columns-v1' if '--compact' in options else 'named') if command == 'context' and launched else None,
                  'launched_cli': launched, 'failure_origin': origin,
                  'started_ns': started_ns, 'finished_ns': finished_ns, 'seconds': seconds,
                  'returncode': status, 'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr)}
        record['partial_stdout_bytes'] = len(partial_stdout)
        with (log_dir / 'calls.jsonl').open('a') as out:
            out.write(json.dumps(record) + '\n')
        sys.stdout.buffer.write(stdout)
        sys.stderr.buffer.write(stderr)
        return status

    def reject(message, code='ARGUMENT'):
        payload = {'error': {'code': code, 'origin': 'adapter', 'message': message,
                             'query_policy': capabilities()}}
        return finish((json.dumps(payload, separators=(',', ':')) + '\n').encode(), b'', 2, 'adapter', False)

    try:
        config = json.loads((HERE / 'tools.json').read_text())
        traces = config['traces']
        executable = config['traceq']
        backend = config.get('query_backend')
        context_format = config.get('context_format')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return reject('Invalid tools.json: ' + str(exc), 'ADAPTER_CONFIG')
    if not isinstance(traces, dict) or not isinstance(executable, str):
        return reject('tools.json requires a traceq path and traces object', 'ADAPTER_CONFIG')
    if len(args) < 2 or trace_id not in traces:
        return reject('Use python3 query.py TRACE_ID COMMAND [options]; available trace IDs: ' + ', '.join(traces))
    if command not in COMMANDS or any(o in FORBIDDEN_OPTIONS for o in options):
        return reject('Use an allowed read query with bounded --limit and shell redirection for output.')
    trace = traces[trace_id]
    if not isinstance(trace, dict) or not isinstance(trace.get('path'), str):
        return reject('Each trace requires a path', 'ADAPTER_CONFIG')
    if backend is not None and (not isinstance(backend, str) or backend not in {'cpp', 'rust'}):
        return reject('query_backend must be cpp or rust', 'ADAPTER_CONFIG')
    if context_format is not None and (not isinstance(context_format, str) or context_format not in {'named', 'columns-v1'}):
        return reject('context_format must be named or columns-v1', 'ADAPTER_CONFIG')
    maximum = MEMORY_MAX_ROWS if command == 'mem-state' else MAX_ROWS if command in ROW_COMMANDS else None
    if maximum is not None and '--help' not in options:
        if options.count('--limit') > 1:
            return reject('Specify --limit once; maximum is ' + str(maximum))
        if '--limit' not in options:
            options += ['--limit', str(DEFAULT_ROWS)]
        try:
            literal = options[options.index('--limit') + 1]
            # mem-state previously passed explicit limits directly to the CLI;
            # retain its valid decimal, hex and leading-zero octal forms.
            base = (16 if literal.lower().startswith('0x') else 8 if len(literal) > 1 and literal[0] == '0' else 10) if command == 'mem-state' else 10
            limit = int(literal, base)
        except (ValueError, IndexError):
            return reject('--limit requires an integer from 1 to ' + str(maximum))
        if not 1 <= limit <= maximum:
            return reject('Per-query --limit must be 1..' + str(maximum) + '; page or select evidence.')
    if command == 'context' and context_format == 'columns-v1' and '--help' not in options and '-h' not in options:
        if '--compact' not in options:
            options += ['--compact']
        if '--json' not in options:
            options += ['--json']
    argv = [executable, command, trace['path'], *options]
    execution = {}
    if backend is not None:
        execution['env'] = {**os.environ, 'TRACEQ_QUERY_BACKEND': backend}
    try:
        result = subprocess.run(argv, capture_output=True, timeout=90, **execution)
    except OSError as exc:
        payload = {'error': {'code': 'QUERY_LAUNCH', 'origin': 'launch', 'message': str(exc)}}
        return finish((json.dumps(payload) + '\n').encode(), b'', 127, 'launch', False, argv)
    except subprocess.TimeoutExpired as exc:
        payload = {'error': {'code': 'QUERY_TIMEOUT', 'origin': 'timeout', 'message': 'traceq exceeded 90 seconds'}}
        return finish((json.dumps(payload) + '\n').encode(), exc.stderr or b'', 124, 'timeout', True, argv, exc.stdout or b'')
    return finish(result.stdout, result.stderr, result.returncode, 'cli' if result.returncode else None, True, argv)


if __name__ == '__main__':
    sys.exit(main())
