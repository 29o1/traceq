# traceq — Query ARM64 Instruction Traces

[简体中文](README.zh-CN.md)

traceq converts ARM64 instruction logs produced by
[GumTrace](https://github.com/lidongyooo/GumTrace) into compact, queryable `.gtb`
files. It answers questions about PCs, values, memory, calls, loops, run
differences, and taint through bounded text or JSON Lines output.

> Let an agent query an execution trace like a database instead of stuffing a
> multi-gigabyte text log into its context window.

```text
GumTrace ──capture──> trace.log ──gt import──> trace.gtb
                                                   │
                         gt find-* / mem-* / taint / diff / fold
```

GumTrace handles live capture. traceq handles import, compression, queries, and
agent-facing output. They are independent projects; this repository does not
bundle GumTrace source or binaries. traceq is currently a 0.x project: the CLI
output contract is covered by tests, while the `libtraceq` C++ API and `.gtb`
format may still evolve.

Only trace and analyze devices, processes, and binaries that you own or are
authorized to inspect. Instruction traces may contain addresses, register and
memory values, and call arguments. Review trace data separately before making
it public.

## Quick Start

Requirements: make and a C++17 compiler such as clang++ or g++. Python 3 is
needed only for benchmarks.

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make all test

# Exercise the complete product path with a public real-device fixture.
./cli/gt import bench/traces/memcpy_device.log -o /tmp/memcpy.gtb
./cli/gt stat /tmp/memcpy.gtb
./cli/gt export --format jsonl --limit 5 /tmp/memcpy.gtb
```

Optionally install `gt` for the current user:

```bash
make install                         # installs to ~/.local/bin/gt by default
export PATH="$HOME/.local/bin:$PATH" # if the directory is not already in PATH
gt --help
```

## Common Queries

| Goal | Command |
|---|---|
| Import a GumTrace log | `gt import trace.log -o trace.gtb` |
| Inspect trace statistics | `gt stat trace.gtb` |
| Export an event window | `gt export --format compact\|jsonl\|upstream --from E --to E --limit N trace.gtb` |
| Find executed PCs | `gt find-pc (--addr A... \| --off O... [--mod M]) [--from E --to E] trace.gtb` |
| Find runtime values | `gt find-value V [--read\|--write] [--from E --to E] trace.gtb` |
| Find memory accesses | `gt mem-access (--addr A... \| --range B,L) [--read\|--write] [--last N] trace.gtb` |
| Reconstruct known memory | `gt mem-state --range B,L --at-ev E [--qword] trace.gtb` |
| Inspect call arguments | `gt func-args --func F [--nth N] [--limit L] trace.gtb` |
| Rebuild a call tree | `gt calltree --func F --depth D trace.gtb` |
| Run forward/backward taint | `gt taint (--seed-addr A\|--seed-reg R\|--seed-q Q\|--seed-nzcv) [--back] trace.gtb` |
| Compare two executions | `gt diff a.gtb b.gtb` |
| Detect repeated loops | `gt fold --top N trace.gtb` |

Every subcommand supports `--help`. `gt` intentionally has no `record`
subcommand: GumTrace captures live execution, then `gt import` brings the log
into the query pipeline.

## Agent Output Contract

- Query commands support `--json`; `export` uses `--format jsonl`.
- Addresses, register values, and SIMD values are hex strings. Event indices
  and counts are decimal numbers.
- Query output is bounded by default. Pass `--limit` explicitly to bound an
  `export` window.
- The final line is always a `meta` record. When output is truncated, `next` is
  a directly executable continuation command.
- Event results include both the `.gtb` event index (`ev`) and the original
  imported log line (`line`).

Example:

```jsonl
{"ev":0,"line":1,"mod":"libc.so","off":"0x57490","txt":"b.hi #0x77df89c554","rd":[],"wr":[]}
{"meta":{"truncated":true,"total":517,"shown":1,"next":"gt export --from 1 --limit 1 --format jsonl trace.gtb"}}
```

Useful structured fields:

- `find-value` returns `kind/rw/reg` or `kind/rw/addr/size`, so callers do not
  need to parse a textual lane description.
- `mem-access` reports access width; reads also include `prior_write_ev` for
  the same address when one was observed.
- `mem-state --qword` emits 8-byte little-endian cells; unknown values are
  `null`.
- `diff` distinguishes execution indices from the real event indices on each
  side. `fold` reports both execution and event ranges.
- `taint` explicitly reports `partial`, its seed, edges, and final register and
  memory-address sets.

## Design

The core data model separates the **static site table from the dynamic event
stream**. During import, module names, PCs, offsets, mnemonics, and operand plans
are deduplicated by address in `SiteArena`. Individual executions and values are
stored in a varint/delta event stream.

| Event | Encoding | Purpose |
|---|---|---|
| EXEC | zigzag delta(site_id) | Executes a static site; hot loops commonly use one byte |
| REGW | tag + reg + zigzag delta | Register writes; the reader also accepts the legacy inline encoding |
| MEM | flags + address/value delta | Memory reads and writes with observed values |
| MEMW_NV | no stored value | Reuses a value already present in a register event |
| CALL/RET/SVC | symbol + argument delta | Calls, returns, and system calls |
| RDVAL/SIMDV | name + delta or 16B | Explicitly observed integer and SIMD values |
| VERBATIM | length + raw bytes | Preserves input lines that cannot be classified |
| CALL2 | symbol + argument count + delta | Upstream call lines with 0–8 arguments |

Integer register values recoverable from write history are not stored twice;
values explicitly observed in the source log are retained. The footer records
counts, the stop reason, and input dialect. Imported LF and CRLF logs can be
reproduced byte-for-byte with `gt export --format upstream`. Unknown input forms
become `VERBATIM` events instead of being silently discarded.

Queries load the `.gtb` event buffer and scan it sequentially. There is no
database ingestion or index-building step. In the intended agent workflow,
query time is normally much smaller than one model-reasoning turn, while an
index would add build time, storage, and dependencies.

## Testing

```bash
make test
```

The product tests exercise the real import/query path through `import_mem`.
Coverage includes CRLF, VERBATIM records, non-canonical hex, JNI calls, 128-bit
SIMD, hexdumps, byte-exact replay, deterministic import, resource guards,
queries, taint, diff, and output pagination. GitHub Actions runs the same suite
on Linux and macOS.

## Benchmarks

`bench/run.py` treats the shipping `gt` executable as an external process. Its
measurements therefore include the startup, import, export, and query costs paid
by an actual user.

```bash
make report
python3 bench/run.py run --repeat 5
python3 bench/run.py run bench/private/your-trace.log
python3 bench/run.py compare OLD/report.json NEW/report.json
```

Each trace has two correctness gates: repeated imports must produce identical
`.gtb` bytes, and an `upstream` export must reproduce the source log byte for
byte. Reports also record import time, size, and min/median/max query timings.
Any correctness-gate failure invalidates the report and returns a non-zero exit
status.

The public repository includes two narrow real-device traces captured from an
author-controlled test app:

| File | Purpose |
|---|---|
| `memcpy_device.log` | A libc memcpy SIMD copy loop with NZCV activity |
| `write_device.log` | A short write path and small-input boundary case |

See [`bench/traces/README.md`](bench/traces/README.md) for their provenance and
review scope. Third-party application traces are not published. Keep local-only
logs under the ignored `bench/private/` directory. Generated reports contain a
host fingerprint and should also be reviewed before publication.

Results from the early synthetic corpus and a private 112 MB real-device log
remain available only as historical records under
[`bench/reports/historical/`](bench/reports/historical/). Their source data is
not public, so they are not presented as a reproducible performance promise on
this page.

## Known Limitations

- traceq consumes GumTrace text logs; it does not perform live capture.
- Queries use sequential scans. An index should be considered only if measured
  workloads show that scanning has become a real bottleneck.
- The upstream text format may merge some pure-store instructions into the next
  physical line. Import and upstream export preserve this behavior.
- `--max-bytes` limits the encoded event stream and stops at an input-line
  boundary. It is not a strict final-file-size limit: the site table and footer
  are still appended.
- The project is at 0.x; the `.gtb` format and C++ API do not yet promise
  long-term ABI stability.

## Repository Layout

```text
cli/                         libtraceq, the gt CLI, and product tests
  include/traceq/            public C++ headers
  src/                       import, GTB codec, expansion, queries, and CLI
  tests/test_main.cpp        tests through the real product path

bench/                       black-box benchmarks; never links product code
  run.py                     correctness gates, timings, and report comparison
  traces/                    reviewed public real-device fixtures
  private/                   local private traces; git-ignored
  frida/                     Frida templates for controlled trace capture
  reports/historical/        archived results that are no longer rerun
```

## Security and License

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting. traceq is released
under the [MIT License](LICENSE). GumTrace and any third-party components
represented in trace data remain subject to their own licenses.
