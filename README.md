# traceq — Query ARM64 Instruction Traces

[简体中文](README.zh-CN.md)

traceq converts ARM64 instruction logs produced by
[GumTrace](https://github.com/lidongyooo/GumTrace) into compact, queryable `.gtb`
files. The CLI supports analysis of PCs, runtime values, memory, calls, loops,
taint, and cross-run differences through bounded text or structured JSON output.

GumTrace records live execution. traceq handles offline import, compression,
queries, and export. The CLI is the primary interface during 0.x; the
`libtraceq` C++ API and `.gtb` format may change between versions.

## Design Philosophy

traceq performs deterministic filtering, state reconstruction, and evidence
correlation locally. It returns the **smallest sufficient evidence** needed by an
agent. This lowers token use, increases context information density, shortens
analysis time, and preserves provenance, unknown state, and truncation details.

## Quick Start

Requires `make` and a C++17 compiler such as `clang++` or `g++`.

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make

./cli/gt import trace.log -o trace.gtb
./cli/gt stat trace.gtb --json
./cli/gt export --format jsonl --limit 5 trace.gtb
```

Optional user-local install:

```bash
make install
export PATH="$HOME/.local/bin:$PATH"
gt --help
```

## Common Commands

| Goal | Command |
|---|---|
| Import a log | `gt import trace.log -o trace.gtb` |
| Inspect trace statistics | `gt stat trace.gtb [--json]` |
| Export an event window | `gt export --format compact\|jsonl\|upstream [--from E] [--to E] [--limit N] trace.gtb` |
| Replay a completed import byte-for-byte | `gt export --format upstream --all trace.gtb -o trace.log` |
| Find executed PCs | `gt find-pc trace.gtb (--addr A... \| --off O... [--mod M]) [--last N] [--context N]` |
| Find runtime values | `gt find-value trace.gtb --value V... [--read\|--write] [--last N] [--context N]` |
| Find memory accesses | `gt mem-access trace.gtb (--addr A... \| --range B,L) [--read\|--write] [--last N] [--context N]` |
| List writes in a window | `gt mem-access trace.gtb --write --from E --to E --limit N` |
| Reconstruct known memory | `gt mem-state trace.gtb --range B,L... --at-ev E... [--qword]` |
| Analyze calls | `gt calls trace.gtb [--top N \| --name F... \| --target-addr A... \| --target-off O... [--mod M]]` |
| Build a call tree | `gt calltree [--func F] [--depth D] trace.gtb` |
| Run taint analysis | `gt taint (--seed-addr A\|--seed-reg R\|--seed-q Q\|--seed-nzcv) [--back] trace.gtb` |
| Compare two executions | `gt diff a.gtb b.gtb` |
| Detect loops | `gt fold trace.gtb [--top N]` |

Every subcommand supports `--help`. `find-value`, `find-pc`, and `calls` accept
repeated filters and scan multiple candidates in one pass. `mem-state` accepts
multiple `--range` and `--at-ev` options and returns every range/event
combination. Without an address or range, `mem-access` lists writes only inside
an explicit event window.

## Agent Output Contract

- Query commands with `--json` return one `{"data":[...],"meta":{...}}` document.
  `export --format jsonl` emits JSON Lines followed by a meta record.
- `find-pc`, `mem-access`, and `find-value` accept `--context N` (1..200) to
  inline the compact instruction window `[ev-N, ev+N]` around the first shown
  hit, replacing the hit-then-export round trip. JSON adds a `"context"` key;
  text prints a `context ev=E:` block after the hit rows.
- Addresses, register values, and SIMD values are hexadecimal strings. Event
  indices and counts are decimal numbers.
- Event results include the `.gtb` event index `ev` and original log line `line`.
- List queries that support `--limit`, plus `export`, default to 20 items. `meta`
  provides `total`, `shown`, and `truncated`. For truncated paginated results,
  `next` contains the continuation command.
- Memory entries from `find-pc --json` and `export --format jsonl` expose
  `w/addr/size/val`; `find-value` exposes `kind/rw/reg` or `kind/rw/addr/size`.
- `mem-state` fills unknown bytes in `data_hex` with `00` and records the actual
  unknown intervals in `unknown`. `--qword` emits 8-byte little-endian cells and
  uses `null` for unknown values.
- `calls` recovers calls from executed `BL`, `BLR`, `BLRAA`, and `BLRAB` sites.
  Call annotations can add names, arguments, and paired return values.
- `diff`, `fold`, and `taint` preserve real event coordinates. `taint` also
  reports `partial`, edges, final taint sets, and address-set truncation.

## Design

Import deduplicates instructions by address and compiles branch operands, memory
widths, pair strides, and taint data-flow roles. Dynamic executions and values
use varint/delta encoding. Queries share one semantic scanner and reconstruct
only known state. Export uses a separate rendering path.

```text
trace.log ──import──> GTB2
                     ├─ static instruction semantics
                     └─ compact dynamic observations
                                  │
                           shared semantic scan
                         ┌────────┴────────┐
                   bounded queries      export
```

A completed import can reproduce LF or CRLF input byte-for-byte with
`gt export --format upstream --all`. When a resource guard stops import,
`stat.stop` records the reason and export covers the recorded prefix.
Unclassified input lines are preserved verbatim.

Keep the original GumTrace `.log` as the durable source and use GTB2 for derived
analysis. Rebuild `.gtb` files from the original log after format upgrades.

## Known Limitations

- Queries scan the event stream sequentially, so latency grows with trace size.
- The GumTrace text format can merge some pure-store instructions into the next
  physical line. Import and upstream export preserve this behavior.
- During import, `--max-bytes` limits the encoded event stream. The site table
  and footer add to the final file size.

## Security and License

Analyze only devices, processes, and binaries that you own or are authorized to
inspect. Instruction logs can contain addresses, register and memory values,
and call arguments; review them before publication.

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting. traceq is released
under the [MIT License](LICENSE). GumTrace and third-party components represented
in trace data remain subject to their own licenses.
