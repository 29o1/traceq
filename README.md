# traceq — Query ARM64 Instruction Traces

[简体中文](README.zh-CN.md)

traceq converts ARM64 instruction logs produced by
[GumTrace](https://github.com/lidongyooo/GumTrace) into compact, queryable `.gtb`
files. It answers questions about PCs, values, memory, calls, loops, run
differences, and taint through bounded text or standard JSON output. Streaming
event export remains available as JSON Lines.

> Give an agent database-style access to an execution trace while keeping a
> multi-gigabyte text log outside its context window.

```text
GumTrace ──capture──> trace.log ──gt import──> trace.gtb
                                                   │
                         gt find-* / mem-* / calls / taint / diff / fold
```

GumTrace handles live capture. traceq handles import, compression, queries, and
agent-facing output. They are independent projects; GumTrace source and binaries
remain in its own repository. traceq is currently a 0.x project. The CLI is the
primary integration surface. The `libtraceq` C++ API and derived `.gtb` format
continue to evolve.

Only trace and analyze devices, processes, and binaries that you own or are
authorized to inspect. Instruction traces may contain addresses, register and
memory values, and call arguments. Review trace data separately before making
it public.

## Design Philosophy

traceq distills massive instruction traces locally into the **smallest
sufficient evidence** needed to reach a conclusion. This lets an agent spend
fewer tokens, get more useful signal from its context window, and complete an
analysis faster. Compact output increases analytical value per token and retains
the provenance, unknown-state, and truncation details needed to verify a
conclusion.

## Quick Start

Requirements: make and a C++17 compiler such as clang++ or g++.

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make

# Try the complete workflow with an included, reviewed real-device trace.
./cli/gt import bench/traces/memcpy_device.log -o /tmp/memcpy.gtb
./cli/gt stat /tmp/memcpy.gtb
./cli/gt export --format jsonl --limit 5 /tmp/memcpy.gtb
```

The fixture's provenance and review scope are documented in
[`bench/traces/README.md`](bench/traces/README.md).

Optionally install `gt` for the current user:

```bash
make install                         # installs to ~/.local/bin/gt by default
export PATH="$HOME/.local/bin:$PATH" # add this when the directory is absent from PATH
gt --help
```

## Common Queries

| Goal | Command |
|---|---|
| Import a GumTrace log | `gt import trace.log -o trace.gtb` |
| Inspect trace statistics | `gt stat trace.gtb` |
| Export a bounded event window | `gt export --format compact\|jsonl\|upstream [--from E --to E] [--limit N] trace.gtb` |
| Replay a normally completed import byte-for-byte | `gt export --format upstream --all trace.gtb -o trace.log` |
| Find executed PCs | `gt find-pc (--addr A... \| --off O... [--mod M]) [--from E --to E] [--last N] trace.gtb` |
| Find runtime values | `gt find-value trace.gtb --value V... [--read\|--write] [--from E --to E] [--last N]` |
| Find memory accesses | `gt mem-access (--addr A... \| --range B,L) [--read\|--write] [--last N] trace.gtb` |
| List writes in a finite window | `gt mem-access trace.gtb --write --from E --to E --limit N` |
| Reconstruct known memory | `gt mem-state --range B,L... --at-ev E... [--qword] trace.gtb` |
| Discover runtime call targets | `gt calls trace.gtb --top N` |
| Inspect calls and arguments | `gt calls trace.gtb [--name F...] [--target-addr A...] [--target-off O... --mod M] [--last N]` |
| Rebuild a call tree | `gt calltree [--func F] --depth D trace.gtb` |
| Run forward/backward taint | `gt taint (--seed-addr A\|--seed-reg R\|--seed-q Q\|--seed-nzcv) [--back] trace.gtb` |
| Compare two executions | `gt diff a.gtb b.gtb` |
| Detect repeated loops | `gt fold --top N trace.gtb` |

Every subcommand supports `--help`. GumTrace captures live execution, and
`gt import` brings the resulting log into the query pipeline.

Repeat `find-value --value`, `find-pc` selectors, or `calls` selectors to inspect
several candidates in one scan; `find-value` applies `--limit`, `--offset`, and
`--last` per value. For
`mem-state`, repeat `--range` and/or `--at-ev`; traceq emits their Cartesian
product from one scan. The single-selector record shape remains unchanged.
`mem-state --at E` and `call-tree` are accepted compatibility aliases. Omit
`calltree --func` to inspect the bounded global call forest first. Selectorless
`mem-access` lists writes inside an explicit `--from`/`--to` event window,
supporting workflows that start from event boundaries and narrow toward an
address.

## Agent Output Contract

- Query commands support `--json` and return one standard
  `{"data":[...],"meta":{...}}` document. `export --format jsonl` remains a
  streaming sequence with a trailing meta record.
- Addresses, register values, and SIMD values are hex strings. Event indices
  and counts are decimal numbers.
- List queries that accept `--limit`, plus `export`, default to 20 rows or lines.
  Snapshot and aggregate commands use explicit selectors or command-specific
  controls; only `export --all` disables the export line budget.
- For paginated list queries, metadata contains exact `total`/`shown` counts.
  Aggregate queries count their primary evidence items, such as taint edges or
  loops. When pagination applies, a truncated result includes a directly
  executable `next` command.
- Event results include both the `.gtb` event index (`ev`) and the original
  imported log line (`line`).

Example:

```json
{"data":[{"ev":0,"line":1,"mod":"libc.so","off":"0x57490","txt":"b.hi #0x77df89c554","rd":[],"wr":[]}],"meta":{"truncated":true,"total":517,"shown":1,"next":"gt find-pc --off 0x57490 --limit 1 --offset 1 trace.gtb --json"}}
```

Useful structured fields:

- `export --format jsonl` and `find-pc --json` memory entries include
  `w/addr/size/val`; `val` is limited to the recorded or inferred access width.
- `calls` discovers executed `BL`, `BLR`, `BLRAA`, and `BLRAB` sites directly.
  Available `call func:` annotations enrich matching rows with names, explicit
  arguments, and reliably paired returns; unknown `x0`–`x7` values are `null`.
- `find-value` returns directly consumable `kind/rw/reg` or
  `kind/rw/addr/size` fields.
- `mem-access` matches accesses that contain a selected address or overlap a
  selected range. It reports access width; reads also include the most recent
  overlapping `prior_write_ev` when one was observed.
- Byte-oriented `mem-state` emits parseable `data_hex` with unknown bytes filled
  as `00`; the `unknown` intervals are authoritative. `--qword` emits 8-byte
  little-endian cells and uses `null` for unknown values.
- `diff` distinguishes execution indices from the real event indices on each
  side. `fold` reports both execution and event ranges.
- `taint` explicitly reports `partial`, its seed, edges, and final register and
  memory-address sets. `addr_total` and `addrs_truncated` distinguish the full
  frontier size from the bounded `addrs` evidence included in the response.

## Design

The core data model separates **static instruction semantics from dynamic
observations**. Import deduplicates instructions and compiles stable facts such
as branch operands, memory width, pair stride, and taint data-flow roles once.
Individual executions and observed values are stored in a compact varint/delta
event stream.

```text
trace.log ──import + semantic compilation──> GTB2
                                             ├─ static instruction semantics
                                             └─ compact dynamic observations
                                                            │
                                                   shared semantic scan
                                              ┌─────────────┴─────────────┐
                                       bounded query evidence      export rendering
                                    find/mem/calls/taint/diff     compact/jsonl/upstream
```

Queries share the same semantic scan and reconstruct only known state. Stable
instruction text is parsed once during import. Repeatable selectors also share
a scan, reducing repeated work when an agent checks several candidates.

When import finishes normally, LF and CRLF logs can be reproduced byte-for-byte
with `gt export --format upstream --all`. If a resource guard stops import,
`stat.stop` records the reason and export reproduces only the recorded prefix.
Unknown input forms remain available as verbatim source evidence.

GTB2 serves as the derived analysis format. The original GumTrace `.log` remains
the durable source. The 0.x CLI reads the current GTB2 layout; after a format
upgrade, rebuild the current `.gtb` from the original log.

## Known Limitations

- GumTrace performs live capture; traceq consumes the resulting text logs.
- Queries currently scan the event stream sequentially, so latency grows with
  trace size.
- The upstream text format may merge some pure-store instructions into the next
  physical line. Import and upstream export preserve this behavior.
- `--max-bytes` limits the encoded event stream and stops at an input-line
  boundary. The site table and footer are appended afterward, so the final file
  may exceed this value.
- During 0.x, the `.gtb` format and C++ API may change across versions.

## Security and License

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting. traceq is released
under the [MIT License](LICENSE). GumTrace and any third-party components
represented in trace data remain subject to their own licenses.
