# traceq — Query ARM64 Instruction Traces

[简体中文](README.zh-CN.md)

traceq converts [GumTrace](https://github.com/lidongyooo/GumTrace) ARM64 logs into
compact `.gtb` binaries. Use the `gt` CLI to query execution, reconstruct observed
state, and trace data dependencies offline.

## Design Philosophy

Raw execution traces are massive (often millions of instructions and multiple gigabytes).
Dumping raw logs into an LLM burns through token budgets, exceeds context windows,
and dilutes attention with irrelevant execution noise.

**traceq keeps deterministic computation local.**

Filtering, memory reconstruction, and dataflow correlation happen entirely on the local
machine. traceq returns only the **smallest sufficient evidence** needed to answer a question
or reach a conclusion. This reduces token consumption and turnaround time while strictly
preserving provenance, truncation markers, and unknown-state boundaries.

## Features

| Commands | Description |
|---|---|
| `stat`, `find-pc`, `find-value` | Inspect trace metadata; locate instructions by address or module offset; search runtime values |
| `mem-access`, `mem-state` | Query memory reads/writes; reconstruct observed memory buffers at any event |
| `calls`, `calltree` | Recover runtime function calls, arguments, and annotated call trees |
| `taint` | Trace register and memory data dependencies forward or backward |
| `fold`, `diff` | Detect execution loops; identify the first execution divergence between two runs |
| `export` | Export bounded slices as compact text, streaming JSONL, or upstream log format |

- **Native Structured Output**: All queries support `--json` (formatted as `{"data": [...], "meta": {...}}`), designed for scripting and LLM function calling.
- **Bounded Context**: Strict pagination controls (`--limit`, `--last`) with optional surrounding context (`--context N`) around matching events.
- **Fast In-Memory Scanning**: Directly scans the loaded `.gtb` event buffer without requiring external databases or indexing steps.

## Quick Start

Requires macOS or Linux, `make`, and a C++17 compiler.

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make

# 1. Import a trace (using the included sample or your own GumTrace log)
./cli/gt import bench/traces/memcpy_device.log -o trace.gtb

# 2. Inspect trace metadata and find the entry point
./cli/gt stat trace.gtb --json

# 3. Query instruction execution at an offset, with 1 line of nearby context
./cli/gt find-pc trace.gtb --mod libc.so --off 0x57490 --limit 1 --context 1 --json
```

Replace the module name and offset with values from `stat`'s `first_at` field.
Run `gt <command> --help` for full command parameters. Optionally run `make install`
to install `gt` to `~/.local/bin`.

## Output Semantics

To provide reliable, hallucination-resistant evidence boundaries for agents and automated workflows:

- **Data & Metadata Separation**: JSON queries return a single `{"data": [...], "meta": {...}}` document. `meta` reports result counts, a `truncated` boolean, and a `next` command for pagination.
- **Explicit Unknown Memory**: In `mem-state`, unobserved bytes are padded with `00` and explicitly flagged by the `unknown` bitmask, preventing unobserved buffers from being mistaken for zero-initialized memory. Stale register values are invalidated when unobserved writes occur.
- **Bounded Taint Coverage**: `taint` tracks dependency propagation and reports `partial: true` alongside a `stop` reason when analysis encounters trace boundaries.
