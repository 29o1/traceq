# traceq — Query ARM64 Instruction Traces

[简体中文](README.zh-CN.md)

traceq converts ARM64 instruction logs from
[GumTrace](https://github.com/lidongyooo/GumTrace) into compact `.gtb` files for
offline queries and export. Analyze execution, runtime values, memory, calls,
loops, taint, and execution-sequence differences through the `gt` CLI.

## Design Philosophy

traceq performs deterministic filtering, state reconstruction, and evidence
correlation locally. It returns the **smallest sufficient evidence** needed by an
agent. This lowers token use, increases context information density, shortens
analysis time, and preserves provenance, unknown state, and truncation details.

## Quick Start

Requires macOS or Linux, `make`, and a C++17 compiler. The import command assumes
that a GumTrace log named `trace.log` is available in the project directory.

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make

./cli/gt import trace.log -o trace.gtb
./cli/gt stat trace.gtb --json
```

Query a location with nearby context; replace the module and offset below with
values from `stat`'s `first_at` field:

```bash
./cli/gt find-pc trace.gtb --mod libdemo.so --off 0x1234 --limit 1 --context 3 --json
```

Optional: `make install` installs `gt` to `~/.local/bin`; add that directory to
`PATH`. Otherwise, use `./cli/gt` from the project directory.

## Commands

Use `gt <command> --help` for parameters. All queries support `--json`.

| Command | Purpose |
|---|---|
| `find-pc` | Find executions by address or module offset |
| `find-value` | Find observed runtime values |
| `mem-access` | Find memory reads and writes |
| `mem-state` | Reconstruct known memory at an event |
| `calls` | Query calls recovered from executed call instructions |
| `calltree` | Build a tree from call/return annotations |
| `taint` | Trace data dependencies forward or backward |
| `diff` | Find the first divergence in module/offset sequences; excludes runtime values |
| `fold` | Detect repeated instruction sequences and loops |
| `export` | Export as `compact`, `jsonl`, or original `upstream` text |

## Reading Results

- Query JSON is one `{"data":[...],"meta":{...}}` document; JSONL export ends
  with a meta record. `meta` reports counts, truncation, and a `next` command
  when available. A truncated JSONL export reports `total: null`.
- List queries with `--limit` and export default to 20 items. For `find-value`,
  limits, offsets, and `--last` apply per distinct value. `--context N` on
  `find-pc`, `find-value`, and `mem-access` adds nearby events for the first shown hit.
- `ev` is a zero-based event-group index; `line`, when present, is a one-based
  source line. Event windows include both endpoints; `mem-state --at-ev E`
  includes observations through E.
- In `mem-state` JSON, read `data_hex` together with `unknown`: unknown bytes
  are padded with `00`. For taint coverage, check `partial` and `stop`.
