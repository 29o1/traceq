# traceq — ARM64 Capture and Evidence Queries

[简体中文](README.zh-CN.md)

traceq captures ARM64 execution as structured GTSW/GTSC streams. The CLI queries
them locally and returns bounded evidence with provenance, including instruction
windows, register snapshots and observed memory accesses. The Android ARM64 SDK
and macOS ARM64 host harness share the trace format. [Capture builds and SDK](capture/traceq/README.md)

## Quick start

To build the Rust CLI, use `make`, Python 3.9 or newer, and `rustup` to
prepare the pinned toolchain.

```sh
git clone https://github.com/29o1/traceq.git
cd traceq
make deps-cli
make
```

Use a profile 2 capture for the execution-state queries below. Choose the
instruction offset, event IDs and memory range from your capture.

```sh
./cli/traceq stat capture.gtsw --json
./cli/traceq find-pc capture.gtsw --off 0x0 --limit 1 --json
./cli/traceq context capture.gtsw --at-ev 0 --at-ev 2 --before 1 --after 1 --json
./cli/traceq last-writers capture.gtsw --range 0x2000,16 --json
```

Use `./cli/traceq --help` and `./cli/traceq COMMAND --help` for available options.
`make install` installs `traceq` in `~/.local/bin` by default.
In Codex, use `$traceq` for capture and query guidance. [TraceQ skill](.agents/skills/traceq/SKILL.md)
For local capture and query regressions on macOS ARM64, run `make check` in a Git checkout.

## Queries

| Commands | Evidence |
| --- | --- |
| `stat`, `instructions`, `find-pc`, `find-value` | Capture metadata, instruction records, PC and value matches |
| `context`, `reg-state`, `boundaries` | Event windows, register snapshots and scope transitions |
| `mem-access`, `mem-state`, `last-writers` | Observed reads and writes, memory snapshots and the last observed write per byte |

`context` gathers multiple event windows in one validated scan. Queries validate
the complete stream and report gaps and unknown values explicitly. JSON results
contain `data` and `meta`. Paginated results include `meta.truncated` and `meta.next`.
