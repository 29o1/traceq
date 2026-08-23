# GumTrace-ng A/B benchmark report

Host: sanitized historical macOS arm64 benchmark host
Apple M4

- driven by `bench/run.py`: the queryable side is the real `gt` CLI, invoked as a subprocess
- legacy = faithful port of the GumTrace text hot path (snprintf reg names, 50MB buffer, per-exec prefix rebuild)
- gtb = static/execution-separated binary format + precompiled site plans + background writer
- corpus: synthetic ARM64 (real encodings), 7015516 executed instructions, inner loop 60 iters
- both recorders consume an identical event stream; engine (Stalker callout) cost is excluded from both sides, which is why the per-event figure is measured in-process by `gt-harness hotpath`

## Recording (hot path)

| metric | legacy text | gtb binary |
|---|---|---|
| recorder time/event | 136.1 ns | 22.33 ns (**6.095x**) |
| recorder time total | 954.6 ms | 156.6 ms |
| wall incl. event source | 1270 ms | 410.7 ms |
| output size | 569.6 MB | 38.01 MB (**14.99x smaller**) |
| events | 7015516 | 7015516 |

## Detail levels (volume scaling)

| detail | size | vs full text |
|---|---|---|
| full (gtb) | 38.01 MB | 14.99x |
| mem-only | 28.15 MB | 20.23x |
| calls-only | 0.1767 MB | 3223x |

site compile (transform time): 3.089 ms for 308 sites; corpus build 0.129 ms

## Query A/B (identical questions, text pipeline vs CLI)

| question | text pipeline | gt CLI | CLI speedup |
|---|---|---|---|
| writes to 0x100000030100 (top5+count) | 1987 ms | 171.4 ms | 11.59x |
| 3rd call args of transform_block_0 | 1370 ms | 172.9 ms | 7.925x |
| loop iteration count | 4116 ms | 181.3 ms | 22.7x |
| forward taint from 0x10000020000 | 2964 ms | 187.1 ms | 15.84x |
| diff two runs | 2778 ms | 339.6 ms | 8.178x |
| run overview (wc+grep ritual vs gt stat) | 2367 ms | 161.7 ms | 14.63x |
| mem accesses of hot addr, full count | 1988 ms | 172.6 ms | 11.52x |
| value search 0x2a00 (full scan) | 1531 ms | 180.8 ms | 8.465x |

## Durability

- gtb crash loss window: **<= 0.25 MB by construction** (one 256KB chunk + footer via signal handler; verified in selftest T5)
- legacy crash loss window: **426 B measured on this call-heavy corpus**. Upstream flushes its 50MB buffer at every function-call info block, so the window tracks call density: small on call-heavy code (like this corpus), up to the full 50MB on call-free hot loops. That per-call direct-write behaviour is the same one the recording benchmark penalises — it trades hot-path speed for a smaller loss window.

## Cross-validation

- expansion byte-identical to legacy text: **YES** (597318782 B, verified with `gt export` + `cmp`)
- taint final reg set equal: YES (text [] vs gtb [])
- diff divergence point equal (instruction offsets): YES — text line ordinals != event ordinals (upstream merges pure-store lines), so the comparison is on first-diverging-instruction offsets

## Agent surface (compact format + streaming queries)

- token proxy over the same 5000-event window: legacy text 478170 B / 47451 tokens -> compact 289264 B / 40590 tokens (**1.65x bytes, 1.17x tokens**)
- 全部命令流式直读 .gtb，无入库步骤；查询延迟见上表

## Acceptance criteria

| criterion | target | actual | verdict |
|---|---|---|---|
| hot-path throughput | >= 3x | 6.095x | PASS |
| output size (full detail) | >= 20x | 14.99x | MISS — see note |
| output size (tiered detail) | >= 20x at a usable tier | mem-only 20.23x, calls-only 3223x | PASS |
| mem-write query vs grep | >= 10x | 11.59x | PASS |
| crash loss window | gtb <= 1MB, crash-safe | 0.25MB by design (T5-verified); legacy workload-dependent | PASS |
| taint consistency | match | match | PASS |
| diff consistency | match | match | PASS |
| byte-identical expansion | match | match | PASS |
| agent token proxy (compact vs legacy, 5000 events) | >= 1.5x bytes | 1.653x bytes / 1.169x ws-tokens | PASS — whitespace splitting undercounts LLM tokens; values are the entropy floor on both sides, real-log module prefixes widen the gap (see real_report) |
