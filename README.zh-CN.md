# traceq — 查询 ARM64 指令轨迹

[English](README.md)

traceq 将 [GumTrace](https://github.com/lidongyooo/GumTrace) 产生的 ARM64 指令日志
转换为紧凑、可查询的 `.gtb` 文件，并通过有界文本或标准 JSON 输出回答 PC、值、
内存、调用、循环、差异和污点问题；流式事件导出仍使用 JSON Lines。

> 让 Agent 像查询数据库一样查询执行轨迹，而不是把整份 GB 级文本塞进上下文。

```text
GumTrace ──capture──> trace.log ──gt import──> trace.gtb
                                                   │
                         gt find-* / mem-* / calls / taint / diff / fold
```

GumTrace 负责实时抓取，traceq 负责导入、压缩、查询和面向 Agent 输出；两个项目
彼此独立，本仓库不包含 GumTrace 的源码或二进制。traceq 当前处于 0.x 阶段：
CLI 输出有测试约束，`libtraceq` C++ API 与 `.gtb` 格式仍可能演进。

请只追踪和分析你拥有或已获授权的设备、进程与二进制。指令 trace 可能包含地址、
寄存器值、内存值和调用参数，发布前应单独做数据审查。

## 设计理念

traceq 在本地把海量指令 trace 提炼成完成判断所需的**最小充分证据**，让 Agent
用更少的 Token 获得更高的上下文有效信息密度，并更快完成分析。它追求的不是单纯
缩短输出，而是提高每个 Token 的分析价值，同时保留验证结论所需的来源、未知性和
截断信息。

## 30 秒上手

依赖：支持 C++17 的 clang++ 或 g++、make；只有 benchmark 需要 python3。

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make all test

# 用仓库自带的公开真机夹具走完整产品路径
./cli/gt import bench/traces/memcpy_device.log -o /tmp/memcpy.gtb
./cli/gt stat /tmp/memcpy.gtb
./cli/gt export --format jsonl --limit 5 /tmp/memcpy.gtb
```

可选安装到当前用户目录：

```bash
make install                         # 默认安装到 ~/.local/bin/gt
export PATH="$HOME/.local/bin:$PATH" # 如果该目录尚未在 PATH 中
gt --help
```

## 常用查询

| 目的 | 命令 |
|---|---|
| 导入 GumTrace 日志 | `gt import trace.log -o trace.gtb` |
| 查看概况 | `gt stat trace.gtb` |
| 导出窗口 | `gt export --format compact\|jsonl\|upstream --from E --to E --limit N trace.gtb` |
| 查执行位置 | `gt find-pc (--addr A... \| --off O... [--mod M]) [--from E --to E] [--last N] trace.gtb` |
| 查运行时值 | `gt find-value trace.gtb --value V... [--read\|--write] [--from E --to E] [--last N]` |
| 查内存访问 | `gt mem-access (--addr A... \| --range B,L) [--read\|--write] [--last N] trace.gtb` |
| 枚举有限窗口内的写入 | `gt mem-access trace.gtb --write --from E --to E --limit N` |
| 重建已知内存 | `gt mem-state --range B,L... --at-ev E... [--qword] trace.gtb` |
| 发现运行时调用目标 | `gt calls trace.gtb --top N` |
| 查调用与参数 | `gt calls trace.gtb [--name F...] [--target-addr A...] [--target-off O... --mod M] [--last N]` |
| 重建调用树 | `gt calltree [--func F] --depth D trace.gtb` |
| 正向/反向污点 | `gt taint (--seed-addr A\|--seed-reg R\|--seed-q Q\|--seed-nzcv) [--back] trace.gtb` |
| 比较两次执行 | `gt diff a.gtb b.gtb` |
| 检测循环 | `gt fold --top N trace.gtb` |

每个子命令都支持 `--help`。`gt` 没有 `record` 子命令：实时 trace 始终由
GumTrace 产生，再通过 `gt import` 进入查询链路。

重复传 `find-value --value`、`find-pc` 或 `calls` 的 selector 可在一次扫描中查询
多个候选；`find-value` 的 `--limit`、`--offset` 和 `--last` 按值分别生效。
`mem-state` 可重复传
`--range` 和/或 `--at-ev`，一次扫描输出两组 selector 的笛卡尔积；单 selector
记录结构保持兼容。同时兼容 `mem-state --at E` 与 `call-tree` 别名。省略
`calltree --func` 时会先输出有界的全局调用森林。地址未知时，无 selector 的
`mem-access` 被刻意限制为显式 `--from`/`--to` 事件窗口内的写入。

## Agent 输出契约

- 查询命令的 `--json` 返回单个标准
  `{"data":[...],"meta":{...}}` 文档；`export --format jsonl` 仍是流式记录，
  末尾带 meta 记录。
- 地址、寄存器值和 SIMD 值使用 hex 字符串，事件号与计数使用十进制数字。
- 查询输出默认有界；`export` 需要显式传 `--limit` 才限制输出窗口。
- 查询元数据给出精确的 `total`/`shown`；可分页且发生截断时，`next` 是可直接
  执行的续页命令。
- 事件类结果同时给出 `.gtb` 事件号 `ev` 和导入日志原始行号 `line`。

例如：

```json
{"data":[{"ev":0,"line":1,"mod":"libc.so","off":"0x57490","txt":"b.hi #0x77df89c554","rd":[],"wr":[]}],"meta":{"truncated":true,"total":517,"shown":1,"next":"gt find-pc --off 0x57490 --limit 1 --offset 1 trace.gtb --json"}}
```

常用结构化字段：

- `export --format jsonl` 与 `find-pc --json` 的内存项包含
  `w/addr/size/val`；`val` 会按记录或推断出的访问宽度截断。
- `calls` 会发现没有 `call func:` 注释的 `BL`、`BLR`、`BLRAA`、`BLRAB`；
  匹配的注释会补充名称、显式参数和可靠配对的返回值，未知的 `x0`–`x7` 为
  `null`。
- `find-value` 返回 `kind/rw/reg` 或 `kind/rw/addr/size`，无需再解析文本 lane。
- `mem-access` 会匹配覆盖指定地址或与指定范围重叠的访问，并返回访问宽度；读事件还会
  给出最近一次重叠写入的 `prior_write_ev`。
- 字节模式 `mem-state` 的 `data_hex` 始终可解析，未知字节以 `00` 填充，
  `unknown` 区间才是未知性的权威信息；`--qword` 以 8 字节小端单元输出，
  未知值为 `null`。
- `diff` 区分执行序号和两侧真实事件号；`fold` 同时返回执行范围与事件范围。
- `taint` 明确报告 `partial`、种子、边、最终寄存器和内存地址集合。

## 设计

核心数据模型是**静态站点表与动态执行流分离**。导入时，模块名、PC、偏移、
助记符和操作数计划在 `SiteArena` 中按地址去重；每次执行和值写入 varint/delta
事件流。

| 事件 | 编码 | 说明 |
|---|---|---|
| EXEC | zigzag delta(site_id) | 执行了某个静态站点；热循环通常只需 1 字节 |
| REGW | tag + reg + zigzag delta | 寄存器写值；reader 兼容旧 inline 编码 |
| MEM | flags + address/value delta | 内存读写及实际值 |
| MEMW_NV | 无存储值 | 值已存在于寄存器事件中，展开时重建 |
| CALL/RET/SVC | symbol + argument delta | 调用、返回和系统调用 |
| RDVAL/SIMDV | name + delta 或 16B | 上游明确观测到的整数/SIMD 值 |
| VERBATIM | length + raw bytes | 无法分类的输入行原样保留 |
| CALL2 | symbol + argument count + delta | 上游 0..8 参数调用行 |

能从写历史恢复的整数寄存器值不会重复存储；日志中明确出现的观测值仍会保留。
footer 记录计数、停止原因和输入方言，导入的 LF/CRLF 日志都可以通过
`gt export --format upstream` 逐字节还原。未知输入形态进入 `VERBATIM`，不会被
静默丢弃。

所有查询直接加载 `.gtb` event buffer 并顺序扫描；可重复 selector 共用同一次扫描，
避免反复加载 100MB 以上的文件，同时不引入数据库或索引步骤。对 Agent 工作流而言，
查询延迟通常远低于一轮模型推理；索引会额外引入构建时间、存储和依赖。

## 测试

```bash
make test
```

产品测试通过 `import_mem` 走真实的 import/query 路径，覆盖 CRLF、VERBATIM、
非规范 hex、JNI 调用、128 位 SIMD、hexdump、逐字节回放、导入确定性、资源护栏、
查询、污点、diff 和输出分页。GitHub Actions 在 Linux 与 macOS 上执行同一套测试。

## Benchmark

`bench/run.py` 只把发布的 `gt` 当作外部进程调用，测量用户真实承担的进程启动、
导入、导出和查询成本。

```bash
make report
python3 bench/run.py run --repeat 5
python3 bench/run.py run bench/private/your-trace.log
python3 bench/run.py compare OLD/report.json NEW/report.json
```

每条 trace 有两道正确性门：重复导入必须产生字节一致的 `.gtb`，`upstream` 导出
必须与源日志逐字节一致。报告还记录 import、体积和查询的 min/median/max；任何
正确性门失败都会使整份报告无效并返回非零退出码。

公开仓库附带两份由受控测试 App 真机录制的窄窗口夹具：

| 文件 | 用途 |
|---|---|
| `memcpy_device.log` | libc memcpy 的 SIMD 拷贝循环与 NZCV |
| `write_device.log` | write 短路径和小输入边界 |

来源和审查范围见 [`bench/traces/README.md`](bench/traces/README.md)。第三方 App
trace 不随仓库发布；仅供本地使用的日志应放在已忽略的 `bench/private/`。生成的
报告包含主机指纹，公开分享前也应检查。

早期合成语料和 112MB 私有真机日志的结果仅作为历史记录保存在
[`bench/reports/historical/`](bench/reports/historical/)，对应原始大 trace 不公开，
因此不作为首页可复现性能承诺。

## 已知限制

- traceq 只消费 GumTrace 文本日志，不负责实时抓取。
- 查询采用顺序扫描；如果未来真实工作负载证明扫描成为瓶颈，再考虑索引。
- 上游文本会把部分纯存储指令并入下一物理行；import/upstream export 保留这一行为。
- `--max-bytes` 限制编码中的事件流并按输入行边界停止，不代表最终文件严格不超过该值；
  站点表和 footer 仍会写入。
- 项目处于 0.x 阶段，`.gtb` 与 C++ API 尚未承诺长期 ABI 稳定。

## 仓库结构

```text
cli/                         libtraceq、gt CLI 与产品测试
  include/traceq/            对外 C++ 头文件
  src/                       import、GTB 编解码、展开、查询与 CLI
  tests/test_main.cpp        真实产品路径测试

bench/                       黑盒 benchmark，不链接产品代码
  run.py                     correctness gates、计时与报告对比
  traces/                    可公开的受控真机夹具
  private/                   本地私有 trace；git ignored
  frida/                     录制受控 trace 的 Frida 模板
  reports/historical/        不再复跑的历史结论
```

## 安全与许可证

安全问题的报告方式见 [`SECURITY.md`](SECURITY.md)。项目采用
[MIT License](LICENSE)。GumTrace 及 trace 中出现的第三方组件仍遵循各自的
许可证。
