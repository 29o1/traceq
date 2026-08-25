# traceq — 查询 ARM64 指令轨迹

[English](README.md)

traceq 将 [GumTrace](https://github.com/lidongyooo/GumTrace) 产生的 ARM64 指令日志
转换为紧凑、可查询的 `.gtb` 文件，并通过有界文本或标准 JSON 输出回答 PC、值、
内存、调用、循环、差异和污点问题；流式事件导出仍使用 JSON Lines。

> 让 Agent 以数据库式查询访问执行轨迹，把 GB 级文本留在上下文窗口之外。

```text
GumTrace ──capture──> trace.log ──gt import──> trace.gtb
                                                   │
                         gt find-* / mem-* / calls / taint / diff / fold
```

GumTrace 负责实时抓取，traceq 负责导入、压缩、查询和面向 Agent 输出；两个项目
彼此独立，GumTrace 的源码和二进制由其自身仓库维护。traceq 当前处于 0.x 阶段：
CLI 是主要使用入口，`libtraceq` C++ API 与派生的 `.gtb` 格式会继续演进。

请只追踪和分析你拥有或已获授权的设备、进程与二进制。指令 trace 可能包含地址、
寄存器值、内存值和调用参数，发布前应单独做数据审查。

## 设计理念

traceq 在本地把海量指令 trace 提炼成完成判断所需的**最小充分证据**，让 Agent
用更少的 Token 获得更高的上下文有效信息密度，并更快完成分析。紧凑输出提高每个
Token 的分析价值，并保留验证结论所需的来源、未知性和截断信息。

## 30 秒上手

依赖：支持 C++17 的 clang++ 或 g++、make。

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make

# 用仓库自带、经过审查的真机 trace 体验完整工作流
./cli/gt import bench/traces/memcpy_device.log -o /tmp/memcpy.gtb
./cli/gt stat /tmp/memcpy.gtb
./cli/gt export --format jsonl --limit 5 /tmp/memcpy.gtb
```

该 trace 的来源和审查范围见
[`bench/traces/README.md`](bench/traces/README.md)。

可选安装到当前用户目录：

```bash
make install                         # 默认安装到 ~/.local/bin/gt
export PATH="$HOME/.local/bin:$PATH" # PATH 缺少该目录时执行
gt --help
```

## 常用查询

| 目的 | 命令 |
|---|---|
| 导入 GumTrace 日志 | `gt import trace.log -o trace.gtb` |
| 查看概况 | `gt stat trace.gtb` |
| 导出有界窗口 | `gt export --format compact\|jsonl\|upstream [--from E --to E] [--limit N] trace.gtb` |
| 逐字节回放一次正常完成的导入 | `gt export --format upstream --all trace.gtb -o trace.log` |
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

每个子命令都支持 `--help`。GumTrace 负责生成实时 trace，`gt import` 将结果接入
查询链路。

重复传 `find-value --value`、`find-pc` 或 `calls` 的 selector 可在一次扫描中查询
多个候选；`find-value` 的 `--limit`、`--offset` 和 `--last` 按值分别生效。
`mem-state` 可重复传
`--range` 和/或 `--at-ev`，一次扫描输出两组 selector 的笛卡尔积；单 selector
记录结构保持兼容。同时兼容 `mem-state --at E` 与 `call-tree` 别名。省略
`calltree --func` 时会先输出有界的全局调用森林。无 selector 的 `mem-access`
枚举显式 `--from`/`--to` 事件窗口内的写入，便于从事件边界逐步定位地址。

## Agent 输出契约

- 查询命令的 `--json` 返回单个标准
  `{"data":[...],"meta":{...}}` 文档；`export --format jsonl` 仍是流式记录，
  末尾带 meta 记录。
- 地址、寄存器值和 SIMD 值使用 hex 字符串，事件号与计数使用十进制数字。
- 支持 `--limit` 的列表查询以及 `export` 默认最多输出 20 行或 20 项；快照和聚合
  命令由显式 selector 或命令自身的参数控制输出，只有 `export --all` 会关闭导出
  行数预算。
- 可分页列表查询的元数据给出精确的 `total`/`shown`；聚合查询统计自己的主要证据
  项，例如污点边或循环。支持分页且发生截断时，`next` 是可直接执行的续页命令。
- 事件类结果同时给出 `.gtb` 事件号 `ev` 和导入日志原始行号 `line`。

例如：

```json
{"data":[{"ev":0,"line":1,"mod":"libc.so","off":"0x57490","txt":"b.hi #0x77df89c554","rd":[],"wr":[]}],"meta":{"truncated":true,"total":517,"shown":1,"next":"gt find-pc --off 0x57490 --limit 1 --offset 1 trace.gtb --json"}}
```

常用结构化字段：

- `export --format jsonl` 与 `find-pc --json` 的内存项包含
  `w/addr/size/val`；`val` 会按记录或推断出的访问宽度截断。
- `calls` 直接从已执行的 `BL`、`BLR`、`BLRAA`、`BLRAB` 发现调用；可用的
  `call func:` 注释会补充名称、显式参数和可靠配对的返回值，未知的 `x0`–`x7`
  为 `null`。
- `find-value` 返回 `kind/rw/reg` 或 `kind/rw/addr/size`，调用方可直接消费这些字段。
- `mem-access` 会匹配覆盖指定地址或与指定范围重叠的访问，并返回访问宽度；读事件还会
  给出最近一次重叠写入的 `prior_write_ev`。
- 字节模式 `mem-state` 的 `data_hex` 始终可解析，未知字节以 `00` 填充，
  `unknown` 区间才是未知性的权威信息；`--qword` 以 8 字节小端单元输出，
  未知值为 `null`。
- `diff` 区分执行序号和两侧真实事件号；`fold` 同时返回执行范围与事件范围。
- `taint` 明确报告 `partial`、种子、边、最终寄存器和内存地址集合；
  `addr_total`/`addrs_truncated` 区分完整前沿大小与响应中有界的 `addrs` 证据。

## 设计

核心数据模型是**静态指令语义与动态观测分离**。导入时按地址去重指令，并一次性
编译分支操作数、内存宽度、成对访存步长和污点数据流角色等稳定语义；每次执行与
实际观测值再写入紧凑的 varint/delta 事件流。

```text
trace.log ──导入并编译稳定语义──> GTB2
                                  ├─ 静态指令语义
                                  └─ 紧凑动态观测
                                           │
                                       共享语义扫描
                               ┌───────────┴───────────┐
                           有界查询证据              导出渲染
                     find/mem/calls/taint/diff   compact/jsonl/upstream
```

所有查询共用同一套语义扫描，只重建已知状态。稳定指令文本仅在导入时解析一次。
可重复 selector 也会共用一次扫描，减少 Agent 同时检查多个候选时的重复工作。

导入正常完成时，LF/CRLF 日志都可以通过 `gt export --format upstream --all`
逐字节还原。如果资源限制提前停止导入，`stat.stop` 会记录原因，导出只能还原已经
记录的前缀。无法分类的输入行会原样保留，继续作为源证据。

GTB2 用作派生分析格式，原始 GumTrace `.log` 作为长期保留的源数据。0.x CLI 读取
当前 GTB2 布局；格式升级后，从原始日志重新生成当前版本的 `.gtb`。

## 已知限制

- 实时抓取由 GumTrace 完成；traceq 从生成的文本日志开始分析。
- 查询当前顺序扫描事件流，因此延迟会随 trace 规模增长。
- 上游文本会把部分纯存储指令并入下一物理行；import/upstream export 保留这一行为。
- `--max-bytes` 限制编码中的事件流并按输入行边界停止；随后还会追加站点表和 footer，
  最终文件可能超过该值。
- 0.x 阶段的 `.gtb` 格式与 C++ API 可能随版本变化。

## 安全与许可证

安全问题的报告方式见 [`SECURITY.md`](SECURITY.md)。项目采用
[MIT License](LICENSE)。GumTrace 及 trace 中出现的第三方组件仍遵循各自的
许可证。
