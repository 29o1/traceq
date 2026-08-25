# traceq — 查询 ARM64 指令轨迹

[English](README.md)

traceq 将 [GumTrace](https://github.com/lidongyooo/GumTrace) 产生的 ARM64 指令日志
转换为紧凑、可查询的 `.gtb` 文件。CLI 支持 PC、运行时值、内存、调用、循环、
污点和跨运行差异分析，并提供有界文本或结构化 JSON 输出。

GumTrace 负责实时录制，traceq 负责离线导入、压缩、查询和导出。CLI 是 0.x 阶段的
主要接口；`libtraceq` C++ API 与 `.gtb` 格式可能随版本变化。

## 设计理念

traceq 在本地完成确定性筛选、状态重建和证据关联，只向 Agent 返回结论所需的
**最小充分证据**。这套路径降低 Token 消耗、提高上下文信息密度、缩短分析时间，
并保留来源、未知状态和截断信息。

## 快速开始

需要 `make` 和支持 C++17 的 `clang++` 或 `g++`。

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make

./cli/gt import trace.log -o trace.gtb
./cli/gt stat trace.gtb --json
./cli/gt export --format jsonl --limit 5 trace.gtb
```

可安装到当前用户目录：

```bash
make install
export PATH="$HOME/.local/bin:$PATH"
gt --help
```

## 常用命令

| 目的 | 命令 |
|---|---|
| 导入日志 | `gt import trace.log -o trace.gtb` |
| 查看概况 | `gt stat trace.gtb [--json]` |
| 导出事件窗口 | `gt export --format compact\|jsonl\|upstream [--from E] [--to E] [--limit N] trace.gtb` |
| 完整回放正常导入 | `gt export --format upstream --all trace.gtb -o trace.log` |
| 查执行位置 | `gt find-pc trace.gtb (--addr A... \| --off O... [--mod M]) [--last N]` |
| 查运行时值 | `gt find-value trace.gtb --value V... [--read\|--write] [--last N]` |
| 查内存访问 | `gt mem-access trace.gtb (--addr A... \| --range B,L) [--read\|--write] [--last N]` |
| 枚举窗口内写入 | `gt mem-access trace.gtb --write --from E --to E --limit N` |
| 重建已知内存 | `gt mem-state trace.gtb --range B,L... --at-ev E... [--qword]` |
| 分析调用 | `gt calls trace.gtb [--top N \| --name F... \| --target-addr A... \| --target-off O... [--mod M]]` |
| 重建调用树 | `gt calltree [--func F] [--depth D] trace.gtb` |
| 运行污点分析 | `gt taint (--seed-addr A\|--seed-reg R\|--seed-q Q\|--seed-nzcv) [--back] trace.gtb` |
| 比较两次执行 | `gt diff a.gtb b.gtb` |
| 检测循环 | `gt fold trace.gtb [--top N]` |

每个子命令都支持 `--help`。`find-value`、`find-pc` 和 `calls` 支持重复筛选
参数，可在一次扫描中查询多个候选。`mem-state` 支持多组 `--range` 和
`--at-ev`，返回每个范围与事件的组合。未指定地址或范围时，`mem-access` 只枚举
显式事件窗口内的写入。

## Agent 输出契约

- 查询命令的 `--json` 返回单个 `{"data":[...],"meta":{...}}` 文档；
  `export --format jsonl` 输出 JSON Lines，并在末尾附加 meta 记录。
- 地址、寄存器值和 SIMD 值使用十六进制字符串；事件号和计数使用十进制数字。
- 事件结果包含 `.gtb` 事件号 `ev` 和原始日志行号 `line`。
- 支持 `--limit` 的列表查询与 `export` 默认输出 20 项。`meta` 提供
  `total`、`shown` 和 `truncated`；结果截断且支持分页时，`next` 给出续页命令。
- `find-pc --json` 与 `export --format jsonl` 的内存项提供
  `w/addr/size/val`；`find-value` 提供 `kind/rw/reg` 或
  `kind/rw/addr/size`。
- `mem-state` 的 `data_hex` 用 `00` 填充未知字节，`unknown` 记录真实未知区间；
  `--qword` 以 8 字节小端单元输出，未知值为 `null`。
- `calls` 可从已执行的 `BL`、`BLR`、`BLRAA` 和 `BLRAB` 恢复调用；调用注释可补充
  名称、参数和配对返回值。
- `diff`、`fold` 和 `taint` 保留真实事件坐标；`taint` 还报告 `partial`、边、
  最终污点集合及地址集合的截断状态。

## 设计

导入阶段按地址去重指令，并编译分支操作数、访存宽度、成对访存步长和污点数据流
角色。动态执行和值使用 varint/delta 编码。查询共用语义扫描，只重建已知状态；
导出使用独立渲染路径。

```text
trace.log ──import──> GTB2
                     ├─ 静态指令语义
                     └─ 紧凑动态观测
                              │
                          共享语义扫描
                    ┌─────────┴─────────┐
                  有界查询            导出
```

正常完成的导入可通过 `gt export --format upstream --all` 逐字节还原 LF 或 CRLF
日志。资源限制提前停止导入时，`stat.stop` 记录原因，导出覆盖已记录前缀。无法分类
的输入行按原文保留。

原始 GumTrace `.log` 适合长期保存，GTB2 用于派生分析。格式升级后应从原始日志
重新生成 `.gtb`。

## 已知限制

- 查询顺序扫描事件流，延迟随轨迹规模增长。
- GumTrace 文本格式可能将部分纯存储指令并入下一物理行，导入和 `upstream`
  导出会保留该行为。
- 导入时，`--max-bytes` 只限制编码后的事件流；站点表和尾部数据会增加最终文件大小。

## 安全与许可证

请仅分析自己拥有或已获授权检查的设备、进程和二进制。指令日志可能包含地址、
寄存器值、内存值和调用参数，公开前应先审查。

安全问题报告方式见 [`SECURITY.md`](SECURITY.md)。项目采用 [MIT License](LICENSE)。
GumTrace 及日志中涉及的第三方组件遵循各自许可证。
