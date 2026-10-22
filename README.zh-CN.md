# traceq — ARM64 trace 指令查询工具

[English](README.md)

traceq 将 [GumTrace](https://github.com/lidongyooo/GumTrace) 采集的 ARM64 文本日志转换为紧凑的 `.gtb` 二进制文件，并通过 `gt` 命令行工具提供高效的离线查询、状态重建与数据依赖追踪。

## 设计理念

原始 trace 指令日志往往极其庞大（动辄数百万行、数个 GB）。直接把完整日志喂给大模型不仅浪费大量 Token，还会因超出上下文窗口或注意力被大量汇编噪声稀释，严重影响分析推理质量。

**traceq 的核心原则是：将确定性计算留在本地。**

指令过滤、内存状态重建和数据流关联全部在本地完成，只向 Agent 或分析人员返回得出结论所需的**最小充分证据**（smallest sufficient evidence）。既大幅降低 Token 消耗与分析耗时，又完整保留了每条证据的来源位置（provenance）、截断标记与未知状态边界。

## 功能特性

| 命令 | 说明 |
|---|---|
| `stat` / `find-pc` / `find-value` | 查看 trace 元数据；按地址或模块偏移定位指令；检索运行时寄存器或内存值 |
| `mem-access` / `mem-state` | 查询内存读写事件；重建指定时刻已观测到的内存缓冲区内容 |
| `calls` / `calltree` | 恢复函数调用关系，提取参数及调用树 |
| `taint` | 正向或反向追踪寄存器与内存的数据依赖链路 |
| `fold` / `diff` | 识别循环与重复执行序列；快速定位两次运行的首个分支分歧点 |
| `export` | 将指定范围切片导出为紧凑文本、流式 JSONL 或原始 GumTrace 格式 |

- **原生结构化输出**：全命令支持 `--json`（格式为 `{"data": [...], "meta": {...}}`），天然适合脚本解析与 LLM 工具调用。
- **有界与上下文支持**：支持 `--limit`、`--last` 分页控制，并通过 `--context N` 附带触发点前后的关键上下文。
- **纯内存扫描**：基于内存缓冲区直接扫描，无需配置数据库或等待繁重的建索引过程。

## 快速开始

环境要求：macOS 或 Linux、`make` 以及支持 C++17 的编译器。

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make

# 1. 导入 trace 日志（使用仓库自带的测试样例或你自己的 GumTrace 日志）
./cli/gt import bench/traces/memcpy_device.log -o trace.gtb

# 2. 查看 trace 概况与首个执行点
./cli/gt stat trace.gtb --json

# 3. 按模块和偏移查询执行记录，并附带相邻 1 条上下文
./cli/gt find-pc trace.gtb --mod libc.so --off 0x57490 --limit 1 --context 1 --json
```

将上述示例中的模块名和偏移替换为 `stat` 输出中 `first_at` 的实际值即可。
常用参数可查看 `gt <command> --help`。可选执行 `make install` 将 `gt` 安装到 `~/.local/bin`。

## 结果语义与约定

为了向 Agent 与自动化分析提供严谨、抗幻觉的证据边界，traceq 的输出遵循以下约定：

- **数据与元数据分离**：JSON 查询统一返回单个 `{"data": [...], "meta": {...}}` 文档。`meta` 中包含条数、截断标记 `truncated` 以及用于下一页的 `next` 命令。
- **未知内存区分**：在 `mem-state` 中，未观测到的字节以 `00` 填充，并由 `unknown` 掩码明确标记，避免将“未观测到”误判为“值为 0”。未观测到的寄存器写入会主动使旧值失效，防止状态重建使用陈旧数据。
- **复制、填充与 dump 证据**：`mem-state` 按有明确范围的 `memcpy`/`memmove`/`memset` 注释及返回目标地址重建状态，跟踪来源依赖，并支持旧 GTB 中保留的 hexdump 短尾。调用尚未返回、来源缺失时，目标旧值会失效；重叠 `memcpy` 没有实际写入证据的部分保持 unknown。`--provenance` 可附加字节来源、原始行号、复制证据和填充参数。来源依赖需要额外扫描元数据，该扫描跳过寄存器重建；普通输出保持精简。
- **事件与原始行号**：`ev` 是从0开始的事件组索引，`line` 是从1开始的原始物理行号。`mem-state --at-line L` 直接解析原始行号并同时返回两种坐标。若行号位于事件组中间，查询会拒绝并给出该组末行及事件索引，避免提前使用后续行的事实。连续返回注释按需要分别保留，维持原始顺序。
- **批量访问查询**：重复 `mem-access --range B,L` 可在一次扫描中查询多个范围的并集；重叠选择器不会重复同一条访问。`--limit`、`--offset`、`--last` 对整个并集生效。单范围保留相对 `off`，多范围使用绝对 `addr`；分页命令保留全部选择器。
- **追踪边界明确**：`taint` 污点分析在遇到 trace 未覆盖的边界时，会明确标记 `partial: true` 与 `stop` 原因，保证数据流推导的可信度。

重复调查时，优先合并选择器，并保存成功查询的 JSON 供后续复用。解析 stdout 前先检查进程退出码：诊断写入 stderr，失败的 JSON 查询不产生结果文档。查询调用完成后的内存效果时，使用返回记录的 `ret_ev` 或 `ret_line`，避免把调用前状态或原始行号误当成目标事件。
