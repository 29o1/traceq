# traceq — 查询 ARM64 指令轨迹

[English](README.md)

traceq 将 [GumTrace](https://github.com/lidongyooo/GumTrace) 产生的 ARM64 指令日志
转换为紧凑的 `.gtb` 文件，通过 `gt` CLI 离线查询和导出，支持执行位置、运行时值、
内存、调用、循环、污点及执行序列差异分析。

## 设计理念

traceq 在本地完成确定性筛选、状态重建和证据关联，只向 Agent 返回结论所需的
**最小充分证据**。这套路径降低 Token 消耗、提高上下文信息密度、缩短分析时间，
并保留来源、未知状态和截断信息。

## 快速开始

需要 macOS 或 Linux、`make` 和 C++17 编译器。以下导入命令假设项目目录中已有
GumTrace 生成的 `trace.log`。

```bash
git clone https://github.com/29o1/traceq.git
cd traceq
make

./cli/gt import trace.log -o trace.gtb
./cli/gt stat trace.gtb --json
```

查询一个执行位置及其上下文，将下面的模块名和偏移替换为 `stat` 输出中
`first_at` 字段的值：

```bash
./cli/gt find-pc trace.gtb --mod libdemo.so --off 0x1234 --limit 1 --context 3 --json
```

可选：`make install` 将 `gt` 安装到 `~/.local/bin`，将该目录加入 `PATH` 即可使用。
未安装时，在项目目录中使用 `./cli/gt`。

## 命令

参数见 `gt <command> --help`，所有查询均支持 `--json`。

| 命令 | 用途 |
|---|---|
| `find-pc` | 按地址或模块偏移查找执行记录 |
| `find-value` | 查找已观测到的运行时值 |
| `mem-access` | 查找内存读写 |
| `mem-state` | 重建某事件时的已知内存 |
| `calls` | 查询从已执行调用指令恢复的调用 |
| `calltree` | 根据调用／返回注释构建树 |
| `taint` | 正向或反向追踪数据依赖 |
| `diff` | 定位模块／偏移序列的首次分歧，不比较运行时值 |
| `fold` | 检测重复指令序列和循环 |
| `export` | 导出 `compact`、`jsonl` 或原始 `upstream` 文本 |

## 结果解读

- 查询 JSON 为单个 `{"data":[...],"meta":{...}}` 文档；JSONL 导出以 meta 记录结尾。
  `meta` 提供计数、截断状态及可用时的 `next` 命令；截断的 JSONL 导出返回 `total: null`。
- 支持 `--limit` 的列表查询与导出默认输出 20 项。`find-value` 的上限、偏移和
  `--last` 按每个不同的候选值分别生效。`find-pc`、`find-value`、`mem-access` 的
  `--context N` 可附带首个展示命中附近的事件。
- `ev` 是从 0 开始的事件组索引；`line` 在提供时表示从 1 开始的原始行号。
  事件窗口包含两端，`mem-state --at-ev E` 包含截至 E 的观测。
- `mem-state` JSON 中的 `data_hex` 需结合 `unknown` 解读：未知字节以 `00` 填充。
  污点分析的覆盖范围需结合 `partial` 和 `stop` 判断。
