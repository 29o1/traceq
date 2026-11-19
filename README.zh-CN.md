# traceq — 面向 Agent 的 ARM64 采集与证据查询

[English](README.md)

traceq 将 ARM64 执行采集为结构化的 GTSW／GTSC 流。CLI 在本地查询指令窗口、寄存器快照
和已观测的内存访问，返回带来源的有界证据。Android ARM64 SDK 和 macOS ARM64 宿主验证程序
共享 trace 格式。[采集构建与 SDK](capture/traceq/README.md)

## 快速开始

构建 Rust CLI 需要 `make`、Python 3.9 或更新版本，以及用于准备固定工具链的 `rustup`。

```sh
git clone https://github.com/29o1/traceq.git
cd traceq
make deps-cli
make
```

以下执行状态查询使用 profile 2 采集文件。请根据实际采集结果选择指令偏移、事件编号和内存范围。

```sh
./cli/traceq stat capture.gtsw --json
./cli/traceq find-pc capture.gtsw --off 0x0 --limit 1 --json
./cli/traceq context capture.gtsw --at-ev 0 --at-ev 2 --before 1 --after 1 --json
./cli/traceq last-writers capture.gtsw --range 0x2000,16 --json
```

用 `./cli/traceq --help` 和 `./cli/traceq COMMAND --help` 查看可用参数。
`make install` 默认将 `traceq` 安装到 `~/.local/bin`。
在 Codex 中使用 `$traceq` 获取采集和查询说明。[TraceQ 技能](.agents/skills/traceq/SKILL.md)
在 macOS ARM64 的 Git checkout 中运行 `make check` 可验证本地采集和查询。

## 查询

| 命令 | 证据 |
| --- | --- |
| `stat`、`instructions`、`find-pc`、`find-value` | 采集元数据、指令记录、PC 和数值匹配 |
| `context`、`reg-state`、`boundaries` | 事件窗口、寄存器快照和采集范围边界 |
| `mem-access`、`mem-state`、`last-writers` | 已观测的读写、内存快照和每字节最后一次观测写入 |

`context` 在一次校验扫描中取得多个事件窗口。查询校验完整的 trace 流，显式报告采集缺口
和未知值。JSON 结果包含 `data` 和 `meta`，分页结果提供 `meta.truncated` 和 `meta.next`。
