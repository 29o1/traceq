---
name: traceq
description: 使用 TraceQ SDK 采集受控的 Android ARM64 原生执行轨迹，或用 traceq CLI 查询已有的 GTSW/GTSC 文件。适用于核对执行指令、寄存器状态、访存记录、写入来源和采集边界。
---

# TraceQ

使用本项目源码树或发布包提供的 Android SDK 和 `traceq` CLI。有现成 trace 时，直接用该文件离线查证。

## 选择入口

- 验证某个 TraceQ 工作区时，使用该工作区的 `cli/traceq`。日常查询使用调用方指定的 `TRACEQ_BIN` 或已安装的 `traceq`。先用 `--help` 核对所选二进制支持 GTSW/GTSC 和所需命令。需要从源码构建并安装 CLI 时，在仓库根目录依次运行 `make deps-cli` 和 `make install`。
- 分析已有的结构化 trace 时，参照[查询](references/analysis.md)检查格式、按范围取证，并解释查询结果。
- 需要从受控原生调用采集新 trace 时，参照[采集](references/capture.md)选择 SDK 接口、代码范围和验证方式。

交付能回答问题的最小证据链，包含 trace 标识、可复现的查询、事件号、记录的 PC 和相关值。对无法确认的结论，保留 `unknown`，并说明对应的采集范围或缺口。
