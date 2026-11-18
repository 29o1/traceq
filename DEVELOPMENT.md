# traceq 构建与开发边界

| 用途 | 源码 | 入口和产物 |
| --- | --- | --- |
| 正式 CLI | `rust/traceq-cli`、`rust/traceq-query`、`rust/traceq-core` | `make` 生成 `cli/traceq`，`make install` 安装它 |
| 正式 Android ARM64 SDK | `rust/traceq-capture`、`rust/traceq-observer`、`capture/traceq` | `ANDROID_NDK_HOME=/path/to/ndk make capture-android` 生成 `build/traceq-android/libtraceq_capture.so` |
| 回归测试 | `tests/` 和 Rust 的单元测试 | `make check-cli-clean` 验证 Mac 干净构建，`make check` 运行本地验证 |
| Agent 评测 | `evaluation/` | `make eval-cli` 生成 `build/evaluation/traceq-eval`，`make check-eval` 做离线入口回归 |

Android 对外头文件在 `capture/traceq/include/AndroidCapture.h`。Mac 宿主采集用于原生验证。
ARM64 观察实验在 `tests/observer/`，SDK 只依赖 CPU 现场布局。
历史 C++ 对照的头文件和独立校验入口在 `tests/reference/`。可选的对照实现来自本地历史归档。

评测入口复用 Rust 查询库。新任务包仍把评测工具保存为 `work/traceq`，沿用
`./traceq agent-query --manifest tools.json`、调用日志及打分口径。`--entry python`
使用现有 Python 适配器与正式 CLI。开发回归只跑固定输入，模型评测由评测脚本显式启动。

```sh
make deps-cli
make eval-cli
python3 evaluation/bench.py repeat --run /path/to/new-run --from-run /path/to/frozen-run
```

旧轮次的任务包保留当时二进制、输入和日志。`git archive HEAD` 按 `.gitattributes`
导出源码发布包，包含正式 CLI 和 Android SDK 的构建输入。完整 Git checkout 还能运行
测试和评测。Git 跟踪这些工具的源码，构建产物、缓存、任务运行记录、trace、隔离实验和
个人笔记留在本地。源码发布包的构建环境仍需按平台准备固定 Rust 工具链和相应 SDK。
