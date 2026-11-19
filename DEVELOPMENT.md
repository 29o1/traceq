# traceq 构建与开发边界

采集与查询技能随仓库维护，调用名为 `$traceq`，显示名为 TraceQ。
在 macOS 上，可从本仓库根目录将技能安装到用户级目录。

```sh
mkdir -p "$HOME/.agents/skills"
ln -s "$PWD/.agents/skills/traceq" "$HOME/.agents/skills/traceq"
```

| 用途 | 源码 | 入口和产物 |
| --- | --- | --- |
| 正式 CLI | `rust/traceq-cli`、`rust/traceq-query`、`rust/traceq-core` | `make deps-cli` 准备固定工具链和锁定依赖，`make` 生成 `cli/traceq`，`make install` 安装它 |
| 正式 Android ARM64 SDK | `rust/traceq-capture`、`rust/traceq-observer`、`capture/traceq` | `ANDROID_NDK_HOME=/path/to/ndk make capture-android` 生成 `build/traceq-android/libtraceq_capture.so` |
| CLI 回归 | `tests/` 和 Rust 的单元测试 | `make check-cli` 运行 CLI 回归，`make check-cli-clean` 在 macOS ARM64 的临时目录验证空缓存构建和回归 |
| 宿主采集回归 | `tests/integration/` | macOS ARM64 上，`make capture-host` 生成 `build/traceq-host/traceq-capture`，`make check` 运行 CLI、构建和宿主采集检查 |
| Agent 评测 | `evaluation/` | `make eval-cli` 生成 `build/evaluation/traceq-eval`，`make check-eval` 做离线入口回归 |

日常 Cargo 构建和回归默认离线。Android 需要已安装的 NDK 和带 `aarch64-linux-android` 标准库的固定 Rust 工具链，
工具链选择见 [Rust 构建脚本](tools/rust_workspace.py)。[Android 头文件](capture/traceq/include/AndroidCapture.h) 声明 SDK 的 C ABI。
采集构建会按 [依赖清单](dependencies/gum-devkits.json) 准备 Gum。可用 `python3 tools/dependencies.py gum --platform android-arm64`
单独准备 Android 依赖。构建只产生本地产物。

ARM64 观察实验在 `tests/observer/`，SDK 只依赖 CPU 现场布局。历史 C++ 对照入口在 `tests/reference/`，可选实现来自本地归档。

评测入口复用 Rust 查询库。任务包以 `work/traceq` 保存评测工具，沿用 `./traceq agent-query --manifest tools.json`、调用日志及打分口径。
`--entry python` 使用 Python 适配器与正式 CLI。开发回归使用固定输入，模型评测由评测脚本显式启动。

```sh
make deps-cli
make eval-cli
python3 evaluation/bench.py repeat --run /path/to/new-run --from-run /path/to/frozen-run
```

旧轮次的任务包保留当时的二进制、输入和日志。`git archive HEAD` 按 [.gitattributes](.gitattributes) 导出 CLI 和 Android SDK 的源码、构建输入与采集查询技能。
构建环境需准备相应工具链和 SDK。测试和评测在完整 Git checkout 中运行。构建产物、缓存、运行记录、trace、实验和个人笔记留在本地。

## Git 与发布快照

仓库保留产品、回归和评测的源码。日常用独立提交记录不同类型的改动。`make check-cli-clean` 从工作区复制 Git 已跟踪的 CLI 构建和回归输入，能验证正在编辑的源码。`make check-eval` 用固定样例校验评测入口，实际模型评测在选定任务包后显式运行。Rust 评测复跑的 `gt_sha256` 标识包内的评测工具，使用 Python 适配器时该字段标识包内的正式 CLI。

源码包从选定的提交或标签导出。先检查同一快照的归档边界，再导出到本地构建目录。以下以 `HEAD` 为例。

```sh
make check-source-release RELEASE_REF=HEAD
make source-release RELEASE_REF=HEAD
```

`check-source-release` 检查归档文件和必需的 CLI／Android SDK 构建输入。发布前应从解压后的源码包分别验证 `make` 和 `make capture-android`。提交中的文件决定归档内容，未提交的文档或实现改动留在工作区。
