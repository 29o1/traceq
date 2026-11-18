# 产品、测试、评测与 Git 边界

正式 CLI 位于 `rust/traceq-cli`，通过 `traceq-query` 调用 `traceq-core`。`make` 和 `make install` 只构建或安装正式 `traceq`。
Agent 可直接调用正式 CLI 的结构化查询。`agent-query` 由独立的 `evaluation/runner` 实现，用于任务包策略、调用记录和评测成本统计。
`make eval-cli` 生成 `build/evaluation/traceq-eval`。历史任务包将它复制为 `work/traceq`，包内名称不代表它是正式 CLI。

正式 Android SDK 位于 `rust/traceq-capture`，复用 `traceq-core` 的事件和编码以及 `traceq-observer` 的 CPU 布局。
`capture/traceq` 提供 C ABI 头文件、链接配置和固定版本的 Gum 源码修补。`tools/` 和 `dependencies/` 提供共享构建输入。
Mac 宿主采集器、普通 C／汇编对照、旧 C++ 参考和观察实验均位于 `tests/`。Rust 的内联单元测试由 `cfg(test)` 隔离。
`rust/traceq-core/tests` 和 `examples` 供独立校验使用，正式构建不编译这些入口，源码发布包也排除它们。

## 按改动运行检查

| 场景 | 命令 | 范围 |
| --- | --- | --- |
| 查询语义 | `make check-cli` | 正式 CLI 与固定输入的回归 |
| 构建或工具链 | `make check-cli-clean` | Mac ARM64 临时空缓存构建与 CLI 回归 |
| 分配器采集 | `ANDROID_NDK_HOME=/path/to/ndk make check-allocator-android` | 一加 11 上自有原生进程的完整 libc 分配／复制采集、查询和两次 11 秒延迟存活，不操作 App |
| 评测适配器 | `make check-eval` | Rust 入口单元测试和 `tests/evaluation/test_entry.py`，无模型调用、无设备调用 |
| 扩展适配器验证 | `python3 tests/evaluation/check_adapter.py --entry rust --trace /path/to/frozen/sample1.gtsw` | 显式提供第 83 轮冻结输入，保留现有断言和成本口径 |
| 评测日志验证 | `python3 tests/evaluation/check_adapter.py --evaluation-logs-only` | 本地假子进程的原始日志与退出状态，无模型调用 |
| 评分负对照 | `python3 tests/evaluation/check_controls.py --baseline /path/to/frozen-run --run /path/to/new-control` | 显式任务包和独立原生预期，需要已有宿主夹具 |
| 模型评测 | `python3 evaluation/run_product_evaluation.py --artifact-dir /path/to/paired-packs` | 显式启动配对任务包中的 Terra/max 评测 |
| 源码发布边界 | `make check-source-release RELEASE_REF=HEAD` | 打包器回归及所选提交的归档检查 |
| 导出源码包 | `make source-release RELEASE_REF=HEAD RELEASE_ARCHIVE=build/release/traceq-source.tar.gz` | 固定一次提交身份，校验通过后原子写入同一份快照 |

采集改动按影响范围选择宿主与一加 11 验收。设备操作统一通过 `/Users/fanjiahao05/.local/bin/revkit-phone` 串行执行。
构建、CLI 回归和评测入口检查不会自动启动模型评测或操作设备。

## Git 记录与发布

产品、测试和评测源码都保留在同一个 Git 仓库，分别按 `feat`／`fix`、`test`、`build` 或 `chore` 提交具体改动。
评测适配器的修复按其行为单独提交，目录边界不需要额外分支或仓库。提交前检查暂存区，避免把已有用户修改混入本轮提交。

`.gitattributes` 从提交归档排除 `tests/`、`evaluation/` 及开发文档。`.gitignore` 将构建缓存、二进制、trace、运行记录和隔离实验留在本地。
忽略规则不影响已跟踪文件，应结合 `git ls-files -ci --exclude-standard` 和 `git diff --cached` 检查。
`git archive` 与 `make source-release` 从所选提交读取内容，未提交的工作区修改不会进入快照。
发布包包含 CLI、Android SDK 和共享构建输入。导出后应在解压目录验证构建，完整 checkout 才提供测试与评测命令。

历史失败、冻结二进制及诊断候选继续保存在本地产物目录。诊断候选通过相关验收并正式切换之前，验收记录仍引用已接受的 SDK／CLI 身份。
