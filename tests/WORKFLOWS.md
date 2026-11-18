# 产品、测试、评测与 Git 边界

正式 CLI 位于 `rust/traceq-cli`，通过 `traceq-query` 调用 `traceq-core`。`make` 和 `make install` 只构建或安装正式 `traceq`。
`make` 更新工作区的 `cli/traceq`，PATH 中已经安装的程序需要通过 `make install` 更新。
切换默认版本时，先保存旧安装的二进制和哈希，再核对 `command -v traceq` 指向的实际文件与已验收的 `cli/traceq` 哈希一致，并用同一份冻结 trace 检查查询。
验收记录同时保存构建产物和实际执行文件的绝对路径及哈希；仅记录源码提交无法确认当前安装的程序身份。
Agent 可直接调用正式 CLI 的结构化查询。`agent-query` 由独立的 `evaluation/runner` 实现，用于任务包策略、调用记录和评测成本统计。
`make eval-cli` 生成 `build/evaluation/traceq-eval`。历史任务包将它复制为 `work/traceq`，包内名称不代表它是正式 CLI。

正式 Android SDK 位于 `rust/traceq-capture`，复用 `traceq-core` 的事件和编码以及 `traceq-observer` 的 CPU 布局。
`capture/traceq` 提供 C ABI 头文件、链接配置和固定版本的 Gum 源码修补。`tools/` 和 `dependencies/` 提供共享构建输入。
Mac 宿主采集器、普通 C／汇编对照、旧 C++ 参考和观察实验均位于 `tests/`。Rust 的内联单元测试由 `cfg(test)` 隔离。
`rust/traceq-core/tests` 和 `examples` 供独立校验使用，正式构建不编译这些入口，源码发布包也排除它们。

| 类别 | 维护的输入 | 构建或运行结果 | Git 和源码发布 |
| --- | --- | --- | --- |
| 正式产品 | `rust/traceq-{cli,query,core,capture,observer}` 的运行时代码，`capture/traceq` 的 C ABI／Gum，`tools/`、`dependencies/` | `cli/traceq`、`build/traceq-android/libtraceq_capture.so` | 源码跟踪，进入产品源码包；生成的二进制忽略 |
| 回归测试 | `tests/`、Rust 的 `cfg(test)`、`tests` 和 `examples` 入口 | `build/traceq-host/`、临时固定输入和检查结果 | 测试源码跟踪；独立测试／示例目录从产品源码包排除，内联测试由编译条件隔离 |
| 评测 | `evaluation/` 的任务打包、查询策略、计费记录和评分；其回归在 `tests/evaluation/` | `build/evaluation/traceq-eval`、显式任务包和模型运行日志 | 评测源码跟踪，评测与其回归从产品源码包排除；生成物忽略 |
| 本地研究和历史证据 | `experiments/`、隔离的 `rust/traceq-engine/`、`docs/`、冻结二进制及失败记录 | `artifacts/`、`.deps/`、`build/` 中的具体实验产物 | 留在本地，不进入 Git 和产品源码包；有价值的最小回归提取到 `tests/` |

这里的“正式产品”说明代码职责。工作区的一次构建仍是候选；通过验收并记录源码、实际二进制哈希和证据后，才能切换为已接受版本。
`cli/traceq`、PATH 中安装的 `traceq`、评测任务包内的 `work/traceq` 分别核对身份，目录名和可执行文件名都不能代替验收记录。
正式 Agent 使用同一个产品 CLI 的 JSON 查询。评测的 `agent-query` 增加任务包限制、调用日志和成本统计，仅由独立评测入口提供。

## 按改动运行检查

| 场景 | 命令 | 范围 |
| --- | --- | --- |
| 查询语义 | `make check-cli` | 正式 CLI 与固定输入的回归 |
| 构建或工具链 | `make check-cli-clean` | Mac ARM64 临时空缓存构建与 CLI 回归 |
| 分配器采集 | `ANDROID_NDK_HOME=/path/to/ndk make check-allocator-android` | 一加 11 上自有原生进程的完整 libc 分配／复制采集、查询和两次 11 秒延迟存活，不操作 App |
| 半字原子访存 | `python3 tests/integration/check_halfword.py --ndk /path/to/ndk --out /path/to/new-run` | 独立汇编／C、别名、失败比较、并发返回值及两次 11 秒延迟存活；`--verify-only` 复用已有 trace |
| 评测适配器 | `make check-eval` | Rust 入口单元测试和 `tests/evaluation/test_entry.py`，无模型调用、无设备调用 |
| 扩展适配器验证 | `python3 tests/evaluation/check_adapter.py --entry rust --trace /path/to/frozen/sample1.gtsw` | 显式提供第 83 轮冻结输入，保留现有断言和成本口径 |
| 评测日志验证 | `python3 tests/evaluation/check_adapter.py --evaluation-logs-only` | 本地假子进程的原始日志与退出状态，无模型调用 |
| 评分负对照 | `python3 tests/evaluation/check_controls.py --baseline /path/to/frozen-run --run /path/to/new-control` | 显式任务包和独立原生预期，需要已有宿主夹具 |
| 模型评测 | `python3 evaluation/run_product_evaluation.py --artifact-dir /path/to/paired-packs` | 显式启动配对任务包中的 Terra/max 评测 |
| 源码发布边界 | `make check-source-release RELEASE_REF=HEAD` | 打包器回归及所选提交的归档检查 |
| 导出源码包 | `make source-release RELEASE_REF=HEAD RELEASE_ARCHIVE=build/release/traceq-source.tar.gz` | 固定一次提交身份，校验通过后原子写入同一份快照 |

采集改动按影响范围选择宿主与一加 11 验收。设备操作统一通过 `/Users/fanjiahao05/.local/bin/revkit-phone` 串行执行。
构建、CLI 回归和评测入口检查不会自动启动模型评测或操作设备。

`DC ZVA` 的 64 字节写入观察要求此前已捕获目标代码完成的 `MRS DCZID_EL0`，值为 4，且此后没有 gap。
缺少观察、值不匹配、读取被丢弃或连续性丢失时，清零访存继续保持 unknown；原始指令仍由目标执行。
地址按实际操作数对齐，保留原始标签位，不自动合并带标签地址与无标签地址。
相关最小回归为 `traceq-capture` 中的两个 `cache_zero` 单元测试、`traceq-core` 的系统编码测试，以及
`tests/test_state_stream.py` 的 `test_cache_zero_preserves_all_accesses_and_precise_mixed_sources`。
原生验收需独立核对完整缓冲、范围外保护字节、65 槽现场及实际返回边界；后续 SDK／脱离调用的边界不能替代目标返回点。

## 已知坐标的取证

同一份 trace 的坐标确定后，先列出需要保留的寄存器、访存和检查点事实，再合并查询。
批量 `context` 已返回入口或返回点的所需寄存器时，直接复用这些值。核对完整现场时仍显式选择完整 65 槽，保留未观察到的 `post: null`。

多个访存范围可共用一次 `mem-access`。读写筛选和分页作用于范围并集，每条重叠访问完整返回一次。
当各范围需要不同方向时，取回并集后按范围和方向选择原始记录，保留访问宽度、来源及 `access_index`。

```sh
traceq mem-access FILE \
  --range INPUT_BASE,INPUT_LEN --range OUTPUT_BASE,OUTPUT_LEN \
  --limit 256 --access-index --compact --json
```

不同范围需要不同时间点时，用 `--range-checkpoint` 合并内存快照。将示例参数替换为已知坐标；`--limit` 按每个范围的每个检查点计算字节，整页仍受 4096 字节单元上限约束。

```sh
traceq mem-state FILE \
  --range INPUT_BASE,INPUT_LEN --range-checkpoint RETURN_EV:pre \
  --range OUTPUT_BASE,OUTPUT_LEN \
  --range-checkpoint LAST_WRITE_EV:post --range-checkpoint RETURN_EV:pre \
  --limit MAX_RANGE_LEN --compact --json
```

紧凑输出按当前响应的列、寄存器集合和来源表解释。合并前后逐项核对原始值、每字节来源、unknown、gap、边界和完成状态，保留双方 argv 与响应。
查询组合的调用数和输出量单独记录；模型的决策、token 和任务耗时需要对应评测证据。

## Git 记录与发布

产品、测试和评测源码都保留在同一个 Git 仓库，分别按 `feat`／`fix`、`test`、`build` 或 `chore` 提交具体改动。
评测适配器的修复按其行为单独提交，目录边界不需要额外分支或仓库。提交前检查暂存区，避免把已有用户修改混入本轮提交。

产品行为和对应回归可拆成相邻提交；评测策略与评分规则的变化另行说明，保留旧任务包的原始指导和打分口径。
Git 提交记录源码进度，已接受版本由验收记录关联到提交及二进制哈希；普通开发提交不会自动成为产品发布。
使用明确路径暂存本轮文件，通过 `git diff --cached --stat`、`git diff --cached --check` 和完整暂存差异核对后提交。工作区含用户修改或待验收候选时，避免整仓暂存。

`.gitattributes` 从提交归档排除 `tests/`、`evaluation/` 及开发文档。`.gitignore` 将构建缓存、二进制、trace、运行记录和隔离实验留在本地。
忽略规则不影响已跟踪文件，应结合 `git ls-files -ci --exclude-standard` 和 `git diff --cached` 检查。
`git archive` 与 `make source-release` 从所选提交读取内容，未提交的工作区修改不会进入快照。
发布包包含 CLI、Android SDK 和共享构建输入。导出后应在解压目录验证构建，完整 checkout 才提供测试与评测命令。

历史失败、冻结二进制及诊断候选继续保存在本地产物目录。诊断候选通过相关验收并正式切换之前，验收记录仍引用已接受的 SDK／CLI 身份。
