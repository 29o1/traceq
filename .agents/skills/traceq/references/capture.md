# 采集 TraceQ 执行轨迹

对自有测试程序或调用方提供的进程内调试适配器，从选定的 TraceQ 工作区构建 Android ARM64 SDK。构建需要 CMake、已安装的 Android NDK，以及固定 Rust 工具链的 `aarch64-linux-android` 目标。`dependencies/gum-devkits.json` 记录指定的 Gum 依赖版本。在 TraceQ 源码根目录运行以下命令。

```sh
make deps-cli
ANDROID_NDK_HOME=/path/to/ndk make capture-android
```

使用同一工作区下的 `build/traceq-android/libtraceq_capture.so` 和 `capture/traceq/include/AndroidCapture.h`。适配器按真实函数原型调用目标，通过 `traceq_capture_invoke` 或 `traceq_capture_invoke_at` 采集。问题确实涉及其他代码区间时，用 `traceq_capture_invoke_ranges_at` 显式指定额外范围。

- 核对二进制身份、目标原型、已加载模块或地址，以及代码范围。让适配器、上下文和代码映射在所属线程的同步调用完成前保持有效。使用测试程序可控的新输出路径，确保该路径可写。
- 对同一输入做一次普通执行，核对采集时的原生返回值和相关缓冲区内容。分别记录采集状态与目标返回结果。用 `stat` 校验结构化文件，并用本次记录的同一份 CLI 核对关键事实。
- 采集失败或超时时，先查看适配器结果、SDK 报告、文件大小和进程标识。遇到结构校验错误时保留原文件。遇到范围或观测缺口时，先定位具体缺了哪条事实，再决定是否补采。
- 停止采集后，确认同一进程仍能执行相关原生操作。
