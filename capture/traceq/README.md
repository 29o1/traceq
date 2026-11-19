# traceq capture

基于 Frida Gum/Stalker 采集 ARM64 执行，生成可用 `cli/traceq` 查询的结构化 trace。
Android SDK 面向受控的单线程原生调用。调用方为 `traceq_capture_invoke` 系列接口提供匹配
目标原型的适配器，按模块名或模块内地址选择范围，也可补充代码区间。[Android C ABI](include/AndroidCapture.h)

## 构建

从仓库根目录运行 `make deps-cli` 准备 Rust 工具链和依赖。Android 构建需要 CMake、
已安装的 NDK 和所选 Rust 工具链的 `aarch64-linux-android` 标准库。

```sh
ANDROID_NDK_HOME=/path/to/ndk make capture-android
```

Android 库位于 `build/traceq-android/libtraceq_capture.so`。在 macOS ARM64 的 Git checkout 中，
`make capture-host` 生成 `build/traceq-host/traceq-capture`，供本地采集验证。
构建脚本按平台准备 Gum devkit。[固定依赖及校验和](../../dependencies/gum-devkits.json)

查询命令见[中文 README](../../README.zh-CN.md)。采集实现源自 GumTrace，来源仓库、提交、路径
和哈希见 [PROVENANCE.json](PROVENANCE.json)。
