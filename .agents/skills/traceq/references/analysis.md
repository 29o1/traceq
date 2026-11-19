# 查询结构化执行证据

## 确认可以查到什么

遇到陌生文件时，先运行 `traceq stat FILE --json`，按文件内容确认格式，并查看 profile、指令数、gap 和采集范围。GTSW 和 GTSC 的 profile 2 提供执行状态，profile 1 提供结构化写入记录。执行状态查询即使只选很小的窗口，也会校验到 END 及其尾部。解释结果前先检查退出码。校验失败时保留原文件和错误信息。

## 按问题选择查询

用所选 CLI 的子命令帮助核对可选参数。示例中的 `TRACEQ_BIN` 是正式 CLI 的路径。其他变量取自当前 trace 或任务。

```sh
"$TRACEQ_BIN" stat "$TRACE_FILE" --json
"$TRACEQ_BIN" instructions "$TRACE_FILE" --limit 12 --json
"$TRACEQ_BIN" find-pc "$TRACE_FILE" --module "$MODULE" --off "$MODULE_OFFSET" --limit 8 --json
"$TRACEQ_BIN" context "$TRACE_FILE" --at-ev "$EVENT" --before 2 --after 2 --json
"$TRACEQ_BIN" reg-state "$TRACE_FILE" --at-ev "$EVENT" --phase pre --reg x0 --json
"$TRACEQ_BIN" mem-access "$TRACE_FILE" --range "$BASE,$LENGTH" --write --limit 16 --json
"$TRACEQ_BIN" mem-state "$TRACE_FILE" --range "$BASE,$LENGTH" --at-ev "$EVENT" --phase pre --json
"$TRACEQ_BIN" last-writers "$TRACE_FILE" --range "$BASE,$LENGTH" --at-seq "$EVENT" --limit 16 --json
"$TRACEQ_BIN" boundaries "$TRACE_FILE" --limit 8 --json
```

如果 `last-writers --help` 列出了 `--checkpoint`，可以一次扫描比较两个截点的写入历史。两个截点都取该事件中已记录访存之后的状态。需要指令执行前的快照时，用 `mem-state --phase pre`。

```sh
"$TRACEQ_BIN" last-writers "$TRACE_FILE" --range "$BASE,$LENGTH" --checkpoint "$EVENT" --checkpoint "$LATER_EVENT" --runs --limit 16 --json
```

- 已知数值但缺少坐标时，先用 `find-value` 找候选。确定来源前，核对事件、操作数或内存位置，以及原生输入输出。
- 同一份 trace 有多个事件或范围时，使用命令支持的批量选择。用 `meta.shown`、`meta.total` 和 `meta.truncated` 解读分页状态，翻页时使用同一份 CLI。
- 优先查看带字段名的 JSON 行。输出量较大时，可使用紧凑格式或将连续字节的写入归并为区段。遇到引用索引时，用当前响应的元数据解析。

## 解释并交付证据

- 分清记录到的读写、指定事件执行前后的状态，以及最后一次观测到的写入。后续出现 gap 时，旧写入仍可能作为历史证据保留，而当前值为未知。
- 保留完整事件坐标、阶段和记录的 PC。`off` 相对采集基址。定位到模块时，优先使用模块查询返回的 `module_offset`，或根据已确认的模块映射换算。
- 缺少观测、拿不到执行后状态、查询无结果分别对应不同情况。报告 `unknown` 时附上采集范围或 gap。有效的 END 表明采集范围内留下的记录通过了流完整性校验。
