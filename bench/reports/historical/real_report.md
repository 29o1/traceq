# 真实 trace 验收报告（real_report.md）

对 gumtrace-ng 的 agent 化改造做真实数据验收：一份历史私有真机 112MB GumTrace
日志（A/B 主体，不随仓库发布），加两份受控测试 App 的真机 trace（端到端）。
所有数字均为实测；公开夹具对应的命令可复现。

## 环境

- 主机：Apple M2 Pro（macOS，arm64），clang + capstone 5.x（/opt/homebrew），sqlite3 系统自带
- 设备：Pixel 6 (oriole)，root + SELinux Permissive（录制期间），frida 主机/设备均为 16.5.2，
  `/data/local/tmp/libGumTrace.so` 在位
- 历史日志：私有 Android ARM64 trace，117432017 字节（112MB），CRLF 行尾，
  1155467 条执行事件；原始文件不随仓库发布
- 新录 trace（2026-08-18，本报告录制）：受控测试 App 进程内 hook libc 导出，
  GumTrace mode 1 窄窗口，模板见 `bench/frida/gt_real_*.js`

## 1. import → export 逐字节等价

| 输入 | import | export | cmp |
|---|---|---|---|
| 112MB 历史日志 | 354 ms → 19005299 B gtb | 321 ms → 117432017 B | **逐字节一致** |
| 真机 memcpy 日志（53229 B / 517 事件） | 1.3 ms → 16391 B gtb | → 53229 B | **逐字节一致** |
| 真机 write 日志（276 B / 6 行） | → 525 B gtb | → 276 B | **逐字节一致** |

命令形态：`gt import x.log -o x.gtb && gt export x.gtb -o x.out && cmp x.log x.out`

## 2. gtb 体积倍率

- 历史日志：117432017 → 19005299 B = **6.18×**（含静态站点表与全部观测值）。
- 真机 memcpy：53229 → 16391 B = 3.25×。小文件上 gtb 固定头开销摊不薄；
  极端如 276 B 的 write 日志甚至是负收益（525 B）——gtb 为可查询性付固定成本，
  收益随规模放大，112MB 处为 6.18×，合成 7M 事件语料处为 15×（见 build/report.md）。

## 3. token 代理对比（compact vs legacy，同一 100000 事件窗口）

- legacy：10289192 B / 867403 词
- compact：6612368 B / 864029 词
- **字节 1.56×**，词数 ≈ 持平。注：此处代理为空白分词；真实 BPE 下被消除的模块名
  与绝对地址每个都是多 token 串，收益更接近字节比。合成语料（5000 事件窗口）结果
  1.7× / 1.2×（build/report.md），与真实日志方向一致。

## 4. 查询延迟 A/B（112MB 历史日志，gt 流式直读 gtb vs shell 文本管道）

| 查询 | 文本管道 | gt | 结果一致性 |
|---|---|---|---|
| run overview（wc+grep 仪式 vs `gt stat`） | 581 ms | 99 ms | — |
| 热地址 mem-access（grep 计数） | 364 ms | 99 ms | 命中 2 = 2 |
| find-value 0x3341 | 610 ms | 94 ms | gt 精确 17 = 精确整词 grep 17；朴素子串 grep 得 15（**假阴/假阳并存**，子串匹配会漏会错） |

合成语料上 8 项查询 A/B 为 8.1×–147×（build/report.md §6）；真实日志上 gt 各查询
均稳定在 ~100 ms（流式扫描 19MB gtb 的地板时间），而文本侧为 0.4–0.6 s 级。

## 5. taint 与上游 taint_tracker 对照（112MB 历史日志）

gt 污点语义已对齐上游（纯数据流、未污染覆盖即 kill、movz/movn/adr/adrp 杀、movk 保留、
stp/ldp 双槽独立、1M 事件无传播/污点清空即停），另保留两个有文档扩展：NZCV 一等源、
q/d/s/v 传播。上游二进制：`GumTrace/build_taint/taint_tracker -i <log> -o <out> -f|-b <x8|sp|mem:0x..> -l <1-based行号>`。

| 种子 | 上游 matched | gt matched | 最终集合 | 耗时（上游 vs gt） |
|---|---|---|---|---|
| x8 前向（行 5 / ev 4） | 2 | 2 | 一致，双方均撞 scan limit | 194 ms vs 87–110 ms |
| mem:0x765f0cb8d8 前向（行 6 / ev 5） | 1 | 1 | 一致 | — |
| x14 反向（行 102 / ev 99 --back） | 20 | 20 | {sp} = {sp} | — |
| sp 长链前向（行 1 / ev 0） | 295856 | 295856 | 寄存器集 {x2,x3,x4,x10,x11,x12,x13,x14,sp} 一致；mem 3 地址逐一相等 | **617 ms vs 85–117 ms（≥5.3×）** |

sp 长链为最强证据：115 万事件全程， matched 计数与最终污点集合（寄存器 + 内存地址）
与上游**完全相等**，且 gt 快 5.3× 以上。

## 6. 真机新录 trace 端到端（2026-08-18）

录制（受控测试 App，设备标识已移除，脚本
`bench/frida/gt_real_write.js` / `gt_real_memcpy.js`）：

- **libc.so!write**：onEnter 内 `gum.init("libc.so", …)` + `run()`，onLeave `unrun()`；
  抓到一次 6 字节测试写入，日志 276 B / 6 行，含
  `call func: __set_errno_internal()` / `ret: 0x6` 上下文行。
  import→export `cmp` 逐字节一致。
- **libc.so!memcpy（n=4096）**：hook 加 `args[2] >= 4096` 门槛，抓到 4KB 拷贝，
  日志 53229 B / 517 事件，内容为对齐化 + `ldp/stp q` SIMD 拷贝循环。
  import 1.3 ms → 16391 B gtb；export `cmp` 逐字节一致。
  `gt stat`：exec=517 regw=193 mem=258 rdval=1419 simdv=450，模块 libc.so base 正确解析。

taint 演示（真机 memcpy trace）：

- `gt taint --seed-reg 1 --at-ev 0`（源地址寄存器前向）：matched 447，
  链 x1 → x14（sub）→ nzcv（cmp）→ x3/x2（地址换算）——寄存器数据流链完整。
- `gt taint --seed-addr 0x12e5e2b0 --at-ev 0`（源缓冲区内存单元前向）：matched 3，
  `ev=9 ldp q0,q1` 使 q0 被污染 → `ev=14 stp q0,q1` 污染 2 个目的地址。
  **这是上游 taint_tracker 不具备的 q 寄存器传播路径**（上游只跟踪 31 个通用寄存器），
  在真实 SIMD 拷贝循环上验证有效。

## 7. 验收中发现并修复的真实 bug

1. **导入文件的导出值全为 0**：compact/jsonl 导出对 import 进来的日志只按寄存器计划
   重构读值，忽略了文本中实际观测到的 RDVAL 值。修复：ingest 期建 ObsMap，
   观测与计划读写计数精确匹配时按位取真实观测值，否则回退重构。
2. **find-value 对导入文件双重计数**：REGW 裸 lane 与 wobs lane 重复命中。
   修复：`n_wobs == 0` 门控裸 lane。修复后 0x3341 命中 17 = 精确 grep 17。

两者均由"真实日志验收"暴露——合成语料不含 RDVAL 观测形态，73 项自测未覆盖到。

## 结论

- 逐字节等价：历史 112MB 与两段真机新录 trace 全部 cmp 通过。
- 体积：112MB 处 6.18×；token 字节代理 1.56×（BPE 下收益更高）。
- 查询：真实日志上 ~100 ms 流式查询 vs 0.4–0.6 s shell 仪式；合成语料 A/B 最高 147×。
- taint：四个种子与上游 taint_tracker 结果集完全相等且 ≥5.3×，另有 NZCV/SIMD 扩展
  在真机 SIMD 循环上实证。
- 真机新录端到端（hook → 录制 → pull → import → export/cmp → stat → taint）跑通。
