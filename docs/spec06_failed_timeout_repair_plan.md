# SPEC06 失败/超时基本块可行性判定与无回归修复规划

## 1. 背景与基线

本规划以当前 Git 版本为基线：

- 当前 HEAD：`aaabdf6 Add resumable SPEC06 profiling generator`
- `prof.py` 最近功能提交：`fe8b0ab Fix valid initial state generation`
- SPEC06 输入：`/home/huxiabing/Documents/raw_data/spec06/`
- 当前输出：`/home/huxiabing/Documents/raw_data/spec06_pp/`
- 汇总文件：`/home/huxiabing/Documents/raw_data/spec06_pp/_summary.json`
- 基本块总数：459580
- 单块 timeout：300 秒
- 并发数：2

当前结果：

| 状态 | 数量 | 占总数 |
|---|---:|---:|
| passed | 436194 | 94.91% |
| skipped | 20949 | 4.56% |
| failed | 2375 | 0.52% |
| timeout | 62 | 0.01% |

本轮直接处理 2375 个 failed 和 62 个 timeout，目标是先判断它们是否存在合法 initial，再对可解失败按结构范式迭代修复。

历史回归基线为 `tests/analysis_results.json` 中的 2079 个基本块：

- passed：2021
- skipped：58
- failed：0
- timeout：0

2021 个已通过块是硬回归门。任何一个从 PASS 变成 SKIP、FAIL 或 TIMEOUT 都视为回归，不接受相关代码修改。

## 2. 当前数据限制

`tests/generate_spec06_pp.py` 在正式 JSON 中只保留：

- `init_binary`
- `block_binary`
- `qemu_result`

非通过块的三个字段都写为 `null`。任务完成后，逐块状态所在的 `.partial.jsonl` 又会被删除。因此当前 31 个正式 JSON 只能定位 23386 个非通过块，不能逐块区分：

- 20949 个 skip
- 2375 个 failed
- 62 个 timeout

`_summary.json` 只保留每个 benchmark 的聚合数量，也不能恢复失败 ID。因此在修改 `prof.py` 前，必须先重建可复现的逐块状态基线，不能直接根据三个 `null` 字段猜测失败类型。

## 3. 总体目标与硬约束

### 3.1 最终目标

1. 所有当前 failed/timeout 块都完成合法 initial 可行性判定。
2. 存在合法 initial 的块必须修到 PASS，不能用 SKIP 掩盖生成器缺陷。
3. 只有能给出明确无解或方法能力边界证明的块才能标记为 SKIP。
4. timeout 必须先定位阶段并优化；timeout 本身不是无解证明。
5. 最终 SPEC06 结果中 failed=0、timeout=0；剩余非通过块只能是有逐块理由的 skip。
6. 历史 2021 个 PASS 全部继续 PASS。
7. 已通过的 436194 个 SPEC06 块在最终全量验证中不得回退。

### 3.2 禁止事项

- 禁止针对单个 block ID 写特例。
- 禁止因为 solver 返回 unknown、搜索超时或启发式找不到值就标记 SKIP。
- 禁止放宽 replay/QEMU 验证来制造假 PASS。
- 禁止覆盖当前 `/home/huxiabing/Documents/raw_data/spec06_pp/` 基线结果。
- 禁止只验证修复样例而不运行 2079 回归门。
- 禁止提高并发后把资源争用造成的假 timeout 当真实失败。

## 4. 合法 initial 的判定标准

一个基本块“存在合法 initial”至少要同时满足以下条件：

1. 块中的指令能被当前 RISC-V parser、remap 和汇编链正确表达。
2. 所有 live-in 寄存器都能在进入基本块前被初始化，且 init 使用的 scratch 不破坏最终 live-in。
3. 所有实际执行的 load/store 地址都落在 pp 可访问、可初始化的内存窗口内。
4. 访问宽度和对齐满足 QEMU 与目标 RISC-V 环境要求。
5. initial memory slot 覆盖所有会影响地址或数据语义的 source load。
6. memory slot、被测块中的 store、profile 保留区之间不存在非法覆盖；必要的真实 alias 必须保留。
7. `lui/auipc/gp/sp` 等地址来源按最终地址表达式判断，不能仅凭出现某条指令判无解。
8. 生成的 init 和 block 能成功汇编。
9. concrete replay 能证明每个实际访存安全，并保持求解模型与物化值一致。
10. `qemu-riscv64 tools/pp/pp <init> <code>` 返回成功且有有效测量输出。

可行性结论分为四类：

| 结论 | 含义 | 后续动作 |
|---|---|---|
| `pass_witness` | 已找到可汇编、可 replay、可 QEMU 测量的 initial | 直接转 PASS |
| `fixable` | 完整约束 SAT，但生产生成器未找到或物化错误 | 修复通用范式 |
| `skip_proven` | 完整模型 UNSAT，或存在明确且不可绕过的方法限制 | 写入具体 skip reason |
| `unknown` | 超时、solver unknown、诊断信息不足 | 保持待判定，不得转 SKIP |

### 4.1 允许的 skip 证明类型

- 最终访存地址完全固定且不可控，必然落在 pp 合法窗口外。
- 访问必然覆盖 profile 保存区、返回状态或其他不可破坏区域。
- 需要当前 pp/init 汇编无法表达的架构状态，例如未建模 CSR 或特殊执行上下文。
- 在所有安全寄存器重映射下都不存在可用 scratch，且保存恢复也无法保持块入口语义。
- 完整地址、宽度、对齐和 slot 约束模型得到可复现 UNSAT，并能记录导致 UNSAT 的约束组。

以下情况不能单独作为 skip 理由：

- 当前启发式没有找到 concrete value。
- 当前 materialize 或 replay 失败。
- 单次或多次 timeout。
- 仅仅出现 `gp`、`lui`、`auipc`、正 `sp` 偏移、乘法或多级 pointer load。
- 为避免回归而主动绕过新失败。

## 5. 阶段 0：冻结基线并恢复逐块状态

### 5.1 冻结现有结果

保存以下不可变信息：

- Git commit 和 dirty status。
- 当前 `_summary.json` 的副本。
- 31 个源 JSON 的文件名、条数和 SHA-256。
- 31 个当前输出 JSON 的文件名、条数和 SHA-256。
- 历史 2079 基线报告及 2021 个 PASS ID。

建议报告目录：

```text
tests/failure_reports/spec06_aaabdf6_baseline/
  manifest.json
  summary.json
  source_sha256.txt
  output_sha256.txt
  legacy_pass_2021.ids
  legacy_skip_58.ids
```

### 5.2 新增诊断 sidecar

拟新增 `tests/retest_spec06_nonpassing.py`，复用 `generate_spec06_pp.py` 的单块隔离、timeout 和断点续跑能力，但不得在完成后删除逐块结果。

从当前输出中选择三个结果字段均为 `null` 的 23386 个块，以原始 SPEC06 JSON 为真实输入，生成：

```text
tests/failure_reports/spec06_aaabdf6_baseline/status.partial.jsonl
tests/failure_reports/spec06_aaabdf6_baseline/status.json
tests/failure_reports/spec06_aaabdf6_baseline/failed.ids
tests/failure_reports/spec06_aaabdf6_baseline/timeout.ids
tests/failure_reports/spec06_aaabdf6_baseline/skipped.ids
```

每条 sidecar 至少保存：

```text
source_file
source_index
id
function
asm
status
failure_kind
error
timeout_stage
stage_detail
elapsed_s
git_commit
```

执行条件与原始基线保持一致：`jobs=2`、`timeout=300`。重建结果应尽量复现 20949 skipped、2375 failed、62 timeout；若数量不一致，必须先分析并发、环境、非确定性和代码版本差异，不能在不稳定基线上开始修复。

### 5.3 timeout 复核

对恢复出的 timeout 集合执行两轮低干扰复核：

1. `jobs=1, timeout=600`
2. 仍超时的代表块使用 `jobs=1, timeout=1800, verbose=true`

如果 300 秒 timeout 在低并发下通过，应记录为资源争用或预算型 timeout，而不是算法无解。

## 6. 阶段 1：逐块 initial 可行性判定

### 6.1 诊断信息补全

为每个 failed/timeout 保存以下阶段信息：

- parser/remap/branch legalize 是否完成。
- symbolic collect 是否完成及状态数。
- 首个不安全访存指令、宽度和地址表达式。
- 参与地址计算的 live-in、loaded value 和 fixed term。
- solver 结果、耗时、约束数量和最后加入的约束组。
- materialized register/memory slot 值。
- concrete replay 首个分歧。
- QEMU return code、stderr 和是否得到 cycles。

timeout worker 被终止前必须读取并保留 `.stage.json`，不能只写“300 秒超时”。

### 6.2 完整可行性检查

生产启发式之外增加一个诊断模式，用更完整但更慢的模型判断：

- 约束所有实际访存最终地址，而不是只约束中间 base。
- 保留真实 load/store alias 和执行顺序。
- 分开建模 pointer source slot、ordinary data slot 和 profile reserved slot。
- 正确处理 1/2/4/8 字节宽度、符号扩展、零扩展和 `*w` 指令截断。
- 显式建模 `sp` 两侧合法窗口、`gp`、`lui/auipc + controllable residual`。
- SAT 时冻结同一个 model 物化 register 和 memory，禁止二次求值改变依赖。
- UNSAT 时按约束组缩小 unsat core，区分真实无解与生成器额外限制。

只有下列两种情况可以结束可行性判定：

- 得到可 replay、可 QEMU 执行的 witness。
- 得到可复现的无解/方法限制证明。

其余情况保持 `unknown`。

### 6.3 可行性报告

输出：

```text
tests/failure_reports/spec06_feasibility.json
tests/failure_reports/spec06_feasibility.csv
docs/spec06_failed_timeout_feasibility.md
```

每个块必须有结论、证据和下一步，不能只有汇总数量。

## 7. 阶段 2：提取失败范式

### 7.1 结构化特征

对所有 `fixable` 和 `unknown` 块提取：

- failure stage 和 failure kind。
- 规范化 opcode 序列和访存宽度序列。
- live-in 寄存器类别和数量。
- `sp/gp/lui/auipc` 地址来源。
- 地址表达式 DAG：add/sub/mul/shift/extend/load chain。
- pointer load/store 链深度。
- source-critical slot 数量。
- fixed term、scaled residual、正负 offset。
- alias、store-forward 和混合宽度关系。
- solver 约束数、状态数和 timeout stage。
- replay 首个分歧类型与 QEMU 失败类型。

### 7.2 聚类与人工确认

按“规范化地址表达式 + 访存行为 + 首个失败阶段”聚类，而不是只按 benchmark 或错误字符串聚类。

每个范式保存：

- 范式名称和精确定义。
- block 数量和 benchmark 分布。
- 3 至 10 个代表 ID。
- 是否已有合法 initial witness。
- 根因假设。
- 预期修改区域。
- 回归风险和反例样本。

输出：

```text
tests/failure_reports/spec06_patterns.json
tests/failure_reports/spec06_patterns.csv
tests/failure_reports/spec06_pattern_ids/<pattern>.ids
docs/spec06_failed_timeout_patterns.md
```

### 7.3 当前优先级参考

当前 failed 高发 benchmark 如下。此表只用于安排诊断顺序，最终仍以结构范式聚类结果为准。

| benchmark | failed | timeout |
|---|---:|---:|
| 445.gobmk | 1398 | 1 |
| 481.wrf | 280 | 4 |
| 403.gcc | 209 | 2 |
| 416.gamess | 109 | 16 |
| 464.h264ref | 101 | 20 |
| 447.dealII | 63 | 0 |
| 454.calculix | 37 | 4 |
| 458.sjeng | 34 | 0 |
| 483.xalancbmk | 22 | 4 |
| 465.tonto | 21 | 0 |

预期优先检查但尚不能先验定性的范式：

- unsupported/parser/assembly failure。
- fixed address 与 controllable residual 判断错误。
- positive-sp 和 profile reserved window。
- pointer source slot 被 store 覆盖。
- 多级 pointer load 和 store-forward。
- scaled index、乘法 residual 和 `base + index - 1`。
- 混合宽度 alias、符号扩展、零扩展和 `*w` 截断。
- materialize model 与 concrete replay 不一致。
- replay 通过但 QEMU 失败。
- symbolic collect、solver、materialize 或 repair 搜索爆炸。

## 8. 阶段 3：按范式迭代修复

每个范式使用相同闭环：

1. 固定代表块、同范式全集和反例 ID 集。
2. 在当前基线提交复现失败。
3. 为根因增加最小单元测试或诊断断言。
4. 修改通用地址/slot/solver/replay 逻辑，不判断具体 block ID。
5. 运行代表块，确认得到合法 witness 和 QEMU PASS。
6. 运行同范式全集，统计 PASS/SKIP/FAIL/TIMEOUT 迁移。
7. 运行 2079 硬回归门。
8. 通过后单独 Git commit，并更新范式报告。

建议修复顺序：

1. 明确异常、未定义变量、parser/assembly 等确定性代码错误。
2. 能被完整模型证明无解的方法限制，转为带具体理由的 SKIP。
3. 数量最大的可解范式，优先处理 445.gobmk 聚类。
4. pointer slot、alias、store-forward 和 replay 一致性。
5. scaled/mixed-width/word-semantics 地址表达式。
6. replay PASS 但 QEMU FAIL 的模型差异。
7. timeout 性能问题。

每次只修一个清晰范式。若一个修改同时影响多个范式，必须拆分测试结果并说明共享根因。

## 9. 阶段 4：timeout 专项

62 个 timeout 必须按最后阶段拆分：

```text
parse/remap
symbolic_collect
constraint_build
solver_check
materialize
concrete_replay
repair
assemble
qemu
worker_shutdown
```

优化原则：

- 先排除并发和 worker queue 假 timeout。
- 对地址表达式做结构缓存和 component 分解。
- 优先约束最终访存地址，减少中间值枚举。
- 对独立 memory component 分组求解。
- 对已确认坏的候选做 blocking clause，避免重复搜索。
- 为昂贵 fallback 设置可观测预算，但预算耗尽返回 timeout/unknown，不返回 skip。
- 同构块共享范式和约束简化规则，不共享具体求解值。

验收时恢复统一的 `jobs=2, timeout=300`。提高 timeout 只能用于诊断，不能作为最终修复。

## 10. 无回归验证体系

### 10.1 2079 硬回归门

建立固定集合：

```text
tests/failure_reports/id_sets/legacy_pass_2021.ids
tests/failure_reports/id_sets/legacy_skip_58.ids
```

每个候选修复进入 Git 前必须执行：

```bash
PYTHONPATH=src python tests/test_all_failures.py \
  --timeout 300 --jobs 2 \
  --report-prefix legacy2079_after_<pattern>
```

硬性验收：

- 2021 个原 PASS ID 仍全部 PASS。
- 任何 PASS -> SKIP 也算回归。
- 58 个原 SKIP 可以保持 SKIP或改进为 PASS，但不能变成 FAIL/TIMEOUT。
- 新增 failed=0，新增 timeout=0。

使用 `tests/failure_reports/report_diff.py` 或扩展后的统一 diff 工具比较 ID 级状态，不只比较总数。

### 10.2 SPEC06 单调通过门

建立并持续扩展 locked-pass 集合：

- 初始包含当前 436194 个 PASS。
- 每轮新修复为 PASS 的块加入集合。
- 开发阶段对受影响 opcode/地址范式做分层抽样回归。
- 每个里程碑重跑全部当前非通过集合。
- 最终必须重跑 459580 个全量基本块，验证整个 locked-pass 集合。

由于全量运行约需 65.5 小时，开发中不能每次修改都全跑 SPEC06，但任何里程碑和最终结论都必须经过全量验证。

### 10.3 结果 diff 的失败条件

自动 diff 遇到以下情况直接返回非零：

- legacy PASS 变为任何非 PASS。
- locked SPEC06 PASS 在全量验证中变为非 PASS。
- 新增 timeout。
- 新增没有证明材料的 skip。
- 源字段 `id/function/asm/binary` 被改写。
- `init_binary/block_binary/qemu_result` 出现部分为 null、部分非 null 的不一致状态。

## 11. 里程碑与验收

### M0：基线可复现

- 恢复 23386 个非通过块的逐块状态。
- failed/timeout/skipped 都有 ID sidecar。
- 2079 回归基线可稳定复现。

### M1：可行性判定完成

- 2437 个 failed/timeout 全部进入 `fixable`、`skip_proven` 或 `unknown`。
- `skip_proven` 有逐块原因和证据。
- `unknown` 有明确缺失信息，不被伪装为 skip。

### M2：失败范式稳定

- 所有 fixable/unknown 被结构范式覆盖。
- 每个范式有代表、全集、反例和回归集。
- 范式数量和成员关系可以由脚本重复生成。

### M3：范式迭代修复

- 每个已修范式在目标集合上无 failed/timeout。
- 每次提交通过 2079 硬回归门。
- SPEC06 locked-pass 集合单调增长。

### M4：最终全量验收

使用新目录，禁止覆盖基线：

```text
/home/huxiabing/Documents/raw_data/spec06_pp_fixed_<git-short-sha>/
```

最终执行：

```bash
PYTHONPATH=src python tests/generate_spec06_pp.py \
  --input-dir /home/huxiabing/Documents/raw_data/spec06 \
  --output-dir /home/huxiabing/Documents/raw_data/spec06_pp_fixed_<git-short-sha> \
  --jobs 2 --timeout 300 --progress-every 100
```

最终验收标准：

- files=31，total=459580。
- failed=0，timeout=0。
- 所有剩余 skipped 都有 `skip_proven` sidecar。
- 当前 436194 个 SPEC06 PASS 全部仍为 PASS。
- 历史 2021 个 PASS 全部仍为 PASS。
- 删除三个新增结果字段后，新输出与原始 SPEC06 输入逐项一致。
- 每个块的三个结果字段要么全为字符串，要么全为 `null`。
- 输出 JSON 全部通过完整解析校验。

## 12. Git 与报告纪律

- 当前 `aaabdf6` 作为修复前代码基线，不改写历史。
- 先提交诊断基础设施，再提交算法修复。
- 每个 commit 只覆盖一个失败范式或一个明确的诊断能力。
- commit message 写明范式和状态变化，例如：

```text
Fix source-critical pointer slot aliasing

SPEC06 pattern: pointer_source_slot_overwritten
before: 184 failed, 3 timeout
after: 0 failed, 0 timeout
legacy2079: 2021 pass, 58 skip, 0 regression
```

- 大型 JSON、partial、QEMU 输出和生成二进制不提交 Git，只提交脚本、精简 ID 集、Markdown 汇总和必要的小型回归用例。
- 每次提交保存对应 report 路径和执行命令，保证可追溯。

## 13. 首轮执行顺序

1. 实现状态保留 sidecar 和非通过块选择器。
2. 在不修改 `prof.py` 的情况下重建 23386 个非通过块状态。
3. 对 62 个 timeout 做单并发复核并记录 timeout stage。
4. 对 2375 个 failed 执行可行性扫描，先分出 `skip_proven`。
5. 生成结构范式报告和 ID 集。
6. 选择数量最大且已证明可解的范式开始第一轮通用修复。
7. 运行范式全集和 2079 硬回归门。
8. 通过后提交 Git，再进入下一个范式。

该顺序确保先获得可靠事实，再修改求解器；先证明是否有合法 initial，再决定 PASS、SKIP 或继续修复；并把“不能让历史成功块回退”落实为自动失败门，而不是人工承诺。
