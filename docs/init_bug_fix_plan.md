# Initial 生成器剩余 247 个可解失败块修复规划

本文基于当前报告：

- `tests/failure_reports/current_full_after_5922eb0_300s.json`
- `tests/failure_reports/current_full_after_5922eb0_300s_init_feasibility_reviewed.json`

当前全量结果为 2079 个基本块中 1757 通过、249 failed、73 skipped。249 个 failed 中，`450.soplex_229` 和 `450.soplex_4486` 已确认为方法局限下天然无解，记录在 `docs/soplex_unmeasurable_blocks.md`。其余 247 个 failed 块应存在合法 initial，修复目标是把这些块从 failed 收敛到 pass，且不让当前已通过块回退。

## 总体目标

最终验收口径：

- 全量 2079 个基本块重跑后，failed 只允许剩下已确认天然无解的 `450.soplex_229` 和 `450.soplex_4486`。
- 当前 1757 个已通过块不能新增失败。
- 任何新增 skip 必须能证明是固定不可控地址类方法局限，不能因为求解器失败而 skip。
- replay 通过但 pp 失败的块需要单独定位真实执行差异，不能混入 initial 无解。

## 当前失败分布

按 failure kind：

| 类型 | 数量 | 定性 |
|---|---:|---|
| `replay_failed` | 125 | initial 已生成但 concrete replay 不一致，属于 materialize/replay 语义 bug |
| `other_failed` | 55 | 主要是 concrete value、slot non-overlap、sp value 选择失败 |
| `timeout_failed` | 44 | 求解/物化/回放性能问题；其中 `473.astar_473` 单块重跑已通过 |
| `constraint_unsat` | 14 | 2 个天然无解，12 个是当前约束过强 |
| `pp_failed` | 11 | 模型 replay 通过但真实 pp 执行失败 |

按主要失败范式：

| 范式 | 数量 | 主要修复方向 |
|---|---:|---|
| `bad_materialized_init_replay_failed` | 125 | 统一模型求解、物化和 replay 的语义，避免二次求值破坏依赖 |
| `concrete_value_selection_gap` | 43 | 增强地址反推、乘法残差归零、loaded offset 归零、bitmask/shift 反推 |
| `solver_timeout` | 43 | 减少全局约束规模，按地址组求解，加入阶段化快速路径 |
| `replay_pass_pp_fail` | 11 | 定位模型与真实执行差异，尤其浮点/ABI/栈布局/调用返回状态 |
| `slot_nonoverlap_selection_gap` | 9 | 改造栈槽分配器，支持宽度、对齐、允许必要别名 |
| `sp_value_selection_gap` | 3 | 加强把 symbolic/load 值选成 `sp + offset` 的反推 |

失败最多的 benchmark：

| benchmark | 可解失败数 |
|---|---:|
| `465.tonto` | 65 |
| `481.wrf` | 34 |
| `444.namd` | 31 |
| `445.gobmk` | 29 |
| `416.gamess` | 27 |
| `464.h264ref` | 13 |
| `456.hmmer` | 12 |
| `403.gcc` | 11 |

## 修复原则

1. 先修范式，不针对单个 block 写特例。
2. 每轮修改必须保留本轮前的 full report，并对比新增失败。
3. 所有修复都要经过三层验证：单块代表用例、同范式全部用例、全量 2079。
4. 对 `lui/auipc` 的判断只看它是否形成固定不可控访存地址。`lui + 可控索引/乘法残差/load base` 仍应当求解。
5. 不把 timeout 当作无解。timeout 只能说明当前搜索策略或约束规模有问题。
6. replay 是 initial 生成器的最低正确性门槛：生成的 init 必须能在 concrete replay 中复现 symbolic 约束下的访存安全性。

## 阶段 0：建立可重复定位和回归门

目标：后续修 bug 前先把 “失败减少且无回退” 固化成自动化检查。

具体任务：

- 从 reviewed JSON 生成固定 ID 文件：
  - `solvable_247.ids`
  - `method_limit_2.ids`
  - 按 pattern 拆分的 `replay_failed.ids`、`concrete_value_selection_gap.ids`、`solver_timeout.ids`、`pp_failed.ids`
- 增加一个 report diff 脚本，输入 old report 和 new report，输出：
  - 新增 failed 的 ID
  - 新增 skipped 的 ID
  - 从 failed 变 pass 的 ID
  - failure kind 变化
- 单块 verbose 运行时保存：
  - `.init.asm`
  - `.code.asm`
  - `.stage.json`
  - first replay mismatch
  - first unsafe concrete address

验收：

```bash
python tests/test_all_failures.py --report-prefix baseline_247_check --timeout 300 --jobs 4
```

并能用 diff 脚本确认当前基线为 249 failed，其中 247 可解、2 天然无解。

## 阶段 1：修复 materialize/replay 不一致

覆盖范式：`bad_materialized_init_replay_failed`，125 个。

核心判断：这类块已经生成了 concrete init，但 replay 失败，说明求解模型、init 物化、concrete replay 三者没有使用同一组一致的值。

主要代码区域：

- `init_states_for_block()`
- `materialize_init()`
- `replay_concrete_init()`
- `concrete_prefix_states()`
- `replay_prefix_state()`
- `find_replay_access_constraints()`

修复设计：

- 将 materialize 改成单模型冻结流程：所有 live-in register、init memory word、pointer slot、sp-affine slot 从同一个 solver model 中取值，禁止后续 `choose_value()` 重新求出与 model 不一致的值。
- replay 失败时记录首个失败访存：
  - 原始指令
  - symbolic 地址表达式
  - materialized concrete 地址
  - 期望栈范围和宽度
  - 参与该地址的寄存器和 init memory word
- 对 replay mismatch 增加一次 bounded repair：
  - 把首个失败地址加入 “必须落栈” 约束。
  - 禁止已发现的坏 slot 布局。
  - 重新 materialize 一次。
- 避免 source slot 被后续 store 覆盖：
  - 如果某个 load 的值参与后续地址计算，该 load 所在 init slot 必须被标记为 source-critical。
  - source-critical slot 不应与早于该 load 的 store 或 replay 中会覆盖它的 store 冲突。

优先代表块：

- `465.tonto_32057`
- `416.gamess_1416`
- `445.gobmk_850`
- `481.wrf_4109`
- `483.xalancbmk_11449`

验收：

- 125 个 replay_failed 中至少先消掉一批同构块。
- 修复后所有新增通过块必须 pp 通过，不允许从 `replay_failed` 大量变成 `pp_failed`。

## 阶段 2：统一栈槽分配和别名策略

覆盖范式：

- `slot_nonoverlap_selection_gap`，9 个。
- `sp_value_selection_gap`，3 个。
- `many_pointer_slots_store_zero_triplets`，1 个。
- `structure_copy_with_loaded_base_and_source_pointer`，1 个。

主要代码区域：

- `choose_mem_slot_value()`
- `choose_memory_value()`
- `choose_stack_relative_register_value()`
- `choose_base_register_value()`
- `symbolic_word_slot_no_overlap()`
- `symbolic_init_slots_no_overlap()`
- `find_alias_constraints()`
- `find_store_pointer_constraints()`
- `find_pointer_slot_store_constraints()`

修复设计：

- 引入一个统一的 stack slot allocator，集中处理：
  - 访问宽度：1/2/4/8 字节。
  - 对齐：按指令宽度要求对齐。
  - 生命周期：source load slot、pointer value slot、ordinary data slot 分开。
  - 必要别名：同一个源地址多次 load 必须能复用同一个 slot。
  - 禁止别名：source-critical slot 不与会破坏它的 store 重叠。
- 对 “多个 pointer slot 写 0/8/16” 的块，允许顺序分配多个 24 字节区域，而不是把所有 pointer-like slot 过度约束到同一窄范围。
- 对 `sp_value_selection_gap`，补充把任意 symbolic value 选为 `sp + offset` 的统一接口，不只处理寄存器，也处理 loaded value 和 init memory word。

优先代表块：

- `437.leslie3d_581`
- `403.gcc_170`
- `403.gcc_6826`
- `450.soplex_1254`
- `435.gromacs_4840`
- `483.xalancbmk_43161`

验收：

- 9 个 non-overlap failure 全部不再报 `cannot choose non-overlapping concrete value`。
- 3 个 sp value selection failure 不再报 `cannot choose stack pointer value`。
- replay_failed 数量不能上升。

## 阶段 3：地址反推和 concrete value 选择增强

覆盖范式：`concrete_value_selection_gap`，43 个，以及 12 个可解 `constraint_unsat` 中的一部分。

主要代码区域：

- `choose_value()`
- `value_selection_constraints()`
- `concrete_value_from_materialized()`
- `constraints_to_constant()`
- `constraints_to_carrier()`
- `add_neutral_arithmetic_constraints()`
- `add_arithmetic_address_hint_constraints()`
- `add_scalar_zero_address_load_constraints()`
- `add_loaded_pointer_scalar_offset_constraints()`
- `add_loaded_pointer_residual_anchor_constraints()`
- `add_livein_base_residual_anchor_constraints()`
- `add_loaded_address_scalar_zero_constraints()`
- `add_register_anchor_simplification_constraints()`
- `choose_scaled_address_register_value()`
- `choose_affine_addr_offset()`
- `choose_pointer_load_addr_offset()`
- `choose_carrier_residual_stack_offset()`

需要覆盖的地址表达式范式：

- `base + loaded_offset`
- `base + reg_offset`
- `base + (idx << scale)`
- `base + idx * stride`
- `fixed_lui_base + controllable_residual`
- `loaded_base + loaded_stride * scalar`
- `sign/zero extend` 后参与地址计算
- `andi`、`extract`、`subw/addw` 产生的小下标

修复设计：

- 建立一个地址 demand propagation：
  - 从每条 load/store 的最终地址反推到参与变量。
  - 对可归零的乘法项，优先选择一个因子为 0。
  - 对需要保持非零 stride 的情况，选择 stride=1，反推 index 到 `sp - base + offset`。
  - 对 loaded base，给它分配 stack pointer value。
  - 对 loaded offset，优先归零或限制到小正数。
- 支持 `lui + residual`：
  - 如果访存地址是固定 `lui/auipc + imm`，仍归为 method limit。
  - 如果是 `lui + controllable_reg/load/mul_residual`，反推 residual。
- 增加 bitvector 简化 extractor：
  - 识别 `SignExt`、`ZeroExt`、`Extract`、`Concat`、`Shl`、`Add/Sub`。
  - 能把常见 `w` 指令产生的 32 位符号扩展转成可求的小整数约束。

优先代表块：

- `444.namd_196` 到 `444.namd_2158` 这一组：大量同构 loaded/masked index。
- `445.gobmk_801`：`fixed_lui_base + controllable_mul_residual`。
- `456.hmmer_2873/2881/2882`：loaded buffer pointer + loaded byte offset。
- `481.wrf_16800`：`a6 + t4 * ld148(s5)`。
- `416.gamess_23434`：多级数组索引和乘法残差。

验收：

- 43 个 `concrete_value_selection_gap` 大部分转为 pass。
- 12 个可解 `constraint_unsat` 至少消除固定代表块：
  - `445.gobmk_801`
  - `456.hmmer_2873`
  - `456.hmmer_2881`
  - `456.hmmer_2882`
  - `481.wrf_16800`

## 阶段 4：约束 UNSAT 的过约束修复

覆盖 12 个可解 `constraint_unsat`：

```text
400.perlbench_22032
403.gcc_65434
416.gamess_23434
437.leslie3d_581
445.gobmk_801
450.soplex_1254
456.hmmer_2873
456.hmmer_2881
456.hmmer_2882
458.sjeng_2359
481.wrf_14672
481.wrf_16800
```

修复设计：

- 把 global constraints 拆成可验证的约束组：
  - range constraints
  - slot no-overlap constraints
  - pointer value constraints
  - residual zero/one constraints
  - replay-derived constraints
- 每组加入前先做 satisfiable 快速检查；失败时记录 unsat group 和涉及变量。
- 对大结构体负偏移访问，按 “寄存器基址 + 负偏移仍落栈” 处理，不能因为偏移为负就丢弃。
- 对 dynamic sp 调整，建立原始 sp 和调整后 sp 的双窗口关系：
  - 原始 sp 保证初始化区域有效。
  - 调整后的 sp 作为普通可控 base，访问仍落入合成栈。
- 对多级 pointer slot，先求必要的最终访存地址，再反推中间 slot，避免同时约束全部中间表达式导致 UNSAT。

优先代表块：

- `403.gcc_65434`：动态 `sp -= aligned(a0 + 17)`。
- `458.sjeng_2359`：`gp - 1272` 负偏移读取 pointer。
- `481.wrf_14672`：大量 `-18xx(base)` 结构体字段和多维索引。
- `400.perlbench_22032`：字符串 offset 和二级 pointer slot。

验收：

- 12 个可解 `constraint_unsat` 不再出现 `init memory constraints are unsatisfiable`。
- 只保留 `450.soplex_229/4486` 两个 method-limit unsat。

## 阶段 5：timeout 性能修复

覆盖范式：`solver_timeout`，43 个，加上 `473.astar_473` 这类 full run timeout 但单块可过的情况。

主要代码区域：

- `static_collect_memory_accesses()`
- `add_access_range_constraints()`
- `try_add_constraint()`
- `try_add_constraint_set_fast()`
- `try_add_constraint_set()`
- `solver_eval_limited()`
- `concrete_prefix_states()`
- `replay_prefix_state()`

修复设计：

- 地址范围约束按同一 base 分组：
  - 同一 base 的多个固定 offset，只需要检查最小 offset 和最大 offset 加访问宽度。
  - 不要对每条访存都重复调用重型 solver。
- 对明显可控的 base 寄存器先直接锚定到 `sp + min_offset`，再检查全部 offset 是否落在 4KB 窗口内。
- 对 `materialize_init:load_slots:entry` 和 `memory_values:slot` timeout，优先使用 slot allocator 的确定性分配，不走枚举。
- 对 `concrete_replay_prefix` timeout，缓存前缀状态时加入更精确 key，并限制只 replay 到首个新依赖点。
- 对 timeout 块先跑代表集，确认每类 timeout 是哪个 stage：
  - `transform:done`
  - `init:materialize_init:load_slots:entry`
  - `init:materialize_init:memory_values:slot`
  - `init:materialize_init:global_constraints:access_range`
  - `init:concrete_replay_prefix`

优先代表块：

- `464.h264ref_4808`
- `464.h264ref_5793`
- `465.tonto_32060`
- `481.wrf_4543`
- `473.astar_473`

验收：

- 同样 timeout 阈值 300s 下，timeout_failed 明显下降。
- 不通过简单加大 timeout 来掩盖指数级约束问题。

## 阶段 6：pp_failed 修复

覆盖范式：`replay_pass_pp_fail`，11 个。

ID：

```text
416.gamess_21236
416.gamess_21391
416.gamess_22175
416.gamess_22335
416.gamess_23071
416.gamess_23298
416.gamess_23311
416.gamess_71136
465.tonto_14904
465.tonto_14937
465.tonto_25366
```

修复设计：

- 对每个 pp_failed 保存：
  - generated init
  - generated profile code
  - qemu exit code
  - stderr/stdout
  - 最后执行到的地址或 signal
- 对比 angr replay 和 qemu 行为：
  - 浮点寄存器和 FCSR 是否初始化一致。
  - `gp/tp/ra/sp` 是否被 profile wrapper 破坏。
  - 栈对齐、保存区和真实返回地址是否一致。
  - init 中 narrow store/load 是否存在真实机器上的未对齐差异。
- 先修 pp 工具或 wrapper 的共性问题，再回到 initial 生成。

验收：

- 11 个 replay-pass pp-fail 全部要么 pass，要么被证明为 pp wrapper 的明确边界问题并单独记录。
- 浮点指令块必须继续可测，不能用禁用浮点作为规避。

## 阶段 7：benchmark 优先级

如果按 benchmark 聚焦，建议顺序如下：

1. `465.tonto`：65 个，可覆盖 replay、timeout、pp 三类大头；能暴露地址反推和 materialize 一致性。
2. `444.namd`：31 个，集中在 concrete value selection，适合一次性验证 loaded/masked index 反推。
3. `481.wrf`：34 个，覆盖负偏移大结构体、timeout、多维索引。
4. `445.gobmk`：29 个，覆盖 `lui + residual`、non-overlap、timeout。
5. `416.gamess`：27 个，覆盖 pp、replay、多级数组和 Fortran 风格大栈帧。

每个 benchmark 修复完成后都要跑：

```bash
python tests/test_all_failures.py --report-prefix focus_<benchmark> --timeout 300 --jobs 4 --ids-file <benchmark_failed_ids>
```

然后再跑全量，避免局部修复导致其他 benchmark 回退。

## 每轮修复工作流

每一轮只处理一个主范式：

1. 选择 3 到 5 个代表块，跑 verbose，保存 init/code/stage。
2. 写下该范式的必要解关系，例如 `base = sp + k`、`offset = 0`、`stride = 1`。
3. 修改通用逻辑。
4. 跑代表块。
5. 跑该范式全部 ID。
6. 跑全量 2079。
7. 用 report diff 检查：
   - 新增通过数量。
   - 新增失败数量必须为 0。
   - 新增 skip 必须为 0，除非记录为 method limit。
8. git commit 当前稳定点。

## 预期收敛顺序

建议按下面顺序执行，因为前面的修复会减少后面噪声：

1. 阶段 0：基线和 diff 工具。
2. 阶段 2：栈槽分配和 alias 策略。
3. 阶段 3：地址反推和 value selection。
4. 阶段 4：constraint_unsat 过约束。
5. 阶段 1：replay_failed 一致性修复。
6. 阶段 5：timeout 性能。
7. 阶段 6：pp_failed。

其中阶段 1 和阶段 3 会相互影响。如果某个 replay_failed 的根因是地址反推错误，应归入阶段 3 先修；如果根因是物化和 replay 使用不同 concrete 值，应归入阶段 1。

## 风险点

- 过度归零可能破坏数据依赖：只能归零 non-address-critical 或可证明为 residual 的项。
- 过强 non-overlap 会制造 UNSAT；过弱 non-overlap 会让 init slot 被 store 覆盖。需要用生命周期而不是简单全局不重叠。
- `lui/auipc` 不能一概 skip。只有固定不可控地址访存才能 skip。
- timeout 修复不能只靠增大阈值；必须减少 solver 查询次数和约束复杂度。
- pp_failed 不能轻易归咎 initial；replay 已通过时，要优先检查 wrapper、ABI、浮点状态和真实执行环境。

## 最终交付物

- 修复后的 `src/rvmca/trans/prof.py`。
- 每轮 report：
  - focus report
  - full report
  - report diff
- 更新后的 failure feasibility 文档：
  - 只保留 `450.soplex_229`
  - `450.soplex_4486`
  - 以及可能新证明的 method-limit 块
- git commit，commit message 需要说明本轮修复的范式和全量结果。

