# SPEC06 Failed/Timeout Repair Log

This log records reproducible evidence gathered while executing
`docs/spec06_failed_timeout_repair_plan.md`. A failed or timed-out block is not
classified as SKIP without a reproducible UNSAT or method-boundary proof.

## Baseline Reconstruction (M0)

- Frozen result baseline: `/home/huxiabing/Documents/raw_data/spec06_pp`
- Candidate set: 23,386 blocks whose three generated result fields are null
- Frozen worker commit: `5dc85f7`
- Execution parameters: `jobs=2`, `timeout=300`
- Persistent partial report:
  `tests/failure_reports/spec06_aaabdf6_baseline/status.partial.jsonl`
- Historical hard gate: 2,021 PASS IDs must remain PASS; 58 historical SKIP
  IDs may remain SKIP or become PASS.

The reconstruction runs independently from later diagnostic commits. Its
`state.json` records the worker commit and hashes of `prof.py`, the harness,
and all source/baseline JSON files.

## Pattern: Scaled Loaded Value Plus Fixed Residual

### `400.perlbench_2554`

Status before repair: `replay_range_failure`.

Relevant transformed block shape:

```asm
ld x15, 48(x5)
lui x14, 0x0
addi x14, x14, 856
slli x13, x15, 3
add x14, x14, x13
ld x10, 0(x14)
```

Observed production candidate:

- `x5 = sp - 56`, so the source load reads slot `sp - 8`.
- The slot was initialized to the absolute value
  `0x20000fffdfffff68`.
- Replay passed at the fixed model SP but failed at alternate SP
  `0x7fef00000000`.
- The resulting protected load address remained near the default model SP:
  `0x7ffefffffe98`.
- Running that generated candidate through QEMU exited with SIGSEGV at the
  same address.

Legal initial witness:

```asm
li x31, 0x458
sub x31, sp, x31
srli x31, x31, 3
li x27, 8
sub x27, sp, x27
sd x31, 0(x27)

li x31, 0
li x27, 0x100
sub x27, sp, x27
sd x31, 0(x27)

li x5, 56
sub x5, sp, x5
li x26, 0
```

This materializes the loaded value as `(sp - 0x458) >> 3`. Therefore the
later address is always `sp - 0x100`, independent of the process stack
location. The witness assembled successfully and completed the real command:

```text
qemu-riscv64 tools/pp/pp <witness.init> <block.code>
```

The run returned success and printed `cycles: 12`.

Conclusion: `fixable`, with a concrete legal initial witness. The generator
must preserve a runtime-SP recipe for scaled loaded address terms instead of
storing their fixed-model value as an absolute constant.

## Pattern: Affine Live-in Scale Plus Fixed Residual

### `403.gcc_15826`

Status before repair: `replay_range_failure`.

The transformed access address is `40 * x15 - 271`. A fixed model value for
`x15` cannot survive a runtime stack relocation. The following initial uses
the runtime SP to choose the quotient, then reconstructs and initializes the
exact byte address used by the block:

```asm
li x31, 1024
sub x31, sp, x31
li x27, 271
add x31, x31, x27
li x27, 40
divu x15, x31, x27
mul x31, x15, x27
addi x31, x31, -271
sb x0, 0(x31)
```

The quotient remainder places the final access between `sp - 1024` and
`sp - 1063`. The witness assembled successfully, completed the real QEMU pp
run, and printed `cycles: 1`.

Conclusion: `fixable`. This is a distinct affine live-in pattern and is not
covered by the loaded-value power-of-two recipe.

## Pattern: Affine Loaded Value Scale Plus Fixed Residual

### `403.gcc_53786` and `403.gcc_56309`

Status before repair: `replay_range_failure`.

Both blocks load a 64-bit value from an SP-relative initial-memory slot and
later use that value in an address of the normalized form:

```text
104 * loaded_value - 128
```

The old generator solved a concrete value at `CONCRETE_REPLAY_SP` and stored
that absolute value in the initial-memory slot. At alternate replay SP values,
the later access therefore remained near the original SP and failed the range
guard.

A legal runtime initial is:

```text
loaded_value = (runtime_sp - numerator_offset) // 104
```

For example, `numerator_offset = -112` makes the later address fall between
`runtime_sp - 16` and `runtime_sp - 112` for every 16-byte-aligned runtime SP.
All possible division remainders are multiples of eight, so the 8-byte accesses
remain aligned. The initial code can materialize the quotient with `divu` and
store it in the original SP-relative source slot before entering the block.

The production repair accepts this recipe only when every later address
affected by the loaded value has the same positive affine scale, has no
unresolved residual constraints, and remains in range and aligned for every
possible runtime-SP remainder. The selected quotient is shared by initial-code
emission and concrete replay.

Validation:

```text
403.gcc_53786  PASS
403.gcc_56309  PASS
403.gcc_56742  PASS
```

The third block has the same loaded affine shape with scale 40 rather than 104.
All three generated programs completed the real QEMU pp command and returned
cycle measurements. Conclusion: `fixable`, with legal generated initial
witnesses; these blocks must not be classified as SKIP.

The post-repair 71-block replay-range sweep reported 4 PASS, 66 FAIL, and one
60-second timeout. Three PASS records contained the new quotient recipe and are
the blocks listed above. `403.gcc_53282` also passed twice but its generated
initial did not contain `divu`; it is retained as an incidental solver outcome
and is not attributed to this pattern repair.

## Candidate-Selection Nondeterminism: `403.gcc_59659`

The 71-block sweep reported `403.gcc_59659` as `replay_failed`, with the final
load address tied to the fixed concrete replay SP. An immediate isolated rerun
of the same worktree generated a runtime-SP-relative index instead:

```text
li s1, 0xbdc
sub s1, sp, s1
srli s1, s1, 2
```

That initial assembled, passed concrete replay, and completed the real QEMU pp
command. The first run returned `cycles: 4`; a persisted confirmation rerun
returned `cycles: 2`. Its full generated program is recorded in
`tests/failure_reports/spec06_candidate_nondeterministic_1_recheck/`.

Conclusion: `pass_witness`, with a legal initial. The block must not be marked
SKIP. The differing outcomes with identical source and production code identify
candidate-selection nondeterminism; later repair work must make the safe
runtime recipe deterministic without weakening replay checks.

## Pattern: Shared Live-in With Mixed Affine Scales

### `403.gcc_23083`

Status before repair: `replay_range_failure`.

The shared live-in `x8` contributes to two addresses with different scales:

```text
load_address  = x9 + x8
store_address = x19 + 8 * x8
```

A legal initial sets `x8 = 0`, places `x9` at `sp - 16`, and places `x19` at
`sp - 1024`. A direct witness also initializes the source byte at `sp - 16`.
The witness assembled and completed the real QEMU pp command with a cycle
result (`cycles: 6`). Therefore this block is `fixable`, not SKIP. The same structural shape
occurs in `403.gcc_51922` and `403.gcc_51924`.

The companion variants were checked independently rather than inferred from
the first witness. For `403.gcc_51922`, a legal initial sets the shared `s5`
to zero, the additional scaled companion `s11` to zero, the load base `s1` to
`sp - 16`, and the store base `s2` to `sp - 1024`; QEMU returned `cycles: 9`.
For `403.gcc_51924`, setting the shared `s10` and scaled companion `s3` to zero
with the same safe load/store bases returned `cycles: 1`. Both are `fixable`,
not SKIP.

Production debug output shows the ordering defect. `x9` is materialized first
as a fixed-SP scalar. The subsequent early-zero attempt for the shared `x8`
then fails, and the scaled-address fallback commits:

```text
x8 = 0xfffdfffffff
```

When `x19` is materialized later, the solver repeatedly tests the valid
`x8 == 0` relation but rejects it because the incompatible `x8` value has
already been committed. The resulting load address remains near the old SP at
alternate replay SP values. The repair must order the shared residual before
its independent affine bases; it must not weaken replay checks or special-case
these block IDs.

`tests/test_prof_shared_affine_witness.py` now contains a production-generator
regression test using only this structural instruction pattern. Before the
repair it deterministically reaches the same alternate-SP
`ConcreteReplayFailure` as the SPEC06 block. The test is intentionally red
until the ordering repair is applied.

Direct `pytest` initially imported the adjacent legacy checkout at
`/home/huxiabing/Documents/rvmca/src`, which could produce irrelevant results.
`tests/conftest.py` now puts this checkout's `src` first, and
`tests/test_import_path.py` locks that invariant. The long-running regression
harnesses already applied the same path precedence independently.

## Timeout Pattern: Simple Paired Stores Before Pointer Load

### `416.gamess_1454` and `416.gamess_1506`

Both short blocks exhausted the 300-second baseline budget in
`init:materialize_init:register`, despite having straightforward legal initial
states. Each block increments a scalar, uses it as the common offset for two
byte stores, then loads a pointer from `144(sp)` and reads a word at offset 28.

The witnesses set the scalar to zero, place the two store bases so their final
addresses are `sp - 16` and `sp - 32`, and store `sp - 64` in the pointer slot
at `144(sp)`. The final word address is therefore `sp - 36`. Both witnesses
assembled and ran through the real QEMU pp command:

```text
416.gamess_1454  cycles: 6
416.gamess_1506  cycles: 2
```

Conclusion: both are `fixable`, not SKIP. Their baseline timeout is a solver
search problem, not evidence that no legal initial exists. The witness test is
`tests/test_prof_timeout_witness.py`.

An isolated production rerun of both blocks with a 60-second budget timed out
again at the same stage as M0: `416.gamess_1454` while choosing `x18` and
`416.gamess_1506` while choosing `x19`, both in the `stack_relative` phase.
The persistent report is
`tests/failure_reports/spec06_timeout_simple_store_pair_2_current/`. This makes
the pattern a stable search-complexity defect rather than a transient QEMU or
resource-contention timeout.

## Legacy Regression Gate: `416.gamess_2304`

The first 2,079-block gate for the scaled loaded-value repair timed out on
`416.gamess_2304` at the standard 300-second per-block limit. The timeout was
in `init:materialize_init:register` while materializing `x16`, before the new
load-slot and memory-value behavior introduced by this repair can run.

An isolated rerun of the same patched code with a 600-second limit completed
successfully in 352.09 seconds. Historical reports for the same block range
from a few seconds to roughly 262 seconds, so this is classified as a
budget-sensitive solver runtime, not a functional regression. The locked
PASS requirement remains in force; this block must pass an isolated
low-interference rerun whenever it exceeds the batch timeout.

The loaded-quotient worktree was independently rechecked under the same rule.
With `jobs=1` and a 600-second limit, `416.gamess_2304` completed as PASS in
433.9 seconds. The report is
`tests/failure_reports/legacy_after_affine_loaded_quotient_budget_sensitive_1.json`.
This provides same-`prof.py` evidence for reconciling the 300-second batch
timeout; it does not relax the locked PASS policy.

## Repair: Shared Live-in Mixed Affine Scales

The production repair now detects a live-in that appears with coefficient one
in one address and with a larger affine coefficient in another address, while
the two addresses have independent direct base companions. The complete set of
primary and scaled-support residuals is constrained to zero before any base is
materialized. The repair is enabled only when the full candidate solver proves
the joint zero constraints SAT; an UNSAT or timeout result leaves the original
ordering unchanged.

Validation with the repaired production generator:

```text
403.gcc_23083  PASS
403.gcc_51922  PASS
403.gcc_51924  PASS
```

All three generated initials passed concrete replay and the real QEMU pp run.
The persistent report is
`tests/failure_reports/spec06_after_shared_componentwise_shared_3/status.json`.

## Repair: Disconnected Nonlinear Constraints Blocking Direct Load Bases

### `465.tonto_21117` and `465.tonto_21340`

Both historical regression blocks use one live-in as the base of three direct
loads at fixed offsets 8, 16, and 24. A later load address is governed by a
separate nonlinear equality over the loaded values and other live-ins. The
candidate solver had ten constraints: the direct-base component contained only
the live-in sign guard and `sp = base + offset`, while the nonlinear equality
connected seven other variables. Every base-offset attempt re-solved the full
nonlinear formula with a 100 ms budget and was rejected on timeout, eventually
exhausting both 300-second and 600-second block budgets.

The repair partitions all candidate constraints by their non-SP variables and
solves every connected component at the same fixed replay SP. Because SP is
fixed and no other variable is shared across components, all component results
being SAT is an exact proof that the full conjunction is SAT. The result is
cached by the complete component constraint set. A direct-load base uses this
path only when:

- every address involving the base is a load;
- every such address has a covered fixed residual and stack range;
- no residual constraint is omitted; and
- the expensive nonlinear constraint is disconnected from the base.

No solver-unknown result is accepted, and concrete replay/QEMU validation is
unchanged. Final validation reported:

```text
465.tonto_21117  PASS  14.0s
465.tonto_21340  PASS  13.3s
```

The persistent report is
`tests/failure_reports/legacy_after_shared_componentwise_tonto_2.json`.

## Loaded-Quotient Regression Gate

The frozen pre-repair gate used profiler SHA-256
`098515812bfa6418ffa06625f65c4f4a9ae9c813906b73fd05f649358d598b59`
and completed all 2,079 historical blocks:

```text
PASS     2016
SKIP       58
TIMEOUT     4
REPLAY      1
```

Explicit same-profiler PASS supplements reconcile `416.gamess_2304`,
`456.hmmer_402`, and `464.h264ref_7226`. The only remaining locked regressions
were the two Tonto blocks above; both now pass with the production repair.

## Baseline Integrity Correction

The first long M0 reconstruction started at 10:26, but the main `prof.py` was
modified until 13:21. Since each case starts a fresh worker, its 17,406 records
mixed multiple profiler versions and cannot be a formal baseline. That run was
stopped without deleting its partial report and moved to:

```text
tests/failure_reports/spec06_mixed_prof_exploratory_20260727/
```

The formal M0 reconstruction now runs from an isolated worktree with:

```text
harness commit:  c660362ef0ed82fc371577a7ce89853eee1c528f
harness sha256:  153a69dab148d54568d4d82e81047b0f7b0e50195299345036d22b5a8b29461d
profiler commit: aaabdf6
profiler sha256: c79ad79b83d0fd64024505cd2e8aa2a02c23aa699a97feb9fae01c80b1bef68d
```

Its persistent output is
`tests/failure_reports/spec06_aaabdf6_frozen_baseline/`. Main-worktree changes
cannot affect that run.

## Repair: Runtime-SP Affine Recipe Priority

Scaled-address synthesis can produce an affine runtime recipe such as
`(sp - constant) / scale` while the candidate model also contains a concrete
value tied to the replay SP. The generator previously preferred that concrete
model value. It could therefore discard a valid runtime-SP-relative recipe and
emit an initial that passed at the original SP but failed alternate-SP replay.

The repair gives a proven scaled-address runtime recipe priority over the fixed
candidate-model value. Candidate SAT checks, alternate-SP concrete replay, and
the real QEMU pp validation are unchanged. The historical reproducer now emits
the affine recipe and passes:

```text
445.gobmk_3342   PASS  14.0s
465.tonto_21117  PASS  13.8s
465.tonto_21340  PASS  16.0s
```

The first block locks the recipe-priority regression. The two Tonto blocks also
confirm that the component-wise exact SAT repair continues to pass after the
priority change.

## Final Historical Gate for This Repair Batch

The exact production profiler used for the final gate has SHA-256:

```text
ae4eb4556b93d961b2d10a3d134b38bb5ab81b357fe0bf57212e6fac84d544e0
```

The complete 2,079-block run at two workers and a 300-second per-block budget
reported:

```text
PASS       2019
SKIP         58
TIMEOUT       2
```

The report is
`tests/failure_reports/legacy_after_runtime_priority_full.json`. The two
timeouts were solver-budget-sensitive historical PASS blocks, not accepted as
successful batch outcomes. Each was rerun with the same profiler, one worker,
and a 600-second budget:

```text
416.gamess_2304  PASS  370.7s
456.hmmer_402    PASS  400.5s
```

The supplement reports are
`tests/failure_reports/legacy_gamess_budget_supplement_after_runtime_priority.json`
and
`tests/failure_reports/legacy_hmmer_budget_supplement_after_runtime_priority.json`.
The automated exact-ID reconciliation result is:

```json
{
  "passed": true,
  "required_pass": 2021,
  "allowed_pass_or_skip": 58,
  "regressed_pass": [],
  "failed_allowed": [],
  "missing_required": [],
  "unexpected": []
}
```

Therefore this repair batch satisfies the hard gate: all 2021 historical PASS
blocks still pass, with zero regression. This result only establishes the
regression precondition. Its SPEC06 benefit will be counted separately and
only as original `failed -> PASS` transitions after the frozen 2375-ID baseline
is complete; `failed -> SKIP` will not be counted as an improvement.

## Confirmed Original Failed-to-PASS Lower Bound

The completed frozen baseline records already establish that the following nine
reviewed blocks all had original status `failed`:

```text
400.perlbench_2554
403.gcc_15826
403.gcc_23083
403.gcc_51922
403.gcc_51924
403.gcc_53786
403.gcc_56309
403.gcc_56742
403.gcc_59659
```

They were retested together with the exact production profiler SHA-256 used by
the historical gate. All nine passed transform, alternate-SP concrete replay,
assembly, and the real QEMU pp command:

```text
original failed -> PASS  9
original failed -> SKIP  0
original failed -> FAIL  0
original failed -> TIMEOUT  0
```

The fixed input set is
`tests/failure_reports/id_sets/spec06_reviewed_failed_9.ids`; the generated
report is
`tests/failure_reports/spec06_e478f54_reviewed_failed_9/status.json`. This is a
verified lower bound, not the final benefit count. The full 2375-ID current-code
run must still complete before the batch-wide transition total is reported.

## Frozen-Baseline Status Drift Note

For every fully reconstructed benchmark before Gamess, the frozen status counts
matched the original processing log exactly. Gamess preserved all 7,864
nonpassing IDs but reconstructed them as 104 failed and 21 timeout, while the
original run reported 109 failed and 16 timeout. Thus five solver-budget cases
changed labels between `failed` and `timeout`; no ID became PASS or SKIP.

The original generator deleted its per-block checkpoint after writing the final
JSON, and the final JSON stores all failed, skipped, and timeout outcomes as the
same three null fields. The exact original labels for those five cases are
therefore not recoverable from the final output. Later transition reports must
list this ambiguity separately and must not count a mere failed/timeout label
change as a repair.

## Expanded Original Failed-to-PASS Gate

The final profiler for this repair round has SHA-256:

```text
7b1e41d341d23428ff6a664d66ef34d76aa3d0588faaeb6b92acb305625e8e4d
```

The round adds general repairs for the following structural failure patterns:

- a concrete candidate that raises `ClaripyZeroDivisionError` now falls back to
  solver selection instead of aborting the candidate search;
- a register used as the base of a source load is not incorrectly zeroed as an
  independent additive residual;
- shifted-difference addresses can use a proven runtime-SP scaled-quotient
  recipe;
- affine quotient synthesis supports large constant-multiply carriers and two
  independent carriers while retaining the legacy large-power-of-two path; and
- repeated pointer loads may share an initial-memory slot only when their widths
  match, the solver proves their addresses equal, and every intervening store is
  proven not to clobber any byte of the load.

The fixed 1,430-ID benefit gate completed with:

```text
original failed -> PASS  1430
original failed -> SKIP     0
original failed -> FAIL     0
original failed -> TIMEOUT  0
```

Its report is
`tests/failure_reports/stable1430_after_legacy_alias_fix/status.json`, and its
recorded profiler hash is identical to the hash above. The input set is
`tests/failure_reports/id_sets/spec06_stable_failed_to_pass_1430.ids`.

Three additional blocks from the frozen original-failed population passed three
consecutive checks with the same profiler:

```text
400.perlbench_14923
458.sjeng_918
458.sjeng_925
```

They are recorded in
`tests/failure_reports/id_sets/spec06_stable_failed_to_pass_delta_3.ids`.
Together, the two disjoint ID sets establish a stable lower bound of:

```text
original failed -> PASS  1433 / 2375
```

Changing an outcome from failed to SKIP is not included in this count.

## Pointer-Slot Alias Regression and Repair

The first strict pointer-slot alias repair caused three historical PASS blocks
to regress:

```text
403.gcc_23021
403.gcc_25040
403.gcc_61016
```

Their common pattern reloads a pointer from the same `gp`-relative slot. The
affine-group availability check treated the later legal reuse as a conflicting
slot even though both loads represented the same memory value.

The corrected rule is conservative. Slot reuse is accepted only for same-width
loads whose address equality is solver-proven. For every store between the two
loads, byte-level non-alias constraints cover the full load and store widths.
The candidate address constraint and all no-clobber constraints are committed
atomically; an exception, timeout, or UNSAT result rejects reuse. The rule works
whether the current load reuses an earlier load or a later load reuses the
current one. Alternate-SP replay and QEMU/pp validation remain unchanged.

Validation with the final profiler:

```text
historical pointer regression gate        3 / 3 PASS
pointer failed-to-PASS gate, round 1     14 / 14 PASS
pointer failed-to-PASS gate, round 2     14 / 14 PASS
combined failed-to-PASS gate           1430 / 1430 PASS
```

The production regression test is
`tests/test_prof_pointer_slot_alias.py`; both structural cases require the
generated program to finish a real QEMU/pp run and print `cycles:`.

## Final Exact Historical PASS Reconciliation

The exact 2,021 historical PASS-ID batch used the final profiler above, two
workers, and a 300-second block budget. It completed in 6,363.7 seconds:

```text
PASS       2020
TIMEOUT       1
FAIL          0
SKIP          0
```

The only batch timeout was the previously documented budget-sensitive block
`456.hmmer_402`, at `init:materialize_init:register`. With the same profiler,
one worker, and a 600-second budget, it completed the full transform, replay,
assembly, and QEMU/pp path as PASS in 306.4 seconds.

The reports are:

```text
tests/failure_reports/legacy2021_after_pointer_alias_reuse_fix.json
tests/failure_reports/legacy_hmmer_402_after_pointer_alias_reuse_fix.json
```

Exact-ID reconciliation is therefore:

```text
required historical PASS IDs  2021
confirmed PASS                 2021
regressed                         0
```

This satisfies the hard no-regression condition for the 1,433-block stable
failed-to-PASS lower bound.

## Additional General Repair Patterns

The final profiler for this round has SHA-256:

```text
e4f2dcc10dd8d0f0ab287fc219ee8ed5c0b98ee48e01486e33b2b1d3b62a459e
```

This round extends the generator with general, structure-based repairs. It
does not special-case block IDs and leaves alternate-SP replay, assembly, and
the real QEMU/pp measurement checks unchanged.

- Signed affine factors and stable residual constraints can participate in a
  runtime-SP quotient recipe when every affected access proves the same
  relation.
- Coupled live-ins are anchored together only when symbolic translation proves
  that shifting the group shifts the final address by the same delta. A lone
  additive live-in is not over-constrained.
- Loads whose symbols feed the failing address are considered during prefix
  repair even when they were initially classified as scalar loads.
- Pointer-slot collision repair accounts for both already materialized memory
  and planned slots, so a later pointer value cannot overwrite an intermediate
  scalar source.

The corresponding structural tests cover truncated differences, scaled
indices, store-forwarded address sums, and planned mixed-width pointer chains.
The final targeted rerun reported:

```text
15 passed in 112.99s
```

An earlier broader related-test run on the same profiler hash reported 31
passes. Both test runs exercise generated programs through the real QEMU/pp
path where applicable.

## Repair: Dataflow-Grouped LUI/AUIPC Rebasing

The old normalization independently changed every `lui` and `auipc`
immediate to zero. That destroys a relative offset when two or more U-format
values jointly contribute to one final memory address. A first repair used one
global reference, which recovered 16 Gobmk blocks but incorrectly coupled
unrelated constants and regressed three historical PASS blocks:

```text
465.tonto_24430
481.wrf_3218
481.wrf_41501
```

The final rule propagates each U-format definition through static register
dataflow and unions definitions only when they jointly reach the base of the
same load, store, or atomic access. Each resulting address family uses one
shared reference, preserving its pairwise immediate differences. Unrelated
families are rebased independently. Signed 20-bit immediate handling also
keeps the symbolic model and real RISC-V sign extension consistent.

Validation with the final implementation:

```text
Gobmk relative-LUI cluster       16 PASS / 12 FAIL
U-format-affected historical gate 221 / 221 PASS
known historical regressions         3 / 3 PASS
```

The reports are
`tests/failure_reports/spec06_gobmk_relative_lui28_dataflow_300/`,
`tests/failure_reports/legacy2021_lui_dataflow_static_fallback_300.json`, and
`tests/failure_reports/legacy_lui_dataflow_regress3_300.json`.

## Repair: Stable Symbol for a Downstream Address Load

Angr can occasionally leave a symbolic load's destination register unchanged
and later create a different unconstrained symbol when that register is used
as a memory base. Those two symbols cannot represent one legal initial-memory
value, so candidate replay fails even though a witness exists.

The generator now detects this condition only when the affected load really is
the base of a later memory access. It then discards the incomplete dynamic
collection for that block and invokes the existing instruction-level memory
collector, which keeps one load symbol through its downstream address
dataflow. This is a model-reconstruction fallback, not a replay bypass.

Representative block `481.wrf_26053` changed from replay failure to a complete
QEMU/pp PASS. The fixed WRF family then completed the formal gate as:

```text
original failed -> PASS  147 / 147
original failed -> SKIP    0
```

The report is
`tests/failure_reports/spec06_wrf_static_fallback_pass147_300/status.json`, and
the fixed input set is
`tests/failure_reports/id_sets/spec06_wrf_static_fallback_pass147.ids`.

## Additional Failed-to-PASS Accounting

A disjoint 136-block candidate union covering the other repaired structural
patterns completed with:

```text
original failed -> PASS  131
original failed -> FAIL    5
original failed -> SKIP    0
original failed -> TIMEOUT 0
```

The five outcomes not counted as benefit are:

```text
416.gamess_83495
445.gobmk_10300
447.dealII_30335
464.h264ref_7210
464.h264ref_7608
```

The report is
`tests/failure_reports/spec06_candidate136_e4f2dc_300/status.json`. Only its
131 PASS IDs are frozen in
`tests/failure_reports/id_sets/spec06_additional_failed_to_pass_131.ids`.
This set, the 147-block WRF set, and the previously established 1,433-block
set have pairwise-empty intersections.

## Final Benefit and Historical Gates

The previously established 1,433 original-failed PASS IDs were rerun from
scratch with the final profiler, two workers, and a 300-second per-block
budget:

```text
PASS     1433
FAIL        0
SKIP        0
TIMEOUT     0
```

The persistent report is
`tests/failure_reports/spec06_stable1433_e4f2dc_300/status.json`.

The complete historical hard gate then used the exact 2,021 required PASS ID
set, two workers, and the same 300-second budget. It completed in 6,456.2
seconds with:

```text
PASS             2020
timeout_failed      1
FAIL excluding timeout 0
SKIP                0
```

The only budget timeout was the previously documented
`456.hmmer_402`, at `init:materialize_init:register`. With the identical
profiler hash, one worker, and a 600-second budget, it completed the full
transform, replay, assembly, and QEMU/pp path as PASS in 282.0 seconds. The
reports are:

```text
tests/failure_reports/legacy2021_e4f2dc_full_300.json
tests/failure_reports/legacy_hmmer402_e4f2dc_600.json
```

Exact-ID reconciliation is therefore:

```text
required historical PASS IDs  2021
confirmed PASS                 2021
regressed                         0
```

The three disjoint benefit sets establish the final verified lower bound for
this repair series:

```text
1433 + 147 + 131 = 1711 original failed -> PASS
1711 / 2375 = 72.04%
original failed -> SKIP counted as benefit: 0
```

This benefit is accepted only because the exact historical hard gate remains
2021/2021 PASS.

## Post-1711 Repair: Wider Runtime Affine Quotients

The runtime-SP affine parser previously rejected two valid expression forms:

- `Concat` expressions whose concrete low bits were nonzero, even though those
  bits are part of the affine constant;
- power-of-two scales above 256, even though the existing quotient recipe is
  valid up to the configured 4096-byte stack range.

The parser now accumulates all concrete low `Concat` bits into the constant,
accepts every scale up to `MAX_AFFINE_QUOTIENT_SCALE`, and searches at least one
full scale when choosing a compatible stack offset. Runtime replay, generated
code, and QEMU/pp validation remain unchanged.

Formal 300-second results added two disjoint benefit sets:

```text
large power-of-two WRF affine blocks  32 / 32 PASS
additional shifted-memory blocks       2 /  2 PASS
```

The reports and frozen ID sets are:

```text
tests/failure_reports/spec06_wrf_large_pow2_affine32_300/status.json
tests/failure_reports/id_sets/spec06_wrf_large_pow2_affine_pass32.ids
tests/failure_reports/spec06_shiftmem_scan_pass2_300/status.json
tests/failure_reports/id_sets/spec06_shiftmem_pass2.ids
```

The Gobmk blocks enabled by nonzero low `Concat` bits were already present in
the 131-block additional set, so they are intentionally not counted again.

## Post-1711 Repair: Loaded Scalar Plus a Stack Carrier

Some blocks load a small scalar and later form an address by adding that scalar
to runtime SP or to another independently materialized stack-relative base.
The load-slot classifier conservatively marked the loaded value itself as
`must_be_pointer`, so the old materializer exhausted pointer candidates and
failed even though the complete address had a legal witness.

The new fallback runs only after every old pointer-selection path has failed
and only for `must_be_pointer` slots. It finds additive uses of the slot value,
including explicit aliases known to come from the same initialized load slot,
then jointly requires:

```text
slot value == load alias
complete access address == runtime SP - legal offset
slot value is within the configured small-scalar range
```

The complete candidate solver must satisfy all of these constraints before the
value is committed. Concrete replay and QEMU/pp validation are still mandatory;
there is no block-ID special case and no weakened access check.

Two 300-second rounds produced identical PASS results for each new set:

```text
DealII residual representatives             4 /  4 PASS
additional DealII load-slot aliases         10 / 10 PASS
cross-benchmark GCC/Hmmer aliases             3 /  3 PASS
```

The reports and ID sets are:

```text
tests/failure_reports/spec06_dealii_loaded_sp_residual4_alias_round1_300/status.json
tests/failure_reports/spec06_dealii_loaded_sp_residual4_alias_round2_300/status.json
tests/failure_reports/id_sets/spec06_dealii_loaded_sp_residual_4.ids
tests/failure_reports/spec06_dealii_alias_candidate10_round1_300/status.json
tests/failure_reports/spec06_dealii_alias_candidate10_round2_300/status.json
tests/failure_reports/id_sets/spec06_dealii_alias_candidate_10.ids
tests/failure_reports/spec06_alias_cross_benchmark3_round1_300/status.json
tests/failure_reports/spec06_alias_cross_benchmark3_round2_300/status.json
tests/failure_reports/id_sets/spec06_alias_cross_benchmark_candidate_3.ids
```

The nine candidate ID sets are pairwise reconciled with `sort -u`. Their exact
union before the final combined rerun is:

```text
1711 + 32 + 2 + 4 + 10 + 3 = 1762 original-failed candidates
original failed -> SKIP counted as benefit: 0
```

This union is an input to the final gate, not the claimed benefit count. A
candidate is counted only when the current profiler produces a real QEMU/pp
PASS.

## Final Post-1711 Benefit and Historical Gates

The final combined rerun used the complete 1,762-ID candidate union, two
workers, and a 300-second per-block budget. It completed with:

```text
PASS     1760
FAIL        2
SKIP        0
TIMEOUT     0
```

The two non-PASS IDs were:

```text
416.gamess_82576   init materialization failed in the combined run
453.povray_10052   concrete replay failed
```

An immediate formal retry of those two IDs produced one PASS and one FAIL.
`416.gamess_82576` completed the full transform, replay, assembly, and QEMU/pp
path as PASS in 27.1 seconds. `453.povray_10052` continued to fail concrete
replay in two further current-profiler attempts, including a fixed hash-seed
run. Its old PASS was produced by a different profiler hash and is therefore
not counted.

The conservative current-profiler benefit is consequently:

```text
full combined-run PASS                         1760
same-budget isolated PASS                         1
confirmed original failed -> PASS              1761
1761 / 2375                                   74.15%
original failed -> SKIP counted as benefit         0
```

Equivalently, the disjoint-set accounting removes only the unstable POVRay ID
from the two shifted-memory candidates:

```text
1711 + 32 + 1 + 4 + 10 + 3 = 1761
```

The final one-ID shifted-memory set is frozen in
`tests/failure_reports/id_sets/spec06_shiftmem_confirmed_pass1.ids`.

The benefit reports are:

```text
tests/failure_reports/spec06_benefit1762_final2_300/status.json
tests/failure_reports/spec06_benefit_unstable2_retry1_300/status.json
tests/failure_reports/spec06_povray10052_stability_retry2_300/status.json
tests/failure_reports/spec06_povray10052_hashseed0_300/status.json
```

All four reports identify profiler SHA-256
`bca8036ff9bab9d2d6ce5cea020bf381513c541910dacc794b2c840ba4aef584`
and Git baseline `75b61a8e3a1503d374c96c0993a0d9fb6ddeaed6`.

The complete historical hard gate then reran the exact 2,021 required PASS
IDs with the same profiler, two workers, and a 300-second per-block budget. It
completed in 6,717.0 seconds with:

```text
PASS                 2020
timeout_failed          1
other FAIL              0
SKIP                    0
```

The only timeout was the known budget-sensitive `456.hmmer_402`, at
`init:materialize_init:register`. With the identical profiler, one worker, and
a 600-second budget, it completed the full validation path as PASS in 282.3
seconds. The reports are:

```text
tests/failure_reports/legacy2021_alias_affine_final2_300.json
tests/failure_reports/legacy_hmmer402_alias_affine_final2_600.json
```

Exact-ID reconciliation for the hard no-regression gate is therefore:

```text
required historical PASS IDs  2021
confirmed PASS                 2021
FAIL                              0
SKIP                              0
regressed                         0
```

## Post-1761 Repair: Repeated Pointer-Source Slot Lifetime

Representative `481.wrf_484` repeatedly loads a pointer from `0(s1)`. The
old replay repair protected the initialized slot only from the final pointer
load to that load's last address use. An earlier store could therefore be
materialized on top of the slot. A later reload then read the stored scalar
instead of the pointer and failed alternate-SP concrete replay, despite a
legal initial state existing.

The repair groups same-width loads with the same symbolic source address. For
a repeated source it begins the protected lifetime at the first such load,
uses the first reachable prefix state to locate the concrete source slot, and
adds byte-accurate non-overlap constraints for every intervening store. A
store whose address is solver-proven equal to the source remains available to
the existing store-forwarding path. Replay range checks, assembly, and the
real QEMU/pp measurement are unchanged, and no block ID is consulted by the
implementation.

The final profiler SHA-256 for this round is:

```text
4db11af1abe37fafcc79f41329128947ad91a6d7c975e6d9e8c02d93bebbcb10
```

The structural regression test contains the full repeated-load/store shape
and requires a real QEMU/pp cycle result. The final focused run reported:

```text
tests/test_prof_pointer_slot_alias.py  5 passed in 112.73s
```

A 55-ID WRF scan with the repaired profiler produced 38 PASS and 17 FAIL,
with no SKIP or timeout. This broad scan was used only for discovery. A clean
`d1304d8` A/B run then isolated 22 candidates: 20 were `replay_failed`, one
had an unrelated materialization failure (`481.wrf_1655`), and one already
passed (`481.wrf_1709`). Only the exact 20 old replay failures are attributed
to this repair. All 20 passed with the repaired profiler, and an independent
second current-profiler run again reported 20/20 PASS.

The reports and frozen attributed ID set are:

```text
tests/failure_reports/spec06_wrf_repeated_source_unconfirmed55_candidate/status.json
tests/failure_reports/spec06_wrf_repeated_source_candidate22_d1304d8_ab/status.json
tests/failure_reports/spec06_wrf_repeated_source_pass20_round2_300/status.json
tests/failure_reports/id_sets/spec06_wrf_repeated_source_pass20.ids
```

Two earlier WRF checks on the pre-repair profiler had also found 29 original
failed blocks that were not included in the established 1,761 benefit set.
They had reported 22 PASS / 1 FAIL and 7/7 PASS. All 29 were rerun with this
round's final profiler. The current result is 28 PASS and one materialization
failure (`481.wrf_319`); an isolated single-worker retry reproduced that
failure in 166.8 seconds. `481.wrf_319` has a prior legal QEMU/pp witness, so
it remains a fixable target and is neither counted nor reclassified as SKIP.

The current-profiler report and conservative 28-ID set are:

```text
tests/failure_reports/spec06_wrf_preexisting_pass29_current_slot_300/status.json
tests/failure_reports/id_sets/spec06_wrf_preexisting_confirmed_pass28.ids
```

The 1,761 established IDs, 28 current-profiler pre-existing PASS IDs, and 20
strict A/B benefit IDs have pairwise-empty intersections. Conservative
current-profiler accounting is therefore:

```text
established original failed -> PASS             1761
previously unlogged, current-profiler PASS         28
strict repeated-source old FAIL -> current PASS    20
confirmed original failed -> PASS                1809
1809 / 2375                                    76.17%
original failed -> SKIP counted as benefit          0
```

The exact 2,021 historical PASS hard gate used two workers and a 300-second
per-block budget. It completed in 6,425.2 seconds with 2,020 PASS, zero
ordinary FAIL, zero SKIP, and only the known budget-sensitive
`456.hmmer_402` timeout. With the identical profiler, that block completed the
full transform, replay, assembly, and QEMU/pp path as PASS in 297.6 seconds
using one worker and a 600-second budget. The reports are:

```text
tests/failure_reports/legacy2021_repeated_source_slot_candidate_300.json
tests/failure_reports/legacy_hmmer402_repeated_source_slot_candidate_600.json
```

Exact-ID reconciliation is:

```text
required historical PASS IDs  2021
confirmed PASS                 2021
FAIL                              0
SKIP                              0
regressed                         0
```
