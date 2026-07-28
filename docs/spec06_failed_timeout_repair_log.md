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
