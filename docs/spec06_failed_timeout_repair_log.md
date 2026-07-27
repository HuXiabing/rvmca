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
