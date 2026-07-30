import json
import subprocess
from pathlib import Path

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.prog import parse_program
from rvmca.trans.prof import fix_lui_auipc_imm, transform_for_profiling


MULTI_LUI_LOAD_BLOCK = [
    "lui a5,0x2",
    "addi a3,a5,-1824",
    "lui a5,0x1",
    "addi a4,a5,0",
    "add a3,a0,a3",
    "addi a4,a4,1696",
    "lui a2,0x5b1",
    "addi a5,a5,1984",
    "addi sp,sp,-32",
    "addi a2,a2,1992",
    "add a5,a0,a5",
    "slli a3,a3,0x2",
    "add a0,a0,a4",
    "sd ra,24(sp)",
    "sd s0,16(sp)",
    "sd s1,8(sp)",
    "add a3,a2,a3",
    "slli a4,a0,0x2",
    "slli a5,a5,0x2",
    "add a5,a2,a5",
    "lw a0,0(a3)",
    "add a2,a2,a4",
    "lw s1,0(a5)",
    "lw s0,0(a2)",
    "addw a0,a0,a1",
    "addw s1,s1,a1",
    "addw s0,s0,a1",
]

MAGIC_DIV_INDEX_BLOCK = [
    "lui a4,0x2aaab",
    "addi a4,a4,-1365",
    "lui a2,0xaaaab",
    "addi a2,a2,-1365",
    "slli a4,a4,0x20",
    "add a4,a4,a2",
    "mulh a4,a3,a4",
    "srai a2,a3,0x3f",
    "sub a4,a4,a2",
    "slli a2,a4,0x1",
    "add a2,a2,a4",
    "slli a2,a2,0x1",
    "sub a3,a3,a2",
    "ld a2,80(sp)",
    "slli a4,a4,0x3",
    "add a4,a2,a4",
    "ld a2,0(a4)",
]

INCOMPATIBLE_ACCESS_DISTANCE_BLOCK = [
    "addi s0,a4,0",
    "ld a4,48(sp)",
    "addi a5,zero,500",
    "lui a3,0x1",
    "mul a5,a4,a5",
    "lw a4,200(s2)",
    "addi a3,a3,403",
    "ld a0,16(sp)",
    "lui a1,0x7d2",
    "addi a2,sp,428",
    "addi a1,a1,-744",
    "sw s0,240(s10)",
    "addi a5,a5,1000",
    "add a5,a5,a4",
    "addi a4,a5,1499",
    "add a5,a5,a3",
    "ld a3,128(sp)",
    "slli a5,a5,0x2",
    "slli a4,a4,0x2",
    "add a5,a3,a5",
    "lw a5,0(a5)",
    "add a4,a3,a4",
    "lw a4,0(a4)",
    "sd a5,64(sp)",
    "addiw a5,s0,0",
    "sd a5,80(sp)",
    "sd a4,56(sp)",
    "auipc ra,0x312",
]

BOUNDED_SHIFTED_INDEX_BLOCK = [
    "lui a4,0x321",
    "slli a2,a5,0x20",
    "srli a5,a2,0x1e",
    "addi a4,a4,-1752",
    "add a5,a4,a5",
    "lw a0,0(a5)",
]

BOUNDED_WORD_AFFINE_BLOCK = [
    "lw a0,0(s1)",
    "ld a5,144(sp)",
    "addw s10,a5,a0",
    "lui s11,0x17c6",
    "addi s11,s11,-624",
    "slli a1,s10,0x2",
    "add a1,s11,a1",
    "sw a5,4(a1)",
]


def _signed_u_imm(value):
    value &= (1 << 20) - 1
    return value - (1 << 20) if value & (1 << 19) else value


def test_u_immediate_rebase_preserves_pairwise_differences():
    program = parse_program(
        "\n".join([
            "lui a0,0x2",
            "lui a1,0x1",
            "lui a2,0x5b1",
            "add a3,a0,a2",
            "ld a4,0(a3)",
            "add a3,a1,a2",
            "ld a4,0(a3)",
        ])
    )

    rebased = fix_lui_auipc_imm(program)
    original = [
        _signed_u_imm(inst.imm)
        for inst in program.insts
        if inst.name == "lui"
    ]
    normalized = [
        _signed_u_imm(inst.imm)
        for inst in rebased.insts
        if inst.name == "lui"
    ]

    assert max(abs(value) for value in normalized) <= 1 << 19
    for lhs in range(len(original)):
        for rhs in range(len(original)):
            assert normalized[lhs] - normalized[rhs] == original[lhs] - original[rhs]


def test_lui_and_auipc_address_families_are_rebased_independently():
    program = parse_program(
        "\n".join([
            "lui a0,0x1",
            "auipc ra,0xffe56",
        ])
    )

    rebased = fix_lui_auipc_imm(program)

    assert [inst.imm for inst in rebased.insts] == [0, 0]


def test_magic_division_constant_used_by_mulh_is_preserved():
    program = parse_program("\n".join(MAGIC_DIV_INDEX_BLOCK))

    rebased = fix_lui_auipc_imm(program)

    assert [
        inst.imm for inst in rebased.insts if inst.name == "lui"
    ] == [0x2AAAB, 0xAAAAB]


def test_magic_division_index_runs_with_legal_initial(tmp_path):
    asm_path = tmp_path / "magic_division_index.S"
    asm_path.write_text("\n".join(MAGIC_DIV_INDEX_BLOCK) + "\n", encoding="utf-8")
    generated_paths = [
        Path(str(OUTPUT_PATH / asm_path.stem) + suffix)
        for suffix in (
            ".init",
            ".code",
            ".init.asm",
            ".code.asm",
            ".stage.json",
            ".error",
        )
    ]

    try:
        transform_for_profiling(asm_path)
        stage_path = Path(str(OUTPUT_PATH / asm_path.stem) + ".stage.json")
        stage = json.loads(stage_path.read_text(encoding="utf-8"))
        assert stage["stage"] == "transform:done", stage

        completed = subprocess.run(
            [
                "qemu-riscv64",
                str(TOOLS_PATH / "pp" / "pp"),
                str(OUTPUT_PATH / f"{asm_path.stem}.init"),
                str(OUTPUT_PATH / f"{asm_path.stem}.code"),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        assert completed.returncode == 0, completed.stderr
        assert "cycles:" in completed.stdout
    finally:
        for path in generated_paths:
            path.unlink(missing_ok=True)


def test_fixed_access_distance_beyond_replay_stack_is_skipped(tmp_path):
    asm_path = tmp_path / "incompatible_access_distance.S"
    asm_path.write_text(
        "\n".join(INCOMPATIBLE_ACCESS_DISTANCE_BLOCK) + "\n",
        encoding="utf-8",
    )

    result = transform_for_profiling(asm_path)

    assert result.startswith("SKIP: no legal initial:")
    assert "exceeds the 4096-byte replay stack" in result


def test_bounded_shifted_index_outside_replay_stack_is_skipped(tmp_path):
    asm_path = tmp_path / "bounded_shifted_index.S"
    asm_path.write_text(
        "\n".join(BOUNDED_SHIFTED_INDEX_BLOCK) + "\n",
        encoding="utf-8",
    )

    result = transform_for_profiling(asm_path)

    assert result.startswith("SKIP: unmappable fixed address access")


def test_bounded_word_affine_address_outside_replay_stack_is_skipped(tmp_path):
    asm_path = tmp_path / "bounded_word_affine.S"
    asm_path.write_text(
        "\n".join(BOUNDED_WORD_AFFINE_BLOCK) + "\n",
        encoding="utf-8",
    )

    result = transform_for_profiling(asm_path)

    assert result.startswith("SKIP: unmappable fixed address access")


def test_multi_lui_address_family_runs_with_legal_initial(tmp_path):
    asm_path = tmp_path / "multi_lui_address_family.S"
    asm_path.write_text("\n".join(MULTI_LUI_LOAD_BLOCK) + "\n", encoding="utf-8")
    generated_paths = [
        Path(str(OUTPUT_PATH / asm_path.stem) + suffix)
        for suffix in (
            ".init",
            ".code",
            ".init.asm",
            ".code.asm",
            ".stage.json",
            ".error",
        )
    ]

    try:
        transform_for_profiling(asm_path)
        stage_path = Path(str(OUTPUT_PATH / asm_path.stem) + ".stage.json")
        stage = json.loads(stage_path.read_text(encoding="utf-8"))
        assert stage["stage"] == "transform:done", stage

        completed = subprocess.run(
            [
                "qemu-riscv64",
                str(TOOLS_PATH / "pp" / "pp"),
                str(OUTPUT_PATH / f"{asm_path.stem}.init"),
                str(OUTPUT_PATH / f"{asm_path.stem}.code"),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        assert completed.returncode == 0, completed.stderr
        assert "cycles:" in completed.stdout
    finally:
        for path in generated_paths:
            path.unlink(missing_ok=True)
