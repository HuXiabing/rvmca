import json
import subprocess
from pathlib import Path

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.trans.block import assemble_pp_code
from rvmca.trans.prof import (
    CONCRETE_REPLAY_SP,
    _runtime_recipe_address,
    _runtime_reg_recipe_value,
    transform_for_profiling,
)


BLOCK_ASM = [
    "sub a5,s0,s2",
    "srai a5,a5,3",
    "lui a4,0x134",
    "slli a5,a5,2",
    "addi a4,a4,-456",
    "add a5,a4,a5",
    "lw s0,0(a5)",
]

TRANSLATED_DIFFERENCE_BLOCK_ASM = [
    "sub s5,s5,s4",
    "slli a5,s5,0x20",
    "srli a5,a5,0x20",
    "add a5,s4,a5",
    "sb zero,0(a5)",
    "addi a4,zero,61",
    "ld t4,8(sp)",
    "addi s2,a0,0",
    "sw s5,8(a0)",
    "sd s4,16(a0)",
    "sh a4,6(a0)",
]

TRUNCATED_SCALED_INDEX_BLOCK_ASM = [
    "slli a5,s3,0x4",
    "lbu a4,2(s7)",
    "sub a5,a5,s3",
    "slli a5,a5,0x2",
    "sub a5,a5,s3",
    "add a5,a5,a4",
    "lui a4,0x388",
    "slli a5,a5,0x2",
    "addi a4,a4,1352",
    "add a5,a4,a5",
    "lw a2,0(a5)",
    "addi a3,a0,0",
    "addi a1,s5,0",
    "addi a0,s4,0",
]

SIMPLE_ADDITIVE_ADDRESS_BLOCK_ASM = [
    "addi t1,s9,1",
    "add a5,s5,t1",
    "lbu a1,0(a5)",
    "ld a5,328(s7)",
    "slli t1,t1,0x3",
    "slli a1,a1,0x3",
    "add a5,a5,a1",
    "add a1,s6,t1",
    "ld t3,0(a5)",
    "ld a1,0(a1)",
    "slli a5,s11,0x2",
    "add t3,t3,a5",
    "add a1,a1,a5",
    "lw t4,0(t3)",
    "lw a1,0(a1)",
    "lui t3,0xc5219",
    "addi t3,t3,1872",
    "subw a1,a1,t4",
]


def test_scaled_quotient_recipe_tracks_register_and_address_values():
    recipe = ("affine_scaled_quotient", -452, 4, 8)

    for sp_value in (CONCRETE_REPLAY_SP, 0x7FEF00000000, 0x7FFF12345000):
        reg_value = _runtime_reg_recipe_value(sp_value, recipe)
        block_address = ((reg_value >> 3) << 2) - 456

        assert block_address == sp_value - 4
        assert _runtime_recipe_address(sp_value, recipe, -456) == sp_value - 4


def run_qemu(init_path, code_path):
    return subprocess.run(
        [
            "qemu-riscv64",
            str(TOOLS_PATH / "pp" / "pp"),
            str(init_path),
            str(code_path),
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_shifted_difference_address_has_legal_initial(tmp_path):
    init_path = tmp_path / "shifted_difference_witness.init"
    code_path = tmp_path / "shifted_difference_witness.code"
    init_asm = [
        "li x8,0x133e50",
        "sub x8,sp,x8",
        "slli x8,x8,1",
        "li x18,0",
        "sw x0,-24(sp)",
    ]
    init_path.write_text(
        "\n".join(assemble_pp_code(init_asm)) + "\n",
        encoding="utf-8",
    )
    code_path.write_text(
        "\n".join(assemble_pp_code(BLOCK_ASM)) + "\n",
        encoding="utf-8",
    )

    completed = run_qemu(init_path, code_path)

    assert completed.returncode == 0, completed.stderr
    assert "cycles:" in completed.stdout


def test_shifted_difference_address_is_generated_with_runtime_sp_init(tmp_path):
    asm_path = tmp_path / "shifted_difference_runtime_sp.S"
    asm_path.write_text("\n".join(BLOCK_ASM) + "\n", encoding="utf-8")
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
        assert json.loads(stage_path.read_text(encoding="utf-8"))["stage"] == "transform:done"
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x4" in init_asm
        assert "divu x8, x8, x27" in init_asm
        assert "slli x8, x8, 3" in init_asm

        completed = run_qemu(
            OUTPUT_PATH / f"{asm_path.stem}.init",
            OUTPUT_PATH / f"{asm_path.stem}.code",
        )

        assert completed.returncode == 0, completed.stderr
        assert "cycles:" in completed.stdout
    finally:
        for path in generated_paths:
            path.unlink(missing_ok=True)


def test_truncated_difference_live_ins_track_runtime_sp_together(tmp_path):
    asm_path = tmp_path / "truncated_difference_live_ins.S"
    asm_path.write_text(
        "\n".join(TRANSLATED_DIFFERENCE_BLOCK_ASM) + "\n",
        encoding="utf-8",
    )
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
        assert json.loads(stage_path.read_text(encoding="utf-8"))["stage"] == "transform:done"

        completed = run_qemu(
            OUTPUT_PATH / f"{asm_path.stem}.init",
            OUTPUT_PATH / f"{asm_path.stem}.code",
        )

        assert completed.returncode == 0, completed.stderr
        assert "cycles:" in completed.stdout
    finally:
        for path in generated_paths:
            path.unlink(missing_ok=True)


def test_truncated_scaled_index_gets_runtime_sp_recipe(tmp_path):
    asm_path = tmp_path / "truncated_scaled_index.S"
    asm_path.write_text(
        "\n".join(TRUNCATED_SCALED_INDEX_BLOCK_ASM) + "\n",
        encoding="utf-8",
    )
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
        assert json.loads(stage_path.read_text(encoding="utf-8"))["stage"] == "transform:done"

        completed = run_qemu(
            OUTPUT_PATH / f"{asm_path.stem}.init",
            OUTPUT_PATH / f"{asm_path.stem}.code",
        )

        assert completed.returncode == 0, completed.stderr
        assert "cycles:" in completed.stdout
    finally:
        for path in generated_paths:
            path.unlink(missing_ok=True)


def test_simple_additive_address_does_not_anchor_one_live_in(tmp_path):
    asm_path = tmp_path / "simple_additive_address.S"
    asm_path.write_text(
        "\n".join(SIMPLE_ADDITIVE_ADDRESS_BLOCK_ASM) + "\n",
        encoding="utf-8",
    )
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
        assert json.loads(stage_path.read_text(encoding="utf-8"))["stage"] == "transform:done"

        completed = run_qemu(
            OUTPUT_PATH / f"{asm_path.stem}.init",
            OUTPUT_PATH / f"{asm_path.stem}.code",
        )

        assert completed.returncode == 0, completed.stderr
        assert "cycles:" in completed.stdout
    finally:
        for path in generated_paths:
            path.unlink(missing_ok=True)
