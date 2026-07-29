import json
import subprocess
from pathlib import Path

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.trans.prof import (
    CONCRETE_REPLAY_ALT_SPS,
    CONCRETE_REPLAY_SP,
    _runtime_reg_recipe_value,
    transform_for_profiling,
)


LARGE_POWER_OF_TWO_AFFINE_BLOCK_ASM = [
    "lui a5,0x900",
    "slli a7,s0,0xa",
    "addi a5,a5,784",
    "add a5,a5,a7",
    "ld s4,336(a5)",
    "ld a4,304(a5)",
    "ld a3,328(a5)",
    "ld s0,296(a5)",
]

MIXED_LOADED_AND_LIVEIN_AFFINE_BLOCK_ASM = [
    "slli a5,s4,0x4",
    "sub a3,a5,s4",
    "ld a5,8(sp)",
    "slli a3,a3,0x2",
    "lui a4,0x319",
    "sub a3,a3,s4",
    "addi s1,a4,-1616",
    "add a4,a3,a5",
    "add a5,s1,a5",
    "slli a4,a4,0x3",
    "lbu a5,0(a5)",
    "add a4,s3,a4",
    "sd a2,0(a4)",
]


def test_linear_runtime_recipe_tracks_signed_sp_coefficient():
    anchor_value = CONCRETE_REPLAY_SP - 0x380
    recipe = ("affine_linear", anchor_value, -7)

    for sp_value in CONCRETE_REPLAY_ALT_SPS:
        assert _runtime_reg_recipe_value(sp_value, recipe) == (
            anchor_value - 7 * (sp_value - CONCRETE_REPLAY_SP)
        ) & ((1 << 64) - 1)


def test_runtime_affine_loaded_value_address_replays_safely(tmp_path):
    asm_path = tmp_path / "runtime_affine_loaded_value_address.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a5,72(sp)",
                "sub a4,a5,a1",
                "ld a5,24(sp)",
                "sltiu a4,a4,1",
                "or a4,a5,a4",
                "addiw a5,a4,0",
                "sd a5,24(sp)",
                "mul a5,s11,s3",
                "lui a4,0x542",
                "addi a3,a4,1744",
                "lui a4,0x4d7",
                "addi a4,a4,-144",
                "lw a2,120(s4)",
                "add a5,a3,a5",
                "lw a3,64(a5)",
                "slli a5,a3,0x1",
                "add a5,a5,a3",
                "add a5,a5,a1",
                "slli a5,a5,0x2",
                "add a5,a4,a5",
                "lw a5,0(a5)",
                "and a5,a5,a2",
            ]
        )
        + "\n",
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
        transform_for_profiling(asm_path, verbose=True)
        stage_path = Path(str(OUTPUT_PATH / asm_path.stem) + ".stage.json")
        assert json.loads(stage_path.read_text(encoding="utf-8"))["stage"] == "transform:done"
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


def test_large_power_of_two_affine_address_uses_runtime_sp(tmp_path):
    asm_path = tmp_path / "large_power_of_two_affine_address.S"
    asm_path.write_text(
        "\n".join(LARGE_POWER_OF_TWO_AFFINE_BLOCK_ASM) + "\n",
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

        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x400" in init_asm
        assert "divu x8, x8, x27" in init_asm

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


def test_mixed_loaded_and_livein_affine_address_replays_safely(tmp_path):
    asm_path = tmp_path / "mixed_loaded_and_livein_affine_address.S"
    asm_path.write_text(
        "\n".join(MIXED_LOADED_AND_LIVEIN_AFFINE_BLOCK_ASM) + "\n",
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

        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x7" in init_asm
        assert "mul x19, x19, x27" in init_asm

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
