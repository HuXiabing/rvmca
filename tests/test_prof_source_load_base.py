import json
import subprocess
from pathlib import Path

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.trans.prof import transform_for_profiling


LOADED_SP_RESIDUAL_BLOCK_ASM = [
    "sd s1,152(sp)",
    "ld a5,-24(s1)",
    "addi a4,sp,64",
    "addi a5,a5,464",
    "add a5,a5,a4",
    "sd s10,-376(a5)",
    "addi a0,sp,264",
    "sd s9,264(sp)",
]


LOADED_SP_ALIAS_BLOCK_ASM = [
    "sd s1,152(sp)",
    "sd s9,264(sp)",
    "sd zero,480(sp)",
    "sh zero,488(sp)",
    "sd zero,496(sp)",
    "sd zero,504(sp)",
    "sd zero,512(sp)",
    "sd zero,520(sp)",
    "ld a5,-24(s1)",
    "addi a1,zero,0",
    "add a5,a5,sp",
    "sd s10,152(a5)",
    "ld a5,152(sp)",
    "ld a0,-24(a5)",
    "add a0,s8,a0",
]


def test_self_updated_source_load_base_is_not_zeroed(tmp_path):
    asm_path = tmp_path / "self_updated_source_load_base.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a3,0(s9)",
                "add a5,a5,s0",
                "ld a4,0(a5)",
                "ld a5,376(s2)",
                "add a3,a3,s0",
                "ld a3,0(a3)",
                "add a4,a4,s6",
                "add a5,a5,s6",
                "lw a4,0(a4)",
                "lw a5,0(a5)",
                "lw a6,4(a3)",
                "ld a7,32(sp)",
                "addw a5,a5,a4",
                "addw a6,a6,a5",
                "ld a5,56(sp)",
                "ld a4,48(sp)",
                "sd s3,24(sp)",
                "subw a6,a6,a5",
                "ld a5,64(sp)",
                "sd s4,0(sp)",
                "addi a3,zero,7",
                "sd a5,16(sp)",
                "ld a5,40(sp)",
                "addi a1,a4,0",
                "addi a0,zero,1",
                "sd a5,8(sp)",
                "addi a5,zero,0",
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

    for path in generated_paths:
        path.unlink(missing_ok=True)
    try:
        transform_for_profiling(asm_path)
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


def test_symbolic_load_used_as_later_address_keeps_one_value(tmp_path):
    asm_path = tmp_path / "symbolic_load_later_address.S"
    asm_path.write_text(
        "\n".join(
            [
                "lui a5,0x1",
                "lui a4,0x1",
                "addi a5,a5,224",
                "addi a4,a4,-1872",
                "add a4,a4,a5",
                "add a5,a4,sp",
                "ld a5,-2048(a5)",
                "lui a3,0x1",
                "lui a4,0x2",
                "addi a3,a3,-1760",
                "add a4,a5,a4",
                "add a3,a3,sp",
                "ld a4,88(a4)",
                "ld s1,0(a3)",
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

    for path in generated_paths:
        path.unlink(missing_ok=True)
    try:
        transform_for_profiling(asm_path)
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


def test_loaded_sp_residual_uses_a_small_scalar_value(tmp_path):
    asm_path = tmp_path / "loaded_sp_residual.S"
    asm_path.write_text(
        "\n".join(LOADED_SP_RESIDUAL_BLOCK_ASM) + "\n",
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

    for path in generated_paths:
        path.unlink(missing_ok=True)
    try:
        transform_for_profiling(asm_path)
        stage_path = Path(str(OUTPUT_PATH / asm_path.stem) + ".stage.json")
        assert json.loads(stage_path.read_text(encoding="utf-8"))["stage"] == "transform:done"

        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x31, 0x68" in init_asm

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


def test_loaded_sp_alias_uses_a_small_scalar_value(tmp_path):
    asm_path = tmp_path / "loaded_sp_alias.S"
    asm_path.write_text(
        "\n".join(LOADED_SP_ALIAS_BLOCK_ASM) + "\n",
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

    for path in generated_paths:
        path.unlink(missing_ok=True)
    try:
        transform_for_profiling(asm_path)
        stage_path = Path(str(OUTPUT_PATH / asm_path.stem) + ".stage.json")
        assert json.loads(stage_path.read_text(encoding="utf-8"))["stage"] == "transform:done"

        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x31, 0x190" in init_asm

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
