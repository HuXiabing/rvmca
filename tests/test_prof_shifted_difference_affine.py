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
