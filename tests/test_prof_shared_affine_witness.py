import json
import subprocess
from pathlib import Path

import pytest

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.trans.block import assemble_pp_code
from rvmca.trans.prof import transform_for_profiling


def test_shared_livein_affine_addresses_have_legal_initial(tmp_path):
    init_asm = [
        "li x27,16",
        "sub x27,sp,x27",
        "sb x0,0(x27)",
        "li x8,0",
        "li x9,16",
        "sub x9,sp,x9",
        "li x19,1024",
        "sub x19,sp,x19",
        "li x10,0",
    ]
    block_asm = [
        "add x14,x9,x8",
        "slli x15,x8,3",
        "lbu x8,0(x14)",
        "add x15,x19,x15",
        "sd x10,0(x15)",
    ]
    init_path = tmp_path / "shared_affine.init"
    code_path = tmp_path / "shared_affine.code"
    init_path.write_text(
        "\n".join(assemble_pp_code(init_asm)) + "\n",
        encoding="utf-8",
    )
    code_path.write_text(
        "\n".join(assemble_pp_code(block_asm)) + "\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
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

    assert completed.returncode == 0, completed.stderr
    assert "cycles:" in completed.stdout


def test_shared_livein_affine_companion_variants_have_legal_initial(tmp_path):
    cases = [
        (
            "scaled_companion",
            [
                "li x27,16",
                "sub x27,sp,x27",
                "sb x0,0(x27)",
                "li x21,0",
                "li x9,16",
                "sub x9,sp,x9",
                "li x27,0",
                "li x18,1024",
                "sub x18,sp,x18",
                "li x10,0",
            ],
            [
                "add x15,x27,x21",
                "add x21,x9,x21",
                "slli x15,x15,3",
                "lbu x21,0(x21)",
                "add x15,x18,x15",
                "sd x10,0(x15)",
            ],
        ),
        (
            "scaled_sum",
            [
                "li x27,16",
                "sub x27,sp,x27",
                "sb x0,0(x27)",
                "li x26,0",
                "li x19,0",
                "li x9,16",
                "sub x9,sp,x9",
                "li x18,1024",
                "sub x18,sp,x18",
                "li x10,0",
            ],
            [
                "add x14,x19,x26",
                "add x15,x9,x26",
                "slli x14,x14,3",
                "lbu x26,0(x15)",
                "add x14,x18,x14",
                "sd x10,0(x14)",
            ],
        ),
    ]

    for case_name, init_asm, block_asm in cases:
        init_path = tmp_path / f"{case_name}.init"
        code_path = tmp_path / f"{case_name}.code"
        init_path.write_text(
            "\n".join(assemble_pp_code(init_asm)) + "\n",
            encoding="utf-8",
        )
        code_path.write_text(
            "\n".join(assemble_pp_code(block_asm)) + "\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
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

        assert completed.returncode == 0, completed.stderr
        assert "cycles:" in completed.stdout


@pytest.mark.parametrize(
    ("case_name", "block_asm", "zero_regs"),
    [
        (
            "shared_livein_mixed_affine_scales",
            [
                "add x14,x9,x8",
                "slli x15,x8,3",
                "lbu x8,0(x14)",
                "add x15,x19,x15",
                "sd x10,0(x15)",
            ],
            ("x8",),
        ),
        (
            "shared_livein_scaled_companion",
            [
                "add x15,x27,x21",
                "add x21,x9,x21",
                "slli x15,x15,3",
                "lbu x21,0(x21)",
                "add x15,x18,x15",
                "sd x10,0(x15)",
            ],
            ("x21", "x27"),
        ),
        (
            "shared_livein_scaled_sum",
            [
                "add x14,x19,x26",
                "add x15,x9,x26",
                "slli x14,x14,3",
                "lbu x26,0(x15)",
                "add x14,x18,x14",
                "sd x10,0(x14)",
            ],
            ("x19", "x26"),
        ),
    ],
)
def test_shared_livein_mixed_affine_scales_are_generated_safely(
    tmp_path,
    case_name,
    block_asm,
    zero_regs,
):
    asm_path = tmp_path / f"{case_name}.S"
    asm_path.write_text(
        "\n".join(block_asm) + "\n",
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
        for reg in zero_regs:
            assert f"li {reg}, 0" in init_asm
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
