import json
import subprocess
from pathlib import Path

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.trans.prof import transform_for_profiling


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
