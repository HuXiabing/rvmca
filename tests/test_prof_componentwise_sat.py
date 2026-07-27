import json
import subprocess
from pathlib import Path

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.trans.prof import transform_for_profiling


def test_disconnected_nonlinear_constraints_do_not_block_direct_load_bases(tmp_path):
    asm_path = tmp_path / "disconnected_nonlinear_direct_load_bases.S"
    asm_path.write_text(
        "\n".join(
            [
                "addiw a4,a4,1",
                "ld a2,8(sp)",
                "mul a5,a5,s11",
                "mul a3,a3,a2",
                "ld a2,16(sp)",
                "add a5,a5,s10",
                "mul a4,a4,a2",
                "add a5,a5,a3",
                "add a5,a5,a4",
                "ld a4,24(sp)",
                "mul a5,a5,a4",
                "add a5,s9,a5",
                "lw a5,0(a5)",
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
