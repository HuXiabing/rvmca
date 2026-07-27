import subprocess

import pytest

from rvmca.config import TOOLS_PATH
from rvmca.trans.block import assemble_pp_code


@pytest.mark.parametrize(
    ("case_name", "init_asm", "block_asm"),
    [
        (
            "two_stores_s2_s1",
            [
                "li x31,64",
                "sub x31,sp,x31",
                "sd x31,144(sp)",
                "sw x0,28(x31)",
                "li x15,0",
                "li x18,17",
                "sub x18,sp,x18",
                "li x9,33",
                "sub x9,sp,x9",
            ],
            [
                "addiw x15,x15,1",
                "add x14,x18,x15",
                "li x13,32",
                "sb x13,0(x14)",
                "add x15,x9,x15",
                "sb x13,0(x15)",
                "ld x15,144(sp)",
                "lw x15,28(x15)",
            ],
        ),
        (
            "two_stores_s3_s9",
            [
                "li x31,64",
                "sub x31,sp,x31",
                "sd x31,144(sp)",
                "sw x0,28(x31)",
                "li x14,0",
                "li x19,17",
                "sub x19,sp,x19",
                "li x25,33",
                "sub x25,sp,x25",
                "li x24,0",
            ],
            [
                "addiw x14,x14,1",
                "add x15,x19,x14",
                "li x13,32",
                "sb x13,0(x15)",
                "ld x15,144(sp)",
                "add x14,x25,x14",
                "sb x13,0(x14)",
                "lw x15,28(x15)",
                "addiw x24,x24,-1",
            ],
        ),
    ],
)
def test_timeout_block_has_legal_initial(tmp_path, case_name, init_asm, block_asm):
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
