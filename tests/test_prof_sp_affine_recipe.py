import json
import subprocess
from pathlib import Path

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.trans.prof import (
    CONCRETE_REPLAY_SP,
    _affine_quotient_remainders,
    _affine_quotient_value,
    _remap_sp_affine_mem_value,
    _scaled_stack_transform_for_value,
    transform_for_profiling,
)


def test_scaled_stack_recipe_tracks_runtime_sp():
    model_value = 0x20000FFFDFFFFF68
    recipe = _scaled_stack_transform_for_value(model_value)

    assert recipe == (0x4C0, 3)
    for sp_value in (CONCRETE_REPLAY_SP, 0x7FEF00000000, 0x7FFF12345000):
        stored = _remap_sp_affine_mem_value(
            model_value,
            sp_value,
            ("scaled", recipe[0], recipe[1]),
        )
        assert ((stored << 3) + 0x358) & ((1 << 64) - 1) == sp_value - 0x168


def test_scaled_slot_recipe_allows_fixed_residual_outside_stack_window():
    model_value = (CONCRETE_REPLAY_SP - 0x15C0) >> 3

    assert _scaled_stack_transform_for_value(model_value) is None
    recipe = _scaled_stack_transform_for_value(
        model_value,
        max_offset=1 << 40,
    )
    assert recipe == (0x15C0, 3)

    alternate_sp = 0x7FEF00000000
    stored = _remap_sp_affine_mem_value(
        model_value,
        alternate_sp,
        ("scaled", recipe[0], recipe[1]),
    )
    assert ((stored << 3) + 0x7D8) & ((1 << 64) - 1) == alternate_sp - 0xDE8


def test_existing_sp_affine_modes_are_unchanged():
    model_value = CONCRETE_REPLAY_SP - 0x180
    alternate_sp = 0x7FEF00000000

    assert _remap_sp_affine_mem_value(model_value, alternate_sp, "direct") == alternate_sp - 0x180
    inverse_value = 0x100 - CONCRETE_REPLAY_SP
    assert _remap_sp_affine_mem_value(
        inverse_value,
        alternate_sp,
        "inverse",
    ) == (0x100 - alternate_sp) & ((1 << 64) - 1)


def test_affine_quotient_recipe_tracks_aligned_runtime_sp():
    recipe = ("affine_quotient", -0xF8, 40)

    assert _affine_quotient_remainders(recipe[1], recipe[2]) == (0, 8, 16, 24, 32)
    for sp_value in CONCRETE_REPLAY_SP, 0x7FEF00000000, 0x7FFF12345000:
        quotient = _affine_quotient_value(sp_value, recipe)
        address = (40 * quotient - 271) & ((1 << 64) - 1)
        offset = sp_value - address
        assert 23 <= offset <= 55


def test_affine_quotient_memory_recipe_tracks_runtime_sp():
    recipe = ("affine_quotient", -0x70, 104)
    model_value = _affine_quotient_value(CONCRETE_REPLAY_SP, recipe)

    for sp_value in CONCRETE_REPLAY_SP, 0x7FEF00000000, 0x7FFF12345000:
        stored = _remap_sp_affine_mem_value(model_value, sp_value, recipe)
        address = (104 * stored - 128) & ((1 << 64) - 1)
        offset = sp_value - address
        assert 16 <= offset <= 112


def test_scaled_loaded_value_block_runs_with_generated_runtime_sp_init(tmp_path):
    asm_path = tmp_path / "scaled_loaded_runtime_sp.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a5,48(sp)",
                "lui a4,0x130",
                "addi a4,a4,856",
                "slli a3,a5,0x3",
                "add a4,a4,a3",
                "ld a0,0(a4)",
                "addi a1,zero,0",
                "addi s3,s10,32",
                "addi a0,a0,1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    generated_paths = [
        Path(str(OUTPUT_PATH / asm_path.stem) + suffix)
        for suffix in (".init", ".code", ".init.asm", ".code.asm", ".stage.json", ".error")
    ]

    try:
        transform_for_profiling(asm_path)
        stage_path = Path(str(OUTPUT_PATH / asm_path.stem) + ".stage.json")
        assert json.loads(stage_path.read_text(encoding="utf-8"))["stage"] == "transform:done"
        init_asm = Path(str(OUTPUT_PATH / asm_path.stem) + ".init.asm").read_text(encoding="utf-8")
        assert "srli x31, x31, 3" in init_asm
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


def test_affine_quotient_loaded_value_block_runs_with_runtime_sp_init(tmp_path):
    asm_path = tmp_path / "affine_quotient_loaded_mul_104.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a4,16(sp)",
                "addi a5,zero,104",
                "mul s7,a4,a5",
                "lui a5,0x42a",
                "addi a5,a5,-136",
                "add a5,a5,s7",
                "sd zero,8(a5)",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x68" in init_asm
        assert "divu x31, x31, x27" in init_asm
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


def test_large_power_of_two_loaded_value_uses_runtime_quotient(tmp_path):
    asm_path = tmp_path / "large_power_of_two_loaded_quotient.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a3,72(sp)",
                "ld a2,64(sp)",
                "lw t5,0(a3)",
                "lui a3,0xed",
                "addi a3,a3,-536",
                "mulw t5,t5,a4",
                "slli a4,a2,0x6",
                "add a4,a3,a4",
                "lw a4,0(a4)",
                "addiw a3,a2,16",
                "slliw a4,a4,0x1",
                "addw a4,a4,t5",
                "sraw a4,a4,a3",
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

        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x40" in init_asm
        assert "divu x31, x31, x27" in init_asm

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


def test_affine_quotient_loaded_value_keeps_related_accesses_safe(tmp_path):
    asm_path = tmp_path / "affine_quotient_loaded_mul_104_group.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a4,0(sp)",
                "addi a5,zero,104",
                "lui s3,0x42a",
                "mul a5,a4,a5",
                "addi s3,s3,-136",
                "add a5,s3,a5",
                "ld a4,8(a5)",
                "ld a5,0(a5)",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x68" in init_asm
        assert "divu x31, x31, x27" in init_asm
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


def test_affine_livein_quotient_initializes_runtime_access(tmp_path):
    asm_path = tmp_path / "affine_livein_scale_40.S"
    asm_path.write_text(
        "\n".join(
            [
                "slli a4,a5,0x2",
                "add a4,a4,a5",
                "lui a5,0x2f8",
                "slli a4,a4,0x3",
                "addi a5,a5,-304",
                "add a5,a5,a4",
                "lbu a5,33(a5)",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x28" in init_asm
        assert "divu x15, x15, x27" in init_asm
        assert "sb x27, 0(x31)" in init_asm
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


def test_affine_quotient_dynamic_slot_relocates_loaded_pointer(tmp_path):
    asm_path = tmp_path / "affine_quotient_pointer_chain.S"
    asm_path.write_text(
        "\n".join(
            [
                "slli a4,a5,0x2",
                "add a4,a4,a5",
                "lui a5,0x2f8",
                "slli a4,a4,0x3",
                "addi a5,a5,-304",
                "add a5,a5,a4",
                "ld a5,24(a5)",
                "lhu a5,16(a5)",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "divu x15, x15, x27" in init_asm
        assert "sd x27, 0(x31)" in init_asm
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


def test_affine_quotient_supports_constant_mul_carrier(tmp_path):
    asm_path = tmp_path / "affine_quotient_mul_100.S"
    asm_path.write_text(
        "\n".join(
            [
                "addi a2,zero,100",
                "mul a2,s2,a2",
                "lui a3,0x424",
                "addi a3,a3,-1632",
                "add a3,a3,a2",
                "lw s2,48(a3)",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x64" in init_asm
        assert "divu x18, x18, x27" in init_asm
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


def test_affine_quotient_supports_two_independent_scaled_liveins(tmp_path):
    asm_path = tmp_path / "affine_quotient_two_liveins_76.S"
    asm_path.write_text(
        "\n".join(
            [
                "addi a5,zero,76",
                "mul a0,a0,a5",
                "addi sp,sp,-48",
                "lui a2,0x542",
                "sd s0,32(sp)",
                "addi s0,a2,1744",
                "sd ra,40(sp)",
                "sd s1,24(sp)",
                "sd s2,16(sp)",
                "mul a5,a1,a5",
                "add a0,s0,a0",
                "lw s1,8(a0)",
                "add a5,s0,a5",
                "lw s2,8(a5)",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "divu x10, x10, x27" in init_asm
        assert "divu x11, x11, x27" in init_asm
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


def test_affine_quotient_initializes_livein_scratch_register_last(tmp_path):
    asm_path = tmp_path / "affine_quotient_livein_x27_last.S"
    asm_path.write_text(
        "\n".join(
            [
                "addi a5,zero,380",
                "mul a0,a0,a5",
                "lui a2,0x54a",
                "addi s0,a2,-624",
                "mul a5,s11,a5",
                "add a0,s0,a0",
                "lw s1,4(a0)",
                "add a5,s0,a5",
                "lw s2,4(a5)",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        first_recipe = "divu x10, x10, x27"
        scratch_recipe = "divu x27, x27, x31"
        assert first_recipe in init_asm
        assert scratch_recipe in init_asm
        assert init_asm.index(first_recipe) < init_asm.index(scratch_recipe)
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


def test_affine_quotient_handles_add_before_power_of_two_scale(tmp_path):
    asm_path = tmp_path / "affine_quotient_add_then_shift.S"
    asm_path.write_text(
        "\n".join(
            [
                "addi a0,a0,1450",
                "lui a5,0x3ff",
                "slli a0,a0,0x2",
                "addi a5,a5,-88",
                "add a5,a5,a0",
                "lw s0,0(a5)",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x4" in init_asm
        assert "divu x10, x10, x27" in init_asm
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


def test_affine_quotient_supports_large_constant_mul_carrier(tmp_path):
    asm_path = tmp_path / "affine_quotient_mul_744.S"
    asm_path.write_text(
        "\n".join(
            [
                "addi t1,zero,744",
                "mul t1,a0,t1",
                "lui a6,0x46a",
                "addi a6,a6,-1264",
                "add a4,a6,t1",
                "lw a2,12(a4)",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "li x27, 0x2e8" in init_asm
        assert "divu x10, x10, x27" in init_asm
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


def test_affine_quotient_supports_two_independent_large_carriers(tmp_path):
    asm_path = tmp_path / "affine_quotient_two_mul_744.S"
    asm_path.write_text(
        "\n".join(
            [
                "addiw s4,s4,1",
                "addi a4,zero,744",
                "mul a1,a1,a4",
                "lui a5,0x46a",
                "addi a5,a5,-1264",
                "mul a4,a2,a4",
                "add a1,a5,a1",
                "lw a3,12(a1)",
                "lw a0,8(a1)",
                "add a5,a5,a4",
                "lw s3,12(a5)",
                "lw a1,8(a5)",
                "addw s3,s3,a3",
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
        init_asm = Path(
            str(OUTPUT_PATH / asm_path.stem) + ".init.asm"
        ).read_text(encoding="utf-8")
        assert "divu x11, x11, x27" in init_asm
        assert "divu x12, x12, x27" in init_asm
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


def test_large_power_of_two_scale_keeps_legacy_path(tmp_path):
    asm_path = tmp_path / "large_power_of_two_scale.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a5,-1848(gp)",
                "slli a3,a0,0xb",
                "addi a3,a3,112",
                "addi s9,sp,48",
                "add a5,a5,a3",
                "addi a2,s9,0",
                "addi a3,a5,144",
                "addi a4,a2,0",
                "ld t3,0(a5)",
                "ld t1,8(a5)",
                "ld a7,16(a5)",
                "ld a6,24(a5)",
                "ld a0,32(a5)",
                "ld a1,40(a5)",
                "sd t3,0(a4)",
                "sd t1,8(a4)",
                "sd a7,16(a4)",
                "sd a6,24(a4)",
                "sd a0,32(a4)",
                "sd a1,40(a4)",
                "addi a5,a5,48",
                "addi a4,a4,48",
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
