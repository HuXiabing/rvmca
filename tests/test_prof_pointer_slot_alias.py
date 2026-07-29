import json
import subprocess
from pathlib import Path

from rvmca.config import OUTPUT_PATH, TOOLS_PATH
from rvmca.trans.prof import transform_for_profiling


def _assert_profiled_program_runs(asm_path):
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


def test_repeated_pointer_chain_reuses_only_matching_load_slots(tmp_path):
    asm_path = tmp_path / "repeated_pointer_chain.S"
    asm_path.write_text(
        "\n".join(
            [
                "addi a5,s2,8",
                "sd a5,240(s1)",
                "ld a5,16(s2)",
                "ld a4,8(s2)",
                "ld a5,8(a5)",
                "sd a4,0(s3)",
                "ld a5,8(a5)",
                "ld a5,8(a5)",
                "ld a5,8(a5)",
                "addi a4,a5,8",
                "sd a4,248(s1)",
                "ld a4,8(a5)",
                "ld a5,16(s2)",
                "sd a4,8(s1)",
                "ld a5,8(a5)",
                "ld a5,8(a5)",
                "ld a5,8(a5)",
                "ld a5,16(a5)",
                "addi a4,a5,8",
                "sd a4,256(s1)",
                "ld a5,8(a5)",
                "sd a5,16(s1)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _assert_profiled_program_runs(asm_path)


def test_repeated_gp_pointer_loads_keep_nonclobbered_slot_alias(tmp_path):
    asm_path = tmp_path / "repeated_gp_pointer_loads.S"
    asm_path.write_text(
        "\n".join(
            [
                "addi a4,zero,32",
                "ld a5,1592(gp)",
                "ld a5,24(a5)",
                "ld a5,64(a5)",
                "sb a4,7(a5)",
                "ld a5,1592(gp)",
                "ld a3,24(a5)",
                "ld a3,64(a3)",
                "sb a4,20(a3)",
                "ld a5,24(a5)",
                "ld a5,64(a5)",
                "sb a4,6(a5)",
                "ld a5,1592(gp)",
                "ld a3,24(a5)",
                "ld a3,64(a3)",
                "sb a4,16(a3)",
                "ld a3,24(a5)",
                "ld a3,64(a3)",
                "sb a4,53(a3)",
                "ld a3,24(a5)",
                "ld a3,64(a3)",
                "sb a4,54(a3)",
                "ld a3,24(a5)",
                "ld a3,64(a3)",
                "sb a4,55(a3)",
                "ld a3,24(a5)",
                "ld a3,64(a3)",
                "sb a4,56(a3)",
                "ld a5,24(a5)",
                "ld a5,64(a5)",
                "sb a4,57(a5)",
                "ld s0,16(sp)",
                "ld ra,24(sp)",
                "ld s1,8(sp)",
                "ld s2,0(sp)",
                "addi sp,sp,32",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _assert_profiled_program_runs(asm_path)


def test_downstream_pointer_slot_does_not_clobber_intermediate_scalar(tmp_path):
    asm_path = tmp_path / "mixed_width_pointer_chain.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a4,8(a5)",
                "lw a5,0(a4)",
                "addiw a5,a5,-1",
                "slli a5,a5,0x3",
                "add a4,a4,a5",
                "ld a5,8(a4)",
                "sd a0,24(a5)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _assert_profiled_program_runs(asm_path)


def test_prior_store_is_forwarded_into_failing_address_sum(tmp_path):
    asm_path = tmp_path / "store_forwarded_address_sum.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a5,-888(gp)",
                "ld a4,0(a5)",
                "sd zero,144(a4)",
                "ld a4,0(a5)",
                "sd zero,8(a4)",
                "ld a4,0(a5)",
                "ld a5,0(a4)",
                "ld a4,8(a4)",
                "add a5,a5,a4",
                "sb zero,0(a5)",
                "ld a5,0(s1)",
                "lbu a5,163(a5)",
                "andi a5,a5,4",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _assert_profiled_program_runs(asm_path)


def test_repeated_pointer_source_slot_survives_intervening_stores(tmp_path):
    asm_path = tmp_path / "repeated_pointer_source_store_chain.S"
    asm_path.write_text(
        "\n".join(
            [
                "addi a3,zero,1",
                "sd a3,232(a5)",
                "ld a5,0(s1)",
                "ld a1,88(sp)",
                "addi a2,zero,4",
                "add a5,a5,a4",
                "sd a1,240(a5)",
                "ld a5,0(s1)",
                "ld a1,112(sp)",
                "add a5,a5,a4",
                "sd a3,224(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a1,256(a5)",
                "ld a5,0(s1)",
                "ld a1,136(sp)",
                "add a5,a5,a4",
                "sd a1,264(a5)",
                "ld a5,0(s1)",
                "ld a1,64(sp)",
                "add a5,a5,a4",
                "sd a1,248(a5)",
                "ld a5,0(s1)",
                "ld a1,40(sp)",
                "add a5,a5,a4",
                "sd a3,280(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a1,288(a5)",
                "ld a5,0(s1)",
                "ld a1,48(sp)",
                "add a5,a5,a4",
                "sd a1,272(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a3,304(a5)",
                "ld a5,0(s1)",
                "ld a3,96(sp)",
                "add a5,a5,a4",
                "sd a2,312(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a3,296(a5)",
                "ld a5,0(s1)",
                "ld a3,144(sp)",
                "add a5,a5,a4",
                "sd a3,192(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a2,216(a5)",
                "ld t1,0(s1)",
                "lui a1,0x3",
                "add a5,t1,a1",
                "ld a4,304(a5)",
                "ld s6,312(a5)",
                "ld a7,184(a5)",
                "ld s7,192(a5)",
                "ld t4,232(a5)",
                "ld t2,240(a5)",
                "ld s0,256(a5)",
                "ld t5,264(a5)",
                "ld s5,280(a5)",
                "ld s3,288(a5)",
                "ld a6,224(a5)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _assert_profiled_program_runs(asm_path)


def test_many_large_relative_pointer_stores_use_range_checked_candidates(tmp_path):
    asm_path = tmp_path / "many_large_relative_pointer_stores.S"
    asm_path.write_text(
        "\n".join(
            [
                "ld a3,8(sp)",
                "ld a1,16(sp)",
                "addi a2,zero,4",
                "sd a3,1784(a5)",
                "ld a5,0(s1)",
                "addi a3,zero,1",
                "add a5,a5,a4",
                "sd a1,1792(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a3,1776(a5)",
                "ld a5,0(s1)",
                "ld a3,40(sp)",
                "add a5,a5,a4",
                "sd s11,1808(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a3,1816(a5)",
                "ld a5,0(s1)",
                "ld a3,0(sp)",
                "add a5,a5,a4",
                "sd s9,1800(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a3,1832(a5)",
                "ld a5,0(s1)",
                "ld a3,24(sp)",
                "add a5,a5,a4",
                "sd a3,1840(a5)",
                "ld a5,0(s1)",
                "ld a3,56(sp)",
                "add a5,a5,a4",
                "sd s5,1824(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a3,1744(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a2,1768(a5)",
                "ld t1,0(s1)",
                "lui a2,0x2",
                "add a5,t1,a2",
                "ld a4,1832(a5)",
                "ld s2,1840(a5)",
                "ld a7,1736(a5)",
                "ld s3,1744(a5)",
                "ld t4,1784(a5)",
                "ld t0,1792(a5)",
                "ld s0,1808(a5)",
                "ld t6,1816(a5)",
                "ld a6,1776(a5)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _assert_profiled_program_runs(asm_path)


def test_repeated_pointer_source_supports_large_indirect_base(tmp_path):
    asm_path = tmp_path / "repeated_pointer_large_indirect_base.S"
    asm_path.write_text(
        "\n".join(
            [
                "sd s11,-1752(a5)",
                "ld a5,0(s1)",
                "ld a1,40(sp)",
                "addi a3,zero,1",
                "add a5,a5,a4",
                "sd a1,-1744(a5)",
                "ld a5,0(s1)",
                "addi a2,zero,4",
                "add a5,a5,a4",
                "sd a3,-1760(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd s7,-1792(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a2,-1768(a5)",
                "ld t1,0(s1)",
                "lui a7,0x3",
                "add a5,t1,a7",
                "ld a4,-1752(a5)",
                "ld a2,-1744(a5)",
                "ld t3,-1800(a5)",
                "ld a1,-1792(a5)",
                "ld a0,-1760(a5)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _assert_profiled_program_runs(asm_path)


def test_repeated_pointer_source_with_many_disjoint_stores_keeps_slot(tmp_path):
    asm_path = tmp_path / "repeated_pointer_source_many_disjoint_stores.S"
    asm_path.write_text(
        "\n".join(
            [
                "addi a2,zero,1",
                "sd a2,2000(a5)",
                "ld a5,0(s1)",
                "ld a0,88(sp)",
                "lui a3,0x4",
                "add a5,a5,a4",
                "sd a0,2008(a5)",
                "ld a5,0(s1)",
                "ld a0,112(sp)",
                "addi a1,zero,4",
                "add a5,a5,a4",
                "sd a2,1992(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a0,2024(a5)",
                "ld a5,0(s1)",
                "ld a0,136(sp)",
                "add a5,a5,a4",
                "sd a0,2032(a5)",
                "ld a5,0(s1)",
                "ld a0,64(sp)",
                "add a5,a5,a4",
                "sd a0,2016(a5)",
                "ld a5,0(s1)",
                "ld a0,40(sp)",
                "add a5,a5,a3",
                "sd a2,-2048(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a3",
                "sd a0,-2040(a5)",
                "ld a5,0(s1)",
                "ld a0,48(sp)",
                "add a5,a5,a4",
                "sd a0,2040(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a3",
                "sd a2,-2024(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a3",
                "sd a1,-2016(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a3",
                "ld a3,96(sp)",
                "sd a3,-2032(a5)",
                "ld a5,0(s1)",
                "ld a3,144(sp)",
                "add a5,a5,a4",
                "sd a3,1960(a5)",
                "ld a5,0(s1)",
                "add a5,a5,a4",
                "sd a1,1984(a5)",
                "ld t1,0(s1)",
                "lui s7,0x4",
                "lui a1,0x3",
                "add a4,t1,s7",
                "ld a3,-2024(a4)",
                "ld s6,-2016(a4)",
                "add a5,t1,a1",
                "ld s5,-2048(a4)",
                "ld s3,-2040(a4)",
                "ld a7,1952(a5)",
                "ld s10,1960(a5)",
                "ld t4,2000(a5)",
                "ld t2,2008(a5)",
                "ld s0,2024(a5)",
                "ld t5,2032(a5)",
                "ld a6,1992(a5)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _assert_profiled_program_runs(asm_path)
