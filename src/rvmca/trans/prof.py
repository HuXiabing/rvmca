# MIT License
#
# Copyright (c) 2024 Xuezheng (xuezhengxu@126.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Profiling"""

import json
import os
import time
from pathlib import Path
from typing import List, Tuple

from angr.state_plugins import SimActionConstraint, SimEvent
from z3 import BitVecRef

from rvmca.log import DEBUG, INFO, WARNING
from rvmca.trans.block import *
import math

from rvmca.prog import IType, Program, Reg, XREG, FREG, Inst, parse_program, SSAInst, IFmtInst, BFmtInst, UFmtInst, \
    RFmtInst, StoreInst, FRRFmtInst, FRRRRFmtInst
import copy
import angr, claripy

from rvmca.config import *
from rvmca.prog.reg import find_reg_by_name, bitvec_to_reg
from rvmca.utils.cmd_util import run_cmd
from rvmca.utils.file_util import rm_file, read_file, write_to_file
from rvmca.analysis import RVFG

_available_regs = [
    find_reg_by_name(n)
    for n in [f't{i}' for i in range(7)] + \
             [f'a{i}' for i in range(8)] + \
             [f's{i}' for i in range(12)]
]

STACK_RANGE = 0x1000
INIT_ACCESS_ALIGN = 8
INIT_ACCESS_SLOT_WIDTH = 8
TEMP_REG = 't6'
TEMP_REG2 = 's11'
REG_PREFIX = 'rvmca_reg_'
CONCRETE_REPLAY_SP = 0x7fff00000000
CONCRETE_REPLAY_ALT_SPS = [
    CONCRETE_REPLAY_SP,
    CONCRETE_REPLAY_SP - 0x1000000000,
]
MAX_INIT_SOLVE_RETRIES = 8
INIT_PTR_MIN_OFFSET = 16
MAX_SP_REL_OFFSET = 1 << 40
STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD = 6
STATIC_SYMBOLIC_MUL_NODE_LIMIT = 24
GLOBAL_NO_OVERLAP_LOAD_THRESHOLD = 16
GLOBAL_NO_OVERLAP_STORE_THRESHOLD = 12
LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT = 4
LOAD_SLOT_PRUNE_THRESHOLD = 64
HEURISTIC_SOLVER_TIMEOUT_MS = 500
ENABLE_POINTER_LOAD_ANCHORS = False


class UnsupportedBlockError(RuntimeError):
    """Raised for blocks outside the current sp-relative init strategy."""


class ConcreteReplayFailure(AssertionError):
    """Raised when the solver model cannot be replayed concretely."""

    def __init__(self, message: str, candidate_init=None):
        super().__init__(message)
        self.candidate_init = candidate_init


def _stage_file_for_name(name: str) -> Path:
    return Path(str(OUTPUT_PATH / name) + ".stage.json")


def _write_profile_stage(name: str, stage: str):
    data = {
        "name": name,
        "stage": stage,
        "time": time.time(),
    }
    _stage_file_for_name(name).write_text(json.dumps(data, sort_keys=True), encoding="utf-8")


def _align_up(value: int, align: int) -> int:
    return ((value + align - 1) // align) * align


def _signed_u64(value: int) -> int:
    value &= (1 << 64) - 1
    if value & (1 << 63):
        return value - (1 << 64)
    return value


def find_regs_no_def(prog: Program) -> List[Reg]:
    """find undefined registers"""
    check_block_validity(prog)

    regs_defined = set()
    regs_defined.add(XREG[0])

    regs_no_def = set()

    for inst in prog.insts:
        for r in inst.get_uses():
            if r not in regs_defined:
                regs_no_def.add(r)
        r = inst.get_def()
        if r:
            regs_defined.add(r)
    return list(regs_no_def)


def find_addr_regs(prog: Program) -> List[Tuple[int, Reg]]:
    """find address registers"""
    check_block_validity(prog)

    addr_regs = []

    for i, inst in enumerate(prog.insts):
        inst = prog.insts[i]
        addr = inst.get_addr()
        if addr:
            addr_regs.append((i, addr))
    return addr_regs


def remap_regs_for_block(prog: Program, candidate_regs=None) -> Program:
    """Remap registers for a block"""
    if candidate_regs is None:
        candidate_regs = _available_regs
    check_block_validity(prog)

    prog = copy.deepcopy(prog)

    regs = set()
    for inst in prog.insts:
        for reg in inst.get_regs():
            # FIXME: we only consider xregs for now
            if reg in XREG:
                regs.add(reg)
    need_remap = [r for r in regs if r not in candidate_regs]

    if XREG[0] in need_remap:
        need_remap.remove(XREG[0])

    available_regs = [r for r in candidate_regs if r not in regs]
    if len(need_remap) > len(available_regs):
        raise UnsupportedBlockError("not enough safe registers for remapping")

    x_need_remap, f_need_remap = [], []
    for reg in need_remap:
        if reg in XREG:
            x_need_remap.append(reg)
        elif reg in FREG:
            f_need_remap.append(reg)
        else:
            raise ValueError(f'Unsupported reg type: {reg.type}')

    x_available, f_available = [], []
    for reg in available_regs:
        if reg in XREG:
            x_available.append(reg)
        elif reg in FREG:
            f_available.append(reg)
        else:
            raise ValueError(f'Unsupported reg type: {reg.type}')

    if Reg(0) in x_available:
        x_available.remove(Reg(0))

    if len(x_need_remap) > len(x_available):
        raise UnsupportedBlockError("not enough safe x-registers for remapping")
    if len(f_need_remap) > len(f_available):
        raise UnsupportedBlockError("not enough safe f-registers for remapping")

    def map_regs(srcs, tgts):
        map_table = {
            srcs[i]: tgts[i]
            for i in range(len(srcs))
        }
        for inst in prog.insts:
            r = inst.get_def()
            if r and r in srcs:
                inst.set_def(map_table[r])
            new_uses = []
            for r in inst.get_uses():
                if r in srcs:
                    new_uses.append(map_table[r])
                else:
                    new_uses.append(r)
            inst.set_uses(new_uses)

    map_regs(x_need_remap, x_available)
    map_regs(f_need_remap, f_available)

    return prog


def add_undef_reg_checking(prog: Program, undefined_regs: List) -> Program:
    prog = copy.deepcopy(prog)
    insts = [
        BFmtInst('blt', reg.name, 'x0', label='fail')
        for reg in undefined_regs
    ]
    prog.insts = insts + prog.insts
    return prog


def choose_addr_check_temp_reg(prog: Program) -> str:
    used_regs = set()
    for inst in prog.insts:
        used_regs.update(r for r in inst.get_regs() if r in XREG)

    candidates = []
    for reg_name in [TEMP_REG, TEMP_REG2]:
        reg = find_reg_by_name(reg_name)
        if reg not in candidates:
            candidates.append(reg)
    for reg in _available_regs:
        if reg not in candidates:
            candidates.append(reg)

    for reg in candidates:
        if reg not in used_regs and reg not in [XREG[0], XREG[2]]:
            return reg.name

    raise UnsupportedBlockError("no free register for address-check instrumentation")


def append_addi_chunks(insts: List[Inst], reg: str, value: int):
    while value:
        chunk = min(2047, value) if value > 0 else max(-2048, value)
        insts.append(IFmtInst('addi', reg, reg, chunk))
        value -= chunk


def add_addr_range_checking(prog: Program, temp_reg: str = None) -> Program:
    """Add address checking for a block"""

    if temp_reg is None:
        try:
            temp = choose_addr_check_temp_reg(prog)
        except UnsupportedBlockError:
            # Some long blocks use every candidate GPR.  The range checks are
            # only a symbolic-execution guard; the materialized init path still
            # constrains every concrete memory access into the synthetic stack.
            return copy.deepcopy(prog)
    else:
        temp = temp_reg
    check_block_validity(prog)

    prog = copy.deepcopy(prog)
    insts = []
    for inst in prog.insts:
        if inst.type in [IType.Load, IType.Store, IType.Amo]:
            addr = inst.get_addr()
            imm = _signed_u64(inst.imm)
            # temp = base + offset
            insts.append(UFmtInst('li', temp, abs(imm)))
            if imm >= 0:
                insts.append(RFmtInst('add', temp, str(addr), temp))  # 计算实际地址
            else:
                insts.append(RFmtInst('sub', temp, str(addr), temp))
            # temp < sp
            insts.append(BFmtInst('bge', temp, 'sp', label='fail'))
            # temp >= sp - STACK_RANGE
            append_addi_chunks(insts, temp, STACK_RANGE)
            insts.append(BFmtInst('blt', temp, 'sp', label='fail'))
            if inst.width > 1:
                # check address alignment
                mask = inst.width - 1
                append_addi_chunks(insts, temp, -STACK_RANGE)  # 还原回实际地址
                insts.append(IFmtInst('andi', temp, temp, mask))  # 检查地址对齐
                insts.append(BFmtInst('bne', temp, 'x0', label='fail'))
        # if inst.type in [IType.Load, IType.Store, IType.Amo]:
        #     addr = inst.get_addr()
        #     imm = inst.imm

        #     insts.append(UFmtInst('li', temp, imm))
        #     insts.append(RFmtInst('add', temp, str(addr), temp)) # temp = 实际地址

        #     # A. 检查对齐 (在 temp 被加 STACK_RANGE 之前)
        #     if inst.width > 1:
        #         mask = inst.width - 1
        #         # 技巧：如果我们只有一个 temp，可以先算对齐，不合规则直接 fail
        #         # 如果合规，对齐位必然是0，这时 temp 其实没变（或者说变了也没关系，因为后面可以靠 addi 补回来）
        #         # 但最稳妥的是如果有 TEMP_REG2 (如 t1)，直接：
        #         # insts.append(IFmtInst('andi', TEMP_REG2, temp, mask))
        #         # insts.append(BFmtInst('bne', TEMP_REG2, 'x0', label='fail'))

        #     # B. 检查上限：temp < sp
        #     insts.append(BFmtInst('bge', temp, 'sp', label='fail'))

        #     # C. 检查下限：temp >= sp - STACK_RANGE
        #     # 这里不可避免要修改 temp
        #     insts.append(IFmtInst('addi', temp, temp, STACK_RANGE))
        #     insts.append(BFmtInst('blt', temp, 'sp', label='fail'))

        #     # 此时不需要 addi temp, temp, -STACK_RANGE 了，
        #     # 因为原始指令 inst 会使用原来的 rs1+imm，不依赖 temp 里的值

        insts.append(inst)
    prog.insts = insts
    return prog


def fix_lui_auipc_imm(prog: Program) -> Program:
    """Set imm to 0 for lui/auipc instructions.

    This is useful to avoid illegal memory access caused by large random immediates.
    lui rd, imm  -> lui rd, 0
    auipc rd, imm -> auipc rd, 0
    Assuming the specific imm value doesn't affect the block's execution cycle count.

    Args:
        prog: The program to modify

    Returns:
        Modified program
    """
    prog = copy.deepcopy(prog)
    for i, inst in enumerate(prog.insts):
        if isinstance(inst, UFmtInst) and inst.name in ['lui', 'auipc']:
            # Set imm to 0 for lui/auipc instructions
            # lui rd, imm -> lui rd, 0
            # auipc rd, imm -> auipc rd, 0
            inst.imm = 0x0
    return prog


def has_lui_auipc(prog: Program) -> bool:
    return any(isinstance(inst, UFmtInst) and inst.name in ['lui', 'auipc'] for inst in prog.insts)


def find_unmappable_fixed_address_access(prog: Program):
    """Find memory accesses rooted only in a fixed lui/auipc address.

    The profiler can synthesize stack-relative values for unknown registers or
    load-produced pointers, and it can also absorb small lui constants when they
    are added to sp.  A direct global/GOT/static access such as

        auipc a5, imm
        ld    a5, off(a5)

    is different: the accessed address is fixed by PC/global layout, not by the
    block input context, so rewriting it into the synthetic stack would no
    longer measure the original block semantics.
    """

    def const_expr(value):
        return ('const', value & ((1 << 64) - 1))

    def fixed_expr(inst):
        return ('fixed', inst.name, inst.imm, inst.pc)

    def reg_expr(reg):
        if reg == XREG[0]:
            return const_expr(0)
        if reg == XREG[2]:
            return ('sp',)
        return env.get(reg, ('reg', reg))

    def op_expr(op, *args):
        return (op, *args)

    def expr_has(expr, kind):
        if not isinstance(expr, tuple):
            return False
        if expr and expr[0] == kind:
            return True
        return any(expr_has(arg, kind) for arg in expr[1:] if isinstance(arg, tuple))

    def is_dynamic(expr):
        return any(expr_has(expr, kind) for kind in ('sp', 'reg', 'load', 'unknown'))

    def is_fixed_only_address(expr):
        return expr_has(expr, 'fixed') and not is_dynamic(expr)

    def is_unmappable_fixed_address(expr):
        return (
            expr_has(expr, 'fixed_spill')
            and not expr_has(expr, 'sp')
            and not expr_has(expr, 'load')
        )

    def sign_extend_32(expr):
        return op_expr('sext32', expr)

    def eval_r(inst):
        lhs, rhs = reg_expr(inst.rs1), reg_expr(inst.rs2)
        if inst.name in {'add', 'addw'}:
            value = op_expr('add', lhs, rhs)
        elif inst.name in {'sub', 'subw'}:
            value = op_expr('sub', lhs, rhs)
        elif inst.name in {'mul', 'mulw'}:
            value = op_expr('mul', lhs, rhs)
        elif inst.name == 'and':
            value = op_expr('and', lhs, rhs)
        elif inst.name == 'or':
            value = op_expr('or', lhs, rhs)
        elif inst.name == 'xor':
            value = op_expr('xor', lhs, rhs)
        else:
            return ('unknown', inst.pc, inst.name)
        if inst.name.endswith('w'):
            return sign_extend_32(value)
        return value

    def eval_i(inst):
        lhs = reg_expr(inst.rs1)
        if inst.name in {'addi', 'addiw'}:
            value = op_expr('add', lhs, const_expr(inst.imm))
        elif inst.name == 'andi':
            value = op_expr('and', lhs, const_expr(inst.imm))
        elif inst.name == 'ori':
            value = op_expr('or', lhs, const_expr(inst.imm))
        elif inst.name == 'xori':
            value = op_expr('xor', lhs, const_expr(inst.imm))
        elif inst.name in {'slli', 'srli', 'srai'}:
            value = op_expr(inst.name, lhs, const_expr(inst.imm))
        else:
            return ('unknown', inst.pc, inst.name)
        if inst.name == 'addiw':
            return sign_extend_32(value)
        return value

    env = {XREG[0]: const_expr(0), XREG[2]: ('sp',)}
    memory = {}
    for inst in prog.insts:
        if inst.type in [IType.Load, IType.Store, IType.Amo]:
            addr_expr = op_expr('add', reg_expr(inst.rs1), const_expr(inst.imm))
            if is_fixed_only_address(addr_expr) or is_unmappable_fixed_address(addr_expr):
                return inst
            addr_key = str(addr_expr)
            if inst.type in [IType.Store, IType.Amo]:
                memory[addr_key] = reg_expr(inst.rs2)
            if inst.type == IType.Load:
                stored_expr = memory.get(addr_key)
                if stored_expr is not None and expr_has(stored_expr, 'fixed'):
                    env[inst.rd] = ('fixed_spill', stored_expr)
                else:
                    env[inst.rd] = stored_expr if stored_expr is not None else ('load', inst.pc, inst.name)
            continue

        if isinstance(inst, RFmtInst):
            env[inst.rd] = eval_r(inst)
            continue

        if isinstance(inst, IFmtInst):
            env[inst.rd] = eval_i(inst)
            continue

        if isinstance(inst, UFmtInst):
            if inst.name in {'lui', 'auipc'}:
                env[inst.rd] = fixed_expr(inst)
            elif inst.name == 'li':
                env[inst.rd] = const_expr(inst.imm)
            continue

        rd = inst.get_def()
        if rd:
            env[rd] = ('unknown', inst.pc, inst.name)

    return None


def init_states_for_block(prog: Program, name: str, verbose: bool) -> List[Inst]:
    """generate init code for a block"""
    _write_profile_stage(name, "init:collect_undefined_regs")
    regs_defined = {XREG[0], XREG[2]}  # x0, sp
    init_code = []

    def compile_block(program: Program, bin_name: str):
        _write_profile_stage(name, "init:compile_symbolic_wrapper")
        wrapper_path = PROJECT_PATH / 'src' / 'rvmca' / 'trans' / 'template' / 'block_wrapper.S'
        wrapper = read_file(wrapper_path)
        wrapper = wrapper.replace('#CODE#', program.code)
        write_to_file(f'{OUTPUT_PATH / bin_name}.S', wrapper, append=False)
        run_cmd(f'{RISCV_GCC} {OUTPUT_PATH / bin_name}.S -o {OUTPUT_PATH / bin_name}.exe')

    # compile and load binary
    # add address range checking for symbolic execution
    prog2se = add_addr_range_checking(prog)

    # collect undefined registers
    from rvmca.analysis import CFG, path_to_ssa
    cfg = CFG(prog.insts)
    ssas = path_to_ssa(cfg.edges)
    if verbose:
        print('ssas:', ssas)
    rvfg = RVFG(ssas)
    # rvfg.plot(OUTPUT_PATH / 'fail')
    # # FIXME: we only consider xregs for now
    # regs_undefined = list({r for r in rvfg.find_undef_regs()
    #                        if r in XREG and r not in regs_defined})

    # Find undefined registers from SSA instructions:
    # In SSA form, a register with index 0 (e.g., a5_0) that appears in use_regs
    # is undefined (except x0_0 which is the zero register).
    regs_undefined = []
    for ssa_inst in ssas:
        for reg_bitvec in ssa_inst.get_uses():
            # Extract register name and index (e.g., "a5_0" -> name="a5", index=0)
            reg_str = str(reg_bitvec)
            if '_' not in reg_str:
                continue
            reg_name = reg_str.split('_')[0]
            try:
                reg_idx = int(reg_str.split('_')[1])
            except (ValueError, IndexError):
                continue

            # Register with index 0 is undefined (except x0)
            if reg_idx == 0 and reg_name != 'x0':
                from rvmca.prog.reg import find_reg_by_name
                reg = find_reg_by_name(reg_name)
                # Handle both XREG and FREG
                if reg in XREG and reg not in regs_defined and reg not in regs_undefined:
                    regs_undefined.append(reg)

    # add dummy checking for undefined registers to avoid unconstrained symbol(regs_undefined>0)
    prog2se = add_undef_reg_checking(prog2se, list(regs_undefined))
    # print("prog2se",prog2se)
    last_inst = prog2se.insts[-1]
    if isinstance(last_inst, BFmtInst):
        last_inst.label = 'rvmca_block_end'
        last_inst.imm = None

    if verbose:
        INFO('\n<New Block with address range checking>:')
        INFO(prog2se.code)
    compile_block(prog2se, name)
    _write_profile_stage(name, "init:load_symbolic_project")
    proj = angr.Project(f'{OUTPUT_PATH / name}.exe', auto_load_libs=False)
    begin_addr = proj.loader.main_object.get_symbol('rvmca_block_begin').rebased_addr
    end_addr = proj.loader.main_object.get_symbol('rvmca_block_end').rebased_addr
    fail_symbol = proj.loader.main_object.get_symbol('fail')
    fail_addr = fail_symbol.rebased_addr if fail_symbol is not None else None
    # print(f'begin_addr: {begin_addr:#x}, end_addr: {end_addr:#x}')
    init_state = proj.factory.blank_state(addr=begin_addr,
                                          mode='symbolic',
                                          add_options={
                                              angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,  # 用符号填充未约束的内存
                                              angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,  # 用符号填充未约束的寄存器
                                              angr.options.CONSERVATIVE_WRITE_STRATEGY,  # 保守的写策略
                                              angr.options.CONSERVATIVE_READ_STRATEGY,  # 保守的读策略
                                          },
                                          )
    from rvmca.prog import UFmtInst
    init_state.options.discard(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)  # 未约束的寄存器会被符号填充而不是零填充
    if verbose:
        DEBUG(init_state.options.tally())

    # init_state.options.remove(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    # block = proj.factory.block(begin_addr)
    # INFO("<Block>")
    # for inst in block.capstone.insns:
    #     INFO(f"{inst.address:#x}: {inst.mnemonic} {inst.op_str}")
    # end_addr = block.instruction_addrs[-1]

    def concrete_bvv(value: int):
        return claripy.BVV(value & ((1 << 64) - 1), 64)

    def write_stage(stage: str, **extra):
        data = {
            "name": name,
            "stage": stage,
            "time": time.time(),
        }
        data.update(extra)
        _stage_file_for_name(name).write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    def concrete_stack_addr(offset: int, sp_value: int = CONCRETE_REPLAY_SP) -> int:
        return (sp_value - offset) & ((1 << 64) - 1)

    def stack_offset_for_value(value: int):
        offset = (CONCRETE_REPLAY_SP - value) & ((1 << 64) - 1)
        if offset <= MAX_SP_REL_OFFSET and concrete_stack_addr(offset) == (value & ((1 << 64) - 1)):
            return offset
        return None

    def signed_stack_offset_for_value(value: int):
        value &= (1 << 64) - 1
        down_offset = (CONCRETE_REPLAY_SP - value) & ((1 << 64) - 1)
        if down_offset <= MAX_SP_REL_OFFSET and concrete_stack_addr(down_offset) == value:
            return down_offset

        up_offset = (value - CONCRETE_REPLAY_SP) & ((1 << 64) - 1)
        if up_offset <= MAX_SP_REL_OFFSET and ((CONCRETE_REPLAY_SP + up_offset) & ((1 << 64) - 1)) == value:
            return -up_offset

        return None

    def scaled_stack_transform_for_value(value: int, sp_value: int = CONCRETE_REPLAY_SP):
        value &= (1 << 64) - 1
        for shift in range(1, 5):
            shifted = (value << shift) & ((1 << 64) - 1)
            offset = (sp_value - shifted) & ((1 << 64) - 1)
            if offset > STACK_RANGE:
                continue
            if ((sp_value - offset) & ((1 << 64) - 1)) != shifted:
                continue
            return offset, shift
        return None

    def remap_sp_relative_value(value: int, from_sp: int, to_sp: int, allow_scaled_stack: bool = False) -> int:
        value &= (1 << 64) - 1
        offset = (from_sp - value) & ((1 << 64) - 1)
        if offset <= MAX_SP_REL_OFFSET and ((from_sp - offset) & ((1 << 64) - 1)) == value:
            return (to_sp - offset) & ((1 << 64) - 1)
        offset = (value - from_sp) & ((1 << 64) - 1)
        if offset <= MAX_SP_REL_OFFSET and ((from_sp + offset) & ((1 << 64) - 1)) == value:
            return (to_sp + offset) & ((1 << 64) - 1)
        if allow_scaled_stack:
            scaled = scaled_stack_transform_for_value(value, from_sp)
            if scaled is not None:
                stack_offset, shift = scaled
                shifted = (to_sp - stack_offset) & ((1 << 64) - 1)
                if shifted & ((1 << shift) - 1) == 0:
                    return shifted >> shift
        return value

    def sp_affine_mode(sp_affine_mem_offsets, addr_offset):
        if not sp_affine_mem_offsets:
            return None
        if isinstance(sp_affine_mem_offsets, dict):
            return sp_affine_mem_offsets.get(addr_offset)
        if addr_offset in sp_affine_mem_offsets:
            return 'direct'
        return None

    def remap_sp_affine_mem_value(value: int, sp_value: int, mode: str) -> int:
        value &= (1 << 64) - 1
        if mode == 'inverse':
            return (value + ((CONCRETE_REPLAY_SP - sp_value) & ((1 << 64) - 1))) & ((1 << 64) - 1)
        return (sp_value + ((value - CONCRETE_REPLAY_SP) & ((1 << 64) - 1))) & ((1 << 64) - 1)

    def sp_affine_cache_items(sp_affine_mem_offsets):
        if not sp_affine_mem_offsets:
            return ()
        if isinstance(sp_affine_mem_offsets, dict):
            return tuple(sorted((offset, mode) for offset, mode in sp_affine_mem_offsets.items()))
        return tuple(sorted((offset, 'direct') for offset in sp_affine_mem_offsets))

    def set_concrete_state(state, reg_values, mem_values, sp_value=CONCRETE_REPLAY_SP, sp_affine_mem_offsets=None):
        for i in range(32):
            setattr(state.regs, f'x{i}', claripy.BVV(0, 64))
        state.regs.sp = concrete_bvv(sp_value)
        state.regs.x0 = claripy.BVV(0, 64)
        for reg, value in reg_values.items():
            setattr(state.regs, reg.name, concrete_bvv(
                remap_sp_relative_value(value, CONCRETE_REPLAY_SP, sp_value, allow_scaled_stack=True)
            ))
        for addr_offset, value in mem_values.items():
            mode = sp_affine_mode(sp_affine_mem_offsets, addr_offset)
            if mode is not None:
                stored_value = remap_sp_affine_mem_value(value, sp_value, mode)
            else:
                stored_value = remap_sp_relative_value(value, CONCRETE_REPLAY_SP, sp_value)
            state.memory.store(
                concrete_stack_addr(addr_offset, sp_value),
                concrete_bvv(stored_value),
                endness=proj.arch.memory_endness,
            )

    def replay_concrete_init(reg_values, mem_values, debug=False, sp_value=CONCRETE_REPLAY_SP, sp_affine_mem_offsets=None):
        _write_profile_stage(name, "init:concrete_replay")
        replay_state = proj.factory.blank_state(
            addr=begin_addr,
            mode='symbolic',
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        set_concrete_state(replay_state, reg_values, mem_values, sp_value=sp_value, sp_affine_mem_offsets=sp_affine_mem_offsets)
        replay_mgr = proj.factory.simulation_manager(replay_state)
        replay_mgr.explore(find=end_addr)
        if replay_mgr.found:
            return replay_mgr.found[0]
        if debug:
            print(f"replay failed for {name}")
            print("sp_value", hex(sp_value))
            print("reg_values", {reg.name: hex(remap_sp_relative_value(value, CONCRETE_REPLAY_SP, sp_value)) for reg, value in reg_values.items()})
            debug_mem_values = {}
            for offset, value in mem_values.items():
                mode = sp_affine_mode(sp_affine_mem_offsets, offset)
                if mode is not None:
                    debug_mem_values[offset] = hex(remap_sp_affine_mem_value(value, sp_value, mode))
                else:
                    debug_mem_values[offset] = hex(remap_sp_relative_value(value, CONCRETE_REPLAY_SP, sp_value))
            print("mem_values", debug_mem_values)
            if fail_addr is not None:
                fail_state = proj.factory.blank_state(
                    addr=begin_addr,
                    mode='symbolic',
                    add_options={
                        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                    },
                )
                set_concrete_state(fail_state, reg_values, mem_values, sp_value=sp_value, sp_affine_mem_offsets=sp_affine_mem_offsets)
                fail_mgr = proj.factory.simulation_manager(fail_state)
                fail_mgr.explore(find=fail_addr)
                if fail_mgr.found:
                    state = fail_mgr.found[0]
                    regs = {}
                    for reg_name in ['x5', 'x6', 'x10', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x24', 'x26', 'x31', 'sp']:
                        regs[reg_name] = hex(state.solver.eval(getattr(state.regs, reg_name)))
                    print("fail_regs", regs)
                    try:
                        recent = list(state.history.bbl_addrs.hardcopy)[-12:]
                        print("fail_recent_bbls", [hex(addr) for addr in recent])
                    except Exception:
                        pass
            for stash_name in ["active", "deadended", "errored", "unconstrained"]:
                stash = getattr(replay_mgr, stash_name, [])
                print(f"replay {stash_name}: {len(stash)}")
                for item in list(stash)[:4]:
                    if stash_name == "errored":
                        print("  error", item.error)
                        state = item.state
                    else:
                        state = item
                    try:
                        ip = state.solver.eval(state.ip)
                        marker = " fail" if fail_addr is not None and ip == fail_addr else ""
                        print(f"  ip={ip:#x}{marker}")
                    except Exception as exc:
                        print(f"  ip=<unknown: {exc}>")
                    try:
                        recent = list(state.history.bbl_addrs.hardcopy)[-8:]
                        print("  recent_bbls", [hex(addr) for addr in recent])
                    except Exception:
                        pass
        return None

    replay_prefix_state_cache = {}

    class ConcretePrefixSolver:
        @staticmethod
        def eval(value):
            return value & ((1 << 64) - 1)

    class ConcretePrefixRegs:
        def __init__(self, values):
            self._values = values

        def __getattr__(self, reg_name):
            if reg_name == 'sp':
                reg_name = 'x2'
            return self._values.get(reg_name, 0)

    class ConcretePrefixState:
        solver = ConcretePrefixSolver()

        def __init__(self, values):
            self.regs = ConcretePrefixRegs(values)

    def concrete_prefix_states(reg_values, mem_values, sp_value=CONCRETE_REPLAY_SP, sp_affine_mem_offsets=None):
        mask = (1 << 64) - 1

        def unsupported(inst_idx, inst, reason):
            if verbose:
                print('concrete_prefix_unsupported', inst_idx, getattr(inst, 'code', str(inst)), reason)
            return None

        def u64(value):
            return value & mask

        def sext(value, bits):
            value &= (1 << bits) - 1
            sign_bit = 1 << (bits - 1)
            if value & sign_bit:
                value -= 1 << bits
            return u64(value)

        def signed(value):
            value &= mask
            if value & (1 << 63):
                return value - (1 << 64)
            return value

        regs = {f'x{i}': 0 for i in range(32)}
        regs['x2'] = u64(sp_value)
        for reg, value in reg_values.items():
            if reg not in XREG:
                return unsupported(-1, reg, 'non_xreg_init')
            regs[reg.name] = u64(remap_sp_relative_value(value, CONCRETE_REPLAY_SP, sp_value, allow_scaled_stack=True))
        regs['x0'] = 0

        mem_words = {}
        for addr_offset, value in mem_values.items():
            mode = sp_affine_mode(sp_affine_mem_offsets, addr_offset)
            if mode is not None:
                stored_value = remap_sp_affine_mem_value(value, sp_value, mode)
            else:
                stored_value = remap_sp_relative_value(value, CONCRETE_REPLAY_SP, sp_value)
            mem_words[addr_offset] = u64(stored_value)

        def reg_value(reg):
            if reg not in XREG:
                return None
            return regs.get(reg.name, 0)

        def set_reg(reg, value):
            if reg not in XREG:
                return False
            if reg != XREG[0]:
                regs[reg.name] = u64(value)
            regs['x0'] = 0
            return True

        def stack_offset_for_addr(addr):
            return (sp_value - addr) & mask

        def load_mem(addr, width, name):
            offset = stack_offset_for_addr(addr)
            word_offset = ((offset + 7) // 8) * 8
            byte_offset = word_offset - offset
            if byte_offset < 0 or byte_offset + width > 8:
                return 0
            word = mem_words.get(word_offset, 0)
            raw = (word >> (byte_offset * 8)) & ((1 << (width * 8)) - 1)
            if name in {'lb', 'lh', 'lw'}:
                return sext(raw, width * 8)
            return raw

        def store_mem(addr, width, value):
            offset = stack_offset_for_addr(addr)
            word_offset = ((offset + 7) // 8) * 8
            byte_offset = word_offset - offset
            if byte_offset < 0 or byte_offset + width > 8:
                return
            lo = byte_offset * 8
            field_mask = ((1 << (width * 8)) - 1) << lo
            word = mem_words.get(word_offset, 0)
            mem_words[word_offset] = u64((word & ~field_mask) | ((value << lo) & field_mask))

        def eval_r(inst):
            lhs = reg_value(inst.rs1)
            rhs = reg_value(inst.rs2)
            if lhs is None or rhs is None:
                return None
            sh64 = rhs & 0x3f
            sh32 = rhs & 0x1f
            if inst.name == 'add':
                return lhs + rhs
            if inst.name == 'sub':
                return lhs - rhs
            if inst.name == 'mul':
                return lhs * rhs
            if inst.name == 'and':
                return lhs & rhs
            if inst.name == 'or':
                return lhs | rhs
            if inst.name == 'xor':
                return lhs ^ rhs
            if inst.name == 'sll':
                return lhs << sh64
            if inst.name == 'srl':
                return lhs >> sh64
            if inst.name == 'sra':
                return signed(lhs) >> sh64
            if inst.name == 'slt':
                return 1 if signed(lhs) < signed(rhs) else 0
            if inst.name == 'sltu':
                return 1 if lhs < rhs else 0
            lhs32, rhs32 = sext(lhs, 32), sext(rhs, 32)
            if inst.name == 'addw':
                return sext(lhs32 + rhs32, 32)
            if inst.name == 'subw':
                return sext(lhs32 - rhs32, 32)
            if inst.name == 'mulw':
                return sext(lhs32 * rhs32, 32)
            if inst.name == 'sllw':
                return sext((lhs & 0xffffffff) << sh32, 32)
            if inst.name == 'srlw':
                return sext((lhs & 0xffffffff) >> sh32, 32)
            if inst.name == 'sraw':
                return sext(sext(lhs, 32) >> sh32, 32)
            return None

        def eval_i(inst):
            lhs = reg_value(inst.rs1)
            if lhs is None:
                return None
            imm = inst.imm
            sh64 = imm & 0x3f
            sh32 = imm & 0x1f
            if inst.name == 'addi':
                return lhs + imm
            if inst.name == 'addiw':
                return sext(lhs + imm, 32)
            if inst.name == 'andi':
                return lhs & imm
            if inst.name == 'ori':
                return lhs | imm
            if inst.name == 'xori':
                return lhs ^ imm
            if inst.name == 'slli':
                return lhs << sh64
            if inst.name == 'srli':
                return lhs >> sh64
            if inst.name == 'srai':
                return signed(lhs) >> sh64
            if inst.name == 'slliw':
                return sext((lhs & 0xffffffff) << sh32, 32)
            if inst.name == 'srliw':
                return sext((lhs & 0xffffffff) >> sh32, 32)
            if inst.name == 'sraiw':
                return sext(sext(lhs, 32) >> sh32, 32)
            if inst.name == 'slti':
                return 1 if signed(lhs) < imm else 0
            if inst.name == 'sltiu':
                return 1 if lhs < (imm & mask) else 0
            return None

        states_by_addr = {}
        for inst_idx, inst in enumerate(prog.insts):
            states_by_addr[begin_addr + inst_idx * 4] = ConcretePrefixState(regs.copy())
            if isinstance(inst, RFmtInst):
                value = eval_r(inst)
                if value is None or not set_reg(inst.rd, value):
                    return unsupported(inst_idx, inst, 'rfmt')
            elif isinstance(inst, IFmtInst):
                value = eval_i(inst)
                if value is None or not set_reg(inst.rd, value):
                    return unsupported(inst_idx, inst, 'ifmt')
            elif isinstance(inst, UFmtInst):
                if inst.name == 'lui':
                    value = inst.imm << 12
                elif inst.name == 'auipc':
                    value = begin_addr + inst_idx * 4 + (inst.imm << 12)
                elif inst.name == 'li':
                    value = inst.imm
                else:
                    return unsupported(inst_idx, inst, 'ufmt')
                if not set_reg(inst.rd, value):
                    return unsupported(inst_idx, inst, 'ufmt_set_reg')
            elif inst.type == IType.Load:
                if inst.rd not in XREG:
                    return unsupported(inst_idx, inst, 'load_non_xreg')
                base = reg_value(inst.rs1)
                if base is None:
                    return unsupported(inst_idx, inst, 'load_base')
                set_reg(inst.rd, load_mem(u64(base + inst.imm), inst.width, inst.name))
            elif inst.type == IType.Store:
                base = reg_value(inst.rs1)
                value = reg_value(inst.rs2)
                if base is None or value is None:
                    return unsupported(inst_idx, inst, 'store_operand')
                store_mem(u64(base + inst.imm), inst.width, value)
            elif inst.type in [IType.Branch, IType.Jump]:
                break
            else:
                return unsupported(inst_idx, inst, 'type')
        states_by_addr[begin_addr + len(prog.insts) * 4] = ConcretePrefixState(regs.copy())
        return states_by_addr

    def replay_prefix_cache_key(reg_values, mem_values, sp_value, sp_affine_mem_offsets):
        mask = (1 << 64) - 1
        return (
            sp_value & mask,
            tuple(sorted((reg.name, value & mask) for reg, value in reg_values.items())),
            tuple(sorted((offset, value & mask) for offset, value in mem_values.items())),
            sp_affine_cache_items(sp_affine_mem_offsets),
        )

    def replay_prefix_state(reg_values, mem_values, target_addr, sp_value=CONCRETE_REPLAY_SP, sp_affine_mem_offsets=None):
        _write_profile_stage(name, "init:concrete_replay_prefix")
        cache_key = replay_prefix_cache_key(reg_values, mem_values, sp_value, sp_affine_mem_offsets)
        if cache_key in replay_prefix_state_cache:
            return replay_prefix_state_cache[cache_key].get(target_addr)

        states_by_addr = concrete_prefix_states(
            reg_values,
            mem_values,
            sp_value=sp_value,
            sp_affine_mem_offsets=sp_affine_mem_offsets,
        )
        if states_by_addr is not None:
            replay_prefix_state_cache[cache_key] = states_by_addr
            return states_by_addr.get(target_addr)

        replay_state = proj.factory.blank_state(
            addr=begin_addr,
            mode='symbolic',
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        set_concrete_state(replay_state, reg_values, mem_values, sp_value=sp_value, sp_affine_mem_offsets=sp_affine_mem_offsets)
        replay_mgr = proj.factory.simulation_manager(replay_state)
        states_by_addr = {}
        max_steps = max(1, len(prog.insts) + 8)
        for _ in range(max_steps):
            for state in list(replay_mgr.active):
                try:
                    ip = state.solver.eval(state.ip)
                except Exception:
                    continue
                states_by_addr.setdefault(ip, state)
                if ip == target_addr:
                    replay_prefix_state_cache[cache_key] = states_by_addr
                    return state
            if not replay_mgr.active:
                replay_prefix_state_cache[cache_key] = states_by_addr
                return None
            replay_mgr.step()
        replay_prefix_state_cache[cache_key] = states_by_addr
        return None

    def concrete_ranges_overlap(addr1, width1, addr2, width2):
        lo1, hi1 = addr1 - width1 + 1, addr1
        lo2, hi2 = addr2 - width2 + 1, addr2
        return max(lo1, lo2) <= min(hi1, hi2)

    def symbolic_no_overlap(addr_symbol, width, mem_offset):
        offset_symbol = init_sp - addr_symbol
        store_lo = offset_symbol - (width - 1)
        mem_lo = claripy.BVV(mem_offset - 7, 64)
        mem_hi = claripy.BVV(mem_offset, 64)
        return claripy.Or(
            claripy.ULT(offset_symbol, mem_lo),
            claripy.ULT(mem_hi, store_lo),
        )

    def symbolic_word_slot_no_overlap(addr_symbol, width, slot_addr_symbol):
        offset_symbol = init_sp - addr_symbol
        slot_offset = init_sp - slot_addr_symbol
        slot_hi = (slot_offset + 7) & claripy.BVV(~7 & ((1 << 64) - 1), 64)
        slot_lo = slot_hi - (INIT_ACCESS_SLOT_WIDTH - 1)
        access_lo = offset_symbol - (width - 1)
        return claripy.Or(
            claripy.ULT(offset_symbol, slot_lo),
            claripy.ULT(slot_hi, access_lo),
        )

    def symbolic_init_slots_no_overlap(addr_symbol_a, addr_symbol_b):
        offset_a = init_sp - addr_symbol_a
        offset_b = init_sp - addr_symbol_b
        slot_hi_a = (offset_a + 7) & claripy.BVV(~7 & ((1 << 64) - 1), 64)
        slot_hi_b = (offset_b + 7) & claripy.BVV(~7 & ((1 << 64) - 1), 64)
        slot_lo_a = slot_hi_a - (INIT_ACCESS_SLOT_WIDTH - 1)
        slot_lo_b = slot_hi_b - (INIT_ACCESS_SLOT_WIDTH - 1)
        return claripy.Or(
            claripy.ULT(slot_hi_a, slot_lo_b),
            claripy.ULT(slot_hi_b, slot_lo_a),
        )

    def symbolic_access_no_overlap(addr_symbol_a, width_a, addr_symbol_b, width_b):
        offset_a = init_sp - addr_symbol_a
        offset_b = init_sp - addr_symbol_b
        return claripy.Or(
            claripy.ULT(offset_a, offset_b - (width_b - 1)),
            claripy.ULT(offset_b, offset_a - (width_a - 1)),
        )

    def init_slot_width(width):
        return max(width, INIT_ACCESS_SLOT_WIDTH)

    def find_base_addr(ssa_inst):  # 找到构造该访存地址的源头
        assert ssa_inst.is_ldst()
        addr_reg = ssa_inst.get_addr()
        tgt_node = rvfg.find_node_by_value(addr_reg)

        clean_insts = ['add', 'addi', 'addw', 'addiw',
                       'sub', 'subw',
                       'mul', 'mulw',
                       'and', 'andi',
                       'slli', 'srli', 'srai'
                       ]

        # 查找来自未定义寄存器的路径
        undef_paths = rvfg.find_clean_paths(rvfg.undef, tgt_node, clean_insts)
        # 查找来自内存加载的路径
        mem_clean_insts = clean_insts + ['ld', 'lw', 'lh', 'lb', 'lwu', 'lhu', 'lbu']
        mem_paths = rvfg.find_clean_paths(rvfg.mem, tgt_node, mem_clean_insts)

        undef_results = []
        for path in undef_paths:
            src = path[0].tgt.value
            if not any(src is item for item in undef_results):
                undef_results.append(src)

        mem_results = []
        for path in mem_paths:
            inst = path[0].attr.inst
            if inst not in mem_results:
                mem_results.append(inst)

        return undef_results + mem_results

    # map ssa inst to its addr base reg
    undef_base_regs = []
    mem_base_insts = []
    for inst in [i for i in ssas if i.is_ldst()]:
        for source in find_base_addr(inst):
            if isinstance(source, BitVecRef):
                source_reg = bitvec_to_reg(source)
                if source_reg not in undef_base_regs:
                    undef_base_regs.append(source_reg)
            elif isinstance(source, Inst):
                if any(m.pc == source.pc for m in mem_base_insts):
                    continue
                for prog_inst in prog2se.insts:
                    if prog_inst.pc == source.pc:
                        mem_base_insts.append(prog_inst)
                        break
    if verbose:
        print("undef_base_regs", undef_base_regs)
        print("mem_base_insts", mem_base_insts)

    # 穿透内存 Store 的追踪逻辑：处理内存作为中转站的情况
    extra_undef = []
    for load_inst in mem_base_insts:
        # 找到在该 Load 之前、且地址相同的最近一次 Store
        try:
            idx = load_inst.idx
            for i in range(idx - 1, -1, -1):
                prev = ssas[i]
                if prev.is_store() and prev.inst.addr == load_inst.addr:
                    # 找到了对应的 Store，追踪它的数据来源 (rs2)
                    data_reg = prev.inst.rs2
                    data_node = rvfg.find_node_by_value(data_reg)
                    if data_node:
                        clean_insts = ['add', 'addi', 'addw', 'addiw',
                                       'sub', 'subw',
                                       'mul', 'mulw',
                                       'and', 'andi',
                                       'slli', 'srli', 'srai'
                                       ]
                        # 查找数据来源的原始路径
                        added_undef_paths = rvfg.find_clean_paths(rvfg.undef, data_node, clean_insts)
                        for p in added_undef_paths:
                            src = p[0].tgt.value
                            if not any(src is item for item in extra_undef):
                                extra_undef.append(src)
                    else:
                        extra_undef.append(data_reg)
                    break  # 找到最近的一次 Store 即可停止
        except (ValueError, AttributeError):
            continue
    if verbose:
        print("extra_undef", extra_undef)

    # zero fill integer registers
    for i in range(32):
        setattr(init_state.regs, f'x{i}', claripy.BVV(0, 64))

    init_sp = claripy.BVS(REG_PREFIX + 'sp', 64)
    init_state.regs.sp = init_sp

    # create variables for undefined registers
    reg_to_symbol = {}
    for r in regs_undefined:
        var = claripy.BVS(f'{REG_PREFIX + r.name}', 64)
        setattr(init_state.regs, r.name, var)
        reg_to_symbol[r] = var

    if verbose:
        DEBUG(f'{reg_to_symbol =}')

    # init_state.add_constraints(init_sp == claripy.BVV(0x7fff0000, 64))
    init_state.add_constraints(init_state.regs.x0 == 0)

    # create a simulation manager
    simgr = proj.factory.simulation_manager(init_state)

    # mapping unconstrained symbol to undefined registers
    _write_profile_stage(name, "init:symbolic_reg_mapping")
    simgr.explore(
        find=begin_addr + len(regs_undefined) * 4,
        avoid=fail_addr,
    )  # 确保符号执行能够执行完所有的寄存器检查指令
    history_events = simgr.found[0].history.events.hardcopy
    history_events = [e for e in history_events if isinstance(e, SimActionConstraint)]
    if verbose:
        DEBUG(f'{history_events = }')
    undef_check_idx = 0
    for event in history_events:
        constraint = event.constraint
        ast = constraint.ast
        if ast.op not in {'SGE', 'SLE', 'SGT', 'SLT'}:
            continue
        args = [arg for arg in ast.args if hasattr(arg, 'variables')]
        symbolic_args = [arg for arg in args if getattr(arg, 'variables', set())]
        zero_args = [
            arg for arg in args
            if not getattr(arg, 'variables', set())
            and getattr(arg, 'concrete_value', None) == 0
        ]
        if len(symbolic_args) != 1 or not zero_args:
            continue
        if undef_check_idx >= len(regs_undefined):
            continue
        reg_symbol = symbolic_args[0]  # 当前引擎真正正在使用的那个符号 AST 对象，符号执行引擎内部用来代表那个未定义寄存器的“符号变量对象”
        if not str(reg_symbol).startswith(f'<BV64 {REG_PREFIX}'):
            r = regs_undefined[undef_check_idx]
            reg_to_symbol[r] = reg_symbol
            if verbose:
                WARNING(f'unconstrained register: {str(reg_symbol)} for {r}')
        undef_check_idx += 1
    if verbose:
        print("reg_to_symbol", reg_to_symbol)

    undef_reg_check_constraints = []
    for r in regs_undefined:
        symbol = reg_to_symbol.get(r)
        if symbol is not None:
            undef_reg_check_constraints.append(symbol.SGE(claripy.BVV(0, 64)))

    # capture unconstrained load value and symbolic memory addresses
    mem_base_insts = list(mem_base_insts)
    mem_base_insts.sort(key=lambda i: prog2se.insts.index(i))
    mem_base_ids = {id(i) for i in mem_base_insts}
    mem_base_map = {}
    load_accesses = []
    mem_accesses = []
    store_accesses = []
    access_insts = []
    for inst_idx, inst in enumerate(prog2se.insts):
        if inst.type in [IType.Load, IType.Store, IType.Amo]:
            access_insts.append((inst_idx, inst))

    def access_match_key(inst):
        return (inst.pc, inst.type, inst.name, getattr(inst, 'code', str(inst)))

    original_access_indices_by_key = {}
    original_access_order = []
    for original_idx, original_inst in enumerate(prog.insts):
        if original_inst.type not in [IType.Load, IType.Store, IType.Amo]:
            continue
        original_access_order.append(original_idx)
        original_access_indices_by_key.setdefault(access_match_key(original_inst), []).append(original_idx)

    original_access_idx_by_inst_idx = {}
    used_original_accesses_by_key = {}
    for access_ordinal, (inst_idx, inst) in enumerate(access_insts):
        key = access_match_key(inst)
        candidates = original_access_indices_by_key.get(key, [])
        used_count = used_original_accesses_by_key.get(key, 0)
        if used_count < len(candidates):
            original_idx = candidates[used_count]
            used_original_accesses_by_key[key] = used_count + 1
        elif access_ordinal < len(original_access_order):
            original_idx = original_access_order[access_ordinal]
        else:
            original_idx = inst_idx
        original_access_idx_by_inst_idx[inst_idx] = original_idx

    def original_access_addr(inst_idx):
        return begin_addr + original_access_idx_by_inst_idx.get(inst_idx, inst_idx) * 4

    has_symbolic_mul = any(inst.name in {'mul', 'mulw'} for inst in prog2se.insts)
    use_static_memory_collection = (
        len(access_insts) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
        or (has_symbolic_mul and len(access_insts) >= 2)
    )

    def static_collect_memory_accesses():
        complex_static_collection = True

        def maybe_simplify(expr):
            return expr if complex_static_collection else claripy.simplify(expr)

        def bvv(value, bits=64):
            return claripy.BVV(value & ((1 << bits) - 1), bits)

        def reg_value(reg):
            if reg == XREG[0]:
                return bvv(0)
            return env.get(reg, reg_to_symbol.get(reg, bvv(0)))

        def set_reg(reg, value):
            if reg != XREG[0]:
                env[reg] = maybe_simplify(value)

        def symbolic_expr(expr):
            return bool(getattr(expr, 'variables', set()))

        def static_ast_node_count(expr):
            seen = set()
            stack = [expr]
            count = 0
            while stack:
                node = stack.pop()
                key = id(node)
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                for arg in getattr(node, 'args', ()):
                    if hasattr(arg, 'op'):
                        stack.append(arg)
            return count

        def should_preserve_symbolic_mul(lhs, rhs):
            if not complex_static_collection:
                return True
            if not (symbolic_expr(lhs) or symbolic_expr(rhs)):
                return True
            return (
                static_ast_node_count(lhs) + static_ast_node_count(rhs)
                <= STATIC_SYMBOLIC_MUL_NODE_LIMIT
            )

        livein_symbol_vars = set()
        for symbol in reg_to_symbol.values():
            livein_symbol_vars.update(getattr(symbol, 'variables', set()))

        def static_ast_vars(expr):
            return getattr(expr, 'variables', set())

        def static_iter_ast_nodes(expr):
            seen = set()
            stack = [expr]
            while stack:
                node = stack.pop()
                key = id(node)
                if key in seen:
                    continue
                seen.add(key)
                yield node
                for arg in getattr(node, 'args', ()):
                    if hasattr(arg, 'op'):
                        stack.append(arg)

        def static_replace_ast(node, target, replacement):
            if node is target:
                return replacement
            if not hasattr(node, 'op'):
                return node
            changed = False
            new_args = []
            for arg in getattr(node, 'args', ()):
                if hasattr(arg, 'op'):
                    new_arg = static_replace_ast(arg, target, replacement)
                else:
                    new_arg = arg
                if new_arg is not arg:
                    changed = True
                new_args.append(new_arg)
            if not changed:
                return node
            return claripy.simplify(node.make_like(node.op, tuple(new_args)))

        def zero_base_plus_mul_residuals(expr):
            result = expr
            for node in list(static_iter_ast_nodes(expr)):
                if getattr(node, 'op', None) not in {'__mul__', 'Mul'}:
                    continue
                node_vars = static_ast_vars(node)
                if not node_vars:
                    continue
                residual = claripy.simplify(result - node)
                residual_vars = static_ast_vars(residual)
                if residual_vars & node_vars:
                    continue
                if not (residual_vars & livein_symbol_vars):
                    continue
                result = static_replace_ast(result, node, bvv(0))
            return maybe_simplify(result)

        def sign_extend_32(expr):
            return claripy.SignExt(32, expr[31:0])

        def zero_extend_32(expr):
            return claripy.ZeroExt(32, expr[31:0])

        def load_value(inst, inst_idx):
            if inst.name == 'ld':
                return claripy.BVS(f'symbolic_read_static_{len(load_accesses)}_{inst_idx}_64', 64)
            value = claripy.BVS(f'symbolic_read_static_{len(load_accesses)}_{inst_idx}_{inst.width * 8}', inst.width * 8)
            if inst.name == 'lw':
                return claripy.SignExt(32, value)
            if inst.name == 'lwu':
                return claripy.ZeroExt(32, value)
            if inst.name == 'lh':
                return claripy.SignExt(48, value)
            if inst.name == 'lhu':
                return claripy.ZeroExt(48, value)
            if inst.name == 'lb':
                return claripy.SignExt(56, value)
            if inst.name == 'lbu':
                return claripy.ZeroExt(56, value)
            return claripy.BVS(f'symbolic_read_static_{len(load_accesses)}_{inst_idx}_64', 64)

        def eval_r(inst):
            lhs, rhs = reg_value(inst.rs1), reg_value(inst.rs2)
            if inst.name == 'add':
                return lhs + rhs
            if inst.name == 'addw':
                return sign_extend_32(lhs + rhs)
            if inst.name == 'sub':
                return lhs - rhs
            if inst.name == 'subw':
                return sign_extend_32(lhs - rhs)
            if inst.name == 'mul':
                if not should_preserve_symbolic_mul(lhs, rhs):
                    return bvv(0)
                return lhs * rhs
            if inst.name == 'mulw':
                if not should_preserve_symbolic_mul(lhs, rhs):
                    return bvv(0)
                return sign_extend_32(lhs * rhs)
            if inst.name == 'and':
                return lhs & rhs
            if inst.name == 'or':
                return lhs | rhs
            if inst.name == 'xor':
                return lhs ^ rhs
            return None

        def eval_i(inst):
            lhs = reg_value(inst.rs1)
            imm = inst.imm
            if inst.name == 'addi':
                return lhs + bvv(imm)
            if inst.name == 'addiw':
                return sign_extend_32(lhs + bvv(imm))
            if inst.name == 'andi':
                return lhs & bvv(imm)
            if inst.name == 'ori':
                return lhs | bvv(imm)
            if inst.name == 'xori':
                return lhs ^ bvv(imm)
            if inst.name == 'slli':
                return lhs << imm
            if inst.name == 'srli':
                return claripy.LShR(lhs, imm)
            if inst.name == 'srai':
                return lhs >> imm
            if inst.name == 'slliw':
                return sign_extend_32(lhs[31:0] << imm)
            if inst.name == 'srliw':
                return sign_extend_32(claripy.LShR(lhs[31:0], imm))
            if inst.name == 'sraiw':
                return sign_extend_32(lhs[31:0] >> imm)
            return None

        env = {XREG[0]: bvv(0), XREG[2]: init_sp}
        env.update(reg_to_symbol)
        access_ids = {id(inst): inst_idx for inst_idx, inst in access_insts}

        for inst_idx, inst in enumerate(prog2se.insts):
            _write_profile_stage(
                name,
                "init:symbolic_memory_access_collection",
            )
            if inst.type in [IType.Load, IType.Store, IType.Amo]:
                base_symbol = reg_value(inst.rs1)
                addr_symbol = maybe_simplify(base_symbol + bvv(inst.imm))
                addr_symbol = zero_base_plus_mul_residuals(addr_symbol)
                mem_accesses.append((inst, addr_symbol, inst_idx, inst.width))
                if inst.type in [IType.Store, IType.Amo]:
                    data_symbol = reg_value(inst.rs2)
                    store_accesses.append((inst, addr_symbol, inst_idx, inst.width, data_symbol))
                if inst.type == IType.Load:
                    rd_symbol = load_value(inst, inst_idx)
                    set_reg(inst.rd, rd_symbol)
                    load_entry = (inst, rd_symbol, addr_symbol, inst_idx)
                    load_accesses.append(load_entry)
                    if id(inst) in mem_base_ids:
                        mem_base_map[inst] = load_entry
                        if verbose:
                            DEBUG(f'memory unconstrained symbol {name}: rd_symbol = {rd_symbol} addr_symbol = {addr_symbol}')
                continue

            if isinstance(inst, RFmtInst):
                value = eval_r(inst)
                if value is not None:
                    set_reg(inst.rd, value)
                continue

            if isinstance(inst, IFmtInst):
                value = eval_i(inst)
                if value is not None:
                    set_reg(inst.rd, value)
                continue

            if isinstance(inst, UFmtInst):
                if inst.name == 'li':
                    set_reg(inst.rd, bvv(inst.imm))
                elif inst.name == 'lui':
                    set_reg(inst.rd, bvv(inst.imm << 12))

        _write_profile_stage(name, "init:symbolic_memory_access_collection:done")
        return claripy.Solver()

    if use_static_memory_collection:
        if verbose:
            print("static_memory_access_collection", {
                "accesses": len(access_insts),
                "threshold": STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD,
            })
        solver = static_collect_memory_accesses()
    else:
        for inst_idx, inst in access_insts:
            _write_profile_stage(name, "init:symbolic_memory_access_collection")
            target_addr = begin_addr + inst_idx * 4  # 模拟执行，停在指令即将执行的那一刻
            pc = simgr.found[0].ip.concrete_value
            assert pc <= target_addr
            if pc < target_addr:
                simgr = proj.factory.simulation_manager(simgr.found[0])
                simgr.explore(find=target_addr, avoid=fail_addr)
                assert simgr.found
            # when rd == rs1 in a load instruction, the state of rs1 will be overwritten
            # we get the state of rs1 before the execution of the load inst
            base_symbol = getattr(simgr.found[0].regs, str(inst.rs1))

            addr_symbol = base_symbol + inst.imm
            mem_accesses.append((inst, addr_symbol, inst_idx, inst.width))
            if inst.type in [IType.Store, IType.Amo]:
                data_symbol = getattr(simgr.found[0].regs, str(inst.rs2))
                store_accesses.append((inst, addr_symbol, inst_idx, inst.width, data_symbol))

            if inst.type != IType.Load:
                continue

            old_rd_symbol = getattr(simgr.found[0].regs, str(inst.rd))
            load_end_addr = target_addr + 4
            simgr = proj.factory.simulation_manager(simgr.found[0])
            simgr.explore(find=load_end_addr, avoid=fail_addr)  ## 执行这条 ld 指令
            assert simgr.found

            rd_symbol = getattr(simgr.found[0].regs, str(inst.rd))
            old_rd_key = str(claripy.simplify(old_rd_symbol))
            rd_key = str(claripy.simplify(rd_symbol))
            if getattr(addr_symbol, 'variables', set()) and (
                not getattr(rd_symbol, 'variables', set()) or old_rd_key == rd_key
            ):
                rd_symbol = claripy.BVS(f'symbolic_read_forced_{len(load_accesses)}_{inst_idx}', 64)
                reg_offset, reg_size = proj.arch.registers[inst.rd.name]
                simgr.found[0].registers.store(reg_offset, rd_symbol, size=reg_size)
                setattr(simgr.found[0].regs, inst.rd.name, rd_symbol)
                setattr(simgr.found[0].regs, f'x{inst.rd.id}', rd_symbol)
            load_entry = (inst, rd_symbol, addr_symbol, inst_idx)
            load_accesses.append(load_entry)
            if id(inst) in mem_base_ids:
                mem_base_map[inst] = load_entry
            if verbose and id(inst) in mem_base_ids:
                DEBUG(f'memory unconstrained symbol {name}: {rd_symbol = } {addr_symbol = }')

    if verbose:
        print('load_accesses', [
            (idx, getattr(inst, 'code', str(inst)), str(addr_symbol), str(rd_symbol), sorted(getattr(rd_symbol, 'variables', set())))
            for inst, rd_symbol, addr_symbol, idx in load_accesses
        ])
        print('mem_accesses', [
            (idx, getattr(inst, 'code', str(inst)), str(addr_symbol), width, sorted(getattr(addr_symbol, 'variables', set())))
            for inst, addr_symbol, idx, width in mem_accesses
        ])

    if use_static_memory_collection:
        if verbose:
            DEBUG(f'{solver.constraints = }')
    else:
        # create a simulation manager
        simgr = proj.factory.simulation_manager(simgr.found[0])
        _write_profile_stage(name, "init:symbolic_execution_to_end")
        simgr.explore(find=end_addr, avoid=fail_addr)

        assert simgr.found, f'simulation fails at {end_addr:#x}'
        final_state = simgr.found[0]

        if verbose:
            DEBUG(f'{final_state.solver.constraints = }')
            DEBUG(f'{final_state.history.events.hardcopy = }')
        solver = final_state.solver
        solver.add(final_state.regs.x0 == 0)

    for constraint in undef_reg_check_constraints:
        solver.add(constraint)

    _write_profile_stage(name, "init:constraint_satisfiability")
    if len(mem_accesses) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
        satisfiable_result = None
        try:
            satisfiable_solver = solver.branch()
            satisfiable_solver.timeout = HEURISTIC_SOLVER_TIMEOUT_MS
            satisfiable_result = satisfiable_solver.satisfiable()
        except Exception:
            pass
        assert satisfiable_result is not False, f"[ERROR]: {name} is not satisfiable"
    else:
        assert solver.satisfiable(), f"[ERROR]: {name} is not satisfiable"

    solver.add(init_sp & 7 == 0)  # stack pointer alignment
    # solver.add(final_state.regs.sp == claripy.BVV(0x70a4a7bff690, 64))
    base_solver = claripy.Solver()
    base_solver.add(solver.constraints)
    concrete_sp_solver = base_solver.branch()
    concrete_sp_solver.timeout = HEURISTIC_SOLVER_TIMEOUT_MS
    concrete_sp_solver.add(init_sp == CONCRETE_REPLAY_SP)
    concrete_sp_result = None
    try:
        concrete_sp_result = concrete_sp_solver.satisfiable()
    except Exception:
        pass
    if concrete_sp_result is not False:
        base_solver.add(init_sp == CONCRETE_REPLAY_SP)
    else:
        raise UnsupportedBlockError(f"fixed replay sp is unsatisfiable for {name}")

    extra_undef_vars = []
    for reg in extra_undef:
        if isinstance(reg, BitVecRef):
            reg = bitvec_to_reg(reg)
        if reg in regs_undefined and reg in reg_to_symbol and reg not in extra_undef_vars:
            extra_undef_vars.append(reg)

    mem_entries = list(load_accesses)

    undef_base_vars = set()
    for base_reg in undef_base_regs:
        if base_reg in reg_to_symbol:
            undef_base_vars.update(getattr(reg_to_symbol[base_reg], 'variables', set()))

    pointer_value_varsets = []
    pointer_source_loads = []
    address_source_loads = []
    address_narrow_source_loads = []
    non_additive_addr_value_varsets = []
    pointer_source_keys = set()
    sp_affine_source_load_keys = set()

    # For every later memory address that depends on loaded data, choose one
    # additive 64-bit load as the stack-relative anchor.  This keeps composite
    # addresses position-independent instead of letting scalar operands encode
    # the fixed replay SP as an absolute constant.
    for _, addr_symbol, access_idx, _ in mem_accesses:
        addr_vars = getattr(addr_symbol, 'variables', set())
        anchor_candidates = []
        sp_affine_candidates = []
        for load_inst, rd_symbol, load_addr_symbol, load_idx in load_accesses:
            if load_idx >= access_idx or load_inst.width != 8:
                continue
            rd_vars = getattr(rd_symbol, 'variables', set())
            if not rd_vars or not (addr_vars & rd_vars):
                continue
            residual = claripy.simplify(addr_symbol - rd_symbol)
            if getattr(residual, 'variables', set()) & rd_vars:
                continue
            residual_vars = getattr(residual, 'variables', set())
            if residual_vars:
                residual_zero_solver = base_solver.branch()
                residual_zero_solver.timeout = HEURISTIC_SOLVER_TIMEOUT_MS
                try:
                    residual_zero_solver.add(residual == 0)
                    residual_zero_sat = residual_zero_solver.satisfiable()
                except Exception:
                    residual_zero_sat = False
                if not residual_zero_sat:
                    sp_affine_candidates.append((load_idx, load_inst, rd_symbol, load_addr_symbol))
                    continue
            anchor_candidates.append((load_idx, load_inst, rd_symbol, load_addr_symbol))
        if anchor_candidates:
            _, load_inst, rd_symbol, load_addr_symbol = max(anchor_candidates, key=lambda item: item[0])
            pointer_source_keys.add((id(load_inst), str(rd_symbol), str(load_addr_symbol)))
        elif sp_affine_candidates:
            load_idx, _, rd_symbol, _ = max(sp_affine_candidates, key=lambda item: item[0])
            sp_affine_source_load_keys.add((load_idx, str(rd_symbol)))

    for load_inst, rd_symbol, load_addr_symbol, load_idx in load_accesses:
        rd_vars = getattr(rd_symbol, 'variables', set())
        if not rd_vars:
            continue
        used_in_later_addr = any(
            access_idx > load_idx and (getattr(addr_symbol, 'variables', set()) & rd_vars)
            for _, addr_symbol, access_idx, _ in mem_accesses
        )
        if not used_in_later_addr:
            continue

        address_source_loads.append((load_inst, rd_symbol, load_addr_symbol, load_idx))
        pointer_key = (id(load_inst), str(rd_symbol), str(load_addr_symbol))
        if pointer_key in pointer_source_keys:
            pointer_value_varsets.append(frozenset(rd_vars))
            pointer_source_loads.append((load_inst, rd_symbol, load_addr_symbol, load_idx))
        else:
            non_additive_addr_value_varsets.append(frozenset(rd_vars))
            address_narrow_source_loads.append((load_addr_symbol, load_idx))
    if verbose:
        print('mem_base_map', mem_base_map)
        print('pointer_source_loads', [
            (load_idx, getattr(load_inst, 'code', str(load_inst)), str(load_addr_symbol), str(rd_symbol))
            for load_inst, rd_symbol, load_addr_symbol, load_idx in pointer_source_loads
        ])
        print('non_additive_addr_value_varsets', [sorted(v) for v in non_additive_addr_value_varsets])

    def load_value_identity_key(load_idx, rd_symbol, load_addr_symbol):
        return (load_idx, id(rd_symbol), id(load_addr_symbol))

    required_load_value_keys = {
        load_value_identity_key(load_idx, rd_symbol, load_addr_symbol)
        for load_inst, rd_symbol, load_addr_symbol, load_idx in address_source_loads
    }

    pointer_loaded_addr_vars = set()
    for varset in pointer_value_varsets:
        pointer_loaded_addr_vars.update(varset)
    address_loaded_addr_vars = set()
    for _, rd_symbol, _, _ in address_source_loads:
        address_loaded_addr_vars.update(getattr(rd_symbol, 'variables', set()))

    mem_base_pcs = {inst.pc for inst in mem_base_insts}

    def min_pointer_offset_for_vars(pointer_vars, producer_idx, avoid_ranges=None):
        avoid_ranges = [] if avoid_ranges is None else avoid_ranges
        min_offset = 0
        for inst, addr_symbol, access_idx, width in mem_accesses:
            if access_idx <= producer_idx:
                continue
            addr_vars = getattr(addr_symbol, 'variables', set())
            if not (addr_vars & pointer_vars):
                continue
            imm = _signed_u64(inst.imm)
            if imm >= 0:
                min_offset = max(min_offset, imm + width)
        min_offset = _align_up(min_offset, INIT_ACCESS_ALIGN)
        if not avoid_ranges:
            return min_offset

        def derived_store_ranges(base_offset):
            ranges = [(base_offset, 8)]
            for store_inst, store_addr_symbol, store_idx, store_width, _ in store_accesses:
                if store_idx <= producer_idx:
                    continue
                if not (getattr(store_addr_symbol, 'variables', set()) & pointer_vars):
                    continue
                imm = _signed_u64(store_inst.imm)
                access_offset = base_offset - imm
                if access_offset <= 0 or access_offset > STACK_RANGE:
                    return None
                ranges.append((access_offset, store_width))
            return ranges

        for offset in range(min_offset, STACK_RANGE + 1, INIT_ACCESS_ALIGN):
            ranges = derived_store_ranges(offset)
            if ranges is None:
                continue
            if any(
                concrete_ranges_overlap(access_offset, access_width, avoid_offset, avoid_width)
                for access_offset, access_width in ranges
                for avoid_offset, avoid_width in avoid_ranges
            ):
                continue
            return offset
        return min_offset

    def forced_same_address(addr_a, addr_b, solver):
        if str(addr_a) == str(addr_b):
            return True
        test_solver = solver.branch()
        test_solver.timeout = HEURISTIC_SOLVER_TIMEOUT_MS
        try:
            test_solver.add(addr_a != addr_b)
            return not test_solver.satisfiable()
        except Exception:
            return False

    def has_forced_prior_same_addr_store(addr_symbol, inst_idx, solver):
        for _, store_addr_symbol, store_idx, _, _ in reversed(store_accesses):
            if store_idx < inst_idx and forced_same_address(store_addr_symbol, addr_symbol, solver):
                return True
        return False

    def stored_value_for_load_expr(store_data_symbol, store_width, load_inst):
        if store_width < load_inst.width:
            return None
        if load_inst.name == 'ld':
            return store_data_symbol
        if load_inst.name == 'lw':
            return claripy.SignExt(32, store_data_symbol[31:0])
        if load_inst.name == 'lwu':
            return claripy.ZeroExt(32, store_data_symbol[31:0])
        if load_inst.name == 'lh':
            return claripy.SignExt(48, store_data_symbol[15:0])
        if load_inst.name == 'lhu':
            return claripy.ZeroExt(48, store_data_symbol[15:0])
        if load_inst.name == 'lb':
            return claripy.SignExt(56, store_data_symbol[7:0])
        if load_inst.name == 'lbu':
            return claripy.ZeroExt(56, store_data_symbol[7:0])
        return None

    store_pointer_required_varsets = []
    for load_inst, rd_symbol, load_addr_symbol, load_idx in pointer_source_loads:
        for _, store_addr_symbol, store_idx, store_width, store_data_symbol in reversed(store_accesses):
            if store_idx >= load_idx:
                continue
            if str(claripy.simplify(store_addr_symbol)) != str(claripy.simplify(load_addr_symbol)):
                continue
            stored_expr = stored_value_for_load_expr(store_data_symbol, store_width, load_inst)
            stored_vars = set() if stored_expr is None else set(getattr(stored_expr, 'variables', set()))
            if stored_vars:
                store_pointer_required_varsets.append(frozenset(stored_vars))
            break
    for load_inst, rd_symbol, load_addr_symbol, load_idx in load_accesses:
        rd_vars = set(getattr(rd_symbol, 'variables', set()))
        if not rd_vars:
            continue
        if any(rd_vars & required_vars for required_vars in store_pointer_required_varsets):
            required_load_value_keys.add(
                load_value_identity_key(load_idx, rd_symbol, load_addr_symbol)
            )

    def stack_pointer_constraints_for_expr(expr, min_offset=INIT_PTR_MIN_OFFSET):
        offset_expr = init_sp - expr
        return [
            claripy.UGE(offset_expr, claripy.BVV(min_offset, 64)),
            claripy.ULE(offset_expr, claripy.BVV(STACK_RANGE, 64)),
            (offset_expr & (INIT_ACCESS_ALIGN - 1)) == 0,
        ]

    def build_arithmetic_address_hints():
        env = {}
        load_value_hints = {}
        load_pointer_hints = {}
        reg_pointer_hints = {}
        reg_value_hints = {}
        load_nonzero_hints = set()
        reg_nonzero_hints = set()

        def const_expr(value):
            return ('const', value & ((1 << 64) - 1))

        def reg_expr(reg):
            return env.get(reg, ('reg', reg))

        def unknown_expr(inst):
            return ('unknown', getattr(inst, 'pc', id(inst)), getattr(inst, 'name', 'unknown'))

        def op_expr(op, *args, preferred=None):
            if preferred is None:
                return (op, *args)
            return (op, *args, {'preferred': preferred})

        def expr_args(expr):
            if not isinstance(expr, tuple):
                return []
            return [arg for arg in expr[1:] if isinstance(arg, tuple)]

        def preferred_arg(expr):
            if not isinstance(expr, tuple) or not expr:
                return None
            marker = expr[-1]
            if isinstance(marker, dict):
                return marker.get('preferred')
            return None

        def has_kind(expr, kind):
            if not isinstance(expr, tuple):
                return False
            if expr[0] == kind:
                return True
            return any(has_kind(arg, kind) for arg in expr_args(expr))

        def contains(expr, target):
            if expr == target:
                return True
            if not isinstance(expr, tuple):
                return False
            return any(contains(arg, target) for arg in expr_args(expr))

        def collect_loads(expr, out=None):
            out = [] if out is None else out
            if not isinstance(expr, tuple):
                return out
            if expr[0] == 'load':
                out.append(expr)
            for arg in expr_args(expr):
                collect_loads(arg, out)
            return out

        def collect_regs(expr, out=None):
            out = [] if out is None else out
            if not isinstance(expr, tuple):
                return out
            if expr[0] == 'reg':
                out.append(expr)
            for arg in expr_args(expr):
                collect_regs(arg, out)
            return out

        def collect_narrow_index_terms(expr, out=None):
            out = [] if out is None else out
            if not isinstance(expr, tuple):
                return out
            if expr[0] == 'narrow':
                out.extend(collect_loads(expr))
                out.extend(collect_regs(expr))
                return out
            for arg in expr_args(expr):
                collect_narrow_index_terms(arg, out)
            return out

        def collect_narrow_exprs(expr, out=None):
            out = [] if out is None else out
            if not isinstance(expr, tuple):
                return out
            if expr[0] == 'narrow':
                out.append(expr)
            for arg in expr_args(expr):
                collect_narrow_exprs(arg, out)
            return out

        def append_reg_value_hint(reg, value):
            if reg not in reg_to_symbol:
                return False
            value &= 0xffffffff
            existing = {v & 0xffffffff for v in reg_value_hints.get(reg, [])}
            if existing and existing != {value}:
                return False
            reg_value_hints.setdefault(reg, []).append(value)
            return True

        def word_affine(expr):
            mask = (1 << 32) - 1

            def normalize(const, coeffs):
                return (
                    const & mask,
                    {reg: coeff & mask for reg, coeff in coeffs.items() if coeff & mask},
                )

            def add_affine(lhs, rhs, sign=1):
                const = lhs[0] + sign * rhs[0]
                coeffs = dict(lhs[1])
                for reg, coeff in rhs[1].items():
                    coeffs[reg] = coeffs.get(reg, 0) + sign * coeff
                return normalize(const, coeffs)

            def scale_affine(affine, factor):
                const, coeffs = affine
                return normalize(
                    const * factor,
                    {reg: coeff * factor for reg, coeff in coeffs.items()},
                )

            if not isinstance(expr, tuple) or not expr:
                return None
            if expr[0] == 'const':
                return normalize(expr[1], {})
            if expr[0] == 'reg':
                reg = expr[1]
                if reg not in reg_to_symbol:
                    return None
                return normalize(0, {reg: 1})
            if expr[0] == 'narrow':
                args = expr_args(expr)
                return word_affine(args[0]) if args else None

            op = expr[0]
            args = expr_args(expr)
            if op == 'add':
                result = normalize(0, {})
                for arg in args:
                    aff = word_affine(arg)
                    if aff is None:
                        return None
                    result = add_affine(result, aff)
                return result
            if op == 'sub':
                if not args:
                    return None
                result = word_affine(args[0])
                if result is None:
                    return None
                for arg in args[1:]:
                    aff = word_affine(arg)
                    if aff is None:
                        return None
                    result = add_affine(result, aff, sign=-1)
                return result
            if op == 'mul' and len(args) == 2:
                lhs, rhs = args
                if is_const_expr(lhs):
                    rhs_aff = word_affine(rhs)
                    return None if rhs_aff is None else scale_affine(rhs_aff, lhs[1])
                if is_const_expr(rhs):
                    lhs_aff = word_affine(lhs)
                    return None if lhs_aff is None else scale_affine(lhs_aff, rhs[1])
            return None

        def add_word_affine_zero_hint(expr):
            affine = word_affine(expr)
            if affine is None:
                return set()
            const, coeffs = affine
            if not coeffs:
                return set()

            regs_by_use = []
            seen_regs = set()
            for reg_expr_item in collect_regs(expr):
                reg = reg_expr_item[1]
                if reg in coeffs and reg not in seen_regs:
                    regs_by_use.append(reg)
                    seen_regs.add(reg)

            target_reg = None
            target_coeff = None
            for reg in reversed(regs_by_use):
                coeff = coeffs.get(reg, 0) & 0xffffffff
                if coeff & 1:
                    target_reg = reg
                    target_coeff = coeff
                    break
            if target_reg is None:
                return set()

            target_value = ((-const) * pow(target_coeff, -1, 1 << 32)) & 0xffffffff
            planned = {}
            for reg in coeffs:
                planned[reg] = 0
            planned[target_reg] = target_value

            for reg, value in planned.items():
                existing = {v & 0xffffffff for v in reg_value_hints.get(reg, [])}
                if existing and existing != {value}:
                    return set()
            for reg, value in planned.items():
                append_reg_value_hint(reg, value)
            return set(planned)

        def mul_depth(expr, target, depth=0):
            if expr == target:
                return depth
            if not isinstance(expr, tuple):
                return -1
            next_depth = depth + 1 if expr[0] == 'mul' else depth
            return max(
                [mul_depth(arg, target, next_depth) for arg in expr_args(expr)] or [-1]
            )

        def carrier_hint_score(expr, target):
            if not contains(expr, target):
                return -1
            if expr == target:
                return 0
            score = 0
            preferred = preferred_arg(expr)
            if preferred is not None and contains(preferred, target):
                score = max(score, 1 + carrier_hint_score(preferred, target))
            for arg in expr_args(expr):
                if arg is preferred:
                    continue
                score = max(score, carrier_hint_score(arg, target))
            return score

        def add_value_hint(expr, value, allow_word_value=False):
            if not isinstance(expr, tuple):
                return False
            value &= ((1 << 64) - 1)
            if expr[0] == 'const':
                return expr[1] == value
            if expr[0] == 'load':
                pc = expr[1]
                load_value_hints.setdefault(pc, []).append(value)
                return True
            if expr[0] == 'reg':
                reg = expr[1]
                if reg not in reg_to_symbol:
                    return False
                if value & (1 << 63):
                    if not allow_word_value:
                        return False
                    value &= 0xffffffff
                reg_value_hints.setdefault(reg, []).append(value)
                return True
            if expr[0] == 'unknown':
                return False
            op = expr[0]
            args = expr_args(expr)
            if op == 'narrow' and args:
                return add_value_hint(args[0], value, allow_word_value=True)
            if value == 0 and op in {'add', 'sub'}:
                signed_terms = []
                concrete_total = 0
                for i, arg in enumerate(args):
                    sign = 1 if op == 'add' or i == 0 else -1
                    if arg[0] == 'const':
                        concrete_total = (concrete_total + sign * arg[1]) & ((1 << 64) - 1)
                    else:
                        signed_terms.append((sign, arg))
                if not signed_terms:
                    return concrete_total == value
                target = (value - concrete_total) & ((1 << 64) - 1)
                for sign, arg in signed_terms[:-1]:
                    if not add_value_hint(arg, 0, allow_word_value=allow_word_value):
                        return False
                sign, arg = signed_terms[-1]
                arg_target = target if sign > 0 else (-target) & ((1 << 64) - 1)
                return add_value_hint(arg, arg_target, allow_word_value=allow_word_value)
            if value == 1 and op == 'mul':
                return all(add_value_hint(arg, 1, allow_word_value=allow_word_value) for arg in args)
            if value == 0 and op == 'mul':
                def zero_mul_arg_key(arg):
                    if isinstance(arg, tuple) and arg and arg[0] == 'reg':
                        return (0, 0)
                    if isinstance(arg, tuple) and arg and arg[0] == 'load':
                        return (0, 1)
                    return (1, len(str(arg)))
                return any(add_value_hint(arg, 0, allow_word_value=allow_word_value) for arg in sorted(args, key=zero_mul_arg_key))
            if value == 0 and op == 'shift' and args:
                return add_value_hint(args[0], 0, allow_word_value=allow_word_value)
            return False

        def constrain_to_carrier(expr, carrier):
            if expr == carrier:
                return True
            if not isinstance(expr, tuple):
                return False
            op = expr[0]
            args = expr_args(expr)
            carrier_args = [arg for arg in args if contains(arg, carrier)]
            if len(carrier_args) != 1:
                return False
            carrier_arg = carrier_args[0]
            if op == 'add':
                return constrain_to_carrier(carrier_arg, carrier) and all(
                    add_value_hint(arg, 0)
                    for arg in args
                    if arg is not carrier_arg
                )
            if op == 'sub':
                if not args or carrier_arg is not args[0]:
                    return False
                return constrain_to_carrier(carrier_arg, carrier) and all(
                    add_value_hint(arg, 0)
                    for arg in args[1:]
                )
            if op == 'mul':
                return constrain_to_carrier(carrier_arg, carrier) and all(
                    add_value_hint(arg, 1)
                    for arg in args
                    if arg is not carrier_arg
                )
            return False

        def carrier_base_score(carrier):
            if carrier[0] == 'load':
                return 1 if carrier[1] in mem_base_pcs else 0
            if carrier[0] == 'reg':
                return 1 if carrier[1] in undef_base_regs else 0
            return 0

        def carrier_order_key(expr, carrier):
            return (
                carrier_hint_score(expr, carrier),
                carrier_base_score(carrier),
                1 if carrier[0] == 'reg' else 0,
                -mul_depth(expr, carrier),
            )

        def choose_carrier(expr):
            loads = collect_loads(expr)
            loads = [load for load in loads if load[2].width == 8]
            regs = collect_regs(expr)
            carriers = loads + regs
            if not carriers:
                return None
            return max(carriers, key=lambda item: carrier_order_key(expr, item))

        def is_const_expr(expr):
            return isinstance(expr, tuple) and expr and expr[0] == 'const'

        def add_pointer_hint(expr, min_offset):
            carrier = expr
            if not (isinstance(carrier, tuple) and carrier and carrier[0] in {'load', 'reg'}):
                carrier = choose_carrier(expr)
            if carrier is None:
                return False
            if carrier[0] == 'load':
                load_pc, load_inst = carrier[1], carrier[2]
                if load_inst.width != 8:
                    return False
                load_pointer_hints[load_pc] = max(
                    load_pointer_hints.get(load_pc, 0),
                    min_offset,
                )
                return True
            if carrier[0] == 'reg':
                reg = carrier[1]
                if reg not in reg_to_symbol:
                    return False
                reg_pointer_hints[reg] = max(
                    reg_pointer_hints.get(reg, 0),
                    min_offset,
                )
                return True
            return False

        def add_nonzero_hint(expr):
            if not isinstance(expr, tuple):
                return False
            if expr[0] == 'load':
                load_nonzero_hints.add(expr[1])
                return True
            if expr[0] == 'reg':
                reg = expr[1]
                if reg in reg_to_symbol:
                    reg_nonzero_hints.add(reg)
                    return True
            return False

        def zero_additive_mul_index(expr, width):
            if not isinstance(expr, tuple):
                return False
            op = expr[0]
            args = expr_args(expr)
            if op in {'add', 'sub'}:
                mul_args = [arg for arg in args if has_kind(arg, 'mul')]
                non_mul_carriers = [
                    arg for arg in args
                    if not has_kind(arg, 'mul') and not is_const_expr(arg)
                ]
                if mul_args and non_mul_carriers:
                    if not all(add_value_hint(arg, 0) for arg in mul_args):
                        return False
                    def additive_index_leaf_carrier(item):
                        loads = [load for load in collect_loads(item) if load[2].width == 8]
                        if loads:
                            return loads[-1]
                        return choose_carrier(item) or item

                    def additive_index_carrier_key(item):
                        carrier = additive_index_leaf_carrier(item)
                        base_key = carrier_order_key(expr, carrier)
                        is_load_carrier = (
                            isinstance(carrier, tuple)
                            and carrier
                            and carrier[0] == 'load'
                        )
                        return base_key + (1 if is_load_carrier else 0,)

                    carriers = sorted(
                        non_mul_carriers,
                        key=additive_index_carrier_key,
                        reverse=True,
                    )
                    for carrier_expr in carriers:
                        carrier = additive_index_leaf_carrier(carrier_expr)
                        if add_pointer_hint(carrier, 0):
                            if carrier_expr != carrier:
                                constrain_to_carrier(carrier_expr, carrier)
                            break
                    return True
                changed = False
                for arg in args:
                    if has_kind(arg, 'mul') and zero_additive_mul_index(arg, width):
                        changed = True
                return changed
            return False

        def collect_signed_add_terms(expr, sign=1, out=None):
            out = [] if out is None else out
            if not isinstance(expr, tuple):
                return out
            op = expr[0]
            args = expr_args(expr)
            if op == 'add':
                for arg in args:
                    collect_signed_add_terms(arg, sign, out)
                return out
            if op == 'sub' and args:
                collect_signed_add_terms(args[0], sign, out)
                for arg in args[1:]:
                    collect_signed_add_terms(arg, -sign, out)
                return out
            out.append((sign, expr))
            return out

        def add_linear_address_hint(addr_expr, width):
            terms = collect_signed_add_terms(addr_expr)
            def is_pointer_capable_linear_term(term):
                if not (isinstance(term, tuple) and term):
                    return False
                if term[0] == 'reg':
                    return True
                if term[0] == 'load':
                    return term[2].width == 8
                return False

            carrier_terms = [
                term for sign, term in terms
                if sign > 0
                and is_pointer_capable_linear_term(term)
            ]
            if not carrier_terms:
                return False

            carrier = carrier_terms[-1]
            changed = add_pointer_hint(carrier, 0)
            const_total = 0
            for sign, term in terms:
                if is_const_expr(term):
                    const_total += sign * _signed_u64(term[1])
            align_target = 0
            if width and width > 1:
                align_target = (-const_total) % width
            adjustable_positive_terms = [
                term for sign, term in terms
                if sign > 0
                and term != carrier
                and isinstance(term, tuple)
                and term
                and term[0] in {'load', 'reg'}
            ]
            adjusted_term = None
            if align_target and adjustable_positive_terms:
                adjusted_term = adjustable_positive_terms[0]
            for sign, term in terms:
                if term == carrier or is_const_expr(term):
                    continue
                if sign < 0:
                    changed = add_value_hint(term, 0) or changed
                elif sign > 0 and isinstance(term, tuple) and term and term[0] in {'load', 'reg'}:
                    target = align_target if term == adjusted_term else 0
                    changed = add_value_hint(term, target) or changed
            return changed

        def apply_address_hint(addr_expr, width):
            affine_hint_regs = set()
            for narrow_expr in collect_narrow_exprs(addr_expr):
                affine_hint_regs.update(add_word_affine_zero_hint(narrow_expr))
            for term in collect_narrow_index_terms(addr_expr):
                if term[0] == 'reg' and term[1] in affine_hint_regs:
                    continue
                add_value_hint(term, 0)
            if not has_kind(addr_expr, 'mul'):
                add_linear_address_hint(addr_expr, width)
                return
            snapshot = (
                copy.deepcopy(load_value_hints),
                copy.deepcopy(load_pointer_hints),
                copy.deepcopy(reg_pointer_hints),
                copy.deepcopy(reg_value_hints),
            )
            if zero_additive_mul_index(addr_expr, width):
                return
            load_value_hints.clear()
            load_value_hints.update(snapshot[0])
            load_pointer_hints.clear()
            load_pointer_hints.update(snapshot[1])
            reg_pointer_hints.clear()
            reg_pointer_hints.update(snapshot[2])
            reg_value_hints.clear()
            reg_value_hints.update(snapshot[3])

            carrier = choose_carrier(addr_expr)
            if carrier is None:
                return
            snapshot = (
                copy.deepcopy(load_value_hints),
                copy.deepcopy(load_pointer_hints),
                copy.deepcopy(reg_pointer_hints),
                copy.deepcopy(reg_value_hints),
            )
            if constrain_to_carrier(addr_expr, carrier):
                if carrier[0] == 'load':
                    load_pointer_hints[carrier[1]] = max(load_pointer_hints.get(carrier[1], 0), 0)
                elif carrier[0] == 'reg':
                    reg_pointer_hints[carrier[1]] = max(reg_pointer_hints.get(carrier[1], 0), 0)
            else:
                load_value_hints.clear()
                load_value_hints.update(snapshot[0])
                load_pointer_hints.clear()
                load_pointer_hints.update(snapshot[1])
                reg_pointer_hints.clear()
                reg_pointer_hints.update(snapshot[2])
                reg_value_hints.clear()
                reg_value_hints.update(snapshot[3])

        for inst in prog.insts:
            if inst.type in [IType.Load, IType.Store, IType.Amo]:
                addr_expr = op_expr('add', reg_expr(inst.rs1), const_expr(inst.imm))
                apply_address_hint(addr_expr, inst.width)
            if inst.type == IType.Load:
                env[inst.rd] = ('load', inst.pc, inst)
                continue
            if isinstance(inst, StoreInst):
                continue
            rd = inst.get_def()
            if not rd:
                continue
            if isinstance(inst, RFmtInst):
                lhs = reg_expr(inst.rs1)
                rhs = reg_expr(inst.rs2)
                if inst.name in {'div', 'divu', 'divw', 'divuw', 'rem', 'remu', 'remw', 'remuw'}:
                    add_nonzero_hint(rhs)
                preferred = None
                if inst.rd == inst.rs1:
                    preferred = lhs
                elif inst.rd == inst.rs2:
                    preferred = rhs
                if inst.name == 'add':
                    env[rd] = op_expr('add', lhs, rhs, preferred=preferred)
                elif inst.name == 'addw':
                    env[rd] = op_expr('narrow', op_expr('add', lhs, rhs, preferred=preferred), preferred=preferred)
                elif inst.name == 'sub':
                    env[rd] = op_expr('sub', lhs, rhs, preferred=preferred)
                elif inst.name == 'subw':
                    env[rd] = op_expr('narrow', op_expr('sub', lhs, rhs, preferred=preferred), preferred=preferred)
                elif inst.name == 'mul':
                    env[rd] = op_expr('mul', lhs, rhs, preferred=preferred)
                elif inst.name == 'mulw':
                    env[rd] = op_expr('narrow', op_expr('mul', lhs, rhs, preferred=preferred), preferred=preferred)
                else:
                    env[rd] = unknown_expr(inst)
            elif isinstance(inst, IFmtInst):
                lhs = reg_expr(inst.rs1)
                preferred = lhs if inst.rd == inst.rs1 else None
                if inst.name == 'addi':
                    env[rd] = op_expr('add', lhs, const_expr(inst.imm), preferred=preferred)
                elif inst.name == 'addiw':
                    env[rd] = op_expr('narrow', op_expr('add', lhs, const_expr(inst.imm), preferred=preferred), preferred=preferred)
                elif inst.name == 'slli':
                    env[rd] = op_expr('mul', lhs, const_expr(1 << inst.imm), preferred=preferred)
                elif inst.name in {'srli', 'srai'}:
                    env[rd] = op_expr('shift', lhs, const_expr(inst.imm), preferred=preferred)
                elif inst.name == 'slliw':
                    env[rd] = op_expr('narrow', op_expr('mul', lhs, const_expr(1 << inst.imm), preferred=preferred), preferred=preferred)
                elif inst.name in {'srliw', 'sraiw'}:
                    env[rd] = op_expr('narrow', lhs, preferred=preferred)
                else:
                    env[rd] = unknown_expr(inst)
            else:
                env[rd] = unknown_expr(inst)

        direct_memory_base_regs = {
            inst.rs1
            for inst in prog.insts
            if inst.type in [IType.Load, IType.Store, IType.Amo]
        }
        for reg in list(reg_pointer_hints):
            if reg in direct_memory_base_regs:
                continue
            values = {value & ((1 << 64) - 1) for value in reg_value_hints.get(reg, [])}
            if len(values) == 1:
                del reg_pointer_hints[reg]

        return load_value_hints, load_pointer_hints, reg_pointer_hints, reg_value_hints, load_nonzero_hints, reg_nonzero_hints

    load_value_hints, load_pointer_hints, reg_pointer_hints, reg_value_hints, load_nonzero_hints, reg_nonzero_hints = build_arithmetic_address_hints()
    direct_memory_base_regs = {
        inst.rs1
        for inst in prog.insts
        if inst.type in [IType.Load, IType.Store, IType.Amo]
    }
    scalar_hint_regs = {
        reg
        for reg, values in reg_value_hints.items()
        if reg not in direct_memory_base_regs
        and len({value & ((1 << 64) - 1) for value in values}) == 1
    }
    if verbose and (load_value_hints or load_pointer_hints or reg_pointer_hints or reg_value_hints or load_nonzero_hints or reg_nonzero_hints):
        print('arithmetic_address_hints', {
            'load_value_hints': {hex(k): v for k, v in load_value_hints.items()},
            'load_pointer_hints': {hex(k): v for k, v in load_pointer_hints.items()},
            'reg_pointer_hints': {str(k): v for k, v in reg_pointer_hints.items()},
            'reg_value_hints': {str(k): v for k, v in reg_value_hints.items()},
            'load_nonzero_hints': [hex(k) for k in sorted(load_nonzero_hints)],
            'reg_nonzero_hints': [str(k) for k in sorted(reg_nonzero_hints, key=lambda r: r.id)],
        })

    load_entries_by_pc = {}
    for load_entry in load_accesses:
        load_inst = load_entry[0]
        load_entries_by_pc.setdefault(load_inst.pc, []).append(load_entry)

    def stable_expr_key(expr):
        return str(claripy.simplify(expr))

    scalar_load_hint_keys = set()
    scalar_zero_address_load_keys = set()
    for pc, values in load_value_hints.items():
        unique_hint_values = {value & ((1 << 64) - 1) for value in values}
        if len(unique_hint_values) != 1:
            continue
        hinted_value = next(iter(unique_hint_values))
        for load_inst, rd_symbol, _, load_idx in load_entries_by_pc.get(pc, []):
            load_key = (load_idx, stable_expr_key(rd_symbol))
            scalar_load_hint_keys.add(load_key)
            rd_vars = getattr(rd_symbol, 'variables', set())
            used_in_later_addr = bool(rd_vars) and any(
                access_idx > load_idx and (getattr(addr_symbol, 'variables', set()) & rd_vars)
                for _, addr_symbol, access_idx, _ in mem_accesses
            )
            if hinted_value == 0 and load_inst.width < 8 and used_in_later_addr:
                scalar_zero_address_load_keys.add(load_key)

    for load_inst, rd_symbol, _, load_idx in address_source_loads:
        if load_inst.width >= 8 or load_inst.pc in load_nonzero_hints:
            continue
        scalar_zero_address_load_keys.add((load_idx, stable_expr_key(rd_symbol)))

    def materialize_init(candidate_solver, retry_index=0):
        _write_profile_stage(name, "init:materialize_init")
        candidate_solver = candidate_solver.branch()
        candidate_init = []
        reg_init = []
        reg_values = {}
        mem_values = {}
        mem_offset_addr_symbols = {}
        mem_slot_symbols = {}
        addr_expr_offsets = {}
        expr_key_cache = {}
        expr_vars_cache = {}
        affine_key_cache = {}
        affine_base_offset_choices = {}
        affine_base_min_offset_cache = {}
        cheap_same_address_cache = {}
        same_address_cache = {}
        forced_same_address_cache = {}
        prior_store_cache = {}
        forced_prior_store_cache = {}
        added_constraint_cache = set()
        equiv_parent = {}
        hint_pointer_load_keys = set()
        register_anchor_min_offsets = {}
        residual_scalar_regs = set()
        local_solver_timeout_ms = 100 if len(mem_accesses) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD else HEURISTIC_SOLVER_TIMEOUT_MS
        def expr_key(expr):
            cache_key = id(expr)
            if cache_key not in expr_key_cache:
                expr_key_cache[cache_key] = str(claripy.simplify(expr))
            return expr_key_cache[cache_key]

        def expr_vars(expr):
            key = id(expr)
            if key not in expr_vars_cache:
                expr_vars_cache[key] = getattr(expr, 'variables', set())
            return expr_vars_cache[key]

        def is_scalar_zero_address_load(load_inst, rd_symbol, load_idx):
            if (load_idx, expr_key(rd_symbol)) in scalar_zero_address_load_keys:
                return True
            if load_inst.width >= 8 or load_inst.pc in load_nonzero_hints:
                return False
            rd_vars = expr_vars(rd_symbol)
            return bool(rd_vars) and any(
                access_idx > load_idx and (expr_vars(addr_symbol) & rd_vars)
                for _, addr_symbol, access_idx, _ in mem_accesses
            )

        for pc, values in load_value_hints.items():
            unique_hint_values = {value & ((1 << 64) - 1) for value in values}
            if len(unique_hint_values) != 1:
                continue
            for load_inst, rd_symbol, _, load_idx in load_entries_by_pc.get(pc, []):
                pointer_loaded_addr_vars.difference_update(expr_vars(rd_symbol))
        for pc in load_pointer_hints:
            for load_inst, rd_symbol, _, _ in load_entries_by_pc.get(pc, []):
                if load_inst.width == 8:
                    pointer_loaded_addr_vars.update(expr_vars(rd_symbol))

        def equiv_find(var):
            parent = equiv_parent.get(var, var)
            if parent != var:
                parent = equiv_find(parent)
                equiv_parent[var] = parent
            return parent

        def equiv_union(var_a, var_b):
            root_a = equiv_find(var_a)
            root_b = equiv_find(var_b)
            if root_a == root_b:
                return
            if str(root_b) < str(root_a):
                root_a, root_b = root_b, root_a
            equiv_parent[root_b] = root_a

        def expr_equiv_roots(expr):
            return {equiv_find(var) for var in expr_vars(expr)}

        def exprs_may_be_related(expr_a, expr_b):
            vars_a = expr_vars(expr_a)
            vars_b = expr_vars(expr_b)
            if vars_a & vars_b:
                return True
            return bool({equiv_find(var) for var in vars_a} & {equiv_find(var) for var in vars_b})

        def register_expr_equality(expr_a, expr_b):
            vars_a = expr_vars(expr_a)
            vars_b = expr_vars(expr_b)
            if len(vars_a) == 1 and len(vars_b) == 1:
                equiv_union(next(iter(vars_a)), next(iter(vars_b)))

        def satisfiable_with(expr, val, timeout_ms=None):
            concrete_value = concrete_expr_value(expr)
            if concrete_value is not None:
                return concrete_value == (val & ((1 << 64) - 1))
            test_solver = candidate_solver.branch()
            test_solver.timeout = local_solver_timeout_ms if timeout_ms is None else timeout_ms
            try:
                test_solver.add(expr == val)
                return test_solver.satisfiable()
            except Exception:
                return False

        def solver_min(expr):
            try:
                test_solver = candidate_solver.branch()
                test_solver.timeout = local_solver_timeout_ms
                return test_solver.min(expr)
            except Exception:
                return None

        def solver_min_with(expr, extra_constraints):
            try:
                test_solver = candidate_solver.branch()
                test_solver.timeout = local_solver_timeout_ms
                return test_solver.min(expr, extra_constraints=extra_constraints)
            except Exception:
                return None

        def solver_eval_with(expr, extra_constraints, n=256):
            try:
                test_solver = candidate_solver.branch()
                test_solver.timeout = local_solver_timeout_ms
                return test_solver.eval(expr, n, extra_constraints=extra_constraints)
            except Exception:
                return []

        def solver_eval_limited(expr, n=1, timeout_ms=1000, extra_constraints=None):
            extra_constraints = [] if extra_constraints is None else extra_constraints
            try:
                test_solver = candidate_solver.branch()
                test_solver.timeout = min(timeout_ms, local_solver_timeout_ms)
                for constraint in extra_constraints:
                    test_solver.add(constraint)
                return test_solver.eval(expr, n)
            except Exception:
                return []

        def concrete_expr_value(expr):
            if expr_vars(expr):
                return None
            try:
                return expr.concrete_value & ((1 << 64) - 1)
            except Exception:
                pass
            try:
                values = solver_eval_limited(expr, n=1, timeout_ms=local_solver_timeout_ms)
                if values:
                    return values[0] & ((1 << 64) - 1)
            except Exception:
                pass
            return None

        def affine_base_const(expr):
            expr = claripy.simplify(expr)
            try:
                bits = expr.size()
            except Exception:
                return None
            if bits != 64:
                return None

            terms = []
            const_total = 0
            mask = (1 << bits) - 1

            def collect(node, sign=1):
                nonlocal const_total
                node = claripy.simplify(node)
                if not expr_vars(node):
                    value = concrete_expr_value(node)
                    if value is None:
                        return False
                    const_total = (const_total + sign * _signed_u64(value)) & mask
                    return True
                op = getattr(node, 'op', '')
                args = [arg for arg in getattr(node, 'args', ()) if hasattr(arg, 'op')]
                if op in {'__add__', 'Add'}:
                    return all(collect(arg, sign) for arg in args)
                if op in {'__sub__', 'Sub'} and args:
                    if not collect(args[0], sign):
                        return False
                    return all(collect(arg, -sign) for arg in args[1:])
                terms.append((sign, node))
                return True

            if not collect(expr):
                return None

            base = claripy.BVV(0, bits)
            for sign, term in terms:
                base = base + term if sign > 0 else base - term
            base = claripy.simplify(base)
            return base, _signed_u64(const_total)

        def affine_key(expr):
            cache_key = id(expr)
            if cache_key not in affine_key_cache:
                result = affine_base_const(expr)
                if result is None:
                    affine_key_cache[cache_key] = None
                else:
                    base, imm = result
                    affine_key_cache[cache_key] = (expr_key(base), imm, base)
            return affine_key_cache[cache_key]

        def affine_same_or_distinct(addr_a, addr_b):
            affine_a = affine_key(addr_a)
            affine_b = affine_key(addr_b)
            if affine_a is None or affine_b is None:
                return None
            base_key_a, imm_a, _ = affine_a
            base_key_b, imm_b, _ = affine_b
            if base_key_a != base_key_b:
                return None
            return imm_a == imm_b

        def affine_accesses_disjoint(addr_a, width_a, addr_b, width_b):
            affine_a = affine_key(addr_a)
            affine_b = affine_key(addr_b)
            if affine_a is None or affine_b is None:
                return None
            base_key_a, imm_a, _ = affine_a
            base_key_b, imm_b, _ = affine_b
            if base_key_a != base_key_b:
                return None
            lo_a, hi_a = imm_a, imm_a + width_a - 1
            lo_b, hi_b = imm_b, imm_b + width_b - 1
            return hi_a < lo_b or hi_b < lo_a

        def concrete_offset_no_overlap_constraint(offset_expr, width, used_offset, used_width):
            used_lo = (used_offset - used_width + 1) & ((1 << 64) - 1)
            used_hi = used_offset & ((1 << 64) - 1)
            access_lo = offset_expr - (width - 1)
            return claripy.Or(
                claripy.ULT(offset_expr, claripy.BVV(used_lo, 64)),
                claripy.ULT(claripy.BVV(used_hi, 64), access_lo),
            )

        def value_selection_constraints(expr, positive=False, align=None, avoid=None, width=8):
            avoid = [] if avoid is None else avoid
            constraints = []
            if positive:
                constraints.append(claripy.UGT(expr, claripy.BVV(0, 64)))
                constraints.append(claripy.ULE(expr, claripy.BVV(STACK_RANGE, 64)))
            if align:
                constraints.append((expr & (align - 1)) == 0)
            for used, used_width in avoid:
                constraints.append(concrete_offset_no_overlap_constraint(expr, width, used, used_width))
            return constraints

        def concrete_value_from_materialized(expr):
            if not expr_vars(expr):
                return concrete_expr_value(expr)
            substitutions = {}
            for reg, value in reg_values.items():
                symbol = reg_to_symbol.get(reg)
                if symbol is None:
                    continue
                substitutions[expr_key(symbol)] = claripy.BVV(
                    value & ((1 << symbol.size()) - 1),
                    symbol.size(),
                )
            substitutions[expr_key(init_sp)] = claripy.BVV(
                CONCRETE_REPLAY_SP & ((1 << init_sp.size()) - 1),
                init_sp.size(),
            )

            cache = {}

            def substitute(node):
                if not hasattr(node, 'op'):
                    return node
                node_key = expr_key(node)
                if node_key in substitutions:
                    return substitutions[node_key]
                cache_key = id(node)
                if cache_key in cache:
                    return cache[cache_key]
                changed = False
                new_args = []
                for arg in getattr(node, 'args', ()):
                    new_arg = substitute(arg)
                    if new_arg is not arg:
                        changed = True
                    new_args.append(new_arg)
                if changed:
                    result = node.make_like(node.op, tuple(new_args))
                    result = claripy.simplify(result)
                else:
                    result = node
                cache[cache_key] = result
                return result

            substituted = substitute(expr)
            if expr_vars(substituted):
                return None
            return concrete_expr_value(claripy.simplify(substituted))

        def choose_value(expr, preferred=None, positive=False, align=None, avoid=None, width=8, required=True, fast_positive=False):
            avoid = [] if avoid is None else avoid
            step = align if align else 1
            complex_memory_block = len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD

            def concrete_value_ok(val):
                if positive and val <= 0:
                    return False
                if align and val % align != 0:
                    return False
                if positive and val > STACK_RANGE:
                    return False
                if any(concrete_ranges_overlap(val, width, used, used_width) for used, used_width in avoid):
                    return False
                return True

            def add_value_if_sat(val):
                if not concrete_value_ok(val):
                    return None
                if satisfiable_with(expr, val):
                    candidate_solver.add(expr == val)
                    return val
                return None

            seen = set()
            def try_candidate(val):
                if val is None or val in seen:
                    return None
                seen.add(val)
                return add_value_if_sat(val)

            if fast_positive and positive:
                for val in solver_eval_with(expr, [], n=8):
                    val &= ((1 << 64) - 1)
                    result = try_candidate(val)
                    if result is not None:
                        return result

            for val in [preferred]:
                result = try_candidate(val)
                if result is not None:
                    return result

            materialized_val = concrete_value_from_materialized(expr)
            result = try_candidate(materialized_val)
            if result is not None:
                return result

            if not positive:
                result = try_candidate(0)
                if result is not None:
                    return result

            def try_stack_base_offset_candidate():
                if not positive:
                    return None
                try:
                    reg_offsets = list(reg_min_stack_offsets.items())
                except NameError:
                    return None
                expr_variables = expr_vars(expr)
                attempts = 0
                max_attempts = 2 if complex_memory_block else None
                for reg, min_base_offset in reg_offsets:
                    symbol = reg_to_symbol.get(reg)
                    if symbol is None:
                        continue
                    symbol_vars = expr_vars(symbol)
                    if not symbol_vars or not (expr_variables & symbol_vars):
                        continue
                    residual = claripy.simplify((init_sp - expr) - symbol)
                    if expr_vars(residual) & symbol_vars:
                        continue
                    residual_value = concrete_expr_value(residual)
                    if residual_value is None:
                        continue
                    imm = _signed_u64(residual_value)
                    base_start = max(INIT_PTR_MIN_OFFSET, min_base_offset)
                    if imm >= 0:
                        base_start = max(base_start, imm + width)
                    base_start = _align_up(base_start, INIT_ACCESS_ALIGN)
                    base_stop = min(STACK_RANGE, base_start + 256)
                    for base_offset in range(base_start, base_stop + 1, INIT_ACCESS_ALIGN):
                        if max_attempts is not None and attempts >= max_attempts:
                            return None
                        access_offset = base_offset - imm
                        if access_offset <= 0 or access_offset > STACK_RANGE:
                            continue
                        if align and access_offset % align != 0:
                            continue
                        if any(concrete_ranges_overlap(access_offset, width, used, used_width) for used, used_width in avoid):
                            continue
                        attempts += 1
                        constraints = [
                            (init_sp - symbol) == base_offset,
                            expr == access_offset,
                        ]
                        if not try_add_constraint_set_fast(
                            constraints,
                            timeout_ms=100 if complex_memory_block else HEURISTIC_SOLVER_TIMEOUT_MS,
                        ):
                            continue
                        return access_offset
                return None

            result = try_stack_base_offset_candidate()
            if result is not None:
                return result

            def try_any_sp_relative_register_candidate():
                if not positive:
                    return None
                expr_variables = expr_vars(expr)
                if not expr_variables:
                    return None
                attempts = 0
                max_attempts = 2 if complex_memory_block else None
                for reg, symbol in reg_to_symbol.items():
                    symbol_vars = expr_vars(symbol)
                    if not symbol_vars or not (expr_variables & symbol_vars):
                        continue
                    residual = claripy.simplify((init_sp - expr) - symbol)
                    if expr_vars(residual) & symbol_vars:
                        continue
                    residual_value = concrete_expr_value(residual)
                    if residual_value is None:
                        continue
                    imm = _signed_u64(residual_value)
                    base_start = INIT_PTR_MIN_OFFSET
                    if imm >= 0:
                        base_start = max(base_start, imm + width)
                    base_start = _align_up(base_start, INIT_ACCESS_ALIGN)
                    starts = []
                    if preferred is not None:
                        starts.append(preferred)
                    starts.append(_align_up(1, align) if align else 1)
                    starts.extend(used + max(width, used_width) for used, used_width in avoid)
                    seen_offsets = set()
                    for start in starts:
                        start = max(1, start)
                        if align:
                            start = _align_up(start, align)
                        for access_offset in range(start, min(STACK_RANGE, start + 256) + 1, step):
                            if max_attempts is not None and attempts >= max_attempts:
                                return None
                            if access_offset in seen_offsets:
                                continue
                            seen_offsets.add(access_offset)
                            if not concrete_value_ok(access_offset):
                                continue
                            base_offset = access_offset + imm
                            if base_offset <= 0 or base_offset > STACK_RANGE:
                                continue
                            if base_offset < base_start:
                                continue
                            if base_offset % INIT_ACCESS_ALIGN != 0:
                                continue
                            constraints = [
                                (init_sp - symbol) == base_offset,
                                expr == access_offset,
                            ]
                            attempts += 1
                            if try_add_constraint_set_fast(constraints):
                                return access_offset
                return None

            result = try_any_sp_relative_register_candidate()
            if result is not None:
                return result

            def try_pointer_load_base_offset_candidate():
                if not positive:
                    return None
                expr_variables = expr_vars(expr)
                attempts = 0
                max_attempts = 2 if complex_memory_block else None
                for _, rd_symbol, _, load_idx in pointer_source_loads:
                    rd_vars = expr_vars(rd_symbol)
                    if not rd_vars or not (expr_variables & rd_vars):
                        continue
                    residual = claripy.simplify((init_sp - expr) - rd_symbol)
                    if expr_vars(residual) & rd_vars:
                        continue
                    residual_value = concrete_expr_value(residual)
                    if residual_value is None:
                        continue
                    imm = _signed_u64(residual_value)
                    base_start = min_pointer_offset_for_vars(rd_vars, load_idx)
                    if imm >= 0:
                        base_start = max(base_start, imm + width)
                    access_starts = []
                    if preferred is not None:
                        access_starts.append(preferred)
                    low = _align_up(1, align) if align else 1
                    access_starts.append(low)
                    access_starts.extend(used + max(width, used_width) for used, used_width in avoid)
                    seen_offsets = set()
                    for start in access_starts:
                        start = max(start, low)
                        if align:
                            start = _align_up(start, align)
                        for access_offset in range(start, min(STACK_RANGE, start + 256) + 1, step):
                            if max_attempts is not None and attempts >= max_attempts:
                                return None
                            if access_offset in seen_offsets:
                                continue
                            seen_offsets.add(access_offset)
                            if not concrete_value_ok(access_offset):
                                continue
                            pointer_offset = access_offset + imm
                            if pointer_offset <= 0 or pointer_offset > STACK_RANGE:
                                continue
                            if pointer_offset < base_start:
                                continue
                            if pointer_offset % INIT_ACCESS_ALIGN != 0:
                                continue
                            attempts += 1
                            constraints = [
                                (init_sp - rd_symbol) == pointer_offset,
                                expr == access_offset,
                            ]
                            if not try_add_constraint_set_fast(
                                constraints,
                                timeout_ms=100 if complex_memory_block else HEURISTIC_SOLVER_TIMEOUT_MS,
                            ):
                                continue
                            return access_offset
                return None

            result = try_pointer_load_base_offset_candidate()
            if result is not None:
                return result

            def try_stack_carrier_offset_candidate():
                addr_symbol = None
                expr_signature = expr_key(expr)
                for _, candidate_addr_symbol, _, _ in mem_accesses:
                    projected_expr = claripy.simplify(init_sp - candidate_addr_symbol)
                    if expr_key(projected_expr) == expr_signature:
                        addr_symbol = claripy.simplify(candidate_addr_symbol)
                        break
                if (
                    addr_symbol is None
                    and
                    getattr(expr, 'op', None) in {'__sub__', 'Sub'}
                    and len(getattr(expr, 'args', ())) == 2
                    and expr_key(expr.args[0]) == expr_key(init_sp)
                ):
                    addr_symbol = claripy.simplify(expr.args[1])
                if addr_symbol is None:
                    addr_symbol = claripy.simplify(init_sp - expr)
                if expr_vars(addr_symbol) & expr_vars(init_sp):
                    return None
                addr_vars = expr_vars(addr_symbol)
                if not addr_vars:
                    return None

                carrier_candidates = []
                seen_carriers = set()

                def add_carrier(symbol, producer_idx, preferred_base):
                    symbol_vars = expr_vars(symbol)
                    if not symbol_vars or not (addr_vars & symbol_vars):
                        return
                    key = expr_key(symbol)
                    if key in seen_carriers:
                        return
                    seen_carriers.add(key)
                    materialized_reg_vars = set()
                    for materialized_reg in reg_values:
                        materialized_symbol = reg_to_symbol.get(materialized_reg)
                        if materialized_symbol is not None:
                            materialized_reg_vars.update(expr_vars(materialized_symbol))
                    deferred_reg_vars = set()
                    for deferred_reg in deferred_regs:
                        deferred_symbol = reg_to_symbol.get(deferred_reg)
                        if deferred_symbol is not None:
                            deferred_reg_vars.update(expr_vars(deferred_symbol))

                    residual = claripy.simplify(addr_symbol - symbol)
                    residual_vars = expr_vars(residual)
                    if not (residual_vars & symbol_vars):
                        residual_affine = affine_base_const(residual)
                        if residual_affine is not None:
                            _, residual_imm = residual_affine
                            if residual_imm:
                                residual_offset_constraints = constraints_to_constant(
                                    residual,
                                    residual_imm,
                                    forbidden_vars=symbol_vars,
                                )
                                if residual_offset_constraints is not None:
                                    carrier_candidates.append((
                                        preferred_base + 2,
                                        count_mul_ancestors(addr_symbol, symbol),
                                        len(addr_vars - symbol_vars),
                                        producer_idx,
                                        symbol,
                                        symbol_vars,
                                        residual_offset_constraints,
                                        residual_imm,
                                    ))

                        def non_reg_mul_zero_constraints(node):
                            for ast_node in iter_ast_nodes(node):
                                if getattr(ast_node, 'op', None) not in {'__mul__', 'Mul'}:
                                    continue
                                for arg in getattr(ast_node, 'args', ()):
                                    if not hasattr(arg, 'op'):
                                        continue
                                    arg_vars = expr_vars(arg)
                                    if not arg_vars:
                                        continue
                                    if arg_vars & (symbol_vars | materialized_reg_vars):
                                        continue
                                    if arg_vars & deferred_reg_vars:
                                        preferred_forbidden = symbol_vars | materialized_reg_vars
                                    else:
                                        preferred_forbidden = symbol_vars | materialized_reg_vars | deferred_reg_vars
                                    sub_constraints = constraints_to_constant(
                                        arg,
                                        0,
                                        forbidden_vars=preferred_forbidden,
                                    )
                                    if sub_constraints is not None:
                                        return sub_constraints
                                    return [arg == expr_bvv(0, arg)]
                            return None

                        load_mul_constraints = non_reg_mul_zero_constraints(residual)
                        if load_mul_constraints is not None:
                            carrier_candidates.append((
                                preferred_base + 3,
                                count_mul_ancestors(addr_symbol, symbol),
                                len(addr_vars - symbol_vars),
                                producer_idx,
                                symbol,
                                symbol_vars,
                                load_mul_constraints,
                                0,
                            ))

                        load_preferred_constraints = constraints_to_constant(
                            residual,
                            0,
                            forbidden_vars=symbol_vars | materialized_reg_vars,
                        )
                        if load_preferred_constraints is not None:
                            carrier_candidates.append((
                                preferred_base + 2,
                                count_mul_ancestors(addr_symbol, symbol),
                                len(addr_vars - symbol_vars),
                                producer_idx,
                                symbol,
                                symbol_vars,
                                load_preferred_constraints,
                                0,
                            ))

                        frozen_constraints = constraints_to_constant(
                            residual,
                            0,
                            forbidden_vars=symbol_vars | materialized_reg_vars,
                        )
                        if frozen_constraints is not None:
                            carrier_candidates.append((
                                preferred_base + 1,
                                count_mul_ancestors(addr_symbol, symbol),
                                len(addr_vars - symbol_vars),
                                producer_idx,
                                symbol,
                                symbol_vars,
                                frozen_constraints,
                                0,
                            ))

                    constraints = constraints_to_carrier(addr_symbol, symbol)
                    if constraints is None:
                        if residual_vars & symbol_vars:
                            return
                        constraints = constraints_to_constant(
                            residual,
                            0,
                            forbidden_vars=symbol_vars,
                        )
                        if constraints is None:
                            return
                    carrier_candidates.append((
                        preferred_base,
                        count_mul_ancestors(addr_symbol, symbol),
                        len(addr_vars - symbol_vars),
                        producer_idx,
                        symbol,
                        symbol_vars,
                        constraints,
                        0,
                    ))

                for load_inst, rd_symbol, _, load_idx in load_accesses:
                    if load_inst.width != 8:
                        continue
                    add_carrier(rd_symbol, load_idx, 1 if load_inst.pc in mem_base_pcs else 0)
                for reg, symbol in reg_to_symbol.items():
                    add_carrier(symbol, -1, 1 if reg in undef_base_regs else 0)

                if not carrier_candidates:
                    return None
                carrier_candidates.sort(
                    key=lambda item: (item[0], item[1], -item[2], item[3]),
                    reverse=True,
                )

                low = _align_up(1, align) if align else 1
                starts = []
                starts.append(low)
                if preferred is not None:
                    starts.append(preferred)
                starts.extend(used + max(width, used_width) for used, used_width in avoid)
                step_local = align if align else 1
                max_carriers = 4 if complex_memory_block else 16
                max_offsets_per_carrier = 4 if complex_memory_block else 32

                for _, _, _, producer_idx, symbol, symbol_vars, constraints, residual_offset in carrier_candidates[:max_carriers]:
                    min_offset = (
                        min_pointer_offset_for_vars(symbol_vars, producer_idx)
                        if producer_idx >= 0
                        else INIT_PTR_MIN_OFFSET
                    )
                    seen_offsets = set()
                    attempts = 0
                    for start in starts:
                        start = _align_up(max(low, start, min_offset), step_local)
                        for access_offset in range(start, min(STACK_RANGE, start + 512) + 1, step_local):
                            if attempts >= max_offsets_per_carrier:
                                break
                            if access_offset in seen_offsets:
                                continue
                            seen_offsets.add(access_offset)
                            if access_offset <= 0 or access_offset > STACK_RANGE:
                                continue
                            if align and access_offset % align != 0:
                                continue
                            if any(
                                concrete_ranges_overlap(access_offset, width, used_offset, used_width)
                                for used_offset, used_width in avoid
                            ):
                                continue
                            carrier_offset = access_offset + residual_offset
                            if carrier_offset < min_offset:
                                continue
                            if carrier_offset <= 0 or carrier_offset > STACK_RANGE:
                                continue
                            if carrier_offset % INIT_ACCESS_ALIGN:
                                continue
                            attempts += 1
                            constraint_set = list(constraints) + [
                                (init_sp - symbol) == carrier_offset,
                                expr == access_offset,
                            ]
                            if try_add_constraint_set_fast(
                                constraint_set,
                                timeout_ms=5000,
                            ):
                                return access_offset
                    if attempts == 0 and preferred is not None:
                        carrier_offset = preferred + residual_offset
                        if carrier_offset <= 0 or carrier_offset > STACK_RANGE:
                            continue
                        constraint_set = list(constraints) + [
                            (init_sp - symbol) == carrier_offset,
                            expr == preferred,
                        ]
                        if try_add_constraint_set_fast(
                            constraint_set,
                            timeout_ms=5000,
                        ):
                            return preferred
                return None

            result = try_stack_carrier_offset_candidate()
            if result is not None:
                return result

            def positive_candidates(limit):
                if not positive:
                    return
                low = _align_up(1, align) if align else 1
                high = STACK_RANGE
                starts = []
                if preferred is not None:
                    starts.append(preferred)
                starts.append(low)
                for used, used_width in sorted(avoid):
                    starts.append(used + max(width, used_width))
                    starts.append(used + width)
                yielded = 0
                for start in starts:
                    start = max(start, low)
                    if align:
                        start = _align_up(start, align)
                    if start > high:
                        continue
                    for val in range(start, high + 1, step):
                        yield val
                        yielded += 1
                        if limit is not None and yielded >= limit:
                            return

            if positive:
                fast_limit = (4 if complex_memory_block else 24) if fast_positive else 256
                for val in positive_candidates(limit=fast_limit):
                    result = try_candidate(val)
                    if result is not None:
                        return result
                if fast_positive and not required:
                    return None
                if not required:
                    return None

            minimum = solver_min(expr)
            for val in [minimum]:
                result = try_candidate(val)
                if result is not None:
                    return result

            extra_constraints = value_selection_constraints(
                expr,
                positive=positive,
                align=align,
                avoid=avoid,
                width=width,
            )
            for val in [solver_min_with(expr, extra_constraints)]:
                result = try_candidate(val)
                if result is not None:
                    return result
            for val in solver_eval_with(expr, extra_constraints, n=512):
                result = try_candidate(val)
                if result is not None:
                    return result

            if preferred is not None and minimum is not None and preferred <= STACK_RANGE:
                start = preferred
            else:
                start = minimum
            if start is not None:
                if positive:
                    start = max(start, 1)
                if align:
                    start = _align_up(start, align)
                for i in range(64):
                    result = try_candidate(start + i * step)
                    if result is not None:
                        return result

            if not required:
                return None

            if positive:
                exhaustive_limit = 32 if fast_positive else None
                for val in positive_candidates(limit=exhaustive_limit):
                    result = try_candidate(val)
                    if result is not None:
                        return result

            final_constraints = value_selection_constraints(
                expr,
                positive=positive,
                align=align,
                avoid=avoid,
                width=width,
            )
            val = solver_min_with(expr, final_constraints)
            if val is not None:
                result = try_candidate(val)
                if result is not None:
                    return result

            val = solver_min_with(
                expr,
                value_selection_constraints(expr, positive=positive, align=align, width=width),
            )
            if val is not None:
                result = try_candidate(val)
                if result is not None:
                    return result

            if positive and avoid:
                low = _align_up(1, align) if align else 1
                attempts = 0
                val = low
                while val <= STACK_RANGE and attempts < 128:
                    if (not align or val % align == 0) and satisfiable_with(expr, val):
                        candidate_solver.add(expr == val)
                        return val
                    attempts += 1
                    val += step

            fallback_constraints = value_selection_constraints(
                expr,
                positive=positive,
                align=align,
                avoid=avoid,
                width=width,
            )
            for val in solver_eval_limited(expr, n=16, timeout_ms=5000, extra_constraints=fallback_constraints):
                val &= ((1 << 64) - 1)
                result = try_candidate(val)
                if result is not None:
                    return result

            val = minimum
            if val is None:
                raise AssertionError(f"cannot choose concrete value for {expr}")
            if not concrete_value_ok(val):
                raise AssertionError(f"cannot choose non-overlapping concrete value for {expr}")
            result = try_candidate(val)
            if result is not None:
                return result
            raise AssertionError(f"cannot choose satisfiable concrete value for {expr}")

        def try_add_constraint(constraint, timeout_ms=HEURISTIC_SOLVER_TIMEOUT_MS):
            constraint_key = str(claripy.simplify(constraint))
            if constraint_key in added_constraint_cache:
                return True
            test_solver = candidate_solver.branch()
            test_solver.timeout = timeout_ms
            try:
                test_solver.add(constraint)
                if test_solver.satisfiable():
                    candidate_solver.add(constraint)
                    added_constraint_cache.add(constraint_key)
                    return True
            except Exception:
                return False
            return False

        def try_add_constraint_set_fast(constraints, timeout_ms=100):
            test_solver = candidate_solver.branch()
            test_solver.timeout = timeout_ms
            try:
                for constraint in constraints:
                    test_solver.add(constraint)
                if not test_solver.satisfiable():
                    return False
            except Exception:
                return False
            for constraint in constraints:
                candidate_solver.add(constraint)
            return True

        def expr_bvv(value, expr):
            try:
                bits = expr.size()
            except Exception:
                bits = 64
            return claripy.BVV(value & ((1 << bits) - 1), bits)

        def try_constrain_expr_value(expr, value):
            if not expr_vars(expr):
                return False
            return try_add_constraint(expr == expr_bvv(value, expr))

        def iter_ast_nodes(expr):
            seen = set()
            stack = [expr]
            while stack:
                node = stack.pop()
                key = id(node)
                if key in seen:
                    continue
                seen.add(key)
                yield node
                for arg in getattr(node, 'args', ()):
                    if hasattr(arg, 'op'):
                        stack.append(arg)

        def add_neutral_arithmetic_constraints(expr, forbidden_vars=None):
            """Prefer simple scalar operands in complex address residuals.

            This is intentionally applied to address residuals, not to the
            whole address expression.  A pointer/base term should stay a
            pointer; only the nonlinear or additive scalar part is normalized.
            """
            forbidden_vars = set() if forbidden_vars is None else set(forbidden_vars)
            mul_ops = {'__mul__', 'Mul'}
            div_ops = {'__floordiv__', '__truediv__', '__div__', 'SDiv', 'UDiv'}
            add_ops = {'__add__', 'Add'}
            sub_ops = {'__sub__', 'Sub'}

            for node in iter_ast_nodes(expr):
                node_vars = expr_vars(node)
                if not node_vars or (node_vars & forbidden_vars):
                    continue
                op = getattr(node, 'op', '')
                symbolic_args = [
                    arg for arg in getattr(node, 'args', ())
                    if hasattr(arg, 'op')
                    and expr_vars(arg)
                    and not (expr_vars(arg) & forbidden_vars)
                ]
                symbolic_args.sort(key=lambda item: len(str(item)))
                if op in mul_ops or op in div_ops:
                    for arg in symbolic_args:
                        if try_constrain_expr_value(arg, 1):
                            break
                elif op in add_ops or op in sub_ops:
                    for arg in symbolic_args:
                        if try_constrain_expr_value(arg, 0):
                            break

        def target_value_for_expr(value, expr):
            try:
                bits = expr.size()
            except Exception:
                bits = 64
            return value & ((1 << bits) - 1)

        def ast_node_count(expr):
            seen = set()
            count = 0
            stack = [expr]
            while stack:
                node = stack.pop()
                key = id(node)
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                for arg in getattr(node, 'args', ()):
                    if hasattr(arg, 'op'):
                        stack.append(arg)
            return count

        def symbolic_zero_priority(expr):
            vars_ = expr_vars(expr)
            has_init_reg = any(str(var).startswith(REG_PREFIX) for var in vars_)
            return (0 if has_init_reg else 1, len(vars_), ast_node_count(expr), len(str(expr)))

        def constraints_to_constant(expr, value, forbidden_vars=None, depth=0):
            forbidden_vars = set() if forbidden_vars is None else set(forbidden_vars)
            expr = claripy.simplify(expr)
            value = target_value_for_expr(value, expr)
            vars_ = expr_vars(expr)
            if not vars_:
                concrete_value = concrete_expr_value(expr)
                if concrete_value is None:
                    return []
                return [] if target_value_for_expr(concrete_value, expr) == value else None
            if vars_ & forbidden_vars:
                return None
            if depth > 8:
                return None

            op = getattr(expr, 'op', '')
            args = [arg for arg in getattr(expr, 'args', ()) if hasattr(arg, 'op')]
            symbolic_args = [arg for arg in args if expr_vars(arg)]
            constraints = []

            if op in {'__add__', 'Add', '__sub__', 'Sub'}:
                signed_terms = []
                concrete_total = 0
                expr_mask = (1 << expr.size()) - 1
                for i, arg in enumerate(args):
                    sign = 1 if op in {'__add__', 'Add'} or i == 0 else -1
                    if expr_vars(arg):
                        signed_terms.append((sign, arg))
                        continue
                    concrete_value = concrete_expr_value(arg)
                    if concrete_value is None:
                        return None
                    concrete_total = (concrete_total + sign * concrete_value) & expr_mask

                if not signed_terms:
                    return [] if concrete_total == value else None

                target = (value - concrete_total) & expr_mask
                signed_terms.sort(key=lambda item: symbolic_zero_priority(item[1]))
                for sign, arg in signed_terms[:-1]:
                    sub_constraints = constraints_to_constant(arg, 0, forbidden_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)

                sign, arg = signed_terms[-1]
                arg_target = target if sign > 0 else (-target) & expr_mask
                sub_constraints = constraints_to_constant(arg, arg_target, forbidden_vars, depth + 1)
                if sub_constraints is None:
                    return None
                constraints.extend(sub_constraints)
                return constraints

            if op in {'__xor__', 'Xor'} and len(args) == 2:
                lhs, rhs = args
                lhs_vars = expr_vars(lhs)
                rhs_vars = expr_vars(rhs)
                if lhs_vars and not rhs_vars:
                    rhs_value = concrete_expr_value(rhs)
                    if rhs_value is None:
                        return None
                    return constraints_to_constant(lhs, value ^ rhs_value, forbidden_vars, depth + 1)
                if rhs_vars and not lhs_vars:
                    lhs_value = concrete_expr_value(lhs)
                    if lhs_value is None:
                        return None
                    return constraints_to_constant(rhs, value ^ lhs_value, forbidden_vars, depth + 1)

            if op == 'Extract' and args:
                source = args[-1]
                source_vars = expr_vars(source)
                if value == 0 and source_vars and all(str(var).startswith(REG_PREFIX) for var in source_vars):
                    return constraints_to_constant(source, 0, forbidden_vars, depth + 1)
                return [expr == expr_bvv(value, expr)]

            if op == 'Concat':
                remaining = expr.size()
                for arg in args:
                    arg_bits = arg.size()
                    remaining -= arg_bits
                    arg_value = (value >> remaining) & ((1 << arg_bits) - 1)
                    sub_constraints = constraints_to_constant(arg, arg_value, forbidden_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                return constraints

            if op in {'ZeroExt', 'SignExt'} and args:
                return constraints_to_constant(args[-1], value, forbidden_vars, depth + 1)

            if op in {'__rshift__', 'SShR'} and len(args) >= 2:
                return [expr == expr_bvv(value, expr)]

            if value == 0:
                if op in {'__mul__', 'Mul'}:
                    for arg in sorted(symbolic_args, key=symbolic_zero_priority):
                        sub_constraints = constraints_to_constant(arg, 0, forbidden_vars, depth + 1)
                        if sub_constraints is not None:
                            return sub_constraints
                    return None
                if op in {'__lshift__', '__rshift__', 'LShR', 'SShR'}:
                    if not args:
                        return None
                    shifted = args[0]
                    if not expr_vars(shifted):
                        return []
                    return constraints_to_constant(shifted, 0, forbidden_vars, depth + 1)

            if op in {'__lshift__', 'LShR', 'SShR'} and len(args) >= 2:
                shift_value = concrete_expr_value(args[1])
                if shift_value is not None:
                    if op == '__lshift__':
                        if value & ((1 << shift_value) - 1):
                            return None
                        return constraints_to_constant(args[0], value >> shift_value, forbidden_vars, depth + 1)
                    return constraints_to_constant(args[0], value << shift_value, forbidden_vars, depth + 1)

            if value == 1:
                if op in {'__mul__', 'Mul'}:
                    for arg in symbolic_args:
                        sub_constraints = constraints_to_constant(arg, 1, forbidden_vars, depth + 1)
                        if sub_constraints is None:
                            return None
                        constraints.extend(sub_constraints)
                    return constraints
                if op in {'__floordiv__', '__truediv__', '__div__', 'SDiv', 'UDiv'}:
                    if not symbolic_args:
                        return []
                    numerator = args[0] if args else None
                    if numerator is None or not expr_vars(numerator):
                        return None
                    sub_constraints = constraints_to_constant(numerator, 1, forbidden_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                    for arg in args[1:]:
                        if not expr_vars(arg):
                            continue
                        sub_constraints = constraints_to_constant(arg, 1, forbidden_vars, depth + 1)
                        if sub_constraints is None:
                            return None
                        constraints.extend(sub_constraints)
                    return constraints

            if len(vars_) == 1:
                return [expr == expr_bvv(value, expr)]

            return None

        def constraints_to_carrier(expr, carrier_expr, depth=0):
            expr = claripy.simplify(expr)
            carrier_expr = claripy.simplify(carrier_expr)
            if expr_key(expr) == expr_key(carrier_expr):
                return []
            carrier_vars = expr_vars(carrier_expr)
            if not carrier_vars or not (expr_vars(expr) & carrier_vars):
                return None
            if depth > 8:
                return None

            op = getattr(expr, 'op', '')
            args = [arg for arg in getattr(expr, 'args', ()) if hasattr(arg, 'op')]
            carrier_args = [arg for arg in args if expr_vars(arg) & carrier_vars]
            if len(carrier_args) != 1:
                return None
            carrier_arg = carrier_args[0]
            constraints = []

            if op in {'__add__', 'Add'}:
                sub_constraints = constraints_to_carrier(carrier_arg, carrier_expr, depth + 1)
                if sub_constraints is None:
                    return None
                constraints.extend(sub_constraints)
                residual_terms = []
                concrete_total = 0
                expr_mask = (1 << expr.size()) - 1
                for arg in args:
                    if arg is carrier_arg:
                        continue
                    if not expr_vars(arg):
                        concrete_value = concrete_expr_value(arg)
                        if concrete_value is None:
                            return None
                        concrete_total = (concrete_total + concrete_value) & expr_mask
                    else:
                        residual_terms.append(arg)
                if residual_terms:
                    target = (-concrete_total) & expr_mask
                    residual_terms.sort(key=symbolic_zero_priority)
                    for arg in residual_terms[:-1]:
                        sub_constraints = constraints_to_constant(arg, 0, carrier_vars, depth + 1)
                        if sub_constraints is None:
                            return None
                        constraints.extend(sub_constraints)
                    sub_constraints = constraints_to_constant(residual_terms[-1], target, carrier_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                elif concrete_total != 0:
                    return None
                return constraints

            if op in {'__sub__', 'Sub'}:
                if args and carrier_arg is not args[0]:
                    return None
                sub_constraints = constraints_to_carrier(carrier_arg, carrier_expr, depth + 1)
                if sub_constraints is None:
                    return None
                constraints.extend(sub_constraints)
                for arg in args[1:]:
                    if not expr_vars(arg):
                        continue
                    sub_constraints = constraints_to_constant(arg, 0, carrier_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                return constraints

            if op in {'__mul__', 'Mul'}:
                sub_constraints = constraints_to_carrier(carrier_arg, carrier_expr, depth + 1)
                if sub_constraints is None:
                    return None
                constraints.extend(sub_constraints)
                for arg in args:
                    if arg is carrier_arg or not expr_vars(arg):
                        continue
                    sub_constraints = constraints_to_constant(arg, 1, carrier_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                return constraints

            if op in {'__floordiv__', '__truediv__', '__div__', 'SDiv', 'UDiv'}:
                if args and carrier_arg is not args[0]:
                    return None
                sub_constraints = constraints_to_carrier(carrier_arg, carrier_expr, depth + 1)
                if sub_constraints is None:
                    return None
                constraints.extend(sub_constraints)
                for arg in args[1:]:
                    if not expr_vars(arg):
                        continue
                    sub_constraints = constraints_to_constant(arg, 1, carrier_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                return constraints

            if op in {'__lshift__', '__rshift__', 'LShR', 'SShR'}:
                if args and carrier_arg is not args[0]:
                    return None
                return constraints_to_carrier(carrier_arg, carrier_expr, depth + 1)

            return None

        def constraints_to_internal_carrier(expr, carrier_expr, depth=0):
            expr = claripy.simplify(expr)
            carrier_expr = claripy.simplify(carrier_expr)
            if expr_key(expr) == expr_key(carrier_expr):
                return []
            carrier_vars = expr_vars(carrier_expr)
            if not carrier_vars or not (expr_vars(expr) & carrier_vars):
                return None
            if depth > 8:
                return None

            op = getattr(expr, 'op', '')
            args = [arg for arg in getattr(expr, 'args', ()) if hasattr(arg, 'op')]
            carrier_args = [arg for arg in args if expr_vars(arg) & carrier_vars]
            constraints = []

            if op in {'__add__', 'Add'}:
                if len(carrier_args) != 1:
                    return None
                carrier_arg = carrier_args[0]
                sub_constraints = constraints_to_internal_carrier(carrier_arg, carrier_expr, depth + 1)
                if sub_constraints is None:
                    return None
                constraints.extend(sub_constraints)
                for arg in args:
                    if arg is carrier_arg or not expr_vars(arg):
                        continue
                    sub_constraints = constraints_to_constant(arg, 0, carrier_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                return constraints

            if op in {'__sub__', 'Sub'}:
                if not args or len(carrier_args) != 1 or carrier_args[0] is not args[0]:
                    return None
                sub_constraints = constraints_to_internal_carrier(args[0], carrier_expr, depth + 1)
                if sub_constraints is None:
                    return None
                constraints.extend(sub_constraints)
                for arg in args[1:]:
                    if not expr_vars(arg):
                        continue
                    sub_constraints = constraints_to_constant(arg, 0, carrier_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                return constraints

            if op in {'__mul__', 'Mul'}:
                if len(carrier_args) != 1:
                    return None
                carrier_arg = carrier_args[0]
                sub_constraints = constraints_to_internal_carrier(carrier_arg, carrier_expr, depth + 1)
                if sub_constraints is None:
                    return None
                constraints.extend(sub_constraints)
                for arg in args:
                    if arg is carrier_arg or not expr_vars(arg):
                        continue
                    sub_constraints = constraints_to_constant(arg, 1, carrier_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                return constraints

            if op in {'__floordiv__', '__truediv__', '__div__', 'SDiv', 'UDiv'}:
                if not args or len(carrier_args) != 1 or carrier_args[0] is not args[0]:
                    return None
                sub_constraints = constraints_to_internal_carrier(args[0], carrier_expr, depth + 1)
                if sub_constraints is None:
                    return None
                constraints.extend(sub_constraints)
                for arg in args[1:]:
                    if not expr_vars(arg):
                        continue
                    sub_constraints = constraints_to_constant(arg, 1, carrier_vars, depth + 1)
                    if sub_constraints is None:
                        return None
                    constraints.extend(sub_constraints)
                return constraints

            if op in {'__lshift__', '__rshift__', 'LShR', 'SShR'}:
                if not args or len(carrier_args) != 1 or carrier_args[0] is not args[0]:
                    return None
                return constraints_to_internal_carrier(args[0], carrier_expr, depth + 1)

            return None

        def count_mul_ancestors(expr, carrier_expr):
            carrier_vars = expr_vars(carrier_expr)
            if not carrier_vars:
                return 0
            count = 0
            stack = [expr]
            while stack:
                node = stack.pop()
                if not (expr_vars(node) & carrier_vars):
                    continue
                if getattr(node, 'op', '') in {'__mul__', 'Mul'}:
                    count += 1
                for arg in getattr(node, 'args', ()):
                    if hasattr(arg, 'op'):
                        stack.append(arg)
            return count

        def try_add_constraint_set(constraints, verify_constraints=None):
            verify_constraints = [] if verify_constraints is None else verify_constraints
            unique_constraints = []
            seen = set()
            for constraint in constraints:
                key = str(claripy.simplify(constraint))
                if key in seen or key in added_constraint_cache:
                    continue
                seen.add(key)
                unique_constraints.append(constraint)
            test_solver = candidate_solver.branch()
            for constraint in unique_constraints:
                test_solver.add(constraint)
            test_solver.timeout = HEURISTIC_SOLVER_TIMEOUT_MS
            try:
                for constraint in verify_constraints:
                    test_solver.add(constraint)
                if not test_solver.satisfiable():
                    return False
            except Exception:
                return False
            for constraint in unique_constraints:
                candidate_solver.add(constraint)
                added_constraint_cache.add(str(claripy.simplify(constraint)))
            return True

        def append_value_init(
            insts,
            reg_name,
            value,
            force_stack_offset=None,
            force_sp_delta=None,
            force_inverse_sp_delta=None,
            allow_scaled_stack=False,
        ):
            if force_sp_delta is not None:
                insts.append(UFmtInst('li', reg_name, force_sp_delta & ((1 << 64) - 1)))
                insts.append(RFmtInst('add', reg_name, 'sp', reg_name))
                return
            if force_inverse_sp_delta is not None:
                insts.append(UFmtInst('li', reg_name, force_inverse_sp_delta & ((1 << 64) - 1)))
                insts.append(RFmtInst('sub', reg_name, reg_name, 'sp'))
                return
            stack_offset = force_stack_offset
            if stack_offset is None:
                stack_offset = signed_stack_offset_for_value(value)
            if stack_offset is not None:
                abs_offset = abs(stack_offset)
                insts.append(UFmtInst('li', reg_name, abs_offset))
                if stack_offset >= 0:
                    insts.append(RFmtInst('sub', reg_name, 'sp', reg_name))
                else:
                    insts.append(RFmtInst('add', reg_name, 'sp', reg_name))
            elif allow_scaled_stack:
                scaled = scaled_stack_transform_for_value(value)
                if scaled is not None:
                    offset, shift = scaled
                    insts.append(UFmtInst('li', reg_name, offset))
                    insts.append(RFmtInst('sub', reg_name, 'sp', reg_name))
                    insts.append(IFmtInst('srli', reg_name, reg_name, shift))
                else:
                    insts.append(UFmtInst('li', reg_name, value & ((1 << 64) - 1)))
            else:
                insts.append(UFmtInst('li', reg_name, value & ((1 << 64) - 1)))

        def mem_value_expr(inst, rd_symbol):
            return rd_symbol

        def load_raw_value(inst, value_expr):
            bits = inst.width * 8
            return value_expr[bits - 1:0]

        def constrain_word_field(word_symbol, byte_offset, inst, value_expr, protected=False):
            bits = inst.width * 8
            lo = byte_offset * 8
            hi = lo + bits - 1
            constraint = word_symbol[hi:lo] == load_raw_value(inst, value_expr)
            if protected:
                timeout_ms = 100 if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD else HEURISTIC_SOLVER_TIMEOUT_MS
                return try_add_constraint(constraint, timeout_ms=timeout_ms)
            if not try_add_constraint(constraint, timeout_ms=local_solver_timeout_ms):
                return False
            return True

        def cheap_same_address(addr_a, addr_b):
            if addr_b is None:
                return False
            cache_key = tuple(sorted((id(addr_a), id(addr_b))))
            if cache_key in cheap_same_address_cache:
                return cheap_same_address_cache[cache_key]

            def remember(value):
                cheap_same_address_cache[cache_key] = value
                return value

            key_a = expr_key(addr_a)
            key_b = expr_key(addr_b)
            if key_a == key_b:
                return remember(True)
            affine_result = affine_same_or_distinct(addr_a, addr_b)
            if affine_result is not None:
                return remember(affine_result)
            diff_value = concrete_expr_value(claripy.simplify(addr_a - addr_b))
            if diff_value is not None:
                return remember(diff_value == 0)
            if not exprs_may_be_related(addr_a, addr_b):
                return remember(False)
            return remember(None)

        def same_address(addr_a, addr_b, allow_solver=True):
            cheap_result = cheap_same_address(addr_a, addr_b)
            if cheap_result is not None:
                return cheap_result
            if not allow_solver:
                return False
            key_a = expr_key(addr_a)
            key_b = expr_key(addr_b)
            cache_key = tuple(sorted((key_a, key_b)))
            if cache_key in same_address_cache:
                return same_address_cache[cache_key]
            test_solver = candidate_solver.branch()
            test_solver.timeout = HEURISTIC_SOLVER_TIMEOUT_MS
            try:
                test_solver.add(addr_a != addr_b)
                result = not test_solver.satisfiable()
            except Exception:
                result = False
            if result:
                same_address_cache[cache_key] = result
            return result

        def forced_same_address_cached(addr_a, addr_b):
            if addr_b is None:
                return False
            key_a = expr_key(addr_a)
            key_b = expr_key(addr_b)
            if key_a == key_b:
                return True
            affine_result = affine_same_or_distinct(addr_a, addr_b)
            if affine_result is not None:
                return affine_result
            cache_key = tuple(sorted((key_a, key_b)))
            if cache_key in forced_same_address_cache:
                return forced_same_address_cache[cache_key]
            if not exprs_may_be_related(addr_a, addr_b):
                return False
            test_solver = candidate_solver.branch()
            test_solver.timeout = HEURISTIC_SOLVER_TIMEOUT_MS
            try:
                test_solver.add(addr_a != addr_b)
                result = not test_solver.satisfiable()
            except Exception:
                result = False
            if result:
                forced_same_address_cache[cache_key] = result
            return result

        def stored_value_for_load(store_data_symbol, store_width, load_inst):
            return stored_value_for_load_expr(store_data_symbol, store_width, load_inst)

        def prior_same_addr_store(addr_symbol, inst_idx, allow_solver=True):
            cache_key = (expr_key(addr_symbol), inst_idx, allow_solver)
            if cache_key in prior_store_cache:
                return prior_store_cache[cache_key]
            for store_inst, store_addr_symbol, store_idx, store_width, store_data_symbol in reversed(store_accesses):
                if store_idx < inst_idx and same_address(store_addr_symbol, addr_symbol, allow_solver=allow_solver):
                    result = store_inst, store_addr_symbol, store_idx, store_width, store_data_symbol
                    prior_store_cache[cache_key] = result
                    return result
            return None

        def has_intervening_same_addr_store(addr_symbol, prev_idx, next_idx, allow_solver=True):
            for _, store_addr_symbol, store_idx, _, _ in store_accesses:
                if prev_idx < store_idx < next_idx and same_address(store_addr_symbol, addr_symbol, allow_solver=allow_solver):
                    return True
            return False

        def has_prior_same_addr_store(addr_symbol, inst_idx, allow_solver=True):
            return prior_same_addr_store(addr_symbol, inst_idx, allow_solver=allow_solver) is not None

        def has_forced_prior_same_addr_store_cached(addr_symbol, inst_idx):
            cache_key = (expr_key(addr_symbol), inst_idx)
            if cache_key in forced_prior_store_cache:
                return forced_prior_store_cache[cache_key]
            for _, store_addr_symbol, store_idx, _, _ in reversed(store_accesses):
                if store_idx < inst_idx and forced_same_address_cached(store_addr_symbol, addr_symbol):
                    forced_prior_store_cache[cache_key] = True
                    return True
            return False

        def add_memory_dataflow_constraints():
            complex_memory_block = len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD
            allow_load_load_solver = (
                len(store_accesses) >= GLOBAL_NO_OVERLAP_STORE_THRESHOLD
                and len(mem_entries) <= 64
            )
            if not complex_memory_block:
                for i, (first_inst, first_rd_symbol, first_addr_symbol, first_idx) in enumerate(mem_entries):
                    first_expr = mem_value_expr(first_inst, first_rd_symbol)
                    for inst, rd_symbol, addr_symbol, inst_idx in mem_entries[i + 1:]:
                        if has_intervening_same_addr_store(first_addr_symbol, first_idx, inst_idx, allow_solver=False):
                            continue
                        if same_address(first_addr_symbol, addr_symbol, allow_solver=allow_load_load_solver):
                            value_expr = mem_value_expr(inst, rd_symbol)
                            candidate_solver.add(value_expr == first_expr)
                            register_expr_equality(value_expr, first_expr)

            for inst, rd_symbol, addr_symbol, inst_idx in mem_entries:
                prior_store = prior_same_addr_store(addr_symbol, inst_idx, allow_solver=False)
                if prior_store is None:
                    continue
                _, _, _, store_width, store_data_symbol = prior_store
                stored_expr = stored_value_for_load(store_data_symbol, store_width, inst)
                if stored_expr is not None:
                    value_expr = mem_value_expr(inst, rd_symbol)
                    candidate_solver.add(value_expr == stored_expr)
                    register_expr_equality(value_expr, stored_expr)

        def add_arithmetic_address_hint_constraints():
            complex_memory_block = len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD
            hint_timeout_ms = 50 if complex_memory_block else HEURISTIC_SOLVER_TIMEOUT_MS
            pointer_hint_budget = LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT * 2 if complex_memory_block else None

            def unique_values(values):
                seen = set()
                result = []
                for value in values:
                    value &= ((1 << 64) - 1)
                    if value in seen:
                        continue
                    seen.add(value)
                    result.append(value)
                return result

            def try_add_constraint_group(constraints):
                constraints = list(constraints)
                if not constraints:
                    return True
                test_solver = candidate_solver.branch()
                test_solver.timeout = hint_timeout_ms
                try:
                    for constraint in constraints:
                        test_solver.add(constraint)
                    if not test_solver.satisfiable():
                        return False
                except Exception:
                    return False
                for constraint in constraints:
                    candidate_solver.add(constraint)
                    added_constraint_cache.add(str(claripy.simplify(constraint)))
                return True

            def has_nonlinear_address_use(reg):
                symbol = reg_to_symbol.get(reg)
                if symbol is None:
                    return False
                symbol_vars = expr_vars(symbol)
                if not symbol_vars:
                    return False
                nonlinear_ops = {'__mul__', 'Mul', '__floordiv__', '__truediv__', '__div__', 'SDiv', 'UDiv'}
                for _, addr_symbol, _, _ in mem_accesses:
                    if not (expr_vars(addr_symbol) & symbol_vars):
                        continue
                    for node in iter_ast_nodes(addr_symbol):
                        if getattr(node, 'op', '') in nonlinear_ops and (expr_vars(node) & symbol_vars):
                            return True
                return False

            fixed_reg_values = {}
            for reg, values in reg_value_hints.items():
                if reg not in reg_to_symbol:
                    continue
                if not has_nonlinear_address_use(reg):
                    continue
                values = unique_values(values)
                if len(values) != 1:
                    continue
                fixed_reg_values[reg] = values[0]
                symbol = reg_to_symbol[reg]
                try_add_constraint(symbol == expr_bvv(values[0], symbol), timeout_ms=hint_timeout_ms)

            for pc, values in load_value_hints.items():
                values = unique_values(values)
                if len(values) != 1:
                    continue
                for load_inst, rd_symbol, _, load_idx in load_entries_by_pc.get(pc, []):
                    constraint = rd_symbol == expr_bvv(values[0], rd_symbol)
                    try_add_constraint(constraint, timeout_ms=hint_timeout_ms)

            pointer_hints_tried = 0
            for pc, min_offset in load_pointer_hints.items():
                for load_inst, rd_symbol, _, load_idx in load_entries_by_pc.get(pc, []):
                    if pointer_hint_budget is not None and pointer_hints_tried >= pointer_hint_budget:
                        break
                    if load_inst.width != 8:
                        continue
                    rd_vars = expr_vars(rd_symbol)
                    if not rd_vars:
                        continue
                    pointer_hints_tried += 1
                    stack_constraints = stack_pointer_constraints_for_expr(
                        rd_symbol,
                        max(min_offset, min_pointer_offset_for_vars(rd_vars, load_idx)),
                    )
                    if try_add_constraint_group(stack_constraints):
                        hint_pointer_load_keys.add((load_idx, expr_key(rd_symbol)))

            reg_hints_tried = 0
            for reg, min_offset in reg_pointer_hints.items():
                if pointer_hint_budget is not None and reg_hints_tried >= pointer_hint_budget:
                    break
                if reg not in reg_to_symbol:
                    continue
                if reg in fixed_reg_values:
                    continue
                symbol = reg_to_symbol[reg]
                stack_constraints = stack_pointer_constraints_for_expr(symbol, min_offset)
                reg_hints_tried += 1
                if try_add_constraint_group(stack_constraints):
                    register_anchor_min_offsets[reg] = max(
                        register_anchor_min_offsets.get(reg, INIT_PTR_MIN_OFFSET),
                        _align_up(max(INIT_PTR_MIN_OFFSET, min_offset), INIT_ACCESS_ALIGN),
                    )

            for pc in load_nonzero_hints:
                for load_inst, rd_symbol, _, _ in load_entries_by_pc.get(pc, []):
                    try_add_constraint(rd_symbol != expr_bvv(0, rd_symbol), timeout_ms=hint_timeout_ms)

            for reg in reg_nonzero_hints:
                if reg not in reg_to_symbol:
                    continue
                symbol = reg_to_symbol[reg]
                try_add_constraint(symbol != expr_bvv(0, symbol), timeout_ms=hint_timeout_ms)

        def add_scalar_zero_address_load_constraints():
            for load_inst, rd_symbol, _, load_idx in mem_entries:
                if not is_scalar_zero_address_load(load_inst, rd_symbol, load_idx):
                    continue
                constraint = rd_symbol == expr_bvv(0, rd_symbol)
                try_add_constraint(constraint, timeout_ms=local_solver_timeout_ms)

        def add_store_pointer_source_constraints():
            for load_inst, rd_symbol, load_addr_symbol, load_idx in pointer_source_loads:
                if (load_idx, expr_key(rd_symbol)) in scalar_load_hint_keys:
                    continue
                prior_store = prior_same_addr_store(load_addr_symbol, load_idx)
                if prior_store is None:
                    continue
                _, _, _, store_width, store_data_symbol = prior_store
                stored_expr = stored_value_for_load(store_data_symbol, store_width, load_inst)
                if stored_expr is not None:
                    constraints = [rd_symbol == stored_expr]
                    stored_vars = expr_vars(stored_expr)
                    if stored_vars:
                        constraints.extend(
                            stack_pointer_constraints_for_expr(
                                stored_expr,
                                min_pointer_offset_for_vars(stored_vars, load_idx),
                            )
                        )
                    try_add_constraint_set(constraints)

        def add_loaded_pointer_scalar_offset_constraints():
            for reg, symbol in reg_to_symbol.items():
                symbol_vars = expr_vars(symbol)
                if not symbol_vars:
                    continue
                has_direct_livein_base_use = any(
                    getattr(inst, 'rs1', None) == reg
                    and (expr_vars(addr_symbol) & symbol_vars)
                    for inst, addr_symbol, _, _ in mem_accesses
                )
                if has_direct_livein_base_use:
                    continue
                for load_inst, rd_symbol, _, load_idx in load_accesses:
                    if load_inst.width != 8:
                        continue
                    rd_vars = expr_vars(rd_symbol)
                    if not rd_vars:
                        continue
                    for _, addr_symbol, access_idx, _ in mem_accesses:
                        if access_idx <= load_idx:
                            continue
                        addr_vars = expr_vars(addr_symbol)
                        if not (addr_vars & symbol_vars) or not (addr_vars & rd_vars):
                            continue
                        if (addr_vars & pointer_loaded_addr_vars) and not (rd_vars & pointer_loaded_addr_vars):
                            continue
                        residual_constraints = constraints_to_carrier(addr_symbol, rd_symbol)
                        if residual_constraints is None:
                            residual = claripy.simplify(addr_symbol - rd_symbol)
                            residual_vars = expr_vars(residual)
                            if (residual_vars & rd_vars) or not (residual_vars & symbol_vars):
                                continue
                            residual_constraints = constraints_to_constant(
                                residual,
                                0,
                                forbidden_vars=rd_vars,
                            )
                            if residual_constraints is None:
                                continue
                        if not any(expr_vars(constraint) & symbol_vars for constraint in residual_constraints):
                            continue
                        stack_constraints = stack_pointer_constraints_for_expr(
                            rd_symbol,
                            min_pointer_offset_for_vars(rd_vars, load_idx),
                        )
                        if try_add_constraint_set(list(residual_constraints) + stack_constraints):
                            break

        def add_loaded_pointer_residual_anchor_constraints():
            small_targets = [-4, 0, 4, 8, 16]
            for load_inst, rd_symbol, _, load_idx in load_accesses:
                if load_inst.width != 8:
                    continue
                rd_vars = expr_vars(rd_symbol)
                if not rd_vars:
                    continue
                for _, addr_symbol, access_idx, width in mem_accesses:
                    if access_idx <= load_idx:
                        continue
                    if not (expr_vars(addr_symbol) & rd_vars):
                        continue
                    residual = claripy.simplify(addr_symbol - rd_symbol)
                    residual_vars = expr_vars(residual)
                    if residual_vars & rd_vars:
                        continue
                    if not residual_vars:
                        residual_value = concrete_expr_value(residual)
                        if residual_value is None:
                            continue
                        imm = _signed_u64(residual_value)
                        min_offset = max(min_pointer_offset_for_vars(rd_vars, load_idx), width)
                        if imm >= 0:
                            min_offset = max(min_offset, imm + width)
                        min_offset = _align_up(min_offset, INIT_ACCESS_ALIGN)
                        if try_add_constraint_set(stack_pointer_constraints_for_expr(rd_symbol, min_offset)):
                            hint_pointer_load_keys.add((load_idx, expr_key(rd_symbol)))
                        continue
                    for target in small_targets:
                        residual_constraints = constraints_to_constant(
                            residual,
                            target,
                            forbidden_vars=rd_vars,
                        )
                        if residual_constraints is None:
                            continue
                        min_offset = max(min_pointer_offset_for_vars(rd_vars, load_idx), width)
                        if target >= 0:
                            min_offset = max(min_offset, target + width)
                        min_offset = _align_up(min_offset, INIT_ACCESS_ALIGN)
                        stack_constraints = stack_pointer_constraints_for_expr(rd_symbol, min_offset)
                        if try_add_constraint_set(list(residual_constraints) + stack_constraints):
                            hint_pointer_load_keys.add((load_idx, expr_key(rd_symbol)))
                            for reg, symbol in reg_to_symbol.items():
                                symbol_vars = expr_vars(symbol)
                                if symbol_vars and (residual_vars & symbol_vars):
                                    residual_scalar_regs.add(reg)
                            break

        def add_livein_base_residual_anchor_constraints():
            small_targets = [0, 4, 8, 16]
            for reg, symbol in reg_to_symbol.items():
                symbol_vars = expr_vars(symbol)
                if not symbol_vars:
                    continue
                for _, addr_symbol, _, width in mem_accesses:
                    if not (expr_vars(addr_symbol) & symbol_vars):
                        continue
                    residual = claripy.simplify(addr_symbol - symbol)
                    residual_vars = expr_vars(residual)
                    if not residual_vars or (residual_vars & symbol_vars):
                        continue
                    target_candidates = list(small_targets)
                    residual_affine = affine_base_const(residual)
                    if residual_affine is not None:
                        _, residual_imm = residual_affine
                        if residual_imm not in target_candidates:
                            target_candidates.insert(0, residual_imm)
                    for target in target_candidates:
                        residual_constraints = constraints_to_constant(
                            residual,
                            target,
                            forbidden_vars=symbol_vars,
                        )
                        if residual_constraints is None:
                            continue
                        min_offset = max(INIT_PTR_MIN_OFFSET, width)
                        if target >= 0:
                            min_offset = max(min_offset, target + width)
                        min_offset = _align_up(min_offset, INIT_ACCESS_ALIGN)
                        stack_constraints = stack_pointer_constraints_for_expr(symbol, min_offset)
                        if try_add_constraint_set(list(residual_constraints) + stack_constraints):
                            register_anchor_min_offsets[reg] = max(
                                register_anchor_min_offsets.get(reg, INIT_PTR_MIN_OFFSET),
                                min_offset,
                            )
                            for other_reg, other_symbol in reg_to_symbol.items():
                                if other_reg == reg:
                                    continue
                                other_vars = expr_vars(other_symbol)
                                if other_vars and (residual_vars & other_vars):
                                    residual_scalar_regs.add(other_reg)
                            break
                    if reg in register_anchor_min_offsets:
                        break

        def add_mul_address_carrier_constraints():
            mul_ops = {'__mul__', 'Mul'}

            def has_singleton_zero_hint(reg):
                values = {
                    value & ((1 << 64) - 1)
                    for value in reg_value_hints.get(reg, [])
                }
                return values == {0}

            for _, addr_symbol, _, width in mem_accesses:
                addr_vars = expr_vars(addr_symbol)
                if not addr_vars:
                    continue
                for mul_node in iter_ast_nodes(addr_symbol):
                    if getattr(mul_node, 'op', None) not in mul_ops:
                        continue
                    mul_args = [
                        arg for arg in getattr(mul_node, 'args', ())
                        if hasattr(arg, 'op')
                    ]
                    if len(mul_args) < 2:
                        continue
                    residual = claripy.simplify(addr_symbol - mul_node)
                    if expr_vars(residual) & expr_vars(mul_node):
                        continue
                    residual_livein_base_vars = set()
                    for _, other_symbol in reg_to_symbol.items():
                        other_vars = expr_vars(other_symbol)
                        if other_vars and (expr_vars(residual) & other_vars):
                            residual_livein_base_vars.update(other_vars)
                    if residual_livein_base_vars:
                        continue
                    residual_value = concrete_expr_value(residual)
                    if residual_value is None:
                        continue
                    residual_imm = _signed_u64(residual_value)

                    carrier_candidates = []
                    for reg, symbol in reg_to_symbol.items():
                        symbol_vars = expr_vars(symbol)
                        if not symbol_vars or not (addr_vars & symbol_vars):
                            continue
                        for carrier_arg in mul_args:
                            if not (expr_vars(carrier_arg) & symbol_vars):
                                continue
                            carrier_constraints = constraints_to_carrier(carrier_arg, symbol)
                            if carrier_constraints is None:
                                continue
                            other_constraints = []
                            valid = True
                            for other_arg in mul_args:
                                if other_arg is carrier_arg:
                                    continue
                                if not expr_vars(other_arg):
                                    other_value = concrete_expr_value(other_arg)
                                    if other_value is None or other_value != 1:
                                        valid = False
                                        break
                                    continue
                                sub_constraints = constraints_to_constant(
                                    other_arg,
                                    1,
                                    forbidden_vars=symbol_vars,
                                )
                                if sub_constraints is None:
                                    valid = False
                                    break
                                other_constraints.extend(sub_constraints)
                            if not valid:
                                continue
                            carrier_candidates.append((
                                has_singleton_zero_hint(reg),
                                reg.id,
                                reg,
                                symbol,
                                symbol_vars,
                                list(carrier_constraints) + other_constraints,
                            ))
                            break

                    carrier_candidates.sort(key=lambda item: (item[0], item[1]))
                    for _, _, reg, symbol, symbol_vars, constraints in carrier_candidates:
                        min_offset = max(INIT_PTR_MIN_OFFSET, width)
                        if residual_imm >= 0:
                            min_offset = max(min_offset, residual_imm + width)
                        min_offset = _align_up(min_offset, INIT_ACCESS_ALIGN)
                        stack_constraints = stack_pointer_constraints_for_expr(symbol, min_offset)
                        if not try_add_constraint_set(list(constraints) + stack_constraints):
                            continue
                        register_anchor_min_offsets[reg] = max(
                            register_anchor_min_offsets.get(reg, INIT_PTR_MIN_OFFSET),
                            min_offset,
                        )
                        for other_reg, other_symbol in reg_to_symbol.items():
                            if other_reg == reg:
                                continue
                            other_vars = expr_vars(other_symbol)
                            if other_vars and (expr_vars(mul_node) & other_vars):
                                residual_scalar_regs.add(other_reg)
                        break

        def add_loaded_address_scalar_zero_constraints():
            def has_scaled_loaded_address_use(symbol_vars):
                for _, addr_symbol, _, _ in mem_accesses:
                    addr_vars = expr_vars(addr_symbol)
                    if not (addr_vars & symbol_vars) or not (addr_vars & address_loaded_addr_vars):
                        continue
                    for node in iter_ast_nodes(addr_symbol):
                        if (
                            getattr(node, 'op', None) in {'__lshift__', 'LShR', 'SShR', '__mul__', 'Mul'}
                            and (expr_vars(node) & symbol_vars)
                        ):
                            return True
                return False

            for reg, symbol in reg_to_symbol.items():
                symbol_vars = expr_vars(symbol)
                if not symbol_vars:
                    continue
                has_direct_livein_base_use = any(
                    getattr(inst, 'rs1', None) == reg
                    and (expr_vars(addr_symbol) & symbol_vars)
                    for inst, addr_symbol, _, _ in mem_accesses
                )
                if has_direct_livein_base_use:
                    continue
                has_loaded_address_use = any(
                    (expr_vars(addr_symbol) & symbol_vars)
                    and (expr_vars(addr_symbol) & address_loaded_addr_vars)
                    for _, addr_symbol, _, _ in mem_accesses
                )
                if has_loaded_address_use:
                    if has_scaled_loaded_address_use(symbol_vars):
                        continue
                    try_add_constraint(symbol == expr_bvv(0, symbol))

        def add_direct_loaded_pointer_stack_constraints():
            for load_inst, rd_symbol, _, load_idx in address_source_loads:
                if load_inst.width != 8:
                    continue
                if (load_idx, expr_key(rd_symbol)) in scalar_load_hint_keys:
                    continue
                rd_vars = expr_vars(rd_symbol)
                if not rd_vars:
                    continue
                min_offset = None
                for access_inst, addr_symbol, access_idx, access_width in mem_accesses:
                    if access_idx <= load_idx:
                        continue
                    if not (expr_vars(addr_symbol) & rd_vars):
                        continue
                    residual = claripy.simplify(addr_symbol - rd_symbol)
                    if expr_vars(residual) & rd_vars:
                        continue
                    residual_value = concrete_expr_value(residual)
                    if residual_value is None:
                        continue
                    imm = _signed_u64(residual_value)
                    required_offset = max(INIT_PTR_MIN_OFFSET, access_width)
                    if imm >= 0:
                        required_offset = max(required_offset, imm + access_width)
                    min_offset = required_offset if min_offset is None else max(min_offset, required_offset)
                if min_offset is None:
                    continue
                try_add_constraint_set(
                    stack_pointer_constraints_for_expr(
                        rd_symbol,
                        _align_up(min_offset, INIT_ACCESS_ALIGN),
                    )
                )

        def add_livein_loaded_offset_base_constraints():
            for reg, symbol in reg_to_symbol.items():
                symbol_vars = expr_vars(symbol)
                if not symbol_vars:
                    continue
                has_direct_livein_base_use = any(
                    getattr(inst, 'rs1', None) == reg
                    and (expr_vars(addr_symbol) & symbol_vars)
                    for inst, addr_symbol, _, _ in mem_accesses
                )
                if has_direct_livein_base_use:
                    continue
                for access_inst, addr_symbol, _, access_width in mem_accesses:
                    addr_vars = expr_vars(addr_symbol)
                    if not (addr_vars & symbol_vars):
                        continue
                    if not (addr_vars & address_loaded_addr_vars):
                        continue
                    residual = claripy.simplify(addr_symbol - symbol)
                    residual_vars = expr_vars(residual)
                    if residual_vars & symbol_vars:
                        continue
                    if not (residual_vars & address_loaded_addr_vars):
                        continue
                    residual_constraints = constraints_to_constant(
                        residual,
                        0,
                        forbidden_vars=symbol_vars,
                    )
                    if residual_constraints is None:
                        continue
                    min_offset = _align_up(max(INIT_PTR_MIN_OFFSET, access_width), INIT_ACCESS_ALIGN)
                    constraints = stack_pointer_constraints_for_expr(symbol, min_offset)
                    constraints.extend(residual_constraints)
                    if try_add_constraint_set(constraints):
                        register_anchor_min_offsets[reg] = max(
                            register_anchor_min_offsets.get(reg, INIT_PTR_MIN_OFFSET),
                            min_offset,
                        )
                        break

        def add_risky_source_no_overlap_constraints():
            if len(store_accesses) >= GLOBAL_NO_OVERLAP_STORE_THRESHOLD:
                return
            if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD:
                return
            if not pointer_source_loads or not address_narrow_source_loads:
                return
            pair_budget = 64 if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD else None
            pairs_tried = 0
            for _, pointer_rd, pointer_addr, pointer_idx in pointer_source_loads:
                if (pointer_idx, expr_key(pointer_rd)) in scalar_load_hint_keys:
                    continue
                if has_forced_prior_same_addr_store_cached(pointer_addr, pointer_idx):
                    continue
                for narrow_addr, narrow_idx in address_narrow_source_loads:
                    if pair_budget is not None and pairs_tried >= pair_budget:
                        return
                    if has_forced_prior_same_addr_store_cached(narrow_addr, narrow_idx):
                        continue
                    if forced_same_address_cached(pointer_addr, narrow_addr):
                        continue
                    if affine_accesses_disjoint(pointer_addr, INIT_ACCESS_SLOT_WIDTH, narrow_addr, INIT_ACCESS_SLOT_WIDTH):
                        continue
                    pairs_tried += 1
                    try_add_constraint(
                        symbolic_access_no_overlap(
                            pointer_addr,
                            INIT_ACCESS_SLOT_WIDTH,
                            narrow_addr,
                            INIT_ACCESS_SLOT_WIDTH,
                        )
                    )

        def add_pointer_slot_store_no_overlap_constraints():
            if len(store_accesses) >= GLOBAL_NO_OVERLAP_STORE_THRESHOLD:
                return
            if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD:
                return
            for load_inst, rd_symbol, load_addr_symbol, load_idx in pointer_source_loads:
                if (load_idx, expr_key(rd_symbol)) in scalar_load_hint_keys:
                    continue
                pointer_vars = getattr(rd_symbol, 'variables', set())
                last_use_idx = load_idx
                for _, addr_symbol, access_idx, _ in mem_accesses:
                    if access_idx <= load_idx:
                        continue
                    if getattr(addr_symbol, 'variables', set()) & pointer_vars:
                        last_use_idx = max(last_use_idx, access_idx)
                if last_use_idx <= load_idx:
                    continue
                for store_inst, store_addr_symbol, store_idx, store_width, _ in store_accesses:
                    if store_idx <= load_idx or store_idx > last_use_idx:
                        continue
                    if same_address(store_addr_symbol, load_addr_symbol, allow_solver=True):
                        continue
                    if has_forced_prior_same_addr_store_cached(load_addr_symbol, load_idx):
                        continue
                    if affine_accesses_disjoint(
                        store_addr_symbol,
                        store_width,
                        load_addr_symbol,
                        init_slot_width(load_inst.width),
                    ):
                        continue
                    try_add_constraint(
                        symbolic_access_no_overlap(
                            store_addr_symbol,
                            store_width,
                            load_addr_symbol,
                            init_slot_width(load_inst.width),
                        )
                    )

        def add_store_load_slot_no_overlap_constraints():
            if len(store_accesses) >= GLOBAL_NO_OVERLAP_STORE_THRESHOLD:
                return
            static_symbolic_block = use_static_memory_collection and len(mem_entries) >= 3
            complex_memory_block = len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
            if static_symbolic_block and not complex_memory_block:
                return
            if complex_memory_block:
                required_load_indices = {
                    load_idx for _, _, _, load_idx in pointer_source_loads + address_source_loads
                }
                load_entries = [
                    entry for entry in mem_entries
                    if entry[3] in required_load_indices
                ]
                pair_budget = 512
            else:
                load_entries = mem_entries
                pair_budget = None
            pairs_tried = 0
            for load_inst, _, load_addr_symbol, load_idx in load_entries:
                if complex_memory_block:
                    load_affine = affine_key(load_addr_symbol)
                    if load_affine is None or ast_node_count(load_affine[2]) > 1:
                        continue
                for _, store_addr_symbol, store_idx, store_width, _ in store_accesses:
                    if store_idx >= load_idx:
                        continue
                    if pair_budget is not None and pairs_tried >= pair_budget:
                        return
                    pairs_tried += 1
                    same_result = cheap_same_address(store_addr_symbol, load_addr_symbol)
                    if same_result is True:
                        continue
                    if affine_accesses_disjoint(
                        store_addr_symbol,
                        store_width,
                        load_addr_symbol,
                        INIT_ACCESS_SLOT_WIDTH,
                    ):
                        continue
                    if same_result is None:
                        if static_symbolic_block and exprs_may_be_related(store_addr_symbol, load_addr_symbol):
                            continue
                        if not static_symbolic_block and same_address(store_addr_symbol, load_addr_symbol):
                            continue
                    constraint = symbolic_word_slot_no_overlap(
                        store_addr_symbol,
                        store_width,
                        load_addr_symbol,
                    )
                    if complex_memory_block:
                        candidate_solver.add(constraint)
                    else:
                        try_add_constraint(
                            constraint,
                            timeout_ms=100 if static_symbolic_block else HEURISTIC_SOLVER_TIMEOUT_MS,
                        )

        def add_load_slot_no_overlap_constraints():
            if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD:
                return
            for i, (_, _, addr_a, idx_a) in enumerate(mem_entries):
                if has_prior_same_addr_store(addr_a, idx_a, allow_solver=False):
                    continue
                for _, _, addr_b, idx_b in mem_entries[i + 1:]:
                    if has_prior_same_addr_store(addr_b, idx_b, allow_solver=False):
                        continue
                    same_result = cheap_same_address(addr_a, addr_b)
                    if same_result is True:
                        continue
                    if same_result is None and exprs_may_be_related(addr_a, addr_b):
                        continue
                    if affine_accesses_disjoint(addr_a, INIT_ACCESS_SLOT_WIDTH, addr_b, INIT_ACCESS_SLOT_WIDTH):
                        continue
                    try_add_constraint(symbolic_init_slots_no_overlap(addr_a, addr_b))

        def add_pointer_scalar_load_slot_no_overlap_constraints():
            if len(mem_entries) >= 32:
                return
            complex_memory_block = len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
            if complex_memory_block:
                return
            pointer_entries = []
            scalar_entries = []
            for load_inst, rd_symbol, addr_symbol, load_idx in mem_entries:
                if has_prior_same_addr_store(addr_symbol, load_idx, allow_solver=False):
                    continue
                if is_scalar_zero_address_load(load_inst, rd_symbol, load_idx):
                    scalar_entries.append((load_inst, addr_symbol, load_idx))
                    continue
                if load_inst.width != 8:
                    continue
                rd_vars = expr_vars(rd_symbol)
                if not rd_vars:
                    continue
                if (rd_vars & pointer_loaded_addr_vars) or (load_idx, expr_key(rd_symbol)) in hint_pointer_load_keys:
                    pointer_entries.append((load_inst, addr_symbol, load_idx))

            pair_budget = 128
            pairs_tried = 0
            for pointer_inst, pointer_addr, pointer_idx in pointer_entries:
                for scalar_inst, scalar_addr, scalar_idx in scalar_entries:
                    if pointer_idx == scalar_idx:
                        continue
                    if (
                        complex_memory_block
                        and (
                            (affine_key(pointer_addr) is None and ast_node_count(pointer_addr) > 8)
                            or (affine_key(scalar_addr) is None and ast_node_count(scalar_addr) > 8)
                        )
                    ):
                        continue
                    if pairs_tried >= pair_budget:
                        return
                    if same_address(pointer_addr, scalar_addr, allow_solver=False):
                        continue
                    if affine_accesses_disjoint(
                        pointer_addr,
                        init_slot_width(pointer_inst.width),
                        scalar_addr,
                        INIT_ACCESS_SLOT_WIDTH,
                    ):
                        continue
                    pairs_tried += 1
                    constraint = symbolic_init_slots_no_overlap(pointer_addr, scalar_addr)
                    if not try_add_constraint(constraint):
                        candidate_solver.add(constraint)
                        added_constraint_cache.add(str(claripy.simplify(constraint)))
        def add_pointer_load_slot_no_overlap_constraints():
            if len(mem_entries) < GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                return
            if address_narrow_source_loads:
                return

            pointer_loads = []
            seen_pointer_loads = set()

            def add_pointer_load(inst, rd_symbol, addr_symbol, inst_idx):
                if inst.width != 8:
                    return
                key = (inst_idx, expr_key(addr_symbol))
                if key in seen_pointer_loads:
                    return
                seen_pointer_loads.add(key)
                pointer_loads.append((inst, rd_symbol, addr_symbol, inst_idx))

            for pc in load_pointer_hints:
                for load_inst, rd_symbol, addr_symbol, load_idx in load_entries_by_pc.get(pc, []):
                    if (load_idx, expr_key(rd_symbol)) in hint_pointer_load_keys:
                        add_pointer_load(load_inst, rd_symbol, addr_symbol, load_idx)

            if not pointer_loads:
                return

            pointer_loads.sort(key=lambda item: item[3], reverse=True)
            pointer_loads = pointer_loads[:LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT]

            pair_budget = 32
            pairs_tried = 0
            for pointer_inst, _, pointer_addr, pointer_idx in pointer_loads:
                if has_prior_same_addr_store(pointer_addr, pointer_idx, allow_solver=False):
                    continue
                other_entries = [
                    entry for entry in mem_entries
                    if entry[0].width < 8
                ]
                other_entries.sort(key=lambda entry: (abs(entry[3] - pointer_idx), entry[3]))
                for other_inst, _, other_addr, other_idx in other_entries:
                    if other_idx == pointer_idx:
                        continue
                    if pairs_tried >= pair_budget:
                        return
                    pairs_tried += 1
                    if has_prior_same_addr_store(other_addr, other_idx, allow_solver=False):
                        continue
                    if same_address(pointer_addr, other_addr, allow_solver=False):
                        continue
                    if affine_accesses_disjoint(
                        pointer_addr,
                        init_slot_width(pointer_inst.width),
                        other_addr,
                        init_slot_width(other_inst.width),
                    ):
                        continue
                    try_add_constraint(symbolic_init_slots_no_overlap(pointer_addr, other_addr))

        def add_pointer_derived_access_slot_no_overlap_constraints():
            if not pointer_source_loads:
                return
            if len(mem_entries) >= 3:
                return
            pair_budget = None
            pairs_tried = 0
            pointer_carriers = [
                (pointer_rd, pointer_idx)
                for _, pointer_rd, _, pointer_idx in pointer_source_loads
                if (pointer_idx, expr_key(pointer_rd)) not in scalar_load_hint_keys
            ]
            for reg, symbol in reg_to_symbol.items():
                if (
                    reg in undef_base_regs
                    or reg in register_anchor_min_offsets
                    or reg in reg_pointer_hints
                ):
                    pointer_carriers.append((symbol, -1))

            seen_carriers = set()
            for pointer_rd, pointer_idx in pointer_carriers:
                carrier_key = expr_key(pointer_rd)
                if carrier_key in seen_carriers:
                    continue
                seen_carriers.add(carrier_key)
                pointer_vars = expr_vars(pointer_rd)
                if not pointer_vars:
                    continue
                for access_inst, access_addr, access_idx, access_width in mem_accesses:
                    if access_idx <= pointer_idx:
                        continue
                    if not (expr_vars(access_addr) & pointer_vars):
                        continue
                    for slot_inst, _, slot_addr, slot_idx in pointer_source_loads:
                        if pair_budget is not None and pairs_tried >= pair_budget:
                            return
                        if slot_idx == pointer_idx:
                            continue
                        if has_prior_same_addr_store(slot_addr, slot_idx, allow_solver=False):
                            continue
                        same_result = cheap_same_address(access_addr, slot_addr)
                        if same_result is True:
                            continue
                        if same_result is None and exprs_may_be_related(access_addr, slot_addr):
                            continue
                        if affine_accesses_disjoint(
                            access_addr,
                            init_slot_width(access_width),
                            slot_addr,
                            init_slot_width(slot_inst.width),
                        ):
                            continue
                        pairs_tried += 1
                        try_add_constraint(symbolic_init_slots_no_overlap(access_addr, slot_addr))

        def add_pointer_value_no_alias_constraints():
            if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                return
            pair_budget = 64 if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD else None
            pairs_tried = 0
            for i, (_, rd_a, addr_a, idx_a) in enumerate(pointer_source_loads):
                if has_prior_same_addr_store(addr_a, idx_a, allow_solver=False):
                    continue
                vars_a = getattr(rd_a, 'variables', set())
                if not vars_a:
                    continue
                for _, rd_b, addr_b, idx_b in pointer_source_loads[i + 1:]:
                    if pair_budget is not None and pairs_tried >= pair_budget:
                        return
                    if has_prior_same_addr_store(addr_b, idx_b, allow_solver=False):
                        continue
                    vars_b = getattr(rd_b, 'variables', set())
                    if not vars_b:
                        continue
                    if idx_a == idx_b:
                        continue
                    source_affine_a = affine_key(addr_a)
                    source_affine_b = affine_key(addr_b)
                    if source_affine_a is not None and source_affine_b is not None:
                        source_base_a, source_imm_a, _ = source_affine_a
                        source_base_b, source_imm_b, _ = source_affine_b
                        if source_base_a == source_base_b:
                            continue
                        source_a_negative = source_imm_a < 0
                        source_b_negative = source_imm_b < 0
                        source_a_pointer_indirect = bool(expr_vars(addr_a) & pointer_loaded_addr_vars)
                        source_b_pointer_indirect = bool(expr_vars(addr_b) & pointer_loaded_addr_vars)
                        suspect_source_pair = (
                            (source_a_pointer_indirect and source_b_pointer_indirect)
                            or (source_a_negative and source_b_pointer_indirect)
                            or (source_b_negative and source_a_pointer_indirect)
                        )
                    else:
                        suspect_source_pair = False
                        source_a_negative = source_b_negative = False
                        source_a_pointer_indirect = source_b_pointer_indirect = False
                    same_value = cheap_same_address(rd_a, rd_b)
                    if same_value is True:
                        continue
                    if same_value is None and exprs_may_be_related(rd_a, rd_b):
                        continue
                    if affine_accesses_disjoint(rd_a, INIT_ACCESS_SLOT_WIDTH, rd_b, INIT_ACCESS_SLOT_WIDTH):
                        continue
                    pairs_tried += 1
                    constraint = symbolic_access_no_overlap(
                        rd_a,
                        INIT_ACCESS_SLOT_WIDTH,
                        rd_b,
                        INIT_ACCESS_SLOT_WIDTH,
                    )
                    if suspect_source_pair:
                        continue
                    try_add_constraint(constraint)

        def add_pointer_anchor_simplification_constraints():
            if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD:
                return
            anchor_accesses = mem_accesses
            candidate_budget = None
            candidates_tried = 0
            long_block = len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD
            if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                anchor_accesses = list(reversed(mem_accesses))[:LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT * 4]
                candidate_budget = LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT * 8
            for access_inst, addr_symbol, access_idx, width in anchor_accesses:
                if _signed_u64(access_inst.imm) < 0:
                    continue
                if long_block and ast_node_count(addr_symbol) > 96:
                    continue
                carrier_candidates = []
                addr_vars = expr_vars(addr_symbol)
                candidate_loads = [
                    entry for entry in load_accesses
                    if entry[3] < access_idx
                ]
                if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                    candidate_loads = list(reversed(candidate_loads))[:LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT]
                for load_inst, rd_symbol, _, load_idx in candidate_loads:
                    if load_idx >= access_idx:
                        continue
                    if load_inst.width != 8:
                        continue
                    if (load_idx, expr_key(rd_symbol)) in scalar_load_hint_keys:
                        continue
                    rd_vars = expr_vars(rd_symbol)
                    if not rd_vars or not (addr_vars & rd_vars):
                        continue
                    if (addr_vars & pointer_loaded_addr_vars) and not (rd_vars & pointer_loaded_addr_vars):
                        continue
                    if long_block and ast_node_count(rd_symbol) > 48:
                        continue
                    if candidate_budget is not None:
                        if candidates_tried >= candidate_budget:
                            break
                        candidates_tried += 1
                    constraints = constraints_to_carrier(addr_symbol, rd_symbol)
                    preferred_base = 1 if load_inst.pc in mem_base_pcs else 0
                    if constraints is not None:
                        carrier_candidates.append((
                            preferred_base,
                            count_mul_ancestors(addr_symbol, rd_symbol),
                            1,
                            load_idx,
                            rd_symbol,
                            rd_vars,
                            constraints,
                        ))
                    internal_constraints = constraints_to_internal_carrier(addr_symbol, rd_symbol)
                    if internal_constraints is not None:
                        carrier_candidates.append((
                            preferred_base,
                            count_mul_ancestors(addr_symbol, rd_symbol),
                            0,
                            load_idx,
                            rd_symbol,
                            rd_vars,
                            internal_constraints,
                        ))
                if verbose and carrier_candidates:
                    print('carrier_candidates', {
                        'access_idx': access_idx,
                        'addr': str(addr_symbol),
                        'candidates': [
                            (preferred, score, kind, load_idx, getattr(rd_symbol, 'shallow_repr', lambda: str(rd_symbol))(), len(constraints))
                            for preferred, score, kind, load_idx, rd_symbol, _, constraints in carrier_candidates
                        ],
                    })
                if not carrier_candidates:
                    continue

                carrier_candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]), reverse=True)
                for _, _, _, load_idx, rd_symbol, rd_vars, constraints in carrier_candidates:
                    stack_constraints = stack_pointer_constraints_for_expr(
                        rd_symbol,
                        min_pointer_offset_for_vars(rd_vars, load_idx),
                    )
                    if try_add_constraint_set(
                        list(constraints) + stack_constraints,
                        verify_constraints=[addr_symbol == rd_symbol],
                    ):
                        if verbose:
                            print('carrier_selected', {
                                'access_idx': access_idx,
                                'load_idx': load_idx,
                                'rd': str(rd_symbol),
                                'constraints': [str(claripy.simplify(c)) for c in list(constraints) + stack_constraints],
                            })
                        break

        def add_register_anchor_simplification_constraints():
            if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                return
            long_register_anchor = len(mem_accesses) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD
            anchor_accesses = mem_accesses
            if long_register_anchor:
                anchor_accesses = list(reversed(mem_accesses))[:LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT * 4]
            for access_inst, addr_symbol, _, width in anchor_accesses:
                if long_register_anchor and ast_node_count(addr_symbol) > 96:
                    continue
                addr_vars = expr_vars(addr_symbol)
                has_pointer_loaded_base = bool(addr_vars & (pointer_loaded_addr_vars | address_loaded_addr_vars))
                carrier_candidates = []
                direct_carrier_keys = set()
                for reg, symbol in reg_to_symbol.items():
                    if reg in scalar_hint_regs:
                        continue
                    symbol_vars = expr_vars(symbol)
                    if not symbol_vars or not (addr_vars & symbol_vars):
                        continue
                    if has_pointer_loaded_base and getattr(access_inst, 'rs1', None) != reg:
                        continue
                    carrier_constraints = constraints_to_carrier(addr_symbol, symbol)
                    if carrier_constraints is not None:
                        residual_vars = addr_vars - symbol_vars
                        direct_carrier_keys.add(reg)
                        carrier_candidates.append((
                            count_mul_ancestors(addr_symbol, symbol),
                            len(residual_vars),
                            0,
                            reg.name,
                            symbol,
                            carrier_constraints,
                            width,
                        ))
                        continue
                    residual = claripy.simplify(addr_symbol - symbol)
                    residual_vars = expr_vars(residual)
                    if residual_vars & symbol_vars:
                        continue
                    if long_register_anchor and ast_node_count(residual) > 64:
                        continue
                    constraints = constraints_to_constant(
                        residual,
                        0,
                        forbidden_vars=symbol_vars,
                    )
                    if constraints is None:
                        continue
                    direct_carrier_keys.add(reg)
                    carrier_candidates.append((
                        count_mul_ancestors(addr_symbol, symbol),
                        len(residual_vars),
                        0,
                        reg.name,
                        symbol,
                        constraints,
                        width,
                    ))

                for reg, symbol in reg_to_symbol.items():
                    if reg in direct_carrier_keys:
                        continue
                    if reg in scalar_hint_regs:
                        continue
                    symbol_vars = expr_vars(symbol)
                    if not symbol_vars or not (addr_vars & symbol_vars):
                        continue
                    if has_pointer_loaded_base and getattr(access_inst, 'rs1', None) != reg:
                        continue
                    residual = claripy.simplify(addr_symbol - symbol)
                    residual_vars = expr_vars(residual)
                    if residual_vars & symbol_vars:
                        continue
                    if long_register_anchor and ast_node_count(residual) > 64:
                        continue
                    # Heuristic for indexed stack accesses such as
                    #   base + ((load - 1) * stride) * scale
                    # where the index can be solved away by prior value hints.
                    # Adding the equality directly lets the solver pick the
                    # needed scalar values without recursively decomposing a
                    # large bit-vector multiplication expression.
                    carrier_candidates.append((
                        count_mul_ancestors(addr_symbol, symbol),
                        len(residual_vars),
                        1,
                        reg.name,
                        symbol,
                        [addr_symbol == symbol],
                        width,
                    ))
                if not carrier_candidates:
                    continue

                carrier_candidates.sort(key=lambda item: (item[0], -item[1], -item[2], item[3]), reverse=True)
                for _, _, _, reg_name, symbol, constraints, access_width in carrier_candidates:
                    min_offset = max(INIT_PTR_MIN_OFFSET, access_width)
                    stack_constraints = stack_pointer_constraints_for_expr(symbol, min_offset)
                    if try_add_constraint_set(
                        list(constraints) + stack_constraints,
                        verify_constraints=[addr_symbol == symbol],
                    ):
                        reg = find_reg_by_name(reg_name)
                        register_anchor_min_offsets[reg] = max(
                            register_anchor_min_offsets.get(reg, INIT_PTR_MIN_OFFSET),
                            _align_up(min_offset, INIT_ACCESS_ALIGN),
                        )
                        break

        def add_store_no_overlap_for_word(word_offset, addr_symbols):
            if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD:
                return
            for _, store_addr_symbol, _, store_width, _ in store_accesses:
                if any(same_address(store_addr_symbol, addr_symbol) for addr_symbol in addr_symbols):
                    continue
                if addr_symbols and all(
                    affine_accesses_disjoint(store_addr_symbol, store_width, addr_symbol, INIT_ACCESS_SLOT_WIDTH)
                    for addr_symbol in addr_symbols
                ):
                    continue
                try_add_constraint(symbolic_no_overlap(store_addr_symbol, store_width, word_offset))

        def add_access_range_constraints():
            direct_add_for_long_block = len(mem_accesses) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD

            def try_add_constraint_group(constraints):
                constraints = list(constraints)
                if not constraints:
                    return True
                if direct_add_for_long_block:
                    test_solver = candidate_solver.branch()
                    test_solver.timeout = local_solver_timeout_ms
                    try:
                        for constraint in constraints:
                            test_solver.add(constraint)
                        if not test_solver.satisfiable():
                            return False
                    except Exception:
                        return False
                    for constraint in constraints:
                        constraint_key = str(claripy.simplify(constraint))
                        if constraint_key in added_constraint_cache:
                            continue
                        candidate_solver.add(constraint)
                        added_constraint_cache.add(constraint_key)
                    return True
                test_solver = candidate_solver.branch()
                test_solver.timeout = HEURISTIC_SOLVER_TIMEOUT_MS
                try:
                    for constraint in constraints:
                        test_solver.add(constraint)
                    if not test_solver.satisfiable():
                        return False
                except Exception:
                    return False
                for constraint in constraints:
                    candidate_solver.add(constraint)
                    added_constraint_cache.add(str(claripy.simplify(constraint)))
                return True

            grouped = {}
            fallback = []
            for _, addr_symbol, _, width in mem_accesses:
                affine = affine_key(addr_symbol)
                if affine is None:
                    fallback.append((addr_symbol, width))
                    continue
                base_key, imm, base = affine
                grouped.setdefault(base_key, {'base': base, 'accesses': []})['accesses'].append((imm, width))

            group_values = list(grouped.values())
            if len(mem_accesses) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                group_values.sort(key=lambda item: (-len(item['accesses']), str(item['base'])))
                group_values = group_values[:LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT * 4]

            for group in group_values:
                base = group['base']
                base_offset = init_sp - base
                lower = 1
                upper = None
                align_constraints = set()
                for imm, width in group['accesses']:
                    lower = max(lower, imm + width)
                    access_upper = STACK_RANGE + imm
                    upper = access_upper if upper is None else min(upper, access_upper)
                    if width > 1:
                        mask = width - 1
                        align_constraints.add((width, (-imm) & mask))
                if lower < 1:
                    lower = 1
                if upper is None:
                    upper = STACK_RANGE
                if lower > upper:
                    group_accesses = group['accesses']
                    if len(mem_accesses) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                        group_accesses = group_accesses[:LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT * 4]
                    for imm, width in group_accesses:
                        addr_symbol = claripy.simplify(base + claripy.BVV(imm & ((1 << 64) - 1), 64))
                        offset_expr = init_sp - addr_symbol
                        constraints = [
                            claripy.UGE(offset_expr, claripy.BVV(width, 64)),
                            claripy.ULE(offset_expr, claripy.BVV(STACK_RANGE, 64)),
                        ]
                        if width > 1:
                            constraints.append((addr_symbol & (width - 1)) == 0)
                        try_add_constraint_group(constraints)
                    continue
                constraints = [
                    claripy.UGE(base_offset, claripy.BVV(lower, 64)),
                    claripy.ULE(base_offset, claripy.BVV(upper, 64)),
                ]
                for width, residue in sorted(align_constraints):
                    constraints.append((base & (width - 1)) == residue)
                if not try_add_constraint_group(constraints):
                    group_accesses = group['accesses']
                    if len(mem_accesses) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                        group_accesses = group_accesses[:LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT * 4]
                    for imm, width in group_accesses:
                        addr_symbol = claripy.simplify(base + claripy.BVV(imm & ((1 << 64) - 1), 64))
                        offset_expr = init_sp - addr_symbol
                        access_constraints = [
                            claripy.UGE(offset_expr, claripy.BVV(width, 64)),
                            claripy.ULE(offset_expr, claripy.BVV(STACK_RANGE, 64)),
                        ]
                        if width > 1:
                            access_constraints.append((addr_symbol & (width - 1)) == 0)
                        try_add_constraint_group(access_constraints)

            if len(mem_accesses) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                fallback = fallback[:LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT * 8]
            for addr_symbol, width in fallback:
                offset_expr = init_sp - addr_symbol
                constraints = [
                    claripy.UGE(offset_expr, claripy.BVV(width, 64)),
                    claripy.ULE(offset_expr, claripy.BVV(STACK_RANGE, 64)),
                ]
                if width > 1:
                    constraints.append((addr_symbol & (width - 1)) == 0)
                try_add_constraint_group(constraints)

        def choose_register_value(symbol, preferred=None, align=None):
            symbol_vars = getattr(symbol, 'variables', set())
            if symbol_vars and not any(
                getattr(constraint, 'variables', set()) & symbol_vars
                for constraint in candidate_solver.constraints
            ):
                val = preferred if preferred is not None else 0
                if align and val % align != 0:
                    val = _align_up(val, align)
                candidate_solver.add(symbol == val)
                return val

            symbol_key = expr_key(symbol)
            for constraint in candidate_solver.constraints:
                if getattr(constraint, 'op', None) not in {'__eq__', 'BoolS'}:
                    continue
                args = [
                    arg for arg in getattr(constraint, 'args', ())
                    if hasattr(arg, 'op')
                ]
                if len(args) != 2:
                    continue
                lhs, rhs = args
                if expr_key(lhs) == symbol_key and not expr_vars(rhs):
                    val = concrete_expr_value(rhs)
                elif expr_key(rhs) == symbol_key and not expr_vars(lhs):
                    val = concrete_expr_value(lhs)
                else:
                    val = None
                if val is None:
                    continue
                val &= ((1 << 64) - 1)
                if align and val % align != 0:
                    continue
                return val

            choices = []
            if preferred is not None:
                choices.append(preferred)
            choices.extend([
                0,
                1,
                2,
                4,
                8,
                16,
                32,
                (-8) & ((1 << 64) - 1),
                (-16) & ((1 << 64) - 1),
                (-32) & ((1 << 64) - 1),
            ])

            seen = set()
            for val in choices:
                if val in seen:
                    continue
                seen.add(val)
                if align and val % align != 0:
                    continue
                stack_offset = stack_offset_for_value(val)
                if stack_offset is not None and any(
                    concrete_ranges_overlap(stack_offset, 8, used_offset, used_width)
                    for used_offset, used_width in used_stack_offsets
                ):
                    continue
                if satisfiable_with(symbol, val, timeout_ms=HEURISTIC_SOLVER_TIMEOUT_MS):
                    candidate_solver.add(symbol == val)
                    if stack_offset is not None:
                        used_stack_offsets.append((stack_offset, 8))
                    return val

            minimum = solver_min(symbol)
            if minimum is not None:
                choices.append(minimum)
                step = align if align else 1
                for i in range(1, 64):
                    choices.append(minimum + i * step)

            for val in choices:
                if val in seen:
                    continue
                seen.add(val)
                if align and val % align != 0:
                    continue
                stack_offset = stack_offset_for_value(val)
                if stack_offset is not None and any(
                    concrete_ranges_overlap(stack_offset, 8, used_offset, used_width)
                    for used_offset, used_width in used_stack_offsets
                ):
                    continue
                if satisfiable_with(symbol, val, timeout_ms=HEURISTIC_SOLVER_TIMEOUT_MS):
                    candidate_solver.add(symbol == val)
                    if stack_offset is not None:
                        used_stack_offsets.append((stack_offset, 8))
                    return val

            val = choose_value(symbol, preferred, align=align)
            stack_offset = stack_offset_for_value(val)
            if stack_offset is not None:
                used_stack_offsets.append((stack_offset, 8))
            return val

        def choose_stack_relative_register_value(symbol):
            offset_expr = init_sp - symbol
            offset = choose_value(
                offset_expr,
                None,
                positive=True,
                align=8,
                avoid=used_stack_offsets,
                width=8,
                required=False,
            )
            if offset is None:
                offset = choose_value(
                    offset_expr,
                    None,
                    positive=True,
                    align=8,
                    required=False,
                )
            if offset is None:
                return None
            used_stack_offsets.append((offset, 8))
            return concrete_stack_addr(offset)

        def choose_base_register_value(symbol, min_offset=INIT_PTR_MIN_OFFSET, fast_anchor=False):
            symbol_vars = expr_vars(symbol)
            start_offset = max(1, min_offset)
            candidates = []
            if concrete_expr_value(symbol) is not None:
                return concrete_expr_value(symbol)
            offset_expr = init_sp - symbol
            fallback_start = _align_up(max(INIT_PTR_MIN_OFFSET, min_offset), INIT_ACCESS_ALIGN)

            def residual_offset_and_constraints(residual):
                residual_vars = expr_vars(residual)
                if residual_vars & symbol_vars:
                    return None
                residual_value = concrete_expr_value(residual)
                if residual_value is not None:
                    return _signed_u64(residual_value), []
                residual_affine = affine_base_const(residual)
                if residual_affine is None:
                    return None
                _, residual_imm = residual_affine
                residual_constraints = constraints_to_constant(
                    residual,
                    residual_imm,
                    forbidden_vars=symbol_vars,
                )
                if residual_constraints is None:
                    return None
                return residual_imm, list(residual_constraints)

            def base_offset_alignment():
                modulus = 1
                residue = 0
                for access_inst, addr_symbol, _, access_width in mem_accesses:
                    if access_width <= 1:
                        continue
                    if not (expr_vars(addr_symbol) & symbol_vars):
                        continue
                    residual = claripy.simplify(addr_symbol - symbol)
                    residual_choice = residual_offset_and_constraints(residual)
                    if residual_choice is None:
                        continue
                    imm, _ = residual_choice
                    width_residue = imm % access_width
                    new_modulus = max(modulus, access_width)
                    if residue % access_width != width_residue:
                        if width_residue % modulus != residue:
                            return None
                        residue = width_residue
                    modulus = new_modulus
                return modulus, residue % modulus

            base_alignment = base_offset_alignment()

            def align_base_offset(start):
                if base_alignment is None:
                    return None
                modulus, residue = base_alignment
                start = max(1, start)
                if modulus <= 1:
                    return start
                delta = (residue - (start % modulus)) % modulus
                return start + delta

            def base_offset_step():
                if base_alignment is None:
                    return INIT_ACCESS_ALIGN
                return max(1, base_alignment[0])

            def base_access_ranges_for_offset(base_offset):
                ranges = []
                for access_inst, addr_symbol, _, access_width in mem_accesses:
                    if not (expr_vars(addr_symbol) & symbol_vars):
                        continue
                    residual = claripy.simplify(addr_symbol - symbol)
                    residual_choice = residual_offset_and_constraints(residual)
                    if residual_choice is None:
                        continue
                    imm, residual_constraints = residual_choice
                    access_offset = base_offset - imm
                    if access_offset <= 0 or access_offset > STACK_RANGE:
                        return None
                    if access_width > 1 and access_offset % access_width:
                        return None
                    ranges.append((access_offset, init_slot_width(access_width), addr_symbol, residual_constraints))
                return ranges

            def stack_ranges_available(ranges):
                if ranges is None:
                    return False
                for offset, width, _, _ in ranges:
                    if any(
                        concrete_ranges_overlap(offset, width, used_offset, used_width)
                        for used_offset, used_width in used_stack_offsets
                    ):
                        return False
                return True

            def reserve_stack_ranges(ranges):
                reserved = []
                for offset, width, _, _ in ranges:
                    if any(
                        concrete_ranges_overlap(offset, width, used_offset, used_width)
                        for used_offset, used_width in used_stack_offsets + reserved
                    ):
                        continue
                    reserved.append((offset, width))
                used_stack_offsets.extend(reserved)

            def reserve_base_access_ranges(ranges):
                for offset, width, addr_symbol, _ in ranges:
                    if addr_symbol is None:
                        continue
                    if any(
                        used_offset == offset
                        and same_address(addr_symbol, used_addr_symbol, allow_solver=False)
                        for used_offset, _, used_addr_symbol in reserved_base_access_ranges
                    ):
                        continue
                    reserved_base_access_ranges.append((offset, width, addr_symbol))

            def try_select_base_offset(base_offset, timeout_ms=HEURISTIC_SOLVER_TIMEOUT_MS):
                ranges = base_access_ranges_for_offset(base_offset)
                if not stack_ranges_available(ranges):
                    return None
                constraints = [offset_expr == base_offset]
                for _, _, _, residual_constraints in ranges:
                    constraints.extend(residual_constraints)
                if try_add_constraint_set_fast(constraints, timeout_ms=timeout_ms):
                    reserve_stack_ranges(ranges)
                    reserve_base_access_ranges(ranges)
                    return concrete_stack_addr(base_offset)
                return None

            def add_base_offset_constraints_direct(base_offset, ranges):
                constraints = [offset_expr == base_offset]
                for _, _, _, residual_constraints in ranges:
                    for constraint in residual_constraints:
                        constraints.append(constraint)
                return try_add_constraint_set_fast(
                    constraints,
                    timeout_ms=local_solver_timeout_ms,
                )

            if fast_anchor and len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                first_offset = align_base_offset(fallback_start)
                if first_offset is None:
                    return None

                starts = [first_offset]
                for used_offset, used_width in used_stack_offsets:
                    starts.append(used_offset + max(INIT_ACCESS_SLOT_WIDTH, used_width))

                seen_offsets = set()
                direct_add_candidate = None
                attempts = 0
                for start in sorted(starts):
                    offset = align_base_offset(start)
                    if offset is None:
                        continue
                    while (
                        offset <= STACK_RANGE
                        and attempts < LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT * 4
                    ):
                        if offset not in seen_offsets:
                            seen_offsets.add(offset)
                            ranges = base_access_ranges_for_offset(offset)
                            if stack_ranges_available(ranges):
                                value = try_select_base_offset(offset, timeout_ms=100)
                                if value is not None:
                                    return value
                                if direct_add_candidate is None:
                                    direct_add_candidate = (offset, ranges)
                            attempts += 1
                        offset += base_offset_step()

                if direct_add_candidate is None:
                    return None
                offset, ranges = direct_add_candidate
                if not add_base_offset_constraints_direct(offset, ranges):
                    return None
                reserve_stack_ranges(ranges)
                reserve_base_access_ranges(ranges)
                return concrete_stack_addr(offset)

            if fast_anchor:
                has_negative_access = False
                for _, addr_symbol, _, _ in mem_accesses:
                    if not (expr_vars(addr_symbol) & symbol_vars):
                        continue
                    residual = claripy.simplify(addr_symbol - symbol)
                    if expr_vars(residual) & symbol_vars:
                        continue
                    residual_value = concrete_expr_value(residual)
                    if residual_value is not None and _signed_u64(residual_value) < 0:
                        has_negative_access = True
                        break
                if has_negative_access:
                    stop_offset = min(STACK_RANGE, fallback_start + 512)
                    first_offset = align_base_offset(fallback_start)
                    if first_offset is None:
                        return None
                    direct_add_candidate = None
                    for preferred_offset in range(first_offset, stop_offset + 1, base_offset_step()):
                        value = try_select_base_offset(preferred_offset, timeout_ms=100)
                        if value is not None:
                            return value
                        if direct_add_candidate is None:
                            ranges = base_access_ranges_for_offset(preferred_offset)
                            if stack_ranges_available(ranges):
                                direct_add_candidate = (preferred_offset, ranges)
                    if direct_add_candidate is not None:
                        offset, ranges = direct_add_candidate
                        if not add_base_offset_constraints_direct(offset, ranges):
                            return None
                        reserve_stack_ranges(ranges)
                        reserve_base_access_ranges(ranges)
                        return concrete_stack_addr(offset)
                else:
                    first_offset = align_base_offset(fallback_start)
                    if first_offset is None:
                        return None
                    stop_offset = min(STACK_RANGE, first_offset + 512)
                    direct_add_candidate = None
                    for preferred_offset in range(first_offset, stop_offset + 1, base_offset_step()):
                        value = try_select_base_offset(preferred_offset)
                        if value is not None:
                            return value
                        if direct_add_candidate is None:
                            ranges = base_access_ranges_for_offset(preferred_offset)
                            if stack_ranges_available(ranges):
                                direct_add_candidate = (preferred_offset, ranges)
                    if direct_add_candidate is not None:
                        offset, ranges = direct_add_candidate
                        if not add_base_offset_constraints_direct(offset, ranges):
                            return None
                        reserve_stack_ranges(ranges)
                        reserve_base_access_ranges(ranges)
                        return concrete_stack_addr(offset)
                return None
            first_offset = align_base_offset(fallback_start)
            if first_offset is None:
                return None
            for offset in range(first_offset, STACK_RANGE + 1, base_offset_step()):
                sat = satisfiable_with(offset_expr, offset)
                if fast_anchor:
                    if not sat:
                        continue
                    value = try_select_base_offset(offset)
                    if value is not None:
                        return value
                if sat:
                    value = try_select_base_offset(offset)
                    if value is not None:
                        return value
            for _, addr_symbol, _, width in mem_accesses:
                if not (expr_vars(addr_symbol) & symbol_vars):
                    continue
                residual = claripy.simplify(addr_symbol - symbol)
                if expr_vars(residual) & symbol_vars:
                    continue
                residual_value = concrete_expr_value(residual)
                if residual_value is None:
                    continue
                imm = _signed_u64(residual_value)
                align = width if width > 1 else 1
                access_start = _align_up(start_offset, align)
                for access_offset in range(access_start, STACK_RANGE + 1, align):
                    value = (CONCRETE_REPLAY_SP - access_offset - imm) & ((1 << 64) - 1)
                    candidates.append(value)

            for offset in range(first_offset, STACK_RANGE + 1, base_offset_step()):
                candidates.append(concrete_stack_addr(offset))

            seen = set()
            relaxed_candidates = []
            for value in candidates:
                value &= ((1 << 64) - 1)
                if value in seen:
                    continue
                seen.add(value)
                stack_offset = stack_offset_for_value(value)
                if stack_offset is not None:
                    ranges = base_access_ranges_for_offset(stack_offset)
                    if not stack_ranges_available(ranges):
                        relaxed_candidates.append(value)
                        continue
                if satisfiable_with(symbol, value):
                    candidate_solver.add(symbol == value)
                    if stack_offset is not None:
                        reserve_stack_ranges(base_access_ranges_for_offset(stack_offset))
                    return value

            for value in relaxed_candidates:
                stack_offset = stack_offset_for_value(value)
                if stack_offset is not None and not stack_ranges_available(base_access_ranges_for_offset(stack_offset)):
                    continue
                if satisfiable_with(symbol, value):
                    candidate_solver.add(symbol == value)
                    if stack_offset is not None:
                        reserve_stack_ranges(base_access_ranges_for_offset(stack_offset))
                    return value

            for offset in range(first_offset, STACK_RANGE + 1, base_offset_step()):
                value = try_select_base_offset(offset)
                if value is not None:
                    return value
            return None

        def scaled_symbol_affine(expr, symbol):
            symbol_key = expr_key(symbol)
            symbol_vars = expr_vars(symbol)
            mask = (1 << 64) - 1

            def parse(node):
                node = claripy.simplify(node)
                if expr_key(node) == symbol_key:
                    return 1, 0, []
                node_vars = expr_vars(node)
                if not node_vars:
                    value = concrete_expr_value(node)
                    if value is None:
                        return None
                    return 0, value & mask, []
                if not (node_vars & symbol_vars):
                    return 0, 0, [node == expr_bvv(0, node)]

                op = getattr(node, 'op', None)
                args = getattr(node, 'args', ())
                if op == '__add__':
                    scale, const, constraints = 0, 0, []
                    for arg in args:
                        parsed = parse(arg)
                        if parsed is None:
                            return None
                        arg_scale, arg_const, arg_constraints = parsed
                        scale += arg_scale
                        const = (const + arg_const) & mask
                        constraints.extend(arg_constraints)
                    return scale, const, constraints
                if op == '__sub__' and len(args) == 2:
                    lhs = parse(args[0])
                    rhs = parse(args[1])
                    if lhs is None or rhs is None:
                        return None
                    return lhs[0] - rhs[0], (lhs[1] - rhs[1]) & mask, lhs[2] + rhs[2]
                if op == '__lshift__' and len(args) == 2:
                    parsed = parse(args[0])
                    shift_value = concrete_expr_value(args[1])
                    if parsed is None or shift_value is None:
                        return None
                    scale, const, constraints = parsed
                    return scale << shift_value, (const << shift_value) & mask, constraints
                if op in {'ZeroExt', 'SignExt'} and args:
                    return parse(args[-1])
                if op == 'Extract' and len(args) == 3:
                    high, low, child = args
                    if low == 0 and expr_key(child) == symbol_key:
                        return 1, 0, []
                    return None
                if op == 'Concat' and args:
                    low_width = 0
                    for low_arg in args[1:]:
                        low_value = concrete_expr_value(low_arg)
                        if low_value not in (0, None):
                            return None
                        if low_value is None:
                            return None
                        low_width += low_arg.size()
                    high = parse(args[0])
                    if high is None:
                        return None
                    return high[0] << low_width, (high[1] << low_width) & mask, high[2]
                return None

            parsed = parse(expr)
            if parsed is None:
                return None
            scale, const, constraints = parsed
            if scale <= 1 or scale & (scale - 1):
                return None
            return scale, const & mask, constraints

        def choose_scaled_address_register_value(symbol):
            symbol_vars = expr_vars(symbol)
            if not symbol_vars:
                return None
            candidates = []
            for inst, addr_symbol, _, width in mem_accesses:
                if not (expr_vars(addr_symbol) & symbol_vars):
                    continue
                scaled = scaled_symbol_affine(addr_symbol, symbol)
                if scaled is None:
                    continue
                scale, const, scaled_constraints = scaled
                align = width if width > 1 else 1
                starts = [align, INIT_PTR_MIN_OFFSET]
                preferred = next_free_stack_offset(
                    used_stack_offsets,
                    align=align,
                    width=INIT_ACCESS_SLOT_WIDTH,
                    start=align,
                )
                if preferred is not None:
                    starts.insert(0, preferred)
                starts.extend(used + max(width, used_width) for used, used_width in used_stack_offsets)
                seen_offsets = set()
                for start in starts:
                    start = _align_up(max(1, start), align)
                    for access_offset in range(start, min(STACK_RANGE, start + 512) + 1, align):
                        if access_offset in seen_offsets:
                            continue
                        seen_offsets.add(access_offset)
                        if any(
                            concrete_ranges_overlap(access_offset, INIT_ACCESS_SLOT_WIDTH, used_offset, used_width)
                            for used_offset, used_width in used_stack_offsets
                        ):
                            continue
                        target_addr = concrete_stack_addr(access_offset)
                        raw_value = (target_addr - const) & ((1 << 64) - 1)
                        if raw_value % scale:
                            continue
                        value = (raw_value // scale) & ((1 << 64) - 1)
                        candidates.append((value, addr_symbol, target_addr, access_offset, scaled_constraints))

            seen_values = set()
            for value, addr_symbol, target_addr, access_offset, scaled_constraints in candidates:
                if value in seen_values:
                    continue
                seen_values.add(value)
                constraints = list(scaled_constraints) + [
                    symbol == value,
                    addr_symbol == target_addr,
                ]
                if try_add_constraint_set_fast(constraints, timeout_ms=HEURISTIC_SOLVER_TIMEOUT_MS):
                    used_stack_offsets.append((access_offset, INIT_ACCESS_SLOT_WIDTH))
                    return value
            return None

        def choose_memory_value(
            expr,
            preferred=None,
            avoid_stack_offsets=None,
            pointer_like=False,
            min_pointer_offset=None,
            allow_pointer_scalar_fallback=True,
        ):
            avoid_stack_offsets = [] if avoid_stack_offsets is None else avoid_stack_offsets
            if pointer_like:
                offset_expr = init_sp - expr
                pointer_vars = expr_vars(expr)
                start_offset = INIT_PTR_MIN_OFFSET if min_pointer_offset is None else max(0, min_pointer_offset)
                start_offset = _align_up(start_offset, INIT_ACCESS_ALIGN)
                long_block = len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                pointer_candidate_limit = 4 if long_block else 32
                pointer_eval_limit = 4 if long_block else 128
                pointer_confirm_timeout_ms = local_solver_timeout_ms if long_block else 5000
                pointer_store_relative_offsets = None

                def get_pointer_store_relative_offsets():
                    nonlocal pointer_store_relative_offsets
                    if pointer_store_relative_offsets is not None:
                        return pointer_store_relative_offsets
                    result = []
                    if pointer_vars:
                        checked = 0
                        for access_inst, access_addr_symbol, _, access_width in mem_accesses:
                            if not (expr_vars(access_addr_symbol) & pointer_vars):
                                continue
                            if long_block:
                                if checked >= 8:
                                    break
                                if ast_node_count(access_addr_symbol) > 96 or ast_node_count(expr) > 96:
                                    continue
                                checked += 1
                            residual = claripy.simplify(access_addr_symbol - expr)
                            if expr_vars(residual) & pointer_vars:
                                continue
                            residual_value = concrete_expr_value(residual)
                            if residual_value is None:
                                continue
                            result.append((_signed_u64(residual_value), init_slot_width(access_width)))
                    pointer_store_relative_offsets = result
                    return pointer_store_relative_offsets

                def pointer_store_ranges_for_offset(offset):
                    ranges = [(offset, 8)]
                    for imm, store_width in get_pointer_store_relative_offsets():
                        access_offset = offset - imm
                        if access_offset <= 0 or access_offset > STACK_RANGE:
                            return None
                        ranges.append((access_offset, store_width))
                    return ranges

                def pointer_offset_conflicts(offset, avoid_ranges):
                    ranges = pointer_store_ranges_for_offset(offset)
                    if ranges is None:
                        return True
                    return any(
                        concrete_ranges_overlap(access_offset, access_width, used_offset, used_width)
                        for access_offset, access_width in ranges
                        for used_offset, used_width in avoid_ranges
                    )

                def next_available_pointer_offset(offset, avoid_ranges):
                    offset = _align_up(max(offset, start_offset), INIT_ACCESS_ALIGN)
                    while offset <= STACK_RANGE:
                        if not pointer_offset_conflicts(offset, avoid_ranges):
                            return offset
                        offset += INIT_ACCESS_ALIGN
                    return None

                def pointer_offset_candidates(avoid_ranges, limit=None):
                    starts = [start_offset]
                    starts.extend(used_offset + max(8, used_width) for used_offset, used_width in avoid_ranges)
                    yielded = 0
                    seen_offsets = set()
                    for start in sorted(starts):
                        offset = next_available_pointer_offset(start, avoid_ranges)
                        while offset is not None and offset <= STACK_RANGE and offset not in seen_offsets:
                            seen_offsets.add(offset)
                            yield offset
                            yielded += 1
                            if limit is not None and yielded >= limit:
                                return
                            offset = next_available_pointer_offset(offset + INIT_ACCESS_ALIGN, avoid_ranges)

                def choose_pointer_offset(offset, relaxed=False):
                    if not relaxed and pointer_offset_conflicts(offset, avoid_stack_offsets):
                        return None
                    value = concrete_stack_addr(offset)
                    if satisfiable_with(expr, value):
                        candidate_solver.add(expr == value)
                        if verbose:
                            label = 'choose_pointer_like_relaxed_selected' if relaxed else 'choose_pointer_like_selected'
                            print(label, str(expr), offset)
                        return value
                    if not relaxed and try_add_constraint(expr == expr_bvv(value, expr), timeout_ms=pointer_confirm_timeout_ms):
                        if verbose:
                            print('choose_pointer_like_confirmed_selected', str(expr), offset)
                        return value
                    if satisfiable_with(offset_expr, offset):
                        candidate_solver.add(offset_expr == offset)
                        if verbose:
                            label = 'choose_pointer_like_relaxed_selected' if relaxed else 'choose_pointer_like_selected'
                            print(label, str(expr), offset)
                        return value
                    if not relaxed and try_add_constraint(offset_expr == offset, timeout_ms=pointer_confirm_timeout_ms):
                        if verbose:
                            print('choose_pointer_like_offset_confirmed_selected', str(expr), offset)
                        return value
                    return None

                if start_offset == 0:
                    for offset in pointer_offset_candidates(avoid_stack_offsets, limit=pointer_candidate_limit):
                        value = choose_pointer_offset(offset)
                        if value is not None:
                            return value

                anchored_candidates = []
                if preferred is not None:
                    anchored_candidates.append(preferred)
                if long_block:
                    write_stage(
                        "init:materialize_init:memory_values:slot",
                        phase="pointer_anchored_eval",
                        pointer_like=True,
                    )
                    anchored_candidates.extend(solver_eval_limited(expr, n=1, timeout_ms=100))
                else:
                    minimum = solver_min(expr)
                    if minimum is not None:
                        anchored_candidates.append(minimum)
                    anchored_candidates.extend(solver_eval_with(expr, [], n=8))
                seen_anchored = set()
                anchored_scalar = None
                for value in anchored_candidates:
                    value &= ((1 << 64) - 1)
                    if value in seen_anchored:
                        continue
                    seen_anchored.add(value)
                    offset = stack_offset_for_value(value)
                    if offset is None:
                        if anchored_scalar is None and satisfiable_with(expr, value):
                            anchored_scalar = value
                        continue
                    if offset % INIT_ACCESS_ALIGN != 0:
                        if anchored_scalar is None and satisfiable_with(expr, value):
                            anchored_scalar = value
                        continue
                    if offset < start_offset or offset > STACK_RANGE:
                        if offset <= STACK_RANGE and anchored_scalar is None and satisfiable_with(expr, value):
                            anchored_scalar = value
                        continue
                    if any(
                        concrete_ranges_overlap(offset, 8, used_offset, used_width)
                        for used_offset, used_width in avoid_stack_offsets
                    ):
                        continue
                    if pointer_offset_conflicts(offset, avoid_stack_offsets):
                        continue
                    if satisfiable_with(expr, value):
                        candidate_solver.add(expr == value)
                        if verbose:
                            print('choose_pointer_like_anchored_selected', str(expr), offset)
                        return value

                if verbose:
                    print('choose_pointer_like', {
                        'expr': str(expr),
                        'preferred': preferred,
                        'start_offset': start_offset,
                        'avoid': avoid_stack_offsets,
                    })
                extra_constraints = value_selection_constraints(
                    offset_expr,
                    positive=True,
                    align=INIT_ACCESS_ALIGN,
                    avoid=avoid_stack_offsets,
                    width=8,
                )
                extra_constraints.append(claripy.UGE(offset_expr, claripy.BVV(start_offset, 64)))
                if long_block:
                    write_stage(
                        "init:materialize_init:memory_values:slot",
                        phase="pointer_candidates",
                        pointer_like=True,
                    )
                for offset in pointer_offset_candidates(avoid_stack_offsets, limit=pointer_candidate_limit):
                    value = choose_pointer_offset(offset)
                    if value is not None:
                        return value
                if long_block:
                    write_stage(
                        "init:materialize_init:memory_values:slot",
                        phase="pointer_eval",
                        pointer_like=True,
                    )
                else:
                    for offset in [solver_min_with(offset_expr, extra_constraints)]:
                        if offset is None:
                            continue
                        if offset < start_offset:
                            continue
                        value = choose_pointer_offset(offset)
                        if value is not None:
                            return value
                for offset in solver_eval_with(offset_expr, extra_constraints, n=pointer_eval_limit):
                    if offset < start_offset:
                        continue
                    value = choose_pointer_offset(offset)
                    if value is not None:
                        return value
                if verbose:
                    print('choose_pointer_like_failed', str(expr), str(offset_expr))
                if long_block and preferred is not None:
                    preferred_offset = stack_offset_for_value(preferred)
                    if (
                        preferred_offset is not None
                        and preferred_offset >= start_offset
                        and preferred_offset <= STACK_RANGE
                        and preferred_offset % INIT_ACCESS_ALIGN == 0
                    ):
                        if verbose:
                            print('choose_pointer_like_direct_preferred_selected', str(expr), preferred_offset)
                        return preferred & ((1 << 64) - 1)
                relaxed_constraints = value_selection_constraints(
                    offset_expr,
                    positive=True,
                    align=INIT_ACCESS_ALIGN,
                    width=8,
                )
                relaxed_constraints.append(claripy.UGE(offset_expr, claripy.BVV(start_offset, 64)))
                if long_block:
                    write_stage(
                        "init:materialize_init:memory_values:slot",
                        phase="pointer_relaxed_candidates",
                        pointer_like=True,
                    )
                for offset in pointer_offset_candidates([], limit=pointer_candidate_limit):
                    value = choose_pointer_offset(offset, relaxed=True)
                    if value is not None:
                        return value
                if long_block:
                    write_stage(
                        "init:materialize_init:memory_values:slot",
                        phase="pointer_relaxed_eval",
                        pointer_like=True,
                    )
                else:
                    for offset in [solver_min_with(offset_expr, relaxed_constraints)]:
                        if offset is None or offset < start_offset:
                            continue
                        value = choose_pointer_offset(offset, relaxed=True)
                        if value is not None:
                            return value
                for offset in solver_eval_with(offset_expr, relaxed_constraints, n=pointer_eval_limit):
                    if offset < start_offset:
                        continue
                    value = choose_pointer_offset(offset, relaxed=True)
                    if value is not None:
                        return value
                if anchored_scalar is not None and allow_pointer_scalar_fallback:
                    candidate_solver.add(expr == anchored_scalar)
                    if verbose:
                        print('choose_pointer_like_scalar_anchored_selected', str(expr), anchored_scalar)
                    return anchored_scalar
                if allow_pointer_scalar_fallback:
                    for scalar_value in (0,):
                        if satisfiable_with(expr, scalar_value):
                            candidate_solver.add(expr == expr_bvv(scalar_value, expr))
                            if verbose:
                                print('choose_pointer_like_scalar_fallback_selected', str(expr), scalar_value)
                            return scalar_value
                raise AssertionError(f"cannot choose stack pointer value for {expr}")

            choices = []
            if preferred is not None:
                choices.append(preferred)
            choices.append(0)

            seen = set()
            for val in choices:
                if val in seen:
                    continue
                seen.add(val)
                stack_offset = stack_offset_for_value(val)
                if stack_offset is not None and any(
                    concrete_ranges_overlap(stack_offset, 8, used_offset, used_width)
                    for used_offset, used_width in avoid_stack_offsets
                ):
                    continue
                if satisfiable_with(expr, val):
                    candidate_solver.add(expr == val)
                    return val

            minimum = solver_min(expr)
            if minimum is not None:
                choices = [minimum]
                for i in range(1, 64):
                    choices.append(minimum + i * 8)
            else:
                choices = []

            for val in choices:
                if val in seen:
                    continue
                seen.add(val)
                stack_offset = stack_offset_for_value(val)
                if stack_offset is not None and any(
                    concrete_ranges_overlap(stack_offset, 8, used_offset, used_width)
                    for used_offset, used_width in avoid_stack_offsets
                ):
                    continue
                if satisfiable_with(expr, val):
                    candidate_solver.add(expr == val)
                    return val

            return choose_value(expr, preferred)

        def choose_mem_slot_value(word_offset, slot):
            if 'chosen_value' in slot:
                return slot['chosen_value']
            val_symbol = slot.get('direct_value_expr', slot['symbol'])
            used_mem_offsets = [
                (used_addr, 8)
                for used_addr, used_slot in mem_slot_symbols.items()
                if used_addr != word_offset
            ]
            used_mem_offsets.extend((used_addr, 8) for used_addr in mem_values)
            preferred_offset = None
            preferred_value = None
            if slot.get('pointer_like'):
                preferred_offset = next_free_stack_offset(
                    used_mem_offsets,
                    align=INIT_ACCESS_ALIGN,
                    width=INIT_ACCESS_SLOT_WIDTH,
                    start=max(INIT_PTR_MIN_OFFSET, slot.get('min_pointer_offset') or 0),
                )
                if preferred_offset is not None:
                    preferred_value = concrete_stack_addr(preferred_offset)
            write_stage(
                "init:materialize_init:memory_values:slot",
                offset=word_offset,
                phase="choose_value",
                pointer_like=bool(slot.get('pointer_like')),
                sp_affine=bool(slot.get('sp_affine')),
            )
            if (
                (len(mem_entries) >= 3 or word_offset > STACK_RANGE)
                and slot.get('pointer_like')
            ):
                if preferred_value is None:
                    fallback_offset = _align_up(
                        max(INIT_PTR_MIN_OFFSET, slot.get('min_pointer_offset') or 0),
                        INIT_ACCESS_ALIGN,
                    )
                    if fallback_offset > STACK_RANGE:
                        fallback_offset = INIT_PTR_MIN_OFFSET
                    preferred_value = concrete_stack_addr(fallback_offset)
                actual_value = preferred_value & ((1 << 64) - 1)
                if try_add_constraint_set_fast(
                    [val_symbol == expr_bvv(actual_value, val_symbol)],
                    timeout_ms=local_solver_timeout_ms,
                ):
                    slot['chosen_value'] = actual_value
                    write_stage(
                        "init:materialize_init:memory_values:slot",
                        offset=word_offset,
                        phase="chosen",
                        pointer_like=True,
                        sp_affine=bool(slot.get('sp_affine')),
                    )
                    return actual_value
            val_vars = expr_vars(val_symbol)
            pointer_feeds_later_store = bool(val_vars) and any(
                expr_vars(store_addr_symbol) & val_vars
                for _, store_addr_symbol, _, _, _ in store_accesses
            )
            if slot.get('pointer_like') and preferred_offset is not None and not pointer_feeds_later_store:
                offset = preferred_offset
                attempts = 0
                max_pointer_slot_attempts = 2 if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD else 32
                pointer_slot_timeout_ms = 100 if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD else 1000
                while offset is not None and attempts < max_pointer_slot_attempts:
                    value = concrete_stack_addr(offset)
                    if try_add_constraint_set_fast(
                        [val_symbol == expr_bvv(value, val_symbol)],
                        timeout_ms=pointer_slot_timeout_ms,
                    ):
                        actual_value = value & ((1 << 64) - 1)
                        slot['chosen_value'] = actual_value
                        write_stage(
                            "init:materialize_init:memory_values:slot",
                            offset=word_offset,
                            phase="chosen",
                            pointer_like=True,
                            sp_affine=bool(slot.get('sp_affine')),
                        )
                        return actual_value
                    attempts += 1
                    offset = next_free_stack_offset(
                        used_mem_offsets,
                        align=INIT_ACCESS_ALIGN,
                        width=INIT_ACCESS_SLOT_WIDTH,
                        start=offset + INIT_ACCESS_ALIGN,
                    )
                if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD:
                    offset = _align_up(max(INIT_PTR_MIN_OFFSET, slot.get('min_pointer_offset') or 0), INIT_ACCESS_ALIGN)
                    relaxed_attempts = 0
                    while offset <= STACK_RANGE and relaxed_attempts < 4:
                        value = concrete_stack_addr(offset)
                        if try_add_constraint_set_fast(
                            [val_symbol == expr_bvv(value, val_symbol)],
                            timeout_ms=100,
                        ):
                            actual_value = value & ((1 << 64) - 1)
                            slot['chosen_value'] = actual_value
                            write_stage(
                                "init:materialize_init:memory_values:slot",
                                offset=word_offset,
                                phase="chosen",
                                pointer_like=True,
                                sp_affine=bool(slot.get('sp_affine')),
                            )
                            return actual_value
                        relaxed_attempts += 1
                        offset += INIT_ACCESS_ALIGN
            if (
                slot.get('scalar_zero')
                and not slot.get('pointer_like')
                and not slot.get('sp_affine')
                and not slot.get('must_be_pointer')
            ):
                zero_constraint = val_symbol == expr_bvv(0, val_symbol)
                if try_add_constraint_set_fast([zero_constraint], timeout_ms=local_solver_timeout_ms):
                    val = 0
                    slot['chosen_value'] = val
                    write_stage(
                        "init:materialize_init:memory_values:slot",
                        offset=word_offset,
                        phase="chosen",
                        pointer_like=False,
                        sp_affine=False,
                    )
                    return val
            if (
                len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                and not slot.get('pointer_like')
                and not slot.get('sp_affine')
                and not slot.get('must_be_pointer')
            ):
                val = 0
                slot['chosen_value'] = val
                write_stage(
                    "init:materialize_init:memory_values:slot",
                    offset=word_offset,
                    phase="chosen",
                    pointer_like=False,
                    sp_affine=False,
                )
                return val
            try:
                val = choose_memory_value(
                    val_symbol,
                    preferred_value,
                    avoid_stack_offsets=used_mem_offsets,
                    pointer_like=slot['pointer_like'],
                    min_pointer_offset=slot.get('min_pointer_offset'),
                    allow_pointer_scalar_fallback=not slot.get('must_be_pointer'),
                )
            except AssertionError:
                if slot.get('pointer_like') or slot.get('sp_affine'):
                    raise
                val = 0
                if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD:
                    candidate_solver.add(val_symbol == expr_bvv(val, val_symbol))
                elif not try_add_constraint_set_fast([val_symbol == expr_bvv(val, val_symbol)]):
                    raise
            actual_value = val & ((1 << 64) - 1)
            slot['chosen_value'] = actual_value
            write_stage(
                "init:materialize_init:memory_values:slot",
                offset=word_offset,
                phase="chosen",
                pointer_like=bool(slot.get('pointer_like')),
                sp_affine=bool(slot.get('sp_affine')),
            )
            return actual_value

        def next_free_stack_offset(avoid_ranges, align=1, width=INIT_ACCESS_SLOT_WIDTH, start=1):
            align = align if align else 1
            offset = _align_up(start, align)
            while offset <= STACK_RANGE:
                if not any(
                    concrete_ranges_overlap(offset, width, used_offset, used_width)
                    for used_offset, used_width in avoid_ranges
                ):
                    return offset
                offset += align
            return None

        def min_offset_for_affine_base(base_key):
            if base_key in affine_base_min_offset_cache:
                return affine_base_min_offset_cache[base_key]
            minimum = INIT_PTR_MIN_OFFSET
            for _, access_addr_symbol, _, access_width in mem_accesses:
                if (
                    len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                    and ast_node_count(access_addr_symbol) > 64
                ):
                    continue
                access_affine = affine_key(access_addr_symbol)
                if access_affine is None:
                    continue
                access_base_key, access_imm, _ = access_affine
                if access_base_key != base_key:
                    continue
                minimum = max(minimum, access_imm + access_width)
            minimum = _align_up(max(INIT_PTR_MIN_OFFSET, minimum), INIT_ACCESS_ALIGN)
            affine_base_min_offset_cache[base_key] = minimum
            return minimum

        def choose_affine_addr_offset(addr_symbol, addr_expr, preferred, align, avoid_ranges, width):
            if not address_narrow_source_loads:
                return None
            if (
                len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                and ast_node_count(addr_symbol) > 64
            ):
                return None
            affine = affine_key(addr_symbol)
            if affine is None:
                return None
            base_key, imm, base = affine
            if not expr_vars(base):
                return None
            step = align if align else 1

            def access_ok(access_offset):
                if access_offset <= 0 or access_offset > STACK_RANGE:
                    return False
                if align and access_offset % align != 0:
                    return False
                if any(
                    concrete_ranges_overlap(access_offset, width, used, used_width)
                    for used, used_width in avoid_ranges
                ):
                    return False
                return True

            if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                for reg, value in reg_values.items():
                    symbol = reg_to_symbol.get(reg)
                    if symbol is None or expr_key(symbol) != base_key:
                        continue
                    base_offset = stack_offset_for_value(value)
                    if base_offset is None:
                        continue
                    access_offset = base_offset - imm
                    if access_ok(access_offset):
                        candidate_solver.add(addr_expr == access_offset)
                        affine_base_offset_choices[base_key] = base_offset
                        return access_offset

            cached_base_offset = affine_base_offset_choices.get(base_key)
            if cached_base_offset is not None:
                access_offset = cached_base_offset - imm
                if access_ok(access_offset):
                    candidate_solver.add(addr_expr == access_offset)
                    return access_offset
                return None

            if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                return None

            starts = []
            if preferred is not None:
                starts.append(preferred + imm)
            starts.append(min_offset_for_affine_base(base_key))
            starts.extend(used + max(width, used_width) + imm for used, used_width in avoid_ranges)

            seen_base_offsets = set()
            attempts = 0
            max_attempts = 2 if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD else 8
            for start in sorted(starts):
                base_start = _align_up(max(start, min_offset_for_affine_base(base_key)), INIT_ACCESS_ALIGN)
                for base_offset in range(base_start, min(STACK_RANGE, base_start + 512) + 1, INIT_ACCESS_ALIGN):
                    if attempts >= max_attempts:
                        return None
                    if base_offset in seen_base_offsets:
                        continue
                    seen_base_offsets.add(base_offset)
                    access_offset = base_offset - imm
                    if not access_ok(access_offset):
                        continue
                    attempts += 1
                    constraints = [
                        (init_sp - base) == base_offset,
                        addr_expr == access_offset,
                    ]
                    if (
                        try_add_constraint_set_fast(constraints)
                        if len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                        else try_add_constraint_set(constraints)
                    ):
                        affine_base_offset_choices[base_key] = base_offset
                        return access_offset
            return None

        def choose_pointer_load_addr_offset(addr_symbol, addr_expr, preferred, align, avoid_ranges, width):
            long_block = len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
            if long_block and ast_node_count(addr_symbol) > 512:
                return None
            addr_vars = expr_vars(addr_symbol)
            source_load_candidates = []
            seen_source_loads = set()
            for load_entry in pointer_source_loads + address_source_loads:
                load_inst, rd_symbol, load_addr_symbol, load_idx = load_entry
                key = (load_idx, expr_key(rd_symbol))
                if key in seen_source_loads:
                    continue
                if key in scalar_load_hint_keys:
                    continue
                seen_source_loads.add(key)
                source_load_candidates.append(load_entry)
            for _, rd_symbol, load_addr_symbol, load_idx in source_load_candidates:
                rd_vars = expr_vars(rd_symbol)
                if not rd_vars or not (addr_vars & rd_vars):
                    continue
                residual = claripy.simplify(addr_symbol - rd_symbol)
                affine_residual_value = None
                if expr_vars(residual) & rd_vars:
                    affine = affine_key(addr_symbol)
                    if affine is None or affine[0] != expr_key(rd_symbol):
                        continue
                    affine_residual_value = affine[1]
                residual_value = concrete_expr_value(residual)
                if residual_value is None and affine_residual_value is not None:
                    residual_value = affine_residual_value
                residual_options = []
                if residual_value is not None:
                    residual_options.append((residual_value, [], True))
                else:
                    seen_residual_targets = set()
                    for residual_target in (-4, 0, 4, 8, 16):
                        target_key = residual_target & ((1 << 64) - 1)
                        if target_key in seen_residual_targets:
                            continue
                        seen_residual_targets.add(target_key)
                        residual_constraints = constraints_to_constant(
                            residual,
                            target_key,
                            forbidden_vars=rd_vars,
                        )
                        if residual_constraints is None:
                            continue
                        residual_options.append((residual_target, residual_constraints, False))
                if not residual_options:
                    continue
                load_addr_key = expr_key(load_addr_symbol)
                load_offset = addr_expr_offsets.get(load_addr_key)
                for residual_value, residual_constraints, residual_is_concrete in residual_options:
                    imm = _signed_u64(residual_value)
                    pointer_avoid_ranges = (
                        [(load_offset, INIT_ACCESS_SLOT_WIDTH)]
                        if load_offset is not None
                        else None
                    )
                    base_start = min_pointer_offset_for_vars(
                        rd_vars,
                        load_idx,
                        avoid_ranges=pointer_avoid_ranges,
                    )
                    if imm >= 0:
                        base_start = max(base_start, imm + width)
                    if load_offset is not None:
                        source_slot = mem_slot_symbols.get(load_offset)
                        source_value = None if source_slot is None else source_slot.get('chosen_value')
                        source_pointer_offset = None if source_value is None else stack_offset_for_value(source_value)
                        if source_pointer_offset is not None:
                            access_offset = source_pointer_offset - imm
                            if (
                                access_offset > 0
                                and access_offset <= STACK_RANGE
                                and (not align or access_offset % align == 0)
                                and source_pointer_offset >= base_start
                                and source_pointer_offset % INIT_ACCESS_ALIGN == 0
                                and not any(
                                    concrete_ranges_overlap(access_offset, width, used, used_width)
                                    for used, used_width in avoid_ranges
                                )
                            ):
                                constraints = list(residual_constraints) + [
                                    (init_sp - rd_symbol) == source_pointer_offset,
                                    addr_expr == access_offset,
                                ]
                                if try_add_constraint_set_fast(constraints, timeout_ms=5000):
                                    return access_offset
                    starts = []
                    if preferred is not None:
                        starts.append(preferred)
                    if long_block and residual_constraints:
                        starts.extend([0x200 - imm, 0x400 - imm, 0x800 - imm, 0xc00 - imm])
                    low = _align_up(1, align) if align else 1
                    starts.append(low)
                    starts.append(base_start - imm)
                    starts.extend(used + max(width, used_width) for used, used_width in avoid_ranges)
                    seen_offsets = set()
                    step = align if align else 1
                    attempts = 0
                    max_attempts = 64 if long_block and residual_constraints else 16
                    for start in starts:
                        start = max(start, low)
                        if align:
                            start = _align_up(start, align)
                        for access_offset in range(start, min(STACK_RANGE, start + 256) + 1, step):
                            if attempts >= max_attempts:
                                break
                            if access_offset in seen_offsets:
                                continue
                            seen_offsets.add(access_offset)
                            if access_offset <= 0 or access_offset > STACK_RANGE:
                                continue
                            if align and access_offset % align != 0:
                                continue
                            if any(concrete_ranges_overlap(access_offset, width, used, used_width) for used, used_width in avoid_ranges):
                                continue
                            pointer_offset = access_offset + imm
                            if pointer_offset <= 0 or pointer_offset > STACK_RANGE:
                                continue
                            if pointer_offset < base_start:
                                continue
                            if pointer_offset % INIT_ACCESS_ALIGN != 0:
                                continue
                            attempts += 1
                            if preferred is not None and access_offset == preferred:
                                constraints = list(residual_constraints) + [
                                    (init_sp - rd_symbol) == pointer_offset,
                                    addr_expr == access_offset,
                                ]
                                if try_add_constraint_set_fast(constraints, timeout_ms=5000):
                                    return access_offset
                            constraints = list(residual_constraints) + [
                                (init_sp - rd_symbol) == pointer_offset,
                                addr_expr == access_offset,
                            ]
                            if not try_add_constraint_set_fast(
                                constraints,
                                timeout_ms=5000,
                            ):
                                continue
                            return access_offset
            return None

        def choose_carrier_residual_stack_offset(addr_symbol, addr_expr, preferred, align, avoid_ranges, width):
            if preferred is None:
                return None
            addr_vars = expr_vars(addr_symbol)
            small_residual_targets = [0, 1, 2, 4, 8, 16]
            carrier_symbols = [(symbol, True) for symbol in reg_to_symbol.values()]
            carrier_symbols.extend(
                (rd_symbol, False)
                for load_inst, rd_symbol, _, _ in load_accesses
                if load_inst.width == 8
            )
            seen_carriers = set()
            for symbol, allow_direct_add in carrier_symbols:
                carrier_key = expr_key(symbol)
                if carrier_key in seen_carriers:
                    continue
                seen_carriers.add(carrier_key)
                symbol_vars = expr_vars(symbol)
                if not symbol_vars or not (addr_vars & symbol_vars):
                    continue
                residual = claripy.simplify(addr_symbol - symbol)
                if expr_vars(residual) & symbol_vars:
                    continue
                residual_targets = []
                residual_value = concrete_expr_value(residual)
                if residual_value is not None:
                    residual_targets.append(_signed_u64(residual_value))
                residual_targets.extend(small_residual_targets)
                seen_targets = set()
                for residual_target in residual_targets:
                    if residual_target in seen_targets:
                        continue
                    seen_targets.add(residual_target)
                    access_offset = preferred
                    if access_offset <= 0 or access_offset > STACK_RANGE:
                        continue
                    if align and access_offset % align != 0:
                        continue
                    if any(concrete_ranges_overlap(access_offset, width, used, used_width) for used, used_width in avoid_ranges):
                        continue
                    base_offset = access_offset + residual_target
                    if base_offset <= 0 or base_offset > STACK_RANGE:
                        continue
                    residual_constraints = constraints_to_constant(
                        residual,
                        residual_target & ((1 << 64) - 1),
                        forbidden_vars=symbol_vars,
                    )
                    if residual_constraints is None:
                        residual_constraints = [residual == expr_bvv(residual_target, residual)]
                    constraints = list(residual_constraints) + [
                        (init_sp - symbol) == base_offset,
                        addr_expr == access_offset,
                    ]
                    if try_add_constraint_set_fast(constraints, timeout_ms=5000):
                        return access_offset
            return None

        reserved_base_access_ranges = []
        used_stack_offsets = []
        scalar_offset = 0
        sp_affine_mem_offsets = {}

        debug_unsat_stages = os.environ.get("RVMCA_DEBUG_UNSAT") == "1"
        def debug_check_stage(stage):
            if not debug_unsat_stages:
                return
            result = None
            try:
                check_solver = candidate_solver.branch()
                check_solver.timeout = local_solver_timeout_ms
                result = check_solver.satisfiable()
            except Exception as exc:
                result = f"error:{type(exc).__name__}"
            print(f"debug_unsat_stage {stage}: {result}")

        _write_profile_stage(name, "init:materialize_init:global_constraints")
        _write_profile_stage(name, "init:materialize_init:global_constraints:loaded_pointer_scalar_offsets")
        add_loaded_pointer_scalar_offset_constraints()
        debug_check_stage("loaded_pointer_scalar_offsets")
        _write_profile_stage(name, "init:materialize_init:global_constraints:loaded_pointer_residual_anchor")
        add_loaded_pointer_residual_anchor_constraints()
        debug_check_stage("loaded_pointer_residual_anchor")
        _write_profile_stage(name, "init:materialize_init:global_constraints:livein_base_residual_anchor")
        add_livein_base_residual_anchor_constraints()
        debug_check_stage("livein_base_residual_anchor")
        _write_profile_stage(name, "init:materialize_init:global_constraints:mul_address_carrier")
        add_mul_address_carrier_constraints()
        debug_check_stage("mul_address_carrier")
        _write_profile_stage(name, "init:materialize_init:global_constraints:arithmetic_hints")
        if retry_index == 0 or len(mem_entries) < GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
            add_arithmetic_address_hint_constraints()
        debug_check_stage("arithmetic_hints")
        _write_profile_stage(name, "init:materialize_init:global_constraints:scalar_zero_address_loads")
        add_scalar_zero_address_load_constraints()
        debug_check_stage("scalar_zero_address_loads")
        _write_profile_stage(name, "init:materialize_init:global_constraints:livein_loaded_offset_base")
        add_livein_loaded_offset_base_constraints()
        debug_check_stage("livein_loaded_offset_base")
        _write_profile_stage(name, "init:materialize_init:global_constraints:loaded_addr_scalar_zero")
        add_loaded_address_scalar_zero_constraints()
        debug_check_stage("loaded_addr_scalar_zero")
        _write_profile_stage(name, "init:materialize_init:global_constraints:direct_loaded_pointer_stack")
        add_direct_loaded_pointer_stack_constraints()
        debug_check_stage("direct_loaded_pointer_stack")
        _write_profile_stage(name, "init:materialize_init:global_constraints:pointer_scalar_load_slot_no_overlap")
        add_pointer_scalar_load_slot_no_overlap_constraints()
        debug_check_stage("pointer_scalar_load_slot_no_overlap")
        _write_profile_stage(name, "init:materialize_init:global_constraints:access_range")
        add_access_range_constraints()
        debug_check_stage("access_range")
        _write_profile_stage(name, "init:materialize_init:global_constraints:memory_dataflow")
        add_memory_dataflow_constraints()
        debug_check_stage("memory_dataflow")
        _write_profile_stage(name, "init:materialize_init:global_constraints:store_pointer_sources")
        if retry_index == 0 or len(mem_entries) < GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
            add_store_pointer_source_constraints()
        debug_check_stage("store_pointer_sources")
        _write_profile_stage(name, "init:materialize_init:global_constraints:load_slot_no_overlap")
        add_load_slot_no_overlap_constraints()
        debug_check_stage("load_slot_no_overlap")
        _write_profile_stage(name, "init:materialize_init:global_constraints:pointer_load_slot_no_overlap")
        add_pointer_load_slot_no_overlap_constraints()
        debug_check_stage("pointer_load_slot_no_overlap")
        _write_profile_stage(name, "init:materialize_init:global_constraints:pointer_derived_slot_no_overlap")
        add_pointer_derived_access_slot_no_overlap_constraints()
        debug_check_stage("pointer_derived_slot_no_overlap")
        _write_profile_stage(name, "init:materialize_init:global_constraints:pointer_value_no_alias")
        add_pointer_value_no_alias_constraints()
        debug_check_stage("pointer_value_no_alias")
        _write_profile_stage(name, "init:materialize_init:global_constraints:pointer_anchor")
        add_pointer_anchor_simplification_constraints()
        debug_check_stage("pointer_anchor")
        _write_profile_stage(name, "init:materialize_init:global_constraints:register_anchor")
        add_register_anchor_simplification_constraints()
        debug_check_stage("register_anchor")
        _write_profile_stage(name, "init:materialize_init:global_constraints:store_load_slot_no_overlap")
        add_store_load_slot_no_overlap_constraints()
        debug_check_stage("store_load_slot_no_overlap")
        _write_profile_stage(name, "init:materialize_init:global_constraints:risky_source_no_overlap")
        add_risky_source_no_overlap_constraints()
        debug_check_stage("risky_source_no_overlap")
        _write_profile_stage(name, "init:materialize_init:global_constraints:pointer_slot_store_no_overlap")
        add_pointer_slot_store_no_overlap_constraints()
        debug_check_stage("pointer_slot_store_no_overlap")
        _write_profile_stage(name, "init:materialize_init:global_constraints:done")

        loaded_addr_vars = set()
        for load_inst, rd_symbol, _, load_idx in load_accesses:
            rd_vars = getattr(rd_symbol, 'variables', set())
            if not rd_vars:
                continue
            for _, addr_symbol, access_idx, _ in mem_accesses:
                if access_idx > load_idx and (getattr(addr_symbol, 'variables', set()) & rd_vars):
                    loaded_addr_vars.update(rd_vars)
                    break

        fixed_reg_value_hints = {}
        def has_nonlinear_address_use_for_reg(reg):
            symbol = reg_to_symbol.get(reg)
            if symbol is None:
                return False
            symbol_vars = expr_vars(symbol)
            if not symbol_vars:
                return False
            nonlinear_ops = {'__mul__', 'Mul', '__floordiv__', '__truediv__', '__div__', 'SDiv', 'UDiv'}
            for _, addr_symbol, _, _ in mem_accesses:
                if not (expr_vars(addr_symbol) & symbol_vars):
                    continue
                for node in iter_ast_nodes(addr_symbol):
                    if getattr(node, 'op', '') in nonlinear_ops and (expr_vars(node) & symbol_vars):
                        return True
            return False

        for reg, values in reg_value_hints.items():
            if reg not in reg_to_symbol:
                continue
            if not has_nonlinear_address_use_for_reg(reg):
                continue
            unique_hint_values = []
            seen_hint_values = set()
            for value in values:
                value &= ((1 << 64) - 1)
                if value in seen_hint_values:
                    continue
                seen_hint_values.add(value)
                unique_hint_values.append(value)
            if len(unique_hint_values) == 1:
                fixed_reg_value_hints[reg] = unique_hint_values[0]

        base_like_regs = set()
        base_like_sources = {}
        reg_min_stack_offsets = {}
        reg_defined_before_access_cache = {}

        def reg_defined_before_access(reg, access_idx):
            key = (reg, access_idx)
            if key not in reg_defined_before_access_cache:
                reg_defined_before_access_cache[key] = any(
                    getattr(prev_inst, 'get_def', lambda: None)() == reg
                    for prev_inst in prog2se.insts[:access_idx]
                )
            return reg_defined_before_access_cache[key]

        for reg, min_offset in register_anchor_min_offsets.items():
            if reg in reg_to_symbol:
                base_like_regs.add(reg)
                base_like_sources.setdefault(reg, 'register_anchor')
                reg_min_stack_offsets[reg] = _align_up(min_offset, INIT_ACCESS_ALIGN)
        for reg in undef_base_regs:
            if reg in reg_to_symbol:
                symbol_vars = expr_vars(reg_to_symbol[reg])
                if symbol_vars and not any(
                    expr_vars(addr_symbol) & symbol_vars
                    for _, addr_symbol, _, _ in mem_accesses
                ):
                    continue
                if symbol_vars and not any(
                    (expr_vars(addr_symbol) & symbol_vars)
                    and not reg_defined_before_access(reg, access_idx)
                    and not (
                        expr_vars(claripy.simplify(addr_symbol - reg_to_symbol[reg]))
                        & symbol_vars
                    )
                    for _, addr_symbol, access_idx, _ in mem_accesses
                ):
                    continue
                base_like_regs.add(reg)
                base_like_sources.setdefault(reg, 'undef_base')
                reg_min_stack_offsets[reg] = max(
                    reg_min_stack_offsets.get(reg, INIT_PTR_MIN_OFFSET),
                    INIT_PTR_MIN_OFFSET,
                )
        for reg in reg_to_symbol:
            symbol_vars = expr_vars(reg_to_symbol[reg])
            for inst, addr_symbol, access_idx, width in mem_accesses:
                if getattr(inst, 'rs1', None) != reg:
                    continue
                if reg_defined_before_access(reg, access_idx):
                    continue
                if symbol_vars and not (expr_vars(addr_symbol) & symbol_vars):
                    continue
                base_like_regs.add(reg)
                base_like_sources.setdefault(reg, 'direct_livein_rs1')
                min_offset = reg_min_stack_offsets.get(reg, INIT_PTR_MIN_OFFSET)
                imm = _signed_u64(inst.imm)
                if imm >= 0:
                    min_offset = max(min_offset, imm + width)
                reg_min_stack_offsets[reg] = _align_up(min_offset, INIT_ACCESS_ALIGN)
        for reg, symbol in reg_to_symbol.items():
            symbol_vars = getattr(symbol, 'variables', set())
            if not symbol_vars:
                continue
            for inst, addr_symbol, _, width in mem_accesses:
                if not (symbol_vars & getattr(addr_symbol, 'variables', set())):
                    continue
                residual = claripy.simplify(addr_symbol - symbol)
                residual_vars = getattr(residual, 'variables', set())
                if not (symbol_vars & residual_vars) and not (residual_vars & loaded_addr_vars):
                    base_like_regs.add(reg)
                    base_like_sources.setdefault(reg, 'additive_residual')
                    min_offset = reg_min_stack_offsets.get(reg, INIT_PTR_MIN_OFFSET)
                    residual_value = concrete_expr_value(residual)
                    if residual_value is not None:
                        imm = _signed_u64(residual_value)
                        if imm >= 0:
                            min_offset = max(min_offset, imm + width)
                    reg_min_stack_offsets[reg] = _align_up(min_offset, INIT_ACCESS_ALIGN)
            if reg in base_like_regs:
                continue

        direct_memory_base_like_regs = set()
        for reg in reg_to_symbol:
            symbol_vars = expr_vars(reg_to_symbol[reg])
            for inst, addr_symbol, _, _ in mem_accesses:
                if getattr(inst, 'rs1', None) != reg:
                    continue
                if symbol_vars and not (expr_vars(addr_symbol) & symbol_vars):
                    continue
                residual = claripy.simplify(addr_symbol - reg_to_symbol[reg])
                if expr_vars(residual) & symbol_vars:
                    continue
                if concrete_expr_value(residual) is None:
                    continue
                direct_memory_base_like_regs.add(reg)
                break

        loaded_pointer_scalar_regs = set()
        pointer_nonlinear_scalar_regs = set()
        for reg, symbol in reg_to_symbol.items():
            if reg not in base_like_regs:
                continue
            symbol_vars = expr_vars(symbol)
            if not symbol_vars:
                continue
            has_direct_livein_base_use = any(
                getattr(inst, 'rs1', None) == reg
                and (expr_vars(addr_symbol) & symbol_vars)
                for inst, addr_symbol, _, _ in mem_accesses
            )
            if has_direct_livein_base_use:
                continue
            addr_uses = [
                addr_symbol
                for _, addr_symbol, _, _ in mem_accesses
                if expr_vars(addr_symbol) & symbol_vars
            ]
            if not addr_uses:
                continue
            scalar_constrained = False
            for load_inst, rd_symbol, _, load_idx in load_accesses:
                if load_inst.width != 8:
                    continue
                rd_vars = expr_vars(rd_symbol)
                if not rd_vars:
                    continue
                for _, addr_symbol, access_idx, _ in mem_accesses:
                    if access_idx <= load_idx:
                        continue
                    addr_vars = expr_vars(addr_symbol)
                    if not (addr_vars & symbol_vars) or not (addr_vars & rd_vars):
                        continue
                    if (addr_vars & pointer_loaded_addr_vars) and not (rd_vars & pointer_loaded_addr_vars):
                        continue
                    residual_constraints = constraints_to_carrier(addr_symbol, rd_symbol)
                    if residual_constraints is None:
                        residual = claripy.simplify(addr_symbol - rd_symbol)
                        residual_vars = expr_vars(residual)
                        if (residual_vars & rd_vars) or not (residual_vars & symbol_vars):
                            continue
                        residual_constraints = constraints_to_constant(
                            residual,
                            0,
                            forbidden_vars=rd_vars,
                        )
                        if residual_constraints is None:
                            continue
                    if not any(expr_vars(constraint) & symbol_vars for constraint in residual_constraints):
                        continue
                    if try_add_constraint_set(residual_constraints):
                        loaded_pointer_scalar_regs.add(reg)
                        scalar_constrained = True
                        break
                if scalar_constrained:
                    break

        nonlinear_ops = {'__mul__', 'Mul', '__floordiv__', '__truediv__', '__div__', 'SDiv', 'UDiv'}
        for reg, symbol in reg_to_symbol.items():
            if reg not in base_like_regs:
                continue
            symbol_vars = expr_vars(symbol)
            if not symbol_vars:
                continue
            has_direct_livein_base_use = any(
                getattr(inst, 'rs1', None) == reg
                and (expr_vars(addr_symbol) & symbol_vars)
                for inst, addr_symbol, _, _ in mem_accesses
            )
            if has_direct_livein_base_use:
                continue
            for _, addr_symbol, _, _ in mem_accesses:
                addr_vars = expr_vars(addr_symbol)
                if not (addr_vars & symbol_vars) or not (addr_vars & pointer_loaded_addr_vars):
                    continue
                if any(
                    getattr(node, 'op', '') in nonlinear_ops
                    and (expr_vars(node) & symbol_vars)
                    for node in iter_ast_nodes(addr_symbol)
                ):
                    pointer_nonlinear_scalar_regs.add(reg)
                    break

        for reg in loaded_pointer_scalar_regs:
            if reg in direct_memory_base_like_regs:
                continue
            base_like_regs.discard(reg)
            base_like_sources.pop(reg, None)
            reg_min_stack_offsets.pop(reg, None)
        for reg in pointer_nonlinear_scalar_regs:
            if reg in direct_memory_base_like_regs:
                continue
            base_like_regs.discard(reg)
            base_like_sources.pop(reg, None)
            reg_min_stack_offsets.pop(reg, None)
        for reg in residual_scalar_regs:
            if reg in direct_memory_base_like_regs:
                continue
            base_like_regs.discard(reg)
            base_like_sources.pop(reg, None)
            reg_min_stack_offsets.pop(reg, None)
        for reg in fixed_reg_value_hints:
            if reg in direct_memory_base_like_regs:
                continue
            base_like_regs.discard(reg)
            base_like_sources.pop(reg, None)
            reg_min_stack_offsets.pop(reg, None)
        for reg in scalar_hint_regs:
            if reg in direct_memory_base_like_regs:
                continue
            if reg in register_anchor_min_offsets:
                continue
            base_like_regs.discard(reg)
            base_like_sources.pop(reg, None)
            reg_min_stack_offsets.pop(reg, None)

        if verbose:
            print('base_like_regs', [str(reg) for reg in sorted(base_like_regs, key=lambda r: r.id)])
            print('reg_min_stack_offsets', {str(reg): offset for reg, offset in reg_min_stack_offsets.items()})
            if loaded_pointer_scalar_regs:
                print('loaded_pointer_scalar_regs', [str(reg) for reg in sorted(loaded_pointer_scalar_regs, key=lambda r: r.id)])
            if pointer_nonlinear_scalar_regs:
                print('pointer_nonlinear_scalar_regs', [str(reg) for reg in sorted(pointer_nonlinear_scalar_regs, key=lambda r: r.id)])
            if residual_scalar_regs:
                print('residual_scalar_regs', [str(reg) for reg in sorted(residual_scalar_regs, key=lambda r: r.id)])
            print('base_like_sources', {str(reg): base_like_sources.get(reg) for reg in sorted(base_like_regs, key=lambda r: r.id)})

        deferred_regs = set()

        def has_scaled_address_carrier_use(symbol):
            symbol_vars = expr_vars(symbol)
            if not symbol_vars:
                return False
            for _, addr_symbol, _, _ in mem_accesses:
                if not (expr_vars(addr_symbol) & symbol_vars):
                    continue
                if scaled_symbol_affine(addr_symbol, symbol) is not None:
                    return True
            return False

        for reg, symbol in reg_to_symbol.items():
            if reg in base_like_regs:
                continue
            symbol_vars = getattr(symbol, 'variables', set())
            if not symbol_vars:
                continue
            if has_scaled_address_carrier_use(symbol):
                continue
            for _, addr_symbol, _, _ in mem_accesses:
                addr_vars = getattr(addr_symbol, 'variables', set())
                if (addr_vars & symbol_vars) and (addr_vars & loaded_addr_vars):
                    deferred_regs.add(reg)
                    break
            if reg in deferred_regs:
                continue
            for _, _, load_addr_symbol, load_idx in address_source_loads:
                for _, store_addr_symbol, store_idx, _, store_data_symbol in store_accesses:
                    if store_idx >= load_idx:
                        continue
                    if not same_address(store_addr_symbol, load_addr_symbol):
                        continue
                    if getattr(store_data_symbol, 'variables', set()) & symbol_vars:
                        deferred_regs.add(reg)
                        break
                if reg in deferred_regs:
                    break

        def materialize_register(r):
            nonlocal scalar_offset
            symbol = reg_to_symbol[r]
            write_stage("init:materialize_init:register", reg=r.name, phase="start")
            hinted_values = sorted({value & ((1 << 64) - 1) for value in reg_value_hints.get(r, [])})
            val = None
            if r not in base_like_regs:
                write_stage("init:materialize_init:register", reg=r.name, phase="scaled_addr_carrier")
                val = choose_scaled_address_register_value(symbol)
            if len(hinted_values) == 1 and r not in direct_memory_base_like_regs:
                write_stage("init:materialize_init:register", reg=r.name, phase="value_hint")
                if val is None:
                    try:
                        val = choose_register_value(symbol, hinted_values[0])
                    except AssertionError:
                        val = None
            if val is None and r in base_like_regs and r in reg_min_stack_offsets:
                write_stage(
                    "init:materialize_init:register",
                    reg=r.name,
                    phase="base_like_pointer",
                    base_source=base_like_sources.get(r),
                    min_offset=reg_min_stack_offsets.get(r),
                )
                if retry_index > 0 and len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
                    direct_offset = _align_up(
                        max(INIT_PTR_MIN_OFFSET, reg_min_stack_offsets[r]),
                        INIT_ACCESS_ALIGN,
                    )
                    if direct_offset <= STACK_RANGE:
                        val = concrete_stack_addr(direct_offset)
                if val is None:
                    val = choose_base_register_value(
                        symbol,
                        min_offset=reg_min_stack_offsets[r],
                        fast_anchor=True,
                    )
            if val is None:
                write_stage("init:materialize_init:register", reg=r.name, phase="stack_relative" if r in base_like_regs else "non_base")
                if r in base_like_regs:
                    direct_offset = next_free_stack_offset(
                        used_stack_offsets,
                        align=INIT_ACCESS_ALIGN,
                        width=8,
                        start=INIT_PTR_MIN_OFFSET,
                    )
                    if direct_offset is not None:
                        val = concrete_stack_addr(direct_offset)
                if val is None:
                    val = (
                        choose_stack_relative_register_value(
                            symbol,
                        )
                        if r in base_like_regs
                        else None
                    )
            if val is None and r not in base_like_regs:
                symbol_vars = expr_vars(symbol)
                has_direct_livein_base_use = symbol_vars and any(
                    getattr(inst, 'rs1', None) == r
                    and (expr_vars(addr_symbol) & symbol_vars)
                    for inst, addr_symbol, _, _ in mem_accesses
                )
                has_loaded_address_use = symbol_vars and any(
                    (expr_vars(addr_symbol) & symbol_vars)
                    and (expr_vars(addr_symbol) & loaded_addr_vars)
                    for _, addr_symbol, _, _ in mem_accesses
                )
                if has_loaded_address_use and not has_direct_livein_base_use:
                    write_stage("init:materialize_init:register", reg=r.name, phase="loaded_addr_scalar_zero")
                    if try_add_constraint(symbol == expr_bvv(0, symbol)):
                        val = 0
            if val is not None:
                stack_offset = stack_offset_for_value(val)
                if stack_offset is not None and not any(
                    concrete_ranges_overlap(stack_offset, 8, used_offset, used_width)
                    for used_offset, used_width in used_stack_offsets
                ):
                    used_stack_offsets.append((stack_offset, 8))
            if val is None:
                write_stage("init:materialize_init:register", reg=r.name, phase="scalar")
                symbol_vars = expr_vars(symbol)
                has_address_use = symbol_vars and any(
                    expr_vars(addr_symbol) & symbol_vars
                    for _, addr_symbol, _, _ in mem_accesses
                )
                if (
                    r not in base_like_regs
                    and not has_address_use
                ):
                    unconstrained_scalar = not any(
                        getattr(constraint, 'variables', set()) & symbol_vars
                        for constraint in candidate_solver.constraints
                    )
                    if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD or unconstrained_scalar:
                        candidate_solver.add(symbol == expr_bvv(0, symbol))
                        val = 0
                    elif try_add_constraint_set_fast([symbol == expr_bvv(0, symbol)]):
                        val = 0
                if val is None and r not in base_like_regs and has_address_use:
                    constrained_address_scalar = any(
                        getattr(constraint, 'variables', set()) & symbol_vars
                        for constraint in candidate_solver.constraints
                    )
                    if constrained_address_scalar:
                        write_stage("init:materialize_init:register", reg=r.name, phase="scalar_base_fallback")
                        val = choose_base_register_value(symbol, INIT_PTR_MIN_OFFSET, fast_anchor=True)
                try:
                    if val is None:
                        val = choose_register_value(symbol, None)
                except AssertionError:
                    write_stage("init:materialize_init:register", reg=r.name, phase="scalar_stack_fallback")
                    fallback_offset = next_free_stack_offset(
                        used_stack_offsets,
                        align=INIT_ACCESS_ALIGN,
                        width=8,
                        start=max(INIT_PTR_MIN_OFFSET, 2048),
                    )
                    if fallback_offset is not None:
                        val = concrete_stack_addr(fallback_offset)
                        if try_add_constraint((init_sp - symbol) == fallback_offset):
                            used_stack_offsets.append((fallback_offset, 8))
                        else:
                            val = None
                    else:
                        val = None
                    if val is None:
                        write_stage("init:materialize_init:register", reg=r.name, phase="scaled_addr_fallback")
                        val = choose_scaled_address_register_value(symbol)
                    if val is None:
                        val = choose_base_register_value(symbol, INIT_PTR_MIN_OFFSET, fast_anchor=True)
                    if val is None:
                        val = choose_stack_relative_register_value(symbol)
                    if val is None:
                        raise
            write_stage("init:materialize_init:register", reg=r.name, phase="emit")
            append_value_init(reg_init, r.name, val, allow_scaled_stack=True)
            reg_values[r] = val & ((1 << 64) - 1)
            scalar_offset += 8

        for r in regs_undefined:
            if r in deferred_regs:
                continue
            _write_profile_stage(name, "init:materialize_init:registers")
            materialize_register(r)
            if debug_unsat_stages:
                debug_check_stage(f"register_{r.name}")

        if (
            ENABLE_POINTER_LOAD_ANCHORS
            and len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD
            and not address_narrow_source_loads
        ):
            anchored_pointer_load_values = set()
            anchor_candidates = list(pointer_source_loads)
            anchor_candidates = [
                entry for entry in anchor_candidates
                if (entry[3], expr_key(entry[1])) not in scalar_load_hint_keys
            ]
            anchor_candidates.sort(key=lambda item: item[3], reverse=True)
            anchor_candidates = anchor_candidates[:LONG_BLOCK_ANCHOR_CANDIDATE_LIMIT]
            for load_inst, rd_symbol, _, load_idx in anchor_candidates:
                if load_inst.width != 8:
                    continue
                rd_key = expr_key(rd_symbol)
                if rd_key in anchored_pointer_load_values:
                    continue
                anchored_pointer_load_values.add(rd_key)
                offset_expr = init_sp - rd_symbol
                min_offset = _align_up(
                    min_pointer_offset_for_vars(expr_vars(rd_symbol), load_idx),
                    INIT_ACCESS_ALIGN,
                )
                preferred_offset = next_free_stack_offset(
                    used_stack_offsets,
                    align=INIT_ACCESS_ALIGN,
                    width=INIT_ACCESS_SLOT_WIDTH,
                    start=min_offset,
                )
                if preferred_offset is None:
                    continue
                write_stage(
                    "init:materialize_init:pointer_load_anchors",
                    inst_idx=load_idx,
                    phase="choose_value",
                )
                value_offset = None
                candidate_offsets = solver_eval_limited(offset_expr, n=4, timeout_ms=100)
                seen_candidate_offsets = set()
                for candidate_offset in candidate_offsets:
                    candidate_offset &= (1 << 64) - 1
                    if candidate_offset in seen_candidate_offsets:
                        continue
                    seen_candidate_offsets.add(candidate_offset)
                    if candidate_offset <= 0 or candidate_offset > STACK_RANGE:
                        continue
                    if candidate_offset % INIT_ACCESS_ALIGN != 0:
                        continue
                    if any(
                        concrete_ranges_overlap(candidate_offset, 8, used_offset, used_width)
                        for used_offset, used_width in used_stack_offsets
                    ):
                        continue
                    if try_add_constraint(offset_expr == candidate_offset, timeout_ms=100):
                        value_offset = candidate_offset
                        break
                if value_offset is None:
                    continue
                if value_offset is not None and not any(
                    concrete_ranges_overlap(value_offset, 8, used_offset, used_width)
                    for used_offset, used_width in used_stack_offsets
                ):
                    used_stack_offsets.append((value_offset, 8))

        _write_profile_stage(name, "init:materialize_init:load_slots")
        access_ranges = list(reserved_base_access_ranges)
        processed_load_addr_keys = set()
        pointer_source_indices = {
            pointer_idx
            for _, pointer_rd_symbol, _, pointer_idx in pointer_source_loads
            if (pointer_idx, expr_key(pointer_rd_symbol)) not in scalar_load_hint_keys
        }
        load_slot_entries = list(enumerate(mem_entries))
        load_slot_entries.sort(
            key=lambda item: (
                0 if item[1][3] in pointer_source_indices else 1,
                item[0],
            )
        )
        for load_slot_idx, (inst, rd_symbol, addr_symbol, inst_idx) in load_slot_entries:
            rd_vars_for_prune = expr_vars(rd_symbol)
            value_used_later_for_prune = bool(rd_vars_for_prune) and any(
                later_idx > inst_idx and (expr_vars(later_addr_symbol) & rd_vars_for_prune)
                for _, later_addr_symbol, later_idx, _ in mem_accesses
            )
            load_value_key_for_prune = (inst_idx, str(claripy.simplify(rd_symbol)), str(claripy.simplify(addr_symbol)))
            force_exact_load_slot = (
                load_value_key_for_prune in required_load_value_keys
                or value_used_later_for_prune
            )
            if (
                len(mem_entries) >= LOAD_SLOT_PRUNE_THRESHOLD
                and not force_exact_load_slot
            ):
                continue
            write_stage(
                "init:materialize_init:load_slots:entry",
                slot=load_slot_idx,
                inst_idx=inst_idx,
                phase="start",
            )
            addr_expr = init_sp - addr_symbol
            addr_key = expr_key(addr_symbol)
            if has_prior_same_addr_store(addr_symbol, inst_idx, allow_solver=False):
                continue
            duplicate_load_addr = addr_key in processed_load_addr_keys
            if addr_key in processed_load_addr_keys:
                if addr_key in addr_expr_offsets:
                    addr = addr_expr_offsets[addr_key]
                    candidate_solver.add(addr_expr == addr)
                else:
                    duplicate_load_addr = False
            if addr_key in addr_expr_offsets:
                addr = addr_expr_offsets[addr_key]
                candidate_solver.add(addr_expr == addr)
            else:
                write_stage(
                    "init:materialize_init:load_slots:entry",
                    slot=load_slot_idx,
                    inst_idx=inst_idx,
                    phase="same_addr_scan",
                )
                same_addr_offset = None
                for used_addr, _, used_addr_symbol in access_ranges:
                    affine_same = affine_same_or_distinct(addr_symbol, used_addr_symbol)
                    if (
                        same_address(addr_symbol, used_addr_symbol, allow_solver=False)
                        or affine_same is True
                    ):
                        same_addr_offset = used_addr
                        break
                if same_addr_offset is not None:
                    addr = same_addr_offset
                    candidate_solver.add(addr_expr == addr)
                    addr_expr_offsets[addr_key] = addr
                else:
                    write_stage(
                        "init:materialize_init:load_slots:entry",
                        slot=load_slot_idx,
                        inst_idx=inst_idx,
                        phase="choose_offset",
                    )
                    avoid_ranges = [
                        (used_addr, used_width)
                        for used_addr, used_width, used_addr_symbol in access_ranges
                        if not same_address(addr_symbol, used_addr_symbol, allow_solver=False)
                    ]
                    preferred_offset = next_free_stack_offset(
                        avoid_ranges,
                        align=inst.width if inst.width > 1 else 1,
                        width=INIT_ACCESS_SLOT_WIDTH,
                    )
                    if (
                        preferred_offset is not None
                        and len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                        and ast_node_count(addr_symbol) > 64
                    ):
                        candidate_solver.add(addr_expr == preferred_offset)
                        addr = preferred_offset
                    else:
                        write_stage(
                            "init:materialize_init:load_slots:entry",
                            slot=load_slot_idx,
                            inst_idx=inst_idx,
                            phase="choose_offset:affine_addr",
                        )
                        addr = choose_affine_addr_offset(
                            addr_symbol,
                            addr_expr,
                            preferred_offset,
                            inst.width if inst.width > 1 else None,
                            avoid_ranges,
                            INIT_ACCESS_SLOT_WIDTH,
                        )
                    write_stage(
                        "init:materialize_init:load_slots:entry",
                        slot=load_slot_idx,
                        inst_idx=inst_idx,
                        phase="choose_offset:pointer_load_addr",
                    )
                    if addr is None:
                        addr = choose_pointer_load_addr_offset(
                            addr_symbol,
                            addr_expr,
                            preferred_offset,
                            inst.width if inst.width > 1 else None,
                            avoid_ranges,
                            INIT_ACCESS_SLOT_WIDTH,
                        )
                    if addr is None and preferred_offset is not None:
                        addr = choose_carrier_residual_stack_offset(
                            addr_symbol,
                            addr_expr,
                            preferred_offset,
                            inst.width if inst.width > 1 else None,
                            avoid_ranges,
                            INIT_ACCESS_SLOT_WIDTH,
                        )
                    if (
                        addr is None
                        and preferred_offset is not None
                        and len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD
                        and not force_exact_load_slot
                    ):
                        addr = preferred_offset
                    elif (
                        addr is None
                        and preferred_offset is not None
                        and len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                    ):
                        addr = choose_carrier_residual_stack_offset(
                            addr_symbol,
                            addr_expr,
                            preferred_offset,
                            inst.width if inst.width > 1 else None,
                            avoid_ranges,
                            INIT_ACCESS_SLOT_WIDTH,
                        )
                        if addr is None and try_add_constraint_set_fast([addr_expr == preferred_offset], timeout_ms=100):
                            addr = preferred_offset
                    if addr is None and not (
                        preferred_offset is not None
                        and len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                    ):
                        write_stage(
                            "init:materialize_init:load_slots:entry",
                            slot=load_slot_idx,
                            inst_idx=inst_idx,
                            phase="choose_offset:positive_avoid",
                        )
                        addr = choose_value(
                            addr_expr,
                            preferred_offset,
                            positive=True,
                            align=inst.width if inst.width > 1 else None,
                            avoid=avoid_ranges,
                            width=INIT_ACCESS_SLOT_WIDTH,
                            required=False,
                            fast_positive=True,
                        )
                    if addr is None and preferred_offset is not None:
                        write_stage(
                            "init:materialize_init:load_slots:entry",
                            slot=load_slot_idx,
                            inst_idx=inst_idx,
                            phase="choose_offset:preferred_no_avoid",
                        )
                        addr = choose_value(
                            addr_expr,
                            preferred_offset,
                            positive=True,
                            align=inst.width if inst.width > 1 else None,
                            width=INIT_ACCESS_SLOT_WIDTH,
                            required=False,
                            fast_positive=True,
                        )
                    if addr is None:
                        try:
                            write_stage(
                                "init:materialize_init:load_slots:entry",
                                slot=load_slot_idx,
                                inst_idx=inst_idx,
                                phase="choose_offset:any_positive",
                            )
                            addr = choose_value(
                                addr_expr,
                                None,
                                positive=True,
                                align=inst.width if inst.width > 1 else None,
                                width=INIT_ACCESS_SLOT_WIDTH,
                                required=not (len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD),
                                fast_positive=True,
                            )
                            if (
                                addr is None
                                and len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                            ):
                                continue
                        except AssertionError:
                            fallback_offset = preferred_offset
                            if fallback_offset is None:
                                fallback_offset = next_free_stack_offset(
                                    avoid_ranges,
                                    align=inst.width if inst.width > 1 else 1,
                                    width=INIT_ACCESS_SLOT_WIDTH,
                                )
                            if fallback_offset is not None and try_add_constraint(addr_expr == fallback_offset):
                                addr = fallback_offset
                            else:
                                if (
                                    len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                                    and not force_exact_load_slot
                                ):
                                    continue
                                raise
                    addr_expr_offsets[addr_key] = addr
            if debug_unsat_stages:
                debug_check_stage(f"load_slot_{load_slot_idx}_idx_{inst_idx}_addr_{addr}")
            processed_load_addr_keys.add(addr_key)
            if not duplicate_load_addr:
                access_ranges.append((addr, INIT_ACCESS_SLOT_WIDTH, addr_symbol))

            write_stage(
                "init:materialize_init:load_slots:entry",
                slot=load_slot_idx,
                inst_idx=inst_idx,
                phase="field",
            )
            value_expr = mem_value_expr(inst, rd_symbol)
            value_vars = getattr(value_expr, 'variables', set())
            value_used_in_later_addr = bool(value_vars) and any(
                later_idx > inst_idx and (expr_vars(later_addr_symbol) & value_vars)
                for _, later_addr_symbol, later_idx, _ in mem_accesses
            )
            value_used_as_later_store_data = bool(value_vars) and any(
                store_idx > inst_idx and (expr_vars(store_data_symbol) & value_vars)
                for _, _, store_idx, _, store_data_symbol in store_accesses
            )
            load_value_key = (inst_idx, str(claripy.simplify(rd_symbol)), str(claripy.simplify(addr_symbol)))
            scalar_zero_load = is_scalar_zero_address_load(inst, value_expr, inst_idx)
            if scalar_zero_load:
                constraint = value_expr == expr_bvv(0, value_expr)
                try_add_constraint(constraint, timeout_ms=local_solver_timeout_ms)
            skip_static_store_data_value = (
                use_static_memory_collection
                and inst.width == 4
                and value_used_as_later_store_data
                and not value_used_in_later_addr
                and load_value_key not in required_load_value_keys
            )
            require_load_value = (
                not skip_static_store_data_value
                and (
                    len(mem_entries) < STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD
                    or load_value_key in required_load_value_keys
                    or value_used_in_later_addr
                )
            )
            word_offset = ((addr + 7) // 8) * 8
            byte_offset = word_offset - addr
            assert 0 <= byte_offset and byte_offset + inst.width <= 8, (
                f"invalid init slot field: offset={addr}, width={inst.width}, "
                f"byte_offset={byte_offset}, inst_idx={inst_idx}, addr={addr_symbol}"
            )
            new_word_slot = word_offset not in mem_slot_symbols
            if word_offset not in mem_slot_symbols:
                word_symbol = claripy.BVS(f'init_mem_word_{len(mem_slot_symbols)}_{word_offset}', 64)
                mem_slot_symbols[word_offset] = {
                    'symbol': word_symbol,
                    'pointer_like': False,
                    'must_be_pointer': False,
                    'min_pointer_offset': 0,
                    'sp_affine': False,
                    'scalar_zero': False,
                }
                mem_offset_addr_symbols[word_offset] = []
            else:
                word_symbol = mem_slot_symbols[word_offset]['symbol']

            slot = mem_slot_symbols[word_offset]
            if scalar_zero_load:
                slot['scalar_zero'] = True
            if (
                not new_word_slot
                and 'direct_value_expr' in slot
            ):
                try_add_constraint(slot['symbol'] == slot['direct_value_expr'], timeout_ms=local_solver_timeout_ms)
                del slot['direct_value_expr']

            if not require_load_value:
                field_added = False
            elif new_word_slot and inst.width == 8 and byte_offset == 0:
                mem_slot_symbols[word_offset]['direct_value_expr'] = value_expr
                field_added = True
            else:
                field_added = constrain_word_field(
                    word_symbol,
                    byte_offset,
                    inst,
                    value_expr,
                    protected=not new_word_slot,
                )
            if not any(
                same_address(addr_symbol, known_addr, allow_solver=False)
                for known_addr in mem_offset_addr_symbols[word_offset]
            ):
                mem_offset_addr_symbols[word_offset].append(addr_symbol)
            if field_added and inst.width == 8 and byte_offset == 0 and (inst_idx, str(value_expr)) in sp_affine_source_load_keys:
                mem_slot_symbols[word_offset]['sp_affine'] = True
            if (
                inst.width == 8
                and byte_offset == 0
                and value_used_in_later_addr
                and value_vars & pointer_loaded_addr_vars
            ):
                mem_slot_symbols[word_offset]['pointer_like'] = True
                mem_slot_symbols[word_offset]['must_be_pointer'] = True
                mem_slot_symbols[word_offset]['min_pointer_offset'] = max(
                    mem_slot_symbols[word_offset]['min_pointer_offset'],
                    min_pointer_offset_for_vars(
                        value_vars,
                        inst_idx,
                        avoid_ranges=[(word_offset, 8)],
                    ),
                )
            if field_added and inst.width == 8 and byte_offset == 0:
                if value_vars & pointer_loaded_addr_vars:
                    mem_slot_symbols[word_offset]['pointer_like'] = True
                    if value_used_in_later_addr:
                        mem_slot_symbols[word_offset]['must_be_pointer'] = True
                    mem_slot_symbols[word_offset]['min_pointer_offset'] = max(
                        mem_slot_symbols[word_offset]['min_pointer_offset'],
                        min_pointer_offset_for_vars(
                            value_vars,
                            inst_idx,
                            avoid_ranges=[(word_offset, 8)],
                        ),
                    )
                for _, later_addr_symbol, later_idx, _ in mem_accesses:
                    if later_idx <= inst_idx:
                        continue
                    later_addr_vars = expr_vars(later_addr_symbol)
                    if not (later_addr_vars & value_vars):
                        continue
                    if (later_addr_vars & pointer_loaded_addr_vars) and not (value_vars & pointer_loaded_addr_vars):
                        continue
                    residual = claripy.simplify(later_addr_symbol - value_expr)
                    residual_vars = expr_vars(residual)
                    if not (residual_vars & value_vars) and concrete_expr_value(residual) is not None:
                        mem_slot_symbols[word_offset]['pointer_like'] = True
                        mem_slot_symbols[word_offset]['must_be_pointer'] = True
                        mem_slot_symbols[word_offset]['min_pointer_offset'] = max(
                            mem_slot_symbols[word_offset]['min_pointer_offset'],
                            min_pointer_offset_for_vars(
                                value_vars,
                                inst_idx,
                                avoid_ranges=[(word_offset, 8)],
                            ),
                        )
                        break
                    if constraints_to_carrier(later_addr_symbol, value_expr) is None:
                        continue
                    mem_slot_symbols[word_offset]['pointer_like'] = True
                    mem_slot_symbols[word_offset]['must_be_pointer'] = True
                    mem_slot_symbols[word_offset]['min_pointer_offset'] = max(
                        mem_slot_symbols[word_offset]['min_pointer_offset'],
                        min_pointer_offset_for_vars(
                            value_vars,
                            inst_idx,
                            avoid_ranges=[(word_offset, 8)],
                        ),
                    )
                    break
                if (inst_idx, expr_key(value_expr)) in hint_pointer_load_keys:
                    value_vars = getattr(value_expr, 'variables', set())
                    mem_slot_symbols[word_offset]['pointer_like'] = True
                    if value_used_in_later_addr:
                        mem_slot_symbols[word_offset]['must_be_pointer'] = True
                    mem_slot_symbols[word_offset]['min_pointer_offset'] = max(
                        mem_slot_symbols[word_offset]['min_pointer_offset'],
                        min_pointer_offset_for_vars(
                            value_vars,
                            inst_idx,
                            avoid_ranges=[(word_offset, 8)],
                        ),
                    )
                for _, pointer_rd_symbol, pointer_addr_symbol, pointer_idx in pointer_source_loads:
                    if (pointer_idx, expr_key(pointer_rd_symbol)) in scalar_load_hint_keys:
                        continue
                    if pointer_idx in pointer_source_indices and has_prior_same_addr_store(pointer_addr_symbol, pointer_idx):
                        continue
                    pointer_vars = getattr(pointer_rd_symbol, 'variables', set())
                    if not (value_vars & pointer_vars):
                        continue
                    mem_slot_symbols[word_offset]['pointer_like'] = True
                    if value_used_in_later_addr:
                        mem_slot_symbols[word_offset]['must_be_pointer'] = True
                    mem_slot_symbols[word_offset]['min_pointer_offset'] = max(
                        mem_slot_symbols[word_offset]['min_pointer_offset'],
                            min_pointer_offset_for_vars(pointer_vars, pointer_idx, avoid_ranges=[(word_offset, 8)]),
                        )
            if field_added and inst.width == 8 and byte_offset == 0:
                for pointer_inst, pointer_rd_symbol, pointer_addr_symbol, pointer_idx in pointer_source_loads:
                    if (pointer_idx, expr_key(pointer_rd_symbol)) in scalar_load_hint_keys:
                        continue
                    if pointer_idx in pointer_source_indices and has_prior_same_addr_store(pointer_addr_symbol, pointer_idx, allow_solver=False):
                        continue
                    if inst_idx == pointer_idx or same_address(addr_symbol, pointer_addr_symbol, allow_solver=False):
                        pointer_vars = getattr(pointer_rd_symbol, 'variables', set())
                        mem_slot_symbols[word_offset]['pointer_like'] = True
                        if value_used_in_later_addr:
                            mem_slot_symbols[word_offset]['must_be_pointer'] = True
                        mem_slot_symbols[word_offset]['min_pointer_offset'] = max(
                            mem_slot_symbols[word_offset]['min_pointer_offset'],
                            min_pointer_offset_for_vars(pointer_vars, pointer_idx, avoid_ranges=[(word_offset, 8)]),
                        )
            if debug_unsat_stages:
                debug_check_stage(f"load_slot_{load_slot_idx}_idx_{inst_idx}_word_{word_offset}_field_{field_added}")

        for word_offset, slot in mem_slot_symbols.items():
            add_store_no_overlap_for_word(word_offset, mem_offset_addr_symbols[word_offset])
            if debug_unsat_stages:
                debug_check_stage(f"store_no_overlap_word_{word_offset}")

        if verbose:
            print('mem_slot_symbols', {
                offset: {
                    'pointer_like': slot.get('pointer_like'),
                    'must_be_pointer': slot.get('must_be_pointer'),
                    'min_pointer_offset': slot.get('min_pointer_offset'),
                    'sp_affine': slot.get('sp_affine'),
                    'symbol': str(slot.get('symbol')),
                }
                for offset, slot in sorted(mem_slot_symbols.items())
            })

        def sp_affine_mode_for_compensation_value(value):
            value &= ((1 << 64) - 1)
            candidate_reg_values = list(reg_values.values())
            for reg, symbol in reg_to_symbol.items():
                if reg in reg_values:
                    continue
                value_bvv = expr_bvv(value, symbol)
                for combined in (
                    claripy.simplify(value_bvv + symbol),
                    claripy.simplify(value_bvv - symbol),
                ):
                    if try_add_constraint_set(stack_pointer_constraints_for_expr(combined)):
                        return 'direct'
                candidate_reg_values.extend(solver_eval_with(symbol, [], n=8))
            seen_reg_values = set()
            for reg_value in candidate_reg_values:
                reg_value &= ((1 << 64) - 1)
                if reg_value in seen_reg_values:
                    continue
                seen_reg_values.add(reg_value)
                reg_stack_offset = signed_stack_offset_for_value(reg_value)
                if reg_stack_offset is None:
                    continue
                plus_value = (value + reg_value) & ((1 << 64) - 1)
                minus_value = (value - reg_value) & ((1 << 64) - 1)
                if -STACK_RANGE <= _signed_u64(plus_value) <= STACK_RANGE:
                    return 'inverse'
                if -STACK_RANGE <= _signed_u64(minus_value) <= STACK_RANGE:
                    return 'direct'
            return None

        _write_profile_stage(name, "init:materialize_init:memory_values")
        if len(mem_entries) >= GLOBAL_NO_OVERLAP_LOAD_THRESHOLD:
            pass
        elif len(mem_entries) >= STATIC_MEMORY_COLLECTION_ACCESS_THRESHOLD:
            satisfiable_result = None
            try:
                satisfiable_check = candidate_solver.branch()
                satisfiable_check.timeout = local_solver_timeout_ms
                satisfiable_result = satisfiable_check.satisfiable()
            except Exception:
                pass
            assert satisfiable_result is not False, f"[ERROR]: {name} init memory constraints are unsatisfiable"
        else:
            assert candidate_solver.satisfiable(), f"[ERROR]: {name} init memory constraints are unsatisfiable"
        for addr, slot in mem_slot_symbols.items():
            write_stage(
                "init:materialize_init:memory_values:slot",
                offset=addr,
                pointer_like=bool(slot.get('pointer_like')),
                sp_affine=bool(slot.get('sp_affine')),
            )
            actual_value = choose_mem_slot_value(addr, slot)
            value_stack_offset = stack_offset_for_value(actual_value)
            force_sp_delta = None
            force_inverse_sp_delta = None
            actual_signed_value = _signed_u64(actual_value)
            scalar_sp_affine_value = -STACK_RANGE <= actual_signed_value <= STACK_RANGE
            write_stage(
                "init:materialize_init:memory_values:slot",
                offset=addr,
                phase="sp_affine_check",
                pointer_like=bool(slot.get('pointer_like')),
                sp_affine=bool(slot.get('sp_affine')),
            )
            combined_sp_affine_mode = (
                sp_affine_mode_for_compensation_value(actual_value)
                if value_stack_offset is None and not scalar_sp_affine_value
                else None
            )
            combined_sp_affine_value = combined_sp_affine_mode is not None
            if combined_sp_affine_mode == 'direct' and not slot.get('sp_affine'):
                combined_sp_affine_value = False
            if combined_sp_affine_mode is not None and verbose:
                print('combined_sp_affine_mode', addr, hex(actual_value), combined_sp_affine_mode)
            if (
                (slot.get('sp_affine') or combined_sp_affine_value)
                and signed_stack_offset_for_value(actual_value) is None
                and not scalar_sp_affine_value
            ):
                mode = combined_sp_affine_mode or 'direct'
                sp_affine_mem_offsets[addr] = mode
                if mode == 'inverse':
                    force_inverse_sp_delta = (actual_value + CONCRETE_REPLAY_SP) & ((1 << 64) - 1)
                else:
                    force_sp_delta = (actual_value - CONCRETE_REPLAY_SP) & ((1 << 64) - 1)

            # prepare value
            append_value_init(
                candidate_init,
                TEMP_REG,
                actual_value,
                force_stack_offset=value_stack_offset,
                force_sp_delta=force_sp_delta,
                force_inverse_sp_delta=force_inverse_sp_delta,
            )
            # prepare address
            candidate_init.append(UFmtInst('li', TEMP_REG2, addr))
            candidate_init.append(RFmtInst('sub', TEMP_REG2, 'sp', TEMP_REG2))

            candidate_init.append(StoreInst('sd', TEMP_REG, TEMP_REG2, 0))
            mem_values[addr] = actual_value

        for r in regs_undefined:
            if r in deferred_regs:
                _write_profile_stage(name, "init:materialize_init:deferred_registers")
                materialize_register(r)

        candidate_init.extend(reg_init)
        return candidate_init, reg_values, mem_values, mem_offset_addr_symbols, candidate_solver, sp_affine_mem_offsets

    def find_alias_constraints(
        reg_values,
        mem_values,
        mem_offset_addr_symbols,
        constraint_solver,
        sp_value=CONCRETE_REPLAY_SP,
        sp_affine_mem_offsets=None,
    ):
        def same_address(addr_a, addr_b):
            if addr_b is None:
                return False
            if str(addr_a) == str(addr_b):
                return True
            test_solver = constraint_solver.branch()
            test_solver.add(addr_a != addr_b)
            return not test_solver.satisfiable()

        constraints = []
        mem_offsets = sorted(mem_values.keys())
        for store_inst, store_addr_symbol, store_inst_idx, store_width, _ in store_accesses:
            store_addr = original_access_addr(store_inst_idx)
            store_state = replay_prefix_state(
                reg_values,
                mem_values,
                store_addr,
                sp_value=sp_value,
                sp_affine_mem_offsets=sp_affine_mem_offsets,
            )
            if store_state is None:
                continue

            concrete_store_addr = store_state.solver.eval(getattr(store_state.regs, str(store_inst.rs1))) \
                                  + store_inst.imm
            concrete_store_offset = (sp_value - concrete_store_addr) & ((1 << 64) - 1)
            for mem_offset in mem_offsets:
                if any(same_address(store_addr_symbol, addr_symbol)
                       for addr_symbol in mem_offset_addr_symbols.get(mem_offset, [])):
                    continue
                if concrete_ranges_overlap(concrete_store_offset, store_width, mem_offset, 8):
                    constraints.append(symbolic_no_overlap(store_addr_symbol, store_width, mem_offset))

        return constraints

    def find_store_pointer_constraints(
        reg_values,
        mem_values,
        constraint_solver,
        sp_value=CONCRETE_REPLAY_SP,
        sp_affine_mem_offsets=None,
    ):
        constraints = []
        seen_loads = set()
        for load_inst, rd_symbol, load_addr_symbol, load_idx in pointer_source_loads + address_source_loads:
            if (load_idx, stable_expr_key(rd_symbol)) in scalar_load_hint_keys:
                continue
            load_key = (load_idx, str(rd_symbol), str(load_addr_symbol))
            if load_key in seen_loads:
                continue
            seen_loads.add(load_key)
            load_addr = original_access_addr(load_idx)
            load_state = replay_prefix_state(
                reg_values,
                mem_values,
                load_addr,
                sp_value=sp_value,
                sp_affine_mem_offsets=sp_affine_mem_offsets,
            )
            if load_state is None:
                continue
            concrete_load_addr = load_state.solver.eval(getattr(load_state.regs, str(load_inst.rs1))) + load_inst.imm
            concrete_load_offset = (sp_value - concrete_load_addr) & ((1 << 64) - 1)
            rd_vars = getattr(rd_symbol, 'variables', set())
            min_offset = min_pointer_offset_for_vars(
                rd_vars,
                load_idx,
                avoid_ranges=[(concrete_load_offset, load_inst.width)],
            )
            pointer_like_load = any(
                p_idx == load_idx and bool(getattr(p_rd, 'variables', set()) & rd_vars)
                for _, p_rd, _, p_idx in pointer_source_loads
            )
            for store_inst, store_addr_symbol, store_idx, store_width, store_data_symbol in reversed(store_accesses):
                if store_idx >= load_idx:
                    continue
                store_addr = original_access_addr(store_idx)
                store_state = replay_prefix_state(
                    reg_values,
                    mem_values,
                    store_addr,
                    sp_value=sp_value,
                    sp_affine_mem_offsets=sp_affine_mem_offsets,
                )
                if store_state is None:
                    continue
                concrete_store_addr = store_state.solver.eval(getattr(store_state.regs, str(store_inst.rs1))) + store_inst.imm
                concrete_store_offset = (sp_value - concrete_store_addr) & ((1 << 64) - 1)
                if not concrete_ranges_overlap(concrete_store_offset, store_width, concrete_load_offset, load_inst.width):
                    continue
                stored_expr = stored_value_for_load_expr(store_data_symbol, store_width, load_inst)
                if stored_expr is not None:
                    constraints.append(rd_symbol == stored_expr)
                    if pointer_like_load and getattr(stored_expr, 'variables', set()):
                        constraints.extend(stack_pointer_constraints_for_expr(stored_expr, min_offset))
                    break
                if not forced_same_address(store_addr_symbol, load_addr_symbol, constraint_solver):
                    constraints.append(symbolic_access_no_overlap(store_addr_symbol, store_width, load_addr_symbol, load_inst.width))
                    break
        return constraints

    def find_pointer_slot_store_constraints(
        reg_values,
        mem_values,
        constraint_solver,
        sp_value=CONCRETE_REPLAY_SP,
        sp_affine_mem_offsets=None,
    ):
        constraints = []
        for load_inst, rd_symbol, load_addr_symbol, load_idx in pointer_source_loads:
            pointer_vars = getattr(rd_symbol, 'variables', set())
            last_use_idx = load_idx
            for _, addr_symbol, access_idx, _ in mem_accesses:
                if access_idx <= load_idx:
                    continue
                if getattr(addr_symbol, 'variables', set()) & pointer_vars:
                    last_use_idx = max(last_use_idx, access_idx)
            if last_use_idx <= load_idx:
                continue
            load_addr = original_access_addr(load_idx)
            load_state = replay_prefix_state(
                reg_values,
                mem_values,
                load_addr,
                sp_value=sp_value,
                sp_affine_mem_offsets=sp_affine_mem_offsets,
            )
            if load_state is None:
                continue
            concrete_load_addr = load_state.solver.eval(getattr(load_state.regs, str(load_inst.rs1))) + load_inst.imm
            concrete_load_offset = (sp_value - concrete_load_addr) & ((1 << 64) - 1)
            for store_inst, store_addr_symbol, store_idx, store_width, _ in store_accesses:
                if store_idx <= load_idx or store_idx > last_use_idx:
                    continue
                store_addr = original_access_addr(store_idx)
                store_state = replay_prefix_state(
                    reg_values,
                    mem_values,
                    store_addr,
                    sp_value=sp_value,
                    sp_affine_mem_offsets=sp_affine_mem_offsets,
                )
                if store_state is None:
                    continue
                concrete_store_addr = store_state.solver.eval(getattr(store_state.regs, str(store_inst.rs1))) + store_inst.imm
                concrete_store_offset = (sp_value - concrete_store_addr) & ((1 << 64) - 1)
                if concrete_ranges_overlap(
                    concrete_store_offset,
                    store_width,
                    concrete_load_offset,
                    init_slot_width(load_inst.width),
                ):
                    if forced_same_address(store_addr_symbol, load_addr_symbol, constraint_solver):
                        continue
                    constraints.append(
                        symbolic_access_no_overlap(
                            store_addr_symbol,
                            store_width,
                            load_addr_symbol,
                            init_slot_width(load_inst.width),
                        )
                    )
        return constraints

    def find_replay_access_constraints(
        reg_values,
        mem_values,
        sp_value=CONCRETE_REPLAY_SP,
        sp_affine_mem_offsets=None,
    ):
        constraints = []
        for inst, addr_symbol, inst_idx, width in mem_accesses:
            access_addr = original_access_addr(inst_idx)
            access_state = replay_prefix_state(
                reg_values,
                mem_values,
                access_addr,
                sp_value=sp_value,
                sp_affine_mem_offsets=sp_affine_mem_offsets,
            )
            if access_state is None:
                continue

            concrete_addr = access_state.solver.eval(getattr(access_state.regs, str(inst.rs1))) + inst.imm
            concrete_offset = (sp_value - concrete_addr) & ((1 << 64) - 1)
            bad_range = concrete_addr >= sp_value or concrete_offset > STACK_RANGE
            bad_align = width > 1 and (concrete_addr & (width - 1)) != 0
            if bad_range:
                offset_expr = init_sp - addr_symbol
                constraints.extend([
                    claripy.UGE(offset_expr, claripy.BVV(width, 64)),
                    claripy.ULE(offset_expr, claripy.BVV(STACK_RANGE, 64)),
                ])
            if bad_align:
                constraints.append((addr_symbol & (width - 1)) == 0)

        return constraints

    def find_narrow_pointer_alias_constraints(
        reg_values,
        mem_values,
        sp_value=CONCRETE_REPLAY_SP,
        sp_affine_mem_offsets=None,
    ):
        constraints = []
        scalar_loads = []
        pointer_loads = []

        for load_inst, rd_symbol, addr_symbol, load_idx in mem_entries:
            rd_vars = getattr(rd_symbol, 'variables', set())
            if not rd_vars:
                continue
            used_in_later_addr = any(
                access_idx > load_idx and (getattr(later_addr, 'variables', set()) & rd_vars)
                for _, later_addr, access_idx, _ in mem_accesses
            )
            if load_inst.width < 8 and load_inst.pc not in load_nonzero_hints and used_in_later_addr:
                scalar_loads.append((load_inst, addr_symbol, load_idx))
            elif (
                load_inst.width == 8
                and used_in_later_addr
                and (
                    rd_vars & pointer_loaded_addr_vars
                    or load_inst.pc in load_pointer_hints
                )
            ):
                pointer_loads.append((load_inst, addr_symbol, load_idx))

        if not scalar_loads or not pointer_loads:
            return constraints

        concrete_addrs = {}

        def concrete_load_addr(load_inst, load_idx):
            key = load_idx
            if key in concrete_addrs:
                return concrete_addrs[key]
            access_addr = original_access_addr(load_idx)
            state = replay_prefix_state(
                reg_values,
                mem_values,
                access_addr,
                sp_value=sp_value,
                sp_affine_mem_offsets=sp_affine_mem_offsets,
            )
            if state is None:
                concrete_addrs[key] = None
                return None
            concrete_addr = state.solver.eval(getattr(state.regs, str(load_inst.rs1))) + load_inst.imm
            concrete_addrs[key] = concrete_addr & ((1 << 64) - 1)
            return concrete_addrs[key]

        seen = set()
        used_slots = set()
        for load_inst, _, load_idx in [
            (entry[0], entry[2], entry[3])
            for entry in mem_entries
        ]:
            concrete_addr = concrete_load_addr(load_inst, load_idx)
            if concrete_addr is None:
                continue
            used_slots.add(((sp_value - concrete_addr) + 7) & ~7)

        def next_unused_slot(exclude_slot):
            offset = INIT_ACCESS_ALIGN
            while offset <= STACK_RANGE:
                if offset != exclude_slot and offset not in used_slots:
                    return offset
                offset += INIT_ACCESS_ALIGN
            return None

        for pointer_inst, pointer_addr_symbol, pointer_idx in pointer_loads:
            pointer_addr = concrete_load_addr(pointer_inst, pointer_idx)
            if pointer_addr is None:
                continue
            pointer_slot = ((sp_value - pointer_addr) + 7) & ~7
            for scalar_inst, scalar_addr_symbol, scalar_idx in scalar_loads:
                scalar_addr = concrete_load_addr(scalar_inst, scalar_idx)
                if scalar_addr is None:
                    continue
                scalar_slot = ((sp_value - scalar_addr) + 7) & ~7
                if pointer_slot != scalar_slot:
                    continue
                key = (pointer_idx, scalar_idx)
                if key in seen:
                    continue
                seen.add(key)
                constraints.append(symbolic_init_slots_no_overlap(pointer_addr_symbol, scalar_addr_symbol))
                target_slot = next_unused_slot(pointer_slot)
                if target_slot is not None:
                    constraints.append(
                        (init_sp - scalar_addr_symbol) == claripy.BVV(target_slot, 64)
                    )

        return constraints

    current_solver = base_solver.branch()
    for retry in range(MAX_INIT_SOLVE_RETRIES + 1):
        _write_profile_stage(name, f"init:solve_retry_{retry}:satisfiability")
        (
            candidate_init,
            reg_values,
            mem_values,
            mem_offset_addr_symbols,
            candidate_solver,
            sp_affine_mem_offsets,
        ) = materialize_init(current_solver, retry)
        _write_profile_stage(name, f"init:solve_retry_{retry}:concrete_replay")
        failed_replay_sp = None
        for replay_sp in CONCRETE_REPLAY_ALT_SPS:
            if replay_concrete_init(
                reg_values,
                mem_values,
                debug=verbose,
                sp_value=replay_sp,
                sp_affine_mem_offsets=sp_affine_mem_offsets,
            ) is None:
                failed_replay_sp = replay_sp
                break
        if failed_replay_sp is None:
            pp_alias_constraints = find_narrow_pointer_alias_constraints(
                reg_values,
                mem_values,
                sp_value=CONCRETE_REPLAY_SP,
                sp_affine_mem_offsets=sp_affine_mem_offsets,
            )
            if pp_alias_constraints and retry < MAX_INIT_SOLVE_RETRIES:
                for constraint in pp_alias_constraints:
                    current_solver.add(constraint)
                continue
            _write_profile_stage(name, "init:done")
            return candidate_init

        _write_profile_stage(name, f"init:solve_retry_{retry}:derive_replay_constraints")
        alias_constraints = find_alias_constraints(
            reg_values,
            mem_values,
            mem_offset_addr_symbols,
            current_solver,
            sp_value=failed_replay_sp,
            sp_affine_mem_offsets=sp_affine_mem_offsets,
        )
        alias_constraints.extend(find_store_pointer_constraints(
            reg_values,
            mem_values,
            current_solver,
            sp_value=failed_replay_sp,
            sp_affine_mem_offsets=sp_affine_mem_offsets,
        ))
        alias_constraints.extend(find_pointer_slot_store_constraints(
            reg_values,
            mem_values,
            current_solver,
            sp_value=failed_replay_sp,
            sp_affine_mem_offsets=sp_affine_mem_offsets,
        ))
        alias_constraints.extend(find_replay_access_constraints(
            reg_values,
            mem_values,
            sp_value=failed_replay_sp,
            sp_affine_mem_offsets=sp_affine_mem_offsets,
        ))
        if not alias_constraints or retry == MAX_INIT_SOLVE_RETRIES:
            raise ConcreteReplayFailure(
                f"[ERROR]: {name} concrete replay fails after init solving",
                candidate_init=candidate_init,
            )

        for constraint in alias_constraints:
            current_solver.add(constraint)

    raise ConcreteReplayFailure(f"[ERROR]: {name} concrete replay fails after init solving")


def replace_branch_jump(inst):
    """
    检查行首的8位十六进制数是否符合RISC-V分支指令的opcode(1100011),
    若符合则替换为00000263,并保留行格式.
    """
    # 匹配行首的8位十六进制数
    match = re.match(r"^\s*([0-9a-fA-F]{8})\b", inst)
    if not match:
        return inst

    hex_value = match.group(1)
    try:
        value = int(hex_value, 16)
        if (value & 0x7F) == 0x63:  # 0x63表示branch类型指令
            # 00000263表示beq x0, x0, 4
            new_inst = re.sub(r"" + hex_value, r"00000263", inst)
            return new_inst
        elif (value & 0x7F) == 0x6F:  # 0x6F表示j类型指令
            # 0040006f表示jal x0,4
            new_inst = re.sub(r"" + hex_value, r"" + r"0040006f", inst)
            return new_inst
        elif (value & 0x7F) == 0x67:  # 0x67表示jalr类型指令
            # 00402067表示jalr x0,4(x0)
            new_inst = re.sub(r"" + hex_value, r"" + r"00402067", inst)
            return new_inst
    except ValueError:
        pass

    return inst


def transform_for_profiling(filepath, output_path='', add_init: str = False, verbose: bool = False):
    def assemble_code(code: str, name: str, suffix: str = 'code'):
        """Output a file named {name}.code"""
        try:
            _write_profile_stage(name, f"assemble:{suffix}:compile")
            write_to_file(f'{OUTPUT_PATH / name}.S', code, append=False)
            run_cmd(f'{RISCV_GCC} {OUTPUT_PATH / name}.S -c -o {OUTPUT_PATH / name}.o')
            _write_profile_stage(name, f"assemble:{suffix}:objdump")
            output = run_cmd(f'{RISCV_OBJDUMP} -d {OUTPUT_PATH / name}.o')

            import re
            pattern = r'^\s*[0-9a-f]+:\s+(.*)'
            # pattern = r'^\s*[0-9a-f]+:\s+([0-9a-f]+)'
            codes = re.findall(pattern, output, re.MULTILINE)
            if codes and codes[-1].startswith('0000006f'):
                codes = codes[:-1]
            if codes:
                codes[-1] = replace_branch_jump(codes[-1])
            machine_code = '\n'.join(codes)
            _write_profile_stage(name, f"assemble:{suffix}:write")
            write_to_file(f'{OUTPUT_PATH / name}.{suffix}', machine_code, append=False)
            return machine_code
        except Exception as e:
            if not verbose:
                cleanup_resources(name)
            raise RuntimeError(f"Assemble code failed: {e}")

    def cleanup_resources(name):
        files_to_remove = [
            f"{OUTPUT_PATH / name}.S",
            f"{OUTPUT_PATH / name}.o",
            f"{OUTPUT_PATH / name}.code",
            f"{OUTPUT_PATH / name}.init",
            f"{OUTPUT_PATH / name}.exe"
        ]
        for file_path in files_to_remove:
            rm_file(file_path)

    # INFO(f'transform [{filepath}]')
    filepath = str(filepath)
    test_name = filepath.split('/')[-1].replace('.S', '')
    content = read_file(filepath) + '\n'
    failed = False
    error_msg = ""

    if output_path == '':
        output_path = f"{OUTPUT_PATH / test_name}"

    result = None
    try:
        # transform block
        _write_profile_stage(test_name, "transform:parse")
        prog = parse_program(content)
        for inst in prog.insts:
            if inst.get_addr() is XREG[0]:
                return f"SKIP: zero-base memory access at {inst.code}"
        # prog = zero_imm_for_block(prog)
        _write_profile_stage(test_name, "transform:legalize_branch")
        prog = legalize_jump_and_branch(prog)
        _write_profile_stage(test_name, "transform:remap_regs")
        prog = remap_regs_for_block(prog)
        _write_profile_stage(test_name, "transform:check_lui_auipc")
        if has_lui_auipc(prog):
            fixed_access = find_unmappable_fixed_address_access(prog)
            if fixed_access is not None:
                return f"SKIP: unmappable fixed address access at {fixed_access.code}"
            if os.environ.get("RVMCA_STRICT_LUI_AUIPC") == "1":
                return f"SKIP: unsupported lui/auipc block: {test_name}"
            prog = fix_lui_auipc_imm(prog)
        # if verbose:
        #     INFO(f'<Block>:\n{content}')
        #     INFO(f'<New Block>:\n{prog.code}')
        _write_profile_stage(test_name, "transform:init_states")
        try:
            init_insts = init_states_for_block(prog, name=test_name, verbose=verbose)
        except UnsupportedBlockError as e:
            return f"SKIP: {e}"
        except ConcreteReplayFailure as e:
            test_code = '\n'.join([inst.code for inst in prog.insts])
            if e.candidate_init:
                init_code = '\n'.join([inst.code for inst in e.candidate_init])
                write_to_file(f'{OUTPUT_PATH / test_name}.init.asm', init_code, append=False)
                assemble_code(init_code, test_name, suffix='init')
            write_to_file(f'{OUTPUT_PATH / test_name}.code.asm', test_code, append=False)
            assemble_code(test_code, test_name, suffix='code')
            raise
        _write_profile_stage(test_name, "transform:build_init_and_test_code")
        init_code = '\n'.join([inst.code for inst in init_insts])
        test_code = '\n'.join([inst.code for inst in prog.insts])
        write_to_file(f'{OUTPUT_PATH / test_name}.init.asm', init_code, append=False)
        write_to_file(f'{OUTPUT_PATH / test_name}.code.asm', test_code, append=False)

        if verbose:
            INFO('\n<New Block with init code>:')
            INFO('# init code')
            INFO(init_code)
            INFO('# test code')
            INFO(test_code)

        _write_profile_stage(test_name, "transform:assemble_init")
        assemble_code(init_code, test_name, suffix='init')  # test_name.init
        _write_profile_stage(test_name, "transform:assemble_code")
        assemble_code(test_code, test_name, suffix='code')  # test_name.code
        _write_profile_stage(test_name, "transform:pp_run")
        result = run_cmd(f"qemu-riscv64 {TOOLS_PATH / 'pp' / 'pp'} {output_path}.init {output_path}.code")

        if not result:
            _write_profile_stage(test_name, "transform:pp_failed_write_error")
            run_cmd(f"echo '# init code' > {output_path}.error")
            run_cmd(f"cat {OUTPUT_PATH / test_name}.init >> {output_path}.error")
            run_cmd(f"echo '\n\n# test code' >> {output_path}.error")
            run_cmd(f"cat {OUTPUT_PATH / test_name}.code >> {output_path}.error")
            run_cmd(f"echo '\n\nError: pp fails.' >> {output_path}.error")
        # rm_file(f"{OUTPUT_PATH / test_name}.code")
        # rm_file(f"{OUTPUT_PATH / test_name}.init")
        # else:
        # run_cmd(f"mv {OUTPUT_PATH / test_name}.code {output_path}.code")
        # run_cmd(f"mv {OUTPUT_PATH / test_name}.init {output_path}.init")
        assert result, "Error: pp fails."
        _write_profile_stage(test_name, "transform:done")
    except UnsupportedBlockError as e:
        return f"SKIP: {e}"
    except Exception as e:
        import traceback
        traceback.print_exc()
        error_msg = e
        failed = True
    finally:
        rm_file(f"{OUTPUT_PATH / test_name}.o")
        rm_file(f"{OUTPUT_PATH / test_name}.S")
        rm_file(f"{OUTPUT_PATH / test_name}.exe")
        if not failed:
            # INFO(f'Successfully!\n')
            pass
        # else:
        #     raise AssertionError(error_msg)
