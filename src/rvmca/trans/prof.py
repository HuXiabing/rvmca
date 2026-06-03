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
    # TODO: check the available registers
    find_reg_by_name(n)
    for n in [f't{i}' for i in range(6)] + \
             [f'a{i}' for i in [0, 1, 2, 3, 4, 6, 7]] + \
             [f's{i}' for i in range(12)]
]

STACK_RANGE = 0x7ff
TEMP_REG = 't6'
TEMP_REG2 = 's11'
REG_PREFIX = 'rvmca_reg_'
CONCRETE_REPLAY_SP = 0x7fff00000000
MAX_INIT_SOLVE_RETRIES = 8
INIT_PTR_MIN_OFFSET = 16
MAX_SP_REL_OFFSET = 1 << 40


class UnsupportedBlockError(RuntimeError):
    """Raised for blocks outside the current sp-relative init strategy."""


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
    assert len(need_remap) <= len(available_regs), 'Fail to remap regs. Not enough available regs!'

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

    assert len(x_need_remap) <= len(x_available), 'Fail to remap regs. Not enough available xregs.'
    assert len(f_need_remap) <= len(f_available), 'Fail to remap regs. Not enough available fregs!'

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


def add_addr_range_checking(prog: Program, temp_reg: str = None) -> Program:
    """Add address checking for a block"""

    temp = TEMP_REG if temp_reg is None else temp_reg
    check_block_validity(prog)

    prog = copy.deepcopy(prog)
    insts = []
    for inst in prog.insts:
        if inst.type in [IType.Load, IType.Store, IType.Amo]:
            addr = inst.get_addr()
            imm = inst.imm
            # temp = base + offset
            insts.append(UFmtInst('li', temp, imm))
            insts.append(RFmtInst('add', temp, str(addr), temp))  # 计算实际地址
            # temp < sp
            insts.append(BFmtInst('bge', temp, 'sp', label='fail'))
            # temp >= sp - STACK_RANGE
            insts.append(IFmtInst('addi', temp, temp, STACK_RANGE))
            insts.append(BFmtInst('blt', temp, 'sp', label='fail'))
            if inst.width > 1:
                # check address alignment
                mask = inst.width - 1
                # TODO: it is ugly
                # temp & mask == 0
                insts.append(IFmtInst('addi', temp, temp, -STACK_RANGE))  # 还原回实际地址
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


def init_states_for_block(prog: Program, name: str, verbose: bool) -> List[Inst]:
    """generate init code for a block"""
    regs_defined = {XREG[0], XREG[2]}  # x0, sp
    init_code = []

    def compile_block(program: Program, bin_name: str):
        wrapper_path = PROJECT_PATH / 'src' / 'rvmca' / 'trans' / 'template' / 'block_wrapper.S'
        wrapper = read_file(wrapper_path)
        wrapper = wrapper.replace('#CODE#', program.code)
        write_to_file(f'{OUTPUT_PATH / bin_name}.S', wrapper, append=False)
        run_cmd(f'{RISCV_GCC} {OUTPUT_PATH / bin_name}.S -o {OUTPUT_PATH / bin_name}.exe')

    # compile and load binary
    # add address range checking for symbolic execution
    prog2se = add_addr_range_checking(prog, TEMP_REG)

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

    def concrete_stack_addr(offset: int) -> int:
        return (CONCRETE_REPLAY_SP - offset) & ((1 << 64) - 1)

    def stack_offset_for_value(value: int):
        offset = (CONCRETE_REPLAY_SP - value) & ((1 << 64) - 1)
        if offset <= MAX_SP_REL_OFFSET and concrete_stack_addr(offset) == (value & ((1 << 64) - 1)):
            return offset
        return None

    def set_concrete_state(state, reg_values, mem_values):
        for i in range(32):
            setattr(state.regs, f'x{i}', claripy.BVV(0, 64))
        state.regs.sp = concrete_bvv(CONCRETE_REPLAY_SP)
        state.regs.x0 = claripy.BVV(0, 64)
        for reg, value in reg_values.items():
            setattr(state.regs, reg.name, concrete_bvv(value))
        for addr_offset, value in mem_values.items():
            state.memory.store(
                concrete_stack_addr(addr_offset),
                concrete_bvv(value),
                endness=proj.arch.memory_endness,
            )

    def replay_concrete_init(reg_values, mem_values, debug=False):
        replay_state = proj.factory.blank_state(
            addr=begin_addr,
            mode='symbolic',
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        set_concrete_state(replay_state, reg_values, mem_values)
        replay_mgr = proj.factory.simulation_manager(replay_state)
        replay_mgr.explore(find=end_addr)
        if replay_mgr.found:
            return replay_mgr.found[0]
        if debug:
            print(f"replay failed for {name}")
            print("reg_values", {reg.name: hex(value) for reg, value in reg_values.items()})
            print("mem_values", {offset: hex(value) for offset, value in mem_values.items()})
            if fail_addr is not None:
                fail_state = proj.factory.blank_state(
                    addr=begin_addr,
                    mode='symbolic',
                    add_options={
                        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                    },
                )
                set_concrete_state(fail_state, reg_values, mem_values)
                fail_mgr = proj.factory.simulation_manager(fail_state)
                fail_mgr.explore(find=fail_addr)
                if fail_mgr.found:
                    state = fail_mgr.found[0]
                    regs = {}
                    for reg_name in ['x5', 'x6', 'x10', 'x12', 'x13', 'x14', 'x24', 'x26', 'x31', 'sp']:
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

    def replay_prefix_state(reg_values, mem_values, target_addr):
        replay_state = proj.factory.blank_state(
            addr=begin_addr,
            mode='symbolic',
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        set_concrete_state(replay_state, reg_values, mem_values)
        replay_mgr = proj.factory.simulation_manager(replay_state)
        replay_mgr.explore(find=target_addr)
        return replay_mgr.found[0] if replay_mgr.found else None

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
    simgr.explore(find=begin_addr + len(regs_undefined) * 4)  # 确保符号执行能够执行完所有的寄存器检查指令
    history_events = simgr.found[0].history.events.hardcopy
    history_events = [e for e in history_events if isinstance(e, SimActionConstraint)]
    if verbose:
        DEBUG(f'{history_events = }')
    for i, event in enumerate(history_events):
        constraint = event.constraint
        assert constraint.ast.op == 'SGE'
        reg_symbol = constraint.ast.args[0]  # 当前引擎真正正在使用的那个符号 AST 对象，符号执行引擎内部用来代表那个未定义寄存器的“符号变量对象”
        if not str(reg_symbol).startswith(f'<BV64 {REG_PREFIX}'):
            r = regs_undefined[i]
            reg_to_symbol[r] = reg_symbol
            if verbose:
                WARNING(f'unconstrained register: {str(reg_symbol)} for {r}')
    if verbose:
        print("reg_to_symbol", reg_to_symbol)

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

    for inst_idx, inst in access_insts:
        target_addr = begin_addr + inst_idx * 4  # 模拟执行，停在指令即将执行的那一刻
        pc = simgr.found[0].ip.concrete_value
        assert pc <= target_addr
        if pc < target_addr:
            simgr = proj.factory.simulation_manager(simgr.found[0])
            simgr.explore(find=target_addr)
            assert simgr.found
        # when rd == rs1 in a load instruction, the state of rs1 will be overwritten
        # we get the state of rs1 before the execution of the load inst
        base_symbol = getattr(simgr.found[0].regs, str(inst.rs1))
        # check if it is unconstrained register
        if base_symbol.op == 'BVS' and base_symbol.args[0].startswith(REG_PREFIX):
            if inst.rs1 in reg_to_symbol.keys():
                base_symbol = reg_to_symbol[inst.rs1]

        addr_symbol = base_symbol + inst.imm
        mem_accesses.append((inst, addr_symbol, inst_idx, inst.width))
        if inst.type in [IType.Store, IType.Amo]:
            data_symbol = getattr(simgr.found[0].regs, str(inst.rs2))
            store_accesses.append((inst, addr_symbol, inst_idx, inst.width, data_symbol))

        if inst.type != IType.Load:
            continue

        load_end_addr = target_addr + 4
        simgr = proj.factory.simulation_manager(simgr.found[0])
        simgr.explore(find=load_end_addr)  ## 执行这条 ld 指令
        assert simgr.found

        rd_symbol = getattr(simgr.found[0].regs, str(inst.rd))
        load_entry = (inst, rd_symbol, addr_symbol, inst_idx)
        load_accesses.append(load_entry)
        if id(inst) in mem_base_ids:
            mem_base_map[inst] = load_entry
        if verbose and id(inst) in mem_base_ids:
            DEBUG(f'memory unconstrained symbol {name}: {rd_symbol = } {addr_symbol = }')

    # create a simulation manager
    simgr = proj.factory.simulation_manager(simgr.found[0])
    simgr.explore(find=end_addr)

    assert simgr.found, f'simulation fails at {end_addr:#x}'
    final_state = simgr.found[0]

    if verbose:
        DEBUG(f'{final_state.solver.constraints = }')
        DEBUG(f'{final_state.history.events.hardcopy = }')
    solver = final_state.solver
    solver.add(final_state.regs.x0 == 0)

    assert solver.satisfiable(), f"[ERROR]: {name} is not satisfiable"

    solver.add(init_sp & 7 == 0)  # stack pointer alignment
    # solver.add(final_state.regs.sp == claripy.BVV(0x70a4a7bff690, 64))
    base_solver = claripy.Solver()
    base_solver.add(solver.constraints)
    concrete_sp_solver = base_solver.branch()
    concrete_sp_solver.add(init_sp == CONCRETE_REPLAY_SP)
    if concrete_sp_solver.satisfiable():
        base_solver.add(init_sp == CONCRETE_REPLAY_SP)

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

    pointer_value_keys = set()
    for load_inst, rd_symbol, _, load_idx in load_accesses:
        if load_inst.width != 8:
            continue
        rd_vars = getattr(rd_symbol, 'variables', set())
        if not rd_vars:
            continue
        for _, addr_symbol, access_idx, _ in mem_accesses:
            addr_vars = getattr(addr_symbol, 'variables', set())
            if access_idx > load_idx and addr_vars & rd_vars:
                pointer_value_keys.add(str(rd_symbol))
                break
    if verbose:
        print('mem_base_map', mem_base_map)

    def materialize_init(candidate_solver):
        candidate_solver = candidate_solver.branch()
        candidate_init = []
        reg_init = []
        reg_values = {}
        mem_values = {}
        mem_offset_addr_symbols = {}
        mem_slot_symbols = {}
        addr_expr_offsets = {}

        def satisfiable_with(expr, val):
            test_solver = candidate_solver.branch()
            test_solver.add(expr == val)
            return test_solver.satisfiable()

        def solver_min(expr):
            try:
                return candidate_solver.min(expr)
            except Exception:
                return None

        def choose_value(expr, preferred=None, positive=False, align=None, avoid=None, width=8, required=True):
            avoid = [] if avoid is None else avoid

            def concrete_value_ok(val):
                if positive and val <= 0:
                    return False
                if align and val % align != 0:
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

            choices = []
            if preferred is not None:
                choices.append(preferred)
            try:
                minimum = candidate_solver.min(expr)
                choices.append(minimum)
                step = align if align else 1
                for i in range(1, 64):
                    choices.append(minimum + i * step)
            except Exception:
                pass

            seen = set()
            for val in choices:
                if val in seen:
                    continue
                seen.add(val)
                if preferred is not None and val < preferred:
                    continue
                result = add_value_if_sat(val)
                if result is not None:
                    return result

            seen = set()
            for val in choices:
                if val in seen:
                    continue
                seen.add(val)
                result = add_value_if_sat(val)
                if result is not None:
                    return result

            search_starts = []
            if preferred is not None:
                search_starts.append(preferred)
            if choices:
                search_starts.extend(choices)
            try:
                search_starts.append(candidate_solver.min(expr))
            except Exception:
                pass

            step = align if align else 1
            seen = set()
            for start in search_starts:
                if positive:
                    start = max(start, 1)
                if align:
                    start = ((start + align - 1) // align) * align
                for i in range(512):
                    val = start + i * step
                    if val in seen:
                        continue
                    seen.add(val)
                    result = add_value_if_sat(val)
                    if result is not None:
                        return result

            if not required:
                return None

            try:
                val = candidate_solver.min(expr)
            except Exception as exc:
                raise AssertionError(f"cannot choose concrete value for {expr}") from exc
            if not concrete_value_ok(val):
                raise AssertionError(f"cannot choose non-overlapping concrete value for {expr}")
            candidate_solver.add(expr == val)
            return val

        def try_add_constraint(constraint):
            test_solver = candidate_solver.branch()
            test_solver.add(constraint)
            if test_solver.satisfiable():
                candidate_solver.add(constraint)
                return True
            return False

        def append_value_init(insts, reg_name, value, force_stack_offset=None):
            stack_offset = force_stack_offset
            if stack_offset is None:
                stack_offset = stack_offset_for_value(value)
            if stack_offset is not None:
                insts.append(UFmtInst('li', reg_name, stack_offset))
                insts.append(RFmtInst('sub', reg_name, 'sp', reg_name))
            else:
                insts.append(UFmtInst('li', reg_name, value & ((1 << 64) - 1)))

        def mem_value_expr(inst, rd_symbol):
            return rd_symbol

        def load_raw_value(inst, value_expr):
            bits = inst.width * 8
            return value_expr[bits - 1:0]

        def constrain_word_field(word_symbol, byte_offset, inst, value_expr):
            bits = inst.width * 8
            lo = byte_offset * 8
            hi = lo + bits - 1
            return try_add_constraint(word_symbol[hi:lo] == load_raw_value(inst, value_expr))

        def same_address(addr_a, addr_b):
            if addr_b is None:
                return False
            if str(addr_a) == str(addr_b):
                return True
            test_solver = candidate_solver.branch()
            test_solver.add(addr_a != addr_b)
            return not test_solver.satisfiable()

        def stored_value_for_load(store_data_symbol, store_width, load_inst):
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

        def prior_same_addr_store(addr_symbol, inst_idx):
            for store_inst, store_addr_symbol, store_idx, store_width, store_data_symbol in reversed(store_accesses):
                if store_idx < inst_idx and same_address(store_addr_symbol, addr_symbol):
                    return store_inst, store_addr_symbol, store_idx, store_width, store_data_symbol
            return None

        def has_intervening_same_addr_store(addr_symbol, prev_idx, next_idx):
            for _, store_addr_symbol, store_idx, _, _ in store_accesses:
                if prev_idx < store_idx < next_idx and same_address(store_addr_symbol, addr_symbol):
                    return True
            return False

        def has_prior_same_addr_store(addr_symbol, inst_idx):
            return prior_same_addr_store(addr_symbol, inst_idx) is not None

        def add_store_no_overlap_for_word(word_offset, addr_symbols):
            for _, store_addr_symbol, _, store_width, _ in store_accesses:
                if any(same_address(store_addr_symbol, addr_symbol) for addr_symbol in addr_symbols):
                    continue
                try_add_constraint(symbolic_no_overlap(store_addr_symbol, store_width, word_offset))

        def choose_register_value(symbol, preferred=None, align=None):
            choices = []
            if preferred is not None:
                choices.append(preferred)
            try:
                minimum = candidate_solver.min(symbol)
                choices.append(minimum)
                step = align if align else 1
                for i in range(1, 64):
                    choices.append(minimum + i * step)
            except Exception:
                pass

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
                if satisfiable_with(symbol, val):
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
                solver_min(offset_expr),
                positive=True,
                align=8,
                avoid=used_stack_offsets,
                width=8,
                required=False,
            )
            if offset is None:
                offset = choose_value(
                    offset_expr,
                    solver_min(offset_expr),
                    positive=True,
                    align=8,
                    required=False,
                )
            if offset is None:
                return None
            used_stack_offsets.append((offset, 8))
            return concrete_stack_addr(offset)

        def choose_memory_value(expr, preferred=None, avoid_stack_offsets=None, pointer_like=False):
            avoid_stack_offsets = [] if avoid_stack_offsets is None else avoid_stack_offsets
            if pointer_like:
                offset_expr = init_sp - expr
                for offset in range(INIT_PTR_MIN_OFFSET, STACK_RANGE + 1, 8):
                    if any(
                        concrete_ranges_overlap(offset, 8, used_offset, used_width)
                        for used_offset, used_width in avoid_stack_offsets
                    ):
                        continue
                    if satisfiable_with(offset_expr, offset):
                        candidate_solver.add(offset_expr == offset)
                        return concrete_stack_addr(offset)

            choices = []
            if preferred is not None:
                choices.append(preferred)
            try:
                minimum = candidate_solver.min(expr)
                choices.append(minimum)
                for i in range(1, 64):
                    choices.append(minimum + i * 8)
            except Exception:
                pass

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

            return choose_value(expr, preferred)

        used_stack_offsets = []
        scalar_offset = 0
        base_like_regs = set()
        for reg, symbol in reg_to_symbol.items():
            symbol_vars = getattr(symbol, 'variables', set())
            if not symbol_vars:
                continue
            for _, addr_symbol, _, _ in mem_accesses:
                if not (symbol_vars & getattr(addr_symbol, 'variables', set())):
                    continue
                residual = claripy.simplify(addr_symbol - symbol)
                if not (symbol_vars & getattr(residual, 'variables', set())):
                    base_like_regs.add(reg)
                    break

        for r in regs_undefined:
            symbol = reg_to_symbol[r]
            val = choose_stack_relative_register_value(symbol) if r in base_like_regs else None
            if val is None:
                preferred = solver_min(symbol)
                if preferred is not None:
                    preferred += scalar_offset
                val = choose_register_value(symbol, preferred)
            append_value_init(reg_init, r.name, val)
            reg_values[r] = val & ((1 << 64) - 1)
            scalar_offset += 8

        for i, (first_inst, first_rd_symbol, first_addr_symbol, first_idx) in enumerate(mem_entries):
            first_expr = mem_value_expr(first_inst, first_rd_symbol)
            for inst, rd_symbol, addr_symbol, inst_idx in mem_entries[i + 1:]:
                if has_intervening_same_addr_store(first_addr_symbol, first_idx, inst_idx):
                    continue
                if same_address(first_addr_symbol, addr_symbol):
                    try_add_constraint(mem_value_expr(inst, rd_symbol) == first_expr)

        for inst, rd_symbol, addr_symbol, inst_idx in mem_entries:
            prior_store = prior_same_addr_store(addr_symbol, inst_idx)
            if prior_store is None:
                continue
            _, _, _, store_width, store_data_symbol = prior_store
            stored_expr = stored_value_for_load(store_data_symbol, store_width, inst)
            if stored_expr is not None:
                try_add_constraint(mem_value_expr(inst, rd_symbol) == stored_expr)

        for _, addr_symbol, _, width in mem_accesses:
            if width > 1:
                try_add_constraint((addr_symbol & (width - 1)) == 0)

        access_ranges = []
        for inst, rd_symbol, addr_symbol, inst_idx in mem_entries:
            addr_expr = init_sp - addr_symbol
            addr_key = str(addr_symbol)
            if has_prior_same_addr_store(addr_symbol, inst_idx):
                continue
            if addr_key in addr_expr_offsets:
                addr = addr_expr_offsets[addr_key]
                candidate_solver.add(addr_expr == addr)
            else:
                avoid_ranges = [
                    (used_addr, used_width)
                    for used_addr, used_width, used_addr_symbol in access_ranges
                    if not same_address(addr_symbol, used_addr_symbol)
                ]
                addr = choose_value(
                    addr_expr,
                    solver_min(addr_expr),
                    positive=True,
                    align=inst.width if inst.width > 1 else None,
                    avoid=avoid_ranges,
                    width=inst.width,
                    required=False,
                )
                if addr is None:
                    addr = choose_value(
                        addr_expr,
                        solver_min(addr_expr),
                        positive=True,
                        align=inst.width if inst.width > 1 else None,
                        width=inst.width,
                    )
                addr_expr_offsets[addr_key] = addr
            access_ranges.append((addr, inst.width, addr_symbol))

            value_expr = mem_value_expr(inst, rd_symbol)
            word_offset = ((addr + 7) // 8) * 8
            byte_offset = word_offset - addr
            assert 0 <= byte_offset and byte_offset + inst.width <= 8
            if word_offset not in mem_slot_symbols:
                word_symbol = claripy.BVS(f'init_mem_word_{len(mem_slot_symbols)}_{word_offset}', 64)
                mem_slot_symbols[word_offset] = {
                    'symbol': word_symbol,
                    'pointer_like': False,
                }
                mem_offset_addr_symbols[word_offset] = []
            else:
                word_symbol = mem_slot_symbols[word_offset]['symbol']

            field_added = constrain_word_field(word_symbol, byte_offset, inst, value_expr)
            if not any(same_address(addr_symbol, known_addr) for known_addr in mem_offset_addr_symbols[word_offset]):
                mem_offset_addr_symbols[word_offset].append(addr_symbol)
            if field_added and str(value_expr) in pointer_value_keys and inst.width == 8 and byte_offset == 0:
                mem_slot_symbols[word_offset]['pointer_like'] = True

        for word_offset, slot in mem_slot_symbols.items():
            add_store_no_overlap_for_word(word_offset, mem_offset_addr_symbols[word_offset])

        for addr, slot in mem_slot_symbols.items():
            val_symbol = slot['symbol']
            used_mem_offsets = [(used_addr, 8) for used_addr in mem_values]
            assert candidate_solver.satisfiable(), f"[ERROR]: {name} init memory constraints are unsatisfiable"
            val = choose_memory_value(
                val_symbol,
                solver_min(val_symbol),
                avoid_stack_offsets=used_mem_offsets,
                pointer_like=slot['pointer_like'],
            )
            actual_value = val & ((1 << 64) - 1)
            value_stack_offset = stack_offset_for_value(actual_value)

            # prepare value
            append_value_init(candidate_init, TEMP_REG, actual_value, force_stack_offset=value_stack_offset)
            # prepare address
            candidate_init.append(UFmtInst('li', TEMP_REG2, addr))
            candidate_init.append(RFmtInst('sub', TEMP_REG2, 'sp', TEMP_REG2))

            candidate_init.append(StoreInst('sd', TEMP_REG, TEMP_REG2, 0))
            mem_values[addr] = actual_value

        candidate_init.extend(reg_init)
        return candidate_init, reg_values, mem_values, mem_offset_addr_symbols, candidate_solver

    def find_alias_constraints(reg_values, mem_values, mem_offset_addr_symbols, candidate_solver):
        def same_address(addr_a, addr_b):
            if addr_b is None:
                return False
            if str(addr_a) == str(addr_b):
                return True
            test_solver = candidate_solver.branch()
            test_solver.add(addr_a != addr_b)
            return not test_solver.satisfiable()

        constraints = []
        mem_offsets = sorted(mem_values.keys())
        for store_inst, store_addr_symbol, store_inst_idx, store_width, _ in store_accesses:
            store_addr = begin_addr + store_inst_idx * 4
            store_state = replay_prefix_state(reg_values, mem_values, store_addr)
            if store_state is None:
                continue

            concrete_store_addr = store_state.solver.eval(getattr(store_state.regs, str(store_inst.rs1))) \
                                  + store_inst.imm
            concrete_store_offset = (CONCRETE_REPLAY_SP - concrete_store_addr) & ((1 << 64) - 1)
            for mem_offset in mem_offsets:
                if any(same_address(store_addr_symbol, addr_symbol)
                       for addr_symbol in mem_offset_addr_symbols.get(mem_offset, [])):
                    continue
                if concrete_ranges_overlap(concrete_store_offset, store_width, mem_offset, 8):
                    constraints.append(symbolic_no_overlap(store_addr_symbol, store_width, mem_offset))

        return constraints

    current_solver = base_solver.branch()
    for retry in range(MAX_INIT_SOLVE_RETRIES + 1):
        assert current_solver.satisfiable(), f"[ERROR]: {name} is not satisfiable after init replay constraints"
        candidate_init, reg_values, mem_values, mem_offset_addr_symbols, candidate_solver = materialize_init(current_solver)
        if replay_concrete_init(reg_values, mem_values, debug=verbose) is not None:
            return candidate_init

        alias_constraints = find_alias_constraints(reg_values, mem_values, mem_offset_addr_symbols, candidate_solver)
        if not alias_constraints or retry == MAX_INIT_SOLVE_RETRIES:
            raise AssertionError(f"[ERROR]: {name} concrete replay fails after init solving")

        for constraint in alias_constraints:
            current_solver.add(constraint)

    raise AssertionError(f"[ERROR]: {name} concrete replay fails after init solving")


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
            write_to_file(f'{OUTPUT_PATH / name}.S', code, append=False)
            run_cmd(f'{RISCV_GCC} {OUTPUT_PATH / name}.S -c -o {OUTPUT_PATH / name}.o')
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
        prog = parse_program(content)
        # prog = zero_imm_for_block(prog)
        prog = legalize_jump_and_branch(prog)
        prog = remap_regs_for_block(prog)
        if has_lui_auipc(prog):
            return f"SKIP: unsupported lui/auipc block: {test_name}"
        # fix lui/auipc to use sp as base address
        # prog = fix_lui_auipc_imm(prog)
        # if verbose:
        #     INFO(f'<Block>:\n{content}')
        #     INFO(f'<New Block>:\n{prog.code}')
        init_insts = init_states_for_block(prog, name=test_name, verbose=verbose)
        init_code = '\n'.join([inst.code for inst in init_insts])
        test_code = '\n'.join([inst.code for inst in prog.insts])

        if verbose:
            INFO('\n<New Block with init code>:')
            INFO('# init code')
            INFO(init_code)
            INFO('# test code')
            INFO(test_code)

        assemble_code(init_code, test_name, suffix='init')  # test_name.init
        assemble_code(test_code, test_name, suffix='code')  # test_name.code
        result = run_cmd(f"qemu-riscv64 {TOOLS_PATH / 'pp' / 'pp'} {output_path}.init {output_path}.code")

        if not result:
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

    return result
