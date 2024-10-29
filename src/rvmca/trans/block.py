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

"""Register Re-map"""

from typing import List, Tuple

from rvmca.prog import IType, Program, Reg, XREG, FREG, Inst
import copy
import angr, claripy
from rvmca.config import *
from rvmca.trans.compile import compile_block


def _check_block_validity(prog: Program):
    """Check the validity of a block"""
    for inst in prog.insts[0:-1]:
        assert inst.type not in [IType.Branch, IType.Jump], f"{prog.insts} is not a basic block"


def zero_imm_for_block(prog: Program) -> Program:
    """Zero the immediate in a block"""
    _check_block_validity(prog)

    prog = copy.deepcopy(prog)

    for inst in prog.insts:
        if hasattr(inst, 'imm'):
            if inst.type is IType.Branch:
                inst.imm = 4
            else:
                inst.imm = 0

    return prog


def find_regs_no_def(prog: Program) -> List[Reg]:
    """find undefined registers"""
    _check_block_validity(prog)

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
    _check_block_validity(prog)

    addr_regs = []

    for i, inst in enumerate(prog.insts):
        inst = prog.insts[i]
        addr = inst.get_addr()
        if addr:
            addr_regs.append((i, addr))
    return addr_regs


def remap_regs_for_block(prog: Program, candidate_regs: List[Reg]) -> Program:
    """Remap registers for a block"""
    _check_block_validity(prog)

    prog = copy.deepcopy(prog)

    regs = set()
    for inst in prog.insts[0:-1]:
        for reg in inst.get_regs():
            regs.add(reg)
    need_remap = [r for r in regs if r not in candidate_regs]
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


def init_regs_for_block(prog: Program, filename: str = 'test') -> List[Inst]:
    """generate init code for a block"""
    STACK_RANGE = 0xf00
    regs_defined = {XREG[0], XREG[2]}  # x0, sp
    regs_undefined, regs_addr_undefined = set(), set()
    init_code = []

    # collect undefined registers
    for i, inst in enumerate(prog.insts):
        for r in inst.get_uses():
            if r not in regs_defined:
                if inst.get_addr() == r:
                    regs_addr_undefined.add(r)
                else:
                    regs_undefined.add(r)
        r = inst.get_def()
        if r:
            regs_defined.add(r)

    # compile and load binary
    compile_block(prog, filename)
    proj = angr.Project(OUTPUT_PATH / filename, auto_load_libs=False)
    begin_addr = proj.loader.main_object.get_symbol('rvmca_block_begin')
    end_addr = proj.loader.main_object.get_symbol('rvmca_block_end')
    init_state = proj.factory.blank_state(addr=begin_addr.rebased_addr,
                                          add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES,
                                                       angr.options.MEMORY_SYMBOLIC_BYTES_MAP,
                                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                       angr.options.CONSERVATIVE_WRITE_STRATEGY,
                                                       angr.options.CONSERVATIVE_READ_STRATEGY,
                                                       angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES})

    # create variables for undefined registers
    reg_vars = {}
    for reg_name in [r.name for r in regs_undefined]:
        reg_var = claripy.BVS(reg_name, 64)
        setattr(init_state.regs, reg_name, reg_var)
        reg_vars[reg_name] = reg_var

    # assign sp+offset to undefined address registers
    from rvmca.prog import IFmtInst
    init_sp = init_state.regs.sp
    for i, r in enumerate(regs_addr_undefined):
        offset = -8 * (i + 1)
        setattr(init_state.regs, r.name, init_sp + offset)
        init_code.append(IFmtInst('addi', r.name, 'sp', offset), )

    # create a simulation manager
    simgr = proj.factory.simulation_manager(init_state)
    addr_constraints = []

    for i, inst in enumerate(prog.insts):
        if inst.type in [IType.Branch, IType.Jump]:
            break
        addr_reg = inst.get_addr()
        if addr_reg:
            addr_var = getattr(simgr.one_active.regs, addr_reg.name)
            mask = 1 << inst.width >> 1 - 1
            address = addr_var + inst.imm
            # constraint address to the stack space
            addr_constraints.append(address & mask == 0)
            addr_constraints.append(address >= init_sp - STACK_RANGE)
            addr_constraints.append(address <= init_sp)
        simgr.step(num_inst=1)

    # TODO: handle jump instructions
    simgr.explore(find=end_addr.rebased_addr)
    assert simgr.found

    solver = claripy.Solver()
    solver.add(simgr.found[0].solver.constraints)
    solver.add(addr_constraints)

    from rvmca.prog import UFmtInst
    for k, v in reg_vars.items():
        val = solver.max(v)
        offset = init_sp - val
        if offset.concrete_value <= STACK_RANGE:
            init_code.append(IFmtInst('addi', k, 'sp', offset.concrete_value))
        else:
            init_code.append(UFmtInst('li', k, val))

    return init_code
