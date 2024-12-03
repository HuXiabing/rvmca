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
    RFmtInst, StoreInst
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
            insts.append(RFmtInst('add', temp, str(addr), temp))
            # temp < sp
            insts.append(BFmtInst('bge', temp, 'sp', label='fail'))
            # temp >= sp - STACK_RANGE
            insts.append(IFmtInst('addi', temp, temp, STACK_RANGE))
            insts.append(BFmtInst('blt', temp, 'sp', label='fail'))
            if inst.width == 1:
                continue
            # check address alignment
            mask = (1 << math.floor(math.log2(inst.width))) - 1
            # TODO: it is ugly
            # temp & mask == 0
            insts.append(IFmtInst('addi', temp, temp, -STACK_RANGE))
            insts.append(IFmtInst('andi', temp, temp, mask))
            insts.append(BFmtInst('bne', temp, 'x0', label='fail'))
        insts.append(inst)
    prog.insts = insts
    return prog


def init_states_for_block(prog: Program, name: str) -> List[Inst]:
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
    rvfg = RVFG(ssas)
    # rvfg.plot(OUTPUT_PATH / 'fail')
    # FIXME: we only consider xregs for now
    regs_undefined = list({r for r in rvfg.find_undef_regs()
                           if r in XREG and r not in regs_defined})

    # add dummy checking for undefined registers to avoid unconstrained symbol
    prog2se = add_undef_reg_checking(prog2se, list(regs_undefined))
    last_inst = prog2se.insts[-1]
    if isinstance(last_inst, BFmtInst):
        last_inst.label = 'rvmca_block_end'
        last_inst.imm = None

    INFO('\n<New Block with address range checking>:')
    INFO(prog2se.code)
    compile_block(prog2se, name)
    proj = angr.Project(f'{OUTPUT_PATH / name}.exe', auto_load_libs=False)
    begin_addr = proj.loader.main_object.get_symbol('rvmca_block_begin').rebased_addr
    end_addr = proj.loader.main_object.get_symbol('rvmca_block_end').rebased_addr
    init_state = proj.factory.blank_state(addr=begin_addr,
                                          mode='symbolic',
                                          add_options={
                                              angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                              angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                              angr.options.CONSERVATIVE_WRITE_STRATEGY,
                                              angr.options.CONSERVATIVE_READ_STRATEGY,
                                          },
                                          )
    from rvmca.prog import UFmtInst
    init_state.options.discard(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    DEBUG(init_state.options.tally())

    # init_state.options.remove(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    # block = proj.factory.block(begin_addr)
    # INFO("<Block>")
    # for inst in block.capstone.insns:
    #     INFO(f"{inst.address:#x}: {inst.mnemonic} {inst.op_str}")
    # end_addr = block.instruction_addrs[-1]

    def find_base_addr(ssa_inst):
        assert ssa_inst.is_ldst()
        addr_reg = ssa_inst.get_addr()
        tgt_node = rvfg.find_node_by_value(addr_reg)
        clean_insts = ['add', 'addi', 'addw', 'addiw']
        paths = rvfg.find_clean_paths(rvfg.undef, tgt_node, clean_insts)
        if len(paths) == 0:
            clean_insts.append('ld')
            paths = rvfg.find_clean_paths(rvfg.mem, tgt_node, clean_insts)
            assert len(paths) > 0
            return [p[0].attr.inst for p in paths]
        else:
            return [p[0].tgt.value for p in paths]

    # map ssa inst to its addr base reg
    undef_base_regs = []
    mem_base_insts = []
    for inst in [i for i in ssas if i.is_ldst()]:
        for r in find_base_addr(inst):
            if isinstance(r, BitVecRef):
                reg = bitvec_to_reg(r)
                if reg not in undef_base_regs:
                    undef_base_regs.append(reg)
            elif isinstance(r, Inst):
                for i in prog2se.insts:
                    if i.pc == r.pc:
                        mem_base_insts.append(i)
                        break

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

    DEBUG(f'{regs_undefined =}')

    # init_state.add_constraints(init_sp == claripy.BVV(0x7fff0000, 64))
    init_state.add_constraints(init_state.regs.x0 == 0)

    # create a simulation manager
    simgr = proj.factory.simulation_manager(init_state)

    # mapping unconstrained symbol to undefined registers
    simgr.explore(find=begin_addr + len(regs_undefined) * 4)
    history_events = simgr.found[0].history.events.hardcopy
    DEBUG(f'{history_events = }')
    history_events = [e for e in history_events if isinstance(e, SimActionConstraint)]
    for i, event in enumerate(history_events):
        constraint = event.constraint
        assert constraint.ast.op is 'SGE'
        reg_symbol = constraint.ast.args[0]
        if not str(reg_symbol).startswith(f'<BV64 {REG_PREFIX}'):
            r = regs_undefined[i]
            reg_to_symbol[r] = reg_symbol
            WARNING(f'unconstrained register: {str(reg_symbol)} for {r}')

    # capture unconstrained load value
    mem_base_insts = list(mem_base_insts)
    mem_base_insts.sort(key=lambda i: i.pc)
    mem_base_map = {}
    for inst in mem_base_insts:
        target_addr = begin_addr + prog2se.insts.index(inst) * 4
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

        target_addr += 4
        simgr = proj.factory.simulation_manager(simgr.found[0])
        simgr.explore(find=target_addr)
        assert simgr.found

        events = list(simgr.found[0].history.events.hardcopy)
        events = [e for e in events if not isinstance(e, SimActionConstraint)]
        events.reverse()
        for event in events:
            if event.ins_addr == target_addr - 4:
                rd_symbol = getattr(simgr.found[0].regs, str(inst.rd))
                mem_base_map[inst] = (rd_symbol, addr_symbol)
                DEBUG(f'memory unconstrained symbol {name}: {rd_symbol = } {addr_symbol = }')
                break

    # create a simulation manager
    simgr = proj.factory.simulation_manager(simgr.found[0])
    simgr.explore(find=end_addr)

    assert simgr.found, f'simulation fails at {end_addr:#x}'
    final_state = simgr.found[0]

    DEBUG(f'{final_state.solver.constraints = }')
    DEBUG(f'{final_state.history.events.hardcopy = }')
    solver = final_state.solver
    solver.add(final_state.regs.x0 == 0)

    assert solver.satisfiable(), f"[ERROR]: {name} is not satisfiable"

    solver.add(init_sp & 7 == 0)  # stack pointer alignment
    # solver.add(final_state.regs.sp == claripy.BVV(0x70a4a7bff690, 64))

    undefined_reg_vars = [reg for reg in regs_undefined if reg not in undef_base_regs]
    undefined_base_vars = [reg for reg in regs_undefined if reg in undef_base_regs]

    for r in undefined_reg_vars:
        symbol = reg_to_symbol[r]
        val = solver.min(symbol)
        init_code.append(UFmtInst('li', r.name, val))
        solver.add(symbol == val)

    for r in undefined_base_vars:
        symbol = reg_to_symbol[r]
        val = solver.min(init_sp - symbol)
        init_code.append(UFmtInst('li', r.name, val))
        init_code.append(RFmtInst('sub', r.name, 'sp', r.name))
        solver.add(init_sp - symbol == val)

    mem_val_map = {}

    for rd_symbol, addr_symbol in mem_base_map.values():
        addr = solver.min(init_sp - addr_symbol)
        assert addr > 0
        solver.add(init_sp - addr_symbol == addr)

        if addr in mem_val_map:
            val = mem_val_map[addr]
        else:
            val = solver.min(init_sp - rd_symbol)
            assert val > 0
            solver.add(init_sp - rd_symbol == val)

        # prepare value
        init_code.append(UFmtInst('li', TEMP_REG, val))
        init_code.append(RFmtInst('sub', TEMP_REG, 'sp', TEMP_REG))
        # prepare address
        init_code.append(UFmtInst('li', TEMP_REG2, addr))
        init_code.append(RFmtInst('sub', TEMP_REG2, 'sp', TEMP_REG2))

        init_code.append(StoreInst('sd', TEMP_REG, TEMP_REG2, 0))

        mem_val_map[addr] = val

    return init_code


def transform_for_profiling(filepath, output_path=''):
    def assemble_code(code: str, name: str, suffix: str = 'code'):
        """Output a file named {name}.code"""
        write_to_file(f'{OUTPUT_PATH / name}.S', code, append=False)
        run_cmd(f'{RISCV_GCC} {OUTPUT_PATH / name}.S -c -o {OUTPUT_PATH / name}.o')
        output = run_cmd(f'{RISCV_OBJDUMP} -d {OUTPUT_PATH / name}.o')

        import re
        pattern = r'^\s*[0-9a-f]+:\s+(.*)'
        # pattern = r'^\s*[0-9a-f]+:\s+([0-9a-f]+)'
        codes = re.findall(pattern, output, re.MULTILINE)
        if codes[-1].startswith('0000006f'):
            codes = codes[:-1]
        machine_code = '\n'.join(codes)
        write_to_file(f'{OUTPUT_PATH / name}.{suffix}', machine_code, append=False)
        return machine_code

    # read file
    INFO(f'transform [{filepath}]')
    filepath = str(filepath)
    test_name = filepath.split('/')[-1].replace('.S', '')
    content = read_file(filepath) + '\n'
    failed = False
    error_msg = ""

    if output_path == '':
        output_path = f"{OUTPUT_PATH / test_name}"

    try:
        # transform block
        INFO(f'<Block>:\n{content}')
        prog = parse_program(content)
        # prog = zero_imm_for_block(prog)
        prog = legalize_jump_and_branch(prog)
        prog = remap_regs_for_block(prog)
        INFO(f'<New Block>:\n{prog.code}')
        init_insts = init_states_for_block(prog, name=test_name)
        init_code = '\n'.join([inst.code for inst in init_insts])
        test_code = '\n'.join([inst.code for inst in prog.insts])
        INFO('\n<New Block with init code>:')
        INFO('# init code')
        INFO(init_code)
        INFO('# test code')
        INFO(test_code)

        assemble_code(init_code, test_name, suffix='init')
        assemble_code(test_code, test_name)

        # run new block with pp
        test_path = OUTPUT_PATH / test_name
        result = run_cmd(f"qemu-riscv64 {TOOLS_PATH / 'pp' / 'pp'} {test_path}.init {test_path}.code")

        if not result:
            run_cmd(f"echo '# init code' > {output_path}.error")
            run_cmd(f"cat {OUTPUT_PATH / test_name}.init >> {output_path}.error")
            run_cmd(f"echo '\n\n# test code' >> {output_path}.error")
            run_cmd(f"cat {OUTPUT_PATH / test_name}.code >> {output_path}.error")
            run_cmd(f"echo '\n\nError: pp fails.' >> {output_path}.error")
            rm_file(f"{OUTPUT_PATH / test_name}.code")
            rm_file(f"{OUTPUT_PATH / test_name}.init")
        else:
            run_cmd(f"mv {OUTPUT_PATH / test_name}.code {output_path}.code")
            run_cmd(f"mv {OUTPUT_PATH / test_name}.init {output_path}.init")
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
            INFO(f'Successfully!\n')
        else:
            raise AssertionError(error_msg)
