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
from rvmca.log import DEBUG, INFO
from rvmca.trans.block import *
import math

from rvmca.prog import IType, Program, Reg, XREG, FREG, Inst, parse_program, SSAInst, IFmtInst, BFmtInst, UFmtInst, \
    RFmtInst
import copy
import angr, claripy
from rvmca.config import *
from rvmca.prog.reg import find_reg_by_name, bitvec_to_reg
from rvmca.utils.cmd_util import run_cmd
from rvmca.utils.file_util import rm_file, read_file, write_to_file
from rvmca.analysis import RDG

_available_regs = [
    # TODO: check the available registers
    find_reg_by_name(n)
    for n in [f't{i}' for i in range(7)] + \
             [f'a{i}' for i in [0, 1, 2, 3, 4, 6, 7]] + \
             [f's{i}' for i in range(12)]
]

STACK_RANGE = 0x7ff


def _legalize_branch(inst: Inst) -> Inst:
    assert inst.type is IType.Branch
    new_inst = copy.deepcopy(inst)
    new_inst.imm = 4
    return new_inst


def _legalize_jump(inst: Inst) -> Inst:
    assert inst.type is IType.Jump
    from rvmca.prog.inst import BFmtInst, JalrInst, JFmtInst
    if isinstance(inst, JalrInst):
        new_inst = BFmtInst('beq', inst.rd.name, inst.rs1.name, 4)
    elif isinstance(inst, JFmtInst):
        new_inst = BFmtInst('bne', inst.rd.name, inst.rd.name, 4)
    else:
        raise NotImplementedError
    return new_inst


def legalize_jump_and_branch(prog: Program) -> Program:
    """Legalize jump and branch for a block"""
    check_block_validity(prog)

    prog = copy.deepcopy(prog)

    if prog.insts[-1].type is IType.Jump:
        prog.insts[-1] = _legalize_jump(prog.insts[-1])
    elif prog.insts[-1].type is IType.Branch:
        prog.insts[-1] = _legalize_branch(prog.insts[-1])

    return prog


def zero_imm_for_block(prog: Program) -> Program:
    """Zero the immediate in a block"""
    check_block_validity(prog)
    prog = copy.deepcopy(prog)
    for idx, inst in enumerate(prog.insts):
        if hasattr(inst, 'imm') \
                and inst.type not in [IType.Branch, IType.Jump]:
            inst.imm = 0
    return prog


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


def add_addr_range_checking(prog: Program, temp_reg: str = None) -> Program:
    """Add address checking for a block"""

    temp = 'gp' if temp_reg is None else temp_reg
    check_block_validity(prog)

    prog = copy.deepcopy(prog)
    # TODO: find a proper label offset
    fail_offset = 0x700
    insts = []
    for inst in prog.insts:
        if inst.type in [IType.Load, IType.Store, IType.Amo]:
            addr = inst.get_addr()
            imm = inst.imm
            insts.append(UFmtInst('li', temp, imm))
            insts.append(RFmtInst('add', temp, str(addr), temp))
            insts.append(BFmtInst('bge', temp, 'sp', fail_offset))
            insts.append(IFmtInst('addi', temp, temp, STACK_RANGE))
            insts.append(BFmtInst('blt', temp, 'sp', fail_offset))
            # check address alignment
            mask = (1 << math.floor(math.log2(inst.width))) - 1
            insts.append(IFmtInst('addi', temp, temp, -STACK_RANGE))
            insts.append(IFmtInst('andi', temp, temp, mask))
            insts.append(BFmtInst('bne', temp, 'x0', fail_offset))
        insts.append(inst)
    assert len(insts) * 4 < fail_offset
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
    prog2se = add_addr_range_checking(prog, 'gp')
    print('\n<New Block with address range checking>:')
    print(prog2se.code)
    compile_block(prog2se, name)
    proj = angr.Project(f'{OUTPUT_PATH / name}.exe', auto_load_libs=False)
    begin_addr = proj.loader.main_object.get_symbol('rvmca_block_begin').rebased_addr
    end_addr = proj.loader.main_object.get_symbol('rvmca_block_end').rebased_addr
    init_state = proj.factory.blank_state(addr=begin_addr,
                                          mode='symbolic',
                                          add_options={
                                              angr.options.SYMBOLIC_WRITE_ADDRESSES,
                                              # angr.options.MEMORY_SYMBOLIC_BYTES_MAP,
                                              # angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                                              # angr.options.TRACK_SOLVER_VARIABLES,
                                              # angr.options.TRACK_REGISTER_ACTIONS,
                                              # angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                              # angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                                              angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                              angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                              angr.options.CONSERVATIVE_WRITE_STRATEGY,
                                              angr.options.CONSERVATIVE_READ_STRATEGY,
                                              # angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES
                                          }
                                          )
    from rvmca.prog import IFmtInst, UFmtInst
    init_sp = claripy.BVS('sp', 64)
    init_state.regs.sp = init_sp

    # block = proj.factory.block(begin_addr)
    # INFO("<Block>")
    # for inst in block.capstone.insns:
    #     INFO(f"{inst.address:#x}: {inst.mnemonic} {inst.op_str}")
    # end_addr = block.instruction_addrs[-1]

    # collect undefined registers
    from rvmca.analysis import CFG, path_to_ssa
    cfg = CFG(prog.insts)
    ssas = path_to_ssa(cfg.edges)
    rdg = RDG(ssas)
    # rdg.plot(OUTPUT_PATH / 'fail')
    # FIXME: we only consider xregs for now
    regs_undefined = {r for r in rdg.find_undef_regs()
                      if r in XREG and r not in regs_defined}

    def find_base_addr(ssa_inst):
        assert ssa_inst.is_ldst()
        addr_reg = ssa_inst.get_addr()
        paths = rdg.find_paths(rdg.start, rdg.find_node_by_value(addr_reg))
        clean_path = []
        for path in paths:
            has_taint = False
            for edge in path:
                if not isinstance(edge.attr, SSAInst):
                    continue
                if edge.attr.name not in ['add', 'addi', 'addw', 'addiw']:
                    has_taint = True
                    break
            if not has_taint:
                clean_path.append(path)
        assert len(clean_path) >= 1
        return [p[0].tgt for p in clean_path]

    # map ssa inst to its addr base reg
    base_regs = set()
    for inst in [i for i in ssas if i.is_ldst()]:
        for reg in find_base_addr(inst):
            base_regs.add(bitvec_to_reg(reg))

    init_state.regs.x0 = 0
    # create variables for undefined registers
    reg_vars = {}
    for reg in regs_undefined:
        if reg in base_regs:
            offset = claripy.BVS(f'{reg.name}_sp_offset', 64)
            setattr(init_state.regs, reg.name, init_sp - offset)
            reg_vars[reg] = offset
        else:
            reg_vars[reg] = getattr(init_state.regs, reg.name)

    # create a simulation manager
    simgr = proj.factory.simulation_manager(init_state)

    simgr.explore(find=end_addr)
    assert simgr.found, f'simulation fails at {end_addr:#x}'
    DEBUG(f'{simgr.found[0].solver.constraints = }')

    solver = claripy.Solver()
    solver.add(simgr.found[0].solver.constraints)
    # solver.add(addr_constraints)
    solver.add(init_sp == claripy.BVV(0x7fff0000, 64))
    solver.add(init_state.regs.x0 == 0)
    DEBUG(f'{solver.constraints = }')
    assert solver.satisfiable(), f"[ERROR]: {name} is not satisfiable"

    for k, v in reg_vars.items():
        val = solver.min(v)
        reg_name = k.name
        if k in base_regs:
            init_code.append(IFmtInst('addi', reg_name, 'sp', -val))
        else:
            init_code.append(UFmtInst('li', reg_name, val))
        solver.add(v == val)

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
        machine_code = '\n'.join(re.findall(pattern, output, re.MULTILINE))
        write_to_file(f'{OUTPUT_PATH / name}.{suffix}', machine_code, append=False)
        return machine_code

    # read file
    print(f'transform [{filepath}]')
    filepath = str(filepath)
    test_name = filepath.split('/')[-1].replace('.S', '')
    content = read_file(filepath) + '\n'
    failed = False
    error_msg = ""

    if output_path == '':
        output_path = f"{OUTPUT_PATH / test_name}"

    try:
        # transform block
        print('<Block>:')
        print(content)
        prog = parse_program(content)
        # prog = zero_imm_for_block(prog)
        prog = legalize_jump_and_branch(prog)
        prog = remap_regs_for_block(prog)
        print('<New Block>:')
        print(prog.code)
        init_insts = init_states_for_block(prog, name=test_name)
        init_code = '\n'.join([inst.code for inst in init_insts])
        test_code = '\n'.join([inst.code for inst in prog.insts])
        print('\n<New Block with init code>:')
        print('# init code')
        print(init_code)
        print('# test code')
        print(test_code)

        assemble_code(init_code, test_name, suffix='init')
        assemble_code(test_code, test_name)

        # run new block with pp
        result = run_cmd(f"qemu-riscv64 {TOOLS_PATH / 'pp' / 'pp'} {OUTPUT_PATH / test_name}")

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
            print(f'Successfully!\n')
        else:
            raise AssertionError(error_msg)
