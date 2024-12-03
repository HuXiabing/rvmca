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

"""Instruction Generator"""

import random
from typing import Dict

from rvmca.prog.inst import *
from rvmca.trans.block import *
from rvmca.prog.reg import XREG, FREG

rfmt_insts = {
    n: RFmtInst(n, 'x0', 'x0', 'x0')
    for n in ['add', 'addw', 'and', 'div', 'divu', 'divuw', 'divw',
              'mul', 'mulh', 'mulhsu', 'mulhu', 'mulw', 'rem', 'remu',
              'remuw', 'remw', 'sll', 'sllw', 'slt', 'sltu', 'sra',
              'sraw', 'srl', 'srlw', 'sub', 'subw', 'xor']
}

ifmt_insts = {
    n: IFmtInst(n, 'x0', 'x0', 0)
    for n in ['addi', 'addiw', 'andi', 'ori', 'slli', 'slliw',
              'slti', 'sltiu', 'srai', 'sraiw', 'srli', 'srliw', 'xori']
}

ufmt_insts = {
    n: UFmtInst(n, 'x0', 0)
    for n in ['auipc', 'lui']
}

load_insts = {
    n: LoadInst(n, 'x0', 'x0', 0)
    for n in ['lb', 'lbu', 'ld', 'lh', 'lhu', 'lw', 'lwu']
}

store_insts = {
    n: StoreInst(n, 'x0', 'x0', 0)
    for n in ['sb', 'sd', 'sh', 'sw']
}

branch_insts = {
    n: BFmtInst(n, 'x0', 'x0', 0)
    for n in ['beq', 'bge', 'bgeu', 'blt', 'bltu', 'bne']
}

jalr_inst = JalrInst('jalr', 'x0', 'x0', 0)
jal_inst = JFmtInst('jal', 'x0', 0)

normal_insts = {**rfmt_insts, **ifmt_insts, **load_insts, **store_insts}
exit_insts = {**branch_insts, 'jalr': jalr_inst, 'jal': jal_inst}

riscv_insts = {**normal_insts, **exit_insts}


def gen_reg(candidates: List = None):
    if candidates is None:
        candidates = XREG
    return random.choice(candidates)


def gen_inst(candidates: Dict = None):
    if candidates is None:
        candidates = riscv_insts
    return random.choice(list(candidates.values()))


def gen_imm(start=-8, end=8, divisor=1):
    return random.randint(start // divisor, end // divisor) * divisor


def gen_block(num_insts: int = 10, seed: int = None):
    if seed is not None:
        random.seed(seed)

    # generate dummy instructions for a block
    block = [gen_inst(normal_insts) for _ in range(num_insts)]
    exit_inst = legalize_jump_or_branch_inst(gen_inst(exit_insts))
    block.append(exit_inst)

    # register allocation
    for inst in block:
        if inst.get_def():
            reg = gen_reg()
            inst.set_def(reg)
        num_uses = len(inst.get_uses())
        if num_uses > 0:
            inst.set_uses([gen_reg() for _ in range(num_uses)])

    # assign immediate
    for inst in block[:-1]:
        if hasattr(inst, 'imm'):
            inst.imm = gen_imm(-8, 8, 8)

    return block
