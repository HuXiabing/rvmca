# MIT License
#
# Copyright (c) 2023 Xuezheng (xuezhengxu@126.com)
#               2023 Deheng (dehengyang@qq.com)
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

"""Simulator with Symbolic Execution"""

from z3 import *

from rvmca import config
from rvmca.prog import *

is_x0 = lambda x: str(x).startswith('x0')


class SymbolicExecutor:
    """SymbolicExecutor.

    Parameters
    ----------

    Attributes
    ----------
    solver: Solver
        The z3 SMT solver.
    """

    def __init__(self):
        self.solver = Solver()

        self.events = []
        self.relations = {}
        self.path = []
        self.mem_ssa_idx = 0

    def reset(self):
        """Reset the simulator."""
        self.solver = Solver()
        self.events = []
        self.relations = {}
        self.path = []
        self.mem_ssa_idx = 0

    def verify(self) -> bool:
        """Verify the execution path."""
        return self.solver.check() == sat

    def run(self, path: List[SSAInst], pid=-1):
        """Simulating the path with symbolic execution and generate events.
        Refer to https://theory.stanford.edu/~nikolaj/programmingz3.html
        """

        if not path:
            return

        new_events = []

        REG_SIZE = config.get_var('reg_size')

        def add_rel(key: str, pair):
            self.relations.setdefault(key, [])
            self.relations[key].append(pair)

        for ssa in path:
            inst = ssa.inst
            name = ssa.name
            match name:
                case 'add' | 'xor' | 'sub' | 'subw' | 'or':
                    rd, rs1, rs2 = ssa.operands
                    if is_x0(rd):
                        continue
                    match name:
                        case 'add':
                            self.solver.add(rd == rs1 + rs2)
                        case 'xor':
                            self.solver.add(rd == rs1 ^ rs2)
                        case 'subw' | 'sub':
                            # TODO: sub: x[8+rd’] = x[8+rd’] - x[8+rs2’] while subw: x[8+rd’] = sext((x[8+rd’] - x[8+rs2’])[31:0])
                            # deal with subw [31:0] if possible
                            self.solver.add(rd == rs1 - rs2)
                        case 'or':
                            self.solver.add(rd == rs1 | rs2)
                case 'li':
                    rd, imm = ssa.operands
                    if is_x0(rd):
                        continue
                    self.solver.add(rd == imm)
                case 'ori' | 'addi' | 'addiw' | 'andi':
                    rd, rs1, imm = ssa.operands
                    if is_x0(rd):
                        continue
                    match name:
                        case 'ori':
                            self.solver.add(rd == rs1 | imm)
                        case 'addi' | 'addiw':  # TODO:addiw
                            self.solver.add(rd == rs1 + imm)
                        case 'andi':
                            self.solver.add(rd == rs1 & imm)
                case 'lb' | 'lbu' | 'ld' | 'lh' | 'lhu' | 'lw' | 'lwu':
                    rd, rs1, imm = ssa.operands
                    if is_x0(rd):
                        continue

                    # rd == mem_idx
                    value = BitVec(f'mem_{self.mem_ssa_idx}', REG_SIZE)
                    self.solver.add(rd == value)
                    self.mem_ssa_idx += 1
                    addr = rs1 + imm

                    # generate a READ event.
                case n if n.startswith('lr.'):
                    rd, imm, rs1 = ssa.operands
                    # rd == mem_idx
                    value = BitVec(f'mem_{self.mem_ssa_idx}', REG_SIZE)
                    self.mem_ssa_idx += 1
                    if not is_x0(rd):
                        self.solver.add(rd == value)
                    # generate a READ event.
                case n if n.startswith('sc.'):
                    rd, rs2, rs1 = ssa.operands
                    if ssa.sc_succeed:
                        # generate a write event and rd is 0
                        self.solver.add(rd == 0)
                    else:
                        # no event is generated and rd is non-zero
                        self.solver.add(rd == 1)
                case 'sb' | 'sd' | 'sh' | 'sw':
                    rs2, rs1, imm = ssa.operands
                    # generate a WRITE event.
                case 'beq' | 'bge' | 'bgeu' | 'blt' | 'bltu' | 'bne' | 'ble' | 'bnez':
                    rs1, rs2, _ = ssa.operands
                    match name:
                        case 'beq':
                            self.solver.add(rs1 == rs2) if ssa.branch_taken else self.solver.add(rs1 != rs2)
                        case 'bge' | 'bgeu':
                            self.solver.add(rs1 >= rs2) if ssa.branch_taken else self.solver.add(rs1 < rs2)
                        case 'bgt' | 'bgtu':
                            self.solver.add(rs1 > rs2) if ssa.branch_taken else self.solver.add(rs1 <= rs2)
                        case 'ble' | 'bleu':
                            self.solver.add(rs1 <= rs2) if ssa.branch_taken else self.solver.add(rs1 > rs2)
                        case 'blt' | 'bltu':
                            self.solver.add(rs1 < rs2) if ssa.branch_taken else self.solver.add(rs1 >= rs2)
                        case 'bne' | 'bnez':
                            self.solver.add(rs1 != rs2) if ssa.branch_taken else self.solver.add(rs1 == rs2)
                # case 'bnez':
                #     rs, imm = ssa.operands
                #     self.solver.add(rs != 0) if ssa.branch_taken else self.solver.add(rs == 0)
                #     msg += f"branch {'taken' if ssa.branch_taken else 'not taken'}"
                case n if n.startswith('amoadd') | n.startswith('amoswap') | n.startswith('amoor') | n.startswith(
                        'amoand') | n.startswith('amoxor'):
                    rd, rs2, rs1 = ssa.operands
                    value = BitVec(f'mem_{self.mem_ssa_idx}', REG_SIZE)
                    self.mem_ssa_idx += 1
                    # put old value to rd
                    if not is_x0(rd):
                        self.solver.add(rd == value)
                    match n:
                        case n if n.startswith('amoadd'):
                            new_value = rs2 + value
                        case n if n.startswith('amoswap'):
                            new_value = rs2
                        case n if n.startswith('amoor'):
                            new_value = rs2 | value
                        case n if n.startswith('amoand'):
                            new_value = rs2 & value
                        case n if n.startswith('amoxor'):
                            new_value = rs2 ^ value
                        case _:
                            raise NotImplementedError
                    # write new value to mem
                    # add_rel('rmw', (e1, e2))
                case 'fence' | 'fence.i' | 'fence.tso':
                    pass
                case 'jal':
                    pass
                case 'mem':
                    pass
                case _:
                    raise NotImplementedError(f'{name}')

        # set pid for all events
        for e in new_events:
            e.pid = pid

        self.path.extend(path)
        self.events.extend(new_events)

    @staticmethod
    def simplify_expr(value):
        return simplify(value) if is_expr(value) else value
