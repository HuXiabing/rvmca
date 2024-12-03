# MIT License
#
# Copyright (c) 2023 Xuezheng (xuezhengxu@126.com)
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
"""Instruction Class Definition"""
from collections import namedtuple
from typing import Optional, List

from rvmca.prog.reg import find_reg_by_name, Reg
from rvmca.prog.types import *

INST_LEN = 4

read_inst_conds = ['lb', 'lbu', 'ld', 'lh', 'lhu', 'lw', 'lwu']
write_inst_conds = ['sb', 'sd', 'sh', 'sw']
# TODO: incomplete
read_write_inst_conds = ['amoswap', 'amoadd', 'amoor', 'amoand', 'amoxor']


# AMOMAX AMOMAXU AMOMIN AMOMINU

class Inst:
    """The instruction (in the raw format, not in ssa)."""
    global_id = 0

    def __init__(self, name: str = ''):
        self.pid = -1
        self.idx = Inst.global_id
        self.pc = self.idx * INST_LEN
        self.name = name
        self.type = IType.Unknown
        self.etype = EType.Unknown

        Inst.global_id += 1

    def init(self, inst_to_copy):
        self.idx = inst_to_copy.idx
        self.pc = inst_to_copy.pc
        # self.name = inst_to_copy.name
        self.type = inst_to_copy.type
        self.etype = inst_to_copy.etype

    @property
    def operands(self):
        raise NotImplementedError

    def get_event_type(self):
        """
        to serve Suggestion
        """
        if self.name in read_inst_conds or self.name.startswith('lr.'):
            etype = EType.Read
        elif self.name in write_inst_conds or self.name.startswith('sc.'):
            etype = EType.Write
        elif self.is_amo(self.name):
            etype = EType.ReadWrite
        else:
            etype = EType.Unknown
        return etype

    @staticmethod
    def is_amo(name):
        for cond in read_write_inst_conds:
            if name.startswith(cond):
                return True
        return False

    def get_def(self) -> Optional[Reg]:
        """Get the defined register (the destination register)."""
        raise NotImplementedError

    def get_uses(self) -> Optional[List[Reg]]:
        """Get the used registers (the source registers)."""
        raise NotImplementedError

    def set_def(self, r: Reg):
        """Set the defined register (the destination register)."""
        raise NotImplementedError

    def set_uses(self, regs: List[Reg]):
        """Set the used registers (the source registers)."""
        raise NotImplementedError

    def get_regs(self) -> Optional[List[Reg]]:
        """Get all registers in operands."""
        regs = []
        defs, uses = self.get_def(), self.get_uses()
        if defs:
            regs.append(defs)
        if uses:
            regs.extend(uses)
        return regs

    def get_addr(self) -> Optional[Reg]:
        """Get the address register (only for memory access instructions)."""
        return None

    def get_data(self) -> Optional[Reg]:
        """Get the data register (only for memory access instructions)."""
        return None

    def mnemonic(self, operands) -> str:
        """Get the mnemonic of the instruction (e.g., only for memory access instructions)."""
        raise NotImplementedError

    def __repr__(self):
        return f'<0x{"{:0>2X}".format(self.pc)}> {self.mnemonic(self.operands)}'

    @property
    def code(self):
        return self.mnemonic(self.operands)


class RFmtInst(Inst):
    def __init__(self, name: str, rd: str, rs1: str, rs2: str):
        super().__init__(name)
        self.rd, self.rs1, self.rs2 = (find_reg_by_name(name)
                                       for name in [rd, rs1, rs2])
        self.type = IType.Normal

    @property
    def operands(self):
        return self.rd, self.rs1, self.rs2

    def get_def(self):
        return self.rd

    def get_uses(self):
        return [self.rs1, self.rs2]

    def set_def(self, r: Reg):
        self.rd = r

    def set_uses(self, regs: List[Reg]):
        assert len(regs) == len(self.get_uses())
        self.rs1, self.rs2 = regs[0], regs[1]

    def mnemonic(self, operands):
        rd, rs1, rs2 = operands
        return f'{self.name} {rd}, {rs1}, {rs2}'


class UFmtInst(Inst):
    def __init__(self, name: str, rd: str, imm: int):
        super().__init__(name)
        self.rd, self.imm = find_reg_by_name(rd), int(imm)
        self.type = IType.Normal

    @property
    def operands(self):
        return self.rd, self.imm

    def get_def(self):
        return self.rd

    def get_uses(self):
        return []

    def set_def(self, r: Reg):
        self.rd = r

    def set_uses(self, regs: List[Reg]):
        pass

    def mnemonic(self, operands):
        rd, imm = operands
        if self.name == 'lui':
            # TODO: handle negative lui imm operand
            imm = abs(imm)
        return f'{self.name} {rd}, {hex(abs(imm))}'


class AmoInst(Inst):
    def __init__(self, name: str, rd: str, rs2: str, rs1: str, inst_to_copy=None):
        super().__init__(name)
        self.rd, self.rs2, self.rs1 = (find_reg_by_name(name)
                                       for name in [rd, rs2, rs1])
        if name.startswith('lr.'):
            self.type = IType.Lr
        elif name.startswith('sc.'):
            self.type = IType.Sc
        elif name.startswith('amo'):
            self.type = IType.Amo
        else:
            raise NotImplementedError

        if name.endswith('.aq'):
            self.flag = MoFlag.Acquire
        elif name.endswith('.aqrl') | name.endswith('.aq.rl'):
            self.flag = MoFlag.Strong
        elif name.endswith('.rl'):
            self.flag = MoFlag.Release
        else:
            self.flag = MoFlag.Relax

        if inst_to_copy is not None:
            super().init(inst_to_copy)

    @property
    def operands(self):
        return self.rd, self.rs2, self.rs1

    def get_def(self):
        return self.rd

    def get_uses(self):
        return [self.rs1, self.rs2]

    def set_def(self, r: Reg):
        self.rd = r

    def set_uses(self, regs: List[Reg]):
        assert len(regs) == len(self.get_uses())
        self.rs1, self.rs2 = regs[0], regs[1]

    def get_data(self):
        return self.rs2

    def get_addr(self):
        return self.rs1

    def get_rs_name(self):
        return self.rs1.name

    def get_rd_name(self):
        return self.rd.name

    def get_data_src_reg_name(self):
        return self.rs2.name

    def mnemonic(self, operands):
        rd, rs2, rs1 = operands
        if self.name.startswith('lr.'):
            return f'{self.name} {rd}, 0({rs1})'
        else:
            return f'{self.name} {rd}, {rs2}, ({rs1})'


class IFmtInst(Inst):
    def __init__(self, name: str, rd: str, rs1: str, imm: int):
        super().__init__(name)
        self.rd = find_reg_by_name(rd)
        self.rs1 = find_reg_by_name(rs1)
        self.imm = imm
        self.type = IType.Normal

    @property
    def operands(self):
        return self.rd, self.rs1, self.imm

    def get_def(self):
        return self.rd

    def get_uses(self):
        return [self.rs1]

    def set_def(self, r: Reg):
        self.rd = r

    def set_uses(self, regs: List[Reg]):
        assert len(regs) == len(self.get_uses())
        self.rs1 = regs[0]

    def mnemonic(self, operands):
        rd, rs1, imm = operands
        return f'{self.name} {rd}, {rs1}, {imm}'


class BFmtInst(Inst):
    def __init__(self, name: str, rs1: str, rs2: str, imm: int = None, label: str = None):
        super().__init__(name)
        self.rs1 = find_reg_by_name(rs1)
        self.rs2 = find_reg_by_name(rs2)
        self.imm = imm
        self.label = label
        self.type = IType.Branch

    def set_label_pos(self, label_inst_idx, label_pos):
        self.label_inst_idx, self.label_pos = label_inst_idx, label_pos

    def get_label_pos(self):
        # inst_idx, after/before
        return self.label, self.label_inst_idx, self.label_pos

    @property
    def operands(self):
        return self.rs1, self.rs2, self.imm

    def get_def(self):
        return None

    def get_uses(self):
        return [self.rs1, self.rs2]

    def set_def(self, r: Reg):
        pass

    def set_uses(self, regs: List[Reg]):
        assert len(regs) == len(self.get_uses())
        self.rs1, self.rs2 = regs[0], regs[1]

    @property
    def tgt_pc(self):
        return self.pc + self.imm

    @property
    def tgt_id(self):
        return int((self.pc + self.imm) / INST_LEN)

    def mnemonic(self, operands):
        rs1, rs2, imm = operands
        imm = self.label if imm is None else imm
        return f'{self.name} {rs1}, {rs2}, {imm}'


class LABEL_POS(Enum):
    # support labels index and write to suggested_program
    AFTER = 1
    BEFORE = -1


class JFmtInst(Inst):
    def __init__(self, name: str, rd: str, imm: int = None, label: str = None):
        super().__init__(name)
        self.rd = find_reg_by_name(rd)
        self.imm = imm
        self.label = label
        self.type = IType.Jump

    def set_label_pos(self, label_inst_idx, label_pos):
        self.label_inst_idx, self.label_pos = label_inst_idx, label_pos

    @property
    def operands(self):
        return self.rd, self.imm

    def get_def(self):
        return None

    def get_uses(self):
        return []

    def set_def(self, r: Reg):
        pass

    def set_uses(self, regs: List[Reg]):
        pass

    @property
    def tgt_pc(self):
        return self.pc + self.imm

    @property
    def tgt_id(self):
        return int(self.tgt_pc / INST_LEN)

    def mnemonic(self, operands):
        rd, imm = operands
        return f'{self.name} {rd}, {imm} #<{hex(self.tgt_pc)}>'


Address = namedtuple("Address", ["base", "offset"])

_mem_width_map = {
    'lb': 1,
    'lbu': 1,
    'sb': 1,
    'lh': 2,
    'lhu': 2,
    'sh': 2,
    'lw': 4,
    'lwu': 4,
    'sw': 4,
    'ld': 8,
    'sd': 8
}


class MemoryAccessInst(Inst):
    def __init__(self, name: str, rs1: str, imm: int):
        super().__init__(name)
        self.rs1: Reg = find_reg_by_name(rs1)
        self.imm = imm

    def get_def(self):
        raise NotImplementedError

    def get_uses(self):
        raise NotImplementedError

    @property
    def addr(self):
        return Address(self.rs1, self.imm)

    def get_addr(self) -> Reg:
        return self.rs1

    @property
    def width(self):
        assert self.name in _mem_width_map, f"not implemented for {self.name}"
        return _mem_width_map[self.name]


class LoadInst(MemoryAccessInst):
    def __init__(self, name: str, rd: str, rs1: str, imm: int):
        super().__init__(name, rs1, imm)
        self.rd = find_reg_by_name(rd)
        self.type = IType.Load

    def get_rd_name(self):
        return self.rd.name

    def get_rs_name(self):
        return self.rs1.name

    @property
    def operands(self):
        return self.rd, self.rs1, self.imm

    def get_def(self):
        return self.rd

    def get_uses(self):
        return [self.rs1]

    def set_def(self, r: Reg):
        self.rd = r

    def set_uses(self, regs: List[Reg]):
        assert len(regs) == len(self.get_uses())
        self.rs1 = regs[0]

    def mnemonic(self, operands):
        rd, rs1, imm = operands
        return f'{self.name} {rd}, {imm}({rs1})'


class StoreInst(MemoryAccessInst):
    def __init__(self, name: str, rs2: str, rs1: str, imm: int):
        super().__init__(name, rs1, imm)
        self.rs2 = find_reg_by_name(rs2)
        self.type = IType.Store

    def get_rs_name(self):
        return self.rs1.name

    def get_data_src_reg_name(self):
        return self.rs2.name

    @property
    def operands(self):
        return self.rs2, self.rs1, self.imm

    def get_def(self):
        return None

    def get_uses(self):
        return [self.rs1, self.rs2]

    def set_def(self, r: Reg):
        pass

    def set_uses(self, regs: List[Reg]):
        assert len(regs) == len(self.get_uses())
        self.rs1, self.rs2 = regs[0], regs[1]

    def get_data(self):
        return self.rs2

    def mnemonic(self, operands):
        rs2, rs1, imm = operands
        return f'{self.name} {rs2}, {imm}({rs1})'


def _fence(t: EType, flag: str):
    match t:
        case EType.Read:
            return 'r' in flag
        case EType.Write:
            return 'w' in flag
        case EType.ReadWrite:  # for mem_access inst
            return 'rw' in flag
        case _:
            return False


class MemAccessInst(Inst):
    def __init__(self, mem_access_op):
        super().__init__('mem')
        self.name = 'mem'
        self.mem_access_op = mem_access_op

        if mem_access_op == 'w':
            self.etype = EType.Write
        elif mem_access_op == 'r':
            self.etype = EType.Read
        elif mem_access_op == 'rw':
            self.etype = EType.ReadWrite
        else:
            raise Exception("unknown mem_access_op type")

    @property
    def operands(self):
        return []

    def get_def(self):
        return None

    def get_uses(self):
        return []

    def set_def(self, r: Reg):
        pass

    def set_uses(self, regs: List[Reg]):
        pass

    def mnemonic(self, operands):
        return f'{self.name} {self.mem_access_op}'


class FenceInst(Inst):
    def __init__(self, name: str, pre: str = 'rw', suc: str = 'rw'):
        super().__init__(name)
        self.pre, self.suc = pre, suc
        self.type = IType.Fence

    def ordered_pre(self, t: EType) -> bool:
        return _fence(t, self.pre)

    def ordered_suc(self, t: EType) -> bool:
        return _fence(t, self.suc)

    def ordered(self, t1: EType, t2: EType) -> bool:
        return self.ordered_pre(t1) and self.ordered_suc(t2)

    @property
    def operands(self):
        return []

    def get_def(self):
        return None

    def get_uses(self):
        return []

    def set_def(self, r: Reg):
        pass

    def set_uses(self, regs: List[Reg]):
        pass

    def mnemonic(self, operands):
        return f'{self.name} {self.pre}, {self.suc}'


class FenceTsoInst(Inst):
    def __init__(self):
        super().__init__('fence.tso')
        self.type = IType.FenceTso

    def ordered(self, t1: EType, t2: EType) -> bool:
        # w, w   r, r/w
        return not (t1 == EType.Write and t2 == EType.Read)

    @property
    def operands(self):
        return []

    def get_def(self):
        return None

    def get_uses(self):
        return []

    def set_def(self, r: Reg):
        pass

    def set_uses(self, regs: List[Reg]):
        pass

    def mnemonic(self, operands):
        return f'{self.name}'


class FenceIInst(Inst):
    def __init__(self):
        super().__init__('fence.i')
        self.type = IType.FenceI

    def ordered(self, t1: EType, t2: EType) -> bool:
        return False

    @property
    def operands(self):
        return []

    def get_def(self):
        return None

    def get_uses(self):
        return []

    def set_def(self, r: Reg):
        pass

    def set_uses(self, regs: List[Reg]):
        pass

    def mnemonic(self, operands):
        return f'{self.name}'


class JalrInst(Inst):
    def __init__(self, name: str, rd: str, rs1: str, imm: int):
        super().__init__(name)
        self.rd = find_reg_by_name(rd)
        self.rs1 = find_reg_by_name(rs1)
        self.imm = imm
        self.type = IType.Jump

    @property
    def operands(self):
        return self.rd, self.rs1, self.imm

    def get_def(self):
        return self.rd

    def get_uses(self):
        return [self.rs1]

    def set_def(self, r: Reg):
        self.rd = r

    def set_uses(self, regs: List[Reg]):
        assert len(regs) == len(self.get_uses())
        self.rs1 = regs[0]

    @property
    def tgt_id(self):
        return None

    @property
    def tgt_pc(self):
        return None

    def mnemonic(self, operands):
        rd, rs1, imm = operands
        return f'{self.name} {rd}, {imm}({rs1})'


class Label:
    def __init__(self, label, idx):
        self.label = label
        self.idx = idx

    def __str__(self):
        return f'{self.label}:'


class FRRFmtInst(Inst):
    def __init__(self, name: str, rd: str, rs1: str):
        super().__init__(name)
        self.rd, self.rs1 = (find_reg_by_name(name)
                             for name in [rd, rs1])
        self.type = IType.Normal

    @property
    def operands(self):
        return self.rd, self.rs1

    def get_def(self):
        return self.rd

    def get_uses(self):
        return [self.rs1]

    def set_def(self, r: Reg):
        self.rd = r

    def set_uses(self, regs: List[Reg]):
        assert len(regs) == len(self.get_uses())
        self.rs1 = regs[0]

    def mnemonic(self, operands):
        rd, rs1 = operands
        return f'{self.name} {rd}, {rs1}'


class FRRRRFmtInst(Inst):
    def __init__(self, name: str, rd: str, rs1: str, rs2: str, rs3: str):
        super().__init__(name)
        self.rd, self.rs1, self.rs2, self.rs3 = (find_reg_by_name(name)
                                                 for name in [rd, rs1, rs2, rs3])
        self.type = IType.Normal

    @property
    def operands(self):
        return self.rd, self.rs1, self.rs2, self.rs3

    def get_def(self):
        return self.rd

    def get_uses(self):
        return [self.rs1, self.rs2, self.rs3]

    def set_def(self, r: Reg):
        self.rd = r

    def set_uses(self, regs: List[Reg]):
        assert len(regs) == len(self.get_uses())
        self.rs1, self.rs2, self.rs3 = regs[0], regs[1], regs[2]

    def mnemonic(self, operands):
        rd, rs1, rs2, rs3 = operands
        return f'{self.name} {rd}, {rs1}, {rs2}, {rs3}'


class SSAInst:
    """
    build from an Inst
    """

    def __init__(self, inst: Inst, idx: int = -1):
        self.inst = inst
        self.branch_taken = None
        self.sc_succeed = None  # for sc
        # reg -> BitVec
        self.use_rmap = {}
        self.def_rmap = {}
        self.idx = idx

    @property
    def type(self):
        return self.inst.type

    @property
    def pc(self):
        return self.inst.pc

    @property
    def name(self):
        return self.inst.name if self.inst else 'none'

    def get_def(self):
        if self.sc_succeed is False:
            # there is no dst register if sc fails
            return None
        d = self.inst.get_def()
        return self.def_rmap[d] if d is not None else None

    def get_uses(self):
        return [self.use_rmap[u] for u in self.inst.get_uses()]

    def get_data(self):
        d = self.inst.get_data()
        return self.use_rmap[d] if d is not None else None

    def get_addr(self):
        a = self.inst.get_addr()
        return self.use_rmap[a] if a is not None else None

    def is_ldst(self):
        return self.is_load() or self.is_store()

    def is_load(self):
        return self.inst.type in [IType.Load, IType.Amo]

    def is_store(self):
        return self.inst.type in [IType.Store, IType.Amo]

    def verify(self):
        if isinstance(self.inst, BFmtInst):
            assert self.branch_taken is not None, f'need branch_taken flag for {self}'

    @property
    def operands(self):
        ops = list(self.inst.operands)
        op = self.inst.get_def()
        idx = 0
        if op is not None:
            ops[idx] = self.def_rmap[op]
            idx += 1
        for i in range(idx, len(ops)):
            if isinstance(ops[i], Reg):
                ops[i] = self.use_rmap[ops[i]]
        return ops

    def __repr__(self):
        return f'<0x{"{:0>2X}".format(self.inst.pc)}>\t{self.inst.mnemonic(self.operands)}\t'
