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

"""Program Class Definition"""
from typing import Dict

from antlr4 import *

from rvmca.prog import *
from rvmca.prog.parser.ProgramLexer import ProgramLexer
from rvmca.prog.parser.ProgramListener import ProgramListener
from rvmca.prog.parser.ProgramParser import ProgramParser


def _auto_int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        try:
            return int(value, 16)
        except ValueError:
            raise ValueError(f"The {value} cannot be converted to an integer.")


class Program:
    def __init__(self, insts=None):
        self.insts = [] if insts is None else insts
        self.labels: Dict[str, int] = {}

    def __repr__(self):
        insts_repr = [str(i) for i in self.insts]
        attach_label_before = lambda l, i: f"{l}:\n{i}"
        attach_label_after = lambda l, i: f"{i}{l}:"
        for label, label_id in self.labels.items():
            if label_id < len(insts_repr):
                attach_label = attach_label_before
            else:
                attach_label = attach_label_after
                label_id = -1
                insts_repr[-1] = attach_label_after(label, insts_repr[-1])
            insts_repr[label_id] = attach_label(label, insts_repr[label_id])
        return '\n'.join(insts_repr)

    @property
    def code(self):
        return '\n'.join([i.code for i in self.insts])


class ProgramParseListener(ProgramListener):
    def __init__(self):
        self.program = Program()
        Inst.global_id = 0

    def enterInst_j(self, ctx: ProgramParser.Inst_jContext):
        imm, label = ctx.IMM(), ctx.LABEL()
        inst = JFmtInst('jal', 'x0')
        if imm is not None:
            inst.imm = _auto_int(imm.getText())
        elif label is not None:
            inst.label = label.getText()
        self.program.insts.append(inst)

    def enterInst_jr(self, ctx: ProgramParser.Inst_jrContext):
        rs1 = ctx.REG().getText()
        inst = JalrInst('jalr', 'x0', rs1, 0)
        self.program.insts.append(inst)

    def enterInst_nop(self, ctx: ProgramParser.Inst_nopContext):
        inst = IFmtInst('addi', 'x0', 'x0', 0)
        self.program.insts.append(inst)

    def enterRfmt(self, ctx: ProgramParser.RfmtContext):
        rd, rs1, rs2 = (ctx.REG(i).getText() for i in range(3))
        if ctx.R_FMT_NAME():
            inst = RFmtInst(ctx.R_FMT_NAME().getText(), rd, rs1, rs2)
        else:  # is an or inst
            inst = RFmtInst('or', rd, rs1, rs2)
        self.program.insts.append(inst)

    def enterInst_f_f_f(self, ctx: ProgramParser.Inst_f_f_fContext):
        rd, rs1, rs2 = (ctx.FREG(i).getText() for i in range(3))
        self.program.insts.append(RFmtInst(ctx.FFF_NAME().getText(), rd, rs1, rs2))

    def enterInst_fcsr(self, ctx: ProgramParser.Inst_fcsrContext):
        # TODO
        raise NotImplementedError

    def enterInst_fscsr(self, ctx: ProgramParser.Inst_fscsrContext):
        # TODO
        raise NotImplementedError

    def enterInst_f_x(self, ctx: ProgramParser.Inst_f_xContext):
        rd, rs1 = ctx.FREG().getText(), ctx.REG().getText()
        self.program.insts.append(FRRFmtInst(ctx.FX_NAME().getText(), rd, rs1))

    def enterInst_x_f(self, ctx: ProgramParser.Inst_x_fContext):
        rd, rs1 = ctx.REG().getText(), ctx.FREG().getText()
        self.program.insts.append(FRRFmtInst(ctx.XF_NAME().getText(), rd, rs1))

    def enterInst_f_f(self, ctx: ProgramParser.Inst_f_fContext):
        rd, rs1 = ctx.FREG(0).getText(), ctx.FREG(1).getText()
        name = ctx.FF_NAME().getText()
        if name.startswith('fabs'):
            inst = RFmtInst(name.replace('fabs', 'fsgnjx'), rd, rs1, rs1)
        elif name.startswith('fmv'):
            inst = RFmtInst(name.replace('fabs', 'fsgnj'), rd, rs1, rs1)
        elif name.startswith('fneg'):
            inst = RFmtInst(name.replace('fabs', 'fsgnjn'), rd, rs1, rs1)
        else:
            inst = FRRFmtInst(name, rd, rs1)

        self.program.insts.append(inst)

    def enterInst_x_f_f(self, ctx: ProgramParser.Inst_x_f_fContext):
        rd, rs1, rs2 = ctx.REG().getText(), ctx.FREG(0).getText(), ctx.FREG(1).getText()
        self.program.insts.append(RFmtInst(ctx.XFF_NAME().getText(), rd, rs1, rs2))

    def enterInst_f_ldst(self, ctx: ProgramParser.Inst_f_ldstContext):
        name = ctx.F_LDST_NAME().getText()
        rd, imm, rs1 = ctx.FREG().getText(), _auto_int(ctx.IMM().getText()), ctx.REG().getText()
        if name.startswith('fl'):
            inst = LoadInst(name, rd, rs1, imm)
        elif name.startswith('fs'):
            inst = StoreInst(name, rd, rs1, imm)
        else:
            raise NotImplementedError(name)

        self.program.insts.append(inst)

    def enterInst_f_f_f_f(self, ctx: ProgramParser.Inst_f_f_f_fContext):
        rd, rs1, rs2, rs3 = [ctx.FREG(i).getText() for i in range(4)]
        self.program.insts.append(FRRRRFmtInst(ctx.FFFF_NAME().getText(), rd, rs1, rs2, rs3))

    def enterAmofmt(self, ctx: ProgramParser.AmofmtContext):
        rd, rs2, rs1 = (ctx.REG(i).getText() for i in range(3))
        name = ctx.AMO_NAME().getText()
        if ctx.MO_FLAG() is not None:
            name += ctx.MO_FLAG().getText()
        inst = AmoInst(name, rd, rs2, rs1)
        self.program.insts.append(inst)

    def enterInst_fence(self, ctx: ProgramParser.Inst_fenceContext):
        pre, suc = ctx.mem_access_op(0), ctx.mem_access_op(1)
        inst = FenceInst('fence') if pre is None else FenceInst('fence', pre.getText(), suc.getText())
        self.program.insts.append(inst)

    def enterInst_fencei(self, ctx: ProgramParser.Inst_fenceiContext):
        self.program.insts.append(FenceIInst())

    def enterInst_fencetso(self, ctx: ProgramParser.Inst_fencetsoContext):
        self.program.insts.append(FenceTsoInst())

    def enterIfmt(self, ctx: ProgramParser.IfmtContext):
        rd, rs1, imm = ctx.REG(0).getText(), ctx.REG(1).getText(), _auto_int(ctx.IMM().getText())
        inst = IFmtInst(ctx.I_FMT_NAME().getText(), rd, rs1, imm)
        self.program.insts.append(inst)

    def enterMfmt(self, ctx: ProgramParser.MfmtContext):
        rd, rs1, imm = ctx.REG(0).getText(), ctx.REG(1).getText(), _auto_int(ctx.IMM().getText())
        ld_name, sd_name, jalr = ctx.LD_NAME(), ctx.SD_NAME(), ctx.JALR()
        inst = None
        if ld_name is not None:
            ld_name_str = ld_name.getText()
            if ld_name_str.startswith('lr'):
                inst = AmoInst(ld_name_str, rd, 'x0', rs1)
            else:
                inst = LoadInst(ld_name_str, rd, rs1, imm)
        elif sd_name is not None:
            inst = StoreInst(sd_name.getText(), rd, rs1, imm)
        elif jalr is not None:
            inst = JalrInst('jalr', rd, rs1, imm)
        assert inst is not None, f"[ERROR] parser: unknown MFmt instruction"
        self.program.insts.append(inst)

    def enterUfmt(self, ctx: ProgramParser.UfmtContext):
        ufmt_name, reg, imm = ctx.U_FMT_NAME().getText(), ctx.REG().getText(), _auto_int(ctx.IMM().getText())
        inst = UFmtInst(ufmt_name, reg, imm)
        assert inst is not None, f"[ERROR] parser: unknown UFmt instruction"
        self.program.insts.append(inst)

    def enterBfmt(self, ctx: ProgramParser.BfmtContext):
        rs1, rs2, imm, label = ctx.REG(0).getText(), ctx.REG(1).getText(), ctx.IMM(), ctx.LABEL()
        inst = BFmtInst(ctx.B_FMT_NAME().getText(), rs1, rs2)
        if imm is not None:
            inst.imm = _auto_int(imm.getText())
        elif label is not None:
            inst.label = label.getText()
        self.program.insts.append(inst)

    def enterInst_bz(self, ctx: ProgramParser.Inst_bzContext):
        rs1, imm, label = ctx.REG().getText(), ctx.IMM(), ctx.LABEL()
        inst = BFmtInst(ctx.BRANCH_PSEUDO_ZERO_NAME().getText()[:-1], rs1, 'x0')
        if imm is not None:
            inst.imm = _auto_int(imm.getText())
        elif label is not None:
            inst.label = label.getText()
        self.program.insts.append(inst)

    def enterInst_bgtle(self, ctx: ProgramParser.Inst_bgtleContext):
        rs1, rs2, imm, label = ctx.REG(0).getText(), ctx.REG(1).getText(), ctx.IMM(), ctx.LABEL()
        inst = BFmtInst(ctx.BRANCH_PSEUDO_NAME().getText(), rs1, rs2)
        if imm is not None:
            inst.imm = _auto_int(imm.getText())
        elif label is not None:
            inst.label = label.getText()
        self.program.insts.append(inst)

    def enterInst_neg(self, ctx: ProgramParser.Inst_negContext):
        rd, rs2 = ctx.REG(0).getText(), ctx.REG(1).getText()
        inst = RFmtInst(ctx.NEG_NAME().getText().replace('neg', 'sub'), rd, 'x0', rs2)
        self.program.insts.append(inst)

    def enterInst_mv(self, ctx: ProgramParser.Inst_mvContext):
        inst = IFmtInst('addi', ctx.REG(0).getText(), ctx.REG(1).getText(), 0)
        self.program.insts.append(inst)

    def enterJfmt(self, ctx: ProgramParser.JfmtContext):
        rd, imm, label = ctx.REG().getText(), ctx.IMM(), ctx.LABEL()
        inst = JFmtInst('jal', rd)
        if imm is not None:
            inst.imm = _auto_int(imm.getText())
        elif label is not None:
            inst.label = label.getText()
        self.program.insts.append(inst)

    def enterInst_ret(self, ctx: ProgramParser.Inst_retContext):
        inst = JalrInst('jalr', 'x0', 'ra', 0)
        self.program.insts.append(inst)

    def enterLabel(self, ctx: ProgramParser.LabelContext):
        label = ctx.LABEL().getText()
        assert label not in self.program.labels, '[ERROR] parser: duplicated label'
        self.program.labels[label] = Inst.global_id

    def exitProg(self, ctx: ProgramParser.ProgContext):
        insts, labels = self.program.insts, self.program.labels

        # check if all labels are defined
        for inst in insts:
            if isinstance(inst, BFmtInst) or isinstance(inst, JFmtInst):
                label = inst.label
                if label is not None:
                    assert label in labels, f"[ERROR] parser: unknown label {label}"
                    inst.imm = (labels[label] - inst.idx) * 4


def parse_program(text):
    text += '\n'
    lexer = ProgramLexer(InputStream(text))
    stream = CommonTokenStream(lexer)
    parser = ProgramParser(stream)
    tree = parser.prog()
    listener = ProgramParseListener()
    walker = ParseTreeWalker()
    walker.walk(listener, tree)
    return listener.program
