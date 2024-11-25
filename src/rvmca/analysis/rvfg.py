# MIT License
#
# Copyright (c) 2022-2023 Xuezheng (xuezhengxu@126.com)
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

"""Register Value Flow Graph (RVFG)"""

import time

from z3 import BitVec

from rvmca.analysis.base import *
from rvmca.log import *
from typing import List, Set
from rvmca.prog import SSAInst, find_reg_by_name, Reg


class RVFGNode(BaseNode):
    """The RVFG node.

    Parameters
    ----------
    value: Any
        Register in BitVec.
    label: str
        The node label for pretty printing.

    Attributes
    ----------
    value: Any
        Register in BitVec.
    label: str
        The node label for pretty printing.
    shape: str
        The node shape.
    preds: list
        The predecessors of the node.
    succs: list
        The successors of the node.

    """

    def __init__(self, value: BitVec = None, label: str = None):
        super().__init__(value, label)
        self.shape = 'polygon'

    def reg(self) -> Reg:
        return find_reg_by_name(str(self.value).split('_')[0])

    def ssa_reg(self) -> BitVec:
        return self.value


class RVFGEdge(BaseEdge):
    """The RVFG edge.

    Parameters
    ----------
    src: RVFGNode
        The source node of the edge.
    tgt: RVFGNode
        The target node of the edge.
    attr: String
        The attribute of the edge.
    """

    def __init__(self, src: RVFGNode, tgt: RVFGNode, attr: str = ""):
        super().__init__(src, tgt, attr)


class RVFG(BaseGraph):
    """The register value flow graph (RVFG).

    Parameters
    ----------
    inputs: list
        A list of RVFG node values.
    name: str, optional
        The name of the rvfg. The default is a time stamp.

    Attributes
    ----------
    start: RVFGNode
        The start node of the RVFG.
    end: RVFGNode
        The end node of the RVFG.
    nodes: list
        The ddg nodes.
    edges: list
        The ddg edges.
    """
    idx = 0

    def __init__(self, inputs: List[SSAInst], name: str = None):
        super().__init__(inputs, name)
        self.start, self.end = RVFGNode(label='start'), RVFGNode(label='end')
        self.nodes.extend([self.start, self.end])

        self.undef, self.mem = RVFGNode(label='undef'), RVFGNode(label='mem')
        self.nodes.extend([self.undef, self.mem])

        self._construct(inputs)

        if self.name is None:
            self.name = f'{time.strftime("%Y-%m-%d")}_{RVFG.idx}'
            RVFG.idx += 1

    def _construct_edge(self, src, tgt, attr):
        return RVFGEdge(src, tgt, attr)

    def _construct(self, inputs: List[SSAInst]):
        """Construct the RVFG."""
        reg_set = set()
        for inst in inputs:
            def_reg = inst.get_def()
            use_regs = inst.get_uses()
            if def_reg is not None:
                reg_set.add(def_reg)
            for reg in use_regs:
                reg_set.add(reg)

        nodes = [RVFGNode(value=v) for v in reg_set if not str(v).startswith('x0_')]
        assert nodes, 'empty RVFG'

        def find_node_by_reg(r):
            for n in nodes:
                if n.value is r:
                    return n
            ERROR(f'{r} not in {nodes}')
            raise ValueError

        for inst in inputs:
            def_reg = inst.get_def()
            if str(def_reg).startswith('x0_'):
                continue
            use_regs = [reg for reg in inst.get_uses() if not str(reg).startswith('x0_')]
            tgt = find_node_by_reg(def_reg) if def_reg is not None else self.end
            if inst.is_load():
                self.add_edge(self.mem, tgt, inst)
                continue
            for reg in use_regs:
                src = find_node_by_reg(reg)
                # prevent cycles in register dependencies
                # e.g. 'add x1, x1, x2'
                if src is tgt:
                    continue
                self.add_edge(src, tgt, inst)
        for node in nodes:
            if len(node.preds) == 0:
                if node is not self.mem:
                    self.add_edge(self.undef, node)
            if len(node.succs) == 0:
                self.add_edge(node, self.end)

        self.add_edge(self.start, self.mem)
        self.add_edge(self.start, self.undef)

        self.nodes.extend(nodes)

    def find_undef_regs(self) -> Set[Reg]:
        from rvmca.prog.reg import bitvec_to_reg
        return {bitvec_to_reg(n.value) for n in self.undef.succs}

    def find_clean_paths(self, start, end, clean_edges):
        paths = self.find_paths(start, end)
        clean_path = []

        for path in paths:
            has_taint = False
            for edge in path:
                if not isinstance(edge.attr, SSAInst):
                    continue
                inst_name = edge.attr.name
                if inst_name not in clean_edges:
                    has_taint = True
                    break

            if not has_taint:
                clean_path.append(path)
        return clean_path
