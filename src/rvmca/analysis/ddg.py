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

"""Data Dependency Graph (DDG)"""

import time
from rvmca.analysis.base import *
from typing import List
from rvmca.prog import SSAInst


class DDGNode(BaseNode):
    """The DDG node.

    Parameters
    ----------
    value: Any
        Inst.
    label: str
        The node label for pretty printing.

    Attributes
    ----------
    value: Any
        Inst or Label.
    label: str
        The node label for pretty printing.
    shape: str
        The node shape.

        'polygon': for Inst nodes.
        'ellipse': for `start` and `end` nodes.
    preds: list
        The predecessors of the node.
    succs: list
        The successors of the node.

    """

    def __init__(self, value: SSAInst = None, label: str = None):
        super().__init__(value, label)
        self.shape = 'polygon'

    @property
    def inst(self):
        return self.value.inst

    @property
    def ssa_inst(self):
        return self.value


class DDGEdge(BaseEdge):
    """The DDG edge.

    Parameters
    ----------
    src: DDGNode
        The source node of the edge.
    tgt: DDGNode
        The target node of the edge.
    attr: String
        The attribute of the edge.
    """

    def __init__(self, src: DDGNode, tgt: DDGNode, attr: str = ""):
        super().__init__(src, tgt, attr)


class DDG(BaseGraph):
    """The data dependency graph (DDG).

    Parameters
    ----------
    inputs: list
        A list of DDG node values.
    name: str, optional
        The name of the ddg. The default is a time stamp.

    Attributes
    ----------
    start: DDGNode
        The start node of the ddg.
    end: CFGNode
        The end node of the ddg.
    nodes: list
        The ddg nodes.
    edges: list
        The ddg edges.
    """
    idx = 0

    def __init__(self, inputs: List[SSAInst], name: str = None):
        super().__init__(inputs, name)
        # TODO: for now, we do not add start and end node into graph
        self.start, self.end = DDGNode(label='start'), DDGNode(label='end')
        self._construct(inputs)

        if self.name is None:
            self.name = f'{time.strftime("%Y-%m-%d")}_{DDG.idx}'
            DDG.idx += 1

    def _construct_edge(self, src, tgt, attr: str = ""):
        return DDGEdge(src, tgt, attr)

    def _construct(self, inputs: List[SSAInst]):
        """Construct the DDG."""
        nodes = [DDGNode(value=v) for v in inputs]
        assert nodes, 'empty DDG'

        # add other edges.
        for i, src in enumerate(nodes):
            for j, tgt in enumerate(nodes):
                if i == j:
                    continue
                def_reg = src.value.get_def()
                use_regs = tgt.value.get_uses()
                if def_reg is not None and def_reg in use_regs:
                    self.add_edge(src, tgt)
