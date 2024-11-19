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

"""Control Flow Graph (CFG)"""

from rvmca.analysis.base import *
import time
from typing import List, Dict

import networkx as nx
from z3 import BitVec

from rvmca import config
from rvmca.prog import Inst, IType, SSAInst
from rvmca.utils.plot import plot_graph, AGraphNode, AGraphEdge


# colors
GREEN = '#95BE91'
RED = '#B22222'


class CFGNode(BaseNode):
    """The CFG node.

    Parameters
    ----------
    value: Any
        Inst or Label.
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

    def __init__(self, value=None, label: str = None):
        """
        value is None or a xxxInst
        """
        super().__init__(value, label)

        if isinstance(value, Inst):
            self.shape = 'polygon'
        else:  # generally, for start, end, and undef node.
            self.shape = 'ellipse'

    def get_inst_idx(self):
        return self.value.idx if self.value is not None else None

    def is_undef(self):
        return self.label == 'undef'

    def is_end(self):
        return self.label == 'end'


BRANCH_TRUE = "true"
BRANCH_FALSE = "false"
SC_SUCCEED = "sc_succeed"
SC_FAIL = "sc_fail"


class CFGEdge(BaseEdge):
    """The CFG edge.

    Parameters
    ----------
    src: CFGNode
        The source node of the edge.
    tgt: CFGNode
        The target node of the edge.
    attr: String
        The attribute of the edge, e.g., true, false, ppo.
    """

    def __init__(self, src: CFGNode, tgt: CFGNode, attr: str = ""):
        super().__init__(src, tgt, attr)


def path_to_ssa(path: List[CFGEdge]) -> List[SSAInst]:
    insts = []
    r2i = {}  # reg -> index
    r2v = {}  # reg -> var (BitVec)
    ssa_idx = 0
    x0 = BitVec('x0_0', config.REG_SIZE)
    for edge in path:
        # record the taken flag for branches (we use it later in symbolic execution phase).
        # FIXME: we assume that the last inst in insts is the src inst (only valid in simple path).
        if edge.attr == BRANCH_TRUE:
            insts[-1].branch_taken = True
        elif edge.attr == BRANCH_FALSE:
            insts[-1].branch_taken = False
        elif edge.attr == SC_SUCCEED:
            insts[-1].sc_succeed = True
        elif edge.attr == SC_FAIL:
            insts[-1].sc_succeed = False
        src, tgt = edge.src, edge.tgt  # start from the second node (as the first is the start node)
        if tgt.is_undef() or tgt.is_end():
            break

        # construct the ssa inst and record its index in the path.
        inst = tgt.value
        ssa_inst = SSAInst(inst, ssa_idx)
        ssa_idx += 1

        reg_sym_name = lambda x, i: f'{x}_{i}'

        # for each used register, map it to the existing variable or a new one (if not exist).
        for u in inst.get_uses():
            idx = r2i.setdefault(u.name, 0)
            if u.name == 'x0':
                var = x0
            else:
                var = r2v.setdefault(u.name, BitVec(reg_sym_name(u, idx), config.REG_SIZE))
            ssa_inst.use_rmap[u] = var

        # for the defined register, map it to a new variable.
        d = inst.get_def()
        if d is not None:
            if d.name == 'x0':
                idx = 0
                var = r2v.setdefault(d, x0)
            else:
                # defined register index starts from 1
                idx = r2i[d.name] + 1 if d.name in r2i else 1
                var = BitVec(reg_sym_name(d, idx), config.REG_SIZE)
                r2v[d.name] = var
            r2i[d.name] = idx
            ssa_inst.def_rmap[d] = var

        insts.append(ssa_inst)

    for i in insts:
        i.verify()

    return insts


class CFG(BaseGraph):
    """The control flow graph (CFG).

    Parameters
    ----------
    inputs: list
        A list of CFG node values.
    name: str, optional
        The name of the cfg. The default is a time stamp.

    Attributes
    ----------
    start: CFGNode
        The start node of the cfg.
    end: CFGNode
        The end node of the cfg.
    undef: CFGNode
        The undef node of the cfg.
    nodes: list
        The cfg nodes.
    edges: list
        The cfg edges.
    """
    idx = 0

    def __init__(self, inputs: List[Inst], name: str = None):
        super().__init__(inputs, name)
        self.start, self.end = CFGNode(label='start'), CFGNode(label='end')
        self.undef = CFGNode(label='undef')
        self._construct(inputs)

        if self.name is None:
            # get valid file name format for both Linux and Windows os. (Tue May 30 18:55:38 2023 ->
            # self.name = f'{time.strftime("%Y-%m-%d_%H-%M-%S")}_{CFG.idx}'
            self.name = f'{time.strftime("%Y-%m-%d")}_{CFG.idx}'
            CFG.idx += 1

    def _construct_edge(self, src, tgt, attr):
        return CFGEdge(src, tgt, attr)

    def _verify(self):
        """Verify the legitimacy of the CFG"""
        valid = 0
        for e in self.edges:
            # check if the cfg has an exit.
            # TODO: Traverse all paths of CFG from the start node,
            #  and ensure that the end points of the paths are all end node or undef node,
            #  and at least one path leads to the end node.
            if e.tgt is self.end:
                valid = 1
                break
        assert valid, "[ERROR] illegal CFG. The input program must have an exit."

    def _construct(self, inputs: List[Inst]):
        """Construct the CFG."""
        nodes = [CFGNode(value=v) for v in inputs]
        assert nodes, 'empty CFG'

        # add an edge from the start node to the first inst.
        self.add_edge(self.start, nodes[0])

        # add other edges.
        for i, src in enumerate(nodes):
            # find the candidate target node (the next inst or the end node).
            tgt = nodes[i + 1] if i != len(nodes) - 1 else self.end
            inst_type = src.value.type
            match inst_type:
                case IType.Jump | IType.Branch:
                    attr = ""
                    # add edge from branch to the next inst (false condition, not taken).
                    if inst_type == IType.Branch:
                        self.add_edge(src, tgt, BRANCH_FALSE)
                        attr = BRANCH_TRUE
                    # find the target node (true condition, taken)
                    tgt_id = src.value.tgt_id
                    if tgt_id is not None:
                        # the target node is out of range.
                        if tgt_id > len(nodes) or tgt_id < 0:
                            self.add_edge(src, self.undef, attr)
                        # the target node is the end node.
                        elif tgt_id == len(nodes):
                            self.add_edge(src, self.end, attr)
                        # the target node is an inst in the range.
                        else:
                            self.add_edge(src, nodes[tgt_id], attr)
                    # if we cannot determine the target node (indirect jump), goto the undef node.
                    else:
                        self.add_edge(src, self.undef, attr)
                case IType.Sc:
                    self.add_edge(src, tgt, SC_SUCCEED)
                    self.add_edge(src, tgt, SC_FAIL)
                case _:
                    # for normal insts, we link the current inst to the next.
                    self.add_edge(src, tgt)
        self.nodes = nodes + [self.start, self.end, self.undef]
        self._verify()

    def find_all_paths(self) -> List[List[CFGEdge]]:
        """Find all simple paths from start to end (or undef).
        A simple path is a path with no repeated nodes.
        Refer to https://networkx.org/documentation/stable/reference/algorithms/simple_paths.html
        """

        ni = lambda x: self.nodes.index(x)  # node index map
        G = nx.MultiDiGraph([(ni(e.src), ni(e.tgt)) for e in self.edges])  # construct a graph
        # MultiDiGraph: node(src, tgt, id)

        paths = list(nx.all_simple_edge_paths(G, ni(self.start), ni(self.end)))
        if G.has_node(ni(self.undef)):
            paths.extend(nx.all_simple_edge_paths(G, ni(self.start), ni(self.undef)))

        def find_cfg_edges(path):
            """find cfg edges from a nx path"""
            edges = []
            for (x, y, i) in path:
                src, tgt = self.nodes[x], self.nodes[y]
                edges.append(list(filter(lambda e: e.src == src and e.tgt == tgt, self.edges))[i])
            return edges

        return [find_cfg_edges(path) for path in paths]

    def plot_path(self, path: List[CFGEdge], filename=None):
        """Plot the path on the CFG (path is a list of CFG edges)."""
        nodes = [AGraphNode(name=n.label, shape=n.shape) for n in self.nodes]
        edges = [AGraphEdge(e.src.label, e.tgt.label, e.attr, color=GREEN if e in path else "black") for e in
                 self.edges]  # color: green-like

        plot_graph(self.name if filename is None else filename, nodes, edges)

    def plot_ppo(self, path: List[CFGEdge], ppo_rels: List[CFGEdge], filename=None):
        """Plot the path and ppo relations on the CFG (both path and ppo are lists of CFG edges)."""
        nodes = [AGraphNode(name=n.label, shape=n.shape) for n in self.nodes]
        edges = [AGraphEdge(e.src.label, e.tgt.label, e.attr, color=GREEN if e in path else "black") for e in
                 self.edges]
        edges += [AGraphEdge(e.src.label, e.tgt.label, e.attr, color=RED) for e in ppo_rels]

        plot_graph(self.name if filename is None else filename, nodes, edges)


def cfg_to_ssa(cfg: CFG) -> Dict[Inst, SSAInst]:
    # TODO: transform each inst to its SSA form
    raise NotImplementedError
