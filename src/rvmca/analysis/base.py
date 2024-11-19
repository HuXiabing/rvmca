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

"""Graph Base"""

from typing import List
from rvmca.utils.plot import plot_graph, AGraphNode, AGraphEdge
import networkx as nx


class BaseNode:
    """The Base node.

    Parameters
    ----------
    value: Any
    label: str
        The node label for pretty printing.

    Attributes
    ----------
    value: Any
    label: str
        The node label for pretty printing.
    preds: list
        The predecessors of the node.
    succs: list
        The successors of the node.

    """

    def __init__(self, value=None, label: str = None):
        self.value = value
        self.label = str(value) if label is None else label
        self.preds, self.succs = [], []

    def __repr__(self):
        """facilitate debugging"""
        return f"{self.label}"


class BaseEdge:
    """The base edge.

    Parameters
    ----------
    src: CFGNode
        The source node of the edge.
    tgt: CFGNode
        The target node of the edge.
    attr: String
        The attribute of the edge, e.g., true, false, ppo.
    """

    def __init__(self, src, tgt, attr: str = ""):
        self.src, self.tgt, self.attr = src, tgt, attr

    def __repr__(self):
        return f'({self.src.label} -> {self.tgt.label})'


class BaseGraph:
    """The base graph.

    Parameters
    ----------
    inputs: list
        A list of node values.
    name: str, optional
        The graph name. The default is a time stamp.

    Attributes
    ----------
    nodes: list
        The cfg nodes.
    edges: list
        The cfg edges.
    """
    idx = 0

    def __init__(self, inputs: List, name: str = None):
        self.name = name
        self.nodes, self.edges = [], []

    def _construct_edge(self, src, tgt, attr):
        raise NotImplementedError

    def add_edge(self, src: BaseNode, tgt: BaseNode, attr=''):
        """Add an edge from src to tgt."""
        if tgt not in src.succs:
            src.succs.append(tgt)
        if src not in tgt.preds:
            tgt.preds.append(src)
        if (src, tgt) not in self.edges:
            self.edges.append(self._construct_edge(src, tgt, attr))

    def _verify(self):
        """Verify the legitimacy of the CFG"""
        pass

    def _construct(self, inputs: List):
        """Construct the graph."""
        raise NotImplementedError

    def find_node_by_value(self, value):
        for node in self.nodes:
            if value == node.value:
                return node
        assert ValueError, f'Node {value} is not found.'

    def plot(self, filename=None):
        """Plot the graph."""
        if not isinstance(filename, str):
            filename = str(filename)
        nodes = [AGraphNode(name=n.label, shape=n.shape) for n in self.nodes]
        edges = [AGraphEdge(e.src.label, e.tgt.label, str(e.attr)) for e in self.edges]
        plot_graph(self.name if filename is None else filename, nodes, edges)

    def find_paths(self, start, end) -> List[List[BaseEdge]]:
        """Find all simple paths from start to end.
        A simple path is a path with no repeated nodes.
        Refer to https://networkx.org/documentation/stable/reference/algorithms/simple_paths.html
        """

        ni = lambda x: self.nodes.index(x)  # node index map
        G = nx.MultiDiGraph([(ni(e.src), ni(e.tgt)) for e in self.edges])  # construct a graph

        paths = list(nx.all_simple_edge_paths(G, ni(start), ni(end)))

        def find_edges(path):
            edges = []
            for (x, y, i) in path:
                src, tgt = self.nodes[x], self.nodes[y]
                edges.append(list(filter(lambda e: e.src == src and e.tgt == tgt, self.edges))[i])
            return edges

        return [find_edges(path) for path in paths]
