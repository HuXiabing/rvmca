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

"""Helpers for Graph Plotting"""
from typing import List

import pygraphviz as pgv


class AGraphNode:
    """The graph node.

    Parameters
    ----------
    name: str
        The node name.
    shape: str, optional
        The node shape. e.g., polygon, circle, ellipse. The default is 'polygon'.
    color: str, optional
        The node color. The default is 'black'.
    style: str, optional
        The node edge style. The default is 'bold'.

    References
    ----------
    For detailed node attributes, refer to
    pygraphviz: https://zhuanlan.zhihu.com/p/104636240
    or https://pygraphviz.github.io/

    """

    def __init__(self, name, shape='polygon', color='black', style='bold'):
        self.name, self.shape, self.color, self.style = name, shape, color, style


class AGraphEdge:
    """The graph edge.

    Parameters
    ----------
    src: str
        The source node of the edge.
    tgt: str
        The target node of the edge.
    dir: str, optional
        The edge direction. The default is 'forward'.
    """

    def __init__(self, src, tgt, label: str = "", dir: str = 'forward', color: str = "black"):
        self.src, self.tgt = src, tgt
        self.label, self.color = label, color
        self.dir = dir

    def unpack(self):
        """Unpack the edge and get the source and target nodes.

        Returns
        -------
        str, str
            The name of the source node,
            the name of the target node.

        Examples
        --------
        >>> s, t = AGraphNode('s'), AGraphNode('t')
        >>> edge = AGraphEdge('s', 't')
        >>> a, b = edge.unpack() # `a` is 's' and `b` is 't'
        """
        return self.src, self.tgt


class Cluster:
    def __init__(self, label, nodes=None):
        self.label = label
        self.nodes = nodes if nodes else []
        self.color = '#00cc66'


def plot_graph(filename, nodes, edges, clusters: List[Cluster] = None):
    """Plot a graph using the `pygraphviz` library.

    Parameters
    ----------
    filename: str
        The name of the file to save the graph to.
    nodes: list
        A list of AGraphNode objects.
    edges: list
        A list of AGraphEdge objects.
    clusters: list
        A list of Cluster (SubGraph)
    References
    ----------
    pygraphviz: https://zhuanlan.zhihu.com/p/104636240

    Examples
    --------
    Plot a graph to 'add.png'.

    >>> plot_graph('add', nodes, edges)

    """

    g = pgv.AGraph(directed=True, strict=False, rankdir="TB")

    for node in nodes:
        g.add_node(node.name, shape=node.shape, color=node.color, style=node.style)
    for edge in edges:
        g.add_edge(edge.unpack(), dir=edge.dir, label=edge.label, color=edge.color, fontcolor=edge.color)

    if clusters:
        for cluster in clusters:
            with g.add_subgraph(name='cluster_' + cluster.label, label=cluster.label) as sg:
                for n in cluster.nodes:
                    sg.add_node(n)

    g.layout()
    g.draw(filename + '.dot', format='dot', prog='dot')
