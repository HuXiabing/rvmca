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

"""Instruction Scheduling"""
from rvmca.log import INFO
from rvmca.trans.block import *

from rvmca.prog import IType, Program, parse_program
from rvmca.utils.file_util import read_file, write_to_file


def random_scheduling(program: Program, limit=1000, plot=False):
    """random schedule insts via topological sorting (returns a generator)"""
    check_block_validity(program)

    dag = {k: set() for k in program.insts}

    # preserve the last inst if it is a branch or jump
    last_inst = program.insts[-1]
    if last_inst.type in [IType.Branch, IType.Jump]:
        for inst in program.insts[:-1]:
            dag[inst].add(last_inst)

    # preserve the order of memory instructions
    mem_insts = [i for i in program.insts if i.type in
                 [IType.Load, IType.Store, IType.Amo, IType.Fence, IType.FenceI]]
    for i in range(len(mem_insts) - 1):
        prev, next = mem_insts[i], mem_insts[i + 1]
        dag[prev].add(next)

    # preserve RAW & WAW dependencies
    for i in range(len(program.insts)):
        inst1 = program.insts[i]
        rd_1 = inst1.get_def()
        if not rd_1 or rd_1 is XREG[0]:
            continue
        for j in range(i + 1, len(program.insts)):
            inst2 = program.insts[j]
            for reg in inst2.get_uses():
                if reg is rd_1:
                    dag[inst1].add(inst2)
                    break
            rd_2 = inst2.get_def()
            if rd_2 is rd_1:
                # rd_1 is re-defined
                dag[inst1].add(inst2)
                break

    # preserve WAR dependencies
    for i in range(len(program.insts)):
        inst1 = program.insts[i]
        for rs_1 in inst1.get_uses():
            if rs_1 is XREG[0]:
                continue
            for j in range(i + 1, len(program.insts)):
                inst2 = program.insts[j]
                if inst2.get_def() is rs_1:
                    dag[inst1].add(inst2)
                    break

    if plot:
        from rvmca.utils.plot import AGraphNode, AGraphEdge, plot_graph
        nodes = [AGraphNode(str(k)) for k in dag.keys()]
        edges = []
        for k, v in dag.items():
            edges.extend([AGraphEdge(str(k), str(n)) for n in v])
        plot_graph('ddg', nodes, edges)

    finished = False

    def find_ordering(graph, in_degree, visited, stack, result) -> int:
        if all(visited[v] for v in graph):
            result.append(stack[:])
            if len(result) >= limit:
                return True
            return False

        for vertex in graph:
            if finished:
                break
            if visited[vertex]:
                continue

            if in_degree[vertex] == 0:
                visited[vertex] = True
                stack.append(vertex)
                for neighbor in graph[vertex]:
                    in_degree[neighbor] -= 1
                if find_ordering(graph, in_degree, visited, stack, result):
                    return True
                stack.pop()
                for neighbor in graph[vertex]:
                    in_degree[neighbor] += 1
                visited[vertex] = False

    def all_topological_sorts(graph):
        in_degree = {u: 0 for u in graph}
        for u in graph:
            for v in graph[u]:
                in_degree[v] += 1

        visited = {u: False for u in graph}
        result = []
        find_ordering(graph, in_degree, visited, [], result)
        return result

    all_orders = all_topological_sorts(dag)
    for i, order in enumerate(all_orders, 1):
        import copy
        new_prog = copy.deepcopy(program)
        new_prog.insts = order
        yield new_prog


def transform_for_random_scheduling(filepath, output_path='', limit=1000):
    # read file
    INFO(f'transform [{filepath}]')
    filepath = str(filepath)
    test_name = filepath.split('/')[-1].replace('.S', '')
    content = read_file(filepath) + '\n'

    if output_path == '':
        output_path = f"{OUTPUT_PATH / test_name}"

    INFO(f'<Block>:\n{content}')
    prog = parse_program(content)
    i = 0
    for new_prog in random_scheduling(prog, limit):
        write_to_file(f'{output_path}-{i}.S', new_prog.code, append=False)
        i += 1
    print(f'Successfully generate {i} files ({output_path}-*.S).')
