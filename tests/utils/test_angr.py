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
"""Test for angr"""

import angr, claripy
from rvmca.config import *


class TestAngr:
    def test1(self):
        # https://docs.angr.io/en/latest/advanced-topics/ir.html

        # load the program binary
        proj = angr.Project(INPUT_PATH / 'bin' / 'hello')

        # translate the starting basic block
        irsb = proj.factory.block(proj.entry).vex
        # and then pretty-print it
        irsb.pp()

        # translate and pretty-print a basic block starting at an address
        irsb = proj.factory.block(0x10690).vex
        irsb.pp()

        # this is the IR Expression of the jump target of the unconditional exit at the end of the basic block
        print(irsb.next)

        # this is the type of the unconditional exit (e.g., a call, ret, syscall, etc)
        print(irsb.jumpkind)

        # you can also pretty-print it
        irsb.next.pp()

        # iterate through each statement and print all the statements
        for stmt in irsb.statements:
            stmt.pp()

        # pretty-print the IR expression representing the data,
        # and the *type* of that IR expression written by every store statement
        import pyvex
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.Store):
                print("Data:", )
                stmt.data.pp()
                print("")
                print("Type:", )
                print(stmt.data.result_type)
                print("")

        # pretty-print the condition and jump target of every conditional exit from the basic block
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.Exit):
                print("Condition:", )
                stmt.guard.pp()
                print("")
                print("Target:", )
                stmt.dst.pp()
                print("")

        # these are the types of every temp in the IRSB
        print(irsb.tyenv.types)

        # here is one way to get the type of temp 0
        print(irsb.tyenv.types[0])

    def test2(self):
        # https://docs.angr.io/en/latest/core-concepts/symbolic.html

        proj = angr.Project(OUTPUT_PATH / 'test1')

        begin_addr = proj.loader.main_object.get_symbol('rvmca_block_begin')
        end_addr = proj.loader.main_object.get_symbol('rvmca_block_end')
        # translate the starting basic block
        print(f"Begin addr: {begin_addr}")
        print(f"End addr: {end_addr}")

        zero = claripy.BVS('zero', 64)
        init_state = proj.factory.blank_state(addr=begin_addr.rebased_addr)

        # 列出所有访存指令的位置，地址寄存器
        # 增加约束：在对应位置的，地址寄存器的值，等于0
        # 求解所有寄存器的值，再加上sp的值

        # init_state.regs.x0 = zero
        # init_state.regs.x1 = zero
        # init_state.regs.x2 = zero
        # init_state.regs.x3 = zero
        # init_state.regs.x4 = zero
        # init_state.regs.x5 = zero
        # init_state.regs.x6 = zero
        # init_state.regs.x7 = zero

        # Create a simulation manager
        simgr = proj.factory.simulation_manager(init_state)

        # Explore the binary, looking for the address of helloWorld
        simgr.explore(find=end_addr.rebased_addr)

        # Check if we found a state that reached the target
        if simgr.found:
            input_value = simgr.found[0].solver.eval(zero)
            print(f"Value of zero that reaches block_end: {input_value}")
            # Get the constraints for reaching the helloWorld function
            constraints = simgr.found[0].solver.constraints
            print(f'Constraints: {constraints}')
            # Create a solver with the constraints
            solver = claripy.Solver()
            solver.add(constraints)
            min_val = solver.min(zero)
            max_val = solver.max(zero)
            print(f"Function arg: min = {min_val}, max = {max_val}")
        else:
            print("Did not find a state that reaches block_end.")

    def test_pyvex(self):
        import pyvex
        import archinfo

        # translate an RISC-V basic block (of nops) at 0x400400 into VEX
        # irsb = pyvex.lift(b"", 0x104e0, archinfo.ArchRISCV64())
        irsb = pyvex.lift(b'\xb3\x28\x16\x03', 0x104e0, archinfo.ArchRISCV64())

        # pretty-print the basic block
        irsb.pp()

        # this is the IR Expression of the jump target of the unconditional exit at the end of the basic block
        print(irsb.next)

        # this is the type of the unconditional exit (i.e., a call, ret, syscall, etc)
        print(irsb.jumpkind)

        # you can also pretty-print it
        irsb.next.pp()

        # iterate through each statement and print all the statements
        for stmt in irsb.statements:
            stmt.pp()

        # pretty-print the IR expression representing the data, and the *type* of that IR expression written by every store statement
        import pyvex
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.Store):
                print("Data:", end="")
                stmt.data.pp()
                print("")

                print("Type:", end="")
                print(stmt.data.result_type)
                print("")

        # pretty-print the condition and jump target of every conditional exit from the basic block
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.Exit):
                print("Condition:", end="")
                stmt.guard.pp()
                print("")

                print("Target:", end="")
                stmt.dst.pp()
                print("")

        # these are the types of every temp in the IRSB
        print(irsb.tyenv.types)

        # here is one way to get the type of temp 0
        # print(irsb.tyenv.types[0])