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
"""Test for RISC-V Program Parser"""
from rvmca.analysis import CFG, path_to_ssa, cfg_to_ssa
from rvmca.prog import *


class TestProg:
    def test1(self):
        text = 'li x1, 5' \
                'addi x2, x1, 1' \
                'add x2, x2, x2'
        program = parse_program(text)
        print(program.insts)

    def test2(self):
        text = 'li x1, 5' \
               'addi x2, x1, 1' \
               'add x2, x2, x2'
        program = parse_program(text)
        cfg = CFG(program.insts)
        paths = cfg.find_all_paths()
        for p in paths:
            ssa = path_to_ssa(p)
            print(ssa)

    def test3(self):
        # TODO:
        text = 'li x1, 5' \
               'addi x2, x1, 1' \
               'add x2, x2, x2'
        program = parse_program(text)
        cfg = CFG(program.insts)
        i2s = cfg_to_ssa(cfg)
        for i in program.insts:
            print(f'{i} -> {i2s[i]}')