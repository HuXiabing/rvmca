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
from rvmca.trans.block import *
from rvmca.prog import *
from rvmca.utils.file_util import *
from rvmca.config import *

available_regs = [
    # TODO: check the available registers
    find_reg_by_name(n)
    for n in [
        'x0',
        # 't0', 't1', 't2', 't3', 't4', 't5', 't6',
        'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7']
]


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

    def test_400_perlbench(self):
        directory = INPUT_PATH / 'spec06' / '400_perlbench'
        for file in list_files(directory, '.S'):
            content = read_file(file) + '\n'
            prog = parse_program(content)
            print('\nOriginal program:')
            print(prog)
            prog = remap_regs_for_block(prog, available_regs)
            print('\nRemap registers:')
            print(prog)

            print('\nInit code:')
            inits = init_regs_for_block(prog)
            print('\n')
            for inst in inits:
                print(inst)

            print('\nZero immediate:')
            prog = zero_imm_for_block(prog)
            print(prog)

    def test_compile(self):
        directory = INPUT_PATH / 'spec06' / '400_perlbench'
        for file in list_files(directory, '.S'):
            content = read_file(file) + '\n'
            prog = parse_program(content)
            prog = remap_regs_for_block(prog, available_regs)
            inits = init_regs_for_block(prog)
            prog = zero_imm_for_block(prog)

            from rvmca.trans.compile import compile_block

            compile_block(prog, 'test1')

    def test_init_addr_reg(self):
        filename = INPUT_PATH / 'spec06' / '400_perlbench' / '1.S'
        content = read_file(filename) + '\n'
        prog = parse_program(content)
        prog = remap_regs_for_block(prog, available_regs)
        # prog = zero_imm_for_block(prog)
        init_code = init_regs_for_block(prog)
        print(init_code)
