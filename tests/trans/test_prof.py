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
import pytest

from rvmca.analysis import CFG, path_to_ssa, DDG, RVFG
from rvmca.trans.prof import *
from rvmca.utils.file_util import *
from rvmca.config import *

all_tests = list_files(TESTS_INPUT_PATH / 'coremark-gcc14-O2', '.S')
# all_tests = list_files(TESTS_INPUT_PATH / 'manual', '.S')

class TestProf:

    def test_one_case_with_name(self):
        filepath = '/home/xuezheng/PycharmProjects/rvmca/input/test.S'
        self.test_one_case(filepath)

    @pytest.mark.parametrize('filepath', all_tests)
    def test_one_case(self, filepath):
        transform_for_profiling(filepath)

    def test_400_perlbench(self):
        directory = INPUT_PATH / 'spec06' / '400_perlbench'
        for file in list_files(directory, '.S'):
            transform_for_profiling(file)

    def test_manual(self):
        directory = TESTS_INPUT_PATH / 'manual'
        for file in list_files(directory, '.S'):
            transform_for_profiling(file)

    def test_fail(self):
        file = TESTS_INPUT_PATH / 'manual' / '5.S'
        # file = TESTS_INPUT_PATH / 'coremark-gcc14-O2' / 'block-28.S'
        transform_for_profiling(file)

    def test_cfg(self):
        filepath = INPUT_PATH / 'test.S'
        content = read_file(filepath) + '\n'
        prog = parse_program(content)
        prog = remap_regs_for_block(prog)
        prog = zero_imm_for_block(prog)
        prog = legalize_jump_and_branch(prog)

        cfg = CFG(prog.insts)
        cfg.plot(OUTPUT_PATH / 'test')
        ssas = path_to_ssa(cfg.edges)
        print()
        print('\n'.join([str(ssa) for ssa in ssas]))

    def test_ddg_rvfg(self):
        filepath = INPUT_PATH / 'test.S'
        content = read_file(filepath) + '\n'
        prog = parse_program(content)
        prog = remap_regs_for_block(prog)
        prog = zero_imm_for_block(prog)
        prog = legalize_jump_and_branch(prog)

        cfg = CFG(prog.insts)
        cfg.plot(OUTPUT_PATH / 'test.cfg')
        ssas = path_to_ssa(cfg.edges)
        print()
        print('\n'.join([str(ssa) for ssa in ssas]))

        ddg = DDG(ssas)
        ddg.plot(OUTPUT_PATH / 'test.ddg')

        rvfg = RVFG(ssas)
        rvfg.plot(OUTPUT_PATH / 'test.rvfg')

