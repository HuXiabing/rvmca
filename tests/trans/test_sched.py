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

from rvmca.trans.sched import *
from rvmca.utils.file_util import *
from rvmca.config import *

all_tests = list_files(TESTS_INPUT_PATH / 'dv', '.S')


class TestSched:

    def test_one_case_with_name(self):
        filepath = '/home/huxiabing/Documents/rvmca/tests/output/code/test.S'
        self.test_one_case(filepath)

    @pytest.mark.parametrize('filepath', all_tests)
    def test_one_case(self, filepath):
        transform_for_random_scheduling(filepath, limit=10)

    def test1(self):
        program_raw = '\n'.join([
            'add x0, x1, x2',
            'add x0, x0, x5',
            'add x1, x0, x8',
        ])
        print()
        program = parse_program(program_raw)
        print('<Block>:')
        print(program.code)
        i = 0
        for prog in random_scheduling(program, 10):
            print(f'\n<New Block {i}>:')
            print(prog.code)
            i += 1

    def test2(self):
        program_raw = '\n'.join([
            'ld x1, 0(x2)',
            'fence',
            'sd x4, 0(x3)',
            'add x1, x1, x1',
            'bne x5, x6, 0'
        ])
        print()
        program = parse_program(program_raw)
        print('<Block>:')
        print(program.code)
        i = 0
        for prog in random_scheduling(program, 10):
            print(f'\n<New Block {i}>:')
            print(prog.code)
            i += 1
