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

from rvmca.prog import *
from rvmca.utils.file_util import *
from rvmca.config import *


class TestProg:

    def test1(self):
        text = 'li x1, 5' \
               'addi x2, x1, 1' \
               'add x2, x2, x2'
        program = parse_program(text)
        print(program.insts)

    def test_parser(self):
        directory = INPUT_PATH / 'dv'
        for file in list_files(directory, '.S'):
            content = read_file(file) + '\n'
            parse_program(content)

    def test_fp(self):
        text =  'fabs.d f1, f5\n' \
                'fclass.d x3, f3\n' \
                'fcvt.d.w f1, x3\n' \
                'fdiv.d f3, f4, f6\n' \
                'fld f31, -12(sp)\n' \
                'fle.s x8, f30, f31\n' \
                'fmadd.s f2, f5, f17, f4\n' \
                'fmv.x.d x3, f4\n' \
                'fmv.d.x f3, x4\n' \
                'fsd f8, 36(x5)'
        program = parse_program(text)
        print(program.insts)
