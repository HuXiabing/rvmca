# MIT License
#
# Copyright (c) 2024 Anonymous Authors (anonymous@example.invalid)
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
"""Test for RISC-V Block"""
from rvmca.trans import *


class TestBlock:

    def test_assemble(self):
        src = ['add x0, x1, x2', 'mul x3, x4, x4']
        code = assemble(src)
        print(code)

    def test_assemble_pp(self):
        src = ['add x0, x1, x2', 'mul x3, x4, x4']
        code = assemble_pp_code(src)
        print(code)

    def test_disassemble(self):
        src = ['add x0, x1, x2', 'mul x3, x4, x4']
        code = assemble(src)
        insts = disassemble(code)
        print(insts)
