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
"""Test for Embeddings"""
import pytest

from rvmca.analysis import CFG, path_to_ssa, DDG
from rvmca.trans.prof import *
from rvmca.utils.file_util import *
from rvmca.config import *
from rvmca.trans.embed import *

binary = load_binary(TESTS_INPUT_PATH / 'bin' / 'coremark.riscv.clang20.o2')


class TestEmbed:

    def test1(self):
        print(hash_function(binary, 'main'))

    def test2(self):
        print(hash_functions(binary, ['main', 'main']))

    def test3(self):
        print(hash_elf(binary))
