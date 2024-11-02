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

from rvmca.trans.block import *
from rvmca.utils.file_util import *
from rvmca.config import *

all_tests = list_files(TESTS_INPUT_PATH / 'dv', '.S')


class TestTrans:

    def test_one_case_with_name(self):
        filepath = '/home/xuezheng/PycharmProjects/rvmca/tests/input/dv/test805.S'
        self.test_one_case(filepath)

    @pytest.mark.parametrize('filepath', all_tests)
    def test_one_case(self, filepath):
        transform_for_profiling(filepath)

    def test_400_perlbench(self):
        directory = INPUT_PATH / 'spec06' / '400_perlbench'
        for file in list_files(directory, '.S'):
            transform_for_profiling(file)
