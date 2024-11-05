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
"""Test for elf tools"""

from rvmca.config import *


class TestElf:
    def test_elf_low_high_api(self):
        """Test elf low/high api"""
        # pyelftools does not support write elf files.
        # see https://github.com/eliben/pyelftools/issues/15
        pass

    def test_makeelf(self):
        """Test makeelf"""
        # https://github.com/v3l0c1r4pt0r/makeelf
        # makeelf has many bugs. Do not use it.
        # from makeelf.elf import *
        pass

    def test_lief(self):
        """Test lief"""
        # https://lief.re/doc/latest/index.html

        import lief
        binary = lief.parse(TESTS_INPUT_PATH / 'bin' / 'hello')
        assert type(binary) is lief.ELF.Binary

        assert binary.has_section_with_va(0x10698)

        # modify instructions
        binary.patch_address(0x10698, [0xff, 0xff, 0xff, 0xff])

        binary.write(str(TESTS_INPUT_PATH / 'bin' / 'hello_new'))
