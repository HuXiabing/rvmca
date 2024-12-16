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

"""Binary Embedding"""

import lief
import hashlib


def load_binary(path: str) -> lief.Binary:
    return lief.parse(path)


def hash_function(binary: lief.Binary, func_name: str) -> str:
    func_symbol = binary.get_symbol(func_name)
    assert func_symbol.is_function
    content = binary.get_content_from_virtual_address(func_symbol.value, func_symbol.size)
    return hashlib.md5(content.tobytes()).hexdigest()


def hash_functions(binary: lief.Binary, func_names: list[str]) -> str:
    h = ''
    for func_name in func_names:
        h += hash_function(binary, func_name)
        h = hashlib.md5(h.encode('utf-8')).hexdigest()
    return h


def hash_elf(binary: lief.Binary) -> str:
    func_names = [str(func.name) for func in binary.exported_functions]
    return hash_functions(binary, func_names)
