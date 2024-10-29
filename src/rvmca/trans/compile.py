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

from rvmca.config import *
from rvmca.prog import Program
from rvmca.utils.file_util import read_file, write_to_file
from rvmca.utils.cmd_util import run_cmd


def compile_block(program: Program, bin_name: str):
    wrapper_path = PROJECT_PATH / 'src' / 'rvmca' / 'trans' / 'template' / 'block_wrapper.S'
    wrapper = read_file(wrapper_path)
    wrapper = wrapper.replace('#CODE#', program.code)
    write_to_file(f'{OUTPUT_PATH / bin_name}.S', wrapper, append=False)
    run_cmd(f'{RISCV_GCC} {OUTPUT_PATH / bin_name}.S -o {OUTPUT_PATH / bin_name}')


def assemble_code(code: str, name: str = 'test'):
    """Output a file named {name}.code"""
    write_to_file(f'{OUTPUT_PATH / name}.S', code, append=False)
    run_cmd(f'{RISCV_GCC} {OUTPUT_PATH / name}.S -c -o {OUTPUT_PATH / name}.o')
    output = run_cmd(f'{RISCV_OBJDUMP} -d {OUTPUT_PATH / name}.o')

    import re
    pattern = r'^\s*[0-9a-f]+:\s+(.*)'
    # pattern = r'^\s*[0-9a-f]+:\s+([0-9a-f]+)'
    machine_code = '\n'.join(re.findall(pattern, output, re.MULTILINE))
    write_to_file(f'{OUTPUT_PATH / name}.code', machine_code, append=False)
    return machine_code
